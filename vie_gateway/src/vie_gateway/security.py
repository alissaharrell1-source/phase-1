from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from jsonschema import Draft202012Validator, SchemaError
from .canonical import canonical_json_bytes
from .contracts import IntentContract, Permit, TokenClaims

class AuthorizationError(ValueError):
    """Raised for any authentication, binding, or policy failure."""


class IntentSigner:
    def __init__(self, secret: str | None) -> None:
        self.secret = (secret or os.environ.get("MADVA_INTENT_SECRET", "")).encode()

    def verify(self, intent: IntentContract) -> None:
        if not self.secret:
            return
        if not intent.signature:
            raise AuthorizationError("missing_intent_signature")
        canonical = intent.model_dump(mode="json", exclude={"signature"})
        try:
            message = canonical_json_bytes(canonical)
        except ValueError as exc:
            raise AuthorizationError("invalid_intent_signature") from exc
        expected = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, intent.signature):
            raise AuthorizationError("invalid_intent_signature")

def _decode_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _normalize_identity_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize common OIDC tenant aliases without weakening the binding."""
    normalized = dict(payload)
    tenant_id = normalized.get("tenant_id")
    tid = normalized.get("tid")
    if tenant_id is not None and tid is not None and tenant_id != tid:
        raise AuthorizationError("tenant_claim_mismatch")
    if tenant_id is None and isinstance(tid, str) and tid:
        normalized["tenant_id"] = tid
    return normalized

class TokenValidator:
    """Minimal HS256 boundary; production should use configured OIDC/JWKS verification."""
    def __init__(self, secret: str | None = None, issuer: str = "madva", audience: str = "vie-gateway") -> None:
        self.secret = (secret or os.environ.get("MADVA_TOKEN_SECRET", "")).encode()
        self.issuer, self.audience = issuer, audience

    def validate(self, token: str) -> TokenClaims:
        if not self.secret:
            raise AuthorizationError("token_validation_unconfigured")
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthorizationError("invalid_token")
        encoded_header, encoded_payload, encoded_signature = parts
        try:
            header = json.loads(_decode_part(encoded_header))
            payload = json.loads(_decode_part(encoded_payload))
            actual = _decode_part(encoded_signature)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorizationError("invalid_token") from exc
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise AuthorizationError("unsupported_token_algorithm")
        expected = hmac.new(self.secret, f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, actual):
            raise AuthorizationError("invalid_signature")
        audience = payload.get("aud")
        audience_matches = audience == self.audience or (
            isinstance(audience, list) and self.audience in audience
        )
        if payload.get("iss") != self.issuer or not audience_matches:
            raise AuthorizationError("issuer_or_audience_mismatch")
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(time.time()):
            raise AuthorizationError("expired_token")
        try:
            return TokenClaims.model_validate(_normalize_identity_claims(payload))
        except AuthorizationError:
            raise
        except Exception as exc:
            raise AuthorizationError("invalid_claims") from exc

class JITAuthorizer:
    def __init__(self, require_tenant_binding: bool = False) -> None:
        self.require_tenant_binding = require_tenant_binding

    def authorize(self, claims: TokenClaims, intent: IntentContract, tool: str, operation: str,
                  arguments: dict[str, Any] | None = None) -> Permit:
        if self.require_tenant_binding and not claims.tenant_id:
            raise AuthorizationError("tenant_binding_required")
        if claims.tenant_id != intent.tenant_id:
            if self.require_tenant_binding or claims.tenant_id is not None or intent.tenant_id is not None:
                raise AuthorizationError("tenant_mismatch")
        if claims.intent_scope != intent.purpose:
            raise AuthorizationError("intent_scope_mismatch")
        if tool != intent.tool or operation != intent.operation:
            raise AuthorizationError("tool_or_operation_mismatch")
        if intent.expires_at <= datetime.now(UTC):
            raise AuthorizationError("intent_expired")
        if intent.arguments_schema:
            try:
                Draft202012Validator.check_schema(intent.arguments_schema)
                Draft202012Validator(intent.arguments_schema).validate(arguments or {})
            except SchemaError as exc:
                raise AuthorizationError("invalid_intent_arguments_schema") from exc
            except Exception as exc:
                raise AuthorizationError("tool_arguments_schema_violation") from exc
        return Permit(permit_id=uuid4(), agent_id=claims.agent_id, requester_id=claims.requester_id,
                      tenant_id=claims.tenant_id,
                      policy_id=intent.policy_id, policy_version=intent.policy_version,
                      intent_scope=claims.intent_scope, tool=tool, operation=operation,
                      contract_id=intent.contract_id,
                      expires_at=min(intent.expires_at, datetime.now(UTC) + timedelta(minutes=5)))


class OIDCTokenValidator:
    """Async OIDC/JWKS validator with a bounded in-memory key cache."""

    def __init__(self, jwks_uri: str, issuer: str, audience: str, allowed_algorithms: tuple[str, ...] = ("RS256",),
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.allowed_algorithms = allowed_algorithms
        self.transport = transport
        self._keys: dict[str, dict[str, object]] = {}

    async def _load_keys(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=5.0, transport=self.transport) as client:
                response = await client.get(self.jwks_uri)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise AuthorizationError("oidc_provider_unavailable") from exc
        except (TypeError, ValueError) as exc:
            raise AuthorizationError("invalid_jwks") from exc
        if not isinstance(body, dict):
            raise AuthorizationError("invalid_jwks")
        keys = body.get("keys", [])
        if not isinstance(keys, list):
            raise AuthorizationError("invalid_jwks")
        self._keys = {str(item["kid"]): item for item in keys if isinstance(item, dict) and "kid" in item}

    async def validate(self, token: str) -> TokenClaims:
        try:
            header = jwt.get_unverified_header(token)
            algorithm = str(header.get("alg", ""))
            kid = str(header.get("kid", ""))
        except jwt.PyJWTError as exc:
            raise AuthorizationError("invalid_token") from exc
        if algorithm not in self.allowed_algorithms or not kid:
            raise AuthorizationError("unsupported_token_algorithm")
        if kid not in self._keys:
            await self._load_keys()
        jwk = self._keys.get(kid)
        if jwk is None:
            raise AuthorizationError("unknown_signing_key")
        try:
            key: Any = RSAAlgorithm.from_jwk(json.dumps(jwk))
            payload = jwt.decode(token, key=key, algorithms=list(self.allowed_algorithms),
                                 issuer=self.issuer, audience=self.audience, options={"require": ["exp", "iss", "aud"]})
            return TokenClaims.model_validate(_normalize_identity_claims(payload))
        except AuthorizationError:
            raise
        except (jwt.PyJWTError, ValueError) as exc:
            raise AuthorizationError("oidc_validation_failed") from exc
