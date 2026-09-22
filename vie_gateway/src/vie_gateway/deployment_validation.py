from __future__ import annotations

import asyncio
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from .credentials import VaultCredentialProvider


_DIGEST_IMAGE = re.compile(r"@sha256:[0-9a-f]{64}$")
_PLACEHOLDER_VALUES = {"", "replace-with-random-secret", "replace-with-image-digest",
                       "replace-with-upstream-token", "replace-with-collector-token"}


@dataclass(frozen=True)
class DeploymentValidation:
    errors: tuple[str, ...]
    checks: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, object]:
        return {"valid": self.valid, "errors": list(self.errors), "checks": list(self.checks)}


def _value(environment: Mapping[str, str], name: str) -> str:
    return environment.get(name, "").strip()


def _is_true(environment: Mapping[str, str], name: str) -> bool:
    return _value(environment, name).lower() == "true"


def _check_url(environment: Mapping[str, str], name: str, *, require_tls: bool, errors: list[str], checks: list[str]) -> None:
    value = _value(environment, name)
    if not value:
        errors.append(f"missing_{name.lower()}")
        return
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        errors.append(f"invalid_{name.lower()}")
        return
    if require_tls and parsed.scheme != "https":
        errors.append(f"{name.lower()}_tls_required")
        return
    checks.append(name.lower())


def validate_environment(environment: Mapping[str, str]) -> DeploymentValidation:
    """Validate deployment configuration without contacting external services.

    The result is intentionally limited to check names and stable error codes;
    it never echoes URLs, paths, credentials, or image references.
    """
    errors: list[str] = []
    checks: list[str] = []
    production = _is_true(environment, "MADVA_PRODUCTION")
    if not production:
        errors.append("production_mode_required")
    require_tls = production

    _check_url(environment, "MADVA_OIDC_JWKS_URL", require_tls=require_tls, errors=errors, checks=checks)
    _check_url(environment, "MADVA_OIDC_ISSUER", require_tls=require_tls, errors=errors, checks=checks)
    if not _value(environment, "MADVA_OIDC_AUDIENCE"):
        errors.append("missing_madva_oidc_audience")
    else:
        checks.append("madva_oidc_audience")

    intent_secret = _value(environment, "MADVA_INTENT_SECRET")
    if intent_secret in _PLACEHOLDER_VALUES or len(intent_secret) < 32:
        errors.append("intent_secret_too_short_or_placeholder")
    else:
        checks.append("madva_intent_secret")

    runtime_image = _value(environment, "MADVA_RUNTIME_IMAGE")
    upstream_url = _value(environment, "MADVA_MCP_UPSTREAM_URL")
    if bool(runtime_image) == bool(upstream_url):
        errors.append("exactly_one_execution_backend_required")
    elif runtime_image:
        if not _DIGEST_IMAGE.search(runtime_image):
            errors.append("runtime_image_must_be_digest_pinned")
        else:
            checks.append("immutable_execution_image")
    else:
        _check_url(environment, "MADVA_MCP_UPSTREAM_URL", require_tls=require_tls, errors=errors, checks=checks)
        if not _value(environment, "MADVA_MCP_UPSTREAM_ALLOWED_HOSTS"):
            errors.append("missing_madva_mcp_upstream_allowed_hosts")
        else:
            checks.append("mcp_upstream_allowlist")

    if not _value(environment, "MADVA_AUDIT_LOG_PATH"):
        errors.append("missing_madva_audit_log_path")
    else:
        checks.append("durable_audit_path")
    if not _value(environment, "MADVA_REQUIRE_TENANT_BINDING") or not _is_true(environment, "MADVA_REQUIRE_TENANT_BINDING"):
        errors.append("tenant_binding_required")
    else:
        checks.append("tenant_binding_required")
    if not _value(environment, "MADVA_POLICY_REGISTRY_PATH"):
        errors.append("missing_madva_policy_registry_path")
    else:
        checks.append("policy_registry_path")
    if not _is_true(environment, "MADVA_REQUIRE_APPROVED_POLICY"):
        errors.append("approved_policy_required")
    else:
        checks.append("approved_policy_required")

    if _is_true(environment, "MADVA_REQUIRE_VAULT"):
        _check_url(environment, "VAULT_ADDR", require_tls=require_tls, errors=errors, checks=checks)
        if not _value(environment, "VAULT_TOKEN_FILE"):
            errors.append("missing_vault_token_file")
        else:
            checks.append("vault_token_file")

    if _is_true(environment, "MADVA_REQUIRE_OTEL"):
        endpoint = "OTEL_EXPORTER_OTLP_ENDPOINT" if _value(environment, "OTEL_EXPORTER_OTLP_ENDPOINT") else "MADVA_SIEM_OTLP_ENDPOINT"
        _check_url(environment, endpoint, require_tls=require_tls, errors=errors, checks=checks)

    return DeploymentValidation(tuple(errors), tuple(checks))


async def validate_live_environment(environment: Mapping[str, str]) -> DeploymentValidation:
    """Run safe network and storage checks after static validation succeeds."""
    static = validate_environment(environment)
    if not static.valid:
        return static
    errors = list(static.errors)
    checks = list(static.checks)
    production = _is_true(environment, "MADVA_PRODUCTION")

    issuer = _value(environment, "MADVA_OIDC_ISSUER").rstrip("/")
    jwks_url = _value(environment, "MADVA_OIDC_JWKS_URL")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            discovery = await client.get(f"{issuer}/.well-known/openid-configuration")
            discovery.raise_for_status()
            metadata = discovery.json()
            if not isinstance(metadata, dict) or str(metadata.get("issuer", "")).rstrip("/") != issuer:
                errors.append("oidc_discovery_issuer_mismatch")
            elif str(metadata.get("jwks_uri", "")) != jwks_url:
                errors.append("oidc_discovery_jwks_mismatch")
            keys_response = await client.get(jwks_url)
            keys_response.raise_for_status()
            keys_body = keys_response.json()
            if not isinstance(keys_body, dict) or not isinstance(keys_body.get("keys"), list) or not keys_body["keys"]:
                errors.append("oidc_jwks_empty")
            else:
                checks.append("oidc_discovery_and_jwks")
    except (httpx.HTTPError, ValueError, TypeError):
        errors.append("oidc_provider_unavailable")

    audit_path = Path(_value(environment, "MADVA_AUDIT_LOG_PATH"))
    try:
        with tempfile.NamedTemporaryFile(prefix=".madva-validation-", dir=audit_path.parent, delete=True) as probe:
            probe.write(b"madva-validation-probe\n")
            probe.flush()
        checks.append("audit_storage_writable")
    except OSError:
        errors.append("audit_storage_unwritable")

    if _is_true(environment, "MADVA_REQUIRE_VAULT"):
        vault_addr = _value(environment, "VAULT_ADDR").rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                health = await client.get(f"{vault_addr}/v1/sys/health")
                health.raise_for_status()
            token_file = _value(environment, "VAULT_TOKEN_FILE")
            reference = _value(environment, "MADVA_VALIDATION_VAULT_REFERENCE")
            if reference:
                with tempfile.TemporaryDirectory(prefix="madva-vault-validation-") as lease_root:
                    provider = VaultCredentialProvider(
                        vault_addr,
                        token_file=token_file,
                        require_tls=production,
                        lease_root=lease_root,
                    )
                    lease = await provider.acquire(
                        reference,
                        uuid4(),
                        datetime.now(UTC) + timedelta(minutes=1),
                    )
                    await provider.release(lease)
                checks.append("vault_health_and_credential_access")
            else:
                checks.append("vault_health_and_token_file")
        except (httpx.HTTPError, OSError, PermissionError, ValueError):
            errors.append("vault_unavailable_or_credential_check_failed")

    if _is_true(environment, "MADVA_REQUIRE_OTEL"):
        endpoint_name = "OTEL_EXPORTER_OTLP_ENDPOINT" if _value(environment, "OTEL_EXPORTER_OTLP_ENDPOINT") else "MADVA_SIEM_OTLP_ENDPOINT"
        parsed = urlsplit(_value(environment, endpoint_name))
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(parsed.hostname, port), timeout=5.0)
            writer.close()
            await writer.wait_closed()
            del reader
            checks.append("otel_endpoint_reachable")
        except (asyncio.TimeoutError, OSError, ValueError):
            errors.append("otel_endpoint_unreachable")

    return DeploymentValidation(tuple(errors), tuple(checks))
