from datetime import UTC, datetime, timedelta

import jwt
import pytest

from vie_gateway.security import AuthorizationError, TokenValidator


SECRET = "security-test-secret-with-at-least-48-bytes-for-hs384"


def _token(payload: dict[str, object], *, secret: str = SECRET) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


def _claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "agent_id": "agent-security-test",
        "requester_id": "requester-security-test",
        "intent_scope": "read-only",
        "exp": int(datetime.now(UTC).timestamp()) + 60,
        "iss": "issuer.example",
        "aud": "vie-gateway",
        "jti": "security-regression-jti",
    }
    claims.update(overrides)
    return claims


def test_security_rejects_non_hs256_algorithm() -> None:
    token = jwt.encode(_claims(), SECRET, algorithm="HS384")
    with pytest.raises(AuthorizationError, match="unsupported_token_algorithm"):
        TokenValidator(secret=SECRET, issuer="issuer.example").validate(token)


def test_security_rejects_expired_token() -> None:
    token = _token(_claims(exp=int(datetime.now(UTC).timestamp()) - 1))
    with pytest.raises(AuthorizationError, match="expired_token"):
        TokenValidator(secret=SECRET, issuer="issuer.example").validate(token)


def test_security_rejects_conflicting_tenant_claims() -> None:
    token = _token(_claims(tenant_id="tenant-a", tid="tenant-b"))
    with pytest.raises(AuthorizationError, match="tenant_claim_mismatch"):
        TokenValidator(secret=SECRET, issuer="issuer.example").validate(token)


def test_security_rejects_wrong_audience_even_with_valid_signature() -> None:
    token = _token(_claims(aud="another-service"))
    with pytest.raises(AuthorizationError, match="issuer_or_audience_mismatch"):
        TokenValidator(secret=SECRET, issuer="issuer.example").validate(token)
