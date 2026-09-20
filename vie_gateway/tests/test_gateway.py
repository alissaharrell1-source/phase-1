from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from uuid import uuid4
import pytest
from vie_gateway.contracts import IntentContract, TokenClaims
from vie_gateway.security import AuthorizationError, IntentSigner, JITAuthorizer, OIDCTokenValidator
from vie_gateway.runtime import DockerConfig, DockerRunner
from vie_gateway.telemetry import AuditTracer
from vie_gateway.contracts import ExecutionResult, Permit
from vie_gateway.verification import Verifier
from vie_gateway.credentials import CredentialLease, VaultCredentialProvider
from vie_gateway.dlp import DLPScanner

def test_jit_authorizer_binds_scope_and_tool() -> None:
    intent = IntentContract(contract_id=uuid4(), purpose="echo-purpose", tool="echo", operation="run",
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))
    claims = TokenClaims(agent_id="agent-1", requester_id="requester-1", intent_scope="echo-purpose",
                         exp=int(datetime.now(UTC).timestamp()) + 60, iss="madva", aud="vie-gateway", jti="jti-1")
    permit = JITAuthorizer().authorize(claims, intent, "echo", "run")
    assert permit.contract_id == intent.contract_id
    assert permit.tool == "echo"

def test_jit_authorizer_rejects_scope_mismatch() -> None:
    intent = IntentContract(contract_id=uuid4(), purpose="approved", tool="echo", operation="run",
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))
    claims = TokenClaims(agent_id="agent-1", requester_id="requester-1", intent_scope="different",
                         exp=int(datetime.now(UTC).timestamp()) + 60, iss="madva", aud="vie-gateway", jti="jti-1")
    with pytest.raises(AuthorizationError, match="intent_scope_mismatch"):
        JITAuthorizer().authorize(claims, intent, "echo", "run")

def test_jit_authorizer_enforces_argument_schema() -> None:
    intent = IntentContract(contract_id=uuid4(), purpose="approved", tool="echo", operation="run",
                            arguments_schema={"type": "object", "required": ["value"],
                                              "properties": {"value": {"type": "string"}},
                                              "additionalProperties": False},
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))
    claims = TokenClaims(agent_id="agent-1", requester_id="requester-1", intent_scope="approved",
                         exp=int(datetime.now(UTC).timestamp()) + 60, iss="madva", aud="vie-gateway", jti="jti-1")
    with pytest.raises(AuthorizationError, match="tool_arguments_schema_violation"):
        JITAuthorizer().authorize(claims, intent, "echo", "run", {"value": "ok", "extra": True})

def test_docker_runner_requires_immutable_image_and_hardening() -> None:
    with pytest.raises(ValueError, match="immutable_digest"):
        DockerRunner(DockerConfig(image="madva/tool:latest"))
    command = DockerRunner(DockerConfig(image="madva/tool@sha256:" + "a" * 64)).command()
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command

def test_docker_runner_mounts_only_opaque_read_only_lease() -> None:
    runner = DockerRunner(DockerConfig(image="madva/tool@sha256:" + "a" * 64))
    lease = CredentialLease(reference="vault://payments/api", host_path="C:/secure/lease",
                            container_path="/run/secrets/api", expires_at=datetime.now(UTC) + timedelta(minutes=1))
    command = runner.command([lease])
    joined = " ".join(command)
    assert "type=bind" in joined
    assert "readonly" in joined
    assert "vault://payments/api" not in joined

def test_trace_adapter_has_safe_fallback_without_active_span() -> None:
    fallback = "local-correlation"
    assert AuditTracer().current_trace_id(fallback) == fallback

def test_verifier_rejects_output_outside_intent_contract() -> None:
    contract_id = uuid4()
    intent = IntentContract(contract_id=contract_id, purpose="approved", tool="echo", operation="run",
                            output_schema={"type": "object", "required": ["status"],
                                           "properties": {"status": {"type": "string"}},
                                           "additionalProperties": False},
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))
    permit = Permit(permit_id=uuid4(), agent_id="agent-1", requester_id="requester-1",
                    intent_scope="approved", tool="echo", operation="run", contract_id=contract_id,
                    expires_at=datetime.now(UTC) + timedelta(minutes=1))
    result = ExecutionResult(status="completed", output={"unexpected": True}, session_id=uuid4())
    receipt = Verifier().verify(uuid4(), intent, permit, result)
    assert receipt.verification == "fail"
    assert "output_schema_violation" in receipt.findings

def test_dlp_scanner_detects_token_like_output() -> None:
    findings = DLPScanner().scan({"result": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value-123456"})
    assert [finding.category for finding in findings] == ["jwt_like_token"]

def test_verifier_does_not_assume_cleanup_succeeded() -> None:
    contract_id = uuid4()
    intent = IntentContract(contract_id=contract_id, purpose="approved", tool="echo", operation="run",
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))
    permit = Permit(permit_id=uuid4(), agent_id="agent-1", requester_id="requester-1",
                    intent_scope="approved", tool="echo", operation="run", contract_id=contract_id,
                    expires_at=datetime.now(UTC) + timedelta(minutes=1))
    result = ExecutionResult(status="completed", output={"ok": True}, session_id=uuid4(), cleanup_status="unknown")
    receipt = Verifier().verify(uuid4(), intent, permit, result)
    assert receipt.cleanup_status == "unknown"
    assert "cleanup_not_verified" in receipt.findings


@pytest.mark.asyncio
async def test_vault_provider_writes_and_releases_opaque_lease(tmp_path) -> None:
    import httpx

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/secret/data/tool"
        assert request.headers["X-Vault-Token"] == "test-vault-token"
        return httpx.Response(200, json={"data": {"data": {"api_key": "secret-value"}}})

    provider = VaultCredentialProvider("http://vault", "test-vault-token",
                                       transport=httpx.MockTransport(handler), lease_root=str(tmp_path))
    lease = await provider.acquire("vault://secret/tool#api_key", uuid4(),
                                   datetime.now(UTC) + timedelta(minutes=1))
    path = tmp_path / Path(lease.host_path).relative_to(tmp_path)
    assert path.read_text(encoding="utf-8") == "secret-value"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    assert "secret-value" not in lease.model_dump_json()
    await provider.release(lease)
    assert not path.exists()


@pytest.mark.asyncio
async def test_vault_provider_rejects_invalid_reference(tmp_path) -> None:
    provider = VaultCredentialProvider("http://vault", "test-vault-token", lease_root=str(tmp_path))
    with pytest.raises(PermissionError, match="invalid_vault_reference"):
        await provider.acquire("https://example.invalid/secret", uuid4(),
                               datetime.now(UTC) + timedelta(minutes=1))

def test_intent_signer_requires_and_verifies_signature(monkeypatch) -> None:
    secret = "intent-secret"
    monkeypatch.setenv("MADVA_INTENT_SECRET", secret)
    unsigned = IntentContract(contract_id=uuid4(), purpose="approved", tool="echo", operation="run",
                              expires_at=datetime.now(UTC) + timedelta(minutes=1))
    with pytest.raises(AuthorizationError, match="missing_intent_signature"):
        IntentSigner(None).verify(unsigned)
    canonical = unsigned.model_dump(mode="json", exclude={"signature"})
    import hashlib, hmac, json
    signature = hmac.new(secret.encode(), json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    signed = unsigned.model_copy(update={"signature": signature})
    IntentSigner(None).verify(signed)

@pytest.mark.asyncio
async def test_oidc_validator_verifies_rsa_jwks_token() -> None:
    import jwt
    import httpx
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from jwt.algorithms import RSAAlgorithm

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk["kid"] = "test-key"
    token = jwt.encode({"agent_id": "agent-1", "requester_id": "requester-1", "intent_scope": "approved",
                        "exp": int(datetime.now(UTC).timestamp()) + 60, "iss": "https://issuer.example",
                        "aud": "vie-gateway", "jti": "jti-oidc"}, private_key, algorithm="RS256", headers={"kid": "test-key"})

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": [public_jwk]})

    validator = OIDCTokenValidator("https://issuer.example/.well-known/jwks.json", "https://issuer.example",
                                   "vie-gateway", transport=httpx.MockTransport(handler))
    claims = await validator.validate(token)
    assert claims.agent_id == "agent-1"


@pytest.mark.asyncio
async def test_oidc_validator_accepts_standard_audience_array() -> None:
    import jwt
    import httpx
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk["kid"] = "array-audience-key"
    token = jwt.encode(
        {"agent_id": "agent-1", "requester_id": "requester-1", "intent_scope": "approved",
         "exp": int(datetime.now(UTC).timestamp()) + 60, "iss": "https://issuer.example",
         "aud": ["vie-gateway", "account"], "jti": "jti-array-audience", "sub": "provider-subject",
         "scope": "openid profile", "iat": int(datetime.now(UTC).timestamp())},
        private_key, algorithm="RS256", headers={"kid": "array-audience-key"})

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"keys": [public_jwk]})

    validator = OIDCTokenValidator("https://issuer.example/.well-known/jwks.json", "https://issuer.example",
                                   "vie-gateway", transport=httpx.MockTransport(handler))
    claims = await validator.validate(token)
    assert claims.aud == ["vie-gateway", "account"]
