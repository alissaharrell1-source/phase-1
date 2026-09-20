from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from vie_gateway.app import create_app


def _part(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(secret: str, scope: str = "echo-purpose") -> str:
    header = _part({"alg": "HS256", "typ": "JWT"})
    payload = _part({
        "agent_id": "agent-1", "requester_id": "requester-1", "intent_scope": scope,
        "exp": int(datetime.now(UTC).timestamp()) + 60, "iss": "madva", "aud": "vie-gateway", "jti": "jti-1",
    })
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def _request(scope: str = "echo-purpose") -> dict[str, object]:
    contract_id = str(uuid4())
    return {
        "jsonrpc": "2.0", "id": "call-1", "method": "tools/call",
        "params": {
            "tool": "echo", "operation": "run", "arguments": {"value": "hello"},
            "intent_contract": {
                "contract_id": contract_id, "purpose": "echo-purpose", "tool": "echo", "operation": "run",
                "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
            },
        },
    }


def test_mcp_proxy_executes_and_returns_audit_receipt(monkeypatch) -> None:
    secret = "test-secret"
    monkeypatch.setenv("MADVA_TOKEN_SECRET", secret)
    with TestClient(create_app()) as client:
        response = client.post("/mcp", json=_request(), headers={"Authorization": f"Bearer {_token(secret)}"})
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["output"] == {"echo": {"value": "hello"}}
    assert body["result"]["audit_receipt"]["verification"] == "pass"


def test_mcp_proxy_denies_scope_mismatch(monkeypatch) -> None:
    secret = "test-secret"
    monkeypatch.setenv("MADVA_TOKEN_SECRET", secret)
    with TestClient(create_app()) as client:
        bad_token = _token(secret, "wrong-scope")
        response = client.post("/mcp", json=_request(), headers={"Authorization": f"Bearer {bad_token}"})
    assert response.status_code == 200
    assert response.json()["error"] == {"code": -32002, "message": "intent_scope_mismatch"}


def test_mcp_proxy_requires_bearer_token(monkeypatch) -> None:
    monkeypatch.setenv("MADVA_TOKEN_SECRET", "test-secret")
    with TestClient(create_app()) as client:
        response = client.post("/mcp", json=_request())
    assert response.status_code == 200
    assert response.json()["error"] == {"code": -32001, "message": "missing_bearer_token"}


def test_mcp_proxy_denies_credentials_without_vault_provider(monkeypatch) -> None:
    secret = "test-secret"
    monkeypatch.setenv("MADVA_TOKEN_SECRET", secret)
    request = _request()
    request["params"]["intent_contract"]["credential_refs"] = ["vault://payments/api"]
    with TestClient(create_app()) as client:
        response = client.post("/mcp", json=request,
                               headers={"Authorization": f"Bearer {_token(secret)}"})
    assert response.status_code == 200
    assert response.json()["error"]["message"] == "credential_provider_not_configured"
