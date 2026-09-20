from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest


def _part(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(secret: str) -> str:
    header = _part({"alg": "HS256", "typ": "JWT"})
    payload = _part({
        "agent_id": "agent-ci", "requester_id": "requester-ci", "intent_scope": "echo-purpose",
        "exp": int(time.time()) + 60, "iss": "madva", "aud": "vie-gateway", "jti": str(uuid4()),
    })
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


@pytest.mark.integration
def test_running_gateway_forwards_to_mcp_container() -> None:
    gateway_url = os.environ.get("MADVA_TEST_GATEWAY_URL")
    if not gateway_url:
        pytest.skip("MADVA_TEST_GATEWAY_URL is not configured")
    secret = os.environ.get("MADVA_TEST_TOKEN_SECRET", "local-development-only-change-me")
    contract = {
        "contract_id": str(uuid4()), "purpose": "echo-purpose", "tool": "echo", "operation": "run",
        "arguments": {"value": "docker-ci"},
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }
    request = {"jsonrpc": "2.0", "id": "docker-upstream-ci", "method": "tools/call",
               "params": {"tool": "echo", "operation": "run", "arguments": {"value": "docker-ci"},
                           "intent_contract": contract}}
    response = httpx.post(f"{gateway_url.rstrip('/')}/mcp", json=request,
                          headers={"Authorization": f"Bearer {_token(secret)}"}, timeout=15)
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["output"] == {"echo": {"value": "docker-ci"}, "tool": "echo"}
    assert body["result"]["audit_receipt"]["verification"] == "pass"
