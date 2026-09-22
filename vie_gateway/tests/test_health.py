from fastapi.testclient import TestClient

from vie_gateway.app import create_app


def test_health_endpoint_reports_service() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readiness_reports_local_mode_ready(monkeypatch) -> None:
    monkeypatch.delenv("MADVA_RUNTIME_IMAGE", raising=False)
    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_production_readiness_requires_security_and_isolation(monkeypatch) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    for name in ("MADVA_OIDC_JWKS_URL", "MADVA_OIDC_ISSUER", "MADVA_INTENT_SECRET", "MADVA_RUNTIME_IMAGE"):
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert "missing_madva_oidc_jwks_url" in response.json()["issues"]


def test_production_readiness_accepts_mcp_upstream(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    monkeypatch.setenv("MADVA_OIDC_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("MADVA_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("MADVA_INTENT_SECRET", "intent-secret")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", "tools.example")
    monkeypatch.setenv("MADVA_AUDIT_LOG_PATH", str(tmp_path / "receipts.jsonl"))
    policy_path = tmp_path / "policies.json"
    policy_path.write_text('{"policies": []}', encoding="utf-8")
    monkeypatch.setenv("MADVA_POLICY_REGISTRY_PATH", str(policy_path))
    monkeypatch.delenv("MADVA_RUNTIME_IMAGE", raising=False)
    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_production_readiness_rejects_unallowlisted_mcp_upstream(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    monkeypatch.setenv("MADVA_OIDC_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("MADVA_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("MADVA_INTENT_SECRET", "intent-secret")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.delenv("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("MADVA_AUDIT_LOG_PATH", str(tmp_path / "receipts.jsonl"))
    monkeypatch.delenv("MADVA_RUNTIME_IMAGE", raising=False)
    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert "missing_madva_mcp_upstream_allowed_hosts" in response.json()["issues"]


def test_health_reports_mcp_upstream_runtime(monkeypatch) -> None:
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.delenv("MADVA_RUNTIME_IMAGE", raising=False)
    with TestClient(create_app()) as client:
        response = client.get("/healthz")
    assert response.json()["runtime"] == "mcp-upstream"


def test_production_readiness_requires_vault_agent_token_file(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    monkeypatch.setenv("MADVA_OIDC_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("MADVA_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("MADVA_INTENT_SECRET", "intent-secret")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", "tools.example")
    monkeypatch.setenv("MADVA_AUDIT_LOG_PATH", str(tmp_path / "receipts.jsonl"))
    policy_path = tmp_path / "policies.json"
    policy_path.write_text('{"policies": []}', encoding="utf-8")
    monkeypatch.setenv("MADVA_POLICY_REGISTRY_PATH", str(policy_path))
    monkeypatch.setenv("MADVA_REQUIRE_VAULT", "true")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example")
    token_path = tmp_path / "vault-agent" / "token"
    monkeypatch.setenv("VAULT_TOKEN_FILE", str(token_path))

    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert "vault_token_file_unavailable" in response.json()["issues"]

    token_path.parent.mkdir()
    token_path.write_text("short-lived-token\n", encoding="utf-8")
    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 200


def test_production_readiness_requires_otlp_endpoint_when_enabled(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    monkeypatch.setenv("MADVA_OIDC_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("MADVA_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("MADVA_INTENT_SECRET", "intent-secret")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", "tools.example")
    monkeypatch.setenv("MADVA_AUDIT_LOG_PATH", str(tmp_path / "receipts.jsonl"))
    policy_path = tmp_path / "policies.json"
    policy_path.write_text('{"policies": []}', encoding="utf-8")
    monkeypatch.setenv("MADVA_POLICY_REGISTRY_PATH", str(policy_path))
    monkeypatch.setenv("MADVA_REQUIRE_OTEL", "true")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("MADVA_SIEM_OTLP_ENDPOINT", raising=False)

    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert "missing_otlp_endpoint" in response.json()["issues"]
