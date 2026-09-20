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


def test_production_readiness_accepts_mcp_upstream(monkeypatch) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    monkeypatch.setenv("MADVA_OIDC_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("MADVA_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("MADVA_INTENT_SECRET", "intent-secret")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", "tools.example")
    monkeypatch.delenv("MADVA_RUNTIME_IMAGE", raising=False)
    with TestClient(create_app()) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_production_readiness_rejects_unallowlisted_mcp_upstream(monkeypatch) -> None:
    monkeypatch.setenv("MADVA_PRODUCTION", "true")
    monkeypatch.setenv("MADVA_OIDC_JWKS_URL", "https://issuer.example/jwks")
    monkeypatch.setenv("MADVA_OIDC_ISSUER", "https://issuer.example")
    monkeypatch.setenv("MADVA_INTENT_SECRET", "intent-secret")
    monkeypatch.setenv("MADVA_MCP_UPSTREAM_URL", "https://tools.example/mcp")
    monkeypatch.delenv("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", raising=False)
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
