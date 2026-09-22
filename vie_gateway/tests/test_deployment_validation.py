from __future__ import annotations

from vie_gateway.deployment_validation import validate_environment


def _valid() -> dict[str, str]:
    return {
        "MADVA_PRODUCTION": "true",
        "MADVA_OIDC_JWKS_URL": "https://identity.example/jwks.json",
        "MADVA_OIDC_ISSUER": "https://identity.example",
        "MADVA_OIDC_AUDIENCE": "vie-gateway",
        "MADVA_INTENT_SECRET": "x" * 48,
        "MADVA_RUNTIME_IMAGE": "registry.example/tool@sha256:" + "a" * 64,
        "MADVA_AUDIT_LOG_PATH": "/var/lib/madva/audit/receipts.jsonl",
        "MADVA_REQUIRE_TENANT_BINDING": "true",
        "MADVA_POLICY_REGISTRY_PATH": "/etc/madva/policies.json",
        "MADVA_REQUIRE_APPROVED_POLICY": "true",
        "MADVA_REQUIRE_VAULT": "true",
        "VAULT_ADDR": "https://vault.example",
        "VAULT_TOKEN_FILE": "/var/run/secrets/madva/vault-token",
        "MADVA_REQUIRE_OTEL": "true",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example:4318",
    }


def test_valid_production_environment() -> None:
    result = validate_environment(_valid())
    assert result.valid
    assert result.as_dict()["errors"] == []


def test_rejects_non_digest_runtime_image() -> None:
    environment = _valid()
    environment["MADVA_RUNTIME_IMAGE"] = "registry.example/tool:latest"
    result = validate_environment(environment)
    assert "runtime_image_must_be_digest_pinned" in result.errors


def test_rejects_missing_tenant_and_approved_policy_enforcement() -> None:
    environment = _valid()
    environment["MADVA_REQUIRE_TENANT_BINDING"] = "false"
    environment["MADVA_REQUIRE_APPROVED_POLICY"] = "false"
    result = validate_environment(environment)
    assert "tenant_binding_required" in result.errors
    assert "approved_policy_required" in result.errors


def test_upstream_backend_requires_allowlist() -> None:
    environment = _valid()
    environment.pop("MADVA_RUNTIME_IMAGE")
    environment["MADVA_MCP_UPSTREAM_URL"] = "https://mcp.example/mcp"
    result = validate_environment(environment)
    assert "missing_madva_mcp_upstream_allowed_hosts" in result.errors


def test_errors_do_not_echo_secret_or_paths() -> None:
    environment = _valid()
    environment["MADVA_INTENT_SECRET"] = "secret-value-that-must-not-appear"
    environment["MADVA_RUNTIME_IMAGE"] = "registry.example/tool:latest"
    result = validate_environment(environment)
    rendered = str(result.as_dict())
    assert "secret-value" not in rendered
    assert "/var/lib/madva" not in rendered
