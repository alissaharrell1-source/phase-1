from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


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
