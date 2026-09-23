from __future__ import annotations

from pathlib import Path


RECORD = Path(__file__).parents[2] / "docs" / "STAGING_CONFIGURATION_RECORD.md"


def test_staging_configuration_record_has_required_handoff_fields() -> None:
    text = RECORD.read_text(encoding="utf-8")

    for required in (
        "MADVA_OIDC_ISSUER",
        "MADVA_OIDC_JWKS_URL",
        "VAULT_ADDR",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "MADVA_AUDIT_LOG_PATH",
        "MADVA_POLICY_REGISTRY_PATH",
        "STAGING_VALIDATION_RUNBOOK.md",
        "deployment-evidence.json",
    ):
        assert required in text


def test_staging_configuration_record_stays_redacted() -> None:
    text = RECORD.read_text(encoding="utf-8")

    # The record is a checked-in template, not a place for live endpoints or credentials.
    assert "http://" not in text
    assert "https://" not in text
    assert "eyJ" not in text
    assert "<staging-environment-id>" in text
    assert "<approved-kubernetes-context>" in text
    assert "@sha256:<64-hex-digest>" in text
