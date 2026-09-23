import asyncio

import pytest

from vie_gateway.telemetry import (
    _otlp_headers,
    _otlp_trace_endpoint,
    check_otlp_endpoint_reachable,
    validate_otlp_endpoint,
)


def test_otlp_endpoint_is_normalized_for_siem_export() -> None:
    assert _otlp_trace_endpoint("https://siem.example/otlp") == "https://siem.example/otlp/v1/traces"
    assert _otlp_trace_endpoint("https://siem.example/otlp/v1/traces") == "https://siem.example/otlp/v1/traces"


def test_otlp_headers_parse_without_logging_payloads() -> None:
    assert _otlp_headers("Authorization=Bearer redacted, x-tenant=tenant-a, malformed") == {
        "Authorization": "Bearer redacted", "x-tenant": "tenant-a"
    }


def test_otlp_endpoint_validation_requires_safe_url() -> None:
    validate_otlp_endpoint("https://collector.example/otlp", require_tls=True)
    with pytest.raises(ValueError, match="otlp_tls_required"):
        validate_otlp_endpoint("http://collector.example/otlp", require_tls=True)
    with pytest.raises(ValueError, match="credentials_or_query"):
        validate_otlp_endpoint("https://user:secret@collector.example/otlp?token=secret")


def test_otlp_reachability_fails_closed_for_unreachable_endpoint() -> None:
    with pytest.raises(ValueError, match="otlp_endpoint_unreachable"):
        asyncio.run(check_otlp_endpoint_reachable("http://127.0.0.1:1", timeout_seconds=0.2))
