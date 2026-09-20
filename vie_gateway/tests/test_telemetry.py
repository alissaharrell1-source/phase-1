from vie_gateway.telemetry import _otlp_headers, _otlp_trace_endpoint


def test_otlp_endpoint_is_normalized_for_siem_export() -> None:
    assert _otlp_trace_endpoint("https://siem.example/otlp") == "https://siem.example/otlp/v1/traces"
    assert _otlp_trace_endpoint("https://siem.example/otlp/v1/traces") == "https://siem.example/otlp/v1/traces"


def test_otlp_headers_parse_without_logging_payloads() -> None:
    assert _otlp_headers("Authorization=Bearer redacted, x-tenant=tenant-a, malformed") == {
        "Authorization": "Bearer redacted", "x-tenant": "tenant-a"
    }
