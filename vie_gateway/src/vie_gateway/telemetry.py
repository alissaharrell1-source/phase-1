from __future__ import annotations

import asyncio
from contextlib import contextmanager
import os
import ssl
from typing import Iterator
from urllib.parse import urlparse

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span
except ImportError:  # pragma: no cover - exercised only in minimal installs
    trace = None  # type: ignore[assignment]
    Span = object  # type: ignore[misc, assignment]

_configured = False


def _otlp_headers(raw: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in (raw or "").split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        if key.strip() and value.strip():
            headers[key.strip()] = value.strip()
    return headers


def _otlp_trace_endpoint(endpoint: str) -> str:
    normalized = endpoint.rstrip("/")
    return normalized if normalized.endswith("/v1/traces") else f"{normalized}/v1/traces"


def validate_otlp_endpoint(endpoint: str, *, require_tls: bool = False) -> None:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("otlp_endpoint_invalid")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("otlp_endpoint_must_not_contain_credentials_or_query")
    if require_tls and parsed.scheme != "https":
        raise ValueError("otlp_tls_required")


async def check_otlp_endpoint_reachable(endpoint: str, *, timeout_seconds: float = 2.0) -> None:
    """Verify the configured OTLP host accepts a bounded connection.

    Readiness uses this check only when telemetry is explicitly required. It
    validates TLS certificates for HTTPS endpoints but does not send a span or
    record endpoint details in the readiness response.
    """
    validate_otlp_endpoint(endpoint)
    parsed = urlparse(endpoint)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("otlp_endpoint_invalid")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    tls = parsed.scheme == "https"
    ssl_context = ssl.create_default_context() if tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                hostname,
                port,
                ssl=ssl_context,
                server_hostname=hostname if tls else None,
            ),
            timeout=timeout_seconds,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ValueError) as exc:
        raise ValueError("otlp_endpoint_unreachable") from exc
    writer.close()
    await writer.wait_closed()
    del reader


def configure_tracing(service_name: str = "madva-vie-gateway") -> None:
    """Configure the SDK once; export spans only when an OTLP endpoint is set."""
    global _configured
    if _configured or trace is None:
        return
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    except ImportError:
        return
    service_name = os.environ.get("OTEL_SERVICE_NAME", service_name)
    provider = TracerProvider(resource=Resource.create({
        "service.name": service_name,
        "service.version": os.environ.get("MADVA_SERVICE_VERSION", "0.1.0"),
        "deployment.environment": os.environ.get("MADVA_ENVIRONMENT", "unknown"),
    }))
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get("MADVA_SIEM_OTLP_ENDPOINT")
    if endpoint:
        validate_otlp_endpoint(endpoint, require_tls=os.environ.get("MADVA_PRODUCTION", "false").lower() == "true")
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(
            endpoint=_otlp_trace_endpoint(endpoint),
            headers=_otlp_headers(os.environ.get("OTEL_EXPORTER_OTLP_HEADERS")),
        )))
    trace.set_tracer_provider(provider)
    _configured = True


class AuditTracer:
    """Small OTel adapter; exporters are configured by the host application."""

    def __init__(self, service_name: str = "madva-vie-gateway") -> None:
        self._tracer = trace.get_tracer(service_name) if trace is not None else None

    def current_trace_id(self, fallback: str) -> str:
        if trace is None:
            return fallback
        context = trace.get_current_span().get_span_context()
        return format(context.trace_id, "032x") if context.is_valid else fallback

    def current_span(self) -> Span | None:
        """Return the active span so callers can add bounded, sanitized attributes."""
        if trace is None:
            return None
        current = trace.get_current_span()
        return current if current.get_span_context().is_valid else None

    @contextmanager
    def span(self, name: str, **attributes: str) -> Iterator[Span | None]:
        if self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(name) as current:
            for key, value in attributes.items():
                current.set_attribute(key, value)
            yield current
