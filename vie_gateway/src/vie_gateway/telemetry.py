from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Iterator

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span
except ImportError:  # pragma: no cover - exercised only in minimal installs
    trace = None  # type: ignore[assignment]
    Span = object  # type: ignore[misc, assignment]

_configured = False


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
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")))
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
