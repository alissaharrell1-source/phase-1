from __future__ import annotations

import asyncio

import httpx
import pytest

from vie_gateway.ha_smoke import run_smoke


@pytest.mark.asyncio
async def test_health_smoke_records_success_and_latency() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/healthz"
        return httpx.Response(200, json={"status": "ok"})

    result = await run_smoke("http://gateway", iterations=8, concurrency=3,
                             transport=httpx.MockTransport(handler))
    assert result.successful == 8
    assert result.failed == 0
    assert result.status_counts == {"200": 8}
    assert result.latency_ms["p95"] >= 0


@pytest.mark.asyncio
async def test_readiness_smoke_fails_on_non_ready_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"status": "not_ready"})

    result = await run_smoke("http://gateway", path="/readyz", iterations=3,
                             concurrency=2, transport=httpx.MockTransport(handler))
    assert result.successful == 0
    assert result.failed == 3
    assert result.status_counts == {"503": 3}


def test_smoke_rejects_query_and_unsafe_bounds() -> None:
    with pytest.raises(ValueError, match="gateway_url_credentials_query_or_fragment_forbidden"):
        asyncio.run(run_smoke("http://gateway?token=secret"))
