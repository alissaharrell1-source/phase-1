from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import statistics
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx


SECRET = "benchmark-secret-with-at-least-32-bytes"


def _part(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token() -> str:
    header = _part({"alg": "HS256", "typ": "JWT"})
    payload = _part({
        "agent_id": "benchmark-agent", "requester_id": "benchmark-requester",
        "intent_scope": "benchmark-purpose", "exp": int(datetime.now(UTC).timestamp()) + 300,
        "iss": "madva", "aud": "vie-gateway", "jti": str(uuid4()),
    })
    signature = hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def _request() -> dict[str, object]:
    return {
        "jsonrpc": "2.0", "id": str(uuid4()), "method": "tools/call",
        "params": {
            "tool": "echo", "operation": "run", "arguments": {"value": "benchmark"},
            "intent_contract": {
                "contract_id": str(uuid4()), "purpose": "benchmark-purpose", "tool": "echo",
                "operation": "run", "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
            },
        },
    }


async def _run(iterations: int, concurrency: int) -> dict[str, object]:
    os.environ["MADVA_PRODUCTION"] = "false"
    os.environ["MADVA_TOKEN_SECRET"] = SECRET
    os.environ.pop("MADVA_OIDC_JWKS_URL", None)
    os.environ.pop("MADVA_REQUIRE_APPROVED_POLICY", None)
    from vie_gateway.app import create_app

    app = create_app()
    headers = {"Authorization": f"Bearer {_token()}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://benchmark") as client:
        for _ in range(min(5, iterations)):
            response = await client.post("/mcp", json=_request(), headers=headers)
            response.raise_for_status()
        latencies: list[float] = []
        started = time.perf_counter()

        async def call() -> None:
            request_started = time.perf_counter()
            response = await client.post("/mcp", json=_request(), headers=headers)
            response.raise_for_status()
            body = response.json()
            if "result" not in body or "error" in body:
                raise RuntimeError("benchmark_request_failed")
            latencies.append((time.perf_counter() - request_started) * 1000)

        for offset in range(0, iterations, concurrency):
            await asyncio.gather(*(call() for _ in range(min(concurrency, iterations - offset))))
        elapsed = time.perf_counter() - started

    ordered = sorted(latencies)
    percentile = lambda fraction: ordered[min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))]
    return {
        "iterations": iterations,
        "concurrency": concurrency,
        "requests_per_second": round(iterations / elapsed, 2),
        "latency_ms": {"mean": round(statistics.fmean(latencies), 3),
                       "p50": round(percentile(0.50), 3), "p95": round(percentile(0.95), 3),
                       "p99": round(percentile(0.99), 3)},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the local VIE gateway path without external services.")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args()
    if args.iterations < 1 or args.concurrency < 1:
        parser.error("iterations and concurrency must be positive")
    print(json.dumps(asyncio.run(_run(args.iterations, args.concurrency)), sort_keys=True))


if __name__ == "__main__":
    main()
