from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime, timedelta
from statistics import mean
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx


def _part(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(secret: str) -> str:
    header = _part({"alg": "HS256", "typ": "JWT"})
    payload = _part(
        {
            "agent_id": "agent-http-benchmark",
            "requester_id": "requester-http-benchmark",
            "intent_scope": "echo-purpose",
            "exp": int(time.time()) + 300,
            "iss": "madva",
            "aud": "vie-gateway",
            "jti": str(uuid4()),
        }
    )
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def _request(token: str, request_id: str) -> dict[str, Any]:
    contract = {
        "contract_id": str(uuid4()),
        "purpose": "echo-purpose",
        "tool": "echo",
        "operation": "run",
        "arguments": {"value": "http-load-fixture"},
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "tool": "echo",
            "operation": "run",
            "arguments": {"value": "http-load-fixture"},
            "intent_contract": contract,
        },
    }


async def _run(url: str, secret: str, iterations: int, concurrency: int) -> dict[str, object]:
    endpoint = urlsplit(url).path or "/"
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    status_counts: dict[str, int] = {}
    failures = 0

    async with httpx.AsyncClient(timeout=15) as client:
        async def call(index: int) -> None:
            nonlocal failures
            async with semaphore:
                started = time.perf_counter()
                try:
                    response = await client.post(
                        url,
                        json=_request(_token(secret), f"http-load-{index}"),
                        headers={"Authorization": f"Bearer {_token(secret)}"},
                    )
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    latencies.append(elapsed_ms)
                    status = str(response.status_code)
                    status_counts[status] = status_counts.get(status, 0) + 1
                    body = response.json()
                    verified = body.get("result", {}).get("audit_receipt", {}).get("verification") == "pass"
                    if response.status_code != 200 or not verified:
                        failures += 1
                except (httpx.HTTPError, ValueError, TypeError, AttributeError):
                    failures += 1

        started = time.perf_counter()
        await asyncio.gather(*(call(index) for index in range(iterations)))
        duration = time.perf_counter() - started

    ordered = sorted(latencies)

    def percentile(percent: float) -> float:
        if not ordered:
            return 0.0
        index = min(len(ordered) - 1, int(len(ordered) * percent))
        return round(ordered[index], 3)

    return {
        "endpoint_path": endpoint,
        "iterations": iterations,
        "concurrency": concurrency,
        "duration_seconds": round(duration, 3),
        "requests_per_second": round(iterations / duration, 2) if duration else 0.0,
        "successful": iterations - failures,
        "failed": failures,
        "status_counts": status_counts,
        "latency_ms": {
            "mean": round(mean(latencies), 3) if latencies else 0.0,
            "p50": percentile(0.50),
            "p95": percentile(0.95),
            "p99": percentile(0.99),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a redacted authenticated HTTP MCP gateway benchmark")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args()
    if args.iterations < 1 or args.concurrency < 1:
        parser.error("iterations and concurrency must be positive")
    secret = os.environ.get("MADVA_TEST_TOKEN_SECRET", "local-development-only-change-me")
    result = asyncio.run(_run(args.url, secret, args.iterations, args.concurrency))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
