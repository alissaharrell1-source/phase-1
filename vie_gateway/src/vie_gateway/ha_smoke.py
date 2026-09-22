from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx


@dataclass(frozen=True)
class SmokeResult:
    iterations: int
    concurrency: int
    path: str
    successful: int
    failed: int
    status_counts: dict[str, int]
    requests_per_second: float
    latency_ms: dict[str, float]

    def as_dict(self) -> dict[str, object]:
        return {
            "iterations": self.iterations,
            "concurrency": self.concurrency,
            "path": self.path,
            "successful": self.successful,
            "failed": self.failed,
            "status_counts": self.status_counts,
            "requests_per_second": self.requests_per_second,
            "latency_ms": self.latency_ms,
        }

    def as_evidence(self, *, environment: str, commit: str,
                    executed_at: str | None = None) -> dict[str, object]:
        """Return URL-free, redacted evidence suitable for release review."""
        valid = self.failed == 0
        return {
            "schema_version": 1,
            "environment": environment,
            "commit": commit,
            "executed_at": executed_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "validator": "madva-ha-smoke",
            "result": {
                "valid": valid,
                "errors": [] if valid else ["endpoint_smoke_failed"],
                "checks": ["endpoint_smoke", f"path:{self.path}"],
                "smoke": self.as_dict(),
            },
        }


def write_evidence(path: Path, result: SmokeResult, *, environment: str,
                   commit: str) -> None:
    path.write_text(json.dumps(result.as_evidence(environment=environment, commit=commit),
                               sort_keys=True) + "\n", encoding="utf-8")


def _validate_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("gateway_url_must_be_http")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("gateway_url_credentials_query_or_fragment_forbidden")


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))
    return round(ordered[index], 3)


async def run_smoke(url: str, *, path: str = "/healthz", iterations: int = 100,
                    concurrency: int = 10, timeout_seconds: float = 5.0,
                    transport: httpx.AsyncBaseTransport | None = None) -> SmokeResult:
    if path not in {"/healthz", "/readyz"}:
        raise ValueError("unsupported_smoke_path")
    if iterations < 1 or iterations > 10_000 or concurrency < 1 or concurrency > 100:
        raise ValueError("smoke_bounds_invalid")
    _validate_url(url)
    latencies: list[float] = []
    statuses: Counter[str] = Counter()
    started = time.perf_counter()
    async with httpx.AsyncClient(timeout=timeout_seconds, transport=transport) as client:
        async def call() -> None:
            request_started = time.perf_counter()
            try:
                response = await client.get(f"{url.rstrip('/')}{path}")
                statuses[str(response.status_code)] += 1
                if response.status_code == 200:
                    latencies.append((time.perf_counter() - request_started) * 1000)
            except httpx.HTTPError:
                statuses["transport_error"] += 1

        for offset in range(0, iterations, concurrency):
            await asyncio.gather(*(call() for _ in range(min(concurrency, iterations - offset))))
    elapsed = time.perf_counter() - started
    successful = statuses.get("200", 0)
    return SmokeResult(
        iterations=iterations,
        concurrency=concurrency,
        path=path,
        successful=successful,
        failed=iterations - successful,
        status_counts=dict(sorted(statuses.items())),
        requests_per_second=round(iterations / elapsed, 2) if elapsed else float(iterations),
        latency_ms={
            "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0,
            "p50": _percentile(latencies, 0.50) if latencies else 0.0,
            "p95": _percentile(latencies, 0.95) if latencies else 0.0,
            "p99": _percentile(latencies, 0.99) if latencies else 0.0,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a bounded MADVA HA health/readiness smoke test")
    parser.add_argument("--url", default=os.environ.get("MADVA_TEST_GATEWAY_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--path", choices=["/healthz", "/readyz"], default="/healthz")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--evidence-output", type=Path,
                        help="write URL-free JSON evidence to this path")
    parser.add_argument("--environment", default=os.environ.get("MADVA_ENVIRONMENT"),
                        help="deployment label for evidence output")
    parser.add_argument("--commit", default=os.environ.get("MADVA_COMMIT"),
                        help="40-character commit for evidence output")
    args = parser.parse_args()
    try:
        result = asyncio.run(run_smoke(args.url, path=args.path, iterations=args.iterations,
                                       concurrency=args.concurrency, timeout_seconds=args.timeout))
    except (ValueError, httpx.HTTPError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 2
    if args.evidence_output:
        if not args.environment or not args.commit or len(args.commit) != 40:
            print(json.dumps({"valid": False, "error": "evidence_metadata_required"}, sort_keys=True))
            return 2
        write_evidence(args.evidence_output, result, environment=args.environment, commit=args.commit)
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
