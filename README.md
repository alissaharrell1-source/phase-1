# MADVA Phase 1 — Verified Intent Execution Gateway

MADVA Phase 1 is an open security-engineering prototype for a Verified Intent Execution (VIE) gateway. It intercepts MCP `tools/call` JSON-RPC requests, validates identity and intent, creates a least-privilege permit, executes through an isolated backend, verifies the result, and emits a tamper-evident audit receipt.

## Current status

The functional Phase 1 MVP is complete. Phase 2 hardening in this repository includes:

- tenant-bound authorization and versioned policy approval;
- append-only hash-chained audit storage with multi-process locking;
- a three-replica Kubernetes deployment profile;
- OIDC, Vault, and OTLP/SIEM integration hardening;
- independent security regressions and a reproducible benchmark.

This is not a claim of independent certification or production readiness. Review the [security policy](SECURITY.md) and [operations guide](docs/OPERATIONS.md) before connecting real identities, secrets, or tools.

## Quick start

```powershell
Set-Location vie_gateway
python -m pip install -e ".[dev]"
python -m pytest -q
python -m mypy src
python benchmarks/benchmark_gateway.py --iterations 100 --concurrency 10
```

For the local MCP integration stack:

```powershell
docker compose -f compose.dev.yaml up -d --build mcp-upstream vie-gateway
$env:MADVA_TEST_GATEWAY_URL = "http://127.0.0.1:8000"
python -m pytest -q tests/test_docker_upstream.py
```

The local profile uses demo credentials only. Never expose it publicly or reuse its credentials.

## Architecture

The gateway is a LangGraph state machine with four explicit stages:

`Architect → Security → Infrastructure → Verification`

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for trust boundaries and extension points. The detailed implementation and configuration reference is in [vie_gateway/README.md](vie_gateway/README.md).

For assessment preparation, see the [threat model](docs/THREAT_MODEL.md), [security assessment plan](docs/SECURITY_ASSESSMENT_PLAN.md), and [control/evidence matrix](docs/CONTROL_EVIDENCE_MATRIX.md).

## Project map

- `vie_gateway/src/vie_gateway/` — typed gateway implementation.
- `vie_gateway/tests/` — unit, integration, and security regression tests.
- `vie_gateway/benchmarks/` — repeatable local performance baseline.
- `vie_gateway/deploy/kubernetes/` — high-availability deployment profile.
- `Meta-Architect/`, `Security & IAM Engine/`, `Runtime Isolation/`, `Verification & Audit/` — agent role and design materials.
- `.github/workflows/ci.yml` — test, type-check, container, integration, security, and benchmark checks.

## Community

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [docs/OPEN_SOURCE_STRATEGY.md](docs/OPEN_SOURCE_STRATEGY.md). A project license has not yet been selected; do not represent or redistribute this repository as licensed open-source software until the project owner adds an explicit license.
