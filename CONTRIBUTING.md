# Contributing to MADVA

Thank you for helping improve MADVA. Security-sensitive changes should be small, reviewable, and backed by tests that demonstrate both the allowed and denied paths.

## Development setup

Use Python 3.11 or newer. From the repository root:

```powershell
Set-Location vie_gateway
python -m pip install -e ".[dev]"
python -m pytest -q
python -m mypy src
```

Optional checks:

```powershell
python -m pytest -q tests/security
python benchmarks/benchmark_gateway.py --iterations 100 --concurrency 10
docker compose -f compose.dev.yaml up -d --build mcp-upstream vie-gateway
```

## Change expectations

- Preserve strict Pydantic contracts and asynchronous boundaries.
- Add a regression test for every authorization, isolation, or verification behavior change.
- Keep tool arguments, outputs, credentials, and bearer tokens out of logs, spans, and audit receipts.
- Keep production defaults fail-closed. Local-development shortcuts must be explicitly gated by environment settings.
- Use immutable image digests for execution images.
- Update the relevant documentation when configuration, deployment, or threat assumptions change.
- Do not commit `.env` files, tokens, private keys, customer data, or generated audit logs.

## Pull requests

Open a focused pull request against `main`. Describe the trust boundary affected, the threat or failure mode addressed, tests run, and any deployment migration required. Reviewers should be able to reproduce the validation locally and understand what remains intentionally out of scope.

Do not include sensitive exploit details in a public pull request. Follow [SECURITY.md](SECURITY.md) for vulnerability reports.
