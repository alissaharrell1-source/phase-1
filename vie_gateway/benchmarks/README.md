# MADVA security and performance checks

The independent security regressions are in `tests/security/test_regressions.py` and run in CI with the rest of the unit suite. They cover algorithm confusion, expiry, audience, and conflicting tenant claims.

Run the local benchmark after installing the development dependencies:

```powershell
python benchmarks/benchmark_gateway.py --iterations 1000 --concurrency 25
```

The benchmark uses the in-process deterministic runner and reports requests per second plus mean/p50/p95/p99 latency as JSON. It does not print tokens, arguments, or tool output. Treat results as a repeatable local baseline, not a production capacity claim; run a separate load test against the deployed gateway and MCP backend before setting SLOs.

For the deployed local gateway and MCP fixture, run the authenticated HTTP benchmark:

```powershell
$env:PYTHONPATH = "src"
python benchmarks/benchmark_http_gateway.py --url http://127.0.0.1:8000/mcp --iterations 100 --concurrency 10
```

It uses the local-only HMAC test boundary by default, checks the verification receipt for each response, and emits only bounded status and latency metrics. Set `MADVA_TEST_TOKEN_SECRET` only when the gateway uses a different non-production test secret. Do not use this fixture or secret in staging or production.
