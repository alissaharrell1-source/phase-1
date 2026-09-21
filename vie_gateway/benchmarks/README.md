# MADVA security and performance checks

The independent security regressions are in `tests/security/test_regressions.py` and run in CI with the rest of the unit suite. They cover algorithm confusion, expiry, audience, and conflicting tenant claims.

Run the local benchmark after installing the development dependencies:

```powershell
python benchmarks/benchmark_gateway.py --iterations 1000 --concurrency 25
```

The benchmark uses the in-process deterministic runner and reports requests per second plus mean/p50/p95/p99 latency as JSON. It does not print tokens, arguments, or tool output. Treat results as a repeatable local baseline, not a production capacity claim; run a separate load test against the deployed gateway and MCP backend before setting SLOs.
