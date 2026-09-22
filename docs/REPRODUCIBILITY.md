# Reproducible build and test procedure

The gateway runtime and development dependencies are recorded in `vie_gateway/requirements.lock` and `vie_gateway/requirements-dev.lock`. CI installs those exact versions, installs the local package without resolving new dependencies, and runs `pip check` before tests. The gateway Dockerfile pins the Python base image by digest and installs the runtime lock.

From a clean Python 3.12 environment:

```powershell
Set-Location vie_gateway
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
python -m pip check
python -m pytest -q
python -m mypy src
python benchmarks/benchmark_gateway.py --iterations 100 --concurrency 10
```

Record the commit SHA, Python version, operating system, Docker version, lock-file hash, image digest, test summary, mypy result, and benchmark JSON with each release or assessment. Docker-backed tests additionally require the immutable credential-tool image digest and a running gateway URL as described in the root README.

Lock files are refreshed deliberately during dependency review. A refresh must run the full test, security scan, container build/scan, Docker integration, and benchmark workflows before the new lock is accepted.
