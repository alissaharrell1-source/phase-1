# MADVA VIE Gateway — Phase 1

Initial modular scaffold for the Verified Intent Execution Gateway.

- `contracts.py` — strict typed MCP, Intent Contract, token, permit, execution, and audit models.
- `security.py` — fail-closed HS256 local boundary, configurable async OIDC/JWKS validation, signed Intent Contracts, JSON Schema argument enforcement, and JIT downscoped authorization.
- `runtime.py` — asynchronous ephemeral-runner boundary; Docker/Wasm adapters belong behind this interface.
- `runtime.py` — includes a digest-pinned, network-disabled Docker adapter with bounded resources.
- `verification.py` — post-execution contract, output-schema, and DLP comparison with audit receipt generation.
- `dlp.py` — lightweight token-leakage scanner for the execution boundary; full DSPM remains deployment-specific.
- `telemetry.py` — OpenTelemetry SDK/span adapter with optional OTLP HTTP export.
- `credentials.py` — deny-by-default credential lease interface for vault-backed, read-only runtime mounts.
- `app.py` — FastAPI MCP JSON-RPC proxy.
- MCP failures are returned as structured JSON-RPC errors with stable codes; transport-level HTTP success does not imply tool authorization or execution success.
- `/healthz` reports service health; `/readyz` reports whether configured runtime dependencies are available.

The local runner is only a deterministic test adapter. Set `MADVA_OIDC_JWKS_URL`, `MADVA_OIDC_ISSUER`, and `MADVA_OIDC_AUDIENCE` to enable OIDC/JWKS validation; otherwise the local HS256 validator is used. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces over OTLP HTTP. The Docker adapter is an execution boundary, not a complete deployment policy: production still requires image admission, credential isolation, vault integration, and teardown verification.

Set `MADVA_RUNTIME_IMAGE` to an immutable image reference such as `registry.example/tool@sha256:<digest>` to route the Infrastructure graph node through Docker. If it is unset, the in-process runner is used for local tests only.

Set `MADVA_INTENT_SECRET` to require HMAC-signed Intent Contracts. Without it, unsigned contracts remain available for local development and tests.

Set `MADVA_PRODUCTION=true` to make readiness require OIDC/JWKS configuration, signed Intent Contracts, and an immutable Docker runtime image.

`Dockerfile` builds the gateway as a non-root user. `compose.yaml` supplies a hardened local deployment profile; provide secrets and endpoint values through the environment or an external secret manager, never by committing them to the file.

Copy `.env.example` to the deployment environment and replace every placeholder with values from the selected identity provider, image registry, secret manager, and OTLP collector. Do not commit the resulting `.env` file.

`.github/workflows/ci.yml` runs tests, type checking, Compose validation, and the container build on every push and pull request.

For local infrastructure, `compose.dev.yaml` provides optional profiles for Keycloak (`identity`), Vault (`secrets`), and Jaeger plus the OpenTelemetry Collector (`observability`). These images use demo credentials and are for local development only; do not expose them publicly or reuse their credentials.

Credential references are denied unless a vault-backed `CredentialProvider` is injected. Secret values are never placed in graph state or Docker command arguments.

## Run

```powershell
python -m pip install -e ".[dev]"
python -m pytest
uvicorn vie_gateway.app:app --reload
```

To start the gateway with local observability:

```powershell
docker compose -f compose.dev.yaml --profile observability up --build
```

Then open `http://localhost:16686` for Jaeger and `http://localhost:8000/healthz` for the gateway. Add `--profile identity --profile secrets` when you want the local Keycloak and Vault services as well.

The local Keycloak profile imports `keycloak/madva-local-realm.json`. It is a demo-only realm with a service-account client and the three MADVA token-binding claims. Never expose it publicly or reuse its credentials. The OIDC endpoints are:

```text
Issuer: http://localhost:8080/realms/madva-local
JWKS:   http://localhost:8080/realms/madva-local/protocol/openid-connect/certs
Token:  http://localhost:8080/realms/madva-local/protocol/openid-connect/token
```
