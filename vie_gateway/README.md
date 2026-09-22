# MADVA VIE Gateway — Phase 1

Initial modular scaffold for the Verified Intent Execution Gateway.

- `contracts.py` — strict typed MCP, Intent Contract, token, permit, execution, and audit models.
- `security.py` — fail-closed HS256 local boundary, configurable async OIDC/JWKS validation, signed Intent Contracts, JSON Schema argument enforcement, and JIT downscoped authorization.
- `runtime.py` — asynchronous ephemeral-runner boundary; Docker/Wasm adapters belong behind this interface.
- `runtime.py` — includes a digest-pinned, network-disabled Docker adapter with bounded resources.
- `verification.py` — post-execution contract, output-schema, and DLP comparison with audit receipt generation.
- `dlp.py` — lightweight token-leakage scanner for the execution boundary; full DSPM remains deployment-specific.
- `telemetry.py` — OpenTelemetry SDK/span adapter with optional OTLP HTTP export.
- `audit_store.py` — fsync-backed append-only audit receipt chain with tamper detection.
- `credentials.py` — deny-by-default credential lease interface for vault-backed, read-only runtime mounts.
- `app.py` — FastAPI MCP JSON-RPC proxy.
- MCP failures are returned as structured JSON-RPC errors with stable codes; transport-level HTTP success does not imply tool authorization or execution success.
- `/healthz` reports service health; `/readyz` reports whether configured runtime dependencies are available.

The local runner is only a deterministic test adapter. Set `MADVA_OIDC_JWKS_URL`, `MADVA_OIDC_ISSUER`, and `MADVA_OIDC_AUDIENCE` to enable OIDC/JWKS validation; otherwise the local HS256 validator is used. OIDC `tid` claims are normalized to `tenant_id` and conflicting tenant claims are rejected. Set `OTEL_EXPORTER_OTLP_ENDPOINT` (or `MADVA_SIEM_OTLP_ENDPOINT`) to export sanitized audit spans to an OTLP collector or SIEM; use `OTEL_EXPORTER_OTLP_HEADERS` for collector authentication. The Docker adapter is an execution boundary, not a complete deployment policy: production still requires image admission, credential isolation, vault integration, and teardown verification.

Set `MADVA_RUNTIME_IMAGE` to an immutable image reference such as `registry.example/tool@sha256:<digest>` to route the Infrastructure graph node through Docker. If it is unset, the in-process runner is used for local tests only.

Set `MADVA_MCP_UPSTREAM_URL` to route approved calls to an MCP JSON-RPC server instead of the local or Docker runner. The gateway sends the standard `tools/call` shape (`params.name` and `params.arguments`), validates the JSON-RPC response, and never forwards the inbound MADVA bearer token. Use `MADVA_MCP_UPSTREAM_TOKEN` only for a separately scoped upstream credential.

Upstream calls default to the stateless MCP protocol version `2026-07-28`, sending protocol-version, method, tool-name, and gateway client identity metadata. Override this with `MADVA_MCP_UPSTREAM_PROTOCOL_VERSION` for a compatible upstream deployment.

For older handshake-based MCP servers, set `MADVA_MCP_UPSTREAM_LIFECYCLE=legacy`; the runner will perform `initialize`, preserve `Mcp-Session-Id`, send `notifications/initialized`, and then issue the approved tool call.

The development Compose profile includes a small demo MCP server under `examples/mcp-upstream` and routes the gateway to it automatically. It uses demo credentials only and must not be exposed publicly.

Set `MADVA_INTENT_SECRET` to require HMAC-signed Intent Contracts. Without it, unsigned contracts remain available for local development and tests.

Set `MADVA_PRODUCTION=true` to make readiness require OIDC/JWKS configuration, signed Intent Contracts, and either an immutable Docker runtime image or an MCP upstream with an explicit host allowlist.

Before a staging deployment, run `madva-deployment-validate` (or `python -m vie_gateway.deployment_validation_cli`) with the deployment environment loaded. Add `--live` to check OIDC discovery/JWKS, Vault health and optional credential access, OTLP connectivity, and audit-volume writability. It emits redacted JSON only and exits `0` when the contract is satisfied or `2` with stable configuration errors.

Set `MADVA_AUDIT_LOG_PATH` to persist audit receipts in an append-only SHA-256 hash chain. Production readiness requires this setting. Stored records contain receipt metadata only; tool arguments, tool output, credentials, and bearer tokens are not persisted.

Set `MADVA_AUDIT_HOST_PATH` to a writable, persistent host directory and mount it at `/var/lib/madva/audit`. The deployment owner is responsible for provisioning that directory with least-privilege permissions and backing it up.

Tenant isolation is enabled automatically in production. The validated token and Intent Contract must both carry the same `tenant_id`; the value is propagated into the JIT permit and audit receipt. Set `MADVA_REQUIRE_TENANT_BINDING=true` to enable the same enforcement in non-production environments.

Policy revisions are bound to an Intent Contract with `policy_id` and `policy_version`. Set `MADVA_POLICY_REGISTRY_PATH` to an administrator-owned JSON registry. Production requires the referenced revision to be registered with status `approved`; draft, pending, rejected, or revoked revisions are denied. The `PolicyRegistry` lifecycle (`submit`, `approve`, `reject`, and `revoke`) provides the approval workflow, and the selected revision is propagated into the permit and audit receipt. Set `MADVA_REQUIRE_APPROVED_POLICY=true` to enforce this in non-production environments.

`Dockerfile` builds the gateway as a non-root user. `compose.yaml` supplies a hardened local deployment profile; provide secrets and endpoint values through the environment or an external secret manager, never by committing them to the file.

`deploy/kubernetes` supplies a three-replica high-availability deployment with rolling updates, readiness/liveness probes, topology spreading, a PodDisruptionBudget, non-root execution, and a read-only root filesystem. Its RWX audit volume must support reliable advisory file locking and fsync; the audit writer coordinates concurrent replicas through a sidecar lock file. Follow `deploy/kubernetes/README.md` before applying it.

Copy `.env.example` to the deployment environment and replace every placeholder with values from the selected identity provider, image registry, secret manager, and OTLP collector. Do not commit the resulting `.env` file.

`.github/workflows/ci.yml` runs tests, type checking, Compose validation, and the container build on every push and pull request.

For local infrastructure, `compose.dev.yaml` provides optional profiles for Keycloak (`identity`), Vault (`secrets`), and Jaeger plus the OpenTelemetry Collector (`observability`). These images use demo credentials and are for local development only; do not expose them publicly or reuse their credentials.

Credential references are denied unless a vault-backed `CredentialProvider` is injected. `VAULT_TOKEN_FILE` is preferred over `VAULT_TOKEN` so Vault Agent or an external secret manager can rotate short-lived credentials without restarting the gateway. Production Vault access requires an HTTPS `VAULT_ADDR`; optional `VAULT_NAMESPACE` is sent as a request header. Secret values are never placed in graph state, spans, or Docker command arguments, and lease files are overwritten, fsynced, and removed on release.

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

The local Keycloak profile imports `keycloak/madva-local-realm.json`. It is a demo-only realm with a service-account client, the three MADVA token-binding claims, and a `tenant_id` claim for exercising production tenant binding. The live validation evidence is recorded in [`docs/LOCAL_IDP_VALIDATION.md`](../docs/LOCAL_IDP_VALIDATION.md). Never expose it publicly or reuse its credentials. The OIDC endpoints are:

```text
Issuer: http://localhost:8080/realms/madva-local
JWKS:   http://localhost:8080/realms/madva-local/protocol/openid-connect/certs
Token:  http://localhost:8080/realms/madva-local/protocol/openid-connect/token
```
