# MADVA Staging Validation Runbook

Use this runbook after the target staging identity provider, Vault Agent, OTLP collector, and persistent audit volume are provisioned. Run it from the staging operator environment or a trusted self-hosted runner that can reach those services.

## 1. Load deployment configuration

Set the production contract variables in the process environment or inject them through the approved secret manager. Do not commit a populated `.env` file and do not place secret values in the evidence record.

Required configuration includes:

- `MADVA_PRODUCTION=true`
- OIDC issuer, JWKS URL, and audience
- `MADVA_INTENT_SECRET`
- Exactly one execution backend: an immutable `MADVA_RUNTIME_IMAGE` digest or an allowlisted MCP upstream
- `MADVA_AUDIT_LOG_PATH`
- `MADVA_REQUIRE_TENANT_BINDING=true`
- `MADVA_REQUIRE_APPROVED_POLICY=true` and `MADVA_POLICY_REGISTRY_PATH`
- Vault address and token-file settings when Vault is required
- `MADVA_REQUIRE_OTEL=true` and an OTLP endpoint when telemetry is required

For an authenticated Vault credential-access check, also set `MADVA_VALIDATION_VAULT_REFERENCE` to a non-sensitive test reference approved for staging validation. The validator never prints the retrieved value.

## 2. Run the validator

From `vie_gateway`:

```powershell
python -m pip install --no-deps -e .
python -m vie_gateway.deployment_validation_cli --live | Tee-Object deployment-validation.json
if ($LASTEXITCODE -ne 0) { throw "MADVA staging validation failed" }
```

The output is redacted JSON. Exit code `0` means the static contract and live checks passed. Exit code `2` means the release is not ready for the next gate.

## 3. Attach evidence

Record the repository commit, staging environment identifier, validator command, UTC execution time, result JSON, and remediation references. Never attach environment files, tokens, Vault responses, tool arguments, or customer data.

## Acceptance

The staging run must pass OIDC discovery/JWKS, audit-volume write probing, and all configured Vault and OTLP checks. A local Keycloak or dev Vault pass is useful development evidence but does not replace this target-environment run.
