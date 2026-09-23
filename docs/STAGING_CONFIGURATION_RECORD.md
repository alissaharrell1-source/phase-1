# MADVA Staging Configuration Record

Status: **Template — populate for an approved non-production staging environment**

This record is the deployment handoff for the M1 staging validation gate. It contains configuration references and ownership metadata only. Do not put tokens, private keys, Vault responses, customer data, populated `.env` files, or sensitive endpoint URLs in this file or in the attached evidence.

## 1. Environment identity

| Field | Value |
|---|---|
| Environment identifier | `<staging-environment-id>` |
| Kubernetes context | `<approved-kubernetes-context>` |
| Namespace | `<madva-namespace>` |
| Repository commit | `<40-character-git-commit>` |
| Immutable gateway image | `<registry-image>@sha256:<64-hex-digest>` |
| Configuration owner | `<team-or-role>` |
| Approval reference | `<change-or-approval-id>` |

The Kubernetes context and approval reference must be resolved by the staging operator. Do not substitute the local Docker Desktop or `kind` rehearsal cluster for this record.

## 2. Required service references

Record the approved configuration source or variable name, not its secret value or URL.

| Capability | Required reference | Required contract |
|---|---|---|
| OIDC issuer | `MADVA_OIDC_ISSUER` | TLS-enabled issuer; discovery and JWKS reachable from the gateway |
| OIDC audience | `MADVA_OIDC_AUDIENCE` | Matches the staging gateway registration |
| OIDC JWKS | `MADVA_OIDC_JWKS_URL` | TLS-enabled JWKS endpoint; key rotation procedure documented |
| Vault | `VAULT_ADDR` | TLS-enabled address; Vault Agent/CSI injects credentials without Git-stored tokens |
| Vault token file | `MADVA_VAULT_TOKEN_FILE` | Ephemeral, least-privileged token file with renewal and rotation owner |
| OTLP/SIEM | `OTEL_EXPORTER_OTLP_ENDPOINT` | TLS-enabled collector/export path with retention and access policy |
| Audit storage | `MADVA_AUDIT_LOG_PATH` | Persistent RWX storage with fsync, advisory-lock, backup, restore, and tamper-detection owners |
| Policy registry | `MADVA_POLICY_REGISTRY_PATH` | Versioned, approval-gated policy source available to all replicas |

The populated values must be injected by the approved deployment or secret-management system. The staging evidence should contain only check names and redacted results accepted by `security/validate_deployment_evidence.py`.

## 3. Security and runtime contract

The staging deployment must set or prove the following before validation:

- `MADVA_PRODUCTION=true`
- `MADVA_REQUIRE_TENANT_BINDING=true`
- `MADVA_REQUIRE_APPROVED_POLICY=true`
- `MADVA_REQUIRE_OTEL=true`
- Exactly one execution backend is configured: an immutable runtime image digest or an allowlisted MCP upstream.
- Intent, OIDC, Vault, and telemetry secrets are supplied at runtime and are absent from logs, images, manifests, and evidence.
- Audit writes are durable and shared by all replicas; storage failure does not fail open an authorization or audit boundary.
- TLS certificate ownership, rotation, and failure response are documented for OIDC, Vault, and OTLP/SIEM.

## 4. Validation and evidence handoff

From the trusted staging operator environment, follow [`STAGING_VALIDATION_RUNBOOK.md`](STAGING_VALIDATION_RUNBOOK.md):

```powershell
python -m vie_gateway.deployment_validation_cli --live | Tee-Object deployment-validation.json
if ($LASTEXITCODE -ne 0) { throw "MADVA staging validation failed" }
python ..\security\validate_deployment_evidence.py --path deployment-evidence.json
```

Attach only the redacted `deployment-evidence.json` and the remediation references to the release record. The record must identify:

- the exact commit and immutable image digest;
- the staging environment and Kubernetes namespace;
- the UTC validation time and validator version;
- the checks that passed or failed; and
- an owner and remediation reference for every failed check.

Do not attach the unredacted process environment, endpoint credentials, Vault token files, tool arguments, audit payloads, or customer data.

## 5. Sign-off

| Gate | Owner | Status | Evidence/remediation reference |
|---|---|---|---|
| OIDC discovery and JWKS | `<identity owner>` | `pending` | `<reference>` |
| Vault health and credential injection | `<secrets owner>` | `pending` | `<reference>` |
| OTLP/SIEM connectivity and redaction | `<telemetry owner>` | `pending` | `<reference>` |
| RWX audit write and restore contract | `<storage owner>` | `pending` | `<reference>` |
| Immutable image and runtime policy | `<platform owner>` | `pending` | `<reference>` |
| MADVA staging validation | `<release owner>` | `pending` | `<deployment-evidence.json>` |

This template is not staging evidence. M1 remains open until a populated record and a passing, validated redacted evidence artifact exist for the selected non-production environment.
