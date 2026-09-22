# MADVA Phase 2 Plan

Status: **Engineering plan started; implementation follows the target-environment contract**

Phase 2 hardens the Phase 1 VIE gateway into an operable, assessable platform. Phase 1 established the modular execution path and local acceptance baseline. Phase 2 closes the deployment, operations, integration, and assurance gaps that cannot be proven by repository tests alone.

## Ordered milestones

### M1 — Target deployment contract and validation harness

- Define the target Kubernetes, identity-provider, Vault Agent, OTLP/SIEM, and shared-storage assumptions.
- Convert the local OIDC and Vault checks into repeatable environment validation commands.
- Keep secrets and tenant data out of logs and evidence artifacts.

Exit criteria: a deployment-specific configuration record exists, validation commands run against non-production staging services, and every failed check has an actionable remediation.

### M2 — HA, disruption, and performance acceptance

- Exercise three-replica rollout, readiness/liveness behavior, PDB behavior, and node/pod disruption.
- Test concurrent audit writers, shared-storage failure, restore verification, and tamper detection.
- Establish latency, throughput, timeout, cleanup, and resource-limit baselines.

Exit criteria: disruption and load evidence is attached to the release record and no audit or authorization boundary fails open.

### M3 — Enterprise integrations

- Validate the selected identity provider's key rotation, outage behavior, tenant mapping, and approval-service integration.
- Validate Vault Agent authentication, renewal, atomic token-file rotation, TLS, namespace, and outage behavior.
- Validate OTLP/SIEM retention, access control, encryption, deletion, and payload-redaction behavior.

Exit criteria: target integration evidence closes the applicable C-01, C-03, C-04, C-06, and C-09 gates.

### M4 — Policy and tenant operations

- Add administrator-facing policy submission, approval, revocation, and version-diff workflows.
- Add tenant lifecycle and isolation checks to the operational API and deployment runbooks.
- Publish SDK/examples for MCP callers and implement migration-safe configuration documentation.

Exit criteria: policy and tenant changes are auditable, versioned, approval-gated, and covered by integration tests.

### M5 — Independent assurance and release

- Run independent host/runtime escape, DSPM or memory-exposure, and cross-language signing reviews.
- Replicate the locked build and tests in an independent environment.
- Complete the machine-readable release review and publish the open-source/community release materials.

Exit criteria: all applicable closure gates have evidence, findings are remediated or accepted, and the release review is approved.

## Immediate implementation step — complete

The first M1 deliverable is now present as `madva-deployment-validate`. It fails closed, emits redacted machine-readable results, and is runnable by CI or an operator without embedding credentials in the repository. The next M1 increment is live endpoint checks against staging identity, Vault, OTLP, and shared-storage services.

## Completion boundary

Phase 2 is complete only when the target deployment passes the applicable milestones and the evidence is attached to the release record. A green unit or CI suite alone is not sufficient for Phase 2 production readiness.
