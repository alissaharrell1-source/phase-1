# Security control and evidence matrix

| Control | Implementation | Evidence | Remaining validation |
| --- | --- | --- | --- |
| C-01 Token authenticity and claims | `vie_gateway/src/vie_gateway/security.py` | `tests/security/test_regressions.py`, OIDC rotation/outage tests | External identity-provider key-rotation and outage review |
| C-02 Intent integrity | `IntentSigner`, shared canonical JSON profile, and Architect stage | `tests/test_gateway.py`, `docs/INTENT_SIGNING.md` | Cross-language implementation review against the published vector |
| C-03 Tenant isolation | `JITAuthorizer`, production flags, and explicit tenant claim mapping | tenant tests, security regressions, and `docs/TENANT_CLAIMS.md` | Verify the target identity-provider mapping against this contract |
| C-04 Approved policy revision | `PolicyRegistry` with approval metadata invariants | `tests/test_policy.py`, `docs/POLICY_APPROVALS.md` | Review the external approval service and registry distribution on the target platform |
| C-05 Execution isolation | Hardened `DockerRunner`, Kubernetes security context, and host-namespace guards | Docker tests, timeout-cleanup path, and manifest regression checks | Independent host/runtime escape assessment |
| C-06 Credential isolation | `VaultCredentialProvider`, opaque leases, and Vault readiness gate | Vault tests, token-file rotation regression, Docker credential integration, and `docs/VAULT_DEPLOYMENT.md` | Execute the Vault Agent rotation test in the target deployment |
| C-07 Result verification/DLP | `Verifier`, output schema, `DLPScanner` | gateway and verification tests | DSPM coverage assessment |
| C-08 Audit integrity | `JsonlAuditStore`, cross-process lock, and read-only backup verifier | audit tests, restore/tamper tests, and `madva-audit-verify` | Shared-storage disruption and backup restore in the target platform |
| C-09 Telemetry redaction | bounded OTel attributes | span tests and OTLP config checks | Collector retention/access review |
| C-10 HA operations | Kubernetes Deployment, Service, PDB, probes | Kustomize render and operations guide | Cluster disruption/load test |
| C-11 Reproducibility | CI, security suite, benchmark | GitHub Actions artifacts and benchmark JSON | External environment replication |
| C-12 Supply-chain hygiene | Dependency audit, Bandit, Trivy workflow, Dependabot, and machine-readable triage policy | `.github/workflows/security.yml` artifacts, `security/scan-policy.json`, and `docs/SUPPLY_CHAIN_TRIAGE.md` | Advisory applicability and remediation review for each release |
