# Security control and evidence matrix

| Control | Implementation | Evidence | Remaining validation |
| --- | --- | --- | --- |
| C-01 Token authenticity and claims | `vie_gateway/src/vie_gateway/security.py` | `tests/security/test_regressions.py`, OIDC tests | External key-rotation and provider outage review |
| C-02 Intent integrity | `IntentSigner` and Architect stage | `tests/test_gateway.py` | Canonicalization and cross-language signing review |
| C-03 Tenant isolation | `JITAuthorizer` and production flags | tenant tests and security regressions | Identity-provider claim mapping review |
| C-04 Approved policy revision | `PolicyRegistry` | `tests/test_policy.py` | Human approval service and registry distribution review |
| C-05 Execution isolation | `DockerRunner`, Kubernetes security context | Docker tests and manifest rendering | Host/runtime escape assessment |
| C-06 Credential isolation | `VaultCredentialProvider` and opaque leases | Vault tests and Docker credential integration | Vault Agent/rotation integration test |
| C-07 Result verification/DLP | `Verifier`, output schema, `DLPScanner` | gateway and verification tests | DSPM coverage assessment |
| C-08 Audit integrity | `JsonlAuditStore`, cross-process lock, and read-only backup verifier | audit tests, restore/tamper tests, and `madva-audit-verify` | Shared-storage disruption and backup restore in the target platform |
| C-09 Telemetry redaction | bounded OTel attributes | span tests and OTLP config checks | Collector retention/access review |
| C-10 HA operations | Kubernetes Deployment, Service, PDB, probes | Kustomize render and operations guide | Cluster disruption/load test |
| C-11 Reproducibility | CI, security suite, benchmark | GitHub Actions artifacts and benchmark JSON | External environment replication |
| C-12 Supply-chain hygiene | Dependency audit, Bandit, and Trivy workflow | `.github/workflows/security.yml` artifacts | Triage policy for newly disclosed vulnerabilities |
