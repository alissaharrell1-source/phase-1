# Independent security assessment plan

## Objective

Obtain an external review of the VIE gateway's security design and implementation, with emphasis on the closed-loop sequence: identity and intent validation → JIT authorization → isolated execution → result verification → audit receipt.

## Scope

### In scope

- FastAPI/MCP request boundary and JSON-RPC error behavior.
- HS256 development boundary and OIDC/JWKS production validation.
- Intent signatures, tenant binding, policy approval states, permit expiry, and replay assumptions.
- Docker execution hardening, credential lease mounting and cleanup, and MCP upstream forwarding.
- Output schema validation, DLP findings, OTel redaction, and audit-chain integrity.
- Kubernetes HA manifests and operational fail-closed requirements.

### Out of scope for this milestone

- Certification of the host kernel, cloud account, identity provider, Vault, SIEM, or Kubernetes control plane.
- Complete DSPM coverage, a production WORM audit service, or a formal availability SLA.
- Security of third-party MCP tools and images beyond the gateway's admission and isolation controls.

## Review method

1. **Desk review:** threat model, architecture, contracts, deployment manifests, and configuration defaults.
2. **Automated review:** unit/security suites, type checking, dependency/container scanning, and static analysis.
3. **Dynamic review:** malformed tokens/contracts, policy transitions, tenant confusion, replay attempts, tool/argument injection, timeout/cleanup failures, and upstream protocol abuse.
4. **Infrastructure review:** image digest enforcement, container capabilities, filesystem/network restrictions, Kubernetes rollout and storage assumptions.
5. **Retest:** verify every material finding against a regression test and a documented mitigation.

## Evidence package

- Commit under review and release image digests.
- `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, and `docs/OPERATIONS.md`.
- CI JUnit test artifacts, security regression output, mypy output, Compose/Kustomize validation, and benchmark methodology.
- CI dependency, static-analysis, and container-scan artifacts from `.github/workflows/security.yml`.
- Redacted policy registry and deployment configuration.
- Audit-chain verification output from a disposable test fixture.

## Exit criteria

- No unresolved critical or high-severity gateway findings without an explicitly accepted risk owner.
- Each security claim has an executable regression test or a named deployment control.
- Findings involving secrets, tenant boundaries, or audit integrity have red-team reproductions and retest evidence.
- Limitations and residual risks are published with the release rather than hidden behind the MVP label.
