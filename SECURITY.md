# Security policy

MADVA is security-sensitive software and is still under active development. Do not use this repository as evidence of a security certification or independent assessment.

## Reporting a vulnerability

Please do not open a public issue for an exploitable vulnerability. Use GitHub's private vulnerability reporting for `alissaharrell1-source/phase-1` when enabled. If private reporting is unavailable, contact the repository owner privately through the GitHub account before sharing exploit details publicly.

Include:

- affected commit, component, and deployment mode;
- concise reproduction steps or a minimal proof of concept;
- impact, required privileges, and whether secrets or tenant boundaries are crossed;
- suggested mitigation, if known.

Do not include real credentials, customer data, production audit records, or private keys. Use redacted fixtures.

Maintainers will acknowledge receipt when practical, triage severity, coordinate a fix, and publish release notes after a mitigation is available. Timelines are best-effort while the project is pre-release.

## Security assumptions

- Production identity validation uses OIDC/JWKS, not the local HS256 development boundary.
- Production requires signed Intent Contracts, tenant binding, an approved policy revision, durable audit storage, and an isolated execution backend.
- The audit filesystem must provide reliable locking and fsync when shared by replicas.
- Demo Compose credentials and local Keycloak/Vault services are development-only.
- OTLP collectors, Vault, identity providers, registries, and upstream MCP servers remain part of the deployment trust boundary.
- CI runs dependency, static-analysis, and container-image scans; passing scans reduce known-risk exposure but do not replace independent testing or image provenance review.
- Supply-chain severity thresholds, remediation SLAs, exception requirements, and Dependabot coverage are defined in [`docs/SUPPLY_CHAIN_TRIAGE.md`](docs/SUPPLY_CHAIN_TRIAGE.md).
