# MADVA VIE threat model

This model describes the Phase 1 gateway boundary for assessor review. It is a design artifact, not a substitute for an independent assessment.

## Assets

| Asset | Confidentiality | Integrity | Availability |
| --- | --- | --- | --- |
| OIDC/JWT claims and tenant binding | high | high | medium |
| Intent Contract and policy revision | medium | critical | high |
| Vault credential material | critical | high | medium |
| Tool arguments and execution output | high | high | medium |
| Audit receipts and hash chain | medium | critical | high |
| OTLP audit metadata | medium | high | medium |

## Actors and boundaries

- **Caller:** may be untrusted and may submit malformed, replayed, over-scoped, or cross-tenant requests.
- **Identity provider:** signs claims; compromise or misconfiguration is outside the gateway's cryptographic boundary but must fail closed when validation is unavailable.
- **MCP/tool backend:** may be buggy or malicious; it receives only an approved call and separately scoped upstream credentials.
- **Vault/secret manager:** supplies short-lived secret material; secrets must not enter graph state, spans, or receipts.
- **Operator:** can configure deployment, policy, storage, and collectors; production changes require controlled review.
- **Storage/collector:** receives durable audit data and must be protected against unauthorized modification or loss.

## Threats and controls

| ID | Threat | Primary control | Residual risk |
| --- | --- | --- | --- |
| T1 | Forged, expired, wrong-audience, or wrong-algorithm token | OIDC/JWT validation and fail-closed claim checks | Identity-provider or key-management compromise |
| T2 | Replay or scope expansion | JTI-bearing token, signed Intent Contract, bounded JIT permit | Distributed replay detection and permit persistence remain deployment work |
| T3 | Cross-tenant execution | Token/contract tenant equality and production enforcement | Correct tenant claims remain an upstream identity responsibility |
| T4 | Unapproved policy execution | Versioned `PolicyRegistry` with approved-state requirement | Registry distribution and human approval tooling are deployment responsibilities |
| T5 | Tool escapes or credential theft | Network-disabled, read-only, capability-dropped sandbox and opaque leases | Kernel, container runtime, or tool-image vulnerabilities |
| T6 | Sensitive result leakage | Output schema validation, DLP scan, sanitized telemetry | Scanner coverage is not a complete DSPM implementation |
| T7 | Audit deletion or tampering | fsync-backed hash chain and replica lock coordination | Shared storage, backup, and WORM guarantees are external controls |
| T8 | Observability leaks secrets | Bounded receipt/span attributes and no payload persistence | Collector access control and retention remain deployment work |
| T9 | Availability loss during rollout | Three replicas, probes, rolling updates, and PDB | Upstream MCP, identity, Vault, storage, and cluster failures |

## Assessment focus

An independent review should prioritize token/contract binding, policy-state transitions, sandbox escape and argument injection, credential lifecycle cleanup, concurrent audit writers, telemetry redaction, and failure behavior when dependencies are unavailable or return malformed data.
