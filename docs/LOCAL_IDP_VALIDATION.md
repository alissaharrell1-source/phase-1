# Local Identity Provider Validation

Date: 2026-09-22  
Environment: Keycloak `26.3` via `compose.dev.yaml` identity profile  
Status: **Passed as a local external-style check; target-provider validation remains open**

## Checks performed

- Keycloak realm discovery returned the configured MADVA issuer and JWKS endpoint.
- The service-account token endpoint issued a three-segment JWT.
- MADVA's asynchronous `OIDCTokenValidator` validated the token's RS256 signature against the live Keycloak JWKS endpoint and enforced issuer and audience.
- The validated claims included `agent_id`, `requester_id`, `intent_scope`, and `tenant_id`.
- `JITAuthorizer(require_tenant_binding=True)` issued a permit with `tenant_id=tenant-local` for a matching Intent Contract.

The local realm's `tenant_id` mapper is intentionally hardcoded to `tenant-local` so tenant binding is exercised in development. The realm credentials and endpoint are demo-only and must not be exposed or reused.

## Boundary

This evidence validates the MADVA integration path against the checked-in Keycloak fixture. It does not close C-01 or C-03 for a production identity provider. The target deployment still needs independent key-rotation and outage testing, claim-mapping review, tenant isolation evidence, and confirmation of the production issuer, audience, and JWKS behavior.
