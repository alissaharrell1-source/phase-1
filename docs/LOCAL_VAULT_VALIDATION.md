# Local Vault Credential Validation

Date: 2026-09-22  
Environment: Vault `1.20` dev server via `compose.dev.yaml` secrets profile  
Status: **Passed as a local external-style check; target deployment validation remains open**

## Checks performed

- A demo KV v2 value was written to `secret/tool` in the local Vault server.
- MADVA's `VaultCredentialProvider` fetched the value using a `vault://secret/tool#api_key` reference.
- The provider created an opaque lease file and did not place the secret in the `CredentialLease` model.
- Lease release sanitized and removed the file and left the temporary lease root empty.
- The Vault value was rotated, and a subsequent lease read the new value without restarting the provider.

Secret values are intentionally omitted from this record. The local root token and KV contents are demo-only and must not be reused or exposed.

## Boundary

This validates the provider behavior against a live local Vault endpoint. It does not close C-06 for a production deployment. The target environment still needs Vault Agent or sidecar authentication, atomic token-file rotation, TLS and namespace validation, policy/role review, renewal behavior, outage handling, and pod restart evidence.
