# Tenant claim mapping contract

MADVA binds an execution to one canonical tenant identifier before JIT authorization. The gateway accepts these identity-provider claims:

| Claim | Meaning | Required handling |
| --- | --- | --- |
| `tenant_id` | MADVA canonical tenant identifier | Must be a non-empty string |
| `tid` | Supported identity-provider alias for the tenant identifier | Normalized to `tenant_id`; must be a non-empty string |

If both claims are present, they must contain the exact same value. Missing claims remain unbound and are rejected when production tenant binding is enabled. Empty, non-string, or conflicting claims fail closed before authorization.

The normalized value is compared with `IntentContract.tenant_id` by `JITAuthorizer`; it is also propagated into the issued permit and audit receipt. Identity-provider deployments must map their tenant or organization claim to `tenant_id` or `tid` and verify that mapping during integration review.
