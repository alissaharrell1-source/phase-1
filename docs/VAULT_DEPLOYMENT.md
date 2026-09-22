# Vault Agent deployment contract

For a production deployment using Vault-backed credential references, configure:

- `VAULT_ADDR` to an HTTPS Vault endpoint;
- `VAULT_TOKEN_FILE` to a file path supplied by Vault Agent or an equivalent secret manager;
- optional `VAULT_NAMESPACE` for the target Vault namespace; and
- `MADVA_REQUIRE_VAULT=true`.

The agent must write the token file on an in-memory, application-readable mount and replace it atomically during rotation. It must not place a root token in a Kubernetes Secret, image layer, process argument, or repository. The gateway rereads the file for every new credential lease, so rotation applies to new calls without restarting the pod. Existing leases remain bounded by their Intent Contract expiry and are sanitized during release.

The deployment owner must validate the concrete Vault Agent Injector or sidecar configuration on the target cluster, including authentication role binding, token renewal/rotation, file permissions, TLS verification, namespace selection, pod restart behavior, and failure behavior when Vault or the token file is unavailable. Readiness is intentionally fail-closed while the required token file is absent.
