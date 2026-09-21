# MADVA operations guide

## Preflight

Before production rollout, verify:

- OIDC JWKS, issuer, and audience are configured and reachable.
- Intent signing secret is supplied by a secret manager and rotated through a controlled procedure.
- Tenant binding and approved policy enforcement are enabled.
- The execution backend uses immutable image digests or an allowlisted MCP upstream.
- The audit path is durable, backed up, and on locking-capable storage.
- OTLP export points to an authenticated collector/SIEM without including payloads.
- Vault uses HTTPS and a rotating token file or equivalent short-lived authentication.

## Kubernetes rollout

Follow [the Kubernetes deployment guide](../vie_gateway/deploy/kubernetes/README.md), create the external `madva-gateway-secrets` Secret, replace placeholder image and policy values, then run:

```powershell
kubectl apply -k vie_gateway/deploy/kubernetes
kubectl -n madva-system rollout status deployment/madva-vie-gateway
kubectl -n madva-system get pods,svc,pdb
```

Do not route production traffic until all replicas are Ready and the policy registry contains the intended approved revisions.

## Health and incidents

- `/healthz` reports process health.
- `/readyz` reports required production configuration and backend readiness.
- A failed readiness probe should remove a pod from service; investigate configuration or dependency health before restarting repeatedly.
- A failed audit-chain verification is an integrity incident. Preserve the affected file, stop automated repair, and investigate storage access, unauthorized modification, and concurrent-writer behavior.
- A DLP or verification failure is a blocked result, not proof that execution was safe. Retain the receipt and inspect the isolated backend under incident procedures.

## Backup and rotation

Back up audit records with their lock sidecar and verify the chain after restore. Rotate OIDC, intent-signing, Vault, upstream, and OTLP credentials through the external secret manager. Never copy secrets into audit records, benchmark output, issue reports, or container arguments.
