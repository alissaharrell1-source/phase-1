# MADVA VIE Gateway high-availability deployment

This base deploys three gateway replicas behind a Kubernetes `ClusterIP` Service. Rolling updates keep all replicas available, the PodDisruptionBudget preserves two replicas during voluntary disruption, and topology spreading avoids placing replicas on the same node.

Before applying it:

1. Create the `madva-gateway-secrets` Secret in the `madva-system` namespace with `MADVA_OIDC_JWKS_URL`, `MADVA_OIDC_ISSUER`, and `MADVA_INTENT_SECRET` keys.
2. Replace the placeholder gateway image digest in `deployment.yaml` with the release-approved immutable digest.
3. Replace `policy-registry.yaml` with the administrator-approved policy revisions, then roll out the change. The gateway loads the registry at startup.
4. Select an RWX volume implementation that honors advisory file locking and fsync. The audit chain cannot safely use an object-store mount or an RWX provider without those guarantees.
5. Deploy the isolated MCP execution service and configure its internal address in `configmap.yaml`. Keep the gateway Service internal or put it behind an authenticated ingress.
6. For Vault-backed credentials, inject `VAULT_ADDR=https://...` and a rotating `VAULT_TOKEN_FILE` through Vault Agent or an external secret manager; do not place a root token in this repository.
7. Configure the OTLP collector/SIEM endpoint and authentication headers through deployment secrets or an external secret manager.

Apply with:

```powershell
kubectl apply -k deploy/kubernetes
kubectl -n madva-system rollout status deployment/madva-vie-gateway
kubectl -n madva-system get pods,svc,pdb
```

The placeholder policy registry intentionally contains no approved revisions, so production tool calls remain fail-closed until the deployment owner supplies approved policy records.
