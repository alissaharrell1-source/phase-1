# MADVA staging disruption runbook

This runbook is for a disposable staging cluster only. It must use a release-approved immutable image, non-sensitive fixture data, and the target storage, identity, Vault, OTLP, MCP upstream, ingress, and node topology. Do not use production credentials or customer data.

## 1. Preflight and baseline

Set only non-secret identifiers in the operator shell:

```powershell
$env:MADVA_COMMIT = (git rev-parse HEAD)
$env:MADVA_ENVIRONMENT = "staging"
kubectl config current-context
kubectl version --output=yaml
kubectl -n madva-system get nodes
```

Render the release-approved image digest into a temporary manifest bundle, then run both preflights before applying it:

```powershell
python security/validate_kubernetes_ha.py --path .\rendered-manifests
python -m pip install --no-deps -e .\vie_gateway
python -m vie_gateway.deployment_validation_cli --live
```

The HA manifest validator must return `{"valid": true, "errors": []}`. The deployment validator must also be valid. Do not proceed on a failed check.

Apply and confirm the baseline:

```powershell
kubectl apply -k .\rendered-manifests
kubectl -n madva-system rollout status deployment/madva-vie-gateway --timeout=5m
kubectl -n madva-system get deployment madva-vie-gateway
kubectl -n madva-system get pods -l app.kubernetes.io/name=madva-vie-gateway -o wide
kubectl -n madva-system get pdb madva-vie-gateway
```

Before disruption, confirm three Ready replicas, a `ClusterIP` Service, a PDB with `minAvailable: 2`, and healthy audit, Vault, OTLP, and MCP dependencies. Run the bounded `/healthz` and `/readyz` smoke commands from `docs/HA_TEST_PLAN.md` and retain their redacted evidence files.

## 2. Execute one scenario at a time

Keep the authenticated workload limited to the staging tenant and approved non-sensitive tool fixture. Capture only counts, latency, readiness transitions, audit receipt counts, and redacted finding codes.

### Pod deletion

Select one gateway pod, delete only that pod, and immediately run the smoke workload. Wait for the replacement to become Ready:

```powershell
$pod = kubectl -n madva-system get pods -l app.kubernetes.io/name=madva-vie-gateway -o jsonpath="{.items[0].metadata.name}"
kubectl -n madva-system delete pod $pod --wait=false
kubectl -n madva-system rollout status deployment/madva-vie-gateway --timeout=5m
```

Pass requires at least two available replicas, no readiness failure routed as success, no audit-chain break, and no sensitive exposure.

### Node drain

Use the platform-approved drain procedure. Never force-delete workloads or bypass the PDB:

```powershell
$node = kubectl -n madva-system get pod -l app.kubernetes.io/name=madva-vie-gateway -o jsonpath="{.items[0].spec.nodeName}"
kubectl cordon $node
kubectl drain $node --ignore-daemonsets --delete-emptydir-data --timeout=10m
kubectl -n madva-system rollout status deployment/madva-vie-gateway --timeout=5m
kubectl uncordon $node
```

If the drain attempts to violate the PDB, stop and record a failed `node_drain` test; do not add `--force` or `--disable-eviction`.

### Rolling update

Apply the next approved immutable digest through the release process and watch the rollout:

```powershell
kubectl -n madva-system rollout status deployment/madva-vie-gateway --timeout=10m
kubectl -n madva-system rollout history deployment/madva-vie-gateway
```

Pass requires zero unavailable replicas, readiness removal for unready pods, and either a completed rollout or a safely paused rollout with no fail-open authorization or audit behavior.

### Audit, OTLP, and storage failure exercises

Use the staging platform's approved dependency-failure mechanism. Do not edit production-like secrets or delete persistent data. During each exercise, confirm the documented readiness/fail-closed behavior, then restore the dependency and verify audit sequence/hash-chain integrity. Record `audit_dependency_outage`, `otlp_dependency_outage`, and `shared_storage_restore` separately when exercised.

## 3. Record and validate evidence

Create the template once per staging release:

```powershell
python security\create_ha_disruption_evidence.py `
  --output ha-disruption-evidence.json `
  --environment staging `
  --commit $env:MADVA_COMMIT `
  --image-digest sha256:<approved-digest> `
  --kubernetes-version <version> `
  --node-count <count> `
  --replicas-expected 3
```

Update only the bounded fields under `result.tests` and `result.checks`. Use `status: pass` only when the scenario's acceptance criteria passed. Then set `result.valid` to `true` only after every listed test is `pass`, `errors` is empty, the audit chain is valid, and sensitive exposure is false:

```powershell
python security\validate_ha_disruption_evidence.py --path ha-disruption-evidence.json
```

The final output must be `{"errors": [], "valid": true}`. Attach that file, the two health/readiness smoke artifacts, deployment validation output, and the release commit to the staging review record. These artifacts do not contain URLs, pod names, tenant identifiers, credentials, response bodies, or free-form notes.

## 4. Stop conditions and rollback

Stop the run and keep the release blocked if a PDB is violated, readiness routes traffic to an unready pod, authorization fails open, audit verification fails, storage restore is incomplete, a sensitive value appears in telemetry, or the approved SLO is exceeded. Use the release process's last known-good immutable digest for rollback and rerun the baseline before any further disruption.
