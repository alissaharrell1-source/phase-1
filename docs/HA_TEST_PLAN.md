# High-availability disruption and load test plan

The Kubernetes manifests provide the availability mechanisms; they are not proof of cluster-level availability. Execute this plan against a disposable staging cluster that matches the target storage, identity, Vault, OTLP, MCP upstream, ingress, and node topology.

## Preconditions

- Apply the Kustomize base with a release-approved immutable image and approved policy registry.
- Confirm three Ready replicas, the internal `ClusterIP` Service, `madva-vie-gateway` PDB, and healthy audit/Vault/OTLP dependencies.
- Generate a representative authenticated MCP workload using a staging tenant and non-sensitive tool fixture. Never use production credentials or customer data.

Before applying the bundle, run `python security/validate_kubernetes_ha.py --path vie_gateway/deploy/kubernetes` against the rendered manifests. The checked-in base intentionally contains an image-digest placeholder and must fail until the release process substitutes an approved immutable digest. Run the validator again on the rendered staging bundle; only a valid result satisfies the manifest preflight.

The `ha-contracts` job in GitHub Actions performs the same contract checks on every push and pull request using a temporary digest-pinned render. Passing CI proves the repository contracts are internally consistent; it does not replace the staging disruption run.

## Load test

Run the repository benchmark for a local baseline, then use an authenticated HTTP load tool at the staging Service or ingress. Record image digest, Kubernetes version, node count, CPU/memory limits, request rate, concurrency, duration, p50/p95/p99 latency, error rate, readiness transitions, audit receipt count, and upstream dependency saturation. Repeat at the planned steady-state and peak concurrency.

For a bounded unauthenticated service smoke before the authenticated workload, run `madva-ha-smoke --url https://staging-gateway.example --path /healthz --iterations 300 --concurrency 20` and repeat with `--path /readyz`. The command emits status counts and latency percentiles without recording response bodies. It is a health/readiness signal, not a substitute for the authenticated MCP workload below.

To create review evidence, provide an environment label and the exact commit, for example `madva-ha-smoke --url https://staging-gateway.example --path /healthz --iterations 300 --concurrency 20 --environment staging --commit $env:MADVA_COMMIT --evidence-output ha-healthz-evidence.json`. Validate the artifact with `python security/validate_ha_smoke_evidence.py --path ha-healthz-evidence.json`. The artifact is URL-free and contains only bounded metrics, status counts, and the selected endpoint path.

## Disruption test

1. Delete one gateway pod and confirm the Service continues serving requests while a replacement becomes Ready.
2. Cordon and drain one node using the platform's approved drain procedure; confirm the PDB preserves at least two available replicas and topology spreading reschedules safely.
3. During a rolling image update, confirm no unavailable replicas, readiness removes unready pods from traffic, and the rollout either completes or pauses safely.
4. Temporarily make the audit or OTLP dependency unavailable in staging and confirm the documented fail-closed/readiness behavior without exposing payloads.

Record the disruption run in `security/ha-disruption-evidence.schema.json` and validate it with `python security/validate_ha_disruption_evidence.py --path ha-disruption-evidence.json`. The contract accepts only an immutable image digest, bounded cluster metadata, named disruption cases, numeric observations, and redacted finding codes. Do not add URLs, pod names, tenant identifiers, credentials, response bodies, or free-form notes.

Create the initial operator template with `python security/create_ha_disruption_evidence.py --output ha-disruption-evidence.json --environment staging --commit $env:MADVA_COMMIT --image-digest sha256:<approved-digest> --kubernetes-version v1.31.4 --node-count 3 --replicas-expected 3`. The generated artifact is deliberately marked `valid: false` and `test_results_pending`; update only the bounded test fields from observed staging results, then rerun the validator. Do not mark the result valid while any test is `not_run` or `fail`.

## Acceptance criteria

- At least two gateway replicas remain available during voluntary single-node disruption.
- No request is routed to an unready pod, and the Service recovers without manual data repair.
- Audit sequence and hash-chain verification pass after the test and after restore from the staging backup.
- No sensitive test value appears in logs, spans, receipts, benchmark output, or uploaded evidence.
- The recorded error rate and latency remain within the deployment's approved SLO; otherwise keep the release blocked and attach the evidence to the review.
