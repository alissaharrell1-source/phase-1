# Supply-chain vulnerability triage

MADVA treats dependency, GitHub Action, and container-image findings as release-risk signals. Automated scans are required evidence, but a passing scan is not a security certification or a substitute for reviewing provenance and exploitability.

## Required response

- Critical findings block merges and releases until upgraded, removed, or covered by a time-limited approved exception. Target remediation is one calendar day.
- High findings block merges and releases unless an approved exception exists. Target remediation is seven calendar days.
- Medium findings require a maintainer decision and tracked remediation within 30 calendar days.
- Low findings are tracked for remediation within 90 calendar days or the next planned dependency-maintenance release.
- Unfixed findings from Trivy or dependency scanning must be triaged explicitly; `ignore-unfixed` changes reporting behavior, not ownership or risk acceptance.

The machine-readable thresholds and exception schema are in [`security/scan-policy.json`](../security/scan-policy.json). Dependabot opens weekly update pull requests for Python dependencies and GitHub Actions in [`.github/dependabot.yml`](../.github/dependabot.yml).

Each release also requires a reviewed record at [`security/release-review.json`](../security/release-review.json). The validator checks advisory applicability, disposition, blocking severity handling, and exception metadata. The normal CI path validates its shape; the published-release workflow additionally requires `status: approved` and an exact release-tag match.

## Exception requirements

An exception must identify the advisory, affected component, severity, accountable owner, reason the finding cannot yet be fixed, compensating mitigation, and an expiration date no more than 30 days after approval. A security-focused maintainer must approve it. Exceptions are never a reason to suppress the scan or remove the finding from evidence artifacts.

## Triage workflow

1. Confirm the finding applies to the shipped dependency or image and record its advisory identifier.
2. Check whether a patched version, safe configuration, or replacement is available.
3. Open or update a private security work item with severity, exploitability, affected deployment modes, owner, and target date. Do not include secrets or customer data.
4. Upgrade, rebuild, and rerun the full CI security workflow. Add a regression test when the finding affects gateway behavior or a security boundary.
5. Close the item only after the scan is clean or an approved exception is recorded with a future review date.

Before publishing a release, update `security/release-review.json` with the release tag, reviewed commit, UTC review timestamp, security reviewer, and every finding's applicability and disposition. Run:

```powershell
python security/validate_release_review.py --path security/release-review.json --require-approved --release v0.1.0
```

For a release that has completed staging HA validation, add the disruption artifact to the release record and enforce the commit-bound gate with `python security/validate_release_review.py --path security/release-review.json --require-approved --release v0.1.0 --require-ha-evidence --ha-evidence ha-disruption-evidence.json`. The gate rejects missing, invalid, local-only, or commit-mismatched HA evidence.

The workflow retains JSON scan evidence as CI artifacts. Material findings involving tokens, tenant boundaries, credentials, sandboxing, or audit integrity also require review against the threat model and independent assessment plan.
