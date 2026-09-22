import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "security" / "validate_release_review.py"


def _run(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--path", str(path), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def test_pending_release_review_is_valid_for_normal_ci(tmp_path: Path) -> None:
    review = tmp_path / "review.json"
    review.write_text(json.dumps({
        "schema_version": 1, "release": "unreleased", "status": "pending",
        "reviewed_commit": "", "reviewed_at": "", "reviewer": "", "findings": [],
    }), encoding="utf-8")
    result = _run(review)
    assert result.returncode == 0


def test_release_review_requires_approval_and_matching_tag(tmp_path: Path) -> None:
    review = tmp_path / "review.json"
    review.write_text(json.dumps({
        "schema_version": 1, "release": "v0.1.0", "status": "approved",
        "reviewed_commit": "a" * 40, "reviewed_at": "2026-09-22T12:00:00+00:00",
        "reviewer": "security-maintainer", "findings": [],
    }), encoding="utf-8")
    assert _run(review, "--require-approved", "--release", "v0.1.0").returncode == 0
    assert _run(review, "--require-approved", "--release", "v0.2.0").returncode == 2


def test_release_review_blocks_unresolved_high_finding(tmp_path: Path) -> None:
    review = tmp_path / "review.json"
    review.write_text(json.dumps({
        "schema_version": 1, "release": "v0.1.0", "status": "approved",
        "reviewed_commit": "a" * 40, "reviewed_at": "2026-09-22T12:00:00+00:00",
        "reviewer": "security-maintainer", "findings": [{
            "identifier": "CVE-TEST", "component": "demo", "severity": "high",
            "applicability": "applicable", "disposition": "remediate",
        }],
    }), encoding="utf-8")
    result = _run(review, "--require-approved", "--release", "v0.1.0")
    assert result.returncode == 2
    assert "blocking_finding_unresolved" in result.stdout


def _ha_evidence(commit: str) -> dict[str, object]:
    return {
        "schema_version": 1, "environment": "staging", "commit": commit,
        "executed_at": "2026-09-22T12:00:00Z", "validator": "madva-ha-disruption",
        "release": {"image_digest": "sha256:" + "b" * 64, "kubernetes_version": "v1.31.4",
                    "node_count": 3, "replicas_expected": 3},
        "result": {"valid": True, "errors": [], "checks": ["audit_chain_verified"], "tests": [{
            "name": "pod_delete", "status": "pass", "replicas_available": 2,
            "requests_total": 10, "requests_failed": 0, "p95_latency_ms": 4.0,
            "audit_receipts_verified": 10, "audit_chain_valid": True,
            "sensitive_values_exposed": False, "findings": [],
        }]},
    }


def test_release_review_can_require_matching_ha_evidence(tmp_path: Path) -> None:
    commit = "c" * 40
    review = tmp_path / "review.json"
    evidence = tmp_path / "ha.json"
    review.write_text(json.dumps({
        "schema_version": 1, "release": "v0.1.0", "status": "approved",
        "reviewed_commit": commit, "reviewed_at": "2026-09-22T12:00:00+00:00",
        "reviewer": "security-maintainer", "findings": [],
    }), encoding="utf-8")
    evidence.write_text(json.dumps(_ha_evidence(commit)), encoding="utf-8")
    result = _run(review, "--require-approved", "--release", "v0.1.0",
                  "--require-ha-evidence", "--ha-evidence", str(evidence))
    assert result.returncode == 0


def test_release_review_rejects_missing_or_mismatched_ha_evidence(tmp_path: Path) -> None:
    review = tmp_path / "review.json"
    evidence = tmp_path / "ha.json"
    review.write_text(json.dumps({
        "schema_version": 1, "release": "v0.1.0", "status": "approved",
        "reviewed_commit": "d" * 40, "reviewed_at": "2026-09-22T12:00:00+00:00",
        "reviewer": "security-maintainer", "findings": [],
    }), encoding="utf-8")
    assert _run(review, "--require-approved", "--release", "v0.1.0", "--require-ha-evidence").returncode == 2
    evidence.write_text(json.dumps(_ha_evidence("e" * 40)), encoding="utf-8")
    result = _run(review, "--require-approved", "--release", "v0.1.0",
                  "--require-ha-evidence", "--ha-evidence", str(evidence))
    assert result.returncode == 2
    assert "ha_evidence_commit_mismatch" in result.stdout
