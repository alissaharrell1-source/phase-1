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
