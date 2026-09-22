from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "security" / "validate_deployment_evidence.py"


def _evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "environment": "staging",
        "commit": "a" * 40,
        "executed_at": datetime.now(UTC).isoformat(),
        "validator": "madva-deployment-validate",
        "result": {"valid": True, "errors": [], "checks": ["oidc_discovery_and_jwks"]},
    }


def _run(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), "--path", str(path)], capture_output=True, text=True, check=False)


def test_valid_evidence_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(_evidence()), encoding="utf-8")
    result = _run(path)
    assert result.returncode == 0
    assert json.loads(result.stdout)["valid"] is True


def test_evidence_rejects_secrets_and_unknown_fields(tmp_path: Path) -> None:
    evidence = _evidence()
    evidence["secret"] = "must-not-be-recorded"
    evidence["result"] = {"valid": True, "errors": [], "checks": ["https://identity.example"]}
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    result = _run(path)
    assert result.returncode == 2
    assert json.loads(result.stdout)["valid"] is False
