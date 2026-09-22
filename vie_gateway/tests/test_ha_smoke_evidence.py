from __future__ import annotations

import json
from pathlib import Path

from vie_gateway.ha_smoke import SmokeResult, write_evidence


ROOT = Path(__file__).parents[2]


def _result() -> SmokeResult:
    return SmokeResult(
        iterations=10, concurrency=2, path="/healthz", successful=10, failed=0,
        status_counts={"200": 10}, requests_per_second=12.5,
        latency_ms={"mean": 2.0, "p50": 1.5, "p95": 4.0, "p99": 5.0},
    )


def test_smoke_evidence_is_redacted_and_writes_json(tmp_path: Path) -> None:
    output = tmp_path / "ha-evidence.json"
    write_evidence(output, _result(), environment="local", commit="a" * 40)
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["validator"] == "madva-ha-smoke"
    assert evidence["result"]["smoke"]["path"] == "/healthz"
    assert "url" not in json.dumps(evidence).lower()


def test_smoke_evidence_validator_accepts_valid_artifact(tmp_path: Path) -> None:
    output = tmp_path / "ha-evidence.json"
    write_evidence(output, _result(), environment="staging", commit="b" * 40)
    import sys
    sys.path.insert(0, str(ROOT / "security"))
    from validate_ha_smoke_evidence import validate_evidence

    assert validate_evidence(json.loads(output.read_text(encoding="utf-8"))) == []


def test_smoke_evidence_validator_rejects_inconsistent_counts() -> None:
    from validate_ha_smoke_evidence import validate_evidence

    evidence = _result().as_evidence(environment="local", commit="c" * 40)
    result = evidence["result"]
    assert isinstance(result, dict)
    smoke = result["smoke"]
    assert isinstance(smoke, dict)
    smoke["failed"] = 1
    assert "smoke_counts_inconsistent" in validate_evidence(evidence)
