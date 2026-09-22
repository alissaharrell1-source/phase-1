from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[2] / "security"))
from validate_ha_disruption_evidence import validate_evidence


def _evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "environment": "staging",
        "commit": "a" * 40,
        "executed_at": "2026-09-22T20:00:00Z",
        "validator": "madva-ha-disruption",
        "release": {
            "image_digest": "sha256:" + "b" * 64,
            "kubernetes_version": "v1.31.4",
            "node_count": 3,
            "replicas_expected": 3,
        },
        "result": {
            "valid": True,
            "errors": [],
            "checks": ["pdb_preserved", "audit_chain_verified"],
            "tests": [
                {
                    "name": "pod_delete",
                    "status": "pass",
                    "replicas_available": 2,
                    "requests_total": 100,
                    "requests_failed": 0,
                    "p95_latency_ms": 120.5,
                    "audit_receipts_verified": 100,
                    "audit_chain_valid": True,
                    "sensitive_values_exposed": False,
                    "findings": [],
                }
            ],
        },
    }


def test_valid_disruption_evidence_is_accepted() -> None:
    assert validate_evidence(_evidence()) == []


def test_validator_rejects_urls_and_inconsistent_requests() -> None:
    evidence = _evidence()
    result = evidence["result"]
    assert isinstance(result, dict)
    tests = result["tests"]
    assert isinstance(tests, list)
    test = tests[0]
    assert isinstance(test, dict)
    test["requests_failed"] = 101
    test["findings"] = ["https://example.invalid/secret"]
    errors = validate_evidence(evidence)
    assert "request_counts_inconsistent" in errors
    assert any("does not match" in error or "pattern" in error for error in errors)


def test_valid_result_cannot_hide_nonpassing_test() -> None:
    evidence = _evidence()
    result = evidence["result"]
    assert isinstance(result, dict)
    tests = result["tests"]
    assert isinstance(tests, list)
    test = tests[0]
    assert isinstance(test, dict)
    test["status"] = "not_run"
    assert "valid_result_contains_nonpassing_test" in validate_evidence(evidence)
