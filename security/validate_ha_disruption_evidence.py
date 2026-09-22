from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_PATH = Path(__file__).with_name("ha-disruption-evidence.schema.json")


def validate_evidence(data: object) -> list[str]:
    try:
        schema: Any = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ["evidence_schema_unreadable"]
    errors = [error.message for error in Draft202012Validator(schema).iter_errors(data)]
    if not isinstance(data, dict):
        return errors
    timestamp = data.get("executed_at")
    if isinstance(timestamp, str):
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            errors.append("executed_at_invalid")
    result = data.get("result")
    release = data.get("release")
    if not isinstance(result, dict):
        return errors
    if result.get("valid") is True and result.get("errors"):
        errors.append("valid_result_contains_errors")
    tests = result.get("tests")
    expected = release.get("replicas_expected") if isinstance(release, dict) else None
    if isinstance(tests, list):
        for test in tests:
            if not isinstance(test, dict):
                continue
            requests_total = test.get("requests_total")
            requests_failed = test.get("requests_failed")
            if isinstance(requests_total, int) and isinstance(requests_failed, int):
                if requests_failed > requests_total:
                    errors.append("request_counts_inconsistent")
            available = test.get("replicas_available")
            if isinstance(available, int) and isinstance(expected, int) and available > expected:
                errors.append("replica_count_exceeds_expected")
            if test.get("status") == "pass" and test.get("sensitive_values_exposed") is True:
                errors.append("passing_test_contains_sensitive_exposure")
            if test.get("status") == "pass" and test.get("audit_chain_valid") is not True:
                errors.append("passing_test_has_invalid_audit_chain")
        if result.get("valid") is True and any(
            isinstance(test, dict) and test.get("status") != "pass" for test in tests
        ):
            errors.append("valid_result_contains_nonpassing_test")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MADVA HA disruption evidence")
    parser.add_argument("--path", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"evidence_unreadable:{exc.__class__.__name__}"]}, sort_keys=True))
        return 2
    errors = validate_evidence(data)
    print(json.dumps({"valid": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
