from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


SCHEMA_PATH = Path(__file__).with_name("ha-smoke-evidence.schema.json")


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
    if isinstance(result, dict):
        if result.get("valid") is True and result.get("errors"):
            errors.append("valid_result_contains_errors")
        smoke = result.get("smoke")
        if isinstance(smoke, dict):
            failed = smoke.get("failed")
            successful = smoke.get("successful")
            iterations = smoke.get("iterations")
            if isinstance(failed, int) and isinstance(successful, int) and isinstance(iterations, int):
                if successful + failed != iterations:
                    errors.append("smoke_counts_inconsistent")
                if result.get("valid") is True and failed != 0:
                    errors.append("valid_smoke_contains_failures")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MADVA HA smoke evidence")
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
