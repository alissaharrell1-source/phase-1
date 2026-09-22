from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


SEVERITIES = {"critical", "high", "medium", "low"}
APPLICABILITY = {"applicable", "not_applicable", "unknown"}
DISPOSITIONS = {"fixed", "remediate", "exception", "not_applicable"}
HEX_SHA = re.compile(r"^[0-9a-f]{40}$")


def validate_review(data: object, *, require_approved: bool = False, release: str | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["review_must_be_an_object"]
    if data.get("schema_version") != 1:
        errors.append("unsupported_schema_version")
    status = data.get("status")
    if status not in {"pending", "approved"}:
        errors.append("invalid_review_status")
    if require_approved and status != "approved":
        errors.append("release_review_not_approved")
    if release is not None and data.get("release") != release:
        errors.append("release_name_mismatch")
    if status == "approved":
        for field in ("release", "reviewed_commit", "reviewed_at", "reviewer"):
            if not isinstance(data.get(field), str) or not data[field].strip():
                errors.append(f"approved_review_missing_{field}")
        if isinstance(data.get("reviewed_commit"), str) and not HEX_SHA.fullmatch(data["reviewed_commit"]):
            errors.append("approved_review_commit_invalid")
        if isinstance(data.get("reviewed_at"), str):
            try:
                datetime.fromisoformat(data["reviewed_at"].replace("Z", "+00:00"))
            except ValueError:
                errors.append("approved_review_timestamp_invalid")
    findings = data.get("findings")
    if not isinstance(findings, list):
        errors.append("findings_must_be_a_list")
        return errors
    for index, finding in enumerate(findings):
        prefix = f"finding_{index}"
        if not isinstance(finding, dict):
            errors.append(f"{prefix}_must_be_an_object")
            continue
        if not isinstance(finding.get("identifier"), str) or not finding["identifier"].strip():
            errors.append(f"{prefix}_identifier_required")
        severity = finding.get("severity")
        if severity not in SEVERITIES:
            errors.append(f"{prefix}_severity_invalid")
        applicability = finding.get("applicability")
        if applicability not in APPLICABILITY:
            errors.append(f"{prefix}_applicability_invalid")
        disposition = finding.get("disposition")
        if disposition not in DISPOSITIONS:
            errors.append(f"{prefix}_disposition_invalid")
        if severity in {"critical", "high"} and applicability == "applicable" and disposition not in {"fixed", "exception"}:
            errors.append(f"{prefix}_blocking_finding_unresolved")
        if disposition == "exception":
            exception = finding.get("exception")
            if not isinstance(exception, dict):
                errors.append(f"{prefix}_exception_metadata_required")
            else:
                for field in ("owner", "reason", "mitigation", "approved_by", "expires_on"):
                    if not isinstance(exception.get(field), str) or not exception[field].strip():
                        errors.append(f"{prefix}_exception_{field}_required")
                expires_on = exception.get("expires_on")
                if isinstance(expires_on, str):
                    try:
                        datetime.fromisoformat(expires_on)
                    except ValueError:
                        errors.append(f"{prefix}_exception_expiry_invalid")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MADVA supply-chain release review evidence")
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--require-approved", action="store_true")
    parser.add_argument("--release")
    args = parser.parse_args()
    try:
        data: Any = json.loads(args.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"review_unreadable:{exc.__class__.__name__}"]}, sort_keys=True))
        return 2
    errors = validate_review(data, require_approved=args.require_approved, release=args.release)
    print(json.dumps({"valid": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
