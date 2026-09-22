from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


TEST_NAMES = (
    "pod_delete",
    "node_drain",
    "rolling_update",
    "audit_dependency_outage",
    "otlp_dependency_outage",
    "shared_storage_restore",
)


def build_template(*, environment: str, commit: str, image_digest: str,
                   kubernetes_version: str, node_count: int,
                   replicas_expected: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "environment": environment,
        "commit": commit,
        "executed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "validator": "madva-ha-disruption",
        "release": {
            "image_digest": image_digest,
            "kubernetes_version": kubernetes_version,
            "node_count": node_count,
            "replicas_expected": replicas_expected,
        },
        "result": {
            "valid": False,
            "errors": ["test_results_pending"],
            "checks": ["template_created"],
            "tests": [
                {
                    "name": name,
                    "status": "not_run",
                    "replicas_available": 0,
                    "audit_chain_valid": False,
                    "sensitive_values_exposed": False,
                    "findings": ["not_run"],
                }
                for name in TEST_NAMES
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a redacted MADVA HA disruption evidence template")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--kubernetes-version", required=True)
    parser.add_argument("--node-count", type=int, required=True)
    parser.add_argument("--replicas-expected", type=int, required=True)
    args = parser.parse_args()
    if len(args.commit) != 40:
        parser.error("--commit must be a 40-character commit")
    evidence = build_template(
        environment=args.environment,
        commit=args.commit,
        image_digest=args.image_digest,
        kubernetes_version=args.kubernetes_version,
        node_count=args.node_count,
        replicas_expected=args.replicas_expected,
    )
    args.output.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "valid": False, "error": "test_results_pending"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
