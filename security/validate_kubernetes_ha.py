from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def _documents(directory: Path) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(document, dict):
                documents.append(document)
    return documents


def _find(documents: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any] | None:
    for document in documents:
        metadata = document.get("metadata", {})
        if document.get("kind") == kind and isinstance(metadata, dict) and metadata.get("name") == name:
            return document
    return None


def validate_manifests(directory: Path) -> list[str]:
    try:
        documents = _documents(directory)
    except (OSError, yaml.YAMLError):
        return ["manifest_bundle_unreadable"]
    errors: list[str] = []
    deployment = _find(documents, "Deployment", "madva-vie-gateway")
    pdb = _find(documents, "PodDisruptionBudget", "madva-vie-gie-gateway")
    if pdb is None:
        pdb = _find(documents, "PodDisruptionBudget", "madva-vie-gateway")
    service = _find(documents, "Service", "madva-vie-gateway")
    if deployment is None:
        errors.append("deployment_missing")
        return errors
    spec = deployment.get("spec", {})
    template = spec.get("template", {})
    pod_spec = template.get("spec", {}) if isinstance(template, dict) else {}
    containers = pod_spec.get("containers", []) if isinstance(pod_spec, dict) else []
    container = containers[0] if isinstance(containers, list) and containers and isinstance(containers[0], dict) else {}
    if spec.get("replicas") != 3:
        errors.append("replicas_must_be_three")
    strategy = spec.get("strategy", {})
    rolling = strategy.get("rollingUpdate", {}) if isinstance(strategy, dict) else {}
    if strategy.get("type") != "RollingUpdate" or rolling.get("maxUnavailable") != 0:
        errors.append("rolling_update_must_preserve_availability")
    if rolling.get("maxSurge") != 1:
        errors.append("rolling_update_max_surge_invalid")
    spread = pod_spec.get("topologySpreadConstraints", []) if isinstance(pod_spec, dict) else []
    if not any(
        isinstance(item, dict)
        and item.get("topologyKey") == "kubernetes.io/hostname"
        and item.get("whenUnsatisfiable") == "DoNotSchedule"
        and item.get("nodeTaintsPolicy") == "Honor"
        for item in spread
    ):
        errors.append("taint_aware_hostname_topology_spread_required")
    image = container.get("image", "") if isinstance(container, dict) else ""
    if not isinstance(image, str) or "@sha256:" not in image or "REPLACE_WITH" in image:
        errors.append("immutable_image_digest_required")
    readiness = container.get("readinessProbe", {}) if isinstance(container, dict) else {}
    liveness = container.get("livenessProbe", {}) if isinstance(container, dict) else {}
    startup = container.get("startupProbe", {}) if isinstance(container, dict) else {}
    if readiness.get("httpGet", {}).get("path") != "/readyz":
        errors.append("readiness_probe_must_use_readyz")
    if liveness.get("httpGet", {}).get("path") != "/healthz":
        errors.append("liveness_probe_must_use_healthz")
    if startup.get("httpGet", {}).get("path") != "/healthz":
        errors.append("startup_probe_must_use_healthz")
    if pdb is None:
        errors.append("pdb_missing")
    else:
        pdb_spec = pdb.get("spec", {})
        if pdb_spec.get("minAvailable") != 2:
            errors.append("pdb_min_available_must_be_two")
        if pdb_spec.get("selector", {}).get("matchLabels") != spec.get("selector", {}).get("matchLabels"):
            errors.append("pdb_selector_mismatch")
    if service is None:
        errors.append("service_missing")
    else:
        service_spec = service.get("spec", {})
        if service_spec.get("type") != "ClusterIP":
            errors.append("service_must_be_cluster_ip")
        if service_spec.get("selector") != spec.get("selector", {}).get("matchLabels"):
            errors.append("service_selector_mismatch")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MADVA Kubernetes HA manifests")
    parser.add_argument("--path", type=Path, required=True, help="directory containing rendered YAML manifests")
    args = parser.parse_args()
    errors = validate_manifests(args.path)
    print(json.dumps({"valid": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
