from __future__ import annotations

import shutil
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[2] / "security"))
from validate_kubernetes_ha import validate_manifests


MANIFESTS = Path(__file__).parents[1] / "deploy" / "kubernetes"


def test_checked_in_manifests_fail_closed_on_placeholder_digest() -> None:
    errors = validate_manifests(MANIFESTS)
    assert errors == ["immutable_image_digest_required"]


def test_rendered_manifests_pass_ha_preflight(tmp_path: Path) -> None:
    rendered = tmp_path / "rendered"
    shutil.copytree(MANIFESTS, rendered)
    deployment = rendered / "deployment.yaml"
    content = deployment.read_text(encoding="utf-8")
    content = content.replace("sha256:REPLACE_WITH_GATEWAY_IMAGE_DIGEST", "sha256:" + "a" * 64)
    deployment.write_text(content, encoding="utf-8")
    assert validate_manifests(rendered) == []


def test_preflight_rejects_pdb_or_service_drift(tmp_path: Path) -> None:
    rendered = tmp_path / "rendered"
    shutil.copytree(MANIFESTS, rendered)
    deployment = rendered / "deployment.yaml"
    deployment.write_text(
        deployment.read_text(encoding="utf-8").replace(
            "sha256:REPLACE_WITH_GATEWAY_IMAGE_DIGEST", "sha256:" + "b" * 64
        ),
        encoding="utf-8",
    )
    (rendered / "pdb.yaml").write_text(
        (rendered / "pdb.yaml").read_text(encoding="utf-8").replace("minAvailable: 2", "minAvailable: 1"),
        encoding="utf-8",
    )
    assert "pdb_min_available_must_be_two" in validate_manifests(rendered)
