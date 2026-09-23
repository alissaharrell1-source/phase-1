from pathlib import Path


KUBERNETES = Path(__file__).parents[1] / "deploy" / "kubernetes"


def _read(name: str) -> str:
    return (KUBERNETES / name).read_text(encoding="utf-8")


def test_ha_deployment_preserves_replicas_during_rollout() -> None:
    deployment = _read("deployment.yaml")
    assert "replicas: 3" in deployment
    assert "minReadySeconds: 10" in deployment
    assert "maxUnavailable: 0" in deployment
    assert "maxSurge: 1" in deployment
    assert "path: /healthz" in deployment
    assert "path: /readyz" in deployment
    assert "failureThreshold: 30" in deployment
    assert "topologyKey: kubernetes.io/hostname" in deployment
    assert "nodeTaintsPolicy: Honor" in deployment


def test_ha_service_and_disruption_budget_select_gateway() -> None:
    service = _read("service.yaml")
    pdb = _read("pdb.yaml")
    assert "type: ClusterIP" in service
    assert "targetPort: http" in service
    assert "minAvailable: 2" in pdb
    assert "app.kubernetes.io/name: madva-vie-gateway" in service
    assert "app.kubernetes.io/name: madva-vie-gateway" in pdb
