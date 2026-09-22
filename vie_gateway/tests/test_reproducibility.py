from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_reproducibility_inputs_are_pinned() -> None:
    runtime_lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    dev_lock = (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "fastapi==" in runtime_lock
    assert "langgraph==" in runtime_lock
    assert "-r requirements.lock" in dev_lock
    assert "FROM python:3.12-slim@sha256:" in dockerfile
    assert "pip install --no-cache-dir -r requirements.lock" in dockerfile
