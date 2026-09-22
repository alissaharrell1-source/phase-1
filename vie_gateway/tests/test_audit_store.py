import asyncio
import json
import shutil
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from vie_gateway.audit_store import AuditChainError, JsonlAuditStore
from vie_gateway.contracts import AuditReceipt


def _receipt() -> AuditReceipt:
    return AuditReceipt(
        receipt_id=uuid4(), correlation_id=uuid4(), contract_id=uuid4(), permit_id=uuid4(),
        trace_id="trace-test", verification="pass", execution_status="completed",
        cleanup_status="verified", created_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_audit_store_appends_and_verifies_hash_chain(tmp_path) -> None:
    store = JsonlAuditStore(tmp_path / "audit" / "receipts.jsonl")

    first_hash = await store.append(_receipt())
    second_hash = await store.append(_receipt())

    assert len(first_hash) == 64
    assert len(second_hash) == 64
    assert first_hash != second_hash
    assert await store.verify() == 2


@pytest.mark.asyncio
async def test_audit_store_rejects_tampering(tmp_path) -> None:
    path = tmp_path / "receipts.jsonl"
    store = JsonlAuditStore(path)
    await store.append(_receipt())

    record = json.loads(path.read_text(encoding="utf-8"))
    record["receipt"]["verification"] = "fail"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainError, match="audit_record_hash_invalid"):
        await store.verify()


@pytest.mark.asyncio
async def test_audit_store_does_not_persist_tool_data(tmp_path) -> None:
    store = JsonlAuditStore(tmp_path / "receipts.jsonl")
    await store.append(_receipt())

    stored = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
    assert "tool_arguments" not in stored
    assert "bearer_token" not in stored


@pytest.mark.asyncio
async def test_audit_store_coordinates_multiple_gateway_instances(tmp_path) -> None:
    path = tmp_path / "receipts.jsonl"
    first = JsonlAuditStore(path)
    second = JsonlAuditStore(path)

    await asyncio.gather(first.append(_receipt()), second.append(_receipt()))

    assert await first.verify() == 2


def test_audit_backup_restore_verifies_without_creating_lock_sidecar(tmp_path) -> None:
    source = tmp_path / "receipts.jsonl"
    backup = tmp_path / "restore" / "receipts.jsonl"
    store = JsonlAuditStore(source)

    asyncio.run(store.append(_receipt()))
    asyncio.run(store.append(_receipt()))
    backup.parent.mkdir()
    shutil.copy2(source, backup)

    assert JsonlAuditStore.verify_path(backup) == 2
    assert not backup.with_name("receipts.jsonl.lock").exists()


def test_audit_backup_restore_rejects_tampering(tmp_path) -> None:
    source = tmp_path / "receipts.jsonl"
    backup = tmp_path / "restore.jsonl"
    store = JsonlAuditStore(source)

    asyncio.run(store.append(_receipt()))
    shutil.copy2(source, backup)
    record = json.loads(backup.read_text(encoding="utf-8"))
    record["receipt"]["verification"] = "fail"
    backup.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainError, match="audit_record_hash_invalid"):
        JsonlAuditStore.verify_path(backup)


def test_audit_backup_verification_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(AuditChainError, match="audit_backup_missing"):
        JsonlAuditStore.verify_path(tmp_path / "missing.jsonl")


@pytest.mark.asyncio
async def test_audit_verification_fails_closed_when_shared_lock_is_unavailable(tmp_path, monkeypatch) -> None:
    from contextlib import contextmanager

    path = tmp_path / "receipts.jsonl"
    store = JsonlAuditStore(path)
    await store.append(_receipt())

    @contextmanager
    def unavailable_lock():
        raise OSError("shared storage lock unavailable")
        yield

    monkeypatch.setattr(store, "_exclusive_lock", unavailable_lock)
    with pytest.raises(AuditChainError, match="audit_store_unreadable"):
        await store.verify()
