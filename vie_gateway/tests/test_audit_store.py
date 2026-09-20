import json
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
