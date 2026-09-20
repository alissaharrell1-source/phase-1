from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Protocol

from .contracts import AuditReceipt


class AuditChainError(RuntimeError):
    """Raised when a persisted audit chain is missing, malformed, or modified."""


class AuditStore(Protocol):
    async def append(self, receipt: AuditReceipt) -> str: ...

    async def verify(self) -> int: ...


class JsonlAuditStore:
    """Append-only, locally durable audit storage with a SHA-256 hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()

    @staticmethod
    def _canonical(sequence: int, previous_hash: str, receipt: dict[str, object]) -> bytes:
        return json.dumps(
            {"sequence": sequence, "previous_hash": previous_hash, "receipt": receipt},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _record_hash(cls, sequence: int, previous_hash: str, receipt: dict[str, object]) -> str:
        return hashlib.sha256(cls._canonical(sequence, previous_hash, receipt)).hexdigest()

    @classmethod
    def _verify_lines(cls, lines: list[str]) -> tuple[int, str]:
        previous_hash = ""
        for expected_sequence, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditChainError("audit_record_invalid_json") from exc
            if not isinstance(record, dict):
                raise AuditChainError("audit_record_not_object")
            sequence = record.get("sequence")
            record_previous = record.get("previous_hash")
            receipt = record.get("receipt")
            record_hash = record.get("record_hash")
            if sequence != expected_sequence or not isinstance(record_previous, str):
                raise AuditChainError("audit_sequence_invalid")
            if record_previous != previous_hash or not isinstance(receipt, dict):
                raise AuditChainError("audit_chain_link_invalid")
            if not isinstance(record_hash, str) or record_hash != cls._record_hash(
                sequence, record_previous, receipt
            ):
                raise AuditChainError("audit_record_hash_invalid")
            previous_hash = record_hash
        return len(lines), previous_hash

    def _read_verified(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, ""
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                lines = [line.rstrip("\n") for line in handle]
        except OSError as exc:
            raise AuditChainError("audit_store_unreadable") from exc
        return self._verify_lines(lines)

    def _append_sync(self, receipt: AuditReceipt) -> str:
        sequence, previous_hash = self._read_verified()
        receipt_data = receipt.model_dump(mode="json")
        next_sequence = sequence + 1
        record_hash = self._record_hash(next_sequence, previous_hash, receipt_data)
        record = {
            "sequence": next_sequence,
            "previous_hash": previous_hash,
            "receipt": receipt_data,
            "record_hash": record_hash,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditChainError("audit_store_write_failed") from exc
        return record_hash

    async def append(self, receipt: AuditReceipt) -> str:
        async with self._lock:
            return await asyncio.to_thread(self._append_sync, receipt)

    async def verify(self) -> int:
        async with self._lock:
            return await asyncio.to_thread(lambda: self._read_verified()[0])
