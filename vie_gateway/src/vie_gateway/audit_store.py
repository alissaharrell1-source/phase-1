from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol, cast

from .contracts import AuditReceipt


class AuditChainError(RuntimeError):
    """Raised when a persisted audit chain is missing, malformed, or modified."""


class AuditStore(Protocol):
    async def append(self, receipt: AuditReceipt) -> str: ...

    async def verify(self) -> int: ...


class JsonlAuditStore:
    """Append-only, durable audit storage with a SHA-256 hash chain.

    The sidecar lock coordinates writers from multiple gateway processes when
    the path is backed by a locking-capable shared filesystem.
    """

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
        return self._read_verified_path(self.path)

    @classmethod
    def _read_verified_path(cls, path: Path) -> tuple[int, str]:
        if not path.exists():
            return 0, ""
        try:
            with path.open("r", encoding="utf-8") as handle:
                lines = [line.rstrip("\n") for line in handle]
        except OSError as exc:
            raise AuditChainError("audit_store_unreadable") from exc
        return cls._verify_lines(lines)

    @classmethod
    def verify_path(cls, path: str | Path) -> int:
        """Verify an audit file without creating or acquiring a lock sidecar.

        This is intended for backup and restore validation. Callers should
        validate a consistent filesystem snapshot or a quiesced backup rather
        than a file that is actively being appended.
        """
        backup_path = Path(path)
        if not backup_path.is_file():
            raise AuditChainError("audit_backup_missing")
        return cls._read_verified_path(backup_path)[0]

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        lock_path = self.path.with_name(f"{self.path.name}.lock")
        with lock_path.open("a+", encoding="ascii") as handle:
            if os.name == "nt":
                import msvcrt

                msvcrt_module = cast(Any, msvcrt)
                handle.seek(0)
                handle.write("0")
                handle.flush()
                handle.seek(0)
                msvcrt_module.locking(handle.fileno(), msvcrt_module.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt_module.locking(handle.fileno(), msvcrt_module.LK_UNLCK, 1)
            else:
                import fcntl as fcntl_module

                fcntl = cast(Any, fcntl_module)

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _append_sync(self, receipt: AuditReceipt) -> str:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._exclusive_lock():
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
            def verify_sync() -> int:
                if not self.path.exists():
                    return 0
                try:
                    with self._exclusive_lock():
                        return self._read_verified()[0]
                except OSError as exc:
                    raise AuditChainError("audit_store_unreadable") from exc

            return await asyncio.to_thread(verify_sync)
