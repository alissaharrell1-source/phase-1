from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import tempfile
from typing import Protocol
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field


class CredentialLease(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=1)
    host_path: str = Field(min_length=1)
    container_path: str = Field(min_length=1)
    expires_at: datetime


class CredentialProvider(Protocol):
    async def acquire(self, reference: str, session_id: UUID, expires_at: datetime) -> CredentialLease: ...

    async def release(self, lease: CredentialLease) -> None: ...


class DenyAllCredentialProvider:
    async def acquire(self, reference: str, session_id: UUID, expires_at: datetime) -> CredentialLease:
        raise PermissionError("credential_provider_not_configured")

    async def release(self, lease: CredentialLease) -> None:
        return None


class VaultCredentialProvider:
    """Fetch a Vault KV value into a short-lived, opaque lease file.

    References use ``vault://<mount>/<path>#<field>``. Secret contents never
    enter graph state, logs, command arguments, or the CredentialLease model.
    """

    def __init__(self, address: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None,
                 lease_root: str | None = None) -> None:
        self.address = address.rstrip("/")
        self.token = token
        self.transport = transport
        self.lease_root = Path(lease_root) if lease_root else None

    @staticmethod
    def _parse_reference(reference: str) -> tuple[str, str, str]:
        if not reference.startswith("vault://") or "#" not in reference:
            raise PermissionError("invalid_vault_reference")
        location, field = reference[8:].split("#", 1)
        parts = location.split("/", 1)
        if len(parts) != 2 or not all(parts) or not field or any(part in {".", ".."} for part in parts):
            raise PermissionError("invalid_vault_reference")
        return parts[0], parts[1], field

    async def acquire(self, reference: str, session_id: UUID, expires_at: datetime) -> CredentialLease:
        mount, path, field = self._parse_reference(reference)
        url = f"{self.address}/v1/{mount}/data/{path}"
        async with httpx.AsyncClient(timeout=5.0, transport=self.transport) as client:
            response = await client.get(url, headers={"X-Vault-Token": self.token})
        if response.status_code != 200:
            raise PermissionError("vault_credential_unavailable")
        try:
            value = response.json()["data"]["data"][field]
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("vault_credential_field_unavailable") from exc
        if not isinstance(value, str) or not value:
            raise PermissionError("vault_credential_must_be_nonempty_string")

        directory = Path(tempfile.mkdtemp(prefix=f"madva-lease-{session_id}-", dir=self.lease_root))
        host_path = directory / "secret"
        try:
            descriptor = os.open(host_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(value)
        except OSError as exc:
            try:
                host_path.unlink(missing_ok=True)
                directory.rmdir()
            except OSError:
                pass
            raise PermissionError("vault_lease_write_failed") from exc
        return CredentialLease(reference=reference, host_path=str(host_path),
                               container_path=f"/run/secrets/{field}", expires_at=expires_at)

    async def release(self, lease: CredentialLease) -> None:
        path = Path(lease.host_path)
        try:
            path.unlink(missing_ok=True)
            path.parent.rmdir()
        except OSError:
            return None
