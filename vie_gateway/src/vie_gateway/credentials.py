from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CredentialLease(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=1)
    host_path: str = Field(min_length=1)
    container_path: str = Field(min_length=1)
    expires_at: datetime


class CredentialProvider(Protocol):
    async def acquire(self, reference: str, session_id: UUID, expires_at: datetime) -> CredentialLease: ...


class DenyAllCredentialProvider:
    async def acquire(self, reference: str, session_id: UUID, expires_at: datetime) -> CredentialLease:
        raise PermissionError("credential_provider_not_configured")
