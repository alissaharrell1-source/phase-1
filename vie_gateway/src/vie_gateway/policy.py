from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .contracts import IntentContract


class PolicyApprovalError(ValueError):
    """Raised when an Intent Contract references an unavailable policy revision."""


class PolicyRecord(BaseModel):
    """Immutable approval metadata for one policy revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    policy_id: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    status: Literal["draft", "pending", "approved", "rejected", "revoked"] = "draft"
    content_sha256: str = Field(min_length=64, max_length=64)
    approved_by: str | None = None
    approved_at: datetime | None = None
    decision_reason: str | None = None


class PolicyRegistry:
    """In-memory, versioned policy registry loaded from an administrator-owned file.

    Registration and approval are explicit state transitions. Runtime authorization
    only resolves approved revisions when ``require_approval`` is enabled.
    """

    def __init__(self, records: list[PolicyRecord] | None = None, require_approval: bool = False) -> None:
        self.require_approval = require_approval
        self._records: dict[tuple[str, str], PolicyRecord] = {}
        for record in records or []:
            self.register(record)

    @classmethod
    def from_environment(cls, require_approval: bool | None = None) -> "PolicyRegistry":
        import os

        required = require_approval if require_approval is not None else (
            os.environ.get("MADVA_PRODUCTION", "false").lower() == "true"
            or os.environ.get("MADVA_REQUIRE_APPROVED_POLICY", "false").lower() == "true"
        )
        path = os.environ.get("MADVA_POLICY_REGISTRY_PATH")
        return cls.from_file(path, required) if path else cls(require_approval=required)

    @classmethod
    def from_file(cls, path: str, require_approval: bool = True) -> "PolicyRegistry":
        try:
            body = json.loads(Path(path).read_text(encoding="utf-8"))
            records = body["policies"] if isinstance(body, dict) else body
            if not isinstance(records, list):
                raise ValueError("policies_must_be_a_list")
            return cls([PolicyRecord.model_validate(item) for item in records], require_approval)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise PolicyApprovalError("policy_registry_invalid") from exc

    def register(self, record: PolicyRecord) -> None:
        key = (record.policy_id, record.policy_version)
        if key in self._records:
            raise PolicyApprovalError("policy_revision_already_registered")
        self._records[key] = record

    def submit(self, policy_id: str, policy_version: str, content: object) -> PolicyRecord:
        """Register a draft revision using a canonical content digest."""
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        record = PolicyRecord(policy_id=policy_id, policy_version=policy_version,
                              content_sha256=hashlib.sha256(canonical).hexdigest(), status="pending")
        self.register(record)
        return record

    def approve(self, policy_id: str, policy_version: str, approver: str,
                reason: str | None = None) -> PolicyRecord:
        record = self._get(policy_id, policy_version)
        if record.status not in {"pending", "draft"}:
            raise PolicyApprovalError("policy_revision_not_approvable")
        approved = record.model_copy(update={"status": "approved", "approved_by": approver,
                                             "approved_at": datetime.now(UTC), "decision_reason": reason})
        self._records[(policy_id, policy_version)] = approved
        return approved

    def reject(self, policy_id: str, policy_version: str, reason: str) -> PolicyRecord:
        record = self._get(policy_id, policy_version)
        if record.status not in {"pending", "draft"}:
            raise PolicyApprovalError("policy_revision_not_rejectable")
        rejected = record.model_copy(update={"status": "rejected", "decision_reason": reason})
        self._records[(policy_id, policy_version)] = rejected
        return rejected

    def revoke(self, policy_id: str, policy_version: str, reason: str) -> PolicyRecord:
        record = self._get(policy_id, policy_version)
        if record.status != "approved":
            raise PolicyApprovalError("policy_revision_not_revokeable")
        revoked = record.model_copy(update={"status": "revoked", "decision_reason": reason})
        self._records[(policy_id, policy_version)] = revoked
        return revoked

    def validate_intent(self, intent: IntentContract) -> PolicyRecord | None:
        if intent.policy_id is None or intent.policy_version is None:
            if self.require_approval:
                raise PolicyApprovalError("policy_binding_required")
            return None
        record = self._records.get((intent.policy_id, intent.policy_version))
        if record is None:
            if self.require_approval:
                raise PolicyApprovalError("policy_revision_not_registered")
            return None
        if self.require_approval and record.status != "approved":
            raise PolicyApprovalError("policy_revision_not_approved")
        return record

    def _get(self, policy_id: str, policy_version: str) -> PolicyRecord:
        record = self._records.get((policy_id, policy_version))
        if record is None:
            raise PolicyApprovalError("policy_revision_not_registered")
        return record
