from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class IntentContract(StrictModel):
    contract_id: UUID
    schema_version: str = "1.0.0"
    tenant_id: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    purpose: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    resource: dict[str, Any] = Field(default_factory=dict)
    arguments: dict[str, Any] = Field(default_factory=dict)
    arguments_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    credential_refs: list[str] = Field(default_factory=list)
    signature: str | None = None
    side_effect_class: Literal["read", "write", "external"] = "read"
    expires_at: datetime

class TokenClaims(StrictModel):
    # OIDC providers add standard claims beyond the gateway binding contract.
    model_config = ConfigDict(extra="ignore")
    agent_id: str = Field(min_length=1)
    requester_id: str = Field(min_length=1)
    tenant_id: str | None = None
    intent_scope: str = Field(min_length=1)
    exp: int
    iss: str
    aud: str | list[str]
    jti: str = Field(min_length=1)

class MCPToolCall(StrictModel):
    jsonrpc: Literal["2.0"]
    id: int | str
    method: Literal["tools/call"]
    params: dict[str, Any]

class Permit(StrictModel):
    permit_id: UUID
    agent_id: str
    requester_id: str
    tenant_id: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    intent_scope: str
    tool: str
    operation: str
    contract_id: UUID
    expires_at: datetime
    single_use: bool = True

class ExecutionResult(StrictModel):
    status: Literal["completed", "failed"]
    output: Any = None
    session_id: UUID
    evidence: list[str] = Field(default_factory=list)
    cleanup_status: Literal["verified", "incomplete", "unknown"] = "unknown"

class AuditReceipt(StrictModel):
    schema_version: str = "1.0.0"
    receipt_id: UUID
    correlation_id: UUID
    contract_id: UUID
    permit_id: UUID
    tenant_id: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    trace_id: str
    verification: Literal["pass", "conditional_pass", "fail", "needs_investigation"]
    findings: list[str] = Field(default_factory=list)
    execution_status: str
    cleanup_status: Literal["verified", "incomplete", "unknown"]
    created_at: datetime
