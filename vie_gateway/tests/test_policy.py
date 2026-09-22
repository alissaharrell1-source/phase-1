from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vie_gateway.contracts import IntentContract, MCPToolCall, TokenClaims
from vie_gateway.credentials import DenyAllCredentialProvider
from vie_gateway.graph import GraphDependencies, build_vie_graph
from vie_gateway.policy import PolicyApprovalError, PolicyRecord, PolicyRegistry
from vie_gateway.runtime import EphemeralRunner
from vie_gateway.security import IntentSigner, JITAuthorizer
from vie_gateway.telemetry import AuditTracer
from vie_gateway.verification import Verifier


def test_policy_registry_requires_approval_and_supports_lifecycle() -> None:
    registry = PolicyRegistry(require_approval=True)
    pending = registry.submit("vie-default", "2026.1", {"tools": ["echo"]})
    assert pending.status == "pending"
    intent = IntentContract(contract_id=uuid4(), policy_id="vie-default", policy_version="2026.1",
                            purpose="approved", tool="echo", operation="run",
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))

    with pytest.raises(PolicyApprovalError, match="policy_revision_not_approved"):
        registry.validate_intent(intent)

    approved = registry.approve("vie-default", "2026.1", "security-admin", "reviewed")
    assert approved.status == "approved"
    assert approved.approved_by == "security-admin"
    assert registry.validate_intent(intent) == approved

    revoked = registry.revoke("vie-default", "2026.1", "superseded")
    assert revoked.status == "revoked"
    with pytest.raises(PolicyApprovalError, match="policy_revision_not_approved"):
        registry.validate_intent(intent)


def test_policy_registry_requires_a_named_approver() -> None:
    registry = PolicyRegistry(require_approval=True)
    registry.submit("vie-default", "2026.1", {"tools": ["echo"]})
    with pytest.raises(PolicyApprovalError, match="policy_approver_required"):
        registry.approve("vie-default", "2026.1", "   ")


def test_policy_record_rejects_approved_revision_without_metadata() -> None:
    with pytest.raises(ValidationError, match="approved_policy_requires_metadata"):
        PolicyRecord(policy_id="vie-default", policy_version="2026.1", status="approved",
                     content_sha256="0" * 64)


@pytest.mark.asyncio
async def test_approved_policy_revision_is_propagated_to_receipt() -> None:
    registry = PolicyRegistry(require_approval=True)
    registry.submit("vie-default", "2026.1", {"tools": ["echo"]})
    registry.approve("vie-default", "2026.1", "security-admin")
    intent = IntentContract(contract_id=uuid4(), policy_id="vie-default", policy_version="2026.1",
                            purpose="approved", tool="echo", operation="run",
                            output_schema={"type": "object", "required": ["status"]},
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))
    claims = TokenClaims(agent_id="agent-1", requester_id="requester-1", intent_scope="approved",
                         exp=int(datetime.now(UTC).timestamp()) + 60, iss="madva", aud="vie-gateway", jti="jti-policy")

    class Validator:
        def validate(self, token: str) -> TokenClaims:
            return claims

    async def echo(arguments: dict[str, object]) -> dict[str, object]:
        return {"status": "ok"}

    graph = build_vie_graph(GraphDependencies(
        token_validator=Validator(), oidc_validator=None, authorizer=JITAuthorizer(),
        intent_signer=IntentSigner(""), credential_provider=DenyAllCredentialProvider(),
        runner=EphemeralRunner({"echo": echo}), verifier=Verifier(), tracer=AuditTracer(),
        policy_registry=registry,
    ))
    call = MCPToolCall(jsonrpc="2.0", id="call-policy", method="tools/call",
                       params={"arguments": {}, "intent_contract": intent.model_dump(mode="json")})

    state = await graph.ainvoke({"call": call, "authorization": "Bearer test-token"})

    assert state["receipt"].policy_id == "vie-default"
    assert state["receipt"].policy_version == "2026.1"
