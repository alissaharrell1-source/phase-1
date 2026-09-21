from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from vie_gateway.audit_store import AuditChainError, AuditStore
from vie_gateway.contracts import AuditReceipt, IntentContract, MCPToolCall, Permit, TokenClaims
from vie_gateway.credentials import CredentialLease, CredentialProvider, DenyAllCredentialProvider
from vie_gateway.graph import GraphDependencies, build_vie_graph
from vie_gateway.policy import PolicyRegistry
from vie_gateway.runtime import EphemeralRunner, RuntimeErrorBoundary
from vie_gateway.security import IntentSigner, JITAuthorizer
from vie_gateway.telemetry import AuditTracer
from vie_gateway.verification import Verifier


class Validator:
    def __init__(self) -> None:
        self.claims = TokenClaims(
            agent_id="failure-agent", requester_id="failure-requester", intent_scope="failure-purpose",
            exp=int(datetime.now(UTC).timestamp()) + 60, iss="madva", aud="vie-gateway", jti=str(uuid4()),
        )

    def validate(self, token: str) -> TokenClaims:
        return self.claims


def _intent(**updates: object) -> IntentContract:
    return IntentContract(
        contract_id=uuid4(), purpose="failure-purpose", tool="echo", operation="run",
        expires_at=datetime.now(UTC) + timedelta(minutes=1), **updates,
    )


def _call(intent: IntentContract) -> MCPToolCall:
    return MCPToolCall(jsonrpc="2.0", id="failure-call", method="tools/call",
                       params={"arguments": {}, "intent_contract": intent.model_dump(mode="json")})


def _dependencies(*, runner, credential_provider: CredentialProvider | None = None,
                  audit_store: AuditStore | None = None, policy_registry: PolicyRegistry | None = None) -> GraphDependencies:
    return GraphDependencies(
        token_validator=Validator(), oidc_validator=None, authorizer=JITAuthorizer(),
        intent_signer=IntentSigner(""), credential_provider=credential_provider or DenyAllCredentialProvider(),
        runner=runner, verifier=Verifier(), tracer=AuditTracer(), audit_store=audit_store,
        policy_registry=policy_registry,
    )


@pytest.mark.asyncio
async def test_runtime_failure_still_releases_every_credential_lease() -> None:
    released: list[CredentialLease] = []
    lease = CredentialLease(reference="vault://secret/tool#value", host_path="C:/lease", container_path="/run/secrets/value",
                            expires_at=datetime.now(UTC) + timedelta(minutes=1))

    class Provider:
        async def acquire(self, reference: str, session_id, expires_at: datetime) -> CredentialLease:
            return lease

        async def release(self, value: CredentialLease) -> None:
            released.append(value)

    class FailingRunner:
        async def run(self, permit: Permit, arguments: dict[str, object], credential_leases=None):
            raise RuntimeErrorBoundary("injected_runtime_failure")

    state = await build_vie_graph(_dependencies(runner=FailingRunner(), credential_provider=Provider())).ainvoke(
        {"call": _call(_intent(credential_refs=[lease.reference])), "authorization": "Bearer test"})

    assert state["error"] == "injected_runtime_failure"
    assert released == [lease]


@pytest.mark.asyncio
async def test_unapproved_policy_prevents_infrastructure_execution() -> None:
    registry = PolicyRegistry(require_approval=True)
    registry.submit("policy", "draft-1", {"tools": ["echo"]})
    executed: list[bool] = []

    async def handler(arguments: dict[str, object]) -> dict[str, object]:
        executed.append(True)
        return {"status": "unexpected"}

    intent = _intent(policy_id="policy", policy_version="draft-1")
    state = await build_vie_graph(_dependencies(
        runner=EphemeralRunner({"echo": handler}), policy_registry=registry,
    )).ainvoke({"call": _call(intent), "authorization": "Bearer test"})

    assert state["error"] == "policy_revision_not_approved"
    assert executed == []


@pytest.mark.asyncio
async def test_audit_persistence_failure_blocks_success_response() -> None:
    class FailingAuditStore:
        async def append(self, receipt: AuditReceipt) -> str:
            raise AuditChainError("injected_audit_failure")

        async def verify(self) -> int:
            return 0

    async def echo(arguments: dict[str, object]) -> dict[str, object]:
        return {"status": "ok"}

    state = await build_vie_graph(_dependencies(
        runner=EphemeralRunner({"echo": echo}), audit_store=FailingAuditStore(),
    )).ainvoke({"call": _call(_intent()), "authorization": "Bearer test"})

    assert state["error"] == "audit_persistence_failed"
    assert state["stage"] == "failed"
    assert "receipt" not in state
