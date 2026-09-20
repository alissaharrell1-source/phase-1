from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC
from typing import Any, TypedDict
from uuid import UUID, uuid4

from langgraph.graph import END, StateGraph

from .audit_store import AuditStore, JsonlAuditStore
from .contracts import AuditReceipt, ExecutionResult, IntentContract, MCPToolCall, Permit, TokenClaims
from .credentials import CredentialProvider
from .runtime import EphemeralRunner, Runner, RuntimeErrorBoundary
from .security import AuthorizationError, IntentSigner, JITAuthorizer, OIDCTokenValidator, TokenValidator
from .telemetry import AuditTracer
from .verification import Verifier


class VIEState(TypedDict, total=False):
    call: MCPToolCall
    authorization: str
    correlation_id: UUID
    intent: IntentContract
    arguments: dict[str, Any]
    claims: TokenClaims
    permit: Permit
    execution: ExecutionResult
    receipt: AuditReceipt
    stage: str
    error: str


@dataclass(frozen=True)
class GraphDependencies:
    token_validator: TokenValidator
    oidc_validator: OIDCTokenValidator | None
    authorizer: JITAuthorizer
    intent_signer: IntentSigner
    credential_provider: CredentialProvider
    runner: Runner
    verifier: Verifier
    tracer: AuditTracer
    audit_store: AuditStore | None = None


def build_vie_graph(dependencies: GraphDependencies):
    """Build an isolated Architect→Security→Infrastructure→Verification graph."""

    async def architect(state: VIEState) -> VIEState:
        try:
            call = state["call"]
            params = call.params
            arguments = dict(params.get("arguments", {}))
            intent = IntentContract.model_validate(params["intent_contract"])
            dependencies.intent_signer.verify(intent)
            return {
                "intent": intent,
                "arguments": arguments,
                "authorization": state.get("authorization", ""),
                "correlation_id": UUID(str(params.get("correlation_id", uuid4()))),
                "stage": "architect_complete",
            }
        except AuthorizationError as exc:
            return {"stage": "failed", "error": str(exc)}
        except (KeyError, ValueError, TypeError) as exc:
            return {"stage": "failed", "error": "invalid_mcp_request"}

    async def security(state: VIEState) -> VIEState:
        try:
            authorization = state.get("authorization", "")
            if not authorization.startswith("Bearer "):
                return {"stage": "failed", "error": "missing_bearer_token"}
            bearer = authorization.removeprefix("Bearer ").strip()
            oidc = dependencies.oidc_validator
            claims = await oidc.validate(bearer) if oidc is not None else dependencies.token_validator.validate(bearer)
            intent = state["intent"]
            permit = dependencies.authorizer.authorize(
                claims, intent, intent.tool, intent.operation, state.get("arguments", {}))
            return {"claims": claims, "permit": permit, "stage": "security_complete"}
        except AuthorizationError as exc:
            return {"stage": "failed", "error": str(exc)}

    async def infrastructure(state: VIEState) -> VIEState:
        leases = []
        try:
            intent = state["intent"]
            leases = [await dependencies.credential_provider.acquire(ref, state["correlation_id"], intent.expires_at)
                      for ref in intent.credential_refs]
            execution = await dependencies.runner.run(state["permit"], state.get("arguments", {}), leases)
            return {"execution": execution, "stage": "infrastructure_complete"}
        except (RuntimeErrorBoundary, PermissionError) as exc:
            return {"stage": "failed", "error": str(exc)}
        finally:
            for lease in leases:
                await dependencies.credential_provider.release(lease)

    async def verification(state: VIEState) -> VIEState:
        intent = state["intent"]
        permit = state["permit"]
        with dependencies.tracer.span("vie.verify", contract_id=str(intent.contract_id)):
            receipt = dependencies.verifier.verify(
                state["correlation_id"], intent, permit, state["execution"],
                trace_id=dependencies.tracer.current_trace_id(f"local-{state['correlation_id']}"))
            span = dependencies.tracer.current_span()
            if span is not None:
                span.set_attribute("verification.outcome", receipt.verification)
                span.set_attribute("verification.finding_count", str(len(receipt.findings)))
                span.set_attribute("verification.execution_status", receipt.execution_status)
                span.set_attribute("verification.cleanup_status", receipt.cleanup_status)
        if dependencies.audit_store is not None:
            await dependencies.audit_store.append(receipt)
        return {"receipt": receipt, "stage": "verification_complete"}

    def route(state: VIEState) -> str:
        return "failed" if state.get("stage") == "failed" else "next"

    graph = StateGraph(VIEState)
    graph.add_node("architect", architect)
    graph.add_node("security", security)
    graph.add_node("infrastructure", infrastructure)
    graph.add_node("verification", verification)
    graph.set_entry_point("architect")
    graph.add_conditional_edges("architect", route, {"next": "security", "failed": END})
    graph.add_conditional_edges("security", route, {"next": "infrastructure", "failed": END})
    graph.add_conditional_edges("infrastructure", route, {"next": "verification", "failed": END})
    graph.add_edge("verification", END)
    return graph.compile()


def default_dependencies() -> GraphDependencies:
    from .app import _echo

    oidc_validator = None
    if os.environ.get("MADVA_OIDC_JWKS_URL"):
        oidc_validator = OIDCTokenValidator(
            jwks_uri=os.environ["MADVA_OIDC_JWKS_URL"],
            issuer=os.environ.get("MADVA_OIDC_ISSUER", ""),
            audience=os.environ.get("MADVA_OIDC_AUDIENCE", "vie-gateway"),
        )
    from .credentials import DenyAllCredentialProvider, VaultCredentialProvider
    credential_provider = (VaultCredentialProvider(os.environ["VAULT_ADDR"], os.environ["VAULT_TOKEN"])
                           if os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN")
                           else DenyAllCredentialProvider())
    audit_path = os.environ.get("MADVA_AUDIT_LOG_PATH")
    audit_store = JsonlAuditStore(audit_path) if audit_path else None
    return GraphDependencies(TokenValidator(), oidc_validator, JITAuthorizer(), IntentSigner(None), credential_provider,
                             EphemeralRunner({"echo": _echo}), Verifier(), AuditTracer(), audit_store)
