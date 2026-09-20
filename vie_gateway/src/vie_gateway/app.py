from __future__ import annotations

from uuid import UUID, uuid4
from typing import Literal, cast
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from .contracts import IntentContract, MCPToolCall
from .runtime import DockerConfig, DockerRunner, EphemeralRunner, Runner
import os
import shutil
from .security import IntentSigner, JITAuthorizer, OIDCTokenValidator, TokenValidator
from .verification import Verifier
from .telemetry import AuditTracer, configure_tracing
from .graph import GraphDependencies, build_vie_graph
from .credentials import DenyAllCredentialProvider, VaultCredentialProvider
from .mcp_upstream import MCPUpstreamConfig, MCPUpstreamRunner
from .audit_store import JsonlAuditStore

async def _echo(arguments: dict[str, object]) -> dict[str, object]:
    return {"echo": arguments}

def create_app() -> FastAPI:
    app = FastAPI(title="MADVA VIE Gateway", version="0.1.0")
    configure_tracing()
    validator, authorizer = TokenValidator(), JITAuthorizer()
    oidc_validator = None
    if os.environ.get("MADVA_OIDC_JWKS_URL"):
        oidc_validator = OIDCTokenValidator(
            jwks_uri=os.environ["MADVA_OIDC_JWKS_URL"],
            issuer=os.environ.get("MADVA_OIDC_ISSUER", ""),
            audience=os.environ.get("MADVA_OIDC_AUDIENCE", "vie-gateway"),
        )
    verifier, tracer = Verifier(), AuditTracer()
    audit_path = os.environ.get("MADVA_AUDIT_LOG_PATH")
    audit_store = JsonlAuditStore(audit_path) if audit_path else None
    runtime_image = os.environ.get("MADVA_RUNTIME_IMAGE")
    upstream_url = os.environ.get("MADVA_MCP_UPSTREAM_URL")
    upstream_allowed_hosts = frozenset(
        host.strip().lower().rstrip(".")
        for host in os.environ.get("MADVA_MCP_UPSTREAM_ALLOWED_HOSTS", "").split(",")
        if host.strip()
    )
    lifecycle_value = os.environ.get("MADVA_MCP_UPSTREAM_LIFECYCLE", "stateless")
    if lifecycle_value not in {"stateless", "legacy"}:
        raise ValueError("mcp_upstream_lifecycle_invalid")
    upstream_lifecycle = cast(Literal["stateless", "legacy"], lifecycle_value)
    runner: Runner
    if upstream_url:
        runner = MCPUpstreamRunner(MCPUpstreamConfig(
            url=upstream_url,
            timeout_seconds=float(os.environ.get("MADVA_MCP_UPSTREAM_TIMEOUT", "30")),
            bearer_token=os.environ.get("MADVA_MCP_UPSTREAM_TOKEN"),
            allowed_hosts=upstream_allowed_hosts,
            protocol_version=os.environ.get("MADVA_MCP_UPSTREAM_PROTOCOL_VERSION", "2026-07-28"),
            lifecycle=upstream_lifecycle,
        ), tracer=tracer)
    else:
        runner = (DockerRunner(DockerConfig(image=runtime_image))
                  if runtime_image else EphemeralRunner({"echo": _echo}))
    credential_provider = (VaultCredentialProvider(os.environ["VAULT_ADDR"], os.environ["VAULT_TOKEN"])
                           if os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN")
                           else DenyAllCredentialProvider())
    graph = build_vie_graph(GraphDependencies(validator, oidc_validator, authorizer, IntentSigner(None),
                                              credential_provider, runner, verifier, tracer, audit_store))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        runtime = "mcp-upstream" if upstream_url else "docker" if runtime_image else "local"
        return {"status": "ok", "service": "madva-vie-gateway", "runtime": runtime}

    @app.get("/readyz", response_model=None)
    async def readyz() -> JSONResponse | dict[str, str]:
        issues: list[str] = []
        if runtime_image and shutil.which("docker") is None:
            issues.append("docker_unavailable")
        if os.environ.get("MADVA_PRODUCTION", "false").lower() == "true":
            required = {
                "MADVA_OIDC_JWKS_URL": os.environ.get("MADVA_OIDC_JWKS_URL"),
                "MADVA_OIDC_ISSUER": os.environ.get("MADVA_OIDC_ISSUER"),
                "MADVA_INTENT_SECRET": os.environ.get("MADVA_INTENT_SECRET"),
            }
            issues.extend(f"missing_{name.lower()}" for name, value in required.items() if not value)
            if not runtime_image and not upstream_url:
                issues.append("missing_execution_backend")
            if upstream_url and not upstream_allowed_hosts:
                issues.append("missing_madva_mcp_upstream_allowed_hosts")
            if not audit_path:
                issues.append("missing_madva_audit_log_path")
        if issues:
            return JSONResponse(status_code=503, content={"status": "not_ready", "issues": issues})
        return {"status": "ready"}

    @app.post("/mcp", response_model=None)
    async def mcp_proxy(call: MCPToolCall, authorization: str = Header(default="")) -> dict[str, object] | JSONResponse:
        if not authorization.startswith("Bearer "):
            return JSONResponse(status_code=200, content={
                "jsonrpc": "2.0", "id": call.id,
                "error": {"code": -32001, "message": "missing_bearer_token"},
            })
        state = await graph.ainvoke({"call": call, "authorization": authorization})
        if state.get("error"):
            error = state["error"]
            code = -32600 if error == "invalid_mcp_request" else -32001 if error == "missing_bearer_token" else -32002
            return JSONResponse(status_code=200, content={
                "jsonrpc": "2.0", "id": call.id,
                "error": {"code": code, "message": error},
            })
        result = state["execution"]
        receipt = state["receipt"]
        return {"jsonrpc": "2.0", "id": call.id,
                "result": {"output": result.output, "audit_receipt": receipt.model_dump(mode="json")}}

    return app

app = create_app()
