from __future__ import annotations

from uuid import UUID, uuid4
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
    runtime_image = os.environ.get("MADVA_RUNTIME_IMAGE")
    runner: Runner = (DockerRunner(DockerConfig(image=runtime_image))
                      if runtime_image else EphemeralRunner({"echo": _echo}))
    verifier, tracer = Verifier(), AuditTracer()
    credential_provider = (VaultCredentialProvider(os.environ["VAULT_ADDR"], os.environ["VAULT_TOKEN"])
                           if os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN")
                           else DenyAllCredentialProvider())
    graph = build_vie_graph(GraphDependencies(validator, oidc_validator, authorizer, IntentSigner(None),
                                              credential_provider, runner, verifier, tracer))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "madva-vie-gateway", "runtime": "docker" if runtime_image else "local"}

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
                "MADVA_RUNTIME_IMAGE": runtime_image,
            }
            issues.extend(f"missing_{name.lower()}" for name, value in required.items() if not value)
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
