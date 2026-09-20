from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from .contracts import ExecutionResult, Permit
from .credentials import CredentialLease
from .runtime import RuntimeErrorBoundary


@dataclass(frozen=True)
class MCPUpstreamConfig:
    url: str
    timeout_seconds: float = 30.0
    bearer_token: str | None = None
    allowed_hosts: frozenset[str] = frozenset()
    protocol_version: str = "2026-07-28"
    client_name: str = "madva-vie-gateway"
    client_version: str = "0.1.0"
    lifecycle: Literal["stateless", "legacy"] = "stateless"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("mcp_upstream_url_must_be_http")
        if parsed.username or parsed.password:
            raise ValueError("mcp_upstream_url_credentials_forbidden")
        if parsed.query or parsed.fragment:
            raise ValueError("mcp_upstream_url_query_forbidden")
        if self.lifecycle not in {"stateless", "legacy"}:
            raise ValueError("mcp_upstream_lifecycle_invalid")


class MCPUpstreamRunner:
    """Forward one approved call to an MCP JSON-RPC server."""

    def __init__(self, config: MCPUpstreamConfig,
                 client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._client = client

    async def run(self, permit: Permit, arguments: dict[str, Any],
                  credential_leases: list[CredentialLease] | None = None) -> ExecutionResult:
        if credential_leases:
            raise RuntimeErrorBoundary("upstream_credentials_unsupported")
        hostname = (urlsplit(self.config.url).hostname or "").lower().rstrip(".")
        if self.config.allowed_hosts and hostname not in self.config.allowed_hosts:
            raise RuntimeErrorBoundary("mcp_upstream_host_not_allowed")

        client = self._client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=self.config.timeout_seconds)
        try:
            session_id: str | None = None
            if self.config.lifecycle == "legacy":
                initialize_id = str(uuid4())
                initialize_body = await self._post_json(
                    client,
                    {"jsonrpc": "2.0", "id": initialize_id, "method": "initialize",
                     "params": {"protocolVersion": self.config.protocol_version,
                                 "capabilities": {},
                                 "clientInfo": {"name": self.config.client_name,
                                                 "version": self.config.client_version}}},
                    self._headers("initialize"),
                )
                if initialize_body.get("id") != initialize_id or "result" not in initialize_body:
                    raise RuntimeErrorBoundary("mcp_upstream_initialize_failed")
                session_id = initialize_body.get("_session_id")
                notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                await self._post_notification(client, notification, self._headers("notifications/initialized", session_id))

            request_id = str(uuid4())
            payload = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": permit.tool,
                    "arguments": arguments,
                    "_meta": {
                        "io.modelcontextprotocol/clientInfo": {
                            "name": self.config.client_name,
                            "version": self.config.client_version,
                        },
                    },
                },
            }
            body = await self._post_json(client, payload, self._headers("tools/call", session_id, permit.tool))
        except RuntimeErrorBoundary:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeErrorBoundary("mcp_upstream_unavailable") from exc
        finally:
            arguments.clear()
            if owns_client:
                await client.aclose()

        if body.get("id") != request_id:
            raise RuntimeErrorBoundary("mcp_upstream_invalid_response")
        if body.get("error") is not None:
            error = body["error"]
            message = str(error.get("message", "upstream_tool_error"))[:200] if isinstance(error, dict) else "upstream_tool_error"
            raise RuntimeErrorBoundary(f"mcp_upstream_error:{message}")
        if "result" not in body:
            raise RuntimeErrorBoundary("mcp_upstream_missing_result")

        return ExecutionResult(
            status="completed",
            output=body["result"],
            session_id=uuid4(),
            evidence=[f"mcp-upstream:{urlsplit(self.config.url).netloc}",
                      f"mcp-lifecycle:{self.config.lifecycle}"],
            cleanup_status="verified",
        )

    def _headers(self, method: str, session_id: str | None = None,
                 tool: str | None = None) -> dict[str, str]:
        headers = {"content-type": "application/json",
                   "MCP-Protocol-Version": self.config.protocol_version,
                   "Mcp-Method": method}
        if tool:
            headers["Mcp-Name"] = tool
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if self.config.bearer_token:
            headers["authorization"] = f"Bearer {self.config.bearer_token}"
        return headers

    async def _post_json(self, client: httpx.AsyncClient, payload: dict[str, Any],
                         headers: dict[str, str]) -> dict[str, Any]:
        response = await client.post(self.config.url, json=payload, headers=headers)
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError as exc:
            raise RuntimeErrorBoundary("mcp_upstream_invalid_response") from exc
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            raise RuntimeErrorBoundary("mcp_upstream_invalid_response")
        if body.get("error") is not None:
            error = body["error"]
            message = str(error.get("message", "upstream_tool_error"))[:200] if isinstance(error, dict) else "upstream_tool_error"
            raise RuntimeErrorBoundary(f"mcp_upstream_error:{message}")
        session_id = response.headers.get("mcp-session-id")
        if session_id:
            body["_session_id"] = session_id
        return body

    async def _post_notification(self, client: httpx.AsyncClient, payload: dict[str, Any],
                                 headers: dict[str, str]) -> None:
        response = await client.post(self.config.url, json=payload, headers=headers)
        response.raise_for_status()
