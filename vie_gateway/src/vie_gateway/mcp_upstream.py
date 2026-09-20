from __future__ import annotations

from dataclasses import dataclass
from typing import Any
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

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("mcp_upstream_url_must_be_http")
        if parsed.username or parsed.password:
            raise ValueError("mcp_upstream_url_credentials_forbidden")
        if parsed.query or parsed.fragment:
            raise ValueError("mcp_upstream_url_query_forbidden")


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

        request_id = str(uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": permit.tool, "arguments": arguments},
        }
        headers = {"content-type": "application/json"}
        if self.config.bearer_token:
            headers["authorization"] = f"Bearer {self.config.bearer_token}"

        client = self._client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=self.config.timeout_seconds)
        try:
            try:
                response = await client.post(self.config.url, json=payload, headers=headers)
                response.raise_for_status()
                body = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise RuntimeErrorBoundary("mcp_upstream_unavailable") from exc
        finally:
            arguments.clear()
            if owns_client:
                await client.aclose()

        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or body.get("id") != request_id:
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
            evidence=[f"mcp-upstream:{urlsplit(self.config.url).netloc}"],
            cleanup_status="verified",
        )
