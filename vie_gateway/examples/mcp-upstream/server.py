from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class MCPHandler(BaseHTTPRequestHandler):
    server_version = "MADVA-MCP-Demo/1.0"

    def do_POST(self) -> None:  # noqa: N802
        expected = os.environ.get("MCP_UPSTREAM_TOKEN", "local-upstream-token")
        if self.headers.get("authorization") != f"Bearer {expected}":
            self._write({"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32001, "message": "unauthorized"}}, 401)
            return
        try:
            request: dict[str, Any] = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            params = request.get("params", {})
            result = {"echo": params.get("arguments", {}), "tool": params.get("name")}
            self._write({"jsonrpc": "2.0", "id": request.get("id"), "result": result})
        except (ValueError, TypeError, json.JSONDecodeError):
            self._write({"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32600, "message": "invalid_request"}}, 400)

    def _write(self, body: dict[str, Any], status: int = 200) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), MCPHandler).serve_forever()
