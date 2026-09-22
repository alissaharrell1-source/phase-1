from __future__ import annotations

import asyncio
import copy
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal, Protocol
from uuid import UUID, uuid4
from .contracts import ExecutionResult, Permit
from .credentials import CredentialLease

class RuntimeErrorBoundary(RuntimeError):
    pass

ToolHandler = Callable[[dict[str, Any]], Awaitable[Any]]


class Runner(Protocol):
    async def run(self, permit: Permit, arguments: dict[str, Any],
                  credential_leases: list[CredentialLease] | None = None) -> ExecutionResult: ...

@dataclass
class EphemeralRunner:
    handlers: dict[str, ToolHandler]

    async def run(self, permit: Permit, arguments: dict[str, Any],
                  credential_leases: list[CredentialLease] | None = None) -> ExecutionResult:
        if credential_leases:
            raise RuntimeErrorBoundary("credentials_unsupported_by_local_runner")
        from uuid import uuid4
        session_id = uuid4()
        handler = self.handlers.get(permit.tool)
        if handler is None:
            raise RuntimeErrorBoundary("tool_not_available")
        try:
            output = await asyncio.wait_for(handler(arguments), timeout=30)
            output_snapshot = copy.deepcopy(output)
            return ExecutionResult(status="completed", output=output_snapshot, session_id=session_id,
                                   evidence=[f"session:{session_id}"], cleanup_status="verified")
        except asyncio.TimeoutError as exc:
            raise RuntimeErrorBoundary("execution_timeout") from exc
        finally:
            arguments.clear()


@dataclass(frozen=True)
class DockerConfig:
    image: str
    executable: str = "docker"
    timeout_seconds: float = 30.0
    memory: str = "512m"
    cpus: str = "1.0"


class DockerRunner:
    """Execute one approved call in a disposable, restricted Docker session.

    The configured image must contain an entrypoint that reads one JSON object
    from stdin and writes one JSON object to stdout. Image admission and digest
    verification belong to deployment policy, not to this adapter.
    """

    def __init__(self, config: DockerConfig) -> None:
        if not config.image or "@sha256:" not in config.image:
            raise ValueError("docker_image_must_be_immutable_digest")
        self.config = config

    def command(self, credential_leases: list[CredentialLease] | None = None, cidfile: str | None = None) -> list[str]:
        command = [
            self.config.executable, "run", "--rm", "-i",
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=64",
            # This is a container-internal tmpfs mount, not a host temp path.
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",  # nosec B108
            "--memory", self.config.memory, "--cpus", self.config.cpus,
        ]
        if cidfile:
            command.extend(["--cidfile", cidfile])
        for lease in credential_leases or []:
            command.extend(["--mount", f"type=bind,src={lease.host_path},dst={lease.container_path},readonly"])
        command.append(self.config.image)
        return command

    async def _cleanup_verified(self, cidfile: str) -> bool:
        try:
            with open(cidfile, encoding="ascii") as handle:
                container_id = handle.read().strip()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return False
        if not container_id:
            return False
        inspect = await asyncio.create_subprocess_exec(
            self.config.executable, "inspect", container_id,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await inspect.wait()
        return inspect.returncode != 0

    async def _force_remove(self, cidfile: str) -> bool:
        try:
            with open(cidfile, encoding="ascii") as handle:
                container_id = handle.read().strip()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return False
        if not container_id:
            return False
        remove = await asyncio.create_subprocess_exec(
            self.config.executable, "rm", "-f", container_id,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await remove.wait()
        return await self._cleanup_verified(cidfile)

    @staticmethod
    def _remove_cid_artifacts(cidfile: str, cid_directory: str) -> None:
        try:
            os.unlink(cidfile)
        except FileNotFoundError:
            pass
        try:
            os.rmdir(cid_directory)
        except OSError:
            pass

    async def run(self, permit: Permit, arguments: dict[str, Any],
                  credential_leases: list[CredentialLease] | None = None) -> ExecutionResult:
        session_id = uuid4()
        payload = json.dumps({"tool": permit.tool, "operation": permit.operation, "arguments": arguments}).encode()
        cid_directory = tempfile.mkdtemp(prefix="madva-vie-")
        cidfile = os.path.join(cid_directory, "container.cid")
        process = await asyncio.create_subprocess_exec(
            *self.command(credential_leases, cidfile), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        cleanup_status: Literal["verified", "incomplete", "unknown"] = "unknown"
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(payload), self.config.timeout_seconds)
            cleanup_status = "verified" if await self._cleanup_verified(cidfile) else "unknown"
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            cleanup_status = "verified" if await self._force_remove(cidfile) else "unknown"
            raise RuntimeErrorBoundary("execution_timeout") from exc
        finally:
            arguments.clear()
            self._remove_cid_artifacts(cidfile, cid_directory)
        if process.returncode != 0:
            detail = stderr.decode(errors="replace")[-500:]
            raise RuntimeErrorBoundary(f"sandbox_failed:{detail}")
        try:
            output = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeErrorBoundary("sandbox_returned_invalid_json") from exc
        return ExecutionResult(status="completed", output=output, session_id=session_id,
                               evidence=[f"docker-image:{self.config.image}", f"session:{session_id}"],
                               cleanup_status=cleanup_status)
