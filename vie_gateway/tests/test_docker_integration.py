import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from vie_gateway.contracts import Permit
from vie_gateway.credentials import CredentialLease
from vie_gateway.runtime import DockerConfig, DockerRunner


@pytest.mark.asyncio
async def test_digest_pinned_sandbox_receives_credential_without_leaking_it(tmp_path: Path) -> None:
    image = os.environ.get("CREDENTIAL_TOOL_IMAGE")
    if not image:
        pytest.skip("CREDENTIAL_TOOL_IMAGE is required for Docker integration tests")

    secret = tmp_path / "secret"
    secret.write_text("ci-demo-secret", encoding="utf-8")
    lease = CredentialLease(
        reference="vault://secret/tool#api_key",
        host_path=str(secret),
        container_path="/run/secrets/api_key",
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    permit = Permit(
        permit_id=uuid4(), agent_id="agent-ci", requester_id="requester-ci",
        intent_scope="credential-test", tool="echo", operation="run",
        contract_id=uuid4(), expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )

    result = await DockerRunner(DockerConfig(image=image)).run(permit, {"test": True}, [lease])

    assert result.output["credential_present"] is True
    assert "ci-demo-secret" not in json.dumps(result.output)
    assert result.cleanup_status == "verified"
