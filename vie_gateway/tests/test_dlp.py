import pytest

from vie_gateway.dlp import DLPScanner


@pytest.mark.parametrize(
    ("category", "value"),
    [
        ("github_token", "ghp_123456789012345678901234567890123456"),
        ("slack_token", "xoxb-1234567890-abcdef123456"),
        ("database_url_credentials", "postgresql://db-user:db-password@db.example/app"),
        ("sensitive_field", {"api_key": "credential-value"}),
    ],
)
def test_dlp_scanner_detects_common_credential_exposure(category: str, value: object) -> None:
    findings = DLPScanner().scan(value)
    assert category in {finding.category for finding in findings}


def test_dlp_scanner_does_not_flag_normal_result_metadata() -> None:
    assert DLPScanner().scan({"status": "ok", "count": 2}) == []


def test_dlp_scanner_fails_closed_for_cyclic_output() -> None:
    value: list[object] = []
    value.append(value)
    findings = DLPScanner().scan(value)
    assert [finding.category for finding in findings] == ["unserializable_output"]
