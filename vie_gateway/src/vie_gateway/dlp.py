from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class DLPFinding:
    category: str
    pattern: str

class DLPScanner:
    """Deterministic boundary scanner for common secret exposure indicators."""
    _patterns = (
        ("jwt_like_token", re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")),
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
        ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
        ("database_url_credentials", re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^@\s]+@"
        )),
        ("sensitive_field", re.compile(
            r'(?i)"(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)"'
            r"\s*:\s*(?:\"[^\"]+\"|[^\s,}\]]+)"
        )),
    )

    def scan(self, value: Any) -> list[DLPFinding]:
        try:
            serialized = json.dumps(value, sort_keys=True, default=str)
        except (TypeError, ValueError, OverflowError):
            return [DLPFinding("unserializable_output", "json_serialization")]
        return [DLPFinding(category, pattern.pattern) for category, pattern in self._patterns if pattern.search(serialized)]
