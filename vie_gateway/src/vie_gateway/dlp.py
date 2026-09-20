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
    """Small boundary scanner for obvious token leakage; not full DSPM."""
    _patterns = (
        ("jwt_like_token", re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")),
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    )

    def scan(self, value: Any) -> list[DLPFinding]:
        serialized = json.dumps(value, sort_keys=True, default=str)
        return [DLPFinding(category, pattern.pattern) for category, pattern in self._patterns if pattern.search(serialized)]
