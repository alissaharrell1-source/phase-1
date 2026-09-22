from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON data for signatures and other integrity digests.

    MADVA's profile uses lexicographically sorted keys, no insignificant
    whitespace, UTF-8 output, and rejects non-standard NaN or Infinity values.
    Callers must provide JSON-compatible values before invoking this helper.
    """
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("unsupported_canonical_json") from exc
