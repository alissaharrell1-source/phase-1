from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .audit_store import AuditChainError, JsonlAuditStore


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a MADVA audit JSONL backup")
    parser.add_argument("path", type=Path, help="path to the receipts.jsonl backup")
    args = parser.parse_args(argv)

    try:
        records = JsonlAuditStore.verify_path(args.path)
    except AuditChainError as exc:
        print(json.dumps({"verified": False, "error": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps({"path": str(args.path), "records": records, "verified": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
