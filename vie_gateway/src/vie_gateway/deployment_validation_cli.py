from __future__ import annotations

import json
import os
import argparse
import asyncio

from .deployment_validation import validate_environment, validate_live_environment


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MADVA deployment configuration")
    parser.add_argument("--live", action="store_true", help="also check configured OIDC, Vault, OTLP, and audit services")
    args = parser.parse_args()
    result = asyncio.run(validate_live_environment(os.environ)) if args.live else validate_environment(os.environ)
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
