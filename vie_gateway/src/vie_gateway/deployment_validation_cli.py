from __future__ import annotations

import json
import os

from .deployment_validation import validate_environment


def main() -> int:
    result = validate_environment(os.environ)
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0 if result.valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
