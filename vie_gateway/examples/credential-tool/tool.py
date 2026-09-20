import hashlib
import json
import sys
from pathlib import Path


payload = json.load(sys.stdin)
secret_path = Path("/run/secrets/api_key")
secret = secret_path.read_bytes() if secret_path.exists() else b""
print(json.dumps({
    "tool": payload.get("tool"),
    "credential_present": bool(secret),
    "credential_sha256": hashlib.sha256(secret).hexdigest() if secret else None,
}))
