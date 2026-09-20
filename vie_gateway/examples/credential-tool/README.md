# Credential lease demo tool

This image is only a local integration fixture. It reads `/run/secrets/api_key`
and returns a SHA-256 fingerprint instead of the credential value, proving that
the sandbox received the lease without exposing the secret in tool output.

The base image is digest-pinned. Production tool images must also be admitted
by digest and published through the approved registry.
