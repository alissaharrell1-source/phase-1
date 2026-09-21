# MADVA VIE architecture

## Request lifecycle

```text
MCP JSON-RPC request
        |
        v
Architect: parse MCP + validate Intent Contract + verify signature
        |
        v
Security: validate OIDC/JWT + bind tenant + resolve approved policy + issue JIT permit
        |
        v
Infrastructure: acquire opaque leases + execute in isolated backend + verify cleanup
        |
        v
Verification: validate output + scan DLP + emit OTel metadata + append audit receipt
```

The graph terminates before execution on any failed stage. An HTTP 200 JSON-RPC response is only a transport response; authorization and execution outcomes are represented in the JSON-RPC body and audit receipt.

## Trust boundaries

1. The caller supplies an MCP call, bearer token, and Intent Contract. None is trusted before validation.
2. The Security stage is the policy enforcement point. It must not be bypassed by calling Infrastructure directly from the API.
3. The execution backend receives only the approved tool, operation, arguments, and opaque credential mounts. The inbound MADVA bearer token is not forwarded upstream.
4. Verification treats execution output as untrusted data. Output schemas and DLP checks run before a passing receipt is emitted.
5. Audit storage and the OTLP collector are separate sinks. Receipts contain metadata and chain links, not arguments, output, credentials, or bearer tokens.

## Extension rules

- Add new tools through the `Runner` interface and enforce immutable image admission outside the local adapter.
- Add identity providers behind `TokenValidator`/`OIDCTokenValidator`; preserve the required agent, requester, intent-scope, and tenant bindings.
- Add policy sources behind `PolicyRegistry`; never treat an unapproved revision as executable in production.
- Keep credential providers asynchronous and return only `CredentialLease` metadata.
- Add verification findings rather than weakening an existing check.

## State and durability

Graph state is request-scoped. Durable audit records are append-only JSONL records linked by SHA-256. Replica writers coordinate with a sidecar lock file, so production shared storage must honor advisory locks and fsync. Policy registries are loaded at process startup; policy changes require a controlled rollout.
