# Result verification and DSPM coverage

Before a passing audit receipt is emitted, `Verifier` checks the permit/contract binding, execution status, cleanup status, output schema, and the output boundary scanner. The local `DLPScanner` detects JWTs, bearer tokens, AWS access keys, private keys, GitHub tokens, Slack tokens, database URLs containing credentials, and non-empty credential-like output fields. It records only a category and pattern metadata; secret values are never included in findings or receipts.

The scanner also fails closed when an output cannot be serialized for inspection. This prevents an unexpected object shape from bypassing the DLP decision.

This is deterministic boundary protection, not a complete DSPM product. It does not inspect host/process memory, historical storage, container layers, external data stores, or organization-wide data classifications. A target deployment must integrate an approved DSPM or memory-forensics control, define its retention and access policy, exercise it against representative tool outputs and failure paths, and retain evidence of the assessment. A local scan pass must not be presented as proof that no sensitive data exists.
