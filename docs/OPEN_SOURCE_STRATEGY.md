# Open-source and community strategy

## Initial release posture

Phase 1 should be treated as a security-focused pre-release. Publish the implementation, threat assumptions, test evidence, deployment examples, and known limitations together. Do not imply independent certification, production capacity, or a completed DSPM implementation.

## Maintainer practice

- Keep `main` protected and require CI before merge.
- Use focused pull requests with security and deployment notes.
- Tag reproducible releases after the full unit, security, container, and integration checks pass.
- Publish benchmark methodology and environment with every capacity claim.
- Use private vulnerability reporting and publish coordinated advisories when appropriate.
- Review changes to token validation, policy approval, credential handling, audit storage, and execution isolation with at least one security-focused maintainer.

## Contributor experience

The repository provides a local deterministic runner, Docker Compose fixtures, typed contracts, benchmark scripts, issue templates, and focused documentation. Contributors should be able to run the complete local suite without external credentials.

## Roadmap

1. Complete independent security assessment and publish findings.
2. Add production-grade SIEM/storage adapters and failure-injection tests.
3. Establish compatibility/versioning policy for MCP and Intent Contracts.
4. Select and add an explicit project license after owner review.
5. Define release support windows, maintainer ownership, and community governance.
