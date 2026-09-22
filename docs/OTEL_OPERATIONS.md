# OpenTelemetry collector operations

MADVA exports only bounded execution metadata: correlation, contract, tenant, policy, verification outcome, finding count, execution status, cleanup status, and MCP outcome/error metadata. It does not attach tool arguments, tool output, credentials, bearer tokens, intent signatures, or DLP match values to spans.

Production OTLP endpoints must use HTTPS and may not contain URL credentials, query-string tokens, or fragments. Configure authorization headers through an external secret manager or use an equivalent mTLS trust configuration. Set `MADVA_REQUIRE_OTEL=true` so readiness fails when the collector endpoint is absent or unsafe.

The collector/SIEM owner must define and review:

- encryption in transit and at rest;
- authenticated exporter and collector-to-SIEM access;
- least-privilege reader and administrator roles;
- retention, deletion, legal hold, and backup policy;
- tenant-aware access controls and export segregation; and
- alerting for exporter failure without logging sensitive headers or payloads.

The target deployment review must verify those controls and confirm that collector processors do not reintroduce request or response payloads before treating telemetry as an audit receipt sink.
