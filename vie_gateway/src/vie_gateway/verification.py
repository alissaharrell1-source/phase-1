from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4
from jsonschema import Draft202012Validator, SchemaError
from .contracts import AuditReceipt, ExecutionResult, IntentContract, Permit
from .dlp import DLPScanner

class Verifier:
    def __init__(self, dlp_scanner: DLPScanner | None = None) -> None:
        self.dlp_scanner = dlp_scanner or DLPScanner()

    def verify(self, correlation_id: UUID, contract: IntentContract, permit: Permit, result: ExecutionResult,
               trace_id: str | None = None) -> AuditReceipt:
        findings: list[str] = []
        if permit.contract_id != contract.contract_id:
            findings.append("permit_contract_mismatch")
        if result.status != "completed":
            findings.append("execution_failed")
        if result.cleanup_status != "verified":
            findings.append("cleanup_not_verified")
        if self.dlp_scanner.scan(result.output):
            findings.append("sensitive_data_exposure")
        if contract.output_schema:
            try:
                Draft202012Validator.check_schema(contract.output_schema)
                Draft202012Validator(contract.output_schema).validate(result.output)
            except SchemaError:
                findings.append("invalid_output_schema")
            except Exception:
                findings.append("output_schema_violation")
        return AuditReceipt(receipt_id=uuid4(), correlation_id=correlation_id, contract_id=contract.contract_id,
                            permit_id=permit.permit_id, tenant_id=permit.tenant_id,
                            policy_id=permit.policy_id, policy_version=permit.policy_version,
                            trace_id=trace_id or f"local-{correlation_id}",
                            verification="pass" if not findings else "fail", findings=findings,
                            execution_status=result.status, cleanup_status=result.cleanup_status,
                            created_at=datetime.now(UTC))
