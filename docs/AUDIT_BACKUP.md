# Audit backup and restore procedure

The audit file and its lock sidecar are one operational unit. Before copying a live file, quiesce writers or take a filesystem-consistent snapshot that includes both `receipts.jsonl` and `receipts.jsonl.lock`. Do not copy an actively appended JSONL file and assume a partial final line is recoverable.

Validate a restored backup without creating or changing a lock sidecar:

```powershell
madva-audit-verify C:\backup\madva\receipts.jsonl
```

The command returns exit code `0` only when the file exists and every sequence number, chain link, and record hash verifies. Missing, malformed, truncated, reordered, or tampered backups return exit code `2` and a machine-readable error. Preserve failed backups for investigation; do not repair them in place.

The target storage review must exercise a writer interruption, lock/unavailable-storage condition, snapshot restore, missing backup, and tampered record. The gateway fails closed when it cannot verify its live chain or persist a new receipt.
