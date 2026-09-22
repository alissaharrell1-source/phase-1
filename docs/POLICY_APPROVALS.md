# Policy approval and distribution contract

Production authorization requires an Intent Contract to reference an exact `(policy_id, policy_version)` pair present in the administrator-owned registry. The referenced revision must have status `approved`; drafts, pending revisions, rejected revisions, revoked revisions, and missing revisions fail closed.

An approved registry record must include:

- a non-empty `approved_by` identity for the human or approval service;
- an `approved_at` timestamp; and
- the SHA-256 digest of the submitted policy content.

The local registry models the lifecycle `draft -> pending -> approved` and supports `rejected` and `revoked` terminal states. Approval and revocation are explicit transitions. The gateway loads the registry at startup and does not accept policy changes through the request path, so updates require a controlled registry rollout and readiness verification on every replica.

The deployment owner must review the external approval service, reviewer authorization, registry publication mechanism, replica consistency, rollback behavior, and audit retention before production use. The gateway's local checks establish the enforcement boundary but do not replace that deployment review.
