# Customer and Fraud Operations Safety Runbook

## Scope and truth boundary

This is a synthetic, tenant-scoped reference state machine. It has no customer
account, PAN, payment network, token vault, workforce IAM, notification
provider, case-management platform, or fraud engine connection. Subject
references must begin with `synthetic-`. Notification records are outbox
intents only; the package has no send function.

The exact reference contract and production gaps are listed in
[`contracts/operations/customer-fraud-workflows.v1.json`](../contracts/operations/customer-fraud-workflows.v1.json).

## Universal operator rules

1. Confirm tenant and case identity before every action. Cross-tenant access
   must fail rather than search globally.
2. Record a specific immutable reason and correlation ID. Never overwrite prior
   actor, reason, or correlation evidence.
3. Never recover through SMS OTP, email codes, a typed confirmation code, or a
   newly enrolled device approving itself.
4. Treat expiry as terminal. Open a separately correlated case if review must
   restart.
5. Reuse an idempotency key only for the byte-equivalent operation.
6. A destructive trust reset requires two distinct authorized approvers.
7. Never send directly from case logic. Commit state, audit evidence, and the
   notification intent atomically in the production repository.

## Device loss

Open the case using a synthetic/customer reference and identify the affected
device. Contain the device credential before considering reset. A case may
resolve without destructive reset when containment is sufficient. If trust
must be destroyed, request the bounded override and obtain two authorized,
distinct approvals. The affected device cannot approve.

Production adapters still needed: device inventory, token/device revocation,
customer authentication, workforce authorization, and notification delivery.

## Account recovery

Accept only an existing passkey, in-person strong identity process, or an
issuer/bank strong-identity result. Proof verification moves the case forward;
it does not activate a new credential. Request destructive reset separately,
with expiry and two-person approval. A proposed new device cannot approve its
own enrollment or reset.

Production adapters still needed: real WebAuthn assertion and credential
inventory, branch/in-person evidence, bank identity result, recovery risk
engine, and credential issuance ceremony.

## False decline review

Move `opened -> under_review`, then terminate as `upheld` or `overturned`.
Review does not silently rewrite the original authorization decision. An
overturn is an operations conclusion for downstream reconciliation, not proof
that a processor or merchant retried or completed a payment.

Production adapters still needed: authorization evidence, fraud-model
explanations, analyst queue, downstream decision channel, and customer remedy.

## Fraudulent approval dispute

Freeze the synthetic payment/trust reference, enter review, then terminate as
`upheld` or `remediated`. Preserve the disputed approval, device, and
transaction evidence by reference. Do not claim recovery of funds or reversal
until the relevant issuer/processor adapter confirms it.

Production adapters still needed: dispute platform, ledger/authorization
records, provisional credit policy, network reason codes, and evidence export.

## Compromise response

Contain first. Then either eradicate and resolve, or enter the dual-controlled
trust-reset path. Do not reactivate a compromised credential. Coordinate key,
session, token, device, and notification actions through separately authorized
production adapters. Preserve evidence and external audit anchors before
destructive cleanup.

Production adapters still needed: incident management, credential/session
revocation, KMS/HSM response, token vault, endpoint telemetry, and regulatory
notification decisioning.

## Dual control and expiry

Authorized approval roles in the reference model are security operator,
supervisor, and recovery officer. Actor IDs must differ, and an affected/new
device is barred. The second valid approval executes the reference reset and
records a system execution event. In production, role membership, employment
status, authentication strength, conflict-of-interest policy, and approval
session freshness must come from workforce IAM—not request JSON.

At the exact case or override deadline, the operation is expired. Late approval
cannot revive it. A new case must repeat evidence collection and receive a new
correlation and idempotency scope.

## Audit, outbox, and recovery limitations

The reference audit is hash-chained and returned only as defensive copies. That
detects accidental or unsophisticated mutation but is not independently
authenticated. Production must compose the remote audit MAC and independent
trust-anchor boundary, and must durably persist the case snapshot, idempotency
record, audit event, and notification intent in one atomic transaction.

The in-memory snapshot/restore tests demonstrate state invariants only. They do
not establish HA, backup/restore, legal hold, delivery, non-repudiation,
workforce identity, real customer verification, or payment remediation.
