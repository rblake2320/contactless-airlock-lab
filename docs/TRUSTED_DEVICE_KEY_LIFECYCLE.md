# Trusted-device key lifecycle

The issuer simulator supports explicit trusted-device public-key rotation and
terminal compromise handling. These are repository-owned state-machine
operations, not production IAM, wallet, TSP, or HSM integrations.

Rotation is allowed only for an active device, requires a different unused key
identifier, and validates the replacement key against the supported P-256
profile before changing state. Canonical SPKI fingerprints prevent the current
key or another enrolled device's key material from being relabeled under a new
identifier. Every outstanding provisioning or transaction
challenge bound to the old device key is cancelled. Pending provisioning is
declined; pending transactions are declined and any capped-spend reservation is
released. Neither an old-key nor a replacement-key signature can revive those
terminal challenges. A caller must begin a new challenge after rotation.

Invalidation is planned and validated before mutation, so one future-issued
challenge cannot cause older challenges to be partially cancelled before the
operation fails. Pending aggregates are also reconciled when an earlier
approval attempt already terminalized their challenge as expired; this prevents
stranded pending tokens, transactions, or cap reservations.

Compromise immediately moves the device into the existing terminal `revoked`
state and cancels the same outstanding work. It records a distinct
`trusted_device.compromised` audit event, including the invalidated challenge
identifiers and `recoveryDowngradeAvailable: false`. There is no reactivation,
SMS OTP, typed confirmation code, or other weaker recovery route.

`rotateTrustedDeviceKey` represents an administrative action that has already
passed an authorization boundary. A production adapter must authenticate and
authorize that ceremony and protect key administration with appropriate
HSM/KMS and operator controls. The simulator does not claim those integrations.

Tests prove restart persistence, old-challenge invalidation, cap-reservation
release, compromise terminality, transactional rollback after a durable write,
same-key idempotent retry, and exact replay. They do not prove production key
custody, wallet attestation, multi-host failover, or partner recovery policy.
