# WebAuthn Credential Boundary

## What this repository provides

`packages/credentials` defines the boundary between the Airlock protocol and a
reviewed WebAuthn implementation:

- a server-created, purpose-bound credential challenge;
- the issuer's registered credential record;
- the browser/native assertion fields passed to a verifier;
- a fail-closed verification result; and
- a `CredentialVerifier` interface that a production adapter must implement.

`DeterministicTestCredentialVerifier` is a protocol test double. It uses HMAC
and JSON-shaped test data so negative paths are deterministic. It is not
WebAuthn, does not parse authenticator data, does not verify a COSE public key,
does not validate attestation, and provides no evidence of a hardware-backed
credential. Production composition must make it impossible to select this
class.

`SimpleWebAuthnCredentialVerifier` is the production assertion-verification
adapter. It is pinned to `@simplewebauthn/server` 13.3.2 and enforces the exact
stored challenge, HTTPS origin allowlist (with localhost-only HTTP for local
testing), RP ID/hash, active subject/device credential binding, ES256 policy,
UP+UV flags, bounded canonical base64url fields, signature, and counter. Its
tests create a standards-shaped P-256/COSE credential and independently sign
the WebAuthn assertion bytes with Node's cryptographic implementation; they do
not use the deterministic HMAC verifier.

This adapter does **not** implement registration, validate an attestation
statement or trust chain, establish hardware provenance, persist a new counter,
or prove behavior on a real authenticator. Those remain separate gates below.

## Registration requirements

A production registration ceremony must use a maintained, independently
reviewed WebAuthn/FIDO2 server implementation and enforce all of the following:

1. Generate at least 32 bytes of unpredictable server-side challenge entropy.
2. Bind the challenge to the authenticated subject, proposed trusted-device
   record, relying party, allowed origin set, purpose, issuance, and expiry.
3. Set the relying-party ID to the effective production domain and verify the
   exact RP ID hash returned by the authenticator.
4. Require an exact HTTPS origin allowlist. Do not accept suffix, substring,
   reflected, wildcard, `Origin`-header-only, or client-selected origins.
5. Require user verification. Record the policy used; do not reinterpret mere
   user presence as biometric or PIN verification.
6. Decide the permitted algorithms explicitly and reject downgrade or an
   algorithm not offered by the server.
7. Parse and validate `clientDataJSON`, `attestationObject`, authenticator data,
   credential ID, credential public key, flags, and extensions with strict
   size and structure limits.
8. Verify the attestation statement when the pilot requires attested hardware.
   Validate the complete certificate/trust path against controlled metadata or
   partner-approved trust roots; validate revocation and metadata status.
9. Apply an explicit attestation policy to format, AAGUID, authenticator model,
   certification level, backup eligibility/state, attachment, and enterprise
   attestation. An AAGUID alone is not proof of model or security properties.
10. Store the exact credential ID and COSE public key, subject/device binding,
    algorithm, signature counter, transports as hints only, attestation policy
    result, trust-path identifier, creation time, and revocation state.
11. Make challenge consumption and credential creation one atomic,
    idempotency-protected transaction.
12. Prevent a newly registered or recovered device from approving its own
    enrollment or removing all earlier trust anchors without the separately
    approved recovery policy.

Attestation conveys properties asserted by a validated trust chain; it does
not prove that a particular human is legitimate, that an endpoint is malware-
free, or that every platform uses a unique hardware identity. Privacy policy
must account for attestation identifiers and avoid unnecessary device
fingerprinting.

## Assertion requirements

A production `CredentialVerifier` must:

1. Load the unconsumed challenge and active credential from issuer-owned state.
2. Reject unknown protocol versions, purposes, credentials, algorithms, RP IDs,
   origins, extensions, and malformed or oversized values.
3. Decode `clientDataJSON`; require `type == "webauthn.get"` and byte-for-byte
   equality with the stored challenge after the prescribed base64url decoding.
4. Verify the exact allowed origin and any permitted cross-origin/top-origin
   behavior explicitly.
5. Parse authenticator data; verify the RP ID hash, user-presence flag, required
   user-verification flag, extension outputs, and backup flags under policy.
6. Verify the assertion signature over `authenticatorData ||
   SHA-256(clientDataJSON)` with the stored COSE public key and algorithm.
7. Evaluate the signature counter. A supported nonzero counter that decreases
   or fails to advance is a clone/race signal and fails or escalates according
   to written issuer policy. Zero-counter authenticators require a documented
   alternate risk policy, not a fabricated increment.
8. Verify the credential's subject and trusted-device authorization for the
   exact Airlock challenge; a cryptographically valid credential is not
   automatically authorized for every account, token, or purpose.
9. Apply server-authoritative expiry and atomic one-time challenge consumption.
10. Update the counter, write the security event, and consume the challenge in
    one durable transaction or fail without partial authorization.

The WebAuthn challenge must itself be linked to the canonical Airlock binding
(for example by storing both under one challenge ID or placing an
issuer-defined digest in authenticated server state). Verifying WebAuthn and
then trusting transaction fields returned independently by a client creates a
substitution gap.

## Attestation trust and lifecycle

Production policy must name who owns authenticator allow/deny decisions, trust
root and FIDO Metadata Service updates, compromised-model response, certificate
revocation, key rotation, and audit retention. Metadata changes must be
reviewed and deployed as security policy, not silently accepted during a live
verification request.

Revocation takes effect before new assertions are evaluated. Device loss and
account recovery require a separate high-assurance workflow with notifications,
delay or restricted capability where appropriate, and protection against an
attacker replacing every existing trust anchor. Synced/passkey credentials and
device-bound credentials have different recovery and assurance properties and
must not be marketed as equivalent without partner policy approval.

## Failure policy

Malformed input, expired or consumed challenge, missing user verification,
credential mismatch, invalid signature, disallowed origin/RP ID, revoked key,
counter anomaly, failed attestation policy, verifier outage, or ambiguous state
fails closed for a request already selected for mandatory confirmation. There
is no silent downgrade to SMS, email, a typed code, or the deterministic test
verifier.

Operational errors returned to clients should be stable and non-sensitive.
Detailed parser, certificate, key, and policy evidence belongs in access-
controlled security telemetry correlated by opaque identifiers.

## Integration sequence

1. Select and review the production WebAuthn library and supported platforms.
2. Implement the `CredentialVerifier` adapter without importing the test
   verifier into the production dependency graph.
3. Add official WebAuthn conformance vectors plus malformed-encoding,
   origin/RP substitution, UV/UP, extension, counter, and attestation-chain
   negative tests.
4. Exercise real supported authenticators across registration, assertion,
   revocation, recovery, backup/sync, and metadata-compromise scenarios.
5. Complete issuer, wallet/TSP, privacy, accessibility, fraud, and independent
   application-security review before any pilot handles real payment data.

The current assertion adapter accepts only
`protocolVersion=airlock-webauthn.v1`, purpose
`approve-airlock-challenge`, and a bounded canonical challenge identifier.
Enrollment-purpose assertions and unknown versions fail closed before
cryptographic verification. This adapter is still not wired into realtime
session login or the standalone OIDC verifier.
