# Signed approval algorithm profile

`airlock.ecdsa-p256-sha256-der.v1` is the only accepted approval profile.

It fixes:

- EC curve: NIST P-256 (`prime256v1`);
- digest: SHA-256;
- signature encoding: ASN.1 DER as emitted and verified by Node crypto;
- signed payload: UTF-8 domain separator
  `airlock-signed-approval.v1\0`, the algorithm identifier, `\0`, then the
  canonical binding bytes.

Enrollment stores the profile beside the public key. Signing includes it in the
approval and in the signed bytes. Verification requires exact agreement among
the approval, enrollment record, key type/curve, and supported runtime profile.
Restore repeats the enrollment profile and key checks.

There is no implicit default on received data, alias, `none` profile, SHA-1
fallback, curve substitution, or negotiation to the oldest common option.
Adding an algorithm requires a new exact identifier, implementation, vectors,
migration policy, and explicit allow-list update. Removing one requires a
documented enrollment migration; it must never reinterpret an old key under a
new profile.
