# Source Specification Review

The project began from two local design documents:

- `Contactless Payment Airlock Protocol: Full Technical Specification`
- `Part One Rewrite: The Transaction-Time Airlock (Issuer-Overlay Architecture)`

The rewrite supersedes original claims that depended on changing the NFC/EMV
exchange. The executable project goes one step further: it does not assume an
issuer controls merchant capture after returning `APPROVED`.

## Retained

- trusted-device confirmation replacing SMS OTP;
- device-bound signed challenges;
- exact transaction and provisioning binding;
- token caps and event-triggered cap removal;
- risk and reputation observations;
- visible activity and audit history;
- optional liveness as a non-authoritative risk signal.

## Corrected

- Software confirmation windows are not RF distance bounding.
- The lab does not prevent NFC relay attacks.
- A normal payment cryptogram and authorization can exist before a reversal.
- Authorization reversal can race clearing and does not recover merchandise.
- Terminal identifiers are weak risk signals, not authoritative identities.
- A biometric success proves local user verification, not informed consent or
  freedom from coercion.
- Prior-art and patent conclusions from the original architecture do not carry
  over to the corrected system.

## Partner pitch

The repository demonstrates complete protocol behavior with replaceable
adapters. A partner evaluation determines which production strategy their
rails support:

1. confirmation before authorization approval;
2. partner-enforced deferred completion;
3. post-authorization monitoring and reversal, explicitly without an airlock
   or settlement-prevention guarantee.

