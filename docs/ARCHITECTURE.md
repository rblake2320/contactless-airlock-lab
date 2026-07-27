# Architecture

## Core decision

The system separates a platform-independent protocol core from replaceable
payment-rail adapters.

The core owns challenge construction, canonical signing payloads, device-key
verification, one-time challenge consumption, expiry, policy decisions, state
transitions, and audit events. Adapters own issuer authorization messages,
processor webhooks, wallet/TSP provisioning calls, push delivery, device
attestation, reversal requests, and clearing notifications.

## Demonstrated strategies

### Provisioning gate

A new wallet token remains inactive or capped until a previously enrolled
trusted device approves a signed challenge. No SMS, email, or manually
transferable code is used.

### Pre-authorization step-up

For a policy-selected risky transaction, the issuer simulator waits for
trusted-device confirmation before returning approval. This is the strongest
security strategy but requires a rail or merchant experience that tolerates
the confirmation latency.

### Partner-enforced provisional authorization

The simulator can return a provisional approval and model later confirmation,
reversal, clearing, and exceptions. This is a partnership-dependent strategy,
not a universal settlement guarantee.

## Trust boundaries

- merchant/terminal to acquirer/processor;
- processor/network to issuer decisioning;
- wallet/TSP to issuer provisioning;
- issuer backend to notification service;
- trusted application to hardware-backed device key;
- partner adapters to the protocol core;
- operational users to fraud and audit consoles.

Every inbound event is authenticated, versioned, idempotent, and recorded with
correlation and causation identifiers.

