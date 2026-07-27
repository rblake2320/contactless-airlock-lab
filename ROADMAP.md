# Build Roadmap

The repository is built in evidence-gated slices. A checked item means the
behavior exists at the scope stated and has executable evidence. It does not
promote simulator behavior into a production payment claim.

## P0: Protocol foundation

- [x] Separate private repository with product boundaries
- [x] P-256 trusted-device signing reference implementation
- [x] Canonical transaction/provisioning challenge payload
- [x] Exact-field and unknown-field rejection
- [x] One-time challenge consumption in the single-process lab
- [x] Expiry and terminal-state behavior
- [x] Monotonic provisioning and transaction state machines
- [x] In-memory hash-chain audit integrity check
- [x] Fraudulent provisioning, legitimate flow, and reversal/clearing scenarios
- [x] Threat model, security policy, test plan, and partner boundaries

## P1: Durable service

- [ ] PostgreSQL durable state and schema migrations
- [ ] Transactional compare-and-swap challenge consumption
- [ ] Idempotency records for every external mutation
- [ ] Transactional outbox and at-least-once event consumers
- [ ] Multi-process concurrency and restart tests
- [ ] OpenAPI 3.1 issuer API
- [ ] AsyncAPI partner event contract
- [ ] Authentication and signed webhook verification
- [ ] Structured reason codes and privacy-safe observability

## P2: Partner simulators and operator experience

- [ ] Independent merchant/terminal simulator
- [ ] Processor/network authorization, reversal, clearing, and retry simulator
- [ ] Wallet/TSP provisioning simulator
- [ ] Trusted-device web/mobile demonstration using WebAuthn
- [ ] Fraud-operations and cardholder activity interfaces
- [ ] Scenario controls for latency, duplication, outage, and reordering
- [ ] Exportable evidence bundle for every partner demonstration

## P3: Security closure

- [ ] Property-based state-machine tests
- [ ] Barrier-driven multi-instance race tests
- [ ] Fuzz canonical message decoding and schema validation
- [ ] Key rotation, revocation, recovery, and compromised-device exercises
- [ ] Push-fatigue and misleading-transaction UX tests
- [ ] Caps enforced transactionally across concurrent authorizations
- [x] Strict TypeScript static checking in the default quality gate
- [x] Secret-free CI runs tests, scenarios, demo, dependency audit,
      and a narrow committed-credential precheck
- [ ] Dedicated SAST, full-history secret scanning, SBOM/provenance, and
      container scanning
- [ ] Independent application-security review

## P4: Partner pilot

- [ ] Sponsor issuer/processor sandbox access
- [ ] Captured authorization and reversal semantics
- [ ] Wallet/TSP app-to-app provisioning integration
- [ ] Written handling for stand-in, advice, offline, transit, incremental,
      partial, tip-adjusted, duplicate, and late-clearing events
- [ ] Partner-approved liability and customer-recovery policy
- [ ] Controlled pilot with synthetic or authorized test credentials
- [ ] Evidence-based decision on pre-authorization versus deferred completion

## Release language

Before P4 evidence, describe the project as a reference implementation and
partner integration lab. Do not claim production fraud prevention, NFC relay
resistance, wallet integration, issuer certification, or guaranteed settlement
prevention.

The detailed exit criteria and external dependencies are maintained in
[`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).
