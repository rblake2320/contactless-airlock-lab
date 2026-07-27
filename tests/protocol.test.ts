import assert from "node:assert/strict";
import test from "node:test";
import { generateDeviceKeyPair, signApproval } from "../packages/crypto/deviceKeys.ts";
import { ChallengeStore } from "../packages/state-machine/challengeStore.ts";
import {
  transitionProvisioning,
  transitionTransaction,
} from "../packages/state-machine/transitions.ts";

function fixture() {
  const keys = generateDeviceKeyPair("device-key-1");
  const store = new ChallengeStore();
  const binding = store.create(
    {
      purpose: "provision-payment-token",
      subjectId: "cardholder-1",
      accountId: "account-1",
      paymentTokenId: "pending-token-1",
      trustedDeviceId: "trusted-device-1",
      ttlMs: 30_000,
    },
    new Date("2026-07-27T10:00:00.000Z"),
  );
  return { keys, store, binding };
}

test("trusted device confirms an exact provisioning challenge once", () => {
  const { keys, store, binding } = fixture();
  const approval = signApproval(binding, keys.keyId, keys.privateKeyPem);
  const result = store.consume(
    approval,
    keys.publicKeyPem,
    new Date("2026-07-27T10:00:01.000Z"),
  );
  assert.equal(result.status, "confirmed");
  assert.throws(() => store.consume(approval, keys.publicKeyPem), /already terminal/);
});

test("field substitution invalidates the signed binding", () => {
  const { keys, store, binding } = fixture();
  const approval = signApproval(binding, keys.keyId, keys.privateKeyPem);
  approval.binding = { ...approval.binding, paymentTokenId: "attacker-token" };
  assert.throws(
    () => store.consume(approval, keys.publicKeyPem),
    /binding mismatch/,
  );
});

test("expired challenge becomes terminal and cannot be revived", () => {
  const { keys, store, binding } = fixture();
  const approval = signApproval(binding, keys.keyId, keys.privateKeyPem);
  assert.throws(
    () =>
      store.consume(
        approval,
        keys.publicKeyPem,
        new Date("2026-07-27T10:01:00.000Z"),
      ),
    /expired/,
  );
  assert.equal(store.get(binding.challengeId)?.status, "expired");
});

test("challenge expires exactly at the server deadline", () => {
  const { keys, store, binding } = fixture();
  const approval = signApproval(binding, keys.keyId, keys.privateKeyPem);
  assert.throws(
    () =>
      store.consume(
        approval,
        keys.publicKeyPem,
        new Date(binding.expiresAt),
      ),
    /expired/,
  );
});

test("property ordering does not change canonical signed meaning", () => {
  const { keys, store, binding } = fixture();
  const reversed = Object.fromEntries(
    Object.entries(binding).reverse(),
  ) as unknown as typeof binding;
  const approval = signApproval(reversed, keys.keyId, keys.privateKeyPem);
  const result = store.consume(
    approval,
    keys.publicKeyPem,
    new Date("2026-07-27T10:00:01.000Z"),
  );
  assert.equal(result.status, "confirmed");
});

test("transaction state machine exposes reversal-clearing race", () => {
  let state = transitionTransaction("received", "confirmation_pending");
  state = transitionTransaction(state, "expired");
  state = transitionTransaction(state, "reversal_requested");
  state = transitionTransaction(state, "reversed");
  state = transitionTransaction(state, "clearing_received");
  state = transitionTransaction(state, "exception");
  assert.equal(state, "exception");
});

test("provisioning cannot activate before approval", () => {
  assert.throws(
    () => transitionProvisioning("requested", "token_active_full"),
    /invalid provisioning transition/,
  );
});
