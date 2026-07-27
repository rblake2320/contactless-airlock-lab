import assert from "node:assert/strict";
import test from "node:test";
import {
  createDeterministicTestAssertion,
  DeterministicTestCredentialVerifier,
} from "../packages/credentials/deterministicTestVerifier.ts";
import type {
  CredentialChallenge,
  RegisteredCredential,
} from "../packages/credentials/types.ts";

const SECRET = "deterministic-test-secret-only";

function fixture() {
  const challenge: CredentialChallenge = {
    protocolVersion: "airlock-webauthn.v1",
    challengeId: "challenge-1",
    challenge: Buffer.from("32-bytes-of-randomness-for-a-test!").toString("base64url"),
    purpose: "approve-airlock-challenge",
    subjectId: "subject-1",
    trustedDeviceId: "device-1",
    relyingPartyId: "airlock.example",
    allowedOrigins: ["https://airlock.example"],
    issuedAt: "2026-07-27T10:00:00.000Z",
    expiresAt: "2026-07-27T10:01:00.000Z",
    userVerification: "required",
  };
  const credential: RegisteredCredential = {
    credentialId: Buffer.from("credential-1").toString("base64url"),
    subjectId: "subject-1",
    trustedDeviceId: "device-1",
    relyingPartyId: "airlock.example",
    publicKeyCose: Buffer.from("not-a-real-cose-key").toString("base64url"),
    algorithm: -7,
    signCount: 8,
    status: "active",
    trust: { level: "lab-unverified" },
  };
  const verifier = new DeterministicTestCredentialVerifier(SECRET);
  const assertion = createDeterministicTestAssertion({
    secret: SECRET,
    challenge,
    credential,
  });
  return { assertion, challenge, credential, verifier };
}

test("deterministic boundary accepts the exact active credential assertion", async () => {
  const value = fixture();
  const result = await value.verifier.verifyAssertion({
    ...value,
    now: new Date("2026-07-27T10:00:30.000Z"),
  });
  assert.deepEqual(result, {
    verified: true,
    credentialId: value.credential.credentialId,
    signCount: 9,
    userPresent: true,
    userVerified: true,
    origin: "https://airlock.example",
    relyingPartyId: "airlock.example",
  });
});
test("origin, challenge, and credential substitution fail closed", async () => {
  const origin = fixture();
  origin.assertion = createDeterministicTestAssertion({
    secret: SECRET,
    challenge: origin.challenge,
    credential: origin.credential,
    origin: "https://attacker.example",
  });
  assert.deepEqual(
    await origin.verifier.verifyAssertion({
      ...origin,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "origin_mismatch" },
  );

  const substituted = fixture();
  const tampered = JSON.parse(
    Buffer.from(substituted.assertion.clientDataJSON, "base64url").toString("utf8"),
  ) as { challenge: string; origin: string; type: string };
  tampered.challenge = "attacker-challenge";
  substituted.assertion.clientDataJSON = Buffer.from(
    JSON.stringify(tampered),
  ).toString("base64url");
  assert.deepEqual(
    await substituted.verifier.verifyAssertion({
      ...substituted,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "invalid_challenge" },
  );

  const credential = fixture();
  credential.assertion.credentialId = "other-credential";
  assert.deepEqual(
    await credential.verifier.verifyAssertion({
      ...credential,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "credential_mismatch" },
  );
});

test("expiry, revocation, absent verification, and counter rollback fail closed", async () => {
  const expired = fixture();
  assert.deepEqual(
    await expired.verifier.verifyAssertion({
      ...expired,
      now: new Date(expired.challenge.expiresAt),
    }),
    { verified: false, code: "expired_challenge" },
  );

  const revoked = fixture();
  revoked.credential.status = "revoked";
  assert.deepEqual(
    await revoked.verifier.verifyAssertion({
      ...revoked,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "credential_revoked" },
  );

  const noUv = fixture();
  noUv.assertion = createDeterministicTestAssertion({
    secret: SECRET,
    challenge: noUv.challenge,
    credential: noUv.credential,
    userVerified: false,
  });
  assert.deepEqual(
    await noUv.verifier.verifyAssertion({
      ...noUv,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "user_verification_required" },
  );

  const rollback = fixture();
  rollback.assertion = createDeterministicTestAssertion({
    secret: SECRET,
    challenge: rollback.challenge,
    credential: rollback.credential,
    signCount: 8,
  });
  assert.deepEqual(
    await rollback.verifier.verifyAssertion({
      ...rollback,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "counter_rollback" },
  );
});

test("a valid-looking assertion made with another test secret is rejected", async () => {
  const value = fixture();
  value.assertion = createDeterministicTestAssertion({
    secret: "different-test-secret-value",
    challenge: value.challenge,
    credential: value.credential,
  });
  assert.deepEqual(
    await value.verifier.verifyAssertion({
      ...value,
      now: new Date("2026-07-27T10:00:30.000Z"),
    }),
    { verified: false, code: "signature_invalid" },
  );
});
