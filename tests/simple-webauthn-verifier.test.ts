import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import test from "node:test";
import { SimpleWebAuthnCredentialVerifier } from "../packages/credentials/simpleWebAuthnVerifier.ts";
import type {
  CredentialAssertion,
  CredentialChallenge,
  RegisteredCredential,
} from "../packages/credentials/types.ts";

function es256CosePublicKey(x: Uint8Array, y: Uint8Array): Buffer {
  assert.equal(x.length, 32);
  assert.equal(y.length, 32);
  return Buffer.concat([
    Buffer.from([
      0xa5, // map(5)
      0x01, 0x02, // 1 (kty): 2 (EC2)
      0x03, 0x26, // 3 (alg): -7 (ES256)
      0x20, 0x01, // -1 (crv): 1 (P-256)
      0x21, 0x58, 0x20, // -2 (x): bytes(32)
    ]),
    x,
    Buffer.from([0x22, 0x58, 0x20]), // -3 (y): bytes(32)
    y,
  ]);
}

function fixture(options: {
  counter?: number;
  flags?: number;
  origin?: string;
} = {}) {
  const rpID = "airlock.example";
  const origin = options.origin ?? "https://airlock.example";
  const challengeValue = randomBytes(32).toString("base64url");
  const credentialID = randomBytes(32).toString("base64url");
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  assert.ok(jwk.x && jwk.y);
  const publicKeyCose = es256CosePublicKey(
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ).toString("base64url");

  const challenge: CredentialChallenge = {
    protocolVersion: "airlock-webauthn.v1",
    challengeId: "challenge-production-vector",
    challenge: challengeValue,
    purpose: "approve-airlock-challenge",
    subjectId: "subject-1",
    trustedDeviceId: "trusted-device-1",
    relyingPartyId: rpID,
    allowedOrigins: [origin],
    issuedAt: "2026-07-28T12:00:00.000Z",
    expiresAt: "2026-07-28T12:01:00.000Z",
    userVerification: "required",
  };
  const credential: RegisteredCredential = {
    credentialId: credentialID,
    subjectId: challenge.subjectId,
    trustedDeviceId: challenge.trustedDeviceId,
    relyingPartyId: rpID,
    publicKeyCose,
    algorithm: -7,
    signCount: 40,
    status: "active",
    transports: ["internal"],
    trust: { level: "lab-unverified" },
  };

  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: challengeValue,
      origin,
      crossOrigin: false,
    }),
    "utf8",
  );
  const authenticatorData = Buffer.alloc(37);
  createHash("sha256").update(rpID, "utf8").digest().copy(authenticatorData, 0);
  authenticatorData[32] = options.flags ?? 0x05; // UP | UV
  authenticatorData.writeUInt32BE(options.counter ?? 41, 33);
  const signedBytes = Buffer.concat([
    authenticatorData,
    createHash("sha256").update(clientDataJSON).digest(),
  ]);
  const assertion: CredentialAssertion = {
    credentialId: credentialID,
    clientDataJSON: clientDataJSON.toString("base64url"),
    authenticatorData: authenticatorData.toString("base64url"),
    signature: sign("sha256", signedBytes, privateKey).toString("base64url"),
  };
  return { assertion, challenge, credential };
}

const verifier = new SimpleWebAuthnCredentialVerifier();
const NOW = new Date("2026-07-28T12:00:30.000Z");

test("production adapter verifies an independently signed ES256 WebAuthn assertion", async () => {
  const value = fixture();
  assert.deepEqual(
    await verifier.verifyAssertion({ ...value, now: NOW }),
    {
      verified: true,
      credentialId: value.credential.credentialId,
      signCount: 41,
      userPresent: true,
      userVerified: true,
      origin: "https://airlock.example",
      relyingPartyId: "airlock.example",
    },
  );
});

test("production adapter rejects a cryptographically invalid assertion", async () => {
  const value = fixture();
  const signature = Buffer.from(value.assertion.signature, "base64url");
  signature[signature.length - 1] ^= 1;
  value.assertion.signature = signature.toString("base64url");
  assert.deepEqual(
    await verifier.verifyAssertion({ ...value, now: NOW }),
    { verified: false, code: "signature_invalid" },
  );
});

test("signed assertion rejects unsupported envelope version, purpose, and challenge id", async () => {
  const cases: Array<(challenge: CredentialChallenge) => void> = [
    (challenge) => {
      (challenge as { protocolVersion: string }).protocolVersion =
        "airlock-webauthn.v2";
    },
    (challenge) => {
      challenge.purpose = "enroll-trusted-device";
    },
    (challenge) => {
      challenge.challengeId = "";
    },
    (challenge) => {
      challenge.challengeId = "../cross-tenant";
    },
    (challenge) => {
      challenge.challengeId = `c${"x".repeat(128)}`;
    },
  ];
  for (const mutate of cases) {
    // fixture() creates a genuine ES256 signature over the challenge bytes.
    // Mutating only the surrounding server envelope must still fail closed.
    const value = fixture();
    mutate(value.challenge);
    assert.deepEqual(
      await verifier.verifyAssertion({ ...value, now: NOW }),
      { verified: false, code: "invalid_challenge" },
    );
  }
});

test("strict RP, origin, UP, UV, counter, and algorithm boundaries fail closed", async () => {
  const wrongOrigin = fixture();
  wrongOrigin.challenge.allowedOrigins = ["https://different.example"];
  assert.deepEqual(
    await verifier.verifyAssertion({ ...wrongOrigin, now: NOW }),
    { verified: false, code: "origin_mismatch" },
  );

  const wrongRp = fixture();
  wrongRp.challenge.relyingPartyId = "different.example";
  wrongRp.credential.relyingPartyId = "different.example";
  assert.deepEqual(
    await verifier.verifyAssertion({ ...wrongRp, now: NOW }),
    { verified: false, code: "rp_id_mismatch" },
  );

  const noPresence = fixture({ flags: 0x04 });
  assert.deepEqual(
    await verifier.verifyAssertion({ ...noPresence, now: NOW }),
    { verified: false, code: "user_presence_required" },
  );

  const noVerification = fixture({ flags: 0x01 });
  assert.deepEqual(
    await verifier.verifyAssertion({ ...noVerification, now: NOW }),
    { verified: false, code: "user_verification_required" },
  );

  const rollback = fixture({ counter: 40 });
  assert.deepEqual(
    await verifier.verifyAssertion({ ...rollback, now: NOW }),
    { verified: false, code: "counter_rollback" },
  );

  const wrongAlgorithm = fixture();
  wrongAlgorithm.credential.algorithm = -257;
  assert.deepEqual(
    await verifier.verifyAssertion({ ...wrongAlgorithm, now: NOW }),
    { verified: false, code: "attestation_policy_failed" },
  );
});

test("non-canonical base64url and insecure remote origins are rejected", async () => {
  const malformed = fixture();
  malformed.assertion.signature += "=";
  assert.deepEqual(
    await verifier.verifyAssertion({ ...malformed, now: NOW }),
    { verified: false, code: "malformed_assertion" },
  );

  const insecure = fixture({ origin: "http://airlock.example" });
  assert.deepEqual(
    await verifier.verifyAssertion({ ...insecure, now: NOW }),
    { verified: false, code: "origin_mismatch" },
  );
});
