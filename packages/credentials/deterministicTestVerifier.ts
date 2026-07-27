import { createHmac, timingSafeEqual } from "node:crypto";
import type {
  AssertionVerificationRequest,
  AssertionVerificationResult,
  CredentialAssertion,
  CredentialChallenge,
  RegisteredCredential,
} from "./types.ts";
import type { CredentialVerifier } from "./verifier.ts";

interface TestClientData {
  type: "webauthn.get";
  challenge: string;
  origin: string;
}
interface TestAuthenticatorData {
  rpId: string;
  userPresent: boolean;
  userVerified: boolean;
  signCount: number;
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decode<T>(value: string): T | undefined {
  try {
    return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as T;
  } catch {
    return undefined;
  }
}

function signatureFor(
  secret: string,
  credentialId: string,
  clientDataJSON: string,
  authenticatorData: string,
): string {
  return createHmac("sha256", secret)
    .update(credentialId)
    .update(".")
    .update(clientDataJSON)
    .update(".")
    .update(authenticatorData)
    .digest("base64url");
}

function equalBase64Url(left: string, right: string): boolean {
  const a = Buffer.from(left, "base64url");
  const b = Buffer.from(right, "base64url");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Deterministic protocol test double.
 *
 * It deliberately uses HMAC and JSON-shaped authenticator data. It is not a
 * WebAuthn implementation, does not validate COSE keys or attestation, and
 * must never be selected by a production composition root.
 */
export class DeterministicTestCredentialVerifier implements CredentialVerifier {
  readonly #secret: string;

  constructor(secret: string) {
    if (secret.length < 16) throw new Error("test verifier secret is too short");
    this.#secret = secret;
  }

  async verifyAssertion(
    request: AssertionVerificationRequest,
  ): Promise<AssertionVerificationResult> {
    const { assertion, challenge, credential } = request;
    const nowMs = request.now.getTime();
    if (!Number.isFinite(nowMs)) return { verified: false, code: "invalid_challenge" };
    if (
      !Number.isFinite(Date.parse(challenge.issuedAt)) ||
      !Number.isFinite(Date.parse(challenge.expiresAt)) ||
      Date.parse(challenge.expiresAt) <= Date.parse(challenge.issuedAt)
    ) {
      return { verified: false, code: "invalid_challenge" };
    }
    if (nowMs >= Date.parse(challenge.expiresAt)) {
      return { verified: false, code: "expired_challenge" };
    }
    if (credential.status !== "active") {
      return { verified: false, code: "credential_revoked" };
    }
    if (assertion.credentialId !== credential.credentialId) {
      return { verified: false, code: "credential_mismatch" };
    }
    if (credential.subjectId !== challenge.subjectId) {
      return { verified: false, code: "subject_mismatch" };
    }
    if (credential.trustedDeviceId !== challenge.trustedDeviceId) {
      return { verified: false, code: "device_mismatch" };
    }
    if (credential.relyingPartyId !== challenge.relyingPartyId) {
      return { verified: false, code: "rp_id_mismatch" };
    }

    const client = decode<TestClientData>(assertion.clientDataJSON);
    const authenticator = decode<TestAuthenticatorData>(assertion.authenticatorData);
    if (
      !client ||
      client.type !== "webauthn.get" ||
      !authenticator ||
      !Number.isSafeInteger(authenticator.signCount) ||
      authenticator.signCount < 0
    ) {
      return { verified: false, code: "malformed_assertion" };
    }
    if (client.challenge !== challenge.challenge) {
      return { verified: false, code: "invalid_challenge" };
    }
    if (!challenge.allowedOrigins.includes(client.origin)) {
      return { verified: false, code: "origin_mismatch" };
    }
    if (authenticator.rpId !== challenge.relyingPartyId) {
      return { verified: false, code: "rp_id_mismatch" };
    }
    if (!authenticator.userPresent) {
      return { verified: false, code: "user_presence_required" };
    }
    if (!authenticator.userVerified) {
      return { verified: false, code: "user_verification_required" };
    }
    if (
      authenticator.signCount !== 0 &&
      credential.signCount !== 0 &&
      authenticator.signCount <= credential.signCount
    ) {
      return { verified: false, code: "counter_rollback" };
    }

    const expected = signatureFor(
      this.#secret,
      assertion.credentialId,
      assertion.clientDataJSON,
      assertion.authenticatorData,
    );
    if (!equalBase64Url(expected, assertion.signature)) {
      return { verified: false, code: "signature_invalid" };
    }
    return {
      verified: true,
      credentialId: assertion.credentialId,
      signCount: authenticator.signCount,
      userPresent: true,
      userVerified: true,
      origin: client.origin,
      relyingPartyId: authenticator.rpId,
    };
  }
}

export function createDeterministicTestAssertion(input: {
  secret: string;
  challenge: CredentialChallenge;
  credential: RegisteredCredential;
  origin?: string;
  signCount?: number;
  userPresent?: boolean;
  userVerified?: boolean;
}): CredentialAssertion {
  const clientDataJSON = encode({
    type: "webauthn.get",
    challenge: input.challenge.challenge,
    origin: input.origin ?? input.challenge.allowedOrigins[0],
  });
  const authenticatorData = encode({
    rpId: input.challenge.relyingPartyId,
    userPresent: input.userPresent ?? true,
    userVerified: input.userVerified ?? true,
    signCount: input.signCount ?? input.credential.signCount + 1,
  });
  return {
    credentialId: input.credential.credentialId,
    clientDataJSON,
    authenticatorData,
    signature: signatureFor(
      input.secret,
      input.credential.credentialId,
      clientDataJSON,
      authenticatorData,
    ),
  };
}
