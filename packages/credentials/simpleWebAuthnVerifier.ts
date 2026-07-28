import { createHash, timingSafeEqual } from "node:crypto";
import {
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  Base64URLString,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import type { CredentialVerifier } from "./verifier.ts";
import type {
  AssertionVerificationRequest,
  AssertionVerificationResult,
  Base64Url,
  CredentialFailureCode,
} from "./types.ts";

const MAX_ENCODED_FIELD = 16_384;
const MAX_CREDENTIAL_ID_BYTES = 1_024;
const MAX_PUBLIC_KEY_BYTES = 2_048;
const ES256_COSE_ALGORITHM = -7;
const UINT32_MAX = 0xffff_ffff;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CHALLENGE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

class AssertionRejected extends Error {
  readonly code: CredentialFailureCode;

  constructor(code: CredentialFailureCode) {
    super(code);
    this.code = code;
  }
}

function reject(code: CredentialFailureCode): never {
  throw new AssertionRejected(code);
}

function decodeBase64Url(
  value: Base64Url,
  maximumBytes: number,
): Uint8Array<ArrayBuffer> {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ENCODED_FIELD ||
    !BASE64URL.test(value)
  ) {
    reject("malformed_assertion");
  }
  const bytes = Buffer.from(value, "base64url");
  if (
    bytes.length === 0 ||
    bytes.length > maximumBytes ||
    bytes.toString("base64url") !== value
  ) {
    reject("malformed_assertion");
  }
  return Uint8Array.from(bytes);
}

function parseDate(value: string): number {
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch)) reject("invalid_challenge");
  return epoch;
}

function assertSafeCounter(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
    reject("malformed_assertion");
  }
}

function normalizeOrigin(value: unknown): string {
  if (typeof value !== "string") reject("malformed_assertion");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    reject("malformed_assertion");
  }
  if (
    parsed.origin !== value ||
    (parsed.protocol !== "https:" &&
      !(parsed.protocol === "http:" &&
        (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1")))
  ) {
    reject("origin_mismatch");
  }
  return parsed.origin;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Production authentication adapter backed by @simplewebauthn/server.
 *
 * This verifies an already-registered credential assertion. Registration,
 * attestation trust, authenticator hardware provenance, and persistence of the
 * returned signCount are intentionally separate integration gates.
 */
export class SimpleWebAuthnCredentialVerifier implements CredentialVerifier {
  async verifyAssertion(
    request: AssertionVerificationRequest,
  ): Promise<AssertionVerificationResult> {
    try {
      const { assertion, challenge, credential } = request;
      const now = request.now.getTime();
      if (!Number.isFinite(now)) reject("invalid_challenge");
      if (challenge.protocolVersion !== "airlock-webauthn.v1") {
        reject("invalid_challenge");
      }
      // This adapter verifies authentication assertions only. Registration
      // and enrollment ceremonies have a separate verifier and cannot be
      // relabeled into an approval assertion.
      if (challenge.purpose !== "approve-airlock-challenge") {
        reject("invalid_challenge");
      }
      if (
        typeof challenge.challengeId !== "string" ||
        !CHALLENGE_ID.test(challenge.challengeId)
      ) {
        reject("invalid_challenge");
      }

      const issuedAt = parseDate(challenge.issuedAt);
      const expiresAt = parseDate(challenge.expiresAt);
      if (expiresAt <= issuedAt || now < issuedAt) reject("invalid_challenge");
      if (now >= expiresAt) reject("expired_challenge");
      if (challenge.userVerification !== "required") {
        reject("invalid_challenge");
      }
      decodeBase64Url(challenge.challenge, 1_024);

      if (credential.status !== "active") reject("credential_revoked");
      if (assertion.credentialId !== credential.credentialId) {
        reject("credential_mismatch");
      }
      decodeBase64Url(credential.credentialId, MAX_CREDENTIAL_ID_BYTES);
      if (credential.subjectId !== challenge.subjectId) {
        reject("subject_mismatch");
      }
      if (credential.trustedDeviceId !== challenge.trustedDeviceId) {
        reject("device_mismatch");
      }
      if (credential.relyingPartyId !== challenge.relyingPartyId) {
        reject("rp_id_mismatch");
      }
      if (
        !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(
          challenge.relyingPartyId,
        )
      ) {
        reject("rp_id_mismatch");
      }
      if (credential.algorithm !== ES256_COSE_ALGORITHM) {
        reject("attestation_policy_failed");
      }
      assertSafeCounter(credential.signCount);
      const publicKey = decodeBase64Url(
        credential.publicKeyCose,
        MAX_PUBLIC_KEY_BYTES,
      );

      if (
        !Array.isArray(challenge.allowedOrigins) ||
        challenge.allowedOrigins.length === 0 ||
        challenge.allowedOrigins.length > 16
      ) {
        reject("invalid_challenge");
      }
      const expectedOrigins = challenge.allowedOrigins.map(normalizeOrigin);
      if (new Set(expectedOrigins).size !== expectedOrigins.length) {
        reject("invalid_challenge");
      }

      const clientDataBytes = decodeBase64Url(assertion.clientDataJSON, 8_192);
      let clientData: unknown;
      try {
        clientData = JSON.parse(Buffer.from(clientDataBytes).toString("utf8"));
      } catch {
        reject("malformed_assertion");
      }
      if (!clientData || typeof clientData !== "object") {
        reject("malformed_assertion");
      }
      const client = clientData as Record<string, unknown>;
      if (client.type !== "webauthn.get") reject("malformed_assertion");
      if (client.challenge !== challenge.challenge) reject("invalid_challenge");
      const actualOrigin = normalizeOrigin(client.origin);
      if (!expectedOrigins.includes(actualOrigin)) reject("origin_mismatch");
      if (client.crossOrigin === true) reject("origin_mismatch");

      const authenticatorData = decodeBase64Url(
        assertion.authenticatorData,
        4_096,
      );
      if (authenticatorData.length < 37) reject("malformed_assertion");
      const expectedRpIdHash = createHash("sha256")
        .update(challenge.relyingPartyId, "utf8")
        .digest();
      if (!equalBytes(authenticatorData.subarray(0, 32), expectedRpIdHash)) {
        reject("rp_id_mismatch");
      }
      const flags = authenticatorData[32]!;
      if ((flags & 0x01) === 0) reject("user_presence_required");
      if ((flags & 0x04) === 0) reject("user_verification_required");
      const assertedCounter = Buffer.from(authenticatorData).readUInt32BE(33);
      if (
        (credential.signCount !== 0 || assertedCounter !== 0) &&
        assertedCounter <= credential.signCount
      ) {
        reject("counter_rollback");
      }

      decodeBase64Url(assertion.signature, 1_024);
      if (assertion.userHandle !== undefined) {
        decodeBase64Url(assertion.userHandle, 1_024);
      }

      const response: AuthenticationResponseJSON = {
        id: credential.credentialId as Base64URLString,
        rawId: credential.credentialId as Base64URLString,
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: assertion.clientDataJSON as Base64URLString,
          authenticatorData: assertion.authenticatorData as Base64URLString,
          signature: assertion.signature as Base64URLString,
          userHandle: assertion.userHandle as Base64URLString | undefined,
        },
      };
      const webAuthnCredential: WebAuthnCredential = {
        id: credential.credentialId as Base64URLString,
        publicKey,
        counter: credential.signCount,
        transports: credential.transports as
          | AuthenticatorTransportFuture[]
          | undefined,
      };
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: expectedOrigins,
        expectedRPID: challenge.relyingPartyId,
        expectedType: "webauthn.get",
        credential: webAuthnCredential,
        requireUserVerification: true,
      });
      if (!verification.verified) reject("signature_invalid");

      const info = verification.authenticationInfo;
      assertSafeCounter(info.newCounter);
      if (
        info.credentialID !== credential.credentialId ||
        info.origin !== actualOrigin ||
        info.rpID !== challenge.relyingPartyId
      ) {
        reject("signature_invalid");
      }
      if (!info.userVerified) reject("user_verification_required");

      return {
        verified: true,
        credentialId: credential.credentialId,
        signCount: info.newCounter,
        userPresent: true,
        userVerified: true,
        origin: info.origin,
        relyingPartyId: info.rpID,
      };
    } catch (error) {
      if (error instanceof AssertionRejected) {
        return { verified: false, code: error.code };
      }
      // Library parsing and cryptographic errors are deliberately not exposed.
      return { verified: false, code: "signature_invalid" };
    }
  }
}
