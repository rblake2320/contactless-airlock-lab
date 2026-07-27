/**
 * WebAuthn-shaped boundary types for the lab.
 *
 * These types carry values to a production verifier adapter. They do not parse
 * authenticator data, validate attestation, or establish hardware provenance.
 */

export type Base64Url = string;

export interface CredentialChallenge {
  protocolVersion: "airlock-webauthn.v1";
  challengeId: string;
  /** Random WebAuthn challenge bytes, base64url encoded. */
  challenge: Base64Url;
  purpose: "enroll-trusted-device" | "approve-airlock-challenge";
  subjectId: string;
  trustedDeviceId: string;
  relyingPartyId: string;
  allowedOrigins: readonly string[];
  issuedAt: string;
  expiresAt: string;
  userVerification: "required";
}

export interface RegisteredCredential {
  credentialId: Base64Url;
  subjectId: string;
  trustedDeviceId: string;
  relyingPartyId: string;
  /** COSE public key bytes, base64url encoded for persistence/transport. */
  publicKeyCose: Base64Url;
  algorithm: number;
  signCount: number;
  status: "active" | "revoked";
  transports?: readonly (
    | "internal"
    | "hybrid"
    | "usb"
    | "nfc"
    | "ble"
  )[];
  /**
   * A production adapter sets this only from its verified registration policy.
   * "lab-unverified" is never evidence of hardware backing or attestation.
   */
  trust:
    | { level: "lab-unverified" }
    | {
        level: "attested";
        attestationFormat: string;
        aaguid: string;
        trustPathId: string;
        verifiedAt: string;
      };
}

export interface CredentialAssertion {
  credentialId: Base64Url;
  clientDataJSON: Base64Url;
  authenticatorData: Base64Url;
  signature: Base64Url;
  userHandle?: Base64Url;
}

export interface AssertionVerificationRequest {
  challenge: CredentialChallenge;
  credential: RegisteredCredential;
  assertion: CredentialAssertion;
  now: Date;
}

export type CredentialFailureCode =
  | "invalid_challenge"
  | "expired_challenge"
  | "credential_mismatch"
  | "credential_revoked"
  | "subject_mismatch"
  | "device_mismatch"
  | "rp_id_mismatch"
  | "origin_mismatch"
  | "signature_invalid"
  | "user_presence_required"
  | "user_verification_required"
  | "counter_rollback"
  | "attestation_policy_failed"
  | "malformed_assertion";

export type AssertionVerificationResult =
  | {
      verified: true;
      credentialId: Base64Url;
      signCount: number;
      userPresent: true;
      userVerified: true;
      origin: string;
      relyingPartyId: string;
    }
  | {
      verified: false;
      code: CredentialFailureCode;
    };
