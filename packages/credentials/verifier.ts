import type {
  AssertionVerificationRequest,
  AssertionVerificationResult,
} from "./types.ts";

/**
 * Replaceable boundary for a reviewed WebAuthn implementation.
 *
 * Production implementations must perform the checks documented in
 * docs/WEBAUTHN_BOUNDARY.md. Callers must consume an Airlock challenge only
 * after this interface returns `verified: true`.
 */
export interface CredentialVerifier {
  verifyAssertion(
    request: AssertionVerificationRequest,
  ): Promise<AssertionVerificationResult>;
}
