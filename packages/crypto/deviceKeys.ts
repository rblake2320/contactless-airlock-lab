import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalizeBinding } from "../protocol/canonical.ts";
import type {
  ApprovalAlgorithm,
  ChallengeBinding,
  SignedApproval,
} from "../protocol/types.ts";

export const APPROVAL_ALGORITHM: ApprovalAlgorithm =
  "airlock.ecdsa-p256-sha256-der.v1";

export interface DeviceKeyPair {
  keyId: string;
  algorithm: ApprovalAlgorithm;
  privateKeyPem: string;
  publicKeyPem: string;
}

function assertAlgorithm(algorithm: unknown): asserts algorithm is ApprovalAlgorithm {
  if (algorithm !== APPROVAL_ALGORITHM) {
    throw new Error("unsupported approval algorithm");
  }
}

function assertP256Key(key: KeyObject, kind: "private" | "public"): void {
  if (
    key.type !== kind ||
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new Error(`approval ${kind} key does not match algorithm profile`);
  }
}

function approvalPayload(
  binding: ChallengeBinding,
  algorithm: ApprovalAlgorithm,
): Buffer {
  const domain = Buffer.from(`airlock-signed-approval.v1\0${algorithm}\0`, "utf8");
  return Buffer.concat([domain, Buffer.from(canonicalizeBinding(binding))]);
}

export function validatePublicKeyProfile(
  publicKey: string | KeyObject,
  algorithm: unknown,
): KeyObject {
  assertAlgorithm(algorithm);
  const key = typeof publicKey === "string" ? createPublicKey(publicKey) : publicKey;
  assertP256Key(key, "public");
  return key;
}

export function generateDeviceKeyPair(keyId: string): DeviceKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return {
    keyId,
    algorithm: APPROVAL_ALGORITHM,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function signApproval(
  binding: ChallengeBinding,
  keyId: string,
  privateKey: string | KeyObject,
  algorithm: ApprovalAlgorithm = APPROVAL_ALGORITHM,
): SignedApproval {
  assertAlgorithm(algorithm);
  const key = typeof privateKey === "string" ? createPrivateKey(privateKey) : privateKey;
  assertP256Key(key, "private");
  return {
    binding,
    keyId,
    algorithm,
    signature: sign("sha256", approvalPayload(binding, algorithm), key).toString("base64url"),
  };
}

export function verifyApproval(
  approval: SignedApproval,
  publicKey: string | KeyObject,
  expectedAlgorithm: ApprovalAlgorithm = APPROVAL_ALGORITHM,
): boolean {
  assertAlgorithm(expectedAlgorithm);
  if (approval.algorithm !== expectedAlgorithm) {
    throw new Error("approval algorithm mismatch");
  }
  const key = validatePublicKeyProfile(publicKey, expectedAlgorithm);
  return verify(
    "sha256",
    approvalPayload(approval.binding, approval.algorithm),
    key,
    Buffer.from(approval.signature, "base64url"),
  );
}
