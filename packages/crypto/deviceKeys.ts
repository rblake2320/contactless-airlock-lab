import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { canonicalizeBinding } from "../protocol/canonical.ts";
import type { ChallengeBinding, SignedApproval } from "../protocol/types.ts";

export interface DeviceKeyPair {
  keyId: string;
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateDeviceKeyPair(keyId: string): DeviceKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return {
    keyId,
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function signApproval(
  binding: ChallengeBinding,
  keyId: string,
  privateKey: string | KeyObject,
): SignedApproval {
  const key = typeof privateKey === "string" ? createPrivateKey(privateKey) : privateKey;
  return {
    binding,
    keyId,
    signature: sign("sha256", canonicalizeBinding(binding), key).toString("base64url"),
  };
}

export function verifyApproval(
  approval: SignedApproval,
  publicKey: string | KeyObject,
): boolean {
  const key = typeof publicKey === "string" ? createPublicKey(publicKey) : publicKey;
  return verify(
    "sha256",
    canonicalizeBinding(approval.binding),
    key,
    Buffer.from(approval.signature, "base64url"),
  );
}

