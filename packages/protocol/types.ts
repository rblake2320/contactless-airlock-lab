export type Currency = "USD" | "EUR" | "GBP" | "CAD" | "AUD";

export type ChallengePurpose =
  | "provision-payment-token"
  | "confirm-transaction";

export interface ChallengeBinding {
  protocolVersion: "airlock.v1";
  purpose: ChallengePurpose;
  challengeId: string;
  subjectId: string;
  accountId: string;
  paymentTokenId: string;
  trustedDeviceId: string;
  transactionId?: string;
  merchantId?: string;
  amountMinor?: number;
  currency?: Currency;
  issuedAt: string;
  expiresAt: string;
  audience: "airlock-issuer";
}

export interface SignedApproval {
  binding: ChallengeBinding;
  keyId: string;
  signature: string;
}

export type ChallengeStatus =
  | "created"
  | "confirmed"
  | "expired"
  | "cancelled";

export interface ChallengeRecord {
  binding: ChallengeBinding;
  status: ChallengeStatus;
  consumedAt?: string;
}

export type TransactionState =
  | "received"
  | "confirmation_pending"
  | "confirmed"
  | "declined"
  | "expired"
  | "reversal_requested"
  | "reversed"
  | "clearing_received"
  | "settled"
  | "exception";

export type ProvisioningState =
  | "requested"
  | "risk_scored"
  | "trusted_device_challenge"
  | "approved"
  | "token_active_capped"
  | "token_active_full"
  | "declined"
  | "expired";

