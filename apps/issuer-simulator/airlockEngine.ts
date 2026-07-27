import { AuditLog } from "../../packages/audit/auditLog.ts";
import type { DeviceKeyPair } from "../../packages/crypto/deviceKeys.ts";
import type {
  ChallengeBinding,
  ProvisioningState,
  SignedApproval,
  TransactionState,
} from "../../packages/protocol/types.ts";
import { ChallengeStore } from "../../packages/state-machine/challengeStore.ts";
import {
  transitionProvisioning,
  transitionTransaction,
} from "../../packages/state-machine/transitions.ts";

export interface TrustedDevice {
  deviceId: string;
  subjectId: string;
  keyId: string;
  publicKeyPem: string;
  status: "active" | "revoked";
}

export interface PaymentToken {
  tokenId: string;
  subjectId: string;
  accountId: string;
  state: "pending" | "active_capped" | "active_full" | "declined";
  perTransactionCapMinor?: number;
  dailyCapMinor?: number;
}

export interface ProvisioningRequest {
  requestId: string;
  tokenId: string;
  trustedDeviceId: string;
  state: ProvisioningState;
  challenge: ChallengeBinding;
}

export interface TransactionRecord {
  transactionId: string;
  tokenId: string;
  merchantId: string;
  amountMinor: number;
  currency: "USD";
  state: TransactionState;
  strategy: "pre_authorization_step_up" | "provisional_monitoring";
  challenge?: ChallengeBinding;
  capReservation?: { spendKey: string; amountMinor: number };
}

export class AirlockEngine {
  readonly audit = new AuditLog();
  readonly challenges = new ChallengeStore();
  readonly #devices = new Map<string, TrustedDevice>();
  readonly #tokens = new Map<string, PaymentToken>();
  readonly #provisioning = new Map<string, ProvisioningRequest>();
  readonly #transactions = new Map<string, TransactionRecord>();
  readonly #dailySpend = new Map<string, number>();

  enrollTrustedDevice(
    subjectId: string,
    keys: Pick<DeviceKeyPair, "keyId" | "publicKeyPem">,
    deviceId = crypto.randomUUID(),
  ): TrustedDevice {
    if (this.#devices.has(deviceId)) throw new Error("trusted device id already exists");
    const device: TrustedDevice = {
      deviceId,
      subjectId,
      keyId: keys.keyId,
      publicKeyPem: keys.publicKeyPem,
      status: "active",
    };
    this.#devices.set(deviceId, device);
    this.audit.append("trusted_device.enrolled", deviceId, {
      deviceId,
      subjectId,
      keyId: keys.keyId,
    });
    return structuredClone(device);
  }

  getDevice(deviceId: string): TrustedDevice | undefined {
    const value = this.#devices.get(deviceId);
    return value ? structuredClone(value) : undefined;
  }

  revokeTrustedDevice(deviceId: string, now = new Date()): TrustedDevice {
    const device = this.#must(this.#devices, deviceId, "trusted device");
    if (device.status === "revoked") throw new Error("trusted device already revoked");
    device.status = "revoked";
    this.audit.append("trusted_device.revoked", deviceId, {
      deviceId,
      subjectId: device.subjectId,
      keyId: device.keyId,
    }, now);
    return structuredClone(device);
  }

  requestProvisioning(input: {
    subjectId: string;
    accountId: string;
    tokenId: string;
    trustedDeviceId: string;
    capMinor: number;
    now?: Date;
  }): ProvisioningRequest {
    if (this.#tokens.has(input.tokenId)) throw new Error("payment token id already exists");
    if (
      !Number.isSafeInteger(input.capMinor) ||
      input.capMinor <= 0 ||
      input.capMinor > Math.floor(Number.MAX_SAFE_INTEGER / 2)
    ) {
      throw new Error("cap must be a positive safe integer");
    }
    const device = this.#requireActiveDevice(input.trustedDeviceId, input.subjectId);
    const requestId = crypto.randomUUID();
    const token: PaymentToken = {
      tokenId: input.tokenId,
      subjectId: input.subjectId,
      accountId: input.accountId,
      state: "pending",
      perTransactionCapMinor: input.capMinor,
      dailyCapMinor: input.capMinor * 2,
    };
    this.#tokens.set(token.tokenId, token);
    let state: ProvisioningState = "requested";
    state = transitionProvisioning(state, "risk_scored");
    state = transitionProvisioning(state, "trusted_device_challenge");
    const challenge = this.challenges.create(
      {
        purpose: "provision-payment-token",
        subjectId: input.subjectId,
        accountId: input.accountId,
        paymentTokenId: input.tokenId,
        trustedDeviceId: device.deviceId,
        ttlMs: 120_000,
      },
      input.now,
    );
    const request = { requestId, tokenId: token.tokenId, trustedDeviceId: device.deviceId, state, challenge };
    this.#provisioning.set(requestId, request);
    this.audit.append("provisioning.challenge_created", requestId, {
      requestId,
      tokenId: token.tokenId,
      trustedDeviceId: device.deviceId,
      challengeId: challenge.challengeId,
    }, input.now);
    return structuredClone(request);
  }

  approveProvisioning(
    requestId: string,
    approval: SignedApproval,
    now = new Date(),
    activation: "capped" | "full" = "full",
  ): ProvisioningRequest {
    if (activation !== "capped" && activation !== "full") {
      throw new Error("invalid activation mode");
    }
    const request = this.#must(this.#provisioning, requestId, "provisioning request");
    const device = this.#requireActiveDevice(request.trustedDeviceId);
    if (approval.keyId !== device.keyId) throw new Error("device key id mismatch");
    this.challenges.consume(approval, device.publicKeyPem, now);
    request.state = transitionProvisioning(request.state, "approved");
    request.state = transitionProvisioning(
      request.state,
      activation === "capped" ? "token_active_capped" : "token_active_full",
    );
    const token = this.#must(this.#tokens, request.tokenId, "payment token");
    token.state = activation === "capped" ? "active_capped" : "active_full";
    if (activation === "full") {
      delete token.perTransactionCapMinor;
      delete token.dailyCapMinor;
    }
    this.audit.append("provisioning.approved", requestId, {
      requestId,
      tokenId: token.tokenId,
      challengeId: approval.binding.challengeId,
      activation,
    }, now);
    return structuredClone(request);
  }

  authorize(input: {
    transactionId: string;
    tokenId: string;
    merchantId: string;
    amountMinor: number;
    strategy: TransactionRecord["strategy"];
    trustedDeviceId: string;
    now?: Date;
  }): TransactionRecord {
    if (this.#transactions.has(input.transactionId)) {
      throw new Error("transaction id already exists");
    }
    if (!Number.isSafeInteger(input.amountMinor) || input.amountMinor <= 0) {
      throw new Error("transaction amount must be a positive safe integer");
    }
    if (
      input.strategy !== "pre_authorization_step_up" &&
      input.strategy !== "provisional_monitoring"
    ) {
      throw new Error("invalid transaction strategy");
    }
    const token = this.#must(this.#tokens, input.tokenId, "payment token");
    if (token.state === "pending" || token.state === "declined") {
      throw new Error("payment token is not spendable");
    }
    this.#requireActiveDevice(input.trustedDeviceId, token.subjectId);
    if (
      token.state === "active_capped" &&
      input.amountMinor > (token.perTransactionCapMinor ?? 0)
    ) {
      throw new Error("transaction exceeds new-token cap");
    }
    let capReservation: TransactionRecord["capReservation"];
    if (token.state === "active_capped") {
      const day = (input.now ?? new Date()).toISOString().slice(0, 10);
      const spendKey = `${token.tokenId}:${day}`;
      const nextTotal = (this.#dailySpend.get(spendKey) ?? 0) + input.amountMinor;
      if (nextTotal > (token.dailyCapMinor ?? 0)) {
        throw new Error("transaction exceeds new-token daily cap");
      }
      this.#dailySpend.set(spendKey, nextTotal);
      capReservation = { spendKey, amountMinor: input.amountMinor };
    }
    let state: TransactionState = "received";
    state = transitionTransaction(state, "confirmation_pending");
    const challenge = this.challenges.create(
      {
        purpose: "confirm-transaction",
        subjectId: token.subjectId,
        accountId: token.accountId,
        paymentTokenId: token.tokenId,
        trustedDeviceId: input.trustedDeviceId,
        transactionId: input.transactionId,
        merchantId: input.merchantId,
        amountMinor: input.amountMinor,
        currency: "USD",
        ttlMs: 30_000,
      },
      input.now,
    );
    const transaction: TransactionRecord = {
      transactionId: input.transactionId,
      tokenId: token.tokenId,
      merchantId: input.merchantId,
      amountMinor: input.amountMinor,
      currency: "USD",
      strategy: input.strategy,
      state,
      challenge,
      capReservation,
    };
    this.#transactions.set(input.transactionId, transaction);
    this.audit.append("transaction.confirmation_pending", input.transactionId, {
      strategy: input.strategy,
      challengeId: challenge.challengeId,
      amountMinor: input.amountMinor,
      merchantId: input.merchantId,
    }, input.now);
    return structuredClone(transaction);
  }

  confirmTransaction(
    transactionId: string,
    approval: SignedApproval,
    now = new Date(),
  ): TransactionRecord {
    const transaction = this.#must(this.#transactions, transactionId, "transaction");
    if (!transaction.challenge) throw new Error("transaction has no challenge");
    const device = this.#requireActiveDevice(transaction.challenge.trustedDeviceId);
    if (approval.keyId !== device.keyId) throw new Error("device key id mismatch");
    this.challenges.consume(approval, device.publicKeyPem, now);
    transaction.state = transitionTransaction(transaction.state, "confirmed");
    this.audit.append("transaction.confirmed", transactionId, {
      challengeId: approval.binding.challengeId,
      strategy: transaction.strategy,
    }, now);
    return structuredClone(transaction);
  }

  expireAndReverse(transactionId: string, now = new Date()): TransactionRecord {
    const transaction = this.#must(this.#transactions, transactionId, "transaction");
    transaction.state = transitionTransaction(transaction.state, "expired");
    transaction.state = transitionTransaction(transaction.state, "reversal_requested");
    transaction.state = transitionTransaction(transaction.state, "reversed");
    this.#releaseCapReservation(transaction);
    this.audit.append("transaction.reversed_after_timeout", transactionId, {
      strategy: transaction.strategy,
      settlementPrevented: false,
    }, now);
    return structuredClone(transaction);
  }

  receiveClearing(transactionId: string, now = new Date()): TransactionRecord {
    const transaction = this.#must(this.#transactions, transactionId, "transaction");
    const reversedBeforeClearing = [
      "expired",
      "reversal_requested",
      "reversed",
    ].includes(transaction.state);
    transaction.state = transitionTransaction(transaction.state, "clearing_received");
    transaction.state = transitionTransaction(
      transaction.state,
      reversedBeforeClearing ? "exception" : "settled",
    );
    this.audit.append("transaction.clearing_received", transactionId, {
      resultingState: transaction.state,
      reversedBeforeClearing,
    }, now);
    return structuredClone(transaction);
  }

  getToken(tokenId: string): PaymentToken | undefined {
    const value = this.#tokens.get(tokenId);
    return value ? structuredClone(value) : undefined;
  }

  getTransaction(transactionId: string): TransactionRecord | undefined {
    const value = this.#transactions.get(transactionId);
    return value ? structuredClone(value) : undefined;
  }

  #requireActiveDevice(deviceId: string, subjectId?: string): TrustedDevice {
    const device = this.#must(this.#devices, deviceId, "trusted device");
    if (device.status !== "active") throw new Error("trusted device is revoked");
    if (subjectId && device.subjectId !== subjectId) throw new Error("trusted device subject mismatch");
    return device;
  }

  #releaseCapReservation(transaction: TransactionRecord): void {
    if (!transaction.capReservation) return;
    const { spendKey, amountMinor } = transaction.capReservation;
    const remaining = Math.max(0, (this.#dailySpend.get(spendKey) ?? 0) - amountMinor);
    if (remaining === 0) this.#dailySpend.delete(spendKey);
    else this.#dailySpend.set(spendKey, remaining);
    delete transaction.capReservation;
  }

  #must<K, V>(map: Map<K, V>, key: K, label: string): V {
    const value = map.get(key);
    if (!value) throw new Error(`unknown ${label}`);
    return value;
  }
}
