import { AuditLog, type AuditLogSnapshot } from "../../packages/audit/auditLog.ts";
import { timingSafeEqual } from "node:crypto";
import type { DeviceKeyPair } from "../../packages/crypto/deviceKeys.ts";
import type {
  ChallengeBinding,
  ProvisioningState,
  SignedApproval,
  TransactionState,
} from "../../packages/protocol/types.ts";
import { canonicalizeBinding } from "../../packages/protocol/canonical.ts";
import {
  ChallengeStore,
  type ChallengeStoreSnapshot,
} from "../../packages/state-machine/challengeStore.ts";
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

export interface AirlockEngineSnapshot {
  schemaVersion: 1;
  audit: AuditLogSnapshot;
  challenges: ChallengeStoreSnapshot;
  devices: TrustedDevice[];
  tokens: PaymentToken[];
  provisioning: ProvisioningRequest[];
  transactions: TransactionRecord[];
  dailySpend: Array<{ spendKey: string; amountMinor: number }>;
}

export class AirlockEngine {
  readonly audit: AuditLog;
  readonly challenges: ChallengeStore;
  readonly #devices = new Map<string, TrustedDevice>();
  readonly #tokens = new Map<string, PaymentToken>();
  readonly #provisioning = new Map<string, ProvisioningRequest>();
  readonly #transactions = new Map<string, TransactionRecord>();
  readonly #dailySpend = new Map<string, number>();

  constructor(audit = new AuditLog(), challenges = new ChallengeStore()) {
    this.audit = audit;
    this.challenges = challenges;
  }

  static restore(snapshot: AirlockEngineSnapshot): AirlockEngine {
    if (
      !snapshot ||
      snapshot.schemaVersion !== 1 ||
      !Array.isArray(snapshot.devices) ||
      !Array.isArray(snapshot.tokens) ||
      !Array.isArray(snapshot.provisioning) ||
      !Array.isArray(snapshot.transactions) ||
      !Array.isArray(snapshot.dailySpend)
    ) {
      throw new Error("invalid engine snapshot");
    }
    const engine = new AirlockEngine(
      AuditLog.restore(snapshot.audit),
      ChallengeStore.restore(snapshot.challenges),
    );
    for (const device of snapshot.devices) {
      if (
        !device ||
        typeof device.deviceId !== "string" ||
        typeof device.subjectId !== "string" ||
        typeof device.keyId !== "string" ||
        typeof device.publicKeyPem !== "string" ||
        !["active", "revoked"].includes(device.status)
      ) {
        throw new Error("invalid trusted device snapshot");
      }
      engine.#restoreUnique(engine.#devices, device.deviceId, device, "trusted device");
    }
    for (const token of snapshot.tokens) {
      if (
        !token ||
        typeof token.tokenId !== "string" ||
        typeof token.subjectId !== "string" ||
        typeof token.accountId !== "string" ||
        !["pending", "active_capped", "active_full", "declined"].includes(token.state)
      ) {
        throw new Error("invalid payment token snapshot");
      }
      if (
        token.state === "active_capped" &&
        (!Number.isSafeInteger(token.perTransactionCapMinor) ||
          (token.perTransactionCapMinor ?? 0) <= 0 ||
          !Number.isSafeInteger(token.dailyCapMinor) ||
          (token.dailyCapMinor ?? 0) <= 0)
      ) {
        throw new Error("invalid capped token snapshot");
      }
      engine.#restoreUnique(engine.#tokens, token.tokenId, token, "payment token");
    }
    for (const request of snapshot.provisioning) {
      const token = request && engine.#tokens.get(request.tokenId);
      const device = request && engine.#devices.get(request.trustedDeviceId);
      if (
        !request ||
        typeof request.requestId !== "string" ||
        !token ||
        !device ||
        !engine.challenges.get(request.challenge?.challengeId) ||
        request.challenge.purpose !== "provision-payment-token" ||
        request.challenge.paymentTokenId !== request.tokenId ||
        request.challenge.trustedDeviceId !== request.trustedDeviceId ||
        request.challenge.subjectId !== token.subjectId ||
        request.challenge.accountId !== token.accountId ||
        device.subjectId !== token.subjectId ||
        ![
          "requested", "risk_scored", "trusted_device_challenge", "approved",
          "token_active_capped", "token_active_full", "declined", "expired",
        ].includes(request.state)
      ) {
        throw new Error("invalid provisioning snapshot");
      }
      engine.#assertStoredChallengeMatches(request.challenge);
      engine.#assertProvisioningChallengeStatus(request);
      engine.#restoreUnique(engine.#provisioning, request.requestId, request, "provisioning request");
    }
    for (const transaction of snapshot.transactions) {
      const token = transaction && engine.#tokens.get(transaction.tokenId);
      const challengeDevice = transaction?.challenge
        ? engine.#devices.get(transaction.challenge.trustedDeviceId)
        : undefined;
      if (
        !transaction ||
        typeof transaction.transactionId !== "string" ||
        !token ||
        !Number.isSafeInteger(transaction.amountMinor) ||
        transaction.amountMinor <= 0 ||
        transaction.currency !== "USD" ||
        !["pre_authorization_step_up", "provisional_monitoring"].includes(transaction.strategy) ||
        !transaction.challenge ||
        transaction.challenge.purpose !== "confirm-transaction" ||
        transaction.challenge.transactionId !== transaction.transactionId ||
        transaction.challenge.paymentTokenId !== transaction.tokenId ||
        transaction.challenge.subjectId !== token.subjectId ||
        transaction.challenge.accountId !== token.accountId ||
        transaction.challenge.merchantId !== transaction.merchantId ||
        transaction.challenge.amountMinor !== transaction.amountMinor ||
        transaction.challenge.currency !== transaction.currency ||
        !challengeDevice ||
        challengeDevice.subjectId !== token.subjectId ||
        ![
          "received", "confirmation_pending", "confirmed", "declined", "expired",
          "reversal_requested", "reversed", "clearing_received", "settled", "exception",
        ].includes(transaction.state)
      ) {
        throw new Error("invalid transaction snapshot");
      }
      engine.#assertStoredChallengeMatches(transaction.challenge);
      engine.#assertTransactionChallengeStatus(transaction);
      engine.#restoreUnique(
        engine.#transactions,
        transaction.transactionId,
        transaction,
        "transaction",
      );
    }
    for (const spend of snapshot.dailySpend) {
      const separator = spend?.spendKey?.lastIndexOf(":") ?? -1;
      const tokenId = separator > 0 ? spend.spendKey.slice(0, separator) : "";
      const day = separator > 0 ? spend.spendKey.slice(separator + 1) : "";
      const spendToken = engine.#tokens.get(tokenId);
      if (
        !spend ||
        typeof spend.spendKey !== "string" ||
        !spendToken ||
        spendToken.state !== "active_capped" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
        new Date(`${day}T00:00:00.000Z`).toISOString().slice(0, 10) !== day ||
        !Number.isSafeInteger(spend.amountMinor) ||
        spend.amountMinor <= 0 ||
        engine.#dailySpend.has(spend.spendKey)
      ) {
        throw new Error("invalid daily-spend snapshot");
      }
      engine.#dailySpend.set(spend.spendKey, spend.amountMinor);
    }
    const reservedSpend = new Map<string, number>();
    for (const transaction of engine.#transactions.values()) {
      if (!transaction.capReservation) continue;
      const { spendKey, amountMinor } = transaction.capReservation;
      if (
        typeof spendKey !== "string" ||
        !Number.isSafeInteger(amountMinor) ||
        amountMinor <= 0 ||
        spendKey !== `${transaction.tokenId}:${transaction.challenge!.issuedAt.slice(0, 10)}`
      ) {
        throw new Error("invalid cap reservation snapshot");
      }
      reservedSpend.set(spendKey, (reservedSpend.get(spendKey) ?? 0) + amountMinor);
    }
    if (
      reservedSpend.size !== engine.#dailySpend.size ||
      [...reservedSpend].some(
        ([key, amount]) => engine.#dailySpend.get(key) !== amount,
      )
    ) {
      throw new Error("daily-spend snapshot does not match reservations");
    }
    return engine;
  }

  snapshot(): AirlockEngineSnapshot {
    return {
      schemaVersion: 1,
      audit: this.audit.snapshot(),
      challenges: this.challenges.snapshot(),
      devices: structuredClone([...this.#devices.values()]),
      tokens: structuredClone([...this.#tokens.values()]),
      provisioning: structuredClone([...this.#provisioning.values()]),
      transactions: structuredClone([...this.#transactions.values()]),
      dailySpend: [...this.#dailySpend].map(([spendKey, amountMinor]) => ({
        spendKey,
        amountMinor,
      })),
    };
  }

  enrollTrustedDevice(
    subjectId: string,
    keys: Pick<DeviceKeyPair, "keyId" | "publicKeyPem">,
    deviceId: string = crypto.randomUUID(),
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
    if (!transaction.challenge) throw new Error("transaction has no challenge");
    this.challenges.cancel(transaction.challenge.challengeId, now);
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

  #assertStoredChallengeMatches(binding: ChallengeBinding): void {
    const stored = this.challenges.get(binding.challengeId);
    const storedCanonical = stored ? canonicalizeBinding(stored.binding) : undefined;
    const referenceCanonical = canonicalizeBinding(binding);
    if (
      !stored ||
      !storedCanonical ||
      storedCanonical.length !== referenceCanonical.length ||
      !timingSafeEqual(storedCanonical, referenceCanonical)
    ) {
      throw new Error("snapshot challenge reference mismatch");
    }
  }

  /**
   * A restored aggregate may only reference a challenge status that its
   * lifecycle could have produced. This prevents a fabricated active token
   * from retaining a consumable challenge.
   */
  #assertProvisioningChallengeStatus(request: ProvisioningRequest): void {
    const status = this.challenges.get(request.challenge.challengeId)!.status;
    const expected: Readonly<Record<ProvisioningState, readonly string[]>> = {
      requested: ["created"],
      risk_scored: ["created"],
      trusted_device_challenge: ["created"],
      approved: ["confirmed"],
      token_active_capped: ["confirmed"],
      token_active_full: ["confirmed"],
      declined: ["cancelled"],
      expired: ["expired"],
    };
    if (!expected[request.state].includes(status)) {
      throw new Error("provisioning lifecycle/challenge status mismatch");
    }
  }

  /**
   * Confirmation-derived states require a confirmed challenge. Timeout and
   * decline paths require cancellation; timeout reversal cancels at source.
   * Reversal/clearing exception states accept either origin because the state
   * graph permits both a confirmed-transaction reversal and a timeout reversal.
   */
  #assertTransactionChallengeStatus(transaction: TransactionRecord): void {
    const status = this.challenges.get(transaction.challenge!.challengeId)!.status;
    const expected: Readonly<Record<TransactionState, readonly string[]>> = {
      received: ["created"],
      confirmation_pending: ["created"],
      confirmed: ["confirmed"],
      declined: ["cancelled"],
      expired: ["cancelled", "expired"],
      reversal_requested: ["confirmed", "cancelled", "expired"],
      reversed: ["confirmed", "cancelled", "expired"],
      clearing_received: ["confirmed", "cancelled", "expired"],
      settled: ["confirmed"],
      exception: ["confirmed", "cancelled", "expired"],
    };
    if (!expected[transaction.state].includes(status)) {
      throw new Error("transaction lifecycle/challenge status mismatch");
    }
  }

  #restoreUnique<K, V>(map: Map<K, V>, key: K, value: V, label: string): void {
    if (map.has(key)) throw new Error(`duplicate ${label} in snapshot`);
    map.set(key, structuredClone(value));
  }

  #must<K, V>(map: Map<K, V>, key: K, label: string): V {
    const value = map.get(key);
    if (!value) throw new Error(`unknown ${label}`);
    return value;
  }
}
