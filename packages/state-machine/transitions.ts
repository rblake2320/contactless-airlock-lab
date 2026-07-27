import type { ProvisioningState, TransactionState } from "../protocol/types.ts";

const TRANSACTION_TRANSITIONS: Readonly<Record<TransactionState, readonly TransactionState[]>> = {
  received: ["confirmation_pending", "declined"],
  confirmation_pending: ["confirmed", "expired", "declined"],
  confirmed: ["clearing_received", "reversal_requested"],
  declined: [],
  expired: ["reversal_requested", "clearing_received"],
  reversal_requested: ["reversed", "clearing_received", "exception"],
  reversed: ["clearing_received"],
  clearing_received: ["settled", "exception"],
  settled: [],
  exception: [],
};

const PROVISIONING_TRANSITIONS: Readonly<Record<ProvisioningState, readonly ProvisioningState[]>> = {
  requested: ["risk_scored", "declined"],
  risk_scored: ["trusted_device_challenge", "approved", "declined"],
  trusted_device_challenge: ["approved", "declined", "expired"],
  approved: ["token_active_capped", "token_active_full"],
  token_active_capped: ["token_active_full", "declined"],
  token_active_full: [],
  declined: [],
  expired: [],
};

export function transitionTransaction(
  current: TransactionState,
  next: TransactionState,
): TransactionState {
  if (!TRANSACTION_TRANSITIONS[current].includes(next)) {
    throw new Error(`invalid transaction transition: ${current} -> ${next}`);
  }
  return next;
}

export function transitionProvisioning(
  current: ProvisioningState,
  next: ProvisioningState,
): ProvisioningState {
  if (!PROVISIONING_TRANSITIONS[current].includes(next)) {
    throw new Error(`invalid provisioning transition: ${current} -> ${next}`);
  }
  return next;
}

