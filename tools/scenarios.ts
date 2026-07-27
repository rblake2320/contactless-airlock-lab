import { AirlockEngine } from "../apps/issuer-simulator/airlockEngine.ts";
import { generateDeviceKeyPair, signApproval } from "../packages/crypto/deviceKeys.ts";

interface ScenarioResult {
  scenario: string;
  passed: boolean;
  evidence: Record<string, unknown>;
}

function lab() {
  const engine = new AirlockEngine();
  const keys = generateDeviceKeyPair("trusted-device-key");
  engine.enrollTrustedDevice("cardholder", keys, "trusted-device");
  return { engine, keys };
}

function blockedFraudulentProvisioning(): ScenarioResult {
  const { engine } = lab();
  const request = engine.requestProvisioning({
    subjectId: "cardholder",
    accountId: "account",
    tokenId: "criminal-wallet-token",
    trustedDeviceId: "trusted-device",
    capMinor: 2_500,
  });
  let blocked = false;
  try {
    engine.authorize({
      transactionId: "fraud-cashout",
      tokenId: "criminal-wallet-token",
      merchantId: "gift-card-merchant",
      amountMinor: 2_000,
      strategy: "pre_authorization_step_up",
      trustedDeviceId: "trusted-device",
    });
  } catch (error) {
    blocked = error instanceof Error && error.message.includes("not spendable");
  }
  return {
    scenario: "fraudulent provisioning without trusted-device approval",
    passed: blocked,
    evidence: {
      challengeId: request.challenge.challengeId,
      provisioningState: request.state,
      tokenState: engine.getToken("criminal-wallet-token")?.state,
      authorizationBlocked: blocked,
      smsOtpUsed: false,
    },
  };
}

function legitimateProvisioningAndTransaction(): ScenarioResult {
  const { engine, keys } = lab();
  const request = engine.requestProvisioning({
    subjectId: "cardholder",
    accountId: "account",
    tokenId: "legitimate-token",
    trustedDeviceId: "trusted-device",
    capMinor: 2_500,
  });
  engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
  );
  const transaction = engine.authorize({
    transactionId: "legitimate-purchase",
    tokenId: "legitimate-token",
    merchantId: "merchant",
    amountMinor: 3_000,
    strategy: "pre_authorization_step_up",
    trustedDeviceId: "trusted-device",
  });
  const confirmed = engine.confirmTransaction(
    transaction.transactionId,
    signApproval(transaction.challenge!, keys.keyId, keys.privateKeyPem),
  );
  const cleared = engine.receiveClearing(confirmed.transactionId);
  return {
    scenario: "trusted provisioning and pre-authorization confirmation",
    passed: cleared.state === "settled" && engine.audit.verify(),
    evidence: {
      tokenState: engine.getToken("legitimate-token")?.state,
      transactionState: cleared.state,
      auditEventCount: engine.audit.all().length,
      auditChainValid: engine.audit.verify(),
    },
  };
}

function reversalClearingRace(): ScenarioResult {
  const { engine, keys } = lab();
  const request = engine.requestProvisioning({
    subjectId: "cardholder",
    accountId: "account",
    tokenId: "monitored-token",
    trustedDeviceId: "trusted-device",
    capMinor: 5_000,
  });
  engine.approveProvisioning(
    request.requestId,
    signApproval(request.challenge, keys.keyId, keys.privateKeyPem),
  );
  engine.authorize({
    transactionId: "approve-reverse-race",
    tokenId: "monitored-token",
    merchantId: "merchant",
    amountMinor: 4_000,
    strategy: "provisional_monitoring",
    trustedDeviceId: "trusted-device",
  });
  engine.expireAndReverse("approve-reverse-race");
  const result = engine.receiveClearing("approve-reverse-race");
  return {
    scenario: "clearing arrives after timeout reversal",
    passed: result.state === "exception",
    evidence: {
      transactionState: result.state,
      settlementPreventionClaimed: false,
      partnerReconciliationRequired: true,
    },
  };
}

const results = [
  blockedFraudulentProvisioning(),
  legitimateProvisioningAndTransaction(),
  reversalClearingRace(),
];
const passed = results.every((result) => result.passed);
console.log(JSON.stringify({ passed, results }, null, 2));
if (!passed) process.exitCode = 1;

