import { generateDeviceKeyPair, signApproval } from "../packages/crypto/deviceKeys.ts";
import { ChallengeStore } from "../packages/state-machine/challengeStore.ts";
import { transitionProvisioning } from "../packages/state-machine/transitions.ts";

const keys = generateDeviceKeyPair("trusted-device-key-demo");
const store = new ChallengeStore();
let state = transitionProvisioning("requested", "risk_scored");
state = transitionProvisioning(state, "trusted_device_challenge");

const challenge = store.create({
  purpose: "provision-payment-token",
  subjectId: "cardholder-demo",
  accountId: "account-demo",
  paymentTokenId: "new-wallet-token-demo",
  trustedDeviceId: "existing-trusted-device-demo",
  ttlMs: 60_000,
});

const approval = signApproval(challenge, keys.keyId, keys.privateKeyPem);
store.consume(approval, keys.publicKeyPem);
state = transitionProvisioning(state, "approved");
state = transitionProvisioning(state, "token_active_full");

console.log(JSON.stringify({
  scenario: "trusted-device provisioning approval",
  challengeId: challenge.challengeId,
  result: state,
  smsOtpUsed: false,
  biometricMaterialStored: false,
}, null, 2));
