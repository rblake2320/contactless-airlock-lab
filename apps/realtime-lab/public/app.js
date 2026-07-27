const $ = (id) => document.getElementById(id);
const short = (value, length = 13) => !value ? "—" : value.length > length ? `${value.slice(0, length)}…` : value;

function render(state) {
  $("device-state").textContent = state.device?.status ?? "absent";
  $("device-state").dataset.tone = state.device?.status === "active" ? "good" : "bad";
  $("device-key").textContent = short(state.device?.keyId);
  $("request-state").textContent = state.provisioning?.state ?? "not requested";
  $("token-state").textContent = state.token?.state ?? "absent";
  $("transaction-state").textContent = state.transaction?.state ?? "absent";
  $("challenge-id").textContent = short(state.transaction?.challenge?.challengeId);
  $("strategy").textContent = state.transaction?.strategy?.replaceAll("_", " ") ?? "—";
  $("bound-amount").textContent = state.confirmation?.amountMinor
    ? `${(state.confirmation.amountMinor / 100).toFixed(2)} ${state.confirmation.currency}`
    : "—";
  $("bound-merchant").textContent = state.confirmation?.merchantId ?? "—";
  $("bound-token").textContent = state.confirmation?.paymentTokenId ?? "—";
  $("bound-device").textContent = state.confirmation?.trustedDeviceId ?? "—";
  $("bound-nonce").textContent = short(state.confirmation?.challengeId, 20);
  $("bound-expiry").textContent = state.confirmation?.expiresAt
    ? new Date(state.confirmation.expiresAt).toLocaleTimeString()
    : "—";
  $("audit-valid").textContent = state.audit.valid ? "valid" : "INVALID";
  $("audit-valid").dataset.tone = state.audit.valid ? "good" : "bad";
  $("result-title").textContent = state.lastResult.ok ? "Accepted" : "Blocked";
  $("result-title").dataset.tone = state.lastResult.ok ? "good" : "bad";
  $("result-message").textContent = state.lastResult.message;
  $("event-count").textContent = `${state.audit.events.length} event${state.audit.events.length === 1 ? "" : "s"}`;
  $("events").replaceChildren(...state.audit.events.slice().reverse().map((event) => {
    const item = document.createElement("li");
    const top = document.createElement("div");
    const type = document.createElement("strong");
    const time = document.createElement("time");
    const hash = document.createElement("code");
    type.textContent = event.type;
    time.textContent = new Date(event.occurredAt).toLocaleTimeString();
    time.dateTime = event.occurredAt;
    hash.textContent = `${event.hash.slice(0, 18)}… ← ${event.previousHash === "GENESIS" ? "GENESIS" : `${event.previousHash.slice(0, 10)}…`}`;
    top.append(type, time);
    item.append(top, hash);
    return item;
  }));
  document.querySelectorAll("[data-capability]").forEach((button) => {
    button.disabled = !state.actions[button.dataset.capability];
  });
}

async function action(path, body) {
  document.body.dataset.busy = "true";
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const payload = await response.json();
    render(payload.state ?? payload);
  } finally {
    delete document.body.dataset.busy;
  }
}

document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", () => action(button.dataset.action));
});
$("request-transaction").addEventListener("click", () => action("/api/transaction/request", {
  amount: $("amount").value,
  merchantId: $("merchant").value,
}));

const events = new EventSource("/api/events");
events.addEventListener("state", (event) => {
  $("connection").textContent = "Live";
  render(JSON.parse(event.data));
});
events.onerror = () => { $("connection").textContent = "Reconnecting"; };
