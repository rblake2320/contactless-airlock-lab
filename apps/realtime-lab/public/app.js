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
  const outcome = state.lastResult.outcome ?? (state.lastResult.ok ? "accepted" : "blocked");
  $("result-title").textContent = outcome === "accepted"
    ? "Accepted"
    : outcome === "warning"
      ? "Exception"
      : "Blocked";
  $("result-title").dataset.tone = outcome === "accepted"
    ? "good"
    : outcome === "warning"
      ? "warning"
      : "bad";
  $("audit-copy-valid").textContent = state.demonstration?.name === "audit-tamper"
    ? state.demonstration.auditCopyValid ? "unexpectedly valid" : "INVALID — tampering detected"
    : "not tested";
  $("audit-copy-valid").dataset.tone = state.demonstration?.name === "audit-tamper" ? "bad" : "";
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
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    const text = await response.text();
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`Server returned an unreadable response (HTTP ${response.status}).`);
    }
    render(payload.state ?? payload);
  } catch (error) {
    $("connection").textContent = "Connection error";
    $("result-title").textContent = "Network error";
    $("result-title").dataset.tone = "bad";
    $("result-message").textContent = error instanceof Error
      ? `The lab request did not complete: ${error.message}`
      : "The lab request did not complete. Check that the local server is running.";
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
