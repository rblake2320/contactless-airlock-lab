const $ = (id) => document.getElementById(id);
const short = (value, length = 13) => !value ? "—" : value.length > length ? `${value.slice(0, length)}…` : value;
const PENDING_KEYS_STORAGE = "airlock.pending-idempotency.v1";

function readPendingKeys() {
  try {
    return JSON.parse(globalThis.sessionStorage?.getItem(PENDING_KEYS_STORAGE) ?? "{}");
  } catch {
    return {};
  }
}

const pendingKeys = readPendingKeys();

function savePendingKeys() {
  try {
    globalThis.sessionStorage?.setItem(PENDING_KEYS_STORAGE, JSON.stringify(pendingKeys));
  } catch {
    // Storage denial must not prevent the local simulator from operating.
  }
}

function idempotencyFor(path, body) {
  const identity = `${path}\n${JSON.stringify(body ?? {})}`;
  pendingKeys[identity] ??= globalThis.crypto.randomUUID();
  savePendingKeys();
  return { identity, key: pendingKeys[identity] };
}

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

// Render a state-less server rejection (HttpError / 429 rate-limit) as a real
// Blocked decision. These bodies are {code, error} with NO `state`/`audit`, so
// they must NEVER be handed to render() (which dereferences state.audit) and
// must NEVER be mislabeled as a network error — they are understood server
// responses, not transport failures.
function showRejection(payload, status) {
  $("result-title").textContent = "Blocked";
  $("result-title").dataset.tone = "bad";
  $("result-message").textContent = payload.error
    ? `${payload.error} (${payload.code})`
    : `Request rejected (${payload.code ?? "ERROR"}, HTTP ${status}).`;
}

async function action(path, body, trigger) {
  // Suppress rapid re-entry (double-click / concurrent submit): one in-flight
  // request at a time — distinct from disabling the initiating control below.
  if (document.body.dataset.busy === "true") return;
  document.body.dataset.busy = "true";
  if (trigger) trigger.disabled = true; // held disabled for the whole in-flight window
  const idempotency = idempotencyFor(path, body);
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": idempotency.key,
      },
      body: JSON.stringify(body ?? {}),
    });
    const text = await response.text();
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`Server returned an unreadable response (HTTP ${response.status}).`);
    }
    delete pendingKeys[idempotency.identity];
    savePendingKeys();
    if (payload && payload.state) {
      // A domain/persistence rejection that carries authoritative state.
      render(payload.state);
    } else if (payload && typeof payload.code === "string") {
      // State-less rejection (429/400/413/415/428/431): show the real code and
      // message. No render() runs and no state changed, so restore the (possibly
      // capability-gated) initiating control to its pre-click enabled state.
      showRejection(payload, response.status);
      if (trigger) trigger.disabled = false;
    } else {
      // Success: the response is the public state snapshot itself.
      render(payload);
    }
  } catch (error) {
    // Genuine transport failure only. No render() and no state change, so
    // restore the initiating control.
    $("connection").textContent = "Connection error";
    $("result-title").textContent = "Network error";
    $("result-title").dataset.tone = "bad";
    $("result-message").textContent = error instanceof Error
      ? `The lab request did not complete: ${error.message}`
      : "The lab request did not complete. Check that the local server is running.";
    if (trigger) trigger.disabled = false;
  } finally {
    delete document.body.dataset.busy;
    // render() re-applies gating for [data-capability] controls; a trigger
    // WITHOUT a capability (Reset lab, Tamper audit copy) is never managed by
    // gating, so restore it on EVERY outcome or it stays disabled forever after
    // its in-flight disable.
    if (trigger && !trigger.hasAttribute?.("data-capability")) trigger.disabled = false;
  }
}

document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", () => action(button.dataset.action, undefined, button));
});
// A real <form> submit (not a bare click) is what makes the amount/merchant
// inputs' native required/pattern/maxlength constraints actually run: the
// browser blocks an invalid submit and shows its own validation UI before
// this listener ever fires, with no JS-side re-validation, coercion, or
// silent fallback layered on top. The server remains the sole authority —
// these attributes only reject syntactically-invalid input earlier and more
// accessibly; every value that does reach the server is still fully
// re-validated there regardless of what the browser allowed through.
$("transaction-request-form").addEventListener("submit", (event) => {
  event.preventDefault();
  // Return the promise so callers/tests can await the in-flight action.
  return action("/api/transaction/request", {
    amount: $("amount").value,
    merchantId: $("merchant").value,
  }, event.submitter ?? undefined);
});

// Announce connection-status changes (Connecting -> Live -> Reconnecting /
// Connection error) to assistive tech. Set from script so the static HTML
// stays owned by its lane. Optional-chained so a minimal/test DOM without
// setAttribute does not throw at module load.
$("connection")?.setAttribute?.("aria-live", "polite");

const events = new EventSource("/api/events");
events.addEventListener("state", (event) => {
  $("connection").textContent = "Live";
  render(JSON.parse(event.data));
});
events.onerror = () => { $("connection").textContent = "Reconnecting"; };
