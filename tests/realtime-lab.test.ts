import assert from "node:assert/strict";
import test from "node:test";
import type { AddressInfo } from "node:net";
import { createLabServer } from "../apps/realtime-lab/server.ts";

async function withLab(fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const server = createLabServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

async function post(baseUrl: string, path: string, body?: unknown) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { response, payload: await response.json() };
}

test("real-time lab runs the authentic provisioning and transaction path", async () => {
  await withLab(async (baseUrl) => {
    assert.equal((await fetch(`${baseUrl}/api/health`)).status, 200);
    assert.equal((await post(baseUrl, "/api/provision/request")).response.status, 200);
    const attack = await post(baseUrl, "/api/provision/attack");
    assert.equal(attack.response.status, 409);
    assert.match(attack.payload.error, /not spendable/);
    assert.equal((await post(baseUrl, "/api/provision/approve")).response.status, 200);
    const requested = await post(baseUrl, "/api/transaction/request", { amountMinor: 2_500, merchantId: "synthetic-merchant-001" });
    assert.equal(requested.response.status, 200);
    assert.equal(requested.payload.transaction.state, "confirmation_pending");
    const confirmed = await post(baseUrl, "/api/transaction/confirm");
    assert.equal(confirmed.response.status, 200);
    assert.equal(confirmed.payload.transaction.state, "confirmed");
    assert.equal(confirmed.payload.audit.valid, true);
  });
});

test("real-time lab demonstrates merged device revocation behavior", async () => {
  await withLab(async (baseUrl) => {
    await post(baseUrl, "/api/provision/request");
    await post(baseUrl, "/api/device/revoke");
    const approval = await post(baseUrl, "/api/provision/approve");
    assert.equal(approval.response.status, 409);
    assert.match(approval.payload.error, /revoked/);
    assert.equal(approval.payload.state.device.status, "revoked");
    assert.equal(approval.payload.state.audit.valid, true);
  });
});
