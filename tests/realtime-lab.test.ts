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
    const requested = await post(baseUrl, "/api/transaction/request", { amount: "25.00", merchantId: "synthetic-merchant-001" });
    assert.equal(requested.response.status, 200);
    assert.equal(requested.payload.transaction.state, "confirmation_pending");
    const confirmed = await post(baseUrl, "/api/transaction/confirm");
    assert.equal(confirmed.response.status, 200);
    assert.equal(confirmed.payload.transaction.state, "confirmed");
    assert.equal(confirmed.payload.audit.valid, true);
  });
});

test("real-time lab strictly rejects malformed transaction input without fallback", async () => {
  const invalidAmounts = ["", "abc", "25.001", "1e309", "90071992547409.92"];
  for (const amount of invalidAmounts) {
    await withLab(async (baseUrl) => {
      await post(baseUrl, "/api/provision/request");
      await post(baseUrl, "/api/provision/approve");
      const result = await post(baseUrl, "/api/transaction/request", {
        amount,
        merchantId: "synthetic-merchant-001",
      });
      assert.equal(result.response.status, 409, `amount ${JSON.stringify(amount)} should fail`);
      assert.equal(result.payload.state.transaction, undefined);
      assert.equal(result.payload.state.lastResult.ok, false);
    });
  }

  for (const merchantId of ["", "   ", "merchant with spaces", "x".repeat(65)]) {
    await withLab(async (baseUrl) => {
      await post(baseUrl, "/api/provision/request");
      await post(baseUrl, "/api/provision/approve");
      const result = await post(baseUrl, "/api/transaction/request", {
        amount: "25.00",
        merchantId,
      });
      assert.equal(result.response.status, 409, `merchant ${JSON.stringify(merchantId)} should fail`);
      assert.equal(result.payload.state.transaction, undefined);
    });
  }
});

test("real-time lab exposes immutable confirmation data and blocks binding attacks", async () => {
  await withLab(async (baseUrl) => {
    await post(baseUrl, "/api/provision/request");
    await post(baseUrl, "/api/provision/approve");
    const requested = await post(baseUrl, "/api/transaction/request", {
      amount: "25.00",
      merchantId: "merchant-A",
    });
    assert.deepEqual(
      {
        amountMinor: requested.payload.confirmation.amountMinor,
        merchantId: requested.payload.confirmation.merchantId,
      },
      { amountMinor: 2_500, merchantId: "merchant-A" },
    );

    for (const attack of ["altered-amount", "altered-merchant", "wrong-key", "wrong-device", "modified-nonce"]) {
      const result = await post(baseUrl, `/api/demonstrate/${attack}`);
      assert.equal(result.response.status, 200);
      assert.equal(result.payload.demonstration.name, attack);
      assert.equal(result.payload.demonstration.blocked, true);
      assert.equal(result.payload.transaction.state, "confirmation_pending");
    }

    const tamper = await post(baseUrl, "/api/demonstrate/audit-tamper");
    assert.equal(tamper.response.status, 200);
    assert.equal(tamper.payload.demonstration.blocked, true);
    assert.equal(tamper.payload.audit.valid, true, "the authoritative audit log must remain untouched");
  });
});

test("real-time lab demonstrates expired and reused approvals as terminal failures", async () => {
  await withLab(async (baseUrl) => {
    await post(baseUrl, "/api/provision/request");
    await post(baseUrl, "/api/provision/approve");
    await post(baseUrl, "/api/transaction/request", { amount: "25.00", merchantId: "merchant-A" });
    const expired = await post(baseUrl, "/api/demonstrate/expired-challenge");
    assert.equal(expired.response.status, 200);
    assert.equal(expired.payload.demonstration.blocked, true);
    assert.equal(expired.payload.transaction.state, "reversed");
  });

  await withLab(async (baseUrl) => {
    await post(baseUrl, "/api/provision/request");
    await post(baseUrl, "/api/provision/approve");
    await post(baseUrl, "/api/transaction/request", { amount: "25.00", merchantId: "merchant-A" });
    const reused = await post(baseUrl, "/api/demonstrate/reused-signature");
    assert.equal(reused.response.status, 200);
    assert.equal(reused.payload.demonstration.blocked, true);
    assert.equal(reused.payload.transaction.state, "confirmed");
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
