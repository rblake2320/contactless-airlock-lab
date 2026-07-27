import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { createLabServer } from "../apps/realtime-lab/server.ts";

const SENTINELS = {
  authorization: "Bearer privacy-authorization-sentinel",
  idempotency: "privacy-idempotency-sentinel",
  pan: "4111111111111111",
  cvv: "975-CVV-DO-NOT-ECHO",
  signature: "privacy-raw-signature-sentinel",
};

const FORBIDDEN_PUBLIC_KEYS = new Set([
  "authorization",
  "cookie",
  "cvv",
  "idempotencyKey",
  "idempotency-key",
  "pan",
  "privateKey",
  "privateKeyPem",
  "publicKeyPem",
  "signature",
]);

function allKeys(value: unknown, result = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const child of value) allKeys(child, result);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      result.add(key);
      allKeys(child, result);
    }
  }
  return result;
}

function assertNoSensitiveOutput(value: unknown): void {
  const encoded = JSON.stringify(value);
  for (const sentinel of Object.values(SENTINELS)) {
    assert.equal(encoded.includes(sentinel), false, `output exposed ${sentinel}`);
  }
  const privateKeyMarker = ["BEGIN", "PRIVATE", "KEY"].join(" ");
  assert.equal(encoded.includes(privateKeyMarker), false);
  for (const key of allKeys(value)) {
    assert.equal(
      FORBIDDEN_PUBLIC_KEYS.has(key),
      false,
      `public output exposed forbidden key ${key}`,
    );
  }
}

async function startPersistentLab() {
  const directory = await mkdtemp(join(tmpdir(), "airlock-privacy-"));
  const server = createLabServer({ dbPath: join(directory, "lab.sqlite") });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: async () => {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => error ? reject(error) : resolve()));
      await rm(directory, { recursive: true, force: true });
    },
  };
}

async function post(
  baseUrl: string,
  path: string,
  key: string,
  body: Record<string, unknown> = {},
) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      authorization: SENTINELS.authorization,
      "content-type": "application/json",
      "idempotency-key": key,
    },
    body: JSON.stringify(body),
  });
  return {
    status: response.status,
    payload: await response.json() as Record<string, unknown>,
  };
}

test("HTTP errors, public state, and audit never expose request secrets or signatures", async () => {
  const lab = await startPersistentLab();
  try {
    const requested = await post(
      lab.baseUrl,
      "/api/provision/request",
      `${SENTINELS.idempotency}-provision`,
    );
    assert.equal(requested.status, 200);
    assertNoSensitiveOutput(requested.payload);

    const approved = await post(
      lab.baseUrl,
      "/api/provision/approve",
      `${SENTINELS.idempotency}-approve`,
    );
    assert.equal(approved.status, 200);
    assertNoSensitiveOutput(approved.payload);

    const invalid = await post(
      lab.baseUrl,
      "/api/transaction/request",
      `${SENTINELS.idempotency}-invalid`,
      {
        amount: SENTINELS.pan,
        merchantId: "synthetic-merchant",
        pan: SENTINELS.pan,
        cvv: SENTINELS.cvv,
        signature: SENTINELS.signature,
      },
    );
    assert.equal(invalid.status, 409);
    assertNoSensitiveOutput(invalid.payload);

    const transaction = await post(
      lab.baseUrl,
      "/api/transaction/request",
      `${SENTINELS.idempotency}-transaction`,
      { amount: "12.34", merchantId: "synthetic-merchant" },
    );
    assert.equal(transaction.status, 200);
    assertNoSensitiveOutput(transaction.payload);

    const attack = await post(
      lab.baseUrl,
      "/api/demonstrate/wrong-key",
      `${SENTINELS.idempotency}-attack`,
    );
    assert.equal(attack.status, 200);
    assertNoSensitiveOutput(attack.payload);

    const stateResponse = await fetch(`${lab.baseUrl}/api/state`, {
      headers: { authorization: SENTINELS.authorization },
    });
    assert.equal(stateResponse.status, 200);
    const state = await stateResponse.json() as Record<string, unknown>;
    assertNoSensitiveOutput(state);
    assertNoSensitiveOutput(state.audit);
  } finally {
    await lab.close();
  }
});
test("server source keeps public projection and console diagnostics away from secret-bearing fields", async () => {
  const source = await readFile(
    new URL("../apps/realtime-lab/server.ts", import.meta.url),
    "utf8",
  );
  const projectionStart = source.indexOf("function publicSnapshot");
  const projectionEnd = source.indexOf("\nfunction json", projectionStart);
  assert.notEqual(projectionStart, -1);
  assert.notEqual(projectionEnd, -1);
  const projection = source.slice(projectionStart, projectionEnd);
  assert.doesNotMatch(
    projection,
    /privateKey|publicKeyPem|signature|authorization|cookie|idempotency/i,
  );

  const consoleStatements = source
    .split(/\r?\n/)
    .filter((line) => /\bconsole\.(?:log|info|warn|error)\s*\(/.test(line))
    .join("\n");
  assert.notEqual(consoleStatements.length, 0);
  assert.doesNotMatch(
    consoleStatements,
    /privateKey|publicKeyPem|signature|authorization|cookie|idempotency|req\.headers/i,
  );
});
