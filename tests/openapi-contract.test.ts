import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createLabServer,
  findRouteManifestEntry,
  REASON_CODES,
  REALTIME_LAB_API_ROUTES,
  ROUTE_MANIFEST,
} from "../apps/realtime-lab/server.ts";
import { DurableStore } from "../packages/storage/durableStore.ts";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type ObjectValue = { [key: string]: any };

const contractPath = new URL(
  "../contracts/openapi/realtime-lab.openapi.json",
  import.meta.url,
);
const contract = JSON.parse(readFileSync(contractPath, "utf8")) as ObjectValue;
function resolve<T extends ObjectValue>(value: T): T {
  if (!value?.$ref) return value;
  assert.match(value.$ref, /^#\//);
  let current: any = contract;
  for (const token of value.$ref.slice(2).split("/")) {
    current = current[token.replaceAll("~1", "/").replaceAll("~0", "~")];
  }
  assert.ok(current, `unresolved OpenAPI reference: ${value.$ref}`);
  return current as T;
}

function schemaFor(path: string, method: string, status: number): ObjectValue {
  const operation = contract.paths[path][method];
  const response = resolve(operation.responses[String(status)]);
  return resolve(response.content["application/json"].schema);
}

function validate(value: Json, candidate: ObjectValue, location = "$"): void {
  const schema = resolve(candidate);
  if (schema.oneOf) {
    const matches = schema.oneOf.filter((option: ObjectValue) => {
      try {
        validate(value, option, location);
        return true;
      } catch {
        return false;
      }
    });
    assert.equal(matches.length, 1, `${location}: expected exactly one oneOf match`);
  }
  if (schema.not) {
    assert.throws(() => validate(value, schema.not, location), `${location}: not`);
  }
  if ("const" in schema) assert.deepEqual(value, schema.const, `${location}: const`);
  if (schema.enum) assert.ok(schema.enum.includes(value), `${location}: enum`);
  if (schema.type === "object") {
    assert.ok(value && typeof value === "object" && !Array.isArray(value), `${location}: object`);
    const object = value as ObjectValue;
    for (const key of schema.required ?? []) {
      assert.ok(Object.hasOwn(object, key), `${location}: missing ${key}`);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(object)) {
        assert.ok(Object.hasOwn(schema.properties ?? {}, key), `${location}: unknown ${key}`);
      }
    }
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(object, key)) validate(object[key], child as ObjectValue, `${location}.${key}`);
    }
  } else if (schema.type === "array") {
    assert.ok(Array.isArray(value), `${location}: array`);
    for (const [index, item] of value.entries()) {
      validate(item, schema.items, `${location}[${index}]`);
    }
  } else if (schema.type === "string") {
    assert.equal(typeof value, "string", `${location}: string`);
    const stringValue = value as string;
    if (schema.minLength !== undefined) assert.ok(stringValue.length >= schema.minLength, `${location}: minLength`);
    if (schema.maxLength !== undefined) assert.ok(stringValue.length <= schema.maxLength, `${location}: maxLength`);
    if (schema.pattern) assert.match(stringValue, new RegExp(schema.pattern), `${location}: pattern`);
  } else if (schema.type === "integer") {
    assert.ok(typeof value === "number" && Number.isSafeInteger(value), `${location}: integer`);
    if (schema.minimum !== undefined) assert.ok(value >= schema.minimum, `${location}: minimum`);
    if (schema.maximum !== undefined) assert.ok(value <= schema.maximum, `${location}: maximum`);
  } else if (schema.type === "boolean") {
    assert.equal(typeof value, "boolean", `${location}: boolean`);
  }
}

async function listen(options = {}) {
  const server = createLabServer(options);
  await new Promise<void>((resolvePromise) =>
    server.listen(0, "127.0.0.1", resolvePromise)
  );
  const { port } = server.address() as AddressInfo;
  return {
    server,
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolvePromise, reject) =>
      server.close((error) => error ? reject(error) : resolvePromise())
    ),
  };
}

async function post(
  baseUrl: string,
  path: string,
  body?: string,
  headers: Record<string, string> = {},
) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers,
    ...(body === undefined ? {} : { body }),
  });
}

test("OpenAPI path/method set exactly matches the router's runtime manifest", () => {
  assert.equal(contract.openapi, "3.1.0");
  assert.match(contract.info.description, /SIMULATOR ONLY/);
  // Derived from ROUTE_MANIFEST — the same data structure the live server
  // uses for 405 dispatch — rather than hand-listed, so this test fails the
  // moment a route is added/changed in the manifest without a matching
  // OpenAPI update, instead of only catching drift someone remembered to
  // mirror here by hand. Static asset routes (/, /app.js, /styles.css) are
  // excluded: this contract documents the JSON API, not asset serving.
  // HEAD is excluded from this comparison and checked separately below: it
  // is a transport-level convention implied by GET, not a distinct declared
  // operation, matching how this contract (and most OpenAPI-documented
  // HTTP APIs) treats it.
  const sourceRoutes = new Set<string>();
  for (const entry of ROUTE_MANIFEST) {
    if (!entry.path.startsWith("/api/")) continue;
    const path = entry.isPrefix ? `${entry.path}{attackName}` : entry.path;
    for (const method of entry.methods) {
      if (method === "HEAD") continue;
      sourceRoutes.add(`${method.toLowerCase()} ${path}`);
    }
  }
  const contractRoutes = new Set<string>();
  for (const [path, pathItem] of Object.entries(contract.paths) as Array<[string, ObjectValue]>) {
    for (const method of ["get", "post"]) {
      if (pathItem[method]) contractRoutes.add(`${method} ${path}`);
    }
  }
  assert.deepEqual([...contractRoutes].sort(), [...sourceRoutes].sort());
});

test("ROUTE_MANIFEST never offers HEAD without the corresponding GET", () => {
  // The structural guarantee that stands in for OpenAPI HEAD parity: every
  // manifest entry that accepts HEAD also accepts GET, so HEAD is always a
  // strict "same response, no body" mirror of a documented GET operation —
  // never an independent capability that could diverge from the contract.
  for (const entry of ROUTE_MANIFEST) {
    if (entry.methods.includes("HEAD")) {
      assert.ok(
        entry.methods.includes("GET"),
        `${entry.label} (${entry.path}) offers HEAD without GET`,
      );
    }
  }
});

test("every REALTIME_LAB_API_ROUTES value is covered by a ROUTE_MANIFEST entry", () => {
  for (const [name, path] of Object.entries(REALTIME_LAB_API_ROUTES)) {
    if (name === "demonstrationPrefix") continue; // covered via prefix match, not equality
    const matching = ROUTE_MANIFEST.filter((entry) => entry.matches(path));
    assert.ok(matching.length >= 1, `${name} (${path}) matched no manifest entry`);
    // auditTamper legitimately matches both its own exact entry and the
    // demonstration prefix entry (both POST-only, so no behavioral
    // ambiguity) — every other route must resolve to exactly one entry.
    if (name !== "auditTamper") {
      assert.equal(matching.length, 1, `${name} (${path}) matched ${matching.length} manifest entries`);
    }
  }
});

test("findRouteManifestEntry resolves auditTamper to its exact entry, not the demonstration prefix", () => {
  const entry = findRouteManifestEntry(REALTIME_LAB_API_ROUTES.auditTamper);
  assert.equal(entry?.label, "auditTamper");
});

test("transaction request schema and live parser agree at positive and negative boundaries", async () => {
  const requestSchema = resolve(
    contract.paths["/api/transaction/request"].post.requestBody
      .content["application/json"].schema,
  );
  const cases: Array<{ amount: unknown; accepted: boolean }> = [
    { amount: "0.01", accepted: true },
    { amount: "1", accepted: true },
    { amount: "25.0", accepted: true },
    { amount: " 25.00 ", accepted: true },
    { amount: "90071992547409.91", accepted: true },
    { amount: "0", accepted: false },
    { amount: "0.00", accepted: false },
    { amount: "90071992547409.92", accepted: false },
    { amount: "90071992547410", accepted: false },
    { amount: "-1.00", accepted: false },
    { amount: "1.001", accepted: false },
    { amount: "1e3", accepted: false },
    { amount: 25, accepted: false },
  ];
  const lab = await listen();
  try {
    for (const [index, item] of cases.entries()) {
      const instance = { amount: item.amount, merchantId: "merchant-1" } as Json;
      let schemaAccepted = true;
      try {
        validate(instance, requestSchema);
      } catch {
        schemaAccepted = false;
      }
      assert.equal(schemaAccepted, item.accepted, `schema case ${index}: ${String(item.amount)}`);

      await post(lab.baseUrl, "/api/reset");
      await post(lab.baseUrl, "/api/provision/request");
      await post(lab.baseUrl, "/api/provision/approve");
      const response = await post(
        lab.baseUrl,
        "/api/transaction/request",
        JSON.stringify(instance),
        { "content-type": "application/json" },
      );
      assert.equal(
        response.status === 200,
        item.accepted,
        `live case ${index}: ${String(item.amount)} returned ${response.status}`,
      );
    }
  } finally {
    await lab.close();
  }
});

test("all references resolve and every mutation declares real controls and errors", () => {
  const operationIds = new Set<string>();
  const walk = (value: unknown): void => {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) return value.forEach(walk);
    const object = value as ObjectValue;
    if (object.$ref) resolve(object);
    Object.values(object).forEach(walk);
  };
  walk(contract);
  for (const pathItem of Object.values(contract.paths) as ObjectValue[]) {
    for (const method of ["get", "post"]) {
      const operation = pathItem[method];
      if (!operation) continue;
      assert.ok(!operationIds.has(operation.operationId), "duplicate operationId");
      operationIds.add(operation.operationId);
      assert.equal(operation["x-simulator-only"], true);
      if (operation.operationId === "loginSession") {
        assert.deepEqual(operation.security, [{ loginBearer: [] }]);
      } else if (["getSession", "logoutSession"].includes(operation.operationId)) {
        assert.deepEqual(operation.security, [{ sessionCookie: [] }]);
      } else if (operation.operationId === "getLabHealth") {
        assert.deepEqual(operation.security, []);
      } else {
        assert.deepEqual(operation.security, [{}, { sessionCookie: [] }]);
      }
      if (method === "post") {
        if (["loginSession", "logoutSession"].includes(operation.operationId)) {
          assert.equal(operation["x-maxBodyBytes"], 0);
          continue;
        }
        assert.equal(operation["x-maxBodyBytes"], 16384);
        const names = operation.parameters.map((parameter: ObjectValue) => resolve(parameter).name);
        assert.ok(names.includes("Origin"));
        assert.ok(names.includes("Sec-Fetch-Site"));
        assert.ok(names.includes("Idempotency-Key"));
        for (const status of ["200", "400", "403", "409", "413", "415", "428", "431", "503"]) {
          assert.ok(operation.responses[status], `${operation.operationId}: missing ${status}`);
        }
      }
    }
  }
  const idempotency = contract.components.parameters.IdempotencyKey;
  assert.equal(idempotency.schema.maxLength, 128);
  assert.equal(idempotency["x-requiredWhen"], "AIRLOCK_DB_PATH is set");
  const authenticatedProfile =
    contract["x-airlock-access-profiles"].authenticated;
  const operations = Object.values(contract.paths).flatMap(
    (pathItem: any) => ["get", "post"]
      .map((method) => pathItem[method]?.operationId)
      .filter(Boolean),
  );
  const protectedOperations = operations.filter(
    (operationId: string) =>
      !["getLabHealth", "loginSession"].includes(operationId),
  );
  assert.deepEqual(
    [...authenticatedProfile.sessionProtectedOperationIds].sort(),
    [...protectedOperations].sort(),
  );
  const csrfOperations = Object.values(contract.paths).flatMap(
    (pathItem: any) => pathItem.post &&
        pathItem.post.operationId !== "loginSession"
      ? [pathItem.post.operationId]
      : [],
  );
  assert.deepEqual(
    [...authenticatedProfile.csrfProtectedOperationIds].sort(),
    [...csrfOperations].sort(),
  );
  assert.deepEqual(
    authenticatedProfile.csrfRequiredHeaders,
    ["Origin", "X-CSRF-Token"],
  );
  assert.equal(authenticatedProfile.oidcRuntimeComposition, true);
  assert.equal(authenticatedProfile.webAuthnRuntimeComposition, false);
  assert.equal(
    Object.hasOwn(authenticatedProfile, "oidcWebAuthnRuntimeComposition"),
    false,
    "combined identity-composition flag must not collapse distinct runtime states",
  );
  assert.deepEqual(authenticatedProfile.loginOperationIds, ["loginSession"]);
  assert.deepEqual(authenticatedProfile.loginSecurity, [{ loginBearer: [] }]);
  assert.deepEqual(
    Object.keys(authenticatedProfile.loginProviderProfiles).sort(),
    ["bootstrap-controlled-demo", "oidc"],
  );
  assert.match(
    contract.components.securitySchemes.loginBearer.bearerFormat,
    /controlled-demo credential or OIDC JWT access token/,
  );
  assert.equal(
    Object.hasOwn(contract.components.securitySchemes, "bootstrapBearer"),
    false,
  );
  assert.deepEqual(
    contract.components.schemas.ReasonCode.enum,
    [...REASON_CODES],
    "runtime and OpenAPI reason-code vocabularies drifted",
  );
  assert.throws(
    () => validate(
      { code: "UNDECLARED_CODE", error: "message" },
      contract.components.schemas.SimpleError,
    ),
    /enum/,
  );
  const lastResult = contract.components.schemas.LastResult;
  validate({
    ok: true,
    outcome: "accepted",
    code: "RESET",
    action: "reset",
    message: "reset",
    at: new Date().toISOString(),
  }, lastResult);
  assert.throws(
    () => validate({
      ok: true,
      outcome: "accepted",
      code: "INTERNAL_ERROR",
      action: "broken",
      message: "broken",
      at: new Date().toISOString(),
    }, lastResult),
    /oneOf/,
  );
});

test("live success, conflict, and SSE payloads conform to declared schemas", async () => {
  const lab = await listen();
  try {
    const healthResponse = await fetch(`${lab.baseUrl}/api/health`);
    const health = await healthResponse.json() as Json;
    validate(health, schemaFor("/api/health", "get", 200));

    const initial = await (await fetch(`${lab.baseUrl}/api/state`)).json() as Json;
    validate(initial, schemaFor("/api/state", "get", 200));

    const requestedResponse = await post(lab.baseUrl, "/api/provision/request");
    validate(
      await requestedResponse.json() as Json,
      schemaFor("/api/provision/request", "post", 200),
    );
    const conflictResponse = await post(lab.baseUrl, "/api/provision/request");
    assert.equal(conflictResponse.status, 409);
    validate(
      await conflictResponse.json() as Json,
      schemaFor("/api/provision/request", "post", 409),
    );

    const controller = new AbortController();
    const events = await fetch(`${lab.baseUrl}/api/events`, { signal: controller.signal });
    assert.match(events.headers.get("content-type") ?? "", /^text\/event-stream/);
    const reader = events.body!.getReader();
    const first = await reader.read();
    const text = new TextDecoder().decode(first.value);
    controller.abort();
    assert.match(text, /^event: state\ndata: /);
    const dataLine = text.split("\n").find((line) => line.startsWith("data: "))!;
    validate(JSON.parse(dataLine.slice(6)), contract.components.schemas.PublicState);
  } finally {
    await lab.close();
  }
});

test("live accepted, warning, and blocked results use declared stable codes", async () => {
  const lab = await listen();
  const expectResult = async (
    path: string,
    expectedCode: string,
    body?: Record<string, unknown>,
  ) => {
    const response = await post(
      lab.baseUrl,
      path,
      body ? JSON.stringify(body) : undefined,
      body ? { "content-type": "application/json" } : {},
    );
    assert.equal(response.status, 200, `${path}: status`);
    const payload = await response.json() as ObjectValue;
    validate(payload, contract.components.schemas.PublicState);
    assert.equal(payload.lastResult.code, expectedCode, `${path}: result code`);
    assert.ok(REASON_CODES.includes(payload.lastResult.code));
    return payload;
  };
  try {
    const initial = await (await fetch(`${lab.baseUrl}/api/state`)).json() as ObjectValue;
    assert.equal(initial.lastResult.code, "RESET");
    await expectResult("/api/provision/request", "PROVISIONING_REQUESTED");
    await expectResult("/api/provision/approve", "PROVISIONING_APPROVED");
    await expectResult("/api/transaction/request", "TRANSACTION_PENDING", {
      amount: "1.00",
      merchantId: "merchant",
    });
    await expectResult("/api/transaction/confirm", "TRANSACTION_CONFIRMED");
    await expectResult("/api/transaction/clear", "TRANSACTION_SETTLED");

    await expectResult("/api/reset", "RESET");
    await expectResult("/api/provision/request", "PROVISIONING_REQUESTED");
    await expectResult("/api/provision/approve", "PROVISIONING_APPROVED");
    await expectResult("/api/transaction/request", "TRANSACTION_PENDING", {
      amount: "1.00",
      merchantId: "merchant",
    });
    await expectResult("/api/transaction/expire", "TRANSACTION_EXPIRED_REVERSED");
    const warning = await expectResult(
      "/api/transaction/clear",
      "CLEARING_AFTER_REVERSAL",
    );
    assert.equal(warning.lastResult.outcome, "warning");

    await expectResult("/api/reset", "RESET");
    await expectResult("/api/device/revoke", "DEVICE_REVOKED");
    await expectResult("/api/reset", "RESET");
    await expectResult("/api/provision/request", "PROVISIONING_REQUESTED");
    await expectResult("/api/provision/approve", "PROVISIONING_APPROVED");
    await expectResult("/api/transaction/request", "TRANSACTION_PENDING", {
      amount: "1.00",
      merchantId: "merchant",
    });
    const blocked = await expectResult(
      "/api/demonstrate/altered-merchant",
      "ATTACK_BLOCKED",
    );
    assert.equal(blocked.lastResult.outcome, "blocked");
  } finally {
    await lab.close();
  }
});

test("live request failures use documented statuses and exact error shapes", async () => {
  const lab = await listen();
  try {
    const cases = [
      await post(lab.baseUrl, "/api/transaction/request", "{", { "content-type": "application/json" }),
      await post(lab.baseUrl, "/api/reset", undefined, { origin: "http://evil.invalid" }),
      await post(lab.baseUrl, "/api/reset", "x".repeat(16_385), { "content-type": "application/json" }),
      await post(lab.baseUrl, "/api/transaction/request", "{}", { "content-type": "text/plain" }),
    ];
    for (const [index, expected] of [400, 403, 413, 415].entries()) {
      const response = cases[index];
      assert.equal(response.status, expected);
      const payload = await response.json() as ObjectValue;
      validate(payload, contract.components.schemas.SimpleError);
      assert.equal(
        payload.code,
        ["MALFORMED_JSON", "CROSS_ORIGIN_REJECTED", "PAYLOAD_TOO_LARGE", "UNSUPPORTED_MEDIA_TYPE"][index],
      );
    }
    const missing = await fetch(`${lab.baseUrl}/api/not-real`);
    assert.equal(missing.status, 404);
    const missingPayload = await missing.json() as ObjectValue;
    validate(missingPayload, contract.components.schemas.SimpleError);
    assert.equal(missingPayload.code, "NOT_FOUND");
  } finally {
    await lab.close();
  }

  const directory = mkdtempSync(join(tmpdir(), "airlock-openapi-"));
  const persistent = await listen({ dbPath: join(directory, "lab.sqlite") });
  try {
    const required = await post(persistent.baseUrl, "/api/reset");
    assert.equal(required.status, 428);
    const requiredPayload = await required.json() as ObjectValue;
    validate(requiredPayload, contract.components.schemas.SimpleError);
    assert.equal(requiredPayload.code, "IDEMPOTENCY_KEY_REQUIRED");
    const tooLong = await post(persistent.baseUrl, "/api/reset", undefined, {
      "idempotency-key": `a${"b".repeat(128)}`,
    });
    assert.equal(tooLong.status, 431);
    const tooLongPayload = await tooLong.json() as ObjectValue;
    validate(tooLongPayload, contract.components.schemas.SimpleError);
    assert.equal(tooLongPayload.code, "IDEMPOTENCY_KEY_TOO_LONG");
  } finally {
    await persistent.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("live domain rejection paths expose stable codes without message parsing", async () => {
  const lab = await listen();
  const request = async (
    path: string,
    expectedCode: string,
    body?: Record<string, unknown>,
  ) => {
    const response = await post(
      lab.baseUrl,
      path,
      body ? JSON.stringify(body) : undefined,
      body ? { "content-type": "application/json" } : {},
    );
    const payload = await response.json() as ObjectValue;
    assert.equal(response.status, 409, `${path}: status`);
    assert.equal(payload.code, expectedCode, `${path}: code`);
    assert.ok(typeof payload.error === "string" && payload.error.length > 0);
    validate(payload, contract.components.schemas.StateError);
  };
  try {
    await request("/api/provision/approve", "PROVISIONING_REQUIRED");
    await post(lab.baseUrl, "/api/provision/request");
    await request("/api/provision/request", "PROVISIONING_ALREADY_REQUESTED");
    await request("/api/transaction/request", "TOKEN_NOT_SPENDABLE", {
      amount: "1.00",
      merchantId: "merchant",
    });
    await post(lab.baseUrl, "/api/provision/approve");
    await request("/api/transaction/confirm", "TRANSACTION_REQUIRED");
    await request("/api/transaction/request", "AMOUNT_NON_POSITIVE", {
      amount: "0.00",
      merchantId: "merchant",
    });
    await request("/api/transaction/request", "AMOUNT_FORMAT_INVALID", {
      amount: "1.001",
      merchantId: "merchant",
    });
    await request("/api/transaction/request", "MERCHANT_INVALID", {
      amount: "1.00",
      merchantId: "merchant with spaces",
    });
    await post(
      lab.baseUrl,
      "/api/transaction/request",
      JSON.stringify({ amount: "1.00", merchantId: "merchant" }),
      { "content-type": "application/json" },
    );
    await request("/api/transaction/request", "TRANSACTION_ALREADY_EXISTS", {
      amount: "1.00",
      merchantId: "merchant",
    });
    await request("/api/transaction/clear", "CLEARING_NOT_ALLOWED");
    await post(lab.baseUrl, "/api/transaction/confirm");
    await request("/api/transaction/confirm", "TRANSACTION_NOT_PENDING");
    await post(lab.baseUrl, "/api/reset");
    await post(lab.baseUrl, "/api/device/revoke");
    await request("/api/device/revoke", "DEVICE_ALREADY_REVOKED");
  } finally {
    await lab.close();
  }
});

test("persistence failures carry the declared 503 machine code", async () => {
  const directory = mkdtempSync(join(tmpdir(), "airlock-code-503-"));
  const dbPath = join(directory, "lab.sqlite");
  const lab = await listen({
    dbPath,
    storeFactory: (path: string) => {
      const store = new DurableStore(path);
      return {
        get: store.get.bind(store),
        create: store.create.bind(store),
        compareAndSwap: store.compareAndSwap.bind(store),
        getIdempotent: store.getIdempotent.bind(store),
        runIdempotent: () => {
          throw new Error("synthetic persistence outage");
        },
        close: store.close.bind(store),
      };
    },
  });
  try {
    const response = await post(lab.baseUrl, "/api/reset", undefined, {
      "idempotency-key": "force-503",
    });
    assert.equal(response.status, 503);
    const payload = await response.json() as ObjectValue;
    assert.equal(payload.code, "PERSISTENCE_UNAVAILABLE");
    validate(payload, contract.components.schemas.StateError);
  } finally {
    await lab.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("security invariant failure is a coded HTTP 500 blocked result", async () => {
  const lab = await listen({ auditCopyVerifier: () => true });
  try {
    const response = await post(lab.baseUrl, "/api/demonstrate/audit-tamper");
    assert.equal(response.status, 500);
    const payload = await response.json() as ObjectValue;
    validate(
      payload,
      schemaFor("/api/demonstrate/audit-tamper", "post", 500),
    );
    assert.equal(payload.lastResult.code, "SECURITY_INVARIANT_FAILED");
    assert.equal(payload.lastResult.ok, false);
    assert.equal(payload.lastResult.outcome, "blocked");
  } finally {
    await lab.close();
  }
});
