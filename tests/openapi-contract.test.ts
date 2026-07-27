import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createLabServer,
  REALTIME_LAB_API_ROUTES,
} from "../apps/realtime-lab/server.ts";

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
    return;
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
  const sourceRoutes = new Set([
    `get ${REALTIME_LAB_API_ROUTES.health}`,
    `get ${REALTIME_LAB_API_ROUTES.state}`,
    `get ${REALTIME_LAB_API_ROUTES.events}`,
    `post ${REALTIME_LAB_API_ROUTES.reset}`,
    `post ${REALTIME_LAB_API_ROUTES.provisionRequest}`,
    `post ${REALTIME_LAB_API_ROUTES.provisionAttack}`,
    `post ${REALTIME_LAB_API_ROUTES.provisionApprove}`,
    `post ${REALTIME_LAB_API_ROUTES.deviceRevoke}`,
    `post ${REALTIME_LAB_API_ROUTES.transactionRequest}`,
    `post ${REALTIME_LAB_API_ROUTES.transactionConfirm}`,
    `post ${REALTIME_LAB_API_ROUTES.transactionExpire}`,
    `post ${REALTIME_LAB_API_ROUTES.transactionClear}`,
    `post ${REALTIME_LAB_API_ROUTES.auditTamper}`,
    `post ${REALTIME_LAB_API_ROUTES.demonstrationPrefix}{attackName}`,
  ]);
  const contractRoutes = new Set<string>();
  for (const [path, pathItem] of Object.entries(contract.paths) as Array<[string, ObjectValue]>) {
    for (const method of ["get", "post"]) {
      if (pathItem[method]) contractRoutes.add(`${method} ${path}`);
    }
  }
  assert.deepEqual([...contractRoutes].sort(), [...sourceRoutes].sort());
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
      assert.deepEqual(operation.security, []);
      if (method === "post") {
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
      validate(await response.json() as Json, contract.components.schemas.SimpleError);
    }
    const missing = await fetch(`${lab.baseUrl}/api/not-real`);
    assert.equal(missing.status, 404);
    validate(await missing.json() as Json, contract.components.schemas.SimpleError);
  } finally {
    await lab.close();
  }

  const directory = mkdtempSync(join(tmpdir(), "airlock-openapi-"));
  const persistent = await listen({ dbPath: join(directory, "lab.sqlite") });
  try {
    const required = await post(persistent.baseUrl, "/api/reset");
    assert.equal(required.status, 428);
    validate(await required.json() as Json, contract.components.schemas.SimpleError);
    const tooLong = await post(persistent.baseUrl, "/api/reset", undefined, {
      "idempotency-key": `a${"b".repeat(128)}`,
    });
    assert.equal(tooLong.status, 431);
    validate(await tooLong.json() as Json, contract.components.schemas.SimpleError);
  } finally {
    await persistent.close();
    rmSync(directory, { recursive: true, force: true });
  }
});
