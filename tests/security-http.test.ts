import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import test from "node:test";
import type { AddressInfo } from "node:net";
import vm from "node:vm";
import { createLabServer } from "../apps/realtime-lab/server.ts";

async function withLab(fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const server = createLabServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
}

async function post(
  baseUrl: string,
  path: string,
  init: { headers?: Record<string, string>; body?: string } = {},
) {
  const request: RequestInit = { method: "POST" };
  if (init.headers) request.headers = init.headers;
  if (init.body !== undefined) request.body = init.body;
  return fetch(`${baseUrl}${path}`, request);
}

test("mutation endpoints reject hostile browser origins without changing state", async () => {
  await withLab(async (baseUrl) => {
    const before = await (await fetch(`${baseUrl}/api/state`)).json();
    const hostile = [
      { origin: "http://evil.example", "sec-fetch-site": "cross-site" },
      { origin: "http://localhost:9999", "sec-fetch-site": "same-site" },
      { origin: "null", "sec-fetch-site": "cross-site" },
      { origin: `${baseUrl}/path`, "sec-fetch-site": "same-origin" },
      { origin: baseUrl, "sec-fetch-site": "cross-site" },
    ];
    for (const headers of hostile) {
      const response = await post(baseUrl, "/api/provision/request", { headers });
      assert.equal(response.status, 403, JSON.stringify(headers));
    }
    const after = await (await fetch(`${baseUrl}/api/state`)).json();
    assert.equal(after.provisioning, undefined);
    assert.equal(after.audit.events.length, before.audit.events.length);
  });
});

test("same-origin browser requests and headerless CLI requests remain operational", async () => {
  await withLab(async (baseUrl) => {
    const browser = await post(baseUrl, "/api/provision/request", {
      headers: {
        origin: baseUrl,
        "sec-fetch-site": "same-origin",
        "content-type": "application/json",
      },
      body: "{}",
    });
    assert.equal(browser.status, 200);
  });
  await withLab(async (baseUrl) => {
    const cli = await post(baseUrl, "/api/provision/request");
    assert.equal(cli.status, 200);
  });
});

test("all mutation request bodies are bounded by declared and streamed bytes", async () => {
  await withLab(async (baseUrl) => {
    const oversized = "x".repeat(16 * 1024 + 1);
    const declared = await post(baseUrl, "/api/reset", {
      headers: { "content-type": "application/json" },
      body: oversized,
    });
    assert.equal(declared.status, 413);

    const target = new URL("/api/reset", baseUrl);
    const chunkedStatus = await new Promise<number>((resolve, reject) => {
      const req = httpRequest({
        hostname: target.hostname,
        port: target.port,
        path: target.pathname,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "transfer-encoding": "chunked",
        },
      }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      });
      req.on("error", reject);
      req.write("x".repeat(9_000));
      req.end("x".repeat(9_000));
    });
    assert.equal(chunkedStatus, 413);
  });
});

test("JSON mutation rejects missing, misleading, and malformed content types", async () => {
  await withLab(async (baseUrl) => {
    assert.equal((await post(baseUrl, "/api/provision/request")).status, 200);
    assert.equal((await post(baseUrl, "/api/provision/approve")).status, 200);

    const invalidRequests: Array<{
      headers?: Record<string, string>;
      body: string;
      status: number;
    }> = [
      { headers: {}, body: JSON.stringify({ amount: "1.00", merchantId: "merchant" }), status: 415 },
      { headers: { "content-type": "text/plain" }, body: JSON.stringify({ amount: "1.00", merchantId: "merchant" }), status: 415 },
      { headers: { "content-type": "application/json" }, body: "{", status: 400 },
      { headers: { "content-type": "application/json" }, body: "[]", status: 400 },
    ];
    for (const request of invalidRequests) {
      const response = await post(baseUrl, "/api/transaction/request", request);
      assert.equal(response.status, request.status);
    }

    const valid = await post(baseUrl, "/api/transaction/request", {
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify({ amount: "1.00", merchantId: "merchant" }),
    });
    assert.equal(valid.status, 200);
  });
});

test("security headers cover API, static assets, errors, and deny framing", async () => {
  await withLab(async (baseUrl) => {
    for (const path of ["/", "/app.js", "/api/health", "/missing"]) {
      const response = await fetch(`${baseUrl}${path}`);
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(response.headers.get("x-frame-options"), "DENY");
      assert.equal(response.headers.get("referrer-policy"), "no-referrer");
      assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
      assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
      assert.match(response.headers.get("permissions-policy") ?? "", /payment=\(\)/);
    }
  });
});

test("browser surfaces a failed mutation instead of failing silently", async () => {
  const elements = new Map<string, {
    textContent: string;
    dataset: Record<string, string>;
    value: string;
    addEventListener: (name: string, handler: () => Promise<void>) => void;
  }>();
  let transactionHandler: (() => Promise<void>) | undefined;
  let requestHeaders: Record<string, string> | undefined;
  let uuidCalls = 0;
  const element = (id: string) => {
    if (!elements.has(id)) {
      elements.set(id, {
        textContent: "",
        dataset: {},
        value: id === "amount" ? "25.00" : "merchant",
        addEventListener: (_name, handler) => {
          if (id === "request-transaction") transactionHandler = handler;
        },
      });
    }
    return elements.get(id)!;
  };
  class FakeEventSource {
    onerror?: () => void;
    constructor(_path: string) {}
    addEventListener(_name: string, _handler: (event: { data: string }) => void) {}
  }
  const source = await readFile(
    new URL("../apps/realtime-lab/public/app.js", import.meta.url),
    "utf8",
  );
  vm.runInNewContext(source, {
    document: {
      body: { dataset: {} },
      getElementById: element,
      querySelectorAll: () => [],
    },
    EventSource: FakeEventSource,
    fetch: async (_path: string, init: { headers: Record<string, string> }) => {
      requestHeaders = init.headers;
      throw new Error("synthetic connection refusal");
    },
    crypto: {
      randomUUID: () => {
        uuidCalls += 1;
        return "00000000-0000-4000-8000-000000000099";
      },
    },
    console,
  });
  assert.ok(transactionHandler, "transaction click handler should be registered");
  await transactionHandler();
  assert.equal(element("connection").textContent, "Connection error");
  assert.equal(element("result-title").textContent, "Network error");
  assert.match(element("result-message").textContent, /did not complete/);
  assert.equal(
    requestHeaders?.["idempotency-key"],
    "00000000-0000-4000-8000-000000000099",
  );
  await transactionHandler();
  assert.equal(uuidCalls, 1, "network retry must reuse the pending request key");
});
