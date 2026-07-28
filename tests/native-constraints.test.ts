import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { createLabServer } from "../apps/realtime-lab/server.ts";

// Regex-based text scan, deliberately with no DOM/HTML-parser dependency —
// same zero-dependency-tooling convention as scripts/no-test-verifier-in-prod.mjs.
// This does not re-implement parseAmountMinor/parseMerchantId's logic (that
// would just be two copies of the same regex that could drift together);
// instead every case below is checked against BOTH the extracted HTML
// attribute AND the live server response, so drift between markup and
// server validation fails here directly.

const htmlPath = new URL("../apps/realtime-lab/public/index.html", import.meta.url);
const html = readFileSync(htmlPath, "utf8");

function extractInputTag(id: string): string {
  const match = new RegExp(`<input id="${id}"[^>]*>`).exec(html);
  assert.ok(match, `<input id="${id}"> not found in index.html`);
  return match[0];
}

function attr(tag: string, name: string): string | undefined {
  const match = new RegExp(`${name}="([^"]*)"`).exec(tag);
  return match?.[1];
}

function hasFlag(tag: string, name: string): boolean {
  return new RegExp(`(^|\\s)${name}(\\s|=|>)`).test(tag);
}

const amountTag = extractInputTag("amount");
const merchantTag = extractInputTag("merchant");

test("amount input declares required, text type (no numeric coercion), and a real maxlength", () => {
  assert.equal(attr(amountTag, "type"), "text", "amount must be type=text, not type=number, to avoid silent numeric coercion/rounding");
  assert.ok(hasFlag(amountTag, "required"), "amount must be required");
  const maxlength = Number(attr(amountTag, "maxlength"));
  assert.ok(Number.isInteger(maxlength) && maxlength > 0, "amount must declare a positive maxlength");
});

test("merchant input declares required, text type, and a real maxlength", () => {
  assert.equal(attr(merchantTag, "type"), "text");
  assert.ok(hasFlag(merchantTag, "required"), "merchant must be required");
  const maxlength = Number(attr(merchantTag, "maxlength"));
  assert.ok(Number.isInteger(maxlength) && maxlength > 0, "merchant must declare a positive maxlength");
});

test("the form uses a real <form>+type=submit, not a bare button, so native validation actually fires", () => {
  const formMatch = /<form id="transaction-request-form">[\s\S]*?<\/form>/.exec(html);
  assert.ok(formMatch, "transaction-request-form must be a real <form>");
  const formBody = formMatch[0];
  assert.match(formBody, /<button[^>]*type="submit"[^>]*>/, "submit control must be type=submit inside the form");
  assert.doesNotMatch(formBody, /novalidate/, "novalidate would disable the native validation this test exists to prove works");
});

interface AmountCase { amount: string; accepted: boolean }
const AMOUNT_CASES: AmountCase[] = [
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
  { amount: "01.00", accepted: false },
  { amount: "25,00", accepted: false },
  { amount: "$25.00", accepted: false },
];

interface MerchantCase { merchantId: string; accepted: boolean }
const MERCHANT_CASES: MerchantCase[] = [
  { merchantId: "synthetic-merchant-001", accepted: true },
  { merchantId: "a", accepted: true },
  { merchantId: "A0._:-", accepted: true },
  { merchantId: " padded-merchant ", accepted: true },
  { merchantId: "", accepted: false },
  { merchantId: "-leading-hyphen", accepted: false },
  { merchantId: "has space", accepted: false },
  { merchantId: "has/slash", accepted: false },
  { merchantId: "a".repeat(65), accepted: false },
  { merchantId: "<script>", accepted: false },
];

function htmlPatternRegExp(tag: string): RegExp {
  const pattern = attr(tag, "pattern");
  assert.ok(pattern, "pattern attribute must be present");
  // HTML's pattern attribute is implicitly fully anchored (behaves as if
  // wrapped in ^(?:...)$) against the whole value.
  return new RegExp(`^(?:${pattern})$`);
}

test("HTML amount pattern accepts/rejects exactly the same boundary cases as the live server", async () => {
  const patternRegExp = htmlPatternRegExp(amountTag);
  const server = createLabServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    for (const [index, item] of AMOUNT_CASES.entries()) {
      assert.equal(
        patternRegExp.test(item.amount),
        item.accepted,
        `HTML pattern case ${index}: ${JSON.stringify(item.amount)}`,
      );
      await fetch(`${baseUrl}/api/reset`, { method: "POST" });
      await fetch(`${baseUrl}/api/provision/request`, { method: "POST" });
      await fetch(`${baseUrl}/api/provision/approve`, { method: "POST" });
      const response = await fetch(`${baseUrl}/api/transaction/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ amount: item.amount, merchantId: "merchant-1" }),
      });
      assert.equal(
        response.status === 200,
        item.accepted,
        `live server case ${index}: ${JSON.stringify(item.amount)} returned ${response.status}`,
      );
    }
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
});

test("HTML merchant pattern accepts/rejects exactly the same boundary cases as the live server", async () => {
  const patternRegExp = htmlPatternRegExp(merchantTag);
  const server = createLabServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    for (const [index, item] of MERCHANT_CASES.entries()) {
      assert.equal(
        patternRegExp.test(item.merchantId),
        item.accepted,
        `HTML pattern case ${index}: ${JSON.stringify(item.merchantId)}`,
      );
      await fetch(`${baseUrl}/api/reset`, { method: "POST" });
      await fetch(`${baseUrl}/api/provision/request`, { method: "POST" });
      await fetch(`${baseUrl}/api/provision/approve`, { method: "POST" });
      const response = await fetch(`${baseUrl}/api/transaction/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ amount: "25.00", merchantId: item.merchantId }),
      });
      assert.equal(
        response.status === 200,
        item.accepted,
        `live server case ${index}: ${JSON.stringify(item.merchantId)} returned ${response.status}`,
      );
    }
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
});

test("maxlength never truncates a value the pattern would otherwise accept", () => {
  const amountMaxlength = Number(attr(amountTag, "maxlength"));
  const merchantMaxlength = Number(attr(merchantTag, "maxlength"));
  for (const item of AMOUNT_CASES.filter((c) => c.accepted)) {
    assert.ok(item.amount.length <= amountMaxlength, `"${item.amount}" (${item.amount.length}) exceeds amount maxlength ${amountMaxlength}`);
  }
  for (const item of MERCHANT_CASES.filter((c) => c.accepted)) {
    assert.ok(item.merchantId.length <= merchantMaxlength, `"${item.merchantId}" (${item.merchantId.length}) exceeds merchant maxlength ${merchantMaxlength}`);
  }
});

test("server remains the sole authority: a raw fetch bypassing the HTML form entirely is still independently rejected", async () => {
  const server = createLabServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await fetch(`${baseUrl}/api/reset`, { method: "POST" });
    await fetch(`${baseUrl}/api/provision/request`, { method: "POST" });
    await fetch(`${baseUrl}/api/provision/approve`, { method: "POST" });
    // These bypass the browser entirely (no form, no pattern attribute in
    // play at all) and use values the HTML pattern would have blocked, to
    // prove the server enforces this independently rather than trusting
    // whatever the client claims.
    const rejections: Array<{ body: unknown; expectedCode: string }> = [
      { body: { amount: "1e3", merchantId: "merchant-1" }, expectedCode: "AMOUNT_FORMAT_INVALID" },
      { body: { amount: "-1.00", merchantId: "merchant-1" }, expectedCode: "AMOUNT_NON_POSITIVE" },
      { body: { amount: "25.00", merchantId: "has space" }, expectedCode: "MERCHANT_INVALID" },
      { body: { amount: "25.00", merchantId: "" }, expectedCode: "MERCHANT_REQUIRED" },
      { body: { amount: 25, merchantId: "merchant-1" }, expectedCode: "AMOUNT_REQUIRED" },
    ];
    for (const { body, expectedCode } of rejections) {
      const response = await fetch(`${baseUrl}/api/transaction/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      assert.notEqual(response.status, 200, JSON.stringify(body));
      const payload = await response.json();
      assert.equal(payload.code, expectedCode, JSON.stringify(body));
    }
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve()));
  }
});
