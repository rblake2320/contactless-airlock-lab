import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalizeBinding } from "../packages/protocol/canonical.ts";
import type { ChallengeBinding } from "../packages/protocol/types.ts";

interface Vector {
  id: string;
  valid: boolean;
  binding: unknown;
  canonicalBase64?: string;
  sha256?: string;
  errorCode?: string;
}

interface VectorDocument {
  schemaVersion: string;
  vectors: Vector[];
}

const vectorUrl = new URL(
  "../packages/protocol/vectors/canonical-bindings-v1.json",
  import.meta.url,
);
const document = JSON.parse(
  readFileSync(vectorUrl, "utf8"),
) as VectorDocument;

test("TypeScript matches every versioned canonical byte and hash vector", () => {
  assert.equal(document.schemaVersion, "airlock.canonical-vectors.v1");
  const valid = document.vectors.filter((vector) => vector.valid);
  assert.equal(valid.length, 7);
  for (const vector of valid) {
    const bytes = Buffer.from(
      canonicalizeBinding(vector.binding as ChallengeBinding),
    );
    assert.equal(
      bytes.toString("base64"),
      vector.canonicalBase64,
      `${vector.id}: canonical bytes`,
    );
    assert.equal(
      createHash("sha256").update(bytes).digest("hex"),
      vector.sha256,
      `${vector.id}: SHA-256`,
    );
  }
});

test("TypeScript rejects every invalid cross-language vector", () => {
  const invalid = document.vectors.filter((vector) => !vector.valid);
  assert.equal(invalid.length, 12);
  for (const vector of invalid) {
    let message = "";
    try {
      canonicalizeBinding(vector.binding as ChallengeBinding);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    assert.notEqual(message, "", `${vector.id}: expected rejection`);
    const code =
      message.startsWith("unknown challenge field") ? "UNKNOWN_FIELD" :
      message === "unsupported challenge purpose" ? "UNSUPPORTED_PURPOSE" :
      message === "unsupported transaction currency" ? "UNSUPPORTED_CURRENCY" :
      message.includes("positive safe-integer amount") ? "INVALID_AMOUNT" :
      message === "invalid issuedAt" || message === "invalid expiresAt"
        ? "INVALID_TIMESTAMP" :
      message.startsWith("invalid challenge field") ? "INVALID_FIELD" :
      "UNCLASSIFIED";
    assert.equal(code, vector.errorCode, `${vector.id}: rejection category`);
  }
});

test("numeric wire aliases converge while NFC and NFD opaque IDs remain distinct", () => {
  const byId = new Map(document.vectors.map((vector) => [vector.id, vector]));
  const exponent = byId.get("transaction-exponent-integer")!;
  const decimal = byId.get("transaction-decimal-integer")!;
  assert.equal(
    (exponent.binding as ChallengeBinding).amountMinor,
    1_000,
  );
  assert.equal(
    (decimal.binding as ChallengeBinding).amountMinor,
    1_000,
  );
  for (const vector of [exponent, decimal]) {
    const canonical = Buffer.from(
      canonicalizeBinding(vector.binding as ChallengeBinding),
    ).toString("utf8");
    assert.match(canonical, /"amountMinor":1000/);
    assert.doesNotMatch(canonical, /1e3|1000\.0/);
  }

  const nfc = byId.get("opaque-id-nfc")!;
  const nfd = byId.get("opaque-id-nfd")!;
  const nfcSubject = (nfc.binding as ChallengeBinding).subjectId;
  const nfdSubject = (nfd.binding as ChallengeBinding).subjectId;
  assert.equal(nfcSubject.normalize("NFC"), nfdSubject.normalize("NFC"));
  assert.notEqual(nfcSubject, nfdSubject);
  assert.notEqual(nfc.canonicalBase64, nfd.canonicalBase64);
  assert.notEqual(nfc.sha256, nfd.sha256);
});

test("independent Python stdlib verifier matches bytes, hashes, and rejection set", () => {
  const python = process.platform === "win32" ? "python" : "python3";
  const verifier = fileURLToPath(
    new URL("../packages/protocol/python_reference_verifier.py", import.meta.url),
  );
  const result = spawnSync(
    python,
    [verifier, "--vectors", fileURLToPath(vectorUrl)],
    { encoding: "utf8", timeout: 15_000 },
  );
  assert.equal(
    result.status,
    0,
    `Python verifier failed: ${result.stderr || result.stdout}`,
  );
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: true,
    valid: 7,
    invalid: 12,
  });
});
