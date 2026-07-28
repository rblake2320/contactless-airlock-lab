import assert from "node:assert/strict";
import test from "node:test";
import { runLiveAcceptance } from "../tools/live-acceptance.ts";

test("isolated live acceptance exercises restart, limits, backup, and audit tamper", {
  timeout: 30_000,
}, async () => {
  const report = await runLiveAcceptance();
  assert.equal(report.passed, true);
  assert.equal(report.isolatedRoot, true);
  assert.equal(report.restartPersistence.passed, true);
  assert.equal(report.rateLimit.status, 429);
  assert.equal(report.rateLimit.stateUnchanged, true);
  assert.equal(report.sseLimit.acceptedBeforeLimit, 4);
  assert.equal(report.sseLimit.rejectedStatus, 429);
  assert.equal(report.sseLimit.reopenedAfterDisconnect, true);
  assert.equal(report.backupRestore.verifyOnly, true);
  assert.equal(report.backupRestore.materializedRestore, true);
  assert.equal(report.backupRestore.restoredStateVerified, true);
  assert.equal(report.auditTamper.blocked, true);
  assert.equal(report.auditTamper.authoritativeAuditValid, true);
});
