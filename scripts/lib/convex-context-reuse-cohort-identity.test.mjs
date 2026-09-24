import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";

function identity() {
  const payload = {
    entries: ["functions/first.ts", "functions/second.ts"],
    entryGraphSha256s: ["1".repeat(64), "2".repeat(64)],
    kind: "convex-context-reuse-cohort-analysis",
    policyFingerprint: "3".repeat(64),
    sharedAnalysisSha256: "4".repeat(64),
    thirdPartyMaterialFingerprints: {
      "node_modules/example/index.js": "5".repeat(64),
    },
  };
  return { ...payload, resultSha256: fingerprintJson(payload) };
}

test("authenticates the exact cohort graph and freezes returned identity", () => {
  const value = identity();
  const authenticated = authenticateConvexContextReuseCohortAnalysisIdentity(value, {
    expectedEntryGraphs: [
      { dependencyGraphSha256: "1".repeat(64), entryPath: "functions/first.ts" },
      { dependencyGraphSha256: "2".repeat(64), entryPath: "functions/second.ts" },
    ],
  });
  assert.deepEqual(authenticated, value);
  assert.equal(Object.isFrozen(authenticated), true);
  assert.equal(Object.isFrozen(authenticated.entries), true);
  assert.equal(Object.isFrozen(authenticated.thirdPartyMaterialFingerprints), true);
});

test("rejects changed identity bytes and a different admitted graph", () => {
  const value = identity();
  assert.throws(
    () => authenticateConvexContextReuseCohortAnalysisIdentity({ ...value, policyFingerprint: "6".repeat(64) }),
    /digest is invalid/u
  );
  assert.throws(
    () => authenticateConvexContextReuseCohortAnalysisIdentity(value, {
      expectedEntryGraphs: [
        { dependencyGraphSha256: "1".repeat(64), entryPath: "functions/first.ts" },
        { dependencyGraphSha256: "7".repeat(64), entryPath: "functions/second.ts" },
      ],
    }),
    /wrong entry graph/u
  );
  const malformed = { ...value, entries: ["functions/../first.ts", "functions/second.ts"] };
  assert.throws(
    () => authenticateConvexContextReuseCohortAnalysisIdentity(malformed),
    /entry 0 is invalid/u
  );
});
