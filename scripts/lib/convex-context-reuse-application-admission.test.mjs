import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  authenticateConvexContextReuseApplicationAdmission,
  authenticateConvexContextReuseApplicationAdmissionPolicy,
  captureContextReuseExternalDependencyIdentities,
  loadConvexContextReuseApplicationAdmissionPolicy,
} from "./convex-context-reuse-application-admission.mjs";
import {
  authenticateConvexContextReuseApplicationAdmission as authenticateFromAnalyzer,
  convexContextReuseTestHooks,
  retainConvexContextReuseApplicationAdmission,
} from "./convex-context-reuse.mjs";

function safeAnalysis() {
  return {
    analysisInputGraphSha256: "b".repeat(64),
    analysisInputSha256: "a".repeat(64),
    categoryCounts: {},
    diagnosticCounts: {},
    diagnostics: [],
    entries: [],
    generatedInventoryInputSha256: "1".repeat(64),
    kind: "convex-context-reuse-analysis",
    metrics: {
      cacheHits: 0,
      cacheLookupUs: 0,
      cacheMisses: 0,
      esbuildGraphUs: 0,
      graphReadUs: 0,
      modulesAnalyzed: 0,
      parseUs: 0,
      parsedModules: 0,
      peakRssBytes: null,
      reachabilityUs: 0,
      semanticUs: 0,
      sourceReadUs: 0,
      wallTimeUs: 0,
    },
    moduleSummarySchema: "convex-wasm-module-summary-test",
    policyFingerprint: "0".repeat(64),
    safe: true,
    suppressedFindings: 0,
    thirdPartyMaterialFingerprints: {},
  };
}

test("application admission binds the exact analysis graph", () => {
  const analysis = safeAnalysis();
  const admitted = authenticateConvexContextReuseApplicationAdmission(analysis, {
    expectedAnalysisInputGraphSha256: analysis.analysisInputGraphSha256,
    expectedEntries: [],
  });
  assert.deepEqual(admitted.identity.entries, []);
  assert.equal(admitted.identity.kind, "convex-context-reuse-analysis");
  assert.throws(
    () =>
      authenticateConvexContextReuseApplicationAdmission(analysis, {
        expectedAnalysisInputGraphSha256: "c".repeat(64),
        expectedEntries: [],
      }),
    /graph-input identity does not match/u
  );
});

test("analyzer and admission module share retained result authority", () => {
  const result = safeAnalysis();
  const admission = retainConvexContextReuseApplicationAdmission(result, {
    expectedAnalysisInputGraphSha256: result.analysisInputGraphSha256,
    expectedEntries: [],
  });
  const authentications = convexContextReuseTestHooks.applicationAdmissionFullAuthenticationCount();
  assert.strictEqual(
    authenticateFromAnalyzer(result, {
      expectedAnalysisInputGraphSha256: result.analysisInputGraphSha256,
      expectedEntries: [],
    }),
    admission
  );
  assert.equal(convexContextReuseTestHooks.applicationAdmissionFullAuthenticationCount(), authentications);
});

test("external dependency capture identifies Node builtins without a package manifest", () => {
  const captured = captureContextReuseExternalDependencyIdentities(process.cwd(), {
    inputs: {
      "functions/example.ts": {
        imports: [{ external: true, path: "node:crypto" }],
      },
    },
  });
  assert.deepEqual(captured.externalDependencies, {
    "node:crypto": { packageName: "node:crypto", version: process.version },
  });
  assert.equal(captured.externalDependencyManifestPaths.size, 0);
});

test("application admission policy accepts explicit first-party roots", () => {
  const policy = {
    admittedFinding: {
      category: "unsupported-construct",
      fileRoots: ["functions/", "shared/"],
      rule: "unresolved-mutator-application",
      severity: "unsupported",
    },
    hardFindings: "block",
    kind: "convex-context-reuse-application-admission-policy",
    otherUnsupportedFindings: "block",
    rationale:
      "This fixture admits only reviewed unresolved mutator applications under the selected first-party roots.",
  };
  assert.deepEqual(
    authenticateConvexContextReuseApplicationAdmissionPolicy(policy).admittedFinding.fileRoots,
    ["functions/", "shared/"]
  );
  for (const root of ["node_modules/", "../functions/", "functions//"]) {
    assert.throws(
      () =>
        authenticateConvexContextReuseApplicationAdmissionPolicy({
          ...policy,
          admittedFinding: { ...policy.admittedFinding, fileRoots: [root] },
        }),
      /sorted first-party file roots/u
    );
  }
});

test("loads an application policy without following a replacement link", async (context) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-context-reuse-admission-"));
  context.after(() => fs.rm(root, { force: true, recursive: true }));
  const policyPath = join(root, "convex-context-reuse-application-admission.json");
  const policy = {
    admittedFinding: {
      category: "unsupported-construct",
      fileRoots: ["functions/"],
      rule: "unresolved-mutator-application",
      severity: "unsupported",
    },
    hardFindings: "block",
    kind: "convex-context-reuse-application-admission-policy",
    otherUnsupportedFindings: "block",
    rationale:
      "This fixture admits one reviewed finding category in its first-party functions directory.",
  };
  assert.equal(loadConvexContextReuseApplicationAdmissionPolicy(root), undefined);
  await fs.writeFile(policyPath, `${JSON.stringify(policy)}\n`);
  assert.deepEqual(loadConvexContextReuseApplicationAdmissionPolicy(root), policy);
  await fs.rename(policyPath, join(root, "policy-target.json"));
  await fs.symlink(join(root, "policy-target.json"), policyPath);
  assert.throws(() => loadConvexContextReuseApplicationAdmissionPolicy(root));
});
