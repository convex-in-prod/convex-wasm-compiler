import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  authenticateConvexContextReuseApplicationAdmission,
  authenticateConvexContextReuseApplicationAdmissionPolicy,
  captureContextReuseExternalDependencyIdentities,
  dependencyMaterial,
  loadConvexContextReuseApplicationAdmissionPolicy,
} from "./convex-context-reuse-application-admission.mjs";
import {
  authenticateConvexContextReuseApplicationAdmission as authenticateFromAnalyzer,
  buildContextReuseGraph,
  convexContextReuseTestHooks,
  retainConvexContextReuseApplicationAdmission,
} from "./convex-context-reuse.mjs";

import { buildSyntheticDeploymentApplication } from "../test-fixtures/deployment-application.mjs";

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
  assert.equal(
    convexContextReuseTestHooks.applicationAdmissionFullAuthenticationCount(),
    authentications
  );
  assert.throws(
    () =>
      authenticateFromAnalyzer(result, {
        strictEntries: ["functions/action.ts"],
      }),
    /Selected action entry is missing/u
  );
  assert.equal(
    convexContextReuseTestHooks.applicationAdmissionFullAuthenticationCount(),
    authentications
  );
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

test("bundled dependency identities distinguish nested versions of the same import", async (context) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-context-reuse-versions-"));
  context.after(() => fs.rm(root, { force: true, recursive: true }));
  const boundaries = [
    "node_modules/@fixture/shared",
    "node_modules/parent/node_modules/@fixture/shared",
  ];
  for (const [index, boundary] of boundaries.entries()) {
    await fs.mkdir(join(root, boundary), { recursive: true });
    await fs.writeFile(
      join(root, boundary, "package.json"),
      JSON.stringify({
        name: "@fixture/shared",
        version: `${index + 1}.0.0`,
      })
    );
  }
  const imports = boundaries.map((boundary) => ({
    external: false,
    original: "@fixture/shared",
    path: `${boundary}/index.js`,
  }));
  const metafile = {
    inputs: Object.fromEntries(
      imports.map((dependency, index) => [`functions/entry${index}.js`, { imports: [dependency] }])
    ),
  };
  const captured = captureContextReuseExternalDependencyIdentities(root, metafile);
  assert.deepEqual(captured.externalDependencies, {
    [imports[0].path]: { packageName: "@fixture/shared", version: "1.0.0" },
    [imports[1].path]: { packageName: "@fixture/shared", version: "2.0.0" },
  });
  assert.deepEqual(
    captured.externalDependencyManifestPaths,
    new Set(boundaries.map((boundary) => join(root, boundary, "package.json")))
  );
  for (const [key, identity] of Object.entries(captured.externalDependencies)) {
    assert.deepEqual(
      dependencyMaterial(root, key, captured.externalDependencyResolutions[key]).identity,
      identity
    );
  }
  await fs.writeFile(
    join(root, boundaries[1], "package.json"),
    JSON.stringify({
      name: "@fixture/shared",
      version: "3.0.0",
    })
  );
  const changed = captureContextReuseExternalDependencyIdentities(root, metafile);
  assert.deepEqual(
    changed.externalDependencies[imports[0].path],
    captured.externalDependencies[imports[0].path]
  );
  assert.equal(changed.externalDependencies[imports[1].path].version, "3.0.0");
  await fs.writeFile(
    join(root, boundaries[1], "package.json"),
    JSON.stringify({
      name: "different-package",
      version: "3.0.0",
    })
  );
  assert.throws(
    () => captureContextReuseExternalDependencyIdentities(root, metafile),
    /Resolved dependency .* has package name/u
  );
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

for (const encoding of ["expanded", "grouped", "admission"]) {
  test(`strict action admission survives database-policy retention with mixed entries (${encoding})`, () => {
    const result = safeAnalysis();
    result.entries = ["functions/action.ts", "functions/query.ts"];
    const diagnostic = {
      category: "unsupported-construct",
      dependencyChain: [],
      entry: "functions/query.ts",
      file: "functions/query.ts",
      message: "The mutator receiver requires source review.",
      rule: "unresolved-mutator-application",
      severity: "unsupported",
      span: { column: 1, end: 1, endColumn: 2, endLine: 1, line: 1, start: 0 },
    };
    diagnostic.id = `ctx-${createHash("sha256")
      .update(
        [
          "context-reuse-diagnostic",
          diagnostic.rule,
          diagnostic.file,
          "0",
          "1",
          diagnostic.message,
          "",
        ].join("\0")
      )
      .digest("hex")
      .slice(0, 20)}`;
    result.safe = false;
    result.diagnostics = [diagnostic];
    if (encoding !== "expanded") {
      const { dependencyChain, entry, ...definition } = diagnostic;
      delete result.diagnostics;
      result.diagnosticEncoding = encoding;
      result.diagnosticDefinitions = [definition];
      result.diagnosticGroups = [
        { entry, findingIds: [diagnostic.id], ...(encoding === "grouped" ? { dependencyChain } : {}) },
      ];
    }
    result.diagnosticCounts = { unsupported: 1 };
    result.categoryCounts = { "unsupported-construct": 1 };
    const applicationAdmissionPolicy = {
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
        "This fixture admits only reviewed unresolved mutator applications in database function graphs.",
    };
    const options = { applicationAdmissionPolicy, strictEntries: ["functions/query.ts"] };
    assert.throws(
      () => authenticateConvexContextReuseApplicationAdmission(result, options),
      /without admitted findings/u
    );
    const retained = retainConvexContextReuseApplicationAdmission(result, {
      applicationAdmissionPolicy,
      strictEntries: ["functions/action.ts"],
    });
    const authentications = convexContextReuseTestHooks.applicationAdmissionFullAuthenticationCount();
    assert.throws(
      () => authenticateConvexContextReuseApplicationAdmission(result, options),
      /without admitted findings/u
    );
    assert.strictEqual(
      authenticateConvexContextReuseApplicationAdmission(result, {
        applicationAdmissionPolicy,
        strictEntries: ["functions/action.ts"],
      }),
      retained
    );
    assert.equal(
      convexContextReuseTestHooks.applicationAdmissionFullAuthenticationCount(),
      authentications
    );
  });
}

test("analysis graph authority cannot be replaced after construction", async (context) => {
  const { applicationRoot, inventory } = await buildSyntheticDeploymentApplication(context, {
    bindAnalysis: false,
  });
  const graph = await buildContextReuseGraph(
    applicationRoot,
    { inventory },
    { sourceRoots: ["shared"] }
  );
  for (const [field, replacement] of [
    ["kind", "convex-context-reuse-action-graph"],
    ["databaseFunctions", []],
    ["defaultDatabaseEntries", []],
    ["selectedActionEntries", ["functions/read.ts"]],
    ["actionFunctions", []],
    ["sourceTexts", { "functions/read.ts": "export const read = undefined;" }],
  ]) {
    assert.throws(() => {
      graph[field] = replacement;
    }, TypeError);
    assert.throws(() => {
      delete graph[field];
    }, TypeError);
  }
  assert.throws(() => {
    graph.databaseFunctions.length = 0;
  }, TypeError);
  const serialized = JSON.stringify(graph);
  assert.throws(() => {
    graph.toJSON = () => ({ kind: "convex-context-reuse-graph" });
  }, TypeError);
  assert.throws(() => {
    Object.defineProperty(graph, "toJSON", { value: () => ({}) });
  }, TypeError);
  Object.setPrototypeOf(graph, { toJSON: () => ({}) });
  assert.equal(JSON.stringify(graph), serialized);
  graph.acceptanceMetadata = "non-authority";
  assert.equal(graph.acceptanceMetadata, "non-authority");
});
