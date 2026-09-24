import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveConvexWasmApplicationBundlerPackageSet } from "../lib/convex-wasm-application-package-set.mjs";
import { createConvexContextReuseAnalysisInputGraphSha256 } from "../lib/convex-context-reuse-analysis-input.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "../lib/convex-wasm-compiler-contract.mjs";
import {
  bindConvexWasmContextReuseAnalysisGraphSession,
  buildConvexWasmDeploymentGraphSession,
  captureConvexWasmContextReuseAnalysisInputGraphBasis,
  captureConvexWasmContextReuseSourceTexts,
} from "../lib/convex-wasm-deployment-graph.mjs";
import { captureConvexWasmGitSourceSnapshot } from "../lib/convex-wasm-git-source-snapshot.mjs";
import { buildConvexWasmOfficialOutputApplicationUnit } from "../lib/convex-wasm-official-output-application-unit.mjs";
import { buildConvexWasmOfficialOutputChunkApplicationUnit } from "../lib/convex-wasm-official-output-chunk-application-unit.mjs";
import { buildConvexWasmOfficialOutputChunkUnits } from "../lib/convex-wasm-official-output-chunk-unit.mjs";
import {
  buildConvexWasmOfficialOutputPrototype,
  selectConvexWasmOfficialOutputPrototype,
} from "../lib/convex-wasm-official-output-prototype.mjs";
import { createConvexWasmSourceEnvelope } from "../lib/convex-wasm-source-envelope.mjs";

const compilerRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export async function buildSyntheticDeploymentApplication(context, { bindAnalysis = true } = {}) {
  const applicationRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-deployment-graph-"));
  context.after(() => fs.rm(applicationRoot, { force: true, recursive: true }));
  await Promise.all([
    fs.mkdir(join(applicationRoot, "functions")),
    fs.mkdir(join(applicationRoot, "shared")),
    fs.mkdir(join(applicationRoot, "scripts")),
  ]);
  await fs.mkdir(join(applicationRoot, "functions", "_generated"));
  await Promise.all([
    fs.writeFile(
      join(applicationRoot, "package.json"),
      '{"name":"example","version":"1.0.0","type":"module"}\n'
    ),
    fs.writeFile(
      join(applicationRoot, "convex.json"),
      '{"functions":"functions/","bundler":{"includeSourcesContent":false,"experimentalContextReuse":{"default":true}}}\n'
    ),
    fs.writeFile(
      join(applicationRoot, "functions", "read.ts"),
      'import { query } from "./_generated/server";\nimport { generated } from "./_generated/api";\nimport { answer } from "../shared/helper";\nexport const read = query({ handler: async () => generated ? answer : 0 });\n'
    ),
    fs.writeFile(join(applicationRoot, "shared", "helper.ts"), "export const answer = 42;\n"),
    fs.writeFile(
      join(applicationRoot, "functions", "_generated", "server.js"),
      'import { queryGeneric } from "convex/server";\nexport const query = queryGeneric;\n'
    ),
    fs.writeFile(
      join(applicationRoot, "functions", "_generated", "api.ts"),
      "export const generated = true;\n"
    ),
    fs.writeFile(
      join(applicationRoot, "scripts", "convex-wasm-dependency-adapters.json"),
      '{"kind":"convex-wasm-dependency-adapter-descriptor","adapters":[]}\n'
    ),
    fs.writeFile(
      join(applicationRoot, "scripts", "convex-wasm-registration-adapters.json"),
      '{"kind":"convex-wasm-registration-adapter-descriptor","adapters":[],"sourceOperations":[]}\n'
    ),
    fs.cp(join(compilerRoot, "node_modules"), join(applicationRoot, "node_modules"), {
      recursive: true,
    }),
  ]);
  const inventory = {
    actions: [],
    authority: { sourceRoot: "functions", snapshot: { inputSha256: "a".repeat(64) } },
    functions: [
      {
        entryPath: "functions/read.ts",
        exportName: "read",
        modulePath: "read",
        udfKind: "query",
        visibility: "public",
      },
    ],
    kind: "convex-generated-api-inventory-v1",
    snapshot: { inputSha256: "a".repeat(64) },
  };
  const graph = await buildConvexWasmDeploymentGraphSession({
    inventory,
    materialVerificationConcurrency: 2,
    repoRoot: applicationRoot,
  });
  const packages = resolveConvexWasmApplicationBundlerPackageSet(applicationRoot);
  assert.deepEqual(graph.graphTemplate.toolchain, {
    convex: packages.convex.version,
    esbuild: packages.esbuild.version,
  });
  assert.ok(graph.dependencyGraphByEntry.has("functions/read.ts"));
  assert.equal(graph.inputMaterials["functions/read.ts"].virtual, false);
  assert.equal(graph.inputMaterials["shared/helper.ts"].virtual, false);
  assert.ok(
    graph.dependencyGraphByEntry.get("functions/read.ts").inputPaths.includes("shared/helper.ts")
  );
  await Promise.all([graph.verifyInputMaterials(), graph.verifyBundleInputMaterials()]);

  execFileSync("git", ["init", "-q"], { cwd: applicationRoot });
  execFileSync("git", ["add", "functions", "shared", "convex.json", "scripts"], {
    cwd: applicationRoot,
  });
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex.json", "functions", "scripts", "shared"],
    repoRoot: applicationRoot,
  });
  const pendingGraph = await buildConvexWasmDeploymentGraphSession({
    effectExecutionMode: convexWasmGuestPromiseEffectExecutionMode,
    gitSourceSnapshot: { repoRoot: applicationRoot, snapshot },
    inventory,
    materialVerificationConcurrency: 2,
    repoRoot: applicationRoot,
  });
  const basis = captureConvexWasmContextReuseAnalysisInputGraphBasis(pendingGraph);
  const sourceTexts = await captureConvexWasmContextReuseSourceTexts(pendingGraph, {
    functionsRoot: "functions",
    sourceRoots: ["functions/", "shared/"],
  });
  assert.match(sourceTexts["functions/read.ts"], /export const read/u);
  assert.match(sourceTexts["shared/helper.ts"], /export const answer/u);
  assert.match(sourceTexts["functions/_generated/api.ts"], /export const generated/u);
  await assert.rejects(
    captureConvexWasmContextReuseSourceTexts(pendingGraph, {
      functionsRoot: "other",
      sourceRoots: ["other/"],
    }),
    /functions root disagrees with the graph inventory/u
  );
  const analysis = {
    analysisInputGraphSha256: createConvexContextReuseAnalysisInputGraphSha256(basis),
    analysisInputSha256: "b".repeat(64),
    categoryCounts: {},
    diagnosticCounts: {},
    diagnostics: [],
    entries: ["functions/read.ts"],
    generatedInventoryInputSha256: inventory.authority.snapshot.inputSha256,
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
    moduleSummarySchema: "synthetic-analysis-v1",
    policyFingerprint: "c".repeat(64),
    safe: true,
    suppressedFindings: 0,
    thirdPartyMaterialFingerprints: {},
  };
  if (!bindAnalysis) {
    return {
      analysis,
      applicationRoot,
      inventory,
      packageSet: packages,
      pendingGraph,
    };
  }
  assert.throws(
    () =>
      bindConvexWasmContextReuseAnalysisGraphSession({
        contextReuseAnalysis: { ...analysis, analysisInputGraphSha256: "d".repeat(64) },
        graphSession: pendingGraph,
      }),
    /graph-input identity does not match/u
  );
  const stagedGraph = bindConvexWasmContextReuseAnalysisGraphSession({
    contextReuseAnalysis: analysis,
    graphSession: pendingGraph,
  });
  assert.ok(stagedGraph.sourceGraphSnapshot);
  assert.ok(stagedGraph.dependencyGraphByEntry.has("functions/read.ts"));
  await stagedGraph.verifyGitSourceSnapshot();
  const sourceEnvelope = createConvexWasmSourceEnvelope({
    graphSession: stagedGraph,
    inventory,
    selectedExports: [{ exportName: "read", modulePath: "read" }],
  });
  assert.equal(sourceEnvelope.selectedRoutes[0].entryPath, "functions/read.ts");
  const selection = selectConvexWasmOfficialOutputPrototype({
    entryPath: "functions/read.ts",
    exportName: "read",
    graphSession: stagedGraph,
    inventory,
    sourceEnvelope,
  });
  const requireFromApplication = createRequire(join(applicationRoot, "package.json"));
  const requireFromConvex = createRequire(requireFromApplication.resolve("convex/package.json"));
  const esbuild = requireFromConvex("esbuild");
  const prototype = await buildConvexWasmOfficialOutputPrototype({
    esbuild,
    selection,
  });
  const applicationUnit = buildConvexWasmOfficialOutputApplicationUnit({
    prototype,
    selections: [selection],
  });
  assert.equal(applicationUnit.identity.routes[0].entryPath, "functions/read.ts");
  assert.equal(applicationUnit.identity.javascript.size, Buffer.byteLength(applicationUnit.javascript));
  const chunkUnits = await buildConvexWasmOfficialOutputChunkUnits({
    esbuild,
    selections: [selection],
  });
  const chunkApplicationUnit = buildConvexWasmOfficialOutputChunkApplicationUnit({ chunkUnits });
  assert.equal(chunkApplicationUnit.identity.entries[0].entryPath, "functions/read.ts");
  return {
    applicationRoot,
    applicationUnit,
    chunkApplicationUnit,
    graphSession: stagedGraph,
    inventory,
    packageSet: packages,
    selection,
    sourceEnvelope,
  };
}
