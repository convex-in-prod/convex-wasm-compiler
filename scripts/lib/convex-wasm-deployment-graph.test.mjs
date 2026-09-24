import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmOfficialOutputModuleGraphInputs } from "./convex-wasm-official-output-artifact-adapter.mjs";
import { buildSyntheticDeploymentApplication } from "../test-fixtures/deployment-application.mjs";

test("builds and selects an official SDK query from a separate application", async (context) => {
  const application = await buildSyntheticDeploymentApplication(context);
  assert.equal(application.chunkApplicationUnit.identity.entries[0].entryPath, "functions/read.ts");
  assert.equal(application.sourceEnvelope.selectedRoutes[0].exportName, "read");
  const cacheRoot = join(application.applicationRoot, "cache");
  await fs.mkdir(cacheRoot, { mode: 0o700 });
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "synthetic-module-graph-inputs",
    cacheRoot,
    repositoryRoot: application.applicationRoot,
    scope: "isolated-test",
  });
  let compilerInputs;
  const prepared = await buildConvexWasmOfficialOutputModuleGraphInputs({
    applicationUnit: application.chunkApplicationUnit,
    artifactConfig: {
      cacheLayout,
      cacheRoot,
      limits: { artifacts: { generatedJavaScriptBytes: 1024 * 1024 } },
      runtime: { includeDirectories: [] },
    },
    compiler: async (options) => {
      compilerInputs = options;
      return { kind: "synthetic-compiler-output" };
    },
    contextReuseAnalysisIdentity: application.graphSession.contextReuseAnalysisIdentity,
    platformLimits: {},
    sdkPackageVersion: application.packageSet.convex.version,
  });
  assert.equal(prepared.compilerOutput.kind, "synthetic-compiler-output");
  assert.equal(compilerInputs[0].capabilityEntry.entryPath, "functions/read.ts");
});
