import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmOfficialOutputModuleGraphInputs } from "./convex-wasm-official-output-artifact-adapter.mjs";
import { buildSyntheticDeploymentApplication } from "../test-fixtures/deployment-application.mjs";
import { buildConvexWasmDeploymentGraphSession } from "./convex-wasm-deployment-graph.mjs";

test("matches the installed CLI for grouped forwarding entries and exclusions", async (context) => {
  const { applicationRoot, inventory } =
    await buildSyntheticDeploymentApplication(context);
  const packagePath = join(applicationRoot, "package.json");
  const packageJson = JSON.parse(await fs.readFile(packagePath, "utf8"));
  await fs.writeFile(
    packagePath,
    JSON.stringify({ ...packageJson, dependencies: { convex: "^1.46.0" } }),
  );
  const entry = await fs.readFile(
    join(applicationRoot, "functions/read.ts"),
    "utf8",
  );
  await fs.writeFile(
    join(applicationRoot, "shared/registered.ts"),
    entry
      .replaceAll('"./_generated/', '"../functions/_generated/')
      .replace('"../shared/helper"', '"./helper"'),
  );
  await fs.mkdir(join(applicationRoot, "functions/nested"));
  await Promise.all([
    fs.writeFile(
      join(applicationRoot, "functions/read.ts"),
      'export { read } from "../shared/registered";\n',
    ),
    fs.writeFile(
      join(applicationRoot, "functions/nested/other.ts"),
      'export { read } from "../../shared/registered";\n',
    ),
  ]);
  inventory.functions.push({
    ...inventory.functions[0],
    entryPath: "functions/nested/other.ts",
    modulePath: "nested/other",
  });
  for (const excluded of [false, true]) {
    await fs.writeFile(
      join(applicationRoot, "convex.json"),
      JSON.stringify({
        functions: "functions/",
        bundler: {
          includeSourcesContent: false,
          experimentalContextReuse: {
            default: true,
            httpActions: true,
            exclusions: excluded
              ? { "nested/other.ts": "Exercise the fresh entry contract." }
              : {},
          },
        },
      }),
    );
    const graph = await buildConvexWasmDeploymentGraphSession({
      inventory,
      materialVerificationConcurrency: 2,
      repoRoot: applicationRoot,
    });
    const requestPath = join(
      applicationRoot,
      excluded ? "excluded-request" : "grouped-request",
    );
    await promisify(execFile)(
      process.execPath,
      [
        join(applicationRoot, "node_modules/convex/bin/main.js"),
        "deploy",
        "--yes",
        "--codegen",
        "disable",
        "--typecheck",
        "disable",
        "--push-all-modules",
        "--write-push-request",
        requestPath,
      ],
      {
        cwd: applicationRoot,
        env: {
          ...process.env,
          CONVEX_DEPLOYMENT: "",
          CONVEX_DEPLOY_KEY: "",
          CONVEX_DEPLOYMENT_TOKEN: "",
          CONVEX_SELF_HOSTED_URL: "http://127.0.0.1:1",
          CONVEX_SELF_HOSTED_ADMIN_KEY: "local-request-only-placeholder",
        },
        timeout: 30_000,
      },
    );
    const request = JSON.parse(
      await fs.readFile(`${requestPath}.json`, "utf8"),
    );
    const official = request.appDefinition.changedModules.filter(
      (module) => module.environment === "isolate",
    );
    assert.equal(official.length, graph.deploymentOutputModulesByPath.size);
    for (const { path, source, sourceMap } of official) {
      assert.deepEqual(graph.deploymentOutputModulesByPath.get(path), {
        path,
        source,
        sourceMap,
      });
    }
    const initializers = official.filter((module) =>
      module.path.includes("context_init_"),
    );
    assert.equal(initializers.length, excluded ? 0 : 1);
    if (!excluded) {
      assert.match(initializers[0].source, /import "\.\.\/nested\/other.js";/u);
      assert.match(initializers[0].source, /import "\.\.\/read.js";/u);
      assert.deepEqual(JSON.parse(initializers[0].sourceMap), {
        version: 3,
        sources: [],
        names: [],
        mappings: "",
      });
    }
    await graph.verifyBundleInputMaterials();
  }
});

test("builds and selects an official SDK query from a separate application", async (context) => {
  const application = await buildSyntheticDeploymentApplication(context);
  assert.equal(
    application.chunkApplicationUnit.identity.entries[0].entryPath,
    "functions/read.ts",
  );
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
    contextReuseAnalysisIdentity:
      application.graphSession.contextReuseAnalysisIdentity,
    platformLimits: {},
    sdkPackageVersion: application.packageSet.convex.version,
  });
  assert.equal(prepared.compilerOutput.kind, "synthetic-compiler-output");
  assert.equal(
    compilerInputs[0].capabilityEntry.entryPath,
    "functions/read.ts",
  );
});
