import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmOfficialOutputModuleGraphInputs } from "./convex-wasm-official-output-artifact-adapter.mjs";
import { buildSyntheticDeploymentApplication } from "../test-fixtures/deployment-application.mjs";
import {
  bindConvexWasmContextReuseAnalysisGraphSession,
  buildConvexWasmDeploymentGraphSession,
} from "./convex-wasm-deployment-graph.mjs";
import { createConvexContextReuseAnalysisInputGraphSha256 } from "./convex-context-reuse-analysis-input.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "./convex-wasm-compiler-contract.mjs";
import { captureConvexWasmGitSourceSnapshot } from "./convex-wasm-git-source-snapshot.mjs";
import { publishConvexWasmSourceGraphSnapshot } from "./convex-wasm-source-graph-snapshot-cache.mjs";

async function compareCliModules(applicationRoot, graph, requestPath) {
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
    }
  );
  const request = JSON.parse(await fs.readFile(`${requestPath}.json`, "utf8"));
  const official = request.appDefinition.changedModules.filter(
    (module) => module.environment === "isolate"
  );
  assert.equal(official.length, graph.deploymentOutputModulesByPath.size);
  for (const { path, source, sourceMap } of official) {
    assert.deepEqual(graph.deploymentOutputModulesByPath.get(path), {
      path,
      source,
      sourceMap,
    });
  }
  return official;
}

test("matches the installed CLI for grouped forwarding entries and exclusions", async (context) => {
  const { applicationRoot, inventory } = await buildSyntheticDeploymentApplication(context);
  const packagePath = join(applicationRoot, "package.json");
  const packageJson = JSON.parse(await fs.readFile(packagePath, "utf8"));
  await fs.writeFile(
    packagePath,
    JSON.stringify({ ...packageJson, dependencies: { convex: "^1.46.0" } })
  );
  const entry = await fs.readFile(join(applicationRoot, "functions/read.ts"), "utf8");
  await fs.writeFile(
    join(applicationRoot, "shared/registered.ts"),
    entry
      .replaceAll('"./_generated/', '"../functions/_generated/')
      .replace('"../shared/helper"', '"./helper"')
  );
  await fs.mkdir(join(applicationRoot, "functions/nested"));
  await Promise.all([
    fs.writeFile(
      join(applicationRoot, "functions/read.ts"),
      'export { read } from "../shared/registered";\n'
    ),
    fs.writeFile(
      join(applicationRoot, "functions/nested/other.ts"),
      'export { read } from "../../shared/registered";\n'
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
            exclusions: excluded ? { "nested/other.ts": "Exercise the fresh entry contract." } : {},
          },
        },
      })
    );
    const graph = await buildConvexWasmDeploymentGraphSession({
      inventory,
      materialVerificationConcurrency: 2,
      repoRoot: applicationRoot,
    });
    const requestPath = join(applicationRoot, excluded ? "excluded-request" : "grouped-request");
    const official = await compareCliModules(applicationRoot, graph, requestPath);
    const initializers = official.filter((module) => module.path.includes("context_init_"));
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

test("action groups match the CLI and exclude unselected entries", async (context) => {
  const { applicationRoot, inventory } = await buildSyntheticDeploymentApplication(context);
  await fs.writeFile(
    join(applicationRoot, "package.json"),
    JSON.stringify({
      name: "example",
      version: "1.0.0",
      type: "module",
      dependencies: { convex: "^1.47.0" },
    })
  );
  await fs.appendFile(
    join(applicationRoot, "functions/_generated/server.js"),
    'export { actionGeneric as action } from "convex/server";\n'
  );
  await fs.writeFile(
    join(applicationRoot, "shared/actions.ts"),
    'import { action } from "../functions/_generated/server";\n' +
      "export const first = action({ handler: async (_ctx, args) => args.first });\n" +
      "export const second = action({ handler: async (_ctx, args) => args.second });\n"
  );
  for (const modulePath of ["first", "second", "unselected"]) {
    await fs.writeFile(
      join(applicationRoot, `functions/${modulePath}.ts`),
      'export { first, second } from "../shared/actions";\n'
    );
    for (const exportName of ["first", "second"]) {
      inventory.actions.push({
        entryPath: `functions/${modulePath}.ts`,
        modulePath,
        exportName,
        udfKind: "action",
        visibility: "public",
      });
    }
  }
  for (const grouping of [true, false]) {
    await fs.writeFile(
      join(applicationRoot, "convex.json"),
      JSON.stringify({
        functions: "functions/",
        bundler: {
          includeSourcesContent: false,
          experimentalContextReuse: {
            default: true,
            actions: { entries: ["first.ts", "second.ts"], grouping },
          },
        },
      })
    );
    const graph = await buildConvexWasmDeploymentGraphSession({
      inventory,
      repoRoot: applicationRoot,
      materialVerificationConcurrency: 2,
    });
    const official = await compareCliModules(
      applicationRoot,
      graph,
      join(applicationRoot, `actions-${grouping}`)
    );
    const initializers = official.filter(({ path }) => path.includes("context_init_"));
    assert.equal(initializers.length, grouping ? 1 : 0);
    if (grouping) {
      assert.match(initializers[0].source, /import "\.\.\/first.js"/u);
      assert.match(initializers[0].source, /import "\.\.\/second.js"/u);
      assert.doesNotMatch(initializers[0].source, /unselected/u);
    }
    for (const entry of ["first.js", "second.js"]) {
      assert.match(graph.deploymentOutputModulesByPath.get(entry).source, /actions: true/u);
    }
    assert.doesNotMatch(
      graph.deploymentOutputModulesByPath.get("unselected.js").source,
      /actions: true/u
    );
    await graph.verifyBundleInputMaterials();
  }
});

for (const mixedEntry of [false, true]) {
  test(`action analysis survives pending binding and cached graph admission (mixed=${mixedEntry})`, async (context) => {
    const { applicationRoot, inventory, analysis } = await buildSyntheticDeploymentApplication(
      context,
      { bindAnalysis: false }
    );
    const actionEntry = mixedEntry ? "read" : "run";
    const entryPath = `functions/${actionEntry}.ts`;
    const actionSource =
      'import { actionGeneric } from "convex/server";\n' +
      "export const run = actionGeneric({ handler: async (_ctx, args) => args });\n";
    await Promise.all([
      fs.appendFile(join(applicationRoot, entryPath), actionSource),
      fs.writeFile(
        join(applicationRoot, "convex.json"),
        JSON.stringify({
          functions: "functions/",
          bundler: {
            experimentalContextReuse: {
              default: true,
              actions: { entries: [`${actionEntry}.ts`] },
            },
          },
        })
      ),
      fs.writeFile(
        join(applicationRoot, "convex-context-reuse-application-admission.json"),
        JSON.stringify({
          kind: "convex-context-reuse-application-admission-policy",
          hardFindings: "block",
          otherUnsupportedFindings: "block",
          rationale:
            "This fixture admits database mutator findings while requiring strict analysis of selected action entries.",
          admittedFinding: {
            category: "unsupported-construct",
            fileRoots: ["functions/"],
            rule: "unresolved-mutator-application",
            severity: "unsupported",
          },
        })
      ),
    ]);
    inventory.actions.push({
      entryPath,
      modulePath: actionEntry,
      exportName: "run",
      udfKind: "action",
      visibility: "public",
    });
    await promisify(execFile)("git", ["add", "functions", "convex.json"], { cwd: applicationRoot });
    const snapshot = await captureConvexWasmGitSourceSnapshot({
      pathspecs: ["convex.json", "functions", "scripts", "shared"],
      repoRoot: applicationRoot,
    });
    const options = {
      effectExecutionMode: convexWasmGuestPromiseEffectExecutionMode,
      gitSourceSnapshot: { repoRoot: applicationRoot, snapshot },
      inventory,
      materialVerificationConcurrency: 2,
      repoRoot: applicationRoot,
    };
    const pending = await buildConvexWasmDeploymentGraphSession(options);
    const selectedAnalysis = {
      ...analysis,
      analysisInputGraphSha256: createConvexContextReuseAnalysisInputGraphSha256(
        pending.contextReuseAnalysisInputGraphBasis
      ),
      entries: [...new Set(["functions/read.ts", entryPath])].sort(),
    };
    const rule = "unresolved-mutator-application";
    const message = "Synthetic unresolved collection operation";
    const id = `ctx-${createHash("sha256")
      .update(["context-reuse-diagnostic", rule, entryPath, "0", "1", message, ""].join("\0"))
      .digest("hex")
      .slice(0, 20)}`;
    assert.throws(
      () =>
        bindConvexWasmContextReuseAnalysisGraphSession({
          graphSession: pending,
          contextReuseAnalysis: {
            ...selectedAnalysis,
            safe: false,
            categoryCounts: { "unsupported-construct": 1 },
            diagnosticCounts: { unsupported: 1 },
            diagnostics: [
              {
                id,
                rule,
                message,
                entry: entryPath,
                file: entryPath,
                category: "unsupported-construct",
                severity: "unsupported",
                dependencyChain: [],
                span: { start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 },
              },
            ],
          },
        }),
      /Action context reuse requires supported analysis/u
    );
    const bound = bindConvexWasmContextReuseAnalysisGraphSession({
      contextReuseAnalysis: selectedAnalysis,
      graphSession: pending,
    });
    assert.deepEqual(bound.contextReuseAnalysisIdentity.entries, selectedAnalysis.entries);
    const cacheDirectory = join(applicationRoot, "graph-cache");
    await publishConvexWasmSourceGraphSnapshot({
      cacheDirectory,
      snapshot: bound.sourceGraphSnapshot,
    });
    const cached = await buildConvexWasmDeploymentGraphSession({
      ...options,
      contextReuseAnalysis: selectedAnalysis,
      sourceGraphSnapshotCacheDirectory: cacheDirectory,
    });
    assert.equal(cached.sourceGraphSnapshotCache.lookup, "authenticated-session-hit");
    assert.equal(cached.graphTemplate.functionsRoot, "functions");
    assert.deepEqual(cached.contextReuseAnalysisIdentity, bound.contextReuseAnalysisIdentity);
    await cached.verifyInputMaterials();
  });
}
