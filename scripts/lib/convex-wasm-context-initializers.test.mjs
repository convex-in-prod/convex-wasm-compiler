import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

import { bundledModulesFromResult } from "./convex-wasm-deployment-graph.mjs";
import { contextReuseGroups as separateGroups } from "../test-fixtures/context-reuse-groups-v2.mjs";
import { readSyntheticCliDeploymentModules } from "../test-fixtures/deployment-application.mjs";

const require = createRequire(import.meta.url);
const sdkRoot = dirname(require.resolve("convex/package.json"));
const { contextReuseGroups: installedGroups } = await import(
  pathToFileURL(join(sdkRoot, "dist/esm/bundler/contextReuseGroups.js"))
);
const sourceMap = JSON.stringify({ version: 3, sources: [], names: [], mappings: "" });

async function fixture(context) {
  const repoRoot = await fs.mkdtemp(join(tmpdir(), "convex-initializers-"));
  context.after(() => fs.rm(repoRoot, { recursive: true, force: true }));
  await fs.writeFile(join(repoRoot, "package.json"), '{"type":"module"}\n');
  const entries = ["first", "second", "nested/database", "excluded"];
  const outputFiles = [
    { path: join(repoRoot, "out/_deps/shared.js"), text: "export const value = 7;\n" },
    { path: join(repoRoot, "out/_deps/shared.js.map"), text: sourceMap },
  ];
  const metafile = {
    inputs: {},
    outputs: { "out/_deps/shared.js": { bytes: 24, imports: [], exports: ["value"], inputs: {} } },
  };
  for (const entry of entries) {
    const specifier = entry.includes("/") ? "../_deps/shared.js" : "./_deps/shared.js";
    outputFiles.push({
      path: join(repoRoot, `out/${entry}.js`),
      text: `export { value } from ${JSON.stringify(specifier)};\n//# sourceMappingURL=${entry.split("/").at(-1)}.js.map\n`,
    });
    outputFiles.push({ path: join(repoRoot, `out/${entry}.js.map`), text: sourceMap });
    metafile.outputs[`out/${entry}.js`] = {
      entryPoint: `functions/${entry}.ts`,
      imports: [{ path: "out/_deps/shared.js", kind: "import-statement" }],
      exports: ["value"],
      inputs: {},
    };
  }
  return {
    contextReuseGroups: separateGroups,
    entryPoints: entries.map((entry) => join(repoRoot, `functions/${entry}.ts`)),
    functionsDirectory: join(repoRoot, "functions"),
    metafile,
    outputFiles,
    projectConfig: {
      bundler: {
        experimentalContextReuse: {
          exclusions: { "excluded.ts": "This entry must retain fresh initialization." },
          httpActions: true,
          actions: { entries: ["first.ts", "second.ts"], grouping: true },
        },
      },
    },
    repoRoot,
  };
}

async function consumeModules(input, result) {
  for (const module of result.exactModulesByPath.values()) {
    const path = join(input.repoRoot, "out", module.path);
    await fs.mkdir(dirname(path), { recursive: true });
    await fs.writeFile(path, module.source);
  }
  const policies = new Map();
  for (const entryPoint of input.entryPoints) {
    const path = entryPoint.replace(`${input.functionsDirectory}/`, "").replace(/\.ts$/u, ".js");
    const module = await import(pathToFileURL(join(input.repoRoot, "out", path)));
    assert.equal(module.value, 7);
    policies.set(path, module.experimental_reuseContext);
  }
  return policies;
}

function initializerMembers(input, path) {
  return input.metafile.outputs[`out/${path}`].imports.map((entry) => entry.path).sort();
}

for (const grouping of [true, false]) {
  test(`database membership spans action eligibility with action grouping ${grouping}`, async (context) => {
    const input = await fixture(context);
    input.projectConfig.bundler.experimentalContextReuse.actions.grouping = grouping;
    const result = await bundledModulesFromResult(input);
    const policies = await consumeModules(input, result);
    const first = policies.get("first.js");
    const second = policies.get("second.js");
    const database = policies.get("nested/database.js");
    assert.deepEqual(first.initializationModule, second.initializationModule);
    assert.equal(first.initializationModule.version, 2);
    assert.equal(first.initializationModule.database, database.initializationModule.database);
    assert.deepEqual(initializerMembers(input, first.initializationModule.database), [
      "out/first.js", "out/nested/database.js", "out/second.js",
    ]);
    assert.equal(first.actions, true);
    assert.equal(database.actions, false);
    assert.equal(database.httpActions, true);
    assert.equal(database.initializationModule.action, undefined);
    assert.equal(policies.get("excluded.js"), undefined);
    if (grouping) {
      assert.notEqual(first.initializationModule.database, first.initializationModule.action);
      assert.deepEqual(initializerMembers(input, first.initializationModule.action), [
        "out/first.js", "out/second.js",
      ]);
    } else {
      assert.equal(first.initializationModule.action, undefined);
    }
    const initializers = [...result.exactModulesByPath.values()].filter(({ path }) => path.startsWith("_deps/context_init_"));
    assert.equal(initializers.length, grouping ? 2 : 1);
    for (const module of initializers) {
      assert.equal(module.sourceMap, sourceMap);
      await import(pathToFileURL(join(input.repoRoot, "out", module.path)));
    }
  });
}

test("identical database and action members retain distinct initializer identities", async (context) => {
  const input = await fixture(context);
  input.projectConfig.bundler.experimentalContextReuse.actions.entries.push("nested/database.ts");
  const result = await bundledModulesFromResult(input);
  const policies = await consumeModules(input, result);
  const { database, action } = policies.get("first.js").initializationModule;
  assert.notEqual(database, action);
  assert.equal(result.exactModulesByPath.get(database).source, result.exactModulesByPath.get(action).source);
  assert.deepEqual(initializerMembers(input, database), initializerMembers(input, action));
});

test("a single selected action retains per-entry initialization", async (context) => {
  const input = await fixture(context);
  input.projectConfig.bundler.experimentalContextReuse.actions.entries = ["first.ts"];
  const policies = await consumeModules(input, await bundledModulesFromResult(input));
  assert.equal(policies.get("first.js").actions, true);
  assert.deepEqual(Object.keys(policies.get("first.js").initializationModule), ["version", "database"]);
});

test("entry-local initialization stays outside both shared groups", async (context) => {
  const input = await fixture(context);
  input.outputFiles.find(({ path }) => path.endsWith("/first.js")).text += "export const local = 1;\n";
  const result = await bundledModulesFromResult(input);
  const policies = await consumeModules(input, result);
  assert.equal(policies.get("first.js").actions, true);
  assert.equal(policies.get("first.js").initializationModule, undefined);
  assert.equal(policies.get("second.js").initializationModule.action, undefined);
  assert.deepEqual(initializerMembers(input, policies.get("second.js").initializationModule.database), [
    "out/nested/database.js", "out/second.js",
  ]);
});

test("legacy calls keep disjoint membership and string metadata", async (context) => {
  for (const grouping of [true, false]) {
    const input = await fixture(context);
    const calls = [];
    input.projectConfig.bundler.experimentalContextReuse.actions.grouping = grouping;
    // This five-argument stand-in checks the adapter ABI even after the installed
    // SDK upgrades. Exact legacy bytes are checked against the installed CLI.
    input.contextReuseGroups = async function (ctx, files, metafile, included, folder) {
      assert.equal(arguments.length, 5);
      calls.push([...included].map((path) => path.slice(path.indexOf("/out/") + 5)).sort());
      return separateGroups(ctx, files, metafile, included, folder, "database");
    };
    const policies = await consumeModules(input, await bundledModulesFromResult(input));
    assert.deepEqual(calls, grouping
      ? [["nested/database.js"], ["first.js", "second.js"]]
      : [["nested/database.js"]]);
    assert.equal(typeof policies.get("first.js").initializationModule, grouping ? "string" : "undefined");
    assert.equal(policies.get("nested/database.js").initializationModule, undefined);
    assert.equal(policies.get("excluded.js"), undefined);
  }
});

test("no helper, absent policy, and Node environment never generate initializers", async (context) => {
  for (const mode of ["no-helper", "no-policy", "node"]) {
    const input = await fixture(context);
    if (mode === "no-helper") delete input.contextReuseGroups;
    if (mode === "no-policy") delete input.projectConfig.bundler.experimentalContextReuse;
    if (mode === "node") input.environment = "node";
    const result = await bundledModulesFromResult(input);
    assert.equal(result.exactModulesByPath.size, 5);
    const policies = await consumeModules(input, result);
    for (const policy of policies.values()) assert.equal(policy?.initializationModule, undefined);
  }
});

test("unknown SDK helper signatures fail without probing output", async (context) => {
  const input = await fixture(context);
  input.contextReuseGroups = () => assert.fail("unsupported helper must not run");
  await assert.rejects(bundledModulesFromResult(input), /unsupported signature/u);
});

test("paired reconstruction matches installed SDK source, maps, names, and hashes", async (context) => {
  const input = await fixture(context);
  await fs.symlink(dirname(sdkRoot), join(input.repoRoot, "node_modules"));
  await fs.writeFile(join(input.repoRoot, "package.json"), JSON.stringify({
    name: "example", type: "module", dependencies: { convex: "^1.47.0" },
  }));
  await fs.mkdir(join(input.functionsDirectory, "nested"), { recursive: true });
  await fs.mkdir(join(input.repoRoot, "shared"));
  await fs.writeFile(join(input.repoRoot, "shared/registered.ts"), "export const value = 7;\n");
  for (const entryPoint of input.entryPoints) {
    await fs.writeFile(entryPoint, `export { value } from "${entryPoint.includes("/nested/") ? "../.." : ".."}/shared/registered";\n`);
  }
  const raw = await build({
    absWorkingDir: input.repoRoot,
    bundle: true,
    chunkNames: "_deps/[hash]",
    conditions: ["convex", "module"],
    define: { "process.env.NODE_ENV": '"production"' },
    entryPoints: input.entryPoints,
    format: "esm",
    jsx: "automatic",
    keepNames: true,
    metafile: true,
    minifyIdentifiers: true,
    minifySyntax: true,
    minifyWhitespace: false,
    outbase: input.functionsDirectory,
    outdir: "out",
    platform: "browser",
    sourcemap: true,
    sourcesContent: false,
    splitting: true,
    target: "esnext",
    treeShaking: true,
    write: false,
  });
  for (const grouping of [true, false]) {
    const policy = input.projectConfig.bundler.experimentalContextReuse;
    policy.actions.grouping = grouping;
    await fs.writeFile(join(input.repoRoot, "convex.json"), JSON.stringify({
      functions: "functions/",
      bundler: { includeSourcesContent: false, experimentalContextReuse: { default: true, ...policy } },
    }));
    const official = await readSyntheticCliDeploymentModules(input.repoRoot, join(input.repoRoot, `request-${grouping}`));
    const paired = await bundledModulesFromResult({
      ...input,
      contextReuseGroups: installedGroups,
      metafile: structuredClone(raw.metafile),
      outputFiles: raw.outputFiles,
    });
    assert.equal(paired.exactModulesByPath.size, official.length);
    for (const { environment, ...module } of official) {
      assert.deepEqual(paired.exactModulesByPath.get(module.path), module);
      assert.equal(
        paired.modulesByPath.get(module.path).moduleSha256,
        createHash("sha256").update(module.source).update(module.sourceMap).digest("hex")
      );
    }
    const expectedCount = installedGroups.length === 6 ? (grouping ? 2 : 1) : (grouping ? 1 : 0);
    assert.equal(official.filter(({ path }) => path.startsWith("_deps/context_init_")).length, expectedCount);
  }
});
