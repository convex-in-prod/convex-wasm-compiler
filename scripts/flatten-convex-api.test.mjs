import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { constants, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { API } from "tsrs/unstable/sync";
import * as ts from "tsrs/unstable/ast";
import { convexApiSourceSurfaceProjection } from "./lib/convex-api-flattener-reuse.mjs";
import { projectTsrsCacheRoot } from "./lib/tsrs-cache.mjs";

import {
  captureConvexWasmGitSourceSnapshot,
  publishConvexWasmGitSourceSnapshotFile,
} from "./lib/convex-wasm-git-source-snapshot.mjs";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("bundled flattener uses tsrs for fresh, cached, and captured-source inventories", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-api-tsrs-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheRoot = join(root, "cache");
  const source = `// Astral characters must not shift native UTF-16 positions: 🌍
const [,,ignored] = [1, 2, 3];
import { query, internalAction } from "./_generated/server";
export const read = query({ handler: (): "fresh" => "fresh" });
export const act = internalAction({ handler: async (): Promise<string> => "action" });
`;
  const files = {
    "package.json": JSON.stringify({ private: true, type: "module" }),
    "package-lock.json": '{"lockfileVersion":3}',
    "convex.json": '{"functions":"functions/"}',
    "flattener.config.mjs": `export default {
  sourceRoots: ["support"],
  additionalBuilders: [{ name: "customQuery", kind: "query", visibility: "public", source: "support/builders.ts" }],
  generatedRegistry: { generatedModule: "functions/registry.ts", runtimeIdentifier: "registry", expectedRegisteredExports: ["write"] },
};\n`,
    "functions/tsconfig.json": JSON.stringify({
      compilerOptions: {
        target: "ES2022", module: "ESNext", moduleResolution: "Bundler",
        strict: true, skipLibCheck: true, noEmit: true, types: [],
      },
    }),
    "functions/_generated/dataModel.d.ts": "export type DataModel = import('convex/server').GenericDataModel;\n",
    "functions/_generated/server.d.ts": `import type { QueryBuilder, ActionBuilder, MutationBuilder, GenericDataModel } from "convex/server";
export declare const query: QueryBuilder<GenericDataModel, "public">;
export declare const internalAction: ActionBuilder<GenericDataModel, "internal">;
export declare const mutation: MutationBuilder<GenericDataModel, "public">;
`,
    "functions/_generated/api.d.ts": "export declare const api: {};\nexport declare const internal: {};\n",
    "functions/example.ts": source,
    "support/builders.ts": `import { query } from "../functions/_generated/server";
export const customQuery = query;\n`,
    "functions/wrapped.ts": `import { customQuery } from "../support/builders";
export const customRead = customQuery({ handler: () => 7 });\n`,
    "functions/registry.ts": `import { mutation } from "./_generated/server";
const registry = { write: mutation({ handler: () => true }) };
export const { write } = registry;\n`,
  };
  for (const [path, contents] of Object.entries(files)) {
    await fs.mkdir(dirname(join(root, path)), { recursive: true });
    await fs.writeFile(join(root, path), contents);
  }
  // Exercise the installed native API and dependency reads, not a simulated checker.
  for (const path of ["convex", "tsrs", "@tsrs", ".package-lock.json"]) {
    await fs.cp(join(repositoryRoot, "node_modules", path), join(root, "node_modules", path), {
      recursive: true, mode: constants.COPYFILE_FICLONE,
    });
  }
  await fs.mkdir(join(root, "node_modules/tsrs/node_modules"));
  await fs.rename(join(root, "node_modules/@tsrs"), join(root, "node_modules/tsrs/node_modules/@tsrs"));
  const environment = { ...process.env, XDG_CACHE_HOME: cacheRoot,
    TSRS_CACHE_DIR: join(cacheRoot, "tsrs") };
  delete environment.TSRS_BINARY;
  delete environment.TSRS_CACHE_NAMESPACE;
  function run(mode, extra = [], env = environment) {
    return execFileAsync(process.execPath, [
      join(repositoryRoot, "scripts/flatten-convex-api.mjs"), mode,
      ...(mode.endsWith("snapshot") ? [join(root, "inventory")] : []),
      "--project-root", root, "--config", "flattener.config.mjs", ...extra,
    ], { cwd: root, env, timeout: 120_000, maxBuffer: 1024 * 1024 });
  }
  const cold = JSON.parse((await run("--route-inventory-snapshot")).stdout);
  const routes = JSON.parse(await fs.readFile(join(cold.snapshotPath, "api-routes.json"), "utf8"));
  assert.deepEqual(routes.functions.map(({ exportName, kind, visibility }) => [exportName, kind, visibility]), [
    ["act", "action", "internal"], ["read", "query", "public"],
    ["write", "mutation", "public"], ["customRead", "query", "public"],
  ]);
  assert.equal(cold.generatorCache, "miss");
  const warm = JSON.parse((await run("--route-inventory-snapshot")).stdout);
  assert.equal(warm.generatorCache, "hit");
  assert.equal(warm.inputSha256, cold.inputSha256);
  const evictedPath = join(cacheRoot, "tsrs/project/convex-api/compiler/inventory-routes-v1", `${cold.inputSha256}.routes.json.gz`);
  const evictionHook = join(root, "evict-cache.mjs");
  await fs.writeFile(evictionHook, `
    import fs from "node:fs";
    import { syncBuiltinESMExports } from "node:module";
    const { openSync, readFileSync, closeSync } = fs;
    const paths = new Map();
    fs.openSync = function(path, ...args) {
      const fd = openSync(path, ...args);
      paths.set(fd, path);
      return fd;
    };
    fs.readFileSync = function(path, ...args) {
      const bytes = readFileSync(path, ...args);
      if (paths.get(path) === process.env.CACHE_EVICT_PATH) {
        fs.unlinkSync(process.env.CACHE_EVICT_PATH);
        fs.writeFileSync(process.env.CACHE_EVICT_PATH + ".observed", "evicted");
      }
      return bytes;
    };
    fs.closeSync = function(fd) { paths.delete(fd); return closeSync(fd); };
    syncBuiltinESMExports();
  `);
  const afterEviction = JSON.parse((await run("--route-inventory-snapshot", [], {
    ...environment, NODE_OPTIONS: `--import ${JSON.stringify(evictionHook)}`, CACHE_EVICT_PATH: evictedPath,
  })).stdout);
  assert.equal(await fs.readFile(evictedPath + ".observed", "utf8"), "evicted");
  assert.equal(afterEviction.generatorCache, "miss");
  assert.equal(afterEviction.outputSha256, cold.outputSha256);
  const projectCache = join(cacheRoot, "tsrs/project");
  await fs.chmod(projectCache, 0o777);
  try {
    await assert.rejects(run("--route-inventory-snapshot"), /cache directory is not private/u);
  } finally {
    await fs.chmod(projectCache, 0o700);
  }
  await fs.writeFile(join(root, "functions/example.ts"), source.replace(
    '(): "fresh" => "fresh"', '(): "fresh" => ("fresh")'
  ));
  const surfaceResult = await run("--route-inventory-snapshot");
  const surface = JSON.parse(surfaceResult.stdout);
  assert.equal(surface.generatorCache, "hit");
  assert.notEqual(surface.inputSha256, cold.inputSha256);
  assert.equal(surface.outputSha256, cold.outputSha256);
  assert.match(surfaceResult.stderr, /implementation-safe flattened Convex API inventory/u);
  await fs.writeFile(join(root, "functions/example.ts"), source);
  await assert.rejects(run("--route-inventory-snapshot", [], {
    ...environment, TSRS_BINARY: process.execPath,
  }), /requires the installed tsrs binary/u);

  await fs.appendFile(join(root, "node_modules/tsrs/lib/version.cjs"), "\n// identity change\n");
  const changedCompiler = JSON.parse((await run("--route-inventory-snapshot")).stdout);
  assert.equal(changedCompiler.generatorCache, "miss");
  assert.notEqual(changedCompiler.inputSha256, cold.inputSha256);
  assert.equal(changedCompiler.outputSha256, cold.outputSha256);

  await fs.rename(join(root, "node_modules"), join(root, "installed-packages"));
  await fs.symlink(join(root, "installed-packages"), join(root, "node_modules"), "dir");
  const linked = JSON.parse((await run("--route-inventory-snapshot")).stdout);
  const linkedMetadata = JSON.parse(await fs.readFile(join(linked.snapshotPath, "inventory.json"), "utf8"));
  assert.ok(linkedMetadata.programMaterialPaths.includes("convex/dist/esm-types/server/registration.d.ts"));
  await fs.appendFile(join(root, "node_modules/convex/dist/esm-types/server/registration.d.ts"), "\n// dependency change\n");
  const changedDependency = JSON.parse((await run("--route-inventory-snapshot")).stdout);
  assert.equal(changedDependency.generatorCache, "miss");
  assert.notEqual(changedDependency.inputSha256, linked.inputSha256);

  await run("--write");
  const declaration = await fs.readFile(join(root, "functions/_generated/api.d.ts"), "utf8");
  assert.match(declaration, /"read": FunctionReference<"query", "public",[\s\S]*?ConvertReturnType<Awaited<"fresh">>>;/u);
  assert.match(declaration, /FunctionReference<"action", "internal"/u);
  await run("--check");

  // Failed resolution is part of cache authority too. Exercise an absent package
  // at node_modules and one below an existing scope without changing the npm lock.
  const missingEntry = join(root, "functions/missing.ts");
  const missingSource = `import { query } from "./_generated/server";
import type { Result } from "fixture-missing";
import type { Result as ScopedResult } from "@fixture/missing";
export const read = query({ handler: (): Result & ScopedResult => "present" });\n`;
  await fs.mkdir(join(root, "node_modules/@fixture"));
  await fs.writeFile(missingEntry, missingSource);
  try {
    const absent = JSON.parse((await run("--inventory-snapshot")).stdout);
    for (const [index, name] of ["fixture-missing", "@fixture/missing"].entries()) {
      const directory = join(root, "node_modules", name);
      await fs.mkdir(directory);
      await fs.writeFile(join(directory, "package.json"), JSON.stringify({ name, types: "index.d.ts" }));
      await fs.writeFile(join(directory, "index.d.ts"), 'export type Result = "present";\n');
      if (index === 1) {
        // The declaration surface is unchanged; this also exercises surface-cache rejection.
        await fs.writeFile(missingEntry, missingSource.replace('=> "present"', '=> ("present")'));
      }
      const current = JSON.parse((await run("--inventory-snapshot")).stdout);
      assert.equal(current.generatorCache, "miss");
      assert.notEqual(current.inputSha256, absent.inputSha256);
      if (index === 1) {
        const output = await fs.readFile(join(current.snapshotPath, "api.d.ts"), "utf8");
        assert.match(output, /ConvertReturnType<Awaited<"present">>>;/u);
        assert.doesNotMatch(output, /Awaited<any>/u);
      }
    }
  } finally {
    await fs.rm(missingEntry);
    await fs.rm(join(root, "node_modules/fixture-missing"), { recursive: true, force: true });
    await fs.rm(join(root, "node_modules/@fixture"), { recursive: true, force: true });
  }

  const sourceChangeHook = join(root, "change-config.mjs");
  await fs.writeFile(sourceChangeHook, `
    import { API } from ${JSON.stringify(join(root, "node_modules/tsrs/dist/api/sync/api.js"))};
    import { readFileSync, writeFileSync } from "node:fs";
    const config = ${JSON.stringify(join(root, "functions/tsconfig.json"))};
    const original = readFileSync(config);
    const getter = Object.getOwnPropertyDescriptor(API.prototype, "createSnapshot").get;
    Object.defineProperty(API.prototype, "createSnapshot", { get() {
      const create = getter.call(this);
      return (...args) => {
        writeFileSync(config, '{"compilerOptions":{"noLib":true}}');
        try { return create(...args); } finally { writeFileSync(config, original); }
      };
    }});
  `);
  await assert.rejects(run("--inventory-snapshot", [], {
    ...environment,
    TSRS_CACHE_DIR: join(cacheRoot, "source-change"),
    NODE_OPTIONS: `--import ${JSON.stringify(sourceChangeHook)}`,
  }), (error) => error.code === 75 && /Convex API inputs changed during generation/u.test(error.stderr));

  // One process must return from cache hits, release native resources on failures, and
  // evaluate each call's captured config instead of Node's path-keyed module cache.
  await execFileAsync(process.execPath, ["--input-type=module", "-e", String.raw`
    import assert from "node:assert/strict";
    import { promises as fs } from "node:fs";
    import { main } from ${JSON.stringify(join(repositoryRoot, "scripts/flatten-convex-api.mjs"))};
    import { API } from ${JSON.stringify(join(root, "node_modules/tsrs/dist/api/sync/api.js"))};
    const close = Object.getOwnPropertyDescriptor(API.prototype, "close").get;
    const closed = new Set();
    Object.defineProperty(API.prototype, "close", { get() {
      return () => { close.call(this)(); closed.add(this); };
    }});
    const args = ["--check", "--project-root", ${JSON.stringify(root)}, "--config", "flattener.config.mjs"];
    const configPath = ${JSON.stringify(join(root, "flattener.config.mjs"))};
    const config = await fs.readFile(configPath);
    await main(args);
    await fs.writeFile(configPath, "export default { unknown: true };\n");
    try {
      await assert.rejects(main(args), /Unknown Convex API flattener configuration field: unknown/);
    } finally { await fs.writeFile(configPath, config); }
    await main(args);
    assert.equal(closed.size, 3);
    for (const api of closed) {
      assert.equal(api.activeSnapshots.size, 0);
      assert.equal(api.activeSourceFileLeases.size, 0);
    }
    const runtimePath = ${JSON.stringify(join(root, "node_modules/tsrs/lib/version.cjs"))};
    const runtime = await fs.readFile(runtimePath);
    await fs.appendFile(runtimePath, "\n// changed during this process\n");
    try {
      await assert.rejects(main(args), /Installed tsrs material changed after it was loaded/);
    } finally { await fs.writeFile(runtimePath, runtime); }
    await assert.rejects(main(args), /Installed tsrs material changed after it was loaded/);
  `], { cwd: root, env: environment, timeout: 120_000, maxBuffer: 1024 * 1024 });

  // The native snapshot must not publish types read from an intervening dependency
  // version under the identity of the bytes restored before publication.
  const contractDirectory = join(root, "node_modules", "fixture-contract");
  const contractPath = join(contractDirectory, "index.d.ts");
  const contractEntry = join(root, "functions", "contract.ts");
  const ambientDirectory = join(root, "node_modules", "@types", "fixture-ambient");
  const tsconfigPath = join(root, "functions", "tsconfig.json");
  const originalTsconfig = await fs.readFile(tsconfigPath);
  const dependencyTypesConfig = JSON.parse(originalTsconfig);
  dependencyTypesConfig.include = ["**/*", "../node_modules/@types/**/*.d.ts"];
  await fs.writeFile(tsconfigPath, JSON.stringify(dependencyTypesConfig));
  await fs.mkdir(ambientDirectory, { recursive: true });
  await fs.writeFile(join(ambientDirectory, "index.d.ts"), 'type FixtureAmbientResult = "original";\n');
  await fs.mkdir(contractDirectory);
  await fs.writeFile(join(contractDirectory, "package.json"), '{"name":"fixture-contract","types":"index.d.ts"}');
  await fs.writeFile(contractPath, '\ufeffexport type Result = "original";\n');
  await fs.writeFile(contractEntry, `import { query } from "./_generated/server";
import type { Result } from "fixture-contract";
export const read = query({ handler: (): Result & FixtureAmbientResult => "original" });\n`);
  try {
    await execFileAsync(process.execPath, ["--input-type=module", "-e", String.raw`
      import assert from "node:assert/strict";
      import { readFileSync, renameSync, writeFileSync } from "node:fs";
      import { main } from ${JSON.stringify(join(repositoryRoot, "scripts/flatten-convex-api.mjs"))};
      import { API } from ${JSON.stringify(join(root, "node_modules/tsrs/dist/api/sync/api.js"))};
      const path = ${JSON.stringify(contractPath)};
      const ambient = ${JSON.stringify(ambientDirectory)};
      const hiddenAmbient = ${JSON.stringify(join(root, "hidden-ambient"))};
      const original = readFileSync(path);
      const createSnapshot = Object.getOwnPropertyDescriptor(API.prototype, "createSnapshot").get;
      let snapshots = 0;
      for (const change of ["contents", "missing", "listing"]) {
        Object.defineProperty(API.prototype, "createSnapshot", { get() {
          const create = createSnapshot.call(this);
          return (...args) => {
            snapshots += 1;
            if (change === "listing") renameSync(ambient, hiddenAmbient);
            else if (change === "missing") renameSync(path, path + ".saved");
            else writeFileSync(path, 'export type Result = "intervening";\n');
            try { return create(...args); }
            finally {
              if (change === "listing") renameSync(hiddenAmbient, ambient);
              else if (change === "missing") renameSync(path + ".saved", path);
              else writeFileSync(path, original);
            }
          };
        }});
        await assert.rejects(main([
          "--inventory-snapshot", "dependency-race-inventory",
          "--project-root", ${JSON.stringify(root)}, "--config", "flattener.config.mjs",
        ]), /Convex API inputs changed during generation/);
      }
      assert.equal(snapshots, 3);
    `], { cwd: root, env: environment, timeout: 120_000, maxBuffer: 1024 * 1024 });
    const recovered = JSON.parse((await run("--inventory-snapshot")).stdout);
    const recoveredDeclaration = await fs.readFile(join(recovered.snapshotPath, "api.d.ts"), "utf8");
    assert.match(recoveredDeclaration, /ConvertReturnType<Awaited<"original">>>;/u);
    assert.doesNotMatch(recoveredDeclaration, /intervening/u);
  } finally {
    await fs.rm(contractDirectory, { recursive: true, force: true });
    await fs.rm(ambientDirectory, { recursive: true, force: true });
    await fs.rm(contractEntry);
    await fs.writeFile(tsconfigPath, originalTsconfig);
  }

  await execFileAsync("git", ["init", "-q"], { cwd: root });
  // Route analysis consumes the captured API declaration; other source files retain their
  // physical-input contract. Make a worktree declaration reread change registration inference.
  await fs.writeFile(join(root, "functions/example.ts"), `import { api } from "./_generated/api";
import { query } from "./_generated/server";
import type { RegisteredQuery } from "convex/server";
export const captured: typeof api.example.read._returnType extends "captured"
  ? RegisteredQuery<"public", {}, "captured"> : never = query({ handler: () => "captured" });
`);
  const capturedApi = `export declare const api: { example: { read: { _returnType: "captured" } } };
export declare const internal: {};
`;
  await fs.writeFile(join(root, "functions/_generated/api.d.ts"), capturedApi);
  const pathspecs = ["package.json", "package-lock.json", "convex.json", "flattener.config.mjs", "functions", "support"];
  await execFileAsync("git", ["add", "--", ...pathspecs], { cwd: root });
  const snapshotPath = await publishConvexWasmGitSourceSnapshotFile({
    outputPath: join(root, "snapshot.json"),
    snapshot: await captureConvexWasmGitSourceSnapshot({ repoRoot: root, pathspecs }),
  });
  await fs.writeFile(join(root, "functions/_generated/api.d.ts"), capturedApi.replace('"captured"', '"worktree"'));
  await fs.rm(cacheRoot, { recursive: true });
  const captured = JSON.parse((await run("--route-inventory-snapshot", [
    "--git-source-snapshot", snapshotPath,
  ])).stdout);
  assert.equal(captured.generatorCache, "miss");
  const capturedRoutes = JSON.parse(await fs.readFile(join(captured.snapshotPath, "api-routes.json"), "utf8"));
  assert.deepEqual(capturedRoutes.functions.map(({ exportName }) => exportName), ["captured", "write", "customRead"]);
  await assert.rejects(run("--route-inventory-snapshot"), /did not infer a registered Convex function/u);
  assert.match(await fs.readFile(join(root, "functions/_generated/api.d.ts"), "utf8"), /"worktree"/u);
});


test("surface projection retains syntax authority and UTF-16 ranges after releasing native trees", () => {
  const syntaxApi = new API();
  const sourceFileCache = new Map();
  const sourcePath = "/fixture/entry.tsx";
  const project = (source) => convexApiSourceSurfaceProjection({
    source, sourcePath, sourceFileCache, syntaxApi, ts,
  });
  try {
    const source = '// 🌍\nexport function answer(): string { return "first"; }\nexport const tail = 42;';
    const first = project(source);
    assert.equal(project(source.replace('"first"', '"second"')), first);
    assert.notEqual(project(source.replace('(): string', '(): number')), first);
    assert.notEqual(project(source.replace('return "first";', 'return import("./dependency");')), first);
    const jsx = 'export function view(): unknown { return <span title="first" />; }';
    assert.notEqual(project(jsx), project(jsx.replace('"first"', '"second"')));
    assert.equal(project('export function invalid(): string { return (; }'), undefined);
    project(source);
  } finally {
    syntaxApi.close();
  }
  const retained = sourceFileCache.get(sourcePath);
  assert.equal(retained.statements[1].getText(retained), "export const tail = 42;");
});

test("shared tsrs caches accept application names and respect the selected root", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-api-cache-location-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const name = "@example/an-application-with-a-long-package-name-for-shared-compiler-results";
  await fs.writeFile(join(root, "package.json"), JSON.stringify({ name, private: true }));
  const cache = join(root, "selected-cache");
  assert.equal(projectTsrsCacheRoot(root, { TSRS_CACHE_DIR: cache, XDG_CACHE_HOME: "" }),
    join(cache, name.slice(1).replace("/", "-")));
  assert.equal(projectTsrsCacheRoot(root, { TSRS_CACHE_DIR: cache, TSRS_CACHE_NAMESPACE: "custom" }),
    join(cache, "custom"));
  await fs.writeFile(join(root, "package.json"), JSON.stringify({ private: true }));
  assert.equal(projectTsrsCacheRoot(root, { XDG_CACHE_HOME: cache }), join(cache, "tsrs/project"));
});
