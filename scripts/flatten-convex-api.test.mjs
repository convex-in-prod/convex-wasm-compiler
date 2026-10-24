import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { constants, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

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
  const source = `import { query, internalAction } from "./_generated/server";
export const read = query({ handler: (): "fresh" => "fresh" });
export const act = internalAction({ handler: async (): Promise<string> => "action" });
`;
  const files = {
    "package.json": JSON.stringify({ name: "api-fixture", private: true, type: "module" }),
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
  for (const path of ["convex", "typescript", "tsrs", "@tsrs", ".package-lock.json"]) {
    await fs.cp(join(repositoryRoot, "node_modules", path), join(root, "node_modules", path), {
      recursive: true, mode: constants.COPYFILE_FICLONE,
    });
  }
  const environment = { ...process.env, XDG_CACHE_HOME: cacheRoot };
  delete environment.TSRS_BINARY;
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
