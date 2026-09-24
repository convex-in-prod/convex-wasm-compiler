import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildConvexWasmSourceGraph } from "./convex-wasm-source-graph.mjs";
import { resolveConvexWasmApplicationBundlerPackageSet } from "./convex-wasm-application-package-set.mjs";

const compilerRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("builds a source graph with packages resolved from the application root", async (context) => {
  const applicationRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-"));
  context.after(() => fs.rm(applicationRoot, { force: true, recursive: true }));
  await fs.mkdir(join(applicationRoot, "scripts"));
  await fs.mkdir(join(applicationRoot, "convex"));
  await Promise.all([
    fs.writeFile(join(applicationRoot, "package.json"), '{"name":"example","version":"1.0.0"}\n'),
    fs.writeFile(join(applicationRoot, "convex", "read.ts"), "export const read = () => 42;\n"),
    fs.writeFile(
      join(applicationRoot, "scripts", "convex-wasm-dependency-adapters.json"),
      '{"kind":"convex-wasm-dependency-adapter-descriptor","adapters":[]}\n'
    ),
    fs.writeFile(
      join(applicationRoot, "scripts", "convex-wasm-registration-adapters.json"),
      '{"kind":"convex-wasm-registration-adapter-descriptor","adapters":[],"sourceOperations":[]}\n'
    ),
    fs.symlink(join(compilerRoot, "node_modules"), join(applicationRoot, "node_modules"), "dir"),
  ]);
  const packages = resolveConvexWasmApplicationBundlerPackageSet(applicationRoot);
  const graph = await buildConvexWasmSourceGraph({
    entryPath: "convex/read.ts",
    exportName: "read",
    repoRoot: applicationRoot,
  });
  assert.deepEqual(graph.toolchain, {
    convex: packages.convex.version,
    esbuild: packages.esbuild.version,
  });
  assert.equal(graph.entryPath, "convex/read.ts");
  assert.ok(Object.keys(graph.metafile.inputs).some((path) => path.endsWith("convex/read.ts")));
});
