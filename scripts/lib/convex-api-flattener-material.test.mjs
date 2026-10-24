import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  convexApiCompilerMaterialPaths,
  convexApiInstalledMaterialIdentity,
  convexApiProgramMaterialPaths,
} from "./convex-api-flattener-material.mjs";

test("canonical dependency paths through node_modules remain authenticated", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-api-material-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const installed = join(root, "installed");
  const nodeModulesRoot = join(root, "node_modules");
  await fs.mkdir(join(installed, "dependency"), { recursive: true });
  await fs.symlink(installed, nodeModulesRoot, "dir");
  const declaration = join(installed, "dependency/index.d.ts");
  await fs.writeFile(join(installed, "dependency/package.json"), '{"name":"dependency"}');
  await fs.writeFile(declaration, 'export type Value = "first";');
  const materialPaths = convexApiProgramMaterialPaths({
    nodeModulesRoot,
    sourceFileNames: [declaration, join(root, "functions/example.ts")],
  });
  assert.deepEqual(materialPaths, [
    "dependency", "dependency/index.d.ts", "dependency/package.json",
  ]);
  assert.deepEqual(materialPaths, convexApiProgramMaterialPaths({
    nodeModulesRoot,
    sourceFileNames: [join(nodeModulesRoot, "dependency/index.d.ts")],
  }));
  const before = convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths });
  await fs.writeFile(declaration, 'export type Value = "second";');
  const after = convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths });
  assert.notEqual(before.nodeModulesSha256, after.nodeModulesSha256);
});

test("compiler identity binds installed tsrs binaries and libraries", async (t) => {
  const nodeModulesRoot = await fs.mkdtemp(join(tmpdir(), "convex-api-compiler-material-"));
  t.after(() => fs.rm(nodeModulesRoot, { recursive: true, force: true }));
  const platformRoot = "@tsrs/linux-x64-gnu";
  for (const path of ["typescript", "tsrs", platformRoot]) {
    await fs.mkdir(join(nodeModulesRoot, path), { recursive: true });
    await fs.writeFile(join(nodeModulesRoot, path, "package.json"), "{}");
  }
  const nativePaths = [`${platformRoot}/tsrs`, `${platformRoot}/lib.d.ts`];
  await Promise.all(nativePaths.map((path) => fs.writeFile(join(nodeModulesRoot, path), "original")));
  const materialPaths = convexApiCompilerMaterialPaths({ nodeModulesRoot });
  const original = convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths });
  for (const path of nativePaths) {
    assert.ok(materialPaths.includes(path));
    await fs.writeFile(join(nodeModulesRoot, path), "changed");
    const changed = convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths });
    assert.notEqual(changed.nodeModulesSha256, original.nodeModulesSha256);
    await fs.writeFile(join(nodeModulesRoot, path), "original");
  }
});
