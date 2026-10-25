import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  captureConvexApiInstalledMaterial,
  convexApiCompilerMaterialPaths,
  convexApiInstalledMaterialIdentity,
  convexApiProgramMaterialPaths,
  verifyConvexApiInstalledMaterial,
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
  const root = await fs.mkdtemp(join(tmpdir(), "convex-api-compiler-material-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const nodeModulesRoot = join(root, "node_modules");
  const platformRoot = "@tsrs/linux-x64-gnu";
  for (const path of ["tsrs", platformRoot]) {
    await fs.mkdir(join(nodeModulesRoot, path), { recursive: true });
    await fs.writeFile(join(nodeModulesRoot, path, "package.json"), "{}");
  }
  await fs.writeFile(join(nodeModulesRoot, "tsrs/package.json"), JSON.stringify({
    optionalDependencies: { "@tsrs/linux-x64-gnu": "1.0.0" },
  }));
  const nativePaths = [`${platformRoot}/tsrs`, `${platformRoot}/lib.d.ts`];
  await Promise.all(nativePaths.map((path) => fs.writeFile(join(nodeModulesRoot, path), "original")));
  const materialPaths = convexApiCompilerMaterialPaths({ nodeModulesRoot });
  const capture = captureConvexApiInstalledMaterial({ nodeModulesRoot, materialPaths });
  const original = capture.identity;
  verifyConvexApiInstalledMaterial(capture);
  for (const path of nativePaths) {
    assert.ok(materialPaths.includes(path));
    await fs.writeFile(join(nodeModulesRoot, path), "changed");
    const changed = convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths });
    assert.notEqual(changed.nodeModulesSha256, original.nodeModulesSha256);
    await fs.writeFile(join(nodeModulesRoot, path), "original");
  }
  assert.deepEqual(convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths }), original);
  assert.throws(() => verifyConvexApiInstalledMaterial(capture), /changed after capture/u);
  const nestedRoot = join(root, "nested/node_modules");
  await fs.mkdir(join(nestedRoot, "tsrs/node_modules"), { recursive: true });
  await fs.copyFile(join(nodeModulesRoot, "tsrs/package.json"), join(nestedRoot, "tsrs/package.json"));
  await fs.cp(join(nodeModulesRoot, "@tsrs"), join(nestedRoot, "tsrs/node_modules/@tsrs"), { recursive: true });
  const nestedPaths = convexApiCompilerMaterialPaths({ nodeModulesRoot: nestedRoot });
  for (const path of nativePaths) assert.ok(nestedPaths.includes(`tsrs/node_modules/${path}`));
  const nested = convexApiInstalledMaterialIdentity({ nodeModulesRoot: nestedRoot, materialPaths: nestedPaths });
  await fs.writeFile(join(nestedRoot, "tsrs/node_modules", nativePaths[0]), "nested change");
  assert.notEqual(
    convexApiInstalledMaterialIdentity({ nodeModulesRoot: nestedRoot, materialPaths: nestedPaths }).nodeModulesSha256,
    nested.nodeModulesSha256
  );
});

test("compiler identity retains native package symlink authority", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-api-native-link-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const nodeModulesRoot = join(root, "node_modules");
  await fs.mkdir(join(nodeModulesRoot, "tsrs"), { recursive: true });
  await fs.writeFile(join(nodeModulesRoot, "tsrs/package.json"), JSON.stringify({
    optionalDependencies: { "@tsrs/linux-x64-gnu": "1.0.0" },
  }));
  for (const directory of ["native", "replacement"]) {
    await fs.mkdir(join(nodeModulesRoot, directory, "linux-x64-gnu"), { recursive: true });
    await fs.writeFile(join(nodeModulesRoot, directory, "linux-x64-gnu/package.json"), "{}");
    await fs.writeFile(join(nodeModulesRoot, directory, "linux-x64-gnu/tsrs"), "original");
  }
  const nativeScope = join(nodeModulesRoot, "@tsrs");
  await fs.symlink("native", nativeScope, "dir");
  const materialPaths = convexApiCompilerMaterialPaths({ nodeModulesRoot });
  assert.ok(materialPaths.includes("@tsrs"));
  const capture = captureConvexApiInstalledMaterial({ nodeModulesRoot, materialPaths });
  await fs.unlink(nativeScope);
  await fs.symlink("replacement", nativeScope, "dir");
  assert.throws(() => verifyConvexApiInstalledMaterial(capture), /changed after capture/u);
  assert.notEqual(
    convexApiInstalledMaterialIdentity({ nodeModulesRoot, materialPaths }).nodeModulesSha256,
    capture.identity.nodeModulesSha256
  );
});
