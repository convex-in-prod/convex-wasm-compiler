import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  resolveConvexWasmApplicationBundlerPackageSet,
  resolveConvexWasmApplicationPackageSet,
} from "./convex-wasm-application-package-set.mjs";

async function writePackage(path, name, version) {
  await fs.mkdir(path, { recursive: true });
  await fs.writeFile(join(path, "package.json"), JSON.stringify({ name, version }));
}

test("resolves package identities from each explicit application root", async (context) => {
  const parent = await fs.mkdtemp(join(tmpdir(), "convex-wasm-application-packages-"));
  context.after(() => fs.rm(parent, { force: true, recursive: true }));
  for (const [name, suffix] of [["first", "1"], ["second", "2"]]) {
    const root = join(parent, name);
    await writePackage(root, name, `1.0.${suffix}`);
    await writePackage(join(root, "node_modules", "convex"), "convex", `1.45.${suffix}`);
    await writePackage(join(root, "node_modules", "esbuild"), "esbuild", `0.27.${suffix}`);
    await writePackage(join(root, "node_modules", "typescript"), "typescript", `6.0.${suffix}`);
  }
  await writePackage(
    join(parent, "first", "node_modules", "convex", "node_modules", "esbuild"),
    "esbuild",
    "0.28.1"
  );
  const copyRoot = join(parent, "first-copy");
  await writePackage(copyRoot, "first", "1.0.1");
  await writePackage(join(copyRoot, "node_modules", "convex"), "convex", "1.45.1");
  await writePackage(join(copyRoot, "node_modules", "esbuild"), "esbuild", "0.27.1");
  await writePackage(join(copyRoot, "node_modules", "typescript"), "typescript", "6.0.1");
  await writePackage(
    join(copyRoot, "node_modules", "convex", "node_modules", "esbuild"),
    "esbuild",
    "0.28.1"
  );
  const first = resolveConvexWasmApplicationPackageSet(join(parent, "first"));
  const second = resolveConvexWasmApplicationPackageSet(join(parent, "second"));
  assert.equal(first.convex.version, "1.45.1");
  assert.equal(second.convex.version, "1.45.2");
  assert.equal(first.esbuild.version, "0.28.1");
  assert.equal(second.esbuild.version, "0.27.2");
  assert.equal(second.typescript.version, "6.0.2");
  assert.notEqual(first.convex.sha256, second.convex.sha256);
  assert.notEqual(first.applicationManifestSha256, second.applicationManifestSha256);
  assert.deepEqual(first, resolveConvexWasmApplicationPackageSet(copyRoot));
  assert.deepEqual(
    resolveConvexWasmApplicationBundlerPackageSet(join(parent, "first")),
    {
      applicationManifestSha256: first.applicationManifestSha256,
      convex: first.convex,
      esbuild: first.esbuild,
    }
  );
  assert.equal(Object.isFrozen(first.convex), true);
});

test("source graph package resolution does not require TypeScript", async (context) => {
  const parent = await fs.mkdtemp(join(tmpdir(), "convex-wasm-application-packages-"));
  context.after(() => fs.rm(parent, { force: true, recursive: true }));
  await writePackage(parent, "fixture", "1.0.0");
  await writePackage(join(parent, "node_modules", "convex"), "convex", "1.45.1");
  await writePackage(join(parent, "node_modules", "esbuild"), "esbuild", "0.27.0");
  assert.equal(resolveConvexWasmApplicationBundlerPackageSet(parent).convex.version, "1.45.1");
  assert.throws(
    () => resolveConvexWasmApplicationPackageSet(parent),
    /typescript package is unavailable from the application root/u
  );
});

test("rejects a package identity that disagrees with its resolved package name", async (context) => {
  const parent = await fs.mkdtemp(join(tmpdir(), "convex-wasm-application-packages-"));
  context.after(() => fs.rm(parent, { force: true, recursive: true }));
  const root = join(parent, "invalid");
  await writePackage(root, "fixture", "1.0.0");
  await writePackage(join(root, "node_modules", "convex"), "unexpected", "1.45.0");
  assert.throws(() => resolveConvexWasmApplicationPackageSet(root), /invalid identity/u);
  assert.throws(
    () => resolveConvexWasmApplicationPackageSet(`${root}/..`),
    /application root must be a normalized absolute path/u
  );
  const missingRoot = join(parent, "missing");
  await writePackage(missingRoot, "missing", "1.0.0");
  assert.throws(
    () => resolveConvexWasmApplicationPackageSet(missingRoot),
    /convex package is unavailable from the application root/u
  );
  assert.throws(
    () => resolveConvexWasmApplicationPackageSet(join(parent, "absent")),
    /application root has no package manifest/u
  );
  const invalidUtf8Root = join(parent, "invalid-utf8");
  await fs.mkdir(invalidUtf8Root);
  await fs.writeFile(join(invalidUtf8Root, "package.json"), Buffer.from([0xff]));
  assert.throws(
    () => resolveConvexWasmApplicationPackageSet(invalidUtf8Root),
    /application package manifest is invalid UTF-8 JSON/u
  );
});
