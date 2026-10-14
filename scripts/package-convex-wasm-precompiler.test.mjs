import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  collectPrecompilerSourceIdentity,
  sourceMetadata,
  wasmtimeIdentityFromLockedPackages,
} from "./package-convex-wasm-precompiler.mjs";
import { canonicalCompilerPackageJson, sha256Bytes } from "./lib/convex-wasm-compiler-package.mjs";
import { createPrecompilerPackageManifest } from "./lib/convex-wasm-precompiler-package.mjs";
import { writeFixturePrecompilerPackage } from "./test-fixtures/precompiler-package.mjs";

test("precompiler source binds one shared Wasmtime revision", async (t) => {
  const source = await collectPrecompilerSourceIdentity();
  const metadata = await sourceMetadata(source);
  const root = await fs.mkdtemp(join(tmpdir(), "precompiler-shared-source-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fixture = await writeFixturePrecompilerPackage({ root, identitySeed: "shared-source" });
  const { packageId: originalId, ...payload } = fixture.manifest;
  payload.identities = { ...payload.identities, ...metadata, source };
  const manifest = createPrecompilerPackageManifest(payload);
  assert.notEqual(manifest.packageId, originalId);
  const expected = `git+${metadata.wasmtime.git}?rev=${metadata.wasmtime.revision}#${metadata.wasmtime.revision}`;
  assert(metadata.wasmtime.lockedPackages.some(({ name }) => name === "wasmtime-internal-cranelift"));
  assert(metadata.wasmtime.lockedPackages.every(({ source }) => source === expected));

  const relabeled = structuredClone(payload);
  relabeled.identities.wasmtime.lockedPackages[0].source = expected.replaceAll(metadata.wasmtime.revision, "0".repeat(40));
  assert.throws(() => createPrecompilerPackageManifest(relabeled), /pinned revision/u);
  const staleSource = structuredClone(source);
  staleSource.materials.find(({ path }) => path.endsWith("Cargo.lock")).sha256 = sha256Bytes("changed lock");
  await assert.rejects(sourceMetadata(staleSource), /changed after the source snapshot/u);
});

test("native target identities accept distinct revisions but reject mixed sources", () => {
  for (const repository of ["bytecodealliance", "convex-in-prod"]) {
    for (const revision of ["1".repeat(40), "2".repeat(40)]) {
      const source = `git+https://github.com/${repository}/wasmtime?rev=${revision}#${revision}`;
      const packages = ["wasmtime", "wasmtime-internal-cranelift"].map((name) => ({ name, source, version: "0.0.0" }));
      assert.equal(wasmtimeIdentityFromLockedPackages(packages).revision, revision);
      packages[1].source = source.replaceAll(revision, "3".repeat(40));
      assert.throws(() => wasmtimeIdentityFromLockedPackages(packages), /one exact revision/u);
    }
  }
  assert.throws(() => wasmtimeIdentityFromLockedPackages([{
    name: "wasmtime", version: "0.0.0",
    source: `git+https://github.com/example/wasmtime?rev=${"1".repeat(40)}#${"1".repeat(40)}`,
  }]), /requested revision/u);
});

test("legacy vendored packages retain authenticated source validation", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "precompiler-legacy-source-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fixture = await writeFixturePrecompilerPackage({ root, identitySeed: "legacy-source" });
  const { packageId, ...payload } = fixture.manifest;
  const directory = "scripts/convex-wasm-precompiler/src/vendor/wasmtime-cranelift";
  const materials = ["Cargo.toml", "src/func_environ.rs", "src/lib.rs"].map((path) => ({
    path: `${directory}/${path}`, sha256: sha256Bytes(path), size: Buffer.byteLength(path),
  }));
  payload.identities.source.materials.push(...materials);
  payload.identities.source.materials.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  payload.identities.source.treeSha256 = sha256Bytes(canonicalCompilerPackageJson(payload.identities.source.materials));
  payload.identities.wasmtime.lockedPackages.push({
    name: "wasmtime-internal-cranelift", version: "41.0.1",
    source: `path+${directory}#${sha256Bytes(canonicalCompilerPackageJson(materials))}`,
  });
  assert.notEqual(createPrecompilerPackageManifest(payload).packageId, packageId);
  const changed = structuredClone(payload);
  changed.identities.source.materials.find(({ path }) => path.endsWith("func_environ.rs")).sha256 = sha256Bytes("different lowering");
  changed.identities.source.treeSha256 = sha256Bytes(canonicalCompilerPackageJson(changed.identities.source.materials));
  assert.throws(() => createPrecompilerPackageManifest(changed), /authenticated source tree/u);
});
