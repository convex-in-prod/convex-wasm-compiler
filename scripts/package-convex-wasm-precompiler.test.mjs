import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { collectPrecompilerSourceIdentity, sourceMetadata } from "./package-convex-wasm-precompiler.mjs";
import { canonicalCompilerPackageJson, sha256Bytes } from "./lib/convex-wasm-compiler-package.mjs";
import { createPrecompilerPackageManifest } from "./lib/convex-wasm-precompiler-package.mjs";
import { writeFixturePrecompilerPackage } from "./test-fixtures/precompiler-package.mjs";

test("vendored code generation is bound to native-package source materials", async (t) => {
  const source = await collectPrecompilerSourceIdentity();
  const metadata = await sourceMetadata(source);
  const root = await fs.mkdtemp(join(tmpdir(), "precompiler-vendored-source-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const fixture = await writeFixturePrecompilerPackage({ root, identitySeed: "vendored-source" });
  const { packageId: originalId, ...payload } = fixture.manifest;
  payload.identities = { ...payload.identities, ...metadata, source };
  const manifest = createPrecompilerPackageManifest(payload);
  assert.notEqual(manifest.packageId, originalId);
  const local = metadata.wasmtime.lockedPackages.find(({ name }) => name === "wasmtime-internal-cranelift");
  assert.match(local.source, /^path\+scripts\/convex-wasm-precompiler\/src\/vendor\/wasmtime-cranelift#[0-9a-f]{64}$/u);

  const changed = structuredClone(payload);
  const lowering = changed.identities.source.materials.find(({ path }) => path.endsWith("wasmtime-cranelift/src/func_environ.rs"));
  lowering.sha256 = sha256Bytes("different lowering");
  changed.identities.source.treeSha256 = sha256Bytes(canonicalCompilerPackageJson(changed.identities.source.materials));
  assert.throws(() => createPrecompilerPackageManifest(changed), /authenticated source tree/u);

  const relabeled = structuredClone(payload);
  relabeled.identities.wasmtime.lockedPackages.find(({ name }) => name === local.name).source = `path+../untracked#${metadata.wasmtime.revision}`;
  assert.throws(() => createPrecompilerPackageManifest(relabeled), /pinned revision/u);
});

test("packaging rejects a local compiler override missing from its source snapshot", async () => {
  const source = await collectPrecompilerSourceIdentity();
  source.materials = source.materials.filter(({ path }) => !path.endsWith("wasmtime-cranelift/src/func_environ.rs"));
  await assert.rejects(sourceMetadata(source), /missing authenticated src\/func_environ.rs/u);
});
