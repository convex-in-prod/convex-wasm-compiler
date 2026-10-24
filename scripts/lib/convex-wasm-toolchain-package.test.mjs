import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { packagedGate, sealToolchainPackage, toolchainEnvironment, verifyToolchainPackage } from "./convex-wasm-toolchain-package.mjs";

test("sealed toolchain relocates, seeds an external cache and rejects altered material", async t => {
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "toolchain-package-")));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const built = join(root, "build");
  await fs.mkdir(join(built, "gate/emsdk/upstream/emscripten/cache"), { recursive: true });
  await fs.writeFile(join(built, "gate/emsdk/upstream/emscripten/cache/seed"), "system library");
  const manifest = await sealToolchainPackage(built, { version: "1.0.0",
    nativePackages: { compiler: "native/compiler/id", precompiler: "native/precompiler/id" } });
  const relocated = join(root, "relocated toolchain");
  await fs.rename(built, relocated);
  assert.equal((await verifyToolchainPackage(relocated)).packageId, manifest.packageId);
  assert.equal((await packagedGate(join(relocated, "gate"))).root, relocated);
  const environments = await Promise.all([1, 2].map(() => toolchainEnvironment(relocated, manifest, join(root, "cache"))));
  assert.deepEqual(environments[0], environments[1]);
  // Relocation changes Emscripten's sanity identity. Its erase() keeps the cache
  // directory but removes its contents before rebuilding the required libraries.
  for (const name of await fs.readdir(environments[0].EM_CACHE)) {
    await fs.rm(join(environments[0].EM_CACHE, name), { recursive: true });
  }
  await fs.writeFile(join(environments[0].EM_CACHE, "generated-library"), "generated");
  assert.deepEqual(await toolchainEnvironment(relocated, manifest, join(root, "cache")), environments[0]);
  assert.deepEqual(await fs.readdir(environments[0].EM_CACHE), ["generated-library"]);
  await verifyToolchainPackage(relocated);
  const seed = join(relocated, "gate/emsdk/upstream/emscripten/cache/seed");
  await fs.writeFile(seed, "altered");
  await assert.rejects(verifyToolchainPackage(relocated), /differs/);
  await fs.writeFile(seed, "system library");
  await fs.writeFile(join(relocated, "injected-tool"), "unexpected");
  await assert.rejects(verifyToolchainPackage(relocated), /inventory changed/);
  await fs.rm(join(relocated, "injected-tool"));
  await fs.rm(seed);
  await fs.symlink(join(environments[0].EM_CACHE, "seed"), seed);
  await assert.rejects(verifyToolchainPackage(relocated), /link or special file/);
});
