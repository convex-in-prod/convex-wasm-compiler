import assert from "node:assert/strict";
import { existsSync, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { acquireNativeReleaseFromSelectionFile } from "../acquire-convex-wasm-native-release.mjs";
import { createNativePackageSelection } from "../create-native-package-selection.mjs";
import { canonicalCompilerPackageJson, sha256Bytes } from "./convex-wasm-compiler-package.mjs";
import {
  nativeReleaseTargets,
  validateNativeReleaseSelection,
} from "./convex-wasm-native-release-selection.mjs";
import { writeFixtureCompilerPackage } from "../test-fixtures/native-package/compiler-package-fixture.mjs";
import { writeFixturePrecompilerPackage } from "../test-fixtures/native-package/precompiler-package-fixture.mjs";

async function releaseFixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-release-selection-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const assetsRoot = join(root, "assets");
  await fs.mkdir(assetsRoot);
  const binarySourcePath = await fs.realpath(
    process.platform === "linux" && existsSync("/usr/bin/true") ? "/usr/bin/true" : process.execPath
  );
  const [compiler, precompiler] = await Promise.all([
    writeFixtureCompilerPackage({ root: join(root, "compiler"), binarySourcePath }),
    writeFixturePrecompilerPackage({
      root: join(root, "precompiler"),
      binaryPath: binarySourcePath,
      identitySeed: "release-selection",
    }),
  ]);
  const runtime = `${process.platform}-${process.arch}`;
  const assetBytes = new Map();
  for (const [targetRuntime, targetTriple] of Object.entries(nativeReleaseTargets)) {
    const entries = {};
    for (const kind of ["compiler", "precompiler"]) {
      const fixturePackage = kind === "compiler" ? compiler : precompiler;
      const packageId =
        targetRuntime === runtime
          ? fixturePackage.manifest.packageId
          : sha256Bytes(`${targetRuntime}:${kind}`);
      const name = `${targetTriple}-${kind}-${packageId}`;
      const manifestBytes =
        targetRuntime === runtime
          ? await fs.readFile(fixturePackage.manifestPath)
          : Buffer.from("fixture manifest");
      const binaryBytes =
        targetRuntime === runtime
          ? await fs.readFile(fixturePackage.binaryPath)
          : Buffer.from("fixture binary");
      await Promise.all([
        fs.writeFile(join(assetsRoot, name), binaryBytes),
        fs.writeFile(join(assetsRoot, `${name}-manifest.json`), manifestBytes),
      ]);
      assetBytes.set(name, binaryBytes);
      assetBytes.set(`${name}-manifest.json`, manifestBytes);
      entries[kind] = {
        packageId,
        path: `packages/${kind}/${targetTriple}/${packageId}`,
      };
    }
    await fs.writeFile(
      join(assetsRoot, `${targetTriple}-index.json`),
      `${canonicalCompilerPackageJson({
        ...entries,
        evidenceSha256: "b".repeat(64),
        kind: "convex-wasm-native-release",
        schemaVersion: 1,
        targetTriple,
      })}\n`
    );
  }
  return {
    assetBytes,
    assetsRoot,
    compiler,
    precompiler,
    root,
    runtime,
    selectionPath: join(root, "native-package-selection.json"),
  };
}

test("release selection names all host assets and installs both verified packages", async (t) => {
  const f = await releaseFixture(t);
  const selection = await createNativePackageSelection({
    assetsRoot: f.assetsRoot,
    output: f.selectionPath,
    repository: "example/compiler",
    tag: "v1.2.3",
  });
  assert.deepEqual(validateNativeReleaseSelection(selection), selection);
  assert.equal(
    await fs.readFile(f.selectionPath, "utf8"),
    `${canonicalCompilerPackageJson(selection)}\n`
  );
  for (const [runtime, targetTriple] of Object.entries(nativeReleaseTargets)) {
    for (const kind of ["compiler", "precompiler"]) {
      const reference = selection.packages[runtime][kind];
      assert.equal(reference.targetTriple, targetTriple);
      assert.match(
        reference.download.binaryUrl,
        new RegExp(`^https://github\\.com/example/compiler/releases/download/v1\\.2\\.3/${targetTriple}-${kind}-`, "u")
      );
    }
  }
  if (!Object.hasOwn(nativeReleaseTargets, f.runtime)) {
    await assert.rejects(
      acquireNativeReleaseFromSelectionFile({
        selectionPath: f.selectionPath,
        cacheRoot: join(f.root, "cache"),
      }),
      /unavailable/u
    );
    return;
  }
  const requests = [];
  t.mock.method(globalThis, "fetch", async (url, { signal }) => {
    signal.throwIfAborted();
    requests.push(url);
    const name = new URL(url).pathname.split("/").at(-1);
    const bytes = f.assetBytes.get(name);
    assert.ok(bytes);
    return new Response(bytes);
  });
  const cacheRoot = join(f.root, "cache");
  const installed = await acquireNativeReleaseFromSelectionFile({
    selectionPath: f.selectionPath,
    cacheRoot,
  });
  assert.equal(installed.compiler.manifest.packageId, f.compiler.manifest.packageId);
  assert.equal(installed.precompiler.manifest.packageId, f.precompiler.manifest.packageId);
  assert.deepEqual(await fs.readFile(installed.compiler.binaryPath), await fs.readFile(f.compiler.binaryPath));
  assert.deepEqual(
    await fs.readFile(installed.precompiler.binaryPath),
    await fs.readFile(f.precompiler.binaryPath)
  );
  assert.equal(requests.length, 4);
  const cached = await acquireNativeReleaseFromSelectionFile({
    selectionPath: f.selectionPath,
    cacheRoot,
  });
  assert.equal(cached.compiler.binaryPath, installed.compiler.binaryPath);
  assert.equal(cached.precompiler.binaryPath, installed.precompiler.binaryPath);
  assert.equal(requests.length, 4);
});

test("selection generation rejects missing assets and index target drift", async (t) => {
  const f = await releaseFixture(t);
  const targetTriple = nativeReleaseTargets["linux-x64"];
  const indexPath = join(f.assetsRoot, `${targetTriple}-index.json`);
  const index = JSON.parse(await fs.readFile(indexPath, "utf8"));
  index.targetTriple = "aarch64-apple-darwin";
  await fs.writeFile(indexPath, `${canonicalCompilerPackageJson(index)}\n`);
  await assert.rejects(
    createNativePackageSelection({
      assetsRoot: f.assetsRoot,
      output: f.selectionPath,
      repository: "example/compiler",
      tag: "v1.2.3",
    }),
    /invalid identity/u
  );
  index.targetTriple = targetTriple;
  await fs.writeFile(indexPath, `${canonicalCompilerPackageJson(index)}\n`);
  await fs.rm(join(f.assetsRoot, `${targetTriple}-compiler-${index.compiler.packageId}`));
  await assert.rejects(
    createNativePackageSelection({
      assetsRoot: f.assetsRoot,
      output: f.selectionPath,
      repository: "example/compiler",
      tag: "v1.2.3",
    }),
    /ENOENT/u
  );
  assert.equal(existsSync(f.selectionPath), false);
});

test("selection validation rejects cross-platform package identities", () => {
  const reference = (targetTriple) => ({ packageId: "a".repeat(64), targetTriple });
  const packages = Object.fromEntries(
    Object.entries(nativeReleaseTargets).map(([runtime, targetTriple]) => [
      runtime,
      { compiler: reference(targetTriple), precompiler: reference(targetTriple) },
    ])
  );
  const selection = { kind: "convex-wasm-native-package-selection", packages };
  assert.doesNotThrow(() => validateNativeReleaseSelection(selection));
  packages["linux-x64"].compiler.targetTriple = "aarch64-apple-darwin";
  assert.throws(() => validateNativeReleaseSelection(selection), /does not match its platform/u);
});
