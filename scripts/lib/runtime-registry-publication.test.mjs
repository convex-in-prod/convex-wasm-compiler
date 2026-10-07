import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  prepareFreshRuntimeRegistryModuleGraphs,
  prepareRuntimeRegistryArtifactPublication,
  publishFreshRuntimeRegistry,
} from "./runtime-registry-publication.mjs";

function fileRecord(name, bytes) {
  return { name, sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length };
}

function artifactFixture(receipt) {
  const payload = Buffer.from("authenticated compiled artifact");
  const artifact = fileRecord("artifact.cwasm", payload);
  const cacheKey = "1".repeat(64);
  const stage = "module-graph-leaf-wasmtime-aot";
  const entry = {
    admission: { payload: { ino: receipt } },
    artifactFile: artifact.name,
    artifactSha256: artifact.sha256,
    artifactSize: artifact.size,
    identity: { source: "fixture" },
    key: cacheKey,
    kind: "convex-wasm-artifact-cache-entry-v5",
    metadata: { target: "fixture" },
    stage,
  };
  const sourceEntryBytes = Buffer.from(`${canonicalJson(entry)}\n`);
  const complete = Buffer.from(`${cacheKey}\n`);
  return {
    complete,
    entry,
    payload,
    sourceEntryBytes,
    record: {
      cacheKey,
      files: [fileRecord("COMPLETE", complete), artifact, fileRecord("entry.json", sourceEntryBytes)],
      kind: "aot",
      role: "leaf",
      sha256: artifact.sha256,
      size: artifact.size,
      stage,
    },
  };
}

test("publication removes only physical receipts and retains exact legacy bytes", () => {
  const first = artifactFixture("first-inode");
  const second = artifactFixture("second-inode");
  const portable = prepareRuntimeRegistryArtifactPublication({ ...first, existingEntryBytes: null });
  const repeat = prepareRuntimeRegistryArtifactPublication({ ...second, existingEntryBytes: null });
  assert.equal(portable.entrySource, repeat.entrySource);
  assert.deepEqual(portable.record, repeat.record);
  assert.equal(Object.hasOwn(JSON.parse(portable.entrySource), "admission"), false);
  assert.deepEqual(portable.sourceFiles, first.record.files);
  const legacy = prepareRuntimeRegistryArtifactPublication({
    ...second, existingEntryBytes: first.sourceEntryBytes,
  });
  assert.equal(legacy.entrySource, first.sourceEntryBytes.toString("utf8"));
  assert.deepEqual(legacy.record, first.record);
  for (const mutate of [
    (entry) => { entry.metadata.target = "different"; },
    (entry) => { entry.identity.source = "different"; },
    (entry) => { entry.artifactSha256 = "0".repeat(64); },
  ]) {
    const changed = structuredClone(first.entry);
    mutate(changed);
    assert.throws(() => prepareRuntimeRegistryArtifactPublication({
      ...second, existingEntryBytes: Buffer.from(`${canonicalJson(changed)}\n`),
    }), /differs from its authenticated source record/u);
  }
  assert.throws(() => prepareRuntimeRegistryArtifactPublication({
    ...first, sourceEntryBytes: second.sourceEntryBytes, existingEntryBytes: null,
  }), /differs from its authenticated source record/u);
});

async function registryFixture(root, receipt) {
  const artifact = artifactFixture(receipt);
  const cacheLayout = { immutable: { artifacts: join(root, "artifacts"), packages: join(root, "packages") } };
  const artifactRoot = join(cacheLayout.immutable.artifacts, artifact.record.stage, artifact.record.cacheKey);
  const graphManifestSha256 = "2".repeat(64);
  const packageRoot = join(cacheLayout.immutable.packages, graphManifestSha256);
  await fs.mkdir(artifactRoot, { recursive: true, mode: 0o700 });
  await fs.mkdir(packageRoot, { recursive: true, mode: 0o700 });
  await Promise.all([
    fs.writeFile(join(artifactRoot, "entry.json"), artifact.sourceEntryBytes, { mode: 0o600 }),
    fs.writeFile(join(artifactRoot, "COMPLETE"), artifact.complete, { mode: 0o600 }),
    fs.writeFile(join(artifactRoot, "artifact.cwasm"), artifact.payload, { mode: 0o600 }),
    fs.writeFile(join(packageRoot, "COMPLETE"), "package\n", { mode: 0o600 }),
  ]);
  const moduleGraphs = await prepareFreshRuntimeRegistryModuleGraphs([{
    cacheLayout,
    record: {
      artifacts: [artifact.record],
      graphManifestSha256,
      package: { files: [fileRecord("COMPLETE", Buffer.from("package\n"))] },
    },
  }]);
  const deploymentBytes = Buffer.from("authenticated deployment bytes");
  const deploymentManifest = {
    ...fileRecord("deployment.json", deploymentBytes), deploymentSha256: "3".repeat(64),
  };
  const generationContent = {
    deploymentManifest, moduleGraphs: moduleGraphs.map(({ record }) => record),
  };
  return {
    artifactRoot,
    input: {
      artifacts: { deploymentManifest, sourcePackageRuntimeContentSha256: "4".repeat(64) },
      deploymentBytes,
      generation: { ...generationContent, generationSha256: fingerprintJson(generationContent) },
      moduleGraphs,
      registryRoot: join(root, "registry"),
    },
  };
}

test("fresh registries from independent caches share generation identity and authenticate published bytes", async () => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-registry-publication-"));
  try {
    const first = await registryFixture(join(root, "first"), "first-inode");
    const second = await registryFixture(join(root, "second"), "second-inode");
    assert.deepEqual(first.input.generation, second.input.generation);
    const published = await publishFreshRuntimeRegistry(first.input);
    const repeated = await publishFreshRuntimeRegistry(second.input);
    assert.equal(published.currentSha256, repeated.currentSha256);
    for (const record of first.input.moduleGraphs[0].record.artifacts) {
      for (const expected of record.files) {
        const bytes = await fs.readFile(join(first.input.registryRoot,
          "module-graph-cache", "immutable", "v6", "artifacts", record.stage, record.cacheKey, expected.name));
        assert.deepEqual(fileRecord(expected.name, bytes), expected);
        if (expected.name === "entry.json") assert.equal(Object.hasOwn(JSON.parse(bytes), "admission"), false);
      }
    }
    assert.equal(Object.hasOwn(JSON.parse(await fs.readFile(join(first.artifactRoot, "entry.json"))), "admission"), true);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("fresh publication rejects source metadata changes and payload corruption after preparation", async () => {
  for (const name of ["entry.json", "artifact.cwasm"]) {
    const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-registry-corruption-"));
    try {
      const value = await registryFixture(root, "original-inode");
      const path = join(value.artifactRoot, name);
      const changed = await fs.readFile(path);
      changed[0] ^= 1;
      await fs.writeFile(path, changed);
      await assert.rejects(() => publishFreshRuntimeRegistry(value.input),
        /differs from its authenticated source record|published file differs/u);
      await assert.rejects(() => fs.stat(value.input.registryRoot), { code: "ENOENT" });
      assert.equal((await fs.readdir(root)).some((name) => name.startsWith(".convex-wasm-registry-")), false);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }
});
