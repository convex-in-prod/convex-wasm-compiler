import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-stage.mjs";
import { prepareRuntimeRegistryArtifactPublication } from "./runtime-registry-publication.mjs";
import { prepareRuntimeRegistrySnapshotMetadata, snapshotMetadataKind, validateSnapshotMetadata } from "./convex-wasm-snapshot-metadata.mjs";

const core = { sha256: "a".repeat(64), size: 8 };
const supported = { kind: snapshotMetadataKind, coreSha256: core.sha256, coreSize: core.size,
  state: { kind: "supported", globals: ["counter"], stackLimits: true } };

test("snapshot metadata binds the exact Core and restoration version", () => {
  assert.equal(validateSnapshotMetadata(supported, core), supported);
  for (const changed of [
    { ...supported, kind: "future-version" },
    { ...supported, coreSha256: "b".repeat(64) },
    { ...supported, coreSize: 9 },
    { ...supported, state: { ...supported.state, globals: ["counter", "counter"] } },
    { ...supported, state: { ...supported.state, stackLimits: null } },
    { ...supported, state: { kind: "unsupported", reason: "" } },
    { ...supported, extra: true },
  ]) assert.throws(() => validateSnapshotMetadata(changed, core));
  assert.throws(() => validateSnapshotMetadata(null, core));
  assert.equal(validateSnapshotMetadata({ ...supported, state: { kind: "unsupported", reason: "hidden mutable state" } }, core).state.kind, "unsupported");
});

test("snapshot derivations survive control-key changes and publish without changing artifact files", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-snapshot-metadata-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({ repositoryRoot: root, cacheRoot: root, buildId: "snapshot-test", scope: "isolated-test" });
  await fs.mkdir(cacheLayout.immutable.artifacts, { recursive: true, mode: 0o700 });
  await ensureArtifactStage({
    cacheLayout, cacheRoot: root, stage: "module-snapshot-metadata", extension: "json",
    identity: { kind: snapshotMetadataKind, coreSha256: core.sha256, coreSize: core.size },
    maxArtifactBytes: 16 * 1024 * 1024,
    build: async (workPath) => {
      const outputPath = join(workPath, "snapshot.json");
      await fs.writeFile(outputPath, `${canonicalJson(supported)}\n`);
      return { metadata: null, outputPath, timing: null };
    },
  });
  const source = { artifactFile: "artifact.wasm", artifactSha256: core.sha256, artifactSize: core.size,
    key: "1".repeat(64), kind: "convex-wasm-artifact-cache-entry-v5", stage: "module-graph-base-core-wasm" };
  const bytes = Buffer.from(`${canonicalJson(source)}\n`);
  const record = { cacheKey: source.key, files: [{ name: "entry.json", sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length }],
    kind: "coreWasm", role: "base", ...core, stage: source.stage };
  const graph = { cacheLayout, record: { artifacts: [record] } };
  // A cache hit needs neither Core payloads nor a native package. Changing a
  // control key or role alone must not repeat static inspection.
  const [first, second] = await prepareRuntimeRegistrySnapshotMetadata([graph, {
    ...graph, record: { artifacts: [{ ...record, cacheKey: "2".repeat(64), role: "leaf" }] },
  }], { precompilerPackageDirectory: join(root, "absent-package"), concurrency: 2 });
  assert.deepEqual(first.record.artifacts[0].snapshotMetadata, supported);
  assert.equal(first.record.artifacts[0].snapshotMetadata, second.record.artifacts[0].snapshotMetadata);
  const published = prepareRuntimeRegistryArtifactPublication({ record: first.record.artifacts[0], sourceEntryBytes: bytes, existingEntryBytes: null });
  assert.equal(published.entrySource, bytes.toString());
  assert.deepEqual(published.record.files, record.files);
  assert.deepEqual(published.record.snapshotMetadata, supported);
  await assert.rejects(prepareRuntimeRegistrySnapshotMetadata([{ ...graph, record: { artifacts: [{ ...record, sha256: "b".repeat(64) }] } }],
    { precompilerPackageDirectory: join(root, "absent-package"), concurrency: 1 }), /ENOENT/);

  const selectionPath = join(root, "selection.json");
  await fs.writeFile(selectionPath, "{}\n");
  const previousPackage = process.env.CONVEX_WASM_PRECOMPILER_PACKAGE;
  process.env.CONVEX_WASM_PRECOMPILER_PACKAGE = join(root, "unrelated-environment-package");
  try {
    await assert.rejects(prepareRuntimeRegistrySnapshotMetadata([{ ...graph,
      record: { artifacts: [{ ...record, sha256: "b".repeat(64) }] },
    }], { nativeReleaseSelectionPath: selectionPath, concurrency: 1 }),
    /native release selection has unexpected fields/);
  } finally {
    if (previousPackage === undefined) delete process.env.CONVEX_WASM_PRECOMPILER_PACKAGE;
    else process.env.CONVEX_WASM_PRECOMPILER_PACKAGE = previousPackage;
  }
});
