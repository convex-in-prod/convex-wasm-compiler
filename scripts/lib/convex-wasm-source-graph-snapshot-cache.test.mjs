import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmSourceGraphSnapshotCachePath,
  convexWasmSourceGraphSnapshotCacheIndexPath,
  convexWasmSourceGraphSnapshotScopeSha256,
  loadConvexWasmSourceGraphSnapshotForLookup,
  loadConvexWasmSourceGraphSnapshotByTree,
  loadConvexWasmSourceGraphSnapshot,
  probeConvexWasmSourceGraphSnapshotForLookup,
  publishConvexWasmSourceGraphSnapshot,
} from "./convex-wasm-source-graph-snapshot-cache.mjs";

const digest = (character) => character.repeat(64);

function snapshot() {
  const payload = {
    authority: {
      entries: [{ mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 }],
      kind: "convex-wasm-git-source-snapshot-v1",
      objectFormat: "sha1",
      pathspecs: ["convex"],
      treeOid: "1".repeat(40),
      untrackedPaths: [],
      unstagedPaths: [],
    },
    dependencyGraphs: [
      { entryPath: "convex/a.ts", inputPaths: ["convex/a.ts"], sha256: digest("b") },
    ],
    identity: {
      assumptions: { format: "esm" },
      contextReusePolicy: { entries: [] },
      dependencyAdapter: { kind: "fixture-dependency-adapter-v1" },
      registrationAdapter: { kind: "fixture-registration-adapter-v1" },
      toolchain: { convex: "fixture-convex", esbuild: "fixture-esbuild" },
    },
    inputs: {
      "convex/a.ts": { imports: [], sha256: digest("c"), size: 1, virtual: false },
    },
    kind: "convex-wasm-source-graph-snapshot-v2",
    lookupIdentity: {
      assumptions: { format: "esm" },
      bundleEntryPaths: ["convex/a.ts"],
      bundlerMaterials: { "bundler.js": { sha256: digest("e") } },
      config: { sha256: digest("f"), size: 1 },
      contextReusePolicy: { entries: [] },
      dependencyAdapterDescriptor: { kind: "fixture-dependency-adapter-descriptor-v1" },
      deploymentConfigurationEntryPath: null,
      effectExecutionMode: "blocking-fiber",
      kind: "convex-wasm-source-graph-snapshot-lookup-identity-v2",
      nodeEntryPaths: [],
      registrationAdapter: { kind: "fixture-registration-adapter-v1" },
      toolchain: { convex: "fixture-convex", esbuild: "fixture-esbuild" },
    },
    schemaVersion: 2,
    session: {
      activeDependencyAdapters: { kind: "fixture-active-dependency-adapters-v1" },
      authoritativeInputMaterials: {},
      bundleModulesByPath: {},
      deploymentConfigurationInputMaterials: {},
      deploymentConfigurationModulesByPath: {},
      deploymentOutputModulesByPath: {},
      metafile: { inputs: {}, outputs: {} },
      nodeInputMaterials: {},
      nodeModulesByPath: {},
    },
  };
  return { ...payload, sha256: fingerprintJson(payload) };
}

function reauthenticateSnapshot(value, mutate) {
  const payload = structuredClone(value);
  delete payload.sha256;
  mutate(payload);
  return { ...payload, sha256: fingerprintJson(payload) };
}

test("publishes and loads an immutable authenticated graph snapshot", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const value = snapshot();
  const path = await publishConvexWasmSourceGraphSnapshot({
    cacheDirectory: directory,
    snapshot: value,
  });
  assert.equal(await fs.readFile(path, "utf8"), `${canonicalJson(value)}\n`);
  assert.deepEqual(
    await loadConvexWasmSourceGraphSnapshot({
      cacheDirectory: directory,
      snapshotSha256: value.sha256,
    }),
    value
  );
  const scopeSha256 = convexWasmSourceGraphSnapshotScopeSha256(value);
  assert.equal(scopeSha256.length, 64);
  const changedTree = reauthenticateSnapshot(value, (payload) => {
    payload.authority.treeOid = "2".repeat(40);
  });
  assert.equal(convexWasmSourceGraphSnapshotScopeSha256(changedTree), scopeSha256);
  assert.notEqual(
    convexWasmSourceGraphSnapshotScopeSha256(
      reauthenticateSnapshot(value, (payload) => {
        payload.identity.assumptions = { format: "cjs" };
        payload.lookupIdentity.assumptions = { format: "cjs" };
      })
    ),
    scopeSha256
  );
  assert.notEqual(
    convexWasmSourceGraphSnapshotScopeSha256(
      reauthenticateSnapshot(value, (payload) => {
        payload.dependencyGraphs[0].entryPath = "convex/b.ts";
        payload.dependencyGraphs[0].inputPaths = ["convex/a.ts"];
      })
    ),
    scopeSha256
  );
  assert.deepEqual(
    await loadConvexWasmSourceGraphSnapshotByTree({
      cacheDirectory: directory,
      scopeSha256,
      treeOid: value.authority.treeOid,
    }),
    value
  );
  assert.deepEqual(
    await loadConvexWasmSourceGraphSnapshotForLookup({
      cacheDirectory: directory,
      entryPaths: value.dependencyGraphs.map(({ entryPath }) => entryPath),
      gitSourceSnapshot: value.authority,
      lookupIdentity: value.lookupIdentity,
    }),
    value
  );
  const reference = await probeConvexWasmSourceGraphSnapshotForLookup({
    cacheDirectory: directory,
    entryPaths: value.dependencyGraphs.map(({ entryPath }) => entryPath),
    gitSourceSnapshot: value.authority,
    lookupIdentity: value.lookupIdentity,
  });
  assert.equal(reference.snapshotSha256, value.sha256);
  assert.equal(reference.scopeSha256, scopeSha256);
  assert.equal(reference.treeOid, value.authority.treeOid);
  assert.equal(reference.path, path);
  assert.equal(
    (
      await fs.readFile(
        convexWasmSourceGraphSnapshotCacheIndexPath(
          directory,
          scopeSha256,
          value.authority.treeOid
        ),
        "utf8"
      )
    ).includes(value.sha256),
    true
  );
  assert.equal(
    await loadConvexWasmSourceGraphSnapshot({
      cacheDirectory: directory,
      snapshotSha256: digest("d"),
    }),
    undefined
  );
});

test("creates snapshot-cache directories under a restrictive umask", async (t) => {
  const parent = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-umask-parent-"));
  const directory = join(parent, "missing", "cache");
  t.after(() => fs.rm(parent, { force: true, recursive: true }));
  const value = snapshot();
  const previousUmask = process.umask(0o777);
  try {
    await publishConvexWasmSourceGraphSnapshot({ cacheDirectory: directory, snapshot: value });
  } finally {
    process.umask(previousUmask);
  }
  assert.equal((await fs.stat(parent)).mode & 0o777, 0o700);
  assert.equal((await fs.stat(join(parent, "missing"))).mode & 0o777, 0o700);
  assert.equal((await fs.stat(directory)).mode & 0o777, 0o700);
  assert.equal((await fs.stat(join(directory, "v1"))).mode & 0o777, 0o700);
  assert.equal((await fs.stat(join(directory, "v1", `${value.sha256}.json`))).mode & 0o777, 0o600);
});

test("concurrent publication is immutable and tampering fails closed", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-race-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const value = snapshot();
  const paths = await Promise.all(
    Array.from({ length: 4 }, () =>
      publishConvexWasmSourceGraphSnapshot({ cacheDirectory: directory, snapshot: value })
    )
  );
  assert.deepEqual(new Set(paths).size, 1);
  const path = paths[0];
  const tampered = { ...value, kind: "convex-wasm-source-graph-snapshot-tampered-v1" };
  await fs.writeFile(path, `${JSON.stringify(tampered)}\n`, { mode: 0o600 });
  assert.equal(
    (
      await probeConvexWasmSourceGraphSnapshotForLookup({
        cacheDirectory: directory,
        entryPaths: value.dependencyGraphs.map(({ entryPath }) => entryPath),
        gitSourceSnapshot: value.authority,
        lookupIdentity: value.lookupIdentity,
      })
    ).snapshotSha256,
    value.sha256
  );
  await assert.rejects(
    loadConvexWasmSourceGraphSnapshot({
      cacheDirectory: directory,
      snapshotSha256: value.sha256,
    }),
    /canonical JSON|source graph snapshot kind/u
  );
});

test("projection probes fail closed when their indexed snapshot is missing", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-missing-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const value = snapshot();
  const path = await publishConvexWasmSourceGraphSnapshot({
    cacheDirectory: directory,
    snapshot: value,
  });
  await fs.rm(path);
  await assert.rejects(
    probeConvexWasmSourceGraphSnapshotForLookup({
      cacheDirectory: directory,
      entryPaths: value.dependencyGraphs.map(({ entryPath }) => entryPath),
      gitSourceSnapshot: value.authority,
      lookupIdentity: value.lookupIdentity,
    }),
    /index points to a missing snapshot/u
  );
});

test("rejects a tampered graph snapshot index", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-index-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const value = snapshot();
  await publishConvexWasmSourceGraphSnapshot({ cacheDirectory: directory, snapshot: value });
  const scopeSha256 = convexWasmSourceGraphSnapshotScopeSha256(value);
  const indexPath = convexWasmSourceGraphSnapshotCacheIndexPath(
    directory,
    scopeSha256,
    value.authority.treeOid
  );
  await fs.writeFile(indexPath, "{}\n", { mode: 0o600 });
  await assert.rejects(
    loadConvexWasmSourceGraphSnapshotByTree({
      cacheDirectory: directory,
      scopeSha256,
      treeOid: value.authority.treeOid,
    }),
    /snapshot cache index entry has an unexpected shape/u
  );
});

test("rejects a non-private snapshot cache file", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-mode-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const value = snapshot();
  const path = await publishConvexWasmSourceGraphSnapshot({
    cacheDirectory: directory,
    snapshot: value,
  });
  await fs.chmod(path, 0o644);
  await assert.rejects(
    loadConvexWasmSourceGraphSnapshot({
      cacheDirectory: directory,
      snapshotSha256: value.sha256,
    }),
    /mode 0600/u
  );
});

test("rejects a symlinked index root before creating a scope outside the cache", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-link-"));
  const outside = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-graph-cache-outside-"));
  t.after(() =>
    Promise.all([
      fs.rm(directory, { force: true, recursive: true }),
      fs.rm(outside, { force: true, recursive: true }),
    ])
  );
  await fs.mkdir(join(directory, "v1"), { mode: 0o700 });
  await fs.symlink(outside, join(directory, "v1", "index"));
  const value = snapshot();
  const scopeSha256 = convexWasmSourceGraphSnapshotScopeSha256(value);

  await assert.rejects(
    publishConvexWasmSourceGraphSnapshot({ cacheDirectory: directory, snapshot: value }),
    /non-symlink directory/u
  );
  await assert.rejects(fs.access(join(outside, scopeSha256)), { code: "ENOENT" });
  await assert.rejects(fs.access(convexWasmSourceGraphSnapshotCachePath(directory, value.sha256)), {
    code: "ENOENT",
  });
});
