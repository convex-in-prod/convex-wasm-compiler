#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { deriveConvexWasmCacheLayout } from "./lib/convex-wasm-cache-layout.mjs";
import { maintainConvexWasmCache, measureConvexWasmCacheOccupancy } from "./lib/convex-wasm-cache-retention.mjs";
import { currentConvexWasmRetentionPhase } from "./lib/convex-wasm-cache-retention-immutable.mjs";
import { planStaticHermesRetainedLayout, publishStaticHermesRetainedLayout } from "./lib/convex-wasm-static-hermes-layout-cache.mjs";
import {
  ageTree, materializeModuleGraphPackageFixture, writeCBundleArtifact,
  writeCohortCapsuleFixture, writeCompilerOutputFixture, writeGenericArtifact,
  writeLegacyDeploymentResultCertificate,
} from "./test-fixtures/cache-retention.mjs";

const nowMs = 2_000_000_000_000;

// Every arm creates its own inode graph. Linking or copying one arm's cache into another
// would couple unlink counts, physical witnesses, or access timestamps across measurements.
async function prepare(root, variant, waves) {
  await fs.mkdir(root, { mode: 0o700 });
  const cacheRoot = join(root, "cache");
  const cacheLayout = deriveConvexWasmCacheLayout({ cacheRoot, repositoryRoot: root, buildId: "benchmark", scope: "isolated-test" });
  const metadataHeavy = variant === "metadata";
  const retainedCount = metadataHeavy ? 384 : 768;
  const removedCount = metadataHeavy ? 24 : 128;
  let sharedPayload;
  for (let index = 0; index < retainedCount + removedCount; index += 1) {
    const artifact = await writeGenericArtifact({
      cacheLayout, extension: "wasm", stage: "benchmark-payload",
      identity: { seed: 20261029, index },
      metadata: { padding: "m".repeat(metadataHeavy ? 32 * 1024 : 16) },
      payload: Buffer.alloc(metadataHeavy ? 1024 : 64 * 1024, 37),
    });
    const payload = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key, artifact.entry.artifactFile);
    if (!metadataHeavy) {
      if (sharedPayload === undefined) sharedPayload = payload;
      else {
        await fs.unlink(payload);
        await fs.link(sharedPayload, payload);
      }
    }
  }
  const graph = await materializeModuleGraphPackageFixture({ root, cacheRoot, layout: () => cacheLayout });
  await writeLegacyDeploymentResultCertificate(graph);
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const generatedCIdentity = {
    exportedUnitName: "this_unit", flags: ["-Xemit-c-bundle", "-Xemit-c-layout"],
    generatedSource: { sha256: "a".repeat(64), size: 10 },
    semanticEnvironment: { LANG: "C" }, staticHermes: { materials: "b".repeat(64) },
    unitRole: "untyped-official-chunk",
  };
  const selection = await planStaticHermesRetainedLayout({ cacheLayout, generatedCIdentity, stage: "generated-c" });
  const bundle = await writeCBundleArtifact({ cacheLayout, stage: "generated-c", identity: selection.identity,
    retainedLayout: '{"kind":"static-hermes-c-layout-v1","unitName":"this_unit"}\n' });
  await publishStaticHermesRetainedLayout({ cacheLayout, generatedCEntry: { ...bundle.entry, bundlePath: bundle.root } });
  // Publication receipts bind local inode/timestamps, so independent fixtures cannot
  // share their bytes. Imported entries may omit them; both arms then authenticate
  // the identical layout payloads fully instead of reusing publication admission.
  for (const stage of ["static-hermes-layout-selection", "static-hermes-layout-output"]) {
    const stageRoot = join(cacheLayout.immutable.artifacts, stage);
    for (const key of await fs.readdir(stageRoot)) {
      const entryPath = join(stageRoot, key, "entry.json");
      const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
      assert.ok(Object.hasOwn(entry, "admission"));
      delete entry.admission;
      await fs.writeFile(entryPath, `${JSON.stringify(entry)}\n`);
    }
  }
  await ageTree(cacheLayout.immutable.root);
  const stages = await fs.readdir(cacheLayout.immutable.artifacts);
  let artifactCount = 0;
  for (const stage of stages) {
    for (const key of await fs.readdir(join(cacheLayout.immutable.artifacts, stage))) {
      artifactCount += 1;
      const path = join(cacheLayout.immutable.artifacts, stage, key);
      const entry = JSON.parse(await fs.readFile(join(path, "entry.json"), "utf8"));
      // Root time suffices for the reuse grace. Do not change shared payload mtimes, which
      // would inadvertently retain old entries linked to the same payload.
      if ((stage === "benchmark-payload" && entry.identity.index < retainedCount) ||
          stage === "generated-c" || (waves === 1 && stage !== "benchmark-payload")) {
        await fs.utimes(path, new Date(nowMs - 1000), new Date(nowMs - 1000));
      }
    }
  }
  if (waves === 1) {
    await fs.utimes(join(cacheLayout.immutable.packages, graph.graphManifestSha256), new Date(nowMs - 1000), new Date(nowMs - 1000));
    const lookupBase = join(cacheLayout.immutable.packages, "deployment-results", "v1");
    for (const name of await fs.readdir(lookupBase)) await fs.utimes(join(lookupBase, name), new Date(nowMs - 1000), new Date(nowMs - 1000));
  }
  const occupancy = await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root);
  assert.ok(artifactCount <= 2048 && occupancy.uniqueAllocatedBytes <= 256 * 1024 * 1024);
  return { cacheRoot, seed: 20261029, variant, waves, artifactCount, retainedCount, removedCount, inputAllocatedBytes: occupancy.uniqueAllocatedBytes };
}

// Compare content and hardlink relationships without comparing copy-specific inode IDs.
// This runs outside maintenance timing and intentionally warms the independent fixtures.
async function snapshotTree(root, includeDirectoryTimes) {
  const entries = [];
  const links = new Map();
  async function visit(path) {
    const status = await fs.lstat(path);
    const name = relative(root, path);
    if (status.isDirectory()) {
      entries.push({ path: name, directory: true, mode: status.mode,
        ...(includeDirectoryTimes ? { mtimeMs: status.mtimeMs } : {}) });
      for (const child of (await fs.readdir(path)).sort()) await visit(join(path, child));
    } else {
      assert.ok(status.isFile(), "fixture contains a non-regular file");
      const inode = `${status.dev}:${status.ino}`;
      if (!links.has(inode)) links.set(inode, name);
      entries.push({ path: name, mode: status.mode, mtimeMs: status.mtimeMs,
        linkGroup: links.get(inode), size: status.size,
        sha256: createHash("sha256").update(await fs.readFile(path)).digest("hex") });
    }
  }
  await visit(root);
  return entries;
}

// These hooks observe actual temporary-cache I/O. They are confined to this single-arm
// process and never replace filesystem behavior or inject a production cache authority.
function observeIo() {
  const phases = {};
  const bucket = () => phases[currentConvexWasmRetentionPhase() ?? "maintenance"] ??=
    { payloadReadBytes: 0, otherReadBytes: 0, structuredParses: 0, parsedBytes: 0, lstatCalls: 0, fsyncCalls: 0, fsyncMilliseconds: 0 };
  const open = fs.open;
  const lstat = fs.lstat;
  const parse = JSON.parse;
  fs.open = async function(path, ...args) {
    const handle = await open.call(this, path, ...args);
    const read = handle.read.bind(handle);
    const sync = handle.sync.bind(handle);
    handle.read = async (...args) => {
      const result = await read(...args);
      bucket()[basename(String(path)).startsWith("artifact.") ? "payloadReadBytes" : "otherReadBytes"] += result.bytesRead;
      return result;
    };
    handle.sync = async () => {
      const measurement = bucket();
      const started = performance.now();
      measurement.fsyncCalls += 1;
      try { return await sync(); }
      finally { measurement.fsyncMilliseconds += performance.now() - started; }
    };
    return handle;
  };
  fs.lstat = async function(...args) { bucket().lstatCalls += 1; return await lstat.apply(this, args); };
  JSON.parse = function(source, ...args) {
    bucket().structuredParses += 1;
    bucket().parsedBytes += Buffer.byteLength(String(source));
    return parse(source, ...args);
  };
  return { phases, restore() { fs.open = open; fs.lstat = lstat; JSON.parse = parse; } };
}

async function main(args) {
  const [rawRoot, variant, rawWaves] = args;
  if (args.length !== 3 || !["metadata", "hardlink"].includes(variant) || !["1", "4"].includes(rawWaves)) {
    throw new Error("usage: benchmark-cache-retention.mjs NEW_OUTPUT_DIRECTORY metadata|hardlink 1|4");
  }
  const root = resolve(rawRoot);
  const sourceRoot = fileURLToPath(new URL("..", import.meta.url));
  let identity;
  try {
    identity = JSON.parse(await fs.readFile(join(sourceRoot, "source-identity.json"), "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    identity = {
      revision: execFileSync("git", ["rev-parse", "HEAD"], { cwd: sourceRoot, encoding: "utf8" }).trim(),
      diff: execFileSync("git", ["diff", "HEAD", "--", "scripts/lib/convex-wasm-cache-retention.mjs", "scripts/lib/convex-wasm-cache-retention-immutable.mjs", "scripts/lib/convex-wasm-cache-maintenance-schedule.mjs"], { cwd: sourceRoot, encoding: "utf8" }),
    };
  }
  const sourceRevision = identity.revision;
  const sourceDiff = identity.diff;
  const sourceDigests = {};
  for (const name of ["convex-wasm-cache-retention.mjs", "convex-wasm-cache-retention-immutable.mjs", "convex-wasm-cache-maintenance-schedule.mjs"]) {
    sourceDigests[name] = createHash("sha256").update(await fs.readFile(join(sourceRoot, "scripts", "lib", name))).digest("hex");
  }
  const harnessDigests = {};
  for (const path of ["scripts/benchmark-cache-retention.mjs", "scripts/test-fixtures/cache-retention.mjs",
    "scripts/test-fixtures/convex-wasm-module-graph-registry/fixture.json"]) {
    harnessDigests[path] = createHash("sha256").update(await fs.readFile(join(sourceRoot, path))).digest("hex");
  }
  const fixture = await prepare(root, variant, Number(rawWaves));
  const immutableRoot = join(fixture.cacheRoot, "immutable", "v6");
  const inputTree = await snapshotTree(immutableRoot, true);
  await fs.writeFile(join(root, "input-tree.json"), `${JSON.stringify(inputTree)}\n`, { mode: 0o600 });
  await fs.writeFile(join(root, "source.diff"), sourceDiff, { mode: 0o600 });
  const io = observeIo();
  const cpuStart = process.cpuUsage();
  const started = performance.now();
  const deadline = setTimeout(() => { process.stderr.write("maintenance benchmark exceeded 60 seconds\n"); process.exit(124); }, 60_000);
  let report;
  let cpu;
  let wallMilliseconds;
  try {
    report = await maintainConvexWasmCache({ cacheRoot: fixture.cacheRoot,
      environment: { CONVEX_WASM_CACHE_LOCK_DB: join(root, "lock.sqlite") },
      apply: true, immutableSweep: true, immutableHighWatermarkAllocatedBytes: 1,
      includeImmutableOccupancy: true, nowMs });
    cpu = process.cpuUsage(cpuStart);
    wallMilliseconds = performance.now() - started;
    assert.ok(wallMilliseconds <= 60_000, "maintenance exceeded the measured deadline");
  } finally { clearTimeout(deadline); io.restore(); }
  const peakRssKiB = process.resourceUsage().maxRSS;
  const remainingTree = await snapshotTree(immutableRoot, false);
  await fs.writeFile(join(root, "remaining-tree.json"), `${JSON.stringify(remainingTree)}\n`, { mode: 0o600 });
  const result = {
    kind: "convex-wasm-cache-retention-benchmark-v2", fixture, sourceRevision, sourceDigests, harnessDigests,
    inputTreeSha256: createHash("sha256").update(JSON.stringify(inputTree)).digest("hex"),
    remainingTreeSha256: createHash("sha256").update(JSON.stringify(remainingTree)).digest("hex"),
    policy: { nowMs, immutableHighWatermarkAllocatedBytes: 1 },
    measurementScope: { wallAndCpu: "maintenance including lock acquisition",
      peakRss: "process lifetime through maintenance, including imports and fixture preparation",
      io: "FileHandle.read bytes, JSON.parse calls, fs.lstat calls and FileHandle.sync calls; not all reads or authenticated bytes" },
    node: process.version, platform: process.platform,
    warmth: "fresh independent fixture; creation warms file data and metadata; no OS cache eviction",
    wallMilliseconds, cpu, peakRssKiB,
    io: io.phases, diagnostics: report.diagnostics,
    removed: report.immutable.sweep.removed.map(({ path }) => relative(fixture.cacheRoot, path)),
    retained: report.immutable.plan.retained,
    remainingAllocatedBytes: report.immutable.sweep.remainingAllocatedBytes,
    waves: report.immutable.sweep.waves,
    termination: report.immutable.sweep.termination,
  };
  await fs.writeFile(join(root, "result.json"), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ...result, removed: result.removed.length, retained: report.immutable.plan.authenticated })}\n`);
}

if (import.meta.main) await main(process.argv.slice(2));
