import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { publishArtifactCacheEntryFromMaterial } from "./convex-wasm-artifact-cache-entry.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  ensureArtifactStage,
  ensureArtifactStageAfterObservedMiss,
  ensureArtifactControlStageFromMaterial,
  ensureSpeculativeArtifactStage,
  observeArtifactCacheMiss,
} from "./convex-wasm-artifact-stage.mjs";

test("control stages reuse authenticated material with distinct package identities", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-control-stage-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "control-stage",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let builds = 0;
  const options = {
    build: async (workPath) => {
      builds += 1;
      const outputPath = join(workPath, "module.cwasm");
      await fs.writeFile(outputPath, "authenticated AOT bytes", { mode: 0o600 });
      return { metadata: { target: "synthetic" }, outputPath, timing: { elapsedMs: 1 } };
    },
    cacheLayout,
    cacheRoot,
    extension: "cwasm",
    identity: { package: "one" },
    materialIdentity: { coreWasm: "same-input" },
    materialStage: "module-aot-material",
    maxArtifactBytes: 64,
    stage: "module-aot-control",
  };
  const first = await ensureArtifactControlStageFromMaterial(options);
  const second = await ensureArtifactControlStageFromMaterial({
    ...options,
    identity: { package: "two" },
  });
  assert.equal(builds, 1);
  assert.equal(first.report.cache, "miss");
  assert.equal(second.report.cache, "hit");
  assert.notEqual(first.report.cacheKey, second.report.cacheKey);
  assert.equal(first.entry.artifactSha256, second.entry.artifactSha256);
  assert.equal(
    (await fs.stat(first.entry.artifactPath)).ino,
    (await fs.stat(second.entry.artifactPath)).ino
  );
  const cached = await ensureArtifactControlStageFromMaterial({
    ...options,
    build: async () => { throw new Error("control hit rebuilt material"); },
  });
  assert.equal(cached.report.cache, "hit");
  assert.equal(builds, 1);
  const [concurrentFirst, concurrentSecond] = await Promise.all([
    ensureArtifactControlStageFromMaterial({ ...options, identity: { package: "concurrent" } }),
    ensureArtifactControlStageFromMaterial({ ...options, identity: { package: "concurrent" } }),
  ]);
  assert.equal(concurrentFirst.entry.artifactSha256, concurrentSecond.entry.artifactSha256);
  assert.equal(builds, 1);
  await assert.rejects(
    ensureArtifactControlStageFromMaterial({
      ...options,
      identity: { package: "three" },
      maxArtifactBytes: 5,
    }),
    /above the 5-byte limit/u
  );
});

test("material-to-control publication rejects changed source authority", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-control-source-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "control-source",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const material = await ensureArtifactStage({
    build: async (workPath) => {
      const outputPath = join(workPath, "module.wasm");
      await fs.writeFile(outputPath, "material bytes", { mode: 0o600 });
      return { metadata: { contract: "original" }, outputPath, timing: null };
    },
    cacheLayout,
    cacheRoot,
    extension: "wasm",
    identity: { source: "original" },
    maxArtifactBytes: 64,
    stage: "core-material",
  });
  const identity = { package: "one" };
  const stage = "core-control";
  const key = fingerprintJson({ identity, kind: "convex-wasm-artifact-pipeline-v9", stage });
  await assert.rejects(
    publishArtifactCacheEntryFromMaterial({
      cacheLayout,
      cacheRoot,
      extension: "wasm",
      identity: { package: "different" },
      key,
      maxArtifactBytes: 64,
      sourceEntry: material.entry,
      stage,
    }),
    /identity does not match its key/u
  );
  await assert.rejects(
    publishArtifactCacheEntryFromMaterial({
      cacheLayout,
      cacheRoot,
      extension: "wasm",
      identity,
      key,
      maxArtifactBytes: 64,
      sourceEntry: { ...material.entry, metadata: { contract: "changed" } },
      stage,
    }),
    /material cache entry changed/u
  );
  await fs.writeFile(material.entry.artifactPath, "changed bytes", { mode: 0o600 });
  await assert.rejects(
    publishArtifactCacheEntryFromMaterial({
      cacheLayout,
      cacheRoot,
      extension: "wasm",
      identity,
      key,
      maxArtifactBytes: 64,
      sourceEntry: material.entry,
      stage,
    }),
    /digest or size does not match metadata/u
  );
});

test("artifact stages publish once, authenticate cache hits, and clean scratch", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-stage-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "stage-test",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let builds = 0;
  let prerequisites = 0;
  let misses = 0;
  const bytes = Buffer.from("synthetic stage output");
  const options = {
    authenticatePublicationPrerequisite: async () => { prerequisites += 1; },
    build: async (workPath) => {
      builds += 1;
      const outputPath = join(workPath, "output.wasm");
      await fs.writeFile(outputPath, bytes, { mode: 0o600 });
      return { metadata: { format: "wasm" }, outputPath, timing: { elapsedMs: 1 } };
    },
    cacheLayout,
    cacheRoot,
    extension: "wasm",
    identity: { producerImplementation: "synthetic", source: "fixture" },
    maxArtifactBytes: bytes.length,
    onCacheMiss: () => { misses += 1; },
    stage: "synthetic-stage",
  };
  const [first, shared] = await Promise.all([
    ensureArtifactStage(options),
    ensureArtifactStage(options),
  ]);
  assert.equal(builds, 1);
  assert.equal(misses, 1);
  assert.equal(prerequisites, 1);
  assert.equal(first.report.cache, "miss");
  assert.equal(shared.entry.artifactSha256, first.entry.artifactSha256);
  assert.deepEqual(await fs.readdir(cacheLayout.work.scratch), []);

  const hit = await ensureArtifactStage({
    ...options,
    build: async () => { throw new Error("cache hit rebuilt"); },
    previousIdentity: { source: "old" },
    readCachedArtifactContents: true,
    readPublishedArtifactContents: true,
  });
  assert.equal(hit.report.cache, "hit");
  assert.deepEqual(hit.entry.artifactContents, bytes);
  assert.deepEqual(hit.report.invalidationReasons, [
    "identity-input-changed:producerImplementation",
    "identity-input-changed:source",
  ]);
  assert.equal(prerequisites, 2);
  assert.equal(misses, 1);
});

test("process-shared stages enforce each caller's byte limit", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-stage-limits-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "stage-limits",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let releaseBuild;
  const buildGate = new Promise((resolve) => { releaseBuild = resolve; });
  let buildStarted;
  const started = new Promise((resolve) => { buildStarted = resolve; });
  let builds = 0;
  const options = {
    build: async (workPath) => {
      builds += 1;
      buildStarted();
      await buildGate;
      const outputPath = join(workPath, "output.o");
      await fs.writeFile(outputPath, "three", { mode: 0o600 });
      return { metadata: null, outputPath, timing: null };
    },
    cacheLayout,
    cacheRoot,
    extension: "o",
    identity: { source: "shared-limit" },
    maxArtifactBytes: 5,
    stage: "shared-limit",
  };
  const producer = ensureArtifactStage(options);
  await started;
  const restrictive = ensureArtifactStage({ ...options, maxArtifactBytes: 2 });
  releaseBuild();
  const result = await producer;
  await assert.rejects(restrictive, /above the 2-byte limit/u);
  assert.equal(result.entry.artifactSize, 5);
  assert.equal(builds, 1);
});

test("an admissible follower retries after a producer's operational byte limit", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-stage-retry-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "stage-retry",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let releaseBuild;
  const buildGate = new Promise((resolve) => { releaseBuild = resolve; });
  let buildStarted;
  const started = new Promise((resolve) => { buildStarted = resolve; });
  let builds = 0;
  const options = {
    build: async (workPath) => {
      builds += 1;
      if (builds === 1) {
        buildStarted();
        await buildGate;
      }
      const outputPath = join(workPath, "output.o");
      await fs.writeFile(outputPath, "three", { mode: 0o600 });
      return { metadata: null, outputPath, timing: null };
    },
    cacheLayout,
    cacheRoot,
    extension: "o",
    identity: { source: "retry-limit" },
    maxArtifactBytes: 2,
    stage: "retry-limit",
  };
  const limited = ensureArtifactStage(options);
  await started;
  const permissive = ensureArtifactStage({ ...options, maxArtifactBytes: 5 });
  releaseBuild();
  await assert.rejects(limited, /above the 2-byte limit/u);
  const result = await permissive;
  assert.equal(result.entry.artifactSize, 5);
  assert.equal(builds, 2);
});

test("observed cache misses bind one publication to the exact stage options", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-observed-miss-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "observed-miss",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let builds = 0;
  const options = {
    build: async (workPath) => {
      builds += 1;
      const outputPath = join(workPath, "output.o");
      await fs.writeFile(outputPath, "output", { mode: 0o600 });
      return { metadata: null, outputPath, timing: null };
    },
    cacheLayout,
    cacheRoot,
    extension: "o",
    identity: { source: "observed-miss" },
    maxArtifactBytes: 6,
    stage: "observed-miss",
  };
  const observation = await observeArtifactCacheMiss(options);
  assert.equal(observation.kind, "miss");
  assert.throws(
    () => ensureArtifactStageAfterObservedMiss({ ...options, extension: "wasm" }, observation.token),
    /does not match the artifact stage/u
  );
  assert.throws(
    () => ensureArtifactStageAfterObservedMiss(options, observation.token),
    /invalid or already consumed/u
  );
  const secondObservation = await observeArtifactCacheMiss(options);
  assert.equal(secondObservation.kind, "miss");
  const result = await ensureArtifactStageAfterObservedMiss(options, secondObservation.token);
  assert.equal(result.report.cache, "miss");
  assert.equal(builds, 1);
  const hit = await observeArtifactCacheMiss(options);
  assert.equal(hit.kind, "hit");
  assert.equal(hit.entry.artifactSha256, result.entry.artifactSha256);
  assert.throws(
    () => ensureArtifactStageAfterObservedMiss(options, secondObservation.token),
    /invalid or already consumed/u
  );
});

test("an ordinary follower retries after a speculative producer fails", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-speculative-stage-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "speculative-stage",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let releaseFailure;
  const failureGate = new Promise((resolve) => { releaseFailure = resolve; });
  let firstBuildStarted;
  const started = new Promise((resolve) => { firstBuildStarted = resolve; });
  let builds = 0;
  const options = {
    build: async (workPath) => {
      builds += 1;
      if (builds === 1) {
        firstBuildStarted();
        await failureGate;
        throw new Error("synthetic speculative failure");
      }
      const outputPath = join(workPath, "output.o");
      await fs.writeFile(outputPath, "output", { mode: 0o600 });
      return { metadata: null, outputPath, timing: null };
    },
    cacheLayout,
    cacheRoot,
    extension: "o",
    identity: { source: "speculative-stage" },
    maxArtifactBytes: 6,
    stage: "speculative-stage",
  };
  const speculative = ensureSpeculativeArtifactStage(options);
  const rejected = assert.rejects(speculative, /synthetic speculative failure/u);
  await started;
  const follower = ensureArtifactStage(options);
  releaseFailure();
  await rejected;
  const result = await follower;
  assert.equal(result.entry.artifactSize, 6);
  assert.equal(builds, 2);
});
