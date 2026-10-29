import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readAutomaticCacheMaintenanceSchedule } from "./convex-wasm-cache-maintenance-schedule.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { acquireConvexWasmCacheLock } from "./convex-wasm-cache-lock.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { createConvexWasmBuildWorkLease, maintainConvexWasmCache } from "./convex-wasm-cache-retention.mjs";
import { currentConvexWasmRetentionPhase } from "./convex-wasm-cache-retention-immutable.mjs";
import { ageGenericArtifact, writeGenericArtifact } from "../test-fixtures/cache-retention.mjs";

async function fixture(t) {
  const cacheRoot = await fs.mkdtemp(
    join(tmpdir(), "convex-wasm-maintenance-schedule-"),
  );
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  return { cacheRoot, policy: { highWatermarkBytes: 100 }, nowMs: 1_000_000 };
}

test("only completed maintenance delays a later process using the same policy", async (t) => {
  const options = await fixture(t);
  const failed = await readAutomaticCacheMaintenanceSchedule(options);
  assert.equal(failed.status, "due");
  const retry = await readAutomaticCacheMaintenanceSchedule(options);
  assert.equal(retry.status, "due");
  await retry.complete(options.nowMs);
  const next = await readAutomaticCacheMaintenanceSchedule({
    ...options,
    nowMs: options.nowMs + 10,
  });
  assert.equal(next.status, "deferred");
  assert.equal(
    (
      await readAutomaticCacheMaintenanceSchedule({
        ...options,
        nowMs: next.nextDueAtMs,
      })
    ).status,
    "due",
  );
});

test("a policy change or clock rollback triggers maintenance immediately", async (t) => {
  const options = await fixture(t);
  await (await readAutomaticCacheMaintenanceSchedule(options)).complete(options.nowMs);
  assert.equal(
    (
      await readAutomaticCacheMaintenanceSchedule({
        ...options,
        policy: { highWatermarkBytes: 50 },
      })
    ).status,
    "due",
  );
  assert.equal(
    (
      await readAutomaticCacheMaintenanceSchedule({
        ...options,
        nowMs: options.nowMs - 1,
      })
    ).status,
    "due",
  );
});

test("malformed and linked schedule records cannot suppress maintenance", async (t) => {
  const options = await fixture(t);
  const path = join(options.cacheRoot, "automatic-maintenance.json");
  await fs.writeFile(path, "{}", { mode: 0o600 });
  await assert.rejects(readAutomaticCacheMaintenanceSchedule(options));
  await fs.rm(path);
  const outside = join(options.cacheRoot, "outside");
  await fs.writeFile(outside, "{}", { mode: 0o600 });
  await fs.symlink(outside, path);
  await assert.rejects(
    readAutomaticCacheMaintenanceSchedule(options),
    /non-symlink/u,
  );
  assert.equal(await fs.readFile(outside, "utf8"), "{}");
});

test("a run longer than the interval waits a full interval after completion", async (t) => {
  const options = await fixture(t);
  const schedule = await readAutomaticCacheMaintenanceSchedule(options);
  const completedAtMs = options.nowMs + 20 * 60 * 1000;
  await schedule.complete(completedAtMs);
  const next = await readAutomaticCacheMaintenanceSchedule({ ...options, nowMs: completedAtMs + 1 });
  assert.equal(next.status, "deferred");
  assert.equal(next.previousCompletedAtMs, completedAtMs);
  assert.equal(next.nextDueAtMs, completedAtMs + 15 * 60 * 1000);
  await assert.rejects(schedule.complete(), /completion time/u);
  await assert.rejects(schedule.complete(-1), /completion time/u);
  assert.equal((await readAutomaticCacheMaintenanceSchedule({ ...options, nowMs: completedAtMs + 1 })).status, "deferred");
});

test("a valid legacy receipt is due once and migrates only after success", async (t) => {
  const options = await fixture(t);
  const path = join(options.cacheRoot, "automatic-maintenance.json");
  const legacy = { kind: "convex-wasm-automatic-maintenance-v1", policySha256: fingerprintJson(options.policy), startedAtMs: options.nowMs };
  await fs.writeFile(path, JSON.stringify(legacy), { mode: 0o600 });
  const first = await readAutomaticCacheMaintenanceSchedule(options);
  assert.equal(first.status, "due");
  assert.deepEqual(JSON.parse(await fs.readFile(path, "utf8")), legacy);
  const retry = await readAutomaticCacheMaintenanceSchedule(options);
  assert.equal(retry.status, "due");
  await retry.complete(options.nowMs + 10);
  assert.deepEqual(JSON.parse(await fs.readFile(path, "utf8")), {
    kind: "convex-wasm-automatic-maintenance-v2", policySha256: fingerprintJson(options.policy), completedAtMs: options.nowMs + 10,
  });
  assert.equal((await readAutomaticCacheMaintenanceSchedule({ ...options, nowMs: options.nowMs + 11 })).status, "deferred");
  for (const invalid of [{ ...legacy, startedAtMs: -1 }, { ...legacy, extra: true }, { ...legacy, policySha256: "invalid" }]) {
    await fs.writeFile(path, JSON.stringify(invalid), { mode: 0o600 });
    await assert.rejects(readAutomaticCacheMaintenanceSchedule(options));
  }
});

async function maintenanceFixture(t) {
  const { cacheRoot } = await fixture(t);
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "schedule-work", cacheRoot, repositoryRoot: cacheRoot,
  });
  const options = {
    cacheRoot,
    environment: { CONVEX_WASM_CACHE_LOCK_DB: join(cacheRoot, "test-lock.sqlite") },
    apply: true,
    automaticImmutableSweep: true,
    includeImmutableOccupancy: false,
    immutableHighWatermarkAllocatedBytes: 1,
    abandonedRecoveryMilliseconds: 1_000,
    quiescentMilliseconds: 0,
    nowMs: 2_000_000_000,
    clock: () => options.nowMs,
  };
  return { cacheLayout, options, receiptPath: join(cacheRoot, "automatic-maintenance.json") };
}

test("blocked automatic sweeps neither create nor replace completion receipts", async (t) => {
  for (const receiptKind of ["absent", "v1", "v2"]) {
    await t.test(receiptKind, async (t) => {
      const { cacheLayout, options, receiptPath } = await maintenanceFixture(t);
      const previous = receiptKind === "absent" ? undefined : JSON.stringify({
        kind: `convex-wasm-automatic-maintenance-${receiptKind}`,
        policySha256: fingerprintJson({}),
        ...(receiptKind === "v1" ? { startedAtMs: 0 } : { completedAtMs: 0 }),
      });
      if (previous !== undefined) await fs.writeFile(receiptPath, previous, { mode: 0o600 });
      const artifact = await writeGenericArtifact({
        cacheLayout, extension: "wasm", metadata: {}, payload: "waiting", stage: "waiting",
      });
      await ageGenericArtifact(cacheLayout, artifact);
      const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
      const release = await acquireConvexWasmCacheLock({ environment: options.environment });
      try {
        await createConvexWasmBuildWorkLease({
          cacheLayout, environment: options.environment, nowMs: options.nowMs,
        });
      } finally { release(); }
      const blocked = await maintainConvexWasmCache(options);
      assert.equal(blocked.immutable.sweep.termination, "blocked-work");
      assert.equal(blocked.immutable.sweepAuthorized, false);
      await fs.lstat(artifactPath);
      if (previous === undefined) await assert.rejects(fs.lstat(receiptPath), { code: "ENOENT" });
      else assert.equal(await fs.readFile(receiptPath, "utf8"), previous);

      // The abandonment window ends before the cooldown would have expired.
      options.nowMs += 1_000;
      const retry = await maintainConvexWasmCache(options);
      assert.equal(retry.immutable.sweep.termination,
        retry.immutable.sweep.remainingAllocatedBytes <= options.immutableHighWatermarkAllocatedBytes
          ? "watermark-reached" : "no-eligible-candidates");
      assert.equal(retry.immutable.sweep.removed.length, 1);
      await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
      assert.equal(JSON.parse(await fs.readFile(receiptPath, "utf8")).completedAtMs, options.nowMs);
    });
  }
});

test("failed automatic deletion preserves the receipt and recovery still observes work admission", async (t) => {
  const { cacheLayout, options, receiptPath } = await maintenanceFixture(t);
  await maintainConvexWasmCache(options);
  const previous = await fs.readFile(receiptPath, "utf8");
  const artifact = await writeGenericArtifact({
    cacheLayout, extension: "wasm", metadata: {}, payload: "interrupted", stage: "interrupted",
  });
  await ageGenericArtifact(cacheLayout, artifact);
  const readdir = fs.readdir;
  fs.readdir = async (path, ...args) => {
    if (path.includes("immutable-sweep-trash") && currentConvexWasmRetentionPhase() === "unlink") {
      throw new Error("synthetic automatic deletion failure");
    }
    return await readdir(path, ...args);
  };
  try {
    await assert.rejects(maintainConvexWasmCache({
      // A temporary policy change makes this run due despite the recent receipt.
      ...options, immutableHighWatermarkAllocatedBytes: 2, nowMs: options.nowMs + 1,
    }), /synthetic automatic deletion failure/u);
  } finally { fs.readdir = readdir; }
  assert.equal(await fs.readFile(receiptPath, "utf8"), previous);

  const release = await acquireConvexWasmCacheLock({ environment: options.environment });
  try {
    await createConvexWasmBuildWorkLease({
      cacheLayout, environment: options.environment, nowMs: options.nowMs,
    });
  } finally { release(); }
  const blocked = await maintainConvexWasmCache(options);
  assert.equal(blocked.immutable.sweep.termination, "blocked-work");
  assert.deepEqual(blocked.immutable.sweep.recovered, []);
  assert.equal(await fs.readFile(receiptPath, "utf8"), previous);
  options.nowMs += 1_000;
  const recovered = await maintainConvexWasmCache(options);
  assert.equal(recovered.immutable.sweep.termination, "recovery-completed");
  assert.equal(recovered.immutable.sweep.recovered.length, 1);
  assert.deepEqual(recovered.immutable.sweep.removed, []);
  assert.equal(recovered.diagnostics.counts.inventoryBuilds, 0);
  assert.equal(recovered.diagnostics.counts.dedicatedImmutableOccupancyWalks, 1);
  assert.equal(await fs.readFile(receiptPath, "utf8"), previous);
  assert.equal((await maintainConvexWasmCache(options)).kind, "convex-wasm-cache-maintenance-deferred-v1");
});

test("receipt publication is atomic and has no fallible post-publication temporary cleanup", async (t) => {
  const options = await fixture(t);
  const receiptPath = join(options.cacheRoot, "automatic-maintenance.json");
  const schedule = await readAutomaticCacheMaintenanceSchedule(options);
  const original = { rename: fs.rename, rm: fs.rm };
  fs.rm = async (path, settings) => {
    if (path.includes(".automatic-maintenance-")) throw new Error("unexpected committed temporary cleanup");
    return await original.rm(path, settings);
  };
  try { await schedule.complete(options.nowMs); }
  finally { fs.rm = original.rm; }
  const previous = await fs.readFile(receiptPath, "utf8");
  fs.rename = async (from, to) => {
    if (to === receiptPath) throw new Error("synthetic schedule rename failure");
    return await original.rename(from, to);
  };
  try { await assert.rejects(schedule.complete(options.nowMs + 1), /synthetic schedule rename failure/u); }
  finally { fs.rename = original.rename; }
  assert.equal(await fs.readFile(receiptPath, "utf8"), previous);
  assert.deepEqual(await fs.readdir(options.cacheRoot), ["automatic-maintenance.json"]);
  await fs.chmod(receiptPath, 0o644);
  await assert.rejects(readAutomaticCacheMaintenanceSchedule(options), /mode 0600/u);
});
