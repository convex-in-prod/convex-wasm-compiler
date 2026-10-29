import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

import { parseArguments } from "./maintain-convex-wasm-cache.mjs";
import { deriveConvexWasmCacheLayout } from "./lib/convex-wasm-cache-layout.mjs";
import { maintainConvexWasmCache, measureConvexWasmCacheOccupancy } from "./lib/convex-wasm-cache-retention.mjs";
import { currentConvexWasmRetentionPhase } from "./lib/convex-wasm-cache-retention-immutable.mjs";
import { ageGenericArtifact, writeGenericArtifact } from "./test-fixtures/cache-retention.mjs";

test("cache maintenance CLI defaults to an immutable-safe dry run", () => {
  const parsed = parseArguments([]);
  assert.equal(parsed.apply, false);
  assert.equal(parsed.includeImmutableOccupancy, true);
  assert.equal(parsed.immutableSweep, false);
});

test("cache maintenance CLI parses apply and retention intervals", () => {
  const parsed = parseArguments([
    "--apply",
    "--cache-root",
    "/tmp/convex-wasm-maintenance-test",
    "--work-only",
    "--quiescent-hours",
    "2",
    "--abandoned-recovery-hours",
    "48",
    "--completed-retention-hours",
    "3",
    "--failed-recovery-hours",
    "48",
    "--immutable-high-watermark-bytes",
    "1048576",
    "--immutable-sweep",
  ]);
  assert.equal(parsed.apply, true);
  assert.equal(parsed.cacheRoot, "/tmp/convex-wasm-maintenance-test");
  assert.equal(parsed.includeImmutableOccupancy, false);
  assert.equal(parsed.quiescentMilliseconds, 2 * 60 * 60 * 1_000);
  assert.equal(parsed.abandonedRecoveryMilliseconds, 48 * 60 * 60 * 1_000);
  assert.equal(parsed.completedRetentionMilliseconds, 3 * 60 * 60 * 1_000);
  assert.equal(parsed.failedRecoveryMilliseconds, 48 * 60 * 60 * 1_000);
  assert.equal(parsed.immutableHighWatermarkAllocatedBytes, 1_048_576);
  assert.equal(parsed.immutableSweep, true);
  assert.equal(
    parseArguments(["--dry-run", "--immutable-plan-output", "/tmp/convex-wasm-plan.json"])
      .immutablePlanOutput,
    "/tmp/convex-wasm-plan.json"
  );
});

test("automatic cache maintenance applies without forcing a full immutable sweep", () => {
  const parsed = parseArguments(["--apply", "--automatic", "--work-only"]);
  assert.equal(parsed.apply, true);
  assert.equal(parsed.automaticImmutableSweep, true);
  assert.equal(parsed.immutableSweep, false);
  assert.equal(parsed.includeImmutableOccupancy, false);
});

test("cache maintenance CLI rejects conflicting modes and invalid intervals", () => {
  assert.throws(() => parseArguments(["--dry-run", "--apply"]), /more than once/u);
  assert.throws(() => parseArguments(["--quiescent-hours", "-1"]), /non-negative/u);
  assert.throws(
    () => parseArguments(["--immutable-high-watermark-bytes", "0"]),
    /positive integer/u
  );
  assert.throws(
    () => parseArguments(["--apply", "--immutable-plan-output", "/tmp/plan.json"]),
    /requires --dry-run/u
  );
  assert.throws(() => parseArguments(["--immutable-sweep"]), /requires --apply/u);
  assert.throws(() => parseArguments(["--automatic"]), /requires --apply/u);
  assert.throws(
    () => parseArguments(["--apply", "--automatic", "--immutable-sweep"]),
    /without --immutable-sweep/u
  );
});

test("automatic CLI summaries distinguish eviction, cooldown recovery and deferral", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-cache-cli-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheRoot = join(root, "cache");
  const cacheLayout = deriveConvexWasmCacheLayout({ buildId: "cli", cacheRoot, repositoryRoot: root });
  const environment = { CONVEX_WASM_CACHE_LOCK_DB: join(root, "cache-lock.sqlite") };
  const writeCandidate = async (name) => {
    const artifact = await writeGenericArtifact({
      cacheLayout, extension: "wasm", metadata: {}, payload: name, stage: name,
    });
    await ageGenericArtifact(cacheLayout, artifact);
    return join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  };
  const run = async () => {
    const { stdout } = await promisify(execFile)(process.execPath, [
      fileURLToPath(new URL("./maintain-convex-wasm-cache.mjs", import.meta.url)),
      "--apply", "--automatic", "--work-only", "--cache-root", cacheRoot,
      "--immutable-high-watermark-bytes", "1",
    ], { env: { ...process.env, ...environment }, timeout: 10_000 });
    return JSON.parse(stdout);
  };
  await writeCandidate("first");
  const swept = await run();
  assert.equal(swept.removed, 1);
  assert.equal(swept.recovered, 0);
  assert.equal(swept.termination,
    swept.immutableUniqueAllocatedBytes <= 1 ? "watermark-reached" : "no-eligible-candidates");
  assert.equal(swept.immutableUniqueAllocatedBytes,
    (await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root)).uniqueAllocatedBytes);
  assert.equal(swept.remainingExcessBytes, Math.max(0, swept.immutableUniqueAllocatedBytes - 1));
  assert.equal(swept.waves.length, 1);
  const receiptPath = join(cacheRoot, "automatic-maintenance.json");
  const receipt = await fs.readFile(receiptPath, "utf8");
  await writeCandidate("interrupted");
  const readdir = fs.readdir;
  fs.readdir = async (path, ...args) => {
    if (path.includes("immutable-sweep-trash") && currentConvexWasmRetentionPhase() === "unlink") {
      throw new Error("synthetic CLI recovery interruption");
    }
    return await readdir(path, ...args);
  };
  try {
    await assert.rejects(maintainConvexWasmCache({
      apply: true, immutableSweep: true, immutableHighWatermarkAllocatedBytes: 1,
      cacheRoot, environment, includeImmutableOccupancy: false,
    }), /synthetic CLI recovery interruption/u);
  } finally { fs.readdir = readdir; }
  const waiting = await writeCandidate("waiting");
  const recovered = await run();
  assert.equal(recovered.removed, 0);
  assert.equal(recovered.recovered, 1);
  assert.equal(recovered.termination, "recovery-completed");
  assert.equal(recovered.diagnostics.counts.inventoryBuilds, 0);
  assert.equal(recovered.immutableUniqueAllocatedBytes,
    (await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root)).uniqueAllocatedBytes);
  assert.equal(await fs.readFile(receiptPath, "utf8"), receipt);
  await fs.lstat(waiting);
  assert.equal((await run()).kind, "convex-wasm-cache-maintenance-deferred-v1");
});
