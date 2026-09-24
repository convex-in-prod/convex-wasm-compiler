import assert from "node:assert/strict";
import test from "node:test";

import { parseArguments } from "./maintain-convex-wasm-cache.mjs";

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
