import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readAutomaticCacheMaintenanceSchedule } from "./convex-wasm-cache-maintenance-schedule.mjs";

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
  await retry.complete();
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
  await (await readAutomaticCacheMaintenanceSchedule(options)).complete();
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
