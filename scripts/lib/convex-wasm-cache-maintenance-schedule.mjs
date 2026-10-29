import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

import {
  canonicalJson,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import { readPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";

export const automaticCacheMaintenanceIntervalMs = 15 * 60 * 1_000;
const legacyScheduleSchema = z.strictObject({
  kind: z.literal("convex-wasm-automatic-maintenance-v1"),
  policySha256: z.string().regex(/^[0-9a-f]{64}$/u),
  startedAtMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});

const completionScheduleSchema = z.strictObject({
  kind: z.literal("convex-wasm-automatic-maintenance-v2"),
  policySha256: z.string().regex(/^[0-9a-f]{64}$/u),
  completedAtMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});
const scheduleSchema = z.discriminatedUnion("kind", [legacyScheduleSchema, completionScheduleSchema]);

// The caller holds its build/maintenance lock across this decision, the scan,
// and completion. This lets different lock owners use the same generic policy
// without treating one owner's process-local authority as another's.
export async function readAutomaticCacheMaintenanceSchedule({
  cacheRoot,
  policy,
  nowMs,
}) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new Error(
      "Automatic cache maintenance time must be a nonnegative safe integer",
    );
  }
  await fs.mkdir(cacheRoot, { recursive: true, mode: 0o700 });
  await requirePrivateCacheDirectory(cacheRoot, cacheRoot);
  const path = join(cacheRoot, "automatic-maintenance.json");
  const policySha256 = fingerprintJson(policy);
  let previous;
  try {
    await requirePrivateCacheFile(cacheRoot, path);
    previous = scheduleSchema.parse(
      JSON.parse(
        (
          await readPrivateRegularFile(
            path,
            1024,
            "automatic maintenance schedule",
          )
        ).toString("utf8"),
      ),
    );
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT"))
      throw error;
  }
  // A well-formed v1 receipt is due once: its start time cannot establish a completion
  // cooldown. Reject malformed legacy data instead of treating arbitrary state as absent.
  // A policy change or clock rollback requires a fresh scan. The receipt only
  // defers automatic work; it never authorizes deletion or bypasses disk guards.
  if (
    previous?.kind === "convex-wasm-automatic-maintenance-v2" &&
    previous.policySha256 === policySha256 &&
    nowMs >= previous.completedAtMs &&
    nowMs - previous.completedAtMs < automaticCacheMaintenanceIntervalMs
  ) {
    return {
      status: "deferred",
      previousCompletedAtMs: previous.completedAtMs,
      nextDueAtMs: previous.completedAtMs + automaticCacheMaintenanceIntervalMs,
    };
  }
  return {
    status: "due",
    async complete(completedAtMs) {
      if (!Number.isSafeInteger(completedAtMs) || completedAtMs < 0) {
        throw new Error("Automatic cache maintenance completion time must be a nonnegative safe integer");
      }
      // Persist only after all work succeeds. A long maintenance run earns a full interval
      // after completion, and any thrown failure leaves the previous receipt untouched.
      const temporary = join(
        cacheRoot,
        `.automatic-maintenance-${process.pid}-${randomBytes(8).toString("hex")}`,
      );
      try {
        await fs.writeFile(
          temporary,
          `${canonicalJson({
            kind: "convex-wasm-automatic-maintenance-v2",
            policySha256,
            completedAtMs,
          })}\n`,
          { flag: "wx", mode: 0o600 },
        );
        await fs.rename(temporary, path);
      } catch (error) {
        // Rename commits the receipt and consumes the temporary path. Do not run a
        // fallible cleanup after publication and report a committed cooldown as failure.
        await fs.rm(temporary, { force: true });
        throw error;
      }
    },
  };
}
