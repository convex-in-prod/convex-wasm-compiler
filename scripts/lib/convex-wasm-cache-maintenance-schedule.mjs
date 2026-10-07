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
const scheduleSchema = z.strictObject({
  kind: z.literal("convex-wasm-automatic-maintenance-v1"),
  policySha256: z.string().regex(/^[0-9a-f]{64}$/u),
  startedAtMs: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});

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
  // A policy change or clock rollback requires a fresh scan. The receipt only
  // defers automatic work; it never authorizes deletion or bypasses disk guards.
  if (
    previous !== undefined &&
    previous.policySha256 === policySha256 &&
    nowMs >= previous.startedAtMs &&
    nowMs - previous.startedAtMs < automaticCacheMaintenanceIntervalMs
  ) {
    return {
      status: "deferred",
      previousStartedAtMs: previous.startedAtMs,
      nextDueAtMs: previous.startedAtMs + automaticCacheMaintenanceIntervalMs,
    };
  }
  return {
    status: "due",
    async complete() {
      const temporary = join(
        cacheRoot,
        `.automatic-maintenance-${process.pid}-${randomBytes(8).toString("hex")}`,
      );
      try {
        await fs.writeFile(
          temporary,
          `${canonicalJson({
            kind: "convex-wasm-automatic-maintenance-v1",
            policySha256,
            startedAtMs: nowMs,
          })}\n`,
          { flag: "wx", mode: 0o600 },
        );
        await fs.rename(temporary, path);
      } finally {
        await fs.rm(temporary, { force: true });
      }
    },
  };
}
