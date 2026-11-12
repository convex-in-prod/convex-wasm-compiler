#!/usr/bin/env node

import { resolve } from "node:path";

import { defaultConvexWasmCacheRoot } from "./lib/convex-wasm-cache-layout.mjs";
import {
  maintainConvexWasmCache,
} from "./lib/convex-wasm-cache-retention.mjs";

function usage() {
  return [
    "usage: convex-wasm-cache [--dry-run | --apply]",
    "       [--cache-root PATH] [--work-only]",
    "       [--immutable-plan-output PATH] [--immutable-high-watermark-bytes N]",
    "       [--immutable-sweep | --automatic]",
    "",
    "The default is a dry run. Sweeping requires --immutable-high-watermark-bytes or CONVEX_WASM_CACHE_HIGH_WATERMARK_BYTES.",
  ].join("\n");
}

function bytes(value, option) {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new Error(`${option} must be a positive integer number of bytes\n${usage()}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${option} is outside the supported range\n${usage()}`);
  }
  return parsed;
}

export function parseArguments(argumentsList) {
  let apply = false;
  let automaticImmutableSweep = false;
  let modeSeen = false;
  let cacheRoot = defaultConvexWasmCacheRoot();
  let includeImmutableOccupancy = true;
  let immutableHighWatermarkAllocatedBytes;
  let immutablePlanOutput;
  let immutableSweep = false;
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    if (option === "--apply" || option === "--dry-run") {
      if (modeSeen) throw new Error(`maintenance mode was provided more than once\n${usage()}`);
      modeSeen = true;
      apply = option === "--apply";
      continue;
    }
    if (option === "--work-only") {
      includeImmutableOccupancy = false;
      continue;
    }
    if (option === "--immutable-sweep") {
      immutableSweep = true;
      continue;
    }
    if (option === "--automatic") {
      automaticImmutableSweep = true;
      continue;
    }
    const value = argumentsList[index + 1];
    if (value === undefined) throw new Error(usage());
    index += 1;
    if (option === "--cache-root") cacheRoot = resolve(value);
    else if (option === "--immutable-plan-output") {
      immutablePlanOutput = resolve(value);
    } else if (option === "--immutable-high-watermark-bytes") {
      immutableHighWatermarkAllocatedBytes = bytes(value, option);
    } else {
      throw new Error(usage());
    }
  }
  if (apply && immutablePlanOutput !== undefined) {
    throw new Error(`--immutable-plan-output requires --dry-run\n${usage()}`);
  }
  if (immutableSweep && !apply) {
    throw new Error(`--immutable-sweep requires --apply\n${usage()}`);
  }
  if (automaticImmutableSweep && (!apply || immutableSweep)) {
    throw new Error(`--automatic requires --apply without --immutable-sweep\n${usage()}`);
  }
  return {
    apply,
    automaticImmutableSweep,
    cacheRoot,
    includeImmutableOccupancy,
    ...(immutableHighWatermarkAllocatedBytes === undefined
      ? {}
      : { immutableHighWatermarkAllocatedBytes }),
    ...(immutablePlanOutput === undefined ? {} : { immutablePlanOutput }),
    immutableSweep,
  };
}

export async function main(argumentsList) {
  const options = parseArguments(argumentsList);
  const report = await maintainConvexWasmCache(options);
  if (report.kind === "convex-wasm-cache-maintenance-deferred-v1") {
    process.stdout.write(`${JSON.stringify(report)}\n`);
    return;
  }
  if (options.automaticImmutableSweep) {
    process.stdout.write(
      `${JSON.stringify({
        at: new Date().toISOString(),
        cacheRoot: report.cacheRoot,
        elapsedMilliseconds: report.diagnostics?.elapsedMilliseconds ?? Date.now() - report.nowMs,
        estimatedReclaimedBytes:
          report.immutable.sweep?.removed.reduce(
            (total, entry) => total + entry.estimatedReclaimBytes,
            0
          ) ?? 0,
        immutableUniqueAllocatedBytes:
          report.immutable.sweep?.remainingAllocatedBytes ??
          report.immutable.automaticSweep.occupancy.uniqueAllocatedBytes,
        immutableSweepTriggered: report.immutable.automaticSweep.triggered,
        removed: report.immutable.sweep?.removed.length ?? 0,
        recovered: report.immutable.sweep?.recovered.length ?? 0,
        sweepBlocker: report.immutable.sweepBlocker,
        workRoots: report.work.summary.total,
        termination: report.immutable.sweep?.termination,
        remainingExcessBytes: report.immutable.sweep?.remainingExcessBytes,
        waves: report.immutable.sweep?.waves,
        diagnostics: report.diagnostics,
      })}\n`
    );
    return;
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (import.meta.main) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
