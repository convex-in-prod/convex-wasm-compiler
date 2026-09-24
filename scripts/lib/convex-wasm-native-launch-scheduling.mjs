import { AsyncLocalStorage } from "node:async_hooks";

import { requireExactPlainObject } from "./convex-wasm-artifact-contract.mjs";

const C_OPTIMIZATION_LEVEL_ZERO_STAGE = "c-optimization-level-zero-c-bundle-member-object";
const WORKING_SET_HEADROOM_NUMERATOR = 3;
const WORKING_SET_HEADROOM_DENOMINATOR = 2;
const MEBIBYTE = 1024 * 1024;
const AOT_MINIMUM_WORKING_SET_ESTIMATE_BYTES = 512 * MEBIBYTE;
const AOT_WORKING_SET_BYTES_PER_CORE_WASM_BYTE = 64;
const GENERATED_C_MINIMUM_WORKING_SET_ESTIMATE_BYTES = 64 * MEBIBYTE;
const GENERATED_C_WORKING_SET_BYTES_PER_SOURCE_BYTE = 128;
const GENERATED_C_FALLBACK_WORKING_SET_ESTIMATE_BYTES = 1024 * MEBIBYTE;
const nativeCommandWorkerSlots = new AsyncLocalStorage();
// Bound retained diagnostic events and state intervals so a large application cannot turn timing
// evidence into unbounded build memory.
const CRITICAL_PATH_EVENT_LIMIT = 32_768;

// Only the command owner classifies these failures. Never derive retained diagnostics from an
// error message: command output and arguments can contain application or operator material.
export class ConvexWasmNativeCommandFailure extends Error {
  constructor(message, diagnostic, options) {
    super(message, options);
    let failure;
    if (diagnostic.kind === "command-exit") {
      if (
        !(diagnostic.code === null || Number.isSafeInteger(diagnostic.code)) ||
        !(
          diagnostic.signal === null ||
          (typeof diagnostic.signal === "string" && /^SIG[A-Z0-9]{1,12}$/u.test(diagnostic.signal))
        )
      ) {
        fail("native command failure has an invalid exit code or signal");
      }
      failure = { kind: diagnostic.kind, code: diagnostic.code, signal: diagnostic.signal };
    } else if (
      diagnostic.kind === "command-start" &&
      ["EACCES", "ENOENT", "ENOTDIR", "other"].includes(diagnostic.reason)
    ) {
      failure = { kind: diagnostic.kind, reason: diagnostic.reason };
    } else if (
      diagnostic.kind === "guard-termination" &&
      [
        "disk",
        "disk-growth",
        "resource-monitor-error",
        "output",
        "timeout",
        "interrupted",
      ].includes(diagnostic.terminationKind)
    ) {
      failure = { kind: diagnostic.kind, terminationKind: diagnostic.terminationKind };
    } else if (
      diagnostic.kind === "output-validation" &&
      ["timing-unreadable", "timing-malformed", "timing-incomplete"].includes(diagnostic.reason)
    ) {
      failure = { kind: diagnostic.kind, reason: diagnostic.reason };
    } else {
      fail("native command failure has an unsupported classification");
    }
    Object.defineProperty(this, "nativeFailure", { value: Object.freeze(failure) });
  }
}

function fail(message) {
  throw new Error(`Convex Wasm artifact pipeline: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function defaultStageWorkingSetEstimateBytes(stagePolicy) {
  // Only an authenticated source size may replace the conservative generated-C fallback.
  if (stagePolicy.schedulingClass === "generated-c") {
    return GENERATED_C_FALLBACK_WORKING_SET_ESTIMATE_BYTES;
  }
  return stagePolicy.workingSetEstimateBytes;
}

function workingSetEstimateWithHeadroomBytes(estimateBytes) {
  return Math.ceil(
    (estimateBytes * WORKING_SET_HEADROOM_NUMERATOR) /
      WORKING_SET_HEADROOM_DENOMINATOR
  );
}

function effectiveNativePhaseWorkerSlots(
  stagePolicy,
  requestedWorkerSlots,
  inputWorkingSetEstimateBytes
) {
  if (inputWorkingSetEstimateBytes === undefined || !stagePolicy.schedulingClass.endsWith("aot")) {
    return requestedWorkerSlots;
  }
  // Leaf compilation reserves its requested CPU slots; memory admission remains input-sized.
  // Shared shards retain proportional workers so broad builds can run independent shards.
  if (stagePolicy.schedulingClass === "module-graph-leaf-wasmtime-aot") {
    return requestedWorkerSlots;
  }
  // Scale shared AOT workers with the authenticated input-sized estimate while retaining the
  // caller's configured AOT ceiling.
  return Math.min(
    requestedWorkerSlots,
    Math.max(1, Math.ceil(inputWorkingSetEstimateBytes / AOT_MINIMUM_WORKING_SET_ESTIMATE_BYTES))
  );
}

// This conservative estimate orders native work. The aggregate memory boundary remains the
// caller's configured limit; this estimate is not an artifact input or per-process memory limit.
export function convexWasmNativeAotWorkingSetEstimateBytes(coreWasmBytes) {
  const normalizedCoreWasmBytes = requirePositiveInteger(coreWasmBytes, "Core Wasm byte size");
  if (
    normalizedCoreWasmBytes >
    Math.floor(Number.MAX_SAFE_INTEGER / AOT_WORKING_SET_BYTES_PER_CORE_WASM_BYTE)
  ) {
    fail("Core Wasm byte size produces an unsafe AOT working-set estimate");
  }
  return Math.max(
    AOT_MINIMUM_WORKING_SET_ESTIMATE_BYTES,
    normalizedCoreWasmBytes * AOT_WORKING_SET_BYTES_PER_CORE_WASM_BYTE
  );
}

// Generated JavaScript size is already authenticated artifact identity. This conservative
// source-size estimate affects scheduling only, not the artifact or its identity.
export function convexWasmNativeGeneratedCWorkingSetEstimateBytes(generatedJavaScriptBytes) {
  const normalizedGeneratedJavaScriptBytes = requirePositiveInteger(
    generatedJavaScriptBytes,
    "generated JavaScript byte size"
  );
  if (
    normalizedGeneratedJavaScriptBytes >
    Math.floor(
      Number.MAX_SAFE_INTEGER /
        (GENERATED_C_WORKING_SET_BYTES_PER_SOURCE_BYTE * WORKING_SET_HEADROOM_NUMERATOR)
    )
  ) {
    fail("generated JavaScript byte size produces an unsafe generated-C working-set estimate");
  }
  return workingSetEstimateWithHeadroomBytes(
    Math.max(
      GENERATED_C_MINIMUM_WORKING_SET_ESTIMATE_BYTES,
      normalizedGeneratedJavaScriptBytes * GENERATED_C_WORKING_SET_BYTES_PER_SOURCE_BYTE
    )
  );
}

// These generic defaults control scheduling and telemetry only. The configured aggregate memory
// boundary decides whether a command fits; changing an estimate cannot invalidate an artifact.
const nativePhaseSchedulingStages = Object.freeze({
  "capability-bridge-generated-c": Object.freeze({
    schedulingClass: "generated-c",
    workingSetEstimateBytes: 1024 * MEBIBYTE,
  }),
  "capability-bridge-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 512 * MEBIBYTE,
  }),
  "cohort-selector-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 256 * MEBIBYTE,
  }),
  "console-formatter-generated-c": Object.freeze({
    schedulingClass: "generated-c",
    workingSetEstimateBytes: 1024 * MEBIBYTE,
  }),
  "console-formatter-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 256 * MEBIBYTE,
  }),
  "core-wasm": Object.freeze({
    schedulingClass: "link",
    workingSetEstimateBytes: 1024 * MEBIBYTE,
  }),
  "export-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 2048 * MEBIBYTE,
  }),
  "module-graph-application-pic-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 512 * 1024 * 1024,
  }),
  "static-hermes-runtime-prelude-pch": Object.freeze({
    schedulingClass: "object",
    // PCH construction runs the same Clang frontend and profile flags as an application member.
    workingSetEstimateBytes: 512 * 1024 * 1024,
  }),
  "module-graph-support-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 512 * MEBIBYTE,
  }),
  "generated-c": Object.freeze({
    schedulingClass: "generated-c",
    workingSetEstimateBytes: 1024 * MEBIBYTE,
  }),
  [C_OPTIMIZATION_LEVEL_ZERO_STAGE]: Object.freeze({
    schedulingClass: "c-optimization-level-zero-object",
    workingSetEstimateBytes: 1024 * MEBIBYTE,
  }),
  "runtime-main-object": Object.freeze({
    schedulingClass: "object",
    workingSetEstimateBytes: 256 * MEBIBYTE,
  }),
  "wasmtime-aot": Object.freeze({
    schedulingClass: "aot",
    workingSetEstimateBytes: 512 * MEBIBYTE,
  }),
  "module-graph-common-wasmtime-aot": Object.freeze({
    schedulingClass: "module-graph-common-wasmtime-aot",
    workingSetEstimateBytes: AOT_MINIMUM_WORKING_SET_ESTIMATE_BYTES,
  }),
  "module-graph-shared-wasmtime-aot": Object.freeze({
    schedulingClass: "module-graph-shared-wasmtime-aot",
    workingSetEstimateBytes: AOT_MINIMUM_WORKING_SET_ESTIMATE_BYTES,
  }),
  "module-graph-leaf-wasmtime-aot": Object.freeze({
    schedulingClass: "module-graph-leaf-wasmtime-aot",
    workingSetEstimateBytes: AOT_MINIMUM_WORKING_SET_ESTIMATE_BYTES,
  }),
});

export const convexWasmNativePhaseSchedulingPolicy = Object.freeze({
  kind: "convex-wasm-native-phase-scheduling-policy-v1",
  stages: nativePhaseSchedulingStages,
});

function nativePhaseSchedulingStat(name, schedulingClass) {
  return {
    activeCount: 0,
    activeWorkingSetEstimateBytes: 0,
    completedCount: 0,
    failedCount: 0,
    maximumActiveCount: 0,
    maximumEstimatedWorkingSetBytes: 0,
    maximumQueuedCount: 0,
    maximumQueueWaitMilliseconds: 0,
    name,
    queuedCount: 0,
    requestCount: 0,
    schedulingClass,
    resourceUsage: {
      maximumRssKiB: 0,
      systemCpuMilliseconds: 0,
      userCpuMilliseconds: 0,
      wallMilliseconds: 0,
    },
    totalQueueWaitMilliseconds: 0,
  };
}

function nativePhaseSchedulingStatReport(stat) {
  return {
    completedCount: stat.completedCount,
    failedCount: stat.failedCount,
    maximumActiveCount: stat.maximumActiveCount,
    maximumEstimatedWorkingSetBytes: stat.maximumEstimatedWorkingSetBytes,
    maximumQueuedCount: stat.maximumQueuedCount,
    maximumQueueWaitMilliseconds: stat.maximumQueueWaitMilliseconds,
    name: stat.name,
    requestCount: stat.requestCount,
    schedulingClass: stat.schedulingClass,
    resourceUsage:
      stat.completedCount === 0
        ? null
        : {
            maximumRssKiB: stat.resourceUsage.maximumRssKiB,
            systemCpuMilliseconds: stat.resourceUsage.systemCpuMilliseconds,
            userCpuMilliseconds: stat.resourceUsage.userCpuMilliseconds,
            wallMilliseconds: stat.resourceUsage.wallMilliseconds,
          },
    totalQueueWaitMilliseconds: stat.totalQueueWaitMilliseconds,
  };
}

function requireNativePhaseTiming(timing, stage) {
  if (typeof timing !== "object" || timing === null || Array.isArray(timing)) {
    throw new ConvexWasmNativeCommandFailure(
      `Convex Wasm artifact pipeline: ${stage} native phase did not return resource timing`,
      { kind: "output-validation", reason: "timing-incomplete" }
    );
  }
  for (const field of [
    "maxRssKiB",
    "systemCpuMilliseconds",
    "userCpuMilliseconds",
    "wallMilliseconds",
  ]) {
    if (typeof timing[field] !== "number" || !Number.isFinite(timing[field]) || timing[field] < 0) {
      throw new ConvexWasmNativeCommandFailure(
        `Convex Wasm artifact pipeline: ${stage} native phase timing ${field} must be a nonnegative finite number`,
        { kind: "output-validation", reason: "timing-incomplete" }
      );
    }
  }
  return timing;
}

export function normalizeConvexWasmNativeLaunchPolicy(launchPolicy) {
  requireExactPlainObject(
    launchPolicy,
    ["aggregateMemoryMaxBytes", "aotWorkers", "jobs"],
    "native launch policy"
  );
  const aggregateMemoryMaxBytes = requirePositiveInteger(
    launchPolicy.aggregateMemoryMaxBytes,
    "native launch aggregate memory budget"
  );
  const aotWorkers = requirePositiveInteger(launchPolicy.aotWorkers, "native launch AOT workers");
  const jobs = requirePositiveInteger(launchPolicy.jobs, "native launch jobs");
  if (aotWorkers > jobs) fail("native launch AOT workers must not exceed jobs");
  return Object.freeze({ aggregateMemoryMaxBytes, aotWorkers, jobs });
}

export function createConvexWasmNativePhaseScheduler(launchPolicy) {
  const normalizedLaunchPolicy = normalizeConvexWasmNativeLaunchPolicy(launchPolicy);
  let activeCount = 0;
  let activeAdmissionWorkingSetEstimateBytes = 0;
  let activeWorkerSlots = 0;
  let activeWorkingSetEstimateBytes = 0;
  let completedCount = 0;
  let failedCount = 0;
  let maximumActiveCount = 0;
  let maximumActiveWorkerSlots = 0;
  let maximumEstimatedWorkingSetBytes = 0;
  let maximumQueuedCount = 0;
  let maximumQueueWaitMilliseconds = 0;
  let requestCount = 0;
  let hasSchedulingFailure = false;
  let schedulingFailure;
  let totalQueueWaitMilliseconds = 0;
  const criticalPathStartedAt = process.hrtime.bigint();
  let criticalPathLastStateAt = criticalPathStartedAt;
  const criticalPathEvents = [];
  let criticalPathDroppedEventCount = 0;
  const criticalPathIntervals = [];
  let criticalPathDroppedIntervalCount = 0;
  let criticalPathActiveCommandMilliseconds = 0;
  let criticalPathActiveWorkerSlotMilliseconds = 0;
  let criticalPathIdleNoNativeWorkMilliseconds = 0;
  const criticalPathQueuedStateMilliseconds = {
    fairness: 0,
    memory: 0,
    none: 0,
    runnable: 0,
    "worker-slots": 0,
    "worker-slots-and-memory": 0,
  };
  const classStats = new Map();
  const idleWaiters = new Set();
  const queue = [];
  const stageStats = new Map();
  let backfilledHead;
  let backfilledWorkerSlots = 0;
  const elapsedCriticalPathMilliseconds = (at) => Number(at - criticalPathStartedAt) / 1_000_000;
  // Reports need stage-level causality, not executable arguments, cache keys, or scratch paths.
  const appendCriticalPathEvent = (event) => {
    if (criticalPathEvents.length < CRITICAL_PATH_EVENT_LIMIT) {
      criticalPathEvents.push(event);
      return;
    }
    criticalPathDroppedEventCount += 1;
  };
  const queueState = () => {
    const head = queue[0];
    if (head === undefined) {
      return "none";
    }
    if (canAdmit(head)) {
      return "runnable";
    }
    const remainingBackfillWorkerSlots =
      normalizedLaunchPolicy.jobs - 1 - (backfilledHead === head ? backfilledWorkerSlots : 0);
    if (
      queue.some(
        (entry, index) =>
          index > 0 && canAdmit(entry) && entry.workerSlots > remainingBackfillWorkerSlots
      )
    ) {
      return "fairness";
    }
    const workerSlotsBlocked = activeWorkerSlots + head.workerSlots > normalizedLaunchPolicy.jobs;
    const memoryBlocked =
      activeAdmissionWorkingSetEstimateBytes + head.admissionWorkingSetEstimateBytes >
      normalizedLaunchPolicy.aggregateMemoryMaxBytes;
    if (workerSlotsBlocked && memoryBlocked) {
      return "worker-slots-and-memory";
    }
    if (workerSlotsBlocked) {
      return "worker-slots";
    }
    if (memoryBlocked) {
      return "memory";
    }
    fail("native-phase scheduler retained a queue entry without an admission state");
  };
  const recordCriticalPathState = () => {
    const endedAt = process.hrtime.bigint();
    const durationMilliseconds = Number(endedAt - criticalPathLastStateAt) / 1_000_000;
    if (durationMilliseconds > 0) {
      const state = {
        activeCommandCount: activeCount,
        admissionWorkingSetEstimateBytes: activeAdmissionWorkingSetEstimateBytes,
        activeWorkerSlots,
        estimatedWorkingSetBytes: activeWorkingSetEstimateBytes,
        queueState: queueState(),
        queuedCommandCount: queue.length,
      };
      const prior = criticalPathIntervals.at(-1);
      if (
        prior !== undefined &&
        prior.activeCommandCount === state.activeCommandCount &&
        prior.admissionWorkingSetEstimateBytes === state.admissionWorkingSetEstimateBytes &&
        prior.activeWorkerSlots === state.activeWorkerSlots &&
        prior.estimatedWorkingSetBytes === state.estimatedWorkingSetBytes &&
        prior.queueState === state.queueState &&
        prior.queuedCommandCount === state.queuedCommandCount
      ) {
        prior.endedAtMilliseconds = elapsedCriticalPathMilliseconds(endedAt);
      } else {
        if (criticalPathIntervals.length < CRITICAL_PATH_EVENT_LIMIT) {
          criticalPathIntervals.push({
            ...state,
            endedAtMilliseconds: elapsedCriticalPathMilliseconds(endedAt),
            startedAtMilliseconds: elapsedCriticalPathMilliseconds(criticalPathLastStateAt),
          });
        } else {
          criticalPathDroppedIntervalCount += 1;
        }
      }
      criticalPathActiveCommandMilliseconds += durationMilliseconds * activeCount;
      criticalPathActiveWorkerSlotMilliseconds += durationMilliseconds * activeWorkerSlots;
      if (activeCount === 0 && queue.length === 0) {
        criticalPathIdleNoNativeWorkMilliseconds += durationMilliseconds;
      }
      if (queue.length > 0) {
        criticalPathQueuedStateMilliseconds[queueState()] += durationMilliseconds;
      }
    }
    criticalPathLastStateAt = endedAt;
    return endedAt;
  };
  const resolveIdleWaiters = () => {
    if (activeCount !== 0 || queue.length !== 0) return;
    for (const resolve of idleWaiters) resolve();
    idleWaiters.clear();
  };
  const statFor = (stats, name, schedulingClass) => {
    let stat = stats.get(name);
    if (stat === undefined) {
      stat = nativePhaseSchedulingStat(name, schedulingClass);
      stats.set(name, stat);
    }
    return stat;
  };
  const updateStats = (entry, update) => {
    update(entry.stageStat);
    update(entry.classStat);
  };
  const canAdmit = (entry) =>
    activeWorkerSlots + entry.workerSlots <= normalizedLaunchPolicy.jobs &&
    activeAdmissionWorkingSetEstimateBytes + entry.admissionWorkingSetEstimateBytes <=
      normalizedLaunchPolicy.aggregateMemoryMaxBytes;
  const dequeueNextAdmissible = () => {
    const head = queue[0];
    if (head === undefined) {
      return undefined;
    }
    if (canAdmit(head)) {
      queue.shift();
      if (backfilledHead === head) {
        backfilledHead = undefined;
        backfilledWorkerSlots = 0;
      }
      return head;
    }
    // A blocked normal head may admit one bounded wave of earliest fitting followers. Charge the
    // wave by worker slots and retain the charge until the head runs. This fills otherwise idle
    // slots without allowing a continuing stream of small tasks to starve the head.
    if (backfilledHead !== head) {
      backfilledHead = head;
      backfilledWorkerSlots = 0;
    }
    const remainingBackfillWorkerSlots = normalizedLaunchPolicy.jobs - 1 - backfilledWorkerSlots;
    const backfillIndex = queue.findIndex(
      (entry, index) =>
        index > 0 && entry.workerSlots <= remainingBackfillWorkerSlots && canAdmit(entry)
    );
    if (backfillIndex < 0) {
      return undefined;
    }
    const [backfill] = queue.splice(backfillIndex, 1);
    backfilledWorkerSlots += backfill.workerSlots;
    return backfill;
  };
  const drain = () => {
    if (hasSchedulingFailure) {
      recordCriticalPathState();
      for (const entry of queue.splice(0)) {
        updateStats(entry, (stat) => {
          stat.queuedCount -= 1;
        });
        entry.reject(schedulingFailure);
      }
      resolveIdleWaiters();
      return;
    }
    while (queue.length > 0) {
      recordCriticalPathState();
      const entry = dequeueNextAdmissible();
      if (entry === undefined) {
        return;
      }
      const startedAt = process.hrtime.bigint();
      const queueWaitMilliseconds = Number(startedAt - entry.queuedAt) / 1_000_000;
      activeAdmissionWorkingSetEstimateBytes += entry.admissionWorkingSetEstimateBytes;
      activeWorkingSetEstimateBytes += entry.workingSetEstimateBytes;
      activeCount += 1;
      activeWorkerSlots += entry.workerSlots;
      maximumActiveCount = Math.max(maximumActiveCount, activeCount);
      maximumActiveWorkerSlots = Math.max(maximumActiveWorkerSlots, activeWorkerSlots);
      maximumEstimatedWorkingSetBytes = Math.max(
        maximumEstimatedWorkingSetBytes,
        activeWorkingSetEstimateBytes
      );
      maximumQueueWaitMilliseconds = Math.max(maximumQueueWaitMilliseconds, queueWaitMilliseconds);
      totalQueueWaitMilliseconds += queueWaitMilliseconds;
      updateStats(entry, (stat) => {
        stat.activeCount += 1;
        // Input-sized AOT requests in one stage/class can have different estimates. Track their
        // exact active sum instead of multiplying the largest observed estimate by active count.
        stat.activeWorkingSetEstimateBytes += entry.workingSetEstimateBytes;
        stat.queuedCount -= 1;
        stat.maximumActiveCount = Math.max(stat.maximumActiveCount, stat.activeCount);
        stat.maximumEstimatedWorkingSetBytes = Math.max(
          stat.maximumEstimatedWorkingSetBytes,
          stat.activeWorkingSetEstimateBytes
        );
        stat.maximumQueueWaitMilliseconds = Math.max(
          stat.maximumQueueWaitMilliseconds,
          queueWaitMilliseconds
        );
        stat.totalQueueWaitMilliseconds += queueWaitMilliseconds;
      });
      void (async () => {
        let outcome = "completed";
        let failure;
        try {
          const timing = requireNativePhaseTiming(
            await nativeCommandWorkerSlots.run(entry.workerSlots, entry.operation),
            entry.stage
          );
          completedCount += 1;
          updateStats(entry, (stat) => {
            stat.completedCount += 1;
            stat.resourceUsage.maximumRssKiB = Math.max(
              stat.resourceUsage.maximumRssKiB,
              timing.maxRssKiB
            );
            stat.resourceUsage.systemCpuMilliseconds += timing.systemCpuMilliseconds;
            stat.resourceUsage.userCpuMilliseconds += timing.userCpuMilliseconds;
            stat.resourceUsage.wallMilliseconds += timing.wallMilliseconds;
          });
          entry.resolve(timing);
        } catch (error) {
          outcome = "failed";
          if (error instanceof ConvexWasmNativeCommandFailure) failure = error.nativeFailure;
          failedCount += 1;
          // The first admission-closing failure rejects queued and future work. Active siblings
          // still drain and report their own outcomes without replacing that rejection reason.
          if (entry.failureClosesAdmission && !hasSchedulingFailure) {
            hasSchedulingFailure = true;
            schedulingFailure = error;
          }
          updateStats(entry, (stat) => {
            stat.failedCount += 1;
          });
          entry.reject(error);
        } finally {
          const finishedAt = recordCriticalPathState();
          appendCriticalPathEvent({
            ...(failure === undefined ? {} : { failure }),
            admissionWorkingSetEstimateBytes: entry.admissionWorkingSetEstimateBytes,
            endedAtMilliseconds: elapsedCriticalPathMilliseconds(finishedAt),
            kind: "native-phase",
            outcome,
            queuedAtMilliseconds: elapsedCriticalPathMilliseconds(entry.queuedAt),
            stage: entry.stage,
            startedAtMilliseconds: elapsedCriticalPathMilliseconds(startedAt),
            workerSlots: entry.workerSlots,
            workingSetEstimateBytes: entry.workingSetEstimateBytes,
          });
          activeAdmissionWorkingSetEstimateBytes -= entry.admissionWorkingSetEstimateBytes;
          activeWorkingSetEstimateBytes -= entry.workingSetEstimateBytes;
          activeCount -= 1;
          activeWorkerSlots -= entry.workerSlots;
          updateStats(entry, (stat) => {
            stat.activeCount -= 1;
            stat.activeWorkingSetEstimateBytes -= entry.workingSetEstimateBytes;
          });
          drain();
          resolveIdleWaiters();
        }
      })();
    }
  };
  return Object.freeze({
    get activeCount() {
      return activeCount;
    },
    get activeAdmissionWorkingSetEstimateBytes() {
      return activeAdmissionWorkingSetEstimateBytes;
    },
    get activeWorkingSetEstimateBytes() {
      return activeWorkingSetEstimateBytes;
    },
    get activeWorkerSlots() {
      return activeWorkerSlots;
    },
    idle() {
      if (activeCount === 0 && queue.length === 0) return Promise.resolve();
      return new Promise((resolve) => idleWaiters.add(resolve));
    },
    launchPolicy: normalizedLaunchPolicy,
    get queuedCount() {
      return queue.length;
    },
    beginCriticalPathActivity(activity, stage) {
      requireString(activity, "critical-path activity");
      requireString(stage, "critical-path activity stage");
      const startedAt = process.hrtime.bigint();
      let finished = false;
      return Object.freeze({
        finish({ cache, outcome = "completed" } = {}) {
          if (finished) {
            fail("critical-path activity was already finished");
          }
          if (cache !== undefined && cache !== "hit" && cache !== "miss") {
            fail("critical-path activity cache outcome must be hit or miss");
          }
          if (outcome !== "completed" && outcome !== "failed") {
            fail("critical-path activity outcome must be completed or failed");
          }
          finished = true;
          const endedAt = process.hrtime.bigint();
          appendCriticalPathEvent({
            activity,
            ...(cache === undefined ? {} : { cache }),
            endedAtMilliseconds: elapsedCriticalPathMilliseconds(endedAt),
            kind: "external-activity",
            outcome,
            stage,
            startedAtMilliseconds: elapsedCriticalPathMilliseconds(startedAt),
          });
        },
      });
    },
    report() {
      const reportedAt = recordCriticalPathState();
      return {
        classes: [...classStats.values()]
          .sort((left, right) => compareStrings(left.name, right.name))
          .map(nativePhaseSchedulingStatReport),
        completedCount,
        failedCount,
        kind: "convex-wasm-native-phase-scheduling-report-v1",
        maximumActiveCount,
        maximumActiveWorkerSlots,
        maximumEstimatedWorkingSetBytes,
        maximumQueuedCount,
        maximumQueueWaitMilliseconds,
        launchPolicy: normalizedLaunchPolicy,
        policy: convexWasmNativePhaseSchedulingPolicy,
        requestCount,
        stages: [...stageStats.values()]
          .sort((left, right) => compareStrings(left.name, right.name))
          .map(nativePhaseSchedulingStatReport),
        totalQueueWaitMilliseconds,
        criticalPath: {
          // A report is archival evidence: future scheduler work may append events, coalesce an
          // interval endpoint, and accumulate queue totals without changing this snapshot.
          activeCommandMilliseconds: criticalPathActiveCommandMilliseconds,
          activeWorkerSlotMilliseconds: criticalPathActiveWorkerSlotMilliseconds,
          droppedEventCount: criticalPathDroppedEventCount,
          droppedIntervalCount: criticalPathDroppedIntervalCount,
          elapsedWallMilliseconds: elapsedCriticalPathMilliseconds(reportedAt),
          eventLimit: CRITICAL_PATH_EVENT_LIMIT,
          events: criticalPathEvents.map((event) => ({ ...event })),
          idleNoNativeWorkMilliseconds: criticalPathIdleNoNativeWorkMilliseconds,
          intervals: criticalPathIntervals.map((interval) => ({ ...interval })),
          kind: "convex-wasm-native-phase-critical-path-v1",
          queuedStateMilliseconds: { ...criticalPathQueuedStateMilliseconds },
        },
      };
    },
    run(
      stage,
      operation,
      { failureClosesAdmission = true, workerSlots = 1, workingSetEstimateBytes } = {}
    ) {
      requireString(stage, "native-phase scheduling stage");
      if (typeof operation !== "function") {
        fail("native-phase scheduling operation must be a function");
      }
      if (typeof failureClosesAdmission !== "boolean") {
        fail("native-phase scheduling failureClosesAdmission must be a boolean");
      }
      const stagePolicy = nativePhaseSchedulingStages[stage];
      if (stagePolicy === undefined) {
        fail(`native-phase scheduling stage ${JSON.stringify(stage)} is unsupported`);
      }
      requirePositiveInteger(workerSlots, "native-phase scheduling worker slots");
      const effectiveWorkingSetEstimateBytes =
        workingSetEstimateBytes === undefined
          ? defaultStageWorkingSetEstimateBytes(stagePolicy)
          : requirePositiveInteger(
              workingSetEstimateBytes,
              "native-phase scheduling working-set estimate"
            );
      const effectiveWorkerSlots = effectiveNativePhaseWorkerSlots(
        stagePolicy,
        workerSlots,
        workingSetEstimateBytes
      );
      if (workerSlots > normalizedLaunchPolicy.jobs) {
        fail(
          `native-phase scheduling worker slots ${workerSlots} exceed launch jobs ${normalizedLaunchPolicy.jobs}`
        );
      }
      if (
        stagePolicy.schedulingClass.endsWith("aot") &&
        workerSlots > normalizedLaunchPolicy.aotWorkers
      ) {
        fail(
          `native-phase scheduling AOT worker slots ${workerSlots} exceed configured AOT workers ${normalizedLaunchPolicy.aotWorkers}`
        );
      }
      if (hasSchedulingFailure) {
        return Promise.reject(schedulingFailure);
      }
      // Estimates order work inside the aggregate no-swap slice; they are not a second memory
      // limit. Charge an estimate larger than the slice as the whole slice so it runs alone and
      // the cgroup remains the authoritative boundary. Rejecting it here can waste all earlier
      // compilation before an input-sized AOT estimate becomes known, while never testing whether
      // the bounded command actually fits.
      const admissionWorkingSetEstimateBytes = Math.min(
        effectiveWorkingSetEstimateBytes,
        normalizedLaunchPolicy.aggregateMemoryMaxBytes
      );
      const stageStat = statFor(stageStats, stage, stagePolicy.schedulingClass);
      const classStat = statFor(
        classStats,
        stagePolicy.schedulingClass,
        stagePolicy.schedulingClass
      );
      requestCount += 1;
      stageStat.requestCount += 1;
      classStat.requestCount += 1;
      stageStat.queuedCount += 1;
      classStat.queuedCount += 1;
      stageStat.maximumQueuedCount = Math.max(stageStat.maximumQueuedCount, stageStat.queuedCount);
      classStat.maximumQueuedCount = Math.max(classStat.maximumQueuedCount, classStat.queuedCount);
      return new Promise((resolve, reject) => {
        recordCriticalPathState();
        queue.push({
          classStat,
          failureClosesAdmission,
          operation,
          queuedAt: process.hrtime.bigint(),
          reject,
          admissionWorkingSetEstimateBytes,
          workerSlots: effectiveWorkerSlots,
          workingSetEstimateBytes: effectiveWorkingSetEstimateBytes,
          resolve,
          stage,
          stageStat,
        });
        maximumQueuedCount = Math.max(maximumQueuedCount, queue.length);
        drain();
      });
    },
  });
}

export function convexWasmNativeCommandArguments(command, launchPolicy) {
  const configuredWorkerSlots = convexWasmNativeCommandWorkerSlots(command, launchPolicy);
  if (command.args[0] !== "--package") return command.args;
  const operationalWorkerSlots = nativeCommandWorkerSlots.getStore() ?? configuredWorkerSlots;
  if (operationalWorkerSlots > configuredWorkerSlots) {
    fail(
      `native command worker slots ${operationalWorkerSlots} exceed configured AOT workers ${configuredWorkerSlots}`
    );
  }
  return [...command.args, "--parallel-compilation-workers", String(operationalWorkerSlots)];
}

export function convexWasmNativeCommandWorkerSlots(command, launchPolicy) {
  if (
    !Array.isArray(command?.args) ||
    command.args.some((argument) => typeof argument !== "string")
  ) {
    fail("native command arguments must be an array of strings");
  }
  const normalizedLaunchPolicy = normalizeConvexWasmNativeLaunchPolicy(launchPolicy);
  return command.args[0] === "--package" ? normalizedLaunchPolicy.aotWorkers : 1;
}
