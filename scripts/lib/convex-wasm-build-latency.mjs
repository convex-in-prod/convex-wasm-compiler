const ANALYZER_NAME = "Convex Wasm build latency analyzer";

function fail(message) {
  throw new Error(`${ANALYZER_NAME}: ${message}`);
}

function requireObject(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`);
  }
  return value;
}

function requireFiniteNumber(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    fail(`${label} must be a finite number`);
  }
  return value;
}

function requireNonNegativeNumber(value, label) {
  const number = requireFiniteNumber(value, label);
  if (number < 0) {
    fail(`${label} must be non-negative`);
  }
  return number;
}

function requireString(value, label) {
  if (typeof value !== "string") {
    fail(`${label} must be a string`);
  }
  return value;
}

function countBy(values, keyForValue) {
  const counts = new Map();
  for (const value of values) {
    const key = keyForValue(value);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function cacheCounts(records, label) {
  const counts = countBy(records, (record) => {
    requireObject(record, `${label} record`);
    if (typeof record.stage !== "string" || typeof record.cache !== "string") {
      fail(`${label} records must contain string stage and cache fields`);
    }
    return `${record.stage}\0${record.cache}`;
  });
  return [...counts.entries()]
    .map(([key, count]) => {
      const [stage, cache] = key.split("\0");
      return { cache, count, stage };
    })
    .sort((left, right) =>
      left.stage === right.stage
        ? left.cache.localeCompare(right.cache)
        : left.stage.localeCompare(right.stage)
    );
}

function outcomeCounts(records, field, label) {
  const counts = countBy(records, (record) => {
    requireObject(record, label);
    if (typeof record[field] !== "string") {
      fail(`${label} must contain string ${field}`);
    }
    return record[field];
  });
  return [...counts.entries()]
    .map(([outcome, count]) => ({ count, outcome }))
    .sort((left, right) => left.outcome.localeCompare(right.outcome));
}

function uniqueStringCount(records, field, label) {
  const values = new Set();
  for (const record of records) {
    requireObject(record, label);
    if (typeof record[field] !== "string") {
      fail(`${label} must contain string ${field}`);
    }
    values.add(record[field]);
  }
  return values.size;
}

function sumResourceCpuMilliseconds(stages) {
  return stages.reduce((total, stage, index) => {
    const resourceUsage = requireObject(stage.resourceUsage, `scheduler stage ${index} resource`);
    return (
      total +
      requireNonNegativeNumber(
        resourceUsage.userCpuMilliseconds,
        `scheduler stage ${index} user CPU`
      ) +
      requireNonNegativeNumber(
        resourceUsage.systemCpuMilliseconds,
        `scheduler stage ${index} system CPU`
      )
    );
  }, 0);
}

function criticalPathEvent(event, index, name) {
  const value = requireObject(event, `${name} critical-path event ${index}`);
  const kind = requireString(value.kind, `${name} critical-path event ${index} kind`);
  if (kind !== "external-activity" && kind !== "native-phase") {
    fail(`${name} critical-path event ${index} has unsupported kind ${JSON.stringify(kind)}`);
  }
  const outcome = requireString(value.outcome, `${name} critical-path event ${index} outcome`);
  if (kind === "native-phase" && outcome !== "completed" && outcome !== "failed") {
    fail(`${name} critical-path event ${index} has no terminal outcome`);
  }
  if (kind === "external-activity" && outcome !== "completed") {
    fail(`${name} critical-path event ${index} did not complete`);
  }
  const startedAtMilliseconds = requireNonNegativeNumber(
    value.startedAtMilliseconds,
    `${name} critical-path event ${index} start`
  );
  const endedAtMilliseconds = requireNonNegativeNumber(
    value.endedAtMilliseconds,
    `${name} critical-path event ${index} end`
  );
  if (endedAtMilliseconds < startedAtMilliseconds) {
    fail(`${name} critical-path event ${index} ends before it starts`);
  }
  if (kind === "external-activity") {
    requireString(value.activity, `${name} critical-path event ${index} activity`);
  }
  requireString(value.stage, `${name} critical-path event ${index} stage`);
  return value;
}

function criticalPathInterval(interval, index, name) {
  const value = requireObject(interval, `${name} critical-path interval ${index}`);
  const startedAtMilliseconds = requireNonNegativeNumber(
    value.startedAtMilliseconds,
    `${name} critical-path interval ${index} start`
  );
  const endedAtMilliseconds = requireNonNegativeNumber(
    value.endedAtMilliseconds,
    `${name} critical-path interval ${index} end`
  );
  if (endedAtMilliseconds < startedAtMilliseconds) {
    fail(`${name} critical-path interval ${index} ends before it starts`);
  }
  return value;
}

function snapshotConsistency(name, scheduling) {
  const criticalPath = requireObject(scheduling.criticalPath, `${name} critical path`);
  const events = requireArray(criticalPath.events, `${name} critical-path events`).map(
    (event, index) => criticalPathEvent(event, index, name)
  );
  const intervals = requireArray(criticalPath.intervals, `${name} critical-path intervals`).map(
    (interval, index) => criticalPathInterval(interval, index, name)
  );
  const droppedEventCount = requireNonNegativeNumber(
    criticalPath.droppedEventCount,
    `${name} dropped event count`
  );
  const droppedIntervalCount = requireNonNegativeNumber(
    criticalPath.droppedIntervalCount,
    `${name} dropped interval count`
  );
  const completedNativeEventCount = events.filter(
    (event) => event.kind === "native-phase" && event.outcome === "completed"
  ).length;
  const failedNativeEventCount = events.filter(
    (event) => event.kind === "native-phase" && event.outcome === "failed"
  ).length;
  const retainedIntervalEndMilliseconds = intervals.reduce(
    (latest, interval, index) =>
      Math.max(
        latest,
        requireNonNegativeNumber(interval.endedAtMilliseconds, `${name} interval ${index} end`)
      ),
    0
  );
  const scalarRequestCount = requireNonNegativeNumber(
    scheduling.requestCount,
    `${name} request count`
  );
  const scalarElapsedWallMilliseconds = requireNonNegativeNumber(
    criticalPath.elapsedWallMilliseconds,
    `${name} elapsed wall time`
  );
  const latestEventEndMilliseconds = events.reduce(
    (latest, event) => Math.max(latest, event.endedAtMilliseconds),
    0
  );
  const assessable = droppedEventCount === 0 && droppedIntervalCount === 0;
  const issues = [];
  if (droppedEventCount !== 0) {
    issues.push("critical-path-events-were-dropped");
  }
  if (droppedIntervalCount !== 0) {
    issues.push("critical-path-intervals-were-dropped");
  }
  // A failed speculative command still consumes a scheduler request and native time.
  // This consistency check does not establish successful output publication.
  if (assessable && scalarRequestCount !== completedNativeEventCount + failedNativeEventCount) {
    issues.push("request-count-does-not-match-retained-terminal-native-events");
  }
  if (
    assessable &&
    Math.abs(scalarElapsedWallMilliseconds - retainedIntervalEndMilliseconds) > 0.001
  ) {
    issues.push("elapsed-wall-does-not-match-retained-interval-end");
  }
  if (assessable && latestEventEndMilliseconds > scalarElapsedWallMilliseconds + 0.001) {
    issues.push("event-ends-after-elapsed-wall");
  }
  return {
    assessable,
    completedNativeEventCount,
    failedNativeEventCount,
    consistent: assessable && issues.length === 0,
    droppedEventCount,
    droppedIntervalCount,
    issues,
    name,
    retainedEventCount: events.length,
    retainedIntervalCount: intervals.length,
    retainedIntervalEndMilliseconds,
    latestEventEndMilliseconds,
    scalarElapsedWallMilliseconds,
    scalarRequestCount,
  };
}

function summarizeScheduler(scheduling) {
  requireObject(scheduling, "final native scheduling report");
  const criticalPath = requireObject(scheduling.criticalPath, "final native critical path");
  const launchPolicy = requireObject(scheduling.launchPolicy, "native launch policy");
  const stages = requireArray(scheduling.stages, "native scheduling stages");
  const elapsedWallMilliseconds = requireNonNegativeNumber(
    criticalPath.elapsedWallMilliseconds,
    "native scheduler elapsed wall time"
  );
  const jobs = requireNonNegativeNumber(launchPolicy.jobs, "native scheduler jobs");
  if (!Number.isInteger(jobs) || jobs === 0) {
    fail("native scheduler jobs must be a positive integer");
  }
  const activeCommandMilliseconds = requireNonNegativeNumber(
    criticalPath.activeCommandMilliseconds,
    "native active-command time"
  );
  const activeWorkerSlotMilliseconds = requireNonNegativeNumber(
    criticalPath.activeWorkerSlotMilliseconds,
    "native active worker-slot time"
  );
  const queuedStateMilliseconds = requireObject(
    criticalPath.queuedStateMilliseconds,
    "native queued-state time"
  );
  const queuedObservedMilliseconds = Object.entries(queuedStateMilliseconds).reduce(
    (total, [state, milliseconds]) =>
      state === "none"
        ? total
        : total + requireNonNegativeNumber(milliseconds, `native ${state} queued-state time`),
    0
  );
  const requestCount = requireNonNegativeNumber(scheduling.requestCount, "native request count");
  if (
    elapsedWallMilliseconds === 0 &&
    (activeCommandMilliseconds !== 0 ||
      activeWorkerSlotMilliseconds !== 0 ||
      queuedObservedMilliseconds !== 0 ||
      requestCount !== 0)
  ) {
    fail("zero-length native scheduler report contains native work");
  }
  const elapsedWallDenominator = elapsedWallMilliseconds === 0 ? 1 : elapsedWallMilliseconds;
  return {
    activeCommandMilliseconds,
    activeWorkerSlotMilliseconds,
    averageActiveCommandCount: activeCommandMilliseconds / elapsedWallDenominator,
    averageActiveWorkerSlots: activeWorkerSlotMilliseconds / elapsedWallDenominator,
    elapsedWallMilliseconds,
    idleNoNativeWorkMilliseconds: requireNonNegativeNumber(
      criticalPath.idleNoNativeWorkMilliseconds,
      "native idle time"
    ),
    jobs,
    maximumActiveCount: requireNonNegativeNumber(
      scheduling.maximumActiveCount,
      "maximum active native commands"
    ),
    maximumActiveWorkerSlots: requireNonNegativeNumber(
      scheduling.maximumActiveWorkerSlots,
      "maximum active native worker slots"
    ),
    maximumEstimatedWorkingSetBytes: requireNonNegativeNumber(
      scheduling.maximumEstimatedWorkingSetBytes,
      "maximum estimated native working set"
    ),
    memoryAdmissionFraction:
      requireNonNegativeNumber(
        scheduling.maximumEstimatedWorkingSetBytes,
        "maximum estimated native working set"
      ) /
      requireNonNegativeNumber(
        launchPolicy.aggregateMemoryMaxBytes,
        "aggregate memory admission limit"
      ),
    nativeCommandSlotUtilizationFraction:
      activeCommandMilliseconds / (elapsedWallDenominator * jobs),
    queuedObservedMilliseconds,
    queuedStateMilliseconds: Object.fromEntries(
      Object.entries(queuedStateMilliseconds).sort(([left], [right]) => left.localeCompare(right))
    ),
    requestCount,
    reportedProcessCpuMilliseconds: sumResourceCpuMilliseconds(stages),
    stages: stages.map((stage, index) => {
      requireObject(stage, `scheduler stage ${index}`);
      const resourceUsage = requireObject(
        stage.resourceUsage,
        `scheduler stage ${index} resource usage`
      );
      return {
        maximumActiveCount: requireNonNegativeNumber(
          stage.maximumActiveCount,
          `scheduler stage ${index} maximum active count`
        ),
        maximumQueueWaitMilliseconds: requireNonNegativeNumber(
          stage.maximumQueueWaitMilliseconds,
          `scheduler stage ${index} maximum queue wait`
        ),
        name: stage.name,
        requestCount: requireNonNegativeNumber(
          stage.requestCount,
          `scheduler stage ${index} request count`
        ),
        resourceMaximumRssKiB: requireNonNegativeNumber(
          resourceUsage.maximumRssKiB,
          `scheduler stage ${index} maximum RSS`
        ),
        resourceSystemCpuMilliseconds: requireNonNegativeNumber(
          resourceUsage.systemCpuMilliseconds,
          `scheduler stage ${index} system CPU`
        ),
        resourceUserCpuMilliseconds: requireNonNegativeNumber(
          resourceUsage.userCpuMilliseconds,
          `scheduler stage ${index} user CPU`
        ),
        resourceWallMilliseconds: requireNonNegativeNumber(
          resourceUsage.wallMilliseconds,
          `scheduler stage ${index} resource wall time`
        ),
        totalQueueWaitMilliseconds: requireNonNegativeNumber(
          stage.totalQueueWaitMilliseconds,
          `scheduler stage ${index} total queue wait`
        ),
      };
    }),
    workerSlotUtilizationFraction: activeWorkerSlotMilliseconds / (elapsedWallDenominator * jobs),
  };
}

function roleCategory(role) {
  if (role === "base" || role === "leaf") {
    return role;
  }
  if (typeof role === "string" && role.startsWith("shared-")) {
    return "shared";
  }
  fail(`unknown module-graph role ${JSON.stringify(role)}`);
}

function summarizeModuleTopology(graphs) {
  const modules = graphs.flatMap((graph, graphIndex) => {
    const buildReport = requireObject(graph.buildReport, `module graph ${graphIndex} build report`);
    return requireArray(buildReport.modules, `module graph ${graphIndex} modules`);
  });
  const categories = countBy(modules, (module) => roleCategory(module.role));
  const coreWasm = modules.map((module, index) =>
    requireObject(module.coreWasm, `module reference ${index} Core Wasm`)
  );
  const aot = modules.map((module, index) =>
    requireObject(module.aot, `module reference ${index} AOT`)
  );
  const aotWithMaterialKey = aot.filter((record) => typeof record.materialCacheKey === "string");
  return {
    aotCacheOutcomes: outcomeCounts(aot, "cache", "module AOT record"),
    coreWasmCacheOutcomes: outcomeCounts(coreWasm, "cache", "module Core Wasm record"),
    moduleReferences: modules.length,
    referencesByRole: ["base", "shared", "leaf"].map((role) => ({
      references: categories.get(role) ?? 0,
      role,
    })),
    uniqueAotCacheKeys: uniqueStringCount(aot, "cacheKey", "module AOT record"),
    uniqueAotMaterialCacheKeys:
      aotWithMaterialKey.length === 0
        ? 0
        : uniqueStringCount(aotWithMaterialKey, "materialCacheKey", "module AOT material record"),
    uniqueCoreWasmCacheKeys: uniqueStringCount(coreWasm, "cacheKey", "module Core Wasm record"),
  };
}

function moduleGraphs(buildReport, label) {
  return requireArray(
    requireObject(
      requireObject(buildReport.moduleGraphArtifact, `${label} module-graph artifact`).buildReport,
      `${label} module-graph build report`
    ).graphs,
    `${label} module graphs`
  );
}

function graphIdentityMap(graphs, label) {
  const identities = new Map();
  for (const [index, graph] of graphs.entries()) {
    requireObject(graph, `${label} graph ${index}`);
    if (typeof graph.cohortId !== "string" || typeof graph.graphManifestSha256 !== "string") {
      fail(`${label} graph ${index} must contain string cohort and package identities`);
    }
    if (identities.has(graph.cohortId)) {
      fail(`${label} contains duplicate cohort identity ${graph.cohortId}`);
    }
    identities.set(graph.cohortId, graph.graphManifestSha256);
  }
  return identities;
}

function compareBuildTopology(currentBuildReport, baselineReport) {
  const baselineWrapper = requireObject(baselineReport, "baseline build report wrapper");
  const baselineBuildReport = requireObject(
    baselineWrapper.buildReport ?? baselineWrapper,
    "baseline build report"
  );
  const currentModuleGraphBuildReport = requireObject(
    requireObject(currentBuildReport.moduleGraphArtifact, "current module-graph artifact")
      .buildReport,
    "current module-graph build report"
  );
  const baselineModuleGraphBuildReport = requireObject(
    requireObject(baselineBuildReport.moduleGraphArtifact, "baseline module-graph artifact")
      .buildReport,
    "baseline module-graph build report"
  );
  const currentIdentities = graphIdentityMap(
    requireArray(currentModuleGraphBuildReport.graphs, "current module graphs"),
    "current build"
  );
  const baselineIdentities = graphIdentityMap(
    requireArray(baselineModuleGraphBuildReport.graphs, "baseline module graphs"),
    "baseline build"
  );
  const reusedCohortIds = [...currentIdentities.keys()].filter((cohortId) =>
    baselineIdentities.has(cohortId)
  );
  const baselinePackageKeys = new Set(baselineIdentities.values());
  const currentPackageKeys = new Set(currentIdentities.values());
  return {
    baselineWallMilliseconds: requireNonNegativeNumber(
      baselineBuildReport.wallMilliseconds,
      "baseline build wall time"
    ),
    cohorts: {
      addedIdentityCount: [...currentIdentities.keys()].filter(
        (cohortId) => !baselineIdentities.has(cohortId)
      ).length,
      baselineCount: baselineIdentities.size,
      currentCount: currentIdentities.size,
      removedIdentityCount: [...baselineIdentities.keys()].filter(
        (cohortId) => !currentIdentities.has(cohortId)
      ).length,
      reusedIdentityCount: reusedCohortIds.length,
    },
    packages: {
      baselineKeyCount: baselinePackageKeys.size,
      changedKeyForReusedCohortCount: reusedCohortIds.filter(
        (cohortId) => currentIdentities.get(cohortId) !== baselineIdentities.get(cohortId)
      ).length,
      currentKeyCount: currentPackageKeys.size,
      reusedKeyCount: [...currentPackageKeys].filter((key) => baselinePackageKeys.has(key)).length,
    },
    schedule: {
      baselineSha256: baselineModuleGraphBuildReport.scheduleSha256,
      currentSha256: currentModuleGraphBuildReport.scheduleSha256,
      identityChanged:
        baselineModuleGraphBuildReport.scheduleSha256 !==
        currentModuleGraphBuildReport.scheduleSha256,
    },
  };
}

function summarizeRecordedSpan(events, includes) {
  const selected = events.filter(includes);
  if (selected.length === 0) {
    return { eventCount: 0, kind: "not-recorded" };
  }
  const intervals = selected
    .map(({ endedAtMilliseconds, startedAtMilliseconds }) => ({
      endedAtMilliseconds,
      startedAtMilliseconds,
    }))
    .sort((left, right) =>
      left.startedAtMilliseconds === right.startedAtMilliseconds
        ? left.endedAtMilliseconds - right.endedAtMilliseconds
        : left.startedAtMilliseconds - right.startedAtMilliseconds
    );
  let coveredMilliseconds = 0;
  let coveredUntilMilliseconds = intervals[0].startedAtMilliseconds;
  for (const interval of intervals) {
    if (interval.endedAtMilliseconds <= coveredUntilMilliseconds) continue;
    coveredMilliseconds +=
      interval.endedAtMilliseconds -
      Math.max(interval.startedAtMilliseconds, coveredUntilMilliseconds);
    coveredUntilMilliseconds = interval.endedAtMilliseconds;
  }
  const firstStartedAtMilliseconds = intervals[0].startedAtMilliseconds;
  const lastEndedAtMilliseconds = Math.max(
    ...intervals.map(({ endedAtMilliseconds }) => endedAtMilliseconds)
  );
  return {
    coveredMilliseconds,
    eventCount: selected.length,
    firstStartedAtMilliseconds,
    kind: "recorded",
    lastEndedAtMilliseconds,
    spanMilliseconds: lastEndedAtMilliseconds - firstStartedAtMilliseconds,
  };
}

function recordedActivitySpans(events) {
  return {
    finalMaterialVerification: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "module-graph-final-material-verification"
    ),
    materialSession: summarizeRecordedSpan(
      events,
      ({ kind, stage }) => kind === "external-activity" && stage === "artifact-material-session"
    ),
    materializationPublicationPhysicalAuthentication: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" &&
        (activity === "deployment-materialization-publication-physical-authentication" ||
          activity === "immutable-cache-publication" ||
          activity === "immutable-cache-validation")
    ),
    packagePublicationAuthentication: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" &&
        activity === "module-graph-package-publication-authentication"
    ),
    packageReceiptPublication: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "module-graph-package-receipt-publication"
    ),
    postReceiptFinalization: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "module-graph-post-receipt-finalization"
    ),
    postprocessing: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "deployment-postprocessing"
    ),
    receiptMissConstruction: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "module-graph-receipt-miss-construction"
    ),
    receiptTopologyAuthentication: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "module-graph-receipt-topology-authentication"
    ),
    sourceGraphVerification: summarizeRecordedSpan(
      events,
      ({ activity, kind }) =>
        kind === "external-activity" && activity === "deployment-source-graph-verification"
    ),
  };
}

function recordedTimeline(events, schedulerEndMilliseconds) {
  if (events.length === 0) {
    return { kind: "no-recorded-activity" };
  }
  const firstRecordedActivityMilliseconds = Math.min(
    ...events.map(({ startedAtMilliseconds }) => startedAtMilliseconds)
  );
  const lastRecordedActivityEndMilliseconds = Math.max(
    ...events.map(({ endedAtMilliseconds }) => endedAtMilliseconds)
  );
  if (lastRecordedActivityEndMilliseconds > schedulerEndMilliseconds + 0.001) {
    fail("final critical-path activity ends after the scheduler report");
  }
  return {
    firstRecordedActivityMilliseconds,
    kind: "recorded-activity",
    lastRecordedActivityEndMilliseconds,
  };
}

function nativeCommandTimeline(events, schedulerEndMilliseconds) {
  const nativeEvents = events.filter(({ kind }) => kind === "native-phase");
  if (nativeEvents.length === 0) {
    return { count: 0, kind: "no-native-commands" };
  }
  const firstNativeCommandMilliseconds = Math.min(
    ...nativeEvents.map(({ startedAtMilliseconds }) => startedAtMilliseconds)
  );
  const lastNativeCommandEndMilliseconds = Math.max(
    ...nativeEvents.map(({ endedAtMilliseconds }) => endedAtMilliseconds)
  );
  if (lastNativeCommandEndMilliseconds > schedulerEndMilliseconds + 0.001) {
    fail("final native command ends after the scheduler report");
  }
  return {
    count: nativeEvents.length,
    firstNativeCommandMilliseconds,
    kind: "native-commands-recorded",
    lastNativeCommandEndMilliseconds,
  };
}

function parseElapsedMilliseconds(value) {
  const parts = value.split(":");
  if (
    parts.length < 2 ||
    parts.length > 3 ||
    parts.some((part) => !/^\d+(?:\.\d+)?$/u.test(part))
  ) {
    fail(`invalid GNU time elapsed value ${JSON.stringify(value)}`);
  }
  const numbers = parts.map(Number);
  const [hours, minutes, seconds] = numbers.length === 3 ? numbers : [0, numbers[0], numbers[1]];
  return ((hours * 60 + minutes) * 60 + seconds) * 1_000;
}

function gnuTimeValue(text, label) {
  const line = text
    .split("\n")
    .map((candidate) => candidate.trim())
    .find((candidate) => candidate.startsWith(`${label}:`));
  if (line === undefined) {
    fail(`GNU time report does not contain ${label}`);
  }
  return line.slice(label.length + 1).trim();
}

export function parseGnuTimeReport(text) {
  if (typeof text !== "string") {
    fail("GNU time report must be text");
  }
  const numberValue = (label) => {
    const value = Number(gnuTimeValue(text, label));
    if (!Number.isFinite(value) || value < 0) {
      fail(`GNU time ${label} must be a non-negative number`);
    }
    return value;
  };
  const cpuPercentText = gnuTimeValue(text, "Percent of CPU this job got");
  if (!/^\d+(?:\.\d+)?%$/u.test(cpuPercentText)) {
    fail("GNU time CPU percent is invalid");
  }
  return {
    averageCpuPercent: Number(cpuPercentText.slice(0, -1)),
    elapsedWallMilliseconds: parseElapsedMilliseconds(
      gnuTimeValue(text, "Elapsed (wall clock) time (h:mm:ss or m:ss)")
    ),
    fileSystemInputCount: numberValue("File system inputs"),
    fileSystemOutputCount: numberValue("File system outputs"),
    maximumRssKiB: numberValue("Maximum resident set size (kbytes)"),
    swapCount: numberValue("Swaps"),
    systemCpuMilliseconds: numberValue("System time (seconds)") * 1_000,
    userCpuMilliseconds: numberValue("User time (seconds)") * 1_000,
  };
}

export function analyzeConvexWasmBuildLatency(
  report,
  { baselineReport, logicalCpuCount, outerTiming, reportBytes } = {}
) {
  const wrapper = requireObject(report, "build report wrapper");
  const buildReport = requireObject(wrapper.buildReport ?? wrapper, "build report");
  const wallMilliseconds = requireNonNegativeNumber(
    buildReport.wallMilliseconds,
    "build wall time"
  );
  const counts = requireObject(buildReport.counts, "build counts");
  const inventory = requireObject(buildReport.inventory, "build inventory");
  const graph = requireObject(buildReport.graph, "build graph");
  const inventoryPhases = requireObject(
    inventory.phaseTimingsMilliseconds,
    "inventory phase timings"
  );
  const graphPhases = requireObject(graph.phaseTimingsUs, "graph phase timings");
  const materialSession = requireObject(
    buildReport.artifactMaterialSession,
    "artifact material session"
  );
  const materialScheduling = requireObject(
    requireObject(materialSession.scheduling, "artifact material scheduling").nativePhaseScheduling,
    "artifact material native scheduling"
  );
  const moduleGraphBuildReport = requireObject(
    requireObject(buildReport.moduleGraphArtifact, "module-graph artifact").buildReport,
    "module-graph build report"
  );
  const finalScheduling = requireObject(
    moduleGraphBuildReport.moduleGraphAotScheduling,
    "final module-graph scheduling"
  );
  const finalCriticalPath = requireObject(finalScheduling.criticalPath, "final critical path");
  const finalEvents = requireArray(finalCriticalPath.events, "final critical-path events").map(
    (event, index) => criticalPathEvent(event, index, "final module-graph")
  );
  const finalScheduler = summarizeScheduler(finalScheduling);
  const finalSnapshot = snapshotConsistency("final-module-graph", finalScheduling);
  if (!finalSnapshot.consistent) {
    fail(`final module-graph timing is inconsistent: ${finalSnapshot.issues.join(", ")}`);
  }
  const graphs = moduleGraphs(buildReport, "current build");
  const sharedStages = requireArray(materialSession.sharedStages, "material shared stages");
  const artifacts = requireArray(buildReport.artifacts, "artifact jobs");
  const artifactPhases = artifacts.flatMap((artifact, index) =>
    requireArray(
      requireObject(artifact.buildReport, `artifact job ${index} build report`).phases,
      `artifact job ${index} phases`
    )
  );
  const packageRecords = graphs.map((graphRecord, index) =>
    requireObject(
      requireObject(graphRecord.buildReport, `module graph ${index} build report`).package,
      `module graph ${index} package`
    )
  );
  const schedulerEndMilliseconds = finalScheduler.elapsedWallMilliseconds;
  const activityTimeline = recordedTimeline(finalEvents, schedulerEndMilliseconds);
  const nativeTimeline = nativeCommandTimeline(finalEvents, schedulerEndMilliseconds);
  const result = {
    build: {
      artifactJobs: artifacts.length,
      esbuildGraphMilliseconds:
        requireNonNegativeNumber(graphPhases.esbuildGraph, "esbuild graph time") / 1_000,
      inventoryFlattenerAndValidationMilliseconds: requireNonNegativeNumber(
        inventoryPhases.flattenerAndValidation,
        "inventory flattener and validation time"
      ),
      packages: graphs.length,
      selectedEntries: requireNonNegativeNumber(counts.selectedEntries, "selected entry count"),
      selectedRoutes: requireNonNegativeNumber(counts.selectedRoutes, "selected route count"),
      wallMilliseconds,
    },
    cache: {
      artifactPhaseReferences: cacheCounts(artifactPhases, "artifact phase"),
      moduleGraphPackages: outcomeCounts(packageRecords, "cache", "module-graph package record"),
      physicalSharedStages: cacheCounts(sharedStages, "physical shared stage"),
    },
    input: {
      ...(reportBytes === undefined
        ? {}
        : { reportBytes: requireNonNegativeNumber(reportBytes, "report byte count") }),
    },
    kind: "convex-wasm-build-latency-analysis-v1",
    scheduler: finalScheduler,
    spans: recordedActivitySpans(finalEvents),
    telemetry: {
      snapshots: [
        snapshotConsistency("artifact-material-session", materialScheduling),
        finalSnapshot,
      ],
    },
    timeline: {
      ...(activityTimeline.kind === "recorded-activity"
        ? {
            firstRecordedActivityMilliseconds: activityTimeline.firstRecordedActivityMilliseconds,
            lastRecordedActivityEndMilliseconds:
              activityTimeline.lastRecordedActivityEndMilliseconds,
            prefixBeforeFirstRecordedActivityMilliseconds:
              activityTimeline.firstRecordedActivityMilliseconds,
          }
        : { recordedActivity: activityTimeline }),
      ...(nativeTimeline.kind === "native-commands-recorded"
        ? {
            firstNativeCommandMilliseconds: nativeTimeline.firstNativeCommandMilliseconds,
            lastNativeCommandEndMilliseconds: nativeTimeline.lastNativeCommandEndMilliseconds,
            lastNativeToBuildEndMilliseconds:
              wallMilliseconds - nativeTimeline.lastNativeCommandEndMilliseconds,
            lastNativeToSchedulerEndMilliseconds:
              schedulerEndMilliseconds - nativeTimeline.lastNativeCommandEndMilliseconds,
            prefixBeforeFirstNativeCommandMilliseconds:
              nativeTimeline.firstNativeCommandMilliseconds,
          }
        : { nativeCommands: nativeTimeline }),
      schedulerEndMilliseconds,
      suffixAfterSchedulerEndMilliseconds: wallMilliseconds - schedulerEndMilliseconds,
    },
    topology: {
      moduleGraph: summarizeModuleTopology(graphs),
      packageCacheKeys: uniqueStringCount(
        packageRecords,
        "cacheKey",
        "module-graph package record"
      ),
      physicalSharedStageCount: sharedStages.length,
    },
  };

  if (baselineReport !== undefined) {
    result.comparison = compareBuildTopology(buildReport, baselineReport);
  }

  if (outerTiming !== undefined) {
    requireObject(outerTiming, "outer GNU time telemetry");
    const outerUserCpuMilliseconds = requireNonNegativeNumber(
      outerTiming.userCpuMilliseconds,
      "outer user CPU"
    );
    const outerSystemCpuMilliseconds = requireNonNegativeNumber(
      outerTiming.systemCpuMilliseconds,
      "outer system CPU"
    );
    const outerWallMilliseconds = requireNonNegativeNumber(
      outerTiming.elapsedWallMilliseconds,
      "outer wall time"
    );
    const outerCpuMilliseconds = outerUserCpuMilliseconds + outerSystemCpuMilliseconds;
    const logicalCpuCapacity =
      logicalCpuCount === undefined
        ? undefined
        : requireNonNegativeNumber(logicalCpuCount, "logical CPU count");
    if (
      logicalCpuCapacity !== undefined &&
      (!Number.isInteger(logicalCpuCapacity) || logicalCpuCapacity === 0)
    ) {
      fail("logical CPU count must be a positive integer");
    }
    result.processTelemetry = {
      averageCpuParallelism: outerCpuMilliseconds / outerWallMilliseconds,
      ...(logicalCpuCapacity === undefined
        ? {}
        : {
            availableCpuUtilizationFraction:
              outerCpuMilliseconds / (outerWallMilliseconds * logicalCpuCapacity),
            logicalCpuCount: logicalCpuCapacity,
          }),
      outer: outerTiming,
      outerCpuMilliseconds,
      outerMaximumRssToAdmissionFraction:
        (requireNonNegativeNumber(outerTiming.maximumRssKiB, "outer maximum RSS") * 1_024) /
        requireNonNegativeNumber(
          finalScheduling.launchPolicy.aggregateMemoryMaxBytes,
          "aggregate memory admission limit"
        ),
      outerWrapperMilliseconds: outerWallMilliseconds - wallMilliseconds,
      reportedNativeProcessCpuCoverageFraction:
        finalScheduler.reportedProcessCpuMilliseconds / outerCpuMilliseconds,
      unreportedCpuMillisecondsLowerBound: Math.max(
        0,
        outerCpuMilliseconds - finalScheduler.reportedProcessCpuMilliseconds
      ),
    };
  } else if (logicalCpuCount !== undefined) {
    fail("logical CPU count requires outer GNU time telemetry");
  }

  return result;
}
