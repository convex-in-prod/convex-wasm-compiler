import assert from "node:assert/strict";
import test from "node:test";

import { analyzeConvexWasmBuildLatency, parseGnuTimeReport } from "./convex-wasm-build-latency.mjs";

function schedulerReport({ elapsedWallMilliseconds, events, requestCount }) {
  return {
    criticalPath: {
      activeCommandMilliseconds: 300,
      activeWorkerSlotMilliseconds: 500,
      droppedEventCount: 0,
      droppedIntervalCount: 0,
      elapsedWallMilliseconds,
      events,
      idleNoNativeWorkMilliseconds: 400,
      intervals: [
        {
          endedAtMilliseconds: 200,
          startedAtMilliseconds: 0,
        },
        {
          endedAtMilliseconds: 700,
          startedAtMilliseconds: 200,
        },
      ],
      queuedStateMilliseconds: {
        fairness: 5,
        memory: 20,
        none: 0,
        runnable: 2,
        "worker-slots": 10,
        "worker-slots-and-memory": 3,
      },
    },
    launchPolicy: {
      aggregateMemoryMaxBytes: 1_000,
      jobs: 2,
    },
    maximumActiveCount: 2,
    maximumActiveWorkerSlots: 2,
    maximumEstimatedWorkingSetBytes: 800,
    requestCount,
    stages: [
      {
        maximumActiveCount: 2,
        maximumQueueWaitMilliseconds: 8,
        name: "generated-c",
        requestCount: 2,
        resourceUsage: {
          maximumRssKiB: 100,
          systemCpuMilliseconds: 20,
          userCpuMilliseconds: 50,
          wallMilliseconds: 300,
        },
        totalQueueWaitMilliseconds: 12,
      },
    ],
  };
}

const events = [
  {
    activity: "artifact-stage-build",
    endedAtMilliseconds: 150,
    kind: "external-activity",
    outcome: "completed",
    startedAtMilliseconds: 100,
    stage: "generated-c",
  },
  {
    endedAtMilliseconds: 300,
    kind: "native-phase",
    outcome: "completed",
    startedAtMilliseconds: 200,
    stage: "generated-c",
  },
  {
    endedAtMilliseconds: 600,
    kind: "native-phase",
    outcome: "completed",
    startedAtMilliseconds: 400,
    stage: "core-wasm",
  },
];

function moduleReference(role, digit, cache) {
  return {
    aot: {
      cache,
      cacheKey: `aot-${digit}`,
      materialCacheKey: `material-${digit}`,
    },
    coreWasm: { cache, cacheKey: `core-${digit}` },
    role,
  };
}

function buildReport() {
  const finalScheduling = schedulerReport({
    elapsedWallMilliseconds: 700,
    events,
    requestCount: 2,
  });
  const earlyScheduling = schedulerReport({
    elapsedWallMilliseconds: 400,
    events,
    requestCount: 1,
  });
  return {
    buildReport: {
      artifactMaterialSession: {
        scheduling: { nativePhaseScheduling: earlyScheduling },
        sharedStages: [
          { cache: "miss", stage: "generated-c" },
          { cache: "miss", stage: "module-graph-application-pic-object" },
          { cache: "miss", stage: "static-hermes-c-bundle-member-object" },
        ],
      },
      artifacts: [
        {
          buildReport: {
            phases: [
              { cache: "miss", stage: "generated-c" },
              { cache: "hit", stage: "generated-c" },
            ],
          },
        },
      ],
      counts: { selectedEntries: 3, selectedRoutes: 7 },
      graph: { phaseTimingsUs: { esbuildGraph: 50_000 } },
      inventory: {
        phaseTimingsMilliseconds: { flattenerAndValidation: 100 },
      },
      moduleGraphArtifact: {
        buildReport: {
          graphs: [
            {
              cohortId: "cohort-1",
              graphManifestSha256: "package-1",
              buildReport: {
                modules: [
                  moduleReference("base", "1", "miss"),
                  moduleReference(`shared-${"a".repeat(64)}`, "2", "hit"),
                  moduleReference("leaf", "3", "miss"),
                ],
                package: { cache: "miss", cacheKey: "package-1" },
              },
            },
          ],
          moduleGraphAotScheduling: finalScheduling,
        },
      },
      wallMilliseconds: 1_000,
    },
  };
}

function cachedChangedSourceReplayReport() {
  const report = buildReport();
  const materialScheduling = schedulerReport({
    elapsedWallMilliseconds: 20_000,
    events: [
      {
        activity: "material-fingerprint",
        endedAtMilliseconds: 3_000,
        kind: "external-activity",
        outcome: "completed",
        stage: "artifact-material-session",
        startedAtMilliseconds: 1_000,
      },
      {
        activity: "runtime-header-snapshot",
        endedAtMilliseconds: 8_000,
        kind: "external-activity",
        outcome: "completed",
        stage: "artifact-material-session",
        startedAtMilliseconds: 3_000,
      },
      {
        activity: "material-revalidation",
        endedAtMilliseconds: 20_000,
        kind: "external-activity",
        outcome: "completed",
        stage: "artifact-material-session",
        startedAtMilliseconds: 12_000,
      },
    ],
    requestCount: 0,
  });
  materialScheduling.criticalPath.activeCommandMilliseconds = 0;
  materialScheduling.criticalPath.activeWorkerSlotMilliseconds = 0;
  materialScheduling.criticalPath.idleNoNativeWorkMilliseconds = 20_000;
  materialScheduling.criticalPath.intervals = [
    { endedAtMilliseconds: 20_000, startedAtMilliseconds: 0 },
  ];
  materialScheduling.criticalPath.queuedStateMilliseconds = {
    fairness: 0,
    memory: 0,
    none: 0,
    runnable: 0,
    "worker-slots": 0,
    "worker-slots-and-memory": 0,
  };
  materialScheduling.maximumActiveCount = 0;
  materialScheduling.maximumActiveWorkerSlots = 0;
  materialScheduling.maximumEstimatedWorkingSetBytes = 0;
  materialScheduling.stages = [];

  const finalScheduling = structuredClone(materialScheduling);
  finalScheduling.criticalPath.elapsedWallMilliseconds = 250_000;
  finalScheduling.criticalPath.idleNoNativeWorkMilliseconds = 250_000;
  finalScheduling.criticalPath.events = [
    ...materialScheduling.criticalPath.events,
    {
      activity: "module-graph-receipt-topology-authentication",
      endedAtMilliseconds: 60_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "module-graph-receipt",
      startedAtMilliseconds: 20_000,
    },
    {
      activity: "deployment-source-graph-verification",
      endedAtMilliseconds: 185_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "deployment",
      startedAtMilliseconds: 60_000,
    },
    {
      activity: "module-graph-post-receipt-finalization",
      endedAtMilliseconds: 180_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "module-graph-package",
      startedAtMilliseconds: 60_000,
    },
    {
      activity: "module-graph-receipt-miss-construction",
      endedAtMilliseconds: 90_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "module-graph-package",
      startedAtMilliseconds: 60_000,
    },
    {
      activity: "module-graph-package-publication-authentication",
      endedAtMilliseconds: 150_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "module-graph-package",
      startedAtMilliseconds: 80_000,
    },
    {
      activity: "module-graph-package-receipt-publication",
      endedAtMilliseconds: 160_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "module-graph-package-receipt",
      startedAtMilliseconds: 120_000,
    },
    {
      activity: "module-graph-final-material-verification",
      endedAtMilliseconds: 170_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "module-graph-package",
      startedAtMilliseconds: 140_000,
    },
    {
      activity: "deployment-materialization-publication-physical-authentication",
      endedAtMilliseconds: 225_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "deployment",
      startedAtMilliseconds: 185_000,
    },
    {
      activity: "deployment-postprocessing",
      endedAtMilliseconds: 250_000,
      kind: "external-activity",
      outcome: "completed",
      stage: "deployment",
      startedAtMilliseconds: 225_000,
    },
  ];
  finalScheduling.criticalPath.intervals = [
    { endedAtMilliseconds: 250_000, startedAtMilliseconds: 0 },
  ];
  report.buildReport.artifactMaterialSession.scheduling.nativePhaseScheduling = materialScheduling;
  report.buildReport.artifactMaterialSession.sharedStages = [
    { cache: "hit", stage: "generated-c" },
    { cache: "hit", stage: "module-graph-application-pic-object" },
  ];
  report.buildReport.artifacts = [
    {
      buildReport: {
        phases: [
          { cache: "hit", stage: "generated-c" },
          { cache: "hit", stage: "module-graph-application-pic-object" },
        ],
      },
    },
  ];
  report.buildReport.moduleGraphArtifact.buildReport.moduleGraphAotScheduling = finalScheduling;
  report.buildReport.moduleGraphArtifact.buildReport.graphs[0].buildReport.modules = [
    moduleReference("base", "1", "hit"),
    moduleReference(`shared-${"a".repeat(64)}`, "2", "hit"),
    moduleReference("leaf", "3", "hit"),
  ];
  report.buildReport.moduleGraphArtifact.buildReport.graphs[0].buildReport.package.cache = "hit";
  report.buildReport.wallMilliseconds = 255_000;
  return report;
}

function zeroNativeNoOpReport() {
  const report = cachedChangedSourceReplayReport();
  for (const scheduling of [
    report.buildReport.artifactMaterialSession.scheduling.nativePhaseScheduling,
    report.buildReport.moduleGraphArtifact.buildReport.moduleGraphAotScheduling,
  ]) {
    scheduling.criticalPath.elapsedWallMilliseconds = 1;
    scheduling.criticalPath.events = [];
    scheduling.criticalPath.idleNoNativeWorkMilliseconds = 1;
    scheduling.criticalPath.intervals = [{ endedAtMilliseconds: 1, startedAtMilliseconds: 0 }];
  }
  report.buildReport.wallMilliseconds = 2;
  return report;
}

test("summarizes scheduler utilization, cache topology, and timeline gaps", () => {
  const outerTiming = {
    averageCpuPercent: 150,
    elapsedWallMilliseconds: 1_100,
    fileSystemInputCount: 11,
    fileSystemOutputCount: 12,
    maximumRssKiB: 1,
    swapCount: 0,
    systemCpuMilliseconds: 500,
    userCpuMilliseconds: 1_000,
  };
  const analysis = analyzeConvexWasmBuildLatency(buildReport(), {
    logicalCpuCount: 4,
    outerTiming,
    reportBytes: 123,
  });

  assert.equal(analysis.kind, "convex-wasm-build-latency-analysis-v1");
  assert.deepEqual(analysis.build, {
    artifactJobs: 1,
    esbuildGraphMilliseconds: 50,
    inventoryFlattenerAndValidationMilliseconds: 100,
    packages: 1,
    selectedEntries: 3,
    selectedRoutes: 7,
    wallMilliseconds: 1_000,
  });
  assert.deepEqual(analysis.cache.physicalSharedStages, [
    { cache: "miss", count: 1, stage: "generated-c" },
    { cache: "miss", count: 1, stage: "module-graph-application-pic-object" },
    { cache: "miss", count: 1, stage: "static-hermes-c-bundle-member-object" },
  ]);
  assert.deepEqual(analysis.cache.artifactPhaseReferences, [
    { cache: "hit", count: 1, stage: "generated-c" },
    { cache: "miss", count: 1, stage: "generated-c" },
  ]);
  assert.deepEqual(analysis.topology.moduleGraph.referencesByRole, [
    { references: 1, role: "base" },
    { references: 1, role: "shared" },
    { references: 1, role: "leaf" },
  ]);
  assert.equal(analysis.scheduler.averageActiveCommandCount, 3 / 7);
  assert.equal(analysis.scheduler.averageActiveWorkerSlots, 5 / 7);
  assert.equal(analysis.scheduler.nativeCommandSlotUtilizationFraction, 3 / 14);
  assert.equal(analysis.scheduler.workerSlotUtilizationFraction, 5 / 14);
  assert.equal(analysis.scheduler.queuedObservedMilliseconds, 40);
  assert.deepEqual(analysis.timeline, {
    firstNativeCommandMilliseconds: 200,
    firstRecordedActivityMilliseconds: 100,
    lastNativeCommandEndMilliseconds: 600,
    lastRecordedActivityEndMilliseconds: 600,
    lastNativeToBuildEndMilliseconds: 400,
    lastNativeToSchedulerEndMilliseconds: 100,
    prefixBeforeFirstNativeCommandMilliseconds: 200,
    prefixBeforeFirstRecordedActivityMilliseconds: 100,
    schedulerEndMilliseconds: 700,
    suffixAfterSchedulerEndMilliseconds: 300,
  });
  assert.equal(analysis.processTelemetry.reportedNativeProcessCpuCoverageFraction, 70 / 1_500);
  assert.equal(analysis.processTelemetry.unreportedCpuMillisecondsLowerBound, 1_430);
  assert.equal(analysis.processTelemetry.availableCpuUtilizationFraction, 1_500 / 4_400);
});

test("attributes a fully cached changed-source replay with no native commands", () => {
  const analysis = analyzeConvexWasmBuildLatency(cachedChangedSourceReplayReport());

  assert.equal(analysis.scheduler.requestCount, 0);
  assert.equal(analysis.scheduler.reportedProcessCpuMilliseconds, 0);
  assert.deepEqual(analysis.timeline, {
    firstRecordedActivityMilliseconds: 1_000,
    lastRecordedActivityEndMilliseconds: 250_000,
    nativeCommands: { count: 0, kind: "no-native-commands" },
    prefixBeforeFirstRecordedActivityMilliseconds: 1_000,
    schedulerEndMilliseconds: 250_000,
    suffixAfterSchedulerEndMilliseconds: 5_000,
  });
  assert.deepEqual(analysis.spans, {
    finalMaterialVerification: {
      coveredMilliseconds: 30_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 140_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 170_000,
      spanMilliseconds: 30_000,
    },
    materialSession: {
      coveredMilliseconds: 15_000,
      eventCount: 3,
      firstStartedAtMilliseconds: 1_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 20_000,
      spanMilliseconds: 19_000,
    },
    materializationPublicationPhysicalAuthentication: {
      coveredMilliseconds: 40_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 185_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 225_000,
      spanMilliseconds: 40_000,
    },
    packagePublicationAuthentication: {
      coveredMilliseconds: 70_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 80_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 150_000,
      spanMilliseconds: 70_000,
    },
    packageReceiptPublication: {
      coveredMilliseconds: 40_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 120_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 160_000,
      spanMilliseconds: 40_000,
    },
    postReceiptFinalization: {
      coveredMilliseconds: 120_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 60_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 180_000,
      spanMilliseconds: 120_000,
    },
    postprocessing: {
      coveredMilliseconds: 25_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 225_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 250_000,
      spanMilliseconds: 25_000,
    },
    receiptTopologyAuthentication: {
      coveredMilliseconds: 40_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 20_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 60_000,
      spanMilliseconds: 40_000,
    },
    receiptMissConstruction: {
      coveredMilliseconds: 30_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 60_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 90_000,
      spanMilliseconds: 30_000,
    },
    sourceGraphVerification: {
      coveredMilliseconds: 125_000,
      eventCount: 1,
      firstStartedAtMilliseconds: 60_000,
      kind: "recorded",
      lastEndedAtMilliseconds: 185_000,
      spanMilliseconds: 125_000,
    },
  });
  assert.equal(analysis.cache.moduleGraphPackages[0].outcome, "hit");
  assert.equal(analysis.telemetry.snapshots[1].consistent, true);
});

test("reports no-op zero-native schedulers without manufacturing command timings", () => {
  const analysis = analyzeConvexWasmBuildLatency(zeroNativeNoOpReport());

  assert.deepEqual(analysis.timeline, {
    nativeCommands: { count: 0, kind: "no-native-commands" },
    recordedActivity: { kind: "no-recorded-activity" },
    schedulerEndMilliseconds: 1,
    suffixAfterSchedulerEndMilliseconds: 1,
  });
  for (const span of Object.values(analysis.spans)) {
    assert.deepEqual(span, { eventCount: 0, kind: "not-recorded" });
  }
});

test("detects retained scheduler arrays that changed after a scalar snapshot", () => {
  const analysis = analyzeConvexWasmBuildLatency(buildReport());
  assert.deepEqual(analysis.telemetry.snapshots[0].issues, [
    "request-count-does-not-match-retained-terminal-native-events",
    "elapsed-wall-does-not-match-retained-interval-end",
    "event-ends-after-elapsed-wall",
  ]);
  assert.equal(analysis.telemetry.snapshots[0].consistent, false);
  assert.equal(analysis.telemetry.snapshots[1].consistent, true);
});

test("rejects an inconsistent final scheduler snapshot", () => {
  const report = buildReport();
  report.buildReport.moduleGraphArtifact.buildReport.moduleGraphAotScheduling.requestCount = 1;

  assert.throws(
    () => analyzeConvexWasmBuildLatency(report),
    /final module-graph timing is inconsistent: request-count-does-not-match-retained-terminal-native-events/
  );
});

test("rejects final timing with dropped critical-path records", () => {
  const report = buildReport();
  report.buildReport.moduleGraphArtifact.buildReport.moduleGraphAotScheduling.criticalPath.droppedEventCount = 1;

  assert.throws(
    () => analyzeConvexWasmBuildLatency(report),
    /final module-graph timing is inconsistent: critical-path-events-were-dropped/
  );
});

test("compares stable cohort identities with package-key invalidation", () => {
  const current = buildReport();
  const baseline = structuredClone(current);
  baseline.buildReport.wallMilliseconds = 2_000;
  baseline.buildReport.moduleGraphArtifact.buildReport.scheduleSha256 = "baseline-schedule";
  baseline.buildReport.moduleGraphArtifact.buildReport.graphs[0].graphManifestSha256 =
    "baseline-package";
  current.buildReport.moduleGraphArtifact.buildReport.scheduleSha256 = "current-schedule";

  const analysis = analyzeConvexWasmBuildLatency(current, { baselineReport: baseline });
  assert.deepEqual(analysis.comparison, {
    baselineWallMilliseconds: 2_000,
    cohorts: {
      addedIdentityCount: 0,
      baselineCount: 1,
      currentCount: 1,
      removedIdentityCount: 0,
      reusedIdentityCount: 1,
    },
    packages: {
      baselineKeyCount: 1,
      changedKeyForReusedCohortCount: 1,
      currentKeyCount: 1,
      reusedKeyCount: 0,
    },
    schedule: {
      baselineSha256: "baseline-schedule",
      currentSha256: "current-schedule",
      identityChanged: true,
    },
  });
});

test("parses GNU time process-tree telemetry", () => {
  const timing = parseGnuTimeReport(`
User time (seconds): 10.25
System time (seconds): 2.75
Percent of CPU this job got: 203%
Elapsed (wall clock) time (h:mm:ss or m:ss): 1:02.50
Maximum resident set size (kbytes): 4096
Swaps: 0
File system inputs: 12
File system outputs: 34
`);
  assert.deepEqual(timing, {
    averageCpuPercent: 203,
    elapsedWallMilliseconds: 62_500,
    fileSystemInputCount: 12,
    fileSystemOutputCount: 34,
    maximumRssKiB: 4_096,
    swapCount: 0,
    systemCpuMilliseconds: 2_750,
    userCpuMilliseconds: 10_250,
  });
});
