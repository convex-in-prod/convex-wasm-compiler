import assert from "node:assert/strict";
import test from "node:test";

import {
  ConvexWasmNativeCommandFailure,
  convexWasmNativeAotWorkingSetEstimateBytes,
  convexWasmNativeCommandArguments,
  convexWasmNativeCommandWorkerSlots,
  convexWasmNativeGeneratedCWorkingSetEstimateBytes,
  createConvexWasmNativePhaseScheduler as createRawScheduler,
  normalizeConvexWasmNativeLaunchPolicy,
} from "./convex-wasm-native-launch-scheduling.mjs";

const GIBIBYTE = 1024 * 1024 * 1024;
const MEBIBYTE = 1024 * 1024;

function timing(maxRssKiB = 1) {
  return { maxRssKiB, systemCpuMilliseconds: 0, userCpuMilliseconds: 0, wallMilliseconds: 1 };
}

async function assertUndefinedFailureStopsScheduler(operation) {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 2,
  });
  let releaseSibling;
  let queuedStarted = false;
  const sibling = scheduler.run(
    "runtime-main-object",
    () =>
      new Promise((resolve) => {
        releaseSibling = () => resolve(timing());
      })
  );
  const failed = scheduler.run("generated-c", operation);
  const queued = scheduler.run(
    "wasmtime-aot",
    async () => {
      queuedStarted = true;
      return timing();
    },
    { workerSlots: 2 }
  );
  const idle = scheduler.idle();
  const queuedOutcome = queued.then(
    () => ({ status: "fulfilled" }),
    (error) => ({ error, status: "rejected" })
  );

  try {
    await assert.rejects(failed, (error) => error === undefined);
    assert.deepEqual(
      await Promise.race([
        queuedOutcome,
        new Promise((resolve) => setImmediate(() => resolve({ status: "pending" }))),
      ]),
      { error: undefined, status: "rejected" }
    );
    assert.equal(queuedStarted, false);
    assert.equal(scheduler.queuedCount, 0);
    assert.equal(scheduler.activeCount, 1);
    assert.equal(
      await Promise.race([
        idle.then(() => "resolved"),
        new Promise((resolve) => setImmediate(() => resolve("pending"))),
      ]),
      "pending"
    );
  } finally {
    releaseSibling();
    await Promise.allSettled([failed, sibling, queued]);
    await idle;
  }

  assert.equal(scheduler.activeCount, 0);
}

function createLaunchPolicy(policy) {
  return normalizeConvexWasmNativeLaunchPolicy({
    aggregateMemoryMaxBytes: policy.aggregateMemoryMaxBytes ?? 5 * GIBIBYTE,
    aotWorkers: policy.aotWorkers ?? Math.min(6, policy.jobs),
    jobs: policy.jobs,
  });
}

function createScheduler(policy) {
  return createRawScheduler(createLaunchPolicy(policy));
}

test("requires explicit native memory and worker limits", () => {
  const policy = normalizeConvexWasmNativeLaunchPolicy({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 2,
    jobs: 3,
  });
  assert.deepEqual(policy, {
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 2,
    jobs: 3,
  });
  assert.equal(Object.isFrozen(policy), true);
  assert.throws(
    () => createRawScheduler({ aotWorkers: 2, jobs: 3 }),
    /native launch policy/u
  );
  assert.throws(
    () => normalizeConvexWasmNativeLaunchPolicy({
      aggregateMemoryMaxBytes: 5 * GIBIBYTE,
      aotWorkers: 4,
      jobs: 3,
    }),
    /native launch AOT workers must not exceed jobs/u
  );
});

test("scheduler charges inner parallel work against the shared jobs budget without RSS kill caps", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 2,
  });
  let releaseFirst;
  const started = [];
  const first = scheduler.run(
    "generated-c",
    () =>
      new Promise((resolve) => {
        releaseFirst = () => resolve(timing(9_999_999));
        started.push("first");
      })
  );
  const nested = scheduler.run(
    "wasmtime-aot",
    async () => {
      started.push("nested");
      return timing();
    },
    { workerSlots: 2 }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["first"]);
  releaseFirst();
  await Promise.all([first, nested]);
  const report = scheduler.report();
  assert.equal(report.failedCount, 0);
  assert.equal(report.maximumActiveWorkerSlots, 2);
  assert.equal(
    report.stages.find(({ name }) => name === "generated-c").resourceUsage.maximumRssKiB,
    9_999_999
  );
});

test("generated-C fallback admission uses the conservative envelope within mixed-stage aggregate memory", async () => {
  const aggregateMemoryMaxBytes = 5 * GIBIBYTE;
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes,
    jobs: 9,
  });
  const started = [];
  const releases = [];
  let releaseMixedStage;
  const mixedStage = scheduler.run(
    "module-graph-application-pic-object",
    () =>
      new Promise((resolve) => {
        releaseMixedStage = () => resolve(timing());
      })
  );
  const tasks = Array.from({ length: 6 }, (_, index) =>
    scheduler.run(
      "generated-c",
      () =>
        new Promise((resolve) => {
          started.push(index);
          releases.push(() => resolve(timing()));
        })
    )
  );

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(started.length, 4);
  assert.equal(scheduler.activeCount, 5);
  assert.equal(scheduler.queuedCount, 2);
  const generatedCPolicy = scheduler.report().policy.stages["generated-c"];
  assert.equal(generatedCPolicy.workingSetEstimateBytes, 1024 * MEBIBYTE);
  assert.equal(
    scheduler.activeAdmissionWorkingSetEstimateBytes,
    512 * MEBIBYTE + 4 * 1024 * MEBIBYTE
  );
  assert.deepEqual(scheduler.report().policy.stages["static-hermes-runtime-prelude-pch"], {
    schedulingClass: "object",
    workingSetEstimateBytes: 512 * MEBIBYTE,
  });
  assert.ok(scheduler.activeAdmissionWorkingSetEstimateBytes <= aggregateMemoryMaxBytes);

  releaseMixedStage();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(started.length, 5);
  assert.equal(scheduler.activeAdmissionWorkingSetEstimateBytes, 5 * 1024 * MEBIBYTE);

  releases.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(started.length, 6);
  assert.equal(
    scheduler.report().stages.find(({ name }) => name === "generated-c").maximumActiveCount,
    5
  );

  for (const release of releases) release();
  await Promise.all([mixedStage, ...tasks]);
  assert.equal(scheduler.report().maximumEstimatedWorkingSetBytes, 5 * 1024 * MEBIBYTE);
  assert.equal(scheduler.activeCount, 0);
  assert.equal(scheduler.queuedCount, 0);
});

test("generated-C working-set estimates use a conservative floor and source-size scaling", () => {
  const floorBoundaryBytes = Math.floor((64 * MEBIBYTE) / 128);
  assert.equal(convexWasmNativeGeneratedCWorkingSetEstimateBytes(1), 96 * MEBIBYTE);
  assert.equal(
    convexWasmNativeGeneratedCWorkingSetEstimateBytes(floorBoundaryBytes),
    96 * MEBIBYTE
  );
  assert.equal(
    convexWasmNativeGeneratedCWorkingSetEstimateBytes(floorBoundaryBytes + 1),
    (floorBoundaryBytes + 1) * 128 * (3 / 2)
  );

  const largeSourceBytes = 6 * MEBIBYTE;
  const largeEstimate = convexWasmNativeGeneratedCWorkingSetEstimateBytes(largeSourceBytes);
  assert.equal(largeEstimate, largeSourceBytes * 128 * (3 / 2));

  for (const invalidSize of [0, -1, 1.5, "1", Number.MAX_SAFE_INTEGER]) {
    assert.throws(
      () => convexWasmNativeGeneratedCWorkingSetEstimateBytes(invalidSize),
      /generated JavaScript byte size/u
    );
  }
});

test("all generated-C stages retain the conservative fallback without source size", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 1,
  });
  const stages = ["capability-bridge-generated-c", "console-formatter-generated-c", "generated-c"];
  for (const stage of stages) {
    await scheduler.run(stage, async () => timing());
  }

  const events = scheduler
    .report()
    .criticalPath.events.filter(({ kind }) => kind === "native-phase");
  assert.deepEqual(
    events.map(({ stage, workingSetEstimateBytes }) => ({ stage, workingSetEstimateBytes })),
    stages.map((stage) => ({ stage, workingSetEstimateBytes: 1024 * MEBIBYTE }))
  );
});

test("source-sized generated-C admission fills the aggregate budget with small inputs", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 384 * MEBIBYTE,
    jobs: 5,
  });
  const workingSetEstimateBytes = convexWasmNativeGeneratedCWorkingSetEstimateBytes(440_200);
  const started = [];
  const releases = [];
  const tasks = Array.from({ length: 5 }, (_, index) =>
    scheduler.run(
      "generated-c",
      () =>
        new Promise((resolve) => {
          started.push(index);
          releases.push(() => resolve(timing()));
        }),
      { workingSetEstimateBytes }
    )
  );

  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, [0, 1, 2, 3]);
  assert.equal(scheduler.activeAdmissionWorkingSetEstimateBytes, 384 * MEBIBYTE);
  assert.equal(scheduler.queuedCount, 1);

  releases.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, [0, 1, 2, 3, 4]);
  assert.equal(scheduler.activeAdmissionWorkingSetEstimateBytes, 384 * MEBIBYTE);

  for (const release of releases) release();
  await Promise.all(tasks);
  const stageReport = scheduler.report().stages.find(({ name }) => name === "generated-c");
  assert.equal(stageReport.maximumActiveCount, 4);
  assert.equal(stageReport.maximumEstimatedWorkingSetBytes, 384 * MEBIBYTE);
});

test("stage and class reports sum exact active mixed working-set estimates", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 1,
    jobs: 2,
  });
  const releases = [];
  const tasks = [4 * GIBIBYTE, 512 * MEBIBYTE].map((workingSetEstimateBytes) =>
    scheduler.run(
      "module-graph-leaf-wasmtime-aot",
      () => new Promise((resolve) => releases.push(() => resolve(timing()))),
      { workingSetEstimateBytes }
    )
  );

  await new Promise((resolve) => setImmediate(resolve));
  const report = scheduler.report();
  const expectedMaximum = 4 * GIBIBYTE + 512 * MEBIBYTE;
  assert.equal(report.maximumEstimatedWorkingSetBytes, expectedMaximum);
  assert.equal(
    report.stages.find(({ name }) => name === "module-graph-leaf-wasmtime-aot")
      .maximumEstimatedWorkingSetBytes,
    expectedMaximum
  );
  assert.equal(
    report.classes.find(({ name }) => name === "module-graph-leaf-wasmtime-aot")
      .maximumEstimatedWorkingSetBytes,
    expectedMaximum
  );

  for (const release of releases) release();
  await Promise.all(tasks);
});

test("scheduler records bounded path-free critical-path timing for native and cache activity", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 1,
  });
  const activity = scheduler.beginCriticalPathActivity("immutable-artifact-stage", "generated-c");
  activity.finish({ cache: "miss" });

  let releaseFirst;
  const first = scheduler.run(
    "generated-c",
    () =>
      new Promise((resolve) => {
        releaseFirst = () => resolve(timing());
      })
  );
  await new Promise((resolve) => setImmediate(resolve));
  const second = scheduler.run("runtime-main-object", async () => timing());
  await new Promise((resolve) => setImmediate(resolve));
  releaseFirst();
  await Promise.all([first, second]);

  const criticalPath = scheduler.report().criticalPath;
  assert.equal(criticalPath.kind, "convex-wasm-native-phase-critical-path-v1");
  assert.equal(criticalPath.eventLimit, 32_768);
  assert.equal(criticalPath.droppedEventCount, 0);
  assert.equal(criticalPath.droppedIntervalCount, 0);
  assert.ok(criticalPath.elapsedWallMilliseconds > 0);
  assert.ok(criticalPath.activeCommandMilliseconds > 0);
  assert.ok(criticalPath.activeWorkerSlotMilliseconds > 0);
  assert.ok(criticalPath.queuedStateMilliseconds["worker-slots"] > 0);
  assert.ok(
    criticalPath.events.some(
      ({ activity: name, cache, kind, stage }) =>
        kind === "external-activity" &&
        name === "immutable-artifact-stage" &&
        cache === "miss" &&
        stage === "generated-c"
    )
  );
  const nativeEvents = criticalPath.events.filter(({ kind }) => kind === "native-phase");
  assert.equal(nativeEvents.length, 2);
  assert.ok(nativeEvents.every(({ outcome }) => outcome === "completed"));
  assert.ok(
    nativeEvents.every(
      ({ endedAtMilliseconds, queuedAtMilliseconds, startedAtMilliseconds }) =>
        queuedAtMilliseconds <= startedAtMilliseconds &&
        startedAtMilliseconds <= endedAtMilliseconds
    )
  );
  assert.ok(criticalPath.intervals.some(({ activeWorkerSlots }) => activeWorkerSlots === 1));
});

test("scheduler report snapshots critical-path telemetry", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 1,
  });
  await scheduler.run("runtime-main-object", async () => timing());

  const report = scheduler.report();
  const expectedCriticalPath = structuredClone(report.criticalPath);

  const laterActivity = scheduler.beginCriticalPathActivity(
    "deployment-postprocessing",
    "deployment"
  );
  laterActivity.finish();
  await scheduler.run("runtime-main-object", async () => timing());

  assert.deepEqual(report.criticalPath, expectedCriticalPath);
  assert.ok(
    report.criticalPath.events.every(
      ({ endedAtMilliseconds }) =>
        endedAtMilliseconds <= report.criticalPath.elapsedWallMilliseconds + 0.001
    )
  );
  assert.ok(
    report.criticalPath.intervals.every(
      ({ endedAtMilliseconds }) =>
        endedAtMilliseconds <= report.criticalPath.elapsedWallMilliseconds + 0.001
    )
  );
  assert.ok(
    scheduler
      .report()
      .criticalPath.events.some(({ activity }) => activity === "deployment-postprocessing")
  );
});

test("scheduler rejects queued work after the first failure while active work drains", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 2,
  });
  let failSibling;
  const failure = new Error("first native stage failed");
  const siblingFailure = new Error("second native stage failed");
  const failed = scheduler.run("generated-c", async () => {
    throw failure;
  });
  const sibling = scheduler.run(
    "runtime-main-object",
    () =>
      new Promise((_, reject) => {
        failSibling = () => reject(siblingFailure);
      })
  );
  const queued = scheduler.run("wasmtime-aot", async () => timing(), { workerSlots: 2 });

  await assert.rejects(failed, (error) => error === failure);
  await assert.rejects(queued, (error) => error === failure);
  assert.equal(scheduler.queuedCount, 0);
  assert.equal(scheduler.activeCount, 1);
  failSibling();
  await assert.rejects(sibling, (error) => error === siblingFailure);
  await assert.rejects(
    scheduler.run("runtime-main-object", async () => timing()),
    (error) => error === failure
  );
  await assert.rejects(
    scheduler.run("module-graph-leaf-wasmtime-aot", async () => timing(), {
      workingSetEstimateBytes: 6 * GIBIBYTE,
    }),
    (error) => error === failure
  );
  assert.equal(scheduler.activeCount, 0);
  assert.equal(scheduler.report().failedCount, 2);
});

test("scheduler keeps admission open after an explicitly recoverable failure", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    jobs: 1,
  });
  const failure = new Error("speculative native stage failed");
  let queuedStarted = false;
  const failed = scheduler.run(
    "wasmtime-aot",
    async () => {
      throw failure;
    },
    { failureClosesAdmission: false }
  );
  const queued = scheduler.run("runtime-main-object", async () => {
    queuedStarted = true;
    return timing();
  });

  await assert.rejects(failed, (error) => error === failure);
  await queued;
  assert.equal(queuedStarted, true);
  await scheduler.run("runtime-main-object", async () => timing());
  await scheduler.idle();

  const report = scheduler.report();
  assert.equal(report.failedCount, 1);
  assert.equal(report.completedCount, 2);
});

test("scheduler retains bounded native failure classifications after successful retries", async () => {
  const scheduler = createScheduler({ jobs: 1 });
  const diagnostics = [
    { kind: "command-exit", code: 137, signal: null },
    { kind: "command-exit", code: null, signal: "SIGTERM" },
    { kind: "guard-termination", terminationKind: "resource-monitor-error" },
    { kind: "output-validation", reason: "timing-malformed" },
  ];
  for (const diagnostic of diagnostics) {
    const cause = new Error("private cause");
    const failure = new ConvexWasmNativeCommandFailure(
      "private command output",
      {
        ...diagnostic,
        stderr: "private command output",
        args: ["private argument"],
      },
      { cause }
    );
    await assert.rejects(
      scheduler.run(
        "wasmtime-aot",
        async () => {
          throw failure;
        },
        {
          failureClosesAdmission: false,
        }
      ),
      (error) => {
        assert.equal(error, failure);
        assert.equal(error.message, "private command output");
        assert.equal(error.cause, cause);
        return true;
      }
    );
    await scheduler.run("wasmtime-aot", async () => timing());
  }
  const events = scheduler.report().criticalPath.events;
  assert.deepEqual(
    events.filter(({ outcome }) => outcome === "failed").map(({ failure }) => failure),
    diagnostics
  );
  assert.ok(
    events
      .filter(({ outcome }) => outcome === "completed")
      .every((event) => !Object.hasOwn(event, "failure"))
  );
  assert.ok(!JSON.stringify(events).includes("private"));
  assert.ok(
    events
      .filter(({ failure }) => failure !== undefined)
      .every(({ failure }) => Object.isFrozen(failure))
  );
});

test("scheduler treats undefined throws and rejections as failures", async (t) => {
  await t.test("throw", () =>
    assertUndefinedFailureStopsScheduler(() => {
      throw undefined;
    })
  );
  await t.test("rejection", () =>
    assertUndefinedFailureStopsScheduler(() => Promise.reject(undefined))
  );
});

test("AOT process concurrency and per-process workers are independent", async () => {
  const launchPolicy = createLaunchPolicy({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 2,
    jobs: 3,
  });
  const aotCommand = { args: ["--package", "/fixture/precompiler", "--", "module.wasm"] };
  assert.equal(convexWasmNativeCommandWorkerSlots(aotCommand, launchPolicy), 2);
  assert.deepEqual(convexWasmNativeCommandArguments(aotCommand, launchPolicy), [
    "--package",
    "/fixture/precompiler",
    "--",
    "module.wasm",
    "--parallel-compilation-workers",
    "2",
  ]);
  assert.equal(convexWasmNativeCommandWorkerSlots({ args: ["-c", "input.c"] }, launchPolicy), 1);

  const scheduler = createScheduler(launchPolicy);
  const started = [];
  let release;
  const first = scheduler.run(
    "wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("first");
        release = resolve;
      }),
    { workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, launchPolicy) }
  );
  const second = scheduler.run(
    "wasmtime-aot",
    async () => {
      started.push("second");
      return timing();
    },
    { workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, launchPolicy) }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["first"]);
  release(timing());
  await Promise.all([first, second]);
  assert.equal(scheduler.report().maximumActiveWorkerSlots, 2);
  assert.deepEqual(started, ["first", "second"]);
  assert.throws(
    () => createLaunchPolicy({ aotWorkers: 3, jobs: 2 }),
    /native launch AOT workers must not exceed jobs/u
  );

  const outerPolicy = createLaunchPolicy({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 1,
    jobs: 3,
  });
  const outerScheduler = createScheduler(outerPolicy);
  const outerStarted = [];
  let releaseOuter;
  const outerFirst = outerScheduler.run(
    "wasmtime-aot",
    () =>
      new Promise((resolve) => {
        outerStarted.push("first");
        releaseOuter = resolve;
      }),
    { workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, outerPolicy) }
  );
  const outerSecond = outerScheduler.run(
    "wasmtime-aot",
    async () => {
      outerStarted.push("second");
      return timing();
    },
    { workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, outerPolicy) }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(outerStarted, ["first", "second"]);
  releaseOuter(timing());
  await Promise.all([outerFirst, outerSecond]);
});

test("input-sized AOT work uses matching proportional scheduler and process workers", async () => {
  const launchPolicy = createLaunchPolicy({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 6,
    jobs: 9,
  });
  const aotCommand = { args: ["--package", "/fixture/precompiler", "--", "module.wasm"] };
  const scheduler = createScheduler(launchPolicy);
  const releases = [];
  const operationalWorkerCounts = [];
  const tasks = Array.from({ length: 9 }, () =>
    scheduler.run(
      "module-graph-shared-wasmtime-aot",
      () => {
        operationalWorkerCounts.push(
          Number(convexWasmNativeCommandArguments(aotCommand, launchPolicy).at(-1))
        );
        return new Promise((resolve) => releases.push(() => resolve(timing())));
      },
      {
        workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, launchPolicy),
        workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(8 * MEBIBYTE),
      }
    )
  );

  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(scheduler.activeCount, 9);
  assert.equal(scheduler.activeWorkerSlots, 9);
  assert.deepEqual(operationalWorkerCounts, Array(9).fill(1));
  for (const release of releases) release();
  await Promise.all(tasks);

  let mediumOperationalWorkerCount;
  await scheduler.run(
    "module-graph-shared-wasmtime-aot",
    async () => {
      mediumOperationalWorkerCount = Number(
        convexWasmNativeCommandArguments(aotCommand, launchPolicy).at(-1)
      );
      return timing();
    },
    {
      workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, launchPolicy),
      workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(20 * MEBIBYTE),
    }
  );
  assert.equal(mediumOperationalWorkerCount, 3);

  const largeCoreWasmBytes = 64 * MEBIBYTE;
  let largeOperationalWorkerCount;
  await scheduler.run(
    "module-graph-shared-wasmtime-aot",
    async () => {
      largeOperationalWorkerCount = Number(
        convexWasmNativeCommandArguments(aotCommand, launchPolicy).at(-1)
      );
      return timing();
    },
    {
      workerSlots: convexWasmNativeCommandWorkerSlots(aotCommand, launchPolicy),
      workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(largeCoreWasmBytes),
    }
  );
  assert.equal(largeOperationalWorkerCount, 6);
  const nativeEvents = scheduler
    .report()
    .criticalPath.events.filter(({ kind }) => kind === "native-phase");
  assert.deepEqual(
    nativeEvents.map(({ workerSlots }) => workerSlots),
    [...Array(9).fill(1), 3, 6]
  );
  assert.equal(convexWasmNativeCommandArguments(aotCommand, launchPolicy).at(-1), "6");
  assert.throws(
    () =>
      scheduler.run("module-graph-shared-wasmtime-aot", async () => timing(), {
        workerSlots: 7,
        workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(largeCoreWasmBytes),
      }),
    /AOT worker slots 7 exceed configured AOT workers 6/u
  );
});

test("small leaf AOT uses configured workers and reserves them against concurrent commands", async () => {
  const launchPolicy = createLaunchPolicy({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 6,
    jobs: 6,
  });
  const scheduler = createScheduler(launchPolicy);
  const command = { args: ["--package", "/fixture/precompiler", "--", "module.wasm"] };
  let releaseLeaf;
  let objectStarted = false;
  const leaf = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () => {
      assert.equal(convexWasmNativeCommandArguments(command, launchPolicy).at(-1), "6");
      return new Promise((resolve) => {
        releaseLeaf = () => resolve(timing());
      });
    },
    {
      workerSlots: convexWasmNativeCommandWorkerSlots(command, launchPolicy),
      workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(3 * MEBIBYTE),
    }
  );
  const object = scheduler.run("runtime-main-object", async () => {
    objectStarted = true;
    return timing();
  });
  assert.equal(scheduler.activeWorkerSlots, 6);
  assert.equal(scheduler.activeWorkingSetEstimateBytes, 512 * MEBIBYTE);
  assert.equal(objectStarted, false);
  releaseLeaf();
  await Promise.all([leaf, object]);
  assert.equal(objectStarted, true);
  assert.equal(scheduler.activeWorkerSlots, 0);
  assert.equal(scheduler.report().maximumActiveWorkerSlots, 6);
});

test("AOT admission uses conservative Core Wasm estimates and isolates oversize work", async () => {
  assert.equal(convexWasmNativeAotWorkingSetEstimateBytes(8 * MEBIBYTE), 512 * MEBIBYTE);
  const largeCoreWasmBytes = 64 * MEBIBYTE;
  assert.ok(
    convexWasmNativeAotWorkingSetEstimateBytes(largeCoreWasmBytes) >= 4 * GIBIBYTE,
    "64 MiB Core Wasm estimate must reserve at least 4 GiB"
  );
  assert.equal(convexWasmNativeAotWorkingSetEstimateBytes(128 * MEBIBYTE), 128 * 64 * MEBIBYTE);
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 1,
    jobs: 3,
  });
  const started = [];
  let releaseLarge;
  const large = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        releaseLarge = () => resolve(timing());
        started.push("large");
      }),
    {
      workerSlots: 1,
      workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(largeCoreWasmBytes),
    }
  );
  const small = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    async () => {
      started.push("small");
      return timing();
    },
    {
      workerSlots: 1,
      workingSetEstimateBytes: convexWasmNativeAotWorkingSetEstimateBytes(8 * MEBIBYTE),
    }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["large", "small"]);
  releaseLarge();
  await Promise.all([large, small]);

  const maximumFittingEstimate = 5 * GIBIBYTE;
  const exclusiveScheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 1,
    jobs: 2,
  });
  const exclusiveStarted = [];
  let releaseExclusive;
  const exclusive = exclusiveScheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        exclusiveStarted.push("maximum");
        releaseExclusive = () => resolve(timing());
      }),
    { workerSlots: 1, workingSetEstimateBytes: maximumFittingEstimate }
  );
  const afterExclusive = exclusiveScheduler.run(
    "module-graph-leaf-wasmtime-aot",
    async () => {
      exclusiveStarted.push("small");
      return timing();
    },
    { workerSlots: 1, workingSetEstimateBytes: 512 * MEBIBYTE }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(exclusiveStarted, ["maximum"]);
  assert.equal(exclusiveScheduler.activeAdmissionWorkingSetEstimateBytes, maximumFittingEstimate);
  releaseExclusive();
  await Promise.all([exclusive, afterExclusive]);
  assert.deepEqual(exclusiveStarted, ["maximum", "small"]);

  const oversizedCoreWasmBytes = 128 * MEBIBYTE;
  const oversizedEstimate = convexWasmNativeAotWorkingSetEstimateBytes(oversizedCoreWasmBytes);
  assert.equal(oversizedEstimate, 8 * GIBIBYTE);
  const reducedAggregateMemoryMaxBytes = 5 * GIBIBYTE;
  const oversizedLaunchPolicy = createLaunchPolicy({
    aggregateMemoryMaxBytes: reducedAggregateMemoryMaxBytes,
    aotWorkers: 6,
    jobs: 9,
  });
  const oversizedScheduler = createScheduler(oversizedLaunchPolicy);
  const oversizedAotCommand = {
    args: ["--package", "/fixture/precompiler", "--", "module.wasm"],
  };
  const oversizedStarted = [];
  let releaseOversized;
  const oversized = oversizedScheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        oversizedStarted.push(
          `oversized-${convexWasmNativeCommandArguments(
            oversizedAotCommand,
            oversizedLaunchPolicy
          ).at(-1)}-workers`
        );
        releaseOversized = () => resolve(timing());
      }),
    {
      workerSlots: convexWasmNativeCommandWorkerSlots(oversizedAotCommand, oversizedLaunchPolicy),
      workingSetEstimateBytes: oversizedEstimate,
    }
  );
  const afterOversized = oversizedScheduler.run(
    "module-graph-leaf-wasmtime-aot",
    async () => {
      oversizedStarted.push("after-oversized");
      return timing();
    },
    { workerSlots: 1, workingSetEstimateBytes: 512 * MEBIBYTE }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(oversizedStarted, ["oversized-6-workers"]);
  assert.equal(
    oversizedScheduler.activeAdmissionWorkingSetEstimateBytes,
    reducedAggregateMemoryMaxBytes
  );
  assert.equal(oversizedScheduler.activeWorkingSetEstimateBytes, oversizedEstimate);
  assert.equal(oversizedScheduler.activeWorkerSlots, 6);
  const activeOversizedInterval = oversizedScheduler
    .report()
    .criticalPath.intervals.find(
      ({ activeCommandCount, admissionWorkingSetEstimateBytes, estimatedWorkingSetBytes }) =>
        activeCommandCount === 1 &&
        admissionWorkingSetEstimateBytes === reducedAggregateMemoryMaxBytes &&
        estimatedWorkingSetBytes === oversizedEstimate
    );
  assert.notEqual(activeOversizedInterval, undefined);
  releaseOversized();
  await Promise.all([oversized, afterOversized]);
  assert.deepEqual(oversizedStarted, ["oversized-6-workers", "after-oversized"]);
  const oversizedReport = oversizedScheduler.report();
  assert.equal(oversizedReport.maximumEstimatedWorkingSetBytes, oversizedEstimate);
  const oversizedEvent = oversizedReport.criticalPath.events.find(
    ({ workingSetEstimateBytes }) => workingSetEstimateBytes === oversizedEstimate
  );
  assert.equal(oversizedEvent.admissionWorkingSetEstimateBytes, reducedAggregateMemoryMaxBytes);
});

test("scheduler backfills one bounded worker-slot wave behind a blocked normal head", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 1,
    jobs: 3,
  });
  const started = [];
  let releaseBlocker;
  let releaseHead;
  const releaseSmall = [];
  const blocker = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("blocker");
        releaseBlocker = () => resolve(timing());
      }),
    { workerSlots: 1, workingSetEstimateBytes: 3 * GIBIBYTE }
  );
  const head = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("head");
        releaseHead = () => resolve(timing());
      }),
    { workerSlots: 1, workingSetEstimateBytes: 3 * GIBIBYTE }
  );
  const small = ["small-1", "small-2", "small-3"].map((name, index) =>
    scheduler.run(
      "module-graph-leaf-wasmtime-aot",
      async () => {
        started.push(name);
        if (index === 2) return timing();
        return new Promise((resolve) => {
          releaseSmall.push(() => resolve(timing()));
        });
      },
      { workerSlots: 1, workingSetEstimateBytes: 1 * GIBIBYTE }
    )
  );

  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["blocker", "small-1", "small-2"]);
  assert.equal(scheduler.activeWorkerSlots, 3);

  releaseBlocker();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["blocker", "small-1", "small-2", "head"]);
  releaseHead();
  for (const release of releaseSmall) release();
  await Promise.all([blocker, head, ...small]);
  assert.deepEqual(started, ["blocker", "small-1", "small-2", "head", "small-3"]);
});

test("scheduler applies bounded-wave fairness across mixed native stages", async () => {
  const aggregateMemoryMaxBytes = 5 * GIBIBYTE;
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes,
    aotWorkers: 1,
    jobs: 4,
  });
  const started = [];
  let releaseBlocker;
  let releaseHead;
  let releaseAotBackfill;
  let releaseRuntimeBackfill;
  const releaseGeneratedBackfills = [];
  const blocker = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("blocker");
        releaseBlocker = () => resolve(timing());
      }),
    { workingSetEstimateBytes: 2 * GIBIBYTE }
  );
  const head = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("head");
        releaseHead = () => resolve(timing());
      }),
    { workingSetEstimateBytes: 4 * GIBIBYTE }
  );
  const aotBackfill = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("aot-backfill");
        releaseAotBackfill = () => resolve(timing());
      }),
    { workingSetEstimateBytes: 512 * MEBIBYTE }
  );
  const generatedBackfills = ["generated-1", "generated-2"].map((name) =>
    scheduler.run(
      "generated-c",
      () =>
        new Promise((resolve) => {
          started.push(name);
          releaseGeneratedBackfills.push(() => resolve(timing()));
        })
    )
  );
  const runtimeBackfill = scheduler.run(
    "runtime-main-object",
    () =>
      new Promise((resolve) => {
        started.push("runtime-backfill");
        releaseRuntimeBackfill = () => resolve(timing());
      })
  );

  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["blocker", "aot-backfill", "generated-1", "generated-2"]);
  assert.equal(scheduler.queuedCount, 2);
  assert.ok(scheduler.activeAdmissionWorkingSetEstimateBytes <= aggregateMemoryMaxBytes);

  releaseGeneratedBackfills.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(
    started.includes("runtime-backfill"),
    false,
    "a completed backfill must not replenish the bounded wave before its FIFO head runs"
  );
  assert.ok(scheduler.report().criticalPath.queuedStateMilliseconds.fairness > 0);

  releaseBlocker();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(started.includes("head"), false);
  assert.equal(started.includes("runtime-backfill"), false);

  releaseGeneratedBackfills.shift()();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started.slice(-2), ["head", "runtime-backfill"]);
  assert.ok(scheduler.activeAdmissionWorkingSetEstimateBytes <= aggregateMemoryMaxBytes);

  releaseHead();
  releaseAotBackfill();
  releaseRuntimeBackfill();
  await Promise.all([blocker, head, aotBackfill, ...generatedBackfills, runtimeBackfill]);
});

test("oversize work waits for the full slice while one bounded backfill wave runs", async () => {
  const scheduler = createScheduler({
    aggregateMemoryMaxBytes: 5 * GIBIBYTE,
    aotWorkers: 1,
    jobs: 3,
  });
  const started = [];
  let releaseBlocker;
  const blocker = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    () =>
      new Promise((resolve) => {
        started.push("blocker");
        releaseBlocker = () => resolve(timing());
      }),
    { workerSlots: 1, workingSetEstimateBytes: 1 * GIBIBYTE }
  );
  const oversize = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    async () => {
      started.push("oversize");
      return timing();
    },
    { workerSlots: 1, workingSetEstimateBytes: 6 * GIBIBYTE }
  );
  assert.equal(scheduler.activeCount, 1);
  assert.equal(scheduler.queuedCount, 1);
  assert.equal(scheduler.report().requestCount, 2);
  const small = scheduler.run(
    "module-graph-leaf-wasmtime-aot",
    async () => {
      started.push("small");
      return timing();
    },
    { workerSlots: 1, workingSetEstimateBytes: 1 * GIBIBYTE }
  );

  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, ["blocker", "small"]);
  assert.equal(scheduler.queuedCount, 1);

  releaseBlocker();
  await Promise.all([blocker, oversize, small]);
  assert.deepEqual(started, ["blocker", "small", "oversize"]);
});
