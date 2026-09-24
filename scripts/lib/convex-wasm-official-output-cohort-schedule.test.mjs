import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmSourceEnvelopeKind } from "./convex-wasm-source-envelope.mjs";
import {
  authenticateConvexWasmOfficialOutputCohortSchedule,
  convexWasmOfficialOutputCohortPartitionPolicy,
  createConvexWasmOfficialOutputCohortSchedule,
  scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule,
  scheduleConvexWasmOfficialOutputCohortBuilds,
} from "./convex-wasm-official-output-cohort-schedule.mjs";

const digest = (character) => character.repeat(64);

function withSourceEnvelopeIdentity(envelope) {
  const { sourceEnvelopeSha256: ignoredSourceEnvelopeSha256, ...payload } = envelope;
  return { ...payload, sourceEnvelopeSha256: fingerprintJson(payload) };
}

function sourceEnvelope({ entryCount, routesPerEntry = 1 }) {
  const routes = [];
  for (let entryIndex = 0; entryIndex < entryCount; entryIndex += 1) {
    const paddedEntryIndex = String(entryIndex).padStart(3, "0");
    for (let routeIndex = 0; routeIndex < routesPerEntry(entryIndex); routeIndex += 1) {
      const exportName = `route${String(routeIndex).padStart(2, "0")}`;
      routes.push({
        entryPath: `convex/entry${paddedEntryIndex}.ts`,
        exportName,
        modulePath: `entry${paddedEntryIndex}`,
        runtimeModulePath: `entry${paddedEntryIndex}.js`,
        udfKind: routeIndex % 2 === 0 ? "query" : "mutation",
        visibility: routeIndex % 3 === 0 ? "internal" : "public",
      });
    }
  }
  const selectedRoutes = routes.map((route) => ({
    ...route,
    dependencyGraphSha256: digest(
      (Number(route.modulePath.slice("entry".length)) % 10).toString(16)
    ),
  }));
  const entryPaths = [...new Set(selectedRoutes.map(({ entryPath }) => entryPath))];
  const payload = {
    actions: [],
    contextReuseAnalysis: {
      entries: entryPaths,
      kind: "convex-context-reuse-analysis",
      policyFingerprint: digest("c"),
      resultSha256: digest("d"),
    },
    entryPaths,
    graph: {
      effectExecutionMode: "guest-promise-event-loop",
      inputCount: 1_795,
      sha256: digest("a"),
      toolchain: { convex: "1.44.0", esbuild: "0.27.0" },
    },
    inventoryAuthority: { kind: "fixture-inventory-v1", snapshot: { revision: 1 } },
    kind: convexWasmSourceEnvelopeKind,
    routes,
    schemaVersion: 2,
    selectedRoutes,
  };
  return { ...payload, sourceEnvelopeSha256: fingerprintJson(payload) };
}

test("schedules 167 complete entry namespaces into deterministic 21 cohorts", () => {
  const envelope = sourceEnvelope({
    entryCount: 167,
    routesPerEntry: (entryIndex) => (entryIndex < 75 ? 8 : 7),
  });
  assert.equal(envelope.selectedRoutes.length, 1_244);
  const sourceEnvelopeFileSha256 = digest("b");
  const schedule = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize: 83_712,
  });

  assert.equal(schedule.cohorts.length, 21);
  assert.deepEqual(
    schedule.cohorts.map(({ entryCount }) => entryCount),
    [...Array.from({ length: 20 }, () => 8), 7]
  );
  assert.equal(
    schedule.cohorts.every(
      ({ entryCount }) => entryCount <= convexWasmOfficialOutputCohortPartitionPolicy.maximumEntries
    ),
    true
  );
  assert.deepEqual(
    schedule.cohorts.flatMap(({ entries }) => entries.map(({ entryPath }) => entryPath)),
    envelope.entryPaths
  );
  assert.equal(
    schedule.cohorts.flatMap(({ entries }) => entries).flatMap(({ routes }) => routes).length,
    1_244
  );
  assert.deepEqual(
    authenticateConvexWasmOfficialOutputCohortSchedule({
      schedule,
      sourceEnvelope: envelope,
      sourceEnvelopeFileSha256,
      sourceEnvelopeFileSize: 83_712,
    }),
    schedule
  );

  const repeated = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize: 83_712,
  });
  assert.deepEqual(repeated, schedule);

  const differentEnvelopeFile = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256: digest("c"),
    sourceEnvelopeFileSize: 83_712,
  });
  assert.notEqual(differentEnvelopeFile.identity.sha256, schedule.identity.sha256);
  assert.deepEqual(
    differentEnvelopeFile.cohorts.map(({ cohortId }) => cohortId),
    schedule.cohorts.map(({ cohortId }) => cohortId)
  );
});

test("rejects a selected route subset because cohorts retain complete entry namespaces", () => {
  const envelope = sourceEnvelope({ entryCount: 2, routesPerEntry: () => 2 });
  const partial = structuredClone(envelope);
  partial.selectedRoutes = partial.selectedRoutes.filter(
    ({ entryPath, exportName }) => entryPath !== "convex/entry000.ts" || exportName !== "route01"
  );
  partial.entryPaths = [...new Set(partial.selectedRoutes.map(({ entryPath }) => entryPath))];
  const authenticatedPartial = withSourceEnvelopeIdentity(partial);

  assert.throws(
    () => createConvexWasmOfficialOutputCohortSchedule({ sourceEnvelope: authenticatedPartial }),
    /complete authenticated query\/mutation namespace/u
  );
});

test("rejects schedule mutations and source-envelope or toolchain drift", () => {
  const envelope = sourceEnvelope({ entryCount: 9, routesPerEntry: () => 1 });
  const schedule = createConvexWasmOfficialOutputCohortSchedule({ sourceEnvelope: envelope });
  assert.deepEqual(
    schedule.cohorts.map(({ entryCount }) => entryCount),
    [8, 1]
  );

  const tamperedSchedule = structuredClone(schedule);
  tamperedSchedule.cohorts[0].entries[0].routes[0].visibility = "public";
  assert.throws(
    () =>
      authenticateConvexWasmOfficialOutputCohortSchedule({
        schedule: tamperedSchedule,
        sourceEnvelope: envelope,
      }),
    /identity does not match its complete namespace/u
  );

  const changedToolchain = structuredClone(envelope);
  changedToolchain.graph.toolchain = {
    convex: "1.44.0",
    esbuild: "0.28.0",
  };
  const authenticatedChangedToolchain = withSourceEnvelopeIdentity(changedToolchain);
  assert.throws(
    () =>
      authenticateConvexWasmOfficialOutputCohortSchedule({
        schedule,
        sourceEnvelope: authenticatedChangedToolchain,
      }),
    /source envelope and toolchain/u
  );
});

test("reuses only an exactly authenticated frozen schedule with matching source authority", () => {
  const envelope = sourceEnvelope({ entryCount: 9, routesPerEntry: () => 1 });
  const sourceEnvelopeFileSha256 = digest("b");
  const sourceEnvelopeFileSize = 83_712;
  const constructed = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize,
  });
  const authenticated = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: constructed,
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize,
  });

  assert.notEqual(authenticated, constructed);
  assert.equal(Object.isFrozen(constructed.cohorts[0]), false);
  assert.equal(
    authenticateConvexWasmOfficialOutputCohortSchedule({
      schedule: authenticated,
      sourceEnvelope: envelope,
      sourceEnvelopeFileSha256,
      sourceEnvelopeFileSize,
    }),
    authenticated
  );
  assert.equal(Object.isFrozen(authenticated), true);
  assert.equal(Object.isFrozen(authenticated.cohorts), true);
  assert.equal(Object.isFrozen(authenticated.cohorts[0]), true);
  assert.equal(Object.isFrozen(authenticated.cohorts[0].entries), true);
  assert.equal(Object.isFrozen(authenticated.cohorts[0].entries[0]), true);
  assert.equal(Object.isFrozen(authenticated.cohorts[0].entries[0].routes), true);
  assert.equal(Object.isFrozen(authenticated.cohorts[0].entries[0].routes[0]), true);
  assert.equal(Object.isFrozen(authenticated.identity), true);
  assert.equal(Object.isFrozen(authenticated.identity.cohorts), true);
  assert.equal(Object.isFrozen(authenticated.identity.provenance), true);
  assert.equal(Object.isFrozen(authenticated.identity.provenance.sourceEnvelope), true);
  assert.equal(Object.isFrozen(authenticated.identity.provenance.sourceEnvelope.file), true);
  assert.equal(Object.isFrozen(authenticated.identity.provenance.toolchain), true);

  const changedEnvelope = withSourceEnvelopeIdentity({
    ...envelope,
    graph: {
      ...envelope.graph,
      toolchain: { ...envelope.graph.toolchain, esbuild: "0.28.0" },
    },
  });
  assert.throws(
    () =>
      authenticateConvexWasmOfficialOutputCohortSchedule({
        schedule: authenticated,
        sourceEnvelope: changedEnvelope,
        sourceEnvelopeFileSha256,
        sourceEnvelopeFileSize,
      }),
    /source envelope SHA-256|toolchain/u
  );
  assert.throws(
    () =>
      authenticateConvexWasmOfficialOutputCohortSchedule({
        schedule: authenticated,
        sourceEnvelope: envelope,
        sourceEnvelopeFileSha256: digest("c"),
        sourceEnvelopeFileSize,
      }),
    /source-envelope file identity/u
  );

  const clone = structuredClone(authenticated);
  const authenticatedClone = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: clone,
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize,
  });
  assert.notEqual(authenticatedClone, authenticated);
  assert.deepEqual(authenticatedClone, authenticated);
});

test("does not inherit physical source-envelope authority on the retained fast path", () => {
  const envelope = sourceEnvelope({ entryCount: 1, routesPerEntry: () => 1 });
  const authenticated = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: createConvexWasmOfficialOutputCohortSchedule({ sourceEnvelope: envelope }),
    sourceEnvelope: envelope,
  });
  Object.defineProperty(Object.prototype, "file", {
    configurable: true,
    value: { sha256: digest("b"), size: 83_712 },
  });
  try {
    assert.throws(
      () =>
        authenticateConvexWasmOfficialOutputCohortSchedule({
          schedule: authenticated,
          sourceEnvelope: envelope,
          sourceEnvelopeFileSha256: digest("b"),
          sourceEnvelopeFileSize: 83_712,
        }),
      /source-envelope file identity/u
    );
  } finally {
    delete Object.prototype.file;
  }
});

test("does not inherit top-level physical source-envelope authority", () => {
  const envelope = sourceEnvelope({ entryCount: 1, routesPerEntry: () => 1 });
  const inheritedOptions = Object.create({
    sourceEnvelopeFileSha256: digest("b"),
    sourceEnvelopeFileSize: 83_712,
  });
  inheritedOptions.sourceEnvelope = envelope;
  const unbound = createConvexWasmOfficialOutputCohortSchedule(inheritedOptions);
  assert.equal(Object.hasOwn(unbound.identity.provenance.sourceEnvelope, "file"), false);

  const bound = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256: digest("b"),
    sourceEnvelopeFileSize: 83_712,
  });
  inheritedOptions.schedule = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: bound,
    sourceEnvelope: envelope,
    sourceEnvelopeFileSha256: digest("b"),
    sourceEnvelopeFileSize: 83_712,
  });
  inheritedOptions.sourceEnvelope = envelope;
  assert.throws(
    () => authenticateConvexWasmOfficialOutputCohortSchedule(inheritedOptions),
    /source-envelope file identity/u
  );
});

test("runs authenticated cohort jobs with bounded concurrency and schedule order", async () => {
  const envelope = sourceEnvelope({ entryCount: 17, routesPerEntry: () => 1 });
  const schedule = createConvexWasmOfficialOutputCohortSchedule({ sourceEnvelope: envelope });
  let active = 0;
  let maximumActive = 0;
  const results = await scheduleConvexWasmOfficialOutputCohortBuilds({
    build: async ({ cohort, cohortIndex, scheduleIdentity }) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return {
        cohortId: cohort.cohortId,
        cohortIndex,
        firstEntryPath: cohort.entries[0].entryPath,
        scheduleIdentity,
      };
    },
    concurrency: 2,
    schedule,
    sourceEnvelope: envelope,
  });

  assert.equal(maximumActive, 2);
  assert.deepEqual(
    results.map(({ cohortIndex }) => cohortIndex),
    [0, 1, 2]
  );
  assert.deepEqual(
    results.map(({ firstEntryPath }) => firstEntryPath),
    ["convex/entry000.ts", "convex/entry008.ts", "convex/entry016.ts"]
  );
  assert.equal(
    results.every(({ scheduleIdentity }) => scheduleIdentity === schedule.identity.sha256),
    true
  );
});

test("authenticated schedule runner rejects an unmarked schedule object", async () => {
  const envelope = sourceEnvelope({ entryCount: 1, routesPerEntry: () => 1 });
  const constructed = createConvexWasmOfficialOutputCohortSchedule({ sourceEnvelope: envelope });
  await assert.rejects(
    scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule({
      build: async () => undefined,
      concurrency: 1,
      schedule: constructed,
    }),
    /schedule authenticated by this module/u
  );
  const schedule = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: constructed,
    sourceEnvelope: envelope,
  });
  await assert.rejects(
    scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule({
      build: async () => undefined,
      concurrency: 1,
      schedule: structuredClone(schedule),
    }),
    /schedule authenticated by this module/u
  );
  const result = await scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule({
    build: async ({ scheduleIdentity }) => scheduleIdentity,
    concurrency: 1,
    schedule,
  });
  assert.deepEqual(result, [schedule.identity.sha256]);
});

test("waits for started cohort builds before reporting a failure", async () => {
  const envelope = sourceEnvelope({ entryCount: 17, routesPerEntry: () => 1 });
  const schedule = createConvexWasmOfficialOutputCohortSchedule({ sourceEnvelope: envelope });
  const started = [];
  let releaseSecondBuild;
  let secondBuildStarted;
  const secondBuildStartedPromise = new Promise((resolve) => {
    secondBuildStarted = resolve;
  });
  const secondBuildFinished = new Promise((resolve) => {
    releaseSecondBuild = resolve;
  });
  const failure = new Error("first cohort failed");
  const result = scheduleConvexWasmOfficialOutputCohortBuilds({
    build: async ({ cohortIndex }) => {
      started.push(cohortIndex);
      if (cohortIndex === 0) {
        await secondBuildStartedPromise;
        throw failure;
      }
      if (cohortIndex === 1) {
        secondBuildStarted();
        await secondBuildFinished;
        return cohortIndex;
      }
      throw new Error(`unexpected cohort ${String(cohortIndex)}`);
    },
    concurrency: 2,
    schedule,
    sourceEnvelope: envelope,
  });
  await secondBuildStartedPromise;
  let settled = false;
  void result.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  releaseSecondBuild();
  await assert.rejects(result, failure);
  assert.deepEqual(started, [0, 1]);
});
