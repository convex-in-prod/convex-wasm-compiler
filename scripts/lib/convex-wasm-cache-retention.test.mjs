import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { acquireConvexWasmCacheLock } from "./convex-wasm-cache-lock.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { fingerprintMaterialPaths } from "./convex-wasm-artifact-material.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "./convex-wasm-module-graph-package.mjs";
import {
  C_BUNDLE_MANIFEST_PATH,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import {
  convexWasmBuildWorkRecordName,
  createConvexWasmBuildWorkLease,
  maintainConvexWasmCache,
  measureConvexWasmCacheOccupancy,
  recordConvexWasmSuccessfulCacheUse,
} from "./convex-wasm-cache-retention.mjs";
import {
  currentConvexWasmRetentionPhase,
  planConvexWasmImmutableGc,
  sweepConvexWasmImmutableGc,
} from "./convex-wasm-cache-retention-immutable.mjs";
import { loadOrCreateConvexWasmRuntimeHeaderSnapshotCache } from "./convex-wasm-runtime-header-snapshot-cache.mjs";
import {
  planStaticHermesRetainedLayout,
  publishStaticHermesRetainedLayout,
  staticHermesLayoutCacheReferences,
} from "./convex-wasm-static-hermes-layout-cache.mjs";

async function fixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-cache-retention-"));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheRoot = join(root, "cache");
  const environment = {
    CONVEX_WASM_CACHE_LOCK_DB: join(root, "cache-lock.sqlite"),
  };
  const layout = (buildId) =>
    deriveConvexWasmCacheLayout({
      buildId,
      cacheRoot, scope: "isolated-test",
      repositoryRoot: root,
    });
  return { cacheRoot, environment, layout, root };
}

async function withHeavyLock(environment, operation) {
  const release = await acquireConvexWasmCacheLock({ environment });
  try {
    return await operation();
  } finally {
    release();
  }
}

async function isVerifiedQuarantineRoot(path) {
  if (!path.includes("immutable-sweep-trash") || !/^[0-9a-f]{64}$/u.test(path.split("/").at(-1))) return false;
  try {
    await fs.lstat(`${path}.verified.json`);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function maintenanceOptions(fixtureValue, overrides = {}) {
  return {
    clock: () => overrides.nowMs ?? Date.now(),
    abandonedRecoveryMilliseconds: 1_000,
    cacheRoot: fixtureValue.cacheRoot,
    completedRetentionMilliseconds: 1_000,
    environment: fixtureValue.environment,
    includeImmutableOccupancy: false,
    quiescentMilliseconds: 1_000,
    ...overrides,
  };
}

import {
  writeGenericArtifact,
  ageGenericArtifact,
  ageTree,
  packageFileMaterial,
  writeLegacyV2ModuleGraphPackage,
  writeCBundleArtifact,
  compilerOutputReference,
  compilerOutputCacheIdentity,
  writeCompilerOutputFixture,
  writeCohortCapsuleFixture,
  materializeModuleGraphPackageFixture,
  writeLegacyDeploymentResultCertificate
} from "../test-fixtures/cache-retention.mjs";

test("successful builds remove their object-level work root", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("successful-build");
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await fs.mkdir(layout.work.scratch, { mode: 0o700 });
    await fs.writeFile(join(layout.work.scratch, "recoverable-object"), "object", {
      mode: 0o600,
    });
    await lease.complete(2_000);
  });
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("work cleanup and lease completion drain admitted deletions before lock release", async (t) => {
  for (const boundary of ["maintenance", "lease-completion"]) {
    await t.test(boundary, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout("work-deletion-drain");
      let held = false;
      const cacheLock = {
        acquire() { assert.equal(held, false); held = true; return () => { held = false; }; },
        inheritedAuthorityEnvironment() { return {}; },
        requireAuthority() { assert.equal(held, true); },
      };
      const releaseSetup = cacheLock.acquire();
      let lease;
      const recordPath = join(cacheLayout.work.buildRoot, convexWasmBuildWorkRecordName);
      const delayedPath = join(cacheLayout.work.scratch, "delayed-output");
      try {
        lease = await createConvexWasmBuildWorkLease({ cacheLayout, cacheLock, nowMs: 1_000 });
        await fs.mkdir(cacheLayout.work.scratch, { mode: 0o700 });
        await fs.writeFile(delayedPath, "output", { mode: 0o600 });
        if (boundary === "maintenance") {
          const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
          await fs.writeFile(recordPath, `${JSON.stringify({
            ...record, status: "completed", updatedAtMs: 2_000,
            outcome: { kind: "deployment-completed", completedAtMs: 2_000 },
          })}\n`);
        }
      } finally { releaseSetup(); }

      const started = Promise.withResolvers();
      const delayed = Promise.withResolvers();
      const failed = Promise.withResolvers();
      const unlink = fs.unlink;
      fs.unlink = async (path, ...args) => {
        if (path === recordPath) {
          await started.promise;
          failed.resolve();
          throw new Error("synthetic work unlink failure");
        }
        if (path === delayedPath) {
          started.resolve();
          await delayed.promise;
          assert.equal(held, true, "admitted nested output deletion must remain under the lock");
        }
        return await unlink(path, ...args);
      };
      const options = maintenanceOptions(value, { apply: true, automaticImmutableSweep: true,
        immutableHighWatermarkAllocatedBytes: 1, cacheLock, nowMs: 3_000 });
      const operation = boundary === "maintenance"
        ? maintainConvexWasmCache(options)
        : (async () => {
            const release = cacheLock.acquire();
            try {
              try { await lease.complete(2_000); }
              catch (error) {
                // Match callers that report deployment failure after completed-root cleanup
                // fails: this must preserve the already-written completion authority.
                await lease.fail(2_001);
                throw error;
              }
            } finally { release(); }
          })();
      let settled = false;
      const result = operation.then(
        () => { settled = true; return undefined; },
        (error) => { settled = true; return error; }
      );
      try {
        await failed.promise;
        await new Promise((resolve) => setImmediate(resolve));
        assert.equal(held, true);
        assert.equal(settled, false);
        delayed.resolve();
        assert.match((await result).message, /synthetic work unlink failure/u);
        assert.equal(held, false);
      } finally { delayed.resolve(); await result; fs.unlink = unlink; }
      const completed = JSON.parse(await fs.readFile(recordPath, "utf8"));
      assert.equal(completed.status, "completed");
      assert.deepEqual(completed.outcome, { kind: "deployment-completed", completedAtMs: 2_000 });
      await assert.rejects(fs.lstat(delayedPath), { code: "ENOENT" });
      await assert.rejects(fs.lstat(join(value.cacheRoot, "automatic-maintenance.json")), { code: "ENOENT" });
      const retry = await maintainConvexWasmCache(options);
      assert.equal(retry.work.roots[0].action, "remove");
      assert.equal(retry.work.roots[0].status, "completed");
      await assert.rejects(fs.lstat(cacheLayout.work.buildRoot), { code: "ENOENT" });
    });
  }
});

test("failed work has bounded recovery and is removed after expiry", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("failed-build");
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await fs.mkdir(layout.work.reports, { mode: 0o700 });
    await fs.writeFile(join(layout.work.reports, "failure-evidence.json"), "{}\n", {
      mode: 0o600,
    });
    await lease.fail(2_000);
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 1_000_000 })
  );
  assert.deepEqual(report.work.roots, [
    {
      action: "retain",
      buildId: "failed-build",
      reason: "failed-build-recovery-window-open",
      recoverableUntilMs: 604802000,
      status: "failed",
    },
  ]);
  const record = JSON.parse(
    await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
  );
  assert.equal(record.status, "failed");
  assert.deepEqual(record.outcome, {
    failedAtMs: 2_000,
    kind: "deployment-failed",
    recoverableUntilMs: 604802000,
  });
  assert.equal(
    await fs.readFile(join(layout.work.reports, "failure-evidence.json"), "utf8"),
    "{}\n"
  );
  const expired = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 604802000 })
  );
  assert.equal(expired.work.roots[0].action, "remove");
  assert.equal(expired.work.roots[0].status, "failed");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("legacy failed records receive a deadline before any removal", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("legacy-failed-build");
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await lease.fail(2_000);
    const recordPath = join(layout.work.buildRoot, convexWasmBuildWorkRecordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    await fs.writeFile(
      recordPath,
      `${JSON.stringify({
        ...record,
        outcome: { failedAtMs: 2_000, kind: "deployment-failed", recoverable: true },
      })}\n`,
      { mode: 0o600 }
    );
  });
  const first = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 1_000_000 })
  );
  assert.equal(first.work.roots[0].action, "set-recovery-deadline");
  assert.equal(first.work.roots[0].recoverableUntilMs, 604_802_000);
  assert.equal(
    JSON.parse(
      await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
    ).outcome.recoverableUntilMs,
    604_802_000
  );
});

test("interrupted work is abandoned under quiescence and removed only after recovery", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("interrupted-build");
  await withHeavyLock(value.environment, async () => {
    await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await fs.mkdir(layout.work.timings, { mode: 0o700 });
    await fs.writeFile(join(layout.work.timings, "phase.json"), "{}\n", { mode: 0o600 });
  });

  const dryRun = await maintainConvexWasmCache(maintenanceOptions(value, { nowMs: 3_000 }));
  assert.equal(dryRun.work.roots[0].action, "mark-abandoned");
  assert.equal(
    JSON.parse(
      await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
    ).status,
    "active"
  );

  const first = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_000 })
  );
  assert.equal(first.work.roots[0].action, "mark-abandoned");
  assert.equal(first.work.roots[0].recoverableUntilMs, 4_000);
  assert.equal(
    JSON.parse(
      await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
    ).status,
    "abandoned"
  );

  const recoverable = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_999 })
  );
  assert.equal(recoverable.work.roots[0].action, "retain");
  assert.equal(await fs.readFile(join(layout.work.timings, "phase.json"), "utf8"), "{}\n");

  const expired = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 4_000 })
  );
  assert.equal(expired.work.roots[0].action, "remove");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("completed work left by an interrupted cleanup is removed after retention", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("completed-build");
  await withHeavyLock(value.environment, async () => {
    await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    const recordPath = join(layout.work.buildRoot, convexWasmBuildWorkRecordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    await fs.writeFile(
      recordPath,
      `${JSON.stringify({
        ...record,
        outcome: { completedAtMs: 2_000, kind: "deployment-completed" },
        status: "completed",
        updatedAtMs: 2_000,
      })}\n`
    );
  });

  const retained = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 2_999 })
  );
  assert.equal(retained.work.roots[0].action, "retain");
  const removed = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_000 })
  );
  assert.equal(removed.work.roots[0].action, "remove");
  assert.equal(removed.work.roots[0].status, "completed");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("invalid work records are reported and never removed", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("invalid-build");
  await fs.mkdir(layout.work.buildRoot, { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "work"),
    layout.work.root,
    layout.work.buildRoot,
  ]) {
    await fs.chmod(path, 0o700);
  }
  await fs.writeFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "not-json\n", {
    mode: 0o600,
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 1_000_000 })
  );
  assert.deepEqual(report.work.roots, [
    {
      action: "retain",
      buildId: "invalid-build",
      reason: "invalid-build-work-record",
      status: "invalid",
    },
  ]);
  assert.equal(
    await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8"),
    "not-json\n"
  );
});

test("legacy roots use the same two-phase abandonment protocol", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("legacy-build");
  await fs.mkdir(layout.work.buildRoot, { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "work"),
    layout.work.root,
    layout.work.buildRoot,
  ]) {
    await fs.chmod(path, 0o700);
  }
  await fs.writeFile(join(layout.work.buildRoot, "old-output"), "old", { mode: 0o600 });
  await fs.utimes(layout.work.buildRoot, new Date(1_000), new Date(1_000));

  const marked = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_000 })
  );
  assert.equal(marked.work.roots[0].action, "mark-abandoned");
  assert.equal(marked.work.roots[0].status, "legacy");
  assert.equal(await fs.readFile(join(layout.work.buildRoot, "old-output"), "utf8"), "old");

  const removed = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 4_000 })
  );
  assert.equal(removed.work.roots[0].action, "remove");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("dry-run reports immutable root candidates and hard-linked physical occupancy", async (t) => {
  const value = await fixture(t);
  const artifacts = join(value.cacheRoot, "immutable", "v6", "artifacts", "stage", "entry");
  const packages = join(value.cacheRoot, "immutable", "v6", "packages", "package", "payload");
  await fs.mkdir(dirname(artifacts), { mode: 0o700, recursive: true });
  await fs.mkdir(dirname(packages), { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "immutable"),
    join(value.cacheRoot, "immutable", "v6"),
    join(value.cacheRoot, "immutable", "v6", "artifacts"),
    join(value.cacheRoot, "immutable", "v6", "artifacts", "stage"),
    join(value.cacheRoot, "immutable", "v6", "packages"),
    join(value.cacheRoot, "immutable", "v6", "packages", "package"),
  ]) {
    await fs.chmod(path, 0o700);
  }
  await fs.writeFile(artifacts, Buffer.alloc(8_192, 1), { mode: 0o600 });
  await fs.link(artifacts, packages);

  const occupancy = await measureConvexWasmCacheOccupancy(value.cacheRoot);
  assert.equal(occupancy.regularFileCount, 2);
  assert.equal(occupancy.logicalRegularFileBytes, 16_384);
  assert.equal(occupancy.hardLinkedRegularFileReferences, 2);
  assert.ok(occupancy.allocatedBytes > occupancy.uniqueAllocatedBytes);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, { includeImmutableOccupancy: true, nowMs: 3_000 })
  );
  assert.equal(report.mode, "dry-run");
  assert.equal(report.immutable.sweepAuthorized, false);
  assert.deepEqual(
    report.immutable.rootMarkers.map(({ kind }) => kind),
    [
      "immutable-artifact-object-store",
      "immutable-package-root",
      "deployment-result-certificate-root",
    ]
  );
  assert.equal(report.occupancy.scope, "entire-cache");
  assert.equal(report.occupancy.logicalRegularFileBytes, 16_384);
  assert.ok(report.occupancy.allocatedBytes > report.occupancy.uniqueAllocatedBytes);
});

test("build leases and maintenance reject missing or inherited lock authority", async (t) => {
  const value = await fixture(t);
  await assert.rejects(
    createConvexWasmBuildWorkLease({
      cacheLayout: value.layout("unlocked-build"),
      environment: value.environment,
      nowMs: 1_000,
    }),
    /holds the cache lock/u
  );
  await withHeavyLock(value.environment, async () => {
    await assert.rejects(
      maintainConvexWasmCache(maintenanceOptions(value, { nowMs: 1_000 })),
      /must acquire the top-level cache lock/u
    );
  });
});

test("successful cache-use authority is bounded and immutable GC is dry-run only", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("authority-build");
  const deployment = {
    manifest: {
      moduleGraphBinding: { cohorts: [{ graphManifestSha256: "b".repeat(64) }] },
    },
  };
  deployment.manifest.deploymentSha256 = fingerprintJson(deployment.manifest);
  const emptyPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({ cacheLayout: layout, environment: value.environment, nowMs: 0 })
  );
  assert.equal(emptyPlan.evictions.length, 0);
  await withHeavyLock(value.environment, async () => {
    for (let index = 0; index < 10; index += 1) {
      const manifest = {
        fixtureIndex: index,
        moduleGraphBinding: deployment.manifest.moduleGraphBinding,
      };
      manifest.deploymentSha256 = fingerprintJson(manifest);
      await recordConvexWasmSuccessfulCacheUse({
        buildId: `authority-${index}`,
        cacheLayout: layout,
        deployment: { manifest },
        environment: value.environment,
        recordedAtMs: index,
      });
    }
  });
  const snapshots = await fs.readdir(
    join(value.cacheRoot, "state", "v1", "cache-retention", "v1", "recent-success")
  );
  assert.equal(snapshots.filter((name) => name.endsWith(".json")).length, 8);
});

test("successful-cache snapshot publication rejects a redirected state ancestor", async (t) => {
  const value = await fixture(t);
  const outsideState = join(value.root, "outside-snapshot-state");
  await fs.mkdir(outsideState, { mode: 0o700 });
  await fs.mkdir(value.cacheRoot, { mode: 0o700 });
  await fs.symlink(outsideState, join(value.cacheRoot, "state"), "dir");
  const manifest = {
    fixture: "snapshot-state-redirect",
    moduleGraphBinding: { cohorts: [{ graphManifestSha256: "c".repeat(64) }] },
  };
  manifest.deploymentSha256 = fingerprintJson(manifest);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      recordConvexWasmSuccessfulCacheUse({
        buildId: "snapshot-state-redirect",
        cacheLayout: value.layout("snapshot-state-redirect"),
        deployment: { manifest },
        environment: value.environment,
        recordedAtMs: 1_000,
      })
    ),
    /symlink/u
  );
  await assert.rejects(fs.lstat(join(outsideState, "v1")), { code: "ENOENT" });
});

test("immutable GC authenticates and retires a coherent legacy module graph v2 package triple", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("legacy-v2-package");
  const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.candidates, 1);
  assert.deepEqual(plan.evictions, []);
  assert.deepEqual(
    plan.retained.artifacts,
    [
      `${legacy.aot.stage}\0${legacy.aot.key}`,
      `${legacy.coreWasm.stage}\0${legacy.coreWasm.key}`,
    ].sort()
  );
  const sweep = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.deepEqual(sweep.removed.map(({ key, type }) => ({ key, type })), [
    { key: legacy.key, type: "package" },
  ]);
  await assert.rejects(fs.lstat(legacy.root), { code: "ENOENT" });
  await fs.lstat(join(cacheLayout.immutable.artifacts, legacy.aot.stage, legacy.aot.key));
});

test("immutable GC rejects a legacy v2 package whose provenance identity does not match its artifact", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("legacy-v2-provenance-identity-mismatch");
  const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
  const provenance = {
    ...legacy.provenance,
    identities: {
      ...legacy.provenance.identities,
      base: {
        ...legacy.provenance.identities.base,
        aot: { fixture: "unmatched-legacy-v2-aot-identity" },
      },
    },
  };
  const entry = { ...legacy.entry, provenance: packageFileMaterial(provenance) };
  await Promise.all([
    fs.writeFile(join(legacy.root, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
      mode: 0o600,
    }),
    fs.writeFile(join(legacy.root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
    ),
    /recent immutable authority is corrupt/u
  );
});

test("immutable GC rejects every mixed module graph package triple version", async (t) => {
  await t.test("v2 manifest with v3 provenance", async (t) => {
    const value = await fixture(t);
    const cacheLayout = value.layout("mixed-v2-manifest-v3-provenance");
    const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
    const provenance = {
      ...legacy.provenance,
      kind: "convex-wasm-module-graph-provenance-v3",
      schemaVersion: 3,
    };
    const entry = { ...legacy.entry, provenance: packageFileMaterial(provenance) };
    await Promise.all([
      fs.writeFile(join(legacy.root, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
        mode: 0o600,
      }),
      fs.writeFile(join(legacy.root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
        mode: 0o600,
      }),
    ]);

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });

  await t.test("v2 manifest and provenance with v3 package entry", async (t) => {
    const value = await fixture(t);
    const cacheLayout = value.layout("mixed-v2-triple-v3-package");
    const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
    const entry = { ...legacy.entry, kind: "convex-wasm-module-graph-package-v3" };
    await fs.writeFile(join(legacy.root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    });

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });

  await t.test("v3 manifest with v2 provenance", async (t) => {
    const value = await fixture(t);
    const { cacheLayout, graphManifestSha256 } = await materializeModuleGraphPackageFixture(value);
    const path = join(cacheLayout.immutable.packages, graphManifestSha256);
    const provenance = JSON.parse(await fs.readFile(join(path, "build-provenance.json"), "utf8"));
    provenance.kind = "convex-wasm-module-graph-provenance-v2";
    provenance.schemaVersion = 2;
    await fs.writeFile(join(path, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
      mode: 0o600,
    });

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });

  await t.test("v3 manifest and provenance with v2 package entry", async (t) => {
    const value = await fixture(t);
    const { cacheLayout, graphManifestSha256 } = await materializeModuleGraphPackageFixture(value);
    const path = join(cacheLayout.immutable.packages, graphManifestSha256);
    const entry = JSON.parse(await fs.readFile(join(path, "package-entry.json"), "utf8"));
    entry.kind = "convex-wasm-module-graph-package-v2";
    await fs.writeFile(join(path, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    });

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });
});

test("recent successful use retains its legacy certificate and complete immutable closure", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  const {
    compilerOutput,
    dependencies: [generatedC, picObject, engineProbe],
  } = await writeCompilerOutputFixture(cacheLayout);

  const snapshot = await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "closure-build",
      cacheLayout,
      deployment: {
        buildReport: {
          artifacts: [
            {
              buildReport: {
                compilerOutputCache: { cache: "hit", cacheKey: compilerOutput.key },
              },
            },
          ],
          cache: { certificateSha256: certificate.certificateSha256, deploymentResult: "hit" },
        },
        manifest,
      },
      environment: value.environment,
      recordedAtMs: 1_000,
    })
  );
  assert.equal(snapshot.schemaVersion, 2);
  assert.deepEqual(snapshot.certificateSha256s, [certificate.certificateSha256]);
  assert.deepEqual(snapshot.compilerOutputKeys, [compilerOutput.key]);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.pressure.active, true);
  assert.deepEqual(plan.retained.certificates, [certificate.certificateSha256]);
  assert.deepEqual(
    plan.retained.artifacts,
    [
      `${engineProbe.stage}\0${engineProbe.key}`,
      `${generatedC.stage}\0${generatedC.key}`,
      `${picObject.stage}\0${picObject.key}`,
      `${compilerOutput.stage}\0${compilerOutput.key}`,
      ...packageMaterial.artifactReferences.flatMap((reference) => [
        `${reference.aot.artifact.stage}\0${reference.aot.artifact.cacheKey}`,
        `${reference.coreWasm.artifact.stage}\0${reference.coreWasm.artifact.cacheKey}`,
      ]),
    ].sort()
  );
  assert.deepEqual(plan.evictions, []);

  const compilerOutputEntryPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key,
    "entry.json"
  );
  const compilerOutputEntry = JSON.parse(await fs.readFile(compilerOutputEntryPath, "utf8"));
  compilerOutputEntry.metadata = { kind: "invalid-compiler-output-cache-metadata" };
  await fs.writeFile(compilerOutputEntryPath, `${canonicalJson(compilerOutputEntry)}\n`, {
    mode: 0o600,
  });
  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /retained compiler-output cache entry is unavailable/u
  );
});

test("missing package material makes an older success snapshot stale without authorizing its certificate", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "stale-success",
      cacheLayout,
      deployment: {
        buildReport: {
          cache: { certificateSha256: certificate.certificateSha256, deploymentResult: "hit" },
        },
        manifest,
      },
      environment: value.environment,
    })
  );
  await fs.rm(join(cacheLayout.immutable.packages, graphManifestSha256), { recursive: true });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.staleSnapshots, 1);
  assert.equal(plan.authenticated.retainedSnapshots, 0);
  assert.deepEqual(plan.retained.certificates, []);
});

test("recent successful use retains an older certificate after compact preference changes", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifest, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const olderCertificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifest,
    graphManifestSha256,
    manifest,
    packageMaterial,
    schemaVersion: 1,
  });
  const preferredCertificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  assert.notEqual(olderCertificate.certificateSha256, preferredCertificate.certificateSha256);
  const lookupRoot = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    fingerprintJson({ fixture: "cache-retention-legacy-certificate" })
  );
  await fs.writeFile(join(lookupRoot, "PREFERRED"), `${preferredCertificate.certificateSha256}\n`, {
    mode: 0o600,
  });
  await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "older-certificate-success",
      cacheLayout,
      deployment: {
        buildReport: {
          cache: {
            certificateSha256: olderCertificate.certificateSha256,
            deploymentResult: "hit",
          },
        },
        manifest,
      },
      environment: value.environment,
      recordedAtMs: 1_000,
    })
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.deepEqual(plan.retained.certificates, [olderCertificate.certificateSha256]);
  assert.deepEqual(plan.retained.packages, [graphManifestSha256]);
});

test("immutable GC retains a recently modified schema-4 certificate root", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifest, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifest,
    graphManifestSha256,
    manifest,
    packageMaterial,
    schemaVersion: 4,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
    })
  );
  assert.deepEqual(plan.retained.certificates, [certificate.certificateSha256]);
  assert.deepEqual(plan.evictions, []);
});

test("immutable GC rejects a non-private preferred certificate pointer", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  const lookupRoot = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    fingerprintJson({ fixture: "cache-retention-legacy-certificate" })
  );
  const preferredPointer = join(lookupRoot, "PREFERRED");
  await fs.writeFile(preferredPointer, `${certificate.certificateSha256}\n`, { mode: 0o600 });
  await fs.chmod(preferredPointer, 0o644);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 1);
  assert.deepEqual(plan.retained.certificates, []);
  assert.deepEqual(plan.evictions, []);
});

test("immutable GC bounds certificate candidates before reading their contents", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("certificate-candidate-bound");
  const lookupRoot = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    "a".repeat(64)
  );
  await fs.mkdir(lookupRoot, { mode: 0o700, recursive: true });
  for (const directory of [
    value.cacheRoot,
    join(value.cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.packages,
    join(cacheLayout.immutable.packages, "deployment-results"),
    join(cacheLayout.immutable.packages, "deployment-results", "v1"),
    lookupRoot,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  await Promise.all(
    Array.from({ length: 257 }, (_, index) =>
      fs.mkdir(join(lookupRoot, `${index.toString(16).padStart(64, "0")}`), { mode: 0o700 })
    )
  );

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        nowMs: Date.now(),
      })
    ),
    /recent immutable authority is corrupt/u
  );
});

test("rotated compiler-output schemas remain ordinary age-bounded artifacts", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, manifest } = await materializeModuleGraphPackageFixture(value);
  const legacyCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v3",
    },
    payload: `${canonicalJson({
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v3",
      schemaVersion: 3,
    })}\n`,
    stage: "module-graph-compiler-output",
  });
  await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "rotated-compiler-output",
      cacheLayout,
      deployment: {
        buildReport: {
          artifacts: [
            {
              buildReport: {
                compilerOutputCache: { cache: "hit", cacheKey: legacyCompilerOutput.key },
              },
            },
          ],
        },
        manifest,
      },
      environment: value.environment,
      recordedAtMs: 1_000,
    })
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      nowMs: Date.now(),
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(
    plan.retained.artifacts.includes(`${legacyCompilerOutput.stage}\0${legacyCompilerOutput.key}`)
  );
  assert.deepEqual(plan.evictions, []);
});

test("schema-4/v8 and schema-5/v8 compiler-output records retain their strict closure", async (t) => {
  for (const recordSchemaVersion of [4, 5]) {
    await t.test(`schema ${String(recordSchemaVersion)}`, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout(`compiler-output-schema-${String(recordSchemaVersion)}`);
      const { compilerOutput, dependencies } = await writeCompilerOutputFixture(cacheLayout, {
        recordSchemaVersion,
      });

      const plan = await withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 5_000,
        })
      );

      assert.equal(plan.authenticated.invalid, 0);
      assert.ok(
        [compilerOutput, ...dependencies].every(({ key, stage }) =>
          plan.retained.artifacts.includes(`${stage}\0${key}`)
        )
      );
      assert.deepEqual(plan.evictions, []);
    });
  }
});

test("pre-transport schema-4/v8 compiler-output records remain age-bounded", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-schema-4-pre-transport");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout, {
    historicalPreTransport: true,
    recordSchemaVersion: 4,
  });
  await Promise.all(
    [compilerOutput, ...dependencies].map((artifact) => ageGenericArtifact(cacheLayout, artifact))
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(
    [compilerOutput, ...dependencies].every(
      ({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`)
    )
  );

  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  await ageGenericArtifact(cacheLayout, capsule);
  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 2_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cohort capsule compiler-output cache record has an unsupported descriptor family/u
  );
});

test("schema-5 compiler-output compact authority corruption cannot retain dependencies", async (t) => {
  for (const { mutate, name } of [
    {
      mutate: (record) => {
        record.descriptor.chunkUnitsIdentitySha256 = "invalid";
      },
      name: "compact descriptor",
    },
    {
      mutate: (record) => {
        record.reusableCodeIdentitySha256s.pop();
      },
      name: "reusable-code identities",
    },
    {
      mutate: (record) => {
        record.structuralTopologySha256 = "invalid";
      },
      name: "structural topology",
    },
  ]) {
    await t.test(name, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout(`compiler-output-corrupt-${name.replaceAll(" ", "-")}`);
      const { compilerOutput, dependencies, record } =
        await writeCompilerOutputFixture(cacheLayout);
      mutate(record);
      const source = Buffer.from(`${canonicalJson(record)}\n`);
      const root = join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key);
      const entryPath = join(root, "entry.json");
      const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
      entry.artifactSha256 = createHash("sha256").update(source).digest("hex");
      entry.artifactSize = source.length;
      await Promise.all([
        fs.writeFile(join(root, entry.artifactFile), source, { mode: 0o600 }),
        fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
      ]);

      const plan = await withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      );

      assert.equal(plan.authenticated.invalid, 1);
      assert.ok(
        dependencies.every(
          ({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`)
        )
      );
    });
  }
});

test("maintenance removes an old certificate and package closure while preserving published and recent data", async (t) => {
  const value = await fixture(t);
  const material = await materializeModuleGraphPackageFixture(value);
  const { cacheLayout, graphManifestSha256, packageMaterial } = material;
  const certificate = await writeLegacyDeploymentResultCertificate(material);
  const packagePath = join(cacheLayout.immutable.packages, graphManifestSha256);
  const publishedManifest = join(value.root, "published-graph-manifest.json");
  const manifestBytes = await fs.readFile(join(packagePath, "graph-manifest.json"));
  await fs.link(join(packagePath, "graph-manifest.json"), publishedManifest);
  const aot = packageMaterial.artifactReferences[0].aot.artifact;
  const aotPath = join(cacheLayout.immutable.artifacts, aot.stage, aot.cacheKey, "artifact.cwasm");
  const publishedAot = join(value.root, "published-module.cwasm");
  const aotBytes = await fs.readFile(aotPath);
  await fs.link(aotPath, publishedAot);
  await ageTree(cacheLayout.immutable.root);
  const retained = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: {},
    payload: "recently-used",
    stage: "retained",
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      immutableHighWatermarkAllocatedBytes: 1,
    })
  );

  assert.deepEqual(report.immutable.plan.retained.packages, []);
  assert.deepEqual(
    report.immutable.sweep.removed.slice(0, 2).map(({ key, type }) => ({ key, type })),
    [
      { key: fingerprintJson(certificate.lookupIdentity), type: "certificate-root" },
      { key: graphManifestSha256, type: "package" },
    ]
  );
  assert.equal(report.immutable.plan.incomplete, true);
  assert.equal(report.immutable.plan.candidates, 0);
  assert.deepEqual(report.immutable.plan.retained.artifacts, [`${retained.stage}\0${retained.key}`]);
  await assert.rejects(fs.lstat(packagePath), { code: "ENOENT" });
  assert.equal(report.immutable.plan.authenticated.invalid, 0);
  assert.equal(report.immutable.sweep.removed.length, 2 + packageMaterial.artifactReferences.length * 2);
  const aotRemoval = report.immutable.sweep.removed.find(({ key }) => key === aot.cacheKey);
  const survivingAllocation = (await fs.lstat(publishedAot)).blocks * 512;
  assert.equal(aotRemoval.estimatedReclaimBytes, aotRemoval.allocationBytes - survivingAllocation);
  await assert.rejects(fs.lstat(aotPath), { code: "ENOENT" });
  assert.deepEqual(await fs.readFile(publishedAot), aotBytes);
  assert.deepEqual(await fs.readFile(publishedManifest), manifestBytes);
  await fs.lstat(join(cacheLayout.immutable.artifacts, retained.stage, retained.key));
  assert.ok(report.immutable.sweep.remainingAllocatedBytes > 1);
  assert.equal(report.immutable.sweep.remainingAllocatedBytes,
    (await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root)).uniqueAllocatedBytes);
});

test("immutable plans retire certificate roots before packages and artifacts across certificate schemas", async (t) => {
  for (const schemaVersion of [1, 2, 3, 4]) {
    await t.test(`certificate schema ${String(schemaVersion)}`, async (t) => {
      const value = await fixture(t);
      const material = await materializeModuleGraphPackageFixture(value);
      const { cacheLayout, graphManifestSha256 } = material;
      const certificate = await writeLegacyDeploymentResultCertificate({ ...material, schemaVersion });
      const certificateRoot = join(cacheLayout.immutable.packages, "deployment-results", "v1",
        fingerprintJson(certificate.lookupIdentity));
      if (schemaVersion >= 3) {
        await writeLegacyDeploymentResultCertificate({ ...material, schemaVersion: 1 });
        await fs.writeFile(join(certificateRoot, "PREFERRED"), `${certificate.certificateSha256}\n`, {
          mode: 0o600,
        });
      }
      const unrelated = await writeGenericArtifact({
        cacheLayout,
        extension: "wasm",
        metadata: { fixture: "independent-large-artifact" },
        payload: Buffer.alloc(1024 * 1024),
        stage: "independent-large-artifact",
      });
      const options = {
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      };
      const first = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
      assert.deepEqual(first.removed.map(({ type }) => type), ["certificate-root", "artifact"]);
      await assert.rejects(fs.lstat(certificateRoot), { code: "ENOENT" });
      await loadAndVerifyConvexWasmModuleGraphPackage({
        cacheLayout,
        cacheRoot: value.cacheRoot,
        graphManifestSha256,
        packagePath: join(cacheLayout.immutable.packages, graphManifestSha256),
      });
      const second = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
      assert.equal(second.plan.authenticated.invalid, 0);
      assert.deepEqual(second.removed.map(({ type }) => type), ["package"]);
      await assert.rejects(fs.lstat(join(cacheLayout.immutable.artifacts, unrelated.stage, unrelated.key)), {
        code: "ENOENT",
      });
      for (const reference of material.packageMaterial.artifactReferences) {
        for (const { artifact } of [reference.aot, reference.coreWasm]) {
          await fs.lstat(join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey));
        }
      }
      const third = await withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc(options)
      );
      assert.equal(third.plan.authenticated.invalid, 0);
      assert.equal(third.removed.length, second.plan.retained.artifacts.length);
      assert.ok(third.removed.every(({ type }) => type === "artifact"));
    });
  }
});

test("retiring an old certificate preserves a recently reused package", async (t) => {
  const value = await fixture(t);
  const material = await materializeModuleGraphPackageFixture(value);
  const { cacheLayout, graphManifestSha256 } = material;
  const certificate = await writeLegacyDeploymentResultCertificate(material);
  await ageTree(join(cacheLayout.immutable.packages, "deployment-results"));
  const options = {
    cacheLayout,
    environment: value.environment,
    highWatermarkAllocatedBytes: 1,
    nowMs: Date.now() + 1_000,
  };
  const first = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
  assert.deepEqual(first.removed.map(({ key }) => key), [fingerprintJson(certificate.lookupIdentity)]);
  const second = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
  assert.deepEqual(second.removed, []);
  assert.deepEqual(second.plan.retained.packages, [graphManifestSha256]);
});

test("immutable planning reads a shared payload once per plan across certificates and packages", async (t) => {
  const value = await fixture(t);
  const material = await materializeModuleGraphPackageFixture(value);
  const { cacheLayout, packageMaterial } = material;
  await writeLegacyDeploymentResultCertificate({ ...material, schemaVersion: 3 });
  await writeLegacyDeploymentResultCertificate({ ...material, schemaVersion: 4 });
  const artifact = packageMaterial.artifactReferences[0].aot.artifact;
  const payloadPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey, "artifact.cwasm");
  let payloadBytesRead = 0;
  const open = fs.open;
  fs.open = async function (path, ...args) {
    const handle = await open.call(this, path, ...args);
    if (path === payloadPath) {
      const read = handle.read;
      handle.read = async function (...args) {
        const result = await read.apply(this, args);
        payloadBytesRead += result.bytesRead;
        return result;
      };
    }
    return handle;
  };
  try {
    for (let pass = 1; pass <= 2; pass += 1) {
      await withHeavyLock(value.environment, () => planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
      }));
      assert.equal(payloadBytesRead, artifact.size * pass);
    }
  } finally {
    fs.open = open;
  }
});

test("retained certificate roots preserve both preferred and superseded package closures", async (t) => {
  for (const selected of ["preferred", "superseded", "preferred-with-missing-sibling-package"]) {
    await t.test(`${selected} success snapshot`, async (t) => {
      const value = await fixture(t);
      const material = await materializeModuleGraphPackageFixture(value);
      const { cacheLayout } = material;
      const preferred = await writeLegacyDeploymentResultCertificate(material);
      const supersededPackage = await writeLegacyV2ModuleGraphPackage(cacheLayout);
      const manifestPayload = {
        moduleGraphBinding: { cohorts: [{ graphManifestSha256: supersededPackage.key }] },
      };
      const supersededManifest = {
        ...manifestPayload,
        deploymentSha256: fingerprintJson(manifestPayload),
      };
      const superseded = await writeLegacyDeploymentResultCertificate({
        cacheLayout,
        graphManifest: supersededPackage.manifest,
        graphManifestSha256: supersededPackage.key,
        manifest: supersededManifest,
        schemaVersion: 1,
      });
      const lookupRoot = join(cacheLayout.immutable.packages, "deployment-results", "v1",
        fingerprintJson(preferred.lookupIdentity));
      await fs.writeFile(join(lookupRoot, "PREFERRED"), `${preferred.certificateSha256}\n`, { mode: 0o600 });
      const missingSiblingPackage = selected === "preferred-with-missing-sibling-package";
      if (missingSiblingPackage) await fs.rm(supersededPackage.root, { recursive: true });
      const selectedCertificate = selected === "superseded" ? superseded : preferred;
      await withHeavyLock(value.environment, async () => {
        await recordConvexWasmSuccessfulCacheUse({
          buildId: `${selected}-certificate-success`,
          cacheLayout,
          deployment: {
            buildReport: { cache: { certificateSha256: selectedCertificate.certificateSha256 } },
            manifest: selectedCertificate.manifest,
          },
          environment: value.environment,
        });
        const result = await sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        });
        assert.deepEqual(
          result.removed.map(({ key }) => key).sort(),
          missingSiblingPackage ? [supersededPackage.aot.key, supersededPackage.coreWasm.key].sort() : []
        );
        assert.equal(result.plan.authenticated.invalid, missingSiblingPackage ? 1 : 0);
        assert.equal(result.plan.authenticated.retainedSnapshots, 1);
        assert.deepEqual(result.plan.retained.certificates, [selectedCertificate.certificateSha256]);
      });
      if (!missingSiblingPackage) await fs.lstat(supersededPackage.root);
      await fs.lstat(lookupRoot);
      await loadAndVerifyConvexWasmModuleGraphPackage({
        cacheLayout,
        cacheRoot: value.cacheRoot,
        graphManifestSha256: material.graphManifestSha256,
        packagePath: join(cacheLayout.immutable.packages, material.graphManifestSha256),
      });
    });
  }
});

test("artifact-only sweep removes a compiler-output root before its strict dependencies", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-root-sweep");
  const { compilerOutput, dependencies } = await writeCompilerOutputFixture(cacheLayout);
  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [compilerOutput.key]
  );
  await assert.rejects(
    fs.lstat(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key)),
    { code: "ENOENT" }
  );
  await Promise.all(
    dependencies.map(({ key, stage }) =>
      fs.lstat(join(cacheLayout.immutable.artifacts, stage, key))
    )
  );
});

test("artifact-only sweep removes a topology certificate before its full-record prerequisite", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-topology-root-sweep");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  await fs.rm(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key), {
    recursive: true,
  });
  await Promise.all(
    [compilerOutput, topologyCertificate, ...dependencies].map((artifact) =>
      ageGenericArtifact(cacheLayout, artifact)
    )
  );

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [topologyCertificate.key]
  );
  await assert.rejects(
    fs.lstat(
      join(cacheLayout.immutable.artifacts, topologyCertificate.stage, topologyCertificate.key)
    ),
    { code: "ENOENT" }
  );
  await Promise.all(
    [compilerOutput, ...dependencies].map(({ key, stage }) =>
      fs.lstat(join(cacheLayout.immutable.artifacts, stage, key))
    )
  );
});

test("v6 topology material is age-bounded only after complete authentication", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("rotated-compiler-output-topology-identity");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout, {
    recordSchemaVersion: 4,
  });
  const legacyCompilerOutputIdentity = structuredClone(compilerOutput.entry.identity);
  legacyCompilerOutputIdentity.kind =
    "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v6";
  delete legacyCompilerOutputIdentity.topologyWitnessMaterialIdentitySha256;
  const legacyCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: legacyCompilerOutputIdentity,
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    legacyCompilerOutput,
    record
  );
  await fs.rm(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key), {
    recursive: true,
  });
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });
  await Promise.all(
    [legacyCompilerOutput, ...dependencies].map((artifact) =>
      ageGenericArtifact(cacheLayout, artifact)
    )
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 60_000,
    })
  );

  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(
    plan.retained.artifacts.includes(`${topologyCertificate.stage}\0${topologyCertificate.key}`)
  );
  assert.ok(
    [legacyCompilerOutput, ...dependencies].every(
      ({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`)
    )
  );

  const topologyRoot = join(
    cacheLayout.immutable.artifacts,
    topologyCertificate.stage,
    topologyCertificate.key
  );
  const topologyEntryPath = join(topologyRoot, "entry.json");
  const topologyEntry = JSON.parse(await fs.readFile(topologyEntryPath, "utf8"));
  const partialCertificate = JSON.parse(
    await fs.readFile(join(topologyRoot, topologyEntry.artifactFile), "utf8")
  );
  delete partialCertificate.bridge.object.identitySha256;
  const partialSource = Buffer.from(`${canonicalJson(partialCertificate)}\n`);
  topologyEntry.artifactSha256 = createHash("sha256").update(partialSource).digest("hex");
  topologyEntry.artifactSize = partialSource.length;
  await Promise.all([
    fs.writeFile(join(topologyRoot, topologyEntry.artifactFile), partialSource, { mode: 0o600 }),
    fs.writeFile(topologyEntryPath, `${canonicalJson(topologyEntry)}\n`, { mode: 0o600 }),
  ]);

  const partialPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(partialPlan.authenticated.invalid, 1);
  assert.ok(
    !partialPlan.retained.artifacts.includes(
      `${topologyCertificate.stage}\0${topologyCertificate.key}`
    )
  );
});

test("v6 compiler-output records authenticate descriptor and engine facts before legacy classification", async (t) => {
  for (const { field, value } of [
    { field: "descriptorIdentitySha256", value: "f".repeat(64) },
    { field: "engineCompatibilitySha256", value: "e".repeat(64) },
  ]) {
    await t.test(field, async (t) => {
      const fixtureValue = await fixture(t);
      const cacheLayout = fixtureValue.layout(`rotated-compiler-output-${field}`);
      const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout, {
        recordSchemaVersion: 4,
      });
      const legacyIdentity = structuredClone(compilerOutput.entry.identity);
      legacyIdentity.kind =
        "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v6";
      delete legacyIdentity.topologyWitnessMaterialIdentitySha256;
      legacyIdentity[field] = value;
      const legacyCompilerOutput = await writeGenericArtifact({
        cacheLayout,
        extension: "json",
        identity: legacyIdentity,
        metadata: {
          kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
        },
        payload: `${canonicalJson(record)}\n`,
        stage: "module-graph-compiler-output",
      });
      await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
        recursive: true,
      });
      await ageGenericArtifact(cacheLayout, legacyCompilerOutput);

      const plan = await withHeavyLock(fixtureValue.environment, () =>
        planConvexWasmImmutableGc({
          cacheLayout,
          environment: fixtureValue.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      );

      assert.equal(plan.authenticated.invalid, 1);
      assert.ok(
        !plan.retained.artifacts.includes(
          `${legacyCompilerOutput.stage}\0${legacyCompilerOutput.key}`
        )
      );
    });
  }
});

test("immutable GC rejects compiler-output closure authority from an extended v8 identity", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("extended-compiler-output-cache-identity");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const extendedCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: { ...compilerOutput.entry.identity, unexpected: "field" },
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(
    !plan.retained.artifacts.includes(
      `${extendedCompilerOutput.stage}\0${extendedCompilerOutput.key}`
    )
  );
  assert.ok(
    dependencies.every(({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`))
  );
});

test("immutable GC rejects a v8 identity relabeled onto a different compiler output", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("relabeled-compiler-output-cache-identity");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const relabeledCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: { ...compilerOutput.entry.identity, descriptorIdentitySha256: "f".repeat(64) },
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(
    !plan.retained.artifacts.includes(
      `${relabeledCompilerOutput.stage}\0${relabeledCompilerOutput.key}`
    )
  );
  assert.ok(
    dependencies.every(({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`))
  );
});

test("immutable GC rejects a compiler-output closure with a disagreeing stage entry", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-closure-mismatch");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const compilerOutputPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key
  );
  const tamperedRecord = structuredClone(record);
  tamperedRecord.bridge.generatedC.entry.artifactSha256 = "f".repeat(64);
  const source = Buffer.from(`${canonicalJson(tamperedRecord)}\n`);
  const entryPath = join(compilerOutputPath, "entry.json");
  const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
  entry.artifactSha256 = createHash("sha256").update(source).digest("hex");
  entry.artifactSize = source.length;
  await Promise.all([
    fs.writeFile(join(compilerOutputPath, entry.artifactFile), source, { mode: 0o600 }),
    fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /compiler-output cache closure artifact disagrees with its record/u
  );
});

test("immutable GC rejects compiler-output retention authority for a different artifact family", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-closure-family-mismatch");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const compilerOutputPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key
  );
  const tamperedRecord = structuredClone(record);
  tamperedRecord.bridge.generatedC.extension = "o";
  const source = Buffer.from(`${canonicalJson(tamperedRecord)}\n`);
  const entryPath = join(compilerOutputPath, "entry.json");
  const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
  entry.artifactSha256 = createHash("sha256").update(source).digest("hex");
  entry.artifactSize = source.length;
  await Promise.all([
    fs.writeFile(join(compilerOutputPath, entry.artifactFile), source, { mode: 0o600 }),
    fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
  ]);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(
    dependencies.every(({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`))
  );
});

test("immutable GC authenticates a large cohort capsule and retains its compiler closure", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("large-cohort-capsule");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  const payload = JSON.parse(
    await fs.readFile(
      join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key, capsule.entry.artifactFile),
      "utf8"
    )
  );
  // Retention authenticates topology without rehydrating the other planning fields.
  // Grow that opaque fixture data beyond the former byte limit with fewer UTF-16 code units.
  payload.planning.cohortContract = { fixture: "\u00e9".repeat(5 * 1024 * 1024) };
  const source = `${canonicalJson(payload)}\n`;
  assert.ok(source.length < 8 * 1024 * 1024);
  assert.ok(Buffer.byteLength(source) > 8 * 1024 * 1024);
  const largeCapsule = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: capsule.entry.identity,
    metadata: capsule.entry.metadata,
    payload: source,
    stage: capsule.stage,
  });
  assert.equal(largeCapsule.key, capsule.key);
  const unrelated = await writeGenericArtifact({
    cacheLayout,
    extension: "c",
    identity: { fixture: "unrelated-generated-c" },
    metadata: { fixture: "compiler-output-generated-c" },
    payload: "unrelated-generated-c",
    stage: dependencies[0].stage,
  });
  const closure = [compilerOutput, topologyCertificate, ...dependencies];
  await Promise.all(
    [...closure, unrelated].map((artifact) => ageGenericArtifact(cacheLayout, artifact))
  );
  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now(),
      recentRetentionMilliseconds: 60_000,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(closure.every(({ key, stage }) => plan.retained.artifacts.includes(`${stage}\0${key}`)));
  assert.ok(!plan.retained.artifacts.includes(`${unrelated.stage}\0${unrelated.key}`));
  assert.deepEqual(
    plan.evictions.map(({ key, stage }) => ({ key, stage })),
    [{ key: unrelated.key, stage: unrelated.stage }]
  );
});

test("artifact-only sweep removes a cohort capsule before its strict compiler closure", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-root-sweep");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  await Promise.all(
    [compilerOutput, topologyCertificate, ...dependencies].map((artifact) =>
      ageGenericArtifact(cacheLayout, artifact)
    )
  );

  const recentPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 5_000,
    })
  );
  const strictClosure = [compilerOutput, topologyCertificate, ...dependencies].map(
    ({ key, stage }) => `${stage}\0${key}`
  );
  assert.ok(strictClosure.every((key) => recentPlan.retained.artifacts.includes(key)));
  assert.equal(recentPlan.evictions.length, 0);

  await ageGenericArtifact(cacheLayout, capsule);
  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [capsule.key]
  );
  await assert.rejects(
    fs.lstat(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key)),
    { code: "ENOENT" }
  );
  await Promise.all(
    [compilerOutput, topologyCertificate, ...dependencies].map(({ key, stage }) =>
      fs.lstat(join(cacheLayout.immutable.artifacts, stage, key))
    )
  );
});

test("immutable GC removes an old capsule whose compiler-output record is already absent", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("orphaned-cohort-capsule");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });
  await ageGenericArtifact(cacheLayout, capsule);

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
    })
  );

  assert.equal(result.plan.authenticated.orphanedCapsules, 1);
  assert.equal(result.plan.authenticated.orphanedTopologyCertificates, 1);
  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [capsule.key]
  );
  await assert.rejects(
    fs.lstat(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key)),
    { code: "ENOENT" }
  );
  await fs.lstat(
    join(cacheLayout.immutable.artifacts, topologyCertificate.stage, topologyCertificate.key)
  );
});

test("immutable GC treats rotated v2 through v5 cohort capsules as age-bounded artifacts", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("legacy-cohort-capsule");
  const capsules = [];
  for (const schemaVersion of [2, 3, 4, 5]) {
    const kind = `convex-wasm-official-output-cohort-planning-capsule-v${String(schemaVersion)}`;
    const capsule = await writeGenericArtifact({
      cacheLayout,
      extension: "json",
      identity: { capsuleIdentity: { fixture: "legacy" }, kind, schemaVersion },
      metadata: { kind, schemaVersion },
      payload: "{}\n",
      stage: "module-graph-cohort-planning-capsule",
    });
    await ageGenericArtifact(cacheLayout, capsule);
    capsules.push(capsule);
  }

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key).sort(),
    capsules.map(({ key }) => key).sort()
  );
});

test("immutable GC does not classify a current capsule as legacy from metadata alone", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("current-cohort-capsule-legacy-metadata");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleEntryPath = join(
    cacheLayout.immutable.artifacts,
    capsule.stage,
    capsule.key,
    "entry.json"
  );
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.metadata = {
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  await fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cohort capsule legacy metadata does not match its cache identity/u
  );
});

test("immutable GC authenticates the outer key before classifying a capsule as legacy", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("current-cohort-capsule-rewritten-legacy-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleEntryPath = join(
    cacheLayout.immutable.artifacts,
    capsule.stage,
    capsule.key,
    "entry.json"
  );
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  const currentCapsuleIdentity = structuredClone(capsuleEntry.identity.capsuleIdentity);
  delete currentCapsuleIdentity.sha256;
  const legacyCapsuleIdentityPayload = {
    ...currentCapsuleIdentity,
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  capsuleEntry.identity = {
    capsuleIdentity: {
      ...legacyCapsuleIdentityPayload,
      sha256: fingerprintJson(legacyCapsuleIdentityPayload),
    },
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  capsuleEntry.metadata = {
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  await fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cache entry identity does not match its key/u
  );
});

test("immutable GC rejects a corrupted rotated v3 capsule before legacy classification", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("malformed-legacy-v3-cohort-capsule");
  const kind = "convex-wasm-official-output-cohort-planning-capsule-v3";
  const capsule = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: { capsuleIdentity: { fixture: "legacy" }, kind, schemaVersion: 3 },
    metadata: { kind, schemaVersion: 3 },
    payload: "{}\n",
    stage: "module-graph-cohort-planning-capsule",
  });
  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  await fs.writeFile(join(capsuleRoot, capsule.entry.artifactFile), "corrupt\n", { mode: 0o600 });
  await ageGenericArtifact(cacheLayout, capsule);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cache artifact digest or size does not match metadata/u
  );
});

test("immutable GC fails closed for a non-JSON artifact in the cohort capsule stage", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-family-mismatch");
  const capsule = await writeCBundleArtifact({
    cacheLayout,
    stage: "module-graph-cohort-planning-capsule",
  });
  await ageGenericArtifact(cacheLayout, capsule);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cohort capsule cache entry has an unsupported artifact family/u
  );
});

test("immutable GC rejects a capsule bound to a rotated compiler-output schema", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-legacy-compiler-output");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const compilerOutputEntryPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key,
    "entry.json"
  );
  const compilerOutputEntry = JSON.parse(await fs.readFile(compilerOutputEntryPath, "utf8"));
  compilerOutputEntry.metadata = {
    kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v1",
  };
  await fs.writeFile(compilerOutputEntryPath, `${canonicalJson(compilerOutputEntry)}\n`, {
    mode: 0o600,
  });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output cache record has an unsupported schema/u
  );
});

test("immutable GC rejects a capsule bound to a pre-v8 compiler-output identity", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-legacy-compiler-output-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  const capsulePayloadPath = join(capsuleRoot, capsule.entry.artifactFile);
  const capsulePayload = JSON.parse(await fs.readFile(capsulePayloadPath, "utf8"));
  capsulePayload.planning.topology.cacheIdentity.kind =
    "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v7";
  capsulePayload.planning.topology.cacheKey = fingerprintJson({
    identity: capsulePayload.planning.topology.cacheIdentity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output",
  });
  capsulePayload.planning.topology.certificateCacheKey = fingerprintJson({
    identity: {
      compilerOutputCacheIdentity: capsulePayload.planning.topology.cacheIdentity,
      compilerOutputCacheKey: capsulePayload.planning.topology.cacheKey,
      kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
    },
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output-topology",
  });
  const capsuleSource = Buffer.from(`${canonicalJson(capsulePayload)}\n`);
  const capsuleEntryPath = join(capsuleRoot, "entry.json");
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.artifactSha256 = createHash("sha256").update(capsuleSource).digest("hex");
  capsuleEntry.artifactSize = capsuleSource.length;
  await Promise.all([
    fs.writeFile(capsulePayloadPath, capsuleSource, { mode: 0o600 }),
    fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output cache identity has an unsupported schema/u
  );
});

test("immutable GC closes the exact v8 capsule identity before following references", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-extended-compiler-output-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  const capsulePayloadPath = join(capsuleRoot, capsule.entry.artifactFile);
  const capsulePayload = JSON.parse(await fs.readFile(capsulePayloadPath, "utf8"));
  capsulePayload.planning.topology.cacheIdentity.unexpected = "7".repeat(64);
  capsulePayload.planning.topology.cacheKey = fingerprintJson({
    identity: capsulePayload.planning.topology.cacheIdentity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output",
  });
  capsulePayload.planning.topology.certificateCacheKey = fingerprintJson({
    identity: {
      compilerOutputCacheIdentity: capsulePayload.planning.topology.cacheIdentity,
      compilerOutputCacheKey: capsulePayload.planning.topology.cacheKey,
      kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
    },
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output-topology",
  });
  const capsuleSource = Buffer.from(`${canonicalJson(capsulePayload)}\n`);
  const capsuleEntryPath = join(capsuleRoot, "entry.json");
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.artifactSha256 = createHash("sha256").update(capsuleSource).digest("hex");
  capsuleEntry.artifactSize = capsuleSource.length;
  await Promise.all([
    fs.writeFile(capsulePayloadPath, capsuleSource, { mode: 0o600 }),
    fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output cache identity has unknown field\(s\): unexpected/u
  );
});

test("immutable GC shares exact v6 capsule identity normalization", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-extended-v5-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsulePayload = JSON.parse(
    await fs.readFile(
      join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key, capsule.entry.artifactFile),
      "utf8"
    )
  );
  const { sha256: _sha256, ...identityPayload } = capsulePayload.identity;
  const extendedIdentityPayload = {
    ...identityPayload,
    unexpectedAuthority: "9".repeat(64),
  };
  const extendedIdentity = {
    ...extendedIdentityPayload,
    sha256: fingerprintJson(extendedIdentityPayload),
  };
  capsulePayload.identity = extendedIdentity;
  await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: {
      capsuleIdentity: extendedIdentity,
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      schemaVersion: 6,
    },
    metadata: {
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      schemaVersion: 6,
    },
    payload: `${canonicalJson(capsulePayload)}\n`,
    stage: "module-graph-cohort-planning-capsule",
  });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule identity has unsupported fields/u
  );
});

test("immutable GC rejects a capsule topology certificate that disagrees with its record", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-topology-mismatch");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  const topologyRoot = join(
    cacheLayout.immutable.artifacts,
    topologyCertificate.stage,
    topologyCertificate.key
  );
  const topologyPayloadPath = join(topologyRoot, topologyCertificate.entry.artifactFile);
  const tamperedCertificate = JSON.parse(await fs.readFile(topologyPayloadPath, "utf8"));
  tamperedCertificate.bridge.object.cacheKey = "0".repeat(64);
  const topologySource = Buffer.from(`${canonicalJson(tamperedCertificate)}\n`);
  const topologyEntryPath = join(topologyRoot, "entry.json");
  const topologyEntry = JSON.parse(await fs.readFile(topologyEntryPath, "utf8"));
  topologyEntry.artifactSha256 = createHash("sha256").update(topologySource).digest("hex");
  topologyEntry.artifactSize = topologySource.length;

  await Promise.all([
    fs.writeFile(topologyPayloadPath, topologySource, { mode: 0o600 }),
    fs.writeFile(topologyEntryPath, `${canonicalJson(topologyEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output topology bridge object disagrees/u
  );
});

test("immutable GC rejects a capsule topology descriptor that disagrees with its record", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-descriptor-mismatch");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  const topologyRoot = join(
    cacheLayout.immutable.artifacts,
    topologyCertificate.stage,
    topologyCertificate.key
  );
  const topologyPayloadPath = join(topologyRoot, topologyCertificate.entry.artifactFile);
  const tamperedCertificate = JSON.parse(await fs.readFile(topologyPayloadPath, "utf8"));
  tamperedCertificate.descriptor.descriptorSha256 = "9".repeat(64);
  const topologySource = Buffer.from(`${canonicalJson(tamperedCertificate)}\n`);
  const topologyEntryPath = join(topologyRoot, "entry.json");
  const topologyEntry = JSON.parse(await fs.readFile(topologyEntryPath, "utf8"));
  topologyEntry.artifactSha256 = createHash("sha256").update(topologySource).digest("hex");
  topologyEntry.artifactSize = topologySource.length;

  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  const capsulePayloadPath = join(capsuleRoot, capsule.entry.artifactFile);
  const capsulePayload = JSON.parse(await fs.readFile(capsulePayloadPath, "utf8"));
  capsulePayload.planning.topology.descriptor = tamperedCertificate.descriptor;
  const capsuleSource = Buffer.from(`${canonicalJson(capsulePayload)}\n`);
  const capsuleEntryPath = join(capsuleRoot, "entry.json");
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.artifactSha256 = createHash("sha256").update(capsuleSource).digest("hex");
  capsuleEntry.artifactSize = capsuleSource.length;
  await Promise.all([
    fs.writeFile(topologyPayloadPath, topologySource, { mode: 0o600 }),
    fs.writeFile(topologyEntryPath, `${canonicalJson(topologyEntry)}\n`, { mode: 0o600 }),
    fs.writeFile(capsulePayloadPath, capsuleSource, { mode: 0o600 }),
    fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output topology descriptor disagrees/u
  );
});

test("immutable GC authenticates every generic artifact extension before listing it", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("gc-build");
  const extensions = ["a", "c", "cwasm", "json", "o", "pch", "wasm"];
  const keys = [];
  for (const extension of extensions) {
    const stage = `gc-${extension}-stage`;
    const identity = { extension, fixture: "old-artifact" };
    const key = fingerprintJson({ kind: "convex-wasm-artifact-pipeline-v9", stage, identity });
    keys.push(key);
    const entryPath = join(layout.immutable.artifacts, stage, key);
    await fs.mkdir(entryPath, { mode: 0o700, recursive: true });
    for (const directory of [
      value.cacheRoot,
      join(value.cacheRoot, "immutable"),
      layout.immutable.root,
      layout.immutable.artifacts,
      join(layout.immutable.artifacts, stage),
    ])
      await fs.chmod(directory, 0o700);
    const artifact = Buffer.from(`old-${extension}-artifact-payload`);
    const artifactSha256 = createHash("sha256").update(artifact).digest("hex");
    const artifactFile = `artifact.${extension}`;
    const entry = {
      artifactFile,
      artifactSha256,
      artifactSize: artifact.length,
      identity,
      key,
      kind: "convex-wasm-artifact-cache-entry-v5",
      metadata: { fixture: true },
      stage,
    };
    await Promise.all([
      fs.writeFile(join(entryPath, artifactFile), artifact, { mode: 0o600 }),
      fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
      fs.writeFile(join(entryPath, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
    ]);
    await Promise.all([
      fs.utimes(entryPath, new Date(0), new Date(0)),
      fs.utimes(join(entryPath, artifactFile), new Date(0), new Date(0)),
      fs.utimes(join(entryPath, "entry.json"), new Date(0), new Date(0)),
      fs.utimes(join(entryPath, "COMPLETE"), new Date(0), new Date(0)),
    ]);
  }
  const ageOnlyPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 2_000_000_000,
    })
  );
  assert.equal(ageOnlyPlan.pressure.active, false);
  assert.deepEqual(ageOnlyPlan.evictions, []);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout: layout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: 2_000_000_000,
    })
  );
  assert.equal(plan.candidates, extensions.length);
  assert.ok(plan.evictions.length > 0);
  assert.ok(plan.evictions.every(({ type }) => type === "artifact"));
  assert.ok(plan.evictions.every(({ key }) => keys.includes(key)));
  await Promise.all(plan.evictions.map(({ path }) => fs.lstat(path)));
});

test("immutable GC authenticates maintained JavaScript transform entries", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("raw-transform-retention");
  const transform = await writeGenericArtifact({
    cacheLayout,
    extension: "js",
    identity: { kind: "convex-wasm-official-output-chunk-transform-cache-identity-v5" },
    metadata: {
      kind: "convex-wasm-official-output-chunk-transform-cache-record-v3",
      requireSpecifiers: [],
      schemaVersion: 3,
    },
    payload: "module.exports = 1;\n",
    stage: "official-output-chunk-transform",
  });
  await ageGenericArtifact(cacheLayout, transform);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.candidates, 1);
  assert.deepEqual(
    plan.evictions.map(({ key, stage, type }) => ({ key, stage, type })),
    [{ key: transform.key, stage: transform.stage, type: "artifact" }]
  );
});

test("immutable GC authenticates and evicts only valid runtime header snapshots", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("runtime-header-snapshots");
  await fs.mkdir(cacheLayout.immutable.artifacts, { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.artifacts,
  ]) {
    await fs.chmod(path, 0o700);
  }
  const includeDirectory = join(value.root, "runtime-headers");
  await fs.mkdir(join(includeDirectory, "nested"), { recursive: true });
  await Promise.all([
    fs.writeFile(join(includeDirectory, "runtime.h"), "first runtime header\n"),
    fs.writeFile(join(includeDirectory, "nested", "nested.h"), "nested runtime header\n"),
  ]);
  const createSnapshot = async () => {
    const runtimeHeaderMaterials = await fingerprintMaterialPaths(
      [{ label: "runtime-include-directory-0", path: includeDirectory }],
      "retention runtime header materials"
    );
    return await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache({
      cacheLayout,
      includeDirectories: [includeDirectory],
      runtimeHeaderMaterials,
    });
  };
  const valid = await createSnapshot();
  await fs.writeFile(join(includeDirectory, "runtime.h"), "second runtime header\n");
  const corrupt = await createSnapshot();
  assert.notEqual(valid.key, corrupt.key);
  await fs.writeFile(join(corrupt.inputRoot, "include-0", "runtime.h"), "corrupt snapshot\n");

  const options = {
    cacheLayout,
    environment: value.environment,
    highWatermarkAllocatedBytes: 1,
    nowMs: Date.now() + 60_000,
    recentRetentionMilliseconds: 0,
  };
  const plan = await withHeavyLock(value.environment, () => planConvexWasmImmutableGc(options));
  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(plan.evictions.some(({ key }) => key === valid.key));
  assert.ok(plan.evictions.every(({ key }) => key !== corrupt.key));

  const report = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
  assert.ok(report.removed.some(({ key }) => key === valid.key));
  await assert.rejects(fs.lstat(valid.path), { code: "ENOENT" });
  await fs.lstat(corrupt.path);
});

test("immutable GC ignores stale artifact publication scratch", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("stale-artifact-publication");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "stale-artifact-publication" },
    payload: "stale-artifact-publication",
    stage: "stale-artifact-publication",
  });
  await fs.mkdir(
    join(cacheLayout.immutable.artifacts, artifact.stage, ".publish-crashed-artifact"),
    { mode: 0o700 }
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.deepEqual(
    plan.evictions.map(({ key }) => key),
    [artifact.key]
  );
});

test("immutable GC ignores stale package publication scratch", async (t) => {
  const value = await fixture(t);
  const { cacheLayout } = await materializeModuleGraphPackageFixture(value);
  await fs.mkdir(join(cacheLayout.immutable.packages, ".publish-crashed-package"), {
    mode: 0o700,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.evictions.length, 1);
  assert.equal(plan.evictions[0].type, "package");
  assert.deepEqual(plan.retained.packages, []);
  assert.equal(plan.categories.planningOnlyCandidates.count, 0);
  assert.ok(plan.categories.sweepableCandidates.allocatedBytes > 0);
  assert.equal(plan.categories.sweepableCandidates.count, 1);
  assert.ok(plan.retained.artifacts.length > 0);
});

test("immutable GC authenticates retained layout bytes before admitting a C bundle", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("retained-layout");
  const artifact = await writeCBundleArtifact({
    cacheLayout, retainedLayout: '{"kind":"static-hermes-c-layout-v1"}\n', stage: "retained-layout",
  });
  const options = {
    cacheLayout, environment: value.environment, highWatermarkAllocatedBytes: 1,
    nowMs: Date.now() + 1_000, recentRetentionMilliseconds: 0,
  };
  const valid = await withHeavyLock(value.environment, () => planConvexWasmImmutableGc(options));
  assert.equal(valid.authenticated.invalid, 0);
  assert.ok(valid.evictions.some(({ key }) => key === artifact.key));
  await fs.writeFile(join(artifact.root, artifact.entry.bundle.layout.path), Buffer.alloc(artifact.entry.bundle.layout.size, 32));
  const corrupt = await withHeavyLock(value.environment, () => planConvexWasmImmutableGc(options));
  assert.equal(corrupt.authenticated.invalid, 1);
  assert.ok(corrupt.evictions.every(({ key }) => key !== artifact.key));
});

test("immutable GC preserves layout choices with their retained C bundles", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("layout-closure");
  await fs.mkdir(cacheLayout.cacheRoot, { mode: 0o700 });
  const generatedCIdentity = {
    exportedUnitName: "this_unit", flags: ["-Xemit-c-bundle", "-Xemit-c-layout"],
    generatedSource: { sha256: "a".repeat(64), size: 10 },
    semanticEnvironment: { LANG: "C" }, staticHermes: { materials: "b".repeat(64) },
    unitRole: "untyped-official-chunk",
  };
  const selection = await planStaticHermesRetainedLayout({ cacheLayout, generatedCIdentity, stage: "generated-c" });
  const artifact = await writeCBundleArtifact({
    cacheLayout, stage: "generated-c", identity: selection.identity,
    retainedLayout: '{"kind":"static-hermes-c-layout-v1","unitName":"this_unit"}\n',
  });
  await publishStaticHermesRetainedLayout({ cacheLayout, generatedCEntry: { ...artifact.entry, bundlePath: artifact.root } });
  const references = staticHermesLayoutCacheReferences(selection.identity, "generated-c");
  for (const reference of references) await ageGenericArtifact(cacheLayout, reference);
  const options = {
    cacheLayout, environment: value.environment, highWatermarkAllocatedBytes: 1,
    nowMs: Date.now(), recentRetentionMilliseconds: 60_000,
  };
  const live = await withHeavyLock(value.environment, () => planConvexWasmImmutableGc(options));
  assert.equal(live.authenticated.invalid, 0);
  for (const { key, stage } of references) assert.ok(live.retained.artifacts.includes(`${stage}\0${key}`));
  assert.equal(live.evictions.length, 0);
  await ageGenericArtifact(cacheLayout, artifact);
  const obsolete = await withHeavyLock(value.environment, () => planConvexWasmImmutableGc(options));
  for (const { key } of [...references, artifact]) assert.ok(obsolete.evictions.some((entry) => entry.key === key));
});

test("immutable GC never selects an incomplete C bundle as authenticated garbage", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("incomplete-c-bundle");
  const artifact = await writeCBundleArtifact({
    cacheLayout,
    complete: false,
    stage: "incomplete-c-bundle",
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 1);
  assert.equal(plan.candidates, 0);
  assert.ok(plan.evictions.every(({ key }) => key !== artifact.key));
  await fs.lstat(artifact.root);
});

test("immutable GC does not claim blocks held by a surviving hardlink as reclaimable", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("hardlink-reclaim-estimate");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "hardlink-reclaim-estimate" },
    payload: Buffer.alloc(16_384, 1),
    stage: "hardlink-reclaim-estimate",
  });
  await fs.link(
    join(
      cacheLayout.immutable.artifacts,
      artifact.stage,
      artifact.key,
      artifact.entry.artifactFile
    ),
    join(value.root, "surviving-artifact-hardlink")
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  const candidate = plan.evictions.find(({ key }) => key === artifact.key);
  assert.notEqual(candidate, undefined);
  assert.ok(candidate.allocationBytes > candidate.estimatedReclaimBytes);
  assert.equal(plan.estimatedReclaimBytes, candidate.estimatedReclaimBytes);
});

test("immutable sweep uses a compact quarantine identity for a large C bundle", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-oversized-quarantine-record");
  const bundle = await writeCBundleArtifact({
    cacheLayout,
    functionCount: 2_800,
    stage: "oversized-quarantine-record",
  });
  const bundlePath = bundle.root;
  await Promise.all(
    [
      bundlePath,
      ...["COMPLETE", "entry.json", C_BUNDLE_MANIFEST_PATH].map((name) => join(bundlePath, name)),
      ...[...bundle.entry.bundle.translationUnits, bundle.entry.bundle.header].map(({ path }) =>
        join(bundlePath, path)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [bundle.key]
  );
  await assert.rejects(fs.lstat(bundlePath), { code: "ENOENT" });
});

test("immutable sweep rejects a redirected state ancestor before quarantine", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-state-redirect");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "state-redirect" },
    payload: "state-redirect",
    stage: "state-redirect",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const outsideState = join(value.root, "outside-state");
  await fs.mkdir(outsideState, { mode: 0o700 });
  await fs.symlink(outsideState, join(value.cacheRoot, "state"), "dir");

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      sweepConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /symlink/u
  );
  await fs.lstat(artifactPath);
  await assert.rejects(fs.lstat(join(outsideState, "cache-retention")), { code: "ENOENT" });
});

test("explicit immutable sweep removes only old unretained authenticated artifact entries", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "sweep-candidate" },
    payload: "old-sweep-candidate",
    stage: "sweep-candidate-stage",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.sweepAuthorized, true);
  assert.deepEqual(
    report.immutable.sweep.removed.map(({ key }) => key),
    [artifact.key]
  );
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweeping needs a caller-selected high watermark", async (t) => {
  const value = await fixture(t);
  for (const sweep of [{ immutableSweep: true }, { automaticImmutableSweep: true }]) {
    await assert.rejects(
      maintainConvexWasmCache(maintenanceOptions(value, { apply: true, ...sweep })),
      /requires an explicit high watermark/u
    );
  }
  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      environment: {
        ...value.environment,
        CONVEX_WASM_CACHE_HIGH_WATERMARK_BYTES: "1",
      },
    })
  );
  assert.equal(report.immutable.automaticSweep.highWatermarkAllocatedBytes, 1);
});

test("automatic maintenance skips immutable authentication below its high watermark", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("automatic-below-high-watermark");
  const malformedPath = join(
    cacheLayout.immutable.artifacts,
    "malformed-stage",
    "not-an-artifact-key"
  );
  await fs.mkdir(malformedPath, { mode: 0o700, recursive: true });
  const unexpectedFile = join(malformedPath, "unexpected");
  await fs.writeFile(unexpectedFile, "not an immutable entry", {
    mode: 0o600,
  });
  await fs.link(unexpectedFile, join(malformedPath, "duplicate-hardlink"));
  const occupancy = await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root);
  assert.ok(occupancy.allocatedBytes > occupancy.uniqueAllocatedBytes);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      immutableHighWatermarkAllocatedBytes: occupancy.uniqueAllocatedBytes,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.automaticSweep.triggered, false);
  assert.equal(report.immutable.plan, undefined);
  await fs.lstat(malformedPath);
});

test("automatic maintenance sweeps old immutable artifacts above its high watermark", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("automatic-above-high-watermark");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "automatic-sweep" },
    payload: "old-automatic-sweep-candidate",
    stage: "automatic-sweep-candidate",
  });
  await ageGenericArtifact(cacheLayout, artifact);
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      immutableHighWatermarkAllocatedBytes: 1,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.automaticSweep.triggered, true);
  assert.equal(report.immutable.sweep.trigger, "above-high-watermark");
  assert.deepEqual(
    report.immutable.sweep.removed.map(({ key }) => key),
    [artifact.key]
  );
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("automatic maintenance recovers quarantined entries below its high watermark", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("automatic-quarantine-recovery");
  const artifact = await writeGenericArtifact({
    cacheLayout, extension: "wasm", metadata: {}, payload: Buffer.alloc(1024 * 1024),
    stage: "automatic-quarantine-recovery",
  });
  await ageGenericArtifact(cacheLayout, artifact);
  const options = maintenanceOptions(value, {
    apply: true,
    automaticImmutableSweep: true,
    immutableHighWatermarkAllocatedBytes: 512 * 1024,
  });
  const readdir = fs.readdir;
  fs.readdir = async (path, ...args) => {
    if (path.includes("immutable-sweep-trash") && currentConvexWasmRetentionPhase() === "unlink") {
      throw new Error("synthetic automatic sweep interruption");
    }
    return await readdir(path, ...args);
  };
  try {
    await assert.rejects(maintainConvexWasmCache(options), /synthetic automatic sweep interruption/u);
  } finally {
    fs.readdir = readdir;
  }
  const recovered = await maintainConvexWasmCache(options);
  assert.ok(recovered.immutable.automaticSweep.occupancy.uniqueAllocatedBytes < options.immutableHighWatermarkAllocatedBytes);
  assert.equal(recovered.immutable.automaticSweep.triggered, true);
  assert.equal(recovered.immutable.sweep.recovered.length, 1);
  assert.deepEqual(recovered.immutable.sweep.removed, []);
  assert.equal(recovered.immutable.sweep.trigger, "interrupted-sweep");
  await assert.rejects(fs.lstat(join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash")), {
    code: "ENOENT",
  });
});

test("automatic maintenance shares its interval across calls while explicit sweeps remain immediate", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("automatic-interval");
  const options = maintenanceOptions(value, {
    apply: true,
    automaticImmutableSweep: true,
    immutableHighWatermarkAllocatedBytes: 1,
    nowMs: 2_000_000_000,
  });
  const writeCandidate = async (name) => {
    const artifact = await writeGenericArtifact({
      cacheLayout,
      extension: "wasm",
      identity: { fixture: name },
      metadata: { fixture: name },
      payload: name,
      stage: "automatic-interval-candidate",
    });
    await ageGenericArtifact(cacheLayout, artifact);
    return join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  };
  const first = await writeCandidate("first");
  await maintainConvexWasmCache(options);
  await assert.rejects(fs.lstat(first), { code: "ENOENT" });
  const second = await writeCandidate("second");
  const deferred = await maintainConvexWasmCache({ ...options, nowMs: options.nowMs + 1 });
  assert.equal(deferred.kind, "convex-wasm-cache-maintenance-deferred-v1");
  await fs.lstat(second);
  await maintainConvexWasmCache({ ...options, nowMs: deferred.nextDueAtMs });
  await assert.rejects(fs.lstat(second), { code: "ENOENT" });
  const third = await writeCandidate("third");
  await maintainConvexWasmCache({
    ...options,
    nowMs: deferred.nextDueAtMs + 1,
    automaticImmutableSweep: false,
    immutableSweep: true,
  });
  await assert.rejects(fs.lstat(third), { code: "ENOENT" });
});

test("a recent automatic receipt cannot suppress explicit sweep recovery or authorize new eviction", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cooldown-recovery");
  const options = maintenanceOptions(value, {
    apply: true, automaticImmutableSweep: true, immutableHighWatermarkAllocatedBytes: 1,
    nowMs: 2_000_000_000,
  });
  await maintainConvexWasmCache(options);
  const receiptPath = join(value.cacheRoot, "automatic-maintenance.json");
  const receipt = await fs.readFile(receiptPath, "utf8");
  const interrupted = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "interrupted", stage: "interrupted" });
  await ageGenericArtifact(cacheLayout, interrupted);
  const readdir = fs.readdir;
  fs.readdir = async (path, ...args) => {
    if (path.includes("immutable-sweep-trash") && currentConvexWasmRetentionPhase() === "unlink") throw new Error("synthetic explicit failure");
    return await readdir(path, ...args);
  };
  try {
    await assert.rejects(maintainConvexWasmCache({ ...options, automaticImmutableSweep: false, immutableSweep: true }), /synthetic explicit failure/u);
  } finally { fs.readdir = readdir; }
  assert.equal(await fs.readFile(receiptPath, "utf8"), receipt);
  const waiting = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "waiting", stage: "waiting" });
  await ageGenericArtifact(cacheLayout, waiting);
  const recovered = await maintainConvexWasmCache({ ...options, nowMs: options.nowMs + 1 });
  assert.equal(recovered.immutable.sweep.termination, "recovery-completed");
  assert.equal(recovered.immutable.sweep.recovered.length, 1);
  assert.deepEqual(recovered.immutable.sweep.removed, []);
  assert.equal(recovered.immutable.plan, undefined);
  assert.equal(await fs.readFile(receiptPath, "utf8"), receipt);
  await fs.lstat(join(cacheLayout.immutable.artifacts, waiting.stage, waiting.key));
  const deferred = await maintainConvexWasmCache({ ...options, nowMs: options.nowMs + 2 });
  assert.equal(deferred.kind, "convex-wasm-cache-maintenance-deferred-v1");
});

test("maintenance stamps completion after the work has finished", async (t) => {
  const value = await fixture(t);
  const startedAtMs = 2_000_000_000;
  let clockCalls = 0;
  const completedAtMs = startedAtMs + 20 * 60 * 1000;
  const options = maintenanceOptions(value, {
    apply: true, automaticImmutableSweep: true, immutableHighWatermarkAllocatedBytes: 1,
    clock: () => ++clockCalls === 1 ? startedAtMs : completedAtMs,
  });
  await maintainConvexWasmCache(options);
  assert.equal(clockCalls, 2);
  const next = await maintainConvexWasmCache({ ...options, clock: () => completedAtMs + 1 });
  assert.equal(next.kind, "convex-wasm-cache-maintenance-deferred-v1");
  assert.equal(next.nextDueAtMs, completedAtMs + 15 * 60 * 1000);
});

test("maintenance advances four layers with one inventory and fresh cross-wave hardlink witnesses", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("four-wave-maintenance");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const recordPath = join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key, compilerOutput.entry.artifactFile);
  const alias = await writeGenericArtifact({ cacheLayout, extension: "json", metadata: {}, payload: await fs.readFile(recordPath), stage: "cross-wave-alias" });
  const aliasPath = join(cacheLayout.immutable.artifacts, alias.stage, alias.key, alias.entry.artifactFile);
  await fs.unlink(aliasPath);
  await fs.link(recordPath, aliasPath);
  for (const entry of [compilerOutput, ...dependencies, capsule, topologyCertificate, alias]) await ageGenericArtifact(cacheLayout, entry);
  const retained = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "unchanged retained bytes", stage: "retained-payload" });
  const retainedPath = join(cacheLayout.immutable.artifacts, retained.stage, retained.key, retained.entry.artifactFile);
  const open = fs.open;
  let retainedOpens = 0;
  fs.open = async (...args) => { if (args[0] === retainedPath) retainedOpens += 1; return await open(...args); };
  let result;
  try {
    result = await maintainConvexWasmCache(maintenanceOptions(value, { apply: true, immutableSweep: true, immutableHighWatermarkAllocatedBytes: 1, nowMs: Date.now() }));
  } finally { fs.open = open; }
  assert.equal(result.diagnostics.phases.inventory.calls, 1);
  assert.equal(result.diagnostics.phases.immutableOccupancy.calls, 5);
  assert.equal(retainedOpens, 1);
  assert.equal(result.immutable.sweep.waves.length, 4);
  assert.equal(result.immutable.sweep.removed.length, 7);
  assert.equal(result.immutable.sweep.termination, "no-eligible-candidates");
  assert.equal(result.immutable.sweep.remainingExcessBytes, result.immutable.sweep.remainingAllocatedBytes - 1);
  assert.equal(result.immutable.plan.evictions.length, 0);
  assert.deepEqual(result.immutable.plan.retained.artifacts, [`${retained.stage}\0${retained.key}`]);
  assert.equal(await fs.readFile(retainedPath, "utf8"), "unchanged retained bytes");
});

test("unchanged retained authentication and structured parsing do not grow across deletion waves", async (t) => {
  const arms = [];
  const nowMs = Date.now();
  for (const waveCount of [1, 4]) {
    const value = await fixture(t);
    const material = await materializeModuleGraphPackageFixture(value);
    const { cacheLayout } = material;
    const certificate = await writeLegacyDeploymentResultCertificate(material);
    const disposable = await writeCompilerOutputFixture(cacheLayout);
    const disposableCapsule = await writeCohortCapsuleFixture(cacheLayout, disposable.compilerOutput, disposable.record);
    // The fixture's capsule identity is fixed. Give the disposable capsule its own
    // authenticated identity before constructing the independent retained closure.
    const oldCapsule = disposableCapsule.capsule;
    const oldCapsuleRoot = join(cacheLayout.immutable.artifacts, oldCapsule.stage, oldCapsule.key);
    const oldPayload = JSON.parse(await fs.readFile(join(oldCapsuleRoot, oldCapsule.entry.artifactFile), "utf8"));
    const { sha256: ignoredDigest, ...oldIdentity } = oldPayload.identity;
    const identityPayload = { ...oldIdentity, policies: { fixture: "disposable" } };
    oldPayload.identity = { ...identityPayload, sha256: fingerprintJson(identityPayload) };
    const separateCapsule = await writeGenericArtifact({
      cacheLayout, extension: "json", stage: oldCapsule.stage, metadata: oldCapsule.entry.metadata,
      identity: { ...oldCapsule.entry.identity, capsuleIdentity: oldPayload.identity },
      payload: `${canonicalJson(oldPayload)}\n`,
    });
    await fs.rm(oldCapsuleRoot, { recursive: true });
    for (const entry of [disposable.compilerOutput, ...disposable.dependencies, disposableCapsule.topologyCertificate, separateCapsule]) {
      await ageGenericArtifact(cacheLayout, entry);
    }

    const generatedCIdentity = {
      exportedUnitName: "this_unit", flags: ["-Xemit-c-bundle", "-Xemit-c-layout"],
      generatedSource: { sha256: "a".repeat(64), size: 10 },
      semanticEnvironment: { LANG: "C" }, staticHermes: { materials: "b".repeat(64) },
      unitRole: "untyped-official-chunk",
    };
    const selection = await planStaticHermesRetainedLayout({ cacheLayout, generatedCIdentity, stage: "retained-generated-c" });
    const bundle = await writeCBundleArtifact({
      cacheLayout, stage: "retained-generated-c", identity: selection.identity,
      retainedLayout: '{"kind":"static-hermes-c-layout-v1","unitName":"this_unit"}\n',
    });
    await publishStaticHermesRetainedLayout({ cacheLayout, generatedCEntry: { ...bundle.entry, bundlePath: bundle.root } });
    const layoutReferences = staticHermesLayoutCacheReferences(selection.identity, bundle.stage);
    for (const reference of layoutReferences) {
      const entryPath = join(cacheLayout.immutable.artifacts, reference.stage, reference.key, "entry.json");
      const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
      // Imported/legacy entries have no physical admission receipt. Exercise full
      // payload hashing rather than letting fresh fixture publication skip it.
      delete entry.admission;
      await fs.writeFile(entryPath, `${canonicalJson(entry)}\n`);
      await ageGenericArtifact(cacheLayout, reference);
    }
    const object = await writeGenericArtifact({ cacheLayout, extension: "o", stage: "retained-object", metadata: {}, payload: "retained object" });
    const probe = await writeGenericArtifact({ cacheLayout, extension: "cwasm", stage: "retained-probe", metadata: {}, payload: "retained probe" });
    const generatedC = compilerOutputReference({ ...bundle, extension: "c-bundle" });
    const picObject = compilerOutputReference({ ...object, extension: "o" });
    const record = structuredClone(disposable.record);
    record.descriptor.applicationIdentitySha256 = "e".repeat(64);
    record.descriptor.identitySha256 = "e".repeat(64);
    record.applicationUnits = record.applicationUnits.map(() => ({ generatedC, picObject }));
    record.engineProbe = compilerOutputReference({ ...probe, extension: "cwasm" });
    for (const stage of [record.bridge, record.formatter]) {
      Object.assign(stage, {
        generatedC, generatedCIdentity: bundle.entry.identity,
        object: picObject, objectIdentity: object.entry.identity,
      });
    }
    const compilerOutput = await writeGenericArtifact({
      cacheLayout, extension: "json", stage: disposable.compilerOutput.stage,
      identity: compilerOutputCacheIdentity(record.descriptor.identitySha256),
      metadata: disposable.compilerOutput.entry.metadata, payload: `${canonicalJson(record)}\n`,
    });
    const retainedCapsule = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
    const capsule = retainedCapsule.capsule;
    const topology = retainedCapsule.topologyCertificate;
    const topologyPayload = JSON.parse(await fs.readFile(join(cacheLayout.immutable.artifacts, topology.stage, topology.key, topology.entry.artifactFile), "utf8"));
    // The shared fixture writes single-C references; this closure exercises C bundles.
    for (const unit of [topologyPayload.bridge, topologyPayload.formatter, ...topologyPayload.applicationUnits]) {
      unit.generatedC.extension = "c-bundle";
    }
    const topologyCertificate = await writeGenericArtifact({
      cacheLayout, extension: "json", stage: topology.stage,
      identity: topology.entry.identity, metadata: topology.entry.metadata,
      payload: `${canonicalJson(topologyPayload)}\n`,
    });
    // Keep the compiler/package authorities by a durable snapshot, not by creation time.
    const snapshot = await withHeavyLock(value.environment, () => recordConvexWasmSuccessfulCacheUse({
      buildId: "retained-work", cacheLayout, environment: value.environment, recordedAtMs: 1_000,
      deployment: {
        manifest: material.manifest,
        buildReport: {
          cache: { certificateSha256: certificate.certificateSha256 },
          artifacts: [{ buildReport: { compilerOutputCache: { cacheKey: compilerOutput.key } } }],
        },
      },
    }));
    const certificateRoot = join(cacheLayout.immutable.packages, "deployment-results", "v1", fingerprintJson(certificate.lookupIdentity));
    await ageTree(join(cacheLayout.immutable.packages, material.graphManifestSha256));
    await ageTree(certificateRoot);
    for (const entry of [compilerOutput, topologyCertificate, bundle, object, probe]) await ageGenericArtifact(cacheLayout, entry);
    for (const reference of material.packageMaterial.artifactReferences) {
      for (const { artifact } of [reference.aot, reference.coreWasm]) {
        await ageGenericArtifact(cacheLayout, { stage: artifact.stage, key: artifact.cacheKey });
      }
    }
    const targets = new Map();
    const addTarget = async (path, requiresHash, family) => {
      const bytes = await fs.readFile(path);
      const label = path.slice(value.cacheRoot.length + 1);
      assert.equal(targets.has(path), false);
      // A changed shared inode legitimately requires new byte checks. The companion
      // four-wave hardlink regression covers that case; this arm measures unchanged files.
      assert.equal((await fs.lstat(path)).nlink, 1);
      targets.set(path, { label, requiresHash, family, bytes, sha256: createHash("sha256").update(bytes).digest("hex") });
    };
    for (const entry of [compilerOutput, topologyCertificate, capsule, object, probe]) {
      await addTarget(join(cacheLayout.immutable.artifacts, entry.stage, entry.key, entry.entry.artifactFile), true, entry.stage);
    }
    for (const member of [bundle.entry.bundle.manifest, bundle.entry.bundle.header, ...bundle.entry.bundle.translationUnits, bundle.entry.bundle.layout]) {
      await addTarget(join(bundle.root, member.path), true, "c-bundle");
    }
    for (const reference of layoutReferences) {
      await addTarget(join(cacheLayout.immutable.artifacts, reference.stage, reference.key, "artifact.json"), true, reference.stage);
    }
    for (const reference of material.packageMaterial.artifactReferences) {
      for (const [kind, extension] of [["aot", "cwasm"], ["coreWasm", "wasm"]]) {
        const artifact = reference[kind].artifact;
        await addTarget(join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey, `artifact.${extension}`), true, "package-payloads");
      }
    }
    for (const name of ["graph-manifest.json", "build-provenance.json", "package-entry.json"]) {
      await addTarget(join(cacheLayout.immutable.packages, material.graphManifestSha256, name), true, "package");
    }
    await addTarget(join(certificateRoot, certificate.certificateSha256, "certificate.json"), false, "certificate");
    await addTarget(join(value.cacheRoot, "state", "v1", "cache-retention", "v1", "recent-success", `${snapshot.snapshotSha256}.json`), false, "snapshot");
    const contents = [...targets.values()].map(({ label, sha256 }) => [label, sha256]).sort();
    if (arms.length !== 0) assert.deepEqual(contents, arms[0].contents, "both arms must contain identical retained bytes");

    const occupancy = await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root);
    const measurements = Object.fromEntries([...targets.values()].map(({ label }) => [label, {
      readBytes: 0, fullFileHashes: 0, fullFileHashBytes: 0, parses: 0, phases: {},
    }]));
    const jsonSources = new Map();
    for (const { label, bytes } of targets.values()) {
      if (!label.endsWith(".json")) continue;
      const source = bytes.toString("utf8");
      if (!jsonSources.has(source)) jsonSources.set(source, []);
      jsonSources.get(source).push(label);
    }
    const observe = (label, field, amount) => {
      const row = measurements[label];
      row[field] += amount;
      const phase = currentConvexWasmRetentionPhase();
      assert.notEqual(phase, undefined);
      row.phases[phase] ??= { readBytes: 0, fullFileHashes: 0, fullFileHashBytes: 0, parses: 0 };
      row.phases[phase][field] += amount;
    };
    // Attribute hashes to the exact ArrayBuffer extents populated by real file reads.
    // Digest completion must cover the whole file and match its independently saved
    // SHA-256. Read bytes alone are deliberately not called authenticated bytes.
    const readExtents = new WeakMap();
    const hashInputs = new WeakMap();
    const hashPrototype = Object.getPrototypeOf(createHash("sha256"));
    const original = { open: fs.open, parse: JSON.parse, update: hashPrototype.update, digest: hashPrototype.digest };
    fs.open = async (path, ...args) => {
      const handle = await original.open(path, ...args);
      const target = targets.get(path);
      if (target !== undefined) {
        const read = handle.read;
        handle.read = async function (buffer, offset, ...args) {
          const result = await read.call(this, buffer, offset, ...args);
          const start = buffer.byteOffset + offset;
          const end = start + result.bytesRead;
          const extents = readExtents.get(buffer.buffer) ?? [];
          readExtents.set(buffer.buffer, [...extents.filter((extent) => extent.end <= start || extent.start >= end), { start, end, target }]);
          observe(target.label, "readBytes", result.bytesRead);
          return result;
        };
      }
      return handle;
    };
    hashPrototype.update = function (data, ...args) {
      if (Buffer.isBuffer(data)) {
        const extent = readExtents.get(data.buffer)?.find(({ start, end }) => start <= data.byteOffset && end >= data.byteOffset + data.byteLength);
        if (extent !== undefined) {
          const inputs = hashInputs.get(this) ?? [];
          inputs.push({ target: extent.target, bytes: data.byteLength });
          hashInputs.set(this, inputs);
        }
      }
      return original.update.call(this, data, ...args);
    };
    hashPrototype.digest = function (...args) {
      const digest = original.digest.apply(this, args);
      const inputs = hashInputs.get(this);
      if (inputs !== undefined) {
        const target = inputs[0].target;
        const bytes = inputs.reduce((total, input) => total + input.bytes, 0);
        if (inputs.every((input) => input.target === target) && bytes === target.bytes.length &&
            (Buffer.isBuffer(digest) ? digest.toString("hex") : digest) === target.sha256) {
          observe(target.label, "fullFileHashes", 1);
          observe(target.label, "fullFileHashBytes", bytes);
        }
      }
      return digest;
    };
    JSON.parse = function (source, ...args) {
      for (const label of jsonSources.get(source) ?? []) observe(label, "parses", 1);
      return original.parse.call(this, source, ...args);
    };
    let result;
    try {
      result = await maintainConvexWasmCache(maintenanceOptions(value, {
        apply: true, immutableSweep: true, nowMs,
        immutableHighWatermarkAllocatedBytes: waveCount === 1 ? occupancy.uniqueAllocatedBytes - 1 : 1,
      }));
    } finally {
      fs.open = original.open;
      JSON.parse = original.parse;
      hashPrototype.update = original.update;
      hashPrototype.digest = original.digest;
    }
    assert.equal(result.immutable.sweep.waves.length, waveCount);
    assert.equal(result.immutable.sweep.removed.length, waveCount === 1 ? 1 : 6);
    assert.equal(result.diagnostics.counts.inventoryBuilds, 1);
    for (const { label, requiresHash, family, bytes } of targets.values()) {
      const row = measurements[label];
      assert.ok(row.readBytes >= bytes.length, `${label} must be read during maintenance`);
      if (requiresHash) assert.ok(row.fullFileHashes > 0, `${label} must undergo full payload hashing`);
      if (["package", "certificate", "snapshot"].includes(family) || label.endsWith(`/${bundle.entry.bundle.manifest.path}`)) {
        assert.ok(row.parses > 0, `${label} must be structurally interpreted`);
      }
      assert.deepEqual(Object.keys(row.phases), ["inventory"], `${label} must not be reprocessed during deletion or later planning`);
    }
    for (const entry of [compilerOutput, topologyCertificate, capsule]) {
      const label = `immutable/v6/artifacts/${entry.stage}/${entry.key}/${entry.entry.artifactFile}`;
      assert.equal(measurements[label].parses, 1, `${entry.stage} is interpreted once`);
    }
    for (const path of targets.keys()) await fs.lstat(path);
    const summary = {};
    for (const { family, label } of targets.values()) {
      summary[family] ??= { files: 0, readBytes: 0, fullFileHashes: 0, fullFileHashBytes: 0, parses: 0 };
      summary[family].files += 1;
      for (const field of ["readBytes", "fullFileHashes", "fullFileHashBytes", "parses"]) summary[family][field] += measurements[label][field];
    }
    arms.push({ contents, measurements, summary });
  }
  assert.deepEqual(arms[1].measurements, arms[0].measurements,
    "unchanged retained file authentication, reads and structured parsing must be independent of deletion-wave count");
  t.diagnostic(`Identical retained work in one and four waves: ${JSON.stringify(arms[0].summary)}`);
});

test("cached inventory rejects changed retained authority before advancing a wave", async (t) => {
  for (const mutation of ["rewrite-restored-mtime", "replacement", "permission", "new-authority", "redirected-ancestor", "shared-rewrite"]) {
    await t.test(mutation, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout("changed-authority");
      const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
      const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
      for (const entry of [compilerOutput, ...dependencies, capsule, topologyCertificate]) await ageGenericArtifact(cacheLayout, entry);
      const recordRoot = join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key);
      const recordPath = join(recordRoot, compilerOutput.entry.artifactFile);
      if (mutation === "shared-rewrite") {
        const alias = await writeGenericArtifact({ cacheLayout, extension: "json", metadata: {}, payload: await fs.readFile(recordPath), stage: "cross-wave-alias" });
        const aliasPath = join(cacheLayout.immutable.artifacts, alias.stage, alias.key, alias.entry.artifactFile);
        await fs.unlink(aliasPath);
        await fs.link(recordPath, aliasPath);
        await ageGenericArtifact(cacheLayout, alias);
      }
      const rmdir = fs.rmdir;
      let changed = false;
      fs.rmdir = async (path, ...args) => {
        const result = await rmdir(path, ...args);
        if (!String(path).endsWith("/immutable-sweep-trash") || changed) return result;
        changed = true;
        if (mutation === "rewrite-restored-mtime" || mutation === "shared-rewrite") {
          const status = await fs.stat(recordPath);
          const bytes = await fs.readFile(recordPath);
          bytes[0] = 32;
          await fs.writeFile(recordPath, bytes);
          await fs.utimes(recordPath, status.atime, status.mtime);
        } else if (mutation === "replacement") {
          const status = await fs.stat(recordPath);
          const bytes = await fs.readFile(recordPath);
          await fs.rename(recordPath, join(value.root, "old-record"));
          await fs.writeFile(recordPath, bytes, { mode: 0o600 });
          await fs.utimes(recordPath, status.atime, status.mtime);
        } else if (mutation === "permission") {
          await fs.chmod(recordPath, 0o400);
        } else if (mutation === "new-authority") {
          await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
        } else {
          const stage = join(cacheLayout.immutable.artifacts, compilerOutput.stage);
          await fs.rename(stage, join(value.root, "redirected-stage"));
          await fs.symlink(join(value.root, "redirected-stage"), stage);
        }
        return result;
      };
      try {
        await assert.rejects(maintainConvexWasmCache(maintenanceOptions(value, {
          apply: true, immutableSweep: true, immutableHighWatermarkAllocatedBytes: 1, nowMs: Date.now(),
        })), /immutable (authority|shared file)|removed immutable authority|new immutable authority/u);
      } finally { fs.rmdir = rmdir; }
      assert.equal(changed, true);
      for (const dependency of dependencies) await fs.lstat(join(cacheLayout.immutable.artifacts, dependency.stage, dependency.key));
    });
  }
});

test("immutable occupancy rejects symbolic links inside publication scratch before eviction", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("publication-scratch-link");
  const artifact = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "old artifact", stage: "publication-scratch-link" });
  await ageGenericArtifact(cacheLayout, artifact);
  const artifactRoot = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const scratch = join(cacheLayout.immutable.artifacts, artifact.stage, ".publish-interrupted");
  await fs.mkdir(scratch, { mode: 0o700 });
  await fs.symlink(artifactRoot, join(scratch, "redirected"));
  await assert.rejects(withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc({
    cacheLayout, environment: value.environment, highWatermarkAllocatedBytes: 1,
  })), /symbolic link/u);
  await assert.rejects(maintainConvexWasmCache(maintenanceOptions(value, {
    apply: true, immutableSweep: true, immutableHighWatermarkAllocatedBytes: 1,
  })), /symbolic link/u);
  await fs.lstat(artifactRoot);
});

test("authority fence failure drains admitted metadata reads before releasing the lock", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("fence-read-drain");
  const paths = [];
  for (const name of ["failure", "delayed"]) {
    const entry = await writeGenericArtifact({ cacheLayout, extension: "wasm", identity: { name }, metadata: {}, payload: name, stage: "fence-read-drain" });
    paths.push(join(cacheLayout.immutable.artifacts, entry.stage, entry.key, entry.entry.artifactFile));
  }
  let held = false;
  const cacheLock = {
    acquire() { held = true; return () => { held = false; }; },
    inheritedAuthorityEnvironment() { return {}; },
    requireAuthority() { assert.equal(held, true); },
  };
  const started = Promise.withResolvers();
  const delayed = Promise.withResolvers();
  const failed = Promise.withResolvers();
  const lstat = fs.lstat;
  fs.lstat = async (path, ...args) => {
    if (path === paths[0]) {
      await started.promise;
      failed.resolve();
      throw new Error("synthetic fence read failure");
    }
    if (path === paths[1]) { started.resolve(); await delayed.promise; }
    return await lstat(path, ...args);
  };
  let settled = false;
  const result = maintainConvexWasmCache(maintenanceOptions(value, {
    apply: true, immutableSweep: true, immutableHighWatermarkAllocatedBytes: 1, cacheLock,
  })).then(() => { settled = true; return undefined; }, (error) => { settled = true; return error; });
  try {
    await failed.promise;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(held, true);
    assert.equal(settled, false);
    delayed.resolve();
    assert.match((await result).message, /synthetic fence read failure/u);
    assert.equal(held, false);
  } finally { delayed.resolve(); await result; fs.lstat = lstat; }
});

test("quarantine deletion and recovery drain admitted unlinks before releasing the lock", async (t) => {
  for (const recovery of [false, true]) {
    await t.test(recovery ? "recovery" : "new deletion", async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout("unlink-drain");
      const artifact = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "delayed payload", stage: "unlink-drain" });
      await ageGenericArtifact(cacheLayout, artifact);
      let held = false;
      const cacheLock = {
        acquire() { assert.equal(held, false); held = true; return () => { held = false; }; },
        inheritedAuthorityEnvironment() { return {}; },
        requireAuthority() { assert.equal(held, true); },
      };
      const options = maintenanceOptions(value, { apply: true, immutableSweep: true,
        immutableHighWatermarkAllocatedBytes: 1, cacheLock });
      if (recovery) {
        const readdir = fs.readdir;
        fs.readdir = async (path, ...args) => {
          if (await isVerifiedQuarantineRoot(path)) throw new Error("interrupted before unlink");
          return await readdir(path, ...args);
        };
        try {
          await assert.rejects(maintainConvexWasmCache(options), /interrupted before unlink/u);
        } finally { fs.readdir = readdir; }
      }
      const started = Promise.withResolvers();
      const delayed = Promise.withResolvers();
      const failed = Promise.withResolvers();
      const unlink = fs.unlink;
      fs.unlink = async (path, ...args) => {
        if (path.includes("immutable-sweep-trash") && path.endsWith("/COMPLETE")) {
          await started.promise;
          failed.resolve();
          throw new Error("synthetic child unlink failure");
        }
        if (path.includes("immutable-sweep-trash") && path.endsWith("/artifact.wasm")) {
          started.resolve();
          await delayed.promise;
          assert.equal(held, true, "admitted payload unlink must remain under the lock");
        }
        return await unlink(path, ...args);
      };
      let settled = false;
      const result = maintainConvexWasmCache(options).then(
        () => { settled = true; return undefined; },
        (error) => { settled = true; return error; }
      );
      try {
        await failed.promise;
        await new Promise((resolve) => setImmediate(resolve));
        assert.equal(held, true);
        assert.equal(settled, false);
        delayed.resolve();
        assert.match((await result).message, /synthetic child unlink failure/u);
        assert.equal(held, false);
      } finally { delayed.resolve(); await result; fs.unlink = unlink; }
      const retry = await maintainConvexWasmCache(options);
      assert.equal(retry.immutable.sweep.recovered.length, 1);
      assert.deepEqual(retry.immutable.sweep.removed, []);
    });
  }
});

test("phase measurements do not change a fixed-time plan identity", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("diagnostic-plan-identity");
  const artifact = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "retained", stage: "diagnostic-plan-identity" });
  await ageGenericArtifact(cacheLayout, artifact);
  const options = maintenanceOptions(value, { apply: true, immutableSweep: true,
    immutableHighWatermarkAllocatedBytes: Number.MAX_SAFE_INTEGER, nowMs: 2_000_000_000 });
  const first = await maintainConvexWasmCache(options);
  const second = await maintainConvexWasmCache(options);
  assert.equal(first.immutable.plan.planSha256, second.immutable.plan.planSha256);
  assert.equal(first.immutable.sweep.termination, "watermark-reached");
  assert.equal(first.diagnostics.counts.inventoryBuilds, 1);
  assert.equal(first.diagnostics.counts.dedicatedImmutableOccupancyWalks, 0);
});

test("maintenance keeps its lock until both occupancy reads drain after failure", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("occupancy-failure");
  await fs.mkdir(cacheLayout.immutable.root, { mode: 0o700, recursive: true });
  let held = false;
  const cacheLock = {
    acquire() { held = true; return () => { held = false; }; },
    inheritedAuthorityEnvironment() { return {}; },
    requireAuthority() { assert.equal(held, true); },
  };
  const readdir = fs.readdir;
  const pendingRead = Promise.withResolvers();
  const readStarted = Promise.withResolvers();
  const failure = new Error("synthetic occupancy read failure");
  fs.readdir = async (path, ...args) => {
    if (path === value.cacheRoot) throw failure;
    if (path === cacheLayout.immutable.root) {
      readStarted.resolve();
      await pendingRead.promise;
    }
    return await readdir(path, ...args);
  };
  const result = maintainConvexWasmCache(maintenanceOptions(value, {
    apply: true, automaticImmutableSweep: true, cacheLock,
    immutableHighWatermarkAllocatedBytes: 1, includeImmutableOccupancy: true,
  })).then(() => undefined, (error) => error);
  try {
    await readStarted.promise;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(held, true);
  } finally {
    pendingRead.resolve();
    assert.equal(await result, failure);
    fs.readdir = readdir;
  }
  assert.equal(held, false);
});

test("host lock ownership covers leases, immutable planning and sweeping", async (t) => {
  const value = await fixture(t);
  let held = false;
  const cacheLock = {
    acquire() {
      assert.equal(held, false);
      held = true;
      return () => { held = false; };
    },
    inheritedAuthorityEnvironment() { return held ? { hostLock: "held" } : {}; },
    requireAuthority() {
      if (!held) throw new Error("host lock is not held");
    },
  };
  const cacheLayout = value.layout("host-lock");
  await assert.rejects(createConvexWasmBuildWorkLease({ cacheLayout, cacheLock }), /host lock/u);
  const release = cacheLock.acquire();
  const lease = await createConvexWasmBuildWorkLease({ cacheLayout, cacheLock });
  await assert.rejects(
    maintainConvexWasmCache(maintenanceOptions(value, { apply: true, cacheLock })),
    /not inherit build authority/u
  );
  release();
  await assert.rejects(lease.complete(), /host lock/u);
  const finish = cacheLock.acquire();
  await lease.complete();
  finish();
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "host-lock" },
    payload: "expired candidate",
    stage: "host-lock-candidate",
  });
  await ageGenericArtifact(cacheLayout, artifact);
  const report = await maintainConvexWasmCache(maintenanceOptions(value, {
    apply: true,
    cacheLock,
    immutableSweep: true,
    immutableHighWatermarkAllocatedBytes: 1,
    nowMs: 2_000_000_000,
  }));
  assert.equal(held, false);
  assert.deepEqual(report.immutable.sweep.removed.map(({ key }) => key), [artifact.key]);
});

test("immutable maintenance rejects stale automatic pressure before evicting a candidate", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("stale-automatic-pressure");
  const artifact = await writeGenericArtifact({
    cacheLayout, extension: "wasm", metadata: {}, payload: "old candidate",
    stage: "stale-automatic-pressure",
  });
  await ageGenericArtifact(cacheLayout, artifact);
  const candidatePath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const scratchPath = join(cacheLayout.immutable.artifacts, artifact.stage, ".publish-interrupted");
  await fs.mkdir(scratchPath, { mode: 0o700 });
  await fs.writeFile(join(scratchPath, "payload"), Buffer.alloc(1024 * 1024), { mode: 0o600 });
  const highWatermark = 512 * 1024;
  assert.ok((await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root)).uniqueAllocatedBytes > highWatermark);
  const lstat = fs.lstat;
  let changed = false;
  fs.lstat = async (path, ...args) => {
    if (!changed && currentConvexWasmRetentionPhase() === "recovery") {
      changed = true;
      // Admission has completed, but the inventory's first fence has not been captured.
      await fs.rm(scratchPath, { recursive: true });
    }
    return await lstat(path, ...args);
  };
  try {
    await assert.rejects(maintainConvexWasmCache(maintenanceOptions(value, {
      apply: true, automaticImmutableSweep: true,
      immutableHighWatermarkAllocatedBytes: highWatermark, nowMs: 2_000_000_000,
    })), /immutable occupancy changed after automatic admission/u);
  } finally {
    fs.lstat = lstat;
  }
  assert.equal(changed, true);
  assert.ok((await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root)).uniqueAllocatedBytes < highWatermark);
  await fs.lstat(candidatePath);
  await assert.rejects(fs.lstat(join(value.cacheRoot, "automatic-maintenance.json")), { code: "ENOENT" });
});

test("maintenance preserves entries at the high watermark and stops after reclaiming enough", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("bounded-sweep");
  const large = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    identity: { fixture: "bounded-sweep-large" },
    metadata: { fixture: "bounded-sweep" },
    payload: Buffer.alloc(1024 * 1024),
    stage: "bounded-sweep",
  });
  const small = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    identity: { fixture: "bounded-sweep-small" },
    metadata: { fixture: "bounded-sweep" },
    payload: Buffer.alloc(4096),
    stage: "bounded-sweep",
  });
  await Promise.all([
    ageGenericArtifact(cacheLayout, large),
    ageGenericArtifact(cacheLayout, small),
  ]);

  const occupancy = await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root);
  const atWatermark = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableSweep: true,
      immutableHighWatermarkAllocatedBytes: occupancy.uniqueAllocatedBytes,
      nowMs: 2_000_000_000_000,
    })
  );
  assert.deepEqual(atWatermark.immutable.sweep.removed, []);
  assert.equal(atWatermark.immutable.plan.pressure.active, false);
  assert.equal(atWatermark.immutable.sweep.remainingAllocatedBytes, occupancy.uniqueAllocatedBytes);

  const result = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableSweep: true,
      immutableHighWatermarkAllocatedBytes: 128 * 1024,
      nowMs: 2_000_000_000_000,
    })
  );

  assert.deepEqual(
    result.immutable.sweep.removed.map(({ key }) => key),
    [large.key]
  );
  assert.ok(result.immutable.sweep.remainingAllocatedBytes <= 128 * 1024);
  await fs.lstat(join(cacheLayout.immutable.artifacts, small.stage, small.key));
  await assert.rejects(fs.lstat(join(cacheLayout.immutable.artifacts, large.stage, large.key)), {
    code: "ENOENT",
  });
});

test("immutable sweep handles shared payloads before unlinking or recovering a batch", async (t) => {
  for (const interruption of ["none", "after-rename", "partial-removal"]) {
    await t.test(interruption, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout("immutable-shared-payload");
      const artifacts = [];
      for (const stage of ["shared-first", "shared-second"]) {
        artifacts.push(await writeGenericArtifact({
          cacheLayout, extension: "wasm", metadata: {}, payload: "shared payload", stage,
        }));
      }
      const paths = artifacts.map(({ stage, key }) => join(cacheLayout.immutable.artifacts, stage, key));
      await fs.unlink(join(paths[1], "artifact.wasm"));
      await fs.link(join(paths[0], "artifact.wasm"), join(paths[1], "artifact.wasm"));
      const options = {
        cacheLayout, environment: value.environment, highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000, recentRetentionMilliseconds: 0,
      };
      const original = { open: fs.open, readdir: fs.readdir };
      let verifiedWrites = 0;
      fs.open = async (path, ...args) => {
        if (typeof path === "string" && path.endsWith(".verified.json") && args[0] === "wx" &&
            interruption === "after-rename" && ++verifiedWrites === 2) {
          throw new Error("synthetic shared payload interruption");
        }
        return await original.open(path, ...args);
      };
      fs.readdir = async (path, ...args) => {
        if (interruption === "partial-removal" && await isVerifiedQuarantineRoot(path)) {
          await fs.unlink(join(path, "artifact.wasm"));
          throw new Error("synthetic shared payload interruption");
        }
        return await original.readdir(path, ...args);
      };
      let result;
      try {
        const run = () => withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
        if (interruption === "none") result = await run();
        else await assert.rejects(run, /synthetic shared payload interruption/u);
      } finally {
        Object.assign(fs, original);
      }
      if (interruption === "none") assert.equal(result.removed.length, 2);
      else {
        const retry = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
        assert.equal(retry.recovered.length, 2);
        assert.deepEqual(retry.removed, []);
      }
      for (const path of paths) await assert.rejects(fs.lstat(path), { code: "ENOENT" });
    });
  }
});

test("immutable recovery completes an interrupted source-directory sync before removal", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("interrupted-rename-sync");
  const artifact = await writeGenericArtifact({
    cacheLayout, extension: "wasm", metadata: {}, payload: "interrupted rename sync",
    stage: "interrupted-rename-sync",
  });
  const candidatePath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const sourceParent = dirname(candidatePath);
  const options = {
    cacheLayout, environment: value.environment, highWatermarkAllocatedBytes: 1,
    nowMs: Date.now() + 1_000, recentRetentionMilliseconds: 0,
  };
  const open = fs.open;
  fs.open = async (path, ...args) => {
    const handle = await open(path, ...args);
    if (path === sourceParent && args[0] === "r") {
      handle.sync = async () => {
        throw Object.assign(new Error("synthetic source-directory sync failure"), { code: "EIO" });
      };
    }
    return handle;
  };
  try {
    // The initial rename succeeds, but neither its source sync nor a verified marker completes.
    // Recovery must preserve that quarantine while the same durability fence still fails.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await assert.rejects(
        withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options)),
        /synthetic source-directory sync failure/u
      );
    }
  } finally {
    fs.open = open;
  }
  await assert.rejects(fs.lstat(candidatePath), { code: "ENOENT" });
  const recovered = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
  assert.equal(recovered.recovered.length, 1);
  assert.deepEqual(recovered.removed, []);
});

test("immutable sweep recovers incomplete marker writes without treating them as authority", async (t) => {
  for (const verified of [false, true]) {
    await t.test(verified ? "verified marker" : "base marker", async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout("incomplete-marker");
      const artifact = await writeGenericArtifact({
        cacheLayout, extension: "wasm", metadata: {}, payload: "incomplete-marker", stage: "incomplete-marker",
      });
      const options = {
        cacheLayout, environment: value.environment, highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000, recentRetentionMilliseconds: 0,
      };
      const open = fs.open;
      let interruptedPath;
      fs.open = async (path, ...args) => {
        const handle = await open(path, ...args);
        if (args[0] === "wx" && path.includes("immutable-sweep-trash") &&
            path.endsWith(".verified.json") === verified) {
          interruptedPath = path;
          const writeFile = handle.writeFile;
          handle.writeFile = async function (contents) {
            await writeFile.call(this, contents.slice(0, 16));
            throw Object.assign(new Error("synthetic incomplete marker write"), { code: "ENOSPC" });
          };
        }
        return handle;
      };
      try {
        await assert.rejects(
          withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options)),
          /synthetic incomplete marker write/u
        );
      } finally {
        fs.open = open;
      }
      // A killed process cannot run its temporary-file cleanup. Leave the same partial write
      // behind to exercise recovery of crash residue as well as an ordinary failed write.
      await fs.writeFile(interruptedPath, "{", { mode: 0o600 });
      const retry = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
      assert.equal(retry.recovered.length, verified ? 1 : 0);
      assert.equal(retry.removed.length, verified ? 0 : 1);
      await assert.rejects(fs.lstat(join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key)), {
        code: "ENOENT",
      });
    });
  }
});

test("immutable sweep quarantines a selected root before fallible recursive removal", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-removal-failure");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "sweep-removal-failure" },
    payload: "old-sweep-removal-failure",
    stage: "sweep-removal-failure",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const readdir = fs.readdir;
  let removalAttempted = false;
  fs.readdir = async (path, ...args) => {
    if (await isVerifiedQuarantineRoot(path)) {
      removalAttempted = true;
      throw Object.assign(new Error("synthetic immutable trash removal failure"), {
        code: "EIO",
      });
    }
    return await readdir(path, ...args);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /synthetic immutable trash removal failure/u
    );
  } finally {
    fs.readdir = readdir;
  }
  assert.equal(removalAttempted, true);
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
  const trashRoot = join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash");
  const planRoots = await fs.readdir(trashRoot);
  assert.equal(planRoots.length, 1);
  const quarantineEntries = await fs.readdir(join(trashRoot, planRoots[0]));
  // The base marker and the post-authentication removal marker both remain durable while the
  // recursive delete is in progress, so recovery can distinguish a partial delete from an
  // unverified replacement.
  assert.equal(quarantineEntries.length, 3);
  const quarantinedRoot = quarantineEntries.find((name) => /^[0-9a-f]{64}$/u.test(name));
  assert.notEqual(quarantinedRoot, undefined);
  assert.equal(
    await fs.readFile(
      join(trashRoot, planRoots[0], quarantinedRoot, artifact.entry.artifactFile),
      "utf8"
    ),
    "old-sweep-removal-failure"
  );
  const retry = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(retry.recovered.length, 1);
  assert.equal(retry.recovered[0].status, "removed-quarantined-root");
  assert.deepEqual(retry.removed, []);
  await assert.rejects(fs.lstat(trashRoot), { code: "ENOENT" });
});

test("maintenance recovers interrupted package and certificate retirement and finishes their closure", async (t) => {
  for (const type of ["package", "certificate-root"]) {
    for (const interruption of ["before-rename", "after-rename", "partial-removal", "marker-cleanup"]) {
      await t.test(`${type}: ${interruption}`, async (t) => {
        const value = await fixture(t);
        const material = await materializeModuleGraphPackageFixture(value);
        const { cacheLayout, graphManifestSha256 } = material;
        let candidatePath = join(cacheLayout.immutable.packages, graphManifestSha256);
        if (type === "certificate-root") {
          const certificate = await writeLegacyDeploymentResultCertificate(material);
          candidatePath = join(cacheLayout.immutable.packages, "deployment-results", "v1",
            fingerprintJson(certificate.lookupIdentity));
        }
        await ageTree(cacheLayout.immutable.root);
        const options = {
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        };
        const original = { open: fs.open, rename: fs.rename, readdir: fs.readdir, unlink: fs.unlink };
        const interrupt = () => {
          throw Object.assign(new Error("synthetic root retirement interruption"), { code: "EIO" });
        };
        fs.rename = async (from, to) => {
          if (from === candidatePath && interruption === "before-rename") interrupt();
          return await original.rename(from, to);
        };
        fs.open = async (path, ...args) => {
          if (interruption === "after-rename" && path.endsWith(".verified.json")) interrupt();
          return await original.open(path, ...args);
        };
        fs.readdir = async (path, ...args) => {
          if (interruption === "partial-removal" && await isVerifiedQuarantineRoot(path)) {
            const name = (await original.readdir(path))[0];
            await fs.rm(join(path, name), { recursive: true });
            interrupt();
          }
          return await original.readdir(path, ...args);
        };
        fs.unlink = async (path) => {
          if (interruption === "marker-cleanup" && path.includes("immutable-sweep-trash") &&
              /\/[0-9a-f]{64}\.json$/u.test(path)) interrupt();
          return await original.unlink(path);
        };
        try {
          await assert.rejects(
            withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options)),
            /synthetic root retirement interruption/u
          );
        } finally {
          Object.assign(fs, original);
        }
        if (interruption === "before-rename") await fs.lstat(candidatePath);
        else await assert.rejects(fs.lstat(candidatePath), { code: "ENOENT" });
        const report = await maintainConvexWasmCache(
          maintenanceOptions(value, {
            apply: true,
            immutableSweep: true,
            immutableHighWatermarkAllocatedBytes: options.highWatermarkAllocatedBytes,
            nowMs: options.nowMs,
          })
        );
        const recovered = report.immutable.sweep;
        assert.equal(recovered.recovered.length, 1);
        assert.equal(recovered.recovered[0].status,
          interruption === "before-rename" ? "cleared-pre-rename-marker" :
            interruption === "marker-cleanup" ? "cleared-completed-marker" : "removed-quarantined-root");
        assert.equal(report.immutable.plan.authenticated.invalid, 0);
        assert.equal(report.immutable.plan.candidates, 0);
        const removedRootCount = (interruption === "before-rename" ? 1 : 0) +
          (type === "certificate-root" ? 1 : 0);
        assert.equal(recovered.removed.length,
          removedRootCount + material.packageMaterial.artifactReferences.length * 2);
        assert.equal(new Set(recovered.removed.map(({ path }) => path)).size, recovered.removed.length);
        for (const { aot, coreWasm } of material.packageMaterial.artifactReferences) {
          for (const { artifact } of [aot, coreWasm]) {
            await assert.rejects(fs.lstat(join(cacheLayout.immutable.artifacts,
              artifact.stage, artifact.cacheKey)), { code: "ENOENT" });
          }
        }
        await assert.rejects(fs.lstat(candidatePath), { code: "ENOENT" });
        await assert.rejects(fs.lstat(join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash")), {
          code: "ENOENT",
        });
      });
    }
  }
});

test("immutable sweep rejects changed or redirected package and certificate quarantine trees", async (t) => {
  for (const type of ["package", "certificate-root"]) {
    for (const replacement of ["changed", "symlink"]) {
      await t.test(`${type}: ${replacement}`, async (t) => {
        const value = await fixture(t);
        const material = await materializeModuleGraphPackageFixture(value);
        const { cacheLayout, graphManifestSha256 } = material;
        let candidatePath = join(cacheLayout.immutable.packages, graphManifestSha256);
        let memberPath = join(candidatePath, "COMPLETE");
        if (type === "certificate-root") {
          const certificate = await writeLegacyDeploymentResultCertificate(material);
          candidatePath = join(cacheLayout.immutable.packages, "deployment-results", "v1",
            fingerprintJson(certificate.lookupIdentity));
          memberPath = join(candidatePath, certificate.certificateSha256, "COMPLETE");
        }
        const outside = join(value.root, "outside-authority");
        await fs.writeFile(outside, "surviving outside material", { mode: 0o600 });
        const options = {
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        };
        const originalRename = fs.rename;
        let quarantinedPath;
        fs.rename = async (from, to) => {
          if (from === candidatePath) {
            if (replacement === "changed") await fs.writeFile(memberPath, "changed marker\n");
            else {
              await fs.unlink(memberPath);
              await fs.symlink(outside, memberPath);
            }
            quarantinedPath = to;
          }
          return await originalRename(from, to);
        };
        try {
          await assert.rejects(
            withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options)),
            /changed while it was quarantined|symbolic link/u
          );
        } finally {
          fs.rename = originalRename;
        }
        await assert.rejects(
          withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options)),
          /changed before recovery|symbolic link/u
        );
        await fs.lstat(quarantinedPath);
        assert.equal(await fs.readFile(outside, "utf8"), "surviving outside material");
      });
    }
  }
});

test("immutable sweep does not delete a candidate mutated after reauthentication", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-mutation-race");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "mutation-race" },
    payload: "original-mutation-race",
    stage: "mutation-race",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const payloadPath = join(artifactPath, artifact.entry.artifactFile);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const originalRename = fs.rename;
  fs.rename = async (from, to) => {
    if (from === artifactPath) {
      // Simulate a same-user writer changing the authenticated inode after planning but before
      // the quarantine rename. Restore mtime to exercise the nanosecond/ctime state binding.
      await fs.writeFile(payloadPath, "mutated-after-authentication", { mode: 0o600 });
      await fs.utimes(payloadPath, new Date(0), new Date(0));
    }
    return await originalRename(from, to);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: 2_000_000_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /candidate changed while it was quarantined/u
    );
  } finally {
    fs.rename = originalRename;
  }
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
  const trashRoot = join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash");
  const planRoots = await fs.readdir(trashRoot);
  assert.equal(planRoots.length, 1);
  const quarantineRoot = join(
    trashRoot,
    planRoots[0],
    (await fs.readdir(join(trashRoot, planRoots[0]))).find((name) => /^[0-9a-f]{64}$/u.test(name))
  );
  assert.equal(
    await fs.readFile(join(quarantineRoot, artifact.entry.artifactFile), "utf8"),
    "mutated-after-authentication"
  );

  // The failed post-rename verification left only an unverified marker. Recovery must reject the
  // changed tree rather than treating it as a partial removal and deleting it.
  await assert.rejects(
    withHeavyLock(value.environment, () =>
      sweepConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: 2_000_000_001,
        recentRetentionMilliseconds: 0,
      })
    ),
    /candidate changed before recovery/u
  );
  await fs.lstat(quarantineRoot);
});

test("immutable sweep recovers a partially removed quarantine root", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-partial-removal");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "partial-removal" },
    payload: "partial-removal",
    stage: "partial-removal",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const readdir = fs.readdir;
  let partialRemoval = true;
  fs.readdir = async (path, ...args) => {
    if (partialRemoval && await isVerifiedQuarantineRoot(path)) {
      partialRemoval = false;
      await fs.unlink(join(path, "entry.json"));
      throw Object.assign(new Error("synthetic partial immutable trash removal failure"), {
        code: "EIO",
      });
    }
    return await readdir(path, ...args);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /synthetic partial immutable trash removal failure/u
    );
  } finally {
    fs.readdir = readdir;
  }

  const retry = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(retry.recovered.length, 1);
  assert.equal(retry.recovered[0].status, "removed-quarantined-root");
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweep recovers a fully removed quarantine root", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-full-removal");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "full-removal" },
    payload: "full-removal",
    stage: "full-removal",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const rmdir = fs.rmdir;
  let fullRemoval = true;
  fs.rmdir = async (path, ...args) => {
    if (fullRemoval && path.includes("immutable-sweep-trash") && /^[0-9a-f]{64}$/u.test(path.split("/").at(-1))) {
      fullRemoval = false;
      await rmdir(path, ...args);
      throw Object.assign(new Error("synthetic full immutable trash removal failure"), {
        code: "EIO",
      });
    }
    return await rmdir(path, ...args);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /synthetic full immutable trash removal failure/u
    );
  } finally {
    fs.rmdir = rmdir;
  }

  const retry = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(retry.recovered.length, 1);
  assert.equal(retry.recovered[0].status, "cleared-completed-marker");
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweep waits for an active build lease to enter bounded recovery", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("active-lease-sweep");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "active-lease-candidate" },
    payload: "old-active-lease-candidate",
    stage: "active-lease-candidate-stage",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  await withHeavyLock(value.environment, async () => {
    await createConvexWasmBuildWorkLease({
      cacheLayout,
      environment: value.environment,
      nowMs: 0,
    });
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.sweepAuthorized, false);
  assert.deepEqual(report.immutable.sweep.removed, []);
  assert.deepEqual(report.immutable.sweep.blockedWorkRoots, [
    { buildId: "active-lease-sweep", status: "active" },
  ]);
  await fs.lstat(artifactPath);
});

test("immutable sweep reclaims artifacts while retaining a failed build work root", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("failed-lease-sweep");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "failed-lease-candidate" },
    payload: "old-failed-lease-candidate",
    stage: "failed-lease-candidate-stage",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout,
      environment: value.environment,
      nowMs: 0,
    });
    await lease.fail(0);
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: 2 * 24 * 60 * 60 * 1_000,
    })
  );

  assert.equal(report.immutable.sweepAuthorized, true);
  assert.deepEqual(
    report.immutable.sweep.removed.map(({ key }) => key),
    [artifact.key]
  );
  assert.deepEqual(report.immutable.sweep.blockedWorkRoots, []);
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
  await fs.lstat(cacheLayout.work.buildRoot);
});
