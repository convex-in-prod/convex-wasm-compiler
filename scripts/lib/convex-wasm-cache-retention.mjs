import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import {
  acquireConvexWasmCacheLock,
  inheritedConvexWasmCacheLockAuthorityEnvironment,
  requireConvexWasmCacheLockAuthority,
} from "./convex-wasm-cache-lock.mjs";
import {
  defaultConvexWasmCacheRoot,
  deriveConvexWasmCacheLayout,
  normalizeConvexWasmCacheLayout,
} from "./convex-wasm-cache-layout.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import { readPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import {
  planConvexWasmImmutableGc,
  sweepConvexWasmImmutableGc,
} from "./convex-wasm-cache-retention-immutable.mjs";

export const convexWasmBuildWorkRecordName = "build-work.json";
export const defaultConvexWasmWorkQuiescentMilliseconds = 24 * 60 * 60 * 1_000;
export const defaultConvexWasmAbandonedRecoveryMilliseconds = 7 * 24 * 60 * 60 * 1_000;
export const defaultConvexWasmFailedRecoveryMilliseconds = 7 * 24 * 60 * 60 * 1_000;
export const defaultConvexWasmCompletedRetentionMilliseconds = 24 * 60 * 60 * 1_000;
export const convexWasmRecentSuccessSnapshotLimit = 8;
export const convexWasmRecentSuccessSnapshotPackageLimit = 256;
export const convexWasmRecentSuccessSnapshotCompilerOutputLimit = 256;
export const convexWasmRecentSuccessSnapshotCertificateLimit = 8;
export const convexWasmCacheHighWatermarkEnvironmentName = "CONVEX_WASM_CACHE_HIGH_WATERMARK_BYTES";

const BUILD_WORK_RECORD_KIND = "convex-wasm-build-work-record-v1";
const RECENT_SUCCESS_SNAPSHOT_KIND = "convex-wasm-cache-recent-success-v1";
const BUILD_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_BUILD_WORK_RECORD_BYTES = 16 * 1_024;
const MAX_RECENT_SUCCESS_SNAPSHOT_BYTES = 64 * 1_024;

function fail(message) {
  throw new Error(`Convex Wasm cache retention: ${message}`);
}

function isMissing(error) {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

function requireNonNegativeSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a non-negative safe integer`);
  }
  return value;
}

function requirePositiveSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

export function convexWasmCacheHighWatermarkBytesFromEnvironment(environment = process.env) {
  const raw = environment[convexWasmCacheHighWatermarkEnvironmentName];
  if (raw === undefined || raw === "") {
    return undefined;
  }
  if (!/^[1-9][0-9]*$/u.test(raw)) {
    fail(`${convexWasmCacheHighWatermarkEnvironmentName} must be positive canonical bytes`);
  }
  return requirePositiveSafeInteger(Number(raw), convexWasmCacheHighWatermarkEnvironmentName);
}

function requireNormalizedCacheRoot(cacheRoot) {
  if (
    typeof cacheRoot !== "string" ||
    cacheRoot.length === 0 ||
    !isAbsolute(cacheRoot) ||
    resolve(cacheRoot) !== cacheRoot
  ) {
    fail("cache root must be a normalized absolute path");
  }
  return cacheRoot;
}

function requireBuildId(buildId) {
  if (typeof buildId !== "string" || !BUILD_ID_PATTERN.test(buildId)) {
    fail("build ID must contain 1-128 letters, digits, dots, underscores, or hyphens");
  }
  return buildId;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a SHA-256`);
  }
  return value;
}

function sortedUniqueSha256s(values, description, limit) {
  if (!Array.isArray(values) || values.length > limit) {
    fail(`${description} must contain at most ${String(limit)} SHA-256 values`);
  }
  const normalized = values.map((value) => requireSha256(value, description)).sort(compareStrings);
  if (new Set(normalized).size !== normalized.length) {
    fail(`${description} must not contain duplicate SHA-256 values`);
  }
  return normalized;
}

function buildIdFromLayout(cacheLayout) {
  const prefix = `${cacheLayout.work.root}/`;
  if (!cacheLayout.work.buildRoot.startsWith(prefix)) {
    fail("build root is outside the work root");
  }
  return requireBuildId(cacheLayout.work.buildRoot.slice(prefix.length));
}

function processOwner(pid) {
  return { kind: "process", pid: requirePositiveSafeInteger(pid, "build owner PID") };
}

function legacyOwner() {
  return { kind: "untracked-legacy" };
}

function validateOwner(owner) {
  if (typeof owner !== "object" || owner === null || Array.isArray(owner)) {
    fail("build work record owner must be an object");
  }
  if (owner.kind === "process") {
    if (Object.keys(owner).sort().join(",") !== "kind,pid") {
      fail("process build work record owner has unexpected fields");
    }
    return processOwner(owner.pid);
  }
  if (owner.kind === "untracked-legacy") {
    if (Object.keys(owner).join(",") !== "kind") {
      fail("legacy build work record owner has unexpected fields");
    }
    return legacyOwner();
  }
  fail("build work record owner kind is unsupported");
}

function activeRecord({ buildId, nowMs, owner, startedAtMs = nowMs }) {
  return {
    buildId: requireBuildId(buildId),
    kind: BUILD_WORK_RECORD_KIND,
    owner: validateOwner(owner),
    schemaVersion: 1,
    startedAtMs: requireNonNegativeSafeInteger(startedAtMs, "build start time"),
    status: "active",
    updatedAtMs: requireNonNegativeSafeInteger(nowMs, "build update time"),
  };
}

function completedRecord(record, nowMs) {
  return {
    ...record,
    outcome: {
      completedAtMs: requireNonNegativeSafeInteger(nowMs, "build completion time"),
      kind: "deployment-completed",
    },
    status: "completed",
    updatedAtMs: nowMs,
  };
}

function failedRecord(record, nowMs, failedRecoveryMilliseconds) {
  return {
    ...record,
    outcome: {
      failedAtMs: requireNonNegativeSafeInteger(nowMs, "build failure time"),
      kind: "deployment-failed",
      recoverableUntilMs: safeIntegerSum(
        nowMs,
        requirePositiveSafeInteger(failedRecoveryMilliseconds, "failed build recovery period"),
        "failed build recovery deadline"
      ),
    },
    status: "failed",
    updatedAtMs: nowMs,
  };
}

function boundLegacyFailedRecord(record, failedRecoveryMilliseconds) {
  const failedAtMs = requireNonNegativeSafeInteger(record.outcome.failedAtMs, "build failure time");
  return {
    ...record,
    outcome: {
      failedAtMs,
      kind: "deployment-failed",
      recoverableUntilMs: safeIntegerSum(
        failedAtMs,
        requirePositiveSafeInteger(failedRecoveryMilliseconds, "failed build recovery period"),
        "failed build recovery deadline"
      ),
    },
    status: "failed",
  };
}

function abandonedRecord(record, nowMs, abandonedRecoveryMilliseconds, previousStatus) {
  return {
    ...record,
    outcome: {
      abandonedAtMs: requireNonNegativeSafeInteger(nowMs, "build abandonment time"),
      kind: "quiescent-lock-abandonment",
      previousStatus,
      recoverableUntilMs: safeIntegerSum(
        nowMs,
        requireNonNegativeSafeInteger(
          abandonedRecoveryMilliseconds,
          "abandoned build recovery period"
        ),
        "abandoned build recovery deadline"
      ),
    },
    status: "abandoned",
    updatedAtMs: nowMs,
  };
}

function requireExactKeys(value, expected, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const keys = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(`${description} must contain exactly ${expectedKeys.join(", ")}`);
  }
}

function validateBuildWorkRecord(value, expectedBuildId) {
  const baseKeys = [
    "buildId",
    "kind",
    "owner",
    "schemaVersion",
    "startedAtMs",
    "status",
    "updatedAtMs",
  ];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("build work record must be an object");
  }
  const hasOutcome = value.status !== "active";
  requireExactKeys(value, hasOutcome ? [...baseKeys, "outcome"] : baseKeys, "build work record");
  if (
    value.kind !== BUILD_WORK_RECORD_KIND ||
    value.schemaVersion !== 1 ||
    requireBuildId(value.buildId) !== expectedBuildId
  ) {
    fail("build work record identity is invalid");
  }
  const record = {
    buildId: value.buildId,
    kind: BUILD_WORK_RECORD_KIND,
    owner: validateOwner(value.owner),
    schemaVersion: 1,
    startedAtMs: requireNonNegativeSafeInteger(value.startedAtMs, "build start time"),
    status: value.status,
    updatedAtMs: requireNonNegativeSafeInteger(value.updatedAtMs, "build update time"),
  };
  if (record.updatedAtMs < record.startedAtMs) {
    fail("build work record update time precedes its start time");
  }
  if (value.status === "active") return record;
  if (value.status === "completed") {
    requireExactKeys(value.outcome, ["completedAtMs", "kind"], "completed build outcome");
    if (value.outcome.kind !== "deployment-completed") {
      fail("completed build outcome kind is invalid");
    }
    const completedAtMs = requireNonNegativeSafeInteger(
      value.outcome.completedAtMs,
      "build completion time"
    );
    if (completedAtMs !== record.updatedAtMs) {
      fail("build completion time must match the record update time");
    }
    return {
      ...record,
      outcome: {
        completedAtMs,
        kind: "deployment-completed",
      },
    };
  }
  if (value.status === "failed") {
    const outcomeKeys = Object.keys(value.outcome).sort().join(",");
    const legacyOutcome = outcomeKeys === "failedAtMs,kind,recoverable";
    if (outcomeKeys !== "failedAtMs,kind,recoverableUntilMs" && !legacyOutcome) {
      fail("failed build outcome fields are invalid");
    }
    if (
      value.outcome.kind !== "deployment-failed" ||
      (legacyOutcome && value.outcome.recoverable !== true)
    ) {
      fail("failed build outcome is invalid");
    }
    const failedAtMs = requireNonNegativeSafeInteger(
      value.outcome.failedAtMs,
      "build failure time"
    );
    if (failedAtMs !== record.updatedAtMs) {
      fail("build failure time must match the record update time");
    }
    if (legacyOutcome) {
      return {
        ...record,
        outcome: {
          failedAtMs,
          kind: "deployment-failed",
          recoverable: true,
        },
      };
    }
    const recoverableUntilMs = requireNonNegativeSafeInteger(
      value.outcome.recoverableUntilMs,
      "failed build recovery deadline"
    );
    if (recoverableUntilMs < failedAtMs) {
      fail("failed build recovery deadline precedes failure");
    }
    return {
      ...record,
      outcome: {
        failedAtMs,
        kind: "deployment-failed",
        recoverableUntilMs,
      },
    };
  }
  if (value.status === "abandoned") {
    requireExactKeys(
      value.outcome,
      ["abandonedAtMs", "kind", "previousStatus", "recoverableUntilMs"],
      "abandoned build outcome"
    );
    if (
      value.outcome.kind !== "quiescent-lock-abandonment" ||
      (value.outcome.previousStatus !== "active" && value.outcome.previousStatus !== "legacy")
    ) {
      fail("abandoned build outcome is invalid");
    }
    const abandonedAtMs = requireNonNegativeSafeInteger(
      value.outcome.abandonedAtMs,
      "build abandonment time"
    );
    const recoverableUntilMs = requireNonNegativeSafeInteger(
      value.outcome.recoverableUntilMs,
      "abandoned build recovery deadline"
    );
    if (recoverableUntilMs < abandonedAtMs) {
      fail("abandoned build recovery deadline precedes abandonment");
    }
    if (abandonedAtMs !== record.updatedAtMs) {
      fail("build abandonment time must match the record update time");
    }
    return {
      ...record,
      outcome: {
        abandonedAtMs,
        kind: "quiescent-lock-abandonment",
        previousStatus: value.outcome.previousStatus,
        recoverableUntilMs,
      },
    };
  }
  fail("build work record status is unsupported");
}

function buildWorkRecordPath(buildRoot) {
  return join(buildRoot, convexWasmBuildWorkRecordName);
}

async function writeBuildWorkRecord(cacheRoot, buildRoot, record, { exclusive = false } = {}) {
  const path = buildWorkRecordPath(buildRoot);
  const bytes = Buffer.from(`${JSON.stringify(record)}\n`);
  if (bytes.length > MAX_BUILD_WORK_RECORD_BYTES) {
    fail("build work record exceeds its size limit");
  }
  if (exclusive) {
    await fs.writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    await requirePrivateCacheFile(cacheRoot, path);
    return;
  }
  const temporaryPath = join(
    buildRoot,
    `.${convexWasmBuildWorkRecordName}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`
  );
  try {
    await fs.writeFile(temporaryPath, bytes, { flag: "wx", mode: 0o600 });
    await requirePrivateCacheFile(cacheRoot, temporaryPath);
    await fs.rename(temporaryPath, path);
    await requirePrivateCacheFile(cacheRoot, path);
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
}

async function readBuildWorkRecord(cacheRoot, buildRoot, buildId) {
  const path = buildWorkRecordPath(buildRoot);
  try {
    await requirePrivateCacheFile(cacheRoot, path);
    const bytes = await fs.readFile(path);
    if (bytes.length > MAX_BUILD_WORK_RECORD_BYTES) {
      fail("build work record exceeds its size limit");
    }
    return validateBuildWorkRecord(JSON.parse(bytes.toString("utf8")), buildId);
  } catch (error) {
    if (isMissing(error)) return undefined;
    throw error;
  }
}

export async function createConvexWasmBuildWorkLease({
  cacheLayout: layout,
  environment = process.env,
  nowMs = Date.now(),
}) {
  requireConvexWasmCacheLockAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(layout);
  const buildId = buildIdFromLayout(cacheLayout);
  const failedRecoveryMilliseconds = millisecondsFromEnvironment(
    environment,
    "CONVEX_WASM_FAILED_WORK_RECOVERY_MILLISECONDS",
    defaultConvexWasmFailedRecoveryMilliseconds
  );
  const normalizedNowMs = requireNonNegativeSafeInteger(nowMs, "build lease start time");
  await fs.mkdir(cacheLayout.work.root, { mode: 0o700, recursive: true });
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, cacheLayout.work.root);
  await fs.mkdir(cacheLayout.work.buildRoot, { mode: 0o700 });
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, cacheLayout.work.buildRoot);
  // The active record is a lease bound to the repository-wide cache lock. It needs no
  // heartbeat because maintenance refuses inherited authority and must acquire that lock at its
  // top-level boundary before it can classify an old active record as interrupted.
  const initialRecord = activeRecord({
    buildId,
    nowMs: normalizedNowMs,
    owner: processOwner(process.pid),
  });
  await writeBuildWorkRecord(cacheLayout.cacheRoot, cacheLayout.work.buildRoot, initialRecord, {
    exclusive: true,
  });
  let state = initialRecord;

  const transition = async (nextRecord) => {
    const current = await readBuildWorkRecord(
      cacheLayout.cacheRoot,
      cacheLayout.work.buildRoot,
      buildId
    );
    if (current === undefined || JSON.stringify(current) !== JSON.stringify(state)) {
      fail(`build work record changed during deployment: ${buildId}`);
    }
    await writeBuildWorkRecord(cacheLayout.cacheRoot, cacheLayout.work.buildRoot, nextRecord);
    state = nextRecord;
  };

  return Object.freeze({
    buildId,
    buildRoot: cacheLayout.work.buildRoot,
    async complete(completedAtMs = Date.now()) {
      requireConvexWasmCacheLockAuthority(environment);
      if (state.status !== "active") {
        fail(`cannot complete build work in ${state.status} state`);
      }
      await transition(
        completedRecord(
          state,
          requireNonNegativeSafeInteger(completedAtMs, "build completion time")
        )
      );
      await fs.rm(cacheLayout.work.buildRoot, { recursive: true });
    },
    async fail(failedAtMs = Date.now()) {
      requireConvexWasmCacheLockAuthority(environment);
      // Publication may have succeeded before removal of its completed work root failed. Preserve
      // that completed state so maintenance can remove it after the normal recovery interval.
      if (state.status === "completed") return;
      if (state.status !== "active") {
        fail(`cannot fail build work in ${state.status} state`);
      }
      await transition(
        failedRecord(
          state,
          requireNonNegativeSafeInteger(failedAtMs, "build failure time"),
          failedRecoveryMilliseconds
        )
      );
    },
  });
}

function safeIntegerSum(left, right, description) {
  const value = left + right;
  if (!Number.isSafeInteger(value)) fail(`${description} exceeds the safe integer range`);
  return value;
}

function millisecondsFromEnvironment(environment, name, fallback) {
  const raw = environment[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^[1-9][0-9]*$/u.test(raw)) {
    fail(`${name} must be a positive integer number of milliseconds`);
  }
  return requirePositiveSafeInteger(Number(raw), name);
}

export function convexWasmRecentSuccessSnapshotRoot(cacheRoot) {
  return join(
    requireNormalizedCacheRoot(cacheRoot),
    "state",
    "v1",
    "cache-retention",
    "v1",
    "recent-success"
  );
}

function successfulDeploymentSnapshot({ buildId, deployment, recordedAtMs }) {
  if (typeof deployment !== "object" || deployment === null || Array.isArray(deployment)) {
    fail("successful deployment must be an object");
  }
  const manifest = deployment.manifest;
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    fail("successful deployment manifest must be an object");
  }
  if (
    typeof manifest.deploymentSha256 !== "string" ||
    !SHA256_PATTERN.test(manifest.deploymentSha256)
  ) {
    fail("successful deployment SHA-256 is invalid");
  }
  const { deploymentSha256: ignoredDeploymentSha256, ...manifestPayload } = manifest;
  if (fingerprintJson(manifestPayload) !== manifest.deploymentSha256) {
    fail("successful deployment SHA-256 does not authenticate its manifest");
  }
  const cohorts = manifest.moduleGraphBinding?.cohorts;
  if (!Array.isArray(cohorts) || cohorts.length === 0) {
    fail("successful deployment has no module graph package binding");
  }
  const packageKeys = cohorts
    .map((cohort) => cohort?.graphManifestSha256)
    .map((key) => requireSha256(key, "successful deployment module graph package key"));
  const normalizedPackageKeys = sortedUniqueSha256s(
    packageKeys,
    "successful deployment module graph package keys",
    convexWasmRecentSuccessSnapshotPackageLimit
  );
  const buildReport = deployment.buildReport;
  if (
    buildReport !== undefined &&
    (typeof buildReport !== "object" || buildReport === null || Array.isArray(buildReport))
  ) {
    fail("successful deployment build report must be an object");
  }
  const certificateSha256s = [];
  const certificateSha256 = buildReport?.cache?.certificateSha256;
  if (certificateSha256 !== undefined) {
    certificateSha256s.push(
      requireSha256(certificateSha256, "successful deployment result certificate SHA-256")
    );
  }
  const compilerOutputKeys = [];
  const artifactReports = buildReport?.artifacts;
  if (artifactReports !== undefined) {
    if (
      !Array.isArray(artifactReports) ||
      artifactReports.length > convexWasmRecentSuccessSnapshotCompilerOutputLimit
    ) {
      fail("successful deployment compiler artifact reports exceed their bound");
    }
    for (const artifactReport of artifactReports) {
      if (
        typeof artifactReport !== "object" ||
        artifactReport === null ||
        Array.isArray(artifactReport)
      ) {
        fail("successful deployment compiler artifact report must be an object");
      }
      const compilerOutputCache = artifactReport.buildReport?.compilerOutputCache;
      if (compilerOutputCache === undefined) continue;
      if (
        typeof compilerOutputCache !== "object" ||
        compilerOutputCache === null ||
        Array.isArray(compilerOutputCache)
      ) {
        fail("successful deployment compiler-output cache report must be an object");
      }
      compilerOutputKeys.push(
        requireSha256(
          compilerOutputCache.cacheKey,
          "successful deployment compiler-output cache key"
        )
      );
    }
  }
  const payload = {
    buildId: requireBuildId(buildId),
    certificateSha256s: sortedUniqueSha256s(
      certificateSha256s,
      "successful deployment result certificate SHA-256 values",
      convexWasmRecentSuccessSnapshotCertificateLimit
    ),
    compilerOutputKeys: sortedUniqueSha256s(
      compilerOutputKeys,
      "successful deployment compiler-output cache keys",
      convexWasmRecentSuccessSnapshotCompilerOutputLimit
    ),
    deploymentSha256: manifest.deploymentSha256,
    kind: RECENT_SUCCESS_SNAPSHOT_KIND,
    packageKeys: normalizedPackageKeys,
    recordedAtMs: requireNonNegativeSafeInteger(recordedAtMs, "successful deployment time"),
    schemaVersion: 2,
  };
  return { ...payload, snapshotSha256: fingerprintJson(payload) };
}

export async function recordConvexWasmSuccessfulCacheUse({
  buildId,
  cacheLayout: layout,
  deployment,
  environment = process.env,
  recordedAtMs = Date.now(),
}) {
  requireConvexWasmCacheLockAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(layout);
  const snapshot = successfulDeploymentSnapshot({ buildId, deployment, recordedAtMs });
  const root = convexWasmRecentSuccessSnapshotRoot(cacheLayout.cacheRoot);
  // Do not recursively create this authority path: a pre-existing state ancestor symlink would
  // otherwise make fs.mkdir populate an outside tree before private-cache validation rejects it.
  await fs.mkdir(cacheLayout.cacheRoot, { mode: 0o700, recursive: true });
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, cacheLayout.cacheRoot);
  for (const directory of [
    join(cacheLayout.cacheRoot, "state"),
    join(cacheLayout.cacheRoot, "state", "v1"),
    join(cacheLayout.cacheRoot, "state", "v1", "cache-retention"),
    join(cacheLayout.cacheRoot, "state", "v1", "cache-retention", "v1"),
    root,
  ]) {
    try {
      await fs.mkdir(directory, { mode: 0o700 });
    } catch (error) {
      if (!(error instanceof Error) || error.code !== "EEXIST") throw error;
    }
    await requirePrivateCacheDirectory(cacheLayout.cacheRoot, directory);
  }
  const finalPath = join(root, `${snapshot.snapshotSha256}.json`);
  const temporaryPath = join(
    root,
    `.publish-${snapshot.snapshotSha256}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  try {
    await fs.writeFile(temporaryPath, `${canonicalJson(snapshot)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await requirePrivateCacheFile(cacheLayout.cacheRoot, temporaryPath);
    try {
      await fs.rename(temporaryPath, finalPath);
    } catch (error) {
      if (!(error instanceof Error) || error.code !== "EEXIST") throw error;
    }
    await requirePrivateCacheFile(cacheLayout.cacheRoot, finalPath);
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
  const names = (await fs.readdir(root)).sort(compareStrings);
  const snapshots = [];
  for (const name of names) {
    if (!/^[0-9a-f]{64}\.json$/u.test(name)) continue;
    const path = join(root, name);
    await requirePrivateCacheFile(cacheLayout.cacheRoot, path);
    const snapshotStatus = await fs.lstat(path);
    if (snapshotStatus.size > MAX_RECENT_SUCCESS_SNAPSHOT_BYTES) continue;
    const bytes = await readPrivateRegularFile(
      path,
      MAX_RECENT_SUCCESS_SNAPSHOT_BYTES,
      "recent-success snapshot"
    );
    try {
      const source = bytes.toString("utf8");
      const value = JSON.parse(source);
      if (
        `${canonicalJson(value)}\n` === source &&
        value.kind === RECENT_SUCCESS_SNAPSHOT_KIND &&
        (value.schemaVersion === 1 || value.schemaVersion === 2) &&
        value.snapshotSha256 === name.slice(0, -5) &&
        fingerprintJson(
          Object.fromEntries(Object.entries(value).filter(([key]) => key !== "snapshotSha256"))
        ) === value.snapshotSha256 &&
        Number.isSafeInteger(value.recordedAtMs) &&
        value.recordedAtMs >= 0
      ) {
        snapshots.push({ name, recordedAtMs: value.recordedAtMs });
      }
    } catch {
      // Invalid authority files are retained so immutable GC can fail closed on them.
    }
  }
  snapshots.sort(
    (left, right) => right.recordedAtMs - left.recordedAtMs || compareStrings(right.name, left.name)
  );
  await Promise.all(
    snapshots.slice(convexWasmRecentSuccessSnapshotLimit).map(async ({ name }) => {
      const path = join(root, name);
      await requirePrivateCacheFile(cacheLayout.cacheRoot, path);
      await fs.unlink(path);
    })
  );
  return snapshot;
}

export async function measureConvexWasmCacheOccupancy(path) {
  const root = resolve(path);
  const occupancy = {
    allocatedBytes: 0,
    directoryCount: 0,
    entryCount: 0,
    hardLinkedRegularFileReferences: 0,
    logicalRegularFileBytes: 0,
    regularFileCount: 0,
    symbolicLinkCount: 0,
    uniqueAllocatedBytes: 0,
    uniqueInodeCount: 0,
  };
  let rootStatus;
  try {
    rootStatus = await fs.lstat(root);
  } catch (error) {
    if (isMissing(error)) return occupancy;
    throw error;
  }
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) {
    fail(`occupancy root must be a non-symlink directory: ${root}`);
  }
  const pending = [root];
  const seenInodes = new Set();
  while (pending.length !== 0) {
    const current = pending.pop();
    const names = await fs.readdir(current);
    names.sort();
    for (const name of names) {
      const entryPath = join(current, name);
      const status = await fs.lstat(entryPath);
      occupancy.entryCount += 1;
      const allocatedBytes = safeIntegerSum(0, status.blocks * 512, "cache allocated byte count");
      occupancy.allocatedBytes = safeIntegerSum(
        occupancy.allocatedBytes,
        allocatedBytes,
        "cache allocated byte count"
      );
      const inodeKey = `${String(status.dev)}:${String(status.ino)}`;
      if (!seenInodes.has(inodeKey)) {
        seenInodes.add(inodeKey);
        occupancy.uniqueAllocatedBytes = safeIntegerSum(
          occupancy.uniqueAllocatedBytes,
          allocatedBytes,
          "unique cache allocated byte count"
        );
      }
      if (status.isDirectory() && !status.isSymbolicLink()) {
        occupancy.directoryCount += 1;
        pending.push(entryPath);
      } else if (status.isFile()) {
        occupancy.regularFileCount += 1;
        occupancy.logicalRegularFileBytes = safeIntegerSum(
          occupancy.logicalRegularFileBytes,
          status.size,
          "logical cache file byte count"
        );
        if (status.nlink > 1) occupancy.hardLinkedRegularFileReferences += 1;
      } else if (status.isSymbolicLink()) {
        occupancy.symbolicLinkCount += 1;
      }
    }
  }
  occupancy.uniqueInodeCount = seenInodes.size;
  return occupancy;
}

async function pathExists(path) {
  try {
    await fs.lstat(path);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw error;
  }
}

function immutableRootMarkers(cacheRoot) {
  const immutableRoot = join(cacheRoot, "immutable", "v6");
  const packagesRoot = join(immutableRoot, "packages");
  return [
    {
      authentication: "not-performed",
      kind: "immutable-artifact-object-store",
      path: join(immutableRoot, "artifacts"),
      retentionRole: "transitive-object-candidate",
    },
    {
      authentication: "not-performed",
      kind: "immutable-package-root",
      path: packagesRoot,
      retentionRole: "retained-root-candidate",
    },
    {
      authentication: "not-performed",
      kind: "deployment-result-certificate-root",
      path: join(packagesRoot, "deployment-results", "v1"),
      retentionRole: "retained-root-candidate",
    },
  ];
}

async function inspectWorkRoot({
  abandonedRecoveryMilliseconds,
  apply,
  cacheRoot,
  completedRetentionMilliseconds,
  failedRecoveryMilliseconds,
  nowMs,
  quiescentMilliseconds,
}) {
  const workRoot = join(cacheRoot, "work", "v1");
  if (!(await pathExists(workRoot))) return [];
  await requirePrivateCacheDirectory(cacheRoot, workRoot);
  const entries = await fs.readdir(workRoot, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name));
  const results = [];
  for (const entry of entries) {
    const buildId = entry.name;
    const buildRoot = join(workRoot, buildId);
    if (!BUILD_ID_PATTERN.test(buildId) || !entry.isDirectory() || entry.isSymbolicLink()) {
      results.push({ action: "retain", buildId, reason: "unsafe-work-root", status: "invalid" });
      continue;
    }
    try {
      await requirePrivateCacheDirectory(cacheRoot, buildRoot);
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      results.push({
        action: "retain",
        buildId,
        reason: "invalid-private-work-root",
        status: "invalid",
      });
      continue;
    }
    const rootStatus = await fs.lstat(buildRoot);
    let record;
    try {
      record = await readBuildWorkRecord(cacheRoot, buildRoot, buildId);
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      results.push({
        action: "retain",
        buildId,
        reason: "invalid-build-work-record",
        status: "invalid",
      });
      continue;
    }
    if (record === undefined) {
      const lastObservedAtMs = Math.floor(rootStatus.mtimeMs);
      if (lastObservedAtMs > nowMs || nowMs - lastObservedAtMs < quiescentMilliseconds) {
        results.push({
          action: "retain",
          buildId,
          lastObservedAtMs,
          reason: "legacy-root-not-yet-quiescent",
          status: "legacy",
        });
        continue;
      }
      const nextRecord = abandonedRecord(
        activeRecord({
          buildId,
          nowMs: lastObservedAtMs,
          owner: legacyOwner(),
          startedAtMs: lastObservedAtMs,
        }),
        nowMs,
        abandonedRecoveryMilliseconds,
        "legacy"
      );
      if (apply) await writeBuildWorkRecord(cacheRoot, buildRoot, nextRecord, { exclusive: true });
      results.push({
        action: "mark-abandoned",
        buildId,
        reason: "legacy-root-observed-under-quiescent-heavy-lock",
        recoverableUntilMs: nextRecord.outcome.recoverableUntilMs,
        status: "legacy",
      });
      continue;
    }
    if (record.updatedAtMs > nowMs) {
      results.push({
        action: "retain",
        buildId,
        reason: "build-work-record-is-from-the-future",
        status: "invalid",
      });
      continue;
    }
    if (record.status === "failed") {
      if (record.outcome.recoverable === true) {
        const nextRecord = boundLegacyFailedRecord(record, failedRecoveryMilliseconds);
        if (apply) await writeBuildWorkRecord(cacheRoot, buildRoot, nextRecord);
        results.push({
          action: "set-recovery-deadline",
          buildId,
          reason: "legacy-failed-build-recovery-bounded-under-heavy-lock",
          recoverableUntilMs: nextRecord.outcome.recoverableUntilMs,
          status: "failed",
        });
        continue;
      }
      if (nowMs < record.outcome.recoverableUntilMs) {
        results.push({
          action: "retain",
          buildId,
          reason: "failed-build-recovery-window-open",
          recoverableUntilMs: record.outcome.recoverableUntilMs,
          status: "failed",
        });
        continue;
      }
    }
    if (record.status === "active") {
      if (nowMs - record.updatedAtMs < quiescentMilliseconds) {
        results.push({
          action: "retain",
          buildId,
          reason: "active-lease-not-yet-quiescent",
          status: "active",
        });
        continue;
      }
      const nextRecord = abandonedRecord(record, nowMs, abandonedRecoveryMilliseconds, "active");
      if (apply) await writeBuildWorkRecord(cacheRoot, buildRoot, nextRecord);
      results.push({
        action: "mark-abandoned",
        buildId,
        reason: "active-lease-ended-before-completion-under-quiescent-heavy-lock",
        recoverableUntilMs: nextRecord.outcome.recoverableUntilMs,
        status: "active",
      });
      continue;
    }
    const removable =
      record.status === "failed" || record.status === "abandoned"
        ? nowMs >= record.outcome.recoverableUntilMs
        : nowMs - record.updatedAtMs >= completedRetentionMilliseconds;
    if (!removable) {
      results.push({
        action: "retain",
        buildId,
        reason:
          record.status === "failed"
            ? "failed-build-recovery-window-open"
            : record.status === "abandoned"
              ? "abandoned-build-recovery-window-open"
              : "completed-build-retention-window-open",
        status: record.status,
      });
      continue;
    }
    if (apply) {
      await requirePrivateCacheDirectory(cacheRoot, buildRoot);
      const current = await readBuildWorkRecord(cacheRoot, buildRoot, buildId);
      if (current === undefined || JSON.stringify(current) !== JSON.stringify(record)) {
        fail(`build work record changed before removal: ${buildId}`);
      }
      await fs.rm(buildRoot, { recursive: true });
    }
    results.push({
      action: "remove",
      buildId,
      reason:
        record.status === "failed"
          ? "failed-build-recovery-window-expired"
          : record.status === "abandoned"
            ? "abandoned-build-recovery-window-expired"
            : "completed-build-retention-window-expired",
      status: record.status,
    });
  }
  return results;
}

function workSummary(roots) {
  const summary = {
    active: 0,
    abandoned: 0,
    completed: 0,
    failed: 0,
    invalid: 0,
    legacy: 0,
    markAbandoned: 0,
    remove: 0,
    retain: 0,
    setRecoveryDeadline: 0,
    total: roots.length,
  };
  for (const root of roots) {
    summary[root.status] += 1;
    if (root.action === "mark-abandoned") summary.markAbandoned += 1;
    else if (root.action === "set-recovery-deadline") summary.setRecoveryDeadline += 1;
    else summary[root.action] += 1;
  }
  return summary;
}

export async function maintainConvexWasmCache({
  abandonedRecoveryMilliseconds = defaultConvexWasmAbandonedRecoveryMilliseconds,
  apply = false,
  automaticImmutableSweep = false,
  cacheRoot = defaultConvexWasmCacheRoot(),
  completedRetentionMilliseconds = defaultConvexWasmCompletedRetentionMilliseconds,
  environment = process.env,
  failedRecoveryMilliseconds = defaultConvexWasmFailedRecoveryMilliseconds,
  immutableHighWatermarkAllocatedBytes,
  immutablePlanOutput,
  immutableSweep = false,
  includeImmutableOccupancy = true,
  nowMs,
  quiescentMilliseconds = defaultConvexWasmWorkQuiescentMilliseconds,
} = {}) {
  const normalizedCacheRoot = requireNormalizedCacheRoot(cacheRoot);
  const suppliedNowMs =
    nowMs === undefined ? undefined : requireNonNegativeSafeInteger(nowMs, "maintenance time");
  const normalizedImmutableHighWatermarkAllocatedBytes =
    immutableHighWatermarkAllocatedBytes ??
    convexWasmCacheHighWatermarkBytesFromEnvironment(environment);
  requireNonNegativeSafeInteger(abandonedRecoveryMilliseconds, "abandoned build recovery period");
  requireNonNegativeSafeInteger(completedRetentionMilliseconds, "completed build retention period");
  requirePositiveSafeInteger(failedRecoveryMilliseconds, "failed build recovery period");
  if (normalizedImmutableHighWatermarkAllocatedBytes !== undefined) {
    requirePositiveSafeInteger(
      normalizedImmutableHighWatermarkAllocatedBytes,
      "immutable high watermark"
    );
  }
  requireNonNegativeSafeInteger(quiescentMilliseconds, "work quiescence period");
  if (
    immutablePlanOutput !== undefined &&
    (typeof immutablePlanOutput !== "string" ||
      immutablePlanOutput.length === 0 ||
      !isAbsolute(immutablePlanOutput) ||
      resolve(immutablePlanOutput) !== immutablePlanOutput)
  ) {
    fail("immutable plan output must be a normalized absolute path");
  }
  if (apply && immutablePlanOutput !== undefined) {
    fail("immutable GC plans require dry-run maintenance mode");
  }
  if (immutableSweep && !apply) {
    fail("immutable sweep requires apply mode");
  }
  if (
    typeof apply !== "boolean" ||
    typeof automaticImmutableSweep !== "boolean" ||
    typeof immutableSweep !== "boolean" ||
    typeof includeImmutableOccupancy !== "boolean"
  ) {
    fail(
      "apply, automatic immutable sweep, immutable sweep, and includeImmutableOccupancy must be booleans"
    );
  }
  if (automaticImmutableSweep && !apply) {
    fail("automatic immutable sweep requires apply mode");
  }
  if (
    (automaticImmutableSweep || immutableSweep) &&
    normalizedImmutableHighWatermarkAllocatedBytes === undefined
  ) {
    fail("immutable sweeping requires an explicit high watermark");
  }
  if (Object.keys(inheritedConvexWasmCacheLockAuthorityEnvironment(environment)).length !== 0) {
    fail("maintenance must acquire the top-level cache lock, not inherit build authority");
  }
  const releaseLock = await acquireConvexWasmCacheLock({ environment });
  try {
    requireConvexWasmCacheLockAuthority(environment);
    // The heavy lock can wait behind a build. Date automatic maintenance after that wait so newly
    // completed work records are not mistaken for future records and excluded from cleanup.
    const normalizedNowMs = suppliedNowMs ?? Date.now();
    const cacheExists = await pathExists(normalizedCacheRoot);
    if (cacheExists) await requirePrivateCacheDirectory(normalizedCacheRoot, normalizedCacheRoot);
    const cacheLayout = deriveConvexWasmCacheLayout({
      buildId: "maintenance",
      cacheRoot: normalizedCacheRoot,
      repositoryRoot: normalizedCacheRoot,
    });
    const occupancyRoot = includeImmutableOccupancy
      ? normalizedCacheRoot
      : join(normalizedCacheRoot, "work", "v1");
    // Finish both stable snapshots before an apply run starts removing work roots. Automatic
    // maintenance measures the immutable subtree separately so unrelated cache families cannot
    // trigger the expensive authenticated graph walk after every compilation.
    const [occupancy, immutableOccupancy] = await Promise.all([
      measureConvexWasmCacheOccupancy(occupancyRoot),
      automaticImmutableSweep
        ? measureConvexWasmCacheOccupancy(cacheLayout.immutable.root)
        : undefined,
    ]);
    const roots = await inspectWorkRoot({
      abandonedRecoveryMilliseconds,
      apply,
      cacheRoot: normalizedCacheRoot,
      completedRetentionMilliseconds,
      failedRecoveryMilliseconds,
      nowMs: normalizedNowMs,
      quiescentMilliseconds,
    });
    // A failed/completed build has no live owner of immutable entries. Its small work root stays
    // available for diagnosis, but must not pin the entire cache for its recovery window.
    const immutableSweepBlockers = roots.filter(
      ({ action, status }) => action !== "remove" && status !== "failed" && status !== "completed"
    );
    const automaticImmutableSweepTriggered =
      automaticImmutableSweep &&
      immutableOccupancy.uniqueAllocatedBytes > normalizedImmutableHighWatermarkAllocatedBytes;
    const immutableSweepRequested = immutableSweep || automaticImmutableSweepTriggered;
    const immutableGcOptions = {
      cacheLayout,
      environment,
      ...(normalizedImmutableHighWatermarkAllocatedBytes === undefined
        ? {}
        : { highWatermarkAllocatedBytes: normalizedImmutableHighWatermarkAllocatedBytes }),
      nowMs: normalizedNowMs,
    };
    const immutableSweepResult =
      immutableSweepRequested && immutableSweepBlockers.length === 0
        ? await sweepConvexWasmImmutableGc(immutableGcOptions)
        : undefined;
    const shouldPlanImmutableGc =
      immutablePlanOutput !== undefined ||
      (immutableSweepRequested && (immutableSweep || immutableSweepBlockers.length === 0));
    const immutablePlan =
      immutableSweepResult?.plan ??
      (shouldPlanImmutableGc
        ? await planConvexWasmImmutableGc({
            ...immutableGcOptions,
          })
        : undefined);
    if (immutablePlanOutput !== undefined) {
      await fs.mkdir(dirname(immutablePlanOutput), { mode: 0o700, recursive: true });
      await fs.writeFile(immutablePlanOutput, `${canonicalJson(immutablePlan)}\n`, {
        mode: 0o600,
      });
    }
    const rootMarkers = await Promise.all(
      immutableRootMarkers(normalizedCacheRoot).map(async (root) => ({
        ...root,
        exists: await pathExists(root.path),
      }))
    );
    return {
      cacheRoot: normalizedCacheRoot,
      immutable: {
        ...(automaticImmutableSweep
          ? {
              automaticSweep: {
                highWatermarkAllocatedBytes: normalizedImmutableHighWatermarkAllocatedBytes,
                occupancy: immutableOccupancy,
                triggered: automaticImmutableSweepTriggered,
              },
            }
          : {}),
        rootMarkers,
        sweepAuthorized: immutableSweepRequested && immutableSweepBlockers.length === 0,
        sweepBlocker:
          immutableSweepBlockers.length === 0
            ? immutableSweepRequested
              ? undefined
              : automaticImmutableSweep
                ? "immutable cache is at or below its high watermark"
                : "immutable cache deletion requires explicit immutable sweep mode"
            : "active or unresolved build work remains",
        ...(immutableSweepRequested
          ? {
              sweep: {
                blockedWorkRoots: immutableSweepBlockers.map(({ buildId, status }) => ({
                  buildId,
                  status,
                })),
                recovered: immutableSweepResult?.recovered ?? [],
                removed: immutableSweepResult?.removed ?? [],
                requested: true,
                trigger: immutableSweep ? "explicit" : "above-high-watermark",
                skipped: immutableSweepResult?.skipped ?? 0,
              },
            }
          : {}),
        ...(immutablePlan === undefined ? {} : { plan: immutablePlan }),
      },
      kind: "convex-wasm-cache-retention-report-v1",
      mode: apply ? "apply" : "dry-run",
      nowMs: normalizedNowMs,
      occupancy: {
        ...occupancy,
        scope: includeImmutableOccupancy ? "entire-cache" : "work-only",
      },
      work: {
        abandonedRecoveryMilliseconds,
        completedRetentionMilliseconds,
        failedRecoveryMilliseconds,
        quiescentMilliseconds,
        roots,
        summary: workSummary(roots),
      },
    };
  } finally {
    releaseLock();
  }
}
