import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { join, relative, sep } from "node:path";

import {
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  requireExactPlainObject,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import {
  createBoundedOperationRunner,
  decodeUtf8,
  fingerprintMaterialPaths,
  mapBounded,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";

export const convexWasmRuntimeHeaderSnapshotCacheEntryKind =
  "convex-wasm-runtime-header-snapshot-cache-entry-v1";
export const convexWasmRuntimeHeaderSnapshotCacheStage = "runtime-header-snapshot-v2";

const ARTIFACT_PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const IDENTITY_KIND = "convex-wasm-runtime-header-snapshot-identity-v1";
const LEGACY_CACHE_STAGE = "runtime-header-snapshot-v1";
const MAX_ENTRY_BYTES = 16 * 1024 * 1024;
const MAX_COMPLETION_MARKER_BYTES = 65;
const SNAPSHOT_MODE_NORMALIZATION_CONCURRENCY = 4;
const SNAPSHOT_STATE_READ_CONCURRENCY = 4;
const runtimeHeaderSnapshotCacheFlights = new Map();

async function settleConcurrentWork(promises) {
  const settlements = await Promise.allSettled(promises);
  const failure = settlements.find(({ status }) => status === "rejected");
  if (failure !== undefined) throw failure.reason;
  return settlements.map(({ value }) => value);
}

function dereferencedMaterialEntry(entry, description) {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    fail(`${description} must be an object`);
  }
  if (typeof entry.type !== "string") {
    fail(`${description}.type must be a string`);
  }
  let type = entry.type;
  while (type.startsWith("symbolic-link-to-")) {
    type = type.slice("symbolic-link-to-".length);
  }
  if (type !== "directory") {
    fail(`${description} must authenticate a directory`);
  }
  return { ...entry, type };
}

function normalizeRuntimeHeaderSnapshotIdentity(identity, description) {
  requireExactPlainObject(identity, ["includes", "kind"], description);
  if (identity.kind !== IDENTITY_KIND) {
    fail(`${description}.kind is invalid`);
  }
  if (!Array.isArray(identity.includes)) {
    fail(`${description}.includes must be an array`);
  }
  const includes = Object.freeze(
    identity.includes.map((entry, index) => {
      const entryDescription = `${description}.includes[${index}]`;
      requireExactPlainObject(
        entry,
        ["fileCount", "label", "sha256", "size", "type"],
        entryDescription
      );
      if (entry.label !== `runtime-include-directory-${index}`) {
        fail(`${entryDescription}.label is invalid`);
      }
      if (entry.type !== "directory") {
        fail(`${entryDescription}.type must be directory`);
      }
      requireSha256(entry.sha256, `${entryDescription}.sha256`);
      for (const field of ["fileCount", "size"]) {
        if (!Number.isSafeInteger(entry[field]) || entry[field] < 0) {
          fail(`${entryDescription}.${field} must be a non-negative safe integer`);
        }
      }
      return Object.freeze({ ...entry });
    })
  );
  return Object.freeze({ includes, kind: IDENTITY_KIND });
}

export function createConvexWasmRuntimeHeaderSnapshotIdentity({
  includeDirectories,
  runtimeHeaderMaterials,
}) {
  if (!Array.isArray(includeDirectories)) {
    fail("runtime header include directories must be an array");
  }
  includeDirectories.forEach((path, index) =>
    requireString(path, `runtime header include directories[${index}]`)
  );
  if (
    typeof runtimeHeaderMaterials !== "object" ||
    runtimeHeaderMaterials === null ||
    !Array.isArray(runtimeHeaderMaterials.entries)
  ) {
    fail("runtime header materials must contain authenticated entries");
  }
  const entriesByLabel = new Map();
  for (const entry of runtimeHeaderMaterials.entries) {
    if (typeof entry !== "object" || entry === null || typeof entry.label !== "string") {
      fail("runtime header materials contain an invalid entry");
    }
    if (entriesByLabel.has(entry.label)) {
      fail(`runtime header materials contain duplicate label ${entry.label}`);
    }
    entriesByLabel.set(entry.label, entry);
  }
  // Origin paths and unrelated runtime materials are deliberately absent. The authenticated,
  // ordered dereferenced include entries are the complete reusable-input identity.
  const includes = includeDirectories.map((_, index) => {
    const label = `runtime-include-directory-${index}`;
    const entry = entriesByLabel.get(label);
    if (entry === undefined) {
      fail(`runtime header materials have no ${label} entry`);
    }
    return dereferencedMaterialEntry(entry, `runtime header material ${label}`);
  });
  return normalizeRuntimeHeaderSnapshotIdentity(
    { includes, kind: IDENTITY_KIND },
    "runtime header snapshot identity"
  );
}

export function convexWasmRuntimeHeaderSnapshotCacheKey(identity) {
  return runtimeHeaderSnapshotCacheKeyForStage(identity, convexWasmRuntimeHeaderSnapshotCacheStage);
}

function runtimeHeaderSnapshotCacheKeyForStage(identity, stage) {
  const normalizedIdentity = normalizeRuntimeHeaderSnapshotIdentity(
    identity,
    "runtime header snapshot identity"
  );
  return fingerprintJson({
    identity: normalizedIdentity,
    kind: ARTIFACT_PIPELINE_KIND,
    stage,
  });
}

function snapshotCachePath(cacheLayout, key, stage = convexWasmRuntimeHeaderSnapshotCacheStage) {
  requireSha256(key, "runtime header snapshot cache key");
  return join(cacheLayout.immutable.artifacts, stage, key);
}

function filesystemState(path, status, type) {
  return {
    changeTimeNanoseconds: status.ctimeNs.toString(),
    device: status.dev.toString(),
    group: status.gid.toString(),
    inode: status.ino.toString(),
    mode: Number(status.mode & 0o7777n),
    modificationTimeNanoseconds: status.mtimeNs.toString(),
    owner: status.uid.toString(),
    path,
    size: status.size.toString(),
    type,
  };
}

function normalizeRuntimeHeaderSnapshotState(state, description) {
  if (!Array.isArray(state) || state.length === 0) {
    fail(`${description} must be a non-empty array`);
  }
  return Object.freeze(
    state.map((entry, index) => {
      const entryDescription = `${description}[${index}]`;
      requireExactPlainObject(
        entry,
        [
          "changeTimeNanoseconds",
          "device",
          "group",
          "inode",
          "mode",
          "modificationTimeNanoseconds",
          "owner",
          "path",
          "size",
          "type",
        ],
        entryDescription
      );
      for (const field of [
        "changeTimeNanoseconds",
        "device",
        "group",
        "inode",
        "modificationTimeNanoseconds",
        "owner",
        "size",
      ]) {
        requireString(entry[field], `${entryDescription}.${field}`);
      }
      if (typeof entry.path !== "string" || entry.path.includes("\0")) {
        fail(`${entryDescription}.path must be a string without NUL bytes`);
      }
      if (!Number.isSafeInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777) {
        fail(`${entryDescription}.mode must be a valid filesystem mode`);
      }
      if (entry.type !== "directory" && entry.type !== "file") {
        fail(`${entryDescription}.type must be directory or file`);
      }
      return Object.freeze({ ...entry });
    })
  );
}

function runtimeHeaderSnapshotStateWithoutChangeTimes(state) {
  return state.map((entry) => {
    const normalized = { ...entry };
    delete normalized.changeTimeNanoseconds;
    return normalized;
  });
}

function currentUserId() {
  if (typeof process.getuid !== "function") {
    fail("runtime header snapshot cache validation requires process.getuid()");
  }
  return BigInt(process.getuid());
}

export async function readConvexWasmRuntimeHeaderSnapshotState(inputRoot) {
  const uid = currentUserId();
  const run = createBoundedOperationRunner(SNAPSHOT_STATE_READ_CONCURRENCY);
  const walk = async (path) => {
    const relativePath = relative(inputRoot, path).split(sep).join("/");
    const before = await run(() => fs.lstat(path, { bigint: true }));
    if (before.isFile()) {
      if (before.uid !== uid || (before.mode & 0o7777n) !== 0o600n) {
        fail(`runtime header snapshot file is not private: ${path}`);
      }
      return [filesystemState(relativePath, before, "file")];
    }
    if (!before.isDirectory()) {
      fail(`runtime header snapshot contains an unsupported filesystem entry: ${path}`);
    }
    if (before.uid !== uid || (before.mode & 0o7777n) !== 0o700n) {
      fail(`runtime header snapshot directory is not private: ${path}`);
    }
    const children = await run(() => fs.readdir(path));
    children.sort(compareStrings);
    // A serial await per header repeatedly yields to concurrent cohort processing. Share one
    // filesystem bound across the tree, but retain sorted preorder and drain admitted subtrees
    // before returning or throwing. No permit is held while waiting for recursive children.
    const childEntries = await mapBounded(children, SNAPSHOT_STATE_READ_CONCURRENCY, (child) =>
      walk(join(path, child))
    );
    const after = await run(() => fs.lstat(path, { bigint: true }));
    if (
      canonicalJson(filesystemState(relativePath, before, "directory")) !==
      canonicalJson(filesystemState(relativePath, after, "directory"))
    ) {
      fail(`runtime header snapshot changed while its filesystem state was read: ${path}`);
    }
    return [filesystemState(relativePath, before, "directory"), ...childEntries.flat()];
  };
  const entries = await walk(inputRoot);
  return Object.freeze(entries.map((entry) => Object.freeze(entry)));
}

export async function verifyConvexWasmRuntimeHeaderSnapshotState(inputRoot, expectedState) {
  const normalizedExpectedState = normalizeRuntimeHeaderSnapshotState(
    expectedState,
    "runtime header snapshot state"
  );
  if (
    canonicalJson(await readConvexWasmRuntimeHeaderSnapshotState(inputRoot)) !==
    canonicalJson(normalizedExpectedState)
  ) {
    fail("runtime header snapshot does not match its authenticated material identity");
  }
}

async function readCanonicalEntry(path) {
  const source = decodeUtf8(
    await readPrivateRegularFile(path, MAX_ENTRY_BYTES, "runtime header snapshot cache entry"),
    "runtime header snapshot cache entry"
  );
  let entry;
  try {
    entry = JSON.parse(source);
  } catch (error) {
    throw new Error(`Convex Wasm artifact pipeline: runtime header snapshot entry is not JSON`, {
      cause: error,
    });
  }
  if (`${canonicalJson(entry)}\n` !== source) {
    fail("runtime header snapshot entry is not canonical JSON");
  }
  return entry;
}

function normalizeCacheEntry(entry, { expectedIdentity, key, stage }) {
  requireExactPlainObject(
    entry,
    stage === LEGACY_CACHE_STAGE
      ? ["identity", "key", "kind", "stage"]
      : ["identity", "key", "kind", "stage", "state"],
    "cache entry"
  );
  if (
    entry.kind !== convexWasmRuntimeHeaderSnapshotCacheEntryKind ||
    entry.stage !== stage ||
    entry.key !== key
  ) {
    fail("runtime header snapshot cache entry identity is invalid");
  }
  const identity = normalizeRuntimeHeaderSnapshotIdentity(
    entry.identity,
    "runtime header snapshot cache entry identity"
  );
  if (runtimeHeaderSnapshotCacheKeyForStage(identity, stage) !== key) {
    fail("runtime header snapshot cache entry identity does not match its key");
  }
  if (
    expectedIdentity !== undefined &&
    canonicalJson(identity) !== canonicalJson(expectedIdentity)
  ) {
    fail("runtime header snapshot cache entry has an unexpected identity");
  }
  const state =
    stage === LEGACY_CACHE_STAGE
      ? undefined
      : normalizeRuntimeHeaderSnapshotState(
          entry.state,
          "runtime header snapshot cache entry state"
        );
  return Object.freeze({
    identity,
    key,
    kind: convexWasmRuntimeHeaderSnapshotCacheEntryKind,
    stage,
    ...(state === undefined ? {} : { state }),
  });
}

function completionMarker(entry, stage) {
  return stage === LEGACY_CACHE_STAGE ? `${entry.key}\n` : `${fingerprintJson(entry)}\n`;
}

async function authenticateSnapshotInputs(inputRoot, identity, before) {
  const expectedNames = identity.includes.map((_, index) => `include-${index}`);
  const names = await fs.readdir(inputRoot);
  names.sort(compareStrings);
  if (canonicalJson(names) !== canonicalJson([...expectedNames].sort(compareStrings))) {
    fail("runtime header snapshot input root has unexpected contents");
  }
  const snapshotMaterials = await fingerprintMaterialPaths(
    identity.includes.map((entry, index) => ({
      label: entry.label,
      path: join(inputRoot, `include-${index}`),
    })),
    "runtime header snapshot"
  );
  const actualByLabel = new Map(snapshotMaterials.entries.map((entry) => [entry.label, entry]));
  const actual = identity.includes.map(({ label }) => actualByLabel.get(label));
  if (
    actual.some((entry) => entry === undefined) ||
    canonicalJson(actual) !== canonicalJson(identity.includes)
  ) {
    fail("runtime header snapshot does not match its authenticated material identity");
  }
  const after = await readConvexWasmRuntimeHeaderSnapshotState(inputRoot);
  if (canonicalJson(after) !== canonicalJson(before)) {
    fail("runtime header snapshot changed while it was authenticated");
  }
  return after;
}

export async function authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry({
  cacheLayout,
  expectedIdentity,
  key,
  stage = convexWasmRuntimeHeaderSnapshotCacheStage,
  path = snapshotCachePath(cacheLayout, key, stage),
}) {
  if (stage !== convexWasmRuntimeHeaderSnapshotCacheStage && stage !== LEGACY_CACHE_STAGE) {
    fail("runtime header snapshot cache stage is invalid");
  }
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, path);
  const beforeRoot = await fs.lstat(path, { bigint: true });
  const names = await fs.readdir(path);
  names.sort(compareStrings);
  if (canonicalJson(names) !== canonicalJson(["COMPLETE", "entry.json", "inputs"])) {
    fail("runtime header snapshot cache entry has unexpected contents");
  }
  const entryPath = join(path, "entry.json");
  const completePath = join(path, "COMPLETE");
  await settleConcurrentWork([
    requirePrivateCacheFile(cacheLayout.cacheRoot, entryPath),
    requirePrivateCacheFile(cacheLayout.cacheRoot, completePath),
  ]);
  const [rawEntry, complete] = await settleConcurrentWork([
    readCanonicalEntry(entryPath),
    readPrivateRegularFile(
      completePath,
      MAX_COMPLETION_MARKER_BYTES,
      "runtime header snapshot completion marker"
    ).then((bytes) => decodeUtf8(bytes, "runtime header snapshot completion marker")),
  ]);
  const entry = normalizeCacheEntry(rawEntry, { expectedIdentity, key, stage });
  if (complete !== completionMarker(rawEntry, stage)) {
    fail("runtime header snapshot completion marker is invalid");
  }
  const inputRoot = join(path, "inputs");
  const actualState = await readConvexWasmRuntimeHeaderSnapshotState(inputRoot);
  let state;
  if (entry.state === undefined) {
    // Retention still needs to authenticate entries written by the previous stage. Ordinary
    // compilation writes and loads only v2 entries.
    state = await authenticateSnapshotInputs(inputRoot, entry.identity, actualState);
  } else {
    if (canonicalJson(actualState) === canonicalJson(entry.state)) {
      state = entry.state;
    } else if (
      canonicalJson(runtimeHeaderSnapshotStateWithoutChangeTimes(actualState)) ===
      canonicalJson(runtimeHeaderSnapshotStateWithoutChangeTimes(entry.state))
    ) {
      // chmod advances ctime even when the requested mode already matches. A ctime-only mismatch
      // cannot identify that harmless operation by itself, so authenticate every path and byte
      // before replacing the stale persisted state with process-private current authority.
      // Keep the recovery-selection scan as the pre-hash fence: a fresh baseline here could
      // admit an intervening inode or mtime change merely because the bytes still match.
      state = await authenticateSnapshotInputs(inputRoot, entry.identity, actualState);
    } else {
      fail("runtime header snapshot does not match its authenticated material identity");
    }
  }
  const afterRoot = await fs.lstat(path, { bigint: true });
  if (
    canonicalJson(filesystemState("", afterRoot, "directory")) !==
    canonicalJson(filesystemState("", beforeRoot, "directory"))
  ) {
    fail("runtime header snapshot cache entry changed while it was authenticated");
  }
  return Object.freeze({
    entry,
    identity: entry.identity,
    inputRoot,
    key,
    path,
    stage,
    state,
  });
}

async function loadRuntimeHeaderSnapshotCacheEntry(options) {
  const path = snapshotCachePath(options.cacheLayout, options.key);
  try {
    const status = await fs.lstat(path);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      fail(`runtime header snapshot cache entry is not a non-symlink directory: ${path}`);
    }
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  return await authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry({ ...options, path });
}

async function normalizeSnapshotTreeModes(path) {
  const pending = [path];
  let nextIndex = 0;
  // The header tree contains thousands of entries. Keep lstat/readdir/chmod fanout bounded instead
  // of recursively queueing one filesystem operation and Promise per descendant at once.
  while (nextIndex < pending.length) {
    const paths = pending.slice(nextIndex, nextIndex + SNAPSHOT_MODE_NORMALIZATION_CONCURRENCY);
    nextIndex += paths.length;
    const entries = await settleConcurrentWork(
      paths.map(async (entryPath) => {
        const status = await fs.lstat(entryPath);
        let mode;
        if (status.isFile()) {
          mode = 0o600;
        } else if (status.isDirectory()) {
          mode = 0o700;
        } else {
          fail(`runtime header snapshot contains an unsupported filesystem entry: ${entryPath}`);
        }
        const children = status.isDirectory() ? await fs.readdir(entryPath) : [];
        children.sort(compareStrings);
        return {
          children: children.map((entry) => join(entryPath, entry)),
          mode: (status.mode & 0o7777) === mode ? undefined : mode,
          path: entryPath,
        };
      })
    );
    // A redundant chmod changes ctime even though the admitted bytes and mode remain identical.
    await settleConcurrentWork(
      entries
        .filter((entry) => entry.mode !== undefined)
        .map((entry) => fs.chmod(entry.path, entry.mode))
    );
    for (const entry of entries) pending.push(...entry.children);
  }
}

export async function copyConvexWasmRuntimeHeaderIncludes(inputRoot, includeDirectories) {
  await settleConcurrentWork(
    includeDirectories.map(async (sourcePath, index) => {
      const resolvedSource = await fs.realpath(sourcePath);
      await fs.cp(resolvedSource, join(inputRoot, `include-${index}`), {
        // Admission already dereferences the top-level path and rejects nested symlinks. Preserve
        // a newly introduced nested link so snapshot normalization or the per-work post-compile
        // origin check observes it without first copying an unadmitted target tree.
        dereference: false,
        errorOnExist: true,
        force: false,
        recursive: true,
      });
    })
  );
}

async function createRuntimeHeaderSnapshotCacheEntry({
  cacheLayout,
  identity,
  includeDirectories,
  key,
}) {
  const stageRoot = join(
    cacheLayout.immutable.artifacts,
    convexWasmRuntimeHeaderSnapshotCacheStage
  );
  const publicationPath = join(
    stageRoot,
    `.publish-${key}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  await fs.mkdir(publicationPath, { mode: 0o700 });
  try {
    const inputRoot = join(publicationPath, "inputs");
    await fs.mkdir(inputRoot, { mode: 0o700 });
    await copyConvexWasmRuntimeHeaderIncludes(inputRoot, includeDirectories);
    await normalizeSnapshotTreeModes(inputRoot);
    // Authenticate a newly copied snapshot once. Exact later metadata hits avoid byte reads;
    // ctime-only changes require full material reauthentication without rewriting shared state.
    const state = await authenticateSnapshotInputs(
      inputRoot,
      identity,
      await readConvexWasmRuntimeHeaderSnapshotState(inputRoot)
    );
    const entry = {
      identity,
      key,
      kind: convexWasmRuntimeHeaderSnapshotCacheEntryKind,
      stage: convexWasmRuntimeHeaderSnapshotCacheStage,
      state,
    };
    await settleConcurrentWork([
      fs.writeFile(join(publicationPath, "entry.json"), `${canonicalJson(entry)}\n`, {
        flag: "wx",
        mode: 0o600,
      }),
      fs.writeFile(
        join(publicationPath, "COMPLETE"),
        completionMarker(entry, convexWasmRuntimeHeaderSnapshotCacheStage),
        {
          flag: "wx",
          mode: 0o600,
        }
      ),
    ]);
    const finalPath = snapshotCachePath(cacheLayout, key);
    try {
      await fs.rename(publicationPath, finalPath);
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY")
        )
      ) {
        throw error;
      }
      const winner = await authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry({
        cacheLayout,
        expectedIdentity: identity,
        key,
        path: finalPath,
      });
      if (canonicalJson(winner.identity) !== canonicalJson(identity)) {
        fail("concurrent runtime header snapshot publication has a different identity");
      }
      return winner;
    }
    return Object.freeze({
      entry: normalizeCacheEntry(entry, {
        expectedIdentity: identity,
        key,
        stage: convexWasmRuntimeHeaderSnapshotCacheStage,
      }),
      identity,
      inputRoot: join(finalPath, "inputs"),
      key,
      path: finalPath,
      stage: convexWasmRuntimeHeaderSnapshotCacheStage,
      state,
    });
  } finally {
    await fs.rm(publicationPath, { force: true, recursive: true });
  }
}

async function loadOrCreateRuntimeHeaderSnapshotCacheUncached({
  cacheLayout,
  identity,
  includeDirectories,
  key,
}) {
  const stageRoot = join(
    cacheLayout.immutable.artifacts,
    convexWasmRuntimeHeaderSnapshotCacheStage
  );
  await fs.mkdir(stageRoot, { mode: 0o700, recursive: true });
  await settleConcurrentWork(
    [cacheLayout.immutable.root, cacheLayout.immutable.artifacts, stageRoot].map((directory) =>
      requirePrivateCacheDirectory(cacheLayout.cacheRoot, directory)
    )
  );
  const cached = await loadRuntimeHeaderSnapshotCacheEntry({
    cacheLayout,
    expectedIdentity: identity,
    key,
  });
  if (cached !== undefined) return cached;
  return await createRuntimeHeaderSnapshotCacheEntry({
    cacheLayout,
    identity,
    includeDirectories,
    key,
  });
}

export async function loadOrCreateConvexWasmRuntimeHeaderSnapshotCache({
  cacheLayout,
  includeDirectories,
  runtimeHeaderMaterials,
}) {
  if (!Array.isArray(includeDirectories)) {
    fail("runtime header include directories must be an array");
  }
  const admittedIncludeDirectories = includeDirectories.map((path, index) =>
    requireString(path, `runtime header include directories[${index}]`)
  );
  const identity = createConvexWasmRuntimeHeaderSnapshotIdentity({
    includeDirectories: admittedIncludeDirectories,
    runtimeHeaderMaterials,
  });
  const key = convexWasmRuntimeHeaderSnapshotCacheKey(identity);
  const flightKey = `${cacheLayout.cacheRoot}\0${key}`;
  let flight = runtimeHeaderSnapshotCacheFlights.get(flightKey);
  if (flight === undefined) {
    flight = loadOrCreateRuntimeHeaderSnapshotCacheUncached({
      cacheLayout,
      identity,
      includeDirectories: admittedIncludeDirectories,
      key,
    });
    runtimeHeaderSnapshotCacheFlights.set(flightKey, flight);
    const clear = () => {
      if (runtimeHeaderSnapshotCacheFlights.get(flightKey) === flight) {
        runtimeHeaderSnapshotCacheFlights.delete(flightKey);
      }
    };
    void flight.then(clear, clear);
  }
  return await flight;
}

export const convexWasmRuntimeHeaderSnapshotCacheTestHooks = Object.freeze({
  createRuntimeHeaderSnapshotCacheEntry,
  loadOrCreateRuntimeHeaderSnapshotCacheUncached,
});
