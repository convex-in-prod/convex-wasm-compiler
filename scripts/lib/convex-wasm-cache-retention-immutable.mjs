import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
  requireSha256,
} from "./convex-wasm-artifact-contract.mjs";
import {
  ConvexWasmArtifactByteLimitError,
  createBoundedOperationRunner,
  decodeUtf8,
  hashPrivateRegularFile,
  mapBounded,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";
import { convexWasmCacheLock } from "./convex-wasm-cache-lock.mjs";
import {
  bindArtifactCacheValidationFence,
  validateArtifactCacheEntryInValidationScope,
} from "./convex-wasm-artifact-cache-entry.mjs";
import { staticHermesLayoutCacheReferences } from "./convex-wasm-static-hermes-layout-cache.mjs";
import {
  authenticateStaticHermesCBundle,
  normalizeStaticHermesCBundleOutput,
  staticHermesCBundleMembers,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackageInValidationScope } from "./convex-wasm-module-graph-package.mjs";
import {
  normalizeConvexWasmCacheLayout,
} from "./convex-wasm-cache-layout.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheDirectoryFileIdentities,
  requirePrivateCacheFile,
  withPrivateCacheAncestorValidation,
} from "./convex-wasm-private-cache.mjs";
import {
  normalizeConvexWasmCompilerDescriptorCacheProjection,
  normalizeConvexWasmCompilerOutputCacheIdentity,
} from "./convex-wasm-compiler-topology-witness.mjs";
import {
  convexWasmOfficialOutputCohortCapsuleKind,
  convexWasmOfficialOutputCohortCapsuleMaxBytes,
  convexWasmOfficialOutputCohortCapsuleStage,
  normalizeConvexWasmOfficialOutputCohortCapsuleIdentity,
} from "./convex-wasm-official-output-cohort-capsule-identity.mjs";
import {
  authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry,
  convexWasmRuntimeHeaderSnapshotCacheEntryKind,
  convexWasmRuntimeHeaderSnapshotCacheStage,
} from "./convex-wasm-runtime-header-snapshot-cache.mjs";

export const defaultConvexWasmImmutableMaxRetainedPackages = 512;
// An unconfigured plan can inspect the cache but cannot authorize pressure-based eviction.
// The caller chooses a high watermark for any sweep.
export const unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes = Number.MAX_SAFE_INTEGER;

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const ARTIFACT_PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const C_BUNDLE_ENTRY_KIND = "convex-wasm-c-bundle-cache-entry-v1";
const CERTIFICATE_KIND = "convex-wasm-deployment-result-certificate-v2";
const SNAPSHOT_KIND = "convex-wasm-cache-deployment-v1";
const LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_KINDS = new Set([
  "convex-wasm-official-output-module-graph-compiler-output-cache-v1",
  "convex-wasm-official-output-module-graph-compiler-output-cache-v2",
  "convex-wasm-official-output-module-graph-compiler-output-cache-v3",
]);
const MODULE_GRAPH_COMPILER_OUTPUT_CACHE_KIND =
  "convex-wasm-official-output-module-graph-compiler-output-cache-v4";
const MODULE_GRAPH_COMPILER_OUTPUT_CACHE_RECORD_SCHEMA_VERSION = 5;
const MODULE_GRAPH_COMPILER_OUTPUT_CACHE_RECORD_LEGACY_SCHEMA_VERSION = 4;
const HISTORICAL_MODULE_GRAPH_COMPILER_APPLICATION_KIND =
  "convex-wasm-official-output-chunk-application-unit-v2";
const LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_IDENTITY_KIND =
  "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v6";
const MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE = "module-graph-compiler-output";
const MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND =
  "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4";
const MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE = "module-graph-compiler-output-topology";
const MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_DESCRIPTOR_KIND =
  "convex-wasm-official-output-module-graph-compiler-output-topology-descriptor-v1";
const OFFICIAL_OUTPUT_COHORT_CAPSULE_KIND = convexWasmOfficialOutputCohortCapsuleKind;
const OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSION = 6;
const LEGACY_OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSIONS = new Map([
  ["convex-wasm-official-output-cohort-planning-capsule-v2", 2],
  ["convex-wasm-official-output-cohort-planning-capsule-v3", 3],
  ["convex-wasm-official-output-cohort-planning-capsule-v4", 4],
  ["convex-wasm-official-output-cohort-planning-capsule-v5", 5],
]);
const OFFICIAL_OUTPUT_COHORT_CAPSULE_STAGE = convexWasmOfficialOutputCohortCapsuleStage;
const MODULE_GRAPH_MANIFEST_V2_KIND = "convex-wasm-module-graph-manifest-v2";
const MODULE_GRAPH_MANIFEST_V3_KIND = "convex-wasm-module-graph-manifest-v3";
const MODULE_GRAPH_MANIFEST_V5_KIND = "convex-wasm-module-graph-manifest-v5";
const MODULE_GRAPH_PACKAGE_V2_KIND = "convex-wasm-module-graph-package-v2";
const MODULE_GRAPH_PROVENANCE_V2_KIND = "convex-wasm-module-graph-provenance-v2";
const MAX_METADATA_BYTES = 16 * 1024 * 1024;
const MAX_COMPLETION_MARKER_BYTES = 65;
const MAX_CERTIFICATE_BYTES = 128 * 1024 * 1024;
const MAX_CERTIFICATE_CANDIDATES = 256;
const MAX_COMPILER_OUTPUT_CACHE_BYTES = 64 * 1024 * 1024;
const MAX_DEPLOYMENT_SNAPSHOT_BYTES = 64 * 1024;
const MAX_SWEEP_QUARANTINE_RECORD_BYTES = 64 * 1024;
const MAX_SWEEP_JOURNAL_BYTES = 4 * 1024 * 1024;
const MAX_DEPLOYMENT_SNAPSHOT_CERTIFICATES = 8;
const MAX_DEPLOYMENT_SNAPSHOT_COMPILER_OUTPUTS = 256;
const MAX_DEPLOYMENT_SNAPSHOT_PACKAGES = 256;
const MAX_LEGACY_MODULE_GRAPH_PACKAGE_MODULES = 1_024;
// The producer accepts up to 1,024 physical application units. Retention must authenticate the
// complete closure of every output the producer can publish.
const MAX_COMPILER_OUTPUT_APPLICATION_UNITS = 1_024;
const GENERIC_ARTIFACT_EXTENSIONS = new Set(["a", "c", "cwasm", "js", "json", "o", "pch", "wasm"]);
const COMPILER_OUTPUT_GENERATED_C_EXTENSIONS = new Set(["c", "c-bundle"]);
const COMPILER_OUTPUT_AOT_EXTENSIONS = new Set(["cwasm"]);
const COMPILER_OUTPUT_OBJECT_EXTENSIONS = new Set(["o"]);
const IMMUTABLE_SWEEP_JOURNAL_KIND = "convex-wasm-immutable-gc-journal-v2";

// Measurements belong to the invocation, never to authenticated plan or producer material.
// Nested/concurrent phases overlap; their totals must not be added as a wall-time partition.
const retentionMeasurements = new AsyncLocalStorage();

export function currentConvexWasmRetentionPhase() {
  return retentionMeasurements.getStore()?.phase;
}

export async function measureConvexWasmRetentionPhase(phase, operation) {
  const context = retentionMeasurements.getStore();
  if (context === undefined) return await operation();
  const started = performance.now();
  const measurement = context.phases[phase] ??= { calls: 0, milliseconds: 0 };
  measurement.calls += 1;
  try {
    return await retentionMeasurements.run({ ...context, phase }, operation);
  } finally {
    measurement.milliseconds += performance.now() - started;
  }
}

export async function withConvexWasmRetentionMeasurements(operation) {
  const phases = {};
  const started = performance.now();
  const result = await retentionMeasurements.run({ phases }, operation);
  return {
    ...result,
    diagnostics: {
      elapsedMilliseconds: performance.now() - started, phases, overlappingPhases: true,
      counts: {
        inventoryBuilds: phases.inventory?.calls ?? 0,
        immutableOccupancyMeasurements: phases.immutableOccupancy?.calls ?? 0,
        dedicatedImmutableOccupancyWalks: phases.immutableOccupancyWalk?.calls ?? 0,
        reportOccupancyWalks: phases.reportOccupancy?.calls ?? 0,
        authorityFenceWalks: phases.authorityFence?.calls ?? 0,
      },
    },
  };
}

function fail(message) {
  throw new Error(`Convex Wasm immutable cache retention: ${message}`);
}

function deploymentSnapshotRoot(cacheRoot) {
  return join(resolve(cacheRoot), "state", "v1", "cache-retention", "v1", "deployed-success");
}

function missing(error) {
  return error instanceof Error && error.code === "ENOENT";
}

function requireLimit(value, description, positive = true) {
  if (!Number.isSafeInteger(value) || (positive ? value <= 0 : value < 0)) {
    fail(`${description} must be a ${positive ? "positive" : "non-negative"} safe integer`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort(compareStrings);
  const expectedKeys = [...expected].sort(compareStrings);
  if (
    actual.length !== expectedKeys.length ||
    actual.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(`${description} has unexpected fields`);
  }
}

function isLegacyOfficialOutputCohortCapsuleEntry(entry, stage, key) {
  const legacySchemaVersion = LEGACY_OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSIONS.get(
    entry?.metadata?.kind
  );
  return (
    legacySchemaVersion !== undefined &&
    entry.kind === "convex-wasm-artifact-cache-entry-v5" &&
    entry.stage === stage &&
    entry.key === key &&
    entry.artifactFile === "artifact.json" &&
    typeof entry.metadata === "object" &&
    entry.metadata !== null &&
    !Array.isArray(entry.metadata) &&
    Object.keys(entry.metadata).length === 2 &&
    Object.hasOwn(entry.metadata, "kind") &&
    Object.hasOwn(entry.metadata, "schemaVersion") &&
    entry.metadata.schemaVersion === legacySchemaVersion &&
    typeof entry.identity === "object" &&
    entry.identity !== null &&
    !Array.isArray(entry.identity) &&
    Object.keys(entry.identity).length === 3 &&
    Object.hasOwn(entry.identity, "capsuleIdentity") &&
    Object.hasOwn(entry.identity, "kind") &&
    Object.hasOwn(entry.identity, "schemaVersion") &&
    entry.identity.kind === entry.metadata.kind &&
    entry.identity.schemaVersion === legacySchemaVersion &&
    fingerprintJson({ identity: entry.identity, kind: ARTIFACT_PIPELINE_KIND, stage }) === key
  );
}

function requireSha256List(value, description, limit) {
  if (!Array.isArray(value) || value.length > limit) {
    fail(`${description} exceeds its bound`);
  }
  const values = value.map((entry) => requireSha256(entry, description));
  if (
    canonicalJson(values) !== canonicalJson([...values].sort(compareStrings)) ||
    new Set(values).size !== values.length
  ) {
    fail(`${description} must be sorted and unique`);
  }
  return values;
}

function requireNonEmptyString(value, description) {
  if (typeof value !== "string" || value.length === 0) fail(`${description} is invalid`);
  return value;
}

function requirePositiveSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${description} is invalid`);
  return value;
}

// GC planning runs under the shared cache lock. Drain every started authority read before a
// failure can release that lock, and select the failure by stable input order rather than timing.
async function settleConcurrentWork(promises) {
  const settlements = await Promise.allSettled(promises);
  const failure = settlements.find(({ status }) => status === "rejected");
  if (failure !== undefined) throw failure.reason;
  return settlements.map(({ value }) => value);
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Weak keys retain only a digest alongside a live parsed object, never a second canonical
// byte buffer. Topology binds JSON without the artifact file's trailing newline.
const authenticatedStructuredDigests = new WeakMap();

async function readStructuredArtifact(entry, maximumBytes, description, validation) {
  if (entry.artifactSize > maximumBytes) {
    throw new ConvexWasmArtifactByteLimitError(`${description} has`, entry.artifactSize, maximumBytes);
  }
  await requirePrivateCacheFile(validation.cacheRoot, entry.artifactPath);
  const before = physicalWitness(await fs.lstat(entry.artifactPath, { bigint: true }));
  const key = `${entry.artifactPath}\0${entry.artifactSha256}\0${entry.artifactSize}`;
  let cached = validation.structured.get(key);
  if (cached !== undefined && !sameWitness(cached.witness, before)) {
    validation.structured.delete(key);
    validation.structuredBytes -= cached.bytes;
    cached = undefined;
  }
  if (cached === undefined) {
    const value = readCanonical(entry.artifactPath, maximumBytes, description, entry);
    cached = { value, witness: before, bytes: entry.artifactSize };
    // This is a bounded collection/deletion scope, not the invocation inventory. Drop
    // bulk parse material as the scope ends; only normalized closure facts survive waves.
    const maximumCachedBytes = 4 * 1024 * 1024;
    if (cached.bytes <= maximumCachedBytes) {
      while (validation.structured.size >= 8 || validation.structuredBytes + cached.bytes > maximumCachedBytes) {
        const oldest = validation.structured.keys().next().value;
        validation.structuredBytes -= validation.structured.get(oldest).bytes;
        validation.structured.delete(oldest);
      }
      validation.structured.set(key, cached);
      validation.structuredBytes += cached.bytes;
    }
  }
  const value = await cached.value;
  if (!sameWitness(before, physicalWitness(await fs.lstat(entry.artifactPath, { bigint: true })))) {
    fail(`${description} changed during structured interpretation: ${entry.artifactPath}`);
  }
  return value;
}

async function readCanonical(
  path,
  maximumBytes,
  description,
  expectedArtifact,
  authenticatedFileIdentity
) {
  const bytes = await readPrivateRegularFile(
    path,
    maximumBytes,
    description,
    authenticatedFileIdentity
  );
  if (
    expectedArtifact !== undefined &&
    (bytes.length !== expectedArtifact.artifactSize ||
      sha256(bytes) !== expectedArtifact.artifactSha256)
  ) {
    fail(`${description} changed after its cache entry was authenticated: ${path}`);
  }
  const source = decodeUtf8(bytes, description);
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new Error(`${description} is not JSON: ${path}`, { cause: error });
  }
  // JSON.parse creates data-only trees. Avoid the general canonicalizer's proxy, accessor and
  // frozen-object checks on every node of large records, while retaining exact byte comparison.
  // Numeric object keys can enumerate out of UTF-16 order; the existing normalizer handles them.
  const canonical = parsedJsonKeysAreCanonical(value) ? JSON.stringify(value) : canonicalJson(value);
  // The fatal UTF-8 decoder strips a leading BOM. Reject that byte difference before
  // reusing the original bytes for a digest of canonical JSON without its newline.
  if (`${canonical}\n` !== source || Buffer.byteLength(source) !== bytes.length) {
    fail(`${description} is not canonical JSON: ${path}`);
  }
  if (expectedArtifact !== undefined && value !== null && typeof value === "object") {
    authenticatedStructuredDigests.set(value, sha256(bytes.subarray(0, -1)));
  }
  return value;
}

function parsedJsonKeysAreCanonical(value) {
  if (typeof value === "number") return Number.isFinite(value);
  if (value === null || typeof value !== "object") return true;
  if (Array.isArray(value)) return value.every(parsedJsonKeysAreCanonical);
  let previous;
  for (const key of Object.keys(value)) {
    if (previous !== undefined && key < previous) return false;
    previous = key;
    if (!parsedJsonKeysAreCanonical(value[key])) return false;
  }
  return true;
}

async function pathInfo(path) {
  const status = await fs.lstat(path);
  if (status.isSymbolicLink()) fail(`immutable cache path is a symbolic link: ${path}`);
  return status;
}

function sameDirectoryState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.nlink === right.nlink
  );
}

async function readStableDirectoryNames(path, description) {
  const before = await pathInfo(path);
  if (!before.isDirectory()) fail(`${description} is not a directory: ${path}`);
  const names = (await fs.readdir(path)).sort(compareStrings);
  const after = await pathInfo(path);
  if (!sameDirectoryState(before, after)) {
    fail(`${description} changed while it was enumerated: ${path}`);
  }
  return { names, state: before };
}

async function readStableCertificateLookupNames(path) {
  const before = await pathInfo(path);
  if (!before.isDirectory()) fail(`certificate lookup root is not a directory: ${path}`);
  const names = [];
  const directory = await fs.opendir(path);
  try {
    for (;;) {
      const entry = await directory.read();
      if (entry === null) break;
      // Publication scratch has no authority and is intentionally omitted from the retained
      // listing. This keeps the 256-certificate bound effective before allocating a huge name
      // array for stale crash residue.
      if (entry.name.startsWith(".publish-")) continue;
      names.push(entry.name);
      if (names.length > MAX_CERTIFICATE_CANDIDATES + 1) {
        fail(
          `certificate lookup root has more than ${MAX_CERTIFICATE_CANDIDATES} candidates: ${path}`
        );
      }
    }
  } finally {
    await directory.close();
  }
  const after = await pathInfo(path);
  if (!sameDirectoryState(before, after)) {
    fail(`certificate lookup root changed while it was enumerated: ${path}`);
  }
  return { names: names.sort(compareStrings), state: before };
}

async function verifyStableDirectoryNames(path, listing, expectedNames, description, ignoredName) {
  const after = await pathInfo(path);
  if (!sameDirectoryState(listing.state, after)) {
    fail(`${description} changed while its entries were authenticated: ${path}`);
  }
  const names = (await fs.readdir(path)).sort(compareStrings);
  const normalize = (values) =>
    values.filter((name) => ignoredName === undefined || !name.startsWith(ignoredName));
  if (canonicalJson(normalize(names)) !== canonicalJson(normalize(expectedNames))) {
    fail(`${description} contents changed while they were authenticated: ${path}`);
  }
}

async function treeStats(path, includeIdentity = true) {
  const inodes = new Map();
  const physicalStates = [];
  let allocatedBytes = 0;
  let mtimeMs = 0;
  const pending = [{ path, relativePath: "" }];
  while (pending.length !== 0) {
    const { path: current, relativePath } = pending.pop();
    const status = await fs.lstat(current, { bigint: true });
    if (status.isSymbolicLink()) fail(`immutable cache path is a symbolic link: ${current}`);
    const currentMtimeMs = Number(status.mtimeNs) / 1_000_000;
    if (!Number.isFinite(currentMtimeMs) || currentMtimeMs < 0) {
      fail(`immutable cache entry has an invalid modification time: ${current}`);
    }
    mtimeMs = Math.max(mtimeMs, currentMtimeMs);
    const inode = `${String(status.dev)}:${String(status.ino)}`;
    const entryAllocatedBytesBig = status.blocks * 512n;
    const entryAllocatedBytes = Number(entryAllocatedBytesBig);
    if (!Number.isSafeInteger(entryAllocatedBytes) || entryAllocatedBytes < 0) {
      fail(`immutable cache entry has an invalid allocated byte count: ${current}`);
    }
    const existing = inodes.get(inode);
    if (existing === undefined) {
      inodes.set(inode, {
        allocatedBytes: entryAllocatedBytes,
        linkCount: status.nlink,
        references: 1,
        regularFile: status.isFile(),
      });
      allocatedBytes += entryAllocatedBytes;
      if (!Number.isSafeInteger(allocatedBytes)) {
        fail(`immutable cache tree allocated byte count exceeds the safe integer range: ${path}`);
      }
    } else {
      if (
        existing.allocatedBytes !== entryAllocatedBytes ||
        existing.linkCount !== status.nlink ||
        existing.regularFile !== status.isFile()
      ) {
        fail(`immutable cache inode changed during accounting: ${current}`);
      }
      existing.references += 1;
    }
    // The inode list and maximum mtime are not enough to bind a plan to its tree: a writer can
    // rewrite a file in place and restore its mtime between planning and quarantine. Include each
    // relative path's complete nanosecond state (including ctime) so a replacement or mutation
    // cannot make a different tree look like the planned candidate. The root directory's ctime is
    // omitted because the quarantine rename itself changes that ctime; child states still cover
    // every member and the root inode/type/size/link state remains bound.
    if (includeIdentity) physicalStates.push({
      blocks: String(status.blocks),
      dev: String(status.dev),
      gid: String(status.gid),
      ino: String(status.ino),
      mode: String(status.mode),
      mtimeNs: String(status.mtimeNs),
      nlink: String(status.nlink),
      path: relativePath,
      size: String(status.size),
      type: status.isDirectory() ? "directory" : status.isFile() ? "file" : "other",
      uid: String(status.uid),
      ...(relativePath === "" ? {} : { ctimeNs: String(status.ctimeNs) }),
    });
    if (status.isDirectory()) {
      const names = await fs.readdir(current);
      names.sort(compareStrings);
      for (const name of names) {
        pending.push({
          path: join(current, name),
          relativePath: relativePath === "" ? name : `${relativePath}/${name}`,
        });
      }
    }
  }
  // Pressure accounting needs the complete inode walk, but never consumes its authentication
  // digest. Avoid retaining and canonicalizing every file state for that whole-cache read.
  if (!includeIdentity) return { allocatedBytes };
  let estimatedReclaimBytes = 0;
  for (const inode of inodes.values()) {
    // Removing this tree cannot reclaim a regular file while another hardlink remains outside it.
    if (inode.regularFile && inode.linkCount > inode.references) continue;
    estimatedReclaimBytes += inode.allocatedBytes;
    if (!Number.isSafeInteger(estimatedReclaimBytes)) {
      fail(`immutable cache tree reclaim estimate exceeds the safe integer range: ${path}`);
    }
  }
  physicalStates.sort((left, right) => compareStrings(left.path, right.path));
  return {
    allocatedBytes,
    estimatedReclaimBytes,
    // Keep the historical inode summary for recovery of older quarantine markers. New plans
    // persist only the compact physical-state digest, including for large C bundles.
    identity: `${[...inodes.keys()].sort(compareStrings).join(",")}:${mtimeMs}`,
    treeIdentity: sha256(canonicalBytes(physicalStates)),
    mtimeMs,
  };
}

// The maintenance fence already captured every immutable path and its physical state. Reusing
// that state for inventory accounting avoids walking each authenticated artifact tree again.
function treeStatsFromFence(path, fenceEntries, includeIdentity = true) {
  const prefix = `${path}/`;
  let lower = 0;
  let upper = fenceEntries.length;
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2);
    if (compareStrings(fenceEntries[middle][0], path) < 0) lower = middle + 1;
    else upper = middle;
  }
  const entries = [];
  for (let index = lower; index < fenceEntries.length; index += 1) {
    const [entryPath, witness] = fenceEntries[index];
    if (entryPath !== path && !entryPath.startsWith(prefix)) break;
    entries.push({
      relativePath: entryPath === path ? "" : entryPath.slice(prefix.length),
      witness,
    });
  }
  if (entries.length === 0) fail(`immutable cache tree disappeared from the authority fence: ${path}`);
  const inodes = new Map();
  const physicalStates = [];
  let allocatedBytes = 0;
  let mtimeMs = 0;
  for (const { relativePath, witness } of entries) {
    const currentMtimeMs = Number(witness.mtimeNs) / 1_000_000;
    if (!Number.isFinite(currentMtimeMs) || currentMtimeMs < 0) {
      fail(`immutable cache entry has an invalid modification time: ${path}`);
    }
    mtimeMs = Math.max(mtimeMs, currentMtimeMs);
    const inode = `${String(witness.dev)}:${String(witness.ino)}`;
    const entryAllocatedBytesBig = witness.blocks * 512n;
    const entryAllocatedBytes = Number(entryAllocatedBytesBig);
    if (!Number.isSafeInteger(entryAllocatedBytes) || entryAllocatedBytes < 0) {
      fail(`immutable cache tree allocated byte count exceeds the safe integer range: ${path}`);
    }
    const existing = inodes.get(inode);
    if (existing === undefined) {
      inodes.set(inode, {
        allocatedBytes: entryAllocatedBytes,
        linkCount: witness.nlink,
        references: 1,
        regularFile: witness.type === "file",
      });
      allocatedBytes += entryAllocatedBytes;
      if (!Number.isSafeInteger(allocatedBytes)) {
        fail(`immutable cache tree allocated byte count exceeds the safe integer range: ${path}`);
      }
    } else {
      if (
        existing.allocatedBytes !== entryAllocatedBytes ||
        existing.linkCount !== witness.nlink ||
        existing.regularFile !== (witness.type === "file")
      ) {
        fail(`immutable cache inode changed during accounting: ${path}`);
      }
      existing.references += 1;
    }
    if (includeIdentity) {
      physicalStates.push({
        blocks: String(witness.blocks),
        dev: String(witness.dev),
        gid: String(witness.gid),
        ino: String(witness.ino),
        mode: String(witness.mode),
        mtimeNs: String(witness.mtimeNs),
        nlink: String(witness.nlink),
        path: relativePath,
        size: String(witness.size),
        type: witness.type,
        uid: String(witness.uid),
        ...(relativePath === "" ? {} : { ctimeNs: String(witness.ctimeNs) }),
      });
    }
  }
  if (!includeIdentity) return { allocatedBytes };
  let estimatedReclaimBytes = 0;
  for (const inode of inodes.values()) {
    if (inode.regularFile && inode.linkCount > BigInt(inode.references)) continue;
    estimatedReclaimBytes += inode.allocatedBytes;
    if (!Number.isSafeInteger(estimatedReclaimBytes)) {
      fail(`immutable cache tree reclaim estimate exceeds the safe integer range: ${path}`);
    }
  }
  physicalStates.sort((left, right) => compareStrings(left.path, right.path));
  return {
    allocatedBytes,
    estimatedReclaimBytes,
    identity: `${[...inodes.keys()].sort(compareStrings).join(",")}:${mtimeMs}`,
    treeIdentity: sha256(canonicalBytes(physicalStates)),
    mtimeMs,
  };
}

function inventoryTreeStats(path, validation) {
  return validation.fence === undefined
    ? treeStats(path)
    : treeStatsFromFence(path, validation.fenceEntries);
}

function compilerOutputReferenceKey(reference, extensions, description) {
  requireExactKeys(reference, ["entry", "extension", "report"], description);
  if (
    typeof reference.entry !== "object" ||
    reference.entry === null ||
    Array.isArray(reference.entry)
  ) {
    fail(`${description} entry must be an object`);
  }
  requireExactKeys(reference.report, ["cacheKey", "stage"], `${description} report`);
  const cacheKey = requireSha256(reference.report.cacheKey, `${description} cache key`);
  if (typeof reference.report.stage !== "string" || reference.report.stage.length === 0) {
    fail(`${description} stage is invalid`);
  }
  if (!extensions.has(reference.extension)) {
    fail(`${description} extension is unsupported`);
  }
  if (
    reference.extension === "c-bundle"
      ? reference.entry.kind !== C_BUNDLE_ENTRY_KIND
      : reference.entry.artifactFile !== `artifact.${reference.extension}`
  ) {
    fail(`${description} entry has a different artifact family`);
  }
  if (reference.entry.key !== cacheKey || reference.entry.stage !== reference.report.stage) {
    fail(`${description} entry does not match its cache reference`);
  }
  return `${reference.report.stage}\0${cacheKey}`;
}

function compilerOutputCacheEntrySchema(entry) {
  const source = canonicalJson(entry.metadata);
  if (source === canonicalJson({ kind: MODULE_GRAPH_COMPILER_OUTPUT_CACHE_KIND })) {
    if (entry.identity?.kind === LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_IDENTITY_KIND) {
      normalizeLegacyCompilerOutputCacheIdentityV6(
        entry.identity,
        "compiler-output cache legacy identity"
      );
      return "legacy-v6";
    }
    normalizeConvexWasmCompilerOutputCacheIdentity(
      entry.identity,
      "compiler-output cache identity"
    );
    return "current";
  }
  if (
    typeof entry.metadata?.kind === "string" &&
    source === canonicalJson({ kind: entry.metadata.kind }) &&
    LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_KINDS.has(entry.metadata.kind)
  ) {
    return "legacy";
  }
  fail("compiler-output cache entry has invalid metadata");
}

function normalizeLegacyCompilerOutputCacheIdentityV6(rawIdentity, description) {
  requireExactKeys(
    rawIdentity,
    [
      "cohortInputsSha256",
      "descriptorIdentitySha256",
      "engineCompatibilitySha256",
      "kind",
      "materialSessionSha256",
      "producerIdentitySha256",
    ],
    description
  );
  if (rawIdentity.kind !== LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_IDENTITY_KIND) {
    fail(`${description} has an unsupported schema`);
  }
  return {
    cohortInputsSha256: requireSha256(
      rawIdentity.cohortInputsSha256,
      `${description} cohort inputs`
    ),
    descriptorIdentitySha256: requireSha256(
      rawIdentity.descriptorIdentitySha256,
      `${description} descriptor identity`
    ),
    engineCompatibilitySha256: requireSha256(
      rawIdentity.engineCompatibilitySha256,
      `${description} engine compatibility`
    ),
    kind: LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_IDENTITY_KIND,
    materialSessionSha256: requireSha256(
      rawIdentity.materialSessionSha256,
      `${description} material session`
    ),
    producerIdentitySha256: requireSha256(
      rawIdentity.producerIdentitySha256,
      `${description} producer identity`
    ),
  };
}

function authenticateCompilerOutputLookupIdentity(cacheIdentity, value, description) {
  // These lookup fields are repeated in both record and certificate payloads. Compare them before
  // either payload can grant current closure or authenticated predecessor classification.
  const descriptorIdentitySha256 = requireSha256(
    value?.descriptor?.identitySha256,
    `${description} descriptor identity SHA-256`
  );
  const engineCompatibilitySha256 = requireSha256(
    value?.engine?.compatibilitySha256,
    `${description} engine compatibility SHA-256`
  );
  if (
    cacheIdentity.descriptorIdentitySha256 !== descriptorIdentitySha256 ||
    cacheIdentity.engineCompatibilitySha256 !== engineCompatibilitySha256
  ) {
    fail(`${description} does not match its lookup identity`);
  }
}

function authenticateCompilerOutputTopologyDescriptor(descriptor, description) {
  requireExactKeys(
    descriptor,
    [
      "applicationIdentitySha256",
      "chunkUnitsIdentitySha256",
      "descriptorSha256",
      "identitySha256",
      "kind",
      "schemaVersion",
    ],
    description
  );
  const applicationIdentitySha256 = requireSha256(
    descriptor.applicationIdentitySha256,
    `${description} application identity SHA-256`
  );
  requireSha256(descriptor.chunkUnitsIdentitySha256, `${description} chunk-units identity SHA-256`);
  requireSha256(descriptor.descriptorSha256, `${description} descriptor SHA-256`);
  const identitySha256 = requireSha256(
    descriptor.identitySha256,
    `${description} identity SHA-256`
  );
  if (
    descriptor.kind !== MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_DESCRIPTOR_KIND ||
    descriptor.schemaVersion !== 1 ||
    identitySha256 !== applicationIdentitySha256
  ) {
    fail(`${description} has an unsupported schema`);
  }
  return descriptor;
}

function authenticateCompilerOutputRecord(record, description) {
  const compactDescriptor =
    record?.schemaVersion === MODULE_GRAPH_COMPILER_OUTPUT_CACHE_RECORD_SCHEMA_VERSION;
  requireExactKeys(
    record,
    [
      "applicationUnits",
      "bridge",
      "descriptor",
      "engine",
      "engineProbe",
      "formatter",
      "kind",
      ...(compactDescriptor ? ["reusableCodeIdentitySha256s"] : []),
      "schemaVersion",
      ...(compactDescriptor ? ["structuralTopologySha256"] : []),
    ],
    description
  );
  if (
    record.kind !== MODULE_GRAPH_COMPILER_OUTPUT_CACHE_KIND ||
    (!compactDescriptor &&
      record.schemaVersion !== MODULE_GRAPH_COMPILER_OUTPUT_CACHE_RECORD_LEGACY_SCHEMA_VERSION) ||
    !Array.isArray(record.applicationUnits) ||
    record.applicationUnits.length < 2 ||
    record.applicationUnits.length > MAX_COMPILER_OUTPUT_APPLICATION_UNITS
  ) {
    fail(`${description} has an unsupported schema`);
  }
  requireExactKeys(
    record.bridge,
    [
      "generatedC",
      "generatedCIdentity",
      "generatedSource",
      "object",
      "objectIdentity",
      "requestEnvelope",
      "valueCodec",
    ],
    `${description} bridge`
  );
  requireExactKeys(
    record.formatter,
    ["generatedC", "generatedCIdentity", "generatedSource", "object", "objectIdentity"],
    `${description} formatter`
  );
  if (compactDescriptor) {
    authenticateCompilerOutputTopologyDescriptor(
      record.descriptor,
      `${description} topology descriptor`
    );
    if (
      !Array.isArray(record.reusableCodeIdentitySha256s) ||
      record.reusableCodeIdentitySha256s.length !== record.applicationUnits.length
    ) {
      fail(`${description} reusable-code identities do not match its application units`);
    }
    for (const [index, digest] of record.reusableCodeIdentitySha256s.entries()) {
      requireSha256(digest, `${description} reusable-code identity ${String(index)}`);
    }
    requireSha256(record.structuralTopologySha256, `${description} structural topology SHA-256`);
  } else if (
    record.descriptor?.applicationIdentity?.kind !==
    HISTORICAL_MODULE_GRAPH_COMPILER_APPLICATION_KIND
  ) {
    // Schema 4 spans the executable-material namespace rotation. Only a descriptor that passes
    // the current structural contract may retain current stage-closure authority; the exact
    // pre-transport family remains an authenticated, age-bounded predecessor.
    normalizeConvexWasmCompilerDescriptorCacheProjection(record.descriptor);
  }
  return {
    descriptorFamily:
      compactDescriptor ||
      record.descriptor.applicationIdentity.kind !==
        HISTORICAL_MODULE_GRAPH_COMPILER_APPLICATION_KIND
        ? "current"
        : "historical-pre-transport",
    schemaVersion: record.schemaVersion,
  };
}

function authenticateStandaloneTopologyCertificateStage(
  certificate,
  extensions,
  includeIdentity,
  description
) {
  requireExactKeys(
    certificate,
    [
      "artifactSha256",
      "artifactSize",
      "cacheKey",
      "extension",
      ...(includeIdentity ? ["identity"] : []),
      "identitySha256",
      "stage",
    ],
    description
  );
  requireSha256(certificate.artifactSha256, `${description} artifact SHA-256`);
  requirePositiveSafeInteger(certificate.artifactSize, `${description} artifact size`);
  requireSha256(certificate.cacheKey, `${description} cache key`);
  if (!extensions.has(certificate.extension)) {
    fail(`${description} extension is unsupported`);
  }
  requireNonEmptyString(certificate.stage, `${description} stage`);
  const identitySha256 = requireSha256(
    certificate.identitySha256,
    `${description} identity SHA-256`
  );
  if (includeIdentity) {
    if (
      typeof certificate.identity !== "object" ||
      certificate.identity === null ||
      Array.isArray(certificate.identity) ||
      fingerprintJson(certificate.identity) !== identitySha256
    ) {
      fail(`${description} identity digest is invalid`);
    }
  }
}

function authenticateStandaloneTopologyCertificate(certificate) {
  requireExactKeys(certificate.bridge, ["generatedC", "object"], "compiler-output topology bridge");
  requireExactKeys(
    certificate.formatter,
    ["generatedC", "object"],
    "compiler-output topology formatter"
  );
  authenticateCompilerOutputTopologyDescriptor(
    certificate.descriptor,
    "compiler-output topology descriptor"
  );
  const engine = certificate.engine;
  requireExactKeys(
    engine,
    [
      "compatibilitySha256",
      "config",
      "configurationSha256",
      "package",
      "revision",
      "target",
      "wasmtimeMaterialsSha256",
    ],
    "compiler-output topology engine"
  );
  requireExactKeys(engine.target, ["cpu", "triple"], "compiler-output topology engine target");
  requireSha256(
    engine.compatibilitySha256,
    "compiler-output topology engine compatibility SHA-256"
  );
  const configurationSha256 = requireSha256(
    engine.configurationSha256,
    "compiler-output topology engine configuration SHA-256"
  );
  requireSha256(
    engine.wasmtimeMaterialsSha256,
    "compiler-output topology engine materials SHA-256"
  );
  if (
    typeof engine.config !== "object" ||
    engine.config === null ||
    Array.isArray(engine.config) ||
    typeof engine.package !== "object" ||
    engine.package === null ||
    Array.isArray(engine.package) ||
    configurationSha256 !== fingerprintJson(engine.config)
  ) {
    fail("compiler-output topology engine has an unsupported schema");
  }
  requireNonEmptyString(engine.revision, "compiler-output topology engine revision");
  requireNonEmptyString(engine.target.cpu, "compiler-output topology engine target CPU");
  requireNonEmptyString(engine.target.triple, "compiler-output topology engine target triple");
  authenticateStandaloneTopologyCertificateStage(
    certificate.engineProbe,
    COMPILER_OUTPUT_AOT_EXTENSIONS,
    false,
    "compiler-output topology engine probe"
  );
  authenticateStandaloneTopologyCertificateStage(
    certificate.bridge.generatedC,
    COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
    true,
    "compiler-output topology bridge generated C"
  );
  authenticateStandaloneTopologyCertificateStage(
    certificate.bridge.object,
    COMPILER_OUTPUT_OBJECT_EXTENSIONS,
    true,
    "compiler-output topology bridge object"
  );
  authenticateStandaloneTopologyCertificateStage(
    certificate.formatter.generatedC,
    COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
    true,
    "compiler-output topology formatter generated C"
  );
  authenticateStandaloneTopologyCertificateStage(
    certificate.formatter.object,
    COMPILER_OUTPUT_OBJECT_EXTENSIONS,
    true,
    "compiler-output topology formatter object"
  );
  if (
    certificate.applicationUnits.length < 2 ||
    certificate.applicationUnits.length > MAX_COMPILER_OUTPUT_APPLICATION_UNITS
  ) {
    fail("compiler-output topology certificate has an invalid application-unit count");
  }
  for (const [applicationUnitSlot, unit] of certificate.applicationUnits.entries()) {
    requireExactKeys(
      unit,
      ["generatedC", "picObject"],
      `compiler-output topology application unit ${String(applicationUnitSlot)}`
    );
    authenticateStandaloneTopologyCertificateStage(
      unit.generatedC,
      COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
      false,
      `compiler-output topology application unit ${String(applicationUnitSlot)} generated C`
    );
    authenticateStandaloneTopologyCertificateStage(
      unit.picObject,
      COMPILER_OUTPUT_OBJECT_EXTENSIONS,
      false,
      `compiler-output topology application unit ${String(applicationUnitSlot)} PIC object`
    );
  }
}

async function topologyCertificateCompilerOutputReference(entry, validation) {
  if (entry.stage !== MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE) return undefined;
  if (
    canonicalJson(entry.metadata) !==
    canonicalJson({ kind: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND })
  ) {
    // Rotated topology-certificate schemas are not selected by the current producer and remain
    // ordinary collectible artifacts.
    return undefined;
  }
  if (entry.artifactFile !== "artifact.json") {
    fail("compiler-output topology certificate does not contain JSON");
  }
  requireExactKeys(
    entry.identity,
    ["compilerOutputCacheIdentity", "compilerOutputCacheKey", "kind"],
    "compiler-output topology certificate identity"
  );
  if (entry.identity.kind !== MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND) {
    fail("compiler-output topology certificate identity has an unsupported schema");
  }
  const rawCacheIdentity = entry.identity.compilerOutputCacheIdentity;
  const legacyIdentity =
    rawCacheIdentity?.kind === LEGACY_MODULE_GRAPH_COMPILER_OUTPUT_CACHE_IDENTITY_KIND;
  const cacheIdentity = legacyIdentity
    ? normalizeLegacyCompilerOutputCacheIdentityV6(
        rawCacheIdentity,
        "compiler-output topology certificate compiler identity"
      )
    : normalizeConvexWasmCompilerOutputCacheIdentity(
        rawCacheIdentity,
        "compiler-output topology certificate compiler identity"
      );
  const cacheKey = requireSha256(
    entry.identity.compilerOutputCacheKey,
    "compiler-output topology certificate compiler key"
  );
  if (
    cacheKey !==
    fingerprintJson({
      identity: cacheIdentity,
      kind: ARTIFACT_PIPELINE_KIND,
      stage: MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE,
    })
  ) {
    fail("compiler-output topology certificate points to a different compiler identity");
  }
  const certificate = await readStructuredArtifact(entry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "compiler-output topology certificate", validation);
  requireExactKeys(
    certificate,
    [
      "applicationUnits",
      "bridge",
      "cacheKey",
      "cacheRecordSha256",
      "descriptor",
      "engine",
      "engineProbe",
      "formatter",
      "kind",
      "schemaVersion",
    ],
    "compiler-output topology certificate"
  );
  if (
    certificate.kind !== MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND ||
    certificate.schemaVersion !== 4 ||
    certificate.cacheKey !== cacheKey ||
    !Array.isArray(certificate.applicationUnits)
  ) {
    fail("compiler-output topology certificate has an unsupported schema");
  }
  const cacheRecordSha256 = requireSha256(
    certificate.cacheRecordSha256,
    "compiler-output topology certificate record SHA-256"
  );
  authenticateStandaloneTopologyCertificate(certificate);
  authenticateCompilerOutputLookupIdentity(
    cacheIdentity,
    certificate,
    "compiler-output topology certificate"
  );
  if (legacyIdentity) {
    // The v6 predecessor cannot be selected by the current producer. Authenticate its complete
    // self-contained certificate before leaving it as an ordinary collectible artifact.
    return undefined;
  }
  return {
    cacheIdentity,
    cacheKey,
    cacheRecordSha256,
  };
}

async function compilerOutputArtifactKeys(entry, validation) {
  if (entry.stage !== MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE) return [];
  if (entry.artifactFile !== "artifact.json") {
    fail("compiler-output cache entry does not contain JSON");
  }
  const schema = compilerOutputCacheEntrySchema(entry);
  if (schema === "legacy") {
    // A rotated compiler-output schema has a different cache identity and cannot be reused by the
    // current producer. Keep it as an ordinary bounded artifact until normal age-based eviction.
    return [];
  }
  const record = await readStructuredArtifact(entry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "compiler-output cache record", validation);
  const recordAuthority = authenticateCompilerOutputRecord(record, "compiler-output cache record");
  const cacheIdentity =
    schema === "legacy-v6"
      ? normalizeLegacyCompilerOutputCacheIdentityV6(
          entry.identity,
          "compiler-output cache legacy identity"
        )
      : normalizeConvexWasmCompilerOutputCacheIdentity(
          entry.identity,
          "compiler-output cache identity"
        );
  authenticateCompilerOutputLookupIdentity(cacheIdentity, record, "compiler-output cache record");
  if (schema === "legacy-v6") {
    if (
      recordAuthority.schemaVersion !==
      MODULE_GRAPH_COMPILER_OUTPUT_CACHE_RECORD_LEGACY_SCHEMA_VERSION
    ) {
      fail("compiler-output cache legacy identity has an unsupported record schema");
    }
    // The predecessor is age-bounded only after its record proves the descriptor and engine facts
    // repeated by its exact six-field lookup identity. It never grants stage-closure authority.
    return [];
  }
  if (recordAuthority.descriptorFamily === "historical-pre-transport") {
    return [];
  }
  for (const [description, identity, reference] of [
    [
      "compiler-output cache bridge generated-C identity",
      record.bridge.generatedCIdentity,
      record.bridge.generatedC,
    ],
    [
      "compiler-output cache bridge object identity",
      record.bridge.objectIdentity,
      record.bridge.object,
    ],
    [
      "compiler-output cache formatter generated-C identity",
      record.formatter.generatedCIdentity,
      record.formatter.generatedC,
    ],
    [
      "compiler-output cache formatter object identity",
      record.formatter.objectIdentity,
      record.formatter.object,
    ],
  ]) {
    if (canonicalJson(identity) !== canonicalJson(reference.entry.identity)) {
      fail(`${description} disagrees with its stage reference`);
    }
  }
  const references = [
    [record.engineProbe, COMPILER_OUTPUT_AOT_EXTENSIONS, "compiler-output cache engine probe"],
    [
      record.bridge.generatedC,
      COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
      "compiler-output cache bridge generated C",
    ],
    [
      record.bridge.object,
      COMPILER_OUTPUT_OBJECT_EXTENSIONS,
      "compiler-output cache bridge object",
    ],
    [
      record.formatter.generatedC,
      COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
      "compiler-output cache formatter generated C",
    ],
    [
      record.formatter.object,
      COMPILER_OUTPUT_OBJECT_EXTENSIONS,
      "compiler-output cache formatter object",
    ],
  ];
  for (const [index, unit] of record.applicationUnits.entries()) {
    requireExactKeys(
      unit,
      ["generatedC", "picObject"],
      `compiler-output cache application unit ${String(index)}`
    );
    references.push(
      [
        unit.generatedC,
        COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
        `compiler-output cache application unit ${String(index)} generated C`,
      ],
      [
        unit.picObject,
        COMPILER_OUTPUT_OBJECT_EXTENSIONS,
        `compiler-output cache application unit ${String(index)} PIC object`,
      ]
    );
  }
  const referencesByKey = new Map();
  for (const [reference, extensions, description] of references) {
    const key = compilerOutputReferenceKey(reference, extensions, description);
    const normalized = {
      entry: reference.entry,
      extension: reference.extension,
      key,
    };
    const prior = referencesByKey.get(key);
    if (
      prior !== undefined &&
      (prior.extension !== normalized.extension ||
        canonicalJson(prior.entry) !== canonicalJson(normalized.entry))
    ) {
      fail(`compiler-output cache references disagree for ${key}`);
    }
    referencesByKey.set(key, normalized);
  }
  return [...referencesByKey.values()].sort((left, right) => compareStrings(left.key, right.key));
}

function artifactCacheEntryProjection(entry) {
  const projected = { ...entry };
  delete projected.artifactPath;
  delete projected.bundlePath;
  delete projected.artifactContents;
  return projected;
}

function authenticateCompilerOutputClosure(artifactRecord, artifactsByKey) {
  for (const reference of artifactRecord.closureArtifactReferences) {
    const target = artifactsByKey.get(reference.key);
    if (target === undefined) {
      fail(`compiler-output cache closure artifact is unavailable: ${reference.key}`);
    }
    if (
      (reference.extension === "c-bundle" && target.type !== "c-bundle") ||
      (reference.extension !== "c-bundle" && target.type !== "artifact") ||
      canonicalJson(artifactCacheEntryProjection(target.entry)) !== canonicalJson(reference.entry)
    ) {
      fail(`compiler-output cache closure artifact disagrees with its record: ${reference.key}`);
    }
  }
}

function authenticateTopologyCertificateStage(
  reference,
  certificate,
  extensions,
  includeIdentity,
  description
) {
  compilerOutputReferenceKey(reference, extensions, description);
  const expectedIdentity = fingerprintJson(reference.entry.identity);
  const expected = {
    artifactSha256: requireSha256(
      reference.entry.artifactSha256,
      `${description} artifact SHA-256`
    ),
    artifactSize: requirePositiveSafeInteger(
      reference.entry.artifactSize,
      `${description} artifact size`
    ),
    cacheKey: reference.report.cacheKey,
    extension: reference.extension,
    ...(includeIdentity ? { identity: reference.entry.identity } : {}),
    identitySha256: expectedIdentity,
    stage: reference.report.stage,
  };
  requireExactKeys(
    certificate,
    [
      "artifactSha256",
      "artifactSize",
      "cacheKey",
      "extension",
      ...(includeIdentity ? ["identity"] : []),
      "identitySha256",
      "stage",
    ],
    description
  );
  if (canonicalJson(certificate) !== canonicalJson(expected)) {
    fail(`${description} disagrees with its compiler-output record`);
  }
}

function authenticateCapsuleTopologyCertificate(certificate, record, recordAuthority) {
  if (recordAuthority.descriptorFamily !== "current") {
    fail("cohort capsule compiler-output cache record has an unsupported descriptor family");
  }
  requireExactKeys(certificate.bridge, ["generatedC", "object"], "cohort capsule topology bridge");
  requireExactKeys(
    certificate.formatter,
    ["generatedC", "object"],
    "cohort capsule topology formatter"
  );
  if (canonicalJson(certificate.engine) !== canonicalJson(record.engine)) {
    fail("cohort capsule compiler-output topology engine disagrees with its record");
  }
  if (
    canonicalJson(certificate.bridge.generatedC.identity) !==
      canonicalJson(record.bridge.generatedCIdentity) ||
    canonicalJson(certificate.bridge.object.identity) !==
      canonicalJson(record.bridge.objectIdentity) ||
    canonicalJson(certificate.formatter.generatedC.identity) !==
      canonicalJson(record.formatter.generatedCIdentity) ||
    canonicalJson(certificate.formatter.object.identity) !==
      canonicalJson(record.formatter.objectIdentity)
  ) {
    fail("cohort capsule compiler-output topology identity disagrees with its record");
  }
  const descriptor = authenticateCompilerOutputTopologyDescriptor(
    certificate.descriptor,
    "cohort capsule compiler-output topology descriptor"
  );
  let expectedDescriptor;
  if (recordAuthority.schemaVersion === MODULE_GRAPH_COMPILER_OUTPUT_CACHE_RECORD_SCHEMA_VERSION) {
    // Schema 5 persists the exact topology descriptor used by the certificate. The record digest,
    // strict current lookup identity, and exact comparison below bind that compact authority without
    // restoring the retired full descriptor.
    expectedDescriptor = record.descriptor;
  } else {
    const recordDescriptor = record.descriptor;
    if (
      typeof recordDescriptor !== "object" ||
      recordDescriptor === null ||
      Array.isArray(recordDescriptor)
    ) {
      fail("cohort capsule compiler-output record descriptor is invalid");
    }
    requireExactKeys(
      recordDescriptor,
      ["applicationIdentity", "chunkUnitsIdentity", "identitySha256", "kind", "schemaVersion"],
      "cohort capsule compiler-output record descriptor"
    );
    if (
      recordDescriptor.kind !==
        "convex-wasm-official-output-module-graph-compiler-cache-descriptor-v1" ||
      recordDescriptor.schemaVersion !== 1 ||
      requireSha256(
        recordDescriptor.applicationIdentity?.sha256,
        "cohort capsule compiler-output record application identity SHA-256"
      ) !== recordDescriptor.identitySha256
    ) {
      fail("cohort capsule compiler-output record descriptor has an unsupported schema");
    }
    expectedDescriptor = {
      applicationIdentitySha256: requireSha256(
        recordDescriptor.applicationIdentity?.sha256,
        "cohort capsule compiler-output record application identity SHA-256"
      ),
      chunkUnitsIdentitySha256: requireSha256(
        recordDescriptor.chunkUnitsIdentity?.sha256,
        "cohort capsule compiler-output record chunk-units identity SHA-256"
      ),
      descriptorSha256: fingerprintJson(recordDescriptor),
      identitySha256: requireSha256(
        recordDescriptor.identitySha256,
        "cohort capsule compiler-output record descriptor identity SHA-256"
      ),
      kind: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_DESCRIPTOR_KIND,
      schemaVersion: 1,
    };
  }
  if (canonicalJson(descriptor) !== canonicalJson(expectedDescriptor)) {
    fail("cohort capsule compiler-output topology descriptor disagrees with its record");
  }
  authenticateTopologyCertificateStage(
    record.engineProbe,
    certificate.engineProbe,
    COMPILER_OUTPUT_AOT_EXTENSIONS,
    false,
    "cohort capsule compiler-output topology engine probe"
  );
  authenticateTopologyCertificateStage(
    record.bridge.generatedC,
    certificate.bridge.generatedC,
    COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
    true,
    "cohort capsule compiler-output topology bridge generated C"
  );
  authenticateTopologyCertificateStage(
    record.bridge.object,
    certificate.bridge.object,
    COMPILER_OUTPUT_OBJECT_EXTENSIONS,
    true,
    "cohort capsule compiler-output topology bridge object"
  );
  authenticateTopologyCertificateStage(
    record.formatter.generatedC,
    certificate.formatter.generatedC,
    COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
    true,
    "cohort capsule compiler-output topology formatter generated C"
  );
  authenticateTopologyCertificateStage(
    record.formatter.object,
    certificate.formatter.object,
    COMPILER_OUTPUT_OBJECT_EXTENSIONS,
    true,
    "cohort capsule compiler-output topology formatter object"
  );
  if (certificate.applicationUnits.length !== record.applicationUnits.length) {
    fail(
      "cohort capsule compiler-output topology application-unit count disagrees with its record"
    );
  }
  for (const [applicationUnitSlot, unit] of record.applicationUnits.entries()) {
    const certificateUnit = certificate.applicationUnits[applicationUnitSlot];
    requireExactKeys(
      certificateUnit,
      ["generatedC", "picObject"],
      `cohort capsule compiler-output topology application unit ${String(applicationUnitSlot)}`
    );
    authenticateTopologyCertificateStage(
      unit.generatedC,
      certificateUnit.generatedC,
      COMPILER_OUTPUT_GENERATED_C_EXTENSIONS,
      false,
      `cohort capsule compiler-output topology application unit ${String(applicationUnitSlot)} generated C`
    );
    authenticateTopologyCertificateStage(
      unit.picObject,
      certificateUnit.picObject,
      COMPILER_OUTPUT_OBJECT_EXTENSIONS,
      false,
      `cohort capsule compiler-output topology application unit ${String(applicationUnitSlot)} PIC object`
    );
  }
}

async function cohortCapsuleArtifactClosure(entry, cacheLayout, validation) {
  if (entry.stage !== OFFICIAL_OUTPUT_COHORT_CAPSULE_STAGE) return undefined;
  if (entry.artifactFile !== "artifact.json") {
    fail("cohort capsule cache entry does not contain JSON");
  }
  requireExactKeys(entry.metadata, ["kind", "schemaVersion"], "cohort capsule metadata");
  if (LEGACY_OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSIONS.has(entry.metadata.kind)) {
    if (!isLegacyOfficialOutputCohortCapsuleEntry(entry, entry.stage, entry.key)) {
      fail("cohort capsule legacy metadata does not match its cache identity");
    }
    // A rotated capsule cannot be selected by the current producer. Keep it as an ordinary
    // collectible artifact rather than making an existing legacy cache block current retention
    // planning.
    return undefined;
  }
  if (
    entry.metadata.kind !== OFFICIAL_OUTPUT_COHORT_CAPSULE_KIND ||
    entry.metadata.schemaVersion !== OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSION
  ) {
    fail("cohort capsule cache entry has invalid metadata");
  }
  requireExactKeys(
    entry.identity,
    ["capsuleIdentity", "kind", "schemaVersion"],
    "cohort capsule cache identity"
  );
  if (
    entry.identity.kind !== OFFICIAL_OUTPUT_COHORT_CAPSULE_KIND ||
    entry.identity.schemaVersion !== OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSION
  ) {
    fail("cohort capsule cache identity is invalid");
  }
  const capsuleIdentity = normalizeConvexWasmOfficialOutputCohortCapsuleIdentity(
    entry.identity.capsuleIdentity,
    "cohort capsule identity"
  );
  const payload = await readCanonical(
    entry.artifactPath,
    convexWasmOfficialOutputCohortCapsuleMaxBytes,
    "cohort capsule",
    entry
  );
  requireExactKeys(
    payload,
    ["identity", "kind", "planning", "schemaVersion", "sourceEnvelopeSha256"],
    "cohort capsule"
  );
  if (
    payload.kind !== OFFICIAL_OUTPUT_COHORT_CAPSULE_KIND ||
    payload.schemaVersion !== OFFICIAL_OUTPUT_COHORT_CAPSULE_SCHEMA_VERSION ||
    canonicalJson(payload.identity) !== canonicalJson(capsuleIdentity)
  ) {
    fail("cohort capsule payload is not bound to its cache identity");
  }
  requireSha256(payload.sourceEnvelopeSha256, "cohort capsule source-envelope SHA-256");
  const topology = payload.planning?.topology;
  requireExactKeys(
    topology,
    ["cacheIdentity", "cacheKey", "cacheRecordSha256", "certificateCacheKey", "descriptor"],
    "cohort capsule compiler-output topology"
  );
  // Close the current identity shape before deriving or following any immutable references. A kind
  // label alone does not authenticate the fields that define the compiler-output lookup key.
  const compilerOutputCacheIdentity = normalizeConvexWasmCompilerOutputCacheIdentity(
    topology.cacheIdentity,
    "cohort capsule compiler-output cache identity"
  );
  const compilerOutputCacheKey = requireSha256(
    topology.cacheKey,
    "cohort capsule compiler-output cache key"
  );
  if (
    compilerOutputCacheKey !==
    fingerprintJson({
      identity: compilerOutputCacheIdentity,
      kind: ARTIFACT_PIPELINE_KIND,
      stage: MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE,
    })
  ) {
    fail("cohort capsule compiler-output cache identity is invalid");
  }
  const topologyCacheIdentity = {
    compilerOutputCacheIdentity,
    compilerOutputCacheKey,
    kind: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND,
  };
  const topologyCertificateCacheKey = requireSha256(
    topology.certificateCacheKey,
    "cohort capsule compiler-output topology certificate key"
  );
  if (
    topologyCertificateCacheKey !==
    fingerprintJson({
      identity: topologyCacheIdentity,
      kind: ARTIFACT_PIPELINE_KIND,
      stage: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE,
    })
  ) {
    fail("cohort capsule compiler-output topology certificate identity is invalid");
  }
  const compilerOutputCacheRecordSha256 = requireSha256(
    topology.cacheRecordSha256,
    "cohort capsule compiler-output topology certificate record SHA-256"
  );
  const [compilerOutputMaterial, topologyCertificateMaterial] = await settleConcurrentWork([
    (async () => {
      const compilerOutputEntry = await validateArtifactCacheEntryInValidationScope(
        validation.artifacts,
        cacheLayout.cacheRoot,
        cacheLayout,
        MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE,
        compilerOutputCacheKey,
        "json",
        MAX_COMPILER_OUTPUT_CACHE_BYTES
      );
      if (compilerOutputEntry === undefined) {
        return undefined;
      }
      // A capsule topology is only consumable with the current full compiler-output record.
      // Legacy records cannot satisfy current closure merely because a certificate describes them.
      if (compilerOutputCacheEntrySchema(compilerOutputEntry) !== "current") {
        fail("cohort capsule compiler-output cache record has an unsupported schema");
      }
      const record = await readStructuredArtifact(compilerOutputEntry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "cohort capsule compiler-output cache record", validation);
      if (authenticatedStructuredDigests.get(record) !== compilerOutputCacheRecordSha256) {
        fail("cohort capsule compiler-output cache record digest is invalid");
      }
      authenticateCompilerOutputLookupIdentity(
        compilerOutputCacheIdentity,
        record,
        "cohort capsule compiler-output cache record"
      );
      return record;
    })(),
    (async () => {
      const topologyCertificateEntry = await validateArtifactCacheEntryInValidationScope(
        validation.artifacts,
        cacheLayout.cacheRoot,
        cacheLayout,
        MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE,
        topologyCertificateCacheKey,
        "json",
        MAX_COMPILER_OUTPUT_CACHE_BYTES
      );
      if (topologyCertificateEntry === undefined) {
        return undefined;
      }
      if (
        canonicalJson(topologyCertificateEntry.metadata) !==
        canonicalJson({ kind: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND })
      ) {
        fail("cohort capsule compiler-output topology certificate changed");
      }
      return {
        certificate: await readStructuredArtifact(topologyCertificateEntry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "cohort capsule compiler-output topology certificate", validation),
        entry: topologyCertificateEntry,
      };
    })(),
  ]);
  const missingDependencies = [
    ...(compilerOutputMaterial === undefined
      ? [
          {
            cacheKey: compilerOutputCacheKey,
            stage: MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE,
          },
        ]
      : []),
    ...(topologyCertificateMaterial === undefined
      ? [
          {
            cacheKey: topologyCertificateCacheKey,
            stage: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE,
          },
        ]
      : []),
  ];
  if (missingDependencies.length !== 0) {
    // A fully authenticated capsule whose referenced entry has already disappeared cannot grant
    // retention authority, but it is safe to treat the capsule itself as a collectible artifact.
    // This lets maintenance recover from interrupted/manual older cleanup without classifying
    // malformed capsule bytes or a changed dependency as an orphan.
    return { kind: "orphaned", missingDependencies };
  }
  const compilerOutputRecord = compilerOutputMaterial;
  const { certificate, entry: topologyCertificateEntry } = topologyCertificateMaterial;
  requireExactKeys(
    certificate,
    [
      "applicationUnits",
      "bridge",
      "cacheKey",
      "cacheRecordSha256",
      "descriptor",
      "engine",
      "engineProbe",
      "formatter",
      "kind",
      "schemaVersion",
    ],
    "cohort capsule compiler-output topology certificate"
  );
  if (
    certificate.kind !== MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND ||
    certificate.schemaVersion !== 4 ||
    certificate.cacheKey !== compilerOutputCacheKey ||
    certificate.cacheRecordSha256 !== compilerOutputCacheRecordSha256 ||
    canonicalJson(certificate.descriptor) !== canonicalJson(topology.descriptor) ||
    !Array.isArray(certificate.applicationUnits)
  ) {
    fail("cohort capsule compiler-output topology certificate has an unsupported schema");
  }
  authenticateCapsuleTopologyCertificate(
    certificate,
    compilerOutputRecord,
    authenticateCompilerOutputRecord(
      compilerOutputRecord,
      "cohort capsule compiler-output cache record"
    )
  );
  const topologyCertificateBytes = canonicalBytes(certificate);
  if (
    sha256(topologyCertificateBytes) !== topologyCertificateEntry.artifactSha256 ||
    topologyCertificateBytes.length !== topologyCertificateEntry.artifactSize
  ) {
    fail("cohort capsule compiler-output topology certificate is absent or changed");
  }
  return {
    closure: {
      compilerOutputCacheKey,
      compilerOutputCacheRecordSha256,
      topologyCertificateArtifactSha256: sha256(topologyCertificateBytes),
      topologyCertificateArtifactSize: topologyCertificateBytes.length,
      topologyCertificateCacheKey,
    },
    kind: "complete",
  };
}

async function authenticateGenericArtifact({ cacheLayout, key, metadata, path, stage, validation }) {
  // The family dispatch already read this metadata. It selects the expected extension only;
  // the scoped validator below authenticates the current entry and its complete payload.
  if (
    metadata.kind !== "convex-wasm-artifact-cache-entry-v5" ||
    metadata.stage !== stage ||
    metadata.key !== key
  ) {
    fail(`artifact entry identity is invalid: ${path}`);
  }
  if (typeof metadata.artifactFile !== "string" || !metadata.artifactFile.startsWith("artifact.")) {
    fail(`artifact entry extension is invalid: ${path}`);
  }
  const expectedExtension = metadata.artifactFile.slice("artifact.".length);
  if (!GENERIC_ARTIFACT_EXTENSIONS.has(expectedExtension)) {
    fail(`artifact entry extension is invalid: ${path}`);
  }
  const entry = await validateArtifactCacheEntryInValidationScope(
    validation.artifacts,
    cacheLayout.cacheRoot,
    cacheLayout,
    stage,
    key,
    expectedExtension,
    1024 * 1024 * 1024
  );
  if (entry === undefined) fail(`artifact entry disappeared during authentication: ${path}`);
  const [capsuleResolution, closureArtifactReferences, topologyCompilerOutputReference] =
    await settleConcurrentWork([
      cohortCapsuleArtifactClosure(entry, cacheLayout, validation),
      compilerOutputArtifactKeys(entry, validation),
      topologyCertificateCompilerOutputReference(entry, validation),
    ]);
  return {
    closureArtifactKeys: closureArtifactReferences.map(({ key }) => key),
    closureArtifactReferences,
    ...(capsuleResolution?.kind === "complete"
      ? { capsuleClosure: capsuleResolution.closure }
      : {}),
    ...(capsuleResolution?.kind === "orphaned"
      ? { orphanedCapsuleDependencies: capsuleResolution.missingDependencies }
      : {}),
    ...(topologyCompilerOutputReference === undefined ? {} : { topologyCompilerOutputReference }),
    key,
    path,
    stage,
    type: "artifact",
    entry,
  };
}

async function authenticateRuntimeHeaderSnapshot({ cacheLayout, key, path, stage }) {
  const snapshot = await authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry({
    cacheLayout,
    key,
    path,
    stage,
  });
  return { entry: snapshot.entry, key, path, stage, type: "artifact" };
}

async function authenticateArtifactFamily({ cacheLayout, key, metadata, path, stage, validation }) {
  if (
    metadata.kind === convexWasmRuntimeHeaderSnapshotCacheEntryKind ||
    stage === convexWasmRuntimeHeaderSnapshotCacheStage
  ) {
    return await authenticateRuntimeHeaderSnapshot({ cacheLayout, key, path, stage });
  }
  return await authenticateGenericArtifact({ cacheLayout, key, metadata, path, stage, validation });
}

async function authenticateCBundle({ cacheLayout, key, path, stage }) {
  const entry = await readCanonical(join(path, "entry.json"), MAX_METADATA_BYTES, "C bundle entry");
  requireExactKeys(
    entry,
    ["artifactSha256", "artifactSize", "bundle", "identity", "key", "kind", "metadata", "stage"],
    "C bundle entry"
  );
  if (
    entry.kind !== C_BUNDLE_ENTRY_KIND ||
    entry.stage !== stage ||
    entry.key !== key ||
    requireSha256(entry.artifactSha256, "C bundle entry artifact SHA-256") !==
      entry.artifactSha256 ||
    !Number.isSafeInteger(entry.artifactSize) ||
    entry.artifactSize <= 0
  ) {
    fail(`C bundle entry identity is invalid: ${path}`);
  }
  const bundle = normalizeStaticHermesCBundleOutput(entry.bundle, "C bundle entry bundle");
  const expectedNames = [
    "COMPLETE",
    "entry.json",
    bundle.manifest.path,
    ...staticHermesCBundleMembers(bundle).map(({ path: memberPath }) => memberPath),
  ].sort(compareStrings);
  const entryListing = await readStableDirectoryNames(path, "C bundle entry");
  const names = entryListing.names;
  if (canonicalJson(names) !== canonicalJson(expectedNames)) {
    fail(`C bundle entry has unexpected contents: ${path}`);
  }
  await settleConcurrentWork(
    names.map((name) => requirePrivateCacheFile(cacheLayout.cacheRoot, join(path, name)))
  );
  const currentEntry = await readCanonical(
    join(path, "entry.json"),
    MAX_METADATA_BYTES,
    "C bundle entry"
  );
  if (canonicalJson(currentEntry) !== canonicalJson(entry)) {
    fail(`C bundle entry changed while its members were being authenticated: ${path}`);
  }
  const complete = decodeUtf8(
    await readPrivateRegularFile(
      join(path, "COMPLETE"),
      MAX_COMPLETION_MARKER_BYTES,
      "C bundle entry completion marker"
    ),
    "C bundle entry completion marker"
  );
  if (complete !== `${key}\n`) fail(`C bundle entry completion marker is invalid: ${path}`);
  const authenticated = await authenticateStaticHermesCBundle(path, bundle, 1_024 * 1024 * 1024);
  if (
    authenticated.artifactSha256 !== entry.artifactSha256 ||
    authenticated.artifactSize !== entry.artifactSize
  ) {
    fail(`C bundle entry digest does not match its authenticated contents: ${path}`);
  }
  await settleConcurrentWork(
    ["COMPLETE", "entry.json"].map((name) =>
      requirePrivateCacheFile(cacheLayout.cacheRoot, join(path, name))
    )
  );
  const finalEntry = await readCanonical(
    join(path, "entry.json"),
    MAX_METADATA_BYTES,
    "C bundle entry"
  );
  if (canonicalJson(finalEntry) !== canonicalJson(entry)) {
    fail(`C bundle entry changed while its members were being authenticated: ${path}`);
  }
  const finalComplete = decodeUtf8(
    await readPrivateRegularFile(
      join(path, "COMPLETE"),
      MAX_COMPLETION_MARKER_BYTES,
      "C bundle entry completion marker"
    ),
    "C bundle entry completion marker"
  );
  if (finalComplete !== complete) {
    fail(
      `C bundle entry completion marker changed while its members were being authenticated: ${path}`
    );
  }
  await verifyStableDirectoryNames(path, entryListing, names, "C bundle entry");
  if (fingerprintJson({ kind: ARTIFACT_PIPELINE_KIND, stage, identity: entry.identity }) !== key) {
    fail(`C bundle entry identity does not match its key: ${path}`);
  }
  return { key, path, stage, type: "c-bundle", entry, bundle };
}

async function listArtifactEntries(cacheLayout, validation) {
  const root = cacheLayout.immutable.artifacts;
  const records = [];
  if (!(await exists(root))) return records;
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const rootListing = await readStableDirectoryNames(root, "artifact root");
  for (const stage of rootListing.names) {
    const stagePath = join(root, stage);
    const stageStatus = await pathInfo(stagePath);
    if (!stageStatus.isDirectory() || stageStatus.isSymbolicLink()) {
      fail(`artifact stage is not a non-symlink directory: ${stagePath}`);
    }
    await requirePrivateCacheDirectory(cacheLayout.cacheRoot, stagePath);
    const stageListing = await readStableDirectoryNames(stagePath, "artifact stage");
    // Publication scratch is not immutable authority. Keep inventory reads bounded, preserve
    // listing order and drain admitted reads on failure before the caller releases the cache lock.
    const keys = stageListing.names.filter((key) => !key.startsWith(".publish-"));
    const stageRecords = await mapBounded(keys, 4, async (key) => {
      if (!SHA256_PATTERN.test(key)) {
        fail(`artifact stage has an unexpected entry: ${join(stagePath, key)}`);
      }
      const path = join(stagePath, key);
      const status = await pathInfo(path);
      if (!status.isDirectory()) fail(`artifact cache entry is not a directory: ${path}`);
      try {
        const entryPath = join(path, "entry.json");
        await requirePrivateCacheFile(cacheLayout.cacheRoot, entryPath);
        const metadata = await readCanonical(entryPath, MAX_METADATA_BYTES, "artifact entry");
        if (
          stage === OFFICIAL_OUTPUT_COHORT_CAPSULE_STAGE &&
          metadata.kind !== "convex-wasm-artifact-cache-entry-v5"
        ) {
          fail("cohort capsule cache entry has an unsupported artifact family");
        }
        const authenticated =
          metadata.kind === C_BUNDLE_ENTRY_KIND
            ? await authenticateCBundle({ cacheLayout, key, path, stage })
            : await authenticateArtifactFamily({ cacheLayout, key, metadata, path, stage, validation });
        return { ...(await inventoryTreeStats(path, validation)), ...authenticated, authenticated: true };
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        // Legacy classification occurs inside cohortCapsuleArtifactClosure only after the generic
        // artifact wrapper and payload bytes authenticate. A malformed capsule of any generation
        // is corruption, not an age-bounded legacy candidate.
        if (stage === OFFICIAL_OUTPUT_COHORT_CAPSULE_STAGE) {
          throw new Error(`${error.message}; cohort capsule path: ${path}`, { cause: error });
        }
        let stats = {};
        try {
          stats = await inventoryTreeStats(path, validation);
        } catch {
          // Keep an unsafe or disappearing object in the invalid set without granting authority.
        }
        return {
          ...stats,
          path,
          key,
          stage,
          type: "artifact",
          authenticated: false,
          reason: "authentication-failed",
        };
      }
    });
    for (const record of stageRecords) records.push(record);
    await verifyStableDirectoryNames(stagePath, stageListing, stageListing.names, "artifact stage");
  }
  await verifyStableDirectoryNames(root, rootListing, rootListing.names, "artifact root");
  return records;
}

function legacyV2ArtifactReference(value, description) {
  requireExactKeys(value, ["cacheKey", "sha256", "size", "stage"], description);
  const stage = requireNonEmptyString(value.stage, `${description} stage`);
  if (stage.includes("/") || stage.includes("\\")) {
    fail(`${description} stage is invalid`);
  }
  return {
    cacheKey: requireSha256(value.cacheKey, `${description} cache key`),
    sha256: requireSha256(value.sha256, `${description} SHA-256`),
    size: requirePositiveSafeInteger(value.size, `${description} size`),
    stage,
  };
}

function legacyV2PackageFileMaterial(value, bytes, description) {
  requireExactKeys(value, ["sha256", "size"], description);
  if (
    requireSha256(value.sha256, `${description} SHA-256`) !== sha256(bytes) ||
    requirePositiveSafeInteger(value.size, `${description} size`) !== bytes.length
  ) {
    fail(`${description} does not authenticate its package file`);
  }
}

function legacyV2ModuleGraphPackageTriple({ entry, key, manifest, provenance }) {
  const manifestFields = Object.hasOwn(manifest, "sharedShards")
    ? [
        "engine",
        "graphManifestSha256",
        "hostAbi",
        "initialization",
        "kind",
        "modules",
        "producerImplementation",
        "replacement",
        "routing",
        "schemaVersion",
        "sharedShards",
        "toolchain",
      ]
    : [
        "engine",
        "graphManifestSha256",
        "hostAbi",
        "initialization",
        "kind",
        "modules",
        "producerImplementation",
        "replacement",
        "routing",
        "schemaVersion",
        "toolchain",
      ];
  requireExactKeys(manifest, manifestFields, "legacy v2 module graph manifest");
  if (manifest.kind !== MODULE_GRAPH_MANIFEST_V2_KIND || manifest.schemaVersion !== 2) {
    fail("legacy module graph manifest has an unsupported kind or schema version");
  }
  const manifestKey = requireSha256(
    manifest.graphManifestSha256,
    "legacy module graph manifest SHA-256"
  );
  const { graphManifestSha256: ignoredGraphManifestSha256, ...manifestPayload } = manifest;
  if (manifestKey !== key || fingerprintJson(manifestPayload) !== manifestKey) {
    fail("legacy module graph manifest does not authenticate its key");
  }
  if (
    !Array.isArray(manifest.modules) ||
    manifest.modules.length === 0 ||
    manifest.modules.length > MAX_LEGACY_MODULE_GRAPH_PACKAGE_MODULES
  ) {
    fail("legacy module graph manifest has an invalid module set");
  }
  const modules = manifest.modules.map((module, index) => {
    if (typeof module !== "object" || module === null || Array.isArray(module)) {
      fail(`legacy module graph manifest module ${String(index)} is invalid`);
    }
    const role = requireNonEmptyString(
      module.role,
      `legacy module graph manifest module ${String(index)} role`
    );
    if (
      typeof module.contract !== "object" ||
      module.contract === null ||
      Array.isArray(module.contract)
    ) {
      fail(`legacy module graph manifest module ${String(index)} contract is invalid`);
    }
    if (
      typeof module.artifacts !== "object" ||
      module.artifacts === null ||
      Array.isArray(module.artifacts)
    ) {
      fail(`legacy module graph manifest module ${String(index)} artifacts are invalid`);
    }
    requireExactKeys(
      module.artifacts,
      ["aot", "coreWasm"],
      `legacy module graph manifest module ${String(index)} artifacts`
    );
    return {
      aot: legacyV2ArtifactReference(
        module.artifacts.aot,
        `legacy module graph manifest module ${String(index)} AOT`
      ),
      coreWasm: legacyV2ArtifactReference(
        module.artifacts.coreWasm,
        `legacy module graph manifest module ${String(index)} Core Wasm`
      ),
      contract: module.contract,
      role,
    };
  });
  const roles = modules.map(({ role }) => role).sort(compareStrings);
  if (new Set(roles).size !== roles.length)
    fail("legacy module graph manifest has duplicate roles");

  const provenanceFields = Object.hasOwn(manifest, "sharedShards")
    ? [
        "engine",
        "hostAbi",
        "identities",
        "kind",
        "producerIdentity",
        "routing",
        "schemaVersion",
        "sharedShards",
        "toolchain",
      ]
    : [
        "engine",
        "hostAbi",
        "identities",
        "kind",
        "producerIdentity",
        "routing",
        "schemaVersion",
        "toolchain",
      ];
  requireExactKeys(provenance, provenanceFields, "legacy v2 module graph provenance");
  if (provenance.kind !== MODULE_GRAPH_PROVENANCE_V2_KIND || provenance.schemaVersion !== 2) {
    fail("legacy module graph provenance has an unsupported kind or schema version");
  }
  if (
    canonicalJson(provenance.engine) !== canonicalJson(manifest.engine) ||
    canonicalJson(provenance.hostAbi) !== canonicalJson(manifest.hostAbi) ||
    canonicalJson(provenance.routing) !== canonicalJson(manifest.routing) ||
    canonicalJson(provenance.toolchain) !== canonicalJson(manifest.toolchain) ||
    canonicalJson(provenance.sharedShards) !== canonicalJson(manifest.sharedShards)
  ) {
    fail("legacy module graph provenance disagrees with its manifest");
  }
  requireExactKeys(provenance.identities, roles, "legacy module graph provenance identities");
  for (const role of roles) {
    requireExactKeys(
      provenance.identities[role],
      ["aot", "coreWasm"],
      `legacy module graph provenance identity ${role}`
    );
  }
  requireExactKeys(
    manifest.producerImplementation,
    ["kind", "sha256"],
    "legacy module graph manifest producer implementation"
  );
  if (
    typeof provenance.producerIdentity !== "object" ||
    provenance.producerIdentity === null ||
    Array.isArray(provenance.producerIdentity) ||
    canonicalJson(manifest.producerImplementation) !==
      canonicalJson({
        kind: provenance.producerIdentity.kind,
        sha256: provenance.producerIdentity.sha256,
      })
  ) {
    fail("legacy module graph provenance producer identity disagrees with its manifest");
  }
  requireNonEmptyString(manifest.producerImplementation.kind, "legacy module graph producer kind");
  requireSha256(manifest.producerImplementation.sha256, "legacy module graph producer SHA-256");

  requireExactKeys(
    entry,
    ["artifacts", "key", "kind", "manifest", "provenance"],
    "legacy v2 module graph package entry"
  );
  if (
    entry.kind !== MODULE_GRAPH_PACKAGE_V2_KIND ||
    requireSha256(entry.key, "legacy module graph package entry key") !== key
  ) {
    fail("legacy module graph package entry has an unsupported kind or key");
  }
  legacyV2PackageFileMaterial(
    entry.manifest,
    canonicalBytes(manifest),
    "legacy module graph package entry manifest"
  );
  legacyV2PackageFileMaterial(
    entry.provenance,
    canonicalBytes(provenance),
    "legacy module graph package entry provenance"
  );
  requireExactKeys(entry.artifacts, roles, "legacy module graph package entry artifacts");
  for (const { aot, coreWasm, role } of modules) {
    requireExactKeys(
      entry.artifacts[role],
      ["aot", "coreWasm"],
      `legacy module graph package entry artifact ${role}`
    );
    if (
      canonicalJson(
        legacyV2ArtifactReference(
          entry.artifacts[role].aot,
          `legacy module graph package entry AOT ${role}`
        )
      ) !== canonicalJson(aot) ||
      canonicalJson(
        legacyV2ArtifactReference(
          entry.artifacts[role].coreWasm,
          `legacy module graph package entry Core Wasm ${role}`
        )
      ) !== canonicalJson(coreWasm)
    ) {
      fail(`legacy module graph package entry artifact ${role} disagrees with its manifest`);
    }
  }
  return modules.map((module) => ({
    ...module,
    aotIdentity: provenance.identities[module.role].aot,
    coreWasmIdentity: provenance.identities[module.role].coreWasm,
  }));
}

async function readLegacyV2ModuleGraphPackage(cacheLayout, key, path, firstManifest) {
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, path);
  const names = (await fs.readdir(path)).sort(compareStrings);
  if (
    canonicalJson(names) !==
    canonicalJson([
      "COMPLETE",
      "build-provenance.json",
      "graph-manifest.json",
      "package-entry.json",
    ])
  ) {
    fail(`legacy module graph package has unexpected contents: ${path}`);
  }
  await settleConcurrentWork(
    ["COMPLETE", "build-provenance.json", "graph-manifest.json", "package-entry.json"].map((name) =>
      requirePrivateCacheFile(cacheLayout.cacheRoot, join(path, name))
    )
  );
  const [complete, provenance, entry] = await settleConcurrentWork([
    readPrivateRegularFile(
      join(path, "COMPLETE"),
      65,
      "legacy module graph package completion marker"
    ),
    readCanonical(
      join(path, "build-provenance.json"),
      MAX_METADATA_BYTES,
      "legacy module graph provenance"
    ),
    readCanonical(
      join(path, "package-entry.json"),
      MAX_METADATA_BYTES,
      "legacy module graph package entry"
    ),
  ]);
  const manifest =
    firstManifest ??
    (await readCanonical(
      join(path, "graph-manifest.json"),
      MAX_METADATA_BYTES,
      "legacy module graph manifest"
    ));
  if (decodeUtf8(complete, "legacy module graph package completion marker") !== `${key}\n`) {
    fail(`legacy module graph package completion marker is invalid: ${path}`);
  }
  return { entry, manifest, provenance };
}

async function authenticateLegacyV2Package({
  cacheLayout,
  expectedGraphManifest,
  key,
  manifest: initialManifest,
  path,
  validation,
}) {
  const first = await readLegacyV2ModuleGraphPackage(cacheLayout, key, path, initialManifest);
  const modules = legacyV2ModuleGraphPackageTriple({ ...first, key });
  if (
    expectedGraphManifest !== undefined &&
    canonicalJson(expectedGraphManifest) !== canonicalJson(first.manifest)
  ) {
    fail(`legacy module graph package manifest disagrees with its authenticated binding: ${path}`);
  }
  await settleConcurrentWork(
    modules.flatMap(({ aot, aotIdentity, contract, coreWasm, coreWasmIdentity, role }) => [
      (async () => {
        const entry = await validateArtifactCacheEntryInValidationScope(
          validation.artifacts,
          cacheLayout.cacheRoot,
          cacheLayout,
          coreWasm.stage,
          coreWasm.cacheKey,
          "wasm",
          320 * 1024 * 1024
        );
        if (
          entry === undefined ||
          entry.artifactSha256 !== coreWasm.sha256 ||
          entry.artifactSize !== coreWasm.size ||
          canonicalJson(entry.identity) !== canonicalJson(coreWasmIdentity) ||
          canonicalJson(entry.metadata) !== canonicalJson({ contract })
        ) {
          fail(`legacy ${role} module package Core Wasm does not match its authenticated artifact`);
        }
      })(),
      (async () => {
        const entry = await validateArtifactCacheEntryInValidationScope(
          validation.artifacts,
          cacheLayout.cacheRoot,
          cacheLayout,
          aot.stage,
          aot.cacheKey,
          "cwasm",
          1024 * 1024 * 1024
        );
        if (
          entry === undefined ||
          entry.artifactSha256 !== aot.sha256 ||
          entry.artifactSize !== aot.size ||
          canonicalJson(entry.identity) !== canonicalJson(aotIdentity)
        ) {
          fail(`legacy ${role} module package AOT does not match its authenticated artifact`);
        }
      })(),
    ])
  );
  const second = await readLegacyV2ModuleGraphPackage(cacheLayout, key, path);
  if (
    canonicalJson(first.entry) !== canonicalJson(second.entry) ||
    canonicalJson(first.manifest) !== canonicalJson(second.manifest) ||
    canonicalJson(first.provenance) !== canonicalJson(second.provenance)
  ) {
    fail(`legacy module graph package changed while its artifacts were verified: ${path}`);
  }
  return {
    graphManifest: first.manifest,
    key,
    packageMaterial: {
      artifactReferences: modules
        .map(({ aot, coreWasm, role }) => ({
          aot: { artifact: aot },
          coreWasm: { artifact: coreWasm },
          role,
        }))
        .sort((left, right) => compareStrings(left.role, right.role)),
    },
    path,
  };
}

async function authenticatePackage(cacheLayout, key, path, validation, packageMaterial, expectedGraphManifest) {
  requireSha256(key, "module graph package key");
  // Certificate contracts derive this path from untrusted cache bytes. Validate the complete
  // private package directory before reading its manifest so an already replaced or symlinked
  // package path cannot redirect the initial read outside the immutable cache.
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, path);
  const manifest = await readCanonical(
    join(path, "graph-manifest.json"),
    MAX_METADATA_BYTES,
    "module graph package manifest version"
  );
  let verified;
  if (manifest.kind === MODULE_GRAPH_MANIFEST_V2_KIND && manifest.schemaVersion === 2) {
    if (packageMaterial !== undefined) {
      fail("legacy module graph package cannot use current package material");
    }
    verified = await authenticateLegacyV2Package({
      cacheLayout,
      expectedGraphManifest,
      key,
      manifest,
      path,
      validation,
    });
  } else if (
    (manifest.kind === MODULE_GRAPH_MANIFEST_V3_KIND && manifest.schemaVersion === 3) ||
    (manifest.kind === MODULE_GRAPH_MANIFEST_V5_KIND && manifest.schemaVersion === 5)
  ) {
    verified = await loadAndVerifyConvexWasmModuleGraphPackageInValidationScope({
      cacheLayout,
      cacheRoot: cacheLayout.cacheRoot,
      ...(packageMaterial === undefined ? {} : { authenticatedPackageMaterial: packageMaterial }),
      ...(expectedGraphManifest === undefined ? {} : { expectedGraphManifest }),
      graphManifestSha256: key,
      packagePath: path,
    }, validation.packages, validation.artifacts);
  } else fail("module graph package manifest has an unsupported kind or schema version");
  return {
    key,
    path,
    type: "package",
    artifactKeys: verified.packageMaterial.artifactReferences.flatMap((reference) => [
      `${reference.aot.artifact.stage}\0${reference.aot.artifact.cacheKey}`,
      `${reference.coreWasm.artifact.stage}\0${reference.coreWasm.artifact.cacheKey}`,
    ]),
  };
}

async function listPackages(cacheLayout, validation) {
  const root = cacheLayout.immutable.packages;
  const records = [];
  if (!(await exists(root))) return records;
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const rootListing = await readStableDirectoryNames(root, "package root");
  for (const key of rootListing.names) {
    // Package publishers use private .publish-* siblings and cleanup is intentionally separate
    // from authority. Treat stale publication scratch as non-authoritative residue so one crash
    // cannot block retention of unrelated complete packages.
    if (key.startsWith(".publish-")) continue;
    if (key === "deployment-results") {
      const deploymentResultsRoot = join(root, key);
      if (!(await pathInfo(deploymentResultsRoot)).isDirectory()) {
        fail(`deployment-results root is not a directory: ${deploymentResultsRoot}`);
      }
      await requirePrivateCacheDirectory(cacheLayout.cacheRoot, deploymentResultsRoot);
      continue;
    }
    if (!SHA256_PATTERN.test(key)) {
      fail(`package root has an unexpected entry: ${join(root, key)}`);
    }
    const path = join(root, key);
    const status = await pathInfo(path);
    if (!status.isDirectory()) fail(`module graph package is not a directory: ${path}`);
    try {
      const verified = await authenticatePackage(cacheLayout, key, path, validation);
      records.push({ ...(await inventoryTreeStats(path, validation)), ...verified, authenticated: true });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      let stats = {};
      try {
        stats = await inventoryTreeStats(path, validation);
      } catch {
        // Keep an unsafe or disappearing object in the invalid set without granting authority.
      }
      records.push({
        ...stats,
        path,
        key,
        type: "package",
        authenticated: false,
        reason: "authentication-failed",
      });
    }
  }
  await verifyStableDirectoryNames(root, rootListing, rootListing.names, "package root");
  return records;
}

function certificatePackageContracts(certificate) {
  if (
    certificate.schemaVersion !== 1 &&
    certificate.schemaVersion !== 2 &&
    certificate.schemaVersion !== 3 &&
    certificate.schemaVersion !== 4
  ) {
    fail("deployment certificate has an unsupported schema");
  }
  const compact = certificate.schemaVersion === 3 || certificate.schemaVersion === 4;
  const field = compact ? "packageReferences" : "packageGraphs";
  const contracts = certificate[field];
  if (!Array.isArray(contracts) || contracts.length === 0)
    fail("certificate has no package contracts");
  const normalized = contracts.map((contract, index) => {
    requireExactKeys(
      contract,
      compact
        ? ["graphManifestSha256", "packageMaterial"]
        : certificate.schemaVersion === 1
          ? ["graphManifest", "graphManifestSha256"]
          : ["graphManifest", "graphManifestSha256", "packageMaterial"],
      `certificate package contract ${String(index)}`
    );
    if (
      compact &&
      (typeof contract.packageMaterial !== "object" ||
        contract.packageMaterial === null ||
        Array.isArray(contract.packageMaterial) ||
        contract.packageMaterial.schemaVersion !== 2)
    ) {
      fail("compact certificate package material must use schema version 2");
    }
    return {
      key: requireSha256(contract.graphManifestSha256, "certificate package key"),
      packageMaterial: certificate.schemaVersion === 1 ? undefined : contract.packageMaterial,
      graphManifest: compact ? undefined : contract.graphManifest,
    };
  });
  const expected = normalized.map(({ key }) => key).sort(compareStrings);
  if (canonicalJson(expected) !== canonicalJson(normalized.map(({ key }) => key))) {
    fail("certificate package references are not sorted");
  }
  if (new Set(expected).size !== expected.length) {
    fail("certificate package references contain duplicates");
  }
  return normalized;
}

async function authenticateCertificateRoot(cacheLayout, lookupKey, lookupRoot, validation) {
  // Validate every lookup root, including an empty legacy root. Otherwise a root containing no
  // certificate entries could bypass the private owner/mode checks applied to its children.
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, lookupRoot);
  const lookupListing = await readStableCertificateLookupNames(lookupRoot);
  const lookupNames = lookupListing.names;
  for (const name of lookupNames) {
    if (name !== "PREFERRED" && !name.startsWith(".publish-") && !SHA256_PATTERN.test(name)) {
      fail(`certificate lookup root has an unexpected entry: ${join(lookupRoot, name)}`);
    }
  }
  const names = lookupNames.filter((name) => SHA256_PATTERN.test(name)).sort(compareStrings);
  if (names.length > MAX_CERTIFICATE_CANDIDATES) {
    fail(
      `certificate lookup root has more than ${MAX_CERTIFICATE_CANDIDATES} candidates: ${lookupRoot}`
    );
  }
  // PREFERRED selects ordinary lookup, but exact certificate reads can still open superseded
  // entries. Authenticate each certificate and preserve its package closure until that entry
  // is removed; the pointer cannot make an extant certificate safe to orphan.
  let preferredSourceAtListing;
  let preferredFileIdentity;
  if (lookupNames.includes("PREFERRED")) {
    const preferredPath = join(lookupRoot, "PREFERRED");
    await requirePrivateCacheFile(cacheLayout.cacheRoot, preferredPath);
    preferredFileIdentity = await fs.lstat(preferredPath);
    preferredSourceAtListing = decodeUtf8(
      await readPrivateRegularFile(
        preferredPath,
        MAX_COMPLETION_MARKER_BYTES,
        "certificate preferred pointer",
        preferredFileIdentity
      ),
      "certificate preferred pointer"
    );
    if (!/^[0-9a-f]{64}\n$/u.test(preferredSourceAtListing)) {
      fail(`certificate preferred pointer is invalid: ${lookupRoot}`);
    }
    const preferred = preferredSourceAtListing.slice(0, -1);
    if (!names.includes(preferred)) {
      fail(`certificate preferred pointer does not name a complete certificate: ${lookupRoot}`);
    }
  }
  const certificates = [];
  const missingPackageKeys = new Set();
  for (const key of names) {
    const path = join(lookupRoot, key);
    // Certificate contents are authority-bearing data. Validate the entry directory before
    // opening any child so a hash-named symlink cannot redirect reads outside the immutable
    // cache tree.
    await requirePrivateCacheDirectory(cacheLayout.cacheRoot, path);
    const entryListing = await readStableDirectoryNames(path, "certificate entry");
    const entryNames = entryListing.names;
    if (canonicalJson(entryNames) !== canonicalJson(["COMPLETE", "certificate.json"])) {
      fail(`certificate entry has unexpected contents: ${path}`);
    }
    const authenticatedFiles = await requirePrivateCacheDirectoryFileIdentities(
      cacheLayout.cacheRoot,
      path
    );
    if (authenticatedFiles === undefined) {
      fail(`certificate entry disappeared during authentication: ${path}`);
    }
    if (canonicalJson(authenticatedFiles.names) !== canonicalJson(entryNames)) {
      fail(`certificate entry contents changed while its files were authenticated: ${path}`);
    }
    if (
      decodeUtf8(
        await readPrivateRegularFile(
          join(path, "COMPLETE"),
          MAX_COMPLETION_MARKER_BYTES,
          "deployment certificate completion marker",
          authenticatedFiles.fileIdentities.get("COMPLETE")
        ),
        "deployment certificate completion marker"
      ) !== `${key}\n`
    ) {
      fail(`certificate completion marker is invalid: ${path}`);
    }
    const certificate = await readCanonical(
      join(path, "certificate.json"),
      MAX_CERTIFICATE_BYTES,
      "deployment certificate",
      undefined,
      authenticatedFiles.fileIdentities.get("certificate.json")
    );
    if (certificate.kind !== CERTIFICATE_KIND || certificate.certificateSha256 !== key)
      fail(`certificate key is invalid: ${path}`);
    const { certificateSha256: ignored, ...payload } = certificate;
    if (
      fingerprintJson(payload) !== key ||
      fingerprintJson(certificate.lookupIdentity) !== lookupKey
    )
      fail(`certificate authentication failed: ${path}`);
    const contracts = certificatePackageContracts(certificate);
    let missingPackageDependency = false;
    const boundCohorts = certificate.manifest?.moduleGraphBinding?.cohorts;
    if (
      !Array.isArray(boundCohorts) ||
      canonicalJson(
        boundCohorts.map((cohort) => cohort?.graphManifestSha256).sort(compareStrings)
      ) !== canonicalJson(contracts.map(({ key }) => key))
    ) {
      fail(`certificate package binding is invalid: ${path}`);
    }
    for (const contract of contracts) {
      const packagePath = join(cacheLayout.immutable.packages, contract.key);
      if (!(await exists(packagePath))) {
        missingPackageKeys.add(contract.key);
        missingPackageDependency = true;
        continue;
      }
      const verified = await authenticatePackage(
        cacheLayout,
        contract.key,
        packagePath,
        validation,
        contract.packageMaterial,
        contract.graphManifest
      );
      if (verified.key !== contract.key) {
        fail(`certificate package authentication failed: ${contract.key}`);
      }
    }
    const finalCertificate = await readCanonical(
      join(path, "certificate.json"),
      MAX_CERTIFICATE_BYTES,
      "deployment certificate",
      undefined,
      authenticatedFiles.fileIdentities.get("certificate.json")
    );
    if (canonicalJson(finalCertificate) !== canonicalJson(certificate)) {
      fail(`deployment certificate changed while its packages were authenticated: ${path}`);
    }
    const finalComplete = decodeUtf8(
      await readPrivateRegularFile(
        join(path, "COMPLETE"),
        MAX_COMPLETION_MARKER_BYTES,
        "deployment certificate completion marker",
        authenticatedFiles.fileIdentities.get("COMPLETE")
      ),
      "deployment certificate completion marker"
    );
    if (finalComplete !== `${key}\n`) {
      fail(
        `deployment certificate completion marker changed while its packages were authenticated: ${path}`
      );
    }
    await authenticatedFiles.verify();
    // Only package keys are needed after authentication. Superseded legacy certificates can
    // embed large manifests; retaining those payloads would multiply the planner's memory use.
    certificates.push({
      ...(await inventoryTreeStats(path, validation)),
      type: "certificate-entry",
      stage: lookupKey,
      ...(preferredSourceAtListing === `${key}\n` ? { removePreferred: true } : {}),
      authenticated: !missingPackageDependency,
      key,
      packageKeys: contracts.map(({ key }) => key),
      path,
    });
    await verifyStableDirectoryNames(path, entryListing, entryNames, "certificate entry");
  }
  if (preferredSourceAtListing !== undefined) {
    const preferredPath = join(lookupRoot, "PREFERRED");
    await requirePrivateCacheFile(cacheLayout.cacheRoot, preferredPath);
    const finalPreferredSource = decodeUtf8(
      await readPrivateRegularFile(
        preferredPath,
        MAX_COMPLETION_MARKER_BYTES,
        "certificate preferred pointer",
        preferredFileIdentity
      ),
      "certificate preferred pointer"
    );
    if (finalPreferredSource !== preferredSourceAtListing) {
      fail(
        `certificate preferred pointer changed while certificates were authenticated: ${lookupRoot}`
      );
    }
  }
  await verifyStableDirectoryNames(
    lookupRoot,
    lookupListing,
    lookupListing.names,
    "certificate lookup root",
    ".publish-"
  );
  const packageKeys = [
    ...new Set(certificates.flatMap(({ packageKeys }) => packageKeys)),
  ].sort(compareStrings);
  if (missingPackageKeys.size !== 0) {
    // The certificate bytes still authenticate, but an older cleanup removed some package
    // directories. Keep independently complete siblings available to deployed retention,
    // but do not authorize removal of the incomplete lookup root. Invalid present packages fail above.
    return {
      ...(await inventoryTreeStats(lookupRoot, validation)),
      authenticated: false,
      certificates,
      key: lookupKey,
      missingPackageKeys: [...missingPackageKeys].sort(compareStrings),
      packageKeys,
      path: lookupRoot,
      reason: "missing-package-dependency",
      type: "certificate-root",
    };
  }
  return {
    ...(await inventoryTreeStats(lookupRoot, validation)),
    path: lookupRoot,
    key: lookupKey,
    type: "certificate-root",
    packageKeys,
    certificates,
    authenticated: true,
  };
}

async function listCertificates(cacheLayout, validation) {
  const root = join(cacheLayout.immutable.packages, "deployment-results", "v1");
  const records = [];
  if (!(await exists(root))) {
    // A missing v1 root is an ordinary empty certificate namespace, but existing ancestors still
    // must remain private. In particular, do not let a dangling or redirected deployment-results
    // directory turn an outside tree into an apparent cache miss.
    try {
      await requirePrivateCacheDirectory(cacheLayout.cacheRoot, join(root, ".."));
    } catch (error) {
      if (missing(error)) return records;
      throw error;
    }
    return records;
  }
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const rootListing = await readStableDirectoryNames(root, "certificate root");
  for (const lookupKey of rootListing.names) {
    if (!SHA256_PATTERN.test(lookupKey)) {
      fail(`certificate root has an unexpected entry: ${join(root, lookupKey)}`);
    }
    const lookupRoot = join(root, lookupKey);
    if (!(await pathInfo(lookupRoot)).isDirectory())
      fail(`certificate lookup root is not a directory: ${lookupRoot}`);
    try {
      records.push(
        await authenticateCertificateRoot(cacheLayout, lookupKey, lookupRoot, validation)
      );
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      let stats = {};
      try {
        stats = await inventoryTreeStats(lookupRoot, validation);
      } catch {
        // Keep an unsafe or disappearing object in the invalid set without granting authority.
      }
      records.push({
        ...stats,
        path: lookupRoot,
        key: lookupKey,
        type: "certificate-root",
        authenticated: false,
        reason: "authentication-failed",
      });
    }
  }
  await verifyStableDirectoryNames(root, rootListing, rootListing.names, "certificate root");
  return records;
}

async function listSnapshots(cacheLayout) {
  const root = deploymentSnapshotRoot(cacheLayout.cacheRoot);
  if (!(await exists(root))) return [];
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const path = join(root, "current.json");
  if (!(await exists(path))) return [];
  await requirePrivateCacheFile(cacheLayout.cacheRoot, path);
  const status = await fs.lstat(path);
  // Keep the identity as JSON data because snapshots are retained in the derived inventory
  // index. Passing fs.Stats through the index would make canonical serialization fail, while
  // these fields are the complete identity required by readPrivateRegularFile.
  const fileIdentity = {
    dev: status.dev,
    ino: status.ino,
    mode: status.mode,
    mtimeMs: status.mtimeMs,
    size: status.size,
    uid: status.uid,
  };
  const snapshot = await readCanonical(
    path, MAX_DEPLOYMENT_SNAPSHOT_BYTES, "deployed snapshot", undefined, fileIdentity
  );
  const { snapshotSha256, ...payload } = snapshot;
  requireExactKeys(snapshot, [
    "buildId", "certificateSha256s", "compilerOutputKeys", "deploymentSha256", "kind",
    "packageKeys", "recordedAtMs", "schemaVersion", "snapshotSha256",
  ], "deployed snapshot");
  if (snapshot.kind !== SNAPSHOT_KIND || snapshot.schemaVersion !== 2 ||
      fingerprintJson(payload) !== snapshotSha256 ||
      !Number.isSafeInteger(snapshot.recordedAtMs) || snapshot.recordedAtMs < 0) {
    fail("deployed snapshot authentication failed");
  }
  requireSha256(snapshot.deploymentSha256, "deployed snapshot SHA-256");
  const normalized = {
    certificateSha256s: requireSha256List(snapshot.certificateSha256s,
      "deployed certificate SHA-256 values", MAX_DEPLOYMENT_SNAPSHOT_CERTIFICATES),
    compilerOutputKeys: requireSha256List(snapshot.compilerOutputKeys,
      "deployed compiler-output cache keys", MAX_DEPLOYMENT_SNAPSHOT_COMPILER_OUTPUTS),
    packageKeys: requireSha256List(snapshot.packageKeys,
      "deployed package SHA-256 values", MAX_DEPLOYMENT_SNAPSHOT_PACKAGES),
  };
  const finalSnapshot = await readCanonical(
    path, MAX_DEPLOYMENT_SNAPSHOT_BYTES, "deployed snapshot", undefined, fileIdentity
  );
  if (canonicalJson(finalSnapshot) !== canonicalJson(snapshot)) {
    fail("deployed snapshot changed while its authority was authenticated");
  }
  return [{ path, name: "current.json", fileIdentity, rawSnapshot: snapshot,
    snapshot: normalized, authenticated: true }];
}

async function exists(path) {
  try {
    await fs.lstat(path);
    return true;
  } catch (error) {
    if (missing(error)) return false;
    throw error;
  }
}

async function immutableCacheAllocatedBytesMeasured(cacheLayout) {
  if (!(await exists(cacheLayout.immutable.root))) return 0;
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, cacheLayout.immutable.root);
  const rootStatus = await fs.lstat(cacheLayout.immutable.root);
  // Occupancy reports count the root's contents. Use the same boundary for pressure so an
  // explicit sweep cannot evict an entry when measured occupancy is already at its watermark.
  return (await treeStats(cacheLayout.immutable.root, false)).allocatedBytes - rootStatus.blocks * 512;
}

function immutableSweepTrashRoot(cacheLayout) {
  return join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash");
}

function immutableSweepQuarantineRecord(planSha256, candidate) {
  const payload = {
    candidate,
    kind: "convex-wasm-immutable-gc-quarantine-v1",
    planSha256: requireSha256(planSha256, "immutable sweep plan SHA-256"),
  };
  const record = { ...payload, candidateSha256: fingerprintJson(payload) };
  if (canonicalBytes(record).length > MAX_SWEEP_QUARANTINE_RECORD_BYTES) {
    fail(`immutable sweep quarantine record exceeds ${MAX_SWEEP_QUARANTINE_RECORD_BYTES} bytes`);
  }
  return record;
}

// New sweeps use one durable record for a whole deletion wave. The record contains only the
// source roots and their authenticated candidate identities; the moved trees themselves remain
// the recovery payload. Keeping the record at wave scope removes the per-entry marker and fsync
// cost without allowing an unrecorded rename to become deletion authority.
function immutableSweepJournal(plan) {
  const entries = plan.evictions.map((candidate) => {
    const quarantineRecord = immutableSweepQuarantineRecord(plan.planSha256, candidate);
    return {
      candidateSha256: quarantineRecord.candidateSha256,
      path: candidate.path,
    };
  }).sort((left, right) => compareStrings(left.candidateSha256, right.candidateSha256));
  const payload = {
    entries,
    kind: IMMUTABLE_SWEEP_JOURNAL_KIND,
    planSha256: requireSha256(plan.planSha256, "immutable sweep journal plan SHA-256"),
  };
  const journal = { ...payload, journalSha256: fingerprintJson(payload) };
  if (canonicalBytes(journal).length > MAX_SWEEP_JOURNAL_BYTES) {
    fail(`immutable sweep journal exceeds ${MAX_SWEEP_JOURNAL_BYTES} bytes`);
  }
  return journal;
}

function matchesQuarantineCandidateTree(stats, candidate) {
  if (candidate.physicalStateIdentity !== undefined) {
    if (stats.treeIdentity !== candidate.physicalStateIdentity) return false;
    // Older durable markers also carry the full inode summary. New markers use the digest in
    // both fields so large bundles cannot exceed the bounded quarantine record size.
    if (candidate.treeIdentity === candidate.physicalStateIdentity) return true;
  }
  return stats.identity === candidate.treeIdentity;
}

async function createPrivateDirectoryTree(cacheRoot, directories) {
  for (const directory of directories) {
    let created = false;
    try {
      await fs.mkdir(directory, { mode: 0o700 });
      created = true;
    } catch (error) {
      if (!(error instanceof Error && error.code === "EEXIST")) throw error;
    }
    await requirePrivateCacheDirectory(cacheRoot, directory);
    // Persist each newly created ancestor once. The journal and batch boundaries below cover
    // candidate moves/removals; no per-entry directory sync is needed.
    if (created) await syncDirectory(dirname(directory));
  }
}

async function syncDirectory(path) {
  const handle = await fs.open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writePrivateDurableFile(cacheRoot, path, contents) {
  const temporaryPath = join(dirname(path), `.publish-${randomBytes(16).toString("hex")}-${basename(path)}`);
  const handle = await fs.open(temporaryPath, "wx", 0o600);
  try {
    try {
      await handle.writeFile(contents);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await requirePrivateCacheFile(cacheRoot, temporaryPath);
    // Install fully synced bytes exclusively. A partial write or process crash must leave only
    // publication scratch, never a malformed marker that permanently prevents recovery.
    await fs.link(temporaryPath, path);
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
  await requirePrivateCacheFile(cacheRoot, path);
  await syncDirectory(dirname(path));
}

export async function removeConvexWasmCacheTree(root) {
  // Node's recursive rm rejects on the first child failure while sibling removals can
  // still be running. Drain our bounded children before allowing lock release or recovery.
  // One operation bound covers nested trees without holding a permit across recursion.
  const run = createBoundedOperationRunner(4);
  const remove = async (path) => {
    const status = await run(() => fs.lstat(path));
    if (!status.isDirectory()) {
      await run(() => fs.unlink(path));
      return;
    }
    const names = (await run(() => fs.readdir(path))).sort(compareStrings);
    await mapBounded(names, 4, (name) => remove(join(path, name)));
    await run(() => fs.rmdir(path));
  };
  await remove(root);
}

async function recoverImmutableSweepJournal(cacheLayout, planRoot, names) {
  const journalPath = join(planRoot, "journal.json");
  await requirePrivateCacheFile(cacheLayout.cacheRoot, journalPath);
  const journal = await readCanonical(
    journalPath,
    MAX_SWEEP_JOURNAL_BYTES,
    "immutable sweep journal"
  );
  requireExactKeys(journal, ["entries", "journalSha256", "kind", "planSha256"], "immutable sweep journal");
  const { journalSha256, ...payload } = journal;
  if (
    journal.kind !== IMMUTABLE_SWEEP_JOURNAL_KIND ||
    requireSha256(journal.planSha256, "immutable sweep journal plan SHA-256") !== journal.planSha256 ||
    fingerprintJson(payload) !== journalSha256
  ) {
    fail(`immutable sweep journal authentication failed: ${journalPath}`);
  }
  const planSha256 = basename(planRoot);
  if (journal.planSha256 !== planSha256 || !Array.isArray(journal.entries)) {
    fail(`immutable sweep journal plan identity is invalid: ${journalPath}`);
  }
  const entries = journal.entries.map((entry) => {
    requireExactKeys(entry, ["candidateSha256", "path"], "immutable sweep journal entry");
    const candidateSha256 = requireSha256(entry.candidateSha256, "immutable sweep journal candidate SHA-256");
    if (typeof entry.path !== "string" || !entry.path.startsWith(`${cacheLayout.immutable.root}/`)) {
      fail(`immutable sweep journal candidate path is invalid: ${journalPath}`);
    }
    return { candidateSha256, path: entry.path };
  }).sort((left, right) => compareStrings(left.candidateSha256, right.candidateSha256));
  if (
    canonicalJson(entries) !== canonicalJson(journal.entries) ||
    new Set(entries.map(({ candidateSha256 }) => candidateSha256)).size !== entries.length
  ) {
    fail(`immutable sweep journal entries are not sorted and unique: ${journalPath}`);
  }
  const allowedNames = new Set(["journal.json", ...entries.map(({ candidateSha256 }) => candidateSha256)]);
  for (const name of names) {
    if (name.startsWith(".publish-")) {
      await requirePrivateCacheFile(cacheLayout.cacheRoot, join(planRoot, name));
      continue;
    }
    if (!allowedNames.has(name)) fail(`immutable sweep journal has an unexpected entry: ${planRoot}`);
  }
  const recovered = [];
  // A canonical root that was never renamed is deliberately left alone. Only a tree that is
  // physically below this journal's private trash directory was selected by the authenticated
  // wave and can be removed after a crash.
  for (const { candidateSha256, path } of entries) {
    const trashPath = join(planRoot, candidateSha256);
    if (!(await exists(trashPath))) {
      recovered.push({ candidateSha256, planSha256, status: "not-moved" });
      continue;
    }
    await requirePrivateCacheDirectory(cacheLayout.cacheRoot, trashPath);
    await measureConvexWasmRetentionPhase("unlink", () => removeConvexWasmCacheTree(trashPath));
    recovered.push({ candidateSha256, path, planSha256, status: "removed-batch-root" });
  }
  for (const name of names) {
    if (name !== "journal.json" && name.startsWith(".publish-")) {
      await fs.unlink(join(planRoot, name));
    }
  }
  await fs.unlink(journalPath);
  await syncDirectory(planRoot);
  await fs.rmdir(planRoot);
  await syncDirectory(dirname(planRoot));
  return recovered;
}

async function removeQuarantinedImmutableGcCandidatesMeasured(cacheLayout) {
  const root = immutableSweepTrashRoot(cacheLayout);
  if (!(await exists(root))) return [];
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const recovered = [];
  for (const planSha256 of (await fs.readdir(root)).sort(compareStrings)) {
    requireSha256(planSha256, "quarantined immutable sweep plan SHA-256");
    const planRoot = join(root, planSha256);
    await requirePrivateCacheDirectory(cacheLayout.cacheRoot, planRoot);
    const names = (await fs.readdir(planRoot)).sort(compareStrings);
    if (names.includes("journal.json")) {
      recovered.push(...await recoverImmutableSweepJournal(cacheLayout, planRoot, names));
      continue;
    }
    const candidateRoots = new Set(names.filter((name) => SHA256_PATTERN.test(name)));
    const markerNames = names.filter((name) => /^[0-9a-f]{64}\.json$/u.test(name));
    const verifiedMarkerNames = new Set(
      names.filter((name) => /^[0-9a-f]{64}\.verified\.json$/u.test(name))
    );
    const publicationNames = names.filter((name) =>
      /^\.publish-[0-9a-f]{32}-[0-9a-f]{64}(?:\.verified)?\.json$/u.test(name)
    );
    if (candidateRoots.size + markerNames.length + verifiedMarkerNames.size + publicationNames.length !== names.length) {
      fail(`immutable sweep quarantine has an unexpected entry: ${planRoot}`);
    }
    for (const name of publicationNames) {
      await requirePrivateCacheFile(cacheLayout.cacheRoot, join(planRoot, name));
    }
    // Verify every complete tree before unlinking any payload. Different candidates can share
    // hardlinks, so removing one changes the inode state used to authenticate another.
    const pendingRemovals = [];
    for (const markerName of markerNames) {
      const candidateSha256 = markerName.slice(0, -5);
      const markerPath = join(planRoot, markerName);
      await requirePrivateCacheFile(cacheLayout.cacheRoot, markerPath);
      const record = await readCanonical(
        markerPath,
        MAX_SWEEP_QUARANTINE_RECORD_BYTES,
        "immutable sweep quarantine record"
      );
      requireExactKeys(
        record,
        ["candidate", "candidateSha256", "kind", "planSha256"],
        "immutable sweep quarantine record"
      );
      const candidateKeys = [
        "allocationBytes",
        "estimatedReclaimBytes",
        "identity",
        "key",
        "mtimeMs",
        "path",
        "stage",
        "treeIdentity",
        "type",
      ];
      // Keep v1 markers recoverable after an upgrade. They predate the compact physical-state
      // digest and therefore retain the older inode/mtime comparison only; newly planned markers
      // always carry the stronger digest.
      if (Object.hasOwn(record.candidate, "physicalStateIdentity")) {
        candidateKeys.push("physicalStateIdentity");
      }
      if (record.candidate.type === "certificate-entry" && record.candidate.removePreferred === true) {
        candidateKeys.push("removePreferred");
      }
      requireExactKeys(record.candidate, candidateKeys, "immutable sweep quarantine candidate");
      const expectedRecord = immutableSweepQuarantineRecord(planSha256, record.candidate);
      if (
        record.kind !== expectedRecord.kind ||
        record.planSha256 !== planSha256 ||
        record.candidateSha256 !== candidateSha256 ||
        canonicalJson(record) !== canonicalJson(expectedRecord)
      ) {
        fail(`immutable sweep quarantine record is invalid: ${markerPath}`);
      }
      const canonicalPath = evictionCandidatePath(cacheLayout, record.candidate);
      const candidateRoot = join(planRoot, candidateSha256);
      const verifiedMarkerName = `${candidateSha256}.verified.json`;
      const verifiedMarkerPath = join(planRoot, verifiedMarkerName);
      const removalAuthorized = verifiedMarkerNames.has(verifiedMarkerName);
      if (removalAuthorized) {
        await requirePrivateCacheFile(cacheLayout.cacheRoot, verifiedMarkerPath);
        const verifiedRecord = await readCanonical(
          verifiedMarkerPath,
          MAX_SWEEP_QUARANTINE_RECORD_BYTES,
          "immutable sweep verified quarantine record"
        );
        requireExactKeys(
          verifiedRecord,
          ["candidate", "candidateSha256", "kind", "planSha256", "state"],
          "immutable sweep verified quarantine record"
        );
        const verifiedRecordBase = { ...verifiedRecord };
        delete verifiedRecordBase.state;
        if (
          verifiedRecord.state !== "verified" ||
          canonicalJson(verifiedRecordBase) !== canonicalJson(record)
        ) {
          fail(`immutable sweep verified quarantine record is invalid: ${verifiedMarkerPath}`);
        }
      }
      let status;
      let candidatePresent = false;
      if (candidateRoots.has(candidateSha256)) {
        candidatePresent = true;
        try {
          await requirePrivateCacheDirectory(cacheLayout.cacheRoot, candidateRoot);
        } catch (error) {
          if (!missing(error)) throw error;
          // Recursive removal may have completed the root itself before the process crashed.
          // The marker still proves that this exact candidate was quarantined, so finish recovery
          // without treating the already-absent root as a redirected or malformed tree.
          candidatePresent = false;
        }
        // The canonical cache key was removed by an atomic rename before this tree entered the
        // quarantine. A partial prior removal is safe to finish, but symlinks still fail closed.
        if (candidatePresent && !removalAuthorized) {
          const recoveredStats = await treeStats(candidateRoot);
          // No recursive removal can begin without the verified marker. An unverified tree must
          // still match the complete planned state; missing children cannot authorize deletion.
          if (
            recoveredStats.allocatedBytes !== record.candidate.allocationBytes ||
            recoveredStats.estimatedReclaimBytes !== record.candidate.estimatedReclaimBytes ||
            !matchesQuarantineCandidateTree(recoveredStats, record.candidate) ||
            recoveredStats.mtimeMs !== record.candidate.mtimeMs
          ) {
            fail(`quarantined immutable candidate changed before recovery: ${candidateRoot}`);
          }
          // The prior process may have stopped between rename and its source-directory sync.
          // Persist that side before authorizing removal; publishing the verified marker below
          // syncs the destination directory and completes the other side of the rename.
          await requirePrivateCacheDirectory(cacheLayout.cacheRoot, dirname(canonicalPath));
          await syncDirectory(dirname(canonicalPath));
          // The complete post-rename state has now been authenticated. Persist a separate
          // removal-authorized marker before recursive deletion so a crash during removal can
          // safely finish a partial tree without treating it as a replacement.
          await writePrivateDurableFile(
            cacheLayout.cacheRoot,
            verifiedMarkerPath,
            `${canonicalJson({ ...record, state: "verified" })}\n`
          );
        }
        candidateRoots.delete(candidateSha256);
        status = "removed-quarantined-root";
      } else {
        status = (await exists(canonicalPath))
          ? "cleared-pre-rename-marker"
          : "cleared-completed-marker";
      }
      pendingRemovals.push({ candidatePresent, candidateRoot, candidateSha256, markerPath, status, verifiedMarkerPath });
    }
    if (candidateRoots.size !== 0) {
      fail(`immutable sweep quarantine contains a root without authority: ${planRoot}`);
    }
    for (const verifiedMarkerName of verifiedMarkerNames) {
      const candidateSha256 = verifiedMarkerName.slice(0, -".verified.json".length);
      if (!markerNames.includes(`${candidateSha256}.json`)) {
        fail(`immutable sweep verified quarantine marker has no base record: ${planRoot}`);
      }
    }
    for (const { candidatePresent, candidateRoot, candidateSha256, markerPath, status, verifiedMarkerPath } of pendingRemovals) {
      if (candidatePresent) {
        await removeConvexWasmCacheTree(candidateRoot);
        // Keep the durable marker until removal of the quarantined tree is itself durable.
        await syncDirectory(planRoot);
      }
      if (await exists(verifiedMarkerPath)) {
        await fs.unlink(verifiedMarkerPath);
        await syncDirectory(planRoot);
      }
      await fs.unlink(markerPath);
      await syncDirectory(planRoot);
      recovered.push({ candidateSha256, planSha256, status });
    }
    // These incomplete or already published marker writes have no independent removal authority.
    // Leave them untouched until every complete marker/tree above has passed recovery admission.
    for (const name of publicationNames) await fs.unlink(join(planRoot, name));
    await fs.rmdir(planRoot);
    await syncDirectory(root);
  }
  if (await exists(root)) {
    await fs.rmdir(root);
    await syncDirectory(dirname(root));
  }
  return recovered;
}

function evictionCandidatePath(cacheLayout, candidate) {
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    Array.isArray(candidate) ||
    requireSha256(candidate.key, "immutable eviction key") !== candidate.key
  ) {
    fail("immutable eviction candidate is invalid");
  }
  let path;
  if (candidate.type === "artifact" || candidate.type === "c-bundle") {
    if (
      typeof candidate.stage !== "string" ||
      candidate.stage.length === 0 ||
      candidate.stage === "." ||
      candidate.stage === ".." ||
      candidate.stage.includes("/") ||
      candidate.stage.includes("\\")
    ) fail("immutable eviction candidate stage is invalid");
    path = join(cacheLayout.immutable.artifacts, candidate.stage, candidate.key);
  } else if (candidate.type === "package" && candidate.stage === null) {
    path = join(cacheLayout.immutable.packages, candidate.key);
  } else if (candidate.type === "certificate-entry") {
    requireSha256(candidate.stage, "certificate lookup key");
    path = join(cacheLayout.immutable.packages, "deployment-results", "v1", candidate.stage, candidate.key);
  } else if (candidate.type === "certificate-root" && candidate.stage === null) {
    path = join(cacheLayout.immutable.packages, "deployment-results", "v1", candidate.key);
  } else fail("immutable eviction candidate type or stage is invalid");
  if (Object.hasOwn(candidate, "removePreferred") &&
      (candidate.type !== "certificate-entry" || candidate.removePreferred !== true)) {
    fail("immutable eviction preferred-pointer removal is invalid");
  }
  if (candidate.path !== path) fail("immutable eviction candidate path is invalid");
  if (
    !Number.isSafeInteger(candidate.allocationBytes) ||
    candidate.allocationBytes < 0 ||
    !Number.isSafeInteger(candidate.estimatedReclaimBytes) ||
    candidate.estimatedReclaimBytes < 0 ||
    !Number.isFinite(candidate.mtimeMs) ||
    candidate.mtimeMs < 0 ||
    typeof candidate.treeIdentity !== "string" ||
    candidate.treeIdentity.length === 0 ||
    (candidate.physicalStateIdentity !== undefined &&
      requireSha256(
        candidate.physicalStateIdentity,
        "immutable eviction physical state identity"
      ) !== candidate.physicalStateIdentity)
  ) {
    fail("immutable eviction candidate state is invalid");
  }
  return path;
}

async function authenticateEvictionRoot(cacheLayout, candidate, validation) {
  const path = evictionCandidatePath(cacheLayout, candidate);
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, path);
  const status = await pathInfo(path);
  if (!status.isDirectory()) fail(`immutable eviction candidate is not a directory: ${path}`);
  let authenticated;
  if (candidate.type === "artifact") {
    const metadata = await readCanonical(
      join(path, "entry.json"),
      MAX_METADATA_BYTES,
      "artifact entry"
    );
    authenticated = await authenticateArtifactFamily({
      cacheLayout,
      key: candidate.key,
      metadata,
      path,
      stage: candidate.stage,
      validation,
    });
  } else if (candidate.type === "c-bundle") {
    authenticated = await authenticateCBundle({
      cacheLayout,
      key: candidate.key,
      path,
      stage: candidate.stage,
    });
  } else if (candidate.type === "package") {
    authenticated = await authenticatePackage(cacheLayout, candidate.key, path, validation);
  } else if (candidate.type === "certificate-entry") {
    const root = await authenticateCertificateRoot(cacheLayout, candidate.stage, dirname(path), validation);
    authenticated = root.certificates.find(({ key }) => key === candidate.key);
    if (!authenticated?.authenticated || Boolean(authenticated.removePreferred) !== Boolean(candidate.removePreferred)) {
      fail(`immutable eviction certificate entry changed: ${path}`);
    }
  } else {
    authenticated = await authenticateCertificateRoot(cacheLayout, candidate.key, path, validation);
    if (!authenticated.authenticated) fail(`immutable eviction certificate is invalid: ${path}`);
  }
  const stats = await treeStats(path);
  if (authenticated.type !== candidate.type) fail(`immutable eviction candidate changed type: ${path}`);
  return { path, stats };
}

async function reauthenticateEvictionCandidateMeasured(cacheLayout, candidate, validation) {
  const { path, stats } = await authenticateEvictionRoot(cacheLayout, candidate, validation);
  if (
    stats.allocatedBytes !== candidate.allocationBytes ||
    stats.estimatedReclaimBytes !== candidate.estimatedReclaimBytes ||
    !matchesQuarantineCandidateTree(stats, candidate) ||
    stats.mtimeMs !== candidate.mtimeMs
  ) {
    fail(`immutable eviction candidate changed after planning: ${path}`);
  }
  return { path, stats };
}

function inventoryRecordsByPath(inventory) {
  return new Map([
    ...inventory.certificates.flatMap((root) => [root, ...(root.certificates ?? [])]),
    ...inventory.packages,
    ...inventory.artifacts,
  ].map((record) => [record.path, record]));
}

function refreshInventoryPhysicalStats(inventory, fence) {
  const fenceEntries = [...fence].sort(([left], [right]) => compareStrings(left, right));
  const fencedPaths = new Set(fenceEntries.map(([path]) => path));
  for (const record of inventoryRecordsByPath(inventory).values()) {
    // A completed wave removes records from the inventory before this refresh. Keep the helper
    // conservative if a future caller supplies a pre-filtered snapshot: a missing record cannot
    // contribute deletion authority for the settled tree.
    if (!fencedPaths.has(record.path)) continue;
    Object.assign(record, treeStatsFromFence(record.path, fenceEntries));
  }
}

function authenticatedInventoryCandidate(candidate, record) {
  if (
    record === undefined ||
    record.authenticated !== true ||
    record.type !== candidate.type ||
    record.allocatedBytes !== candidate.allocationBytes ||
    record.estimatedReclaimBytes !== candidate.estimatedReclaimBytes ||
    !matchesQuarantineCandidateTree(record, candidate) ||
    record.mtimeMs !== candidate.mtimeMs
  ) {
    return undefined;
  }
  return { path: candidate.path, stats: record };
}

async function collectImmutableInventory(cacheLayout, fence) {
  // Packages, certificates and the artifact inventory repeatedly reach the same immutable
  // entries. Reuse the existing physical-state-fenced validators within this one locked plan,
  // instead of hashing and parsing their complete closures again for each referring root.
  const validation = {
    packages: new Map(),
    artifacts: new Map(),
    structured: new Map(),
    structuredBytes: 0,
    cacheRoot: cacheLayout.cacheRoot,
    ...(fence === undefined
      ? {}
      : { fence, fenceEntries: [...fence].sort(([left], [right]) => compareStrings(left, right)) }),
  };
  if (fence !== undefined) bindArtifactCacheValidationFence(validation.artifacts, validation.fenceEntries);
  const [allSnapshots, packages, artifacts] = await settleConcurrentWork([
    listSnapshots(cacheLayout),
    listPackages(cacheLayout, validation),
    listArtifactEntries(cacheLayout, validation),
  ]);
  const packageRecordsByKey = new Map(packages.map((record) => [record.key, record]));
  const snapshots = allSnapshots;
  for (const { snapshot } of snapshots) {
    for (const key of snapshot.packageKeys) {
      if (!packageRecordsByKey.get(key)?.authenticated) {
        fail(`deployed snapshot references an unavailable package: ${key}`);
      }
    }
  }
  const certificates = await listCertificates(cacheLayout, validation);
  const artifactsByKey = new Map(
    artifacts
      .filter((record) => record.authenticated)
      .map((record) => [`${record.stage}\0${record.key}`, record])
  );
  const artifactRecordsByKey = new Map(
    artifacts.map((record) => [`${record.stage}\0${record.key}`, record])
  );
  // A compiler-output cache record is only authoritative together with the exact immutable
  // entries it names. The entry key alone authenticates the target's identity, not the record's
  // embedded artifact digest/size/metadata projection, so compare every closure reference against
  // the already-authenticated target before granting retention authority.
  for (const artifactRecord of artifacts) {
    if (
      !artifactRecord.authenticated ||
      artifactRecord.type !== "artifact" ||
      artifactRecord.stage !== MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE ||
      compilerOutputCacheEntrySchema(artifactRecord.entry) !== "current"
    ) {
      continue;
    }
    authenticateCompilerOutputClosure(artifactRecord, artifactsByKey);
  }
  // A compact topology hit intentionally avoids reopening its full record. Preserve the
  // publication prerequisite across GC: the certificate can be removed in this plan, while its
  // exact current record and strict stage closure become reclaimable only in a later plan.
  for (const artifactRecord of artifacts) {
    const reference = artifactRecord.topologyCompilerOutputReference;
    if (!artifactRecord.authenticated || reference === undefined) continue;
    const compilerOutputRecordKey = `${MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE}\0${reference.cacheKey}`;
    const compilerOutput = artifactRecordsByKey.get(compilerOutputRecordKey);
    if (compilerOutput === undefined) {
      // The certificate cannot retain anything once its exact full record has disappeared. Keep
      // the independently authenticated certificate as a collectible artifact so an interrupted
      // older cleanup cannot block every future sweep.
      artifactRecord.orphanedTopologyCertificate = {
        cacheKey: reference.cacheKey,
        stage: MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE,
      };
      continue;
    }
    if (
      !compilerOutput.authenticated ||
      compilerOutput.type !== "artifact" ||
      compilerOutputCacheEntrySchema(compilerOutput.entry) !== "current" ||
      canonicalJson(compilerOutput.entry.identity) !== canonicalJson(reference.cacheIdentity)
    ) {
      fail("compiler-output topology certificate full record is absent or changed");
    }
    const [record, certificate] = await settleConcurrentWork([
      readStructuredArtifact(compilerOutput.entry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "compiler-output topology certificate full record", validation),
      readStructuredArtifact(artifactRecord.entry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "compiler-output topology certificate", validation),
    ]);
    if (
      authenticatedStructuredDigests.get(record) !== reference.cacheRecordSha256 ||
      certificate.cacheKey !== reference.cacheKey ||
      certificate.cacheRecordSha256 !== reference.cacheRecordSha256
    ) {
      fail("compiler-output topology certificate full record is absent or changed");
    }
    const recordAuthority = authenticateCompilerOutputRecord(
      record,
      "compiler-output topology certificate full record"
    );
    if (recordAuthority.descriptorFamily === "historical-pre-transport") continue;
    authenticateCapsuleTopologyCertificate(certificate, record, recordAuthority);
  }
  // A capsule hit fails closed when either its topology certificate or full compiler record is
  // missing. Keep that strict closure for this plan, but leave the capsule itself removable so a
  // later deployment can rebuild it before a subsequent sweep reclaims newly unreachable stages.
  for (const artifactRecord of artifacts) {
    if (!artifactRecord.authenticated || artifactRecord.capsuleClosure === undefined) continue;
    const compilerOutputArtifactKey = `${MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE}\0${artifactRecord.capsuleClosure.compilerOutputCacheKey}`;
    const compilerOutput = artifactsByKey.get(compilerOutputArtifactKey);
    if (compilerOutput === undefined || compilerOutput.type !== "artifact") {
      fail("cohort capsule compiler-output record is absent or changed");
    }
    const topologyCertificateArtifactKey = `${MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE}\0${artifactRecord.capsuleClosure.topologyCertificateCacheKey}`;
    const topologyCertificate = artifactsByKey.get(topologyCertificateArtifactKey);
    if (
      topologyCertificate === undefined ||
      topologyCertificate.type !== "artifact" ||
      canonicalJson(topologyCertificate.entry.metadata) !==
        canonicalJson({ kind: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND }) ||
      topologyCertificate.entry.artifactSha256 !==
        artifactRecord.capsuleClosure.topologyCertificateArtifactSha256 ||
      topologyCertificate.entry.artifactSize !==
        artifactRecord.capsuleClosure.topologyCertificateArtifactSize
    ) {
      fail("cohort capsule compiler-output topology certificate is absent or changed");
    }
    const [compilerOutputRecord, topologyCertificateRecord] = await settleConcurrentWork([
      readStructuredArtifact(compilerOutput.entry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "cohort capsule compiler-output cache record", validation),
      readStructuredArtifact(topologyCertificate.entry, MAX_COMPILER_OUTPUT_CACHE_BYTES, "cohort capsule compiler-output topology certificate", validation),
    ]);
    // The topology certificate binds the canonical record bytes without the trailing newline
    // used by the immutable artifact file. Compare that semantic digest, not the file digest.
    if (
      authenticatedStructuredDigests.get(compilerOutputRecord) !==
      artifactRecord.capsuleClosure.compilerOutputCacheRecordSha256
    ) {
      fail("cohort capsule compiler-output record is absent or changed");
    }
    const topologyCertificateBytes = canonicalBytes(topologyCertificateRecord);
    if (
      sha256(topologyCertificateBytes) !==
        artifactRecord.capsuleClosure.topologyCertificateArtifactSha256 ||
      topologyCertificateBytes.length !==
        artifactRecord.capsuleClosure.topologyCertificateArtifactSize
    ) {
      fail("cohort capsule compiler-output topology certificate is absent or changed");
    }
  }
  // Reachability needs only normalized edges and family classification. Drop authenticated
  // metadata, reference projections, and bundle manifests once their cross-checks finish;
  // keeping those parse trees for every surviving wave would turn CPU reuse into an RSS cost.
  for (const artifact of artifacts) {
    if (artifact.authenticated) {
      if (artifact.type === "artifact" && artifact.stage === MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE) {
        artifact.compilerOutputSchema = compilerOutputCacheEntrySchema(artifact.entry);
      }
      if (artifact.type === "c-bundle") {
        artifact.layoutReferences = staticHermesLayoutCacheReferences(artifact.entry.identity, artifact.stage);
      }
      if (artifact.topologyCompilerOutputReference !== undefined) {
        artifact.topologyCompilerOutputReference = { cacheKey: artifact.topologyCompilerOutputReference.cacheKey };
      }
      if (artifact.capsuleClosure !== undefined) {
        const { compilerOutputCacheKey, topologyCertificateCacheKey } = artifact.capsuleClosure;
        artifact.capsuleClosure = { compilerOutputCacheKey, topologyCertificateCacheKey };
      }
    }
    delete artifact.entry;
    delete artifact.bundle;
    delete artifact.closureArtifactReferences;
  }
  return { snapshots, packages, artifacts, certificates };
}

function physicalWitness(status) {
  return {
    dev: status.dev, ino: status.ino, mode: status.mode, uid: status.uid, gid: status.gid,
    size: status.size, blocks: status.blocks, nlink: status.nlink,
    mtimeNs: status.mtimeNs, ctimeNs: status.ctimeNs,
    type: status.isDirectory() ? "directory" : status.isFile() ? "file" : "other",
  };
}

function sameWitness(left, right, ignored = []) {
  return right !== undefined && Object.keys(left).every((key) => ignored.includes(key) || left[key] === right[key]);
}

async function captureInventoryFence(cacheLayout) {
  return await measureConvexWasmRetentionPhase("authorityFence", async () => {
    const fence = new Map();
    if (typeof process.getuid !== "function") {
      fail("private cache validation requires process.getuid()");
    }
    const uid = process.getuid();
    // Ancestor identity is part of authority. Checking just entry inodes would miss an
    // ancestor replaced by a symlink to the same bytes. State ancestors may gain our own
    // quarantine directories, so only their identity/access state is retained here.
    for (const root of [cacheLayout.immutable.root, deploymentSnapshotRoot(cacheLayout.cacheRoot)]) {
      const ancestors = [];
      for (let path = dirname(root); path !== dirname(cacheLayout.cacheRoot); path = dirname(path)) ancestors.push(path);
      for (const path of ancestors.reverse()) {
        if (!(await exists(path))) break;
        await requirePrivateCacheDirectory(cacheLayout.cacheRoot, path);
        const { dev, ino, mode, uid, gid, type } = physicalWitness(await fs.lstat(path, { bigint: true }));
        fence.set(path, { dev, ino, mode, uid, gid, type });
      }
      if (!(await exists(root))) continue;
      await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
      const pending = [root];
      while (pending.length !== 0) {
        // Bound metadata concurrency just like inventory authentication. mapBounded drains
        // every admitted sibling before propagating failure and releasing the cache lock.
        const captured = await mapBounded(pending.splice(-64), 4, async (path) => {
          const status = await fs.lstat(path, { bigint: true });
          // This walk also supplies occupancy, whose existing boundary rejects links even
          // in non-authoritative publication scratch. Reuse must preserve that boundary.
          if (root === cacheLayout.immutable.root && status.isSymbolicLink()) {
            fail(`immutable authority path is a symbolic link: ${path}`);
          }
          if (
            status.isDirectory() &&
            (status.uid !== BigInt(uid) || (status.mode & 0o7777n) !== 0o700n)
          ) {
            fail(`immutable authority directory must be owned by the current user with mode 0700: ${path}`);
          }
          const witness = physicalWitness(status);
          // Never follow malformed members; authentication owns their classification.
          const children = status.isDirectory() ? await fs.readdir(path) : [];
          if (status.isDirectory() && !sameWitness(witness, physicalWitness(await fs.lstat(path, { bigint: true })))) {
            fail(`immutable directory changed during authority capture: ${path}`);
          }
          return { path, witness, children };
        });
        for (const { path, witness, children } of captured) {
          fence.set(path, witness);
          for (const name of children) pending.push(join(path, name));
        }
      }
    }
    return fence;
  });
}

function trustedInventoryDirectories(fence) {
  return new Set(
    [...fence].filter(([, witness]) => witness.type === "directory").map(([path]) => path)
  );
}

function trustedInventoryFiles(fence) {
  const uid = BigInt(process.getuid());
  return new Set(
    [...fence]
      .filter(
        ([, witness]) =>
          witness.type === "file" &&
          witness.uid === uid &&
          (witness.mode & 0o7777n) === 0o600n
      )
      .map(([path]) => path)
  );
}

function immutableInventoryIndexPath(cacheLayout) {
  return join(cacheLayout.state.root, "cache-retention", "v1", "immutable-inventory.json");
}

function fenceIdentity(fence, cacheLayout) {
  const roots = [cacheLayout.immutable.root, deploymentSnapshotRoot(cacheLayout.cacheRoot)];
  const states = [...fence]
    .filter(([path]) => roots.some((root) => path === root || path.startsWith(`${root}/`)))
    .map(([path, witness]) => ({
    blocks: String(witness.blocks),
    ctimeNs: String(witness.ctimeNs),
    dev: String(witness.dev),
    gid: String(witness.gid),
    ino: String(witness.ino),
    mode: String(witness.mode),
    mtimeNs: String(witness.mtimeNs),
    nlink: String(witness.nlink),
    path,
    size: String(witness.size),
    type: witness.type,
    uid: String(witness.uid),
    })).sort((left, right) => compareStrings(left.path, right.path));
  return sha256(canonicalBytes(states));
}

function inventoryIndexPayload(cacheLayout, fence, inventory) {
  const payload = {
    fenceSha256: fenceIdentity(fence, cacheLayout),
    inventory,
    kind: "convex-wasm-immutable-gc-inventory-v1",
  };
  return { ...payload, indexSha256: fingerprintJson(payload) };
}

async function persistImmutableInventoryIndex(cacheLayout, fence, inventory) {
  await createPrivateDirectoryTree(cacheLayout.cacheRoot, [
    join(cacheLayout.cacheRoot, "state"),
    cacheLayout.state.root,
    join(cacheLayout.state.root, "cache-retention"),
    join(cacheLayout.state.root, "cache-retention", "v1"),
  ]);
  const index = inventoryIndexPayload(cacheLayout, fence, inventory);
  await replacePrivateDurableFile(
    cacheLayout.cacheRoot,
    immutableInventoryIndexPath(cacheLayout),
    `${canonicalJson(index)}\n`
  );
}

async function readImmutableInventoryIndex(cacheLayout, fence) {
  const path = immutableInventoryIndexPath(cacheLayout);
  try {
    await requirePrivateCacheFile(cacheLayout.cacheRoot, path);
    const index = await readCanonical(path, MAX_METADATA_BYTES * 4, "immutable inventory index");
    const { indexSha256, ...payload } = index ?? {};
    if (
      index.kind !== "convex-wasm-immutable-gc-inventory-v1" ||
      requireSha256(indexSha256, "immutable inventory index SHA-256") !== indexSha256 ||
      fingerprintJson(payload) !== indexSha256 ||
      index.fenceSha256 !== fenceIdentity(fence, cacheLayout) ||
      typeof index.inventory !== "object" ||
      index.inventory === null ||
      !Array.isArray(index.inventory.snapshots) ||
      !Array.isArray(index.inventory.packages) ||
      !Array.isArray(index.inventory.artifacts) ||
      !Array.isArray(index.inventory.certificates)
    ) {
      return undefined;
    }
    return index.inventory;
  } catch (error) {
    if (missing(error)) return undefined;
    // The index is derived cache state. A partial or stale index must trigger the existing full
    // authenticated inventory rather than becoming deletion authority.
    return undefined;
  }
}

async function replacePrivateDurableFile(cacheRoot, path, contents) {
  const temporaryPath = join(dirname(path), `.publish-${randomBytes(16).toString("hex")}-${basename(path)}`);
  const handle = await fs.open(temporaryPath, "wx", 0o600);
  let closed = false;
  try {
    await handle.writeFile(contents);
    await handle.sync();
    await handle.close();
    closed = true;
    await requirePrivateCacheFile(cacheRoot, temporaryPath);
    if (await exists(path)) await requirePrivateCacheFile(cacheRoot, path);
    await fs.rename(temporaryPath, path);
    await requirePrivateCacheFile(cacheRoot, path);
    await syncDirectory(dirname(path));
  } finally {
    await fs.rm(temporaryPath, { force: true });
    if (!closed) await handle.close();
  }
}

function plannedWaveRemovedPaths(fence, evictions, alreadyRemovedPaths = new Set()) {
  const roots = new Set(evictions.flatMap((candidate) => candidate.removePreferred
    ? [candidate.path, join(dirname(candidate.path), "PREFERRED")] : [candidate.path]));
  const removedPaths = new Set(alreadyRemovedPaths);
  for (const [path, witness] of fence) {
    for (let ancestor = path; ancestor !== dirname(ancestor); ancestor = dirname(ancestor)) {
      if (!roots.has(ancestor)) continue;
      removedPaths.add(path);
      break;
    }
  }
  return removedPaths;
}

function createFenceOccupancy(cacheLayout, fence) {
  const inodes = new Map();
  for (const [path, witness] of fence) {
    if (!path.startsWith(`${cacheLayout.immutable.root}/`)) continue;
    const inode = `${witness.dev}:${witness.ino}`;
    let record = inodes.get(inode);
    if (record === undefined) {
      record = { allocatedBytes: Number(witness.blocks * 512n), paths: new Set() };
      if (!Number.isSafeInteger(record.allocatedBytes) || record.allocatedBytes < 0) {
        fail("immutable occupancy exceeds the safe integer range");
      }
      inodes.set(inode, record);
    }
    record.paths.add(path);
  }
  return {
    allocatedBytes: [...inodes.values()].reduce((total, { allocatedBytes }) => total + allocatedBytes, 0),
    inodes,
  };
}

function applyFenceRemovals(occupancy, fence, removedPaths) {
  const affected = new Set();
  for (const path of removedPaths) {
    const witness = fence.get(path);
    if (witness === undefined) continue;
    const inode = `${witness.dev}:${witness.ino}`;
    const record = occupancy.inodes.get(inode);
    if (record === undefined || !record.paths.delete(path)) continue;
    affected.add(inode);
  }
  for (const inode of affected) {
    const record = occupancy.inodes.get(inode);
    if (record.paths.size === 0) {
      occupancy.allocatedBytes -= record.allocatedBytes;
      occupancy.inodes.delete(inode);
    }
  }
  if (!Number.isSafeInteger(occupancy.allocatedBytes) || occupancy.allocatedBytes < 0) {
    fail("immutable occupancy became invalid after planned removals");
  }
  return occupancy.allocatedBytes;
}

function deriveImmutablePlan({ inventory, immutableAllocatedBytes, highWatermarkAllocatedBytes,
  maxRetainedPackages, nowMs }) {
  const { snapshots, packages, artifacts, certificates } = inventory;
  const packagesByKey = new Map(packages.filter((record) => record.authenticated).map((record) => [record.key, record]));
  const artifactsByKey = new Map(
    artifacts
      .filter((record) => record.authenticated)
      .map((record) => [`${record.stage}\0${record.key}`, record])
  );
  const artifactRecordsByKey = new Map(
    artifacts.map((record) => [`${record.stage}\0${record.key}`, record])
  );
  const certificatesBySha256 = new Map();
  for (const root of certificates) {
    if (root.certificates === undefined) continue;
    for (const certificate of root.certificates) {
      if (!certificate.authenticated) continue;
      if (certificatesBySha256.has(certificate.key)) {
        fail(`deployment certificate key is duplicated: ${certificate.key}`);
      }
      certificatesBySha256.set(certificate.key, { certificate, root });
    }
  }
  const retainedPaths = new Set(snapshots.map(({ path }) => path));
  const retainedPackageKeys = new Set();
  const retainedArtifactKeys = new Set();
  const retainedCertificateSha256s = new Set();
  const retainArtifact = (key) => {
    const artifactRecord = artifactsByKey.get(key);
    if (artifactRecord === undefined) fail(`retained artifact is unavailable: ${key}`);
    retainedArtifactKeys.add(key);
    retainedPaths.add(artifactRecord.path);
  };
  const retainPackage = (key) => {
    if (retainedPackageKeys.size >= maxRetainedPackages && !retainedPackageKeys.has(key))
      fail("retained package bound exceeded");
    const packageRecord = packagesByKey.get(key);
    if (packageRecord === undefined) fail(`retained package is unavailable: ${key}`);
    retainedPackageKeys.add(key);
    retainedPaths.add(packageRecord.path);
    for (const artifactKey of packageRecord.artifactKeys) retainArtifact(artifactKey);
  };
  const retainCertificate = (key) => {
    const certificate = certificatesBySha256.get(key);
    if (certificate === undefined) fail(`retained deployment certificate is unavailable: ${key}`);
    retainedCertificateSha256s.add(key);
    retainedPaths.add(certificate.root.path);
    retainedPaths.add(certificate.certificate.path);
    for (const packageKey of certificate.certificate.packageKeys) retainPackage(packageKey);
  };
  const retainCompilerOutput = (key) => {
    const compilerOutputKey = `${MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE}\0${key}`;
    const compilerOutput = artifactsByKey.get(compilerOutputKey);
    if (compilerOutput === undefined || compilerOutput.type !== "artifact") {
      fail(`retained compiler-output cache entry is unavailable: ${key}`);
    }
    retainArtifact(compilerOutputKey);
    if (compilerOutput.compilerOutputSchema !== "current") return;
    for (const artifactKey of compilerOutput.closureArtifactKeys) retainArtifact(artifactKey);
  };
  // Every surviving topology authority keeps its full record, including when the
  // topology itself is selected in this wave. Only a completed removal releases an edge.
  for (const record of artifacts) {
    if (record.authenticated && record.topologyCompilerOutputReference !== undefined &&
        record.orphanedTopologyCertificate === undefined) {
      retainCompilerOutput(record.topologyCompilerOutputReference.cacheKey);
    }
  }
  // Pin the packages of every surviving certificate for this pass. A completed root or entry
  // removal releases its edges for the next wave, including superseded entries beside a
  // retained deployment certificate.
  for (const certificateRoot of certificates) {
    const keys = certificateRoot.packageKeys ?? [];
    for (const key of keys) {
      const packageRecord = packagesByKey.get(key);
      if (packageRecord !== undefined) retainedPaths.add(packageRecord.path);
    }
  }
  // Preserve each physical package's artifact closure for this pass. Retiring the package makes
  // that closure eligible on a later pass, after no surviving authority can still open it.
  for (const packageRecord of packages) {
    if (!packageRecord.authenticated) continue;
    for (const artifactKey of packageRecord.artifactKeys) retainArtifact(artifactKey);
  }
  // A compiler-output record is also a strict cache authority: a missing referenced stage fails
  // authentication instead of becoming a cache miss. Pin its closure for this plan. The record
  // itself may be removed now, and a later sweep can then reclaim its newly unreachable closure.
  for (const artifactRecord of artifacts) {
    if (
      !artifactRecord.authenticated ||
      artifactRecord.type !== "artifact" ||
      artifactRecord.stage !== MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE ||
      artifactRecord.compilerOutputSchema !== "current"
    ) {
      continue;
    }
    for (const artifactKey of artifactRecord.closureArtifactKeys) retainArtifact(artifactKey);
  }
  // Capsule closure was authenticated during collection. Recomputing reachability
  // consumes those compact facts; it must never reopen or reinterpret their payloads.
  for (const record of artifacts) {
    if (!record.authenticated || record.capsuleClosure === undefined) continue;
    retainCompilerOutput(record.capsuleClosure.compilerOutputCacheKey);
    retainArtifact(`${MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE}\0${record.capsuleClosure.topologyCertificateCacheKey}`);
  }
  for (const snapshot of snapshots) {
    for (const key of snapshot.snapshot.certificateSha256s) retainCertificate(key);
    for (const key of snapshot.snapshot.compilerOutputKeys) retainCompilerOutput(key);
    for (const key of snapshot.snapshot.packageKeys) retainPackage(key);
  }
  const deployedCompilerOutputKeys = new Set(snapshots.flatMap(({ snapshot }) => snapshot.compilerOutputKeys));
  for (const record of artifacts) {
    if (!record.authenticated) continue;
    const compilerOutputKey = record.topologyCompilerOutputReference?.cacheKey ?? record.capsuleClosure?.compilerOutputCacheKey;
    if (deployedCompilerOutputKeys.has(compilerOutputKey)) retainArtifact(`${record.stage}\0${record.key}`);
  }
  // Retain each live bundle's pinned input and published output. These small entries preserve
  // unchanged-build identities and the next edit's seed without retaining historical C bundles.
  for (const record of artifacts) {
    if (record.type !== "c-bundle" || !retainedArtifactKeys.has(`${record.stage}\0${record.key}`)) continue;
    for (const reference of record.layoutReferences) {
      const key = `${reference.stage}\0${reference.key}`;
      // Layout entries may already have been evicted independently by an older cache manager.
      if (artifactRecordsByKey.has(key)) retainArtifact(key);
    }
  }
  for (const record of artifacts) {
    if (retainedArtifactKeys.has(`${record.stage}\0${record.key}`)) retainedPaths.add(record.path);
  }
  const candidates = [];
  // A retained lookup directory does not retain its superseded certificate entries. Remove
  // those entries first; their package closures become collectible in the following wave.
  const certificateRecords = certificates.flatMap((root) => retainedPaths.has(root.path)
    ? [root, ...root.certificates] : [root]);
  const objectRecords = [...certificateRecords, ...packages, ...artifacts];
  const retainedRecords = objectRecords.filter((record) => retainedPaths.has(record.path));
  for (const record of objectRecords) {
    if (!record.authenticated || retainedPaths.has(record.path))
      continue;
    candidates.push({
      allocationBytes: record.allocatedBytes,
      estimatedReclaimBytes: record.estimatedReclaimBytes,
      identity: record.treeIdentity,
      key: record.key,
      mtimeMs: record.mtimeMs,
      path: record.path,
      stage: record.stage ?? null,
      // Recovery still accepts older markers with a full inode summary, but new markers only
      // store the stronger compact physical-state digest.
      treeIdentity: record.treeIdentity,
      physicalStateIdentity: record.treeIdentity,
      type: record.type,
      ...(record.removePreferred ? { removePreferred: true } : {}),
    });
  }
  // Retire roots before independent artifacts. Their dependencies stay pinned for this pass;
  // later passes can reclaim the newly unreachable data.
  const removalPriority = { "certificate-entry": 0, "certificate-root": 0, package: 1, artifact: 2, "c-bundle": 2 };
  candidates.sort(
    (left, right) =>
      removalPriority[left.type] - removalPriority[right.type] ||
      right.estimatedReclaimBytes - left.estimatedReclaimBytes ||
      compareStrings(left.path, right.path)
  );
  const evictions = [];
  let estimatedReclaimBytes = 0;
  const diskPressure = immutableAllocatedBytes > highWatermarkAllocatedBytes;
  const reclaimToHighWatermarkBytes = diskPressure
    ? immutableAllocatedBytes - highWatermarkAllocatedBytes
    : 0;
  if (diskPressure) {
    for (const candidate of candidates) {
      evictions.push(candidate);
      estimatedReclaimBytes += candidate.estimatedReclaimBytes;
      if (estimatedReclaimBytes >= reclaimToHighWatermarkBytes) break;
    }
  }
  const payload = {
    authenticated: {
      candidates: candidates.length,
      invalid: [...certificates, ...packages, ...artifacts].filter(
        (record) => !record.authenticated
      ).length,
      orphanedCapsules: artifacts.filter(
        (record) => record.authenticated && record.orphanedCapsuleDependencies !== undefined
      ).length,
      orphanedTopologyCertificates: artifacts.filter(
        (record) => record.authenticated && record.orphanedTopologyCertificate !== undefined
      ).length,
      retainedArtifacts: retainedArtifactKeys.size,
      retainedCertificates: retainedCertificateSha256s.size,
      retainedPackages: retainedPackageKeys.size,
      retainedSnapshots: snapshots.length,
    },
    bounds: {
      highWatermarkAllocatedBytes,
      maxRetainedPackages,
    },
    candidates: candidates.length,
    categories: {
      retained: {
        allocatedBytes: retainedRecords.reduce(
          (total, record) => total + (record.allocatedBytes ?? 0),
          0
        ),
        count: retainedRecords.length + snapshots.length,
      },
      invalid: {
        allocatedBytes: objectRecords
          .filter((record) => !record.authenticated)
          .reduce((total, record) => total + (record.allocatedBytes ?? 0), 0),
        count: objectRecords.filter((record) => !record.authenticated).length,
      },
      candidates: {
        allocatedBytes: candidates.reduce(
          (total, candidate) => total + candidate.allocationBytes,
          0
        ),
        count: candidates.length,
      },
      planningOnlyCandidates: {
        allocatedBytes: 0,
        count: 0,
      },
      sweepableCandidates: {
        allocatedBytes: candidates.reduce(
          (total, candidate) => total + candidate.allocationBytes,
          0
        ),
        count: candidates.length,
      },
    },
    createdAtMs: nowMs,
    evictions,
    estimatedReclaimBytes,
    incomplete: estimatedReclaimBytes < reclaimToHighWatermarkBytes,
    kind: "convex-wasm-immutable-gc-plan-v1",
    pressure: {
      active: diskPressure,
      immutableAllocatedBytes,
      reclaimToHighWatermarkBytes,
    },
    retained: {
      artifacts: [...retainedArtifactKeys].sort(compareStrings),
      certificates: [...retainedCertificateSha256s].sort(compareStrings),
      packages: [...retainedPackageKeys].sort(compareStrings),
      snapshots: snapshots.map(({ name }) => name).sort(compareStrings),
    },
  };
  return { candidates, plan: { ...payload, planSha256: fingerprintJson(payload) } };
}

async function planConvexWasmImmutableGcMeasured({
  cacheLayout: rawCacheLayout,
  cacheLock = convexWasmCacheLock,
  environment = process.env,
  highWatermarkAllocatedBytes = unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes,
  maxRetainedPackages = defaultConvexWasmImmutableMaxRetainedPackages,
  nowMs = Date.now(),
} = {}) {
  cacheLock.requireAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  requireLimit(nowMs, "GC planning time", false);
  requireLimit(maxRetainedPackages, "maximum retained packages");
  requireLimit(highWatermarkAllocatedBytes, "immutable high watermark");
  const [inventory, immutableAllocatedBytes] = await settleConcurrentWork([
    measureConvexWasmRetentionPhase("inventory", () =>
      withPrivateCacheAncestorValidation(() => collectImmutableInventory(cacheLayout))),
    immutableCacheAllocatedBytes(cacheLayout),
  ]);
  return (await measureConvexWasmRetentionPhase("planDerivation", () => deriveImmutablePlan({
    inventory, immutableAllocatedBytes, highWatermarkAllocatedBytes, maxRetainedPackages,
    nowMs,
  }))).plan;
}


export async function sweepConvexWasmImmutableGc({
  cacheLayout: rawCacheLayout,
  cacheLock = convexWasmCacheLock,
  environment = process.env,
  highWatermarkAllocatedBytes = unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes,
  maxRetainedPackages = defaultConvexWasmImmutableMaxRetainedPackages,
  nowMs = Date.now(),
} = {}) {
  cacheLock.requireAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  const recovered = await removeQuarantinedImmutableGcCandidates(cacheLayout);
  const plan = await planConvexWasmImmutableGc({
    cacheLayout,
    cacheLock,
    environment,
    highWatermarkAllocatedBytes,
    maxRetainedPackages,
    nowMs,
  });
  return { ...await sweepImmutablePlan({ cacheLayout, plan }), recovered };
}

export async function maintainConvexWasmImmutableGc({
  cacheLayout: rawCacheLayout,
  initialImmutableAllocatedBytes,
  cacheLock = convexWasmCacheLock,
  environment = process.env,
  highWatermarkAllocatedBytes = unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes,
  maxRetainedPackages = defaultConvexWasmImmutableMaxRetainedPackages,
  nowMs = Date.now(),
}) {
  cacheLock.requireAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  requireLimit(nowMs, "GC planning time", false);
  requireLimit(maxRetainedPackages, "maximum retained packages");
  requireLimit(highWatermarkAllocatedBytes, "immutable high watermark");
  if (initialImmutableAllocatedBytes !== undefined) requireLimit(initialImmutableAllocatedBytes, "initial immutable occupancy", false);
  const recovered = await removeQuarantinedImmutableGcCandidates(cacheLayout);
  const fence = await captureInventoryFence(cacheLayout);
  let inventory = await readImmutableInventoryIndex(cacheLayout, fence);
  let inventoryFromIndex = inventory !== undefined;
  if (inventory !== undefined) {
    const snapshots = await listSnapshots(cacheLayout);
    const snapshotProjection = (values) => values.map(({ path, name, rawSnapshot, snapshot }) => ({
      name, path, rawSnapshot, snapshot,
    }));
    if (canonicalJson(snapshotProjection(inventory.snapshots)) === canonicalJson(snapshotProjection(snapshots))) {
      inventory = { ...inventory, snapshots };
    } else {
      inventory = undefined;
      inventoryFromIndex = false;
    }
  }
  if (inventory === undefined) {
    inventory = await measureConvexWasmRetentionPhase("inventory", () =>
      withPrivateCacheAncestorValidation(
        () => collectImmutableInventory(cacheLayout, fence),
        {
          trustedDirectories: trustedInventoryDirectories(fence),
          trustedFiles: trustedInventoryFiles(fence),
          trustedNoSymlinkAncestors: new Set([dirname(cacheLayout.cacheRoot)]),
        }
      ));
  }
  // The fence already observed every inode and its allocated blocks. Compute occupancy
  // from that one measured state rather than issuing another whole-tree walk. Supported cache
  // publishers and builders are excluded by the same lock; selected roots are reauthenticated
  // immediately before their rename.
  const fenceOccupancy = await measureConvexWasmRetentionPhase(
    "immutableOccupancy",
    () => createFenceOccupancy(cacheLayout, fence)
  );
  // Automatic admission measured earlier, before recovery and inventory authentication.
  // Reuse that measurement only if the current fence agrees: intervening cleanup must not
  // leave stale pressure authorizing eviction below the watermark. This adds no filesystem walk.
  let remainingAllocatedBytes;
  if (initialImmutableAllocatedBytes === undefined) {
    remainingAllocatedBytes = fenceOccupancy.allocatedBytes;
  } else {
    remainingAllocatedBytes = fenceOccupancy.allocatedBytes;
    if (remainingAllocatedBytes !== initialImmutableAllocatedBytes) {
      fail("immutable occupancy changed after automatic admission");
    }
  }
  const removed = [];
  const waves = [];
  let removedAuthorityPaths = new Set();
  let records = inventoryRecordsByPath(inventory);
  const derive = () => measureConvexWasmRetentionPhase("planDerivation", () => deriveImmutablePlan({
    inventory, immutableAllocatedBytes: remainingAllocatedBytes, highWatermarkAllocatedBytes,
    maxRetainedPackages, nowMs,
  }));
  let { plan, candidates } = await derive();
  if (inventoryFromIndex && remainingAllocatedBytes > highWatermarkAllocatedBytes && candidates.length !== 0) {
    // The persisted index is a performance cache, not authenticated authority. A pressure run
    // must rebuild the complete payload-derived inventory before selecting any deletion wave;
    // otherwise a self-consistent index edit could remove a live closure edge while retaining its
    // valid physical witnesses. Runs below the watermark may continue using the index because
    // they perform no deletion, and a forged index can only defer reclamation there.
    inventory = await measureConvexWasmRetentionPhase("inventory", () =>
      withPrivateCacheAncestorValidation(
        () => collectImmutableInventory(cacheLayout, fence),
        {
          trustedDirectories: trustedInventoryDirectories(fence),
          trustedFiles: trustedInventoryFiles(fence),
          trustedNoSymlinkAncestors: new Set([dirname(cacheLayout.cacheRoot)]),
        }
      ));
    inventoryFromIndex = false;
    records = inventoryRecordsByPath(inventory);
    ({ plan, candidates } = await derive());
  }
  for (;;) {
    if (remainingAllocatedBytes <= highWatermarkAllocatedBytes || candidates.length === 0) {
      // A removal changes directory membership and hard-link counts, so the original fence is
      // no longer a valid index binding. Capture the settled state once and refresh surviving
      // record witnesses before persisting the derived inventory, so hard-link changes caused by
      // this invocation cannot turn the next index hit into stale rename authority.
      const settledFence = removed.length === 0 ? fence : await captureInventoryFence(cacheLayout);
      if (removed.length !== 0) refreshInventoryPhysicalStats(inventory, settledFence);
      // Snapshot publication is excluded by the shared cache lock, so the authenticated
      // snapshot record from this invocation remains valid while immutable roots are retired.
      // An empty cache root is a valid no-op for explicit maintenance. Do not create a
      // retention index (and its state ancestors) merely to record an empty inventory; callers
      // that later publish cache material create and authenticate those roots themselves.
      if (await exists(cacheLayout.cacheRoot)) {
        await persistImmutableInventoryIndex(cacheLayout, settledFence, inventory);
      }
      return {
        kind: "convex-wasm-immutable-gc-sweep-v1", plan, recovered, removed, waves, skipped: 0,
        remainingAllocatedBytes,
        remainingExcessBytes: Math.max(0, remainingAllocatedBytes - highWatermarkAllocatedBytes),
        termination: remainingAllocatedBytes <= highWatermarkAllocatedBytes ? "watermark-reached" : "no-eligible-candidates",
      };
    }
    if (waves.length !== 0) {
      // Earlier unlinks can change the physical witnesses of roots that share hard-linked
      // payloads. Refresh only the next wave's selected roots, rather than reopening every
      // eligible record before deriving the plan.
      const validation = { packages: new Map(), artifacts: new Map(), structured: new Map(), structuredBytes: 0, cacheRoot: cacheLayout.cacheRoot };
      await measureConvexWasmRetentionPhase("candidateRefresh", async () => {
        for (const candidate of plan.evictions) {
          const { stats } = await authenticateEvictionRoot(cacheLayout, candidate, validation);
          Object.assign(records.get(candidate.path), stats);
        }
      });
      ({ plan, candidates } = await derive());
    }
    const removedPaths = plannedWaveRemovedPaths(fence, plan.evictions, removedAuthorityPaths);
    const started = performance.now();
    // Freshly collected inventory may reuse its in-memory authentication within this locked
    // invocation. An index-derived plan is only allowed to reach this point after the complete
    // inventory rebuild above; retain the fallback reauthentication for defensive callers.
    const wave = await sweepImmutablePlan({ cacheLayout, plan, authenticatedCandidates: records });
    const deleted = new Set(wave.removed.map(({ path }) => path));
    if (deleted.size !== plan.evictions.length) fail("immutable wave did not remove every selected root");
    removedAuthorityPaths = removedPaths;
    for (const family of ["certificates", "packages", "artifacts"]) {
      inventory[family] = inventory[family].filter(({ path }) => !deleted.has(path));
    }
    for (const root of inventory.certificates) {
      if (root.certificates === undefined) continue;
      root.certificates = root.certificates.filter(({ path }) => !deleted.has(path));
      root.packageKeys = [...new Set(root.certificates.flatMap(({ packageKeys }) => packageKeys))];
    }
    removed.push(...wave.removed);
    // The static fence records every inode path. Applying the completed wave in memory accounts
    // for shared hardlinks exactly, without another whole-cache occupancy walk.
    remainingAllocatedBytes = applyFenceRemovals(fenceOccupancy, fence, removedPaths);
    waves.push({ wave: waves.length + 1, selected: plan.evictions.length, removed: wave.removed.length,
      remainingAllocatedBytes, elapsedMilliseconds: performance.now() - started });
    ({ plan, candidates } = await derive());
  }
}

// This operation executes exactly one already-minted plan. The public low-level sweeper
// retains its one-plan contract; only top-level maintenance advances dependency waves.
async function sweepImmutablePlan({ cacheLayout, plan, authenticatedCandidates }) {
  const removed = [];
  if (plan.evictions.length === 0) {
    return {
      kind: "convex-wasm-immutable-gc-sweep-v1",
      plan,
      removed,
      skipped: 0,
    };
  }
  const trashBaseRoot = immutableSweepTrashRoot(cacheLayout);
  const trashRoot = join(trashBaseRoot, plan.planSha256);
  // Recursive mkdir follows an existing symlink ancestor. Authenticate every known ancestor
  // after creation so a redirected state tree cannot receive quarantined artifacts. Directory
  // durability is covered by the single journal publication below; it need not be synced once
  // per candidate.
  await createPrivateDirectoryTree(cacheLayout.cacheRoot, [
    join(cacheLayout.cacheRoot, "state"),
    cacheLayout.state.root,
    join(cacheLayout.state.root, "cache-retention"),
    join(cacheLayout.state.root, "cache-retention", "v1"),
    trashBaseRoot,
    trashRoot,
  ]);
  // Deletion starts a fresh scope, independent of planning. Selected roots still reopen and
  // check their current physical state. One durable journal covers the whole wave; a crash can
  // therefore recover every root that was actually renamed without a marker and directory sync
  // for each entry.
  const validation = { packages: new Map(), artifacts: new Map(), structured: new Map(), structuredBytes: 0, cacheRoot: cacheLayout.cacheRoot };
  const journal = immutableSweepJournal(plan);
  await measureConvexWasmRetentionPhase("quarantine", () => writePrivateDurableFile(
    cacheLayout.cacheRoot,
    join(trashRoot, "journal.json"),
    `${canonicalJson(journal)}\n`
  ));
  const quarantineEntries = plan.evictions.map((candidate) => ({
    candidate,
    candidateSha256: immutableSweepQuarantineRecord(plan.planSha256, candidate).candidateSha256,
    path: candidate.path,
  }));
  await measureConvexWasmRetentionPhase("quarantine", async () => {
    // A prepared but undeployed certificate can own PREFERRED. Removing that pointer before its
    // target leaves ordinary lookup free to select the surviving deployed certificate. The
    // pointer is small and is still covered by the existing cache lock.
    const authenticated = await mapBounded(
      plan.evictions,
      16,
      (candidate) => {
        const fromInventory = authenticatedInventoryCandidate(
          candidate,
          authenticatedCandidates?.get(candidate.path)
        );
        return fromInventory ?? reauthenticateEvictionCandidate(cacheLayout, candidate, validation);
      }
    );
    const authenticatedByPath = new Map(authenticated.map(({ path: authenticatedPath, stats }) => [
      authenticatedPath,
      stats,
    ]));
    await mapBounded(quarantineEntries, 16, async ({ candidate, candidateSha256, path }) => {
      // Keep the fresh authentication paired with the rename; no second tree walk is needed
      // after the atomic move because the cache lock excludes supported writers.
      if (!authenticatedByPath.has(path)) fail(`immutable eviction candidate path changed: ${path}`);
      if (candidate.removePreferred) await fs.unlink(join(dirname(path), "PREFERRED"));
      await fs.rename(path, join(trashRoot, candidateSha256));
    });
  });
  await measureConvexWasmRetentionPhase("quarantine", () => syncDirectory(trashRoot));
  await measureConvexWasmRetentionPhase("unlink", async () => {
    const removedFlags = await mapBounded(quarantineEntries, 16, async ({ candidateSha256 }) => {
      const trashPath = join(trashRoot, candidateSha256);
      if (await exists(trashPath)) {
        await removeConvexWasmCacheTree(trashPath);
        return true;
      }
      return false;
    });
    for (const [index, wasRemoved] of removedFlags.entries()) {
      if (wasRemoved) removed.push(quarantineEntries[index].candidate);
    }
    await syncDirectory(trashRoot);
  });
  await fs.unlink(join(trashRoot, "journal.json"));
  await syncDirectory(trashRoot);
  await fs.rmdir(trashRoot);
  await fs.rmdir(trashBaseRoot);
  await syncDirectory(dirname(trashBaseRoot));
  return {
    kind: "convex-wasm-immutable-gc-sweep-v1",
    plan,
    removed,
    skipped: plan.evictions.length - removed.length,
  };
}

async function immutableCacheAllocatedBytes(...args) {
  return await measureConvexWasmRetentionPhase("immutableOccupancy", () =>
    measureConvexWasmRetentionPhase("immutableOccupancyWalk", () => immutableCacheAllocatedBytesMeasured(...args)));
}

async function removeQuarantinedImmutableGcCandidates(...args) {
  return await measureConvexWasmRetentionPhase("recovery", () => removeQuarantinedImmutableGcCandidatesMeasured(...args));
}

async function reauthenticateEvictionCandidate(...args) {
  return await measureConvexWasmRetentionPhase("selectedAuthentication", () => reauthenticateEvictionCandidateMeasured(...args));
}

export async function planConvexWasmImmutableGc(...args) {
  return await measureConvexWasmRetentionPhase("plan", () => planConvexWasmImmutableGcMeasured(...args));
}

// Recovery is independent of new pressure eviction: a recent automatic receipt must not
// strand a failed explicit sweep's durable quarantine outside the measured immutable tree.
export async function recoverConvexWasmImmutableGc({ cacheLayout, cacheLock = convexWasmCacheLock, environment = process.env }) {
  cacheLock.requireAuthority(environment);
  return await removeQuarantinedImmutableGcCandidates(normalizeConvexWasmCacheLayout(cacheLayout));
}
