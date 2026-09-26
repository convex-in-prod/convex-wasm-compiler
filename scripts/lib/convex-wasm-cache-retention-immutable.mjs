import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
  requireSha256,
} from "./convex-wasm-artifact-contract.mjs";
import { decodeUtf8, readPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import { requireConvexWasmCacheLockAuthority } from "./convex-wasm-cache-lock.mjs";
import { validateArtifactCacheEntry } from "./convex-wasm-artifact-cache-entry.mjs";
import {
  authenticateStaticHermesCBundle,
  normalizeStaticHermesCBundleOutput,
  staticHermesCBundleMembers,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "./convex-wasm-module-graph-package.mjs";
import {
  normalizeConvexWasmCacheLayout,
} from "./convex-wasm-cache-layout.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheDirectoryFileIdentities,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import {
  normalizeConvexWasmCompilerDescriptorCacheProjection,
  normalizeConvexWasmCompilerOutputCacheIdentity,
} from "./convex-wasm-compiler-topology-witness.mjs";
import {
  convexWasmOfficialOutputCohortCapsuleKind,
  convexWasmOfficialOutputCohortCapsuleStage,
  normalizeConvexWasmOfficialOutputCohortCapsuleIdentity,
} from "./convex-wasm-official-output-cohort-capsule-identity.mjs";
import {
  authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry,
  convexWasmRuntimeHeaderSnapshotCacheEntryKind,
  convexWasmRuntimeHeaderSnapshotCacheStage,
} from "./convex-wasm-runtime-header-snapshot-cache.mjs";

export const defaultConvexWasmImmutableRecentRetentionMilliseconds = 24 * 60 * 60 * 1_000;
export const defaultConvexWasmImmutableMaxPlannedEvictions = 4_096;
export const defaultConvexWasmImmutableMaxEstimatedReclaimBytes = 8 * 1024 ** 3;
export const defaultConvexWasmImmutableMaxRetainedPackages = 512;
// An unconfigured plan can inspect the cache but cannot authorize pressure-based eviction.
// The caller chooses a high watermark for any sweep.
export const unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes = Number.MAX_SAFE_INTEGER;

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const ARTIFACT_PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const C_BUNDLE_ENTRY_KIND = "convex-wasm-c-bundle-cache-entry-v1";
const CERTIFICATE_KIND = "convex-wasm-deployment-result-certificate-v2";
const SNAPSHOT_KIND = "convex-wasm-cache-recent-success-v1";
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
const MAX_COHORT_CAPSULE_BYTES = 8 * 1024 * 1024;
const MAX_RECENT_SUCCESS_SNAPSHOT_BYTES = 64 * 1024;
const MAX_SWEEP_QUARANTINE_RECORD_BYTES = 64 * 1024;
const MAX_RECENT_SUCCESS_SNAPSHOT_CERTIFICATES = 8;
const MAX_RECENT_SUCCESS_SNAPSHOT_COMPILER_OUTPUTS = 256;
const MAX_RECENT_SUCCESS_SNAPSHOT_PACKAGES = 256;
const MAX_LEGACY_MODULE_GRAPH_PACKAGE_MODULES = 1_024;
// The producer accepts up to 1,024 physical application units. Retention must authenticate the
// complete closure of every output the producer can publish.
const MAX_COMPILER_OUTPUT_APPLICATION_UNITS = 1_024;
const GENERIC_ARTIFACT_EXTENSIONS = new Set(["a", "c", "cwasm", "js", "json", "o", "pch", "wasm"]);
const COMPILER_OUTPUT_GENERATED_C_EXTENSIONS = new Set(["c", "c-bundle"]);
const COMPILER_OUTPUT_AOT_EXTENSIONS = new Set(["cwasm"]);
const COMPILER_OUTPUT_OBJECT_EXTENSIONS = new Set(["o"]);

function fail(message) {
  throw new Error(`Convex Wasm immutable cache retention: ${message}`);
}

function recentSuccessRoot(cacheRoot) {
  return join(resolve(cacheRoot), "state", "v1", "cache-retention", "v1", "recent-success");
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
  if (`${canonicalJson(value)}\n` !== source) fail(`${description} is not canonical JSON: ${path}`);
  return value;
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

async function treeStats(path) {
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
    physicalStates.push({
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

async function topologyCertificateCompilerOutputReference(entry) {
  if (entry.stage !== MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_STAGE) return undefined;
  if (
    canonicalJson(entry.metadata) !==
    canonicalJson({ kind: MODULE_GRAPH_COMPILER_OUTPUT_TOPOLOGY_CACHE_KIND })
  ) {
    // Rotated topology-certificate schemas are not selected by the current producer and remain
    // ordinary age-bounded artifacts.
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
  const certificate = await readCanonical(
    entry.artifactPath,
    MAX_COMPILER_OUTPUT_CACHE_BYTES,
    "compiler-output topology certificate",
    entry
  );
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
    // The v6 predecessor cannot be selected by the v7 producer. Authenticate its complete
    // self-contained certificate before leaving it as an ordinary age-bounded artifact.
    return undefined;
  }
  return {
    cacheIdentity,
    cacheKey,
    cacheRecordSha256,
  };
}

async function compilerOutputArtifactKeys(entry) {
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
  const record = await readCanonical(
    entry.artifactPath,
    MAX_COMPILER_OUTPUT_CACHE_BYTES,
    "compiler-output cache record",
    entry
  );
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
    // strict v7 lookup identity, and exact comparison below bind that compact authority without
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

async function cohortCapsuleArtifactClosure(entry, cacheLayout) {
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
    // age-bounded artifact rather than making an existing legacy cache block current retention
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
    MAX_COHORT_CAPSULE_BYTES,
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
  // Close the v7 identity shape before deriving or following any immutable references. A kind
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
      const compilerOutputEntry = await validateArtifactCacheEntry(
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
      // Legacy records cannot satisfy v5 closure merely because a certificate describes them.
      if (compilerOutputCacheEntrySchema(compilerOutputEntry) !== "current") {
        fail("cohort capsule compiler-output cache record has an unsupported schema");
      }
      const record = await readCanonical(
        compilerOutputEntry.artifactPath,
        MAX_COMPILER_OUTPUT_CACHE_BYTES,
        "cohort capsule compiler-output cache record",
        compilerOutputEntry
      );
      if (sha256(Buffer.from(canonicalJson(record))) !== compilerOutputCacheRecordSha256) {
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
      const topologyCertificateEntry = await validateArtifactCacheEntry(
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
        certificate: await readCanonical(
          topologyCertificateEntry.artifactPath,
          MAX_COMPILER_OUTPUT_CACHE_BYTES,
          "cohort capsule compiler-output topology certificate",
          topologyCertificateEntry
        ),
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
    // retention authority, but it is safe to treat the capsule itself as an age-bounded artifact.
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

async function authenticateGenericArtifact({ cacheLayout, key, path, stage }) {
  const metadata = await readCanonical(
    join(path, "entry.json"),
    MAX_METADATA_BYTES,
    "artifact entry"
  );
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
  const entry = await validateArtifactCacheEntry(
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
      cohortCapsuleArtifactClosure(entry, cacheLayout),
      compilerOutputArtifactKeys(entry),
      topologyCertificateCompilerOutputReference(entry),
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

async function authenticateArtifactFamily({ cacheLayout, key, metadata, path, stage }) {
  if (
    metadata.kind === convexWasmRuntimeHeaderSnapshotCacheEntryKind ||
    stage === convexWasmRuntimeHeaderSnapshotCacheStage
  ) {
    return await authenticateRuntimeHeaderSnapshot({ cacheLayout, key, path, stage });
  }
  return await authenticateGenericArtifact({ cacheLayout, key, path, stage });
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

async function listArtifactEntries(cacheLayout) {
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
    for (const key of stageListing.names) {
      // Artifact publishers stage complete entries in private sibling directories. A process
      // crash can leave one behind; it is not an immutable entry and must not make maintenance
      // fail closed for otherwise valid cache contents.
      if (key.startsWith(".publish-")) continue;
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
            : await authenticateArtifactFamily({ cacheLayout, key, metadata, path, stage });
        records.push({ ...(await treeStats(path)), ...authenticated, authenticated: true });
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
          stats = await treeStats(path);
        } catch {
          // Keep an unsafe or disappearing object in the invalid set without granting authority.
        }
        records.push({
          ...stats,
          path,
          key,
          stage,
          type: "artifact",
          authenticated: false,
          reason: "authentication-failed",
        });
      }
    }
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
        const entry = await validateArtifactCacheEntry(
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
        const entry = await validateArtifactCacheEntry(
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

async function authenticatePackage(cacheLayout, key, path, packageMaterial, expectedGraphManifest) {
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
    });
  } else if (
    (manifest.kind === MODULE_GRAPH_MANIFEST_V3_KIND && manifest.schemaVersion === 3) ||
    (manifest.kind === MODULE_GRAPH_MANIFEST_V5_KIND && manifest.schemaVersion === 5)
  ) {
    verified = await loadAndVerifyConvexWasmModuleGraphPackage({
      cacheLayout,
      cacheRoot: cacheLayout.cacheRoot,
      ...(packageMaterial === undefined ? {} : { authenticatedPackageMaterial: packageMaterial }),
      ...(expectedGraphManifest === undefined ? {} : { expectedGraphManifest }),
      graphManifestSha256: key,
      packagePath: path,
    });
  } else fail("module graph package manifest has an unsupported kind or schema version");
  return {
    key,
    path,
    type: "package",
    artifactKeys:
      verified.packageMaterial?.artifactReferences?.flatMap((reference) => [
        `${reference.aot.artifact.stage}\0${reference.aot.artifact.cacheKey}`,
        `${reference.coreWasm.artifact.stage}\0${reference.coreWasm.artifact.cacheKey}`,
      ]) ?? [],
    graphManifest: verified.graphManifest,
  };
}

async function listPackages(cacheLayout) {
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
      const verified = await authenticatePackage(cacheLayout, key, path);
      records.push({ ...(await treeStats(path)), ...verified, authenticated: true });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      let stats = {};
      try {
        stats = await treeStats(path);
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

async function listCertificates(cacheLayout, packagesByKey, snapshotCertificateSha256s) {
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
      // Older valid lookup roots contain only immutable certificate directories. Match the
      // deployment reader's preferred certificate when present, but a recent-success snapshot is
      // independent retention authority. Schema migration and interrupted pointer publication can
      // legitimately leave multiple complete certificates in one lookup root, and a successful
      // legacy hit can record its older SHA after a compact successor becomes preferred.
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
        const selectedNames = new Set([preferred]);
        for (const name of names) {
          if (snapshotCertificateSha256s.has(name)) selectedNames.add(name);
        }
        names.splice(0, names.length, ...[...selectedNames].sort(compareStrings));
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
            continue;
          }
          const verified = await authenticatePackage(
            cacheLayout,
            contract.key,
            packagePath,
            contract.packageMaterial,
            contract.graphManifest
          );
          if (!packagesByKey.has(contract.key) || verified.key !== contract.key) {
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
        certificates.push({ certificate, contracts, key, path });
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
        ...new Set(certificates.flatMap(({ contracts }) => contracts.map(({ key }) => key))),
      ].sort(compareStrings);
      if (missingPackageKeys.size !== 0) {
        // The certificate bytes still authenticate, but an older cleanup removed some package
        // directories. Such a root cannot retain a complete deployment and must not make newer
        // cache entries undeletable. Existing but invalid package directories still fail above.
        records.push({
          ...(await treeStats(lookupRoot)),
          authenticated: false,
          key: lookupKey,
          missingPackageKeys: [...missingPackageKeys].sort(compareStrings),
          path: lookupRoot,
          reason: "missing-package-dependency",
          type: "certificate-root",
        });
        continue;
      }
      for (const key of packageKeys) {
        if (!packagesByKey.has(key)) fail(`certificate references an unavailable package: ${key}`);
      }
      records.push({
        ...(await treeStats(lookupRoot)),
        path: lookupRoot,
        key: lookupKey,
        type: "certificate-root",
        packageKeys,
        certificates,
        authenticated: true,
      });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      let stats = {};
      try {
        stats = await treeStats(lookupRoot);
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
  const root = recentSuccessRoot(cacheLayout.cacheRoot);
  if (!(await exists(root))) return [];
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const records = [];
  const rootListing = await readStableDirectoryNames(root, "recent-success root");
  for (const name of rootListing.names) {
    if (name.startsWith(".publish-")) continue;
    if (!/^[0-9a-f]{64}\.json$/u.test(name)) {
      fail(`recent-success root has an unexpected entry: ${join(root, name)}`);
    }
    const path = join(root, name);
    try {
      await requirePrivateCacheFile(cacheLayout.cacheRoot, path);
      const fileIdentity = await fs.lstat(path);
      const snapshot = await readCanonical(
        path,
        MAX_RECENT_SUCCESS_SNAPSHOT_BYTES,
        "recent-success snapshot",
        undefined,
        fileIdentity
      );
      const { snapshotSha256: ignored, ...payload } = snapshot;
      if (
        snapshot.kind !== SNAPSHOT_KIND ||
        snapshot.snapshotSha256 !== name.slice(0, -5) ||
        fingerprintJson(payload) !== snapshot.snapshotSha256
      ) {
        fail(`recent-success snapshot authentication failed: ${path}`);
      }
      const legacy = snapshot.schemaVersion === 1;
      if (!legacy && snapshot.schemaVersion !== 2) {
        fail(`recent-success snapshot schema is unsupported: ${path}`);
      }
      requireExactKeys(
        snapshot,
        legacy
          ? [
              "buildId",
              "deploymentSha256",
              "kind",
              "packageKeys",
              "recordedAtMs",
              "schemaVersion",
              "snapshotSha256",
            ]
          : [
              "buildId",
              "certificateSha256s",
              "compilerOutputKeys",
              "deploymentSha256",
              "kind",
              "packageKeys",
              "recordedAtMs",
              "schemaVersion",
              "snapshotSha256",
            ],
        "recent-success snapshot"
      );
      if (
        !Number.isSafeInteger(snapshot.recordedAtMs) ||
        snapshot.recordedAtMs < 0 ||
        requireSha256(snapshot.deploymentSha256, "recent-success deployment SHA-256") !==
          snapshot.deploymentSha256
      ) {
        fail(`recent-success snapshot metadata is invalid: ${path}`);
      }
      records.push({
        path,
        name,
        fileIdentity,
        rawSnapshot: snapshot,
        snapshot: {
          ...(legacy
            ? { certificateSha256s: [], compilerOutputKeys: [] }
            : {
                certificateSha256s: requireSha256List(
                  snapshot.certificateSha256s,
                  "recent-success certificate SHA-256 values",
                  MAX_RECENT_SUCCESS_SNAPSHOT_CERTIFICATES
                ),
                compilerOutputKeys: requireSha256List(
                  snapshot.compilerOutputKeys,
                  "recent-success compiler-output cache keys",
                  MAX_RECENT_SUCCESS_SNAPSHOT_COMPILER_OUTPUTS
                ),
              }),
          packageKeys: requireSha256List(
            snapshot.packageKeys,
            "recent-success package SHA-256 values",
            MAX_RECENT_SUCCESS_SNAPSHOT_PACKAGES
          ),
        },
        authenticated: true,
      });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      fail(`recent-success authority is corrupt: ${path}`);
    }
  }
  for (const { fileIdentity, path, rawSnapshot } of records) {
    const finalSnapshot = await readCanonical(
      path,
      MAX_RECENT_SUCCESS_SNAPSHOT_BYTES,
      "recent-success snapshot",
      undefined,
      fileIdentity
    );
    if (canonicalJson(finalSnapshot) !== canonicalJson(rawSnapshot)) {
      fail(`recent-success snapshot changed while its authority was authenticated: ${path}`);
    }
  }
  await verifyStableDirectoryNames(
    root,
    rootListing,
    rootListing.names,
    "recent-success root",
    ".publish-"
  );
  return records;
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

async function immutableCacheAllocatedBytes(cacheLayout) {
  if (!(await exists(cacheLayout.immutable.root))) return 0;
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, cacheLayout.immutable.root);
  return (await treeStats(cacheLayout.immutable.root)).allocatedBytes;
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

function matchesQuarantineCandidateTree(stats, candidate) {
  if (candidate.physicalStateIdentity !== undefined) {
    if (stats.treeIdentity !== candidate.physicalStateIdentity) return false;
    // Older durable markers also carry the full inode summary. New markers use the digest in
    // both fields so large bundles cannot exceed the bounded quarantine record size.
    if (candidate.treeIdentity === candidate.physicalStateIdentity) return true;
  }
  return stats.identity === candidate.treeIdentity;
}

async function createPrivateDirectory(cacheRoot, directory) {
  try {
    await fs.mkdir(directory, { mode: 0o700 });
  } catch (error) {
    if (!(missing(error) || (error instanceof Error && error.code === "EEXIST"))) throw error;
  }
  await requirePrivateCacheDirectory(cacheRoot, directory);
  // Persist the directory entry in its parent before a later rename depends on this quarantine
  // path surviving a host crash.
  await syncDirectory(dirname(directory));
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
  const handle = await fs.open(path, "wx", 0o600);
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await requirePrivateCacheFile(cacheRoot, path);
  await syncDirectory(dirname(path));
}

async function removeQuarantinedImmutableGcCandidates(cacheLayout) {
  const root = immutableSweepTrashRoot(cacheLayout);
  if (!(await exists(root))) return [];
  await requirePrivateCacheDirectory(cacheLayout.cacheRoot, root);
  const recovered = [];
  for (const planSha256 of (await fs.readdir(root)).sort(compareStrings)) {
    requireSha256(planSha256, "quarantined immutable sweep plan SHA-256");
    const planRoot = join(root, planSha256);
    await requirePrivateCacheDirectory(cacheLayout.cacheRoot, planRoot);
    const names = (await fs.readdir(planRoot)).sort(compareStrings);
    const candidateRoots = new Set(names.filter((name) => SHA256_PATTERN.test(name)));
    const markerNames = names.filter((name) => /^[0-9a-f]{64}\.json$/u.test(name));
    const verifiedMarkerNames = new Set(
      names.filter((name) => /^[0-9a-f]{64}\.verified\.json$/u.test(name))
    );
    if (candidateRoots.size + markerNames.length + verifiedMarkerNames.size !== names.length) {
      fail(`immutable sweep quarantine has an unexpected entry: ${planRoot}`);
    }
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
      const canonicalPath = evictionArtifactPath(cacheLayout, record.candidate);
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
      if (candidateRoots.has(candidateSha256)) {
        let candidatePresent = true;
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
          try {
            const recoveredStats = await treeStats(candidateRoot);
            // A marker can be observed after a rename but before (or during) removal. If the
            // quarantined tree is still complete, require the exact plan-time state before
            // deleting it; otherwise a concurrent replacement could be mistaken for the planned
            // candidate and irreversibly removed. Missing children are tolerated below only for
            // the crash-after-recursive-removal case covered by the durable marker.
            if (
              recoveredStats.allocatedBytes !== record.candidate.allocationBytes ||
              recoveredStats.estimatedReclaimBytes !== record.candidate.estimatedReclaimBytes ||
              !matchesQuarantineCandidateTree(recoveredStats, record.candidate) ||
              recoveredStats.mtimeMs !== record.candidate.mtimeMs
            ) {
              fail(`quarantined immutable candidate changed before recovery: ${candidateRoot}`);
            }
          } catch (error) {
            // A process can be interrupted after recursive removal deletes one child. Missing
            // children are therefore expected during recovery; any other authentication failure
            // (including a symlink) remains fatal.
            if (!missing(error)) throw error;
          }
          // The complete post-rename state has now been authenticated. Persist a separate
          // removal-authorized marker before recursive deletion so a crash during removal can
          // safely finish a partial tree without treating it as a replacement.
          await writePrivateDurableFile(
            cacheLayout.cacheRoot,
            verifiedMarkerPath,
            `${canonicalJson({ ...record, state: "verified" })}\n`
          );
        }
        if (candidatePresent) {
          await fs.rm(candidateRoot, { force: true, maxRetries: 0, recursive: true });
          // Keep the durable marker until removal of the quarantined tree is itself durable.
          await syncDirectory(planRoot);
        }
        candidateRoots.delete(candidateSha256);
        status = "removed-quarantined-root";
      } else {
        status = (await exists(canonicalPath))
          ? "cleared-pre-rename-marker"
          : "cleared-completed-marker";
      }
      if (await exists(verifiedMarkerPath)) {
        await fs.unlink(verifiedMarkerPath);
        await syncDirectory(planRoot);
      }
      await fs.unlink(markerPath);
      await syncDirectory(planRoot);
      recovered.push({ candidateSha256, planSha256, status });
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
    await fs.rmdir(planRoot);
    await syncDirectory(root);
  }
  await fs.rmdir(root);
  await syncDirectory(dirname(root));
  return recovered;
}

function evictionArtifactPath(cacheLayout, candidate) {
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    Array.isArray(candidate) ||
    (candidate.type !== "artifact" && candidate.type !== "c-bundle") ||
    typeof candidate.stage !== "string" ||
    candidate.stage.length === 0 ||
    candidate.stage.includes("/") ||
    candidate.stage.includes("\\") ||
    requireSha256(candidate.key, "immutable eviction key") !== candidate.key
  ) {
    fail("immutable eviction candidate is invalid");
  }
  const path = join(cacheLayout.immutable.artifacts, candidate.stage, candidate.key);
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

async function reauthenticateEvictionCandidate(cacheLayout, candidate) {
  const path = evictionArtifactPath(cacheLayout, candidate);
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
    });
  } else {
    authenticated = await authenticateCBundle({
      cacheLayout,
      key: candidate.key,
      path,
      stage: candidate.stage,
    });
  }
  const stats = await treeStats(path);
  if (
    authenticated.type !== candidate.type ||
    stats.allocatedBytes !== candidate.allocationBytes ||
    stats.estimatedReclaimBytes !== candidate.estimatedReclaimBytes ||
    !matchesQuarantineCandidateTree(stats, candidate) ||
    stats.mtimeMs !== candidate.mtimeMs
  ) {
    fail(`immutable eviction candidate changed after planning: ${path}`);
  }
  return { path, stats };
}

export async function planConvexWasmImmutableGc({
  cacheLayout: rawCacheLayout,
  environment = process.env,
  highWatermarkAllocatedBytes = unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes,
  maxEstimatedReclaimBytes = defaultConvexWasmImmutableMaxEstimatedReclaimBytes,
  maxPlannedEvictions = defaultConvexWasmImmutableMaxPlannedEvictions,
  maxRetainedPackages = defaultConvexWasmImmutableMaxRetainedPackages,
  nowMs = Date.now(),
  recentRetentionMilliseconds = defaultConvexWasmImmutableRecentRetentionMilliseconds,
} = {}) {
  requireConvexWasmCacheLockAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  requireLimit(nowMs, "GC planning time", false);
  requireLimit(maxEstimatedReclaimBytes, "maximum estimated reclaim bytes");
  requireLimit(maxPlannedEvictions, "maximum planned evictions");
  requireLimit(maxRetainedPackages, "maximum retained packages");
  requireLimit(highWatermarkAllocatedBytes, "immutable high watermark");
  requireLimit(recentRetentionMilliseconds, "recent retention period", false);
  const [allSnapshots, packages, artifacts, immutableAllocatedBytes] = await settleConcurrentWork([
    listSnapshots(cacheLayout),
    listPackages(cacheLayout),
    listArtifactEntries(cacheLayout),
    immutableCacheAllocatedBytes(cacheLayout),
  ]);
  const packagesByKey = new Map(
    packages.filter((record) => record.authenticated).map((record) => [record.key, record])
  );
  const packageRecordsByKey = new Map(packages.map((record) => [record.key, record]));
  const staleSnapshots = [];
  const snapshots = [];
  for (const snapshot of allSnapshots) {
    const missingKeys = snapshot.snapshot.packageKeys.filter((key) => {
      const record = packageRecordsByKey.get(key);
      if (record !== undefined && !record.authenticated) {
        fail(`recent-success snapshot references an invalid package: ${key}`);
      }
      return record === undefined;
    });
    if (missingKeys.length === 0) snapshots.push(snapshot);
    else staleSnapshots.push({ name: snapshot.name, missingPackageKeys: missingKeys });
  }
  const snapshotCertificateSha256s = new Set(
    snapshots.flatMap(({ snapshot }) => snapshot.certificateSha256s)
  );
  const certificates = await listCertificates(
    cacheLayout,
    packagesByKey,
    snapshotCertificateSha256s
  );
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
    if (!root.authenticated) continue;
    for (const certificate of root.certificates) {
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
    for (const contract of certificate.certificate.contracts) retainPackage(contract.key);
  };
  const retainCompilerOutput = (key) => {
    const compilerOutputKey = `${MODULE_GRAPH_COMPILER_OUTPUT_CACHE_STAGE}\0${key}`;
    const compilerOutput = artifactsByKey.get(compilerOutputKey);
    if (compilerOutput === undefined || compilerOutput.type !== "artifact") {
      fail(`retained compiler-output cache entry is unavailable: ${key}`);
    }
    retainArtifact(compilerOutputKey);
    if (compilerOutputCacheEntrySchema(compilerOutput.entry) !== "current") return;
    for (const artifactKey of compilerOutput.closureArtifactKeys) retainArtifact(artifactKey);
  };
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
      // the independently authenticated certificate as an age-bounded artifact so an interrupted
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
      readCanonical(
        compilerOutput.entry.artifactPath,
        MAX_COMPILER_OUTPUT_CACHE_BYTES,
        "compiler-output topology certificate full record",
        compilerOutput.entry
      ),
      readCanonical(
        artifactRecord.entry.artifactPath,
        MAX_COMPILER_OUTPUT_CACHE_BYTES,
        "compiler-output topology certificate",
        artifactRecord.entry
      ),
    ]);
    if (
      sha256(Buffer.from(canonicalJson(record))) !== reference.cacheRecordSha256 ||
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
    retainCompilerOutput(reference.cacheKey);
  }
  // Artifact-only sweeping must not leave a published immutable root pointing at a missing
  // dependency. Package and certificate removal is still planning-only, so every package that is
  // physically present pins its artifact closure even when it is not a retained recent root.
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
      compilerOutputCacheEntrySchema(artifactRecord.entry) !== "current"
    ) {
      continue;
    }
    for (const artifactKey of artifactRecord.closureArtifactKeys) retainArtifact(artifactKey);
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
      readCanonical(
        compilerOutput.entry.artifactPath,
        MAX_COMPILER_OUTPUT_CACHE_BYTES,
        "cohort capsule compiler-output cache record",
        compilerOutput.entry
      ),
      readCanonical(
        topologyCertificate.entry.artifactPath,
        MAX_COMPILER_OUTPUT_CACHE_BYTES,
        "cohort capsule compiler-output topology certificate",
        topologyCertificate.entry
      ),
    ]);
    // The topology certificate binds the canonical record bytes without the trailing newline
    // used by the immutable artifact file. Compare that semantic digest, not the file digest.
    if (
      sha256(Buffer.from(canonicalJson(compilerOutputRecord))) !==
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
    retainCompilerOutput(artifactRecord.capsuleClosure.compilerOutputCacheKey);
    retainArtifact(topologyCertificateArtifactKey);
  }
  for (const snapshot of snapshots) {
    for (const key of snapshot.snapshot.certificateSha256s) retainCertificate(key);
    for (const key of snapshot.snapshot.compilerOutputKeys) retainCompilerOutput(key);
    for (const key of snapshot.snapshot.packageKeys) retainPackage(key);
  }
  const recentCutoffMs = nowMs - recentRetentionMilliseconds;
  for (const record of [...certificates, ...packages, ...artifacts]) {
    if (
      !record.authenticated &&
      record.reason !== "missing-package-dependency" &&
      record.mtimeMs !== undefined &&
      record.mtimeMs >= recentCutoffMs
    ) {
      fail(`recent immutable authority is corrupt: ${record.path}`);
    }
  }
  for (const record of certificates) {
    if (record.authenticated && record.mtimeMs >= recentCutoffMs) {
      retainedPaths.add(record.path);
      for (const certificate of record.certificates)
        retainedCertificateSha256s.add(certificate.key);
      for (const key of record.packageKeys) retainPackage(key);
    }
  }
  for (const record of packages) {
    if (record.authenticated && record.mtimeMs >= recentCutoffMs) {
      retainPackage(record.key);
    }
  }
  for (const record of artifacts) {
    if (record.authenticated && record.mtimeMs >= recentCutoffMs)
      retainedArtifactKeys.add(`${record.stage}\0${record.key}`);
  }
  for (const record of artifacts) {
    if (retainedArtifactKeys.has(`${record.stage}\0${record.key}`)) retainedPaths.add(record.path);
  }
  const candidates = [];
  const objectRecords = [...certificates, ...packages, ...artifacts];
  const retainedRecords = objectRecords.filter((record) => retainedPaths.has(record.path));
  const recentReusableRecords = objectRecords.filter(
    (record) =>
      record.authenticated && !retainedPaths.has(record.path) && record.mtimeMs >= recentCutoffMs
  );
  for (const record of objectRecords) {
    if (!record.authenticated || retainedPaths.has(record.path) || record.mtimeMs >= recentCutoffMs)
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
    });
  }
  // Large expired objects reclaim useful space within the bounded per-run eviction count.
  candidates.sort(
    (left, right) =>
      right.estimatedReclaimBytes - left.estimatedReclaimBytes ||
      compareStrings(left.path, right.path)
  );
  const sweepableCandidates = candidates.filter(
    ({ type }) => type === "artifact" || type === "c-bundle"
  );
  const planningOnlyCandidates = candidates.filter(
    ({ type }) => type !== "artifact" && type !== "c-bundle"
  );
  const evictions = [];
  let estimatedReclaimBytes = 0;
  const diskPressure = immutableAllocatedBytes > highWatermarkAllocatedBytes;
  const reclaimToHighWatermarkBytes = diskPressure
    ? immutableAllocatedBytes - highWatermarkAllocatedBytes
    : 0;
  let incomplete = diskPressure && reclaimToHighWatermarkBytes > maxEstimatedReclaimBytes;
  if (diskPressure) {
    for (const candidate of sweepableCandidates) {
      if (evictions.length >= maxPlannedEvictions) break;
      // A large entry may not fit in the remaining per-pass budget, while
      // smaller entries later in this list still do.
      if (estimatedReclaimBytes + candidate.estimatedReclaimBytes > maxEstimatedReclaimBytes)
        continue;
      evictions.push(candidate);
      estimatedReclaimBytes += candidate.estimatedReclaimBytes;
      if (estimatedReclaimBytes >= reclaimToHighWatermarkBytes) break;
    }
    if (estimatedReclaimBytes < reclaimToHighWatermarkBytes) incomplete = true;
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
      staleSnapshots: staleSnapshots.length,
    },
    bounds: {
      highWatermarkAllocatedBytes,
      maxEstimatedReclaimBytes,
      maxPlannedEvictions,
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
      recentReusable: {
        allocatedBytes: recentReusableRecords.reduce(
          (total, record) => total + (record.allocatedBytes ?? 0),
          0
        ),
        count: recentReusableRecords.length,
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
        allocatedBytes: planningOnlyCandidates.reduce(
          (total, candidate) => total + candidate.allocationBytes,
          0
        ),
        count: planningOnlyCandidates.length,
      },
      sweepableCandidates: {
        allocatedBytes: sweepableCandidates.reduce(
          (total, candidate) => total + candidate.allocationBytes,
          0
        ),
        count: sweepableCandidates.length,
      },
    },
    createdAtMs: nowMs,
    evictions,
    estimatedReclaimBytes,
    incomplete,
    kind: "convex-wasm-immutable-gc-plan-v1",
    pressure: {
      active: diskPressure,
      immutableAllocatedBytes,
      reclaimToHighWatermarkBytes,
    },
    recentRetentionMilliseconds,
    retained: {
      artifacts: [...retainedArtifactKeys].sort(compareStrings),
      certificates: [...retainedCertificateSha256s].sort(compareStrings),
      packages: [...retainedPackageKeys].sort(compareStrings),
      snapshots: snapshots.map(({ name }) => name).sort(compareStrings),
    },
  };
  return { ...payload, planSha256: fingerprintJson(payload) };
}

export async function sweepConvexWasmImmutableGc({
  cacheLayout: rawCacheLayout,
  environment = process.env,
  highWatermarkAllocatedBytes = unconfiguredConvexWasmImmutableHighWatermarkAllocatedBytes,
  maxEstimatedReclaimBytes = defaultConvexWasmImmutableMaxEstimatedReclaimBytes,
  maxPlannedEvictions = defaultConvexWasmImmutableMaxPlannedEvictions,
  maxRetainedPackages = defaultConvexWasmImmutableMaxRetainedPackages,
  nowMs = Date.now(),
  recentRetentionMilliseconds = defaultConvexWasmImmutableRecentRetentionMilliseconds,
} = {}) {
  requireConvexWasmCacheLockAuthority(environment);
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  const recovered = await removeQuarantinedImmutableGcCandidates(cacheLayout);
  const plan = await planConvexWasmImmutableGc({
    cacheLayout,
    environment,
    highWatermarkAllocatedBytes,
    maxEstimatedReclaimBytes,
    maxPlannedEvictions,
    maxRetainedPackages,
    nowMs,
    recentRetentionMilliseconds,
  });
  const removed = [];
  const trashBaseRoot = immutableSweepTrashRoot(cacheLayout);
  const trashRoot = join(trashBaseRoot, plan.planSha256);
  if (plan.evictions.length !== 0) {
    // Recursive mkdir follows an existing symlink ancestor. Create and authenticate each state
    // directory separately so a redirected `state` tree cannot receive quarantined artifacts.
    for (const directory of [
      join(cacheLayout.cacheRoot, "state"),
      cacheLayout.state.root,
      join(cacheLayout.state.root, "cache-retention"),
      join(cacheLayout.state.root, "cache-retention", "v1"),
      trashBaseRoot,
      trashRoot,
    ]) {
      await createPrivateDirectory(cacheLayout.cacheRoot, directory);
    }
  }
  for (const candidate of plan.evictions) {
    // Package and certificate roots remain planning-only until their separate authority lifecycle
    // is reviewed. Artifacts account for the dominant cache footprint and have one-entry paths.
    if (candidate.type !== "artifact" && candidate.type !== "c-bundle") continue;
    const { path, stats } = await reauthenticateEvictionCandidate(cacheLayout, candidate);
    const quarantineRecord = immutableSweepQuarantineRecord(plan.planSha256, candidate);
    const markerPath = join(trashRoot, `${quarantineRecord.candidateSha256}.json`);
    const verifiedMarkerPath = join(trashRoot, `${quarantineRecord.candidateSha256}.verified.json`);
    const trashPath = join(trashRoot, quarantineRecord.candidateSha256);
    // The durable marker must precede the rename. Otherwise a host crash could recover the moved
    // root without the record that authorizes its removal.
    await writePrivateDurableFile(
      cacheLayout.cacheRoot,
      markerPath,
      `${canonicalJson(quarantineRecord)}\n`
    );
    await fs.rename(path, trashPath);
    // Persist both sides of the cross-directory rename before recursive removal starts. If either
    // sync fails, the marker still makes every crash outcome recoverable.
    await syncDirectory(dirname(path));
    await syncDirectory(trashRoot);
    const movedStats = await treeStats(trashPath);
    if (
      movedStats.allocatedBytes !== stats.allocatedBytes ||
      movedStats.estimatedReclaimBytes !== stats.estimatedReclaimBytes ||
      movedStats.identity !== stats.identity ||
      movedStats.treeIdentity !== stats.treeIdentity ||
      movedStats.mtimeMs !== stats.mtimeMs
    ) {
      fail(`immutable eviction candidate changed while it was quarantined: ${path}`);
    }
    // Make the post-rename authentication durable before recursive removal. Recovery may only
    // tolerate a partial tree after this marker exists; an unverified quarantine is never deleted.
    await writePrivateDurableFile(
      cacheLayout.cacheRoot,
      verifiedMarkerPath,
      `${canonicalJson({ ...quarantineRecord, state: "verified" })}\n`
    );
    await fs.rm(trashPath, { maxRetries: 0, recursive: true });
    // Do not clear the authority record until deletion of the quarantined tree is durable.
    await syncDirectory(trashRoot);
    await fs.unlink(markerPath);
    await syncDirectory(trashRoot);
    await fs.unlink(verifiedMarkerPath);
    await syncDirectory(trashRoot);
    removed.push(candidate);
  }
  if (plan.evictions.length !== 0) {
    await fs.rmdir(trashRoot);
    await syncDirectory(trashBaseRoot);
    await fs.rmdir(trashBaseRoot);
    await syncDirectory(dirname(trashBaseRoot));
  }
  return {
    kind: "convex-wasm-immutable-gc-sweep-v1",
    plan,
    recovered,
    removed,
    skipped: plan.evictions.length - removed.length,
  };
}
