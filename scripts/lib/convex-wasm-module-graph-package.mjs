import { createHash, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isProxy } from "node:util/types";
import { isOwnedConvexWasmCohortCapsuleWorkerResult } from "./convex-wasm-cohort-capsule-worker.mjs";

import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  normalizeJson,
  requireBoolean,
  requireEnum,
  requireExactPlainObject,
  requireManifestString,
  requirePositiveInteger,
  requireSha256,
  requireString,
  requireStringArray,
} from "./convex-wasm-artifact-contract.mjs";
import { decodeUtf8, readPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import {
  artifactCacheEntryPhysicalStateInValidationScope,
  artifactCacheEntryPhysicalStateRetainsAuthenticatedBytes,
  requireAuthenticatedArtifactCacheEntryJsonDigests,
  validateArtifactCacheEntry,
  validateArtifactCacheEntryInValidationScope,
} from "./convex-wasm-artifact-cache-entry.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { requirePrivateCacheDirectory, requirePrivateCacheFile } from "./convex-wasm-private-cache.mjs";
import {
  MODULE_GRAPH_BASE_ROLE,
  MODULE_GRAPH_LEAF_ROLE,
  MODULE_GRAPH_LEGACY_SHARED_ROLE,
  moduleGraphRoleClass,
  moduleGraphRoles,
  moduleGraphSharedRole,
  moduleGraphSharedRoles,
  moduleGraphSharedShardSha256,
  normalizeModuleGraphHostAbi,
  normalizeModuleGraphModule,
  normalizeModuleGraphRoleSequence,
  validateModuleGraphProviders,
} from "./convex-wasm-module-graph-contract.mjs";
import { normalizeConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import { convexWasmOfficialOutputChunkNativeSymbolLocatorKind } from "./convex-wasm-native-symbol-identity.mjs";
import { convexWasmStaticHermesCBundleMemberCompilationPolicy } from "./convex-wasm-static-hermes-c-bundle.mjs";
import {
  authenticateConvexWasmPhysicalShardLogicalUnit,
  convexWasmPhysicalShardKind,
  convexWasmPhysicalShardLogicalUnitKind,
  convexWasmPhysicalShardPlanKind,
  convexWasmPhysicalShardPlanningRequestKind,
  convexWasmPhysicalShardPolicyKind,
  fingerprintConvexWasmPhysicalShardJson,
  planConvexWasmPhysicalShards,
} from "./convex-wasm-physical-shard-planner.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";

export const convexWasmModuleGraphManifestKind = "convex-wasm-module-graph-manifest-v5";
export const convexWasmModuleGraphPackageEntryKind = "convex-wasm-module-graph-package-v5";
export const convexWasmModuleGraphProvenanceKind = "convex-wasm-module-graph-provenance-v5";
export const convexWasmModuleGraphSharedLinkOrderKind =
  "convex-wasm-module-graph-shared-source-membership-link-order-v1";

const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const ARTIFACT_CACHE_ENTRY_KIND = "convex-wasm-artifact-cache-entry-v5";
const ENGINE_IDENTITY_KIND = "convex-wasm-wasmtime-engine-identity";
const LEGACY_MODULE_GRAPH_MANIFEST_KIND = "convex-wasm-module-graph-manifest-v3";
const LEGACY_MODULE_GRAPH_PACKAGE_ENTRY_KIND = "convex-wasm-module-graph-package-v3";
const LEGACY_MODULE_GRAPH_PROVENANCE_KIND = "convex-wasm-module-graph-provenance-v3";
const MODULE_GRAPH_CORE_IDENTITY_AUTHORITY_KIND =
  "convex-wasm-module-graph-core-identity-authority-v1";
const MAX_COMPLETION_MARKER_BYTES = 65;
const MAX_CORE_WASM_BYTES = 320 * 1024 * 1024;
const MAX_MANIFEST_IDENTIFIER_BYTES = 256;
const MAX_MODULE_GRAPH_MANIFEST_BYTES = 8 * 1024 * 1024;
const MAX_MODULE_GRAPH_PROVENANCE_BYTES = 16 * 1024 * 1024;
const MAX_SERIALIZED_MODULE_BYTES = 1024 * 1024 * 1024;
export const convexWasmModuleGraphCoreWasmMaxBytes = MAX_CORE_WASM_BYTES;
export const convexWasmSerializedModuleMaxBytes = MAX_SERIALIZED_MODULE_BYTES;
const MODULE_GRAPH_PHYSICAL_SHARD_TARGET_PIC_OBJECT_BYTES = 8 * 1024 * 1024;
const MODULE_GRAPH_PACKAGE_FILES = new Set([
  "COMPLETE",
  "build-provenance.json",
  "graph-manifest.json",
  "package-entry.json",
]);
const MODULE_GRAPH_SHARED_MODULES_KIND = "convex-wasm-module-graph-shared-modules-v1";
const NATIVE_ARTIFACT_IDENTITY_SCHEMA_VERSION = 2;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
// Only exact trees produced and deeply frozen after full validation receive this authority.
// A frozen clone, accessor-backed object, proxy, or other lookalike must still be validated.
const authenticatedModuleGraphManifests = new WeakSet();
const authenticatedModuleGraphManifestModules = new WeakMap();
const authenticatedModuleGraphProvenances = new WeakMap();
const authenticatedModuleGraphPackageVerifications = new WeakMap();
const authenticatedModuleGraphPackagePhysicalStateWitnesses = new WeakMap();
const moduleGraphPackagePhysicalStateWitnessAuthorities = new WeakMap();
const moduleGraphPackagePhysicalStateWitnessCollectionContinuations = new WeakMap();
const authenticatedStableCoreIdentities = new WeakSet();
const deeplyFrozenStableCoreModuleValues = new WeakSet();
// Caller-owned validation maps must not expose the exact objects that carry private memo
// eligibility. Key a private single-flight map by the caller's validation-scope identity instead.
const stableCoreIdentityAuthorityMemos = new WeakMap();
// Validation scopes parse canonical immutable entries into new object identities. Reuse therefore
// remains scoped to the build that retained the exact authenticated Core identity object.
const normalizedStableCoreModules = new WeakMap();
let moduleGraphPackageVerificationSequence = 0n;
// Package-file JSON is parsed only after its exact canonical bytes have been authenticated. Keep
// those immutable subtrees available to validators so they do not clone large identity payloads
// merely to sort keys that are already in canonical order.
const authenticatedModuleGraphPackageJsonValues = new WeakSet();
// Cohort-local closure planning is useful before the complete schedule is available, but it must
// not become a serializable planning authority. Only exact objects minted by this module or
// restored from an owned worker response may skip local SCC/closure derivation in the global plan.
const authenticatedModuleGraphPhysicalShardCohortContributions = new WeakSet();

export function restoreConvexWasmModuleGraphPhysicalShardCohortContributionFromWorker(transferred) {
  if (!isOwnedConvexWasmCohortCapsuleWorkerResult(transferred)) {
    fail("cohort planning contribution restoration requires an owned capsule worker result");
  }
  const contribution = transferred.authority.cohortPlanningContribution;
  // Structured clone loses the private brand of the worker-authenticated contribution. The
  // receiving pipeline freezes this exact tree before restoring it for global shard planning.
  if (!Object.isFrozen(contribution))
    fail("transferred cohort planning contribution must be frozen");
  authenticatedModuleGraphPhysicalShardCohortContributions.add(contribution);
}

// A complete plan assembled from exact retained cohort contributions can hand its already
// authenticated occurrence topology directly to the immediately following producer step. The
// authority remains bound to every caller-owned object reference that established it.
const retainedModuleGraphPhysicalShardPlanningAuthorities = new WeakMap();
// Plan-input witnesses validate the fused producer without entering its returned topology or any
// serializable planning value. Generic and retained producer results therefore keep one shape.
const retainedModuleGraphPhysicalShardOccurrencePlanningInputs = new WeakMap();
const SUPPORTED_AOT_TARGETS = new Map([
  ["aarch64-apple-darwin", { architecture: "arm64", operatingSystem: "darwin" }],
  ["aarch64-unknown-linux-gnu", { architecture: "arm64", operatingSystem: "linux" }],
  ["x86_64-apple-darwin", { architecture: "x64", operatingSystem: "darwin" }],
  ["x86_64-unknown-linux-gnu", { architecture: "x64", operatingSystem: "linux" }],
]);

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function moduleGraphPackageDirectoryState(status, description) {
  if (status.isSymbolicLink() || !status.isDirectory()) {
    fail(`${description} is not a non-symlink directory`);
  }
  return Object.freeze({
    ctimeNs: status.ctimeNs,
    dev: status.dev,
    gid: status.gid,
    ino: status.ino,
    mode: status.mode,
    mtimeNs: status.mtimeNs,
    nlink: status.nlink,
    size: status.size,
    uid: status.uid,
  });
}

function moduleGraphPackageDirectoryStatesEqual(left, right) {
  return (
    left.ctimeNs === right.ctimeNs &&
    left.dev === right.dev &&
    left.gid === right.gid &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.mtimeNs === right.mtimeNs &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.uid === right.uid
  );
}

function moduleGraphPackageFileState(status, description) {
  if (status.isSymbolicLink() || !status.isFile()) {
    fail(`${description} is not a non-symlink regular file`);
  }
  return Object.freeze({
    ctimeNs: status.ctimeNs.toString(),
    dev: status.dev.toString(),
    gid: status.gid.toString(),
    ino: status.ino.toString(),
    mode: status.mode.toString(),
    mtimeNs: status.mtimeNs.toString(),
    nlink: status.nlink.toString(),
    size: status.size.toString(),
    uid: status.uid.toString(),
  });
}

async function moduleGraphPackagePhysicalState(cacheRoot, packagePath) {
  await requirePrivateCacheDirectory(cacheRoot, packagePath);
  const before = moduleGraphPackageDirectoryState(
    await fs.lstat(packagePath, { bigint: true }),
    "module graph package"
  );
  const names = (await fs.readdir(packagePath)).sort(compareStrings);
  const files = await settleModuleGraphPackageFilesystemWork(
    names.map(async (name) => [
      name,
      moduleGraphPackageFileState(
        await fs.lstat(join(packagePath, name), { bigint: true }),
        `module graph package ${name}`
      ),
    ])
  );
  const afterStatus = await fs.lstat(packagePath, { bigint: true });
  if (afterStatus.isSymbolicLink() || !afterStatus.isDirectory()) return undefined;
  const after = moduleGraphPackageDirectoryState(afterStatus, "module graph package");
  if (!moduleGraphPackageDirectoryStatesEqual(before, after)) return undefined;
  const stringifyState = (state) =>
    Object.fromEntries(Object.entries(state).map(([field, value]) => [field, value.toString()]));
  return JSON.stringify({
    directory: stringifyState(after),
    files: files.map(([name, state]) => [name, stringifyState(state)]),
  });
}

function moduleGraphPackageAncestorStatus(status, description) {
  if (status.isSymbolicLink() || !status.isDirectory()) {
    fail(`${description} is not a non-symlink directory`);
  }
  return [
    status.dev.toString(),
    status.gid.toString(),
    status.ino.toString(),
    status.mode.toString(),
    status.uid.toString(),
  ].join(":");
}

function moduleGraphPackageAncestorPaths(cacheLayout, cacheRoot, graphManifest, packagePath) {
  const normalizedCacheRoot = resolve(cacheRoot);
  const exactDirectories = new Set([resolve(packagePath)]);
  for (const module of graphManifest.modules) {
    for (const artifact of Object.values(module.artifacts)) {
      exactDirectories.add(
        resolve(join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey))
      );
    }
  }
  const ancestors = new Set();
  for (const directory of exactDirectories) {
    const relativeDirectory = relative(normalizedCacheRoot, directory);
    if (
      relativeDirectory === "" ||
      relativeDirectory === ".." ||
      relativeDirectory.startsWith(`..${sep}`)
    ) {
      fail("module graph package physical-state directory escapes the cache root");
    }
    for (let ancestor = dirname(directory); ; ancestor = dirname(ancestor)) {
      ancestors.add(ancestor);
      if (ancestor === normalizedCacheRoot) break;
      const relativeAncestor = relative(normalizedCacheRoot, ancestor);
      if (relativeAncestor === ".." || relativeAncestor.startsWith(`..${sep}`)) {
        fail("module graph package physical-state ancestor escapes the cache root");
      }
    }
  }
  return [...ancestors].sort(compareStrings);
}

async function moduleGraphPackageAncestorPhysicalState(
  cacheLayout,
  cacheRoot,
  graphManifest,
  packagePath,
  physicalStateMemo
) {
  const paths = moduleGraphPackageAncestorPaths(cacheLayout, cacheRoot, graphManifest, packagePath);
  try {
    // Authority minting and witness admission each bracket their boundary with two complete state
    // captures. Read each ancestor once per capture so the boundary remains a double check.
    return JSON.stringify(
      await settleModuleGraphPackageFilesystemWork(
        paths.map(async (path) => [
          path,
          moduleGraphPackageAncestorStatus(
            await (physicalStateMemo === undefined
              ? fs.lstat(path, { bigint: true })
              : memoizePhysicalStateRead(
                  physicalStateMemo,
                  `ancestor\0${resolve(path)}`,
                  async () => await fs.lstat(path, { bigint: true })
                )),
            `module graph package ancestor ${path}`
          ),
        ])
      )
    );
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "ELOOP")
    ) {
      return undefined;
    }
    throw error;
  }
}

function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    if (!deeplyFrozenStableCoreModuleValues.has(value)) {
      for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
      if (!Object.isFrozen(value)) Object.freeze(value);
    }
    authenticatedModuleGraphPackageJsonValues.add(value);
  }
  return value;
}

function deeplyFreezeStableCoreModuleValue(value) {
  if (value !== null && typeof value === "object") {
    if (deeplyFrozenStableCoreModuleValues.has(value)) return value;
    for (const nested of Object.values(value)) deeplyFreezeStableCoreModuleValue(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
    deeplyFrozenStableCoreModuleValues.add(value);
  }
  return value;
}

function authenticateModuleGraphPackageVerification(verification) {
  moduleGraphPackageVerificationSequence += 1n;
  authenticatedModuleGraphPackageVerifications.set(
    verification,
    Object.freeze({
      graphManifest: verification.graphManifest,
      package: verification.package,
      packageMaterial: verification.packageMaterial,
      sequence: moduleGraphPackageVerificationSequence,
    })
  );
  return verification;
}

export function currentConvexWasmModuleGraphPackageVerificationSequence() {
  return moduleGraphPackageVerificationSequence;
}

export function authenticatedConvexWasmModuleGraphPackageVerificationSequence(value) {
  const authenticated = authenticatedModuleGraphPackageVerifications.get(value);
  return authenticated !== undefined &&
    value.graphManifest === authenticated.graphManifest &&
    value.package === authenticated.package &&
    value.packageMaterial === authenticated.packageMaterial
    ? authenticated.sequence
    : undefined;
}

function authenticateModuleGraphPackagePhysicalStateWitness(verification, physicalState) {
  const authenticated = authenticatedModuleGraphPackageVerifications.get(verification);
  if (
    authenticated === undefined ||
    verification.graphManifest !== authenticated.graphManifest ||
    verification.package !== authenticated.package ||
    verification.packageMaterial !== authenticated.packageMaterial
  ) {
    fail("module graph package physical-state witness lacks package verification authority");
  }
  const token = Object.freeze({});
  const authority = Object.freeze({
    ...physicalState,
    graphManifest: verification.graphManifest,
    // The verification result remains caller-visible and mutable. Retain only its authenticated
    // path value; artifact paths are recovered from the deeply frozen graph manifest below.
    packagePath: verification.package.path,
  });
  authenticatedModuleGraphPackagePhysicalStateWitnesses.set(verification, token);
  moduleGraphPackagePhysicalStateWitnessAuthorities.set(token, authority);
  return token;
}

export function authenticatedConvexWasmModuleGraphPackagePhysicalStateWitness(verification) {
  const authenticated = authenticatedModuleGraphPackageVerifications.get(verification);
  return authenticated !== undefined &&
    verification.graphManifest === authenticated.graphManifest &&
    verification.package === authenticated.package &&
    verification.packageMaterial === authenticated.packageMaterial
    ? authenticatedModuleGraphPackagePhysicalStateWitnesses.get(verification)
    : undefined;
}

export function readConvexWasmModuleGraphPublicationPayloadStates(verification) {
  const witness = authenticatedConvexWasmModuleGraphPackagePhysicalStateWitness(verification);
  const authority = moduleGraphPackagePhysicalStateWitnessAuthorities.get(witness);
  if (authority === undefined) fail("runtime publication requires authenticated package material");
  const modulesByRole = new Map(
    authority.graphManifest.modules.map((module) => [module.role, module])
  );
  return JSON.parse(authority.referencedArtifactPhysicalState).map(([role, kind, encoded]) => {
    const artifact = modulesByRole.get(role).artifacts[kind];
    const name = kind === "coreWasm" ? "artifact.wasm" : "artifact.cwasm";
    const state = JSON.parse(encoded).files.find(([file]) => file === name);
    if (state === undefined) fail("authenticated package lacks its publication payload state");
    return [
      join(authority.cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey, name),
      state[1],
    ];
  });
}

function memoizePhysicalStateRead(memo, key, read) {
  let result = memo.get(key);
  if (result === undefined) {
    result = Promise.resolve().then(read);
    memo.set(key, result);
    const clearResult = () => {
      if (memo.get(key) === result) memo.delete(key);
    };
    // Retain only an actual fulfilled state for the rest of this pass. Overlapping callers still
    // drain one missing or failed read, but a later package in the pass must not inherit absence
    // or a filesystem failure as though it were reusable physical authority.
    void result.then((value) => {
      if (value === undefined) clearResult();
    }, clearResult);
  }
  return result;
}

async function settleModuleGraphPackageFilesystemWork(work) {
  const results = await Promise.allSettled(work);
  const failures = results.filter((result) => result.status === "rejected");
  const failure =
    failures.find((result) => !isMissingPhysicalStateError(result.reason)) ?? failures[0];
  if (failure !== undefined) throw failure.reason;
  return results.map((result) => result.value);
}

function isMissingPhysicalStateError(error) {
  return (
    error instanceof Error &&
    "code" in error &&
    (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "ELOOP")
  );
}

async function scanModuleGraphPackagePhysicalStateWitnessCollection(authorities) {
  // A fulfilled read is retained only for this one complete collection pass. Shared Core/AOT
  // entries and cache ancestors are therefore inspected once per pass, while the second pass
  // always starts with fresh maps and cannot reuse earlier filesystem state.
  const artifactPhysicalStateMemo = new Map();
  const ancestorPhysicalStateMemo = new Map();
  return await settleModuleGraphPackageFilesystemWork(
    authorities.map(async (authority) => {
      try {
        const [packagePhysicalState, referencedArtifactPhysicalState, ancestorPhysicalState] =
          await settleModuleGraphPackageFilesystemWork([
            moduleGraphPackagePhysicalState(authority.cacheRoot, authority.packagePath),
            moduleGraphPackageReferencedArtifactPhysicalState({
              artifactPhysicalStateMemo,
              cacheLayout: authority.cacheLayout,
              cacheRoot: authority.cacheRoot,
              immutableCacheValidationMemo: new Map(),
              expectedGraphManifest: authority.graphManifest,
            }),
            moduleGraphPackageAncestorPhysicalState(
              authority.cacheLayout,
              authority.cacheRoot,
              authority.graphManifest,
              authority.packagePath,
              ancestorPhysicalStateMemo
            ),
          ]);
        if (
          packagePhysicalState === undefined ||
          referencedArtifactPhysicalState === undefined ||
          ancestorPhysicalState === undefined
        ) {
          return undefined;
        }
        return { ancestorPhysicalState, packagePhysicalState, referencedArtifactPhysicalState };
      } catch (error) {
        if (isMissingPhysicalStateError(error)) return undefined;
        throw error;
      }
    })
  );
}

export function detachConvexWasmDenseDataPropertyArray(values, invalidMessage) {
  if (!Array.isArray(values)) {
    fail(invalidMessage);
  }
  // Capture the public length once, then require it to agree with the array's own ordinary length
  // property. A Proxy must not shrink the detached authority sequence between validation reads.
  const length = Reflect.get(values, "length");
  const lengthDescriptor = Object.getOwnPropertyDescriptor(values, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    lengthDescriptor.enumerable ||
    lengthDescriptor.configurable ||
    !Number.isSafeInteger(length) ||
    length < 0 ||
    lengthDescriptor.value !== length
  ) {
    fail(invalidMessage);
  }
  const detached = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(values, String(index));
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      fail(invalidMessage);
    }
    detached.push(descriptor.value);
  }
  return detached;
}

export async function verifyConvexWasmModuleGraphPackagePhysicalStateWitnessCollectionWithContinuation(
  tokens,
  continuation
) {
  if (!Array.isArray(tokens)) {
    fail("module graph package physical-state witness collection is empty or invalid");
  }
  // Resolve every opaque token before starting filesystem work. A valid sibling must not turn a
  // forged collection member into a partial physical-authentication attempt. Read each token from
  // one dense data property and retain that detached sequence: holes and accessors must not escape
  // validation or be observed again after the physical-state scans have started.
  const authenticatedTokens = Object.freeze(
    detachConvexWasmDenseDataPropertyArray(
      tokens,
      "module graph package physical-state witness collection is sparse or non-ordinary"
    )
  );
  if (authenticatedTokens.length === 0) {
    fail("module graph package physical-state witness collection is empty or invalid");
  }
  const authorities = authenticatedTokens.map((token) => {
    const authority = moduleGraphPackagePhysicalStateWitnessAuthorities.get(token);
    if (authority === undefined) {
      fail("module graph package physical-state witness is invalid");
    }
    return authority;
  });
  let first;
  if (continuation === undefined) {
    first = await scanModuleGraphPackagePhysicalStateWitnessCollection(authorities);
  } else {
    const retained =
      moduleGraphPackagePhysicalStateWitnessCollectionContinuations.get(continuation);
    // Consume prior state before any filesystem work. Only its exact package collection may reuse
    // the retained capture; an absent, mismatched, or replayed value takes the ordinary two-pass
    // path rather than turning a compatibility or concurrent-authority refresh into a failure.
    moduleGraphPackagePhysicalStateWitnessCollectionContinuations.delete(continuation);
    const matchesRetainedCollection =
      retained !== undefined &&
      retained.tokens.length === authenticatedTokens.length &&
      retained.tokens.every((token, index) => token === authenticatedTokens[index]) &&
      retained.authorities.every((authority, index) => authority === authorities[index]);
    first = matchesRetainedCollection
      ? retained.states
      : await scanModuleGraphPackagePhysicalStateWitnessCollection(authorities);
  }
  const second = await scanModuleGraphPackagePhysicalStateWitnessCollection(authorities);
  const unchanged = Object.freeze(
    authorities.map((authority, index) => {
      const firstState = first[index];
      const secondState = second[index];
      return (
        firstState !== undefined &&
        secondState !== undefined &&
        firstState.packagePhysicalState === secondState.packagePhysicalState &&
        secondState.packagePhysicalState === authority.packagePhysicalState &&
        firstState.referencedArtifactPhysicalState ===
          secondState.referencedArtifactPhysicalState &&
        secondState.referencedArtifactPhysicalState === authority.referencedArtifactPhysicalState &&
        firstState.ancestorPhysicalState === secondState.ancestorPhysicalState &&
        secondState.ancestorPhysicalState === authority.ancestorPhysicalState
      );
    })
  );
  let nextContinuation;
  if (unchanged.every(Boolean)) {
    nextContinuation = Object.freeze({});
    // The second complete capture can become the first side of exactly one later publication
    // window. The later completion still performs a fresh complete collection scan; it merely
    // avoids rereading this already authenticated state before that scan.
    moduleGraphPackagePhysicalStateWitnessCollectionContinuations.set(
      nextContinuation,
      Object.freeze({
        authorities: Object.freeze([...authorities]),
        states: second,
        tokens: authenticatedTokens,
      })
    );
  }
  return Object.freeze({ continuation: nextContinuation, unchanged });
}

export async function verifyConvexWasmModuleGraphPackagePhysicalStateWitnessCollection(tokens) {
  const { unchanged } =
    await verifyConvexWasmModuleGraphPackagePhysicalStateWitnessCollectionWithContinuation(tokens);
  return unchanged;
}

export async function verifyConvexWasmModuleGraphPackagePhysicalStateWitness(token) {
  const [unchanged] = await verifyConvexWasmModuleGraphPackagePhysicalStateWitnessCollection([
    token,
  ]);
  return unchanged;
}

function normalizeModuleGraphJsonValue(value, description) {
  return authenticatedModuleGraphPackageJsonValues.has(value)
    ? value
    : normalizeJson(value, description);
}

function producerImplementationIdentity(producerIdentity) {
  return { kind: producerIdentity.kind, sha256: producerIdentity.sha256 };
}

function normalizeProducerImplementationIdentity(value, description) {
  assertPlainObject(value, description);
  const keys = Object.keys(value).sort(compareStrings);
  if (!stringArrayEqual(keys, ["kind", "sha256"])) {
    fail(`${description} has unsupported fields`);
  }
  if (value.kind !== "convex-wasm-artifact-producer-identity-v1") {
    fail(`${description}.kind is unsupported`);
  }
  return { kind: value.kind, sha256: requireSha256(value.sha256, `${description}.sha256`) };
}

function nativeStageIdentity(identity) {
  const withSchemaVersion = {
    ...identity,
    nativeArtifactIdentitySchemaVersion: NATIVE_ARTIFACT_IDENTITY_SCHEMA_VERSION,
  };
  // Keep identity objects in canonical key order so top-level insertion order does not force an
  // otherwise canonical nested identity through normalizeJson during package authentication.
  return Object.fromEntries(
    Object.keys(withSchemaVersion)
      .sort(compareStrings)
      .map((key) => [key, withSchemaVersion[key]])
  );
}

function requireNonnegativeSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a nonnegative safe integer`);
  }
  return value;
}

function normalizeEngineConfig(engineConfig, description) {
  assertPlainObject(engineConfig, description);
  assertExactKeys(
    engineConfig,
    new Set(["consumeFuel", "epochInterruption", "profilingStrategy", "wasmExceptions"]),
    description
  );
  return {
    consumeFuel: requireBoolean(engineConfig.consumeFuel, `${description}.consumeFuel`),
    epochInterruption: requireBoolean(
      engineConfig.epochInterruption,
      `${description}.epochInterruption`
    ),
    profilingStrategy: requireEnum(
      engineConfig.profilingStrategy,
      new Set(["perf-map"]),
      `${description}.profilingStrategy`
    ),
    wasmExceptions: requireBoolean(engineConfig.wasmExceptions, `${description}.wasmExceptions`),
  };
}

export function normalizeEngineIdentity(engineIdentity, expectedEngineConfig, expectedTarget) {
  assertPlainObject(engineIdentity, "Wasmtime engine identity");
  assertExactKeys(
    engineIdentity,
    new Set(["engineCompatibilitySha256", "engineConfig", "kind", "target"]),
    "Wasmtime engine identity"
  );
  if (engineIdentity.kind !== ENGINE_IDENTITY_KIND) {
    fail(`Wasmtime engine identity kind must be ${ENGINE_IDENTITY_KIND}`);
  }
  const engineConfig = normalizeEngineConfig(
    engineIdentity.engineConfig,
    "Wasmtime engine identity.engineConfig"
  );
  assertPlainObject(engineIdentity.target, "Wasmtime engine identity.target");
  assertExactKeys(
    engineIdentity.target,
    new Set(["cpu", "triple"]),
    "Wasmtime engine identity.target"
  );
  const target = {
    cpu: requireManifestString(
      engineIdentity.target.cpu,
      "Wasmtime engine identity.target.cpu",
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    ),
    triple: requireManifestString(
      engineIdentity.target.triple,
      "Wasmtime engine identity.target.triple",
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    ),
  };
  if (
    !engineConfig.consumeFuel ||
    !engineConfig.epochInterruption ||
    !engineConfig.wasmExceptions
  ) {
    fail("Wasmtime engine identity must enable fuel, epoch interruption, and Wasm exceptions");
  }
  if (target.cpu !== "baseline" || !SUPPORTED_AOT_TARGETS.has(target.triple)) {
    fail("Wasmtime engine identity target must use a supported explicit triple and baseline CPU");
  }
  if (
    canonicalJson(engineConfig) !== canonicalJson(expectedEngineConfig) ||
    canonicalJson(target) !==
      canonicalJson({ cpu: expectedTarget.cpu, triple: expectedTarget.triple })
  ) {
    fail("Wasmtime engine identity does not match the requested engine configuration and target");
  }
  return {
    engineCompatibilitySha256: requireSha256(
      engineIdentity.engineCompatibilitySha256,
      "Wasmtime engine identity.engineCompatibilitySha256"
    ),
    engineConfig,
    kind: ENGINE_IDENTITY_KIND,
    target,
  };
}

export function alignConvexWasmModuleGraphCursor(value, exponent) {
  return Math.ceil(value / 2 ** exponent) * 2 ** exponent;
}

function memoizeImmutableCacheValidation(memo, key, validate) {
  let validation = memo.get(key);
  if (validation === undefined) {
    validation = Promise.resolve().then(validate);
    memo.set(key, validation);
    const clearFailedValidation = () => {
      if (memo.get(key) === validation) memo.delete(key);
    };
    void validation.then(undefined, clearFailedValidation);
  }
  return validation;
}

function normalizeModuleGraphInitialization(value, modules) {
  const description = "module graph initialization";
  requireExactPlainObject(
    value,
    ["baseHeapBase", "baseTableSize", "constructorOrder", "moduleOrder", "relocationOrder"],
    description
  );
  const initialization = {
    baseHeapBase: requirePositiveInteger(value.baseHeapBase, `${description}.baseHeapBase`),
    baseTableSize: requirePositiveInteger(value.baseTableSize, `${description}.baseTableSize`),
    constructorOrder: requireStringArray(value.constructorOrder, `${description}.constructorOrder`),
    moduleOrder: requireStringArray(value.moduleOrder, `${description}.moduleOrder`),
    relocationOrder: requireStringArray(value.relocationOrder, `${description}.relocationOrder`),
  };
  const orderedRoles = moduleGraphRoles(modules);
  const initializationRoles = modules.slice(1).map(({ role }) => role);
  if (!stringArrayEqual(initialization.moduleOrder, orderedRoles)) {
    fail(`${description}.moduleOrder must instantiate base, shared modules, then leaf`);
  }
  for (const field of ["constructorOrder", "relocationOrder"]) {
    if (!stringArrayEqual(initialization[field], initializationRoles)) {
      fail(`${description}.${field} must initialize shared modules before leaf`);
    }
  }
  let memoryCursor = initialization.baseHeapBase;
  let tableCursor = initialization.baseTableSize;
  for (const module of modules.slice(1)) {
    memoryCursor = alignConvexWasmModuleGraphCursor(memoryCursor, module.layout.memoryAlign);
    tableCursor = alignConvexWasmModuleGraphCursor(tableCursor, module.layout.tableAlign);
    if (module.layout.memoryBase !== memoryCursor || module.layout.tableBase !== tableCursor) {
      fail(`${module.role} module layout is not the deterministic next graph placement`);
    }
    memoryCursor += module.layout.memorySize;
    tableCursor += module.layout.tableSize;
  }
  return {
    ...initialization,
    finalMemoryCursor: memoryCursor,
    finalTableCursor: tableCursor,
  };
}

function normalizeModuleGraphRouting(value) {
  const description = "module graph routing";
  requireExactPlainObject(value, ["cohortId", "kind", "routes"], description);
  if (value.kind !== "convex-wasm-module-graph-routing-v2") {
    fail(`${description}.kind is unsupported`);
  }
  if (!Array.isArray(value.routes) || value.routes.length === 0) {
    fail(`${description}.routes must be a non-empty array`);
  }
  const routes = value.routes
    .map((route, index) => {
      const routeDescription = `${description}.routes[${index}]`;
      requireExactPlainObject(
        route,
        [
          "entryId",
          "entrySelectorId",
          "entrySymbol",
          "exportName",
          "routeId",
          "udfKind",
          "visibility",
        ],
        routeDescription
      );
      if (!new Set(["query", "mutation"]).has(route.udfKind)) {
        fail(`${routeDescription}.udfKind is unsupported`);
      }
      if (!new Set(["internal", "public"]).has(route.visibility)) {
        fail(`${routeDescription}.visibility is unsupported`);
      }
      return {
        entryId: requireSha256(route.entryId, `${routeDescription}.entryId`),
        entrySelectorId: requireString(
          route.entrySelectorId,
          `${routeDescription}.entrySelectorId`
        ),
        entrySymbol: requireString(route.entrySymbol, `${routeDescription}.entrySymbol`),
        exportName: requireString(route.exportName, `${routeDescription}.exportName`),
        routeId: requireSha256(route.routeId, `${routeDescription}.routeId`),
        udfKind: route.udfKind,
        visibility: route.visibility,
      };
    })
    .sort((left, right) => compareStrings(left.routeId, right.routeId));
  if (new Set(routes.map(({ routeId }) => routeId)).size !== routes.length) {
    fail(`${description}.routes contain duplicate route identities`);
  }
  return {
    cohortId: requireSha256(value.cohortId, `${description}.cohortId`),
    kind: value.kind,
    routes,
  };
}

function normalizeModuleGraphToolchain(value) {
  const description = "module graph toolchain provenance";
  requireExactPlainObject(
    value,
    ["aot", "core", "staticHermesCBundleMemberCompilation"],
    description
  );
  if (
    canonicalJson(value.staticHermesCBundleMemberCompilation) !==
    canonicalJson(convexWasmStaticHermesCBundleMemberCompilationPolicy)
  ) {
    fail(
      "module graph toolchain must preserve the authenticated -Oz application and forced -O0 member policy"
    );
  }
  return {
    aot: normalizeModuleGraphJsonValue(value.aot, `${description}.aot`),
    core: normalizeModuleGraphJsonValue(value.core, `${description}.core`),
    staticHermesCBundleMemberCompilation: convexWasmStaticHermesCBundleMemberCompilationPolicy,
  };
}

function normalizeModuleGraphEngine(value) {
  const description = "module graph engine";
  requireExactPlainObject(
    value,
    [
      "compatibilitySha256",
      "config",
      "configurationSha256",
      "package",
      "revision",
      "target",
      "wasmtimeMaterialsSha256",
    ],
    description
  );
  const config = normalizeEngineConfig(value.config, `${description}.config`);
  const targetValue = requireExactPlainObject(
    value.target,
    ["cpu", "triple"],
    `${description}.target`
  );
  const normalizedEngineIdentity = normalizeEngineIdentity(
    {
      engineCompatibilitySha256: value.compatibilitySha256,
      engineConfig: config,
      kind: ENGINE_IDENTITY_KIND,
      target: targetValue,
    },
    config,
    targetValue
  );
  const configurationSha256 = requireSha256(
    value.configurationSha256,
    `${description}.configurationSha256`
  );
  if (configurationSha256 !== fingerprintJson(config)) {
    fail(`${description}.configurationSha256 is invalid`);
  }
  return {
    compatibilitySha256: normalizedEngineIdentity.engineCompatibilitySha256,
    config,
    configurationSha256,
    package: normalizeModuleGraphJsonValue(value.package, `${description}.package`),
    revision: requireString(value.revision, `${description}.revision`),
    target: normalizedEngineIdentity.target,
    wasmtimeMaterialsSha256: requireSha256(
      value.wasmtimeMaterialsSha256,
      `${description}.wasmtimeMaterialsSha256`
    ),
  };
}

function moduleGraphCoreStage(role) {
  return `module-graph-${role}-core-wasm`;
}

function moduleGraphCoreMaterialStage() {
  return "module-graph-core-wasm-material";
}

function moduleGraphAotStage(role) {
  return `module-graph-${role}-wasmtime-aot`;
}

function moduleGraphAotMaterialStage() {
  return "module-graph-wasmtime-aot-material";
}

function moduleGraphAotSchedulingStage(role, hasReviewedCommon) {
  if (role === MODULE_GRAPH_LEGACY_SHARED_ROLE) {
    return hasReviewedCommon ? "module-graph-common-wasmtime-aot" : "wasmtime-aot";
  }
  if (moduleGraphRoleClass(role) === "shared") return "module-graph-shared-wasmtime-aot";
  if (role === MODULE_GRAPH_LEAF_ROLE) return "module-graph-leaf-wasmtime-aot";
  return "wasmtime-aot";
}

function normalizeModuleGraphBuildResult(value, role, kind, workPath) {
  const description = `${role} module ${kind} build result`;
  requireExactPlainObject(
    value,
    kind === "Core Wasm"
      ? ["contract", "outputPath", "timing"]
      : ["engineIdentity", "outputPath", "timing"],
    description
  );
  const outputPath = resolve(requireString(value.outputPath, `${description}.outputPath`));
  const relativeOutput = relative(workPath, outputPath);
  if (
    relativeOutput === "" ||
    relativeOutput === ".." ||
    relativeOutput.startsWith(`..${sep}`) ||
    isAbsolute(relativeOutput)
  ) {
    fail(`${description}.outputPath must be inside its private build directory`);
  }
  return { ...value, outputPath };
}

function moduleGraphManifestSha256(manifest) {
  const { graphManifestSha256: ignoredGraphManifestSha256, ...payload } = manifest;
  return fingerprintJson(payload);
}

function verifyRawCanonicalModuleGraphManifestIdentity(bytes, expectedGraphManifestSha256) {
  const description = "module graph package manifest raw identity";
  if (bytes.length < 2 || bytes[bytes.length - 1] !== 0x0a || bytes[bytes.length - 2] !== 0x7d) {
    fail(`${description} must have exactly one final newline`);
  }
  const payload = bytes.subarray(0, bytes.length - 1);
  const fieldPrefix = Buffer.from('"graphManifestSha256":');
  const field = Buffer.from(`"graphManifestSha256":"${expectedGraphManifestSha256}",`);
  const fieldOffset = payload.indexOf(fieldPrefix);
  if (
    fieldOffset < 0 ||
    payload.indexOf(fieldPrefix, fieldOffset + fieldPrefix.length) >= 0 ||
    !payload.subarray(fieldOffset, fieldOffset + field.length).equals(field)
  ) {
    fail(`${description} must contain its exact unique graph identity field`);
  }

  let depth = 0;
  let escaped = false;
  let inString = false;
  let identityDepth;
  for (let index = 0; index < payload.length; index += 1) {
    const byte = payload[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (byte === 0x5c) {
        escaped = true;
      } else if (byte === 0x22) {
        inString = false;
      }
      continue;
    }
    if (index === fieldOffset) identityDepth = depth;
    if (byte === 0x22) {
      inString = true;
    } else if (byte === 0x7b || byte === 0x5b) {
      depth += 1;
    } else if (byte === 0x7d || byte === 0x5d) {
      depth -= 1;
      if (depth < 0) fail(`${description} is not structurally valid JSON`);
    }
  }
  if (
    inString ||
    escaped ||
    depth !== 0 ||
    identityDepth !== 1 ||
    !(
      payload.subarray(0, Buffer.byteLength('{"engine":')).equals(Buffer.from('{"engine":')) ||
      (payload
        .subarray(0, Buffer.byteLength('{"contextReuseAnalysis":'))
        .equals(Buffer.from('{"contextReuseAnalysis":')) &&
        payload.subarray(0, fieldOffset).includes(Buffer.from(',"engine":')))
    ) ||
    !payload
      .subarray(
        fieldOffset + field.length,
        fieldOffset + field.length + Buffer.byteLength('"hostAbi":')
      )
      .equals(Buffer.from('"hostAbi":'))
  ) {
    fail(`${description} field is not in its canonical top-level position`);
  }

  const actualGraphManifestSha256 = createHash("sha256")
    .update(payload.subarray(0, fieldOffset))
    .update(payload.subarray(fieldOffset + field.length))
    .digest("hex");
  if (actualGraphManifestSha256 !== expectedGraphManifestSha256) {
    fail(`${description} does not match its requested identity`);
  }
}

function verifyRawCanonicalModuleGraphProvenanceIdentity(bytes, authority) {
  const description = "module graph package provenance raw identity";
  if (
    bytes.length !== authority.size + 1 ||
    bytes.length < 2 ||
    bytes[bytes.length - 1] !== 0x0a ||
    hashBytes(bytes.subarray(0, -1)) !== authority.sha256
  ) {
    fail(`${description} does not match its authenticated provenance`);
  }
}

function moduleGraphPackageEntry(packageKey, manifestBytes, provenanceBytes, modules, manifest) {
  const contextReuseAnalysis =
    manifest.contextReuseAnalysis === undefined
      ? undefined
      : authenticateConvexContextReuseCohortAnalysisIdentity(manifest.contextReuseAnalysis);
  return {
    artifacts: Object.fromEntries(
      modules.map(({ aot, coreWasm, role }) => [
        role,
        {
          aot: {
            cacheKey: aot.report.cacheKey,
            sha256: aot.entry.artifactSha256,
            size: aot.entry.artifactSize,
            stage: moduleGraphAotStage(role),
          },
          coreWasm: {
            cacheKey: coreWasm.report.cacheKey,
            sha256: coreWasm.entry.artifactSha256,
            size: coreWasm.entry.artifactSize,
            stage: moduleGraphCoreStage(role),
          },
        },
      ])
    ),
    key: packageKey,
    kind: convexWasmModuleGraphPackageEntryKind,
    manifest: { sha256: hashBytes(manifestBytes), size: manifestBytes.length },
    provenance: { sha256: hashBytes(provenanceBytes), size: provenanceBytes.length },
    ...(contextReuseAnalysis === undefined ? {} : { contextReuseAnalysis }),
  };
}

function normalizeModuleGraphArtifactReference(value, role, kind) {
  const description = `${role} module ${kind} artifact reference`;
  requireExactPlainObject(value, ["cacheKey", "sha256", "size", "stage"], description);
  const expectedStage = kind === "aot" ? moduleGraphAotStage(role) : moduleGraphCoreStage(role);
  if (value.stage !== expectedStage) {
    fail(`${description}.stage must be ${expectedStage}`);
  }
  return {
    cacheKey: requireSha256(value.cacheKey, `${description}.cacheKey`),
    sha256: requireSha256(value.sha256, `${description}.sha256`),
    size: requirePositiveInteger(value.size, `${description}.size`),
    stage: expectedStage,
  };
}

// Both inputs have already passed the closed artifact-reference validator. Compare the fixed
// primitive shape directly instead of serializing it for every package-module check.
function moduleGraphArtifactReferenceEqual(left, right) {
  return (
    left.cacheKey === right.cacheKey &&
    left.sha256 === right.sha256 &&
    left.size === right.size &&
    left.stage === right.stage
  );
}

function moduleGraphArtifactPairEqual(left, right) {
  return (
    moduleGraphArtifactReferenceEqual(left.aot, right.aot) &&
    moduleGraphArtifactReferenceEqual(left.coreWasm, right.coreWasm)
  );
}

function moduleGraphPublicationDataProperty(value, key, description) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
    fail(`${description}.${key} must be an enumerable data property`);
  }
  return descriptor.value;
}

function detachModuleGraphPublishedArtifact({
  cacheLayout,
  expectedArtifact,
  expectedIdentity,
  expectedMetadata,
  extension,
  kind,
  publishedArtifact,
  role,
}) {
  const description = `${role} module published ${kind}`;
  assertPlainObject(publishedArtifact, description);
  const entry = moduleGraphPublicationDataProperty(publishedArtifact, "entry", description);
  const report = moduleGraphPublicationDataProperty(publishedArtifact, "report", description);
  requireExactPlainObject(
    entry,
    [
      // Physical admission belongs to cache validation, not the detached receipt identity.
      ...(Object.hasOwn(entry, "admission") ? ["admission"] : []),
      "artifactFile",
      "artifactPath",
      "artifactSha256",
      "artifactSize",
      "identity",
      "key",
      "kind",
      "metadata",
      "stage",
    ],
    `${description} cache entry`
  );
  assertPlainObject(report, `${description} report`);
  const jsonDigests = requireAuthenticatedArtifactCacheEntryJsonDigests(entry);
  // Capture outer fields before publication yields. The private JSON admission above binds
  // deeply frozen identity/metadata trees, so retain those trees rather than cloning them again.
  // Another consumer can replace outer fields but cannot mutate the captured nested material.
  const detached = {
    artifactFile: moduleGraphPublicationDataProperty(
      entry,
      "artifactFile",
      `${description} cache entry`
    ),
    artifactPath: moduleGraphPublicationDataProperty(
      entry,
      "artifactPath",
      `${description} cache entry`
    ),
    artifactSha256: moduleGraphPublicationDataProperty(
      entry,
      "artifactSha256",
      `${description} cache entry`
    ),
    artifactSize: moduleGraphPublicationDataProperty(
      entry,
      "artifactSize",
      `${description} cache entry`
    ),
    identity: moduleGraphPublicationDataProperty(entry, "identity", `${description} cache entry`),
    key: moduleGraphPublicationDataProperty(entry, "key", `${description} cache entry`),
    kind: moduleGraphPublicationDataProperty(entry, "kind", `${description} cache entry`),
    metadata: moduleGraphPublicationDataProperty(entry, "metadata", `${description} cache entry`),
    stage: moduleGraphPublicationDataProperty(entry, "stage", `${description} cache entry`),
  };
  const reportCacheKey = requireSha256(
    moduleGraphPublicationDataProperty(report, "cacheKey", `${description} report`),
    `${description} report cache key`
  );
  const reportStage = requireString(
    moduleGraphPublicationDataProperty(report, "stage", `${description} report`),
    `${description} report stage`
  );
  const artifact = normalizeModuleGraphArtifactReference(
    {
      cacheKey: detached.key,
      sha256: detached.artifactSha256,
      size: detached.artifactSize,
      stage: detached.stage,
    },
    role,
    kind
  );
  const expectedArtifactPath = join(
    cacheLayout.immutable.artifacts,
    artifact.stage,
    artifact.cacheKey,
    `artifact.${extension}`
  );
  if (
    detached.kind !== ARTIFACT_CACHE_ENTRY_KIND ||
    detached.artifactFile !== `artifact.${extension}` ||
    resolve(requireString(detached.artifactPath, `${description} artifact path`)) !==
      resolve(expectedArtifactPath) ||
    reportCacheKey !== artifact.cacheKey ||
    reportStage !== artifact.stage ||
    !moduleGraphArtifactReferenceEqual(artifact, expectedArtifact) ||
    !authenticatedJsonValuesEqual(detached.identity, expectedIdentity)
  ) {
    fail(`${description} does not match its authenticated graph identity`);
  }
  if (kind === "coreWasm") {
    requireExactPlainObject(detached.metadata, ["contract"], `${description} metadata`);
    if (!authenticatedJsonValuesEqual(detached.metadata, expectedMetadata)) {
      fail(`${description} metadata does not match its authenticated graph identity`);
    }
  } else {
    const engineIdentity = normalizeEngineIdentity(
      detached.metadata,
      expectedMetadata.engineConfig,
      expectedMetadata.target
    );
    if (engineIdentity.engineCompatibilitySha256 !== expectedMetadata.engineCompatibilitySha256) {
      fail(`${description} metadata has a different engine compatibility identity`);
    }
  }
  return {
    artifact,
    artifactSha256: artifact.sha256,
    artifactSize: artifact.size,
    identitySha256: jsonDigests.identitySha256,
    metadataSha256: jsonDigests.metadataSha256,
  };
}

function createModuleGraphPublishedPackageMaterial({
  cacheLayout,
  manifest,
  manifestBytes,
  modules,
  packageKey,
  provenanceBytes,
}) {
  if (modules.length !== manifest.modules.length) {
    fail("published module graph artifacts do not exactly cover their graph manifest");
  }
  const expectedIdentities = expectedModuleGraphArtifactIdentities(manifest);
  const expectedAotMetadata = {
    engineCompatibilitySha256: manifest.engine.compatibilitySha256,
    engineConfig: manifest.engine.config,
    kind: ENGINE_IDENTITY_KIND,
    target: manifest.engine.target,
  };
  const detachedModules = manifest.modules.map((module, index) => {
    const publishedModule = modules[index];
    assertPlainObject(publishedModule, `published module graph artifact ${index}`);
    const role = requireString(
      moduleGraphPublicationDataProperty(
        publishedModule,
        "role",
        `published module graph artifact ${index}`
      ),
      `published module graph artifact ${index} role`
    );
    const expectedIdentity = expectedIdentities[module.role];
    if (role !== module.role || expectedIdentity === undefined) {
      fail("published module graph artifacts do not exactly cover their graph manifest");
    }
    const aot = detachModuleGraphPublishedArtifact({
      cacheLayout,
      expectedArtifact: module.artifacts.aot,
      expectedIdentity: expectedIdentity.aot,
      expectedMetadata: expectedAotMetadata,
      extension: "cwasm",
      kind: "aot",
      publishedArtifact: moduleGraphPublicationDataProperty(
        publishedModule,
        "aot",
        `published module graph artifact ${index}`
      ),
      role,
    });
    const coreWasm = detachModuleGraphPublishedArtifact({
      cacheLayout,
      expectedArtifact: module.artifacts.coreWasm,
      expectedIdentity: expectedIdentity.coreWasm,
      expectedMetadata: { contract: module.contract },
      extension: "wasm",
      kind: "coreWasm",
      publishedArtifact: moduleGraphPublicationDataProperty(
        publishedModule,
        "coreWasm",
        `published module graph artifact ${index}`
      ),
      role,
    });
    return {
      aot: { entry: aot, report: aot.artifact },
      coreWasm: { entry: coreWasm, report: coreWasm.artifact },
      role,
    };
  });
  const packageEntry = moduleGraphPackageEntry(
    packageKey,
    manifestBytes,
    provenanceBytes,
    detachedModules,
    manifest
  );
  const packageEntryBytes = Buffer.from(`${canonicalJson(packageEntry)}\n`);
  normalizeModuleGraphPackageEntry(packageEntry, manifestBytes, provenanceBytes, manifest);
  const artifactReferences = detachedModules
    .map(({ aot, coreWasm, role }) => ({
      aot: {
        artifact: aot.entry.artifact,
        identitySha256: aot.entry.identitySha256,
        metadataSha256: aot.entry.metadataSha256,
      },
      coreWasm: {
        artifact: coreWasm.entry.artifact,
        identitySha256: coreWasm.entry.identitySha256,
        metadataSha256: coreWasm.entry.metadataSha256,
      },
      role,
    }))
    .sort((left, right) => compareStrings(left.role, right.role));
  if (!moduleGraphPackageArtifactReferencesBindGraph(artifactReferences, manifest)) {
    fail("published module graph artifact references do not exactly cover their graph manifest");
  }
  return {
    packageEntryBytes,
    packageMaterial: moduleGraphPackageMaterial({
      artifactReferences,
      complete: Buffer.from(`${packageKey}\n`),
      entry: { bytes: packageEntryBytes },
      manifest: { bytes: manifestBytes, value: manifest },
      provenance: { bytes: provenanceBytes },
    }),
  };
}

// These arrays contain already-normalized primitive identities. Comparing their members directly
// avoids serializing the same digest lists merely to check order or equality during validation.
function stringArrayEqual(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right)) return false;
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function isStrictlySortedUniqueStringArray(values) {
  for (let index = 1; index < values.length; index += 1) {
    if (compareStrings(values[index - 1], values[index]) >= 0) return false;
  }
  return true;
}

function createModuleGraphLeafInvalidation(modules, routing) {
  const leaf = modules.at(-1);
  return {
    cohortId: routing.cohortId,
    contractSha256: leaf.contract.contractSha256,
    kind: "convex-wasm-module-graph-leaf-invalidation-v2",
    routeIds: routing.routes.map(({ routeId }) => routeId),
    sourceProvenanceSha256: leaf.sourceProvenance.sha256,
  };
}

function moduleGraphStableModuleIdentity(module) {
  return {
    artifacts: module.artifacts,
    contract: module.contract,
    layout: module.layout,
    link: module.link,
    objectCompilation: module.objectCompilation,
    ownership: module.ownership,
    providers: module.providers,
    role: module.role,
    ...(module.sharedShardSha256 === undefined
      ? {}
      : { sharedShardSha256: module.sharedShardSha256 }),
    sourceProvenance: module.sourceProvenance,
  };
}

function normalizeModuleGraphPhysicalShardPlan(value) {
  const description = "module graph physical shard plan";
  requireExactPlainObject(
    value,
    [
      "components",
      "kind",
      "planSha256",
      "policy",
      "residualComponents",
      "sharedShards",
      "shardOrder",
    ],
    description
  );
  if (value.kind !== convexWasmPhysicalShardPlanKind) {
    fail(`${description}.kind is unsupported`);
  }
  if (!Array.isArray(value.sharedShards) || !Array.isArray(value.shardOrder)) {
    fail(`${description} has no shared-shard order`);
  }
  const { planSha256, ...plan } = value;
  if (
    requireSha256(planSha256, `${description}.planSha256`) !==
    fingerprintConvexWasmPhysicalShardJson({
      domain: "convex-wasm-physical-shard-plan-identity-v2",
      plan,
    })
  ) {
    fail(`${description}.planSha256 is invalid`);
  }
  const requireCanonicalSha256Array = (rawValue, itemDescription, { allowEmpty }) => {
    if (!Array.isArray(rawValue) || (!allowEmpty && rawValue.length === 0)) {
      fail(`${itemDescription} must be ${allowEmpty ? "an array" : "a non-empty array"}`);
    }
    const items = rawValue.map((item, index) =>
      requireSha256(item, `${itemDescription}[${index}]`)
    );
    if (!isStrictlySortedUniqueStringArray(items)) {
      fail(`${itemDescription} must be sorted without duplicates`);
    }
    return items;
  };
  if (!Array.isArray(value.components)) {
    fail(`${description}.components must be an array`);
  }
  const components = value.components.map((component, index) => {
    const componentDescription = `${description}.components[${index}]`;
    requireExactPlainObject(
      component,
      [
        "bindingIdentitySha256s",
        "codeIdentitySha256s",
        "componentBindingSha256",
        "componentSha256",
        "dependencies",
        "logicalUnitSha256s",
        "occurrenceCohortSha256s",
        "picObjectByteWeight",
        "shareable",
        "sharedEligible",
      ],
      componentDescription
    );
    const normalized = {
      bindingIdentitySha256s: requireCanonicalSha256Array(
        component.bindingIdentitySha256s,
        `${componentDescription}.bindingIdentitySha256s`,
        { allowEmpty: false }
      ),
      codeIdentitySha256s: requireCanonicalSha256Array(
        component.codeIdentitySha256s,
        `${componentDescription}.codeIdentitySha256s`,
        { allowEmpty: false }
      ),
      componentBindingSha256: requireSha256(
        component.componentBindingSha256,
        `${componentDescription}.componentBindingSha256`
      ),
      componentSha256: requireSha256(
        component.componentSha256,
        `${componentDescription}.componentSha256`
      ),
      dependencies: requireCanonicalSha256Array(
        component.dependencies,
        `${componentDescription}.dependencies`,
        { allowEmpty: true }
      ),
      logicalUnitSha256s: (() => {
        if (
          !Array.isArray(component.logicalUnitSha256s) ||
          component.logicalUnitSha256s.length === 0
        ) {
          fail(`${componentDescription}.logicalUnitSha256s must be a non-empty array`);
        }
        const identities = component.logicalUnitSha256s.map((identity, identityIndex) =>
          requireSha256(identity, `${componentDescription}.logicalUnitSha256s[${identityIndex}]`)
        );
        if (new Set(identities).size !== identities.length) {
          fail(`${componentDescription}.logicalUnitSha256s must not contain duplicates`);
        }
        return identities;
      })(),
      occurrenceCohortSha256s: requireCanonicalSha256Array(
        component.occurrenceCohortSha256s,
        `${componentDescription}.occurrenceCohortSha256s`,
        { allowEmpty: false }
      ),
      picObjectByteWeight: requireNonnegativeSafeInteger(
        component.picObjectByteWeight,
        `${componentDescription}.picObjectByteWeight`
      ),
      shareable: requireBoolean(component.shareable, `${componentDescription}.shareable`),
      sharedEligible: requireBoolean(
        component.sharedEligible,
        `${componentDescription}.sharedEligible`
      ),
    };
    if (normalized.sharedEligible && !normalized.shareable) {
      fail(`${componentDescription} cannot be shared when it is not shareable`);
    }
    if (
      normalized.logicalUnitSha256s.length !== normalized.codeIdentitySha256s.length ||
      normalized.bindingIdentitySha256s.length !== normalized.codeIdentitySha256s.length
    ) {
      fail(`${componentDescription} logical-unit identity mapping is incomplete`);
    }
    return normalized;
  });
  if (
    !isStrictlySortedUniqueStringArray(
      components.map(({ componentBindingSha256 }) => componentBindingSha256)
    ) ||
    new Set(components.map(({ componentSha256 }) => componentSha256)).size !== components.length
  ) {
    fail(`${description}.components must be ordered by unique component identity`);
  }
  const componentBySha256 = new Map(
    components.map((component) => [component.componentSha256, component])
  );
  for (const component of components) {
    if (
      component.dependencies.some((dependencySha256) => !componentBySha256.has(dependencySha256))
    ) {
      fail(`${description}.components reference an unknown component dependency`);
    }
  }
  const sharedShards = value.sharedShards.map((shard, index) => {
    const shardDescription = `${description}.sharedShards[${index}]`;
    requireExactPlainObject(
      shard,
      [
        "componentBindingSha256s",
        "componentSha256s",
        "dependencies",
        "kind",
        "oversize",
        "picObjectByteWeight",
        "shardSha256",
      ],
      shardDescription
    );
    if (shard.kind !== convexWasmPhysicalShardKind) {
      fail(`${shardDescription}.kind is unsupported`);
    }
    const componentBindingSha256s = requireCanonicalSha256Array(
      shard.componentBindingSha256s,
      `${shardDescription}.componentBindingSha256s`,
      { allowEmpty: false }
    );
    const componentSha256s = requireCanonicalSha256Array(
      shard.componentSha256s,
      `${shardDescription}.componentSha256s`,
      { allowEmpty: false }
    );
    const shardSha256 = requireSha256(shard.shardSha256, `${shardDescription}.shardSha256`);
    if (
      shardSha256 !==
      fingerprintConvexWasmPhysicalShardJson({
        domain: "convex-wasm-physical-shard-binding-identity-v2",
        shard: { componentBindingSha256s, kind: convexWasmPhysicalShardKind },
      })
    ) {
      fail(`${shardDescription}.shardSha256 is invalid`);
    }
    return {
      componentBindingSha256s,
      componentSha256s,
      dependencies: requireCanonicalSha256Array(
        shard.dependencies,
        `${shardDescription}.dependencies`,
        { allowEmpty: true }
      ),
      oversize: requireBoolean(shard.oversize, `${shardDescription}.oversize`),
      picObjectByteWeight: requireNonnegativeSafeInteger(
        shard.picObjectByteWeight,
        `${shardDescription}.picObjectByteWeight`
      ),
      shardSha256,
    };
  });
  if (!isStrictlySortedUniqueStringArray(sharedShards.map(({ shardSha256 }) => shardSha256))) {
    fail(`${description}.sharedShards must be ordered by unique shard identity`);
  }
  const shardByComponentSha256 = new Map();
  for (const shard of sharedShards) {
    let occurrenceCohortSha256s;
    const expectedWeight = shard.componentSha256s.reduce((total, componentSha256) => {
      const component = componentBySha256.get(componentSha256);
      if (component === undefined || !component.sharedEligible) {
        fail(`${description}.sharedShards contain a residual or unknown component`);
      }
      if (
        occurrenceCohortSha256s !== undefined &&
        !stringArrayEqual(component.occurrenceCohortSha256s, occurrenceCohortSha256s)
      ) {
        fail(`${description}.sharedShards mix component occurrence cohorts`);
      }
      occurrenceCohortSha256s = component.occurrenceCohortSha256s;
      if (shardByComponentSha256.has(componentSha256)) {
        fail(`${description}.sharedShards repeat a component`);
      }
      shardByComponentSha256.set(componentSha256, shard.shardSha256);
      return total + component.picObjectByteWeight;
    }, 0);
    if (expectedWeight !== shard.picObjectByteWeight) {
      fail(`${description}.sharedShards PIC object weight is invalid`);
    }
    const expectedBindings = shard.componentSha256s
      .map((componentSha256) => componentBySha256.get(componentSha256).componentBindingSha256)
      .sort(compareStrings);
    if (!stringArrayEqual(expectedBindings, shard.componentBindingSha256s)) {
      fail(`${description}.sharedShards component bindings are invalid`);
    }
  }
  if (
    components.some(
      (component) =>
        component.sharedEligible !== shardByComponentSha256.has(component.componentSha256)
    )
  ) {
    fail(`${description}.sharedShards do not cover exactly the eligible components`);
  }
  const shardBySha256 = new Map(sharedShards.map((shard) => [shard.shardSha256, shard]));
  for (const shard of sharedShards) {
    const expectedDependencies = [
      ...new Set(
        shard.componentSha256s.flatMap((componentSha256) =>
          componentBySha256
            .get(componentSha256)
            .dependencies.map((dependencySha256) => shardByComponentSha256.get(dependencySha256))
        )
      ),
    ]
      .filter((dependencySha256) => dependencySha256 !== shard.shardSha256)
      .sort(compareStrings);
    if (!stringArrayEqual(shard.dependencies, expectedDependencies)) {
      fail(`${description}.sharedShards dependencies are invalid`);
    }
  }
  const shardOrder = value.shardOrder.map((shardSha256, index) =>
    requireSha256(shardSha256, `${description}.shardOrder[${index}]`)
  );
  if (
    new Set(shardOrder).size !== shardOrder.length ||
    !stringArrayEqual(
      [...shardOrder].sort(compareStrings),
      [...shardBySha256.keys()].sort(compareStrings)
    )
  ) {
    fail(`${description}.shardOrder does not cover every shared shard once`);
  }
  const positionByShardSha256 = new Map(
    shardOrder.map((shardSha256, index) => [shardSha256, index])
  );
  if (
    sharedShards.some((shard) =>
      shard.dependencies.some(
        (dependencySha256) =>
          positionByShardSha256.get(dependencySha256) >=
          positionByShardSha256.get(shard.shardSha256)
      )
    )
  ) {
    fail(`${description}.shardOrder is not dependency first`);
  }
  return {
    components,
    planSha256,
    sharedShards,
    shardOrder,
  };
}

function normalizeModuleGraphSharedShards(value, modules, description) {
  const sharedRoles = moduleGraphSharedRoles(modules);
  if (value === undefined) {
    if (
      !stringArrayEqual(moduleGraphRoles(modules), [
        MODULE_GRAPH_BASE_ROLE,
        MODULE_GRAPH_LEGACY_SHARED_ROLE,
        MODULE_GRAPH_LEAF_ROLE,
      ])
    ) {
      fail(`${description} must declare ordered content-addressed shared shards`);
    }
    return undefined;
  }
  requireExactPlainObject(value, ["kind", "shards"], description);
  if (value.kind !== MODULE_GRAPH_SHARED_MODULES_KIND || !Array.isArray(value.shards)) {
    fail(`${description} is unsupported`);
  }
  const shards = value.shards.map((shard, index) => {
    const shardDescription = `${description}.shards[${index}]`;
    requireExactPlainObject(shard, ["role", "shardSha256"], shardDescription);
    const shardSha256 = requireSha256(shard.shardSha256, `${shardDescription}.shardSha256`);
    const role = requireString(shard.role, `${shardDescription}.role`);
    if (role !== moduleGraphSharedRole(shardSha256)) {
      fail(`${shardDescription} role does not bind its content identity`);
    }
    return { role, shardSha256 };
  });
  if (new Set(shards.map(({ role }) => role)).size !== shards.length) {
    fail(`${description}.shards repeat a role`);
  }
  if (
    !stringArrayEqual(
      shards.map(({ role }) => role),
      sharedRoles
    )
  ) {
    fail(`${description} does not match the ordered shared modules`);
  }
  return { kind: MODULE_GRAPH_SHARED_MODULES_KIND, shards };
}

function retainedModuleGraphPhysicalShardPlanningAuthority({
  allowPartialCohortMatrix,
  authenticatedCohortUnitMatrix,
  cohortPlanningContributions,
  physicalShardPlanning,
}) {
  if (allowPartialCohortMatrix) return undefined;
  const authority = retainedModuleGraphPhysicalShardPlanningAuthorities.get(physicalShardPlanning);
  if (authority !== undefined) {
    // Only the combined synchronous producer can present the retained contribution references.
    // Consume before checking them so a mismatched caller cannot restore stale authority later.
    retainedModuleGraphPhysicalShardPlanningAuthorities.delete(physicalShardPlanning);
  }
  if (
    authority === undefined ||
    !moduleGraphPhysicalShardProducerMatrixIsOrdinary(authenticatedCohortUnitMatrix) ||
    !moduleGraphPhysicalShardProducerReferenceArrayMatches(
      cohortPlanningContributions,
      authority.contributionReferences
    ) ||
    physicalShardPlanning.plan !== authority.plan ||
    authenticatedCohortUnitMatrix !== authority.authenticatedCohortUnitMatrix ||
    cohortPlanningContributions !== authority.cohortPlanningContributions ||
    !moduleGraphPhysicalShardProducerReferenceArrayMatches(
      authenticatedCohortUnitMatrix,
      authority.cohorts.map(({ cohort }) => cohort)
    )
  ) {
    return undefined;
  }
  for (const [index, retainedCohort] of authority.cohorts.entries()) {
    const cohort = authenticatedCohortUnitMatrix[index];
    if (
      cohort !== retainedCohort.cohort ||
      cohort.cohortId !== retainedCohort.cohortId ||
      cohort.cohortIndex !== retainedCohort.cohortIndex ||
      cohort.output !== retainedCohort.compilerOutput ||
      cohort.units !== retainedCohort.units ||
      !moduleGraphPhysicalShardProducerReferenceArrayMatches(
        cohort.units,
        retainedCohort.unitReferences
      )
    ) {
      return undefined;
    }
  }
  return authority;
}

function moduleGraphPhysicalShardProducerReferenceArrayMatches(value, expectedValues) {
  if (
    !Array.isArray(value) ||
    !Array.isArray(expectedValues) ||
    isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length !== expectedValues.length
  ) {
    return false;
  }
  for (let index = 0; index < expectedValues.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.value !== expectedValues[index]
    ) {
      return false;
    }
  }
  return true;
}

function moduleGraphPhysicalShardProducerValueIsOrdinary(
  value,
  { jsonOnly = false, role = "value" } = {},
  ancestors = new WeakSet()
) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "undefined"
  ) {
    return !jsonOnly || value !== undefined;
  }
  if (typeof value === "number") return !jsonOnly || Number.isFinite(value);
  if (typeof value !== "object" || isProxy(value) || ancestors.has(value)) return false;
  const isArray = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (isArray ? Array.prototype : Object.prototype)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) return false;
  if (isArray) {
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      keys.length !== value.length + 1
    ) {
      return false;
    }
  }
  ancestors.add(value);
  const dataKeys = isArray ? keys.filter((key) => key !== "length") : keys;
  for (const key of dataKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      ancestors.delete(value);
      return false;
    }
    if (role === "cohort" && (key === "descriptor" || key === "output" || key === "scheduled")) {
      continue;
    }
    const nestedRole = role === "matrix" ? "cohort" : key === "units" ? "units" : "value";
    if (
      !moduleGraphPhysicalShardProducerValueIsOrdinary(
        descriptor.value,
        { jsonOnly, role: nestedRole },
        ancestors
      )
    ) {
      ancestors.delete(value);
      return false;
    }
  }
  ancestors.delete(value);
  return true;
}

function moduleGraphPhysicalShardProducerMatrixIsOrdinary(value) {
  return moduleGraphPhysicalShardProducerValueIsOrdinary(value, { role: "matrix" });
}

function moduleGraphPhysicalShardProducerPlanningIsOrdinary(value) {
  return moduleGraphPhysicalShardProducerValueIsOrdinary(value, { jsonOnly: true });
}

function detachModuleGraphPhysicalShardProducerValue(
  value,
  description,
  witnesses,
  { jsonOnly = false, role = "value" } = {},
  ancestors = new WeakSet()
) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "undefined"
  ) {
    if (jsonOnly && value === undefined) fail(`${description} must contain JSON data`);
    return value;
  }
  if (typeof value === "number") {
    if (jsonOnly && !Number.isFinite(value)) fail(`${description} contains a non-finite number`);
    return value;
  }
  if (typeof value !== "object" || isProxy(value)) {
    fail(`${description} must contain only non-proxy plain data`);
  }
  if (ancestors.has(value)) fail(`${description} must not contain a cycle`);
  const isArray = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (isArray ? Array.prototype : Object.prototype)) {
    fail(`${description} must contain only plain objects and arrays`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    fail(`${description} must not contain symbol properties`);
  }
  const descriptors = new Map(
    keys.map((key) => [key, Object.getOwnPropertyDescriptor(value, key)])
  );
  const lengthDescriptor = descriptors.get("length");
  if (
    isArray &&
    (lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      keys.length !== lengthDescriptor.value + 1)
  ) {
    fail(`${description} must contain dense ordinary arrays`);
  }
  ancestors.add(value);
  const detached = isArray ? [] : {};
  if (isArray) detached.length = lengthDescriptor.value;
  for (const key of isArray ? keys.filter((item) => item !== "length") : keys) {
    const descriptor = descriptors.get(key);
    if (descriptor === undefined || !descriptor.enumerable) {
      fail(`${description} must contain enumerable data`);
    }
    witnesses.push({ descriptor, key, object: value });
    const sampled = "value" in descriptor ? descriptor.value : descriptor.get?.call(value);
    const nestedRole = role === "matrix" ? "cohort" : key === "units" ? "units" : "value";
    const detachedValue =
      role === "cohort" && (key === "descriptor" || key === "output" || key === "scheduled")
        ? sampled
        : detachModuleGraphPhysicalShardProducerValue(
            sampled,
            `${description}.${key}`,
            witnesses,
            { jsonOnly, role: nestedRole },
            ancestors
          );
    Object.defineProperty(detached, key, {
      configurable: true,
      enumerable: true,
      value: detachedValue,
      writable: true,
    });
  }
  ancestors.delete(value);
  return detached;
}

function detachModuleGraphPhysicalShardProducerInputs(
  authenticatedCohortUnitMatrix,
  physicalShardPlanning
) {
  const witnesses = [];
  const matrix = detachModuleGraphPhysicalShardProducerValue(
    authenticatedCohortUnitMatrix,
    "module graph physical shard producer matrix",
    witnesses,
    { role: "matrix" }
  );
  const planning = detachModuleGraphPhysicalShardProducerValue(
    physicalShardPlanning,
    "module graph physical shard producer plan",
    witnesses,
    { jsonOnly: true }
  );
  for (const { descriptor, key, object } of witnesses) {
    const current = Object.getOwnPropertyDescriptor(object, key);
    if (
      current === undefined ||
      current.enumerable !== descriptor.enumerable ||
      ("value" in descriptor
        ? !("value" in current) || current.value !== descriptor.value
        : "value" in current || current.get !== descriptor.get || current.set !== descriptor.set)
    ) {
      fail("module graph physical shard producer input changed while it was detached");
    }
  }
  return { matrix, planning };
}

function moduleGraphPhysicalShardIntrinsicArtifactIdentity(occurrence, description) {
  const { record } = occurrence;
  assertModuleGraphPhysicalShardRetainedPlanningInput(occurrence, description);
  assertPlainObject(record.applicationUnit, `${description} application unit`);
  assertPlainObject(record.authenticated.generatedC, `${description} generated C`);
  const generatedCIdentitySha256 =
    record.applicationUnit.generatedCIdentitySha256 === undefined
      ? fingerprintJson(
          normalizeJson(
            record.applicationUnit.generatedCIdentity,
            `${description} generated-C identity`
          )
        )
      : requireSha256(
          record.applicationUnit.generatedCIdentitySha256,
          `${description} generated-C identity SHA-256`
        );
  const authenticatedGeneratedCIdentitySha256 =
    record.authenticated.generatedC.identitySha256 === undefined
      ? fingerprintJson(
          normalizeJson(
            record.authenticated.generatedC.identity,
            `${description} authenticated generated-C identity`
          )
        )
      : requireSha256(
          record.authenticated.generatedC.identitySha256,
          `${description} authenticated generated-C identity SHA-256`
        );
  if (authenticatedGeneratedCIdentitySha256 !== generatedCIdentitySha256) {
    fail(`${description} generated-C identity changed across authentication`);
  }
  if (record.authenticated.entry.identity === undefined) {
    requireSha256(record.authenticated.entry.identitySha256, `${description} PIC identity SHA-256`);
  } else {
    normalizeJson(record.authenticated.entry.identity, `${description} PIC identity`);
  }
  return {
    entrySymbol: requireManifestString(
      record.unit.entrySymbol,
      `${description} entry symbol`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    ),
    generatedCSha256: requireSha256(
      record.authenticated.generatedC.artifactSha256,
      `${description} generated C SHA-256`
    ),
    generatedCSize: requirePositiveInteger(
      record.authenticated.generatedC.artifactSize,
      `${description} generated C size`
    ),
    objectSha256: requireSha256(
      record.authenticated.entry.artifactSha256,
      `${description} PIC object SHA-256`
    ),
    objectSize: requirePositiveInteger(
      record.authenticated.entry.artifactSize,
      `${description} PIC object size`
    ),
    reusableCodeIdentitySha256: requireSha256(
      record.unit.reusableCodeIdentitySha256,
      `${description} reusable-code identity`
    ),
  };
}

function moduleGraphSharedLinkOrderMember(unit) {
  if (
    unit.kind !== "convex-wasm-official-output-chunk-unit-v2" ||
    unit.entryPublication !== false ||
    unit.nativeSymbolLocator?.kind !== convexWasmOfficialOutputChunkNativeSymbolLocatorKind
  ) {
    return { kind: "unchanged-non-generated-unit" };
  }
  const sourceMembershipSha256 = requireSha256(
    unit.nativeSymbolLocator.sourceMembershipSha256,
    "module graph shared link source membership"
  );
  if (unit.module.sourceMembershipSha256 !== sourceMembershipSha256) {
    fail("module graph shared link source membership disagrees with authenticated module");
  }
  return { kind: "static-hermes-chunk", sourceMembershipSha256 };
}

export function orderConvexWasmModuleGraphSharedComponents(components) {
  const membershipByRepresentative = new Map();
  const memberships = new Set();
  let classification = "stable-source-membership";
  for (const component of components) {
    for (const representative of component.representatives) {
      const member = moduleGraphSharedLinkOrderMember(representative.record.unit);
      if (member.kind !== "static-hermes-chunk") {
        classification = "unchanged-non-generated-unit";
        break;
      }
      if (memberships.has(member.sourceMembershipSha256)) {
        classification = "unchanged-ambiguous-source-membership";
        break;
      }
      memberships.add(member.sourceMembershipSha256);
      membershipByRepresentative.set(representative, member.sourceMembershipSha256);
    }
    if (classification !== "stable-source-membership") break;
  }
  const linkOrder = { kind: convexWasmModuleGraphSharedLinkOrderKind, classification };
  if (classification !== "stable-source-membership") return { components, linkOrder };

  // Generated SH chunks expose distinct unit factories; recursive require initialization resolves
  // them through descriptor-bound slots, not linker order. Their native definitions are unit-namespaced,
  // and initialization is explicit, not a C constructor. Move complete PIC units only: archive
  // member order and SCC membership stay intact. Other producers and ambiguous logical members
  // retain their existing order instead of inventing a content-derived stable tie-breaker.
  const ordered = components.map((component) => {
    const representatives = [...component.representatives].sort((left, right) =>
      compareStrings(membershipByRepresentative.get(left), membershipByRepresentative.get(right))
    );
    return {
      component: { ...component, representatives },
      membershipKey: representatives
        .map((representative) => membershipByRepresentative.get(representative))
        .join(""),
    };
  });
  ordered.sort((left, right) => compareStrings(left.membershipKey, right.membershipKey));
  return { components: ordered.map(({ component }) => component), linkOrder };
}

function moduleGraphPhysicalShardProducerTopologyFromAuthenticatedOccurrences({
  allowPartialCohortMatrix,
  componentOccurrenceDescriptionBySha256,
  matrixByCohortIndex,
  occurrencesByComponentSha256,
  plan,
  topologyPlan,
}) {
  const planComponentBySha256 = new Map(
    plan.components.map((component) => [component.componentSha256, component])
  );
  const componentRepresentativesBySha256 = new Map();
  for (const [componentSha256, occurrences] of occurrencesByComponentSha256) {
    const description = componentOccurrenceDescriptionBySha256.get(componentSha256);
    if (description === undefined) {
      fail("module graph physical shard producer lacks a component occurrence description");
    }
    const occurrenceCohortSha256s = [...new Set(occurrences.map(({ cohortId }) => cohortId))].sort(
      compareStrings
    );
    const planComponent = planComponentBySha256.get(componentSha256);
    if (planComponent === undefined) {
      fail(`${description} references an unknown plan component`);
    }
    if (
      !allowPartialCohortMatrix &&
      !stringArrayEqual(occurrenceCohortSha256s, planComponent.occurrenceCohortSha256s)
    ) {
      fail(`${description} does not cover its authenticated component cohorts`);
    }
    const occurrencesByCodeIdentitySha256 = new Map();
    for (const occurrence of occurrences) {
      const logicalUnitOccurrences =
        occurrencesByCodeIdentitySha256.get(occurrence.codeIdentitySha256) ?? [];
      logicalUnitOccurrences.push(occurrence);
      occurrencesByCodeIdentitySha256.set(occurrence.codeIdentitySha256, logicalUnitOccurrences);
    }
    const occurrenceCodeIdentitySha256s = [...occurrencesByCodeIdentitySha256.keys()].sort(
      compareStrings
    );
    if (!stringArrayEqual(occurrenceCodeIdentitySha256s, planComponent.codeIdentitySha256s)) {
      fail(`${description} does not cover every component logical unit`);
    }
    const representatives = [];
    for (const codeIdentitySha256 of planComponent.codeIdentitySha256s) {
      const logicalUnitOccurrences = occurrencesByCodeIdentitySha256.get(codeIdentitySha256);
      const logicalUnitCohorts = [
        ...new Set(logicalUnitOccurrences.map(({ cohortId }) => cohortId)),
      ].sort(compareStrings);
      if (!stringArrayEqual(logicalUnitCohorts, occurrenceCohortSha256s)) {
        fail(`${description} logical unit does not cover its authenticated component cohorts`);
      }
      const intrinsicArtifactIdentities = logicalUnitOccurrences.map((occurrence) =>
        moduleGraphPhysicalShardIntrinsicArtifactIdentity(occurrence, description)
      );
      for (const field of Object.keys(intrinsicArtifactIdentities[0])) {
        if (
          intrinsicArtifactIdentities.some(
            (identity) => identity[field] !== intrinsicArtifactIdentities[0][field]
          )
        ) {
          fail(
            `${description} logical unit intrinsic ${field} drifted across equivalent occurrences`
          );
        }
      }
      representatives.push({
        ...logicalUnitOccurrences[0],
        intrinsicArtifactIdentity: intrinsicArtifactIdentities[0],
      });
    }
    componentRepresentativesBySha256.set(componentSha256, representatives);
  }
  const sharedShardBySha256 = new Map(plan.sharedShards.map((shard) => [shard.shardSha256, shard]));
  const sharedShards = plan.shardOrder.flatMap((shardSha256) => {
    const shard = sharedShardBySha256.get(shardSha256);
    // The plan's canonical digest arrays authenticate membership. The topology below owns
    // physical object order; digest order reaches the linker only for a classified unchanged case.
    const components = shard.componentSha256s
      .map((componentSha256) => {
        const occurrences = occurrencesByComponentSha256.get(componentSha256);
        if (occurrences === undefined) return undefined;
        const representatives = componentRepresentativesBySha256.get(componentSha256);
        if (representatives === undefined) {
          fail("module graph physical shard producer lacks component representatives");
        }
        return { componentSha256, occurrences, representatives };
      })
      .filter((component) => component !== undefined);
    if (allowPartialCohortMatrix && components.length === 0) return [];
    if (allowPartialCohortMatrix && components.length !== shard.componentSha256s.length) {
      fail("module graph physical shard partial topology omits a selected shard component");
    }
    return [
      {
        ...orderConvexWasmModuleGraphSharedComponents(components),
        role: moduleGraphSharedRole(shardSha256),
        shardSha256,
      },
    ];
  });
  const cohorts = [...matrixByCohortIndex.values()]
    .sort(({ cohort: left }, { cohort: right }) => left.cohortIndex - right.cohortIndex)
    .map(({ cohort, cohortId, recordsBySlot }) => {
      const selectedShardSha256s = new Set(
        moduleGraphSharedShardsForCohort(plan, cohortId).map(({ shardSha256 }) => shardSha256)
      );
      const selectedSharedShards = sharedShards.filter(({ shardSha256 }) =>
        selectedShardSha256s.has(shardSha256)
      );
      const sharedSlots = new Set(
        selectedSharedShards.flatMap(({ components }) =>
          components
            .flatMap(({ occurrences }) => occurrences)
            .filter((occurrence) => occurrence.cohortIndex === cohort.cohortIndex)
            .map(({ applicationUnitSlot }) => applicationUnitSlot)
        )
      );
      const leafRecords = [...recordsBySlot.values()].filter(
        ({ applicationUnitSlot }) => !sharedSlots.has(applicationUnitSlot)
      );
      const entryPublicationCount = cohort.units.filter(
        ({ unit }) => unit.entryPublication === true
      ).length;
      if (
        leafRecords.length === 0 ||
        leafRecords.filter(({ unit }) => unit.entryPublication === true).length !==
          entryPublicationCount
      ) {
        fail("module graph physical shard producer removed an entry-publication leaf unit");
      }
      return { cohort, leafRecords, sharedShards: selectedSharedShards };
    });
  return { cohorts, plan: topologyPlan, sharedShards };
}

function moduleGraphPhysicalShardProducerTopology(
  { authenticatedCohortUnitMatrix, physicalShardPlanning },
  { verifyPlanning, allowPartialCohortMatrix = false, cohortPlanningContributions }
) {
  const retainedAuthority = retainedModuleGraphPhysicalShardPlanningAuthority({
    allowPartialCohortMatrix,
    authenticatedCohortUnitMatrix,
    cohortPlanningContributions,
    physicalShardPlanning,
  });
  if (retainedAuthority !== undefined) {
    return moduleGraphPhysicalShardProducerTopologyFromAuthenticatedOccurrences({
      allowPartialCohortMatrix: false,
      componentOccurrenceDescriptionBySha256:
        retainedAuthority.componentOccurrenceDescriptionBySha256,
      matrixByCohortIndex: retainedAuthority.matrixByCohortIndex,
      occurrencesByComponentSha256: retainedAuthority.occurrencesByComponentSha256,
      plan: retainedAuthority.topologyPlan,
      topologyPlan: retainedAuthority.topologyPlan,
    });
  }
  if (
    !moduleGraphPhysicalShardProducerMatrixIsOrdinary(authenticatedCohortUnitMatrix) ||
    !moduleGraphPhysicalShardProducerPlanningIsOrdinary(physicalShardPlanning)
  ) {
    ({ matrix: authenticatedCohortUnitMatrix, planning: physicalShardPlanning } =
      detachModuleGraphPhysicalShardProducerInputs(
        authenticatedCohortUnitMatrix,
        physicalShardPlanning
      ));
  }
  if (!Array.isArray(authenticatedCohortUnitMatrix) || authenticatedCohortUnitMatrix.length === 0) {
    fail("module graph physical shard producer requires authenticated cohort units");
  }
  requireExactPlainObject(
    physicalShardPlanning,
    ["componentOccurrences", "kind", "plan", "residualComponents", "sharedShards", "shardOrder"],
    "module graph physical shard producer plan"
  );
  if (
    physicalShardPlanning.kind !==
      "convex-wasm-official-output-module-graph-physical-shard-planning-v2" ||
    canonicalJson(physicalShardPlanning.sharedShards) !==
      canonicalJson(physicalShardPlanning.plan.sharedShards) ||
    canonicalJson(physicalShardPlanning.residualComponents) !==
      canonicalJson(physicalShardPlanning.plan.residualComponents) ||
    !stringArrayEqual(physicalShardPlanning.shardOrder, physicalShardPlanning.plan.shardOrder)
  ) {
    fail("module graph physical shard producer plan disagrees with its authenticated payload");
  }
  const plan = normalizeModuleGraphPhysicalShardPlan(physicalShardPlanning.plan);
  const matrixByCohortIndex = new Map();
  const matrixRecordByCohortAndSlot = new Map();
  const matrixCohortIds = new Set();
  for (const cohort of authenticatedCohortUnitMatrix) {
    assertPlainObject(cohort, "authenticated module graph producer cohort");
    const cohortId = requireSha256(
      cohort.cohortId,
      "authenticated module graph producer cohort ID"
    );
    const cohortIndex = cohort.cohortIndex;
    if (!Number.isSafeInteger(cohortIndex) || cohortIndex < 0) {
      fail("authenticated module graph producer cohort index is invalid");
    }
    if (
      matrixByCohortIndex.has(cohortIndex) ||
      matrixCohortIds.has(cohortId) ||
      !Array.isArray(cohort.units)
    ) {
      fail("authenticated module graph producer cohort matrix is invalid");
    }
    const compilerOutput = cohort.output;
    if (cohort.cohortId !== cohortId || cohort.cohortIndex !== cohortIndex) {
      fail("authenticated module graph producer cohort identity changed during validation");
    }
    matrixCohortIds.add(cohortId);
    const recordsBySlot = new Map();
    for (const record of cohort.units) {
      assertPlainObject(record, "authenticated module graph producer matrix unit");
      if (
        !Number.isSafeInteger(record.applicationUnitSlot) ||
        record.applicationUnitSlot < 0 ||
        recordsBySlot.has(record.applicationUnitSlot)
      ) {
        fail("authenticated module graph producer matrix repeats a unit slot");
      }
      recordsBySlot.set(record.applicationUnitSlot, record);
      matrixRecordByCohortAndSlot.set(
        `${String(cohortIndex)}:${String(record.applicationUnitSlot)}`,
        record
      );
    }
    matrixByCohortIndex.set(cohortIndex, {
      cohort,
      cohortId,
      compilerOutput,
      recordsBySlot,
    });
  }
  const planComponentBySha256 = new Map(
    plan.components.map((component) => [component.componentSha256, component])
  );
  const selectedCohortIndexes = allowPartialCohortMatrix
    ? new Set(authenticatedCohortUnitMatrix.map(({ cohortIndex }) => cohortIndex))
    : undefined;
  if (!Array.isArray(physicalShardPlanning.componentOccurrences)) {
    fail("module graph physical shard producer plan has no component occurrences");
  }
  const occurrencesByComponentSha256 = new Map();
  const componentOccurrenceDescriptionBySha256 = new Map();
  const plannedOccurrenceKeys = new Set();
  for (const [index, componentOccurrence] of physicalShardPlanning.componentOccurrences.entries()) {
    const description = `module graph physical shard producer component occurrence ${index}`;
    requireExactPlainObject(componentOccurrence, ["componentSha256", "occurrences"], description);
    const componentSha256 = requireSha256(
      componentOccurrence.componentSha256,
      `${description}.componentSha256`
    );
    if (
      !planComponentBySha256.has(componentSha256) ||
      occurrencesByComponentSha256.has(componentSha256) ||
      !Array.isArray(componentOccurrence.occurrences) ||
      componentOccurrence.occurrences.length === 0
    ) {
      fail(`${description} is not a complete unique plan component occurrence`);
    }
    const occurrences = componentOccurrence.occurrences
      .filter(
        (occurrence) =>
          selectedCohortIndexes === undefined || selectedCohortIndexes.has(occurrence.cohortIndex)
      )
      .map((occurrence, occurrenceIndex) => {
        const occurrenceDescription = `${description}.occurrences[${occurrenceIndex}]`;
        requireExactPlainObject(
          occurrence,
          [
            "applicationUnitSlot",
            "codeIdentitySha256",
            "cohortId",
            "cohortIndex",
            "picObject",
            "unitIdentitySha256",
          ],
          occurrenceDescription
        );
        const codeIdentitySha256 = requireSha256(
          occurrence.codeIdentitySha256,
          `${occurrenceDescription}.codeIdentitySha256`
        );
        const cohortIndex = occurrence.cohortIndex;
        const applicationUnitSlot = occurrence.applicationUnitSlot;
        const matrix = matrixByCohortIndex.get(cohortIndex);
        const record = matrixRecordByCohortAndSlot.get(
          `${String(cohortIndex)}:${String(applicationUnitSlot)}`
        );
        requireExactPlainObject(
          occurrence.picObject,
          ["byteWeight", "sha256"],
          `${occurrenceDescription}.picObject`
        );
        if (
          !Number.isSafeInteger(cohortIndex) ||
          cohortIndex < 0 ||
          !Number.isSafeInteger(applicationUnitSlot) ||
          applicationUnitSlot < 0 ||
          matrix === undefined ||
          record === undefined ||
          occurrence.cohortId !== matrix.cohortId ||
          occurrence.unitIdentitySha256 !== record.unitIdentitySha256 ||
          occurrence.picObject.byteWeight !== record.authenticated.entry.artifactSize ||
          occurrence.picObject.sha256 !== record.authenticated.entry.artifactSha256
        ) {
          fail(`${occurrenceDescription} does not match an authenticated cohort unit`);
        }
        return {
          applicationUnitSlot,
          codeIdentitySha256,
          cohortId: matrix.cohortId,
          cohortIndex,
          compilerOutput: matrix.compilerOutput,
          record,
        };
      });
    const occurrenceKeys = occurrences.map(
      ({ applicationUnitSlot, cohortIndex }) =>
        `${String(cohortIndex)}:${String(applicationUnitSlot)}`
    );
    if (new Set(occurrenceKeys).size !== occurrenceKeys.length) {
      fail(`${description} repeats an authenticated cohort unit`);
    }
    for (const occurrenceKey of occurrenceKeys) {
      if (plannedOccurrenceKeys.has(occurrenceKey)) {
        fail(`${description} repeats an authenticated cohort unit from another component`);
      }
      plannedOccurrenceKeys.add(occurrenceKey);
    }
    if (occurrences.length === 0) continue;
    componentOccurrenceDescriptionBySha256.set(componentSha256, description);
    occurrencesByComponentSha256.set(componentSha256, occurrences);
  }
  const expectedComponentCount = allowPartialCohortMatrix
    ? physicalShardPlanning.componentOccurrences.filter(({ occurrences }) =>
        occurrences.some(({ cohortIndex }) => selectedCohortIndexes?.has(cohortIndex) === true)
      ).length
    : plan.components.length;
  if (occurrencesByComponentSha256.size !== expectedComponentCount) {
    fail("module graph physical shard producer plan omits component occurrences");
  }
  if (
    !stringArrayEqual(
      [...plannedOccurrenceKeys].sort(compareStrings),
      [...matrixRecordByCohortAndSlot.keys()].sort(compareStrings)
    )
  ) {
    fail(
      "module graph physical shard producer plan does not cover every authenticated cohort unit"
    );
  }
  // Read every occurrence, including its caller-owned compiler-output reference, before this
  // comparison. A getter may replace plan-defining matrix values while occurrences are indexed;
  // generic validation must compare against the resulting current matrix, not its earlier state.
  if (
    verifyPlanning &&
    canonicalJson(physicalShardPlanning) !==
      canonicalJson(
        deriveConvexWasmOfficialOutputModuleGraphPhysicalShardPlan({
          authenticatedCohortUnitMatrix,
        })
      )
  ) {
    fail("module graph physical shard producer plan differs from the authenticated cohort units");
  }
  const topology = moduleGraphPhysicalShardProducerTopologyFromAuthenticatedOccurrences({
    allowPartialCohortMatrix,
    componentOccurrenceDescriptionBySha256,
    matrixByCohortIndex,
    occurrencesByComponentSha256,
    plan,
    topologyPlan: plan,
  });
  return topology;
}

export function deriveConvexWasmOfficialOutputModuleGraphPhysicalShardProducerTopology(options) {
  return moduleGraphPhysicalShardProducerTopology(options, { verifyPlanning: true });
}

// A complete physical-shard plan can be derived from retained cohort planning contributions
// before every cohort's immutable stage entries have been reauthenticated. Once one cohort's
// entries are authenticated, derive only that cohort's producer topology against the same plan.
// The complete matrix remains mandatory for the final topology and publication authority.
export function deriveConvexWasmOfficialOutputModuleGraphPhysicalShardProducerCohortTopology({
  authenticatedCohortUnitMatrix,
  physicalShardPlanning,
}) {
  if (!Array.isArray(authenticatedCohortUnitMatrix) || authenticatedCohortUnitMatrix.length !== 1) {
    fail("module graph physical shard producer cohort topology requires one cohort");
  }
  return moduleGraphPhysicalShardProducerTopology(
    { authenticatedCohortUnitMatrix, physicalShardPlanning },
    {
      allowPartialCohortMatrix: true,
      verifyPlanning: false,
    }
  );
}

export function deriveConvexWasmOfficialOutputModuleGraphPhysicalShardPlanningAndProducerTopology({
  authenticatedCohortUnitMatrix,
  cohortPlanningContributions,
}) {
  const physicalShardPlanning = deriveConvexWasmOfficialOutputModuleGraphPhysicalShardPlan({
    authenticatedCohortUnitMatrix,
    ...(cohortPlanningContributions === undefined ? {} : { cohortPlanningContributions }),
  });
  return {
    physicalShardPlanning,
    shardTopology: moduleGraphPhysicalShardProducerTopology(
      { authenticatedCohortUnitMatrix, physicalShardPlanning },
      { cohortPlanningContributions, verifyPlanning: true }
    ),
  };
}

function moduleGraphSharedShardsForCohort(physicalShardPlan, cohortId) {
  const shardBySha256 = new Map(
    physicalShardPlan.sharedShards.map((shard) => [shard.shardSha256, shard])
  );
  const componentBySha256 = new Map(
    physicalShardPlan.components.map((component) => [component.componentSha256, component])
  );
  const requiredShardSha256s = new Set();
  const includeShard = (shardSha256) => {
    if (requiredShardSha256s.has(shardSha256)) return;
    const shard = shardBySha256.get(shardSha256);
    if (shard === undefined)
      fail("module graph physical shard closure references an unknown shard");
    requiredShardSha256s.add(shardSha256);
    for (const dependencySha256 of shard.dependencies) includeShard(dependencySha256);
  };
  for (const shard of physicalShardPlan.sharedShards) {
    if (
      shard.componentSha256s.some((componentSha256) =>
        componentBySha256.get(componentSha256).occurrenceCohortSha256s.includes(cohortId)
      )
    ) {
      includeShard(shard.shardSha256);
    }
  }
  return physicalShardPlan.shardOrder
    .filter((shardSha256) => requiredShardSha256s.has(shardSha256))
    .map((shardSha256) => ({
      role: moduleGraphSharedRole(shardSha256),
      shardSha256,
    }));
}

function moduleGraphTopologyFromBuildInputs(rawModules, rawPhysicalShardPlan, cohortId) {
  const roles = normalizeModuleGraphRoleSequence(rawModules, "module graph modules");
  if (rawPhysicalShardPlan === undefined) {
    if (
      !stringArrayEqual(roles, [
        MODULE_GRAPH_BASE_ROLE,
        MODULE_GRAPH_LEGACY_SHARED_ROLE,
        MODULE_GRAPH_LEAF_ROLE,
      ])
    ) {
      fail("module graph variable shared modules require an authenticated physical shard plan");
    }
    return { roles, sharedShards: undefined };
  }
  const physicalShardPlan = normalizeModuleGraphPhysicalShardPlan(rawPhysicalShardPlan);
  const sharedShards = moduleGraphSharedShardsForCohort(physicalShardPlan, cohortId);
  const expectedRoles = [
    MODULE_GRAPH_BASE_ROLE,
    ...sharedShards.map(({ role }) => role),
    MODULE_GRAPH_LEAF_ROLE,
  ];
  if (!stringArrayEqual(roles, expectedRoles)) {
    fail("module graph modules do not match the authenticated physical shard plan order");
  }
  return {
    roles,
    sharedShards: {
      kind: MODULE_GRAPH_SHARED_MODULES_KIND,
      shards: sharedShards,
    },
  };
}

function normalizeStableCoreModule(
  coreIdentity,
  role,
  roles,
  engineCompatibilitySha256,
  normalizationMemo
) {
  const retained = normalizationMemo?.get(coreIdentity);
  if (retained !== undefined) {
    if (retained.role !== role) {
      fail(`stable Core Wasm identity was already authenticated for ${retained.role}, not ${role}`);
    }
    if (retained.engineCompatibilitySha256 !== engineCompatibilitySha256) {
      fail(
        `${role} module contract was inspected under a different Wasmtime engine compatibility identity`
      );
    }
    const availableProviders = new Set([...roles, "host", "loader", "weak-zero"]);
    const unsupportedProviderIndex = retained.module.providers.findIndex(
      ({ provider }) => !availableProviders.has(provider)
    );
    if (unsupportedProviderIndex !== -1) {
      fail(`${role} module provider ${unsupportedProviderIndex}.provider is unsupported`);
    }
    return retained.module;
  }
  const module = deeplyFreezeStableCoreModuleValue(
    normalizeModuleGraphModule(
      {
        contract: coreIdentity.contract,
        layout: coreIdentity.layout,
        link: coreIdentity.link,
        objectCompilation: coreIdentity.objectCompilation,
        ownership: coreIdentity.ownership,
        providers: coreIdentity.providers,
        role,
        ...(coreIdentity.sharedShardSha256 === undefined
          ? {}
          : { sharedShardSha256: coreIdentity.sharedShardSha256 }),
        sourceProvenance: coreIdentity.sourceProvenance,
      },
      role,
      roles,
      engineCompatibilitySha256
    )
  );
  normalizationMemo?.set(coreIdentity, Object.freeze({ engineCompatibilitySha256, module, role }));
  return module;
}

// Persisted and generic callers do not supply construction-owned normalized modules.
function normalizeModuleGraphManifest(value, stableCoreIdentitiesByRole) {
  return normalizeModuleGraphManifestWithModules(value, stableCoreIdentitiesByRole);
}

// The package builder has normalized these modules and completed their exact Core artifacts.
// Keep that producer-owned representation through manifest assembly; persisted inputs still
// enter normalizeModuleGraphManifest and reconstruct modules from their authenticated identities.
function createModuleGraphManifestFromBuiltModules(value, builtModules) {
  const modulesByRole = new Map();
  const stableCoreIdentitiesByRole = new Map();
  for (const { aot, aotIdentity, coreIdentity, coreWasm, ...module } of builtModules) {
    modulesByRole.set(module.role, module);
    if (module.role !== MODULE_GRAPH_LEAF_ROLE) {
      stableCoreIdentitiesByRole.set(module.role, coreIdentity);
    }
  }
  return normalizeModuleGraphManifestWithModules(value, stableCoreIdentitiesByRole, modulesByRole);
}

function normalizeModuleGraphManifestWithModules(
  value,
  stableCoreIdentitiesByRole,
  builtModulesByRole
) {
  if (authenticatedModuleGraphManifests.has(value)) return value;
  const description = "module graph manifest";
  const currentFormat =
    value?.kind === convexWasmModuleGraphManifestKind && value?.schemaVersion === 5;
  const legacyFormat =
    value?.kind === LEGACY_MODULE_GRAPH_MANIFEST_KIND && value?.schemaVersion === 3;
  if (!currentFormat && !legacyFormat) {
    fail(`${description}.kind or schemaVersion is unsupported`);
  }
  const moduleField = currentFormat ? "moduleReferences" : "modules";
  requireExactPlainObject(
    value,
    Object.hasOwn(value, "sharedShards")
      ? [
          "engine",
          "graphManifestSha256",
          "hostAbi",
          "initialization",
          "kind",
          moduleField,
          "producerImplementation",
          "replacement",
          "routing",
          "schemaVersion",
          "sharedShards",
          "toolchain",
          ...(currentFormat ? ["contextReuseAnalysis"] : []),
        ]
      : [
          "engine",
          "graphManifestSha256",
          "hostAbi",
          "initialization",
          "kind",
          moduleField,
          "producerImplementation",
          "replacement",
          "routing",
          "schemaVersion",
          "toolchain",
          ...(currentFormat ? ["contextReuseAnalysis"] : []),
        ],
    description
  );
  const engine = normalizeModuleGraphEngine(value.engine);
  const contextReuseAnalysis = currentFormat
    ? authenticateConvexContextReuseCohortAnalysisIdentity(value.contextReuseAnalysis)
    : undefined;
  const hostAbi = normalizeModuleGraphHostAbi(value.hostAbi);
  const producerImplementation = normalizeProducerImplementationIdentity(
    value.producerImplementation,
    `${description}.producerImplementation`
  );
  const rawModules = value[moduleField];
  const roles = normalizeModuleGraphRoleSequence(rawModules, `${description}.${moduleField}`);
  const authorityIdentities = new Map();
  const storedModules = [];
  const modules = rawModules.map((rawModule, index) => {
    const role = roles[index];
    const builtModule = builtModulesByRole?.get(role);
    if (builtModulesByRole !== undefined && builtModule === undefined) {
      fail(`module graph manifest lacks its completed ${role} module`);
    }
    if (
      builtModule !== undefined &&
      builtModule.contract.authority.engineCompatibilitySha256 !== engine.compatibilitySha256
    ) {
      fail(
        `${role} module contract was inspected under a different Wasmtime engine compatibility identity`
      );
    }
    if (currentFormat && role !== MODULE_GRAPH_LEAF_ROLE) {
      requireExactPlainObject(
        rawModule,
        ["artifacts", "authority", "role"],
        `${description}.${moduleField}[${index}]`
      );
      requireExactPlainObject(
        rawModule.artifacts,
        ["aot", "coreWasm"],
        `${description}.${moduleField}[${index}].artifacts`
      );
      requireExactPlainObject(
        rawModule.authority,
        ["kind"],
        `${description}.${moduleField}[${index}].authority`
      );
      if (rawModule.authority.kind !== MODULE_GRAPH_CORE_IDENTITY_AUTHORITY_KIND) {
        fail(`${description}.${moduleField}[${index}].authority.kind is unsupported`);
      }
      const coreIdentity = stableCoreIdentitiesByRole?.get(role);
      if (coreIdentity === undefined) {
        fail(`${description}.${moduleField}[${index}] lacks its authenticated Core Wasm identity`);
      }
      const artifacts = {
        aot: normalizeModuleGraphArtifactReference(rawModule.artifacts.aot, role, "aot"),
        coreWasm: normalizeModuleGraphArtifactReference(
          rawModule.artifacts.coreWasm,
          role,
          "coreWasm"
        ),
      };
      const module =
        builtModule ??
        normalizeStableCoreModule(
          coreIdentity,
          role,
          roles,
          engine.compatibilitySha256,
          authenticatedStableCoreIdentities.has(coreIdentity)
            ? normalizedStableCoreModules
            : undefined
        );
      storedModules.push({
        artifacts,
        authority: {
          kind: MODULE_GRAPH_CORE_IDENTITY_AUTHORITY_KIND,
        },
        role,
      });
      authorityIdentities.set(role, coreIdentity);
      return { ...module, artifacts };
    }
    const sharedShardSha256 = moduleGraphSharedShardSha256(role);
    requireExactPlainObject(
      rawModule,
      sharedShardSha256 === undefined
        ? [
            "artifacts",
            "contract",
            "layout",
            "link",
            "objectCompilation",
            "ownership",
            "providers",
            "role",
            "sourceProvenance",
          ]
        : [
            "artifacts",
            "contract",
            "layout",
            "link",
            "objectCompilation",
            "ownership",
            "providers",
            "role",
            "sharedShardSha256",
            "sourceProvenance",
          ],
      `${description}.modules[${index}]`
    );
    requireExactPlainObject(
      rawModule.artifacts,
      ["aot", "coreWasm"],
      `${description}.modules[${index}].artifacts`
    );
    const { artifacts, ...module } = rawModule;
    const normalized = {
      ...(builtModule ??
        normalizeModuleGraphModule(module, role, roles, engine.compatibilitySha256)),
      artifacts: {
        aot: normalizeModuleGraphArtifactReference(artifacts.aot, role, "aot"),
        coreWasm: normalizeModuleGraphArtifactReference(artifacts.coreWasm, role, "coreWasm"),
      },
    };
    storedModules.push(normalized);
    return normalized;
  });
  const sharedShards = normalizeModuleGraphSharedShards(
    value.sharedShards,
    modules,
    `${description}.sharedShards`
  );
  validateModuleGraphProviders(modules, hostAbi);
  if (
    modules.some((module) => !stringArrayEqual(module.ownership.tags, modules[0].ownership.tags))
  ) {
    fail(`${description}.modules do not share one Wasm EH tag set`);
  }
  requireExactPlainObject(
    value.initialization,
    [
      "baseHeapBase",
      "baseTableSize",
      "constructorOrder",
      "finalMemoryCursor",
      "finalTableCursor",
      "moduleOrder",
      "relocationOrder",
    ],
    `${description}.initialization`
  );
  const {
    finalMemoryCursor: rawFinalMemoryCursor,
    finalTableCursor: rawFinalTableCursor,
    ...rawInitialization
  } = value.initialization;
  const initialization = normalizeModuleGraphInitialization(rawInitialization, modules);
  if (
    rawFinalMemoryCursor !== initialization.finalMemoryCursor ||
    rawFinalTableCursor !== initialization.finalTableCursor
  ) {
    fail(`${description}.initialization final cursors are invalid`);
  }
  const routing = normalizeModuleGraphRouting(value.routing);
  const toolchain = normalizeModuleGraphToolchain(value.toolchain);
  const leafInvalidation = createModuleGraphLeafInvalidation(modules, routing);
  requireExactPlainObject(
    value.replacement,
    [
      "leafInvalidation",
      "leafInvalidationSha256",
      "previousGraphManifestSha256",
      "replace",
      "stable",
    ],
    `${description}.replacement`
  );
  const leafReplacement = value.replacement.replace === MODULE_GRAPH_LEAF_ROLE;
  const fullReplacement = value.replacement.replace === "all";
  const stableRoles = moduleGraphRoles(modules.slice(0, -1));
  if (
    (!leafReplacement && !fullReplacement) ||
    !stringArrayEqual(value.replacement.stable, leafReplacement ? stableRoles : []) ||
    (leafReplacement && !SHA256_PATTERN.test(value.replacement.previousGraphManifestSha256)) ||
    (fullReplacement && value.replacement.previousGraphManifestSha256 !== null) ||
    canonicalJson(value.replacement.leafInvalidation) !== canonicalJson(leafInvalidation) ||
    requireSha256(
      value.replacement.leafInvalidationSha256,
      `${description}.replacement.leafInvalidationSha256`
    ) !== fingerprintJson(leafInvalidation)
  ) {
    fail(`${description}.replacement does not bind the exact shared and leaf identities`);
  }
  const manifestPayload = {
    ...(currentFormat ? { contextReuseAnalysis } : {}),
    engine,
    hostAbi,
    initialization,
    kind: currentFormat ? convexWasmModuleGraphManifestKind : LEGACY_MODULE_GRAPH_MANIFEST_KIND,
    ...(currentFormat ? { moduleReferences: storedModules } : { modules }),
    producerImplementation,
    replacement: {
      leafInvalidation,
      leafInvalidationSha256: fingerprintJson(leafInvalidation),
      previousGraphManifestSha256: leafReplacement
        ? value.replacement.previousGraphManifestSha256
        : null,
      replace: leafReplacement ? MODULE_GRAPH_LEAF_ROLE : "all",
      stable: leafReplacement ? stableRoles : [],
    },
    routing,
    schemaVersion: currentFormat ? 5 : 3,
    ...(sharedShards === undefined ? {} : { sharedShards }),
    toolchain,
  };
  if (currentFormat) {
    const expectedIdentities = expectedModuleGraphArtifactIdentities({
      ...manifestPayload,
      modules,
    });
    for (const [role, identity] of authorityIdentities) {
      if (!authenticatedJsonValuesEqual(identity, expectedIdentities[role].coreWasm)) {
        fail(`${description} ${role} Core Wasm authority disagrees with its graph identity`);
      }
    }
  }
  const graphManifestSha256 = requireSha256(
    value.graphManifestSha256,
    `${description}.graphManifestSha256`
  );
  if (graphManifestSha256 !== fingerprintJson(manifestPayload)) {
    fail(`${description}.graphManifestSha256 is invalid`);
  }
  freezeAuthenticatedJsonTree(modules);
  const authenticated = { ...manifestPayload, graphManifestSha256 };
  if (currentFormat) {
    Object.defineProperty(authenticated, "modules", {
      configurable: false,
      enumerable: false,
      value: modules,
      writable: false,
    });
  }
  freezeAuthenticatedJsonTree(authenticated);
  authenticatedModuleGraphManifests.add(authenticated);
  authenticatedModuleGraphManifestModules.set(authenticated, modules);
  return authenticated;
}

export function convexWasmModuleGraphManifestModules(value) {
  const modules = authenticatedModuleGraphManifestModules.get(value);
  if (!authenticatedModuleGraphManifests.has(value) || modules === undefined) {
    fail("module graph manifest modules require authenticated manifest authority");
  }
  return modules;
}

function authenticatedConvexWasmModuleGraphManifestSha256(value) {
  if (!authenticatedModuleGraphManifests.has(value)) return undefined;
  return requireSha256(value.graphManifestSha256, "authenticated module graph manifest SHA-256");
}

export function assertConvexWasmModuleGraphLeafReplacement({
  previousGraphManifest,
  replacementGraphManifest,
}) {
  const previous = normalizeModuleGraphManifest(previousGraphManifest);
  const replacement = normalizeModuleGraphManifest(replacementGraphManifest);
  if (
    replacement.replacement.replace !== MODULE_GRAPH_LEAF_ROLE ||
    replacement.replacement.previousGraphManifestSha256 !== previous.graphManifestSha256
  ) {
    fail("module graph replacement does not authenticate its exact previous graph");
  }
  if (
    canonicalJson(previous.engine) !== canonicalJson(replacement.engine) ||
    canonicalJson(previous.hostAbi) !== canonicalJson(replacement.hostAbi) ||
    canonicalJson(previous.initialization) !== canonicalJson(replacement.initialization) ||
    canonicalJson(previous.toolchain) !== canonicalJson(replacement.toolchain)
  ) {
    fail("leaf replacement changed graph-wide engine, host, initialization, or toolchain state");
  }
  const previousStableRoles = moduleGraphRoles(previous.modules.slice(0, -1));
  if (!stringArrayEqual(previousStableRoles, replacement.replacement.stable)) {
    fail("leaf replacement changed the ordered shared module topology");
  }
  const replacementByRole = new Map(replacement.modules.map((module) => [module.role, module]));
  for (const previousModule of previous.modules.slice(0, -1)) {
    const replacementModule = replacementByRole.get(previousModule.role);
    if (
      replacementModule === undefined ||
      canonicalJson(moduleGraphStableModuleIdentity(previousModule)) !==
        canonicalJson(moduleGraphStableModuleIdentity(replacementModule))
    ) {
      fail(`leaf replacement changed the ${previousModule.role} module identity`);
    }
  }
  if (
    canonicalJson(moduleGraphStableModuleIdentity(previous.modules.at(-1))) ===
    canonicalJson(moduleGraphStableModuleIdentity(replacement.modules.at(-1)))
  ) {
    fail("leaf replacement did not change the leaf module identity");
  }
  return true;
}

function normalizeModuleGraphProvenance(value, manifest) {
  const retainedAuthority = authenticatedModuleGraphProvenances.get(value);
  if (retainedAuthority !== undefined) {
    if (retainedAuthority.graphManifestSha256 !== manifest.graphManifestSha256) {
      fail("module graph provenance authority belongs to a different graph manifest");
    }
    return value;
  }
  const description = "module graph provenance";
  const currentFormat =
    value?.kind === convexWasmModuleGraphProvenanceKind && value?.schemaVersion === 5;
  const legacyFormat =
    value?.kind === LEGACY_MODULE_GRAPH_PROVENANCE_KIND && value?.schemaVersion === 3;
  if (!currentFormat && !legacyFormat) {
    fail(`${description}.kind or schemaVersion is unsupported`);
  }
  if (currentFormat) {
    requireExactPlainObject(
      value,
      ["contextReuseAnalysis", "kind", "producerIdentity", "schemaVersion"],
      description
    );
    if (manifest.kind !== convexWasmModuleGraphManifestKind || manifest.schemaVersion !== 5) {
      fail(`${description} v5 requires a v5 graph manifest`);
    }
    const producerIdentity = normalizeConvexWasmProducerIdentity(value.producerIdentity);
    const contextReuseAnalysis = authenticateConvexContextReuseCohortAnalysisIdentity(
      value.contextReuseAnalysis
    );
    if (canonicalJson(contextReuseAnalysis) !== canonicalJson(manifest.contextReuseAnalysis)) {
      fail(`${description} context-reuse analysis disagrees with the graph manifest`);
    }
    if (
      !authenticatedJsonValuesEqual(
        producerImplementationIdentity(producerIdentity),
        manifest.producerImplementation
      )
    ) {
      fail(`${description} disagrees with the graph manifest`);
    }
    const identities = freezeAuthenticatedJsonTree(expectedModuleGraphArtifactIdentities(manifest));
    const authenticated = {
      contextReuseAnalysis,
      kind: convexWasmModuleGraphProvenanceKind,
      producerIdentity,
      schemaVersion: 5,
    };
    Object.defineProperty(authenticated, "identities", {
      configurable: false,
      enumerable: false,
      value: identities,
      writable: false,
    });
    freezeAuthenticatedJsonTree(authenticated);
    const source = canonicalJson(authenticated);
    authenticatedModuleGraphProvenances.set(
      authenticated,
      Object.freeze({
        graphManifestSha256: manifest.graphManifestSha256,
        sha256: hashBytes(Buffer.from(source)),
        size: Buffer.byteLength(source),
      })
    );
    return authenticated;
  }
  requireExactPlainObject(
    value,
    Object.hasOwn(manifest, "sharedShards")
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
        ],
    description
  );
  const engine = normalizeModuleGraphEngine(value.engine);
  const hostAbi = normalizeModuleGraphHostAbi(value.hostAbi);
  const routing = normalizeModuleGraphRouting(value.routing);
  const toolchain = normalizeModuleGraphToolchain(value.toolchain);
  const producerIdentity = normalizeConvexWasmProducerIdentity(value.producerIdentity);
  if (
    canonicalJson(engine) !== canonicalJson(manifest.engine) ||
    canonicalJson(hostAbi) !== canonicalJson(manifest.hostAbi) ||
    canonicalJson(producerImplementationIdentity(producerIdentity)) !==
      canonicalJson(manifest.producerImplementation) ||
    canonicalJson(routing) !== canonicalJson(manifest.routing) ||
    canonicalJson(toolchain) !== canonicalJson(manifest.toolchain) ||
    (manifest.sharedShards !== undefined &&
      canonicalJson(value.sharedShards) !== canonicalJson(manifest.sharedShards))
  ) {
    fail(`${description} disagrees with the graph manifest`);
  }
  const roles = moduleGraphRoles(manifest.modules);
  requireExactPlainObject(value.identities, roles, `${description}.identities`);
  const identities = Object.fromEntries(
    roles.map((role) => {
      const identity = value.identities[role];
      requireExactPlainObject(identity, ["aot", "coreWasm"], `${description}.identities.${role}`);
      return [
        role,
        {
          aot: normalizeModuleGraphJsonValue(identity.aot, `${description}.identities.${role}.aot`),
          coreWasm: normalizeModuleGraphJsonValue(
            identity.coreWasm,
            `${description}.identities.${role}.coreWasm`
          ),
        },
      ];
    })
  );
  const authenticated = freezeAuthenticatedJsonTree({
    engine,
    hostAbi,
    identities,
    kind: LEGACY_MODULE_GRAPH_PROVENANCE_KIND,
    producerIdentity,
    routing,
    schemaVersion: 3,
    ...(manifest.sharedShards === undefined ? {} : { sharedShards: manifest.sharedShards }),
    toolchain,
  });
  const source = canonicalJson(authenticated);
  authenticatedModuleGraphProvenances.set(
    authenticated,
    Object.freeze({
      graphManifestSha256: manifest.graphManifestSha256,
      sha256: hashBytes(Buffer.from(source)),
      size: Buffer.byteLength(source),
    })
  );
  return authenticated;
}

function expectedModuleGraphArtifactIdentities(manifest) {
  const leafInvalidation = manifest.replacement.leafInvalidation;
  const leafInvalidationSha256 = manifest.replacement.leafInvalidationSha256;
  return Object.fromEntries(
    manifest.modules.map((module) => {
      const coreWasm = nativeStageIdentity({
        contract: module.contract,
        kind: "convex-wasm-module-graph-core-wasm-identity-v1",
        layout: module.layout,
        link: module.link,
        objectCompilation: module.objectCompilation,
        ownership: module.ownership,
        pipelineKind: PIPELINE_KIND,
        providers: module.providers,
        role: module.role,
        ...(module.sharedShardSha256 === undefined
          ? {}
          : { sharedShardSha256: module.sharedShardSha256 }),
        ...(module.role === MODULE_GRAPH_LEAF_ROLE
          ? { leafInvalidation, leafInvalidationSha256, routing: manifest.routing }
          : {}),
        sourceProvenance: module.sourceProvenance,
        toolchain: {
          core: manifest.toolchain.core,
          staticHermesCBundleMemberCompilation:
            manifest.toolchain.staticHermesCBundleMemberCompilation,
        },
      });
      const aot = nativeStageIdentity({
        coreWasm: {
          cacheKey: module.artifacts.coreWasm.cacheKey,
          sha256: module.artifacts.coreWasm.sha256,
          size: module.artifacts.coreWasm.size,
        },
        engine: manifest.engine,
        kind: "convex-wasm-module-graph-wasmtime-aot-identity-v1",
        pipelineKind: PIPELINE_KIND,
        role: module.role,
        toolchain: manifest.toolchain.aot,
      });
      return [module.role, { aot, coreWasm }];
    })
  );
}

// These values have already passed closed JSON validators and come either from a canonical private
// cache entry or from a normalized graph manifest. Compare them without allocating normalized
// clones or serialized strings. Artifact digests below still bind the exact cache-entry bytes.
function authenticatedJsonValuesEqual(left, right) {
  if (left === right) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  const leftIsArray = Array.isArray(left);
  if (leftIsArray !== Array.isArray(right)) return false;
  if (leftIsArray) {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index += 1) {
      if (!authenticatedJsonValuesEqual(left[index], right[index])) return false;
    }
    return true;
  }
  if (
    Object.getPrototypeOf(left) !== Object.prototype ||
    Object.getPrototypeOf(right) !== Object.prototype
  ) {
    return false;
  }
  const leftKeys = Object.keys(left);
  if (leftKeys.length !== Object.keys(right).length) return false;
  for (const key of leftKeys) {
    if (!Object.hasOwn(right, key) || !authenticatedJsonValuesEqual(left[key], right[key])) {
      return false;
    }
  }
  return true;
}

function moduleGraphPackageArtifactReferencesBindGraph(references, manifest) {
  if (references.length !== manifest.modules.length) return false;
  const modulesByRole = new Map(manifest.modules.map((module) => [module.role, module]));
  for (const reference of references) {
    const module = modulesByRole.get(reference.role);
    if (
      module === undefined ||
      !moduleGraphArtifactReferenceEqual(reference.aot.artifact, module.artifacts.aot) ||
      !moduleGraphArtifactReferenceEqual(reference.coreWasm.artifact, module.artifacts.coreWasm)
    ) {
      return false;
    }
  }
  return true;
}

function normalizeModuleGraphPackageEntry(value, manifestBytes, provenanceBytes, manifest) {
  const description = "module graph package entry";
  const currentFormat = manifest.schemaVersion === 5;
  requireExactPlainObject(
    value,
    [
      "artifacts",
      "key",
      "kind",
      "manifest",
      "provenance",
      ...(currentFormat ? ["contextReuseAnalysis"] : []),
    ],
    description
  );
  const expectedKind = currentFormat
    ? convexWasmModuleGraphPackageEntryKind
    : LEGACY_MODULE_GRAPH_PACKAGE_ENTRY_KIND;
  if (
    value.kind !== expectedKind ||
    requireSha256(value.key, `${description}.key`) !== manifest.graphManifestSha256
  ) {
    fail(`${description} has an unsupported kind or key`);
  }
  const contextReuseAnalysis = currentFormat
    ? authenticateConvexContextReuseCohortAnalysisIdentity(value.contextReuseAnalysis)
    : undefined;
  if (
    currentFormat &&
    canonicalJson(contextReuseAnalysis) !== canonicalJson(manifest.contextReuseAnalysis)
  ) {
    fail(`${description} context-reuse analysis disagrees with the graph manifest`);
  }
  requireExactPlainObject(
    value.artifacts,
    moduleGraphRoles(manifest.modules),
    `${description}.artifacts`
  );
  const artifacts = Object.fromEntries(
    manifest.modules.map((module) => {
      const artifact = value.artifacts[module.role];
      requireExactPlainObject(
        artifact,
        ["aot", "coreWasm"],
        `${description}.artifacts.${module.role}`
      );
      const normalized = {
        aot: normalizeModuleGraphArtifactReference(artifact.aot, module.role, "aot"),
        coreWasm: normalizeModuleGraphArtifactReference(artifact.coreWasm, module.role, "coreWasm"),
      };
      if (!moduleGraphArtifactPairEqual(normalized, module.artifacts)) {
        fail(`${description}.artifacts.${module.role} disagrees with the graph manifest`);
      }
      return [module.role, normalized];
    })
  );
  const metadataFile = (field, bytes) => {
    requireExactPlainObject(value[field], ["sha256", "size"], `${description}.${field}`);
    const actualSha256 = hashBytes(bytes);
    if (
      requireSha256(value[field].sha256, `${description}.${field}.sha256`) !== actualSha256 ||
      value[field].size !== bytes.length
    ) {
      fail(`${description}.${field} does not authenticate its package file`);
    }
    return { sha256: actualSha256, size: bytes.length };
  };
  return {
    artifacts,
    key: manifest.graphManifestSha256,
    kind: expectedKind,
    manifest: metadataFile("manifest", manifestBytes),
    provenance: metadataFile("provenance", provenanceBytes),
    ...(currentFormat ? { contextReuseAnalysis } : {}),
  };
}

function moduleGraphPackageFileMaterial(bytes) {
  return { sha256: hashBytes(bytes), size: bytes.length };
}

function normalizeModuleGraphPackageFileMaterial(value, description) {
  requireExactPlainObject(value, ["sha256", "size"], description);
  return {
    sha256: requireSha256(value.sha256, `${description} SHA-256`),
    size: requirePositiveInteger(value.size, `${description} size`),
  };
}

export function validateConvexWasmModuleGraphPackageMaterial(value, graphManifestSha256) {
  const graphKey = requireSha256(
    graphManifestSha256,
    "module graph package material manifest SHA-256"
  );
  const schemaVersion = value?.schemaVersion;
  const material = requireExactPlainObject(
    value,
    schemaVersion === 1
      ? ["complete", "graphManifest", "kind", "packageEntry", "provenance", "schemaVersion"]
      : [
          "artifactReferences",
          "complete",
          "graphManifest",
          "kind",
          "packageEntry",
          "provenance",
          "schemaVersion",
        ],
    "module graph package material"
  );
  if (
    material.kind !== "convex-wasm-module-graph-package-material-v1" ||
    (schemaVersion !== 1 && schemaVersion !== 2)
  ) {
    fail("module graph package material has an unsupported kind or schema version");
  }
  const normalized = {
    complete: normalizeModuleGraphPackageFileMaterial(
      material.complete,
      "module graph package material completion marker"
    ),
    graphManifest: normalizeModuleGraphPackageFileMaterial(
      material.graphManifest,
      "module graph package material graph manifest"
    ),
    kind: material.kind,
    packageEntry: normalizeModuleGraphPackageFileMaterial(
      material.packageEntry,
      "module graph package material package entry"
    ),
    provenance: normalizeModuleGraphPackageFileMaterial(
      material.provenance,
      "module graph package material provenance"
    ),
    schemaVersion,
  };
  if (schemaVersion === 2) {
    if (!Array.isArray(material.artifactReferences) || material.artifactReferences.length === 0) {
      fail("module graph package material artifact references must be a non-empty array");
    }
    let previousRole;
    normalized.artifactReferences = material.artifactReferences.map((reference, index) => {
      const entry = requireExactPlainObject(
        reference,
        ["aot", "coreWasm", "role"],
        `module graph package material artifact reference ${index}`
      );
      const role = requireString(
        entry.role,
        `module graph package material artifact reference ${index} role`
      );
      if (
        !(
          role === MODULE_GRAPH_BASE_ROLE ||
          role === MODULE_GRAPH_LEGACY_SHARED_ROLE ||
          role === MODULE_GRAPH_LEAF_ROLE ||
          /^shared-[0-9a-f]{64}$/u.test(role)
        ) ||
        (previousRole !== undefined && compareStrings(previousRole, role) >= 0)
      ) {
        fail("module graph package material artifact references must be sorted and unique roles");
      }
      previousRole = role;
      const normalizeArtifact = (artifact, kind) => {
        const value = requireExactPlainObject(
          artifact,
          ["artifact", "identitySha256", "metadataSha256"],
          `module graph package material ${role} ${kind}`
        );
        return {
          artifact: normalizeModuleGraphArtifactReference(value.artifact, role, kind),
          identitySha256: requireSha256(
            value.identitySha256,
            `module graph package material ${role} ${kind} identity SHA-256`
          ),
          metadataSha256: requireSha256(
            value.metadataSha256,
            `module graph package material ${role} ${kind} metadata SHA-256`
          ),
        };
      };
      return {
        aot: normalizeArtifact(entry.aot, "aot"),
        coreWasm: normalizeArtifact(entry.coreWasm, "coreWasm"),
        role,
      };
    });
  }
  const expectedComplete = Buffer.from(`${graphKey}\n`);
  if (
    normalized.complete.size !== expectedComplete.length ||
    normalized.complete.sha256 !== hashBytes(expectedComplete)
  ) {
    fail("module graph package material completion marker does not match its graph manifest");
  }
  return normalized;
}

export async function loadAuthenticatedConvexWasmModuleGraphPackageManifest({
  authenticatedPackageMaterial,
  cacheLayout: rawCacheLayout,
  cacheRoot,
  graphManifestSha256,
  immutableCacheValidationMemo,
}) {
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  if (cacheRoot !== cacheLayout.cacheRoot) {
    fail("module graph package cache root disagrees with its normalized immutable cache layout");
  }
  const expectedKey = requireSha256(graphManifestSha256, "module graph package manifest SHA-256");
  const packageMaterial = validateConvexWasmModuleGraphPackageMaterial(
    authenticatedPackageMaterial,
    expectedKey
  );
  if (packageMaterial.schemaVersion !== 2) {
    fail("module graph package manifest receipt requires complete artifact references");
  }
  const packagePath = join(cacheLayout.immutable.packages, expectedKey);
  await settleModuleGraphPackageFilesystemWork([
    requirePrivateCacheDirectory(cacheRoot, cacheLayout.immutable.root),
    requirePrivateCacheDirectory(cacheRoot, cacheLayout.immutable.packages),
  ]);
  try {
    await requirePrivateCacheDirectory(cacheRoot, packagePath);
  } catch (error) {
    // An immutable receipt can legitimately outlive a package removed by bounded cache
    // collection. Absence is a cache miss; a present but malformed package remains fatal.
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
  const manifestPath = join(packagePath, "graph-manifest.json");
  const bytes = await readPrivateRegularFile(
    manifestPath,
    MAX_MODULE_GRAPH_MANIFEST_BYTES,
    "module graph package receipt manifest"
  );
  if (
    bytes.length !== packageMaterial.graphManifest.size ||
    hashBytes(bytes) !== packageMaterial.graphManifest.sha256
  ) {
    fail(`module graph package material changed: ${manifestPath}`);
  }
  verifyRawCanonicalModuleGraphManifestIdentity(bytes, expectedKey);
  let value;
  try {
    value = JSON.parse(decodeUtf8(bytes, "module graph package receipt manifest"));
  } catch (error) {
    throw new Error(
      "Convex Wasm artifact pipeline: module graph package manifest is not valid JSON",
      {
        cause: error,
      }
    );
  }
  const stableCoreIdentitiesByRole = await loadModuleGraphStableCoreIdentityAuthorities({
    cacheLayout,
    cacheRoot,
    immutableCacheValidationMemo,
    manifest: value,
  });
  const graphManifest = normalizeModuleGraphManifest(value, stableCoreIdentitiesByRole);
  if (graphManifest.graphManifestSha256 !== expectedKey) {
    fail("module graph package manifest SHA-256 disagrees with its requested identity");
  }
  await requirePrivateCacheFile(cacheRoot, manifestPath);
  return { graphManifest, packageMaterial, packagePath };
}

function moduleGraphPackageMaterial({ complete, entry, manifest, provenance, artifactReferences }) {
  const hasArtifactReferences = artifactReferences !== undefined;
  return validateConvexWasmModuleGraphPackageMaterial(
    {
      ...(hasArtifactReferences ? { artifactReferences } : {}),
      complete: moduleGraphPackageFileMaterial(complete),
      graphManifest: moduleGraphPackageFileMaterial(manifest.bytes),
      kind: "convex-wasm-module-graph-package-material-v1",
      packageEntry: moduleGraphPackageFileMaterial(entry.bytes),
      provenance: moduleGraphPackageFileMaterial(provenance.bytes),
      schemaVersion: hasArtifactReferences ? 2 : 1,
    },
    manifest.value.graphManifestSha256
  );
}

async function readCanonicalModuleGraphPackageFile(path, maximumBytes, description) {
  const bytes = await readPrivateRegularFile(path, maximumBytes, description);
  const source = decodeUtf8(bytes, description);
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new Error(`Convex Wasm artifact pipeline: ${description} is not valid JSON`, {
      cause: error,
    });
  }
  if (`${canonicalJson(value)}\n` !== source) {
    fail(`${description} is not canonical JSON`);
  }
  return { bytes, value: freezeAuthenticatedJsonTree(value) };
}

async function loadModuleGraphCoreIdentityAuthorityUncached({
  artifact,
  cacheLayout,
  cacheRoot,
  role,
}) {
  const entryPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey);
  for (const directory of [
    cacheLayout.immutable.root,
    cacheLayout.immutable.artifacts,
    join(cacheLayout.immutable.artifacts, artifact.stage),
    entryPath,
  ]) {
    await requirePrivateCacheDirectory(cacheRoot, directory);
  }
  const names = (await fs.readdir(entryPath)).sort(compareStrings);
  if (!stringArrayEqual(names, ["COMPLETE", "artifact.wasm", "entry.json"])) {
    fail(`${role} module Core Wasm authority has unexpected files`);
  }
  // This path consumes only the immutable identity record. The package verifier authenticates the
  // referenced Wasm payload before publication, so opening it here would duplicate physical work
  // during receipt admission without granting any additional authority.
  await settleModuleGraphPackageFilesystemWork(
    ["COMPLETE", "entry.json"].map((name) =>
      requirePrivateCacheFile(cacheRoot, join(entryPath, name))
    )
  );
  const [complete, entry] = await settleModuleGraphPackageFilesystemWork([
    readPrivateRegularFile(
      join(entryPath, "COMPLETE"),
      MAX_COMPLETION_MARKER_BYTES,
      `${role} module Core Wasm authority completion marker`
    ),
    readCanonicalModuleGraphPackageFile(
      join(entryPath, "entry.json"),
      MAX_MODULE_GRAPH_PROVENANCE_BYTES,
      `${role} module Core Wasm authority`
    ),
  ]);
  if (!complete.equals(Buffer.from(`${artifact.cacheKey}\n`))) {
    fail(`${role} module Core Wasm authority completion marker is corrupt`);
  }
  const value = entry.value;
  requireExactPlainObject(
    value,
    [
      ...(Object.hasOwn(value, "admission") ? ["admission"] : []),
      "artifactFile",
      "artifactSha256",
      "artifactSize",
      "identity",
      "key",
      "kind",
      "metadata",
      "stage",
    ],
    `${role} module Core Wasm authority`
  );
  if (
    value.kind !== ARTIFACT_CACHE_ENTRY_KIND ||
    value.key !== artifact.cacheKey ||
    value.stage !== artifact.stage ||
    value.artifactFile !== "artifact.wasm" ||
    value.artifactSha256 !== artifact.sha256 ||
    value.artifactSize !== artifact.size ||
    fingerprintJson({ identity: value.identity, kind: PIPELINE_KIND, stage: value.stage }) !==
      artifact.cacheKey
  ) {
    fail(`${role} module Core Wasm authority does not authenticate its graph reference`);
  }
  requireExactPlainObject(
    value.metadata,
    ["contract"],
    `${role} module Core Wasm authority metadata`
  );
  if (!authenticatedJsonValuesEqual(value.metadata.contract, value.identity.contract)) {
    fail(`${role} module Core Wasm authority metadata disagrees with its identity`);
  }
  await requirePrivateCacheFile(cacheRoot, join(entryPath, "entry.json"));
  // The broad authenticated-JSON marker also covers caller-visible manifest subtrees. Mint memo
  // eligibility only after this exact Core identity has passed its private physical authority.
  authenticatedStableCoreIdentities.add(value.identity);
  return value.identity;
}

async function loadModuleGraphStableCoreIdentityAuthorities({
  cacheLayout,
  cacheRoot,
  immutableCacheValidationMemo,
  manifest,
}) {
  if (manifest?.kind !== convexWasmModuleGraphManifestKind || manifest?.schemaVersion !== 5) {
    return undefined;
  }
  if (!Array.isArray(manifest.moduleReferences)) {
    fail("module graph manifest moduleReferences must be an array");
  }
  const roles = normalizeModuleGraphRoleSequence(
    manifest.moduleReferences,
    "module graph manifest.moduleReferences"
  );
  let authorityMemo;
  if (immutableCacheValidationMemo !== undefined) {
    authorityMemo = stableCoreIdentityAuthorityMemos.get(immutableCacheValidationMemo);
    if (authorityMemo === undefined) {
      authorityMemo = new Map();
      stableCoreIdentityAuthorityMemos.set(immutableCacheValidationMemo, authorityMemo);
    }
  }
  const authorities = await settleModuleGraphPackageFilesystemWork(
    manifest.moduleReferences.slice(0, -1).map(async (reference, index) => {
      const role = roles[index];
      requireExactPlainObject(
        reference,
        ["artifacts", "authority", "role"],
        `module graph manifest.moduleReferences[${index}]`
      );
      requireExactPlainObject(
        reference.artifacts,
        ["aot", "coreWasm"],
        `module graph manifest.moduleReferences[${index}].artifacts`
      );
      requireExactPlainObject(
        reference.authority,
        ["kind"],
        `module graph manifest.moduleReferences[${index}].authority`
      );
      if (reference.authority.kind !== MODULE_GRAPH_CORE_IDENTITY_AUTHORITY_KIND) {
        fail(`module graph manifest ${role} authority kind is unsupported`);
      }
      const artifact = normalizeModuleGraphArtifactReference(
        reference.artifacts.coreWasm,
        role,
        "coreWasm"
      );
      const validationKey = [
        "module-graph-core-identity-authority",
        cacheRoot,
        artifact.stage,
        artifact.cacheKey,
      ].join("\0");
      let identity = authorityMemo?.get(validationKey);
      if (identity === undefined) {
        identity = loadModuleGraphCoreIdentityAuthorityUncached({
          artifact,
          cacheLayout,
          cacheRoot,
          role,
        });
        authorityMemo?.set(validationKey, identity);
        void identity.catch(() => {
          if (authorityMemo?.get(validationKey) === identity) {
            authorityMemo.delete(validationKey);
          }
        });
      }
      try {
        return [role, await identity];
      } catch (error) {
        if (error instanceof Error && "code" in error && error.code === "ENOENT") {
          fail(`${role} module package references a missing immutable artifact`);
        }
        throw error;
      }
    })
  );
  return new Map(authorities);
}

function moduleGraphPackageValidationKey({
  ancestorPhysicalState,
  authenticatedPackageMaterial,
  cacheLayout,
  cacheRoot,
  expectedGraphManifest,
  expectedProvenance,
  graphManifestSha256,
  packagePath,
  packagePhysicalState,
  referencedArtifactPhysicalState,
}) {
  const authenticatedExpectedGraphManifest =
    authenticatedModuleGraphManifests.has(expectedGraphManifest);
  const authenticatedExpectedProvenance =
    authenticatedModuleGraphProvenances.get(expectedProvenance);
  return fingerprintJson({
    ...(ancestorPhysicalState === undefined ? {} : { ancestorPhysicalState }),
    ...(authenticatedPackageMaterial === undefined ? {} : { authenticatedPackageMaterial }),
    cacheLayout,
    cacheRoot,
    ...(expectedGraphManifest === undefined
      ? {}
      : authenticatedExpectedGraphManifest
        ? {
            // The authenticated digest covers the exact immutable tree without rescanning its
            // multi-megabyte contents solely to build this in-process validation-memo key.
            authenticatedExpectedGraphManifestSha256: expectedGraphManifest.graphManifestSha256,
          }
        : { expectedGraphManifest }),
    ...(expectedProvenance === undefined
      ? {}
      : authenticatedExpectedProvenance === undefined
        ? { expectedProvenance }
        : { authenticatedExpectedProvenanceSha256: authenticatedExpectedProvenance.sha256 }),
    graphManifestSha256,
    kind: "convex-wasm-module-graph-package-validation-v1",
    packagePhysicalState,
    packagePath: resolve(packagePath),
    ...(referencedArtifactPhysicalState === undefined ? {} : { referencedArtifactPhysicalState }),
  });
}

function moduleGraphPackageAuthorityKey({
  cacheLayout,
  cacheRoot,
  graphManifestSha256,
  packagePath,
}) {
  return fingerprintJson({
    cacheLayout,
    cacheRoot,
    graphManifestSha256,
    kind: "convex-wasm-module-graph-package-validation-authority-v1",
    packagePath: resolve(packagePath),
  });
}

async function moduleGraphPackageReferencedArtifactPhysicalState({
  artifactPhysicalStateMemo,
  cacheLayout,
  cacheRoot,
  immutableCacheValidationMemo,
  packageMaterial,
  expectedGraphManifest,
}) {
  const isSafeArtifact = (artifact) =>
    artifact !== null &&
    typeof artifact === "object" &&
    typeof artifact.stage === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(artifact.stage) &&
    typeof artifact.cacheKey === "string" &&
    SHA256_PATTERN.test(artifact.cacheKey);
  let references;
  if (packageMaterial?.schemaVersion === 2 && Array.isArray(packageMaterial.artifactReferences)) {
    if (
      !packageMaterial.artifactReferences.every(
        (reference) =>
          reference?.aot?.artifact !== undefined &&
          reference?.coreWasm?.artifact !== undefined &&
          isSafeArtifact(reference.aot.artifact) &&
          isSafeArtifact(reference.coreWasm.artifact)
      )
    ) {
      return undefined;
    }
    references = packageMaterial.artifactReferences.flatMap((reference) =>
      [
        ["aot", reference.aot.artifact],
        ["coreWasm", reference.coreWasm.artifact],
      ].map(([kind, artifact]) => ({ artifact, kind, role: reference.role }))
    );
  } else if (
    expectedGraphManifest !== undefined &&
    authenticatedModuleGraphManifests.has(expectedGraphManifest) &&
    Array.isArray(expectedGraphManifest.modules)
  ) {
    references = expectedGraphManifest.modules.flatMap((module) =>
      ["aot", "coreWasm"].map((kind) => ({
        artifact: module.artifacts[kind],
        kind,
        role: module.role,
      }))
    );
  } else {
    references = undefined;
  }
  if (references === undefined) return undefined;
  const states = await settleModuleGraphPackageFilesystemWork(
    references
      .slice()
      .sort((left, right) =>
        compareStrings(`${left.role}\0${left.kind}`, `${right.role}\0${right.kind}`)
      )
      .map(async ({ artifact, kind, role }) => {
        const entryPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey);
        const readPhysicalState = async () =>
          await artifactCacheEntryPhysicalStateInValidationScope(
            immutableCacheValidationMemo,
            cacheRoot,
            entryPath
          );
        const physicalState = await (artifactPhysicalStateMemo === undefined
          ? readPhysicalState()
          : memoizePhysicalStateRead(
              artifactPhysicalStateMemo,
              `${resolve(cacheRoot)}\0${resolve(entryPath)}`,
              readPhysicalState
            ));
        return [role, kind, physicalState];
      })
  );
  if (states.some(([, , physicalState]) => physicalState === undefined)) return undefined;
  return JSON.stringify(states);
}

function moduleGraphPackageReferencedArtifactStateRetainsAuthenticatedBytes(before, after) {
  if (before === undefined || after === undefined) return false;
  const previousStates = JSON.parse(before);
  const currentStates = JSON.parse(after);
  return (
    previousStates.length === currentStates.length &&
    previousStates.every(([previousRole, previousKind, previousState], index) => {
      const [currentRole, currentKind, currentState] = currentStates[index];
      return (
        previousRole === currentRole &&
        previousKind === currentKind &&
        artifactCacheEntryPhysicalStateRetainsAuthenticatedBytes(previousState, currentState)
      );
    })
  );
}

function moduleGraphPackageValidationAuthority(verified) {
  if (
    !authenticatedModuleGraphManifests.has(verified.graphManifest) ||
    verified.packageMaterial?.schemaVersion !== 2
  ) {
    return undefined;
  }
  return Object.freeze({
    // Keep a private copy because the ordinary verification result remains caller-visible.
    authenticatedPackageMaterial: freezeAuthenticatedJsonTree(
      validateConvexWasmModuleGraphPackageMaterial(
        verified.packageMaterial,
        verified.graphManifest.graphManifestSha256
      )
    ),
    expectedGraphManifest: verified.graphManifest,
  });
}

async function loadAndVerifyConvexWasmModuleGraphPackageUncached(
  {
    cacheLayout: rawCacheLayout,
    cacheRoot,
    authenticatedPackageMaterial,
    expectedGraphManifest,
    expectedProvenance,
    graphManifestSha256,
    immutableCacheValidationMemo,
    maximumValidationAttempts = 4,
    packagePath,
  },
  payloadValidationMemo
) {
  requirePositiveInteger(
    maximumValidationAttempts,
    "module graph package referenced-artifact validation attempt limit"
  );
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  if (cacheRoot !== cacheLayout.cacheRoot) {
    fail("module graph package cache root disagrees with its normalized immutable cache layout");
  }
  const expectedKey = requireSha256(graphManifestSha256, "module graph package manifest SHA-256");
  const expectedMaterial =
    authenticatedPackageMaterial === undefined
      ? undefined
      : validateConvexWasmModuleGraphPackageMaterial(authenticatedPackageMaterial, expectedKey);
  const usePackageReceipt = expectedMaterial?.schemaVersion === 2;
  let suppliedGraphManifest;
  if (expectedGraphManifest !== undefined) {
    const stableCoreIdentitiesByRole = authenticatedModuleGraphManifests.has(expectedGraphManifest)
      ? undefined
      : await loadModuleGraphStableCoreIdentityAuthorities({
          cacheLayout,
          cacheRoot,
          immutableCacheValidationMemo,
          manifest: expectedGraphManifest,
        });
    suppliedGraphManifest = normalizeModuleGraphManifest(
      expectedGraphManifest,
      stableCoreIdentitiesByRole
    );
  }
  if (
    suppliedGraphManifest !== undefined &&
    suppliedGraphManifest.graphManifestSha256 !== expectedKey
  ) {
    fail("module graph package expected graph manifest disagrees with its requested identity");
  }
  if (expectedProvenance !== undefined && suppliedGraphManifest === undefined) {
    fail("module graph package expected provenance requires an expected graph manifest");
  }
  const suppliedProvenance =
    expectedProvenance === undefined
      ? undefined
      : normalizeModuleGraphProvenance(expectedProvenance, suppliedGraphManifest);
  const suppliedProvenanceAuthority = authenticatedModuleGraphProvenances.get(suppliedProvenance);
  if (expectedMaterial?.schemaVersion === 1 && suppliedGraphManifest === undefined) {
    fail("module graph package authenticated material has an invalid graph manifest binding");
  }
  const expectedPath = join(cacheLayout.immutable.packages, expectedKey);
  if (resolve(requireString(packagePath, "module graph package path")) !== expectedPath) {
    fail("module graph package path is outside its authenticated immutable cache location");
  }
  for (const directory of [
    cacheLayout.immutable.root,
    cacheLayout.immutable.packages,
    expectedPath,
  ]) {
    await requirePrivateCacheDirectory(cacheRoot, directory);
  }
  const packageDirectoryState = moduleGraphPackageDirectoryState(
    await fs.lstat(expectedPath, { bigint: true }),
    "module graph package"
  );
  const names = (await fs.readdir(expectedPath)).sort(compareStrings);
  if (!stringArrayEqual(names, [...MODULE_GRAPH_PACKAGE_FILES].sort(compareStrings))) {
    fail(`module graph package has unexpected files: ${expectedPath}`);
  }
  await settleModuleGraphPackageFilesystemWork(
    names.map((name) => requirePrivateCacheFile(cacheRoot, join(expectedPath, name)))
  );
  const readAuthenticatedPackageMaterial = async () => {
    const materialPaths = [
      ["COMPLETE", expectedMaterial.complete, MAX_COMPLETION_MARKER_BYTES],
      ["graph-manifest.json", expectedMaterial.graphManifest, MAX_MODULE_GRAPH_MANIFEST_BYTES],
      ["build-provenance.json", expectedMaterial.provenance, MAX_MODULE_GRAPH_PROVENANCE_BYTES],
      ["package-entry.json", expectedMaterial.packageEntry, MAX_MODULE_GRAPH_MANIFEST_BYTES],
    ];
    return Object.fromEntries(
      await settleModuleGraphPackageFilesystemWork(
        materialPaths.map(async ([name, expected, maximumBytes]) => {
          const path = join(expectedPath, name);
          const bytes = await readPrivateRegularFile(
            path,
            maximumBytes,
            `module graph package ${name}`
          );
          if (hashBytes(bytes) !== expected.sha256 || bytes.length !== expected.size) {
            fail(`module graph package material changed: ${path}`);
          }
          // The second private-cache check binds the authenticated read to the exact mode and
          // non-symlink path that remains visible after concurrent artifact verification.
          await requirePrivateCacheFile(cacheRoot, path);
          return [name, bytes];
        })
      )
    );
  };
  if (usePackageReceipt) {
    // A compact certificate does not retain the full graph, so authenticate the graph bytes and
    // prove that its artifact references are the exact complete module set before reading them.
    const first = await readAuthenticatedPackageMaterial();
    if (suppliedProvenanceAuthority !== undefined) {
      verifyRawCanonicalModuleGraphProvenanceIdentity(
        first["build-provenance.json"],
        suppliedProvenanceAuthority
      );
    }
    if (!first.COMPLETE.equals(Buffer.from(`${expectedKey}\n`))) {
      fail(`module graph package completion marker is corrupt: ${expectedPath}`);
    }
    verifyRawCanonicalModuleGraphManifestIdentity(first["graph-manifest.json"], expectedKey);
    // The raw canonical-identity check above proves that these authenticated physical bytes have
    // the same graph digest as the already normalized receipt manifest. Reuse that manifest when
    // present instead of parsing and deeply normalizing every unchanged graph again at final
    // publication. A caller without receipt authority still takes the full parse path.
    const parsedGraphManifest =
      suppliedGraphManifest === undefined
        ? JSON.parse(
            decodeUtf8(first["graph-manifest.json"], "module graph package authenticated manifest")
          )
        : undefined;
    const stableCoreIdentitiesByRole =
      parsedGraphManifest === undefined
        ? undefined
        : await loadModuleGraphStableCoreIdentityAuthorities({
            cacheLayout,
            cacheRoot,
            immutableCacheValidationMemo,
            manifest: parsedGraphManifest,
          });
    const authenticatedGraphManifest =
      suppliedGraphManifest ??
      normalizeModuleGraphManifest(parsedGraphManifest, stableCoreIdentitiesByRole);
    if (
      !moduleGraphPackageArtifactReferencesBindGraph(
        expectedMaterial.artifactReferences,
        authenticatedGraphManifest
      )
    ) {
      fail("module graph package material artifact references do not exactly cover its graph");
    }
    const expectedIdentities = expectedModuleGraphArtifactIdentities(authenticatedGraphManifest);
    const modulesByRole = new Map(
      authenticatedGraphManifest.modules.map((module) => [module.role, module])
    );
    const expectedAotMetadata = {
      engineCompatibilitySha256: authenticatedGraphManifest.engine.compatibilitySha256,
      engineConfig: authenticatedGraphManifest.engine.config,
      kind: ENGINE_IDENTITY_KIND,
      target: authenticatedGraphManifest.engine.target,
    };
    await settleModuleGraphPackageFilesystemWork(
      expectedMaterial.artifactReferences.map(async (reference) => {
        const { aot: expectedAot, coreWasm: expectedCoreWasm, role } = reference;
        const expectedIdentity = expectedIdentities[role];
        const module = modulesByRole.get(role);
        if (expectedIdentity === undefined || module === undefined) {
          fail(`${role} module package has no authenticated graph identity`);
        }
        const [coreWasm, aot] = await settleModuleGraphPackageFilesystemWork([
          immutableCacheValidationMemo === undefined
            ? validateArtifactCacheEntry(
                cacheRoot,
                cacheLayout,
                expectedCoreWasm.artifact.stage,
                expectedCoreWasm.artifact.cacheKey,
                "wasm",
                MAX_CORE_WASM_BYTES
              )
            : validateArtifactCacheEntryInValidationScope(
                immutableCacheValidationMemo,
                cacheRoot,
                cacheLayout,
                expectedCoreWasm.artifact.stage,
                expectedCoreWasm.artifact.cacheKey,
                "wasm",
                MAX_CORE_WASM_BYTES,
                maximumValidationAttempts,
                payloadValidationMemo
              ),
          immutableCacheValidationMemo === undefined
            ? validateArtifactCacheEntry(
                cacheRoot,
                cacheLayout,
                expectedAot.artifact.stage,
                expectedAot.artifact.cacheKey,
                "cwasm",
                MAX_SERIALIZED_MODULE_BYTES
              )
            : validateArtifactCacheEntryInValidationScope(
                immutableCacheValidationMemo,
                cacheRoot,
                cacheLayout,
                expectedAot.artifact.stage,
                expectedAot.artifact.cacheKey,
                "cwasm",
                MAX_SERIALIZED_MODULE_BYTES,
                maximumValidationAttempts,
                payloadValidationMemo
              ),
        ]);
        if (coreWasm === undefined || aot === undefined) {
          fail(`${role} module package references a missing immutable artifact`);
        }
        const coreWasmJson = requireAuthenticatedArtifactCacheEntryJsonDigests(coreWasm);
        const aotJson = requireAuthenticatedArtifactCacheEntryJsonDigests(aot);
        if (
          coreWasm.artifactSha256 !== expectedCoreWasm.artifact.sha256 ||
          coreWasm.artifactSize !== expectedCoreWasm.artifact.size ||
          coreWasmJson.identitySha256 !== expectedCoreWasm.identitySha256 ||
          coreWasmJson.metadataSha256 !== expectedCoreWasm.metadataSha256 ||
          !authenticatedJsonValuesEqual(coreWasm.identity, expectedIdentity.coreWasm) ||
          !authenticatedJsonValuesEqual(coreWasm.metadata, { contract: module.contract }) ||
          aot.artifactSha256 !== expectedAot.artifact.sha256 ||
          aot.artifactSize !== expectedAot.artifact.size ||
          aotJson.identitySha256 !== expectedAot.identitySha256 ||
          aotJson.metadataSha256 !== expectedAot.metadataSha256 ||
          !authenticatedJsonValuesEqual(aot.identity, expectedIdentity.aot) ||
          !authenticatedJsonValuesEqual(aot.metadata, expectedAotMetadata)
        ) {
          fail(`${role} module package artifact does not match its authenticated identity`);
        }
      })
    );
    const second = await readAuthenticatedPackageMaterial();
    const secondNames = (await fs.readdir(expectedPath)).sort(compareStrings);
    // The final names read must still be bound to the private package directory. Without this
    // check, an ancestor/package replacement immediately after the last member read could make
    // the same name set appear valid through a redirected path.
    await requirePrivateCacheDirectory(cacheRoot, expectedPath);
    if (!stringArrayEqual(secondNames, names)) {
      fail(
        `module graph package file universe changed while its artifacts were verified: ${expectedPath}`
      );
    }
    const finalPackageDirectoryState = moduleGraphPackageDirectoryState(
      await fs.lstat(expectedPath, { bigint: true }),
      "module graph package"
    );
    if (
      !moduleGraphPackageDirectoryStatesEqual(packageDirectoryState, finalPackageDirectoryState)
    ) {
      fail(
        `module graph package directory changed while its artifacts were verified: ${expectedPath}`
      );
    }
    for (const name of MODULE_GRAPH_PACKAGE_FILES) {
      if (!first[name].equals(second[name])) {
        fail(`module graph package changed while its artifacts were verified: ${expectedPath}`);
      }
    }
    return authenticateModuleGraphPackageVerification({
      graphManifest: authenticatedGraphManifest,
      package: { cacheKey: expectedKey, path: expectedPath },
      packageMaterial: expectedMaterial,
    });
  }
  const readPackageManifest = async () => {
    if (suppliedGraphManifest === undefined) {
      return await readCanonicalModuleGraphPackageFile(
        join(expectedPath, "graph-manifest.json"),
        MAX_MODULE_GRAPH_MANIFEST_BYTES,
        "module graph package manifest"
      );
    }
    const bytes = await readPrivateRegularFile(
      join(expectedPath, "graph-manifest.json"),
      MAX_MODULE_GRAPH_MANIFEST_BYTES,
      "module graph package manifest"
    );
    // The supplied manifest has already passed the complete graph validator. Authenticate the
    // physical canonical bytes against that exact digest instead of parsing and normalizing the
    // same multi-megabyte tree again during immediate post-build verification.
    verifyRawCanonicalModuleGraphManifestIdentity(bytes, expectedKey);
    return { bytes, value: suppliedGraphManifest };
  };
  const readPackageProvenance = async () => {
    if (suppliedProvenance === undefined) {
      return await readCanonicalModuleGraphPackageFile(
        join(expectedPath, "build-provenance.json"),
        MAX_MODULE_GRAPH_PROVENANCE_BYTES,
        "module graph package provenance"
      );
    }
    const bytes = await readPrivateRegularFile(
      join(expectedPath, "build-provenance.json"),
      MAX_MODULE_GRAPH_PROVENANCE_BYTES,
      "module graph package provenance"
    );
    verifyRawCanonicalModuleGraphProvenanceIdentity(bytes, suppliedProvenanceAuthority);
    return { bytes, value: suppliedProvenance };
  };
  const readPackage = async () => {
    const [complete, manifest, provenance, entry] = await settleModuleGraphPackageFilesystemWork([
      readPrivateRegularFile(
        join(expectedPath, "COMPLETE"),
        MAX_COMPLETION_MARKER_BYTES,
        "module graph package completion marker"
      ),
      readPackageManifest(),
      readPackageProvenance(),
      readCanonicalModuleGraphPackageFile(
        join(expectedPath, "package-entry.json"),
        MAX_MODULE_GRAPH_MANIFEST_BYTES,
        "module graph package entry"
      ),
    ]);
    if (decodeUtf8(complete, "module graph package completion marker") !== `${expectedKey}\n`) {
      fail(`module graph package completion marker is corrupt: ${expectedPath}`);
    }
    return { complete, entry, manifest, provenance };
  };
  const first = await readPackage();
  const stableCoreIdentitiesByRole =
    suppliedGraphManifest === undefined
      ? await loadModuleGraphStableCoreIdentityAuthorities({
          cacheLayout,
          cacheRoot,
          immutableCacheValidationMemo,
          manifest: first.manifest.value,
        })
      : undefined;
  const manifest =
    suppliedGraphManifest ??
    normalizeModuleGraphManifest(first.manifest.value, stableCoreIdentitiesByRole);
  if (manifest.graphManifestSha256 !== expectedKey) {
    fail("module graph package manifest SHA-256 disagrees with its requested identity");
  }
  const provenance =
    suppliedProvenance ?? normalizeModuleGraphProvenance(first.provenance.value, manifest);
  const packageEntry = normalizeModuleGraphPackageEntry(
    first.entry.value,
    first.manifest.bytes,
    first.provenance.bytes,
    manifest
  );
  const expectedIdentities = expectedModuleGraphArtifactIdentities(manifest);
  const artifactReferences = await settleModuleGraphPackageFilesystemWork(
    manifest.modules.map(async (module) => {
      const identities = provenance.identities[module.role];
      const expected = expectedIdentities[module.role];
      if (
        !authenticatedJsonValuesEqual(identities, expected) ||
        !moduleGraphArtifactPairEqual(packageEntry.artifacts[module.role], module.artifacts)
      ) {
        fail(`${module.role} module package provenance does not match its graph identity`);
      }
      const [coreWasm, aot] = await settleModuleGraphPackageFilesystemWork([
        immutableCacheValidationMemo === undefined
          ? validateArtifactCacheEntry(
              cacheRoot,
              cacheLayout,
              module.artifacts.coreWasm.stage,
              module.artifacts.coreWasm.cacheKey,
              "wasm",
              MAX_CORE_WASM_BYTES
            )
          : validateArtifactCacheEntryInValidationScope(
              immutableCacheValidationMemo,
              cacheRoot,
              cacheLayout,
              module.artifacts.coreWasm.stage,
              module.artifacts.coreWasm.cacheKey,
              "wasm",
              MAX_CORE_WASM_BYTES,
              maximumValidationAttempts,
              payloadValidationMemo
            ),
        immutableCacheValidationMemo === undefined
          ? validateArtifactCacheEntry(
              cacheRoot,
              cacheLayout,
              module.artifacts.aot.stage,
              module.artifacts.aot.cacheKey,
              "cwasm",
              MAX_SERIALIZED_MODULE_BYTES
            )
          : validateArtifactCacheEntryInValidationScope(
              immutableCacheValidationMemo,
              cacheRoot,
              cacheLayout,
              module.artifacts.aot.stage,
              module.artifacts.aot.cacheKey,
              "cwasm",
              MAX_SERIALIZED_MODULE_BYTES,
              maximumValidationAttempts,
              payloadValidationMemo
            ),
      ]);
      if (coreWasm === undefined || aot === undefined) {
        fail(`${module.role} module package references a missing immutable artifact`);
      }
      const coreWasmJson = requireAuthenticatedArtifactCacheEntryJsonDigests(coreWasm);
      const aotJson = requireAuthenticatedArtifactCacheEntryJsonDigests(aot);
      if (
        coreWasm.artifactSha256 !== module.artifacts.coreWasm.sha256 ||
        coreWasm.artifactSize !== module.artifacts.coreWasm.size ||
        !authenticatedJsonValuesEqual(coreWasm.identity, expected.coreWasm) ||
        !authenticatedJsonValuesEqual(coreWasm.metadata, { contract: module.contract }) ||
        aot.artifactSha256 !== module.artifacts.aot.sha256 ||
        aot.artifactSize !== module.artifacts.aot.size ||
        !authenticatedJsonValuesEqual(aot.identity, expected.aot)
      ) {
        fail(`${module.role} module package artifact does not match its authenticated identity`);
      }
      const aotEngineIdentity = normalizeEngineIdentity(
        aot.metadata,
        manifest.engine.config,
        manifest.engine.target
      );
      if (aotEngineIdentity.engineCompatibilitySha256 !== manifest.engine.compatibilitySha256) {
        fail(`${module.role} module AOT metadata has a different engine compatibility identity`);
      }
      return {
        aot: {
          artifact: module.artifacts.aot,
          identitySha256: aotJson.identitySha256,
          metadataSha256: aotJson.metadataSha256,
        },
        coreWasm: {
          artifact: module.artifacts.coreWasm,
          identitySha256: coreWasmJson.identitySha256,
          metadataSha256: coreWasmJson.metadataSha256,
        },
        role: module.role,
      };
    })
  );
  const second = await readPackage();
  const secondNames = (await fs.readdir(expectedPath)).sort(compareStrings);
  // Close the final package file-universe scan with a no-follow directory check. The member
  // reads each bind their own path, but a replacement after the last read must not escape the
  // authenticated immutable package location before this result is returned.
  await requirePrivateCacheDirectory(cacheRoot, expectedPath);
  if (!stringArrayEqual(secondNames, names)) {
    fail(
      `module graph package file universe changed while its artifacts were verified: ${expectedPath}`
    );
  }
  const finalPackageDirectoryState = moduleGraphPackageDirectoryState(
    await fs.lstat(expectedPath, { bigint: true }),
    "module graph package"
  );
  if (!moduleGraphPackageDirectoryStatesEqual(packageDirectoryState, finalPackageDirectoryState)) {
    fail(`module graph package directory changed while it was verified: ${expectedPath}`);
  }
  if (
    !first.complete.equals(second.complete) ||
    !first.manifest.bytes.equals(second.manifest.bytes) ||
    !first.provenance.bytes.equals(second.provenance.bytes) ||
    !first.entry.bytes.equals(second.entry.bytes)
  ) {
    fail(`module graph package changed while its artifacts were verified: ${expectedPath}`);
  }
  return authenticateModuleGraphPackageVerification({
    graphManifest: manifest,
    package: { cacheKey: expectedKey, path: expectedPath },
    packageEntry,
    packageMaterial: moduleGraphPackageMaterial({
      ...first,
      artifactReferences: artifactReferences.sort((left, right) =>
        compareStrings(left.role, right.role)
      ),
    }),
    provenance,
  });
}

export async function loadAndVerifyConvexWasmModuleGraphPackage(options) {
  return await loadAndVerifyConvexWasmModuleGraphPackageUncached(options);
}

const moduleGraphPackageValidationScopes = new WeakMap();
const moduleGraphPackagePayloadValidationScopes = new WeakMap();
const moduleGraphPackageAuthoritiesByValidationMemo = new WeakMap();

export function createConvexWasmModuleGraphPackageValidationScope() {
  // The token lets one builder callback and its independent caller verification share exactly one
  // authentication boundary without exposing memo contents that could be forged or retained.
  const scope = Object.freeze({});
  moduleGraphPackageValidationScopes.set(scope, {
    immutableCacheValidationMemo: new Map(),
    packageValidationMemo: new Map(),
  });
  return scope;
}

export function createConvexWasmModuleGraphPackagePayloadValidationScope() {
  // Only this module can resolve the token to the physical-identity keyed digest memo. Callers
  // may coordinate independent package verifiers without gaining authority over memo contents.
  const scope = Object.freeze({});
  moduleGraphPackagePayloadValidationScopes.set(scope, new Map());
  return scope;
}

function moduleGraphPackagePayloadValidationMemo(payloadValidationScope, description) {
  const payloadValidationMemo =
    moduleGraphPackagePayloadValidationScopes.get(payloadValidationScope);
  if (payloadValidationMemo === undefined) {
    fail(`${description} received an invalid payload validation scope`);
  }
  return payloadValidationMemo;
}

export async function validateConvexWasmModuleGraphArtifactInPayloadValidationScope(
  {
    cacheLayout,
    cacheRoot,
    expectedExtension,
    immutableCacheValidationMemo,
    key,
    maxArtifactBytes,
    maximumAttempts = 4,
    stage,
  },
  payloadValidationScope
) {
  // This performs the ordinary complete cache-entry validation. The private scope retains only
  // the payload digest keyed by the exact physical file state, so a following package verifier
  // still authenticates entry metadata and every surrounding state window independently.
  return await validateArtifactCacheEntryInValidationScope(
    immutableCacheValidationMemo,
    cacheRoot,
    normalizeConvexWasmCacheLayout(cacheLayout),
    stage,
    key,
    expectedExtension,
    maxArtifactBytes,
    maximumAttempts,
    moduleGraphPackagePayloadValidationMemo(
      payloadValidationScope,
      "module graph artifact validation"
    )
  );
}

export async function loadAndVerifyConvexWasmModuleGraphPackageCollection({
  cacheLayout,
  cacheRoot,
  immutableCacheValidationMemo,
  maximumAttempts = 4,
  packages,
  validationConcurrency = packages?.length,
  validationScope,
}) {
  requirePositiveInteger(
    maximumAttempts,
    "module graph package collection validation attempt limit"
  );
  if (!Array.isArray(packages) || packages.length === 0) {
    fail("module graph package collection verification requires at least one package");
  }
  requirePositiveInteger(validationConcurrency, "module graph package collection concurrency");
  const graphManifestKeys = new Set();
  const packagePaths = new Set();
  const normalizedPackages = packages.map((packageRecord, index) => {
    assertPlainObject(packageRecord, `module graph package collection entry ${index}`);
    const allowedKeys = new Set([
      "authenticatedPackageMaterial",
      "expectedGraphManifest",
      "expectedProvenance",
      "graphManifestSha256",
      "packagePath",
    ]);
    if (Object.keys(packageRecord).some((key) => !allowedKeys.has(key))) {
      fail(`module graph package collection entry ${index} has unsupported fields`);
    }
    const {
      authenticatedPackageMaterial,
      expectedGraphManifest,
      expectedProvenance,
      graphManifestSha256: rawGraphManifestSha256,
      packagePath: rawPackagePath,
    } = packageRecord;
    const graphManifestSha256 = requireSha256(
      rawGraphManifestSha256,
      `module graph package collection entry ${index} graph manifest SHA-256`
    );
    const packagePath = resolve(
      requireString(rawPackagePath, `module graph package collection entry ${index} path`)
    );
    if (graphManifestKeys.has(graphManifestSha256)) {
      fail(`module graph package collection repeats graph manifest ${graphManifestSha256}`);
    }
    if (packagePaths.has(packagePath)) {
      fail(`module graph package collection repeats package path ${packagePath}`);
    }
    graphManifestKeys.add(graphManifestSha256);
    packagePaths.add(packagePath);
    return Object.freeze({
      ...(authenticatedPackageMaterial === undefined ? {} : { authenticatedPackageMaterial }),
      ...(expectedGraphManifest === undefined ? {} : { expectedGraphManifest }),
      ...(expectedProvenance === undefined ? {} : { expectedProvenance }),
      graphManifestSha256,
      packagePath,
    });
  });
  if (validationScope !== undefined && immutableCacheValidationMemo !== undefined) {
    fail("module graph package collection must have one validation memo owner");
  }
  const validationRecord =
    validationScope === undefined
      ? {
          immutableCacheValidationMemo:
            immutableCacheValidationMemo === undefined ? new Map() : immutableCacheValidationMemo,
          packageValidationMemo: new Map(),
        }
      : moduleGraphPackageValidationScopes.get(validationScope);
  if (validationRecord === undefined) {
    fail("module graph package collection verification received an invalid validation scope");
  }
  // Payload digest reuse belongs only to this one maintained collection authentication. Package
  // publication and later collection calls must establish their own physical-state boundary.
  const payloadValidationScope = createConvexWasmModuleGraphPackagePayloadValidationScope();
  // Every package authentication owns physical reads and may update the shared validation scope.
  // Drain the complete collection before returning a failure so publication cannot advance while
  // a sibling still reads cache state. Failure selection also prevents a missing path from hiding an
  // independently observed non-missing filesystem failure.
  const verifiedPackages = new Array(normalizedPackages.length);
  const failures = new Array(normalizedPackages.length);
  let nextIndex = 0;
  let failed = false;
  await Promise.all(
    Array.from({ length: Math.min(validationConcurrency, normalizedPackages.length) }, async () => {
      while (!failed && nextIndex < normalizedPackages.length) {
        const index = nextIndex++;
        const packageRecord = normalizedPackages[index];
        try {
          verifiedPackages[index] =
            await loadAndVerifyConvexWasmModuleGraphPackageInValidationScope(
              {
                authenticatedPackageMaterial: packageRecord.authenticatedPackageMaterial,
                cacheLayout,
                cacheRoot,
                expectedGraphManifest: packageRecord.expectedGraphManifest,
                expectedProvenance: packageRecord.expectedProvenance,
                graphManifestSha256: packageRecord.graphManifestSha256,
                packagePath: packageRecord.packagePath,
              },
              validationRecord.packageValidationMemo,
              validationRecord.immutableCacheValidationMemo,
              maximumAttempts,
              payloadValidationScope
            );
        } catch (error) {
          // A worker may have advanced to a later package. Retain input-order precedence,
          // not worker-slot precedence, while the other admitted authentications drain.
          failures[index] = { reason: error };
          failed = true;
          return;
        }
      }
    })
  );
  const failure =
    failures.find(
      (result) => result !== undefined && !isMissingPhysicalStateError(result.reason)
    ) ?? failures.find((result) => result !== undefined);
  if (failure !== undefined) throw failure.reason;
  return verifiedPackages;
}

async function loadAndVerifyConvexWasmModuleGraphPackageInValidationScope(
  options,
  validationMemo,
  immutableCacheValidationMemo,
  maximumAttempts = 4,
  payloadValidationScope
) {
  requirePositiveInteger(maximumAttempts, "module graph package scoped validation attempt limit");
  const payloadValidationMemo =
    payloadValidationScope === undefined
      ? undefined
      : moduleGraphPackagePayloadValidationMemo(
          payloadValidationScope,
          "module graph package verification"
        );
  const cacheLayout = normalizeConvexWasmCacheLayout(options.cacheLayout);
  const authorityKey = moduleGraphPackageAuthorityKey({
    cacheLayout,
    cacheRoot: options.cacheRoot,
    graphManifestSha256: options.graphManifestSha256,
    packagePath: options.packagePath,
  });
  let packageAuthorityMemo = moduleGraphPackageAuthoritiesByValidationMemo.get(validationMemo);
  if (packageAuthorityMemo === undefined) {
    packageAuthorityMemo = new Map();
    moduleGraphPackageAuthoritiesByValidationMemo.set(validationMemo, packageAuthorityMemo);
  }
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const priorAuthority = packageAuthorityMemo.get(authorityKey);
    const verificationOptions =
      priorAuthority !== undefined &&
      options.authenticatedPackageMaterial === undefined &&
      options.expectedGraphManifest === undefined
        ? {
            ...options,
            authenticatedPackageMaterial: priorAuthority.authenticatedPackageMaterial,
            expectedGraphManifest: priorAuthority.expectedGraphManifest,
          }
        : options;
    const referencedArtifactAuthority =
      priorAuthority === undefined
        ? {
            authenticatedPackageMaterial: verificationOptions.authenticatedPackageMaterial,
            expectedGraphManifest: verificationOptions.expectedGraphManifest,
          }
        : priorAuthority;
    // A validation scope may serve sequential callers. Include both the package and every
    // referenced immutable entry in its memo key so neither kind of mutation can reuse a success.
    const ancestorManifest = referencedArtifactAuthority.expectedGraphManifest;
    // These three captures are independent sides of the same outer before fence. Start them
    // together and drain them as one group; the matching after group below still closes every
    // package, ancestor, and referenced-entry window before authority can return.
    const [ancestorPhysicalState, before, referencedArtifactPhysicalState] =
      await settleModuleGraphPackageFilesystemWork([
        ancestorManifest === undefined ||
        !authenticatedModuleGraphManifests.has(ancestorManifest) ||
        !Array.isArray(ancestorManifest.modules)
          ? Promise.resolve(undefined)
          : moduleGraphPackageAncestorPhysicalState(
              cacheLayout,
              options.cacheRoot,
              ancestorManifest,
              resolve(options.packagePath)
            ),
        moduleGraphPackagePhysicalState(options.cacheRoot, resolve(options.packagePath)),
        moduleGraphPackageReferencedArtifactPhysicalState({
          cacheLayout,
          cacheRoot: options.cacheRoot,
          immutableCacheValidationMemo,
          packageMaterial: referencedArtifactAuthority.authenticatedPackageMaterial,
          expectedGraphManifest: referencedArtifactAuthority.expectedGraphManifest,
        }),
      ]);
    if (before === undefined) continue;
    const validationKey = moduleGraphPackageValidationKey({
      ancestorPhysicalState,
      authenticatedPackageMaterial: options.authenticatedPackageMaterial,
      cacheLayout,
      cacheRoot: options.cacheRoot,
      expectedGraphManifest: options.expectedGraphManifest,
      expectedProvenance: options.expectedProvenance,
      graphManifestSha256: options.graphManifestSha256,
      packagePath: options.packagePath,
      packagePhysicalState: before,
      referencedArtifactPhysicalState,
    });
    const validate = async () => {
      // Different logical verifications keep different validation-memo keys. When an earlier one
      // authenticated this exact package in the same scope, its private receipt authority lets a
      // later unbound call avoid reparsing provenance. The uncached receipt path still performs
      // both physical package reads and every raw identity and artifact check.
      const verified = await loadAndVerifyConvexWasmModuleGraphPackageUncached(
        {
          ...verificationOptions,
          immutableCacheValidationMemo,
          maximumValidationAttempts: maximumAttempts,
        },
        payloadValidationMemo
      );
      if (!packageAuthorityMemo.has(authorityKey)) {
        const authority = moduleGraphPackageValidationAuthority(verified);
        if (authority !== undefined) packageAuthorityMemo.set(authorityKey, authority);
      }
      return verified;
    };
    // An unbound first call has no manifest or package receipt from which to enumerate referenced
    // artifacts. Do not memoize that result: otherwise a later artifact mutation could reuse the
    // package result without a physical state in the outer key.
    const validation =
      referencedArtifactPhysicalState === undefined
        ? Promise.resolve().then(validate)
        : memoizeImmutableCacheValidation(validationMemo, validationKey, validate);
    const verified = await validation;
    if (referencedArtifactPhysicalState === undefined) {
      // The first unbound call learns its complete artifact universe only from the authenticated
      // package result. Do not return that result without a reference-state window: an early
      // artifact could change after its individual hash while later artifacts were still being
      // checked. The next bounded attempt uses the newly retained private package authority to
      // capture every reference before verification and closes it with the matching scan below.
      if (packageAuthorityMemo.get(authorityKey) === undefined) {
        fail("module graph package verification could not bind its referenced artifact universe");
      }
      continue;
    }
    // These independent after captures close the matching package, reference, and ancestor
    // windows as one drained group. The resulting witness replaces the builder's former outer
    // scans, so a package-read hook that changes a referenced payload must still be observed
    // before this verifier mints reusable physical authority.
    const [after, referencedArtifactPhysicalStateAfter, ancestorPhysicalStateAfter] =
      await settleModuleGraphPackageFilesystemWork([
        moduleGraphPackagePhysicalState(options.cacheRoot, resolve(options.packagePath)),
        moduleGraphPackageReferencedArtifactPhysicalState({
          cacheLayout,
          cacheRoot: options.cacheRoot,
          immutableCacheValidationMemo,
          packageMaterial: referencedArtifactAuthority.authenticatedPackageMaterial,
          expectedGraphManifest: referencedArtifactAuthority.expectedGraphManifest,
        }),
        moduleGraphPackageAncestorPhysicalState(
          cacheLayout,
          options.cacheRoot,
          verified.graphManifest,
          resolve(options.packagePath)
        ),
      ]);
    if (
      before === after &&
      moduleGraphPackageReferencedArtifactStateRetainsAuthenticatedBytes(
        referencedArtifactPhysicalState,
        referencedArtifactPhysicalStateAfter
      ) &&
      ancestorPhysicalState !== undefined &&
      ancestorPhysicalState === ancestorPhysicalStateAfter
    ) {
      authenticateModuleGraphPackagePhysicalStateWitness(verified, {
        ancestorPhysicalState: ancestorPhysicalStateAfter,
        cacheLayout,
        cacheRoot: options.cacheRoot,
        packagePhysicalState: after,
        referencedArtifactPhysicalState: referencedArtifactPhysicalStateAfter,
      });
      return verified;
    }
    if (validationMemo.get(validationKey) === validation) {
      validationMemo.delete(validationKey);
    }
  }
  fail(`module graph package changed repeatedly during scoped validation: ${options.packagePath}`);
}

async function publishModuleGraphPackage({
  cacheLayout,
  cacheRoot,
  includeProducerReceiptPackage = false,
  immutableCacheValidationMemo,
  manifest,
  maximumValidationAttempts,
  modules,
  packageValidationMemo,
  payloadValidationScope,
  provenance,
}) {
  const manifestBytes = Buffer.from(`${canonicalJson(manifest)}\n`);
  const authenticatedProvenance = normalizeModuleGraphProvenance(provenance, manifest);
  const provenanceBytes = Buffer.from(`${canonicalJson(authenticatedProvenance)}\n`);
  if (manifestBytes.length > MAX_MODULE_GRAPH_MANIFEST_BYTES) {
    fail(`module graph manifest exceeded ${MAX_MODULE_GRAPH_MANIFEST_BYTES} bytes`);
  }
  if (provenanceBytes.length > MAX_MODULE_GRAPH_PROVENANCE_BYTES) {
    fail(`module graph provenance exceeded ${MAX_MODULE_GRAPH_PROVENANCE_BYTES} bytes`);
  }
  const packageKey = manifest.graphManifestSha256;
  const packagesRoot = cacheLayout.immutable.packages;
  const finalPath = join(packagesRoot, packageKey);
  const validateExisting = async () => {
    try {
      await requirePrivateCacheDirectory(cacheRoot, finalPath);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        return undefined;
      }
      throw error;
    }
    const existing = await loadAndVerifyConvexWasmModuleGraphPackageInValidationScope(
      {
        cacheLayout,
        cacheRoot,
        expectedGraphManifest: manifest,
        graphManifestSha256: packageKey,
        packagePath: finalPath,
      },
      packageValidationMemo,
      immutableCacheValidationMemo,
      maximumValidationAttempts,
      payloadValidationScope
    );
    if (canonicalJson(existing.graphManifest) !== canonicalJson(manifest)) {
      fail(`module graph package manifest does not match its identity: ${finalPath}`);
    }
    return { cache: "hit", cacheKey: packageKey, path: finalPath, verifiedPackage: existing };
  };
  const existing = await validateExisting();
  if (existing !== undefined) return existing;

  let packageEntryBytes;
  let packageMaterial;
  if (includeProducerReceiptPackage) {
    ({ packageEntryBytes, packageMaterial } = createModuleGraphPublishedPackageMaterial({
      cacheLayout,
      manifest,
      manifestBytes,
      modules,
      packageKey,
      provenanceBytes,
    }));
  } else {
    const packageEntry = moduleGraphPackageEntry(
      packageKey,
      manifestBytes,
      provenanceBytes,
      modules,
      manifest
    );
    packageEntryBytes = Buffer.from(`${canonicalJson(packageEntry)}\n`);
    normalizeModuleGraphPackageEntry(packageEntry, manifestBytes, provenanceBytes, manifest);
  }
  const expectedFiles = new Map([
    ["COMPLETE", Buffer.from(`${packageKey}\n`)],
    ["build-provenance.json", provenanceBytes],
    ["graph-manifest.json", manifestBytes],
    ["package-entry.json", packageEntryBytes],
  ]);

  await fs.mkdir(packagesRoot, { recursive: true, mode: 0o700 });
  await requirePrivateCacheDirectory(cacheRoot, packagesRoot);
  const publicationPath = join(
    packagesRoot,
    `.publish-${packageKey}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  await fs.mkdir(publicationPath, { mode: 0o700 });
  try {
    // Package directories are rebuildable cache entries. Close every temporary file before the
    // atomic rename, but do not force each file and directory to stable storage on the compiler
    // critical path. Receipt-only producer authority may cross the rename; physical or deployment
    // authority still requires complete final-directory authentication.
    await settleModuleGraphPackageFilesystemWork(
      [...expectedFiles].map(([name, contents]) =>
        fs.writeFile(join(publicationPath, name), contents, { flag: "wx", mode: 0o600 })
      )
    );
    await requirePrivateCacheDirectory(cacheRoot, publicationPath);
    await settleModuleGraphPackageFilesystemWork(
      [...MODULE_GRAPH_PACKAGE_FILES].map((name) =>
        requirePrivateCacheFile(cacheRoot, join(publicationPath, name))
      )
    );
    try {
      await fs.rename(publicationPath, finalPath);
      return {
        cache: "miss",
        cacheKey: packageKey,
        path: finalPath,
        ...(includeProducerReceiptPackage
          ? {
              receiptPackage: {
                graphManifest: manifest,
                package: { cacheKey: packageKey, path: finalPath },
                packageMaterial,
                provenance: authenticatedProvenance,
              },
            }
          : {}),
      };
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
      const concurrent = await validateExisting();
      if (concurrent === undefined) {
        fail(`concurrent module graph package publication disappeared: ${finalPath}`);
      }
      return concurrent;
    }
  } finally {
    await fs.rm(publicationPath, { recursive: true, force: true });
  }
}

export {
  authenticatedConvexWasmModuleGraphManifestSha256,
  createModuleGraphManifestFromBuiltModules,
  createModuleGraphLeafInvalidation,
  loadAndVerifyConvexWasmModuleGraphPackageInValidationScope,
  moduleGraphAotMaterialStage,
  moduleGraphAotSchedulingStage,
  moduleGraphAotStage,
  moduleGraphCoreMaterialStage,
  moduleGraphCoreStage,
  moduleGraphManifestSha256,
  moduleGraphTopologyFromBuildInputs,
  nativeStageIdentity,
  normalizeModuleGraphBuildResult,
  normalizeModuleGraphEngine,
  normalizeModuleGraphInitialization,
  normalizeModuleGraphManifest,
  normalizeModuleGraphProvenance,
  normalizeModuleGraphRouting,
  normalizeModuleGraphToolchain,
  publishModuleGraphPackage,
};

function moduleGraphPhysicalShardContentMaterial(unit) {
  return {
    generatedC: {
      sha256: requireSha256(
        unit.authenticated.generatedC.artifactSha256,
        "authenticated module graph generated C SHA-256"
      ),
      size: requirePositiveInteger(
        unit.authenticated.generatedC.artifactSize,
        "authenticated module graph generated C size"
      ),
    },
    reusableCodeIdentitySha256: requireSha256(
      unit.unit.reusableCodeIdentitySha256,
      "authenticated module graph reusable-code identity"
    ),
  };
}

function moduleGraphPhysicalShardContentIdentity(unit) {
  return fingerprintJson({
    domain: "convex-wasm-official-output-module-graph-application-content-v5",
    ...moduleGraphPhysicalShardContentMaterial(unit),
  });
}

function moduleGraphPhysicalShardStableCodeIdentity(unit, description) {
  return fingerprintJson({
    domain: "convex-wasm-official-output-module-graph-stable-code-identity-v1",
    entryPublication: unit.entryPublication,
    nativeSymbolIdentitySha256: requireSha256(
      unit.nativeSymbolIdentitySha256,
      `${description} native symbol identity`
    ),
  });
}

function moduleGraphPhysicalShardOccurrence(unit, cohort) {
  return {
    applicationUnitSlot: unit.applicationUnitSlot,
    cohortId: cohort.cohortId,
    cohortIndex: cohort.cohortIndex,
    picObject: {
      byteWeight: unit.authenticated.entry.artifactSize,
      sha256: unit.authenticated.entry.artifactSha256,
    },
    unitIdentitySha256: unit.unitIdentitySha256,
  };
}

function moduleGraphPhysicalShardCohortInput(units, description) {
  if (!Array.isArray(units) || units.length < 2) fail(`${description} has no unit matrix`);
  const planningInputs = units.map((matrixUnit, unitIndex) => {
    assertPlainObject(matrixUnit, `${description} unit ${unitIndex}`);
    assertPlainObject(matrixUnit.unit, `${description} descriptor unit ${unitIndex}`);
    assertPlainObject(matrixUnit.authenticated, `${description} PIC object ${unitIndex}`);
    assertPlainObject(
      matrixUnit.authenticated.entry,
      `${description} PIC cache entry ${unitIndex}`
    );
    const applicationUnitSlot = matrixUnit.applicationUnitSlot;
    if (!Number.isSafeInteger(applicationUnitSlot) || applicationUnitSlot < 0) {
      fail(`${description} unit ${unitIndex} has an invalid slot`);
    }
    if (!Array.isArray(matrixUnit.unit.dependencies)) {
      fail(`${description} unit ${unitIndex} has invalid dependencies`);
    }
    const contentMaterial = moduleGraphPhysicalShardContentMaterial(matrixUnit);
    return {
      applicationUnitSlot,
      contentIdentitySha256: fingerprintJson({
        domain: "convex-wasm-official-output-module-graph-application-content-v5",
        ...contentMaterial,
      }),
      contentMaterial,
      dependencies: matrixUnit.unit.dependencies.map(({ slot }, dependencyIndex) => {
        if (!Number.isSafeInteger(slot)) {
          fail(`${description} unit ${unitIndex} dependency ${dependencyIndex} has no slot`);
        }
        return slot;
      }),
      entryPublication: matrixUnit.unit.entryPublication,
      linkOrderMember: moduleGraphSharedLinkOrderMember(matrixUnit.unit),
      picObject: {
        byteWeight: requirePositiveInteger(
          matrixUnit.authenticated.entry.artifactSize,
          `${description} unit ${unitIndex} PIC object size`
        ),
        sha256: requireSha256(
          matrixUnit.authenticated.entry.artifactSha256,
          `${description} unit ${unitIndex} PIC object SHA-256`
        ),
      },
      unitIdentitySha256: requireSha256(
        matrixUnit.unitIdentitySha256,
        `${description} unit ${unitIndex} identity`
      ),
    };
  });
  return {
    identitySha256: fingerprintJson({
      domain: "convex-wasm-official-output-module-graph-cohort-planning-input-v1",
      units: planningInputs.map(
        ({
          applicationUnitSlot,
          contentIdentitySha256,
          dependencies,
          entryPublication,
          linkOrderMember,
          picObject,
          unitIdentitySha256,
        }) => ({
          applicationUnitSlot,
          contentIdentitySha256,
          dependencies,
          entryPublication,
          linkOrderMember,
          picObject,
          unitIdentitySha256,
        })
      ),
    }),
    planningInputs,
  };
}

function assertModuleGraphPhysicalShardRetainedPlanningInput(occurrence, description) {
  const planningInput = retainedModuleGraphPhysicalShardOccurrencePlanningInputs.get(occurrence);
  if (planningInput === undefined) return;
  const { record } = occurrence;
  assertPlainObject(record, `${description} retained unit`);
  assertPlainObject(record.unit, `${description} retained descriptor unit`);
  assertPlainObject(record.authenticated, `${description} retained PIC object`);
  assertPlainObject(record.authenticated.entry, `${description} retained PIC cache entry`);
  if (!Array.isArray(record.unit.dependencies)) {
    fail(`${description} planning input changed after contribution authentication`);
  }
  const currentContentMaterial = moduleGraphPhysicalShardContentMaterial(record);
  const currentDependencies = record.unit.dependencies.map(({ slot }, dependencyIndex) => {
    if (!Number.isSafeInteger(slot)) {
      fail(`${description} retained dependency ${dependencyIndex} has no slot`);
    }
    return slot;
  });
  if (
    record.applicationUnitSlot !== planningInput.applicationUnitSlot ||
    currentContentMaterial.generatedC.sha256 !== planningInput.contentMaterial.generatedC.sha256 ||
    currentContentMaterial.generatedC.size !== planningInput.contentMaterial.generatedC.size ||
    currentContentMaterial.reusableCodeIdentitySha256 !==
      planningInput.contentMaterial.reusableCodeIdentitySha256 ||
    !stringArrayEqual(currentDependencies, planningInput.dependencies) ||
    record.unit.entryPublication !== planningInput.entryPublication ||
    canonicalJson(moduleGraphSharedLinkOrderMember(record.unit)) !==
      canonicalJson(planningInput.linkOrderMember) ||
    record.authenticated.entry.artifactSize !== planningInput.picObject.byteWeight ||
    record.authenticated.entry.artifactSha256 !== planningInput.picObject.sha256 ||
    record.unitIdentitySha256 !== planningInput.unitIdentitySha256
  ) {
    fail(`${description} planning input changed after contribution authentication`);
  }
}

function freezeModuleGraphPhysicalShardCohortContribution(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) {
      freezeModuleGraphPhysicalShardCohortContribution(nested);
    }
    Object.freeze(value);
  }
  return value;
}

function deriveModuleGraphPhysicalShardPlanMonolithic(
  { authenticatedCohortUnitMatrix },
  { captureCohortContribution = false } = {}
) {
  if (!Array.isArray(authenticatedCohortUnitMatrix) || authenticatedCohortUnitMatrix.length === 0) {
    fail("module graph physical shard planning requires authenticated cohort units");
  }
  const cohortById = new Map();
  const recordsByCohortIndex = new Map();
  const records = [];
  for (const cohort of authenticatedCohortUnitMatrix) {
    assertPlainObject(cohort, "authenticated module graph cohort");
    const cohortId = requireSha256(cohort.cohortId, "authenticated module graph cohort ID");
    if (!Number.isSafeInteger(cohort.cohortIndex) || cohort.cohortIndex < 0) {
      fail("authenticated module graph cohort index is invalid");
    }
    if (cohortById.has(cohortId) || recordsByCohortIndex.has(cohort.cohortIndex)) {
      fail("authenticated module graph cohort matrix repeats a cohort identity");
    }
    if (!Array.isArray(cohort.units) || cohort.units.length < 2) {
      fail(`authenticated module graph cohort ${cohort.cohortIndex} has no unit matrix`);
    }
    cohortById.set(cohortId, cohort);
    const bySlot = new Map();
    recordsByCohortIndex.set(cohort.cohortIndex, bySlot);
    for (const matrixUnit of cohort.units) {
      assertPlainObject(matrixUnit, `authenticated module graph cohort ${cohort.cohortIndex} unit`);
      const applicationUnitSlot = matrixUnit.applicationUnitSlot;
      if (!Number.isSafeInteger(applicationUnitSlot) || applicationUnitSlot < 0) {
        fail(`authenticated module graph cohort ${cohort.cohortIndex} has an invalid unit slot`);
      }
      if (bySlot.has(applicationUnitSlot)) {
        fail(`authenticated module graph cohort ${cohort.cohortIndex} repeats unit slot`);
      }
      assertPlainObject(matrixUnit.unit, "authenticated module graph descriptor unit");
      assertPlainObject(matrixUnit.authenticated, "authenticated module graph PIC object");
      assertPlainObject(
        matrixUnit.authenticated.entry,
        "authenticated module graph PIC cache entry"
      );
      assertPlainObject(
        matrixUnit.authenticated.generatedC,
        "authenticated module graph generated C"
      );
      const record = {
        ...matrixUnit,
        cohort,
        contentIdentitySha256: moduleGraphPhysicalShardContentIdentity(matrixUnit),
      };
      bySlot.set(applicationUnitSlot, record);
      records.push(record);
    }
  }

  for (const record of records) {
    const { cohort, unit } = record;
    record.dependencyRecords = unit.dependencies.map((dependency, dependencyIndex) => {
      if (!Number.isSafeInteger(dependency.slot)) {
        fail(
          `authenticated module graph cohort ${cohort.cohortIndex} dependency ${dependencyIndex} has no slot`
        );
      }
      const dependencyRecord = recordsByCohortIndex.get(cohort.cohortIndex).get(dependency.slot);
      if (dependencyRecord === undefined || dependencyRecord.unit.entryPublication === true) {
        fail(
          `authenticated module graph cohort ${cohort.cohortIndex} dependency ${dependencyIndex} is not an application unit`
        );
      }
      return dependencyRecord;
    });
    record.dependencyCodeIdentities = [
      ...new Set(
        record.dependencyRecords.map((dependencyRecord) =>
          moduleGraphPhysicalShardStableCodeIdentity(
            dependencyRecord.unit,
            "authenticated module graph dependency"
          )
        )
      ),
    ].sort(compareStrings);
    record.picObject = {
      byteWeight: requirePositiveInteger(
        record.authenticated.entry.artifactSize,
        "authenticated module graph PIC object size"
      ),
      sha256: requireSha256(
        record.authenticated.entry.artifactSha256,
        "authenticated module graph PIC object SHA-256"
      ),
    };
    record.shareable = record.unit.entryPublication !== true;
    record.semanticCodeIdentitySha256 = fingerprintJson({
      domain: "convex-wasm-official-output-module-graph-logical-unit-v3",
      stableCodeIdentitySha256: moduleGraphPhysicalShardStableCodeIdentity(
        record.unit,
        "authenticated module graph unit"
      ),
    });
    record.intrinsicMaterialSha256 = fingerprintJson({
      contentIdentitySha256: record.contentIdentitySha256,
      domain: "convex-wasm-official-output-module-graph-intrinsic-material-v2",
      semanticCodeIdentitySha256: record.semanticCodeIdentitySha256,
      shareable: record.shareable,
    });
    record.codeIdentitySha256 = record.semanticCodeIdentitySha256;
  }

  const semanticMaterialByIntrinsicIdentity = new Map();
  for (const record of records) {
    const existing = semanticMaterialByIntrinsicIdentity.get(record.intrinsicMaterialSha256);
    if (existing === undefined) {
      semanticMaterialByIntrinsicIdentity.set(record.intrinsicMaterialSha256, {
        dependencyCodeIdentities: record.dependencyCodeIdentities,
        picObject: record.picObject,
        shareable: record.shareable,
      });
    } else if (
      existing.dependencyCodeIdentities.length !== record.dependencyCodeIdentities.length ||
      existing.dependencyCodeIdentities.some(
        (dependencyCodeIdentity, index) =>
          dependencyCodeIdentity !== record.dependencyCodeIdentities[index]
      ) ||
      existing.picObject.byteWeight !== record.picObject.byteWeight ||
      existing.picObject.sha256 !== record.picObject.sha256 ||
      existing.shareable !== record.shareable
    ) {
      fail(
        `module graph physical shard intrinsic material ${record.intrinsicMaterialSha256} drifted across cohorts`
      );
    }
  }

  let nextRecordIndex = 0;
  const recordIndexes = new Map();
  const recordLowLinks = new Map();
  const recordStack = [];
  const recordsOnStack = new Set();
  const closureComponents = [];
  function visitRecord(record) {
    recordIndexes.set(record, nextRecordIndex);
    recordLowLinks.set(record, nextRecordIndex);
    nextRecordIndex += 1;
    recordStack.push(record);
    recordsOnStack.add(record);
    for (const dependencyRecord of record.dependencyRecords) {
      if (!recordIndexes.has(dependencyRecord)) {
        visitRecord(dependencyRecord);
        recordLowLinks.set(
          record,
          Math.min(recordLowLinks.get(record), recordLowLinks.get(dependencyRecord))
        );
      } else if (recordsOnStack.has(dependencyRecord)) {
        recordLowLinks.set(
          record,
          Math.min(recordLowLinks.get(record), recordIndexes.get(dependencyRecord))
        );
      }
    }
    if (recordLowLinks.get(record) !== recordIndexes.get(record)) return;
    const componentRecords = [];
    while (true) {
      const member = recordStack.pop();
      recordsOnStack.delete(member);
      componentRecords.push(member);
      if (member === record) break;
    }
    closureComponents.push({ records: componentRecords });
  }
  for (const record of records) {
    if (!recordIndexes.has(record)) visitRecord(record);
  }

  const closureComponentByRecord = new Map();
  for (const component of closureComponents) {
    component.dependencies = new Set();
    component.dependents = new Set();
    component.cyclic =
      component.records.length > 1 ||
      component.records[0].dependencyRecords.includes(component.records[0]);
    component.ambiguousCycle =
      component.cyclic &&
      new Set(component.records.map((record) => record.semanticCodeIdentitySha256)).size !==
        component.records.length;
    for (const record of component.records) closureComponentByRecord.set(record, component);
  }
  for (const component of closureComponents) {
    for (const record of component.records) {
      for (const dependencyRecord of record.dependencyRecords) {
        const dependencyComponent = closureComponentByRecord.get(dependencyRecord);
        if (dependencyComponent === component) continue;
        component.dependencies.add(dependencyComponent);
        dependencyComponent.dependents.add(component);
      }
    }
  }

  // Duplicate semantic labels inside a cycle do not provide an intrinsic way to match nodes
  // across independently bucketed cohorts. Keep that SCC and its complete reverse-dependent cone
  // leaf-local. Their projected planner identities use semantic material only, and their exact
  // cohort-local dependency graph remains in the authenticated producer topology.
  const residualClosureComponents = new Set(
    closureComponents.filter((component) => component.ambiguousCycle)
  );
  const residualClosureQueue = [...residualClosureComponents];
  while (residualClosureQueue.length > 0) {
    const component = residualClosureQueue.shift();
    for (const dependent of component.dependents) {
      if (residualClosureComponents.has(dependent)) continue;
      residualClosureComponents.add(dependent);
      residualClosureQueue.push(dependent);
    }
  }

  const resolvedClosureComponents = new Set();
  function resolveClosureComponent(component) {
    if (resolvedClosureComponents.has(component)) return;
    if (residualClosureComponents.has(component)) {
      for (const dependency of component.dependencies) resolveClosureComponent(dependency);
      const memberPicObjects = component.records
        .map((record) => ({ ...record.picObject }))
        .sort((left, right) => {
          const shaOrder = compareStrings(left.sha256, right.sha256);
          return shaOrder === 0 ? left.byteWeight - right.byteWeight : shaOrder;
        });
      const picObjectByteWeight = memberPicObjects.reduce((total, picObject) => {
        if (picObject.byteWeight > Number.MAX_SAFE_INTEGER - total) {
          fail("module graph physical shard residual aggregate PIC object weight is too large");
        }
        return total + picObject.byteWeight;
      }, 0);
      const residualAggregateSha256 = fingerprintJson({
        domain: "convex-wasm-official-output-module-graph-residual-aggregate-v2",
        externalDependencies: [
          ...new Set(
            component.records.flatMap((record) =>
              record.dependencyRecords
                .filter(
                  (dependencyRecord) => closureComponentByRecord.get(dependencyRecord) !== component
                )
                .map((dependencyRecord) => dependencyRecord.codeIdentitySha256)
            )
          ),
        ].sort(compareStrings),
        members: component.records
          .map((record) => ({
            intrinsicMaterialSha256: record.intrinsicMaterialSha256,
            semanticCodeIdentitySha256: record.semanticCodeIdentitySha256,
          }))
          .sort((left, right) => {
            const semanticOrder = compareStrings(
              left.semanticCodeIdentitySha256,
              right.semanticCodeIdentitySha256
            );
            return semanticOrder === 0
              ? compareStrings(left.intrinsicMaterialSha256, right.intrinsicMaterialSha256)
              : semanticOrder;
          }),
      });
      component.aggregate = {
        bindingIdentitySha256: residualAggregateSha256,
        codeIdentitySha256: residualAggregateSha256,
        dependencies: [],
        intrinsicMaterialSha256: fingerprintJson({
          domain: "convex-wasm-official-output-module-graph-residual-aggregate-material-v2",
          memberPicObjects,
          residualAggregateSha256,
        }),
        occurrences: component.records.map((record) =>
          moduleGraphPhysicalShardOccurrence(record, record.cohort)
        ),
        occurrenceCohortIds: new Set(component.records.map((record) => record.cohort.cohortId)),
        picObject: {
          byteWeight: picObjectByteWeight,
          sha256: fingerprintJson({
            domain: "convex-wasm-official-output-module-graph-residual-aggregate-pic-v1",
            memberPicObjects,
          }),
        },
        shareable: false,
      };
      for (const record of component.records) {
        record.codeIdentitySha256 = residualAggregateSha256;
      }
      resolvedClosureComponents.add(component);
      return;
    }
    for (const dependency of component.dependencies) resolveClosureComponent(dependency);
    if (!component.cyclic) {
      const record = component.records[0];
      record.plannerDependencies = [
        ...new Set(
          record.dependencyRecords.map((dependencyRecord) => dependencyRecord.codeIdentitySha256)
        ),
      ].sort(compareStrings);
      // Stable native symbols identify dependency bindings. The physical planner still labels
      // each resolved node with its exact generated-C/PIC material and resolved dependency
      // variants, so two cohorts cannot collapse different bytes behind the same binding.
      record.codeIdentitySha256 = fingerprintJson({
        dependencies: record.plannerDependencies,
        domain: "convex-wasm-official-output-module-graph-dag-closure-v2",
        intrinsicMaterialSha256: record.intrinsicMaterialSha256,
        semanticCodeIdentitySha256: record.semanticCodeIdentitySha256,
      });
      record.plannerShareable = record.shareable;
      resolvedClosureComponents.add(component);
      return;
    }

    const componentRecordBySemanticIdentity = new Map(
      component.records.map((record) => [record.semanticCodeIdentitySha256, record])
    );
    const cyclicClosureSha256 = fingerprintJson({
      domain: "convex-wasm-official-output-module-graph-cyclic-closure-v2",
      units: [...componentRecordBySemanticIdentity]
        .sort(([left], [right]) => compareStrings(left, right))
        .map(([semanticCodeIdentitySha256, record]) => ({
          externalDependencies: [
            ...new Set(
              record.dependencyRecords
                .filter(
                  (dependencyRecord) => closureComponentByRecord.get(dependencyRecord) !== component
                )
                .map((dependencyRecord) => dependencyRecord.codeIdentitySha256)
            ),
          ].sort(compareStrings),
          internalDependencies: [
            ...new Set(
              record.dependencyRecords
                .filter(
                  (dependencyRecord) => closureComponentByRecord.get(dependencyRecord) === component
                )
                .map((dependencyRecord) => dependencyRecord.semanticCodeIdentitySha256)
            ),
          ].sort(compareStrings),
          intrinsicMaterialSha256: record.intrinsicMaterialSha256,
          semanticCodeIdentitySha256,
        })),
    });
    for (const record of component.records) {
      record.codeIdentitySha256 = fingerprintJson({
        cyclicClosureSha256,
        domain: "convex-wasm-official-output-module-graph-cyclic-logical-unit-v2",
        intrinsicMaterialSha256: record.intrinsicMaterialSha256,
        semanticCodeIdentitySha256: record.semanticCodeIdentitySha256,
      });
      record.plannerShareable = record.shareable;
    }
    for (const record of component.records) {
      record.plannerDependencies = [
        ...new Set(
          record.dependencyRecords.map((dependencyRecord) => dependencyRecord.codeIdentitySha256)
        ),
      ].sort(compareStrings);
    }
    resolvedClosureComponents.add(component);
  }
  for (const component of closureComponents) resolveClosureComponent(component);

  const logicalUnitsByCodeIdentity = new Map();
  for (const component of residualClosureComponents) {
    const existing = logicalUnitsByCodeIdentity.get(component.aggregate.codeIdentitySha256);
    if (existing === undefined) {
      logicalUnitsByCodeIdentity.set(component.aggregate.codeIdentitySha256, component.aggregate);
    } else if (
      existing.dependencies.length !== component.aggregate.dependencies.length ||
      existing.dependencies.some(
        (dependency, index) => dependency !== component.aggregate.dependencies[index]
      ) ||
      existing.picObject.byteWeight !== component.aggregate.picObject.byteWeight ||
      existing.picObject.sha256 !== component.aggregate.picObject.sha256 ||
      existing.shareable !== component.aggregate.shareable
    ) {
      fail(
        `module graph physical shard residual aggregate ${component.aggregate.codeIdentitySha256} is inconsistent`
      );
    } else {
      if (existing.intrinsicMaterialSha256 !== component.aggregate.intrinsicMaterialSha256) {
        fail(
          `module graph physical shard residual aggregate ${component.aggregate.codeIdentitySha256} drifted across cohorts`
        );
      }
      for (const cohortId of component.aggregate.occurrenceCohortIds) {
        existing.occurrenceCohortIds.add(cohortId);
      }
      existing.occurrences.push(...component.aggregate.occurrences);
    }
  }
  for (const record of records) {
    if (residualClosureComponents.has(closureComponentByRecord.get(record))) continue;
    const existing = logicalUnitsByCodeIdentity.get(record.codeIdentitySha256);
    if (existing === undefined) {
      logicalUnitsByCodeIdentity.set(record.codeIdentitySha256, {
        bindingIdentitySha256: record.semanticCodeIdentitySha256,
        codeIdentitySha256: record.codeIdentitySha256,
        dependencies: record.plannerDependencies,
        occurrences: [],
        occurrenceCohortIds: new Set(),
        intrinsicMaterialSha256: record.intrinsicMaterialSha256,
        picObject: record.picObject,
        semanticCodeIdentitySha256: record.semanticCodeIdentitySha256,
        shareable: record.plannerShareable,
      });
    } else if (
      existing.bindingIdentitySha256 !== record.semanticCodeIdentitySha256 ||
      existing.intrinsicMaterialSha256 !== record.intrinsicMaterialSha256 ||
      existing.semanticCodeIdentitySha256 !== record.semanticCodeIdentitySha256 ||
      existing.dependencies.length !== record.plannerDependencies.length ||
      existing.dependencies.some(
        (dependency, index) => dependency !== record.plannerDependencies[index]
      ) ||
      existing.picObject.byteWeight !== record.picObject.byteWeight ||
      existing.picObject.sha256 !== record.picObject.sha256 ||
      existing.shareable !== record.plannerShareable
    ) {
      fail(
        `module graph physical shard closure logical unit ${record.codeIdentitySha256} is inconsistent`
      );
    }
    const logicalUnit = logicalUnitsByCodeIdentity.get(record.codeIdentitySha256);
    logicalUnit.occurrenceCohortIds.add(record.cohort.cohortId);
    logicalUnit.occurrences.push(moduleGraphPhysicalShardOccurrence(record, record.cohort));
  }

  if (captureCohortContribution) {
    if (authenticatedCohortUnitMatrix.length !== 1) {
      fail("module graph cohort planning contribution must contain exactly one cohort");
    }
    const contribution = freezeModuleGraphPhysicalShardCohortContribution({
      inputIdentitySha256: moduleGraphPhysicalShardCohortInput(
        authenticatedCohortUnitMatrix[0].units,
        "authenticated module graph planning cohort"
      ).identitySha256,
      kind: "convex-wasm-official-output-module-graph-cohort-planning-contribution-v2",
      logicalUnits: [...logicalUnitsByCodeIdentity.values()].map((logicalUnit) => ({
        bindingIdentitySha256: logicalUnit.bindingIdentitySha256,
        codeIdentitySha256: logicalUnit.codeIdentitySha256,
        dependencies: logicalUnit.dependencies,
        intrinsicMaterialSha256: logicalUnit.intrinsicMaterialSha256,
        occurrenceSlots: logicalUnit.occurrences.map(
          ({ applicationUnitSlot }) => applicationUnitSlot
        ),
        picObject: logicalUnit.picObject,
        residual: logicalUnit.semanticCodeIdentitySha256 === undefined,
        ...(logicalUnit.semanticCodeIdentitySha256 === undefined
          ? {}
          : { semanticCodeIdentitySha256: logicalUnit.semanticCodeIdentitySha256 }),
        shareable: logicalUnit.shareable,
      })),
      semanticMaterials: records.map(
        ({ dependencyCodeIdentities, intrinsicMaterialSha256, picObject, shareable }) => ({
          dependencyCodeIdentities,
          intrinsicMaterialSha256,
          picObject,
          shareable,
        })
      ),
    });
    authenticatedModuleGraphPhysicalShardCohortContributions.add(contribution);
    return contribution;
  }

  const plannerLogicalUnits = [...logicalUnitsByCodeIdentity.values()]
    .map((logicalUnit) =>
      authenticateConvexWasmPhysicalShardLogicalUnit({
        bindingIdentitySha256: logicalUnit.bindingIdentitySha256,
        codeIdentitySha256: logicalUnit.codeIdentitySha256,
        dependencies: logicalUnit.dependencies,
        kind: convexWasmPhysicalShardLogicalUnitKind,
        occurrences: [...logicalUnit.occurrenceCohortIds].sort(compareStrings),
        picObject: logicalUnit.picObject,
        shareable: logicalUnit.shareable,
      })
    )
    .sort((left, right) => compareStrings(left.codeIdentitySha256, right.codeIdentitySha256));
  // Use a bounded PIC-byte target so shared code does not accumulate into one large module.
  // Oversize SCCs remain singleton shards regardless of the target.
  const plan = planConvexWasmPhysicalShards({
    kind: convexWasmPhysicalShardPlanningRequestKind,
    logicalUnits: plannerLogicalUnits,
    policy: {
      kind: convexWasmPhysicalShardPolicyKind,
      targetShardWeight: MODULE_GRAPH_PHYSICAL_SHARD_TARGET_PIC_OBJECT_BYTES,
    },
  });
  const logicalUnitByCodeIdentity = new Map(
    [...logicalUnitsByCodeIdentity.values()].map((logicalUnit) => [
      logicalUnit.codeIdentitySha256,
      logicalUnit,
    ])
  );
  const componentOccurrences = plan.components.map((component) => ({
    componentSha256: component.componentSha256,
    occurrences: component.codeIdentitySha256s
      .flatMap((codeIdentitySha256) =>
        logicalUnitByCodeIdentity
          .get(codeIdentitySha256)
          .occurrences.map((occurrence) => ({ ...occurrence, codeIdentitySha256 }))
      )
      .sort((left, right) => {
        const cohortOrder = compareStrings(left.cohortId, right.cohortId);
        return cohortOrder === 0
          ? left.applicationUnitSlot - right.applicationUnitSlot
          : cohortOrder;
      }),
  }));
  return {
    componentOccurrences,
    kind: "convex-wasm-official-output-module-graph-physical-shard-planning-v2",
    plan,
    residualComponents: plan.residualComponents,
    sharedShards: plan.sharedShards,
    shardOrder: plan.shardOrder,
  };
}

export function deriveConvexWasmOfficialOutputModuleGraphPhysicalShardCohortContribution({
  authenticatedCohortUnits,
}) {
  return deriveModuleGraphPhysicalShardPlanMonolithic(
    {
      authenticatedCohortUnitMatrix: [
        {
          cohortId: "0".repeat(64),
          cohortIndex: 0,
          units: authenticatedCohortUnits,
        },
      ],
    },
    { captureCohortContribution: true }
  );
}

function deriveModuleGraphPhysicalShardPlanFromCohortContributions({
  authenticatedCohortUnitMatrix,
  cohortPlanningContributions,
}) {
  if (!Array.isArray(authenticatedCohortUnitMatrix) || authenticatedCohortUnitMatrix.length === 0) {
    fail("module graph physical shard planning requires authenticated cohort units");
  }
  if (
    !Array.isArray(cohortPlanningContributions) ||
    cohortPlanningContributions.length !== authenticatedCohortUnitMatrix.length
  ) {
    fail("module graph physical shard planning contributions must cover every cohort once");
  }
  const cohortIds = new Set();
  const cohortIndexes = new Set();
  const semanticMaterialByIntrinsicIdentity = new Map();
  const logicalUnitsByCodeIdentity = new Map();
  const matrixByCohortIndex = new Map();
  // Retain the indexed samples authenticated below. Iterating this caller-owned array afterward
  // would give an unrelated custom iterator a callback inside the private authority boundary.
  const contributionReferences = [];
  const retainedCohorts = [];
  const recordByPlanningOccurrence = new WeakMap();
  for (const [matrixIndex, cohort] of authenticatedCohortUnitMatrix.entries()) {
    assertPlainObject(cohort, "authenticated module graph cohort");
    const cohortId = requireSha256(cohort.cohortId, "authenticated module graph cohort ID");
    const cohortIndex = cohort.cohortIndex;
    if (!Number.isSafeInteger(cohortIndex) || cohortIndex < 0) {
      fail("authenticated module graph cohort index is invalid");
    }
    if (cohortIds.has(cohortId) || cohortIndexes.has(cohortIndex)) {
      fail("authenticated module graph cohort matrix repeats a cohort identity");
    }
    cohortIds.add(cohortId);
    cohortIndexes.add(cohortIndex);
    const cohortUnits = cohort.units;
    const contribution = cohortPlanningContributions[matrixIndex];
    contributionReferences.push(contribution);
    const cohortPlanningInput = moduleGraphPhysicalShardCohortInput(
      cohortUnits,
      `authenticated module graph cohort ${cohortIndex}`
    );
    if (
      !authenticatedModuleGraphPhysicalShardCohortContributions.has(contribution) ||
      contribution.kind !==
        "convex-wasm-official-output-module-graph-cohort-planning-contribution-v2" ||
      contribution.inputIdentitySha256 !== cohortPlanningInput.identitySha256
    ) {
      fail(`authenticated module graph cohort ${cohortIndex} has stale planning authority`);
    }
    const recordsBySlot = new Map(
      cohortUnits.map((matrixUnit) => [matrixUnit.applicationUnitSlot, matrixUnit])
    );
    const planningInputBySlot = new Map(
      cohortPlanningInput.planningInputs.map((planningInput) => [
        planningInput.applicationUnitSlot,
        freezeModuleGraphPhysicalShardCohortContribution(planningInput),
      ])
    );
    // Capture the producer once. Besides avoiding one read per occurrence, this makes an accessor's
    // matrix mutation visible to the retained-reference check and the complete generic fallback.
    const compilerOutput = cohort.output;
    const retainedCohort = {
      cohort,
      cohortId,
      cohortIndex,
      compilerOutput,
      planningInputBySlot,
      recordsBySlot,
      unitReferences: [...cohortUnits],
      units: cohortUnits,
    };
    retainedCohorts.push(retainedCohort);
    matrixByCohortIndex.set(cohortIndex, retainedCohort);
    for (const material of contribution.semanticMaterials) {
      const existing = semanticMaterialByIntrinsicIdentity.get(material.intrinsicMaterialSha256);
      if (existing === undefined) {
        semanticMaterialByIntrinsicIdentity.set(material.intrinsicMaterialSha256, material);
      } else if (
        existing.dependencyCodeIdentities.length !== material.dependencyCodeIdentities.length ||
        existing.dependencyCodeIdentities.some(
          (dependencyCodeIdentity, index) =>
            dependencyCodeIdentity !== material.dependencyCodeIdentities[index]
        ) ||
        existing.picObject.byteWeight !== material.picObject.byteWeight ||
        existing.picObject.sha256 !== material.picObject.sha256 ||
        existing.shareable !== material.shareable
      ) {
        fail(
          `module graph physical shard intrinsic material ${material.intrinsicMaterialSha256} drifted across cohorts`
        );
      }
    }
    for (const localLogicalUnit of contribution.logicalUnits) {
      const occurrences = localLogicalUnit.occurrenceSlots.map((applicationUnitSlot) => {
        const record = recordsBySlot.get(applicationUnitSlot);
        if (record === undefined) {
          fail("module graph physical shard cohort contribution references an unknown unit slot");
        }
        const occurrence = moduleGraphPhysicalShardOccurrence(record, retainedCohort);
        recordByPlanningOccurrence.set(occurrence, record);
        return occurrence;
      });
      const existing = logicalUnitsByCodeIdentity.get(localLogicalUnit.codeIdentitySha256);
      if (existing === undefined) {
        logicalUnitsByCodeIdentity.set(localLogicalUnit.codeIdentitySha256, {
          ...localLogicalUnit,
          occurrenceCohortIds: new Set([cohortId]),
          occurrences,
        });
        continue;
      }
      const inconsistent = localLogicalUnit.residual
        ? !existing.residual ||
          existing.bindingIdentitySha256 !== localLogicalUnit.bindingIdentitySha256 ||
          existing.dependencies.length !== localLogicalUnit.dependencies.length ||
          existing.dependencies.some(
            (dependency, index) => dependency !== localLogicalUnit.dependencies[index]
          ) ||
          existing.picObject.byteWeight !== localLogicalUnit.picObject.byteWeight ||
          existing.picObject.sha256 !== localLogicalUnit.picObject.sha256 ||
          existing.shareable !== localLogicalUnit.shareable
        : existing.residual ||
          existing.bindingIdentitySha256 !== localLogicalUnit.bindingIdentitySha256 ||
          existing.intrinsicMaterialSha256 !== localLogicalUnit.intrinsicMaterialSha256 ||
          existing.semanticCodeIdentitySha256 !== localLogicalUnit.semanticCodeIdentitySha256 ||
          existing.dependencies.length !== localLogicalUnit.dependencies.length ||
          existing.dependencies.some(
            (dependency, index) => dependency !== localLogicalUnit.dependencies[index]
          ) ||
          existing.picObject.byteWeight !== localLogicalUnit.picObject.byteWeight ||
          existing.picObject.sha256 !== localLogicalUnit.picObject.sha256 ||
          existing.shareable !== localLogicalUnit.shareable;
      if (inconsistent) {
        fail(
          `module graph physical shard ${localLogicalUnit.residual ? "residual aggregate" : "closure logical unit"} ${localLogicalUnit.codeIdentitySha256} is inconsistent`
        );
      }
      if (
        localLogicalUnit.residual &&
        existing.intrinsicMaterialSha256 !== localLogicalUnit.intrinsicMaterialSha256
      ) {
        fail(
          `module graph physical shard residual aggregate ${localLogicalUnit.codeIdentitySha256} drifted across cohorts`
        );
      }
      existing.occurrenceCohortIds.add(cohortId);
      existing.occurrences.push(...occurrences);
    }
  }

  const plannerLogicalUnits = [...logicalUnitsByCodeIdentity.values()]
    .map((logicalUnit) =>
      authenticateConvexWasmPhysicalShardLogicalUnit({
        bindingIdentitySha256: logicalUnit.bindingIdentitySha256,
        codeIdentitySha256: logicalUnit.codeIdentitySha256,
        dependencies: logicalUnit.dependencies,
        kind: convexWasmPhysicalShardLogicalUnitKind,
        occurrences: [...logicalUnit.occurrenceCohortIds].sort(compareStrings),
        picObject: logicalUnit.picObject,
        shareable: logicalUnit.shareable,
      })
    )
    .sort((left, right) => compareStrings(left.codeIdentitySha256, right.codeIdentitySha256));
  const plan = planConvexWasmPhysicalShards({
    kind: convexWasmPhysicalShardPlanningRequestKind,
    logicalUnits: plannerLogicalUnits,
    policy: {
      kind: convexWasmPhysicalShardPolicyKind,
      targetShardWeight: MODULE_GRAPH_PHYSICAL_SHARD_TARGET_PIC_OBJECT_BYTES,
    },
  });
  const componentOccurrenceDescriptionBySha256 = new Map();
  const occurrencesByComponentSha256 = new Map();
  const componentOccurrences = plan.components.map((component, componentIndex) => {
    const occurrencePairs = component.codeIdentitySha256s
      .flatMap((codeIdentitySha256) =>
        logicalUnitsByCodeIdentity.get(codeIdentitySha256).occurrences.map((occurrence) => {
          const record = recordByPlanningOccurrence.get(occurrence);
          const matrix = matrixByCohortIndex.get(occurrence.cohortIndex);
          if (record === undefined || matrix === undefined) {
            fail("module graph physical shard retained occurrence lost its authenticated unit");
          }
          const planningInput = matrix.planningInputBySlot.get(occurrence.applicationUnitSlot);
          if (planningInput === undefined) {
            fail("module graph physical shard retained occurrence lost its planning input");
          }
          const retainedOccurrence = {
            applicationUnitSlot: occurrence.applicationUnitSlot,
            codeIdentitySha256,
            cohortId: matrix.cohortId,
            cohortIndex: occurrence.cohortIndex,
            compilerOutput: matrix.compilerOutput,
            record,
          };
          retainedModuleGraphPhysicalShardOccurrencePlanningInputs.set(
            retainedOccurrence,
            planningInput
          );
          Object.freeze(retainedOccurrence);
          return {
            occurrence: { ...occurrence, codeIdentitySha256 },
            retainedOccurrence,
          };
        })
      )
      .sort((left, right) => {
        const cohortOrder = compareStrings(left.occurrence.cohortId, right.occurrence.cohortId);
        return cohortOrder === 0
          ? left.occurrence.applicationUnitSlot - right.occurrence.applicationUnitSlot
          : cohortOrder;
      });
    componentOccurrenceDescriptionBySha256.set(
      component.componentSha256,
      `module graph physical shard producer component occurrence ${componentIndex}`
    );
    occurrencesByComponentSha256.set(
      component.componentSha256,
      Object.freeze(occurrencePairs.map(({ retainedOccurrence }) => retainedOccurrence))
    );
    return {
      componentSha256: component.componentSha256,
      occurrences: occurrencePairs.map(({ occurrence }) => occurrence),
    };
  });
  const physicalShardPlanning = {
    componentOccurrences,
    kind: "convex-wasm-official-output-module-graph-physical-shard-planning-v2",
    plan,
    residualComponents: plan.residualComponents,
    sharedShards: plan.sharedShards,
    shardOrder: plan.shardOrder,
  };
  const topologyPlan = freezeModuleGraphPhysicalShardCohortContribution({
    components: plan.components.map((component) => ({
      bindingIdentitySha256s: [...component.bindingIdentitySha256s],
      codeIdentitySha256s: [...component.codeIdentitySha256s],
      componentBindingSha256: component.componentBindingSha256,
      componentSha256: component.componentSha256,
      dependencies: [...component.dependencies],
      logicalUnitSha256s: [...component.logicalUnitSha256s],
      occurrenceCohortSha256s: [...component.occurrenceCohortSha256s],
      picObjectByteWeight: component.picObjectByteWeight,
      shareable: component.shareable,
      sharedEligible: component.sharedEligible,
    })),
    planSha256: plan.planSha256,
    sharedShards: plan.sharedShards.map((shard) => ({
      componentBindingSha256s: [...shard.componentBindingSha256s],
      componentSha256s: [...shard.componentSha256s],
      dependencies: [...shard.dependencies],
      oversize: shard.oversize,
      picObjectByteWeight: shard.picObjectByteWeight,
      shardSha256: shard.shardSha256,
    })),
    shardOrder: [...plan.shardOrder],
  });
  retainedModuleGraphPhysicalShardPlanningAuthorities.set(physicalShardPlanning, {
    authenticatedCohortUnitMatrix,
    cohortPlanningContributions,
    cohorts: retainedCohorts,
    componentOccurrenceDescriptionBySha256,
    contributionReferences,
    matrixByCohortIndex,
    occurrencesByComponentSha256,
    plan,
    topologyPlan,
  });
  return physicalShardPlanning;
}

export function deriveConvexWasmOfficialOutputModuleGraphPhysicalShardPlan({
  authenticatedCohortUnitMatrix,
  cohortPlanningContributions,
}) {
  return cohortPlanningContributions === undefined
    ? deriveModuleGraphPhysicalShardPlanMonolithic({ authenticatedCohortUnitMatrix })
    : deriveModuleGraphPhysicalShardPlanFromCohortContributions({
        authenticatedCohortUnitMatrix,
        cohortPlanningContributions,
      });
}
