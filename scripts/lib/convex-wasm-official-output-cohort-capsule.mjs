import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  createBoundedRetainedAuthenticatedPayloadCache,
  ensureArtifactStage,
  convexWasmCapabilitySourcePipelineSha256,
  normalizeConvexWasmCapabilityRequestEnvelopeIdentity,
  normalizeConvexWasmGuestNativeJsonCodecIdentity,
  projectConvexWasmOfficialOutputModuleGraphCohortPlanning,
  rehydrateConvexWasmOfficialOutputModuleGraphCohortPlanning,
  restoreConvexWasmCohortPlanningWorkerResult,
} from "./convex-wasm-artifact-pipeline.mjs";
import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
  normalizeJson,
} from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmCompilerOpaqueValueAbiVersion,
  convexWasmGuestPromiseEffectExecutionMode,
} from "./convex-wasm-compiler-contract.mjs";
import { convexWasmCapabilityOfficialWrapperInvocationAbi } from "./convex-wasm-selector-source.mjs";
import {
  artifactCacheEntryPhysicalState,
  readAndValidateArtifactCacheEntry,
  requireAuthenticatedArtifactCacheEntryJsonDigests,
} from "./convex-wasm-artifact-cache-entry.mjs";
import { decodeUtf8 } from "./convex-wasm-artifact-material.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";
import { isRetainedConvexWasmOfficialOutputCohort } from "./convex-wasm-official-output-cohort-schedule.mjs";

export const convexWasmOfficialOutputCohortCapsuleKind =
  "convex-wasm-official-output-cohort-planning-capsule-v6";
export const convexWasmOfficialOutputCohortCapsuleStage = "module-graph-cohort-planning-capsule";

const CAPSULE_SCHEMA_VERSION = 6;
const MAX_CAPSULE_BYTES = 8 * 1024 * 1024;
const MAX_RETAINED_CAPSULE_PROJECTION_BYTES = 96 * 1024 * 1024;
const MAX_RETAINED_CAPSULE_PROJECTIONS = 32;
const COMPILER_OUTPUT_TOPOLOGY_KIND =
  "convex-wasm-official-output-module-graph-compiler-output-topology-v6";
// Official cohort preparation deliberately widens only this ingress limit for the shared
// application JavaScript. Keep the fixed protocol value here rather than trusting a capsule's
// projected options to choose a different exception.
const OFFICIAL_COHORT_GENERATED_JAVASCRIPT_MAX_BYTES = 16 * 1024 * 1024;
const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MATERIAL_LOCATION_ENVIRONMENT_KEYS = new Set(["EM_CONFIG", "EMSDK", "HOME", "PATH"]);
const PHYSICAL_FIELDS = new Set([
  "artifactPath",
  "archives",
  "automaticMaterials",
  "bundlePath",
  "boundedCommandConfig",
  "cacheLayout",
  "cacheRoot",
  "executable",
  "generatedJavaScript",
  "generatedJavaScriptPath",
  "guestSourceProvenance",
  "includeDirectories",
  "mainSourcePath",
  "materialInputs",
  "outputPath",
  "packageBinaryPath",
  "packageDirectory",
  "packageManifestPath",
  "repoRoot",
  "resourceGuard",
  "timeExecutable",
  "workPath",
]);

// The first request still opens and hashes physical capsule bytes. Retain only the fully
// authenticated path-free planning projection and local profiles so an adjacent daemon request can
// rebind fresh command, cache, toolchain, and resource-guard state without repeating the
// multi-megabyte JSON and compiler-contract traversal. The separate state authority below decides
// whether that adjacent request may also omit the repeated byte read.
const retainedAuthenticatedCapsuleProjections = createBoundedRetainedAuthenticatedPayloadCache({
  description: "retained cohort capsule projection",
  maximumBytes: MAX_RETAINED_CAPSULE_PROJECTION_BYTES,
  maximumEntries: MAX_RETAINED_CAPSULE_PROJECTIONS,
});
// The projection cache above still needs authenticated physical bytes on its first use. Retain the
// exact entry state from that read so an adjacent request can replace another multi-megabyte payload
// read with two fresh complete state scans. A state mismatch takes the ordinary read/hash path.
const retainedAuthenticatedCapsulePhysicalStates = new Map();
const retainedCohortIdentities = new WeakMap();
const authenticatedCapsuleIdentities = new WeakSet();
const capsuleCacheKeys = new WeakMap();

function fail(message) {
  throw new Error(`Convex Wasm official-output cohort capsule: ${message}`);
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  const object = requireObject(value, description);
  const actual = Object.keys(object).sort(compareStrings);
  const keys = [...expected].sort(compareStrings);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    fail(`${description} has unsupported fields`);
  }
  return object;
}

function freezeJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeJsonTree(child);
    Object.freeze(value);
  }
  return value;
}

function hashBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function retainedCapsulePhysicalStateKey(cacheRoot, cacheKey) {
  return `${cacheRoot}\0${cacheKey}`;
}

function retainAuthenticatedCapsulePhysicalState({ cacheKey, cacheRoot, entry, physicalState }) {
  const key = retainedCapsulePhysicalStateKey(cacheRoot, cacheKey);
  retainedAuthenticatedCapsulePhysicalStates.delete(key);
  retainedAuthenticatedCapsulePhysicalStates.set(key, Object.freeze({ entry, physicalState }));
  while (retainedAuthenticatedCapsulePhysicalStates.size > MAX_RETAINED_CAPSULE_PROJECTIONS) {
    retainedAuthenticatedCapsulePhysicalStates.delete(
      retainedAuthenticatedCapsulePhysicalStates.keys().next().value
    );
  }
}

async function loadRetainedAuthenticatedCapsuleProjection({ cacheKey, cacheLayout, cacheRoot }) {
  const key = retainedCapsulePhysicalStateKey(cacheRoot, cacheKey);
  const retained = retainedAuthenticatedCapsulePhysicalStates.get(key);
  if (retained === undefined) return undefined;
  requireAuthenticatedArtifactCacheEntryJsonDigests(retained.entry);
  const entryPath = join(
    cacheLayout.immutable.artifacts,
    convexWasmOfficialOutputCohortCapsuleStage,
    cacheKey
  );
  // The passes must be sequential and fresh. Matching only one mixed-time directory/file scan
  // would let it authorize a retained projection without proving one stable complete entry state.
  const first = await artifactCacheEntryPhysicalState(cacheRoot, entryPath);
  const second = await artifactCacheEntryPhysicalState(cacheRoot, entryPath);
  if (first !== retained.physicalState || second !== retained.physicalState) {
    retainedAuthenticatedCapsulePhysicalStates.delete(key);
    return undefined;
  }
  const projection = retainedAuthenticatedCapsuleProjections.get(cacheRoot, retained.entry);
  if (projection === undefined) {
    retainedAuthenticatedCapsulePhysicalStates.delete(key);
    return undefined;
  }
  retainedAuthenticatedCapsulePhysicalStates.delete(key);
  retainedAuthenticatedCapsulePhysicalStates.set(key, retained);
  return projection;
}

function hasPersistableCompilerOutputTopology(compilerOutput) {
  const topology = compilerOutput?.compilerOutputCacheTopology;
  return (
    topology !== null &&
    typeof topology === "object" &&
    !Array.isArray(topology) &&
    topology.kind === COMPILER_OUTPUT_TOPOLOGY_KIND &&
    topology.schemaVersion === 6
  );
}

// Cache identities retain logical module/entry paths, but never retain cache roots, output paths,
// package directories, or other physical locations. Physical locations are rebound to the current
// authenticated cache layout only when a capsule hit is consumed.
function stripPhysicalPaths(value, description) {
  if (Array.isArray(value)) return value.map((child) => stripPhysicalPaths(child, description));
  if (value === null || typeof value !== "object") return value;
  const result = {};
  for (const [key, child] of Object.entries(value)) {
    if (PHYSICAL_FIELDS.has(key)) {
      continue;
    }
    if (key === "environment" && child !== null && typeof child === "object") {
      result[key] = stripPhysicalPaths(
        Object.fromEntries(
          Object.entries(child).filter(
            ([environmentKey]) => !MATERIAL_LOCATION_ENVIRONMENT_KEYS.has(environmentKey)
          )
        ),
        description
      );
      continue;
    }
    result[key] = stripPhysicalPaths(child, description);
  }
  return result;
}

function assertPathFree(value, description, path = "") {
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertPathFree(child, description, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (PHYSICAL_FIELDS.has(key)) {
      fail(`${description} contains physical field ${path}.${key}`);
    }
    if (key === "environment" && child !== null && typeof child === "object") {
      for (const environmentKey of Object.keys(child)) {
        if (MATERIAL_LOCATION_ENVIRONMENT_KEYS.has(environmentKey)) {
          fail(
            `${description} contains physical environment field ${path}.${key}.${environmentKey}`
          );
        }
      }
    }
    assertPathFree(child, description, path.length === 0 ? key : `${path}.${key}`);
  }
}

function sourceEnvelopeIdentity(sourceEnvelope) {
  const source = requireObject(sourceEnvelope, "source envelope");
  const graph = requireObject(source.graph, "source envelope graph");
  return {
    graph: stripPhysicalPaths(
      {
        ...(graph.effectExecutionMode === undefined
          ? {}
          : { effectExecutionMode: graph.effectExecutionMode }),
        toolchain: graph.toolchain,
      },
      "source envelope graph"
    ),
    kind: source.kind,
  };
}

function commandIdentity(command) {
  if (command === undefined) return undefined;
  const value = requireObject(command, "artifact command");
  // `normalizeEnvironment` supplies deterministic defaults when callers omit the optional raw
  // environment. The capsule identity is computed before option normalization, so treating an
  // omitted environment as an empty semantic override keeps that supported caller shape on the
  // same path as the compiler rather than rejecting capsule admission.
  const environment =
    value.environment === undefined
      ? {}
      : requireObject(value.environment, "artifact command environment");
  const semanticEnvironment = Object.fromEntries(
    Object.entries(environment).filter(([key]) => !MATERIAL_LOCATION_ENVIRONMENT_KEYS.has(key))
  );
  for (const [key, defaultValue] of Object.entries({
    LANG: "C",
    LC_ALL: "C",
    SOURCE_DATE_EPOCH: "0",
    TZ: "UTC",
  })) {
    if (!Object.hasOwn(semanticEnvironment, key)) semanticEnvironment[key] = defaultValue;
  }
  return {
    ...value,
    environment: semanticEnvironment,
  };
}

function producerImplementationIdentity(producerIdentity) {
  if (producerIdentity === undefined) return undefined;
  const value = requireObject(producerIdentity, "artifact producer identity");
  if (value.kind !== "convex-wasm-artifact-producer-identity-v1") {
    fail("artifact producer identity has an unsupported kind");
  }
  return {
    kind: value.kind,
    sha256: requireSha256(value.sha256, "artifact producer identity SHA-256"),
  };
}

function cohortIdentity(cohort, cohortIndex) {
  const value = requireObject(cohort, `official-output cohort ${cohortIndex}`);
  if (!Array.isArray(value.entries) || value.entries.length === 0) {
    fail(`official-output cohort ${cohortIndex} has no entries`);
  }
  return {
    cohortId: requireSha256(value.cohortId, `official-output cohort ${cohortIndex} ID`),
    entries: stripPhysicalPaths(value.entries, `official-output cohort ${cohortIndex} entries`),
    entryCount: value.entries.length,
  };
}

export function normalizeConvexWasmOfficialOutputCohortCapsuleIdentity(
  rawIdentity,
  description = "cohort capsule identity"
) {
  if (authenticatedCapsuleIdentities.has(rawIdentity)) return rawIdentity;
  const value = requireObject(rawIdentity, description);
  const expectedKeys = new Set([
    "chunkBindingSha256",
    "cohort",
    "esbuild",
    "kind",
    "policies",
    "schemaVersion",
    "sha256",
    "sourceEnvelope",
  ]);
  if (Object.hasOwn(value, "compilerRecordIdentity")) {
    expectedKeys.add("compilerRecordIdentity");
  }
  if (Object.hasOwn(value, "effectExecutionMode")) {
    expectedKeys.add("effectExecutionMode");
  }
  requireExactKeys(value, expectedKeys, description);
  const normalized = normalizeJson(value, description);
  requireSha256(normalized.chunkBindingSha256, `${description} chunk binding SHA-256`);
  const { sha256, ...payload } = normalized;
  if (
    payload.kind !== convexWasmOfficialOutputCohortCapsuleKind ||
    payload.schemaVersion !== CAPSULE_SCHEMA_VERSION
  ) {
    fail(`${description} has an unsupported schema`);
  }
  if (requireSha256(sha256, `${description} SHA-256`) !== fingerprintJson(payload)) {
    fail(`${description} digest is invalid`);
  }
  const identity = freezeJsonTree({ ...payload, sha256 });
  authenticatedCapsuleIdentities.add(identity);
  return identity;
}

export function prepareConvexWasmOfficialOutputCohortCapsuleIdentities({
  artifactConfig,
  compilerRecordIdentity,
  effectExecutionMode,
  esbuildIdentity,
  platformLimits,
  requestEnvelope,
  sourceEnvelope,
  valueCodec,
}) {
  const config = requireObject(artifactConfig, "artifact config");
  const policies = {
    ...(config.command === undefined ? {} : { command: commandIdentity(config.command) }),
    ...(config.limits === undefined ? {} : { limits: config.limits }),
    platformLimits: requireObject(platformLimits, "platform limits"),
    ...(config.producerIdentity === undefined
      ? {}
      : { producerImplementation: producerImplementationIdentity(config.producerIdentity) }),
    ...(requestEnvelope === undefined ? {} : { requestEnvelope }),
    ...(config.runtime === undefined
      ? {}
      : {
          runtime: config.runtime,
        }),
    ...(config.toolchain === undefined
      ? {}
      : {
          toolchain: config.toolchain,
        }),
    ...(valueCodec === undefined ? {} : { valueCodec }),
  };
  const common = freezeJsonTree(
    normalizeJson(
      {
        ...(compilerRecordIdentity === undefined && config.compiler === undefined
          ? {}
          : {
              compilerRecordIdentity: stripPhysicalPaths(
                compilerRecordIdentity ?? config.compiler,
                "compiler record identity"
              ),
            }),
        ...(effectExecutionMode === undefined ? {} : { effectExecutionMode }),
        esbuild: stripPhysicalPaths(esbuildIdentity ?? {}, "esbuild identity"),
        kind: convexWasmOfficialOutputCohortCapsuleKind,
        policies: stripPhysicalPaths(policies, "cohort capsule policies"),
        schemaVersion: CAPSULE_SCHEMA_VERSION,
        sourceEnvelope: sourceEnvelopeIdentity(sourceEnvelope),
      },
      "cohort capsule identity"
    )
  );
  assertPathFree(common, "cohort capsule common identity");
  const commonSha256 = fingerprintJson(common);
  return ({ cohort, cohortIndex, contextReuseAnalysisIdentity, chunkBindingSha256 }) => {
    requireSha256(chunkBindingSha256, "cohort chunk binding SHA-256");
    const retainedCohort = isRetainedConvexWasmOfficialOutputCohort(cohort);
    const normalizedCohort = retainedCohort ? cohort : cohortIdentity(cohort, cohortIndex);
    const analysis = authenticateConvexContextReuseCohortAnalysisIdentity(
      contextReuseAnalysisIdentity,
      {
        expectedEntryGraphs: normalizedCohort.entries.map(
          ({ dependencyGraphSha256, entryPath }) => ({
            dependencyGraphSha256,
            entryPath,
          })
        ),
      }
    );
    assertPathFree(analysis, "cohort capsule context-reuse analysis");
    const retained = retainedCohort ? retainedCohortIdentities.get(cohort) : undefined;
    if (
      retained?.commonSha256 === commonSha256 &&
      retained.chunkBindingSha256 === chunkBindingSha256 &&
      retained.analysisSha256 === analysis.resultSha256
    ) {
      return retained.identity;
    }
    const payload = {
      ...common,
      chunkBindingSha256,
      cohort: normalizedCohort,
      sourceEnvelope: { ...common.sourceEnvelope, contextReuseAnalysis: analysis },
    };
    const identity = retainedCohort
      ? freezeJsonTree({ ...payload, sha256: fingerprintJson(payload) })
      : normalizeConvexWasmOfficialOutputCohortCapsuleIdentity({
          ...payload,
          sha256: fingerprintJson(payload),
        });
    authenticatedCapsuleIdentities.add(identity);
    if (retainedCohort)
      retainedCohortIdentities.set(cohort, {
        chunkBindingSha256,
        analysisSha256: analysis.resultSha256,
        commonSha256,
        identity,
      });
    return identity;
  };
}

export function createConvexWasmOfficialOutputCohortCapsuleIdentity(options) {
  // Standalone callers retain the complete policy admission. The maintained deployment prepares
  // that policy once and passes graph-owned cohort references directly to the returned consumer.
  return prepareConvexWasmOfficialOutputCohortCapsuleIdentities(options)(options);
}

function capsuleCacheIdentity(rawIdentity) {
  const identity = normalizeConvexWasmOfficialOutputCohortCapsuleIdentity(rawIdentity);
  return {
    capsuleIdentity: identity,
    kind: convexWasmOfficialOutputCohortCapsuleKind,
    schemaVersion: CAPSULE_SCHEMA_VERSION,
  };
}

function capsuleCacheKey(identity) {
  const normalized = normalizeConvexWasmOfficialOutputCohortCapsuleIdentity(identity);
  const retained = capsuleCacheKeys.get(normalized);
  if (retained !== undefined) return retained;
  const key = fingerprintJson({
    identity: capsuleCacheIdentity(normalized),
    kind: PIPELINE_KIND,
    stage: convexWasmOfficialOutputCohortCapsuleStage,
  });
  capsuleCacheKeys.set(normalized, key);
  return key;
}

const COMPILER_CONTRACT_KEYS = new Set([
  "compiler",
  "contextReuseAnalysis",
  "contractId",
  "descriptorIdentitySha256",
  "engine",
  "entries",
  "execution",
  "kind",
  "precompilerMaterialIdentity",
  "producerImplementation",
  "routes",
  "runtimeSurfacePolicySha256",
  "schemaVersion",
  "sourceEnvelopeSha256",
  "sourcePipelineSha256",
]);

function validateCompilerContractIdentity(contract, description) {
  const value = requireExactKeys(contract, COMPILER_CONTRACT_KEYS, description);
  if (
    value.kind !== "convex-wasm-official-output-module-graph-cohort-contract-v2" ||
    value.schemaVersion !== 2
  ) {
    fail(`${description} kind or schema version is unsupported`);
  }
  const { contractId, ...payload } = value;
  if (requireSha256(contractId, `${description} identity`) !== fingerprintJson(payload)) {
    fail(`${description} identity is invalid`);
  }
  authenticateConvexContextReuseCohortAnalysisIdentity(value.contextReuseAnalysis);
  return value;
}

function validateCompilerContractRouteCoverage(contract) {
  const entryIds = new Set();
  contract.entries.forEach((entry, index) => {
    const value = requireObject(entry, `cohort capsule compiler contract entry ${index}`);
    const entryId = requireSha256(
      value.entryId,
      `cohort capsule compiler contract entry ${index} ID`
    );
    if (value.invocationAbi !== convexWasmCapabilityOfficialWrapperInvocationAbi) {
      fail(
        `cohort capsule compiler contract entry ${index} invocation ABI is not the official wrapper ABI`
      );
    }
    if (entryIds.has(entryId)) {
      fail(`cohort capsule compiler contract repeats entry ID ${entryId}`);
    }
    entryIds.add(entryId);
  });
  contract.routes.forEach((route, index) => {
    const value = requireObject(route, `cohort capsule compiler contract route ${index}`);
    const entryId = requireSha256(
      value.entryId,
      `cohort capsule compiler contract route ${index} entry ID`
    );
    if (!entryIds.has(entryId)) {
      fail(`cohort capsule compiler contract route ${index} selects an unknown entry`);
    }
  });
}

function validateCompilerContractCohortBinding(contract, descriptor, scheduledEntries) {
  if (
    !Array.isArray(scheduledEntries) ||
    !Array.isArray(contract.entries) ||
    !Array.isArray(contract.routes) ||
    !Array.isArray(descriptor.entries) ||
    contract.entries.length !== scheduledEntries.length ||
    descriptor.entries.length !== scheduledEntries.length
  ) {
    fail("cohort capsule compiler contract does not match its cohort membership");
  }
  validateCompilerContractRouteCoverage(contract);
  for (const [index, scheduledEntry] of scheduledEntries.entries()) {
    const contractEntry = requireObject(
      contract.entries[index],
      `cohort capsule compiler contract entry ${index}`
    );
    const contractEntryProfile = requireObject(
      contractEntry.localProfile,
      `cohort capsule compiler contract entry ${index} local profile`
    );
    const contractEntryInvocationAbi = contractEntry.invocationAbi;
    const contractEntryProfileSha256 = requireSha256(
      contractEntryProfile.sha256,
      `cohort capsule compiler contract entry ${index} local profile SHA-256`
    );
    const expectedContractEntryId = fingerprintJson({
      domain: "convex-wasm-capability-entry-v1",
      invocationAbi: contractEntryInvocationAbi,
      localProfileSha256: contractEntryProfileSha256,
      selectedEntry: {
        entryPath: contractEntry.entryPath,
        modulePath: contractEntry.modulePath,
      },
    });
    if (
      contractEntry.entryId !== expectedContractEntryId ||
      contractEntry.entrySymbol !== `sh_export_convex_wasm_entry_${expectedContractEntryId}` ||
      contractEntry.entryPath !== scheduledEntry.entryPath ||
      contractEntry.modulePath !== scheduledEntry.modulePath ||
      contractEntry.source?.modulePath !== scheduledEntry.entryPath ||
      contractEntry.source?.runtimeModulePath !== scheduledEntry.runtimeModulePath ||
      contractEntry.source?.resolvedGraphSha256 !== scheduledEntry.dependencyGraphSha256 ||
      contractEntryProfile.dependencyGraphSha256 !== scheduledEntry.dependencyGraphSha256
    ) {
      fail(`cohort capsule compiler contract entry ${index} does not match its cohort membership`);
    }
    const entryRoutes = contract.routes.filter(
      (candidate) => candidate?.entryId === contractEntry.entryId
    );
    const scheduledRouteProjection = entryRoutes
      .map(({ exportName, udfKind, visibility }) => ({ exportName, udfKind, visibility }))
      .sort((left, right) => compareStrings(left.exportName, right.exportName));
    for (const [routeIndex, route] of entryRoutes.entries()) {
      const routeDescription = `cohort capsule compiler contract entry ${index} route ${routeIndex}`;
      const routeExportName = route?.exportName;
      const routeUdfKind = route?.udfKind;
      const routeVisibility = route?.visibility;
      if (
        typeof routeExportName !== "string" ||
        (routeUdfKind !== "query" && routeUdfKind !== "mutation") ||
        (routeVisibility !== "internal" && routeVisibility !== "public") ||
        route?.entrySymbol !== contractEntry.entrySymbol
      ) {
        fail(`${routeDescription} has invalid route authority`);
      }
      const expectedRouteId = fingerprintJson({
        domain: "convex-wasm-capability-route-v1",
        entryId: contractEntry.entryId,
        exportName: routeExportName,
        udfKind: routeUdfKind,
        visibility: routeVisibility,
      });
      const expectedEntrySelectorId = fingerprintJson({
        domain: "convex-wasm-capability-selector-member-v1",
        entrySymbol: contractEntry.entrySymbol,
        handlerExportName: routeExportName,
        handlerUdfKind: routeUdfKind,
        invocationAbi: contractEntryInvocationAbi,
      }).slice(0, 16);
      if (route.routeId !== expectedRouteId || route.entrySelectorId !== expectedEntrySelectorId) {
        fail(`${routeDescription} identity is invalid`);
      }
    }
    if (canonicalJson(scheduledRouteProjection) !== canonicalJson(scheduledEntry.routes)) {
      fail(`cohort capsule compiler contract entry ${index} routes do not match its cohort`);
    }
    const descriptorEntry = requireObject(
      descriptor.entries[index],
      `cohort capsule compiler descriptor entry ${index}`
    );
    if (
      descriptorEntry.dependencyGraphSha256 !== scheduledEntry.dependencyGraphSha256 ||
      descriptorEntry.entryModulePath !== scheduledEntry.runtimeModulePath ||
      descriptorEntry.entryPath !== scheduledEntry.entryPath ||
      descriptorEntry.modulePath !== scheduledEntry.modulePath ||
      canonicalJson(descriptorEntry.routes) !== canonicalJson(scheduledEntry.routes)
    ) {
      fail(`cohort capsule compiler descriptor entry ${index} does not match its cohort`);
    }
  }
}

export const convexWasmOfficialOutputCohortCapsuleTestHooks = Object.freeze({
  assemblePlanningCapsulePayload,
  cohortCapsuleHit,
  authenticatedProjectionCacheStats: () => retainedAuthenticatedCapsuleProjections.stats(),
  planningCapsulePayload,
  rehydratePlanningCapsuleLocalProfiles,
  validateCompilerContractCohortBinding,
  validatePlanningCompilerContractAuthority,
  validatePlanningCapsulePayload,
  validateCompilerContractRouteCoverage,
});

function compilerOutputSourceEnvelopeSha256(compilerOutput, description) {
  const output = requireObject(compilerOutput, description);
  const descriptorSourceEnvelopeSha256 =
    output.descriptor?.applicationIdentity?.sourceEnvelopeSha256;
  const contractSourceEnvelopeSha256 = output.cohortContract?.sourceEnvelopeSha256;
  if (descriptorSourceEnvelopeSha256 === undefined && contractSourceEnvelopeSha256 === undefined) {
    fail(`${description} has no source-envelope provenance`);
  }
  if (descriptorSourceEnvelopeSha256 !== undefined) {
    requireSha256(
      descriptorSourceEnvelopeSha256,
      `${description} descriptor source-envelope SHA-256`
    );
  }
  if (contractSourceEnvelopeSha256 !== undefined) {
    requireSha256(contractSourceEnvelopeSha256, `${description} contract source-envelope SHA-256`);
  }
  if (
    descriptorSourceEnvelopeSha256 !== undefined &&
    contractSourceEnvelopeSha256 !== undefined &&
    descriptorSourceEnvelopeSha256 !== contractSourceEnvelopeSha256
  ) {
    fail(`${description} has inconsistent source-envelope provenance`);
  }
  return descriptorSourceEnvelopeSha256 ?? contractSourceEnvelopeSha256;
}

function compilerContractPolicyProjection(output, description) {
  const options = requireObject(output.options, `${description} options`);
  const command = requireObject(options.command, `${description} command`);
  const runtime = requireObject(options.runtime, `${description} runtime`);
  const toolchain = requireObject(options.toolchain, `${description} toolchain`);
  const emscripten = requireObject(toolchain.emscripten, `${description} Emscripten toolchain`);
  const staticHermes = requireObject(
    toolchain.staticHermes,
    `${description} Static Hermes toolchain`
  );
  const wasmtime = requireObject(toolchain.wasmtime, `${description} Wasmtime toolchain`);
  const commandEnvironment = requireObject(
    command.environment,
    `${description} command environment`
  );
  const semanticEnvironment = Object.fromEntries(
    Object.entries(commandEnvironment).filter(
      ([key]) => !MATERIAL_LOCATION_ENVIRONMENT_KEYS.has(key)
    )
  );
  const wasmtimeTarget = requireObject(wasmtime.target, `${description} Wasmtime target`);
  const limits = requireObject(options.limits, `${description} limits`);
  const artifactLimits = requireObject(limits.artifacts, `${description} artifact limits`);
  const executionLimits = requireObject(limits.execution, `${description} execution limits`);
  if (options.opaqueValueAbiVersion !== convexWasmCompilerOpaqueValueAbiVersion) {
    fail(`${description} opaque value ABI is unsupported`);
  }
  if (options.valueMode !== "guest-native-json") {
    fail(`${description} value mode is unsupported`);
  }
  if (options.effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode) {
    fail(`${description} effect execution mode is unsupported`);
  }
  if (!Array.isArray(options.importedOperations) || options.importedOperations.length !== 0) {
    fail(`${description} imported-operation authority is unsupported`);
  }
  return {
    command: {
      environment: semanticEnvironment,
      maxOutputBytes: command.maxOutputBytes,
      phaseTimeoutMs: command.phaseTimeoutMs,
    },
    compiler: requireObject(options.compiler, `${description} compiler`),
    effectExecutionMode: options.effectExecutionMode,
    limits: {
      artifacts: artifactLimits,
      execution: executionLimits,
    },
    platformLimits: requireObject(options.platformLimits, `${description} platform limits`),
    producerImplementation: producerImplementationIdentity(options.producerIdentity),
    requestEnvelope: options.requestEnvelope,
    runtime: {
      compileFlags: runtime.compileFlags,
      linkFlags: runtime.linkFlags,
      mainCompileFlags: runtime.mainCompileFlags,
    },
    toolchain: {
      emscripten: {
        llvmRevision: emscripten.llvmRevision,
        revision: emscripten.revision,
      },
      staticHermes: {
        flags: staticHermes.flags,
        revision: staticHermes.revision,
      },
      wasmtime: {
        engineConfig: wasmtime.engineConfig,
        packageIdentity: wasmtime.packageIdentity,
        revision: wasmtime.revision,
        target: {
          cpu: wasmtimeTarget.cpu,
          triple: wasmtimeTarget.triple,
        },
      },
    },
    valueCodec: options.valueCodec,
    valueMode: options.valueMode,
  };
}

function compilerContractCompilerProjection(compiler, description) {
  const value = requireObject(compiler, description);
  const expectedKeys = new Set([
    "admittedLanguageVersion",
    "artifactPipelineSha256",
    "compilerRevision",
    "loweringPipelineSha256",
    "sourcePipelineSha256",
    "staticHermesGlobalPolicy",
    "staticHermesRevision",
  ]);
  const normalized = requireExactKeys(value, expectedKeys, description);
  requireSha256(normalized.artifactPipelineSha256, `${description}.artifactPipelineSha256`);
  requireSha256(normalized.loweringPipelineSha256, `${description}.loweringPipelineSha256`);
  requireSha256(normalized.sourcePipelineSha256, `${description}.sourcePipelineSha256`);
  return normalized;
}

function validateRequestedCompilerRecord(outputCompiler, identity, description) {
  const compiler = requireObject(outputCompiler, description);
  const requested = identity.compilerRecordIdentity;
  if (requested === undefined) return;
  const requestedRecord = requireObject(requested, "requested compiler record identity");
  for (const [key, expected] of Object.entries(requestedRecord)) {
    // sourcePipelineSha256 is derived from this cohort's local profiles and the record's kind is
    // a producer-side label, rather than a field emitted by the normalized compiler options. The
    // deployment artifact handoff is likewise an external path seal: it remains in the capsule
    // key, but the artifact adapter deliberately replaces the deployment compiler record with the
    // compiler's normalized semantic identity before construction.
    if (key === "artifactHandoff" || key === "sourcePipelineSha256" || key === "kind") continue;
    const actual =
      key === "runtimeSurfacePolicySha256"
        ? compiler.staticHermesGlobalPolicy?.runtimeSurfacePolicySha256
        : compiler[key];
    if (actual === undefined || canonicalJson(actual) !== canonicalJson(expected)) {
      fail(`${description} does not match its requested compiler record`);
    }
  }
}

function validateCompilerOutputPolicies(output, identity) {
  const projected = compilerContractPolicyProjection(output, "cohort capsule compiler output");
  const policies = requireObject(identity.policies, "cohort capsule policies");
  // Official-output cohort application preparation raises only this one artifact limit to the
  // fixed 16-MiB cohort ingress bound. The remaining artifact and execution limits stay exactly
  // caller-selected and are part of the capsule policy.
  const expectedLimits =
    policies.limits === undefined
      ? undefined
      : {
          ...policies.limits,
          artifacts: {
            ...policies.limits.artifacts,
            generatedJavaScriptBytes: OFFICIAL_COHORT_GENERATED_JAVASCRIPT_MAX_BYTES,
          },
        };
  const compare = (actual, requested, description) => {
    if (canonicalJson(actual) !== canonicalJson(requested)) {
      fail(`${description} does not match its requested policy`);
    }
  };
  for (const key of [
    "command",
    "platformLimits",
    "producerImplementation",
    "requestEnvelope",
    "runtime",
    "toolchain",
    "valueCodec",
  ]) {
    if (policies[key] !== undefined)
      compare(projected[key], policies[key], `cohort capsule ${key}`);
  }
  if (expectedLimits !== undefined)
    compare(projected.limits, expectedLimits, "cohort capsule limits");
  if (identity.effectExecutionMode !== undefined) {
    compare(
      projected.effectExecutionMode,
      identity.effectExecutionMode,
      "cohort capsule effect execution mode"
    );
  }
  validateRequestedCompilerRecord(projected.compiler, identity, "cohort capsule compiler output");
  return projected;
}

function assemblePlanningCapsulePayload({ identity, planning, sourceEnvelopeSha256 }) {
  // Identity is caller-owned, so retain the former one-read normalization at that boundary. The
  // remaining values are local literals or validated scalar provenance, and `planning` is the
  // projector's authenticated normalized result.
  const payload = {
    identity: normalizeJson(identity, "cohort planning capsule identity"),
    kind: convexWasmOfficialOutputCohortCapsuleKind,
    planning,
    schemaVersion: CAPSULE_SCHEMA_VERSION,
    sourceEnvelopeSha256,
  };
  assertPathFree(payload, "cohort planning capsule payload");
  return payload;
}

function planningCapsulePayload({ compilerOutput, identity }) {
  // The projector returns a normalized path-free schema from authenticated compiler output and
  // may reuse the exact producer's frozen projection. Keep that exact value: stripPhysicalPaths
  // and whole-payload normalization each copied and traversed the same multi-megabyte tree again.
  // The complete path-free assertion in assemblePlanningCapsulePayload remains the fail-closed
  // capsule boundary.
  const planning = projectConvexWasmOfficialOutputModuleGraphCohortPlanning(compilerOutput);
  const sourceEnvelopeSha256 = compilerOutputSourceEnvelopeSha256(
    compilerOutput,
    "cohort compiler output"
  );
  return assemblePlanningCapsulePayload({ identity, planning, sourceEnvelopeSha256 });
}

function validatePlanningCapsulePayload(payload, identity, cacheKey, compilerOutput) {
  const value = requireExactKeys(
    payload,
    new Set(["identity", "kind", "planning", "schemaVersion", "sourceEnvelopeSha256"]),
    "cohort planning capsule payload"
  );
  if (
    value.kind !== convexWasmOfficialOutputCohortCapsuleKind ||
    value.schemaVersion !== CAPSULE_SCHEMA_VERSION ||
    canonicalJson(value.identity) !== canonicalJson(identity) ||
    cacheKey !== capsuleCacheKey(value.identity)
  ) {
    fail("cohort planning capsule payload is not bound to its requested identity");
  }
  requireSha256(value.sourceEnvelopeSha256, "cohort planning capsule source-envelope SHA-256");
  if (
    value.sourceEnvelopeSha256 !==
    compilerOutputSourceEnvelopeSha256(compilerOutput, "cohort planning compiler output")
  ) {
    fail("cohort planning capsule source-envelope provenance changed");
  }
  const projectedOptions = validateCompilerOutputPolicies(compilerOutput, identity);
  const { contract, localProfiles } = validatePlanningCompilerContractAuthority(
    compilerOutput,
    projectedOptions
  );
  const sourceContextReuseAnalysis = authenticateConvexContextReuseCohortAnalysisIdentity(
    identity.sourceEnvelope.contextReuseAnalysis
  );
  if (canonicalJson(contract.contextReuseAnalysis) !== canonicalJson(sourceContextReuseAnalysis)) {
    fail("cohort planning compiler contract does not match its capsule identity");
  }
  validateCompilerContractCohortBinding(
    contract,
    compilerOutput.descriptor,
    identity.cohort.entries
  );
  assertPathFree(value, "cohort planning capsule payload");
  return Object.freeze({ localProfiles, payload: value });
}

function rehydratePlanningCapsuleLocalProfiles(compilerOutput) {
  const descriptor = requireObject(
    compilerOutput.descriptor,
    "cohort planning compiler descriptor"
  );
  const applicationUnit = requireObject(
    descriptor.applicationIdentity,
    "cohort planning compiler application identity"
  );
  const contract = requireObject(
    compilerOutput.cohortContract,
    "cohort planning compiler contract"
  );
  const initialization = requireObject(
    descriptor.initialization,
    "cohort planning compiler descriptor initialization"
  );
  if (
    !Array.isArray(descriptor.entries) ||
    !Array.isArray(descriptor.units) ||
    !Array.isArray(applicationUnit.units) ||
    !Array.isArray(contract.entries) ||
    !Number.isSafeInteger(initialization.namespaceSlotCount) ||
    initialization.namespaceSlotCount < 0 ||
    initialization.namespaceSlotCount > descriptor.units.length ||
    descriptor.entries.length !== contract.entries.length
  ) {
    fail("cohort planning local profiles do not match their descriptor");
  }
  const applicationChunkUnits = requireObject(
    applicationUnit.chunkUnits,
    "cohort planning compiler application chunk-units identity"
  );
  const chunkUnitsSha256 = requireSha256(
    applicationChunkUnits.sha256,
    "cohort planning compiler application chunk-units SHA-256"
  );
  const sourceMapChunksSource = canonicalJson(
    descriptor.units
      .slice(0, initialization.namespaceSlotCount)
      .map((unit) => ({ module: unit.module, slot: unit.chunkSlot }))
  );
  // Every profile embeds this same application identity. Freeze and encode it once, then copy
  // the hash state at its canonical first-field boundary. Each profile still authenticates its
  // complete identity, without traversing and hashing the shared descriptor again per entry.
  freezeJsonTree(applicationUnit);
  const profileHashPrefix = createHash("sha256").update(
    `{"applicationUnit":${canonicalJson(applicationUnit)},`
  );
  return Object.freeze(
    contract.entries.map((contractEntry, index) => {
      const descriptorEntry = requireObject(
        descriptor.entries[index],
        `cohort planning descriptor entry ${index}`
      );
      const summary = requireObject(
        contractEntry.localProfile,
        `cohort planning compiler contract entry ${index} local profile`
      );
      const publicationUnit = requireObject(
        descriptor.units[descriptorEntry.entryPublicationUnitSlot],
        `cohort planning descriptor entry ${index} publication unit`
      );
      const publicationJavaScript = requireExactKeys(
        publicationUnit.javascript,
        new Set(["sha256", "size"]),
        `cohort planning descriptor entry ${index} publication JavaScript identity`
      );
      const summaryJavaScript = requireExactKeys(
        summary.javascript,
        new Set(["sha256", "size"]),
        `cohort planning compiler contract entry ${index} JavaScript identity`
      );
      const summarySourceMap = requireExactKeys(
        summary.sourceMap,
        new Set(["sha256", "size"]),
        `cohort planning compiler contract entry ${index} source-map identity`
      );
      const sourceMap = `{"chunks":${sourceMapChunksSource},"kind":"convex-wasm-official-output-chunk-application-source-map-manifest-v2","publication":${canonicalJson(
        applicationUnit.units[descriptorEntry.entryPublicationUnitSlot]
      )}}\n`;
      if (
        summary.metafileSha256 !== chunkUnitsSha256 ||
        canonicalJson(summaryJavaScript) !== canonicalJson(publicationJavaScript) ||
        canonicalJson(summarySourceMap) !==
          canonicalJson({ sha256: hashBytes(sourceMap), size: Buffer.byteLength(sourceMap) })
      ) {
        fail(`cohort planning compiler contract entry ${index} profile changed`);
      }
      const profileFields = freezeJsonTree({
        dependencyGraphSha256: summary.dependencyGraphSha256,
        handoffSlot: descriptorEntry.handoffSlot,
        kind: "convex-wasm-official-output-chunk-local-profile-identity-v2",
        metafileSha256: summary.metafileSha256,
        mode: "authenticated-official-output-chunks",
        output: {
          javascript: summary.javascript,
          sourceMap: summary.sourceMap,
        },
        routes: descriptorEntry.routes,
        selectedEntry: {
          entryPath: contractEntry.entryPath,
          modulePath: contractEntry.modulePath,
        },
      });
      const profileIdentity = Object.freeze({ applicationUnit, ...profileFields });
      const sha256 = requireSha256(
        summary.sha256,
        `cohort planning local profile ${index} SHA-256`
      );
      if (
        profileHashPrefix.copy().update(canonicalJson(profileFields).slice(1)).digest("hex") !==
        sha256
      ) {
        fail(`cohort planning local profile ${index} changed`);
      }
      return Object.freeze({
        identity: profileIdentity,
        kind: "convex-wasm-local-compile-profile-v1",
        sha256,
      });
    })
  );
}

function validatePlanningCompilerContractAuthority(
  compilerOutput,
  projectedOptions = compilerContractPolicyProjection(
    compilerOutput,
    "cohort planning compiler output"
  )
) {
  const contract = validateCompilerContractIdentity(
    compilerOutput.cohortContract,
    "cohort planning compiler contract"
  );
  validateCompilerContractRouteCoverage(contract);
  const contractExecution = requireExactKeys(
    contract.execution,
    new Set([
      "effectExecutionMode",
      "importedOperations",
      "limits",
      "platformLimits",
      "requestEnvelope",
      "valueCodec",
      "valueMode",
    ]),
    "cohort planning compiler contract execution"
  );
  const contractCompiler = compilerContractCompilerProjection(
    contract.compiler,
    "cohort planning compiler contract compiler"
  );
  const contractRequestEnvelope = normalizeConvexWasmCapabilityRequestEnvelopeIdentity(
    contractExecution.requestEnvelope,
    "cohort planning compiler contract request envelope"
  );
  const contractValueCodec = normalizeConvexWasmGuestNativeJsonCodecIdentity(
    contractExecution.valueCodec,
    "cohort planning compiler contract value codec"
  );
  const requestedRequestEnvelope = requireObject(
    projectedOptions.requestEnvelope,
    "cohort planning compiler output request envelope"
  );
  const requestedValueCodec = requireObject(
    projectedOptions.valueCodec,
    "cohort planning compiler output value codec"
  );
  const descriptor = requireObject(
    compilerOutput.descriptor,
    "cohort planning compiler descriptor"
  );
  const applicationIdentity = requireObject(
    descriptor.applicationIdentity,
    "cohort planning compiler application identity"
  );
  const expectedContractCompiler = {
    ...projectedOptions.compiler,
    artifactPipelineSha256: contractCompiler.artifactPipelineSha256,
    staticHermesRevision: projectedOptions.toolchain.staticHermes.revision,
  };
  const localProfiles = rehydratePlanningCapsuleLocalProfiles(compilerOutput);
  const expectedSourcePipelineSha256 = convexWasmCapabilitySourcePipelineSha256(localProfiles);
  if (
    contract.descriptorIdentitySha256 !==
      requireSha256(
        applicationIdentity.sha256,
        "cohort planning compiler application identity SHA-256"
      ) ||
    canonicalJson(contractCompiler) !== canonicalJson(expectedContractCompiler) ||
    canonicalJson(contract.engine) !== canonicalJson(compilerOutput.engine) ||
    contractExecution.effectExecutionMode !== projectedOptions.effectExecutionMode ||
    canonicalJson(contractExecution.importedOperations) !==
      canonicalJson(compilerOutput.options.importedOperations) ||
    canonicalJson(contractExecution.limits) !== canonicalJson(projectedOptions.limits.execution) ||
    canonicalJson(contractExecution.platformLimits) !==
      canonicalJson(projectedOptions.platformLimits) ||
    contractExecution.valueMode !== projectedOptions.valueMode ||
    contractRequestEnvelope.capabilityRequestAbiVersion !==
      requestedRequestEnvelope.capabilityRequestAbiVersion ||
    canonicalJson(contractRequestEnvelope.canonicalVectorCorpus) !==
      canonicalJson(requestedRequestEnvelope.canonicalVectorCorpus) ||
    canonicalJson(contractValueCodec.canonicalVectorCorpus) !==
      canonicalJson(requestedValueCodec.canonicalVectorCorpus) ||
    contractRequestEnvelope.loweringPipelineSha256 !== contractCompiler.loweringPipelineSha256 ||
    contractValueCodec.loweringPipelineSha256 !== contractCompiler.loweringPipelineSha256 ||
    canonicalJson(contract.precompilerMaterialIdentity) !==
      canonicalJson(projectedOptions.toolchain.wasmtime.packageIdentity) ||
    canonicalJson(contract.producerImplementation) !==
      canonicalJson(projectedOptions.producerImplementation) ||
    contract.runtimeSurfacePolicySha256 !==
      projectedOptions.compiler.staticHermesGlobalPolicy.runtimeSurfacePolicySha256 ||
    contract.sourcePipelineSha256 !== expectedSourcePipelineSha256 ||
    projectedOptions.compiler.sourcePipelineSha256 !== expectedSourcePipelineSha256 ||
    contract.sourceEnvelopeSha256 !== applicationIdentity.sourceEnvelopeSha256
  ) {
    fail("cohort planning compiler contract does not match its compiler output");
  }
  return Object.freeze({ contract, localProfiles });
}

export async function isConvexWasmOfficialOutputCohortCapsulePresent({
  cacheLayout: rawCacheLayout,
  cacheRoot,
  identity,
}) {
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  if (cacheRoot !== cacheLayout.cacheRoot)
    fail("cohort capsule cache root disagrees with its immutable layout");
  // Presence only avoids spawning workers for all-miss builds. Any present entry, including a
  // malformed one, still goes through the worker's complete first-open cache authentication.
  try {
    await fs.lstat(
      join(
        cacheLayout.immutable.artifacts,
        convexWasmOfficialOutputCohortCapsuleStage,
        capsuleCacheKey(identity)
      )
    );
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

export async function restoreConvexWasmOfficialOutputCohortCapsuleFromWorker(
  transferred,
  arguments_
) {
  const compilerOutput = restoreConvexWasmCohortPlanningWorkerResult(transferred, arguments_);
  return await cohortCapsuleHit({
    cacheKey: transferred.cacheKey,
    compilerOutput,
    localProfiles: transferred.localProfiles,
  });
}

export async function probeConvexWasmOfficialOutputCohortCapsule({
  cacheLayout: rawCacheLayout,
  cacheRoot,
  artifactConfig,
  capabilityRuntimeHeaderDirectory,
  identity,
}) {
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  if (cacheRoot !== cacheLayout.cacheRoot) {
    fail("cohort capsule cache root disagrees with its immutable layout");
  }
  const cacheKey = capsuleCacheKey(identity);
  const retainedPhysicalProjection = await loadRetainedAuthenticatedCapsuleProjection({
    cacheKey,
    cacheLayout,
    cacheRoot,
  });
  if (retainedPhysicalProjection !== undefined) {
    if (retainedPhysicalProjection.cacheKey !== cacheKey) {
      fail("retained cohort capsule projection has a different cache key");
    }
    const compilerOutput = rehydrateConvexWasmOfficialOutputModuleGraphCohortPlanning({
      cacheLayout,
      cacheRoot,
      artifactConfig,
      capabilityRuntimeHeaderDirectory,
      planning: retainedPhysicalProjection.planning,
    });
    return cohortCapsuleHit({
      cacheKey,
      compilerOutput,
      localProfiles: retainedPhysicalProjection.localProfiles,
    });
  }
  const entryPath = join(
    cacheLayout.immutable.artifacts,
    convexWasmOfficialOutputCohortCapsuleStage,
    cacheKey
  );
  const physicalStateBeforeRead = await artifactCacheEntryPhysicalState(cacheRoot, entryPath);
  const entry = await readAndValidateArtifactCacheEntry(
    cacheRoot,
    cacheLayout,
    convexWasmOfficialOutputCohortCapsuleStage,
    cacheKey,
    "json",
    MAX_CAPSULE_BYTES
  );
  if (entry === undefined) return undefined;
  requireAuthenticatedArtifactCacheEntryJsonDigests(entry);
  if (
    canonicalJson(entry.metadata) !==
    canonicalJson({
      kind: convexWasmOfficialOutputCohortCapsuleKind,
      schemaVersion: CAPSULE_SCHEMA_VERSION,
    })
  ) {
    fail("cohort capsule metadata changed");
  }
  const retainedProjection = retainedAuthenticatedCapsuleProjections.get(cacheRoot, entry);
  if (retainedProjection !== undefined) {
    if (retainedProjection.cacheKey !== cacheKey) {
      fail("retained cohort capsule projection has a different cache key");
    }
    delete entry.artifactContents;
    const physicalStateAfterRead = await artifactCacheEntryPhysicalState(cacheRoot, entryPath);
    if (
      physicalStateBeforeRead !== undefined &&
      physicalStateBeforeRead === physicalStateAfterRead
    ) {
      retainAuthenticatedCapsulePhysicalState({
        cacheKey,
        cacheRoot,
        entry,
        physicalState: physicalStateAfterRead,
      });
    }
    const compilerOutput = rehydrateConvexWasmOfficialOutputModuleGraphCohortPlanning({
      cacheLayout,
      cacheRoot,
      artifactConfig,
      capabilityRuntimeHeaderDirectory,
      planning: retainedProjection.planning,
    });
    return cohortCapsuleHit({
      cacheKey,
      compilerOutput,
      localProfiles: retainedProjection.localProfiles,
    });
  }
  let payload;
  try {
    const source = decodeUtf8(entry.artifactContents, "cohort capsule");
    payload = JSON.parse(source);
    if (`${canonicalJson(payload)}\n` !== source) {
      fail("cohort capsule payload is not canonical JSON");
    }
  } catch (error) {
    throw new Error("Convex Wasm official-output cohort capsule: payload is corrupt", {
      cause: error,
    });
  }
  // The compact projection is enough to authenticate package-receipt planning. Its topology
  // certificate and full compiler-output record stay in their existing immutable stages and are
  // opened lazily by the artifact pipeline only after exact receipt selection requires them.
  const compilerOutput = rehydrateConvexWasmOfficialOutputModuleGraphCohortPlanning({
    cacheLayout,
    cacheRoot,
    artifactConfig,
    capabilityRuntimeHeaderDirectory,
    planning: payload.planning,
  });
  const { localProfiles } = validatePlanningCapsulePayload(
    payload,
    identity,
    cacheKey,
    compilerOutput
  );
  retainedAuthenticatedCapsuleProjections.retain(
    cacheRoot,
    entry,
    Object.freeze({ cacheKey, localProfiles, planning: payload.planning })
  );
  delete entry.artifactContents;
  const physicalStateAfterRead = await artifactCacheEntryPhysicalState(cacheRoot, entryPath);
  if (physicalStateBeforeRead !== undefined && physicalStateBeforeRead === physicalStateAfterRead) {
    retainAuthenticatedCapsulePhysicalState({
      cacheKey,
      cacheRoot,
      entry,
      physicalState: physicalStateAfterRead,
    });
  }
  return cohortCapsuleHit({ cacheKey, compilerOutput, localProfiles });
}

async function cohortCapsuleHit({ cacheKey, compilerOutput, localProfiles }) {
  // The adapter's cold-profile imports reach cache retention, which imports this capsule module.
  // Resolve the report-brand owner after module initialization to avoid that import cycle.
  const { retainAuthenticatedBuildReportCompileProfile } =
    await import("./convex-wasm-official-output-artifact-adapter.mjs");
  // Capsule admission has authenticated and deeply frozen these exact profile identities and
  // their shared application identity. Carry that ownership to the report's existing brand so
  // reporting does not hash both trees again; copied profiles still require full verification.
  const profiles = Object.freeze(
    localProfiles.map((profile) =>
      retainAuthenticatedBuildReportCompileProfile(
        Object.freeze({
          identity: profile.identity,
          kind: profile.kind,
          sha256: profile.sha256,
          async verifyMaterials() {
            // Source and installed materials retain their deployment-boundary verifiers. The
            // artifact pipeline authenticates this compact topology before consuming any receipt.
          },
        })
      )
    )
  );
  return Object.freeze({
    cache: "hit",
    cacheKey,
    compilerOutput,
    localProfiles,
    profiles,
  });
}

export async function publishConvexWasmOfficialOutputCohortCapsule({
  cacheLayout: rawCacheLayout,
  cacheRoot,
  compilerOutput,
  identity,
}) {
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  if (cacheRoot !== cacheLayout.cacheRoot) {
    fail("cohort capsule cache root disagrees with its immutable layout");
  }
  const cacheKey = capsuleCacheKey(identity);
  const payload = planningCapsulePayload({
    compilerOutput,
    identity,
  });
  validatePlanningCapsulePayload(payload, identity, cacheKey, compilerOutput);
  const source = `${canonicalJson(payload)}\n`;
  const published = await ensureArtifactStage({
    build: async (workPath) => {
      const outputPath = join(workPath, "cohort-capsule.json");
      await fs.writeFile(outputPath, source, { mode: 0o600 });
      return {
        metadata: {
          kind: convexWasmOfficialOutputCohortCapsuleKind,
          schemaVersion: CAPSULE_SCHEMA_VERSION,
        },
        outputPath,
        timing: null,
      };
    },
    cacheLayout,
    cacheRoot,
    extension: "json",
    identity: capsuleCacheIdentity(identity),
    maxArtifactBytes: MAX_CAPSULE_BYTES,
    stage: convexWasmOfficialOutputCohortCapsuleStage,
  });
  if (
    published.report.cacheKey !== cacheKey ||
    published.entry.artifactSize !== Buffer.byteLength(source) ||
    published.entry.artifactSha256 !== hashBytes(Buffer.from(source))
  ) {
    fail("published cohort capsule differs from its requested identity");
  }
  return Object.freeze({ cache: published.report.cache, cacheKey });
}

export function createConvexWasmOfficialOutputCohortCapsuleMiss({ compilerOutput, identity }) {
  // Planning-only callers may provide a deliberately minimal compiler result. Such a result is
  // valid for the in-process planner contract but has no authenticated topology to persist.
  if (
    compilerOutput?.kind !== "convex-wasm-official-output-module-graph-compiler-output-v3" ||
    compilerOutput?.schemaVersion !== 3
  ) {
    return undefined;
  }
  // Planning-only builders may return a v3 in-process result without the authenticated topology
  // envelope. Such a result can continue through the current build, but it has no immutable stage
  // references that this capsule can safely persist or rehydrate later.
  if (!hasPersistableCompilerOutputTopology(compilerOutput)) return undefined;
  return Object.freeze({
    cache: "miss",
    cacheKey: capsuleCacheKey(identity),
    compilerOutput,
    identity,
  });
}
