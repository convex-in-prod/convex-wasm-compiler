import {
  canonicalJson,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmCapabilitySourcePipelineSha256,
  normalizeConvexWasmCapabilityRequestEnvelopeIdentity,
  normalizeConvexWasmGuestNativeJsonCodecIdentity,
  normalizeConvexWasmSourceIdentity,
} from "./convex-wasm-capability-identity.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "./convex-wasm-compiler-contract.mjs";
import {
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
} from "./convex-wasm-selector-source.mjs";
import {
  convexWasmTargetRuntimeSurfacePolicyIdentity,
  convexWasmTargetRuntimeSurfacePolicySha256,
} from "./convex-wasm-runtime-surface.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";

export const convexWasmModuleGraphCohortContractKind =
  "convex-wasm-module-graph-cohort-contract-v2";
export const convexWasmModuleGraphRouteReferenceKind =
  "convex-wasm-module-graph-route-reference-v1";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SELECTOR_ID_PATTERN = /^[0-9a-f]{16}$/u;
const INVOCATION_ABIS = new Set([
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
]);
const EXECUTION_LIMIT_FIELDS = Object.freeze([
  "executionFuel",
  "maxGuestMemoryBytes",
  "maxHostOwnedBytes",
  "maxOperationCount",
  "maxResultBytes",
  "maxValueHandles",
  "timeoutMilliseconds",
]);
const PLATFORM_LIMIT_FIELDS = Object.freeze([
  "argumentBytes",
  "documentsRead",
  "documentsWritten",
  "executionTimeMs",
  "readBytes",
  "resultBytes",
  "scheduledArgumentBytes",
  "scheduledFunctions",
  "writeBytes",
]);
const PRECOMPILER_IDENTITY_FIELDS = Object.freeze([
  "binary",
  "kind",
  "manifestKind",
  "manifestSchemaVersion",
  "manifestSha256",
  "packageId",
  "sourceTreeSha256",
  "targetTriple",
  "wasmtimeRevision",
]);

function fail(message) {
  throw new Error(`Convex Wasm module graph cohort contract: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireObject(value, description) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireExactKeys(value, keys, description) {
  const object = requireObject(value, description);
  if (
    canonicalJson(Object.keys(object).sort(compareStrings)) !==
    canonicalJson([...keys].sort(compareStrings))
  ) {
    fail(`${description} has unexpected fields`);
  }
  return object;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function normalizePositiveIntegerRecord(value, fields, description) {
  const record = requireExactKeys(value, new Set(fields), description);
  return Object.fromEntries(
    fields.map((field) => [field, requirePositiveInteger(record[field], `${description} ${field}`)])
  );
}

function normalizePrecompilerMaterialIdentity(value, description) {
  const identity = requireExactKeys(value, new Set(PRECOMPILER_IDENTITY_FIELDS), description);
  const binary = requireExactKeys(
    identity.binary,
    new Set(["sha256", "size"]),
    `${description} binary`
  );
  if (identity.kind !== "convex-wasm-verified-precompiler-package") {
    fail(`${description} kind is unsupported`);
  }
  return {
    binary: {
      sha256: requireSha256(binary.sha256, `${description} binary SHA-256`),
      size: requirePositiveInteger(binary.size, `${description} binary size`),
    },
    kind: identity.kind,
    manifestKind: requireString(identity.manifestKind, `${description} manifest kind`),
    manifestSchemaVersion: requirePositiveInteger(
      identity.manifestSchemaVersion,
      `${description} manifest schema version`
    ),
    manifestSha256: requireSha256(identity.manifestSha256, `${description} manifest SHA-256`),
    packageId: requireSha256(identity.packageId, `${description} package ID`),
    sourceTreeSha256: requireSha256(
      identity.sourceTreeSha256,
      `${description} source tree SHA-256`
    ),
    targetTriple: requireString(identity.targetTriple, `${description} target triple`),
    wasmtimeRevision: requireString(identity.wasmtimeRevision, `${description} Wasmtime revision`),
  };
}

function normalizeLocalProfile(value, description) {
  const profile = requireExactKeys(
    value,
    new Set(["dependencyGraphSha256", "javascript", "metafileSha256", "sha256", "sourceMap"]),
    description
  );
  const javascript = requireExactKeys(
    profile.javascript,
    new Set(["sha256", "size"]),
    `${description} JavaScript`
  );
  const sourceMap = requireExactKeys(
    profile.sourceMap,
    new Set(["sha256", "size"]),
    `${description} source map`
  );
  return {
    dependencyGraphSha256: requireSha256(
      profile.dependencyGraphSha256,
      `${description} dependency graph SHA-256`
    ),
    javascript: {
      sha256: requireSha256(javascript.sha256, `${description} JavaScript SHA-256`),
      size: requirePositiveInteger(javascript.size, `${description} JavaScript size`),
    },
    metafileSha256: requireSha256(profile.metafileSha256, `${description} metafile SHA-256`),
    sha256: requireSha256(profile.sha256, `${description} SHA-256`),
    sourceMap: {
      sha256: requireSha256(sourceMap.sha256, `${description} source-map SHA-256`),
      size: requirePositiveInteger(sourceMap.size, `${description} source-map size`),
    },
  };
}

function normalizeEntry(value, index) {
  const description = `cohort entry ${index}`;
  const entry = requireExactKeys(
    value,
    new Set([
      "entryId",
      "entryPath",
      "entrySymbol",
      "invocationAbi",
      "localProfile",
      "modulePath",
      "source",
    ]),
    description
  );
  const localProfile = normalizeLocalProfile(entry.localProfile, `${description} local profile`);
  const invocationAbi = requireString(entry.invocationAbi, `${description} invocation ABI`);
  if (!INVOCATION_ABIS.has(invocationAbi)) {
    fail(`${description} invocation ABI is unsupported`);
  }
  const normalized = {
    entryId: requireSha256(entry.entryId, `${description} entry ID`),
    entryPath: requireString(entry.entryPath, `${description} entry path`),
    entrySymbol: requireString(entry.entrySymbol, `${description} entry symbol`),
    invocationAbi,
    localProfile,
    modulePath: requireString(entry.modulePath, `${description} module path`),
    source: normalizeConvexWasmSourceIdentity(entry.source),
  };
  const expectedEntryId = fingerprintJson({
    domain: "convex-wasm-capability-entry-v1",
    invocationAbi,
    localProfileSha256: localProfile.sha256,
    selectedEntry: { entryPath: normalized.entryPath, modulePath: normalized.modulePath },
  });
  if (
    normalized.entryId !== expectedEntryId ||
    normalized.entrySymbol !== `sh_export_convex_wasm_entry_${expectedEntryId}`
  ) {
    fail(`${description} identity or symbol is invalid`);
  }
  return normalized;
}

function normalizeRoute(value, entriesById, index) {
  const description = `cohort route ${index}`;
  const route = requireExactKeys(
    value,
    new Set([
      "entryId",
      "entrySelectorId",
      "entrySymbol",
      "exportName",
      "routeId",
      "udfKind",
      "visibility",
    ]),
    description
  );
  const entryId = requireSha256(route.entryId, `${description} entry ID`);
  const entry = entriesById.get(entryId);
  if (entry === undefined) fail(`${description} selects an unknown entry`);
  const entrySelectorId = requireString(route.entrySelectorId, `${description} selector ID`);
  if (!SELECTOR_ID_PATTERN.test(entrySelectorId)) {
    fail(`${description} selector ID must contain 16 lowercase hexadecimal characters`);
  }
  const exportName = requireString(route.exportName, `${description} export name`);
  const udfKind = requireString(route.udfKind, `${description} UDF kind`);
  const visibility = requireString(route.visibility, `${description} visibility`);
  if (!new Set(["mutation", "query"]).has(udfKind)) fail(`${description} UDF kind is unsupported`);
  if (!new Set(["internal", "public"]).has(visibility)) {
    fail(`${description} visibility is unsupported`);
  }
  const expectedRouteId = fingerprintJson({
    domain: "convex-wasm-capability-route-v1",
    entryId,
    exportName,
    udfKind,
    visibility,
  });
  const expectedSelectorId =
    entry.invocationAbi === convexWasmCapabilityLegacyInvocationAbi
      ? expectedRouteId.slice(0, 16)
      : fingerprintJson({
          domain: "convex-wasm-capability-selector-member-v1",
          entrySymbol: entry.entrySymbol,
          handlerExportName: exportName,
          handlerUdfKind: udfKind,
          invocationAbi: entry.invocationAbi,
        }).slice(0, 16);
  if (
    route.entrySymbol !== entry.entrySymbol ||
    route.routeId !== expectedRouteId ||
    entrySelectorId !== expectedSelectorId
  ) {
    fail(`${description} identity is invalid`);
  }
  return {
    entryId,
    entrySelectorId,
    entrySymbol: entry.entrySymbol,
    exportName,
    routeId: expectedRouteId,
    udfKind,
    visibility,
  };
}

function normalizeCompiler(value) {
  const compiler = requireObject(value, "cohort compiler contract");
  if (
    requireSha256(compiler.loweringPipelineSha256, "cohort compiler lowering pipeline SHA-256") !==
      compiler.loweringPipelineSha256 ||
    requireSha256(compiler.artifactPipelineSha256, "cohort compiler artifact pipeline SHA-256") !==
      compiler.artifactPipelineSha256 ||
    requireString(compiler.staticHermesRevision, "cohort compiler Static Hermes revision") !==
      compiler.staticHermesRevision ||
    canonicalJson(compiler.staticHermesGlobalPolicy) !==
      canonicalJson(convexWasmTargetRuntimeSurfacePolicyIdentity)
  ) {
    fail("cohort compiler contract is unsupported");
  }
  return JSON.parse(canonicalJson(compiler));
}

function normalizeRuntimeSurfacePolicySha256(value, compiler) {
  const sha256 = requireSha256(value, "cohort runtime-surface policy SHA-256");
  if (
    sha256 !== convexWasmTargetRuntimeSurfacePolicySha256 ||
    compiler.staticHermesGlobalPolicy.runtimeSurfacePolicySha256 !== sha256
  ) {
    fail("cohort runtime-surface policy identity is invalid");
  }
  return sha256;
}

function normalizeExecution(value, compiler) {
  const execution = requireExactKeys(
    value,
    new Set([
      "effectExecutionMode",
      "importedOperations",
      "limits",
      "platformLimits",
      "requestEnvelope",
      "valueCodec",
      "valueMode",
    ]),
    "cohort execution contract"
  );
  if (
    execution.effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode ||
    canonicalJson(execution.importedOperations) !== "[]" ||
    execution.valueMode !== "guest-native-json"
  ) {
    fail("cohort execution contract is unsupported");
  }
  const limits = normalizePositiveIntegerRecord(
    execution.limits,
    EXECUTION_LIMIT_FIELDS,
    "cohort execution limits"
  );
  const platformLimits = normalizePositiveIntegerRecord(
    execution.platformLimits,
    PLATFORM_LIMIT_FIELDS,
    "cohort platform limits"
  );
  if (
    limits.timeoutMilliseconds > platformLimits.executionTimeMs ||
    limits.maxResultBytes > platformLimits.resultBytes
  ) {
    fail("cohort execution limits exceed their platform limits");
  }
  const requestEnvelope = normalizeConvexWasmCapabilityRequestEnvelopeIdentity(
    execution.requestEnvelope,
    "cohort request-envelope identity"
  );
  const valueCodec = normalizeConvexWasmGuestNativeJsonCodecIdentity(
    execution.valueCodec,
    "cohort value-codec identity"
  );
  if (requestEnvelope.loweringPipelineSha256 !== compiler.loweringPipelineSha256) {
    fail("cohort request-envelope and compiler lowering identities disagree");
  }
  return {
    effectExecutionMode: execution.effectExecutionMode,
    importedOperations: [],
    limits,
    platformLimits,
    requestEnvelope,
    valueCodec,
    valueMode: execution.valueMode,
  };
}

export function validateConvexWasmModuleGraphCohortContract(value) {
  const contract = requireExactKeys(
    value,
    new Set([
      "cohortContractSha256",
      "cohortId",
      "compiler",
      "compilerSourceEnvelopeSha256",
      "contextReuseAnalysis",
      "descriptorIdentitySha256",
      "engine",
      "entries",
      "execution",
      "kind",
      "precompilerMaterialIdentity",
      "producerImplementation",
      "routes",
      "runtimeSurfacePolicySha256",
      "scheduleSha256",
      "schemaVersion",
      "sourceEnvelopeSha256",
      "sourcePipelineSha256",
    ]),
    "module graph cohort contract"
  );
  if (
    contract.kind !== convexWasmModuleGraphCohortContractKind ||
    contract.schemaVersion !== 2 ||
    !Array.isArray(contract.entries) ||
    contract.entries.length === 0 ||
    !Array.isArray(contract.routes) ||
    contract.routes.length === 0
  ) {
    fail("contract kind, schemaVersion, entries, or routes are unsupported");
  }
  const entries = contract.entries.map(normalizeEntry);
  if (
    entries.some((entry, index) => index > 0 && entries[index - 1].entryPath >= entry.entryPath)
  ) {
    fail("cohort entries must be unique and sorted by entry path");
  }
  const entriesById = new Map(entries.map((entry) => [entry.entryId, entry]));
  if (entriesById.size !== entries.length) fail("cohort contains duplicate entry identities");
  const routes = contract.routes.map((route, index) => normalizeRoute(route, entriesById, index));
  if (
    routes.some((route, index) => index > 0 && routes[index - 1].routeId >= route.routeId) ||
    entries.some(({ entryId }) => !routes.some((route) => route.entryId === entryId))
  ) {
    fail("cohort routes must be unique, sorted, and cover every entry");
  }
  if (new Set(routes.map(({ entrySelectorId }) => entrySelectorId)).size !== routes.length) {
    fail("cohort route selector IDs must be unique");
  }
  for (const entry of entries) {
    const entryRoutes = routes.filter(({ entryId }) => entryId === entry.entryId);
    if (
      new Set(entryRoutes.map(({ exportName }) => exportName)).size !== entryRoutes.length ||
      entry.source.modulePath !== entry.entryPath ||
      entry.source.runtimeModulePath !== `${entry.modulePath}.js` ||
      entry.source.exportSha256 !== entry.localProfile.javascript.sha256 ||
      entry.source.resolvedGraphSha256 !== entry.localProfile.dependencyGraphSha256 ||
      !entryRoutes.some(
        ({ exportName, udfKind }) =>
          exportName === entry.source.exportName && udfKind === entry.source.udfKind
      )
    ) {
      fail(`cohort entry ${entry.entryPath} source identity or route table is inconsistent`);
    }
  }
  const compiler = normalizeCompiler(contract.compiler);
  const contextReuseAnalysis = authenticateConvexContextReuseCohortAnalysisIdentity(
    contract.contextReuseAnalysis,
    {
      expectedEntryGraphs: entries
        .map(({ entryPath, localProfile }) => ({
          dependencyGraphSha256: localProfile.dependencyGraphSha256,
          entryPath,
        }))
        .sort((left, right) => compareStrings(left.entryPath, right.entryPath)),
    }
  );
  if (
    compiler.sourcePipelineSha256 !==
    convexWasmCapabilitySourcePipelineSha256(entries.map(({ localProfile }) => localProfile))
  ) {
    fail("cohort compiler source-pipeline identity is invalid");
  }
  const engine = JSON.parse(
    canonicalJson(requireObject(contract.engine, "cohort engine contract"))
  );
  const precompilerMaterialIdentity = normalizePrecompilerMaterialIdentity(
    contract.precompilerMaterialIdentity,
    "cohort precompiler material identity"
  );
  if (canonicalJson(engine.package) !== canonicalJson(precompilerMaterialIdentity)) {
    fail("cohort engine and precompiler material identities disagree");
  }
  const sourcePipelineSha256 = requireSha256(
    contract.sourcePipelineSha256,
    "cohort source-pipeline SHA-256"
  );
  if (sourcePipelineSha256 !== compiler.sourcePipelineSha256) {
    fail("cohort source-pipeline and compiler identities disagree");
  }
  const payload = {
    cohortId: requireSha256(contract.cohortId, "cohort ID"),
    compiler,
    compilerSourceEnvelopeSha256: requireSha256(
      contract.compilerSourceEnvelopeSha256,
      "cohort compiler source-envelope SHA-256"
    ),
    contextReuseAnalysis,
    descriptorIdentitySha256: requireSha256(
      contract.descriptorIdentitySha256,
      "cohort descriptor identity SHA-256"
    ),
    engine,
    entries,
    execution: normalizeExecution(contract.execution, compiler),
    kind: convexWasmModuleGraphCohortContractKind,
    precompilerMaterialIdentity,
    producerImplementation: JSON.parse(
      canonicalJson(requireObject(contract.producerImplementation, "cohort producer identity"))
    ),
    routes,
    runtimeSurfacePolicySha256: normalizeRuntimeSurfacePolicySha256(
      contract.runtimeSurfacePolicySha256,
      compiler
    ),
    scheduleSha256: requireSha256(contract.scheduleSha256, "cohort schedule SHA-256"),
    schemaVersion: 2,
    sourceEnvelopeSha256: requireSha256(
      contract.sourceEnvelopeSha256,
      "cohort source-envelope SHA-256"
    ),
    sourcePipelineSha256,
  };
  const cohortContractSha256 = requireSha256(
    contract.cohortContractSha256,
    "cohort contract SHA-256"
  );
  if (cohortContractSha256 !== fingerprintJson(payload)) {
    fail("cohort contract identity is invalid");
  }
  return Object.freeze({ ...payload, cohortContractSha256 });
}

export function createConvexWasmModuleGraphCohortContract({
  cohortId,
  compilerContract,
  scheduleSha256,
  sourceEnvelopeSha256,
}) {
  const raw = requireExactKeys(
    compilerContract,
    new Set([
      "compiler",
      "contractId",
      "contextReuseAnalysis",
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
    ]),
    "compiler cohort contract"
  );
  if (
    raw.kind !== "convex-wasm-official-output-module-graph-cohort-contract-v2" ||
    raw.schemaVersion !== 2
  ) {
    fail("compiler cohort contract kind or schemaVersion is unsupported");
  }
  const { contractId, ...compilerPayload } = raw;
  if (
    requireSha256(contractId, "compiler cohort contract identity") !==
    fingerprintJson(compilerPayload)
  ) {
    fail("compiler cohort contract identity is invalid");
  }
  const payload = {
    cohortId,
    compiler: raw.compiler,
    compilerSourceEnvelopeSha256: raw.sourceEnvelopeSha256,
    contextReuseAnalysis: authenticateConvexContextReuseCohortAnalysisIdentity(
      raw.contextReuseAnalysis
    ),
    descriptorIdentitySha256: raw.descriptorIdentitySha256,
    engine: raw.engine,
    entries: [...raw.entries].sort((left, right) =>
      compareStrings(left.entryPath, right.entryPath)
    ),
    execution: raw.execution,
    kind: convexWasmModuleGraphCohortContractKind,
    precompilerMaterialIdentity: raw.precompilerMaterialIdentity,
    producerImplementation: raw.producerImplementation,
    routes: [...raw.routes].sort((left, right) => compareStrings(left.routeId, right.routeId)),
    runtimeSurfacePolicySha256: raw.runtimeSurfacePolicySha256,
    scheduleSha256,
    schemaVersion: 2,
    sourceEnvelopeSha256,
    sourcePipelineSha256: raw.sourcePipelineSha256,
  };
  return validateConvexWasmModuleGraphCohortContract({
    ...payload,
    cohortContractSha256: fingerprintJson(payload),
  });
}
