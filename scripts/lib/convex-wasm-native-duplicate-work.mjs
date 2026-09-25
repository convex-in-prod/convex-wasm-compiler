import {
  assertPlainObject,
  canonicalJson,
  fail,
  fingerprintJson,
  normalizeJson,
  requireBoolean,
  requireEnum,
  requireExactPlainObject,
  requirePositiveInteger,
  requireSha256,
  requireString,
  requireStringArray,
} from "./convex-wasm-artifact-contract.mjs";
import {
  C_COMPILER_OPTIMIZATION_FLAG_PATTERN,
  convexWasmStaticHermesCBundleMemberCompilationPolicy,
  normalizeStaticHermesCBundleMember,
  staticHermesCBundleMemberCompilationBaselinePolicy,
} from "./convex-wasm-static-hermes-c-bundle.mjs";

export const convexWasmNativeMemberObjectInputKind = "convex-wasm-native-member-object-input-v1";
export const convexWasmNativeMemberDuplicateWorkReportKind =
  "convex-wasm-native-member-duplicate-work-report-v2";
// A member timing can be shared by every output of one multi-input compiler process. The batch
// identity is telemetry-only; it never participates in the member CAS key.
export const convexWasmNativeMemberBatchTimingKind = "convex-wasm-native-member-batch-timing-v1";

const MEMBER_OBJECT_IDENTITY_KIND = "convex-wasm-static-hermes-c-bundle-member-object-v1";
const MEMBER_OBJECT_STAGE = "static-hermes-c-bundle-member-object";
const RUNTIME_PRELUDE_PCH_PATH = "static-hermes-runtime-prelude.pch";
const RUNTIME_PRELUDE_PCH_STAGE = "static-hermes-runtime-prelude-pch";
const SUPPORTED_MEMBER_COMPILATION_POLICIES = new Set(
  [
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    staticHermesCBundleMemberCompilationBaselinePolicy,
  ].map((policy) => canonicalJson(policy))
);

function requireNonNegativeFiniteNumber(value, description) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    fail(`${description} must be a non-negative finite number`);
  }
  return value;
}

function normalizeMemberObjectIdentity(value, description) {
  requireExactPlainObject(
    value,
    [
      "compilation",
      "emscripten",
      "generatedC",
      "kind",
      "nativeArtifactIdentitySchemaVersion",
      "runtimeHeaders",
      ...(value.runtimePreludePch === undefined ? [] : ["runtimePreludePch"]),
      "semanticEnvironment",
    ],
    description
  );
  if (value.kind !== MEMBER_OBJECT_IDENTITY_KIND) {
    fail(`${description}.kind is unsupported`);
  }
  requirePositiveInteger(
    value.nativeArtifactIdentitySchemaVersion,
    `${description}.nativeArtifactIdentitySchemaVersion`
  );
  requireExactPlainObject(
    value.compilation,
    ["arguments", "executable", "memberCompilationPolicy", "optimization"],
    `${description}.compilation`
  );
  requireStringArray(value.compilation.arguments, `${description}.compilation.arguments`);
  requireString(value.compilation.executable, `${description}.compilation.executable`);
  const memberCompilationPolicy = value.compilation.memberCompilationPolicy;
  requireExactPlainObject(
    memberCompilationPolicy,
    ["cOptimizationLevelZero", "kind", "largeFunctionMember", "normalOptimizationFlag"],
    `${description}.compilation.memberCompilationPolicy`
  );
  requireExactPlainObject(
    memberCompilationPolicy.cOptimizationLevelZero,
    ["cOptimizationLevel", "functionCount", "optimizationFlag", "role", "stage"],
    `${description}.compilation.memberCompilationPolicy.cOptimizationLevelZero`
  );
  if (memberCompilationPolicy.cOptimizationLevelZero.cOptimizationLevel !== 0) {
    fail(`${description}.compilation.memberCompilationPolicy.cOptimizationLevelZero is invalid`);
  }
  requirePositiveInteger(
    memberCompilationPolicy.cOptimizationLevelZero.functionCount,
    `${description}.compilation.memberCompilationPolicy.cOptimizationLevelZero.functionCount`
  );
  for (const field of ["optimizationFlag", "role", "stage"]) {
    requireString(
      memberCompilationPolicy.cOptimizationLevelZero[field],
      `${description}.compilation.memberCompilationPolicy.cOptimizationLevelZero.${field}`
    );
  }
  requireExactPlainObject(
    memberCompilationPolicy.largeFunctionMember,
    ["appliesToFunctionFragments", "minimumMemberBytes", "optimizationFlag", "role"],
    `${description}.compilation.memberCompilationPolicy.largeFunctionMember`
  );
  if (
    requireBoolean(
      memberCompilationPolicy.largeFunctionMember.appliesToFunctionFragments,
      `${description}.compilation.memberCompilationPolicy.largeFunctionMember.appliesToFunctionFragments`
    )
  ) {
    fail(
      `${description}.compilation.memberCompilationPolicy.largeFunctionMember must exclude function fragments`
    );
  }
  requirePositiveInteger(
    memberCompilationPolicy.largeFunctionMember.minimumMemberBytes,
    `${description}.compilation.memberCompilationPolicy.largeFunctionMember.minimumMemberBytes`
  );
  requireString(
    memberCompilationPolicy.largeFunctionMember.optimizationFlag,
    `${description}.compilation.memberCompilationPolicy.largeFunctionMember.optimizationFlag`
  );
  requireString(
    memberCompilationPolicy.largeFunctionMember.role,
    `${description}.compilation.memberCompilationPolicy.largeFunctionMember.role`
  );
  requireString(
    memberCompilationPolicy.kind,
    `${description}.compilation.memberCompilationPolicy.kind`
  );
  if (memberCompilationPolicy.kind !== "convex-wasm-static-hermes-c-bundle-member-compilation-v4") {
    fail(`${description}.compilation.memberCompilationPolicy.kind is unsupported`);
  }
  requireString(
    memberCompilationPolicy.normalOptimizationFlag,
    `${description}.compilation.memberCompilationPolicy.normalOptimizationFlag`
  );
  if (!SUPPORTED_MEMBER_COMPILATION_POLICIES.has(canonicalJson(memberCompilationPolicy))) {
    fail(`${description}.compilation.memberCompilationPolicy is unsupported`);
  }
  const optimization = requireString(
    value.compilation.optimization,
    `${description}.compilation.optimization`
  );
  requireExactPlainObject(
    value.emscripten,
    ["llvmRevision", "materials", "revision"],
    `${description}.emscripten`
  );
  requireString(value.emscripten.llvmRevision, `${description}.emscripten.llvmRevision`);
  requireSha256(value.emscripten.materials, `${description}.emscripten.materials`);
  requireString(value.emscripten.revision, `${description}.emscripten.revision`);
  requireExactPlainObject(value.generatedC, ["header", "member"], `${description}.generatedC`);
  const header = normalizeStaticHermesCBundleMember(
    value.generatedC.header,
    `${description}.generatedC.header`
  );
  const member = normalizeStaticHermesCBundleMember(
    value.generatedC.member,
    `${description}.generatedC.member`
  );
  if (header.role !== "header" || member.role === "header" || header.path === member.path) {
    fail(`${description}.generatedC does not identify a header and distinct translation unit`);
  }
  // Member-local size and the producer's explicit -O0 marker determine the effective flag.
  const expectedOptimization =
    member.cOptimizationLevel === memberCompilationPolicy.cOptimizationLevelZero.cOptimizationLevel
      ? memberCompilationPolicy.cOptimizationLevelZero.optimizationFlag
      : member.role === memberCompilationPolicy.largeFunctionMember.role &&
          member.functionFragmentCount === undefined &&
          member.size >= memberCompilationPolicy.largeFunctionMember.minimumMemberBytes
        ? memberCompilationPolicy.largeFunctionMember.optimizationFlag
        : memberCompilationPolicy.normalOptimizationFlag;
  if (optimization !== expectedOptimization) {
    fail(`${description}.compilation.optimization is unsupported for its generated-C member`);
  }
  const effectiveOptimizationFlags = value.compilation.arguments.filter((argument) =>
    C_COMPILER_OPTIMIZATION_FLAG_PATTERN.test(argument)
  );
  if (effectiveOptimizationFlags.length !== 1 || effectiveOptimizationFlags[0] !== optimization) {
    fail(`${description}.compilation arguments and optimization disagree`);
  }
  requireSha256(value.runtimeHeaders, `${description}.runtimeHeaders`);
  const includePchIndex = value.compilation.arguments.indexOf("-include-pch");
  if (value.runtimePreludePch !== undefined) {
    requireExactPlainObject(
      value.runtimePreludePch,
      ["cacheKey", "stage"],
      `${description}.runtimePreludePch`
    );
    requireSha256(value.runtimePreludePch.cacheKey, `${description}.runtimePreludePch.cacheKey`);
    if (value.runtimePreludePch.stage !== RUNTIME_PRELUDE_PCH_STAGE) {
      fail(`${description}.runtimePreludePch.stage is unsupported`);
    }
    if (
      includePchIndex < 0 ||
      value.compilation.arguments[includePchIndex + 1] !== RUNTIME_PRELUDE_PCH_PATH ||
      value.compilation.arguments.indexOf("-include-pch", includePchIndex + 1) >= 0
    ) {
      fail(`${description}.runtimePreludePch does not match its compilation arguments`);
    }
  } else if (includePchIndex >= 0) {
    fail(`${description}.compilation arguments have no runtimePreludePch identity`);
  }
  assertPlainObject(value.semanticEnvironment, `${description}.semanticEnvironment`);
  for (const [name, environmentValue] of Object.entries(value.semanticEnvironment)) {
    requireString(name, `${description}.semanticEnvironment key`);
    requireString(environmentValue, `${description}.semanticEnvironment.${name}`);
  }
  return normalizeJson(value, description);
}

export function createConvexWasmNativeMemberObjectInput({
  cacheKey,
  identity,
  pipelineKind,
  stage,
}) {
  requireSha256(cacheKey, "native member object input cacheKey");
  requireString(pipelineKind, "native member object input pipelineKind");
  if (stage !== MEMBER_OBJECT_STAGE) {
    fail("native member object input stage is unsupported");
  }
  const normalizedIdentity = normalizeMemberObjectIdentity(
    identity,
    "native member object input identity"
  );
  const expectedCacheKey = fingerprintJson({
    identity: normalizedIdentity,
    kind: pipelineKind,
    stage,
  });
  if (cacheKey !== expectedCacheKey) {
    fail("native member object input cacheKey does not authenticate its identity");
  }
  return {
    cacheKey,
    identity: normalizedIdentity,
    kind: convexWasmNativeMemberObjectInputKind,
    pipelineKind,
    stage,
  };
}

function normalizeTiming(value, description) {
  assertPlainObject(value, description);
  return {
    systemCpuMilliseconds: requireNonNegativeFiniteNumber(
      value.systemCpuMilliseconds,
      `${description}.systemCpuMilliseconds`
    ),
    userCpuMilliseconds: requireNonNegativeFiniteNumber(
      value.userCpuMilliseconds,
      `${description}.userCpuMilliseconds`
    ),
    wallMilliseconds: requireNonNegativeFiniteNumber(
      value.wallMilliseconds,
      `${description}.wallMilliseconds`
    ),
  };
}

function normalizeMemberObjectWork(value, description) {
  assertPlainObject(value, description);
  const keys = ["authenticatedInput", "cache", "member", "optimization", "stage", "timing"];
  if (Object.hasOwn(value, "batch")) keys.push("batch");
  requireExactPlainObject(value, keys, description);
  const cache = requireEnum(value.cache, new Set(["hit", "miss"]), `${description}.cache`);
  const authenticatedInput = createConvexWasmNativeMemberObjectInput({
    ...value.authenticatedInput,
  });
  assertPlainObject(value.member, `${description}.member`);
  const authenticatedMember = { ...authenticatedInput.identity.generatedC.member };
  delete authenticatedMember.sha256;
  delete authenticatedMember.size;
  if (canonicalJson(value.member) !== canonicalJson(authenticatedMember)) {
    fail(`${description}.member disagrees with its authenticated generated-C input`);
  }
  const optimization = requireString(value.optimization, `${description}.optimization`);
  if (optimization !== authenticatedInput.identity.compilation.optimization) {
    fail(`${description}.optimization disagrees with its authenticated compilation`);
  }
  requireString(value.stage, `${description}.stage`);
  if (cache === "hit" && value.timing !== null) {
    fail(`${description} cache hit must not report native timing`);
  }
  if (cache === "miss" && value.timing === null) {
    fail(`${description} cache miss must report native timing`);
  }
  const timing =
    value.timing === null ? null : normalizeTiming(value.timing, `${description}.timing`);
  let batch;
  if (Object.hasOwn(value, "batch")) {
    requireExactPlainObject(
      value.batch,
      ["id", "kind", "memberCacheKeys", "memberCount", "timing"],
      `${description}.batch`
    );
    if (
      value.batch.kind !== convexWasmNativeMemberBatchTimingKind ||
      typeof value.batch.id !== "string" ||
      !/^[0-9a-f]{32}$/u.test(value.batch.id)
    ) {
      fail(`${description}.batch has an unsupported identity`);
    }
    const memberCount = requirePositiveInteger(
      value.batch.memberCount,
      `${description}.batch.memberCount`
    );
    if (memberCount > 4) {
      fail(`${description}.batch.memberCount must be at most four`);
    }
    if (
      !Array.isArray(value.batch.memberCacheKeys) ||
      value.batch.memberCacheKeys.length !== memberCount
    ) {
      fail(`${description}.batch.memberCacheKeys must match memberCount`);
    }
    let previousCacheKey;
    for (const [index, cacheKey] of value.batch.memberCacheKeys.entries()) {
      requireSha256(cacheKey, `${description}.batch.memberCacheKeys[${String(index)}]`);
      if (previousCacheKey !== undefined && previousCacheKey >= cacheKey) {
        fail(`${description}.batch.memberCacheKeys must be sorted and unique`);
      }
      previousCacheKey = cacheKey;
    }
    if (!value.batch.memberCacheKeys.includes(authenticatedInput.cacheKey)) {
      fail(`${description}.batch does not contain its authenticated input`);
    }
    const batchTiming = normalizeTiming(value.batch.timing, `${description}.batch.timing`);
    if (timing !== null && canonicalJson(batchTiming) !== canonicalJson(timing)) {
      fail(`${description}.batch timing disagrees with its member timing`);
    }
    batch = {
      id: value.batch.id,
      kind: value.batch.kind,
      memberCacheKeys: [...value.batch.memberCacheKeys],
      memberCount,
      timing: batchTiming,
    };
  }
  return {
    authenticatedInput,
    batch,
    cache,
    timing,
  };
}

function sumTiming(records, field) {
  return records.reduce((total, { timing }) => total + timing[field], 0);
}

export function analyzeConvexWasmNativeMemberObjectWork(rawWork) {
  if (!Array.isArray(rawWork)) {
    fail("native member object work must be an array");
  }
  const work = rawWork.map((value, index) =>
    normalizeMemberObjectWork(value, `native member object work[${String(index)}]`)
  );
  const groups = Map.groupBy(work, ({ authenticatedInput }) => authenticatedInput.cacheKey);
  // A batched process reports the same resource timing on each member slot. Collapse those slots
  // by the process identity before counting or summing native work. Legacy records without batch
  // metadata remain one process each, so this stays compatible with pre-batching reports.
  const nativeBatchGroups = new Map();
  for (const [index, record] of work.entries()) {
    if (record.batch === undefined && record.timing === null) continue;
    const batchId = record.batch?.id ?? `legacy-${String(index)}`;
    const memberCacheKeys = record.batch?.memberCacheKeys ?? [record.authenticatedInput.cacheKey];
    const timing = record.batch?.timing ?? record.timing;
    const prior = nativeBatchGroups.get(batchId);
    if (prior === undefined) {
      nativeBatchGroups.set(batchId, {
        batchId,
        memberCacheKeys,
        records: [record],
        timing,
      });
      continue;
    }
    if (
      canonicalJson(prior.memberCacheKeys) !== canonicalJson(memberCacheKeys) ||
      canonicalJson(prior.timing) !== canonicalJson(timing)
    ) {
      fail(`native member batch ${batchId} has conflicting members or timing`);
    }
    if (prior.records.length >= (record.batch?.memberCount ?? 1)) {
      fail(`native member batch ${batchId} contains too many member records`);
    }
    prior.records.push(record);
  }
  for (const { batchId, memberCacheKeys, records } of nativeBatchGroups.values()) {
    const observedMemberCacheKeys = records
      .map(({ authenticatedInput }) => authenticatedInput.cacheKey)
      .sort();
    if (canonicalJson(observedMemberCacheKeys) !== canonicalJson(memberCacheKeys)) {
      fail(`native member batch ${batchId} does not exactly cover its declared members`);
    }
  }
  const nativeBatches = [...nativeBatchGroups.values()];
  const duplicateGroups = [];
  const nativeCompilationCount = nativeBatches.length;
  const nativeSystemCpuMilliseconds = sumTiming(nativeBatches, "systemCpuMilliseconds");
  const nativeUserCpuMilliseconds = sumTiming(nativeBatches, "userCpuMilliseconds");
  const nativeWallMilliseconds = sumTiming(nativeBatches, "wallMilliseconds");
  let removableNativeCompilationCount = 0;
  let removableSystemCpuMilliseconds = 0;
  let removableUserCpuMilliseconds = 0;
  let removableWallMilliseconds = 0;

  for (const [cacheKey, records] of groups) {
    const identity = canonicalJson(records[0].authenticatedInput.identity);
    if (
      records.some(
        ({ authenticatedInput }) => canonicalJson(authenticatedInput.identity) !== identity
      )
    ) {
      fail(`native member object work cache key ${cacheKey} has conflicting identities`);
    }
  }
  const nativeBatchesByMembers = Map.groupBy(nativeBatches, ({ memberCacheKeys }) =>
    canonicalJson(memberCacheKeys)
  );
  for (const [memberCacheKeysJson, batches] of nativeBatchesByMembers) {
    if (batches.length < 2) continue;
    const removable = {
      nativeCompilationCount: batches.length - 1,
      systemCpuMilliseconds:
        sumTiming(batches, "systemCpuMilliseconds") -
        Math.min(...batches.map(({ timing }) => timing.systemCpuMilliseconds)),
      userCpuMilliseconds:
        sumTiming(batches, "userCpuMilliseconds") -
        Math.min(...batches.map(({ timing }) => timing.userCpuMilliseconds)),
      wallMilliseconds:
        sumTiming(batches, "wallMilliseconds") -
        Math.min(...batches.map(({ timing }) => timing.wallMilliseconds)),
    };
    removableNativeCompilationCount += removable.nativeCompilationCount;
    removableSystemCpuMilliseconds += removable.systemCpuMilliseconds;
    removableUserCpuMilliseconds += removable.userCpuMilliseconds;
    removableWallMilliseconds += removable.wallMilliseconds;
    const memberCacheKeys = JSON.parse(memberCacheKeysJson);
    duplicateGroups.push({
      authenticatedInputCacheKeys: memberCacheKeys,
      nativeCompilationCount: batches.length,
      requestCount: batches.reduce((count, { records }) => count + records.length, 0),
      removable,
    });
  }

  const cacheHitCount = work.filter(({ cache }) => cache === "hit").length;
  return {
    kind: convexWasmNativeMemberDuplicateWorkReportKind,
    summary: {
      authenticatedInputCount: groups.size,
      cacheHitCount,
      cacheMissCount: work.length - cacheHitCount,
      nativeCompilationCount,
      requestCount: work.length,
    },
    exactReusableNativeWorkCeiling: {
      nativeCompilationCount: removableNativeCompilationCount,
      systemCpuMilliseconds: removableSystemCpuMilliseconds,
      userCpuMilliseconds: removableUserCpuMilliseconds,
      wallMilliseconds: removableWallMilliseconds,
    },
    duplicateGroups: duplicateGroups.sort((left, right) =>
      canonicalJson(left.authenticatedInputCacheKeys).localeCompare(
        canonicalJson(right.authenticatedInputCacheKeys)
      )
    ),
    observedNativeWork: {
      systemCpuMilliseconds: nativeSystemCpuMilliseconds,
      userCpuMilliseconds: nativeUserCpuMilliseconds,
      wallMilliseconds: nativeWallMilliseconds,
    },
  };
}
