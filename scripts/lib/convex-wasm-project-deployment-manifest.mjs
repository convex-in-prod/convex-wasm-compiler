import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "./convex-wasm-compiler-contract.mjs";
import { convexWasmDeploymentDirectArtifactHandoffIdentity } from "./convex-wasm-deployment-artifact-semantics.mjs";
import {
  convexWasmModuleGraphRouteReferenceKind,
  validateConvexWasmModuleGraphCohortContract,
} from "./convex-wasm-module-graph-cohort-contract.mjs";
import {
  convexWasmSourceEnvelopeKind,
  validateConvexWasmSourceEnvelope,
} from "./convex-wasm-source-envelope.mjs";

function fail(message) {
  throw new Error(`Convex Wasm project deployment: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireExactKeys(value, expectedKeys, description) {
  const keys = Object.keys(requireObject(value, description)).sort(compareStrings);
  const expected = [...expectedKeys].sort(compareStrings);
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    fail(`${description} fields are invalid`);
  }
  return value;
}
function bindFrozenGraphIdentityToDeploymentPolicy(
  policyValue,
  frozenGraphBindingIdentity,
  selectedSourceEnvelopeIdentity
) {
  if (
    (frozenGraphBindingIdentity === undefined || frozenGraphBindingIdentity === null) &&
    selectedSourceEnvelopeIdentity === undefined
  ) {
    return policyValue;
  }
  const policy = requireObject(policyValue, "deployment policy");
  const identity = requireObject(policy.identity, "deployment policy identity");
  if (requireSha256(policy.sha256, "deployment policy SHA-256") !== fingerprintJson(identity)) {
    fail("deployment policy digest is invalid before frozen-graph binding");
  }
  const normalizedBindingIdentity =
    frozenGraphBindingIdentity === undefined || frozenGraphBindingIdentity === null
      ? undefined
      : requireExactKeys(
          frozenGraphBindingIdentity,
          new Set(["kind", "sha256"]),
          "frozen-graph binding identity"
        );
  if (
    normalizedBindingIdentity !== undefined &&
    normalizedBindingIdentity.kind !== "convex-isolated-full-frozen-graph-binding-v1"
  ) {
    fail("frozen-graph binding identity kind is invalid");
  }
  const normalizedSelectedSourceEnvelopeIdentity =
    selectedSourceEnvelopeIdentity === undefined
      ? undefined
      : requireExactKeys(
          selectedSourceEnvelopeIdentity,
          new Set(["kind", "sha256"]),
          "selected source-envelope identity"
        );
  if (
    normalizedSelectedSourceEnvelopeIdentity !== undefined &&
    normalizedSelectedSourceEnvelopeIdentity.kind !== convexWasmSourceEnvelopeKind
  ) {
    fail("selected source-envelope identity kind is invalid");
  }
  const boundIdentity = {
    ...identity,
    ...(normalizedBindingIdentity === undefined
      ? {}
      : {
          frozenGraphBindingIdentity: {
            kind: normalizedBindingIdentity.kind,
            sha256: requireSha256(
              normalizedBindingIdentity.sha256,
              "frozen-graph binding identity SHA-256"
            ),
          },
        }),
    ...(normalizedSelectedSourceEnvelopeIdentity === undefined
      ? {}
      : {
          selectedSourceEnvelopeIdentity: {
            kind: normalizedSelectedSourceEnvelopeIdentity.kind,
            sha256: requireSha256(
              normalizedSelectedSourceEnvelopeIdentity.sha256,
              "selected source-envelope identity SHA-256"
            ),
          },
        }),
  };
  return { ...policy, identity: boundIdentity, sha256: fingerprintJson(boundIdentity) };
}

function sourceEnvelopeBaseManifest(envelope, precompilerMaterialIdentity) {
  const dependencyGraphBySelectedRoute = new Map(
    envelope.selectedRoutes.map(({ dependencyGraphSha256, exportName, runtimeModulePath }) => [
      `${runtimeModulePath}:${exportName}`,
      dependencyGraphSha256,
    ])
  );
  // Artifact-semantic edits to this direct handoff require a matching direct revision bump in the
  // non-operational deployment artifact-semantics module.
  const policyIdentity = {
    artifactHandoff: convexWasmDeploymentDirectArtifactHandoffIdentity,
    kind: "convex-wasm-source-envelope-promotion-policy-v1",
    sourceEnvelopeSha256: envelope.sourceEnvelopeSha256,
  };
  return {
    artifactPrecompiler: { materialIdentity: precompilerMaterialIdentity },
    compileSelection: { kind: "convex-wasm-explicit-capability-entry-selection-v1" },
    compiler: { kind: "not-analyzed" },
    counts: {},
    diagnosticCensus: [],
    existingRuntimeActions: envelope.actions.map(
      ({ entryPath, exportName, runtimeModulePath, udfKind, visibility }) => ({
        entryPath,
        exportName,
        runtimeModulePath,
        routing: { decision: "existingRuntime", reason: "action-runtime" },
        udfKind,
        visibility,
      })
    ),
    exports: envelope.routes.map((route) => {
      const dependencyGraphSha256 = dependencyGraphBySelectedRoute.get(
        `${route.runtimeModulePath}:${route.exportName}`
      );
      return {
        artifact: null,
        compiler: { kind: "not-analyzed" },
        dependencies: {},
        ...(dependencyGraphSha256 === undefined ? {} : { dependencyGraphSha256 }),
        diagnosticCensusIds: [],
        diagnostics: [],
        entryPath: route.entryPath,
        exportName: route.exportName,
        packageReference: null,
        routing: {
          decision: "existingRuntime",
          reason: dependencyGraphSha256 === undefined ? "not-analyzed" : "not-selected",
        },
        runtimeModulePath: route.runtimeModulePath,
        source: {
          exportName: route.exportName,
          modulePath: route.entryPath,
          udfKind: route.udfKind,
        },
        sourceCrossCheck: null,
        udfKind: route.udfKind,
        visibility: route.visibility,
      };
    }),
    contextReuseAnalysis: envelope.contextReuseAnalysis,
    graph: envelope.graph,
    inventoryAuthority: envelope.inventoryAuthority,
    kind: convexWasmSourceEnvelopeKind,
    mode: "compile",
    policy: { identity: policyIdentity, sha256: fingerprintJson(policyIdentity) },
    sourceInventory: {
      graphSha256: envelope.graph.sha256,
      kind: "convex-wasm-source-envelope-inventory-v1",
    },
  };
}

export function createConvexWasmModuleGraphDeploymentInputManifest({
  baseManifest: rawBaseManifest,
  cohortContracts: rawCohortContracts,
  contextReuseAnalysisIdentity: rawContextReuseAnalysisIdentity,
  contextReusePolicy: rawContextReusePolicy,
  deployedRuntimeBindings,
  frozenGraphBindingIdentity,
  selectedSourceEnvelopeIdentity,
}) {
  const sourceEnvelope = validateConvexWasmSourceEnvelope(rawBaseManifest);
  if (!Array.isArray(rawCohortContracts) || rawCohortContracts.length === 0) {
    fail("module graph deployment requires at least one cohort contract");
  }
  if (!(deployedRuntimeBindings instanceof Map)) {
    fail("module graph deployment deployedRuntimeBindings must be a Map");
  }
  const contracts = rawCohortContracts.map(validateConvexWasmModuleGraphCohortContract);
  const expectedPrecompiler = contracts[0].precompilerMaterialIdentity;
  if (
    contracts.some(
      (contract) =>
        canonicalJson(contract.precompilerMaterialIdentity) !== canonicalJson(expectedPrecompiler)
    )
  ) {
    fail("module graph cohort contracts use different precompiler identities");
  }
  const baseManifest = sourceEnvelopeBaseManifest(sourceEnvelope, expectedPrecompiler);
  const selectedByKey = new Map();
  for (const contract of contracts) {
    const entriesById = new Map(contract.entries.map((entry) => [entry.entryId, entry]));
    for (const route of contract.routes) {
      const entry = entriesById.get(route.entryId);
      if (entry === undefined) fail("module graph cohort route selects an unknown entry");
      const key = `${entry.modulePath}.js:${route.exportName}`;
      if (selectedByKey.has(key)) fail(`module graph cohort contracts repeat route ${key}`);
      selectedByKey.set(key, { contract, entry, route });
    }
  }
  if (rawContextReusePolicy === undefined) {
    fail("module graph deployment requires a context-reuse policy");
  }
  let contextReusePolicyIdentity;
  let contextReuseAnalysisIdentity;
  {
    const policy = requireObject(rawContextReusePolicy, "module graph context-reuse policy");
    const { sha256, ...payload } = policy;
    if (
      policy.kind !== "convex-wasm-context-reuse-selection" ||
      requireSha256(sha256, "module graph context-reuse policy SHA-256") !==
        fingerprintJson(payload) ||
      !Array.isArray(policy.entries)
    ) {
      fail("module graph context-reuse policy identity is invalid");
    }
    const enabledByEntry = new Map(policy.entries.map((entry) => [entry.entryPath, entry.enabled]));
    for (const { entry } of selectedByKey.values()) {
      if (enabledByEntry.get(entry.entryPath) !== true) {
        fail(`selected module graph entry ${entry.entryPath} is not context-reuse enabled`);
      }
    }
    const candidateAnalysisIdentity =
      rawContextReuseAnalysisIdentity ?? sourceEnvelope.contextReuseAnalysis;
    if (candidateAnalysisIdentity === undefined) {
      fail("module graph context-reuse admission has no complete analysis identity");
    }
    const enabledEntries = [
      ...new Map(policy.entries.map((entry) => [entry.entryPath, entry.enabled])),
    ]
      .filter(([, enabled]) => enabled)
      .map(([entryPath]) => entryPath)
      .sort(compareStrings);
    contextReuseAnalysisIdentity = authenticateConvexContextReuseResultIdentity(
      candidateAnalysisIdentity,
      { expectedEntries: enabledEntries }
    );
    const analyzedEntries = new Set(contextReuseAnalysisIdentity.entries);
    const cohortAnalysisIdentities = contracts.map((contract) =>
      authenticateConvexContextReuseCohortAnalysisIdentity(contract.contextReuseAnalysis)
    );
    const sharedAnalysisSha256 = cohortAnalysisIdentities[0].sharedAnalysisSha256;
    if (
      cohortAnalysisIdentities.some(
        (analysis) =>
          analysis.policyFingerprint !== contextReuseAnalysisIdentity.policyFingerprint ||
          analysis.sharedAnalysisSha256 !== sharedAnalysisSha256 ||
          analysis.entries.some((entryPath) => !analyzedEntries.has(entryPath))
      )
    ) {
      fail("module graph cohort analysis identity disagrees with graph admission");
    }
    if (
      canonicalJson(contextReuseAnalysisIdentity) !==
      canonicalJson(sourceEnvelope.contextReuseAnalysis)
    ) {
      fail("module graph analysis identity disagrees with its source envelope");
    }
    contextReusePolicyIdentity = { kind: policy.kind, sha256 };
  }
  const matched = new Set();
  const exports = baseManifest.exports.map((baseExport) => {
    const key = `${baseExport.runtimeModulePath}:${baseExport.exportName}`;
    const selected = selectedByKey.get(key);
    if (selected === undefined) return baseExport;
    const { contract, entry, route } = selected;
    if (
      baseExport.entryPath !== entry.entryPath ||
      baseExport.udfKind !== route.udfKind ||
      baseExport.visibility !== route.visibility ||
      baseExport.dependencyGraphSha256 !== entry.localProfile.dependencyGraphSha256
    ) {
      fail(`source envelope route ${key} disagrees with its module graph cohort contract`);
    }
    const binding = deployedRuntimeBindings.get(baseExport.runtimeModulePath);
    if (binding?.identity === null || binding?.identity === undefined) {
      fail(`module graph route ${key} has no bound deployed-runtime identity`);
    }
    matched.add(key);
    return {
      ...baseExport,
      artifact: { cohortContractSha256: contract.cohortContractSha256 },
      compiler: contract.compiler,
      compilerLimits: contract.execution.platformLimits,
      dependencyGraphSha256: entry.localProfile.dependencyGraphSha256,
      packageReference: {
        cohortContractSha256: contract.cohortContractSha256,
        entryId: entry.entryId,
        entrySelectorId: route.entrySelectorId,
        kind: convexWasmModuleGraphRouteReferenceKind,
        routeId: route.routeId,
      },
      routing: { decision: "wasm", reason: "runtimeCapability" },
      source: {
        deployedRuntimeIdentity: binding.identity,
        exportName: route.exportName,
        exportSha256: entry.localProfile.javascript.sha256,
        modulePath: entry.entryPath,
        resolvedGraphSha256: entry.localProfile.dependencyGraphSha256,
        udfKind: route.udfKind,
      },
    };
  });
  if (matched.size !== selectedByKey.size) {
    fail("source envelope does not cover every module graph cohort route");
  }
  const selectedWasm = matched.size;
  const artifactFallback = exports.filter(
    (entry) =>
      entry.routing?.decision === "v8Fallback" &&
      entry.routing.reason === "static-hermes-source-incompatibility-v1"
  ).length;
  const unselectedEligible = exports.filter(
    (entry) =>
      entry.routing?.decision === "existingRuntime" && entry.routing.reason === "not-selected"
  ).length;
  const counts = {
    actionsOnExistingRuntime: baseManifest.existingRuntimeActions.length,
    artifactFallback,
    eligible: selectedWasm + artifactFallback + unselectedEligible,
    ineligible: exports.length - selectedWasm - artifactFallback - unselectedEligible,
    mutations: exports.filter((entry) => entry.udfKind === "mutation").length,
    queries: exports.filter((entry) => entry.udfKind === "query").length,
    selectedWasm,
    total: exports.length,
    unselectedEligible,
  };
  const { effectExecutionMode: ignoredEffectExecutionMode, ...baseWithoutExecutionMode } =
    baseManifest;
  const manifestWithoutIdentity = {
    ...baseWithoutExecutionMode,
    compileSelection: {
      exports: [...selectedByKey.values()]
        .map(({ entry, route }) => ({ entryPath: entry.entryPath, exportName: route.exportName }))
        .sort((left, right) => {
          const entryOrder = compareStrings(left.entryPath, right.entryPath);
          return entryOrder === 0 ? compareStrings(left.exportName, right.exportName) : entryOrder;
        }),
      kind: "convex-wasm-explicit-capability-entry-selection-v1",
    },
    counts,
    contextReuseAnalysis: contextReuseAnalysisIdentity,
    contextReusePolicyIdentity,
    effectExecutionMode: convexWasmGuestPromiseEffectExecutionMode,
    exports,
    kind: "convex-wasm-deployment-v7",
    policy: bindFrozenGraphIdentityToDeploymentPolicy(
      baseWithoutExecutionMode.policy,
      frozenGraphBindingIdentity,
      selectedSourceEnvelopeIdentity
    ),
  };
  return {
    ...manifestWithoutIdentity,
    deploymentSha256: fingerprintJson(manifestWithoutIdentity),
  };
}
