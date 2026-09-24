import assert from "node:assert/strict";
import test from "node:test";

import {
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmCapabilitySourcePipelineSha256,
  createConvexWasmCapabilityRequestEnvelopeIdentity,
  createConvexWasmGuestNativeJsonCodecIdentity,
} from "./convex-wasm-capability-identity.mjs";
import { convexWasmCapabilityOfficialWrapperInvocationAbi } from "./convex-wasm-selector-source.mjs";
import {
  bindConvexWasmModuleGraphsToDeploymentManifest,
  convexWasmModuleGraphDeploymentBindingKind,
  convexWasmModuleGraphDeploymentManifestKind,
  createConvexWasmModuleGraphDeploymentBinding,
  validateConvexWasmModuleGraphDeploymentManifest,
} from "./convex-wasm-module-graph-deployment-binding.mjs";
import { createConvexWasmOfficialOutputCohortSchedule } from "./convex-wasm-official-output-cohort-schedule.mjs";
import { convexWasmSourceEnvelopeKind } from "./convex-wasm-source-envelope.mjs";
import {
  convexWasmTargetRuntimeSurfacePolicyIdentity,
  convexWasmTargetRuntimeSurfacePolicySha256,
} from "./convex-wasm-runtime-surface.mjs";

const CAPABILITY_ENTRY_ROUTE_REFERENCE_KIND = "convex-wasm-capability-entry-route-reference-v1";

function createConvexContextReuseCohortAnalysisIdentity({
  analysisIdentity,
  entryGraphs,
  sharedAnalysisIdentity,
  thirdPartyMaterialFingerprints,
}) {
  const payload = {
    entries: entryGraphs.map(({ entryPath }) => entryPath),
    entryGraphSha256s: entryGraphs.map(({ dependencyGraphSha256 }) => dependencyGraphSha256),
    kind: "convex-context-reuse-cohort-analysis",
    policyFingerprint: analysisIdentity.policyFingerprint,
    sharedAnalysisSha256: sharedAnalysisIdentity.sha256,
    thirdPartyMaterialFingerprints,
  };
  return { ...payload, resultSha256: fingerprintJson(payload) };
}

function sourceEnvelope({ authorityRevision = 1, changedEntryIndex, entryCount = 9 } = {}) {
  const routes = Array.from({ length: entryCount }, (_, index) => {
    const suffix = String(index).padStart(2, "0");
    return {
      entryPath: `convex/entry${suffix}.ts`,
      exportName: `route${suffix}`,
      modulePath: `entry${suffix}`,
      runtimeModulePath: `entry${suffix}.js`,
      udfKind: index % 2 === 0 ? "query" : "mutation",
      visibility: index % 3 === 0 ? "internal" : "public",
    };
  });
  const contextReuseAnalysis = {
    entries: routes.map(({ entryPath }) => entryPath).sort(),
    kind: "convex-context-reuse-analysis",
    policyFingerprint: fingerprintJson({ fixtureContextReusePolicy: true }),
    resultSha256: fingerprintJson({ fixtureContextReuseResult: routes }),
  };
  const payload = {
    actions: [],
    contextReuseAnalysis,
    entryPaths: routes.map(({ entryPath }) => entryPath),
    graph: {
      effectExecutionMode: "guest-promise-event-loop",
      inputCount: entryCount,
      sha256: fingerprintJson({ fixtureGraph: routes }),
      toolchain: { convex: "1.44.0", esbuild: "0.27.0" },
    },
    inventoryAuthority: {
      kind: "fixture-inventory-v1",
      snapshot: { revision: authorityRevision },
    },
    kind: convexWasmSourceEnvelopeKind,
    routes,
    schemaVersion: 2,
    selectedRoutes: routes.map((route, index) => ({
      ...route,
      dependencyGraphSha256: fingerprintJson({
        fixtureDependencyGraph: route.entryPath,
        revision: index === changedEntryIndex ? 2 : 1,
      }),
    })),
  };
  return { ...payload, sourceEnvelopeSha256: fingerprintJson(payload) };
}

function deploymentRoute(route) {
  const localProfile = {
    dependencyGraphSha256: route.dependencyGraphSha256,
    javascript: { sha256: fingerprintJson({ javascript: route.entryPath }), size: 1 },
    metafileSha256: fingerprintJson({ metafile: route.entryPath }),
    sha256: fingerprintJson({
      dependencyGraphSha256: route.dependencyGraphSha256,
      localProfile: route.entryPath,
    }),
    sourceMap: { sha256: fingerprintJson({ sourceMap: route.entryPath }), size: 1 },
  };
  const entryId = fingerprintJson({
    domain: "convex-wasm-capability-entry-v1",
    invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
    localProfileSha256: localProfile.sha256,
    selectedEntry: { entryPath: route.entryPath, modulePath: route.modulePath },
  });
  const entrySymbol = `sh_export_convex_wasm_entry_${entryId}`;
  const routeId = fingerprintJson({
    domain: "convex-wasm-capability-route-v1",
    entryId,
    exportName: route.exportName,
    udfKind: route.udfKind,
    visibility: route.visibility,
  });
  const entrySelectorId = fingerprintJson({
    domain: "convex-wasm-capability-selector-member-v1",
    entrySymbol,
    handlerExportName: route.exportName,
    handlerUdfKind: route.udfKind,
    invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
  }).slice(0, 16);
  return {
    deploymentExport: {
      entryPath: route.entryPath,
      exportName: route.exportName,
      packageReference: {
        capabilityEntryPackageId: fingerprintJson({ fixturePackage: route.entryPath }),
        entryId,
        entrySelectorId,
        kind: CAPABILITY_ENTRY_ROUTE_REFERENCE_KIND,
        routeId,
      },
      routing: { decision: "wasm", reason: "runtimeCapability" },
      runtimeModulePath: route.runtimeModulePath,
      udfKind: route.udfKind,
      visibility: route.visibility,
    },
    graphRoute: {
      entryId,
      entrySelectorId,
      entrySymbol,
      exportName: route.exportName,
      routeId,
      udfKind: route.udfKind,
      visibility: route.visibility,
    },
    entry: {
      entryId,
      entryPath: route.entryPath,
      entrySymbol,
      invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
      localProfile,
      modulePath: route.modulePath,
      source: {
        exportName: route.exportName,
        exportSha256: localProfile.javascript.sha256,
        modulePath: route.entryPath,
        resolvedGraphSha256: route.dependencyGraphSha256,
        runtimeModulePath: route.runtimeModulePath,
        udfKind: route.udfKind,
      },
    },
  };
}

function withDeploymentIdentity(payload) {
  return { ...payload, deploymentSha256: fingerprintJson(payload) };
}

function withGraphIdentity(payload) {
  return { ...payload, graphManifestSha256: fingerprintJson(payload) };
}

function replaceGraphRouting(graph, routing) {
  const { graphManifestSha256: ignoredGraphManifestSha256, ...payload } = graph;
  return withGraphIdentity({ ...payload, routing });
}

function fixture(options) {
  const envelope = sourceEnvelope(options);
  const cohortSchedule = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope: envelope,
  });
  const precompilerMaterialIdentity = {
    binary: { sha256: fingerprintJson({ binary: true }), size: 1 },
    kind: "convex-wasm-verified-precompiler-package",
    manifestKind: "convex-wasm-precompiler-package",
    manifestSchemaVersion: 1,
    manifestSha256: fingerprintJson({ manifest: true }),
    packageId: fingerprintJson({ package: true }),
    sourceTreeSha256: fingerprintJson({ sourceTree: true }),
    targetTriple: "x86_64-unknown-linux-gnu",
    wasmtimeRevision: "fixture-wasmtime",
  };
  const engine = {
    compatibilitySha256: fingerprintJson({ compatibility: true }),
    config: { consumeFuel: true, epochInterruption: true },
    configurationSha256: fingerprintJson({ consumeFuel: true, epochInterruption: true }),
    package: precompilerMaterialIdentity,
    revision: precompilerMaterialIdentity.wasmtimeRevision,
    target: { cpu: "baseline", triple: precompilerMaterialIdentity.targetTriple },
    wasmtimeMaterialsSha256: fingerprintJson({ wasmtimeMaterials: true }),
  };
  const producerImplementation = {
    kind: "convex-wasm-artifact-producer-identity-v1",
    sha256: fingerprintJson({ fixtureProducer: true }),
  };
  const records = envelope.selectedRoutes.map(deploymentRoute);
  const byKey = new Map(
    envelope.selectedRoutes.map((route, index) => [
      `${route.runtimeModulePath}\0${route.exportName}`,
      records[index],
    ])
  );
  const sharedContextReuseAnalysisPayload = {
    kind: "convex-context-reuse-shared-analysis",
    moduleSummarySchema: "fixture-module-summary-v1",
    policyFingerprint: envelope.contextReuseAnalysis.policyFingerprint,
  };
  const sharedContextReuseAnalysis = {
    ...sharedContextReuseAnalysisPayload,
    sha256: fingerprintJson(sharedContextReuseAnalysisPayload),
  };
  const contextReuseAnalysisByCohortId = new Map(
    cohortSchedule.cohorts.map((cohort) => [
      cohort.cohortId,
      createConvexContextReuseCohortAnalysisIdentity({
        analysisIdentity: envelope.contextReuseAnalysis,
        entryGraphs: cohort.entries
          .map((entry) => {
            const record = byKey.get(`${entry.runtimeModulePath}\0${entry.routes[0].exportName}`);
            return {
              dependencyGraphSha256: record.entry.localProfile.dependencyGraphSha256,
              entryPath: entry.entryPath,
            };
          })
          .sort((left, right) => left.entryPath.localeCompare(right.entryPath)),
        sharedAnalysisIdentity: sharedContextReuseAnalysis,
        thirdPartyMaterialFingerprints: {},
      }),
    ])
  );
  const deploymentManifest = withDeploymentIdentity({
    contextReuseAnalysis: envelope.contextReuseAnalysis,
    exports: records.map(({ deploymentExport }) => deploymentExport),
    kind: "convex-wasm-deployment-v7",
    mode: "compile",
  });
  const graphManifests = cohortSchedule.cohorts.map((cohort, cohortIndex) => {
    const routes = cohort.entries.flatMap((entry) =>
      entry.routes.map(
        (route) => byKey.get(`${entry.runtimeModulePath}\0${route.exportName}`).graphRoute
      )
    );
    return withGraphIdentity({
      contextReuseAnalysis: contextReuseAnalysisByCohortId.get(cohort.cohortId),
      engine,
      hostAbi: { fixture: true },
      initialization: { fixture: true },
      kind: "convex-wasm-module-graph-manifest-v5",
      modules: [{ fixtureCohortIndex: cohortIndex }],
      producerImplementation,
      replacement: { fixture: true },
      routing: {
        cohortId: cohort.cohortId,
        kind: "convex-wasm-module-graph-routing-v2",
        routes,
      },
      schemaVersion: 5,
      toolchain: { fixture: true },
    });
  });
  const loweringPipelineSha256 = fingerprintJson({ fixtureLowering: true });
  const generatedSource = { sha256: fingerprintJson({ fixtureGeneratedSource: true }), size: 1 };
  const valueCodec = createConvexWasmGuestNativeJsonCodecIdentity({
    canonicalVectorCorpus: {
      kind: "convex-wasm-canonical-convex-value-vector-corpus-v1",
      producer: {
        kind: "convex-sdk-backend-canonical-value-producer-v1",
        sourceSha256: fingerprintJson({ valueProducer: true }),
      },
      schemaVersion: 1,
      sha256: fingerprintJson({ valueCorpus: true }),
    },
    generatedSource,
    loweringPipelineSha256,
  });
  const requestEnvelope = createConvexWasmCapabilityRequestEnvelopeIdentity({
    capabilityRequestAbiVersion: 4,
    canonicalVectorCorpus: {
      kind: "convex-wasm-canonical-capability-request-envelope-vector-corpus-v3",
      producer: {
        kind: "convex-sdk-backend-capability-request-envelope-producer-v3",
        sourceSha256: fingerprintJson({ requestProducer: true }),
      },
      schemaVersion: 1,
      sha256: fingerprintJson({ requestCorpus: true }),
    },
    generatedSource,
    loweringPipelineSha256,
  });
  const cohortContracts = cohortSchedule.cohorts.map((cohort) => {
    const cohortRecords = cohort.entries.map((entry) =>
      byKey.get(`${entry.runtimeModulePath}\0${entry.routes[0].exportName}`)
    );
    const entries = cohortRecords
      .map(({ entry }) => entry)
      .sort((left, right) => left.entryPath.localeCompare(right.entryPath));
    const routes = cohortRecords
      .map(({ graphRoute }) => graphRoute)
      .sort((left, right) => left.routeId.localeCompare(right.routeId));
    const compiler = {
      artifactPipelineSha256: fingerprintJson({ artifactPipeline: true }),
      compilerRevision: "fixture-compiler",
      loweringPipelineSha256,
      sourcePipelineSha256: convexWasmCapabilitySourcePipelineSha256(
        entries.map(({ localProfile }) => localProfile)
      ),
      staticHermesGlobalPolicy: convexWasmTargetRuntimeSurfacePolicyIdentity,
      staticHermesRevision: "fixture-static-hermes",
    };
    const payload = {
      cohortId: cohort.cohortId,
      compiler,
      compilerSourceEnvelopeSha256: envelope.sourceEnvelopeSha256,
      contextReuseAnalysis: contextReuseAnalysisByCohortId.get(cohort.cohortId),
      descriptorIdentitySha256: fingerprintJson({ descriptor: cohort.cohortId }),
      engine,
      entries,
      execution: {
        effectExecutionMode: "guest-promise-event-loop",
        importedOperations: [],
        limits: {
          executionFuel: 1,
          maxGuestMemoryBytes: 1,
          maxHostOwnedBytes: 1,
          maxOperationCount: 1,
          maxResultBytes: 1,
          maxValueHandles: 1,
          timeoutMilliseconds: 1,
        },
        platformLimits: {
          argumentBytes: 1,
          documentsRead: 1,
          documentsWritten: 1,
          executionTimeMs: 1,
          readBytes: 1,
          resultBytes: 1,
          scheduledArgumentBytes: 1,
          scheduledFunctions: 1,
          writeBytes: 1,
        },
        requestEnvelope,
        valueCodec,
        valueMode: "guest-native-json",
      },
      kind: "convex-wasm-module-graph-cohort-contract-v2",
      precompilerMaterialIdentity,
      producerImplementation,
      routes,
      runtimeSurfacePolicySha256: convexWasmTargetRuntimeSurfacePolicySha256,
      scheduleSha256: cohortSchedule.identity.sha256,
      schemaVersion: 2,
      sourceEnvelopeSha256: envelope.sourceEnvelopeSha256,
      sourcePipelineSha256: compiler.sourcePipelineSha256,
    };
    return { ...payload, cohortContractSha256: fingerprintJson(payload) };
  });
  return { cohortContracts, cohortSchedule, deploymentManifest, envelope, graphManifests };
}

function bindingOptions(value) {
  return {
    cohortSchedule: value.cohortSchedule,
    cohortContracts: value.cohortContracts,
    deploymentManifest: value.deploymentManifest,
    graphManifests: value.graphManifests,
    sourceEnvelope: value.envelope,
  };
}

test("binds every authenticated cohort and route into deployment-v8 identity", () => {
  const value = fixture();
  const bound = bindConvexWasmModuleGraphsToDeploymentManifest(bindingOptions(value));
  const { deploymentSha256: ignoredDeploymentSha256, ...payload } = bound;

  assert.equal(bound.kind, convexWasmModuleGraphDeploymentManifestKind);
  assert.equal(bound.moduleGraphBinding.kind, convexWasmModuleGraphDeploymentBindingKind);
  assert.equal(bound.moduleGraphBinding.cohorts.length, value.cohortSchedule.cohorts.length);
  assert.equal(
    bound.moduleGraphBinding.cohorts.flatMap(({ routeIds }) => routeIds).length,
    value.deploymentManifest.exports.length
  );
  assert.equal(bound.deploymentSha256, fingerprintJson(payload));
  assert.notEqual(bound.deploymentSha256, value.deploymentManifest.deploymentSha256);
  assert.equal(
    bound.exports.some((exported) =>
      Object.hasOwn(exported.packageReference, "capabilityEntryPackageId")
    ),
    false
  );
  assert.equal(
    bound.exports.every(
      (exported) =>
        exported.packageReference.kind === "convex-wasm-module-graph-route-reference-v1" &&
        exported.artifact.cohortContractSha256 === exported.packageReference.cohortContractSha256
    ),
    true
  );
  assert.deepEqual(
    validateConvexWasmModuleGraphDeploymentManifest({
      ...bindingOptions(value),
      deploymentManifest: bound,
    }),
    bound
  );
});

test("global authority drift plus one local edit invalidates only one graph package", () => {
  const baseline = fixture({ entryCount: 17 });
  const authorityOnly = fixture({ authorityRevision: 2, entryCount: 17 });
  const changed = fixture({ authorityRevision: 2, changedEntryIndex: 0, entryCount: 17 });
  const graphIds = (value) =>
    value.graphManifests.map(({ graphManifestSha256 }) => graphManifestSha256).sort();
  const baselineGraphIds = graphIds(baseline);
  const authorityOnlyGraphIds = graphIds(authorityOnly);
  const changedGraphIds = graphIds(changed);

  assert.equal(baselineGraphIds.length, 3);
  assert.notEqual(
    authorityOnly.envelope.sourceEnvelopeSha256,
    baseline.envelope.sourceEnvelopeSha256
  );
  assert.notEqual(
    authorityOnly.cohortSchedule.identity.sha256,
    baseline.cohortSchedule.identity.sha256
  );
  assert.deepEqual(authorityOnlyGraphIds, baselineGraphIds);
  assert.equal(
    authorityOnly.cohortContracts.every(
      (contract, index) =>
        contract.cohortContractSha256 !== baseline.cohortContracts[index].cohortContractSha256
    ),
    true
  );

  const retainedGraphIds = changedGraphIds.filter((graphId) =>
    authorityOnlyGraphIds.includes(graphId)
  );
  assert.equal(retainedGraphIds.length, 2);
  assert.equal(
    changedGraphIds.filter((graphId) => !authorityOnlyGraphIds.includes(graphId)).length,
    1
  );
  const binding = createConvexWasmModuleGraphDeploymentBinding(bindingOptions(changed));
  assert.equal(binding.scheduleSha256, changed.cohortSchedule.identity.sha256);
  assert.equal(binding.sourceEnvelopeSha256, changed.envelope.sourceEnvelopeSha256);
  assert.deepEqual(
    binding.cohorts.map(({ graphManifestSha256 }) => graphManifestSha256).sort(),
    changedGraphIds
  );
  assert.notEqual(
    binding.bindingSha256,
    createConvexWasmModuleGraphDeploymentBinding(bindingOptions(baseline)).bindingSha256
  );
});

test("rejects partial route and cohort closure", () => {
  const partialRoute = fixture();
  const firstGraph = partialRoute.graphManifests[0];
  partialRoute.graphManifests[0] = replaceGraphRouting(firstGraph, {
    ...firstGraph.routing,
    routes: firstGraph.routing.routes.slice(1),
  });
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(partialRoute)),
    /does not cover its exact route closure/u
  );

  const partialCohort = fixture();
  partialCohort.graphManifests.pop();
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(partialCohort)),
    /do not cover every authenticated cohort/u
  );
});

test("rejects duplicate route and cohort authority", () => {
  const duplicateCohort = fixture();
  duplicateCohort.graphManifests.push(duplicateCohort.graphManifests[0]);
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(duplicateCohort)),
    /duplicate cohort/u
  );

  const duplicateRoute = fixture();
  const firstGraph = duplicateRoute.graphManifests[0];
  duplicateRoute.graphManifests[0] = replaceGraphRouting(firstGraph, {
    ...firstGraph.routing,
    routes: [...firstGraph.routing.routes, firstGraph.routing.routes[0]],
  });
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(duplicateRoute)),
    /duplicate route identities/u
  );
});

test("rejects graph authority outside the selected deployment or cohort schedule", () => {
  const value = fixture();
  const outside = value.graphManifests[0];
  value.graphManifests.push(
    replaceGraphRouting(outside, {
      ...outside.routing,
      cohortId: fingerprintJson({ outsideCohort: true }),
    })
  );
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value)),
    /outside the authenticated cohort schedule/u
  );

  const outsideRoute = fixture();
  const firstGraph = outsideRoute.graphManifests[0];
  const forgedRoute = {
    ...firstGraph.routing.routes[0],
    routeId: fingerprintJson({ outsideSelectedDeployment: true }),
  };
  outsideRoute.graphManifests[0] = replaceGraphRouting(firstGraph, {
    ...firstGraph.routing,
    routes: [...firstGraph.routing.routes, forgedRoute],
  });
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(outsideRoute)),
    /outside the selected deployment/u
  );
});

test("rejects cohort route drift even when graph content addresses are recomputed", () => {
  const value = fixture();
  const [first, second] = value.graphManifests;
  const firstRoutes = [...first.routing.routes];
  const secondRoutes = [...second.routing.routes];
  [firstRoutes[0], secondRoutes[0]] = [secondRoutes[0], firstRoutes[0]];
  value.graphManifests = [
    replaceGraphRouting(first, { ...first.routing, routes: firstRoutes }),
    replaceGraphRouting(second, { ...second.routing, routes: secondRoutes }),
  ];
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value)),
    /outside its cohort contract/u
  );
});

test("rejects graph entry-symbol drift from its authenticated cohort contract", () => {
  const value = fixture();
  const graph = value.graphManifests[0];
  const routes = structuredClone(graph.routing.routes);
  routes[0].entrySymbol = "sh_export_tampered_graph_entry";
  value.graphManifests[0] = replaceGraphRouting(graph, { ...graph.routing, routes });
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value)),
    /differs from its cohort contract/u
  );
});

test("requires each graph engine identity to match its authenticated cohort contract", () => {
  const value = fixture();
  assert.doesNotThrow(() => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value)));

  const graph = value.graphManifests[0];
  const { graphManifestSha256: ignoredGraphManifestSha256, ...payload } = graph;
  value.graphManifests[0] = withGraphIdentity({
    ...payload,
    engine: { ...graph.engine, compatibilitySha256: fingerprintJson({ tampered: true }) },
  });
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value)),
    /engine identity differs from its authenticated cohort contract/u
  );
});

test("requires each graph producer implementation to match its authenticated cohort contract", () => {
  const value = fixture();
  const graph = value.graphManifests[0];
  const { graphManifestSha256: ignoredGraphManifestSha256, ...payload } = graph;
  value.graphManifests[0] = withGraphIdentity({
    ...payload,
    producerImplementation: {
      ...graph.producerImplementation,
      sha256: fingerprintJson({ tamperedProducer: true }),
    },
  });
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value)),
    /producer implementation differs from its authenticated cohort contract/u
  );
});

test("rejects graph and bound-deployment tampering", () => {
  const graphTamper = fixture();
  graphTamper.graphManifests[0].toolchain.fixture = false;
  assert.throws(
    () => createConvexWasmModuleGraphDeploymentBinding(bindingOptions(graphTamper)),
    /content address is invalid/u
  );

  const bindingTamper = fixture();
  const bound = structuredClone(
    bindConvexWasmModuleGraphsToDeploymentManifest(bindingOptions(bindingTamper))
  );
  bound.moduleGraphBinding.cohorts[0].routeIds[0] = "f".repeat(64);
  const { bindingSha256: ignoredBindingSha256, ...bindingPayload } = bound.moduleGraphBinding;
  bound.moduleGraphBinding.bindingSha256 = fingerprintJson(bindingPayload);
  const { deploymentSha256: ignoredDeploymentSha256, ...deploymentPayload } = bound;
  bound.deploymentSha256 = fingerprintJson(deploymentPayload);
  assert.throws(
    () =>
      validateConvexWasmModuleGraphDeploymentManifest({
        ...bindingOptions(bindingTamper),
        deploymentManifest: bound,
      }),
    /differs from its exact graph, cohort, and route closure/u
  );
});

test("graph input permutation has one deterministic binding and deployment identity", () => {
  const value = fixture();
  const firstBinding = createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value));
  const firstDeployment = bindConvexWasmModuleGraphsToDeploymentManifest(bindingOptions(value));
  value.graphManifests.reverse();
  const permutedBinding = createConvexWasmModuleGraphDeploymentBinding(bindingOptions(value));
  const permutedDeployment = bindConvexWasmModuleGraphsToDeploymentManifest(bindingOptions(value));

  assert.deepEqual(permutedBinding, firstBinding);
  assert.equal(permutedBinding.bindingSha256, firstBinding.bindingSha256);
  assert.deepEqual(permutedDeployment, firstDeployment);
  assert.equal(permutedDeployment.deploymentSha256, firstDeployment.deploymentSha256);
});
