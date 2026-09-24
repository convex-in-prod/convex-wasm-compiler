import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  authenticateConvexContextReuseCohortAnalysisIdentity,
  authenticateConvexContextReuseResultIdentity,
} from "./convex-context-reuse.mjs";
import {
  convexWasmModuleGraphDeploymentManifestKind,
  validateConvexWasmModuleGraphDeploymentManifest,
} from "./convex-wasm-module-graph-deployment-binding.mjs";
import {
  authenticatedConvexWasmModuleGraphPackageVerificationSequence,
  convexWasmModuleGraphManifestModules,
  validateConvexWasmModuleGraphPackageMaterial,
} from "./convex-wasm-module-graph-package.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MODULE_GRAPH_ROUTING_BOUNDARY_KIND = "convex-wasm-runtime-registry-graph-routing-boundary-v1";
const MODULE_GRAPH_SHADOW_ROUTING_BOUNDARY_KIND =
  "convex-wasm-runtime-registry-shadow-routing-boundary-v1";
const MODULE_GRAPH_MANIFEST_V5_KIND = "convex-wasm-module-graph-manifest-v5";
const MODULE_GRAPH_ROUTING_KIND = "convex-wasm-module-graph-routing-v2";
const LOCAL_RUNTIME_GENERATION_V9_KIND = "convex-wasm-runtime-registry-generation-v9";
const LOCAL_RUNTIME_GENERATION_V10_SHADOW_ONLY_KIND =
  "convex-wasm-runtime-registry-generation-v10-shadow-only";

function fail(message) {
  throw new Error(`Convex Wasm runtime registry generation: ${message}`);
}

function requirePlainObject(value, description) {
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

function requireExactFields(value, fields, description) {
  const object = requirePlainObject(value, description);
  if (canonicalJson(Object.keys(object).sort()) !== canonicalJson([...fields].sort())) {
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

function requireIdentityString(value, description) {
  const identity = requireString(value, description);
  if ([...identity].some((character) => /\p{Cc}/u.test(character))) {
    fail(`${description} must not contain control characters`);
  }
  return identity;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function createRuntimeRegistryModuleGraphArtifacts(deploymentBytes, bindingOptions) {
  const deployment = JSON.parse(deploymentBytes.toString("utf8"));
  if (!deploymentBytes.equals(Buffer.from(`${canonicalJson(deployment)}\n`))) {
    fail("deployment manifest must be canonical JSON followed by one newline");
  }
  const bound = validateConvexWasmModuleGraphDeploymentManifest({
    ...bindingOptions,
    deploymentManifest: deployment,
  });
  const selected = bound.exports.filter((entry) => entry.routing?.decision === "wasm");
  if (selected.length === 0) {
    fail("deployment-v8 must select at least one Wasm route");
  }
  const contractRoutes = new Map(
    bound.moduleGraphCohorts.flatMap((cohort) =>
      cohort.routes.map((route) => [route.routeId, route])
    )
  );
  if (contractRoutes.size !== selected.length) {
    fail("deployment-v8 cohort routes differ from its selected Wasm routes");
  }
  const graphRoutes = selected.map((entry) => {
    const reference = entry.packageReference;
    const contractRoute = contractRoutes.get(reference?.routeId);
    if (contractRoute === undefined) {
      fail("selected Wasm route lacks its bound module graph cohort route");
    }
    return {
      entryId: reference.entryId,
      entrySelectorId: reference.entrySelectorId,
      entrySymbol: contractRoute.entrySymbol,
      exportName: entry.exportName,
      routeId: reference.routeId,
      udfKind: entry.udfKind,
      visibility: entry.visibility,
    };
  }).sort((left, right) => left.routeId.localeCompare(right.routeId));
  const sourceIdentities = new Set(
    selected.map((entry) =>
      requireSha256(
        entry.source?.deployedRuntimeIdentity?.sourcePackageRuntimeContentSha256,
        "selected route source-package runtime-content identity"
      )
    )
  );
  if (sourceIdentities.size !== 1) {
    fail("selected routes disagree about source-package runtime content");
  }
  return {
    activationRouteScope: selected.map((entry) => ({
      cohortContractSha256: entry.artifact.cohortContractSha256,
      entryId: entry.packageReference.entryId,
      entryPath: entry.entryPath,
      entrySelectorId: entry.packageReference.entrySelectorId,
      exportName: entry.exportName,
      exportSha256: entry.source.exportSha256,
      routeId: entry.packageReference.routeId,
      runtimeModulePath: entry.runtimeModulePath,
      udfKind: entry.udfKind,
      visibility: entry.visibility,
    })).sort((left, right) => left.routeId.localeCompare(right.routeId)),
    capabilityEntryPackages: [],
    cohortPackages: [],
    contextReuseAnalysis: bound.contextReuseAnalysis,
    deploymentKind: bound.kind,
    deploymentManifest: {
      deploymentSha256: bound.deploymentSha256,
      sha256: sha256(deploymentBytes),
      size: deploymentBytes.length,
    },
    graphRoutes,
    moduleGraphBinding: bound.moduleGraphBinding,
    moduleGraphCohorts: bound.moduleGraphCohorts,
    packages: [],
    sourcePackageRuntimeContentSha256: [...sourceIdentities][0],
    wasmRouteCount: selected.length,
  };
}

export function authenticatedModuleGraphRouting(moduleGraph) {
  const manifest = requirePlainObject(
    moduleGraph.graphManifest,
    "authenticated module graph manifest"
  );
  if (manifest.kind !== MODULE_GRAPH_MANIFEST_V5_KIND || manifest.schemaVersion !== 5) {
    fail("authenticated module graph manifest kind or schemaVersion is unsupported");
  }
  const graphManifestSha256 = requireSha256(
    manifest.graphManifestSha256,
    "authenticated module graph manifest SHA-256"
  );
  const recordGraphManifestSha256 =
    moduleGraph.record === undefined
      ? requireSha256(
          moduleGraph.graphManifestSha256,
          "runtime registry module graph record SHA-256"
        )
      : requireSha256(
          requirePlainObject(moduleGraph.record, "authenticated module graph record")
            .graphManifestSha256,
          "authenticated module graph record SHA-256"
        );
  if (graphManifestSha256 !== recordGraphManifestSha256) {
    fail("authenticated module graph manifest identity differs from its registry record");
  }
  const { graphManifestSha256: ignoredIdentity, ...withoutIdentity } = manifest;
  if (graphManifestSha256 !== fingerprintJson(withoutIdentity)) {
    fail(`module graph ${graphManifestSha256} content address is invalid`);
  }
  const routing = requireExactFields(
    manifest.routing,
    ["cohortId", "kind", "routes"],
    `module graph ${graphManifestSha256} routing`
  );
  if (routing.kind !== MODULE_GRAPH_ROUTING_KIND || !Array.isArray(routing.routes)) {
    fail(`module graph ${graphManifestSha256} routing contract is unsupported`);
  }
  if (routing.routes.length === 0) {
    fail(`module graph ${graphManifestSha256} contains no routes`);
  }
  const routes = routing.routes.map((value, index) => {
    const description = `module graph ${graphManifestSha256} route ${index}`;
    const route = requireExactFields(
      value,
      [
        "entryId",
        "entrySelectorId",
        "entrySymbol",
        "exportName",
        "routeId",
        "udfKind",
        "visibility",
      ],
      description
    );
    const entrySelectorId = requireString(
      route.entrySelectorId,
      `${description} entry selector ID`
    );
    if (!/^[a-f0-9]{16}$/u.test(entrySelectorId)) {
      fail(`${description} entry selector ID must contain 16 lowercase hexadecimal characters`);
    }
    if (!new Set(["query", "mutation"]).has(route.udfKind)) {
      fail(`${description} UDF kind is unsupported`);
    }
    if (!new Set(["internal", "public"]).has(route.visibility)) {
      fail(`${description} visibility is unsupported`);
    }
    return {
      entryId: requireSha256(route.entryId, `${description} entry ID`),
      entrySelectorId,
      entrySymbol: requireIdentityString(route.entrySymbol, `${description} entry symbol`),
      exportName: requireIdentityString(route.exportName, `${description} export name`),
      routeId: requireSha256(route.routeId, `${description} route ID`),
      udfKind: route.udfKind,
      visibility: route.visibility,
    };
  });
  const sortedRouteIds = routes.map(({ routeId }) => routeId).sort();
  if (new Set(sortedRouteIds).size !== sortedRouteIds.length) {
    fail(`module graph ${graphManifestSha256} contains duplicate route identities`);
  }
  return {
    cohortId: requireSha256(routing.cohortId, `module graph ${graphManifestSha256} cohort ID`),
    contextReuseAnalysis: authenticateConvexContextReuseCohortAnalysisIdentity(
      manifest.contextReuseAnalysis
    ),
    graphManifestSha256,
    routes: routes.sort((left, right) => left.routeId.localeCompare(right.routeId)),
  };
}

function localModuleGraphExecutionAuthority(artifacts, moduleGraphs) {
  if (artifacts.deploymentKind !== convexWasmModuleGraphDeploymentManifestKind) {
    fail("module graph execution authority requires a deployment-v8 manifest");
  }
  if (artifacts.moduleGraphBinding === undefined) {
    fail("deployment-v8 module graph binding is missing");
  }
  const contextReuseAnalysis = authenticateConvexContextReuseResultIdentity(
    artifacts.contextReuseAnalysis
  );
  if (
    canonicalJson(artifacts.moduleGraphBinding.contextReuseAnalysis) !==
      canonicalJson(contextReuseAnalysis) ||
    artifacts.moduleGraphCohorts.some(
      (contract) =>
        contract.contextReuseAnalysis.policyFingerprint !== contextReuseAnalysis.policyFingerprint
    )
  ) {
    fail("deployment-v8 graph authority has context-reuse analysis drift");
  }
  const selectedByRouteId = new Map(artifacts.graphRoutes.map((route) => [route.routeId, route]));
  if (selectedByRouteId.size !== artifacts.wasmRouteCount) {
    fail("deployment graph-route closure does not cover every selected Wasm route");
  }
  const bindingByCohort = new Map(
    artifacts.moduleGraphBinding.cohorts.map((cohort) => [cohort.cohortId, cohort])
  );
  const contractByCohort = new Map(
    artifacts.moduleGraphCohorts.map((contract) => [contract.cohortId, contract])
  );
  if (contractByCohort.size !== bindingByCohort.size) {
    fail("deployment-v8 cohort contracts do not cover the binding cohorts");
  }
  const bindingRouteIds = artifacts.moduleGraphBinding.cohorts
    .flatMap((cohort) => cohort.routeIds)
    .sort();
  const selectedRouteIds = [...selectedByRouteId.keys()].sort();
  if (canonicalJson(bindingRouteIds) !== canonicalJson(selectedRouteIds)) {
    fail("deployment-v8 module graph binding does not cover the exact selected-route closure");
  }
  const graphCohortIds = new Set();
  const graphManifestSha256s = new Set();
  const graphRouteIds = new Set();
  for (const moduleGraph of moduleGraphs) {
    const graph = authenticatedModuleGraphRouting(moduleGraph);
    if (graphCohortIds.has(graph.cohortId)) {
      fail(`authenticated module graph records contain duplicate cohort ${graph.cohortId}`);
    }
    if (graphManifestSha256s.has(graph.graphManifestSha256)) {
      fail(
        `authenticated module graph records contain duplicate graph ${graph.graphManifestSha256}`
      );
    }
    const binding = bindingByCohort.get(graph.cohortId);
    if (binding === undefined) {
      fail(
        `authenticated module graph ${graph.graphManifestSha256} is outside deployment-v8 binding`
      );
    }
    if (binding.graphManifestSha256 !== graph.graphManifestSha256) {
      fail(`deployment-v8 binding graph differs for cohort ${graph.cohortId}`);
    }
    const contract = contractByCohort.get(graph.cohortId);
    if (contract === undefined || contract.cohortContractSha256 !== binding.cohortContractSha256) {
      fail(`deployment-v8 cohort contract differs for cohort ${graph.cohortId}`);
    }
    if (
      canonicalJson(graph.contextReuseAnalysis) !== canonicalJson(contract.contextReuseAnalysis)
    ) {
      fail(
        `authenticated module graph ${graph.graphManifestSha256} has context-reuse cohort drift`
      );
    }
    if (
      contract.scheduleSha256 !== artifacts.moduleGraphBinding.scheduleSha256 ||
      contract.sourceEnvelopeSha256 !== artifacts.moduleGraphBinding.sourceEnvelopeSha256
    ) {
      fail(`deployment-v8 routing authority differs for cohort ${graph.cohortId}`);
    }
    const routeIds = graph.routes.map(({ routeId }) => routeId);
    if (
      canonicalJson(routeIds) !== canonicalJson(binding.routeIds) ||
      canonicalJson(contract.routes.map(({ routeId }) => routeId)) !==
        canonicalJson(binding.routeIds)
    ) {
      fail(`deployment-v8 binding route closure differs for cohort ${graph.cohortId}`);
    }
    for (const graphRoute of graph.routes) {
      if (graphRouteIds.has(graphRoute.routeId)) {
        fail(`authenticated module graph records contain duplicate route ${graphRoute.routeId}`);
      }
      graphRouteIds.add(graphRoute.routeId);
      const selectedRoute = selectedByRouteId.get(graphRoute.routeId);
      if (selectedRoute === undefined) {
        fail(
          `authenticated module graph route ${graphRoute.routeId} is outside the selected deployment`
        );
      }
      const comparableGraphRoute = {
        entryId: graphRoute.entryId,
        entrySelectorId: graphRoute.entrySelectorId,
        entrySymbol: graphRoute.entrySymbol,
        exportName: graphRoute.exportName,
        routeId: graphRoute.routeId,
        udfKind: graphRoute.udfKind,
        visibility: graphRoute.visibility,
      };
      const comparableDeploymentRoute = {
        entryId: selectedRoute.entryId,
        entrySelectorId: selectedRoute.entrySelectorId,
        entrySymbol: selectedRoute.entrySymbol,
        exportName: selectedRoute.exportName,
        routeId: selectedRoute.routeId,
        udfKind: selectedRoute.udfKind,
        visibility: selectedRoute.visibility,
      };
      if (canonicalJson(comparableGraphRoute) !== canonicalJson(comparableDeploymentRoute)) {
        fail(
          `authenticated module graph route ${graphRoute.routeId} differs from the selected deployment`
        );
      }
    }
    graphCohortIds.add(graph.cohortId);
    graphManifestSha256s.add(graph.graphManifestSha256);
  }
  if (graphCohortIds.size !== bindingByCohort.size) {
    fail("deployment-v8 binding is missing an authenticated module graph record");
  }
  if (graphRouteIds.size !== selectedRouteIds.length) {
    fail("authenticated module graph records do not cover the selected deployment");
  }
  return Object.freeze({
    cutoverReady: true,
    cutoverState: "module-graph-authorized",
    graphBackedRouteIds: Object.freeze(selectedRouteIds),
    contextReuseAnalysis,
    kind: MODULE_GRAPH_ROUTING_BOUNDARY_KIND,
    missingRouteIds: Object.freeze([]),
    selectedRouteIds: Object.freeze(selectedRouteIds),
    selectedRuntime: "module-graph",
  });
}

function localModuleGraphShadowRoutingBoundary(graphRouting) {
  if (
    graphRouting.kind !== MODULE_GRAPH_ROUTING_BOUNDARY_KIND ||
    graphRouting.cutoverReady !== true ||
    graphRouting.cutoverState !== "module-graph-authorized" ||
    graphRouting.selectedRuntime !== "module-graph" ||
    graphRouting.missingRouteIds.length !== 0
  ) {
    fail("deployment-v8 shadow routing requires a complete module graph closure");
  }
  return Object.freeze({
    artifactComplete: true,
    artifactState: "shadow-only",
    kind: MODULE_GRAPH_SHADOW_ROUTING_BOUNDARY_KIND,
    routeIds: Object.freeze([...graphRouting.selectedRouteIds]),
  });
}

export function createRuntimeRegistryModuleGraphRecord(verified, cacheLayout) {
  if (authenticatedConvexWasmModuleGraphPackageVerificationSequence(verified) === undefined) {
    fail("module graph record requires a verified package");
  }
  const graphManifest = verified.graphManifest;
  const graphManifestSha256 = graphManifest.graphManifestSha256;
  const material = validateConvexWasmModuleGraphPackageMaterial(
    verified.packageMaterial,
    graphManifestSha256
  );
  if (material.schemaVersion !== 2) {
    fail("module graph record requires complete artifact references");
  }
  const packagePath = join(cacheLayout.immutable.packages, graphManifestSha256);
  if (verified.package.path !== packagePath) {
    fail("verified module graph package is outside its immutable cache location");
  }
  const packageFiles = [
    ["COMPLETE", material.complete],
    ["build-provenance.json", material.provenance],
    ["graph-manifest.json", material.graphManifest],
    ["package-entry.json", material.packageEntry],
  ].map(([name, identity]) => ({ name, sha256: identity.sha256, size: identity.size }));
  const referencesByRole = new Map(material.artifactReferences.map((entry) => [entry.role, entry]));
  const artifacts = convexWasmModuleGraphManifestModules(graphManifest).flatMap((module) =>
    ["coreWasm", "aot"].map((kind) => {
      const reference = module.artifacts[kind];
      const materialReference = referencesByRole.get(module.role)?.[kind];
      if (
        materialReference === undefined ||
        canonicalJson(materialReference.artifact) !== canonicalJson(reference)
      ) {
        fail("verified package material differs from its graph artifact reference");
      }
      const stage =
        kind === "coreWasm"
          ? `module-graph-${module.role}-core-wasm`
          : `module-graph-${module.role}-wasmtime-aot`;
      if (reference.stage !== stage) {
        fail("verified graph artifact has the wrong immutable stage");
      }
      const entryRoot = join(cacheLayout.immutable.artifacts, stage, reference.cacheKey);
      const completeBytes = readFileSync(join(entryRoot, "COMPLETE"));
      const expectedComplete = Buffer.from(`${reference.cacheKey}\n`);
      if (!completeBytes.equals(expectedComplete)) {
        fail("verified graph artifact completion marker changed");
      }
      const entryBytes = readFileSync(join(entryRoot, "entry.json"));
      if (entryBytes.length > 16 * 1024 * 1024) {
        fail("verified graph artifact metadata exceeds its byte limit");
      }
      const entry = JSON.parse(entryBytes.toString("utf8"));
      if (
        !entryBytes.equals(Buffer.from(`${canonicalJson(entry)}\n`)) ||
        entry.key !== reference.cacheKey ||
        entry.stage !== stage ||
        entry.artifactSha256 !== reference.sha256 ||
        entry.artifactSize !== reference.size ||
        fingerprintJson(entry.identity) !== materialReference.identitySha256 ||
        fingerprintJson(entry.metadata) !== materialReference.metadataSha256
      ) {
        fail("verified graph artifact metadata changed");
      }
      return {
        cacheKey: reference.cacheKey,
        files: [
          { name: "COMPLETE", sha256: sha256(completeBytes), size: completeBytes.length },
          {
            name: kind === "coreWasm" ? "artifact.wasm" : "artifact.cwasm",
            sha256: reference.sha256,
            size: reference.size,
          },
          { name: "entry.json", sha256: sha256(entryBytes), size: entryBytes.length },
        ],
        kind,
        role: module.role,
        sha256: reference.sha256,
        size: reference.size,
        stage,
      };
    })
  );
  return {
    graphManifest,
    record: {
      artifacts,
      graphManifestSha256,
      package: { files: packageFiles },
    },
  };
}

export function createRuntimeRegistryModuleGraphGeneration(artifacts, moduleGraphs, publication) {
  if (publication !== "primary" && publication !== "shadow-only") {
    fail("module graph generation publication must be primary or shadow-only");
  }
  const deploymentManifest = {
    deploymentSha256: artifacts.deploymentManifest.deploymentSha256,
    sha256: artifacts.deploymentManifest.sha256,
    size: artifacts.deploymentManifest.size,
  };
  if (artifacts.deploymentKind === convexWasmModuleGraphDeploymentManifestKind) {
    if (
      artifacts.capabilityEntryPackages.length !== 0 ||
      artifacts.packages.length !== 0 ||
      artifacts.cohortPackages.length !== 0
    ) {
      fail("deployment-v8 runtime generation must not contain legacy artifact packages");
    }
    if (moduleGraphs.length === 0) {
      fail("deployment-v8 requires authenticated module graph packages");
    }
    const moduleGraphCohorts = [...artifacts.moduleGraphCohorts].sort((left, right) =>
      left.cohortId.localeCompare(right.cohortId)
    );
    const records = moduleGraphs
      .map(({ record }) => record)
      .sort((left, right) => left.graphManifestSha256.localeCompare(right.graphManifestSha256));
    if (
      new Set(records.map(({ graphManifestSha256 }) => graphManifestSha256)).size !== records.length
    ) {
      fail("runtime generation cannot contain duplicate module graph packages");
    }
    const graphRouting = localModuleGraphExecutionAuthority(artifacts, moduleGraphs);
    const withoutIdentity = {
      ...(publication === "shadow-only"
        ? {
            admission: "shadow-only",
            shadowRouting: localModuleGraphShadowRoutingBoundary(graphRouting),
          }
        : { graphRouting }),
      deploymentManifest,
      contextReuseAnalysis: authenticateConvexContextReuseResultIdentity(
        artifacts.contextReuseAnalysis
      ),
      kind:
        publication === "shadow-only"
          ? LOCAL_RUNTIME_GENERATION_V10_SHADOW_ONLY_KIND
          : LOCAL_RUNTIME_GENERATION_V9_KIND,
      moduleGraphBinding: artifacts.moduleGraphBinding,
      moduleGraphCohorts,
      moduleGraphs: records,
    };
    return { ...withoutIdentity, generationSha256: fingerprintJson(withoutIdentity) };
  }
  fail("module graph generation requires a deployment-v8 manifest");
}
