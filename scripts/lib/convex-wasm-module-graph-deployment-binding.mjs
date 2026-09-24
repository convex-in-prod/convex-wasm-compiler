import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmModuleGraphRouteReferenceKind,
  validateConvexWasmModuleGraphCohortContract,
} from "./convex-wasm-module-graph-cohort-contract.mjs";
import { authenticateConvexWasmOfficialOutputCohortSchedule } from "./convex-wasm-official-output-cohort-schedule.mjs";
import { authenticatedConvexWasmModuleGraphManifestSha256 } from "./convex-wasm-module-graph-package.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";

export const convexWasmModuleGraphDeploymentBindingKind =
  "convex-wasm-deployment-module-graph-binding-v2";
export const convexWasmModuleGraphDeploymentManifestKind = "convex-wasm-deployment-v8";

const INPUT_DEPLOYMENT_KIND = "convex-wasm-deployment-v7";
const MODULE_GRAPH_MANIFEST_KIND = "convex-wasm-module-graph-manifest-v5";
const MODULE_GRAPH_ROUTING_KIND = "convex-wasm-module-graph-routing-v2";
const LEGACY_CAPABILITY_ENTRY_ROUTE_REFERENCE_KIND =
  "convex-wasm-capability-entry-route-reference-v1";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SELECTOR_ID_PATTERN = /^[0-9a-f]{16}$/u;

function fail(message) {
  throw new Error(`Convex Wasm module graph deployment binding: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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

function requireExactKeys(value, keys, description) {
  const object = requirePlainObject(value, description);
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

function normalizeProducerImplementation(value, description) {
  const identity = requireExactKeys(value, new Set(["kind", "sha256"]), description);
  if (identity.kind !== "convex-wasm-artifact-producer-identity-v1") {
    fail(`${description} kind is unsupported`);
  }
  return {
    kind: identity.kind,
    sha256: requireSha256(identity.sha256, `${description} SHA-256`),
  };
}

function deploymentWithoutIdentity(deployment) {
  const { deploymentSha256: ignoredDeploymentSha256, ...payload } = deployment;
  return payload;
}

function requireDeploymentIdentity(rawDeployment, allowedKinds) {
  const deployment = requirePlainObject(rawDeployment, "deployment manifest");
  if (!allowedKinds.has(deployment.kind)) {
    fail(`deployment manifest kind ${String(deployment.kind)} is unsupported`);
  }
  if (!Array.isArray(deployment.exports) || deployment.exports.length === 0) {
    fail("deployment manifest exports must be a non-empty array");
  }
  const deploymentSha256 = requireSha256(
    deployment.deploymentSha256,
    "deployment manifest deploymentSha256"
  );
  if (deploymentSha256 !== fingerprintJson(deploymentWithoutIdentity(deployment))) {
    fail("deployment manifest identity is invalid");
  }
  return deployment;
}

function deploymentRouteKey(runtimeModulePath, exportName) {
  return `${runtimeModulePath}\0${exportName}`;
}

function selectedDeploymentRoutes(deployment) {
  const byKey = new Map();
  const byRouteId = new Map();
  for (const [index, rawExport] of deployment.exports.entries()) {
    const exported = requirePlainObject(rawExport, `deployment export ${index}`);
    if (exported.routing?.decision !== "wasm") continue;
    const description = `selected deployment export ${index}`;
    const graphNative = exported.packageReference?.kind === convexWasmModuleGraphRouteReferenceKind;
    const packageReference = requireExactKeys(
      exported.packageReference,
      graphNative
        ? new Set(["cohortContractSha256", "entryId", "entrySelectorId", "kind", "routeId"])
        : new Set(["capabilityEntryPackageId", "entryId", "entrySelectorId", "kind", "routeId"]),
      `${description} package reference`
    );
    if (
      packageReference.kind !==
      (graphNative
        ? convexWasmModuleGraphRouteReferenceKind
        : LEGACY_CAPABILITY_ENTRY_ROUTE_REFERENCE_KIND)
    ) {
      fail(`${description} uses an unsupported route reference`);
    }
    const route = {
      entryId: requireSha256(packageReference.entryId, `${description} entry ID`),
      entryPath: requireString(exported.entryPath, `${description} entry path`),
      entrySelectorId: requireString(
        packageReference.entrySelectorId,
        `${description} entry selector ID`
      ),
      exportName: requireString(exported.exportName, `${description} export name`),
      routeId: requireSha256(packageReference.routeId, `${description} route ID`),
      runtimeModulePath: requireString(
        exported.runtimeModulePath,
        `${description} runtime module path`
      ),
      udfKind: exported.udfKind,
      visibility: exported.visibility,
    };
    const cohortContractSha256 = graphNative
      ? requireSha256(
          packageReference.cohortContractSha256,
          `${description} cohort contract SHA-256`
        )
      : undefined;
    if (!graphNative) {
      requireSha256(
        packageReference.capabilityEntryPackageId,
        `${description} capability-entry package ID`
      );
    }
    if (!SELECTOR_ID_PATTERN.test(route.entrySelectorId)) {
      fail(`${description} entry selector ID must contain 16 lowercase hexadecimal characters`);
    }
    if (!new Set(["query", "mutation"]).has(route.udfKind)) {
      fail(`${description} UDF kind is unsupported`);
    }
    if (!new Set(["internal", "public"]).has(route.visibility)) {
      fail(`${description} visibility is unsupported`);
    }
    const key = deploymentRouteKey(route.runtimeModulePath, route.exportName);
    if (byKey.has(key)) {
      fail(
        `deployment contains duplicate selected route ${route.runtimeModulePath}:${route.exportName}`
      );
    }
    if (byRouteId.has(route.routeId)) {
      fail(`deployment contains duplicate selected route identity ${route.routeId}`);
    }
    byKey.set(key, { ...route, cohortContractSha256 });
    byRouteId.set(route.routeId, { ...route, cohortContractSha256 });
  }
  if (byRouteId.size === 0) {
    fail("deployment manifest selects no Wasm routes");
  }
  return { byKey, byRouteId };
}

function scheduledCohortRoutes(schedule, selectedRoutes) {
  const byCohortId = new Map();
  const scheduledKeys = new Set();
  for (const cohort of schedule.cohorts) {
    if (byCohortId.has(cohort.cohortId)) {
      fail(`cohort schedule repeats cohort ${cohort.cohortId}`);
    }
    const routeIds = [];
    for (const [entryIndex, entry] of cohort.entries.entries()) {
      for (const [routeIndex, route] of entry.routes.entries()) {
        const key = deploymentRouteKey(entry.runtimeModulePath, route.exportName);
        if (scheduledKeys.has(key)) {
          fail(`cohort schedule repeats route ${entry.runtimeModulePath}:${route.exportName}`);
        }
        scheduledKeys.add(key);
        const selected = selectedRoutes.byKey.get(key);
        if (selected === undefined) {
          fail(
            `cohort ${cohort.cohortId} route ${entry.runtimeModulePath}:${route.exportName} is missing from the selected deployment`
          );
        }
        if (
          selected.entryPath !== entry.entryPath ||
          selected.udfKind !== route.udfKind ||
          selected.visibility !== route.visibility
        ) {
          fail(
            `cohort ${cohort.cohortId} entry ${entryIndex} route ${routeIndex} differs from the selected deployment route`
          );
        }
        routeIds.push(selected.routeId);
      }
    }
    routeIds.sort(compareStrings);
    if (new Set(routeIds).size !== routeIds.length) {
      fail(`cohort ${cohort.cohortId} contains duplicate selected route identities`);
    }
    byCohortId.set(cohort.cohortId, routeIds);
  }
  const outsideSchedule = [...selectedRoutes.byKey.keys()]
    .filter((key) => !scheduledKeys.has(key))
    .sort(compareStrings);
  if (outsideSchedule.length > 0) {
    fail(`selected deployment routes are outside the authenticated cohort schedule`);
  }
  return byCohortId;
}

function normalizeCohortContracts(rawContracts, schedule, selectedRoutes) {
  if (!Array.isArray(rawContracts) || rawContracts.length === 0) {
    fail("module graph cohort contracts must be a non-empty array");
  }
  const contractsByCohort = new Map();
  const contractIdentities = new Set();
  const scheduleSha256 = requireSha256(
    schedule.identity.sha256,
    "authenticated cohort schedule SHA-256"
  );
  const sourceEnvelopeSha256 = requireSha256(
    schedule.identity.provenance.sourceEnvelope.sha256,
    "authenticated cohort schedule source-envelope SHA-256"
  );
  for (const rawContract of rawContracts) {
    let contract;
    try {
      contract = validateConvexWasmModuleGraphCohortContract(rawContract);
    } catch (error) {
      throw new Error("Convex Wasm module graph deployment binding: cohort contract is invalid", {
        cause: error,
      });
    }
    if (
      contract.scheduleSha256 !== scheduleSha256 ||
      contract.sourceEnvelopeSha256 !== sourceEnvelopeSha256
    ) {
      fail(
        `cohort contract ${contract.cohortContractSha256} has schedule or source-envelope drift`
      );
    }
    if (contractsByCohort.has(contract.cohortId)) {
      fail(`module graph cohort contracts contain duplicate cohort ${contract.cohortId}`);
    }
    if (contractIdentities.has(contract.cohortContractSha256)) {
      fail(
        `module graph cohort contracts contain duplicate identity ${contract.cohortContractSha256}`
      );
    }
    for (const route of contract.routes) {
      const selected = selectedRoutes.byRouteId.get(route.routeId);
      if (
        selected === undefined ||
        (selected.cohortContractSha256 !== undefined &&
          selected.cohortContractSha256 !== contract.cohortContractSha256)
      ) {
        fail(
          `cohort contract ${contract.cohortContractSha256} route is outside its deployment reference`
        );
      }
      assertGraphRouteMatchesDeployment(route, selected, contract.cohortId);
    }
    contractsByCohort.set(contract.cohortId, contract);
    contractIdentities.add(contract.cohortContractSha256);
  }
  return contractsByCohort;
}

function normalizeGraphRoute(rawRoute, graphManifestSha256, index) {
  const description = `module graph ${graphManifestSha256} route ${index}`;
  const route = requireExactKeys(
    rawRoute,
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
  if (!new Set(["query", "mutation"]).has(route.udfKind)) {
    fail(`${description} UDF kind is unsupported`);
  }
  if (!new Set(["internal", "public"]).has(route.visibility)) {
    fail(`${description} visibility is unsupported`);
  }
  const normalized = {
    entryId: requireSha256(route.entryId, `${description} entry ID`),
    entrySelectorId: requireString(route.entrySelectorId, `${description} entry selector ID`),
    entrySymbol: requireString(route.entrySymbol, `${description} entry symbol`),
    exportName: requireString(route.exportName, `${description} export name`),
    routeId: requireSha256(route.routeId, `${description} route ID`),
    udfKind: route.udfKind,
    visibility: route.visibility,
  };
  if (!SELECTOR_ID_PATTERN.test(normalized.entrySelectorId)) {
    fail(`${description} entry selector ID must contain 16 lowercase hexadecimal characters`);
  }
  return normalized;
}

// The canonical module-graph package loader remains the authority for modules, artifacts, providers,
// and ABI contracts. This consumer verifies the graph content address and reads only its generic
// routing metadata; it does not derive route-local module reachability.
function normalizeGraphManifest(rawManifest) {
  const manifest = requirePlainObject(rawManifest, "authenticated module graph manifest");
  if (manifest.kind !== MODULE_GRAPH_MANIFEST_KIND || manifest.schemaVersion !== 5) {
    fail("authenticated module graph manifest kind or schemaVersion is unsupported");
  }
  const graphManifestSha256 = requireSha256(
    manifest.graphManifestSha256,
    "authenticated module graph manifest SHA-256"
  );
  const authenticatedGraphManifestSha256 =
    authenticatedConvexWasmModuleGraphManifestSha256(manifest);
  if (
    authenticatedGraphManifestSha256 === undefined
      ? graphManifestSha256 !==
        fingerprintJson(
          Object.fromEntries(
            Object.entries(manifest).filter(([key]) => key !== "graphManifestSha256")
          )
        )
      : graphManifestSha256 !== authenticatedGraphManifestSha256
  ) {
    fail(`module graph ${graphManifestSha256} content address is invalid`);
  }
  const routing = requireExactKeys(
    manifest.routing,
    new Set(["cohortId", "kind", "routes"]),
    `module graph ${graphManifestSha256} routing`
  );
  if (routing.kind !== MODULE_GRAPH_ROUTING_KIND || !Array.isArray(routing.routes)) {
    fail(`module graph ${graphManifestSha256} routing contract is unsupported`);
  }
  if (routing.routes.length === 0) {
    fail(`module graph ${graphManifestSha256} contains no routes`);
  }
  const routes = routing.routes
    .map((route, index) => normalizeGraphRoute(route, graphManifestSha256, index))
    .sort((left, right) => compareStrings(left.routeId, right.routeId));
  if (new Set(routes.map(({ routeId }) => routeId)).size !== routes.length) {
    fail(`module graph ${graphManifestSha256} contains duplicate route identities`);
  }
  const contextReuseAnalysis = authenticateConvexContextReuseCohortAnalysisIdentity(
    manifest.contextReuseAnalysis
  );
  return {
    cohortId: requireSha256(routing.cohortId, `module graph ${graphManifestSha256} cohort ID`),
    engine:
      authenticatedGraphManifestSha256 === undefined
        ? JSON.parse(
            canonicalJson(
              requirePlainObject(
                manifest.engine,
                `module graph ${graphManifestSha256} engine identity`
              )
            )
          )
        : manifest.engine,
    graphManifestSha256,
    contextReuseAnalysis,
    producerImplementation: normalizeProducerImplementation(
      manifest.producerImplementation,
      `module graph ${graphManifestSha256} producer implementation`
    ),
    routes,
  };
}

function assertGraphRouteMatchesDeployment(graphRoute, selectedRoute, cohortId) {
  if (selectedRoute === undefined) {
    fail(`module graph cohort ${cohortId} contains a route outside the selected deployment`);
  }
  const comparableGraphRoute = {
    entryId: graphRoute.entryId,
    entrySelectorId: graphRoute.entrySelectorId,
    exportName: graphRoute.exportName,
    routeId: graphRoute.routeId,
    udfKind: graphRoute.udfKind,
    visibility: graphRoute.visibility,
  };
  const comparableDeploymentRoute = {
    entryId: selectedRoute.entryId,
    entrySelectorId: selectedRoute.entrySelectorId,
    exportName: selectedRoute.exportName,
    routeId: selectedRoute.routeId,
    udfKind: selectedRoute.udfKind,
    visibility: selectedRoute.visibility,
  };
  if (canonicalJson(comparableGraphRoute) !== canonicalJson(comparableDeploymentRoute)) {
    fail(
      `module graph cohort ${cohortId} route ${graphRoute.routeId} differs from its deployment route`
    );
  }
}

function assertGraphRouteMatchesContract(graphRoute, contractRoute, cohortId) {
  if (contractRoute === undefined) {
    fail(`module graph cohort ${cohortId} contains a route outside its cohort contract`);
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
  const comparableContractRoute = {
    entryId: contractRoute.entryId,
    entrySelectorId: contractRoute.entrySelectorId,
    entrySymbol: contractRoute.entrySymbol,
    exportName: contractRoute.exportName,
    routeId: contractRoute.routeId,
    udfKind: contractRoute.udfKind,
    visibility: contractRoute.visibility,
  };
  if (canonicalJson(comparableGraphRoute) !== canonicalJson(comparableContractRoute)) {
    fail(
      `module graph cohort ${cohortId} route ${graphRoute.routeId} differs from its cohort contract`
    );
  }
}

function bindingPayload({ cohorts, contextReuseAnalysis, scheduleSha256, sourceEnvelopeSha256 }) {
  return {
    cohorts,
    contextReuseAnalysis: authenticateConvexContextReuseResultIdentity(contextReuseAnalysis),
    kind: convexWasmModuleGraphDeploymentBindingKind,
    scheduleSha256,
    schemaVersion: 2,
    sourceEnvelopeSha256,
  };
}

export function createConvexWasmModuleGraphDeploymentBinding(options) {
  const deployment = requireDeploymentIdentity(
    options.deploymentManifest,
    new Set([INPUT_DEPLOYMENT_KIND, convexWasmModuleGraphDeploymentManifestKind])
  );
  const graphManifests = options.graphManifests;
  if (!Array.isArray(graphManifests) || graphManifests.length === 0) {
    fail("module graph manifests must be a non-empty array");
  }
  const schedule = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: options.cohortSchedule,
    sourceEnvelope: options.sourceEnvelope,
    ...(Object.hasOwn(options, "sourceEnvelopeFileSha256")
      ? { sourceEnvelopeFileSha256: options.sourceEnvelopeFileSha256 }
      : {}),
    ...(Object.hasOwn(options, "sourceEnvelopeFileSize")
      ? { sourceEnvelopeFileSize: options.sourceEnvelopeFileSize }
      : {}),
  });
  const selectedRoutes = selectedDeploymentRoutes(deployment);
  const scheduledRoutesByCohort = scheduledCohortRoutes(schedule, selectedRoutes);
  const contractsByCohort = normalizeCohortContracts(
    options.cohortContracts,
    schedule,
    selectedRoutes
  );
  const sourceEnvelopeSha256 = requireSha256(
    schedule.identity.provenance.sourceEnvelope.sha256,
    "authenticated cohort schedule source-envelope SHA-256"
  );
  const scheduleSha256 = requireSha256(
    schedule.identity.sha256,
    "authenticated cohort schedule SHA-256"
  );
  const contextReuseCandidates = [
    deployment.contextReuseAnalysis,
    options.sourceEnvelope?.contextReuseAnalysis,
  ];
  if (contextReuseCandidates.some((value) => value === undefined)) {
    fail("module graph deployment context-reuse analysis authority is missing");
  }
  const contextReuseAnalysis = authenticateConvexContextReuseResultIdentity(
    contextReuseCandidates[0]
  );
  if (
    contextReuseCandidates.some(
      (value) => canonicalJson(value) !== canonicalJson(contextReuseAnalysis)
    )
  ) {
    fail("module graph deployment context-reuse analysis identities disagree");
  }
  const graphByCohort = new Map();
  const graphIdentities = new Set();
  const graphRouteIds = new Set();
  for (const rawGraphManifest of graphManifests) {
    const graph = normalizeGraphManifest(rawGraphManifest);
    if (graphByCohort.has(graph.cohortId)) {
      fail(`module graph manifests contain duplicate cohort ${graph.cohortId}`);
    }
    if (graphIdentities.has(graph.graphManifestSha256)) {
      fail(`module graph manifests contain duplicate graph ${graph.graphManifestSha256}`);
    }
    const scheduledRouteIds = scheduledRoutesByCohort.get(graph.cohortId);
    if (scheduledRouteIds === undefined) {
      fail(
        `module graph ${graph.graphManifestSha256} is outside the authenticated cohort schedule`
      );
    }
    const cohortContract = contractsByCohort.get(graph.cohortId);
    if (cohortContract === undefined) {
      fail(`module graph ${graph.graphManifestSha256} has no authenticated cohort contract`);
    }
    if (
      canonicalJson(graph.contextReuseAnalysis) !==
        canonicalJson(cohortContract.contextReuseAnalysis) ||
      graph.contextReuseAnalysis.policyFingerprint !== contextReuseAnalysis.policyFingerprint
    ) {
      fail(
        `module graph ${graph.graphManifestSha256} context-reuse analysis differs from its cohort or deployment policy authority`
      );
    }
    if (canonicalJson(graph.engine) !== canonicalJson(cohortContract.engine)) {
      fail(
        `module graph ${graph.graphManifestSha256} engine identity differs from its authenticated cohort contract`
      );
    }
    if (
      canonicalJson(graph.producerImplementation) !==
      canonicalJson(cohortContract.producerImplementation)
    ) {
      fail(
        `module graph ${graph.graphManifestSha256} producer implementation differs from its authenticated cohort contract`
      );
    }
    const contractRouteById = new Map(cohortContract.routes.map((route) => [route.routeId, route]));
    for (const route of graph.routes) {
      if (graphRouteIds.has(route.routeId)) {
        fail(`module graph manifests contain duplicate route ${route.routeId}`);
      }
      graphRouteIds.add(route.routeId);
      assertGraphRouteMatchesDeployment(
        route,
        selectedRoutes.byRouteId.get(route.routeId),
        graph.cohortId
      );
      assertGraphRouteMatchesContract(route, contractRouteById.get(route.routeId), graph.cohortId);
      if (!scheduledRouteIds.includes(route.routeId)) {
        fail(`module graph cohort ${graph.cohortId} route ${route.routeId} has cohort drift`);
      }
    }
    const graphRouteIdsForCohort = graph.routes.map(({ routeId }) => routeId);
    const contractRouteIdsForCohort = cohortContract.routes.map(({ routeId }) => routeId);
    if (
      canonicalJson(graphRouteIdsForCohort) !== canonicalJson(scheduledRouteIds) ||
      canonicalJson(contractRouteIdsForCohort) !== canonicalJson(scheduledRouteIds)
    ) {
      fail(`module graph cohort ${graph.cohortId} does not cover its exact route closure`);
    }
    graphByCohort.set(graph.cohortId, graph);
    graphIdentities.add(graph.graphManifestSha256);
  }
  const missingCohortIds = [...scheduledRoutesByCohort.keys()]
    .filter((cohortId) => !graphByCohort.has(cohortId))
    .sort(compareStrings);
  if (missingCohortIds.length > 0) {
    fail("module graph manifests do not cover every authenticated cohort");
  }
  const extraContractCohortIds = [...contractsByCohort.keys()]
    .filter((cohortId) => !graphByCohort.has(cohortId))
    .sort(compareStrings);
  if (extraContractCohortIds.length > 0) {
    fail("module graph cohort contracts contain a cohort outside the graph closure");
  }
  const cohorts = [...graphByCohort.values()]
    .map((graph) => ({
      cohortId: graph.cohortId,
      cohortContractSha256: contractsByCohort.get(graph.cohortId).cohortContractSha256,
      graphManifestSha256: graph.graphManifestSha256,
      routeIds: graph.routes.map(({ routeId }) => routeId),
    }))
    .sort((left, right) => compareStrings(left.cohortId, right.cohortId));
  const payload = bindingPayload({
    cohorts,
    contextReuseAnalysis,
    scheduleSha256,
    sourceEnvelopeSha256,
  });
  return Object.freeze({ ...payload, bindingSha256: fingerprintJson(payload) });
}

function normalizeDeploymentGraphBinding(rawBinding) {
  const description = "deployment module graph binding";
  const binding = requireExactKeys(
    rawBinding,
    new Set([
      "bindingSha256",
      "cohorts",
      "contextReuseAnalysis",
      "kind",
      "scheduleSha256",
      "schemaVersion",
      "sourceEnvelopeSha256",
    ]),
    description
  );
  if (
    binding.kind !== convexWasmModuleGraphDeploymentBindingKind ||
    binding.schemaVersion !== 2 ||
    !Array.isArray(binding.cohorts) ||
    binding.cohorts.length === 0
  ) {
    fail(`${description} kind, schemaVersion, or cohorts are unsupported`);
  }
  const cohortIds = new Set();
  const graphManifestSha256s = new Set();
  const allRouteIds = new Set();
  const cohorts = binding.cohorts.map((rawCohort, cohortIndex) => {
    const cohortDescription = `${description} cohort ${cohortIndex}`;
    const cohort = requireExactKeys(
      rawCohort,
      new Set(["cohortContractSha256", "cohortId", "graphManifestSha256", "routeIds"]),
      cohortDescription
    );
    const cohortId = requireSha256(cohort.cohortId, `${cohortDescription} cohort ID`);
    const cohortContractSha256 = requireSha256(
      cohort.cohortContractSha256,
      `${cohortDescription} cohort contract SHA-256`
    );
    const graphManifestSha256 = requireSha256(
      cohort.graphManifestSha256,
      `${cohortDescription} graph manifest SHA-256`
    );
    if (!Array.isArray(cohort.routeIds) || cohort.routeIds.length === 0) {
      fail(`${cohortDescription} routeIds must be a non-empty array`);
    }
    const routeIds = cohort.routeIds.map((routeId, routeIndex) =>
      requireSha256(routeId, `${cohortDescription} route ID ${routeIndex}`)
    );
    if (
      new Set(routeIds).size !== routeIds.length ||
      canonicalJson(routeIds) !== canonicalJson([...routeIds].sort(compareStrings))
    ) {
      fail(`${cohortDescription} routeIds must be unique and sorted`);
    }
    if (cohortIds.has(cohortId)) fail(`${description} contains duplicate cohort ${cohortId}`);
    if (graphManifestSha256s.has(graphManifestSha256)) {
      fail(`${description} contains duplicate graph ${graphManifestSha256}`);
    }
    for (const routeId of routeIds) {
      if (allRouteIds.has(routeId)) fail(`${description} contains duplicate route ${routeId}`);
      allRouteIds.add(routeId);
    }
    cohortIds.add(cohortId);
    graphManifestSha256s.add(graphManifestSha256);
    return { cohortContractSha256, cohortId, graphManifestSha256, routeIds };
  });
  if (
    canonicalJson(cohorts.map(({ cohortId }) => cohortId)) !==
    canonicalJson([...cohortIds].sort(compareStrings))
  ) {
    fail(`${description} cohorts must be sorted by cohortId`);
  }
  const contextReuseAnalysis = authenticateConvexContextReuseResultIdentity(
    binding.contextReuseAnalysis
  );
  const payload = bindingPayload({
    cohorts,
    contextReuseAnalysis,
    scheduleSha256: requireSha256(binding.scheduleSha256, `${description} schedule SHA-256`),
    sourceEnvelopeSha256: requireSha256(
      binding.sourceEnvelopeSha256,
      `${description} source-envelope SHA-256`
    ),
  });
  const bindingSha256 = requireSha256(binding.bindingSha256, `${description} binding SHA-256`);
  if (bindingSha256 !== fingerprintJson(payload)) {
    fail(`${description} identity is invalid`);
  }
  return { ...payload, bindingSha256 };
}

export function bindConvexWasmModuleGraphsToDeploymentManifest(options) {
  const deployment = requireDeploymentIdentity(
    options.deploymentManifest,
    new Set([INPUT_DEPLOYMENT_KIND])
  );
  if (Object.hasOwn(deployment, "moduleGraphBinding")) {
    fail("deployment-v7 input already contains a module graph binding");
  }
  if (!Array.isArray(options.cohortContracts) || options.cohortContracts.length === 0) {
    fail("module graph binding requires at least one cohort contract");
  }
  const contracts = options.cohortContracts.map((contract) =>
    validateConvexWasmModuleGraphCohortContract(contract)
  );
  const contractRouteById = new Map(
    contracts.flatMap((contract) =>
      contract.routes.map((route) => [route.routeId, { contract, route }])
    )
  );
  if (contractRouteById.size !== contracts.flatMap(({ routes }) => routes).length) {
    fail("module graph cohort contracts contain duplicate routes");
  }
  const exports = deployment.exports.map((exported, index) => {
    if (exported.routing?.decision !== "wasm") return exported;
    const packageReference = requirePlainObject(
      exported.packageReference,
      `selected deployment export ${index} package reference`
    );
    const selected = contractRouteById.get(packageReference.routeId);
    if (selected === undefined) {
      fail(`selected deployment export ${index} has no module graph cohort contract route`);
    }
    return {
      ...exported,
      artifact: { cohortContractSha256: selected.contract.cohortContractSha256 },
      compiler: selected.contract.compiler,
      compilerLimits: selected.contract.execution.platformLimits,
      packageReference: {
        cohortContractSha256: selected.contract.cohortContractSha256,
        entryId: selected.route.entryId,
        entrySelectorId: selected.route.entrySelectorId,
        kind: convexWasmModuleGraphRouteReferenceKind,
        routeId: selected.route.routeId,
      },
    };
  });
  const graphNativeWithoutBinding = {
    ...deploymentWithoutIdentity(deployment),
    exports,
    kind: convexWasmModuleGraphDeploymentManifestKind,
    moduleGraphCohorts: contracts.sort((left, right) =>
      compareStrings(left.cohortId, right.cohortId)
    ),
  };
  const graphNativeDeployment = {
    ...graphNativeWithoutBinding,
    deploymentSha256: fingerprintJson(graphNativeWithoutBinding),
  };
  const moduleGraphBinding = createConvexWasmModuleGraphDeploymentBinding({
    ...options,
    deploymentManifest: graphNativeDeployment,
  });
  const manifestWithoutIdentity = {
    ...graphNativeWithoutBinding,
    moduleGraphBinding,
  };
  return Object.freeze({
    ...manifestWithoutIdentity,
    deploymentSha256: fingerprintJson(manifestWithoutIdentity),
  });
}

export function validateConvexWasmModuleGraphDeploymentManifest(options) {
  const deployment = requireDeploymentIdentity(
    options.deploymentManifest,
    new Set([convexWasmModuleGraphDeploymentManifestKind])
  );
  const moduleGraphBinding = normalizeDeploymentGraphBinding(deployment.moduleGraphBinding);
  if (!Array.isArray(deployment.moduleGraphCohorts)) {
    fail("deployment-v8 moduleGraphCohorts must be an array");
  }
  const embeddedContracts = deployment.moduleGraphCohorts.map((contract) =>
    validateConvexWasmModuleGraphCohortContract(contract)
  );
  const expected = createConvexWasmModuleGraphDeploymentBinding({
    ...options,
    cohortContracts: embeddedContracts,
  });
  if (canonicalJson(moduleGraphBinding) !== canonicalJson(expected)) {
    fail("deployment module graph binding differs from its exact graph, cohort, and route closure");
  }
  return Object.freeze({
    ...deployment,
    moduleGraphBinding: Object.freeze(moduleGraphBinding),
    moduleGraphCohorts: Object.freeze(embeddedContracts),
  });
}
