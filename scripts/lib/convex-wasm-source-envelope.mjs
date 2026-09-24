import { createHash, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";
import { isProxy } from "node:util/types";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "./convex-wasm-compiler-contract.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";
import { ensureCreatedPrivateDirectoryPath } from "./private-directory.mjs";

export const convexWasmSourceEnvelopeKind = "convex-wasm-source-envelope-v2";
const SOURCE_ENVELOPE_SCHEMA_VERSION = 2;
export const convexWasmSourceEnvelopeMaxBytes = 16 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;
const authenticatedSourceEnvelopes = new WeakSet();
const sourceEnvelopeDerivations = new WeakMap();
const retainedEntryNamespaces = new WeakMap();
const sourceEnvelopeEntryNamespaces = new WeakMap();

function fail(message) {
  throw new Error(`Convex Wasm source envelope: ${message}`);
}

function requireObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256.test(value)) {
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

function requireOwnFields(value, fields, description) {
  const object = requireObject(value, description);
  const missing = fields.filter((field) => !Object.hasOwn(object, field));
  if (missing.length > 0) {
    fail(`${description} omits required field(s): ${missing.join(", ")}`);
  }
  return object;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function routeKey(route) {
  return `${route.entryPath}\0${route.exportName}`;
}

function compareRoutes(left, right) {
  return compareStrings(routeKey(left), routeKey(right));
}

function sourceEnvelopeDerivationCache(graphSession, inventory) {
  const cache = graphSession?.sourceEnvelopeDerivation;
  const materialSha256 = inventory?.snapshot?.materialSha256;
  if (
    typeof materialSha256 !== "string" ||
    typeof cache !== "object" ||
    cache === null ||
    !(cache.routesByEntry instanceof Map) ||
    !(cache.selectedRoutesByIdentity instanceof Map) ||
    typeof cache.counters !== "object" ||
    cache.counters === null
  ) {
    return undefined;
  }
  if (cache.inventoryMaterialSha256 !== materialSha256) {
    cache.inventoryMaterialSha256 = materialSha256;
    cache.routesByEntry.clear();
    cache.selectedRoutesByIdentity.clear();
    cache.actions = undefined;
  }
  return cache;
}

// Route records have already passed the closed validator. Comparing their scalar identity fields
// directly avoids allocating canonical JSON for every route during repeated source-envelope
// checks.
function routeIdentityEqual(left, right, includeDependencyGraph) {
  return (
    left.entryPath === right.entryPath &&
    left.exportName === right.exportName &&
    left.modulePath === right.modulePath &&
    left.runtimeModulePath === right.runtimeModulePath &&
    left.udfKind === right.udfKind &&
    left.visibility === right.visibility &&
    (!includeDependencyGraph || left.dependencyGraphSha256 === right.dependencyGraphSha256)
  );
}

function routeArrayIdentityEqual(left, right, includeDependencyGraph) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (!routeIdentityEqual(left[index], right[index], includeDependencyGraph)) return false;
  }
  return true;
}

function stringArrayIdentityEqual(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export function isOrdinaryJsonData(value, ancestors = new WeakSet()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || isProxy(value)) return false;
  if (
    (Array.isArray(value)
      ? Object.getPrototypeOf(value) !== Array.prototype
      : Object.getPrototypeOf(value) !== Object.prototype) ||
    ancestors.has(value)
  ) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (
    Array.isArray(value)
      ? keys.length !== value.length + 1 || keys.at(-1) !== "length"
      : keys.some((key) => typeof key !== "string")
  ) {
    return false;
  }
  ancestors.add(value);
  for (const key of Array.isArray(value) ? keys.slice(0, -1) : keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      !isOrdinaryJsonData(descriptor.value, ancestors)
    ) {
      ancestors.delete(value);
      return false;
    }
  }
  ancestors.delete(value);
  return true;
}

function cachedRouteMatchesInventory(route, inventoryRoute) {
  const modulePath = inventoryRoute?.modulePath;
  return (
    isOrdinaryJsonData(route) &&
    Object.keys(route).length === 6 &&
    route.entryPath === inventoryRoute?.entryPath &&
    route.exportName === inventoryRoute?.exportName &&
    route.modulePath === modulePath &&
    route.runtimeModulePath === `${modulePath}.js` &&
    route.udfKind === inventoryRoute?.udfKind &&
    route.visibility === inventoryRoute?.visibility
  );
}

function freezeJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeJsonTree(child);
    Object.freeze(value);
  }
  return value;
}

function retainAuthenticatedSourceEnvelope(envelope) {
  if (!isOrdinaryJsonData(envelope)) {
    // Accessors and other unusual objects must be read again into ordinary immutable data before
    // they can acquire exact-object authentication authority.
    return validateConvexWasmSourceEnvelope(JSON.parse(canonicalJson(envelope)));
  }
  const authenticated = freezeJsonTree(structuredClone(envelope));
  authenticatedSourceEnvelopes.add(authenticated);
  const derivation = sourceEnvelopeDerivations.get(envelope);
  if (derivation !== undefined) sourceEnvelopeDerivations.set(authenticated, derivation);
  return authenticated;
}

// Only retained graph producers have a derivation owner. Serialized envelopes keep the ordinary
// schedule reconstruction path; a digest supplied by a caller never grants retained references.
export function retainedConvexWasmSourceEnvelopeEntryNamespaces(envelope) {
  if (!authenticatedSourceEnvelopes.has(envelope)) {
    fail("retained entry namespaces require an authenticated source envelope");
  }
  const derivation = sourceEnvelopeDerivations.get(envelope);
  if (derivation === undefined) return undefined;
  const existing = sourceEnvelopeEntryNamespaces.get(envelope);
  if (existing !== undefined) return existing;
  const previous = retainedEntryNamespaces.get(derivation);
  const current = new Map();
  const entries = [];
  let selectedOffset = 0;
  let inventoryOffset = 0;
  for (const entryPath of envelope.entryPaths) {
    const start = selectedOffset;
    while (envelope.selectedRoutes[selectedOffset]?.entryPath === entryPath) selectedOffset += 1;
    while (
      inventoryOffset < envelope.routes.length &&
      compareStrings(envelope.routes[inventoryOffset].entryPath, entryPath) < 0
    )
      inventoryOffset += 1;
    const inventoryStart = inventoryOffset;
    while (envelope.routes[inventoryOffset]?.entryPath === entryPath) inventoryOffset += 1;
    const first = envelope.selectedRoutes[start];
    if (selectedOffset - start !== inventoryOffset - inventoryStart) {
      fail(
        `selected entry ${entryPath} does not retain its complete authenticated query/mutation namespace`
      );
    }
    const retained = previous?.get(entryPath);
    let unchanged =
      retained !== undefined &&
      retained.dependencyGraphSha256 === first.dependencyGraphSha256 &&
      retained.modulePath === first.modulePath &&
      retained.runtimeModulePath === first.runtimeModulePath &&
      retained.routes.length === selectedOffset - start;
    for (let index = start; index < selectedOffset; index += 1) {
      const route = envelope.selectedRoutes[index];
      if (
        route.modulePath !== first.modulePath ||
        route.runtimeModulePath !== first.runtimeModulePath
      ) {
        fail(`selected entry ${entryPath} has inconsistent authenticated route authority`);
      }
      const prior = retained?.routes[index - start];
      unchanged &&=
        prior !== undefined &&
        prior.exportName === route.exportName &&
        prior.udfKind === route.udfKind &&
        prior.visibility === route.visibility;
    }
    const entry = unchanged
      ? retained
      : freezeJsonTree({
          dependencyGraphSha256: first.dependencyGraphSha256,
          entryPath,
          modulePath: first.modulePath,
          routes: envelope.selectedRoutes
            .slice(start, selectedOffset)
            .map(({ exportName, udfKind, visibility }) => ({ exportName, udfKind, visibility })),
          runtimeModulePath: first.runtimeModulePath,
        });
    current.set(entryPath, entry);
    entries.push(entry);
  }
  const result = Object.freeze(entries);
  retainedEntryNamespaces.set(derivation, current);
  sourceEnvelopeEntryNamespaces.set(envelope, result);
  return result;
}

export function selectConvexWasmContextReuseExports({ graphSession, inventory }) {
  if (!Array.isArray(inventory?.functions) || inventory.functions.length === 0) {
    fail("inventory must contain query or mutation routes");
  }
  if (!(graphSession?.contextReuseEnabledByEntry instanceof Map)) {
    fail("graph session has no context-reuse selection mapping");
  }
  // Context-reuse analyzes database UDF entries only. The isolate graph can still carry
  // action entries in its policy/topology, so do not include an enabled action-only entry when
  // authenticating the analyzer identity (the cached-session path applies the same narrowing).
  const databaseEntries = new Set(
    inventory.functions.map((route, index) =>
      requireString(route.entryPath, `inventory route ${index} entry path`)
    )
  );
  const enabledEntries = [...graphSession.contextReuseEnabledByEntry]
    .filter(([entryPath, enabled]) => enabled && databaseEntries.has(entryPath))
    .map(([entryPath]) => entryPath)
    .sort(compareStrings);
  authenticateConvexContextReuseResultIdentity(graphSession.contextReuseAnalysisIdentity, {
    expectedEntries: enabledEntries,
  });
  const wasmCompilationPolicy = graphSession.wasmCompilationPolicy;
  let selectedModulePaths;
  if (wasmCompilationPolicy !== undefined) {
    if (
      wasmCompilationPolicy?.default !== false ||
      !Array.isArray(wasmCompilationPolicy.modules) ||
      wasmCompilationPolicy.modules.length === 0
    ) {
      fail("Wasm compilation selection must contain at least one configured module");
    }
    selectedModulePaths = new Set(wasmCompilationPolicy.modules);
    if (selectedModulePaths.size !== wasmCompilationPolicy.modules.length) {
      fail("Wasm compilation selection contains duplicate modules");
    }
    const functionsByModule = new Map();
    for (const [index, route] of inventory.functions.entries()) {
      const modulePath = requireString(route.modulePath, `inventory route ${index} module path`);
      const routes = functionsByModule.get(modulePath) ?? [];
      routes.push(route);
      functionsByModule.set(modulePath, routes);
    }
    for (const modulePath of selectedModulePaths) {
      const routes = functionsByModule.get(modulePath);
      if (routes === undefined) {
        fail(`Wasm compilation module does not match a query or mutation module: ${modulePath}`);
      }
      const disabledEntry = routes.find(
        ({ entryPath }) => graphSession.contextReuseEnabledByEntry.get(entryPath) !== true
      );
      if (disabledEntry !== undefined) {
        fail(`Wasm compilation module is not context-reuse enabled: ${modulePath}`);
      }
    }
  }
  const selectedExports = inventory.functions
    .filter((route, index) => {
      const entryPath = requireString(route.entryPath, `inventory route ${index} entry path`);
      const enabled = graphSession.contextReuseEnabledByEntry.get(entryPath);
      if (typeof enabled !== "boolean") {
        fail(`context-reuse selection omits inventory entry ${entryPath}`);
      }
      return (
        enabled && (selectedModulePaths === undefined || selectedModulePaths.has(route.modulePath))
      );
    })
    .map((route, index) => ({
      exportName: requireString(route.exportName, `selected route ${index} export name`),
      modulePath: requireString(route.modulePath, `selected route ${index} module path`),
    }))
    .sort((left, right) => {
      const moduleOrder = compareStrings(left.modulePath, right.modulePath);
      return moduleOrder === 0 ? compareStrings(left.exportName, right.exportName) : moduleOrder;
    });
  if (selectedExports.length === 0) {
    fail("context-reuse selection contains no query or mutation routes");
  }
  return selectedExports;
}

function inventoryRoutes(inventory, graphSession) {
  if (!Array.isArray(inventory?.functions) || inventory.functions.length === 0) {
    fail("inventory must contain query or mutation routes");
  }
  if (!(graphSession?.bundleModulesByPath instanceof Map)) {
    fail("graph session has no complete isolate bundle module mapping");
  }
  const cache = sourceEnvelopeDerivationCache(graphSession, inventory);
  if (cache?.routesByEntry.size > 0) {
    const routes = [...cache.routesByEntry.values()].flat().sort(compareRoutes);
    if (
      routes.length === inventory.functions.length &&
      routes.every((route, index) => cachedRouteMatchesInventory(route, inventory.functions[index]))
    ) {
      for (const route of routes) {
        if (!graphSession.bundleModulesByPath.has(route.runtimeModulePath)) {
          fail(`complete isolate bundle has no runtime module ${route.runtimeModulePath}`);
        }
      }
      cache.counters.routesReused += routes.length;
      return routes;
    }
    // Returned envelopes expose mutable records. A caller must not be able to poison retained
    // derivation state by changing one of those records after construction.
    cache.routesByEntry.clear();
    cache.selectedRoutesByIdentity.clear();
  }
  const routes = inventory.functions
    .map((route, index) => {
      const entryPath = requireString(route.entryPath, `inventory route ${index} entry path`);
      const modulePath = requireString(route.modulePath, `inventory route ${index} module path`);
      const runtimeModulePath = `${modulePath}.js`;
      if (!graphSession.bundleModulesByPath.has(runtimeModulePath)) {
        fail(`complete isolate bundle has no runtime module ${runtimeModulePath}`);
      }
      return {
        entryPath,
        exportName: requireString(route.exportName, `inventory route ${index} export name`),
        modulePath,
        runtimeModulePath,
        udfKind: requireString(route.udfKind, `inventory route ${index} UDF kind`),
        visibility: requireString(route.visibility, `inventory route ${index} visibility`),
      };
    })
    .sort(compareRoutes);
  if (cache !== undefined) {
    const routesByEntry = new Map();
    for (const route of routes) {
      const entryRoutes = routesByEntry.get(route.entryPath);
      if (entryRoutes === undefined) {
        routesByEntry.set(route.entryPath, [route]);
      } else {
        entryRoutes.push(route);
      }
    }
    for (const [entryPath, entryRoutes] of routesByEntry) {
      cache.routesByEntry.set(entryPath, entryRoutes);
    }
    cache.counters.routesRebuilt += routes.length;
  }
  return routes;
}

function inventoryActions(inventory, graphSession) {
  if (!Array.isArray(inventory?.actions)) {
    fail("inventory actions must be an array");
  }
  const cache = sourceEnvelopeDerivationCache(graphSession, inventory);
  if (cache?.actions !== undefined) {
    if (
      cache.actions.length === inventory.actions.length &&
      cache.actions.every((action, index) =>
        cachedRouteMatchesInventory(action, inventory.actions[index])
      )
    ) {
      cache.counters.actionsReused += cache.actions.length;
      return cache.actions;
    }
    cache.actions = undefined;
  }
  const actions = inventory.actions
    .map((action, index) => {
      const modulePath = requireString(action.modulePath, `inventory action ${index} module path`);
      return {
        entryPath: requireString(action.entryPath, `inventory action ${index} entry path`),
        exportName: requireString(action.exportName, `inventory action ${index} export name`),
        modulePath,
        runtimeModulePath: `${modulePath}.js`,
        udfKind: "action",
        visibility: requireString(action.visibility, `inventory action ${index} visibility`),
      };
    })
    .sort(compareRoutes);
  if (cache !== undefined) {
    cache.actions = actions;
    cache.counters.actionsRebuilt += actions.length;
  }
  return actions;
}

function validateRoutes(
  value,
  description,
  udfKinds = ["query", "mutation"],
  { allowEmpty = false, dependencyGraph = true } = {}
) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    fail(`${description} must be ${allowEmpty ? "an" : "a non-empty"} array`);
  }
  const routes = value.map((rawRoute, index) => {
    const route = requireObject(rawRoute, `${description} ${index}`);
    const keys = Object.keys(route).sort(compareStrings);
    const expectedKeys = [
      ...(dependencyGraph ? ["dependencyGraphSha256"] : []),
      "entryPath",
      "exportName",
      "modulePath",
      "runtimeModulePath",
      "udfKind",
      "visibility",
    ];
    if (
      keys.length !== expectedKeys.length ||
      keys.some((key, keyIndex) => key !== expectedKeys[keyIndex])
    ) {
      fail(`${description} ${index} has unsupported fields`);
    }
    const normalized = Object.fromEntries(
      expectedKeys.map((key) => [key, requireString(route[key], `${description} ${index} ${key}`)])
    );
    if (dependencyGraph) {
      requireSha256(normalized.dependencyGraphSha256, `${description} ${index} dependency graph`);
    }
    if (normalized.runtimeModulePath !== `${normalized.modulePath}.js`) {
      fail(`${description} ${index} runtime module path does not match its source module`);
    }
    if (!udfKinds.includes(normalized.udfKind)) {
      fail(`${description} ${index} has unsupported UDF kind ${normalized.udfKind}`);
    }
    if (!["public", "internal"].includes(normalized.visibility)) {
      fail(`${description} ${index} has unsupported visibility ${normalized.visibility}`);
    }
    return normalized;
  });
  for (let index = 1; index < routes.length; index += 1) {
    if (compareRoutes(routes[index - 1], routes[index]) >= 0) {
      fail(`${description} must be lexically sorted and unique`);
    }
  }
  return routes;
}

export function createConvexWasmSourceEnvelope({ graphSession, inventory, selectedExports }) {
  if (!Array.isArray(selectedExports) || selectedExports.length === 0) {
    fail("selected exports must be a non-empty array");
  }
  if (graphSession?.effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode) {
    fail("source envelope graph must use guest-promise-event-loop");
  }
  if (!(graphSession.runtimeModulePathByEntry instanceof Map)) {
    fail("graph session has no selected runtime module path mapping");
  }
  if (!(graphSession.dependencyGraphByEntry instanceof Map)) {
    fail("graph session has no selected dependency graph mapping");
  }
  if (!(graphSession.contextReuseEnabledByEntry instanceof Map)) {
    fail("graph session has no context-reuse selection mapping");
  }
  if (!Array.isArray(inventory?.functions) || inventory.functions.length === 0) {
    fail("inventory must contain query or mutation routes");
  }
  // Context-reuse authenticates database UDF entries only. Action entries may still be
  // present in the graph policy map, but they are outside the analyzer result's entry identity.
  const databaseEntries = new Set(
    inventory.functions.map((route, index) =>
      requireString(route.entryPath, `inventory route ${index} entry path`)
    )
  );
  const enabledEntries = [...graphSession.contextReuseEnabledByEntry]
    .filter(([entryPath, enabled]) => enabled && databaseEntries.has(entryPath))
    .map(([entryPath]) => entryPath)
    .sort(compareStrings);
  const contextReuseAnalysis = authenticateConvexContextReuseResultIdentity(
    graphSession.contextReuseAnalysisIdentity,
    { expectedEntries: enabledEntries }
  );
  const routes = inventoryRoutes(inventory, graphSession);
  const derivationCache = sourceEnvelopeDerivationCache(graphSession, inventory);
  const routesBySelection = new Map(
    routes.map((route) => [`${route.modulePath}\0${route.exportName}`, route])
  );
  const selectedRoutes = selectedExports
    .map((selection, index) => {
      const modulePath = requireString(
        selection?.modulePath,
        `selected export ${index} module path`
      );
      const exportName = requireString(
        selection?.exportName,
        `selected export ${index} export name`
      );
      const route = routesBySelection.get(`${modulePath}\0${exportName}`);
      if (route === undefined) {
        fail(`selected export ${modulePath}:${exportName} was not found`);
      }
      if (graphSession.contextReuseEnabledByEntry.get(route.entryPath) !== true) {
        fail(`selected export ${modulePath}:${exportName} is not context-reuse enabled`);
      }
      const selectedRuntimeModulePath = graphSession.runtimeModulePathByEntry.get(route.entryPath);
      if (selectedRuntimeModulePath !== route.runtimeModulePath) {
        fail(`selected export ${modulePath}:${exportName} has no matching graph entry`);
      }
      const dependencyGraphSha256 = requireSha256(
        graphSession.dependencyGraphByEntry.get(route.entryPath)?.sha256,
        `selected export ${modulePath}:${exportName} dependency graph SHA-256`
      );
      const selectedRouteKey = `${routeKey(route)}\0${dependencyGraphSha256}`;
      const cachedSelectedRoute = derivationCache?.selectedRoutesByIdentity.get(selectedRouteKey);
      if (
        cachedSelectedRoute !== undefined &&
        routeIdentityEqual(cachedSelectedRoute, route, false) &&
        cachedSelectedRoute.dependencyGraphSha256 === dependencyGraphSha256 &&
        Object.keys(cachedSelectedRoute).length === 7
      ) {
        derivationCache.counters.selectedRoutesReused += 1;
        return cachedSelectedRoute;
      }
      const selectedRoute = {
        dependencyGraphSha256,
        ...route,
      };
      if (derivationCache !== undefined) {
        derivationCache.selectedRoutesByIdentity.set(selectedRouteKey, selectedRoute);
        derivationCache.counters.selectedRoutesRebuilt += 1;
      }
      return selectedRoute;
    })
    .sort(compareRoutes);
  for (let index = 1; index < selectedRoutes.length; index += 1) {
    if (compareRoutes(selectedRoutes[index - 1], selectedRoutes[index]) === 0) {
      fail("selected exports must be unique");
    }
  }
  const entryPaths = [...new Set(selectedRoutes.map(({ entryPath }) => entryPath))].sort(
    compareStrings
  );
  const payload = {
    actions: inventoryActions(inventory, graphSession),
    entryPaths,
    graph: {
      effectExecutionMode: graphSession.effectExecutionMode,
      inputCount: requirePositiveInteger(graphSession.inputCount, "graph input count"),
      sha256: requireSha256(graphSession.graphSha256, "graph SHA-256"),
      toolchain: requireObject(graphSession.toolchain, "graph toolchain"),
    },
    contextReuseAnalysis,
    inventoryAuthority: {
      kind: requireString(inventory.kind, "inventory kind"),
      snapshot: requireObject(inventory.snapshot, "inventory snapshot"),
    },
    kind: convexWasmSourceEnvelopeKind,
    routes,
    schemaVersion: SOURCE_ENVELOPE_SCHEMA_VERSION,
    selectedRoutes,
  };
  const envelope = { ...payload, sourceEnvelopeSha256: fingerprintJson(payload) };
  if (derivationCache !== undefined) sourceEnvelopeDerivations.set(envelope, derivationCache);
  return envelope;
}

export function validateConvexWasmSourceEnvelope(value) {
  if (authenticatedSourceEnvelopes.has(value)) return value;
  const envelope = requireObject(value, "source envelope");
  const keys = Object.keys(envelope).sort(compareStrings);
  const expectedKeys = [
    "actions",
    "contextReuseAnalysis",
    "entryPaths",
    "graph",
    "inventoryAuthority",
    "kind",
    "routes",
    "schemaVersion",
    "selectedRoutes",
    "sourceEnvelopeSha256",
  ];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, keyIndex) => key !== expectedKeys[keyIndex])
  ) {
    fail("source envelope has unsupported fields");
  }
  if (
    envelope.kind !== convexWasmSourceEnvelopeKind ||
    envelope.schemaVersion !== SOURCE_ENVELOPE_SCHEMA_VERSION
  ) {
    fail("source envelope kind or schema version is unsupported");
  }
  const { sourceEnvelopeSha256, ...payload } = envelope;
  requireSha256(sourceEnvelopeSha256, "source envelope SHA-256");
  if (sourceEnvelopeSha256 !== fingerprintJson(payload)) {
    fail("source envelope digest is invalid");
  }
  const routes = validateRoutes(envelope.routes, "source envelope routes", undefined, {
    dependencyGraph: false,
  });
  validateRoutes(envelope.actions, "source envelope actions", ["action"], {
    allowEmpty: true,
    dependencyGraph: false,
  });
  const selectedRoutes = validateRoutes(envelope.selectedRoutes, "source envelope selected routes");
  const routesByKey = new Map(routes.map((route) => [routeKey(route), route]));
  const dependencyGraphBySelectedEntry = new Map();
  for (const selected of selectedRoutes) {
    const inventoryRoute = routesByKey.get(routeKey(selected));
    if (inventoryRoute === undefined || !routeIdentityEqual(selected, inventoryRoute, false)) {
      fail(
        `selected route ${selected.entryPath}:${selected.exportName} is not in the route inventory`
      );
    }
    const previousDependencyGraphSha256 = dependencyGraphBySelectedEntry.get(selected.entryPath);
    if (
      previousDependencyGraphSha256 !== undefined &&
      previousDependencyGraphSha256 !== selected.dependencyGraphSha256
    ) {
      fail(`selected routes for ${selected.entryPath} have different dependency graphs`);
    }
    dependencyGraphBySelectedEntry.set(selected.entryPath, selected.dependencyGraphSha256);
  }
  const expectedEntryPaths = [...new Set(selectedRoutes.map(({ entryPath }) => entryPath))].sort(
    compareStrings
  );
  if (!stringArrayIdentityEqual(envelope.entryPaths, expectedEntryPaths)) {
    fail("source envelope entry paths do not match its selected routes");
  }
  const graph = requireOwnFields(
    envelope.graph,
    ["effectExecutionMode", "inputCount", "sha256", "toolchain"],
    "source envelope graph"
  );
  requireSha256(graph.sha256, "source envelope graph SHA-256");
  requirePositiveInteger(graph.inputCount, "source envelope graph input count");
  if (graph.effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode) {
    fail("source envelope graph must use guest-promise-event-loop");
  }
  const toolchain = requireOwnFields(
    graph.toolchain,
    ["convex", "esbuild"],
    "source envelope graph toolchain"
  );
  requireString(toolchain.convex, "source envelope graph Convex version");
  requireString(toolchain.esbuild, "source envelope graph esbuild version");
  const contextReuseAnalysis = authenticateConvexContextReuseResultIdentity(
    envelope.contextReuseAnalysis
  );
  const analyzedEntries = new Set(contextReuseAnalysis.entries);
  if (expectedEntryPaths.some((entryPath) => !analyzedEntries.has(entryPath))) {
    fail("source envelope selects an entry outside its context-reuse analysis");
  }
  const inventoryAuthority = requireOwnFields(
    envelope.inventoryAuthority,
    ["kind", "snapshot"],
    "source envelope inventory authority"
  );
  requireString(inventoryAuthority.kind, "source envelope inventory kind");
  requireObject(inventoryAuthority.snapshot, "source envelope inventory snapshot");
  return retainAuthenticatedSourceEnvelope(envelope);
}

export function projectConvexGeneratedApiInventoryFromSourceEnvelope(value) {
  const envelope = validateConvexWasmSourceEnvelope(value);
  if (envelope.inventoryAuthority.kind !== "convex-generated-api-inventory-v1") {
    fail("source envelope does not carry generated API inventory authority");
  }
  const projectRoute = ({ entryPath, exportName, modulePath, udfKind, visibility }) => ({
    entryPath,
    exportName,
    modulePath,
    udfKind,
    visibility,
  });
  // The envelope routes and actions are the complete inventory population. selectedRoutes is only
  // the deployment selection and must not narrow graph topology or final route authority.
  return freezeJsonTree({
    actions: envelope.actions.map(projectRoute),
    functions: envelope.routes.map(projectRoute),
    kind: envelope.inventoryAuthority.kind,
    snapshot: envelope.inventoryAuthority.snapshot,
  });
}

/**
 * Derive the authenticated source authority consumed by one exact entry cohort.
 *
 * The returned envelope keeps the global graph and inventory authority, but carries only the
 * selected query/mutation namespaces for the requested entries. This is the same authority the
 * official-output compiler binds into an individual cohort artifact.
 */
export function verifyCurrentConvexWasmSourceEnvelope({
  envelope: value,
  graphSession,
  inventory,
}) {
  const envelope = validateConvexWasmSourceEnvelope(value);
  const currentRoutes = inventoryRoutes(inventory, graphSession);
  const currentActions = inventoryActions(inventory, graphSession);
  const graphDifferences = [
    envelope.graph.sha256 === graphSession.graphSha256
      ? undefined
      : `SHA-256 expected=${envelope.graph.sha256} current=${graphSession.graphSha256}`,
    envelope.graph.effectExecutionMode === graphSession.effectExecutionMode
      ? undefined
      : `effect execution mode expected=${envelope.graph.effectExecutionMode} current=${graphSession.effectExecutionMode}`,
    envelope.graph.inputCount === graphSession.inputCount
      ? undefined
      : `input count expected=${String(envelope.graph.inputCount)} current=${String(graphSession.inputCount)}`,
    canonicalJson(envelope.graph.toolchain) === canonicalJson(graphSession.toolchain)
      ? undefined
      : `toolchain expected=${canonicalJson(envelope.graph.toolchain)} current=${canonicalJson(graphSession.toolchain)}`,
  ].filter((difference) => difference !== undefined);
  if (graphDifferences.length !== 0) {
    fail(
      `current installed Convex graph does not match the source envelope: ${graphDifferences.join("; ")}`
    );
  }
  if (!(graphSession.contextReuseEnabledByEntry instanceof Map)) {
    fail("current installed Convex graph has no context-reuse selection mapping");
  }
  const databaseEntries = new Set(currentRoutes.map(({ entryPath }) => entryPath));
  if (
    canonicalJson(envelope.contextReuseAnalysis) !==
    canonicalJson(
      authenticateConvexContextReuseResultIdentity(graphSession.contextReuseAnalysisIdentity, {
        expectedEntries: [...graphSession.contextReuseEnabledByEntry]
          .filter(([entryPath, enabled]) => enabled && databaseEntries.has(entryPath))
          .map(([entryPath]) => entryPath)
          .sort(compareStrings),
      })
    )
  ) {
    fail("current context-reuse result does not match the source envelope");
  }
  if (!(graphSession.dependencyGraphByEntry instanceof Map)) {
    fail("current installed Convex graph has no selected dependency graph mapping");
  }
  for (const route of envelope.selectedRoutes) {
    const currentDependencyGraphSha256 = graphSession.dependencyGraphByEntry.get(
      route.entryPath
    )?.sha256;
    if (currentDependencyGraphSha256 !== route.dependencyGraphSha256) {
      fail(
        `current selected route ${route.entryPath}:${route.exportName} dependency graph changed`
      );
    }
  }
  if (
    envelope.inventoryAuthority.kind !== inventory.kind ||
    canonicalJson(envelope.inventoryAuthority.snapshot) !== canonicalJson(inventory.snapshot) ||
    !routeArrayIdentityEqual(envelope.routes, currentRoutes, false) ||
    !routeArrayIdentityEqual(envelope.actions, currentActions, false)
  ) {
    fail("current generated API inventory does not match the source envelope");
  }
  return envelope;
}

export function verifyConvexWasmSourceEnvelopeSelectionSubset({
  authorityEnvelope: authorityValue,
  selectedEnvelope: selectedValue,
}) {
  const authorityEnvelope = validateConvexWasmSourceEnvelope(authorityValue);
  const selectedEnvelope = validateConvexWasmSourceEnvelope(selectedValue);
  const commonFields = [
    "actions",
    "graph",
    "contextReuseAnalysis",
    "inventoryAuthority",
    "kind",
    "routes",
    "schemaVersion",
  ];
  for (const field of commonFields) {
    const equal =
      field === "actions"
        ? routeArrayIdentityEqual(selectedEnvelope.actions, authorityEnvelope.actions, false)
        : field === "routes"
          ? routeArrayIdentityEqual(selectedEnvelope.routes, authorityEnvelope.routes, false)
          : canonicalJson(selectedEnvelope[field]) === canonicalJson(authorityEnvelope[field]);
    if (!equal) {
      fail(`selected source envelope ${field} differs from its authority envelope`);
    }
  }

  const authoritySelectedRoutes = new Map(
    authorityEnvelope.selectedRoutes.map((route) => [routeKey(route), route])
  );
  for (const selectedRoute of selectedEnvelope.selectedRoutes) {
    const authorityRoute = authoritySelectedRoutes.get(routeKey(selectedRoute));
    if (authorityRoute === undefined || !routeIdentityEqual(selectedRoute, authorityRoute, true)) {
      fail(
        `selected route ${selectedRoute.entryPath}:${selectedRoute.exportName} is not authenticated by the authority envelope`
      );
    }
  }
  return selectedEnvelope;
}

export async function publishConvexWasmSourceEnvelopePublication({ envelope, outputPath }) {
  const authenticatedEnvelope = validateConvexWasmSourceEnvelope(envelope);
  const finalPath = resolve(outputPath);
  const parent = dirname(finalPath);
  const bytes = Buffer.from(`${canonicalJson(authenticatedEnvelope)}\n`);
  if (bytes.length > convexWasmSourceEnvelopeMaxBytes) {
    fail(`encoded source envelope exceeds ${convexWasmSourceEnvelopeMaxBytes} bytes`);
  }
  const file = Object.freeze({
    path: finalPath,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  });
  await ensureCreatedPrivateDirectoryPath(parent, "source-envelope publication parent");
  const temporaryPath = `${finalPath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    const handle = await fs.open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      // Normalize through the already-open descriptor so a restrictive process umask cannot
      // publish a mode narrower than 0600, without ever following the final pathname.
      await handle.chmod(0o600);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporaryPath, finalPath);
    // The temporary file is already mode 0600. Do not chmod the published path by name: chmod
    // follows a replacement symlink, so a concurrent output-path swap could mutate a file outside
    // the requested output directory after the atomic rename.
    const parentHandle = await fs.open(parent, "r");
    try {
      await parentHandle.sync();
    } finally {
      await parentHandle.close();
    }
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
  return { bytes, file };
}

export async function publishConvexWasmSourceEnvelope({ envelope, outputPath }) {
  const publication = await publishConvexWasmSourceEnvelopePublication({
    envelope,
    outputPath,
  });
  return { bytes: publication.bytes.length, path: publication.file.path };
}
