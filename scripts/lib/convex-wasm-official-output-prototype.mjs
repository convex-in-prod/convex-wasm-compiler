import { createHash } from "node:crypto";
import { posix } from "node:path";
import { performance } from "node:perf_hooks";
import { Script, createContext } from "node:vm";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  canDeferConvexWasmDeploymentOutputClosureAuthentication,
  createConvexWasmDeploymentOutputClosureAuthentication,
  projectConvexWasmDeploymentOutputChunkGraph,
  selectConvexWasmDeploymentOutputClosure,
} from "./convex-wasm-output-closure.mjs";
import { verifyCurrentConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { convexWasmStaticHermesEsbuildSupportedSyntax } from "./convex-wasm-static-hermes-syntax.mjs";

export const convexWasmOfficialOutputPrototypeKind = "convex-wasm-official-output-prototype-v1";
export const convexWasmOfficialOutputPrototypeGlobal = "__convexWasmOfficialOutputPrototype";
export const convexWasmOfficialOutputCohortPrototypeKind =
  "convex-wasm-official-output-cohort-prototype-v1";
export const convexWasmOfficialOutputCohortPrototypeGlobal =
  "__convexWasmOfficialOutputCohortPrototype";
export const convexWasmOfficialOutputCohortMaximumEntries = 8;
export const convexWasmOfficialOutputSelectionSourceAuthenticationKind =
  "convex-wasm-official-output-selection-source-authentication-v1";

const selectionSourceAuthenticationRecords = new WeakMap();
const officialOutputSelectionRecords = new WeakMap();
const officialOutputPrototypeRecords = new WeakMap();
const officialOutputCohortPrototypeRecords = new WeakMap();
const officialOutputPrototypeInstanceRecords = new WeakMap();

const convexWasmOfficialOutputInitializationEnvironment = Object.freeze(
  new Proxy(Object.freeze(Object.create(null)), {
    get(_target, property) {
      throw new Error(
        `Convex process.env.${String(property)} cannot be read while initializing official output`
      );
    },
  })
);
export const convexWasmOfficialOutputInitializationProcess = Object.freeze({
  env: convexWasmOfficialOutputInitializationEnvironment,
});

function fail(message) {
  throw new Error(`Convex Wasm official-output prototype: ${message}`);
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
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

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function routeKey(entryPath, exportName) {
  return `${entryPath}\0${exportName}`;
}

function uniqueRoutesByKey(routes, description) {
  const routesByKey = new Map();
  for (const route of routes) {
    const key = routeKey(route.entryPath, route.exportName);
    if (routesByKey.has(key)) {
      fail(`${description} repeats ${route.entryPath}:${route.exportName}`);
    }
    routesByKey.set(key, route);
  }
  return routesByKey;
}

function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
  }
  return value;
}

function immutableAuthenticatedJsonSnapshot(value) {
  return freezeAuthenticatedJsonTree(JSON.parse(canonicalJson(value)));
}

function selectionSourceAuthenticationRecord(value) {
  const record = selectionSourceAuthenticationRecords.get(value);
  if (
    record === undefined ||
    value?.kind !== convexWasmOfficialOutputSelectionSourceAuthenticationKind ||
    value.sourceEnvelopeSha256 !== record.envelope.sourceEnvelopeSha256
  ) {
    fail("official-output selection source authentication is invalid");
  }
  return record;
}

function officialOutputSelectionRecord(selection) {
  const value = requireObject(selection, "official-output selection");
  const record = officialOutputSelectionRecords.get(value);
  if (
    record === undefined ||
    record.kind !== "authenticated-source" ||
    record.selection !== value ||
    record.closure !== value.closure ||
    record.manifestMembership !== value.manifestMembership ||
    record.route !== value.route ||
    record.toolchain !== value.toolchain ||
    selectionSourceAuthenticationRecords.get(record.sourceAuthentication) !== record.sourceRecord
  ) {
    fail("official-output selection provenance is invalid");
  }
  return record;
}

export function authenticateConvexWasmOfficialOutputSelection(selection) {
  const value = requireObject(selection, "official-output selection");
  officialOutputSelectionRecord(value);
  return value;
}

export function authenticateConvexWasmOfficialOutputSelectionSet(selections) {
  if (!Array.isArray(selections) || selections.length === 0) {
    fail("official-output selection set must contain at least one selection");
  }
  const authenticatedSelections = selections.map((selection) =>
    authenticateConvexWasmOfficialOutputSelection(selection)
  );
  const records = authenticatedSelections.map(officialOutputSelectionRecord);
  const sourceAuthentication = records[0].sourceAuthentication;
  if (records.some((record) => record.sourceAuthentication !== sourceAuthentication)) {
    fail("official-output selections do not share the exact source authentication");
  }
  return Object.freeze({
    selections: Object.freeze(authenticatedSelections),
    sourceAuthentication,
  });
}

export function projectConvexWasmOfficialOutputSourceChunkGraph(sourceAuthentication) {
  const record = selectionSourceAuthenticationRecord(sourceAuthentication);
  if (record.chunkGraph !== undefined) return record.chunkGraph;
  verifySelectionSourceAuthenticationBaseline(record);
  // Locators describe occurrences in the complete producer graph, not the route subset that
  // happens to miss its cohort capsule first. Reuse the source owner's exact module admission.
  record.chunkGraph = projectConvexWasmDeploymentOutputChunkGraph({
    authentication: record.outputClosureAuthentication,
    graphSession: record.graphSession,
  });
  return record.chunkGraph;
}

function selectedRoutesFromAuthentication(record, selectedExports) {
  if (!Array.isArray(selectedExports) || selectedExports.length === 0) {
    fail("authenticated official-output selection must contain at least one route");
  }
  const selectedRoutes = selectedExports
    .map((rawSelection, index) => {
      const selection = requireObject(
        rawSelection,
        `authenticated official-output selection ${index}`
      );
      const keys = Object.keys(selection).sort(compareStrings);
      if (keys.length !== 2 || keys[0] !== "exportName" || keys[1] !== "modulePath") {
        fail(`authenticated official-output selection ${index} has unsupported fields`);
      }
      const modulePath = requireString(
        selection.modulePath,
        `authenticated official-output selection ${index} module path`
      );
      const exportName = requireString(
        selection.exportName,
        `authenticated official-output selection ${index} export name`
      );
      const route = record.selectedRoutesByModuleAndExport.get(`${modulePath}\0${exportName}`);
      if (route === undefined) {
        fail(
          `selected export ${modulePath}:${exportName} is not admitted by the authenticated selection manifest`
        );
      }
      return route;
    })
    .sort((left, right) =>
      compareStrings(
        routeKey(left.entryPath, left.exportName),
        routeKey(right.entryPath, right.exportName)
      )
    );
  for (let index = 1; index < selectedRoutes.length; index += 1) {
    if (
      routeKey(selectedRoutes[index - 1].entryPath, selectedRoutes[index - 1].exportName) ===
      routeKey(selectedRoutes[index].entryPath, selectedRoutes[index].exportName)
    ) {
      fail("authenticated official-output selection contains duplicate routes");
    }
  }
  return selectedRoutes;
}

function verifySelectionSourceAuthenticationBaseline(record) {
  const { envelope, graphSession } = record;
  if (!record.firstSelectionBaselineVerified) {
    if (
      graphSession.graphSha256 !== envelope.graph.sha256 ||
      graphSession.effectExecutionMode !== envelope.graph.effectExecutionMode ||
      graphSession.inputCount !== envelope.graph.inputCount ||
      canonicalJson(graphSession.toolchain) !== canonicalJson(envelope.graph.toolchain)
    ) {
      fail("installed Convex graph changed after source authentication");
    }
    if (
      graphSession.bundleModulesByPath !== record.bundleModulesByPath ||
      graphSession.dependencyGraphByEntry !== record.dependencyGraphByEntry ||
      graphSession.deploymentOutputClosureByEntry !== record.deploymentOutputClosureByEntry ||
      graphSession.deploymentOutputModulesByPath !== record.deploymentOutputModulesByPath ||
      graphSession.runtimeModulePathByEntry !== record.runtimeModulePathByEntry
    ) {
      fail("installed Convex graph material changed after source authentication");
    }
    if (
      record.deferredExactClosureAuthentication &&
      !canDeferConvexWasmDeploymentOutputClosureAuthentication({
        authentication: record.outputClosureAuthentication,
        graphSession,
      })
    ) {
      fail("installed Convex graph material changed after source authentication");
    }
    // Authentication owns immutable exact output. First use checks every materialized snapshot;
    // deferred entries retain the exact producer-map authority until their first selection.
    for (const entry of record.entrySnapshotsByPath.values()) {
      if (
        record.runtimeModulePathByEntry.get(entry.entryPath) !== entry.runtimeModulePath ||
        record.dependencyGraphByEntry.get(entry.entryPath) !== entry.dependencyGraph ||
        entry.dependencyGraph.sha256 !== entry.dependencyGraphSha256 ||
        record.deploymentOutputClosureByEntry.get(entry.entryPath) !== entry.closure.identity
      ) {
        fail(`selected entry ${entry.entryPath} changed after source authentication`);
      }
    }
    for (const module of record.moduleSnapshotsByPath.values()) {
      if (
        record.bundleModulesByPath.get(module.path) !== module.bundleIdentity ||
        record.deploymentOutputModulesByPath.get(module.path) !== module.deploymentModule
      ) {
        fail(`deployment output module ${module.path} changed after source authentication`);
      }
    }
    record.firstSelectionBaselineVerified = true;
  }
}

function selectedEntrySnapshot(record, entryPath) {
  const existing = record.entrySnapshotsByPath.get(entryPath);
  if (existing !== undefined) return existing;
  const facts = record.entryFactsByPath.get(entryPath);
  if (facts === undefined) {
    fail(`authenticated selected entry ${entryPath} has no route facts`);
  }
  const dependencyGraph = requireObject(
    record.graphSession.dependencyGraphByEntry.get(entryPath),
    `selected entry ${entryPath} dependency graph`
  );
  if (
    record.graphSession.runtimeModulePathByEntry.get(entryPath) !== facts.runtimeModulePath ||
    dependencyGraph.sha256 !== facts.dependencyGraphSha256
  ) {
    fail(`selected entry ${entryPath} disagrees with its authenticated graph identity`);
  }
  const closure = selectConvexWasmDeploymentOutputClosure({
    authentication: record.outputClosureAuthentication,
    entryPath,
    graphSession: record.graphSession,
  });
  if (closure.identity.entryModulePath !== facts.runtimeModulePath) {
    fail(`selected entry ${entryPath} closure entry disagrees with its authenticated route`);
  }
  const snapshot = {
    closure,
    dependencyGraph,
    dependencyGraphSha256: facts.dependencyGraphSha256,
    entryPath,
    runtimeModulePath: facts.runtimeModulePath,
  };
  record.entrySnapshotsByPath.set(entryPath, snapshot);
  for (const module of closure.modules) {
    const path = module.identity.path;
    const bundleIdentity = record.graphSession.bundleModulesByPath.get(path);
    const deploymentModule = record.graphSession.deploymentOutputModulesByPath.get(path);
    if (bundleIdentity === undefined || deploymentModule === undefined) {
      fail(`selected entry ${entryPath} lost authenticated output module ${path}`);
    }
    const previous = record.moduleSnapshotsByPath.get(path);
    if (
      previous !== undefined &&
      (previous.bundleIdentity !== bundleIdentity ||
        previous.deploymentModule !== deploymentModule ||
        previous.module !== module)
    ) {
      fail(`authenticated selected entries disagree on shared output module ${path}`);
    }
    record.moduleSnapshotsByPath.set(path, { bundleIdentity, deploymentModule, module, path });
  }
  return snapshot;
}

function createSelectionSession(record, selectedRoutes) {
  const { envelope } = record;
  const selectedRoutesByKey = uniqueRoutesByKey(selectedRoutes, "authenticated selection manifest");
  const { actionsByKey, routesByKey } = record;

  return Object.freeze({
    select({ entryPath, exportName }) {
      const selectedEntryPath = requireString(entryPath, "selected entry path");
      const selectedExportName = requireString(exportName, "selected export name");
      const key = routeKey(selectedEntryPath, selectedExportName);
      if (actionsByKey.has(key)) {
        fail(`selected export ${selectedEntryPath}:${selectedExportName} is an action`);
      }
      if (!routesByKey.has(key)) {
        fail(
          `selected export ${selectedEntryPath}:${selectedExportName} is not in the authenticated query/mutation manifest`
        );
      }
      const route = selectedRoutesByKey.get(key);
      if (route === undefined) {
        fail(
          `selected export ${selectedEntryPath}:${selectedExportName} is not admitted by the authenticated selection manifest`
        );
      }
      if (!["query", "mutation"].includes(route.udfKind)) {
        fail(`selected export ${selectedEntryPath}:${selectedExportName} has unsupported UDF kind`);
      }
      if (!["internal", "public"].includes(route.visibility)) {
        fail(
          `selected export ${selectedEntryPath}:${selectedExportName} has unsupported visibility`
        );
      }
      verifySelectionSourceAuthenticationBaseline(record);
      const closure = selectedEntrySnapshot(record, selectedEntryPath).closure;
      if (closure.identity.entryModulePath !== route.runtimeModulePath) {
        fail(`selected export ${selectedEntryPath}:${selectedExportName} closure entry disagrees`);
      }
      const selection = Object.freeze({
        closure,
        manifestMembership: Object.freeze({
          dependencyGraphSha256: route.dependencyGraphSha256,
          inventoryKind: envelope.inventoryAuthority.kind,
          sourceEnvelopeSha256: envelope.sourceEnvelopeSha256,
        }),
        route: Object.freeze({
          entryPath: route.entryPath,
          exportName: route.exportName,
          modulePath: route.modulePath,
          runtimeModulePath: route.runtimeModulePath,
          udfKind: route.udfKind,
          visibility: route.visibility,
        }),
        toolchain: record.toolchain,
      });
      officialOutputSelectionRecords.set(selection, {
        closure: selection.closure,
        kind: "authenticated-source",
        manifestMembership: selection.manifestMembership,
        route: selection.route,
        selection,
        sourceAuthentication: record.authentication,
        sourceRecord: record,
        toolchain: selection.toolchain,
      });
      return selection;
    },
  });
}

export function authenticateConvexWasmOfficialOutputSelectionSource({
  graphSession,
  inventory,
  sourceEnvelope,
}) {
  const envelope = verifyCurrentConvexWasmSourceEnvelope({
    envelope: sourceEnvelope,
    graphSession,
    inventory,
  });
  const selectedRoutesByModuleAndExport = new Map();
  for (const route of envelope.selectedRoutes) {
    const key = `${route.modulePath}\0${route.exportName}`;
    if (selectedRoutesByModuleAndExport.has(key)) {
      fail(`authenticated selection manifest repeats ${route.modulePath}:${route.exportName}`);
    }
    selectedRoutesByModuleAndExport.set(key, route);
  }
  const authentication = Object.freeze({
    kind: convexWasmOfficialOutputSelectionSourceAuthenticationKind,
    sourceEnvelopeSha256: envelope.sourceEnvelopeSha256,
  });
  const outputClosureAuthentication =
    createConvexWasmDeploymentOutputClosureAuthentication(graphSession);
  const toolchain = envelope.graph.toolchain;
  const entryFactsByPath = new Map();
  for (const route of envelope.selectedRoutes) {
    const existing = entryFactsByPath.get(route.entryPath);
    if (
      existing !== undefined &&
      (existing.dependencyGraphSha256 !== route.dependencyGraphSha256 ||
        existing.runtimeModulePath !== route.runtimeModulePath)
    ) {
      fail(`authenticated routes disagree on selected entry ${route.entryPath}`);
    }
    entryFactsByPath.set(route.entryPath, {
      dependencyGraphSha256: route.dependencyGraphSha256,
      runtimeModulePath: route.runtimeModulePath,
    });
  }
  const entrySnapshotsByPath = new Map();
  const moduleSnapshotsByPath = new Map();
  const deferredExactClosureAuthentication =
    canDeferConvexWasmDeploymentOutputClosureAuthentication({
      authentication: outputClosureAuthentication,
      graphSession,
    });
  const record = {
    actionsByKey: uniqueRoutesByKey(envelope.actions, "authenticated action manifest"),
    authentication,
    bundleModulesByPath: graphSession.bundleModulesByPath,
    dependencyGraphByEntry: graphSession.dependencyGraphByEntry,
    deploymentOutputClosureByEntry: graphSession.deploymentOutputClosureByEntry,
    deploymentOutputModulesByPath: graphSession.deploymentOutputModulesByPath,
    deferredExactClosureAuthentication,
    envelope,
    entryFactsByPath,
    entrySnapshotsByPath,
    firstSelectionBaselineVerified: false,
    graphSession,
    moduleSnapshotsByPath,
    outputClosureAuthentication,
    routesByKey: uniqueRoutesByKey(envelope.routes, "authenticated query/mutation manifest"),
    runtimeModulePathByEntry: graphSession.runtimeModulePathByEntry,
    selectedRoutesByModuleAndExport,
    toolchain,
  };
  // Maintained deployment sessions freeze the exact producer graph before this boundary. Capsule
  // hits do not consume source bytes, so authenticate a closure only when a miss selects that
  // entry. Foreign or mutable graph sessions retain the complete eager authentication contract.
  if (!deferredExactClosureAuthentication) {
    for (const entryPath of envelope.entryPaths) selectedEntrySnapshot(record, entryPath);
  }
  selectionSourceAuthenticationRecords.set(authentication, record);
  return authentication;
}

export function createConvexWasmOfficialOutputSelectionSessionFromAuthenticatedSource({
  selectedExports,
  sourceAuthentication,
}) {
  const record = selectionSourceAuthenticationRecord(sourceAuthentication);
  const selectedRoutes = selectedRoutesFromAuthentication(record, selectedExports);
  return createSelectionSession(record, selectedRoutes);
}

export function createConvexWasmOfficialOutputSelectionSession({
  graphSession,
  inventory,
  sourceEnvelope,
}) {
  const sourceAuthentication = authenticateConvexWasmOfficialOutputSelectionSource({
    graphSession,
    inventory,
    sourceEnvelope,
  });
  const record = selectionSourceAuthenticationRecord(sourceAuthentication);
  return createSelectionSession(record, record.envelope.selectedRoutes);
}

export function selectConvexWasmOfficialOutputPrototype(options) {
  const { entryPath, exportName, ...sessionOptions } = options;
  return createConvexWasmOfficialOutputSelectionSession(sessionOptions).select({
    entryPath,
    exportName,
  });
}

function exactOfficialOutputClosureModules(closure, description) {
  const identity = requireObject(closure.identity, `${description} identity`);
  const { sha256, ...identityPayload } = identity;
  if (sha256 !== fingerprintJson(identityPayload)) {
    fail(`${description} identity is invalid`);
  }
  if (!Array.isArray(identity.modules) || !Array.isArray(closure.modules)) {
    fail(`${description} must contain authenticated module identities and exact modules`);
  }
  if (identity.modules.length === 0 || identity.modules.length !== closure.modules.length) {
    fail(`${description} modules do not exactly match its authenticated identity`);
  }
  return closure.modules.map((rawModule, index) => {
    const module = requireObject(rawModule, `${description} module ${index}`);
    const moduleIdentity = requireObject(
      module.identity,
      `${description} module ${index} identity`
    );
    const expectedIdentity = requireObject(
      identity.modules[index],
      `${description} authenticated module identity ${index}`
    );
    if (canonicalJson(moduleIdentity) !== canonicalJson(expectedIdentity)) {
      fail(`${description} modules do not exactly match its authenticated identity`);
    }
    const path = requireString(moduleIdentity.path, `${description} module ${index} path`);
    const source = requireString(module.source, `${description} module ${path} source`);
    const sourceMap = module.sourceMap;
    if (
      moduleIdentity.environment !== "isolate" ||
      moduleIdentity.sourceSha256 !== createHash("sha256").update(source).digest("hex") ||
      moduleIdentity.sourceSize !== Buffer.byteLength(source)
    ) {
      fail(`${description} module ${path} bytes disagree with its authenticated identity`);
    }
    const sourceMapIdentity = requireObject(
      moduleIdentity.sourceMap,
      `${description} module ${path} source map identity`
    );
    let parsedSourceMap;
    try {
      parsedSourceMap = JSON.parse(sourceMap);
    } catch {
      fail(`${description} module ${path} source map is not valid JSON`);
    }
    if (
      typeof sourceMap !== "string" ||
      parsedSourceMap === null ||
      typeof parsedSourceMap !== "object" ||
      Array.isArray(parsedSourceMap) ||
      parsedSourceMap.version !== 3 ||
      !Array.isArray(parsedSourceMap.sources) ||
      sourceMapIdentity.sha256 !== createHash("sha256").update(sourceMap).digest("hex") ||
      sourceMapIdentity.size !== Buffer.byteLength(sourceMap) ||
      sourceMapIdentity.sourcesContentCount !==
        (Array.isArray(parsedSourceMap.sourcesContent)
          ? parsedSourceMap.sourcesContent.filter((value) => value !== null).length
          : 0) ||
      sourceMapIdentity.sourcesCount !== parsedSourceMap.sources.length ||
      moduleIdentity.sourceMembershipSha256 !==
        convexWasmOfficialOutputSourceMembershipIdentitySha256({
          sourceRoot: parsedSourceMap.sourceRoot,
          sources: parsedSourceMap.sources,
        })
    ) {
      fail(`${description} module ${path} source map disagrees with its authenticated identity`);
    }
    if (
      moduleIdentity.moduleSha256 !==
      createHash("sha256")
        .update(source)
        .update(sourceMap === undefined ? "" : sourceMap)
        .digest("hex")
    ) {
      fail(`${description} module ${path} bytes disagree with its authenticated identity`);
    }
    return module;
  });
}

function officialOutputPlugin(modulesByPath, entrySource) {
  return {
    name: "authenticated-official-output-prototype",
    setup(build) {
      build.onResolve({ filter: /^official-output-(?:cohort-)?prototype-entry$/ }, () => ({
        namespace: "official-output-prototype-entry",
        path: "entry.js",
      }));
      build.onLoad({ filter: /.*/, namespace: "official-output-prototype-entry" }, () => ({
        contents: entrySource,
        loader: "js",
      }));
      build.onResolve({ filter: /^official-output:/ }, ({ path }) => {
        const modulePath = path.slice("official-output:".length);
        if (!modulesByPath.has(modulePath)) {
          fail(`prototype entry imports absent official output ${modulePath}`);
        }
        return { namespace: "official-output", path: modulePath };
      });
      build.onResolve({ filter: /.*/, namespace: "official-output" }, ({ importer, path }) => {
        if (!path.startsWith(".")) {
          fail(`official output retained non-relative import ${importer} -> ${path}`);
        }
        const modulePath = posix.normalize(posix.join(posix.dirname(importer), path));
        if (!modulesByPath.has(modulePath)) {
          fail(
            `official output import escapes the authenticated closure ${importer} -> ${modulePath}`
          );
        }
        return { namespace: "official-output", path: modulePath };
      });
      build.onLoad({ filter: /.*/, namespace: "official-output" }, ({ path }) => ({
        contents: modulesByPath.get(path).source,
        loader: "js",
      }));
    },
  };
}

const officialOutputEsbuildSettings = Object.freeze({
  conditions: Object.freeze(["convex", "module"]),
  format: "iife",
  keepNames: true,
  minifyIdentifiers: true,
  minifySyntax: false,
  minifyWhitespace: false,
  platform: "browser",
  sourcemap: false,
  splitting: false,
  supported: convexWasmStaticHermesEsbuildSupportedSyntax,
  target: "esnext",
  treeShaking: true,
});

function esbuildOptions(globalName, entryPoint, modulesByPath, entrySource) {
  return {
    bundle: true,
    conditions: [...officialOutputEsbuildSettings.conditions],
    entryPoints: [entryPoint],
    format: officialOutputEsbuildSettings.format,
    globalName,
    keepNames: officialOutputEsbuildSettings.keepNames,
    logLevel: "silent",
    metafile: true,
    minifyIdentifiers: officialOutputEsbuildSettings.minifyIdentifiers,
    minifySyntax: officialOutputEsbuildSettings.minifySyntax,
    minifyWhitespace: officialOutputEsbuildSettings.minifyWhitespace,
    outfile: `${entryPoint}.js`,
    platform: officialOutputEsbuildSettings.platform,
    plugins: [officialOutputPlugin(modulesByPath, entrySource)],
    sourcemap: officialOutputEsbuildSettings.sourcemap,
    splitting: officialOutputEsbuildSettings.splitting,
    supported: { ...officialOutputEsbuildSettings.supported },
    target: officialOutputEsbuildSettings.target,
    treeShaking: officialOutputEsbuildSettings.treeShaking,
    write: false,
  };
}

export async function buildConvexWasmOfficialOutputPrototype({ esbuild, selection }) {
  requireObject(esbuild, "esbuild API");
  const authenticatedSelection = authenticateConvexWasmOfficialOutputSelection(selection);
  const selectionRecord = officialOutputSelectionRecord(authenticatedSelection);
  const route = requireObject(authenticatedSelection.route, "official-output route");
  const closure = requireObject(authenticatedSelection.closure, "official-output closure");
  if (esbuild.version !== authenticatedSelection.toolchain?.esbuild) {
    fail("outer compiler does not match the authenticated graph esbuild version");
  }
  const modules = exactOfficialOutputClosureModules(closure, "official-output closure");
  const modulesByPath = new Map();
  for (const module of modules) {
    const identity = module.identity;
    const path = requireString(identity.path, "official-output module path");
    if (modulesByPath.has(path)) {
      fail(`official-output closure repeats module ${path}`);
    }
    modulesByPath.set(path, module);
  }
  const entryModulePath = requireString(
    closure.identity?.entryModulePath,
    "official-output entry module path"
  );
  if (!modulesByPath.has(entryModulePath)) {
    fail(`official-output closure omits its entry module ${entryModulePath}`);
  }
  const entrySource =
    `import * as entry from ${JSON.stringify(`official-output:${entryModulePath}`)};\n` +
    "export { entry };\n";
  const started = performance.now();
  const result = await esbuild.build(
    esbuildOptions(
      convexWasmOfficialOutputPrototypeGlobal,
      "official-output-prototype-entry",
      modulesByPath,
      entrySource
    )
  );
  if (result.outputFiles.length !== 1) {
    fail("outer compiler did not emit exactly one JavaScript unit");
  }
  const moduleInputs = Object.keys(result.metafile.inputs)
    .filter((path) => path.startsWith("official-output:"))
    .map((path) => path.slice("official-output:".length))
    .sort(compareStrings);
  const expectedModuleInputs = [...modulesByPath.keys()].sort(compareStrings);
  if (JSON.stringify(moduleInputs) !== JSON.stringify(expectedModuleInputs)) {
    fail("outer compiler did not consume the complete authenticated official-output closure");
  }
  const javascript = result.outputFiles[0].text;
  const identity = {
    closureSha256: requireString(closure.identity.sha256, "official-output closure SHA-256"),
    dependencyGraphSha256: requireString(
      authenticatedSelection.manifestMembership.dependencyGraphSha256,
      "official-output dependency-graph SHA-256"
    ),
    entryModulePath,
    entryPath: requireString(route.entryPath, "official-output route entry path"),
    esbuildVersion: esbuild.version,
    exportName: route.exportName,
    javascriptBytes: Buffer.byteLength(javascript),
    javascriptSha256: createHash("sha256").update(javascript).digest("hex"),
    kind: convexWasmOfficialOutputPrototypeKind,
    metafileSha256: fingerprintJson(result.metafile),
    modulePath: requireString(route.modulePath, "official-output route module path"),
    moduleCount: modulesByPath.size,
    officialSourceBytes: modules.reduce((sum, module) => sum + module.identity.sourceSize, 0),
    sourceEnvelopeSha256: authenticatedSelection.manifestMembership.sourceEnvelopeSha256,
    treeShaking: true,
    udfKind: route.udfKind,
    visibility: route.visibility,
  };
  const prototype = immutableAuthenticatedJsonSnapshot({
    identity: { ...identity, sha256: fingerprintJson(identity) },
    javascript,
    metafile: result.metafile,
    phaseTimingsMilliseconds: { outerCompile: performance.now() - started },
  });
  officialOutputPrototypeRecords.set(prototype, {
    prototype,
    sourceAuthentication: selectionRecord.sourceAuthentication,
  });
  return authenticateConvexWasmOfficialOutputPrototype(prototype);
}

function normalizedCohortSelections(selections) {
  if (!Array.isArray(selections) || selections.length < 2) {
    fail("cohort selections must contain routes from at least two entries");
  }
  const authenticatedSet = authenticateConvexWasmOfficialOutputSelectionSet(selections);
  const routes = authenticatedSet.selections
    .map((selection, index) => {
      const authenticatedSelection = selection;
      const route = requireObject(authenticatedSelection.route, `cohort selection ${index} route`);
      const closure = requireObject(
        authenticatedSelection.closure,
        `cohort selection ${index} closure`
      );
      const membership = requireObject(
        authenticatedSelection.manifestMembership,
        `cohort selection ${index} manifest membership`
      );
      if (
        !authenticatedSelection.toolchain ||
        typeof authenticatedSelection.toolchain.esbuild !== "string"
      ) {
        fail(`cohort selection ${index} has no authenticated esbuild version`);
      }
      if (route.udfKind !== "query" && route.udfKind !== "mutation") {
        fail(`cohort selection ${index} has an unsupported UDF kind`);
      }
      return { closure, membership, route, selection: authenticatedSelection };
    })
    .sort((left, right) => {
      const entryOrder = compareStrings(left.route.entryPath, right.route.entryPath);
      return entryOrder === 0
        ? compareStrings(left.route.exportName, right.route.exportName)
        : entryOrder;
    });
  const sourceEnvelopeSha256 = requireString(
    routes[0].membership.sourceEnvelopeSha256,
    "cohort source-envelope SHA-256"
  );
  const esbuildVersion = routes[0].selection.toolchain.esbuild;
  if (
    routes.some(
      ({ membership, selection }) =>
        membership.sourceEnvelopeSha256 !== sourceEnvelopeSha256 ||
        selection.toolchain.esbuild !== esbuildVersion
    )
  ) {
    fail("cohort selections disagree on authenticated source or toolchain identity");
  }
  for (let index = 1; index < routes.length; index += 1) {
    if (
      routes[index - 1].route.entryPath === routes[index].route.entryPath &&
      routes[index - 1].route.exportName === routes[index].route.exportName
    ) {
      fail(
        `cohort selections repeat route ${routes[index].route.entryPath}:${routes[index].route.exportName}`
      );
    }
  }
  const entries = [];
  for (const item of routes) {
    const previous = entries.at(-1);
    if (previous?.entryPath === item.route.entryPath) {
      if (
        previous.closure.identity.sha256 !== item.closure.identity?.sha256 ||
        previous.entryModulePath !== item.closure.identity?.entryModulePath ||
        previous.modulePath !== item.route.modulePath ||
        previous.runtimeModulePath !== item.route.runtimeModulePath ||
        previous.dependencyGraphSha256 !== item.membership.dependencyGraphSha256
      ) {
        fail(`cohort routes for ${item.route.entryPath} disagree on their official entry`);
      }
      previous.routes.push(item.route);
      continue;
    }
    entries.push({
      closure: item.closure,
      dependencyGraphSha256: requireString(
        item.membership.dependencyGraphSha256,
        "cohort entry dependency-graph SHA-256"
      ),
      entryModulePath: requireString(
        item.closure.identity?.entryModulePath,
        "cohort official entry module path"
      ),
      entryPath: requireString(item.route.entryPath, "cohort entry path"),
      modulePath: requireString(item.route.modulePath, "cohort module path"),
      routes: [item.route],
      runtimeModulePath: requireString(item.route.runtimeModulePath, "cohort runtime module path"),
    });
  }
  if (entries.length < 2 || entries.length > convexWasmOfficialOutputCohortMaximumEntries) {
    fail(
      `cohort must contain between two and ${convexWasmOfficialOutputCohortMaximumEntries} entries`
    );
  }
  return {
    entries,
    esbuildVersion,
    routes,
    sourceAuthentication: authenticatedSet.sourceAuthentication,
    sourceEnvelopeSha256,
  };
}

export async function buildConvexWasmOfficialOutputCohortPrototype({ esbuild, selections }) {
  requireObject(esbuild, "esbuild API");
  const normalized = normalizedCohortSelections(selections);
  if (esbuild.version !== normalized.esbuildVersion) {
    fail("outer compiler does not match the authenticated cohort esbuild version");
  }
  const modulesByPath = new Map();
  const moduleClosures = new Map();
  for (const entry of normalized.entries) {
    const modules = exactOfficialOutputClosureModules(
      entry.closure,
      `official-output closure for ${entry.entryPath}`
    );
    for (const module of modules) {
      const identity = module.identity;
      const path = requireString(identity.path, "official-output module path");
      const existing = modulesByPath.get(path);
      if (
        existing !== undefined &&
        (existing.source !== module.source ||
          fingerprintJson(existing.identity) !== fingerprintJson(identity))
      ) {
        fail(`official-output closures disagree on shared module ${path}`);
      }
      modulesByPath.set(path, module);
      const closures = moduleClosures.get(path) ?? [];
      closures.push(entry.entryPath);
      moduleClosures.set(path, closures);
    }
    if (!modulesByPath.has(entry.entryModulePath)) {
      fail(`official-output closure for ${entry.entryPath} omits its entry module`);
    }
  }
  const entrySource = `${normalized.entries
    .map(
      ({ entryModulePath }, index) =>
        `import * as entry${index} from ${JSON.stringify(`official-output:${entryModulePath}`)};`
    )
    .join(
      "\n"
    )}\nexport { ${normalized.entries.map((_, index) => `entry${index}`).join(", ")} };\n`;
  const started = performance.now();
  const result = await esbuild.build(
    esbuildOptions(
      convexWasmOfficialOutputCohortPrototypeGlobal,
      "official-output-cohort-prototype-entry",
      modulesByPath,
      entrySource
    )
  );
  if (result.outputFiles.length !== 1) {
    fail("outer compiler did not emit exactly one cohort JavaScript unit");
  }
  const moduleInputs = Object.keys(result.metafile.inputs)
    .filter((path) => path.startsWith("official-output:"))
    .map((path) => path.slice("official-output:".length))
    .sort(compareStrings);
  const expectedModuleInputs = [...modulesByPath.keys()].sort(compareStrings);
  if (JSON.stringify(moduleInputs) !== JSON.stringify(expectedModuleInputs)) {
    fail("outer compiler did not consume the complete official-output closure union");
  }
  const javascript = result.outputFiles[0].text;
  const closureUnion = {
    modules: expectedModuleInputs.map((path) => ({
      closures: [...new Set(moduleClosures.get(path))].sort(compareStrings),
      identity: modulesByPath.get(path).identity,
    })),
  };
  const entries = normalized.entries.map((entry, handoffSlot) => ({
    closureSha256: requireString(entry.closure.identity?.sha256, "official closure SHA-256"),
    dependencyGraphSha256: entry.dependencyGraphSha256,
    entryModulePath: entry.entryModulePath,
    entryPath: entry.entryPath,
    handoffSlot,
    modulePath: entry.modulePath,
    routes: entry.routes.map(({ exportName, udfKind, visibility }) => ({
      exportName,
      udfKind,
      visibility,
    })),
    runtimeModulePath: entry.runtimeModulePath,
  }));
  const identity = {
    closureUnion: {
      moduleCount: expectedModuleInputs.length,
      sha256: fingerprintJson(closureUnion),
      sourceBytes: expectedModuleInputs.reduce(
        (sum, path) => sum + modulesByPath.get(path).identity.sourceSize,
        0
      ),
    },
    compilerMode: "static-hermes-untyped-application",
    dependencyGraphSha256: fingerprintJson({
      domain: "convex-wasm-official-output-cohort-dependency-graph-v1",
      entries: entries.map(({ dependencyGraphSha256, entryPath }) => ({
        dependencyGraphSha256,
        entryPath,
      })),
    }),
    entries,
    esbuild: {
      settings: officialOutputEsbuildSettings,
      version: esbuild.version,
    },
    javascript: {
      sha256: createHash("sha256").update(javascript).digest("hex"),
      size: Buffer.byteLength(javascript),
    },
    kind: convexWasmOfficialOutputCohortPrototypeKind,
    metafileSha256: fingerprintJson(result.metafile),
    sourceEnvelopeSha256: normalized.sourceEnvelopeSha256,
    unitCount: 1,
  };
  const prototype = immutableAuthenticatedJsonSnapshot({
    closureUnion,
    identity: { ...identity, sha256: fingerprintJson(identity) },
    javascript,
    metafile: result.metafile,
    phaseTimingsMilliseconds: { outerCompile: performance.now() - started },
  });
  officialOutputCohortPrototypeRecords.set(prototype, {
    prototype,
    sourceAuthentication: normalized.sourceAuthentication,
  });
  return authenticateConvexWasmOfficialOutputCohortPrototype(prototype);
}

export function authenticateConvexWasmOfficialOutputCohortPrototype(prototype) {
  const artifact = requireObject(prototype, "official-output cohort prototype");
  const provenance = officialOutputCohortPrototypeRecords.get(artifact);
  if (provenance === undefined || provenance.prototype !== artifact) {
    fail("official-output cohort prototype provenance is invalid");
  }
  const identity = requireObject(artifact.identity, "official-output cohort prototype identity");
  const { sha256, ...identityPayload } = identity;
  if (
    identity.kind !== convexWasmOfficialOutputCohortPrototypeKind ||
    identity.compilerMode !== "static-hermes-untyped-application" ||
    identity.unitCount !== 1 ||
    !Array.isArray(identity.entries) ||
    identity.entries.length < 2 ||
    identity.entries.length > convexWasmOfficialOutputCohortMaximumEntries ||
    sha256 !== fingerprintJson(identityPayload)
  ) {
    fail("official-output cohort prototype identity is invalid");
  }
  requireString(artifact.javascript, "official-output cohort JavaScript");
  if (
    createHash("sha256").update(artifact.javascript).digest("hex") !== identity.javascript.sha256 ||
    Buffer.byteLength(artifact.javascript) !== identity.javascript.size ||
    fingerprintJson(requireObject(artifact.metafile, "official-output cohort metafile")) !==
      identity.metafileSha256 ||
    fingerprintJson(requireObject(artifact.closureUnion, "official-output closure union")) !==
      identity.closureUnion.sha256
  ) {
    fail("official-output cohort emitted material identity is invalid");
  }
  return artifact;
}

export function convexWasmOfficialOutputCohortPrototypeSourceAuthentication(prototype) {
  const artifact = authenticateConvexWasmOfficialOutputCohortPrototype(prototype);
  return officialOutputCohortPrototypeRecords.get(artifact).sourceAuthentication;
}

export function instantiateConvexWasmOfficialOutputCohortPrototype({ convexFacade, prototype }) {
  const artifact = authenticateConvexWasmOfficialOutputCohortPrototype(prototype);
  const suppliedFacade = requireObject(convexFacade, "canonical Convex facade");
  for (const method of ["syscall", "asyncSyscall", "jsSyscall"]) {
    if (typeof suppliedFacade[method] !== "function") {
      fail(`canonical Convex facade ${method} must be a function`);
    }
  }
  const context = createContext(
    {
      Convex: Object.freeze({
        asyncSyscall: suppliedFacade.asyncSyscall,
        jsSyscall: suppliedFacade.jsSyscall,
        syscall: suppliedFacade.syscall,
      }),
      console: Object.freeze({ debug() {}, error() {}, info() {}, log() {}, warn() {} }),
    },
    {
      codeGeneration: { strings: false, wasm: false },
      name: "convex-wasm-official-output-cohort-prototype",
    }
  );
  new Script(artifact.javascript, {
    filename: "official-output-cohort-prototype.js",
  }).runInContext(context, { timeout: 10_000 });
  const exports = context[convexWasmOfficialOutputCohortPrototypeGlobal];
  if (exports === null || typeof exports !== "object") {
    fail("official-output cohort prototype did not expose its entry namespaces");
  }
  return {
    entries: artifact.identity.entries.map((entry, index) => ({
      identity: entry,
      namespace: requireObject(
        exports[`entry${index}`],
        `official-output entry ${index} namespace`
      ),
    })),
    identity: artifact.identity,
  };
}

export function authenticateConvexWasmOfficialOutputPrototype(prototype) {
  const artifact = requireObject(prototype, "official-output prototype");
  const provenance = officialOutputPrototypeRecords.get(artifact);
  if (provenance === undefined || provenance.prototype !== artifact) {
    fail("official-output prototype provenance is invalid");
  }
  const identity = requireObject(artifact.identity, "official-output prototype identity");
  const { sha256, ...identityPayload } = identity;
  if (
    identity.kind !== convexWasmOfficialOutputPrototypeKind ||
    sha256 !== fingerprintJson(identityPayload)
  ) {
    fail("official-output prototype identity is invalid");
  }
  for (const [field, description] of [
    ["closureSha256", "closure SHA-256"],
    ["dependencyGraphSha256", "dependency-graph SHA-256"],
    ["entryModulePath", "entry module path"],
    ["entryPath", "entry path"],
    ["esbuildVersion", "esbuild version"],
    ["exportName", "export name"],
    ["modulePath", "module path"],
    ["sourceEnvelopeSha256", "source-envelope SHA-256"],
    ["udfKind", "UDF kind"],
    ["visibility", "visibility"],
  ]) {
    requireString(identity[field], `official-output prototype ${description}`);
  }
  requireString(artifact.javascript, "official-output prototype JavaScript");
  if (
    createHash("sha256").update(artifact.javascript).digest("hex") !== identity.javascriptSha256
  ) {
    fail("official-output prototype JavaScript changed after compilation");
  }
  if (
    Buffer.byteLength(artifact.javascript) !== identity.javascriptBytes ||
    fingerprintJson(requireObject(artifact.metafile, "official-output prototype metafile")) !==
      identity.metafileSha256
  ) {
    fail("official-output prototype emitted material identity is invalid");
  }
  return artifact;
}

export function convexWasmOfficialOutputPrototypeSourceAuthentication(prototype) {
  const artifact = authenticateConvexWasmOfficialOutputPrototype(prototype);
  return officialOutputPrototypeRecords.get(artifact).sourceAuthentication;
}

export function instantiateConvexWasmOfficialOutputPrototype({ convexFacade, prototype }) {
  const artifact = authenticateConvexWasmOfficialOutputPrototype(prototype);
  const prototypeRecord = officialOutputPrototypeRecords.get(artifact);
  const identity = immutableAuthenticatedJsonSnapshot(artifact.identity);
  const suppliedFacade = requireObject(convexFacade, "canonical Convex facade");
  for (const method of ["syscall", "asyncSyscall", "jsSyscall"]) {
    if (typeof suppliedFacade[method] !== "function") {
      fail(`canonical Convex facade ${method} must be a function`);
    }
  }
  const canonicalFacade = Object.freeze({
    asyncSyscall: suppliedFacade.asyncSyscall,
    jsSyscall: suppliedFacade.jsSyscall,
    syscall: suppliedFacade.syscall,
  });
  const context = createContext(
    {
      Convex: canonicalFacade,
      console: Object.freeze({
        debug() {},
        error() {},
        info() {},
        log() {},
        warn() {},
      }),
      process: convexWasmOfficialOutputInitializationProcess,
    },
    {
      codeGeneration: { strings: false, wasm: false },
      name: "convex-wasm-official-output-prototype",
    }
  );
  new Script(artifact.javascript, { filename: "official-output-prototype.js" }).runInContext(
    context,
    { timeout: 10_000 }
  );
  const entry = context[convexWasmOfficialOutputPrototypeGlobal]?.entry;
  if (entry === null || typeof entry !== "object") {
    fail("official-output prototype did not expose its entry namespace");
  }
  const instance = Object.freeze({ entry, identity });
  officialOutputPrototypeInstanceRecords.set(instance, {
    entry,
    identity,
    sourceAuthentication: prototypeRecord.sourceAuthentication,
  });
  return instance;
}

export function selectConvexWasmOfficialOutputWrapper({ instance, selection }) {
  const instanceRecord = officialOutputPrototypeInstanceRecords.get(instance);
  if (
    instanceRecord === undefined ||
    instance?.entry !== instanceRecord.entry ||
    instance.identity !== instanceRecord.identity
  ) {
    fail("official-output prototype instance provenance is invalid");
  }
  const authenticatedSelection = authenticateConvexWasmOfficialOutputSelection(selection);
  const selectionRecord = officialOutputSelectionRecord(authenticatedSelection);
  const entry = requireObject(instanceRecord.entry, "official-output entry namespace");
  const route = requireObject(authenticatedSelection.route, "official-output selected route");
  const identity = instanceRecord.identity;
  if (
    selectionRecord.sourceAuthentication !== instanceRecord.sourceAuthentication ||
    authenticatedSelection.closure.identity.sha256 !== identity.closureSha256 ||
    authenticatedSelection.closure.identity.entryModulePath !== identity.entryModulePath ||
    authenticatedSelection.manifestMembership.dependencyGraphSha256 !==
      identity.dependencyGraphSha256 ||
    authenticatedSelection.manifestMembership.sourceEnvelopeSha256 !==
      identity.sourceEnvelopeSha256 ||
    authenticatedSelection.toolchain.esbuild !== identity.esbuildVersion ||
    route.entryPath !== identity.entryPath ||
    route.exportName !== identity.exportName ||
    route.modulePath !== identity.modulePath ||
    route.runtimeModulePath !== identity.entryModulePath ||
    route.udfKind !== identity.udfKind ||
    route.visibility !== identity.visibility
  ) {
    fail("official-output selection does not match the instantiated prototype identity");
  }
  const wrapper = entry[route.exportName];
  const kindProperty = route.udfKind === "query" ? "isQuery" : "isMutation";
  const otherKindProperties =
    route.udfKind === "query" ? ["isMutation", "isAction"] : ["isQuery", "isAction"];
  const visibilityProperty = route.visibility === "public" ? "isPublic" : "isInternal";
  const otherVisibilityProperty = route.visibility === "public" ? "isInternal" : "isPublic";
  const invocationMethod = route.udfKind === "query" ? "invokeQuery" : "invokeMutation";
  if (
    typeof wrapper !== "function" ||
    wrapper[kindProperty] !== true ||
    otherKindProperties.some((property) => wrapper[property] !== undefined) ||
    wrapper[visibilityProperty] !== true ||
    wrapper[otherVisibilityProperty] !== undefined ||
    typeof wrapper[invocationMethod] !== "function" ||
    typeof wrapper.exportArgs !== "function" ||
    typeof wrapper.exportReturns !== "function" ||
    typeof wrapper._handler !== "function"
  ) {
    fail(`selected export ${route.entryPath}:${route.exportName} registration wrapper is invalid`);
  }
  return {
    handler: wrapper._handler,
    invocationMethod,
    metadata: {
      args: wrapper.exportArgs(),
      returns: wrapper.exportReturns(),
      udfKind: route.udfKind,
      visibility: route.visibility,
    },
    wrapper,
  };
}
