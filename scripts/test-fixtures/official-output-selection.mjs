import { canonicalJson, fingerprintJson } from "../lib/convex-wasm-artifact-contract.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "../lib/convex-wasm-compiler-contract.mjs";
import { authenticateConvexContextReuseResultIdentity } from "../lib/convex-context-reuse-result-identity.mjs";
import {
  authenticateConvexWasmOfficialOutputSelectionSource,
  createConvexWasmOfficialOutputSelectionSessionFromAuthenticatedSource,
} from "../lib/convex-wasm-official-output-prototype.mjs";
import { createConvexWasmSourceEnvelope } from "../lib/convex-wasm-source-envelope.mjs";

function snapshot(value) {
  return JSON.parse(canonicalJson(value));
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${description} must be a non-empty string`);
  }
  return value;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/**
 * Route synthetic module graphs through the same opaque source-authentication issuer used by
 * deployment compilation. The fixture boundary constructs graph facts; it never issues selection
 * provenance directly.
 */
export function authenticateConvexWasmOfficialOutputSelectionFixtures(rawSelections) {
  if (!Array.isArray(rawSelections) || rawSelections.length === 0) {
    throw new Error("official-output selection fixtures must contain at least one route");
  }
  const selections = rawSelections.map((rawSelection, index) => {
    const selection = requireObject(rawSelection, `selection fixture ${index}`);
    return {
      closure: requireObject(selection.closure, `selection fixture ${index} closure`),
      manifestMembership: requireObject(
        selection.manifestMembership,
        `selection fixture ${index} manifest membership`
      ),
      route: requireObject(selection.route, `selection fixture ${index} route`),
      toolchain: requireObject(selection.toolchain, `selection fixture ${index} toolchain`),
    };
  });
  const metafile = { inputs: {}, outputs: {} };
  const bundleModulesByPath = new Map();
  const deploymentOutputModulesByPath = new Map();
  const deploymentOutputClosureByEntry = new Map();
  const dependencyGraphByEntry = new Map();
  const runtimeModulePathByEntry = new Map();
  const inventoryFunctions = [];
  const routesByKey = new Map();
  const closureFactsByRawClosure = new WeakMap();

  for (const [selectionIndex, selection] of selections.entries()) {
    const route = selection.route;
    const entryPath = requireString(
      route.entryPath,
      `selection fixture ${selectionIndex} entry path`
    );
    const exportName = requireString(
      route.exportName,
      `selection fixture ${selectionIndex} export name`
    );
    const modulePath = requireString(
      route.modulePath,
      `selection fixture ${selectionIndex} module path`
    );
    const runtimeModulePath = requireString(
      route.runtimeModulePath,
      `selection fixture ${selectionIndex} runtime module path`
    );
    if (runtimeModulePath !== `${modulePath}.js`) {
      throw new Error(`selection fixture ${selectionIndex} runtime module path is not canonical`);
    }
    const dependencyGraphSha256 = requireString(
      selection.manifestMembership.dependencyGraphSha256,
      `selection fixture ${selectionIndex} dependency graph SHA-256`
    );
    const existingRuntimeModulePath = runtimeModulePathByEntry.get(entryPath);
    if (
      existingRuntimeModulePath !== undefined &&
      existingRuntimeModulePath !== runtimeModulePath
    ) {
      throw new Error(`selection fixtures disagree on runtime module path for ${entryPath}`);
    }
    const existingDependencyGraph = dependencyGraphByEntry.get(entryPath);
    if (
      existingDependencyGraph !== undefined &&
      existingDependencyGraph.sha256 !== dependencyGraphSha256
    ) {
      throw new Error(`selection fixtures disagree on dependency graph for ${entryPath}`);
    }
    runtimeModulePathByEntry.set(entryPath, runtimeModulePath);
    dependencyGraphByEntry.set(entryPath, { sha256: dependencyGraphSha256 });

    const closure = selection.closure;
    let exactClosure = closureFactsByRawClosure.get(closure);
    if (exactClosure === undefined) {
      const closureIdentity = requireObject(
        closure.identity,
        `selection fixture ${selectionIndex} closure identity`
      );
      const modules = Array.isArray(closure.modules) ? closure.modules : [];
      const authenticatedModuleIdentities = Array.isArray(closureIdentity.modules)
        ? closureIdentity.modules.map(snapshot)
        : [];
      const declaredImports = Array.isArray(closureIdentity.imports)
        ? closureIdentity.imports.map(snapshot)
        : [];
      requireString(closureIdentity.kind, `selection fixture ${selectionIndex} closure kind`);
      const exactClosureIdentity = {
        entryModulePath: requireString(
          closureIdentity.entryModulePath,
          `selection fixture ${selectionIndex} closure entry module path`
        ),
        imports:
          declaredImports.length > 0 || authenticatedModuleIdentities.length <= 1
            ? declaredImports
            : authenticatedModuleIdentities.slice(1).map(({ path }) => ({
                external: false,
                importerPath: closureIdentity.entryModulePath,
                kind: "import-statement",
                path,
              })),
        kind: "convex-wasm-deployment-output-closure-v1",
        modules: authenticatedModuleIdentities,
      };
      exactClosure = exactClosureIdentity;
      closureFactsByRawClosure.set(closure, exactClosure);

      for (const [moduleIndex, rawModule] of modules.entries()) {
        const module = requireObject(
          rawModule,
          `selection fixture ${selectionIndex} closure module ${moduleIndex}`
        );
        const identity = snapshot(
          requireObject(
            module.identity,
            `selection fixture ${selectionIndex} closure module ${moduleIndex} identity`
          )
        );
        const path = requireString(
          identity.path,
          `selection fixture ${selectionIndex} closure module ${moduleIndex} path`
        );
        const source = requireString(
          module.source,
          `selection fixture ${selectionIndex} closure module ${moduleIndex} source`
        );
        const exactModule = {
          path,
          source,
          ...(module.sourceMap === undefined ? {} : { sourceMap: module.sourceMap }),
        };
        const existingIdentity = bundleModulesByPath.get(path);
        const existingModule = deploymentOutputModulesByPath.get(path);
        if (
          (existingIdentity !== undefined &&
            canonicalJson(existingIdentity) !== canonicalJson(identity)) ||
          (existingModule !== undefined &&
            canonicalJson(existingModule) !== canonicalJson(exactModule))
        ) {
          throw new Error(`selection fixtures disagree on shared output module ${path}`);
        }
        bundleModulesByPath.set(path, identity);
        deploymentOutputModulesByPath.set(path, exactModule);
      }
    }
    const existingClosure = deploymentOutputClosureByEntry.get(entryPath);
    if (
      existingClosure !== undefined &&
      canonicalJson(existingClosure) !== canonicalJson(exactClosure)
    ) {
      throw new Error(`selection fixtures disagree on output closure for ${entryPath}`);
    }
    deploymentOutputClosureByEntry.set(entryPath, exactClosure);

    const routeKey = `${entryPath}\0${exportName}`;
    if (routesByKey.has(routeKey)) {
      throw new Error(`selection fixtures repeat route ${entryPath}:${exportName}`);
    }
    const inventoryRoute = {
      entryPath,
      exportName,
      modulePath,
      udfKind: requireString(route.udfKind, `selection fixture ${selectionIndex} UDF kind`),
      visibility: requireString(route.visibility, `selection fixture ${selectionIndex} visibility`),
    };
    routesByKey.set(routeKey, inventoryRoute);
    inventoryFunctions.push(inventoryRoute);
  }

  const importsByModulePath = new Map(
    [...bundleModulesByPath.keys()].map((modulePath) => [modulePath, new Map()])
  );
  for (const closure of deploymentOutputClosureByEntry.values()) {
    for (const imported of closure.imports) {
      const imports = importsByModulePath.get(imported.importerPath);
      if (imports === undefined) {
        throw new Error(
          `selection fixture closure imports from missing module ${imported.importerPath}`
        );
      }
      const metafileImport = {
        external: imported.external,
        kind: imported.kind,
        path: imported.external ? imported.path : `out/${imported.path}`,
      };
      imports.set(canonicalJson(metafileImport), metafileImport);
    }
  }
  metafile.outputs = Object.fromEntries(
    [...bundleModulesByPath.keys()].sort(compareStrings).map((modulePath) => {
      const entryPaths = [...deploymentOutputClosureByEntry]
        .filter(([, closure]) => closure.entryModulePath === modulePath)
        .map(([entryPath]) => entryPath);
      if (entryPaths.length > 1) {
        throw new Error(`selection fixtures bind multiple entries to output module ${modulePath}`);
      }
      return [
        `out/${modulePath}`,
        {
          ...(entryPaths.length === 0 ? {} : { entryPoint: entryPaths[0] }),
          imports: [...importsByModulePath.get(modulePath).values()],
        },
      ];
    })
  );
  const metafileSha256 = fingerprintJson(metafile);
  for (const closure of new Set(deploymentOutputClosureByEntry.values())) {
    closure.metafileSha256 = metafileSha256;
    closure.sha256 = fingerprintJson(closure);
  }

  const declaredToolchain = snapshot(selections[0].toolchain);
  if (
    selections.some(
      (selection) => canonicalJson(selection.toolchain) !== canonicalJson(declaredToolchain)
    )
  ) {
    throw new Error("selection fixtures disagree on toolchain identity");
  }
  const toolchain = Object.hasOwn(declaredToolchain, "convex")
    ? declaredToolchain
    : { ...declaredToolchain, convex: "official-output-selection-test-fixture" };
  const inventoryKind = requireString(
    selections[0].manifestMembership.inventoryKind,
    "selection fixture inventory kind"
  );
  if (
    selections.some((selection) => selection.manifestMembership.inventoryKind !== inventoryKind)
  ) {
    throw new Error("selection fixtures disagree on inventory identity");
  }
  const graphIdentity = {
    entries: [...runtimeModulePathByEntry].sort(([left], [right]) => compareStrings(left, right)),
    modules: [...bundleModulesByPath.values()].sort((left, right) =>
      compareStrings(left.path, right.path)
    ),
    routes: [...inventoryFunctions].sort((left, right) => {
      const entryOrder = compareStrings(left.entryPath, right.entryPath);
      return entryOrder === 0 ? compareStrings(left.exportName, right.exportName) : entryOrder;
    }),
    toolchain,
  };
  const graphSession = {
    bundleModulesByPath,
    contextReuseAnalysisIdentity: authenticateConvexContextReuseResultIdentity({
      entries: [...runtimeModulePathByEntry.keys()].sort(compareStrings),
      kind: "convex-context-reuse-analysis",
      policyFingerprint: fingerprintJson({ kind: "official-output-selection-fixture-policy-v1" }),
      resultSha256: fingerprintJson({
        graphIdentity,
        kind: "official-output-selection-fixture-result-v1",
      }),
    }),
    contextReuseEnabledByEntry: new Map(
      [...runtimeModulePathByEntry.keys()].map((entryPath) => [entryPath, true])
    ),
    dependencyGraphByEntry,
    deploymentOutputClosureByEntry,
    deploymentOutputMetafileSha256: metafileSha256,
    deploymentOutputModulesByPath,
    effectExecutionMode: convexWasmGuestPromiseEffectExecutionMode,
    graphSha256: fingerprintJson(graphIdentity),
    graphTemplate: { metafile, repoRoot: "/fixture" },
    inputCount: bundleModulesByPath.size,
    runtimeModulePathByEntry,
    toolchain,
  };
  const inventory = {
    actions: [],
    functions: inventoryFunctions,
    kind: inventoryKind,
    snapshot: { kind: "official-output-selection-test-fixture-v1" },
  };
  const selectedExports = inventoryFunctions.map(({ exportName, modulePath }) => ({
    exportName,
    modulePath,
  }));
  const sourceEnvelope = createConvexWasmSourceEnvelope({
    graphSession,
    inventory,
    selectedExports,
  });
  const sourceAuthentication = authenticateConvexWasmOfficialOutputSelectionSource({
    graphSession,
    inventory,
    sourceEnvelope,
  });
  const session = createConvexWasmOfficialOutputSelectionSessionFromAuthenticatedSource({
    selectedExports,
    sourceAuthentication,
  });
  return Object.freeze({
    graphSession,
    inventory,
    selections: Object.freeze(
      selections.map(({ route }) =>
        session.select({ entryPath: route.entryPath, exportName: route.exportName })
      )
    ),
    sourceAuthentication,
    sourceEnvelope,
  });
}

export function authenticateConvexWasmOfficialOutputSelectionFixture(rawSelection) {
  return authenticateConvexWasmOfficialOutputSelectionFixtures([rawSelection]).selections[0];
}
