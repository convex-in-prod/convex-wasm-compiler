import { createHash } from "node:crypto";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { isProxy } from "node:util/types";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { isOrdinaryJsonData } from "./convex-wasm-source-envelope.mjs";

const DEPLOYMENT_OUTPUT_CLOSURE_KIND = "convex-wasm-deployment-output-closure-v1";

function fail(message) {
  throw new Error(`Convex Wasm output closure: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function toPosix(path) {
  return path.split(sep).join("/");
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

function hashPinnedConvexBundle(bundle) {
  return createHash("sha256")
    .update(bundle.source)
    .update(bundle.sourceMap ?? "")
    .digest("hex");
}

function sourceMapIdentity(sourceMap) {
  if (sourceMap === undefined) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(sourceMap);
  } catch {
    fail("installed Convex bundler emitted an invalid source map");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    parsed.version !== 3 ||
    !Array.isArray(parsed.sources)
  ) {
    fail("installed Convex bundler emitted invalid source-membership provenance");
  }
  return {
    identity: {
      sha256: createHash("sha256").update(sourceMap).digest("hex"),
      size: Buffer.byteLength(sourceMap),
      sourcesContentCount: Array.isArray(parsed.sourcesContent)
        ? parsed.sourcesContent.filter((source) => source !== null).length
        : 0,
      sourcesCount: parsed.sources.length,
    },
    sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
      sourceRoot: parsed.sourceRoot,
      sources: parsed.sources,
    }),
  };
}

function bundleModuleIdentity(bundle, description, expectedEnvironment) {
  requireObject(bundle, description);
  if (bundle.environment !== expectedEnvironment) {
    fail(`${description} environment must be ${expectedEnvironment}`);
  }
  const path = requireString(bundle.path, `${description} path`);
  const source = requireString(bundle.source, `${description} source`);
  if (bundle.sourceMap !== undefined && typeof bundle.sourceMap !== "string") {
    fail(`${description} source map must be a string when present`);
  }
  if (expectedEnvironment === "isolate" && bundle.sourceMap === undefined) {
    fail(`${description} isolate module has no source-map provenance`);
  }
  const sourceMap = sourceMapIdentity(bundle.sourceMap);
  return {
    environment: bundle.environment,
    moduleSha256: hashPinnedConvexBundle(bundle),
    path,
    sourceMap: sourceMap?.identity ?? null,
    sourceMembershipSha256:
      bundle.environment === "isolate" ? (sourceMap?.sourceMembershipSha256 ?? null) : null,
    sourceSha256: createHash("sha256").update(source).digest("hex"),
    sourceSize: Buffer.byteLength(source),
  };
}

function outputModulePath(repoRoot, outputPath) {
  const pathFromOutdir = isAbsolute(outputPath)
    ? relative(resolve(repoRoot, "out"), outputPath)
    : relative("out", outputPath);
  return toPosix(pathFromOutdir);
}

function resolveOutputImport({
  importerOutputPath,
  importedPath,
  outputPathsByAbsolutePath,
  outputs,
  repoRoot,
}) {
  if (Object.hasOwn(outputs, importedPath)) {
    return importedPath;
  }
  const importerAbsolutePath = isAbsolute(importerOutputPath)
    ? resolve(importerOutputPath)
    : resolve(repoRoot, importerOutputPath);
  const candidates = new Set([
    isAbsolute(importedPath) ? resolve(importedPath) : resolve(repoRoot, importedPath),
    resolve(dirname(importerAbsolutePath), importedPath),
  ]);
  const matches = new Set();
  for (const candidate of candidates) {
    for (const outputPath of outputPathsByAbsolutePath.get(candidate) ?? []) {
      matches.add(outputPath);
    }
  }
  if (matches.size > 1) {
    fail(
      `esbuild output import ${importedPath} from ${importerOutputPath} matches multiple outputs`
    );
  }
  return matches.values().next().value;
}

// Retain fast-path authority only for exact producer objects. Equal-value copies still take the
// complete closure and byte-authentication path.
const deploymentOutputClosureProjectionAuthorities = new WeakMap();

const deploymentOutputClosureProjectionSelections = new WeakMap();

const deploymentOutputClosureProjectionOutputMaps = new WeakMap();

const deploymentOutputClosureProjectionGraphSessions = new WeakMap();

function isExactPlainMap(value) {
  return (
    !isProxy(value) &&
    value instanceof Map &&
    Object.getPrototypeOf(value) === Map.prototype &&
    Reflect.ownKeys(value).length === 0
  );
}

function isUnproxiedMap(value) {
  return !isProxy(value) && value instanceof Map;
}

function intrinsicMapGet(map, key) {
  return Map.prototype.get.call(map, key);
}

function plainMapSnapshot(map) {
  return new Map(Map.prototype.entries.call(map));
}

function hasExactMapEntries(map, snapshot) {
  if (!isExactPlainMap(map) || snapshot.size !== map.size) return false;
  for (const [key, value] of snapshot) {
    if (intrinsicMapGet(map, key) !== value) return false;
  }
  return true;
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !isProxy(value) &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function hasExactEnumerableDataProperty(object, key, value) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return (
    descriptor !== undefined &&
    "value" in descriptor &&
    descriptor.enumerable &&
    descriptor.value === value
  );
}

function ordinaryOwnDataPropertySnapshot(value) {
  if (!isPlainObject(value)) return undefined;
  const snapshot = new Map();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      return undefined;
    }
    snapshot.set(key, descriptor.value);
  }
  return snapshot;
}

function hasExactOwnDataPropertySnapshot(value, snapshot) {
  if (!isPlainObject(value) || !(snapshot instanceof Map)) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== snapshot.size) return false;
  return keys.every(
    (key) =>
      typeof key === "string" &&
      snapshot.has(key) &&
      hasExactEnumerableDataProperty(value, key, snapshot.get(key))
  );
}

function createConvexWasmDeploymentOutputClosureProjection({
  bundleModulesByPath,
  metafile,
  repoRoot,
}) {
  if (!isExactPlainMap(bundleModulesByPath)) {
    fail("deployment output closure requires bundle module identities");
  }
  requireObject(metafile, "deployment output metafile");
  if (!isOrdinaryJsonData(metafile)) {
    fail("deployment output metafile must contain ordinary JSON data");
  }
  if (!Object.hasOwn(metafile, "outputs")) {
    fail("deployment metafile has no own outputs object");
  }
  const outputs = requireObject(metafile.outputs, "deployment metafile outputs");
  const metafileSha256 = fingerprintJson(metafile);
  freezeAuthenticatedJsonTree(metafile);
  const projection = Object.freeze({});
  const outputPathsByAbsolutePath = new Map();
  for (const outputPath of Object.keys(outputs)) {
    const absoluteOutputPath = isAbsolute(outputPath)
      ? resolve(outputPath)
      : resolve(repoRoot, outputPath);
    const collidingOutputPaths = outputPathsByAbsolutePath.get(absoluteOutputPath);
    if (collidingOutputPaths === undefined) {
      outputPathsByAbsolutePath.set(absoluteOutputPath, [outputPath]);
    } else {
      collidingOutputPaths.push(outputPath);
    }
  }
  const outputPathByModulePath = new Map();
  const modulePathByOutputPath = new Map();
  for (const outputPath of Object.keys(outputs).sort(compareStrings)) {
    const modulePath = outputModulePath(repoRoot, outputPath);
    if (!bundleModulesByPath.has(modulePath)) {
      continue;
    }
    if (outputPathByModulePath.has(modulePath)) {
      fail(`esbuild metafile contains duplicate output module path ${modulePath}`);
    }
    outputPathByModulePath.set(modulePath, outputPath);
    modulePathByOutputPath.set(outputPath, modulePath);
  }
  const closureModulesByPath = new Map();
  const closureModuleSourcesByPath = new Map();
  for (const [modulePath, module] of bundleModulesByPath) {
    requireString(modulePath, "deployment output module path");
    if (!outputPathByModulePath.has(modulePath)) {
      fail(`esbuild metafile is missing deployment output module ${modulePath}`);
    }
    if (!isOrdinaryJsonData(module)) {
      fail(`deployment output module identity ${modulePath} must contain ordinary JSON data`);
    }
    if (module.path !== modulePath) {
      fail(`deployment output module identity path disagrees with map key ${modulePath}`);
    }
    const closureModule = freezeAuthenticatedJsonTree({
      environment: module.environment,
      moduleSha256: module.moduleSha256,
      path: module.path,
      sourceMap: module.sourceMap === null ? null : { ...module.sourceMap },
      sourceMembershipSha256: module.sourceMembershipSha256,
      sourceSha256: module.sourceSha256,
      sourceSize: module.sourceSize,
    });
    closureModulesByPath.set(modulePath, closureModule);
    closureModuleSourcesByPath.set(modulePath, canonicalJson(closureModule));
  }
  const closureImportsByModulePath = new Map();
  const closureImportSourcesByModulePath = new Map();
  for (const [modulePath, outputPath] of outputPathByModulePath) {
    const output = requireObject(outputs[outputPath], `esbuild output ${outputPath}`);
    if (!isOrdinaryJsonData(output)) {
      fail(`esbuild output ${outputPath} must contain ordinary JSON data`);
    }
    const outputImports = Object.hasOwn(output, "imports") ? output.imports : [];
    if (!Array.isArray(outputImports)) {
      fail(`esbuild output ${outputPath} imports must be an array`);
    }
    const imports = outputImports.map((imported, index) => {
      requireObject(imported, `esbuild output ${outputPath} import ${index}`);
      if (
        !isOrdinaryJsonData(imported) ||
        !Object.hasOwn(imported, "kind") ||
        !Object.hasOwn(imported, "path")
      ) {
        fail(`esbuild output ${outputPath} import ${index} shape is invalid`);
      }
      const kind = requireString(
        imported.kind,
        `esbuild output ${outputPath} import ${index} kind`
      );
      const importedPath = requireString(
        imported.path,
        `esbuild output ${outputPath} import ${index} path`
      );
      const external = Object.hasOwn(imported, "external") ? imported.external : undefined;
      if (external === true) {
        return { external: true, kind, path: importedPath };
      }
      if (external !== undefined && external !== false) {
        fail(`esbuild output ${outputPath} import ${index} external flag must be boolean`);
      }
      const importedOutputPath = resolveOutputImport({
        importerOutputPath: outputPath,
        importedPath,
        outputPathsByAbsolutePath,
        outputs,
        repoRoot,
      });
      const importedModulePath = modulePathByOutputPath.get(importedOutputPath);
      if (importedModulePath === undefined) {
        fail(`esbuild output module ${modulePath} imports missing output ${importedPath}`);
      }
      return { external: false, kind, path: importedModulePath };
    });
    imports.sort((left, right) => {
      const pathOrder = compareStrings(left.path, right.path);
      if (pathOrder !== 0) {
        return pathOrder;
      }
      const kindOrder = compareStrings(left.kind, right.kind);
      return kindOrder === 0 ? Number(left.external) - Number(right.external) : kindOrder;
    });
    const closureImports = freezeAuthenticatedJsonTree(
      imports.map((imported) => ({ ...imported, importerPath: modulePath }))
    );
    closureImportsByModulePath.set(modulePath, closureImports);
    closureImportSourcesByModulePath.set(modulePath, closureImports.map(canonicalJson));
  }
  const closuresByEntry = new Map();
  const closureForEntry = (entryPath, entryModulePath) => {
    const cached = closuresByEntry.get(entryPath);
    if (cached !== undefined) {
      if (cached.entryModulePath !== entryModulePath) {
        fail(`deployment output entry ${entryPath} changed its runtime module path`);
      }
      return cached;
    }
    const entryOutputPath = outputPathByModulePath.get(entryModulePath);
    if (entryOutputPath === undefined) {
      fail(`deployment output topology is missing entry module ${entryModulePath}`);
    }
    const entryOutput = requireObject(
      outputs[entryOutputPath],
      `esbuild output ${entryOutputPath}`
    );
    if (!Object.hasOwn(entryOutput, "entryPoint")) {
      fail(`esbuild output ${entryOutputPath} has no entry point`);
    }
    const declaredEntryPoint = requireString(
      entryOutput.entryPoint,
      `esbuild output ${entryOutputPath} entry point`
    );
    const normalizedEntryPoint = isAbsolute(declaredEntryPoint)
      ? toPosix(relative(repoRoot, declaredEntryPoint))
      : toPosix(declaredEntryPoint);
    if (normalizedEntryPoint !== entryPath) {
      fail(`deployment output entry ${entryPath} does not own runtime module ${entryModulePath}`);
    }
    const modulePaths = [];
    const visited = new Set();
    const visit = (modulePath) => {
      if (visited.has(modulePath)) {
        return;
      }
      visited.add(modulePath);
      modulePaths.push(modulePath);
      const imports = closureImportsByModulePath.get(modulePath);
      if (imports === undefined) {
        fail(`deployment output topology is missing module ${modulePath}`);
      }
      for (const imported of imports) {
        if (!imported.external) {
          visit(imported.path);
        }
      }
    };
    visit(entryModulePath);
    const imports = Object.freeze(
      modulePaths.flatMap((modulePath) => closureImportsByModulePath.get(modulePath))
    );
    const identity = Object.freeze({
      entryModulePath,
      imports,
      kind: DEPLOYMENT_OUTPUT_CLOSURE_KIND,
      metafileSha256,
      modules: Object.freeze(modulePaths.map((modulePath) => closureModulesByPath.get(modulePath))),
    });
    // These detached records were admitted once by this projection. Compose the same sorted-key
    // canonical identity bytes without revalidating shared module/import trees for every entry.
    const identitySource =
      `{"entryModulePath":${canonicalJson(entryModulePath)},"imports":[` +
      modulePaths
        .flatMap((modulePath) => closureImportSourcesByModulePath.get(modulePath))
        .join(",") +
      `],"kind":${canonicalJson(DEPLOYMENT_OUTPUT_CLOSURE_KIND)},` +
      `"metafileSha256":${canonicalJson(metafileSha256)},"modules":[` +
      modulePaths.map((modulePath) => closureModuleSourcesByPath.get(modulePath)).join(",") +
      "]}";
    const sha256 = createHash("sha256").update(identitySource).digest("hex");
    const closure = Object.freeze({
      ...identity,
      sha256,
    });
    deploymentOutputClosureProjectionAuthorities.set(
      closure,
      Object.freeze({
        bundleModulesByPath,
        entryModulePath,
        entryPath,
        metafile,
        metafileSha256,
        projection,
        sha256,
      })
    );
    closuresByEntry.set(entryPath, closure);
    return closure;
  };
  return {
    select({ entryPaths, runtimeModulePathByEntry }) {
      if (!isExactPlainMap(runtimeModulePathByEntry)) {
        fail("deployment output closure requires runtime module paths");
      }
      const closures = new Map();
      for (const entryPath of [...entryPaths].sort(compareStrings)) {
        const entryModulePath = runtimeModulePathByEntry.get(entryPath);
        if (entryModulePath === undefined) {
          fail(`missing runtime module path for deployment output entry ${entryPath}`);
        }
        closures.set(entryPath, closureForEntry(entryPath, entryModulePath));
      }
      deploymentOutputClosureProjectionSelections.set(
        closures,
        Object.freeze({
          bundleModulesByPath,
          metafile,
          metafileSha256,
          projection,
          runtimeModulePathByEntry,
        })
      );
      return { closures, metafileSha256 };
    },
  };
}

export function authenticateDeploymentOutputClosureProjectionGraphSession(graphSession) {
  const selection = deploymentOutputClosureProjectionSelections.get(
    graphSession.deploymentOutputClosureByEntry
  );
  const graphTemplate = graphSession.graphTemplate;
  const graphSessionOwnProperties = ordinaryOwnDataPropertySnapshot(graphSession);
  const graphTemplateOwnProperties = ordinaryOwnDataPropertySnapshot(graphTemplate);
  if (
    selection === undefined ||
    graphSessionOwnProperties === undefined ||
    graphTemplateOwnProperties === undefined ||
    graphSession.bundleModulesByPath !== selection.bundleModulesByPath ||
    graphSession.runtimeModulePathByEntry !== selection.runtimeModulePathByEntry ||
    graphTemplate?.metafile !== selection.metafile ||
    graphSession.deploymentOutputMetafileSha256 !== selection.metafileSha256 ||
    !isExactPlainMap(graphSession.bundleModulesByPath) ||
    !isExactPlainMap(graphSession.deploymentOutputClosureByEntry) ||
    !isExactPlainMap(graphSession.deploymentOutputModulesByPath) ||
    !isExactPlainMap(graphSession.runtimeModulePathByEntry) ||
    !hasExactEnumerableDataProperty(graphTemplate, "metafile", selection.metafile) ||
    graphSession.deploymentOutputClosureByEntry.size !== graphSession.runtimeModulePathByEntry.size
  ) {
    return graphSession;
  }
  const selectedOutputMap = graphSession.deploymentOutputModulesByPath;
  const retainedOutputMap = deploymentOutputClosureProjectionOutputMaps.get(selection.projection);
  if (retainedOutputMap !== undefined && retainedOutputMap !== selectedOutputMap) {
    return graphSession;
  }
  for (const [entryPath, closure] of graphSession.deploymentOutputClosureByEntry) {
    const authority = deploymentOutputClosureProjectionAuthorities.get(closure);
    if (
      authority === undefined ||
      authority.projection !== selection.projection ||
      authority.entryPath !== entryPath ||
      authority.entryModulePath !== graphSession.runtimeModulePathByEntry.get(entryPath)
    ) {
      return graphSession;
    }
  }
  deploymentOutputClosureProjectionOutputMaps.set(selection.projection, selectedOutputMap);
  deploymentOutputClosureProjectionGraphSessions.set(
    graphSession,
    Object.freeze({
      bundleModulesByPath: selection.bundleModulesByPath,
      // These maps stay mutable for existing consumers. Reference-only snapshots invalidate the
      // exact fast path after an in-place edit without repeating canonical JSON or byte hashing.
      bundleModulesByPathEntries: plainMapSnapshot(selection.bundleModulesByPath),
      deploymentOutputClosureByEntry: graphSession.deploymentOutputClosureByEntry,
      deploymentOutputClosureByEntryEntries: plainMapSnapshot(
        graphSession.deploymentOutputClosureByEntry
      ),
      deploymentOutputModulesByPath: graphSession.deploymentOutputModulesByPath,
      deploymentOutputModulesByPathEntries: plainMapSnapshot(
        graphSession.deploymentOutputModulesByPath
      ),
      graphTemplate,
      graphSessionOwnProperties,
      graphTemplateOwnProperties,
      metafile: selection.metafile,
      metafileSha256: selection.metafileSha256,
      projection: selection.projection,
      runtimeModulePathByEntry: selection.runtimeModulePathByEntry,
      runtimeModulePathByEntryEntries: plainMapSnapshot(selection.runtimeModulePathByEntry),
    })
  );
  return graphSession;
}

function exactDeploymentOutputClosureProjectionGraphSession(graphSession) {
  const authority = deploymentOutputClosureProjectionGraphSessions.get(graphSession);
  return authority !== undefined &&
    hasExactOwnDataPropertySnapshot(graphSession, authority.graphSessionOwnProperties) &&
    hasExactOwnDataPropertySnapshot(
      authority.graphTemplate,
      authority.graphTemplateOwnProperties
    ) &&
    hasExactMapEntries(authority.bundleModulesByPath, authority.bundleModulesByPathEntries) &&
    hasExactMapEntries(
      authority.deploymentOutputClosureByEntry,
      authority.deploymentOutputClosureByEntryEntries
    ) &&
    hasExactMapEntries(
      authority.deploymentOutputModulesByPath,
      authority.deploymentOutputModulesByPathEntries
    ) &&
    hasExactMapEntries(
      authority.runtimeModulePathByEntry,
      authority.runtimeModulePathByEntryEntries
    ) &&
    deploymentOutputClosureProjectionOutputMaps.get(authority.projection) ===
      authority.deploymentOutputModulesByPath &&
    authority.deploymentOutputClosureByEntry.size === authority.runtimeModulePathByEntry.size
    ? authority
    : undefined;
}

function isDeeplyFrozenBuildInput(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return true;
  if (seen.has(value)) return false;
  if (
    isProxy(value) ||
    !Object.isFrozen(value) ||
    (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype)
  ) {
    return false;
  }
  seen.add(value);
  const frozen = Reflect.ownKeys(value).every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return (
      typeof key === "string" &&
      descriptor !== undefined &&
      "value" in descriptor &&
      isDeeplyFrozenBuildInput(descriptor.value, seen)
    );
  });
  seen.delete(value);
  return frozen;
}

const deploymentOutputClosureOwnKeys = [
  "entryModulePath",
  "imports",
  "kind",
  "metafileSha256",
  "modules",
  "sha256",
];

function unauthenticatedDeploymentOutputClosureIdentity(closure, selectedEntry) {
  const ownKeys = Reflect.ownKeys(closure);
  if (
    !isOrdinaryJsonData(closure) ||
    ownKeys.length !== deploymentOutputClosureOwnKeys.length ||
    ownKeys.some((key) => !deploymentOutputClosureOwnKeys.includes(key))
  ) {
    fail(`selected entry ${selectedEntry} output dependency closure shape is invalid`);
  }
  const { sha256, ...identity } = closure;
  return { identity, sha256 };
}

export function buildConvexWasmDeploymentOutputClosures({
  bundleModulesByPath,
  entryPaths,
  metafile,
  repoRoot,
  runtimeModulePathByEntry,
}) {
  return createConvexWasmDeploymentOutputClosureProjection({
    bundleModulesByPath,
    metafile,
    repoRoot,
  }).select({ entryPaths, runtimeModulePathByEntry });
}

const deploymentOutputClosureAuthenticationRecords = new WeakMap();

export const convexWasmDeploymentOutputClosureAuthenticationKind =
  "convex-wasm-deployment-output-closure-authentication-v1";

function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
  }
  return value;
}

function deploymentOutputMetafileAuthentication(graphSession) {
  const exactGraphSession = exactDeploymentOutputClosureProjectionGraphSession(graphSession);
  if (exactGraphSession !== undefined) {
    return {
      metafile: exactGraphSession.metafile,
      metafileSha256: exactGraphSession.metafileSha256,
    };
  }
  const metafile = requireObject(
    requireObject(graphSession.graphTemplate, "graph template").metafile,
    "deployment output metafile"
  );
  if (!isOrdinaryJsonData(metafile)) {
    fail("deployment output metafile must contain ordinary JSON data");
  }
  const metafileSha256 = fingerprintJson(metafile);
  if (metafileSha256 !== graphSession.deploymentOutputMetafileSha256) {
    fail("deployment output metafile identity disagrees");
  }
  // The authenticated scope intentionally avoids hashing this large metafile for every entry.
  // Freeze the exact JSON authority so an in-place mutation cannot hide behind object reuse.
  return { metafile: freezeAuthenticatedJsonTree(metafile), metafileSha256 };
}

function requirePlainDeploymentOutputGraphSession(graphSession) {
  if (ordinaryOwnDataPropertySnapshot(graphSession) === undefined) {
    fail("deployment output closure graph session shape is invalid");
  }
  if (ordinaryOwnDataPropertySnapshot(graphSession.graphTemplate) === undefined) {
    fail("deployment output closure graph template shape is invalid");
  }
}

function deploymentOutputGraphRepoRoot(graphSession) {
  const repoRoot = requireString(
    graphSession.graphTemplate.repoRoot,
    "deployment output graph repository root"
  );
  if (!isAbsolute(repoRoot)) {
    fail("deployment output graph repository root must be absolute");
  }
  return repoRoot;
}

function createDeploymentOutputClosureAuthenticationRecord(graphSession) {
  const exactGraphAuthority = exactDeploymentOutputClosureProjectionGraphSession(graphSession);
  const deferredSelectionAuthority =
    exactGraphAuthority !== undefined &&
    [
      graphSession.bundleModulesByPath,
      graphSession.deploymentOutputClosureByEntry,
      graphSession.deploymentOutputModulesByPath,
    ].every((map) =>
      [...map.values()].every((value) => isDeeplyFrozenBuildInput(value))
    )
      ? exactGraphAuthority
      : undefined;
  return {
    authenticatedClosuresByEntry: new Map(),
    authenticatedModulesByPath: new Map(),
    bundleModulesByPath: graphSession.bundleModulesByPath,
    completeProjection: undefined,
    deploymentOutputClosureByEntry: graphSession.deploymentOutputClosureByEntry,
    deploymentOutputModulesByPath: graphSession.deploymentOutputModulesByPath,
    deferredSelectionAuthority,
    graphSession,
    graphTemplate: graphSession.graphTemplate,
    repoRoot: deploymentOutputGraphRepoRoot(graphSession),
    runtimeModulePathByEntry: graphSession.runtimeModulePathByEntry,
    ...deploymentOutputMetafileAuthentication(graphSession),
  };
}

export function createConvexWasmDeploymentOutputClosureAuthentication(graphSession) {
  requireObject(graphSession, "deployment output closure graph session");
  requirePlainDeploymentOutputGraphSession(graphSession);
  const authentication = Object.freeze({
    kind: convexWasmDeploymentOutputClosureAuthenticationKind,
  });
  deploymentOutputClosureAuthenticationRecords.set(
    authentication,
    createDeploymentOutputClosureAuthenticationRecord(graphSession)
  );
  return authentication;
}

export function canDeferConvexWasmDeploymentOutputClosureAuthentication({
  authentication,
  graphSession,
}) {
  const record = deploymentOutputClosureAuthenticationRecords.get(authentication);
  return (
    record !== undefined &&
    authentication?.kind === convexWasmDeploymentOutputClosureAuthenticationKind &&
    record.graphSession === graphSession &&
    record.deferredSelectionAuthority !== undefined &&
    exactDeploymentOutputClosureProjectionGraphSession(graphSession) ===
      record.deferredSelectionAuthority
  );
}

export function projectConvexWasmDeploymentOutputChunkGraph({ authentication, graphSession }) {
  const record = deploymentOutputClosureAuthenticationRecord(authentication, graphSession);
  if (record.chunkGraph !== undefined) return record.chunkGraph;
  const entries = [];
  const modulesByPath = new Map();
  const importsByKey = new Map();
  for (const [entryPath, producerClosure] of record.deploymentOutputClosureByEntry) {
    // Immutable producer ownership already admitted topology. Admit each module's exact bytes
    // once, without serializing every overlapping entry closure to derive global locators.
    // Independent fixture graphs still enter through the ordinary first-open closure validator.
    const closure =
      record.deferredSelectionAuthority === undefined
        ? selectConvexWasmDeploymentOutputClosure({ authentication, entryPath, graphSession })
            .identity
        : producerClosure;
    entries.push(Object.freeze({ entryPath, entryModulePath: closure.entryModulePath }));
    for (const expectedIdentity of closure.modules) {
      const modulePath = expectedIdentity.path;
      if (!modulesByPath.has(modulePath)) {
        modulesByPath.set(
          modulePath,
          exactDeploymentOutputModule({
            authenticatedModulesByPath: record.authenticatedModulesByPath,
            expectedIdentity,
            graphSession,
            modulePath,
            selectedEntry: entryPath,
          })
        );
      }
    }
    for (const imported of closure.imports) {
      importsByKey.set(
        `${imported.importerPath}\0${imported.kind}\0${imported.path}\0${String(imported.external)}`,
        imported
      );
    }
  }
  record.chunkGraph = Object.freeze({
    entries: Object.freeze(
      entries.sort((left, right) => compareStrings(left.entryPath, right.entryPath))
    ),
    imports: Object.freeze([...importsByKey.values()]),
    modules: Object.freeze([...modulesByPath.values()]),
  });
  return record.chunkGraph;
}

function deploymentOutputClosureAuthenticationRecord(authentication, graphSession) {
  if (authentication === undefined) {
    // Standalone callers get a fresh authentication scope. Deployment compilation supplies an
    // explicit scope so overlapping entry closures can share exact module authentication.
    return createDeploymentOutputClosureAuthenticationRecord(graphSession);
  }
  const record = deploymentOutputClosureAuthenticationRecords.get(authentication);
  if (
    record === undefined ||
    authentication?.kind !== convexWasmDeploymentOutputClosureAuthenticationKind ||
    record.graphSession !== graphSession ||
    record.bundleModulesByPath !== graphSession.bundleModulesByPath ||
    record.deploymentOutputClosureByEntry !== graphSession.deploymentOutputClosureByEntry ||
    record.deploymentOutputModulesByPath !== graphSession.deploymentOutputModulesByPath ||
    record.graphTemplate !== graphSession.graphTemplate ||
    record.repoRoot !== graphSession.graphTemplate.repoRoot ||
    record.runtimeModulePathByEntry !== graphSession.runtimeModulePathByEntry ||
    (record.deferredSelectionAuthority !== undefined &&
      exactDeploymentOutputClosureProjectionGraphSession(graphSession) !==
        record.deferredSelectionAuthority)
  ) {
    fail("deployment output closure authentication is invalid");
  }
  return record;
}

function completeDeploymentOutputClosure(record, entryPath, runtimeModulePath) {
  record.completeProjection ??= createConvexWasmDeploymentOutputClosureProjection({
    bundleModulesByPath: plainMapSnapshot(record.graphSession.bundleModulesByPath),
    metafile: record.metafile,
    repoRoot: record.repoRoot,
  });
  const { closures } = record.completeProjection.select({
    entryPaths: [entryPath],
    runtimeModulePathByEntry: new Map([[entryPath, runtimeModulePath]]),
  });
  const closure = closures.get(entryPath);
  if (closure === undefined) {
    fail(`missing reconstructed deployment output closure for selected entry ${entryPath}`);
  }
  return closure;
}

function freezeExactDeploymentOutputModule(actualIdentity, deploymentModule) {
  const identity = Object.freeze({
    ...actualIdentity,
    sourceMap:
      actualIdentity.sourceMap === null ? null : Object.freeze({ ...actualIdentity.sourceMap }),
  });
  return Object.freeze({
    identity,
    source: deploymentModule.source,
    ...(deploymentModule.sourceMap === undefined ? {} : { sourceMap: deploymentModule.sourceMap }),
  });
}

function hasExactDeploymentOutputModuleShape(value) {
  const expectedKeys =
    value.sourceMap === undefined ? ["path", "source"] : ["path", "source", "sourceMap"];
  const keys = Reflect.ownKeys(value);
  return keys.length === expectedKeys.length && keys.every((key) => expectedKeys.includes(key));
}

function exactDeploymentOutputModule({
  authenticatedModulesByPath,
  expectedIdentity,
  modulePath,
  selectedEntry,
  graphSession,
}) {
  const currentIdentity = intrinsicMapGet(graphSession.bundleModulesByPath, modulePath);
  if (currentIdentity === undefined) {
    fail(
      `missing authenticated deployment output module identity for selected entry ${selectedEntry} at ${modulePath}`
    );
  }
  if (!isOrdinaryJsonData(currentIdentity)) {
    fail(
      `selected entry ${selectedEntry} deployment output module identity ${modulePath} must contain ordinary JSON data`
    );
  }
  const expectedIdentitySource = canonicalJson(expectedIdentity);
  const currentIdentitySource = canonicalJson(currentIdentity);
  if (currentIdentitySource !== expectedIdentitySource) {
    fail(
      `selected entry ${selectedEntry} deployment output module identity changed for ${modulePath}`
    );
  }
  const deploymentModule = intrinsicMapGet(graphSession.deploymentOutputModulesByPath, modulePath);
  if (deploymentModule === undefined) {
    fail(
      `missing exact deployment output module for selected entry ${selectedEntry} at ${modulePath}`
    );
  }
  requireObject(deploymentModule, `selected entry ${selectedEntry} deployment output module`);
  if (
    !isOrdinaryJsonData(deploymentModule) ||
    !hasExactDeploymentOutputModuleShape(deploymentModule)
  ) {
    fail(`selected entry ${selectedEntry} deployment output module ${modulePath} shape is invalid`);
  }
  if (deploymentModule.path !== modulePath) {
    fail(
      `selected entry ${selectedEntry} deployment output module path ${JSON.stringify(
        deploymentModule.path
      )} disagrees with ${modulePath}`
    );
  }
  const authenticated = authenticatedModulesByPath.get(modulePath);
  if (authenticated !== undefined) {
    if (
      authenticated.expectedIdentitySource !== expectedIdentitySource ||
      authenticated.currentIdentity !== currentIdentity ||
      authenticated.deploymentModule !== deploymentModule
    ) {
      fail(
        `selected entry ${selectedEntry} deployment output module changed during source authentication for ${modulePath}`
      );
    }
    return authenticated.module;
  }
  const actualIdentity = bundleModuleIdentity(
    { environment: "isolate", ...deploymentModule },
    `selected entry ${selectedEntry} deployment output module`,
    "isolate"
  );
  if (canonicalJson(actualIdentity) !== expectedIdentitySource) {
    fail(
      `selected entry ${selectedEntry} deployment output module bytes disagree with its authenticated identity for ${modulePath}`
    );
  }
  const module = freezeExactDeploymentOutputModule(actualIdentity, deploymentModule);
  freezeAuthenticatedJsonTree(currentIdentity);
  freezeAuthenticatedJsonTree(deploymentModule);
  authenticatedModulesByPath.set(modulePath, {
    currentIdentity,
    deploymentModule,
    expectedIdentitySource,
    module,
  });
  return module;
}

export function selectConvexWasmDeploymentOutputClosure({
  authentication,
  entryPath,
  graphSession,
}) {
  requireObject(graphSession, "graph session");
  requirePlainDeploymentOutputGraphSession(graphSession);
  const authenticationRecord = deploymentOutputClosureAuthenticationRecord(
    authentication,
    graphSession
  );
  const { authenticatedClosuresByEntry, authenticatedModulesByPath, metafile, metafileSha256 } =
    authenticationRecord;
  if (
    graphSession.graphTemplate?.metafile !== metafile ||
    graphSession.deploymentOutputMetafileSha256 !== metafileSha256
  ) {
    fail("deployment output metafile changed during source authentication");
  }
  const selectedEntry = requireString(entryPath, "selected entry path");
  if (!isUnproxiedMap(graphSession.runtimeModulePathByEntry)) {
    fail("graph session has no runtime module paths");
  }
  if (!isUnproxiedMap(graphSession.bundleModulesByPath)) {
    fail("graph session has no authenticated isolate bundle module identities");
  }
  if (!isUnproxiedMap(graphSession.deploymentOutputModulesByPath)) {
    fail("graph session has no exact deployment output modules");
  }
  if (!isUnproxiedMap(graphSession.deploymentOutputClosureByEntry)) {
    fail("graph session has no deployment output dependency closures");
  }
  const runtimeModulePath = intrinsicMapGet(graphSession.runtimeModulePathByEntry, entryPath);
  if (runtimeModulePath === undefined) {
    fail(`missing runtime module path for selected entry ${selectedEntry}`);
  }
  requireString(runtimeModulePath, `selected entry ${selectedEntry} runtime module path`);
  const closure = intrinsicMapGet(graphSession.deploymentOutputClosureByEntry, entryPath);
  if (closure === undefined) {
    fail(`missing deployment output dependency closure for selected entry ${selectedEntry}`);
  }
  requireObject(closure, `selected entry ${selectedEntry} output dependency closure`);
  const exactGraphSession = exactDeploymentOutputClosureProjectionGraphSession(graphSession);
  const exactClosureAuthority = deploymentOutputClosureProjectionAuthorities.get(closure);
  const exactProducedClosure =
    exactGraphSession !== undefined &&
    exactClosureAuthority !== undefined &&
    exactClosureAuthority.projection === exactGraphSession.projection &&
    exactClosureAuthority.bundleModulesByPath === graphSession.bundleModulesByPath &&
    exactClosureAuthority.metafile === metafile &&
    exactClosureAuthority.metafileSha256 === metafileSha256 &&
    exactClosureAuthority.entryPath === selectedEntry &&
    exactClosureAuthority.entryModulePath === runtimeModulePath;
  const authenticatedClosure = authenticatedClosuresByEntry.get(selectedEntry);
  if (authenticatedClosure !== undefined && authenticatedClosure.closure !== closure) {
    fail(
      `selected entry ${selectedEntry} output dependency closure changed during source authentication`
    );
  }
  if (closure.entryModulePath !== runtimeModulePath) {
    fail(`selected entry ${selectedEntry} output dependency closure has the wrong entry module`);
  }
  if (exactProducedClosure) {
    // Exact projection ownership binds the immutable identity and its producer-computed digest.
    // Foreign/copy paths below still authenticate the complete caller-provided identity.
    if (closure.sha256 !== exactClosureAuthority.sha256) {
      fail(`selected entry ${selectedEntry} output dependency closure identity disagrees`);
    }
  } else if (authenticatedClosure === undefined) {
    const { identity: closureIdentity, sha256: closureSha256 } =
      unauthenticatedDeploymentOutputClosureIdentity(closure, selectedEntry);
    if (closureSha256 !== fingerprintJson(closureIdentity)) {
      fail(`selected entry ${selectedEntry} output dependency closure identity disagrees`);
    }
  }
  if (closure.metafileSha256 !== metafileSha256) {
    fail(`selected entry ${selectedEntry} output metafile identity disagrees`);
  }
  if (!Array.isArray(closure.modules) || closure.modules.length === 0) {
    fail(`selected entry ${selectedEntry} output dependency closure has no modules`);
  }
  if (closure.modules[0]?.path !== runtimeModulePath) {
    fail(`selected entry ${selectedEntry} output dependency closure is not entry-first`);
  }
  const modules = closure.modules.map((expectedIdentity) => {
    requireObject(expectedIdentity, `selected entry ${selectedEntry} output module identity`);
    return exactDeploymentOutputModule({
      authenticatedModulesByPath,
      expectedIdentity,
      graphSession,
      modulePath: requireString(
        expectedIdentity.path,
        `selected entry ${selectedEntry} output module path`
      ),
      selectedEntry,
    });
  });
  if (!exactProducedClosure && authenticatedClosure === undefined) {
    const expectedClosure = completeDeploymentOutputClosure(
      authenticationRecord,
      selectedEntry,
      runtimeModulePath
    );
    if (canonicalJson(closure) !== canonicalJson(expectedClosure)) {
      fail(
        `selected entry ${selectedEntry} output dependency closure disagrees with authenticated metafile topology`
      );
    }
  }
  if (authenticatedClosure !== undefined) {
    if (
      modules.length !== authenticatedClosure.snapshot.modules.length ||
      modules.some((module, index) => module !== authenticatedClosure.snapshot.modules[index])
    ) {
      fail(
        `selected entry ${selectedEntry} output dependency closure changed during source authentication`
      );
    }
    return authenticatedClosure.snapshot;
  }
  // Producer closures already own frozen rows. Foreign closures are frozen after complete
  // authentication; subsequent selections need only the exact closure reference checked above.
  if (!exactProducedClosure) freezeAuthenticatedJsonTree(closure);
  const snapshot = Object.freeze({
    identity: closure,
    modules: Object.freeze(modules),
  });
  authenticatedClosuresByEntry.set(selectedEntry, {
    closure,
    snapshot,
  });
  return snapshot;
}
