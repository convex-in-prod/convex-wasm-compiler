import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { join, posix } from "node:path";

import { parse as parseBabelAst } from "@babel/parser";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-pipeline.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { decodeUtf8 } from "./convex-wasm-artifact-material.mjs";
import { normalizeConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import {
  authenticateConvexWasmOfficialOutputSelectionSet,
  projectConvexWasmOfficialOutputSourceChunkGraph,
} from "./convex-wasm-official-output-prototype.mjs";
import {
  createConvexWasmOfficialOutputExecutableDependencySpecifier,
  parseConvexWasmOfficialOutputExecutableDependencySpecifier,
} from "./convex-wasm-official-output-chunk-contract.mjs";
import {
  convexWasmOfficialOutputChunkNativeSymbolLocator,
  convexWasmOfficialOutputNativeSymbolIdentitySha256,
} from "./convex-wasm-native-symbol-identity.mjs";
import { convexWasmStaticHermesEsbuildSupportedSyntax } from "./convex-wasm-static-hermes-syntax.mjs";

export const convexWasmOfficialOutputChunkUnitsKind = "convex-wasm-official-output-chunk-units-v3";
export const convexWasmOfficialOutputChunkUnitKind = "convex-wasm-official-output-chunk-unit-v2";
export const convexWasmOfficialOutputChunkTransformSessionKind =
  "convex-wasm-official-output-chunk-transform-session-v1";

const convexWasmOfficialOutputChunkTransformCacheIdentityKind =
  "convex-wasm-official-output-chunk-transform-cache-identity-v5";
const convexWasmOfficialOutputChunkTransformImplementationIdentityKind =
  "convex-wasm-official-output-chunk-transform-implementation-identity-v1";
const convexWasmOfficialOutputChunkTransformCacheRecordKind =
  "convex-wasm-official-output-chunk-transform-cache-record-v3";
const convexWasmOfficialOutputChunkTransformCacheStage = "official-output-chunk-transform";
const convexWasmOfficialOutputChunkTransformCacheMaximumBytes = 64 * 1024 * 1024;
export const convexWasmOfficialOutputChunkPreparationCacheStage =
  "official-output-chunk-preparation";
export const convexWasmOfficialOutputChunkIdentityCacheStage = "official-output-chunk-identity";
export const convexWasmOfficialOutputChunkPreparationCacheRecordKind =
  "convex-wasm-official-output-chunk-preparation-cache-record-v3";
export const convexWasmOfficialOutputChunkIdentityCacheRecordKind =
  "convex-wasm-official-output-chunk-identity-cache-record-v4";
const convexWasmOfficialOutputChunkPreparationCacheIdentityKind =
  "convex-wasm-official-output-chunk-preparation-cache-identity-v3";
const convexWasmOfficialOutputChunkIdentityCacheIdentityKind =
  "convex-wasm-official-output-chunk-identity-cache-identity-v4";
const convexWasmOfficialOutputChunkPreparationCacheMaximumBytes = 4 * 1024 * 1024;
const convexWasmOfficialOutputChunkIdentityCacheMaximumBytes = 4 * 1024 * 1024;
const convexWasmOfficialOutputChunkTransformImplementationSourcePaths = Object.freeze([
  "scripts/lib/convex-wasm-native-symbol-identity.mjs",
  "scripts/lib/convex-wasm-official-output-chunk-contract.mjs",
  "scripts/lib/convex-wasm-official-output-chunk-unit.mjs",
]);

export const convexWasmOfficialOutputChunkModuleTransform = Object.freeze({
  format: "cjs",
  kind: "convex-wasm-esbuild-closed-chunk-transform-v2",
  minifyIdentifiers: true,
  minifySyntax: true,
  minifyWhitespace: false,
  platform: "browser",
  sourcemap: false,
  supported: Object.freeze({
    ...convexWasmStaticHermesEsbuildSupportedSyntax,
    "dynamic-import": false,
  }),
  target: "esnext",
  treeShaking: false,
});

const esbuildChunkModuleTransformOptions = Object.freeze(
  (({ kind: _kind, ...options }) => options)(convexWasmOfficialOutputChunkModuleTransform)
);
const esbuildChunkModuleTransformSha256 = fingerprintJson(
  convexWasmOfficialOutputChunkModuleTransform
);
const chunkTransformSessionRecords = new WeakMap();
const authenticatedChunkUnits = new WeakSet();
const compactAuthenticatedChunkUnits = new WeakSet();
const compactChunkUnitMaterializations = new WeakMap();
const compactChunkUnitReadinessMaterial = new WeakMap();
const physicalUnitReadinessObserverRecords = new WeakMap();
const sourceChunkBindingPaths = new WeakMap();
const sourceChunkBindingPathProjections = new WeakMap();

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const supportedImportKinds = new Set(["dynamic-import", "import-statement"]);
const reservedChunkHostIdentifiers = new Set([
  "__convexWasmOfficialChunkBegin",
  "__convexWasmOfficialChunkPublish",
  "__convexWasmOfficialChunkReportThrown",
  "__convexWasmOfficialChunkRequire",
]);

function fail(message) {
  throw new Error(`Convex Wasm official-output chunk units: ${message}`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

const requireFromChunkUnit = createRequire(import.meta.url);
const babelParserVersion = requireString(
  requireFromChunkUnit("@babel/parser/package.json").version,
  "@babel/parser version"
);

function requireTransformedCode(value, description) {
  if (typeof value !== "string" || value.includes("\0")) {
    fail(`${description} must be a string without NUL bytes`);
  }
  return value;
}

function normalizeTransformedCode(value, description) {
  const code = requireTransformedCode(value, description);
  // Esbuild emits an empty string for comment-only and otherwise empty chunks. Artifact entries
  // and executable chunk units are intentionally non-empty, so retain the same JavaScript
  // semantics through one canonical no-op statement.
  return code.length === 0 ? ";\n" : code;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireArray(value, description) {
  if (!Array.isArray(value)) {
    fail(`${description} must be an array`);
  }
  return value;
}

function requireExactKeys(value, keys, description) {
  const object = requireObject(value, description);
  const actual = Object.keys(object).sort(compareStrings);
  const expected = [...keys].sort(compareStrings);
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${description} has unsupported fields`);
  }
  return object;
}

function requireEsbuild(esbuild) {
  if (typeof esbuild?.transform !== "function" || typeof esbuild.version !== "string") {
    fail("esbuild transform API is invalid");
  }
  return esbuild;
}

function transformImplementationIdentity(producerIdentity) {
  const sourceRecords = [
    ...producerIdentity.sources.map((source) => ({ semantic: true, source })),
    ...(producerIdentity.operationalSources ?? []).map((source) => ({
      semantic: false,
      source,
    })),
  ];
  const sources = convexWasmOfficialOutputChunkTransformImplementationSourcePaths.map((path) => {
    const matching = sourceRecords.filter(({ source }) => source.path === path);
    if (matching.length !== 1) {
      fail(
        `transform implementation producer identity must contain exactly one source record for ${path}`
      );
    }
    if (!matching[0].semantic) {
      fail(`transform implementation source must be a semantic producer source: ${path}`);
    }
    return matching[0].source;
  });
  return Object.freeze({
    kind: convexWasmOfficialOutputChunkTransformImplementationIdentityKind,
    sources: Object.freeze(sources),
  });
}

function normalizePersistentTransformCache(value) {
  const cache = requireExactKeys(
    value,
    new Set(["cacheLayout", "cacheRoot", "producerIdentity"]),
    "official-output chunk persistent transform cache"
  );
  const cacheLayout = normalizeConvexWasmCacheLayout(cache.cacheLayout);
  if (cache.cacheRoot !== cacheLayout.cacheRoot) {
    fail("official-output chunk persistent transform cache root disagrees with its layout");
  }
  const producerIdentity = normalizeConvexWasmProducerIdentity(cache.producerIdentity);
  return Object.freeze({
    cacheLayout,
    cacheRoot: cacheLayout.cacheRoot,
    producerIdentity,
    transformImplementation: transformImplementationIdentity(producerIdentity),
  });
}

export function createConvexWasmOfficialOutputChunkTransformSession({ esbuild, persistentCache }) {
  const authenticatedEsbuild = requireEsbuild(esbuild);
  const normalizedPersistentCache =
    persistentCache === undefined ? undefined : normalizePersistentTransformCache(persistentCache);
  const session = Object.freeze({
    esbuildVersion: authenticatedEsbuild.version,
    kind: convexWasmOfficialOutputChunkTransformSessionKind,
  });
  chunkTransformSessionRecords.set(session, {
    dependencyAnalysisCacheHits: 0,
    dependencyAnalysisCacheMisses: 0,
    dependencyLiteralsByModule: new WeakMap(),
    esbuild: authenticatedEsbuild,
    esbuildVersion: session.esbuildVersion,
    moduleSourcePreparationCacheHits: 0,
    moduleSourcePreparationCacheMisses: 0,
    moduleSourcePreparationsByModule: new WeakMap(),
    persistentIdentityCacheHits: 0,
    persistentIdentityCacheMisses: 0,
    persistentIdentitiesByIdentity: new Map(),
    persistentPreparationCacheHits: 0,
    persistentPreparationCacheMisses: 0,
    persistentPreparationsByIdentity: new Map(),
    preparationTail: Promise.resolve(),
    persistentCache: normalizedPersistentCache,
    transform: authenticatedEsbuild.transform,
    transformInputCacheHits: 0,
    transformInputCacheMisses: 0,
    transformedJavascriptMaterializations: 0,
    transformedModuleBaseCacheHits: 0,
    transformedModuleBaseCacheMisses: 0,
    transformedModuleBasesByInput: new WeakMap(),
    transforms: new Map(),
  });
  return session;
}

export function createConvexWasmOfficialOutputPhysicalUnitReadinessObserver({ limit, onReady }) {
  if (!Number.isSafeInteger(limit) || limit < 1 || typeof onReady !== "function") {
    fail("physical-unit readiness observer requires a positive limit and callback");
  }
  const observer = Object.freeze({
    kind: "convex-wasm-official-output-physical-unit-readiness-observer-v1",
  });
  physicalUnitReadinessObserverRecords.set(observer, {
    claimed: false,
    limit,
    onReady,
  });
  return observer;
}

function claimPhysicalUnitReadinessObserver(observer) {
  if (observer === undefined) return undefined;
  const record = physicalUnitReadinessObserverRecords.get(observer);
  if (
    record === undefined ||
    observer?.kind !== "convex-wasm-official-output-physical-unit-readiness-observer-v1" ||
    record.claimed
  ) {
    fail("physical-unit readiness observer is invalid or was already claimed");
  }
  record.claimed = true;
  return record;
}

function chunkTransformSessionRecord(session, esbuild) {
  if (session === undefined) return undefined;
  const record = chunkTransformSessionRecords.get(session);
  if (
    record === undefined ||
    session?.kind !== convexWasmOfficialOutputChunkTransformSessionKind ||
    session.esbuildVersion !== esbuild.version
  ) {
    fail("official-output chunk transform session is invalid");
  }
  if (record.esbuild !== esbuild || record.transform !== esbuild.transform) {
    fail("official-output chunk transform session belongs to a different esbuild API");
  }
  return record;
}

async function scheduleChunkTransformPreparation(record, prepare) {
  if (record === undefined) return prepare();
  const predecessor = record.preparationTail;
  let release;
  record.preparationTail = new Promise((resolvePromise) => {
    release = resolvePromise;
  });
  await predecessor;
  try {
    return prepare();
  } finally {
    // Cohort preparation performs synchronous parsing on the Node thread. Release the next
    // cohort in a new event-loop turn so transforms started by this cohort can make progress.
    setImmediate(release);
  }
}

async function settleChunkUnitWork(promises) {
  const settlements = await Promise.allSettled(promises);
  const failure = settlements.find((settlement) => settlement.status === "rejected");
  if (failure !== undefined) throw failure.reason;
  return settlements.map((settlement) => settlement.value);
}

function transformCacheIdentity({ esbuildVersion, persistentCache, source, sourcefile }) {
  return {
    esbuild: { version: esbuildVersion },
    kind: convexWasmOfficialOutputChunkTransformCacheIdentityKind,
    parser: { version: babelParserVersion },
    source,
    sourcefile,
    transform: convexWasmOfficialOutputChunkModuleTransform,
    transformImplementation: persistentCache.transformImplementation,
  };
}

function authenticateTransformCacheRecord(code, metadata) {
  const value = requireExactKeys(
    metadata,
    new Set(["kind", "requireSpecifiers", "schemaVersion"]),
    "official-output chunk transform cache metadata"
  );
  const transformedCode = normalizeTransformedCode(
    code,
    "official-output chunk transform cache code"
  );
  const requireSpecifiers = requireArray(
    value.requireSpecifiers,
    "official-output chunk transform cache require specifiers"
  ).map((specifier, index) =>
    requireString(specifier, `official-output chunk transform cache require specifier ${index}`)
  );
  if (
    value.kind !== convexWasmOfficialOutputChunkTransformCacheRecordKind ||
    value.schemaVersion !== 3 ||
    canonicalJson(requireSpecifiers) !==
      canonicalJson([...new Set(requireSpecifiers)].sort(compareStrings))
  ) {
    fail("official-output chunk transform cache record is invalid");
  }
  return { code: transformedCode, requireSpecifiers };
}

function parseCanonicalCacheRecord(entry, description) {
  if (!Buffer.isBuffer(entry.artifactContents)) {
    fail(`${description} lacks authenticated payload bytes`);
  }
  const source = decodeUtf8(entry.artifactContents, description);
  let record;
  try {
    record = JSON.parse(source);
  } catch (error) {
    throw new Error(`Convex Wasm official-output chunk units: ${description} is not valid JSON`, {
      cause: error,
    });
  }
  if (`${canonicalJson(record)}\n` !== source) {
    fail(`${description} is not canonical JSON`);
  }
  return record;
}

function artifactReference(entry, cacheKey, stage) {
  if (entry.key !== cacheKey || entry.stage !== stage) {
    fail("referenced artifact entry changed its cache authority");
  }
  return Object.freeze({
    artifactSha256: requireSha256(entry.artifactSha256, "referenced artifact SHA-256"),
    artifactSize: entry.artifactSize,
    cacheKey: requireSha256(cacheKey, "referenced artifact cache key"),
    stage: requireString(stage, "referenced artifact stage"),
  });
}

function authenticateArtifactReference(value, expectedStage, description) {
  const reference = requireExactKeys(
    value,
    new Set(["artifactSha256", "artifactSize", "cacheKey", "stage"]),
    description
  );
  if (!Number.isSafeInteger(reference.artifactSize) || reference.artifactSize <= 0) {
    fail(`${description} size is invalid`);
  }
  const authenticated = Object.freeze({
    artifactSha256: requireSha256(reference.artifactSha256, `${description} SHA-256`),
    artifactSize: reference.artifactSize,
    cacheKey: requireSha256(reference.cacheKey, `${description} cache key`),
    stage: requireString(reference.stage, `${description} stage`),
  });
  if (authenticated.stage !== expectedStage) {
    fail(`${description} stage changed`);
  }
  return authenticated;
}

function sameArtifactReference(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

async function transformChunkModule({
  esbuild,
  esbuildVersion,
  module,
  persistentCache,
  source,
  sourceIdentity,
  sourcefile,
  transform,
}) {
  const transformSource = async () =>
    await transform.call(esbuild, source, {
      ...esbuildChunkModuleTransformOptions,
      sourcefile,
    });
  if (persistentCache === undefined) {
    const result = await transformSource();
    const code = normalizeTransformedCode(result.code, "official-output chunk transformed code");
    return {
      code,
      cacheReference: undefined,
      persistentCacheMiss: false,
      requireSpecifiers: transformedRequireSpecifiers(code, module.identity.path),
    };
  }
  const identity = transformCacheIdentity({
    esbuildVersion,
    persistentCache,
    source: sourceIdentity,
    sourcefile,
  });
  const cached = await ensureArtifactStage({
    build: async (workPath) => {
      const result = await transformSource();
      const code = normalizeTransformedCode(result.code, "official-output chunk transformed code");
      const requireSpecifiers = transformedRequireSpecifiers(code, module.identity.path);
      const outputPath = join(workPath, "transform.js");
      await fs.writeFile(outputPath, code, { flag: "wx", mode: 0o600 });
      return {
        metadata: {
          kind: convexWasmOfficialOutputChunkTransformCacheRecordKind,
          requireSpecifiers,
          schemaVersion: 3,
        },
        outputPath,
        timing: null,
      };
    },
    cacheLayout: persistentCache.cacheLayout,
    cacheRoot: persistentCache.cacheRoot,
    extension: "js",
    identity,
    maxArtifactBytes: convexWasmOfficialOutputChunkTransformCacheMaximumBytes,
    readCachedArtifactContents: true,
    readPublishedArtifactContents: true,
    stage: convexWasmOfficialOutputChunkTransformCacheStage,
  });
  if (canonicalJson(cached.entry.identity) !== canonicalJson(identity)) {
    fail("official-output chunk transform cache entry identity changed");
  }
  if (!Buffer.isBuffer(cached.entry.artifactContents)) {
    fail("official-output chunk transform cache entry lacks authenticated payload bytes");
  }
  const code = decodeUtf8(
    cached.entry.artifactContents,
    "official-output chunk transform cache record"
  );
  return {
    ...authenticateTransformCacheRecord(code, cached.entry.metadata),
    cacheReference: artifactReference(
      cached.entry,
      cached.report.cacheKey,
      convexWasmOfficialOutputChunkTransformCacheStage
    ),
    persistentCacheMiss: cached.report.cache === "miss",
  };
}

function requireOutputModulePath(value, description) {
  const path = requireString(value, description);
  if (
    path.startsWith("/") ||
    path.includes("\\") ||
    path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    fail(`${description} must be a normalized deployment output path`);
  }
  return path;
}

function normalizeImport(imported, description) {
  const value = requireExactKeys(
    imported,
    new Set(["external", "importerPath", "kind", "path"]),
    description
  );
  if (value.external !== false) {
    fail(`${description} is external; physical official chunks require an exact closed graph`);
  }
  if (!supportedImportKinds.has(value.kind)) {
    fail(`${description} has unsupported import kind ${JSON.stringify(value.kind)}`);
  }
  return {
    external: false,
    importerPath: requireOutputModulePath(value.importerPath, `${description} importer path`),
    kind: value.kind,
    path: requireOutputModulePath(value.path, `${description} path`),
  };
}

function normalizeRoute(route, description) {
  const value = requireExactKeys(
    route,
    new Set([
      "entryPath",
      "exportName",
      "modulePath",
      "runtimeModulePath",
      "udfKind",
      "visibility",
    ]),
    description
  );
  if (value.udfKind !== "query" && value.udfKind !== "mutation") {
    fail(`${description} has unsupported UDF kind`);
  }
  if (value.visibility !== "internal" && value.visibility !== "public") {
    fail(`${description} has unsupported visibility`);
  }
  return {
    entryPath: requireString(value.entryPath, `${description} entry path`),
    exportName: requireString(value.exportName, `${description} export name`),
    modulePath: requireString(value.modulePath, `${description} module path`),
    runtimeModulePath: requireOutputModulePath(
      value.runtimeModulePath,
      `${description} runtime module path`
    ),
    udfKind: value.udfKind,
    visibility: value.visibility,
  };
}

function projectAuthenticatedClosure(rawClosure, selectionIndex) {
  const closure = requireObject(rawClosure, `selection ${selectionIndex} closure`);
  const closureIdentity = requireObject(
    closure.identity,
    `selection ${selectionIndex} closure identity`
  );
  const rawModules = requireArray(closure.modules, `selection ${selectionIndex} closure modules`);
  if (rawModules.length === 0) {
    fail(`selection ${selectionIndex} closure has no exact official chunks`);
  }
  const imports = requireArray(
    closureIdentity.imports,
    `selection ${selectionIndex} closure imports`
  ).map((imported, importIndex) =>
    normalizeImport(imported, `selection ${selectionIndex} closure import ${importIndex}`)
  );
  // Opaque selection provenance is issued only after complete closure/module SHA-256 and exact
  // byte authentication, and it owns this deeply frozen snapshot. Project the chunk fields here;
  // repeating the same byte pass cannot close another mutation window or grant more authority.
  return {
    identity: {
      entryModulePath: requireOutputModulePath(
        closureIdentity.entryModulePath,
        `selection ${selectionIndex} closure entry module path`
      ),
      imports,
      sha256: requireSha256(closureIdentity.sha256, `selection ${selectionIndex} closure SHA-256`),
    },
    modules: rawModules,
  };
}

function normalizeSelectionMembership(selection, index, normalizedClosuresByRawClosure) {
  const authenticatedSelection = selection;
  const value = requireExactKeys(
    authenticatedSelection,
    new Set(["closure", "manifestMembership", "route", "toolchain"]),
    `selection ${index}`
  );
  const route = normalizeRoute(value.route, `selection ${index} route`);
  const rawClosure = requireObject(value.closure, `selection ${index} closure`);
  let closure = normalizedClosuresByRawClosure.get(rawClosure);
  if (closure === undefined) {
    closure = projectAuthenticatedClosure(rawClosure, index);
    normalizedClosuresByRawClosure.set(rawClosure, closure);
  }
  if (closure.identity.entryModulePath !== route.runtimeModulePath) {
    fail(`selection ${index} has an invalid authenticated official-output closure`);
  }
  const membership = requireExactKeys(
    value.manifestMembership,
    new Set(["dependencyGraphSha256", "inventoryKind", "sourceEnvelopeSha256"]),
    `selection ${index} manifest membership`
  );
  return {
    closure,
    dependencyGraphSha256: requireSha256(
      membership.dependencyGraphSha256,
      `selection ${index} dependency graph SHA-256`
    ),
    inventoryKind: requireString(membership.inventoryKind, `selection ${index} inventory kind`),
    route,
    sourceEnvelopeSha256: requireSha256(
      membership.sourceEnvelopeSha256,
      `selection ${index} source envelope SHA-256`
    ),
    toolchain: {
      esbuild: requireString(value.toolchain?.esbuild, `selection ${index} esbuild version`),
    },
  };
}

function cohortSourceEnvelopeSha256({ entries, esbuildVersion, moduleIdentities }) {
  return fingerprintJson({
    domain: "convex-wasm-official-output-cohort-source-envelope-v1",
    entries,
    modules: moduleIdentities,
    toolchain: { esbuild: esbuildVersion },
  });
}

function mergeSelections(selections) {
  if (!Array.isArray(selections) || selections.length === 0) {
    fail("selections must contain at least one authenticated route");
  }
  const authenticatedSet = authenticateConvexWasmOfficialOutputSelectionSet(selections);
  const normalizedClosuresByRawClosure = new WeakMap();
  const normalized = authenticatedSet.selections.map((selection, index) =>
    normalizeSelectionMembership(selection, index, normalizedClosuresByRawClosure)
  );
  const esbuildVersion = normalized[0].toolchain.esbuild;
  const inventoryKind = normalized[0].inventoryKind;
  const admittedSourceEnvelopeSha256 = normalized[0].sourceEnvelopeSha256;
  if (
    normalized.some(
      (selection) =>
        selection.sourceEnvelopeSha256 !== admittedSourceEnvelopeSha256 ||
        selection.inventoryKind !== inventoryKind ||
        selection.toolchain.esbuild !== esbuildVersion
    )
  ) {
    fail("selections disagree on source-envelope, inventory, or esbuild identity");
  }
  const modulesByPath = new Map();
  const importsByKey = new Map();
  const entriesByPath = new Map();
  const mergedClosures = new Set();
  for (const selection of normalized) {
    if (!mergedClosures.has(selection.closure)) {
      for (const module of selection.closure.modules) {
        const existing = modulesByPath.get(module.identity.path);
        if (existing !== undefined && existing !== module) {
          fail(`official-output selections disagree on chunk ${module.identity.path}`);
        }
        modulesByPath.set(module.identity.path, module);
      }
      for (const imported of selection.closure.identity.imports) {
        const key = canonicalJson(imported);
        importsByKey.set(key, imported);
      }
      mergedClosures.add(selection.closure);
    }
    const existing = entriesByPath.get(selection.route.entryPath);
    const entry = existing ?? {
      closureSha256: selection.closure.identity.sha256,
      dependencyGraphSha256: selection.dependencyGraphSha256,
      entryModulePath: selection.route.runtimeModulePath,
      entryPath: selection.route.entryPath,
      modulePath: selection.route.modulePath,
      routes: [],
    };
    if (
      entry.closureSha256 !== selection.closure.identity.sha256 ||
      entry.dependencyGraphSha256 !== selection.dependencyGraphSha256 ||
      entry.entryModulePath !== selection.route.runtimeModulePath ||
      entry.modulePath !== selection.route.modulePath
    ) {
      fail(`official-output selections disagree on entry ${selection.route.entryPath}`);
    }
    entry.routes.push({
      exportName: selection.route.exportName,
      udfKind: selection.route.udfKind,
      visibility: selection.route.visibility,
    });
    entriesByPath.set(entry.entryPath, entry);
  }
  for (const imported of importsByKey.values()) {
    if (!modulesByPath.has(imported.importerPath) || !modulesByPath.has(imported.path)) {
      fail(`official-output chunk graph has an import outside the authenticated closure union`);
    }
  }
  const entryAuthorities = [...entriesByPath.values()]
    .map((entry) => ({
      ...entry,
      routes: entry.routes.sort((left, right) => compareStrings(left.exportName, right.exportName)),
    }))
    .sort((left, right) => compareStrings(left.entryPath, right.entryPath));
  for (const entry of entryAuthorities) {
    if (
      entry.routes.length === 0 ||
      entry.routes.some(
        (route, index) => index > 0 && entry.routes[index - 1].exportName === route.exportName
      ) ||
      !modulesByPath.has(entry.entryModulePath)
    ) {
      fail(`official-output entry ${entry.entryPath} has invalid route or chunk membership`);
    }
  }
  const entries = entryAuthorities.map(({ closureSha256: _closureSha256, ...entry }) => entry);
  return {
    entries,
    esbuildVersion,
    sourceAuthentication: authenticatedSet.sourceAuthentication,
    imports: [...importsByKey.values()].sort((left, right) => {
      const importerOrder = compareStrings(left.importerPath, right.importerPath);
      if (importerOrder !== 0) return importerOrder;
      const pathOrder = compareStrings(left.path, right.path);
      return pathOrder === 0 ? compareStrings(left.kind, right.kind) : pathOrder;
    }),
    modules: [...modulesByPath.values()].sort((left, right) =>
      compareStrings(left.identity.path, right.identity.path)
    ),
  };
}

function isNormalizedDependencySpecifier(specifier) {
  if (specifier.includes("\0") || specifier.includes("\\")) return false;
  const components = specifier.split("/");
  if (components[0] === ".") {
    components.shift();
  } else {
    let parentCount = 0;
    while (components[0] === "..") {
      components.shift();
      parentCount += 1;
    }
    if (parentCount === 0) return false;
  }
  return (
    components.length > 0 &&
    components.every((component) => component.length > 0 && component !== "." && component !== "..")
  );
}

function resolveLiteralSpecifier(importerPath, specifier) {
  if (!isNormalizedDependencySpecifier(specifier)) {
    fail(`chunk ${importerPath} has a computed, external, or non-normalized module specifier`);
  }
  const resolved = posix.normalize(posix.join(posix.dirname(importerPath), specifier));
  if (resolved === ".." || resolved.startsWith("../") || resolved.startsWith("/")) {
    fail(`chunk ${importerPath} import ${JSON.stringify(specifier)} escapes the official output`);
  }
  return resolved;
}

function visitAst(value, visit) {
  if (Array.isArray(value)) {
    for (const member of value) visitAst(member, visit);
    return;
  }
  if (value === null || typeof value !== "object") return;
  visit(value);
  for (const [key, nested] of Object.entries(value)) {
    if (key !== "loc" && key !== "start" && key !== "end") visitAst(nested, visit);
  }
}

function parseChunkJavascript(javascript, modulePath, phase, sourceType) {
  try {
    return parseBabelAst(javascript, {
      plugins: ["importAttributes"],
      sourceType,
    });
  } catch (error) {
    fail(
      `${phase} for ${modulePath} is not parseable: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

function sourceDependencyLiteral(node, modulePath) {
  let kind;
  let literal;
  if (
    node.type === "ImportDeclaration" ||
    node.type === "ExportAllDeclaration" ||
    (node.type === "ExportNamedDeclaration" && node.source !== null)
  ) {
    kind = "import-statement";
    literal = node.source;
  } else if (node.type === "ImportExpression") {
    kind = "dynamic-import";
    literal = node.source;
  } else if (node.type === "CallExpression" && node.callee?.type === "Import") {
    kind = "dynamic-import";
    if (node.arguments.length !== 1) {
      fail(`chunk ${modulePath} has a computed dynamic import before the pinned transform`);
    }
    [literal] = node.arguments;
  } else if (
    node.type === "CallExpression" &&
    node.callee?.type === "Identifier" &&
    node.callee.name === "require"
  ) {
    if (node.arguments.length !== 1) {
      fail(`chunk ${modulePath} has a computed require before the pinned transform`);
    }
    [literal] = node.arguments;
  } else {
    return undefined;
  }
  if (
    literal?.type !== "StringLiteral" ||
    !Number.isSafeInteger(literal.start) ||
    !Number.isSafeInteger(literal.end) ||
    literal.start < 0 ||
    literal.end <= literal.start
  ) {
    fail(`chunk ${modulePath} has a computed dependency before the pinned transform`);
  }
  return { kind, specifier: literal.value, start: literal.start, end: literal.end };
}

function parseModuleDependencyLiterals(module) {
  const ast = parseChunkJavascript(
    module.source,
    module.identity.path,
    "official-output module source",
    "module"
  );
  const literals = [];
  visitAst(ast.program, (node) => {
    const dependency = sourceDependencyLiteral(node, module.identity.path);
    if (dependency !== undefined) literals.push(dependency);
  });
  literals.sort((left, right) => left.start - right.start);
  return literals.map((literal, occurrence) => ({
    ...literal,
    occurrence,
    path: resolveLiteralSpecifier(module.identity.path, literal.specifier),
  }));
}

function moduleDependencyLiteralsForSession(record, module) {
  const cached = record?.dependencyLiteralsByModule.get(module);
  if (cached !== undefined) {
    record.dependencyAnalysisCacheHits += 1;
    return cached;
  }
  const parsed = Object.freeze(
    parseModuleDependencyLiterals(module).map((dependency) => Object.freeze(dependency))
  );
  if (record !== undefined) {
    record.dependencyAnalysisCacheMisses += 1;
    record.dependencyLiteralsByModule.set(module, parsed);
  }
  return parsed;
}

function bindModuleDependencyLiterals({ directImports, literals, module, modulesByPath }) {
  return literals.map((literal) => {
    const pathMatches = directImports.filter((imported) => imported.path === literal.path);
    const matching = pathMatches.filter(
      (imported) => literal.kind === undefined || imported.kind === literal.kind
    );
    if (matching.length === 0) {
      fail(`chunk ${module.identity.path} references a dependency outside its authenticated slots`);
    }
    if (matching.length > 1 || new Set(pathMatches.map(({ kind }) => kind)).size > 1) {
      fail(`chunk ${module.identity.path} has an ambiguous static or dynamic dependency slot`);
    }
    const dependencyModule = modulesByPath.get(literal.path);
    if (dependencyModule === undefined) {
      fail(`chunk ${module.identity.path} dependency has no authenticated module`);
    }
    return {
      end: literal.end,
      kind: matching[0].kind,
      occurrence: literal.occurrence,
      path: literal.path,
      sourceMembershipSha256: dependencyModule.identity.sourceMembershipSha256,
      specifier: literal.specifier,
      start: literal.start,
    };
  });
}

function canonicalChunkBindingPaths({ entries, modules, dependenciesByPath }) {
  const bestByModulePath = new Map();
  const pending = [];
  const admit = (modulePath, bindingPath) => {
    const rank = `${String(bindingPath.imports.length).padStart(10, "0")}\0${canonicalJson(
      bindingPath
    )}`;
    const existing = bestByModulePath.get(modulePath);
    if (existing !== undefined && existing.rank <= rank) return;
    const candidate = { bindingPath, modulePath, rank };
    bestByModulePath.set(modulePath, candidate);
    pending.push(candidate);
  };
  for (const entry of entries) {
    admit(entry.entryModulePath, { entryPath: entry.entryPath, imports: [] });
  }
  while (pending.length > 0) {
    pending.sort((left, right) => compareStrings(left.rank, right.rank));
    const candidate = pending.shift();
    if (bestByModulePath.get(candidate.modulePath) !== candidate) continue;
    for (const dependency of dependenciesByPath.get(candidate.modulePath) ?? []) {
      admit(dependency.path, {
        entryPath: candidate.bindingPath.entryPath,
        imports: [
          ...candidate.bindingPath.imports,
          { kind: dependency.kind, occurrence: dependency.occurrence },
        ],
      });
    }
  }
  const modulesByMembership = new Map();
  for (const module of modules) {
    const members = modulesByMembership.get(module.identity.sourceMembershipSha256) ?? [];
    members.push(module);
    modulesByMembership.set(module.identity.sourceMembershipSha256, members);
  }
  const canonicalEntryPathByModulePath = new Map(
    entries.map((entry) => [entry.entryModulePath, entry.entryPath])
  );
  const bindingPathsByPath = new Map();
  for (const module of modules) {
    const canonicalEntryPath = canonicalEntryPathByModulePath.get(module.identity.path);
    const needsRootedBindingPath =
      module.identity.sourceMap.sourcesCount === 0 ||
      modulesByMembership.get(module.identity.sourceMembershipSha256).length > 1;
    const candidate = bestByModulePath.get(module.identity.path);
    if (canonicalEntryPath === undefined && needsRootedBindingPath && candidate === undefined) {
      fail(`chunk ${module.identity.path} has no entry-rooted stable binding path`);
    }
    const bindingPath =
      canonicalEntryPath !== undefined
        ? { entryPath: canonicalEntryPath, imports: [] }
        : needsRootedBindingPath
          ? candidate.bindingPath
          : {
              entryPath: `source-membership:${module.identity.sourceMembershipSha256}`,
              imports: [],
            };
    bindingPathsByPath.set(module.identity.path, bindingPath);
  }
  if (new Set([...bindingPathsByPath.values()].map(canonicalJson)).size !== modules.length) {
    fail("authenticated chunks contain duplicate stable binding paths");
  }
  return bindingPathsByPath;
}

function admittedSourceChunkBindingPaths(sourceAuthentication, transformSessionRecord) {
  const existing = sourceChunkBindingPaths.get(sourceAuthentication);
  if (existing !== undefined) return existing;
  const graph = projectConvexWasmOfficialOutputSourceChunkGraph(sourceAuthentication);
  const modulesByPath = new Map(graph.modules.map((module) => [module.identity.path, module]));
  const directImportsByPath = new Map();
  for (const imported of graph.imports) {
    const imports = directImportsByPath.get(imported.importerPath) ?? [];
    imports.push(imported);
    directImportsByPath.set(imported.importerPath, imports);
  }
  const membershipCounts = new Map();
  for (const module of graph.modules) {
    membershipCounts.set(
      module.identity.sourceMembershipSha256,
      (membershipCounts.get(module.identity.sourceMembershipSha256) ?? 0) + 1
    );
  }
  const dependenciesByPath = new Map();
  if (
    graph.modules.some(
      (module) =>
        module.identity.sourceMap.sourcesCount === 0 ||
        membershipCounts.get(module.identity.sourceMembershipSha256) > 1
    )
  ) {
    for (const module of graph.modules) {
      dependenciesByPath.set(
        module.identity.path,
        bindModuleDependencyLiterals({
          directImports: directImportsByPath.get(module.identity.path) ?? [],
          literals: moduleDependencyLiteralsForSession(transformSessionRecord, module),
          module,
          modulesByPath,
        })
      );
    }
  }
  const bindingPaths = canonicalChunkBindingPaths({ ...graph, dependenciesByPath });
  sourceChunkBindingPaths.set(sourceAuthentication, bindingPaths);
  return bindingPaths;
}

export function projectConvexWasmOfficialOutputSourceChunkBindingPaths(
  sourceAuthentication,
  transformSession
) {
  const existing = sourceChunkBindingPathProjections.get(sourceAuthentication);
  if (existing !== undefined) return existing;
  const transformSessionRecord =
    transformSession === undefined ? undefined : chunkTransformSessionRecords.get(transformSession);
  if (transformSession !== undefined && transformSessionRecord === undefined) {
    fail("source chunk binding projection has an invalid transform session");
  }
  // Expose immutable values, never the source owner's mutable lookup table.
  const projection = Object.freeze(
    Object.fromEntries(
      [...admittedSourceChunkBindingPaths(sourceAuthentication, transformSessionRecord)].map(
        ([path, binding]) => [
          path,
          Object.freeze({
            entryPath: binding.entryPath,
            imports: Object.freeze(binding.imports.map((edge) => Object.freeze({ ...edge }))),
          }),
        ]
      )
    )
  );
  sourceChunkBindingPathProjections.set(sourceAuthentication, projection);
  return projection;
}

function sameModuleDependencyBindings(left, right) {
  return (
    left.length === right.length &&
    left.every(
      (dependency, index) =>
        dependency.end === right[index].end &&
        dependency.kind === right[index].kind &&
        dependency.occurrence === right[index].occurrence &&
        dependency.path === right[index].path &&
        dependency.sourceMembershipSha256 === right[index].sourceMembershipSha256 &&
        dependency.specifier === right[index].specifier &&
        dependency.start === right[index].start
    )
  );
}

function moduleSourcePreparationForSession({
  bindingPath,
  canonicalEntryPath,
  directImports,
  literals,
  module,
  modulesByPath,
  record,
}) {
  // Rebind every cohort to its own authenticated closure before consulting deployment-local
  // derived material. Exact module identity alone must not admit a different dependency graph.
  const dependencies = bindModuleDependencyLiterals({
    directImports,
    literals,
    module,
    modulesByPath,
  });
  const nativeSymbolLocator = convexWasmOfficialOutputChunkNativeSymbolLocator({
    bindingPath,
    canonicalEntryPath,
    sourceMembershipSha256: module.identity.sourceMembershipSha256,
  });
  const cached = record?.moduleSourcePreparationsByModule
    .get(module)
    ?.find(
      (candidate) =>
        sameModuleDependencyBindings(candidate.dependencies, dependencies) &&
        canonicalJson(candidate.nativeSymbolLocator) === canonicalJson(nativeSymbolLocator)
    );
  if (cached !== undefined) {
    record.moduleSourcePreparationCacheHits += 1;
    return cached;
  }
  const preparation = {
    dependencies: Object.freeze(dependencies.map((dependency) => Object.freeze({ ...dependency }))),
    nativeSymbolLocator,
    transformInputVariants: [],
  };
  if (record !== undefined) {
    record.moduleSourcePreparationCacheMisses += 1;
    const variants = record.moduleSourcePreparationsByModule.get(module) ?? [];
    variants.push(preparation);
    record.moduleSourcePreparationsByModule.set(module, variants);
  }
  return preparation;
}

function moduleTransformInputForSession({
  module,
  nativeSymbolLocatorsByPath,
  preparation,
  record,
  retainInSession = true,
}) {
  const dependencyLocators = preparation.dependencies.map((dependency) => {
    const locator = nativeSymbolLocatorsByPath.get(dependency.path);
    if (locator === undefined) {
      fail(`chunk ${module.identity.path} dependency has no native symbol locator`);
    }
    return locator;
  });
  const cached = retainInSession
    ? preparation.transformInputVariants.find(
        (candidate) =>
          candidate.dependencyLocators.length === dependencyLocators.length &&
          candidate.dependencyLocators.every(
            (locator, index) => locator === dependencyLocators[index]
          )
      )
    : undefined;
  if (cached !== undefined) {
    if (record !== undefined) record.transformInputCacheHits += 1;
    return cached.input;
  }
  const dependencies = moduleExecutableDependencies(
    preparation,
    nativeSymbolLocatorsByPath,
    module
  );
  const source = renderDependencyCanonicalSource(
    module.source,
    dependencies,
    ({ executableSpecifier }) => executableSpecifier
  );
  const sourceIdentity = Object.freeze({
    kind: "convex-wasm-official-output-canonical-transform-source-v1",
    sha256: source === module.source ? module.identity.sourceSha256 : sha256(source),
    size: source === module.source ? module.identity.sourceSize : Buffer.byteLength(source),
  });
  const nativeSymbolIdentitySha256 = convexWasmOfficialOutputNativeSymbolIdentitySha256({
    entryPublication: false,
    nativeSymbolLocator: preparation.nativeSymbolLocator,
  });
  const input = Object.freeze({
    dependencies,
    source,
    sourceIdentity,
    sourcefile: `convex-wasm-executable-${nativeSymbolIdentitySha256}.js`,
  });
  if (retainInSession) {
    preparation.transformInputVariants.push({
      dependencyLocators: Object.freeze(dependencyLocators),
      input,
    });
  }
  if (record !== undefined) record.transformInputCacheMisses += 1;
  return input;
}

function moduleExecutableDependencies(preparation, nativeSymbolLocatorsByPath, module) {
  return Object.freeze(
    preparation.dependencies.map((dependency) =>
      Object.freeze({
        ...dependency,
        executableSpecifier: createConvexWasmOfficialOutputExecutableDependencySpecifier({
          kind: dependency.kind,
          nativeSymbolIdentitySha256: convexWasmOfficialOutputNativeSymbolIdentitySha256({
            entryPublication: false,
            nativeSymbolLocator:
              nativeSymbolLocatorsByPath.get(dependency.path) ??
              fail(`chunk ${module.identity.path} dependency has no native symbol locator`),
          }),
          occurrence: dependency.occurrence,
        }),
      })
    )
  );
}

function chunkPreparationCacheIdentity({
  bindingPath,
  canonicalEntryPath,
  directImports,
  module,
  modulesByPath,
  nativeSymbolLocatorsByPath,
  persistentCache,
}) {
  const imports = directImports
    .map((imported) => {
      const target = modulesByPath.get(imported.path);
      if (target === undefined) {
        fail(`chunk ${module.identity.path} import has no exact target module`);
      }
      const nativeSymbolLocator = nativeSymbolLocatorsByPath.get(imported.path);
      if (nativeSymbolLocator === undefined) {
        fail(`chunk ${module.identity.path} import has no stable target binding`);
      }
      return {
        import: imported,
        nativeSymbolLocator,
      };
    })
    .sort((left, right) => compareStrings(canonicalJson(left), canonicalJson(right)));
  return {
    bindingPath,
    canonicalEntryPath,
    imports,
    kind: convexWasmOfficialOutputChunkPreparationCacheIdentityKind,
    module: module.identity,
    parser: { name: "@babel/parser", version: babelParserVersion },
    producerImplementation: persistentCache.transformImplementation,
    schemaVersion: 3,
  };
}

function authenticateChunkPreparationRecord({
  bindingPath,
  canonicalEntryPath,
  directImports,
  module,
  modulesByPath,
  record,
}) {
  const value = requireExactKeys(
    record,
    new Set(["dependencies", "kind", "nativeSymbolLocator", "schemaVersion"]),
    `chunk ${module.identity.path} preparation cache record`
  );
  if (
    value.kind !== convexWasmOfficialOutputChunkPreparationCacheRecordKind ||
    value.schemaVersion !== 3
  ) {
    fail(`chunk ${module.identity.path} preparation cache record is unsupported`);
  }
  const dependencies = requireArray(
    value.dependencies,
    `chunk ${module.identity.path} preparation cache dependencies`
  ).map((dependency, index) => {
    const normalized = requireExactKeys(
      dependency,
      new Set([
        "end",
        "kind",
        "occurrence",
        "path",
        "sourceMembershipSha256",
        "specifier",
        "start",
      ]),
      `chunk ${module.identity.path} preparation cache dependency ${index}`
    );
    const path = requireOutputModulePath(
      normalized.path,
      `chunk ${module.identity.path} preparation cache dependency ${index} path`
    );
    const target = modulesByPath.get(path);
    if (
      !supportedImportKinds.has(normalized.kind) ||
      !Number.isSafeInteger(normalized.occurrence) ||
      normalized.occurrence !== index ||
      !Number.isSafeInteger(normalized.start) ||
      !Number.isSafeInteger(normalized.end) ||
      normalized.start < 0 ||
      normalized.end <= normalized.start ||
      normalized.end > module.source.length ||
      (index > 0 && value.dependencies[index - 1].end > normalized.start) ||
      target === undefined ||
      normalized.sourceMembershipSha256 !== target.identity.sourceMembershipSha256
    ) {
      fail(`chunk ${module.identity.path} preparation cache dependency ${index} is invalid`);
    }
    const specifier = requireString(
      normalized.specifier,
      `chunk ${module.identity.path} preparation cache dependency ${index} specifier`
    );
    if (
      resolveLiteralSpecifier(module.identity.path, specifier) !== path ||
      !directImports.some(
        (imported) => imported.kind === normalized.kind && imported.path === normalized.path
      )
    ) {
      fail(`chunk ${module.identity.path} preparation cache dependency ${index} changed its edge`);
    }
    return Object.freeze({
      end: normalized.end,
      kind: normalized.kind,
      occurrence: normalized.occurrence,
      path,
      sourceMembershipSha256: requireSha256(
        normalized.sourceMembershipSha256,
        `chunk ${module.identity.path} preparation cache dependency ${index} source membership`
      ),
      specifier,
      start: normalized.start,
    });
  });
  const nativeSymbolLocator = convexWasmOfficialOutputChunkNativeSymbolLocator(
    value.nativeSymbolLocator
  );
  const expectedNativeSymbolLocator = convexWasmOfficialOutputChunkNativeSymbolLocator({
    bindingPath,
    canonicalEntryPath,
    sourceMembershipSha256: module.identity.sourceMembershipSha256,
  });
  if (canonicalJson(nativeSymbolLocator) !== canonicalJson(expectedNativeSymbolLocator)) {
    fail(`chunk ${module.identity.path} preparation cache native symbol locator changed`);
  }
  return {
    dependencies: Object.freeze(dependencies),
    nativeSymbolLocator,
    transformInputVariants: [],
  };
}

async function ensurePersistentChunkPreparation({
  bindingPath,
  canonicalEntryPath,
  directImports,
  module,
  modulesByPath,
  nativeSymbolLocatorsByPath,
  record,
}) {
  const persistentCache = record.persistentCache;
  const identity = chunkPreparationCacheIdentity({
    bindingPath,
    canonicalEntryPath,
    directImports,
    module,
    modulesByPath,
    nativeSymbolLocatorsByPath,
    persistentCache,
  });
  const identityKey = canonicalJson(identity);
  const owned = record.persistentPreparationsByIdentity.get(identityKey);
  if (owned !== undefined) return owned;
  // Share admission itself across concurrent cohorts. The identity binds stable dependency
  // locations; exact current targets are reauthenticated below before the result is returned.
  const admitted = admitPersistentChunkPreparation({
    bindingPath,
    canonicalEntryPath,
    directImports,
    identity,
    module,
    modulesByPath,
    record,
  });
  record.persistentPreparationsByIdentity.set(identityKey, admitted);
  // Failed admission owns no preparation. Preserve the failure for current waiters, but let a
  // later cohort retry after the failed external operation, as transform admission already does.
  void admitted.catch(() => {
    if (record.persistentPreparationsByIdentity.get(identityKey) === admitted) {
      record.persistentPreparationsByIdentity.delete(identityKey);
    }
  });
  return admitted;
}

async function admitPersistentChunkPreparation({
  bindingPath,
  canonicalEntryPath,
  directImports,
  identity,
  module,
  modulesByPath,
  record,
}) {
  const persistentCache = record.persistentCache;
  let builtPreparation;
  const cached = await ensureArtifactStage({
    build: async (workPath) => {
      builtPreparation = moduleSourcePreparationForSession({
        bindingPath,
        canonicalEntryPath,
        directImports,
        literals: moduleDependencyLiteralsForSession(record, module),
        module,
        modulesByPath,
        record,
      });
      const source = `${canonicalJson({
        dependencies: builtPreparation.dependencies,
        kind: convexWasmOfficialOutputChunkPreparationCacheRecordKind,
        nativeSymbolLocator: builtPreparation.nativeSymbolLocator,
        schemaVersion: 3,
      })}\n`;
      const outputPath = join(workPath, "preparation.json");
      await fs.writeFile(outputPath, source, { flag: "wx", mode: 0o600 });
      return {
        metadata: { kind: convexWasmOfficialOutputChunkPreparationCacheRecordKind },
        outputPath,
        timing: null,
      };
    },
    cacheLayout: persistentCache.cacheLayout,
    cacheRoot: persistentCache.cacheRoot,
    extension: "json",
    identity,
    maxArtifactBytes: convexWasmOfficialOutputChunkPreparationCacheMaximumBytes,
    readCachedArtifactContents: true,
    readPublishedArtifactContents: true,
    stage: convexWasmOfficialOutputChunkPreparationCacheStage,
  });
  if (
    canonicalJson(cached.entry.metadata) !==
    canonicalJson({ kind: convexWasmOfficialOutputChunkPreparationCacheRecordKind })
  ) {
    fail(`chunk ${module.identity.path} preparation cache authority changed`);
  }
  if (cached.report.cache === "hit") {
    record.persistentPreparationCacheHits += 1;
  } else {
    record.persistentPreparationCacheMisses += 1;
  }
  const preparation = authenticateChunkPreparationRecord({
    bindingPath,
    canonicalEntryPath,
    directImports,
    module,
    modulesByPath,
    record: parseCanonicalCacheRecord(
      cached.entry,
      `chunk ${module.identity.path} preparation cache record`
    ),
  });
  if (
    builtPreparation !== undefined &&
    (canonicalJson(builtPreparation.dependencies) !== canonicalJson(preparation.dependencies) ||
      canonicalJson(builtPreparation.nativeSymbolLocator) !==
        canonicalJson(preparation.nativeSymbolLocator))
  ) {
    fail(`chunk ${module.identity.path} preparation changed during publication`);
  }
  return Object.freeze({
    preparation,
    reference: artifactReference(
      cached.entry,
      cached.report.cacheKey,
      convexWasmOfficialOutputChunkPreparationCacheStage
    ),
  });
}

function renderDependencyCanonicalSource(source, dependencies, specifier) {
  let rendered = source;
  for (const dependency of [...dependencies].sort((left, right) => right.start - left.start)) {
    rendered = `${rendered.slice(0, dependency.start)}${JSON.stringify(
      specifier(dependency)
    )}${rendered.slice(dependency.end)}`;
  }
  // esbuild's external source-map trailer names the transport output. The separately
  // authenticated module and source-map identities retain it, but executable material does not.
  return rendered.replace(/(^|\n)\/\/# sourceMappingURL=[^\n]*\n?$/u, "$1");
}

function transformedRequireSpecifiers(javascript, modulePath) {
  const ast = parseChunkJavascript(
    javascript,
    modulePath,
    "esbuild module transform output",
    "script"
  );
  const specifiers = new Set();
  visitAst(ast.program, (node) => {
    if (node.type === "Identifier" && reservedChunkHostIdentifiers.has(node.name)) {
      fail(`chunk ${modulePath} references a reserved host callback identifier`);
    }
    if (
      node.type === "ImportExpression" ||
      (node.type === "CallExpression" && node.callee?.type === "Import")
    ) {
      fail(`chunk ${modulePath} retains a computed dynamic import after the pinned transform`);
    }
    if (
      node.type !== "CallExpression" ||
      node.callee?.type !== "Identifier" ||
      node.callee.name !== "require"
    ) {
      return;
    }
    if (node.arguments.length !== 1 || node.arguments[0]?.type !== "StringLiteral") {
      fail(`chunk ${modulePath} has a computed require after the pinned transform`);
    }
    specifiers.add(node.arguments[0].value);
  });
  return [...specifiers].sort(compareStrings);
}

function renderChunkJavascript(transformedJavascript) {
  return `(function(
  globalThis,
  __convexWasmOfficialChunkRequire,
  __convexWasmOfficialChunkBegin,
  __convexWasmOfficialChunkPublish,
  __convexWasmOfficialChunkReportThrown
) {
"use strict";
try {
  if (
    globalThis === null ||
    typeof globalThis !== "object" ||
    !Object.isExtensible(globalThis) ||
    Object.getPrototypeOf(globalThis) !== null
  ) {
    throw new Error("Convex Wasm official chunk global facade is invalid");
  }
  if (typeof __convexWasmOfficialChunkRequire !== "function") {
    throw new Error("Convex Wasm official chunk require is invalid");
  }
  if (typeof __convexWasmOfficialChunkBegin !== "function") {
    throw new Error("Convex Wasm official chunk begin is invalid");
  }
  if (typeof __convexWasmOfficialChunkPublish !== "function") {
    throw new Error("Convex Wasm official chunk publisher is invalid");
  }
  if (typeof __convexWasmOfficialChunkReportThrown !== "function") {
    throw new Error("Convex Wasm official chunk error reporter is invalid");
  }
  let __convexWasmOfficialChunkExports = {};
  const module = {};
  Object.defineProperty(module, "exports", {
    configurable: false,
    enumerable: true,
    get: function() {
      return __convexWasmOfficialChunkExports;
    },
    set: function(value) {
      __convexWasmOfficialChunkExports = value;
      __convexWasmOfficialChunkBegin(value);
    },
  });
  module.exports = __convexWasmOfficialChunkExports;
  const exports = module.exports;
  const require = __convexWasmOfficialChunkRequire;
${transformedJavascript}
  __convexWasmOfficialChunkPublish(module.exports);
} catch (__convexWasmOfficialChunkError) {
  if (typeof __convexWasmOfficialChunkReportThrown === "function") {
    __convexWasmOfficialChunkReportThrown(__convexWasmOfficialChunkError);
  }
  throw __convexWasmOfficialChunkError;
}
})(
  globalThis.__convexWasmApplicationGlobalThis,
  globalThis.__convexWasmOfficialChunkRequire,
  globalThis.__convexWasmOfficialChunkBegin,
  globalThis.__convexWasmOfficialChunkPublish,
  globalThis.__convexWasmOfficialChunkReportThrown
);
`;
}

function artifactModuleIdentity(module) {
  return Object.freeze({
    ...module.identity,
    sourceMap: Object.freeze({ ...module.identity.sourceMap }),
  });
}

function chunkUnitDependencies(transformInput, slotByPath, modulePath) {
  const dependencies = transformInput.dependencies
    .map(({ executableSpecifier, kind, path, specifier }) => ({
      executableSpecifier,
      kind,
      path,
      slot: slotByPath.get(path),
      specifier,
    }))
    .sort((left, right) => compareStrings(canonicalJson(left), canonicalJson(right)));
  if (dependencies.some(({ slot }) => slot === undefined)) {
    fail(`chunk ${modulePath} dependency has no numbered slot`);
  }
  return Object.freeze(dependencies.map((dependency) => Object.freeze(dependency)));
}

function chunkUnitIdentity({
  dependencies,
  javascriptIdentity,
  module,
  nativeSymbolLocator,
  slot,
}) {
  const identity = {
    dependencies,
    javascript: javascriptIdentity,
    kind: convexWasmOfficialOutputChunkUnitKind,
    module: artifactModuleIdentity(module),
    nativeSymbolLocator,
    slot,
    transform: convexWasmOfficialOutputChunkModuleTransform,
  };
  return Object.freeze({ ...identity, sha256: fingerprintJson(identity) });
}

async function transformedModuleBaseForInput({
  esbuild,
  esbuildVersion,
  module,
  record,
  retainInSession = true,
  transformInput,
}) {
  const transformKey =
    record === undefined
      ? undefined
      : fingerprintJson({
          esbuild: esbuildVersion,
          source: transformInput.sourceIdentity,
          sourcefile: transformInput.sourcefile,
          transformSha256: esbuildChunkModuleTransformSha256,
        });
  let transform = transformKey === undefined ? undefined : record.transforms.get(transformKey);
  if (transform === undefined) {
    transform = transformChunkModule({
      esbuild,
      esbuildVersion,
      module,
      persistentCache: record?.persistentCache,
      source: transformInput.source,
      sourceIdentity: transformInput.sourceIdentity,
      sourcefile: transformInput.sourcefile,
      transform: record?.transform ?? esbuild.transform,
    });
    if (transformKey !== undefined) {
      record.transforms.set(transformKey, transform);
      const clearTransform = () => {
        if (record.transforms.get(transformKey) === transform)
          record.transforms.delete(transformKey);
      };
      // Compact authority needs overlap-only single-flight. A settled transform carries the raw
      // source payload, so keeping it in the session would defeat source-free lazy materialization.
      void transform.then(retainInSession ? undefined : clearTransform, clearTransform);
    }
  }
  let transformedModuleBase = retainInSession
    ? record?.transformedModuleBasesByInput.get(transformInput)
    : undefined;
  if (transformedModuleBase === undefined) {
    if (record !== undefined) record.transformedModuleBaseCacheMisses += 1;
    transformedModuleBase = (async () => {
      const { cacheReference, code, persistentCacheMiss, requireSpecifiers } = await transform;
      const expectedRequireSpecifiers = transformInput.dependencies
        .map(({ executableSpecifier }) => executableSpecifier)
        .sort(compareStrings);
      if (canonicalJson(requireSpecifiers) !== canonicalJson(expectedRequireSpecifiers)) {
        fail(`chunk ${module.identity.path} transform changed its authenticated dependency tokens`);
      }
      const javascript = renderChunkJavascript(code);
      return Object.freeze({
        javascript,
        javascriptIdentity: Object.freeze({
          sha256: sha256(javascript),
          size: Buffer.byteLength(javascript),
        }),
        persistentCacheMiss,
        transformArtifact: cacheReference,
      });
    })();
    if (record !== undefined && retainInSession) {
      record.transformedModuleBasesByInput.set(transformInput, transformedModuleBase);
      void transformedModuleBase.catch(() => {
        if (record.transformedModuleBasesByInput.get(transformInput) === transformedModuleBase) {
          record.transformedModuleBasesByInput.delete(transformInput);
        }
      });
    }
  } else {
    record.transformedModuleBaseCacheHits += 1;
  }
  return await transformedModuleBase;
}

function chunkIdentityCacheIdentity({
  esbuildVersion,
  module,
  preparationAuthority,
  nativeSymbolLocatorsByPath,
  persistentCache,
}) {
  // Transformed JavaScript depends on preparation and stable dependency-native symbols, not on
  // dependency executable content or the cohort's numbered slots. Keep this record reusable
  // across cohorts; the caller derives the exact slot-bearing unit identity only after
  // authenticating the cached JavaScript identity.
  return {
    dependencies: preparationAuthority.preparation.dependencies.map((dependency) => {
      const nativeSymbolLocator = nativeSymbolLocatorsByPath.get(dependency.path);
      if (nativeSymbolLocator === undefined) {
        fail(`chunk ${module.identity.path} dependency lacks a stable native binding`);
      }
      return {
        kind: dependency.kind,
        nativeSymbolLocator,
        occurrence: dependency.occurrence,
      };
    }),
    esbuild: { version: esbuildVersion },
    kind: convexWasmOfficialOutputChunkIdentityCacheIdentityKind,
    preparation: preparationAuthority.reference,
    producerImplementation: persistentCache.transformImplementation,
    schemaVersion: 4,
    transform: convexWasmOfficialOutputChunkModuleTransform,
  };
}

function authenticateChunkIdentityRecord({ module, record }) {
  const value = requireExactKeys(
    record,
    new Set(["javascript", "kind", "schemaVersion", "transformArtifact"]),
    `chunk ${module.identity.path} identity cache record`
  );
  if (
    value.kind !== convexWasmOfficialOutputChunkIdentityCacheRecordKind ||
    value.schemaVersion !== 4
  ) {
    fail(`chunk ${module.identity.path} identity cache record is unsupported`);
  }
  const transformArtifact = authenticateArtifactReference(
    value.transformArtifact,
    convexWasmOfficialOutputChunkTransformCacheStage,
    `chunk ${module.identity.path} transform artifact reference`
  );
  const javascript = requireExactKeys(
    value.javascript,
    new Set(["sha256", "size"]),
    `chunk ${module.identity.path} compact JavaScript identity`
  );
  if (
    !Number.isSafeInteger(javascript.size) ||
    javascript.size <= 0 ||
    javascript.sha256 !==
      requireSha256(javascript.sha256, `chunk ${module.identity.path} compact JavaScript SHA-256`)
  ) {
    fail(`chunk ${module.identity.path} compact JavaScript identity is invalid`);
  }
  return Object.freeze({
    javascript: Object.freeze({ sha256: javascript.sha256, size: javascript.size }),
    transformArtifact,
  });
}

async function ensurePersistentChunkIdentity({
  dependencies,
  esbuild,
  esbuildVersion,
  module,
  onRawTransformCacheMiss,
  preparationAuthority,
  record,
  slot,
  nativeSymbolLocatorsByPath,
}) {
  const persistentCache = record.persistentCache;
  const identity = chunkIdentityCacheIdentity({
    esbuildVersion,
    module,
    nativeSymbolLocatorsByPath,
    persistentCache,
    preparationAuthority,
  });
  const identityKey = canonicalJson(identity);
  let admission = record.persistentIdentitiesByIdentity.get(identityKey);
  const ownsAdmission = admission === undefined;
  if (ownsAdmission) {
    // Stable bindings and preparation references are slot-free. Share their complete first-open
    // admission and lazy JavaScript loader, never a unit carrying another cohort's slots.
    admission = admitPersistentChunkIdentity({
      esbuild,
      esbuildVersion,
      identity,
      module,
      nativeSymbolLocatorsByPath,
      onRawTransformCacheMiss,
      preparationAuthority,
      record,
    });
    record.persistentIdentitiesByIdentity.set(identityKey, admission);
    void admission.catch(() => {
      if (record.persistentIdentitiesByIdentity.get(identityKey) === admission) {
        record.persistentIdentitiesByIdentity.delete(identityKey);
      }
    });
  }
  const admitted = await admission;
  const unit = Object.freeze({
    identity: chunkUnitIdentity({
      dependencies,
      javascriptIdentity: admitted.authenticatedRecord.javascript,
      module,
      nativeSymbolLocator: preparationAuthority.preparation.nativeSymbolLocator,
      slot,
    }),
    kind: convexWasmOfficialOutputChunkUnitKind,
  });
  compactChunkUnitMaterializations.set(unit, admitted.load);
  // Only the cohort that started the transform owns its speculative readiness. Session hits
  // must not report another raw miss or duplicate preactivation for the same admitted code.
  if (ownsAdmission && admitted.readinessMaterial !== undefined) {
    compactChunkUnitReadinessMaterial.set(unit, admitted.readinessMaterial);
  }
  return unit;
}

async function admitPersistentChunkIdentity({
  esbuild,
  esbuildVersion,
  identity,
  module,
  nativeSymbolLocatorsByPath,
  onRawTransformCacheMiss,
  preparationAuthority,
  record,
}) {
  const persistentCache = record.persistentCache;
  let transformInput;
  let builtBase;
  const cached = await ensureArtifactStage({
    build: async (workPath) => {
      transformInput = moduleTransformInputForSession({
        module,
        nativeSymbolLocatorsByPath,
        preparation: preparationAuthority.preparation,
        record,
        retainInSession: false,
      });
      builtBase = await transformedModuleBaseForInput({
        esbuild,
        esbuildVersion,
        module,
        record,
        retainInSession: false,
        transformInput,
      });
      if (builtBase.persistentCacheMiss) onRawTransformCacheMiss();
      if (builtBase.transformArtifact === undefined) {
        fail(`chunk ${module.identity.path} compact identity lacks a persistent transform`);
      }
      const source = `${canonicalJson({
        javascript: builtBase.javascriptIdentity,
        kind: convexWasmOfficialOutputChunkIdentityCacheRecordKind,
        schemaVersion: 4,
        transformArtifact: builtBase.transformArtifact,
      })}\n`;
      const outputPath = join(workPath, "identity.json");
      await fs.writeFile(outputPath, source, { flag: "wx", mode: 0o600 });
      return {
        metadata: { kind: convexWasmOfficialOutputChunkIdentityCacheRecordKind },
        outputPath,
        timing: null,
      };
    },
    cacheLayout: persistentCache.cacheLayout,
    cacheRoot: persistentCache.cacheRoot,
    extension: "json",
    identity,
    maxArtifactBytes: convexWasmOfficialOutputChunkIdentityCacheMaximumBytes,
    readCachedArtifactContents: true,
    readPublishedArtifactContents: true,
    stage: convexWasmOfficialOutputChunkIdentityCacheStage,
  });
  if (
    canonicalJson(cached.entry.metadata) !==
    canonicalJson({ kind: convexWasmOfficialOutputChunkIdentityCacheRecordKind })
  ) {
    fail(`chunk ${module.identity.path} identity cache authority changed`);
  }
  if (cached.report.cache === "hit") {
    record.persistentIdentityCacheHits += 1;
  } else {
    record.persistentIdentityCacheMisses += 1;
  }
  const authenticatedRecord = authenticateChunkIdentityRecord({
    module,
    record: parseCanonicalCacheRecord(
      cached.entry,
      `chunk ${module.identity.path} identity cache record`
    ),
  });
  if (
    builtBase !== undefined &&
    (builtBase.javascriptIdentity.sha256 !== authenticatedRecord.javascript.sha256 ||
      builtBase.javascriptIdentity.size !== authenticatedRecord.javascript.size ||
      !sameArtifactReference(builtBase.transformArtifact, authenticatedRecord.transformArtifact))
  ) {
    fail(`chunk ${module.identity.path} compact identity changed during publication`);
  }
  const readinessMaterial =
    cached.report.cache === "miss" && builtBase !== undefined
      ? Object.freeze({
          javascript: builtBase.javascript,
          persistentCacheMiss: builtBase.persistentCacheMiss,
        })
      : undefined;
  let materialization =
    readinessMaterial === undefined ? undefined : Promise.resolve(readinessMaterial.javascript);
  // The compact record, not the just-produced JavaScript, is the returned authority. Release the
  // construction payload. On an identity miss, the one-shot materialization promise now owns the
  // already-produced JavaScript so readiness and a later generated-C miss do not reopen it.
  builtBase = undefined;
  transformInput = undefined;
  let materializationRequested = false;
  const load = async () => {
    if (!materializationRequested) {
      materializationRequested = true;
      record.transformedJavascriptMaterializations += 1;
    }
    materialization ??= (async () => {
      try {
        transformInput ??= moduleTransformInputForSession({
          module,
          nativeSymbolLocatorsByPath,
          preparation: preparationAuthority.preparation,
          record,
          retainInSession: false,
        });
        const base = await transformedModuleBaseForInput({
          esbuild,
          esbuildVersion,
          module,
          record,
          retainInSession: false,
          transformInput,
        });
        if (
          base.transformArtifact === undefined ||
          !sameArtifactReference(base.transformArtifact, authenticatedRecord.transformArtifact) ||
          base.javascriptIdentity.sha256 !== authenticatedRecord.javascript.sha256 ||
          base.javascriptIdentity.size !== authenticatedRecord.javascript.size
        ) {
          fail(
            `chunk ${module.identity.path} transformed JavaScript changed from compact authority`
          );
        }
        return base.javascript;
      } finally {
        // Every cohort sharing this admission observes the same settled result or failure for the
        // session. Release the canonical source used only while reopening or rebuilding it.
        transformInput = undefined;
      }
    })();
    return await materialization;
  };
  return Object.freeze({ authenticatedRecord, load, readinessMaterial });
}

export async function materializeConvexWasmOfficialOutputCompactChunkUnitJavascript(unit) {
  const load = compactChunkUnitMaterializations.get(unit);
  if (load === undefined) {
    fail("compact chunk unit lacks exact materialization authority");
  }
  return await load();
}

export function isConvexWasmOfficialOutputCompactChunkUnit(unit) {
  return compactChunkUnitMaterializations.has(unit);
}

function normalizedUnitIdentity(unit, index) {
  const value = requireExactKeys(
    unit,
    new Set(["identity", "javascript", "kind"]),
    `chunk unit ${index}`
  );
  if (value.kind !== convexWasmOfficialOutputChunkUnitKind) {
    fail(`chunk unit ${index} kind is unsupported`);
  }
  const identity = requireExactKeys(
    value.identity,
    new Set([
      "dependencies",
      "javascript",
      "kind",
      "module",
      "nativeSymbolLocator",
      "slot",
      "transform",
      "sha256",
    ]),
    `chunk unit ${index} identity`
  );
  const { sha256: identitySha256, ...identityPayload } = identity;
  if (
    identity.kind !== convexWasmOfficialOutputChunkUnitKind ||
    identity.slot !== index ||
    identitySha256 !== fingerprintJson(identityPayload)
  ) {
    fail(`chunk unit ${index} identity is invalid`);
  }
  const module = requireExactKeys(
    identity.module,
    new Set([
      "environment",
      "moduleSha256",
      "path",
      "sourceMap",
      "sourceMembershipSha256",
      "sourceSha256",
      "sourceSize",
    ]),
    `chunk unit ${index} module identity`
  );
  if (
    module.environment !== "isolate" ||
    !SHA256_PATTERN.test(module.moduleSha256) ||
    !SHA256_PATTERN.test(module.sourceMembershipSha256) ||
    !SHA256_PATTERN.test(module.sourceSha256) ||
    !Number.isSafeInteger(module.sourceSize) ||
    module.sourceSize <= 0
  ) {
    fail(`chunk unit ${index} module identity is invalid`);
  }
  requireOutputModulePath(module.path, `chunk unit ${index} module path`);
  const sourceMap = requireExactKeys(
    module.sourceMap,
    new Set(["sha256", "size", "sourcesContentCount", "sourcesCount"]),
    `chunk unit ${index} module source map identity`
  );
  if (
    !SHA256_PATTERN.test(sourceMap.sha256) ||
    !Number.isSafeInteger(sourceMap.size) ||
    sourceMap.size <= 0 ||
    !Number.isSafeInteger(sourceMap.sourcesContentCount) ||
    sourceMap.sourcesContentCount < 0 ||
    !Number.isSafeInteger(sourceMap.sourcesCount) ||
    sourceMap.sourcesCount < 0
  ) {
    fail(`chunk unit ${index} module source map identity is invalid`);
  }
  const normalizedSourceMap = Object.freeze({ ...sourceMap });
  const normalizedModule = Object.freeze({
    environment: module.environment,
    moduleSha256: module.moduleSha256,
    path: module.path,
    sourceMap: normalizedSourceMap,
    sourceMembershipSha256: module.sourceMembershipSha256,
    sourceSha256: module.sourceSha256,
    sourceSize: module.sourceSize,
  });
  const nativeSymbolLocator = convexWasmOfficialOutputChunkNativeSymbolLocator(
    identity.nativeSymbolLocator
  );
  if (nativeSymbolLocator.sourceMembershipSha256 !== module.sourceMembershipSha256) {
    fail(`chunk unit ${index} executable native symbol locator is invalid`);
  }
  if (
    canonicalJson(identity.transform) !==
    canonicalJson(convexWasmOfficialOutputChunkModuleTransform)
  ) {
    fail(`chunk unit ${index} uses an unpinned module transform`);
  }
  const javascript = requireString(value.javascript, `chunk unit ${index} JavaScript`);
  const javascriptIdentity = requireExactKeys(
    identity.javascript,
    new Set(["sha256", "size"]),
    `chunk unit ${index} JavaScript identity`
  );
  if (
    javascriptIdentity.sha256 !== sha256(javascript) ||
    javascriptIdentity.size !== Buffer.byteLength(javascript)
  ) {
    fail(`chunk unit ${index} JavaScript bytes disagree with its identity`);
  }
  const dependencies = Object.freeze(
    requireArray(identity.dependencies, `chunk unit ${index} dependencies`).map(
      (dependency, dependencyIndex) => {
        const normalized = requireExactKeys(
          dependency,
          new Set(["executableSpecifier", "kind", "path", "slot", "specifier"]),
          `chunk unit ${index} dependency ${dependencyIndex}`
        );
        if (
          !supportedImportKinds.has(normalized.kind) ||
          !Number.isSafeInteger(normalized.slot) ||
          normalized.slot < 0 ||
          normalized.slot === index
        ) {
          fail(`chunk unit ${index} dependency ${dependencyIndex} is invalid`);
        }
        const specifier = requireString(
          normalized.specifier,
          `chunk unit ${index} dependency ${dependencyIndex} specifier`
        );
        const executableSpecifier = requireString(
          normalized.executableSpecifier,
          `chunk unit ${index} dependency ${dependencyIndex} executable specifier`
        );
        if (!isNormalizedDependencySpecifier(executableSpecifier)) {
          fail(`chunk unit ${index} dependency ${dependencyIndex} executable specifier is invalid`);
        }
        const executableIdentity =
          parseConvexWasmOfficialOutputExecutableDependencySpecifier(executableSpecifier);
        if (executableIdentity.kind !== normalized.kind) {
          fail(
            `chunk unit ${index} dependency ${dependencyIndex} executable specifier kind is invalid`
          );
        }
        const path = requireOutputModulePath(
          normalized.path,
          `chunk unit ${index} dependency ${dependencyIndex} path`
        );
        if (resolveLiteralSpecifier(module.path, specifier) !== path) {
          fail(
            `chunk unit ${index} dependency ${dependencyIndex} does not resolve to its slot path`
          );
        }
        return Object.freeze({
          executableSpecifier,
          kind: normalized.kind,
          path,
          slot: normalized.slot,
          specifier,
        });
      }
    )
  );
  if (
    dependencies.some(
      (dependency, dependencyIndex) =>
        dependencyIndex > 0 &&
        canonicalJson(dependencies[dependencyIndex - 1]) >= canonicalJson(dependency)
    )
  ) {
    fail(`chunk unit ${index} dependencies are not canonical`);
  }
  if (
    new Set(dependencies.map(({ executableSpecifier }) => executableSpecifier)).size !==
    dependencies.length
  ) {
    fail(`chunk unit ${index} repeats an executable dependency specifier`);
  }
  const executableOccurrences = dependencies
    .map(({ executableSpecifier }) =>
      parseConvexWasmOfficialOutputExecutableDependencySpecifier(executableSpecifier)
    )
    .map(({ occurrence }) => occurrence)
    .sort((left, right) => left - right);
  if (executableOccurrences.some((occurrence, occurrenceIndex) => occurrence !== occurrenceIndex)) {
    fail(`chunk unit ${index} executable dependency occurrences are invalid`);
  }
  const normalizedIdentity = Object.freeze({
    dependencies,
    javascript: Object.freeze({ ...javascriptIdentity }),
    kind: identity.kind,
    module: normalizedModule,
    nativeSymbolLocator,
    sha256: identitySha256,
    slot: identity.slot,
    transform: convexWasmOfficialOutputChunkModuleTransform,
  });
  return Object.freeze({ identity: normalizedIdentity, javascript, kind: value.kind });
}

export function authenticateConvexWasmOfficialOutputChunkUnits(chunkUnits) {
  if (authenticatedChunkUnits.has(chunkUnits)) return chunkUnits;
  const artifact = requireExactKeys(
    chunkUnits,
    new Set(["entries", "identity", "kind", "units"]),
    "official-output chunk units"
  );
  if (artifact.kind !== convexWasmOfficialOutputChunkUnitsKind) {
    fail("official-output chunk units kind is unsupported");
  }
  const units = requireArray(artifact.units, "official-output chunk units").map(
    normalizedUnitIdentity
  );
  if (units.length === 0) fail("official-output chunk units are empty");
  const paths = new Set();
  const nativeSymbolLocators = new Set();
  for (const unit of units) {
    if (paths.has(unit.identity.module.path)) {
      fail("official-output chunk units repeat an output path");
    }
    paths.add(unit.identity.module.path);
    const nativeSymbolLocator = canonicalJson(unit.identity.nativeSymbolLocator);
    if (nativeSymbolLocators.has(nativeSymbolLocator)) {
      fail("official-output chunk units repeat native symbol locator authority");
    }
    nativeSymbolLocators.add(nativeSymbolLocator);
    for (const dependency of unit.identity.dependencies) {
      const targetUnit = units[dependency.slot];
      if (targetUnit === undefined || targetUnit.identity.module.path !== dependency.path) {
        fail("official-output chunk unit dependency slot does not match its chunk path");
      }
      const executableIdentity = parseConvexWasmOfficialOutputExecutableDependencySpecifier(
        dependency.executableSpecifier
      );
      const targetNativeSymbolIdentitySha256 = convexWasmOfficialOutputNativeSymbolIdentitySha256({
        entryPublication: false,
        nativeSymbolLocator: targetUnit.identity.nativeSymbolLocator,
      });
      if (executableIdentity.nativeSymbolIdentitySha256 !== targetNativeSymbolIdentitySha256) {
        fail("official-output chunk unit executable dependency does not match its chunk slot");
      }
    }
  }
  const entries = requireArray(artifact.entries, "official-output chunk entries").map(
    (entry, index) => {
      const value = requireExactKeys(
        entry,
        new Set([
          "dependencyGraphSha256",
          "entryModulePath",
          "entryPath",
          "entrySlot",
          "modulePath",
          "routes",
        ]),
        `official-output chunk entry ${index}`
      );
      if (
        !Number.isSafeInteger(value.entrySlot) ||
        value.entrySlot < 0 ||
        value.entrySlot >= units.length
      ) {
        fail(`official-output chunk entry ${index} slot is invalid`);
      }
      const routes = Object.freeze(
        requireArray(value.routes, `official-output chunk entry ${index} routes`).map(
          (route, routeIndex) => {
            const normalized = requireExactKeys(
              route,
              new Set(["exportName", "udfKind", "visibility"]),
              `official-output chunk entry ${index} route ${routeIndex}`
            );
            if (
              (normalized.udfKind !== "query" && normalized.udfKind !== "mutation") ||
              (normalized.visibility !== "internal" && normalized.visibility !== "public")
            ) {
              fail(`official-output chunk entry ${index} route ${routeIndex} is invalid`);
            }
            return Object.freeze({
              exportName: requireString(
                normalized.exportName,
                `official-output chunk entry ${index} route ${routeIndex} export name`
              ),
              udfKind: normalized.udfKind,
              visibility: normalized.visibility,
            });
          }
        )
      );
      return Object.freeze({
        dependencyGraphSha256: requireSha256(
          value.dependencyGraphSha256,
          `official-output chunk entry ${index} dependency graph SHA-256`
        ),
        entryModulePath: requireOutputModulePath(
          value.entryModulePath,
          `official-output chunk entry ${index} module path`
        ),
        entryPath: requireString(value.entryPath, `official-output chunk entry ${index} path`),
        entrySlot: value.entrySlot,
        modulePath: requireString(
          value.modulePath,
          `official-output chunk entry ${index} source path`
        ),
        routes,
      });
    }
  );
  if (
    entries.length === 0 ||
    entries.some(
      (entry, index) =>
        entry.entryModulePath !== units[entry.entrySlot].identity.module.path ||
        (index > 0 && entries[index - 1].entryPath >= entry.entryPath)
    )
  ) {
    fail("official-output chunk entries are not canonical");
  }
  const canonicalEntryPathBySlot = new Map();
  for (const entry of entries) {
    if (canonicalEntryPathBySlot.has(entry.entrySlot)) {
      fail("official-output chunk entries reuse an entry module");
    }
    canonicalEntryPathBySlot.set(entry.entrySlot, entry.entryPath);
  }
  for (const [slot, unit] of units.entries()) {
    if (
      unit.identity.nativeSymbolLocator.canonicalEntryPath !==
      (canonicalEntryPathBySlot.get(slot) ?? null)
    ) {
      fail(`official-output chunk unit ${slot} native symbol locator changed its module identity`);
    }
  }
  const identity = requireExactKeys(
    artifact.identity,
    new Set([
      "entries",
      "esbuild",
      "initialization",
      "kind",
      "sourceEnvelopeSha256",
      "units",
      "sha256",
    ]),
    "official-output chunk units identity"
  );
  const { sha256: identitySha256, ...identityPayload } = identity;
  const esbuildIdentity = requireExactKeys(
    identity.esbuild,
    new Set(["version"]),
    "official-output chunk units esbuild identity"
  );
  const esbuildVersion = requireString(
    esbuildIdentity.version,
    "official-output chunk units esbuild version"
  );
  const expectedSourceEnvelopeSha256 = cohortSourceEnvelopeSha256({
    entries,
    esbuildVersion,
    moduleIdentities: units.map(({ identity: unitIdentity }) => unitIdentity.module),
  });
  if (
    identity.kind !== convexWasmOfficialOutputChunkUnitsKind ||
    canonicalJson(identity.entries) !== canonicalJson(entries) ||
    canonicalJson(identity.units) !== canonicalJson(units.map(({ identity: unit }) => unit)) ||
    canonicalJson(identity.initialization) !==
      canonicalJson({
        dynamicImport: "literal-require-after-promise-microtask",
        kind: "closed-numbered-namespace-slots-v1",
        publication: "selected-entry-namespaces-after-selected-closure-initialization",
      }) ||
    identity.sourceEnvelopeSha256 !== expectedSourceEnvelopeSha256 ||
    identitySha256 !== fingerprintJson(identityPayload)
  ) {
    fail("official-output chunk units identity is invalid");
  }
  const normalizedIdentity = Object.freeze({
    entries: Object.freeze(entries),
    esbuild: Object.freeze({ version: esbuildVersion }),
    initialization: Object.freeze({
      dynamicImport: "literal-require-after-promise-microtask",
      kind: "closed-numbered-namespace-slots-v1",
      publication: "selected-entry-namespaces-after-selected-closure-initialization",
    }),
    kind: identity.kind,
    sha256: identitySha256,
    sourceEnvelopeSha256: identity.sourceEnvelopeSha256,
    units: Object.freeze(units.map(({ identity: unitIdentity }) => unitIdentity)),
  });
  const authenticated = Object.freeze({
    entries: normalizedIdentity.entries,
    identity: normalizedIdentity,
    kind: artifact.kind,
    units: Object.freeze(units),
  });
  authenticatedChunkUnits.add(authenticated);
  return authenticated;
}

export async function buildConvexWasmOfficialOutputChunkUnits({
  compactUnitAuthority = false,
  esbuild,
  physicalUnitReadiness,
  selections,
  transformSession,
}) {
  requireEsbuild(esbuild);
  if (typeof compactUnitAuthority !== "boolean") {
    fail("compact unit authority flag must be a boolean");
  }
  const readinessObserver = claimPhysicalUnitReadinessObserver(physicalUnitReadiness);
  const transformSessionRecord = chunkTransformSessionRecord(transformSession, esbuild);
  if (compactUnitAuthority && transformSessionRecord?.persistentCache === undefined) {
    fail("compact unit authority requires a persistent transform session");
  }
  // Cache provenance only prioritizes speculative readiness. It never enters authenticated units.
  let firstRawTransformCacheMissSlot;
  const claimFirstRawTransformCacheMiss = (slot) => {
    // Reserve priority when the raw transform settles. Compact identity-record publication can
    // complete in a different order and must not let a later transform steal this slot.
    firstRawTransformCacheMissSlot ??= slot;
  };
  const { esbuildVersion, merged, slotByPath, transformedPromises, transformedSettlement } =
    await scheduleChunkTransformPreparation(transformSessionRecord, () => {
      const preparedMerged = mergeSelections(selections);
      const preparedEsbuildVersion = transformSessionRecord?.esbuildVersion ?? esbuild.version;
      if (preparedEsbuildVersion !== preparedMerged.esbuildVersion) {
        fail("module transform esbuild version disagrees with the authenticated official output");
      }
      const modulesByPath = new Map(
        preparedMerged.modules.map((module) => [module.identity.path, module])
      );
      const preparedSlotByPath = new Map(
        preparedMerged.modules.map((module, slot) => [module.identity.path, slot])
      );
      const canonicalEntryPathByModulePath = new Map();
      for (const entry of preparedMerged.entries) {
        const existing = canonicalEntryPathByModulePath.get(entry.entryModulePath);
        if (existing !== undefined && existing !== entry.entryPath) {
          fail(
            `official-output module ${entry.entryModulePath} belongs to multiple source entries`
          );
        }
        canonicalEntryPathByModulePath.set(entry.entryModulePath, entry.entryPath);
      }
      const directImportsByPath = new Map();
      for (const imported of preparedMerged.imports) {
        const imports = directImportsByPath.get(imported.importerPath) ?? [];
        imports.push(imported);
        directImportsByPath.set(imported.importerPath, imports);
      }
      const bindingPathsByPath = admittedSourceChunkBindingPaths(
        preparedMerged.sourceAuthentication,
        transformSessionRecord
      );
      const nativeSymbolLocatorsByPath = new Map(
        preparedMerged.modules.map((module) => [
          module.identity.path,
          convexWasmOfficialOutputChunkNativeSymbolLocator({
            bindingPath: bindingPathsByPath.get(module.identity.path),
            canonicalEntryPath: canonicalEntryPathByModulePath.get(module.identity.path) ?? null,
            sourceMembershipSha256: module.identity.sourceMembershipSha256,
          }),
        ])
      );
      const createPreparationTopology = (preparationAuthoritiesByPath) => {
        if (
          [...preparationAuthoritiesByPath].some(
            ([path, authority]) =>
              canonicalJson(authority.preparation.nativeSymbolLocator) !==
              canonicalJson(nativeSymbolLocatorsByPath.get(path))
          )
        ) {
          fail("authenticated chunk preparation changed its stable native binding");
        }
        return { nativeSymbolLocatorsByPath, preparationAuthoritiesByPath };
      };
      const eagerPreparationTopology = compactUnitAuthority
        ? undefined
        : createPreparationTopology(
            new Map(
              preparedMerged.modules.map((module) => [
                module.identity.path,
                {
                  preparation: moduleSourcePreparationForSession({
                    bindingPath: bindingPathsByPath.get(module.identity.path),
                    canonicalEntryPath:
                      canonicalEntryPathByModulePath.get(module.identity.path) ?? null,
                    directImports: directImportsByPath.get(module.identity.path) ?? [],
                    literals: moduleDependencyLiteralsForSession(transformSessionRecord, module),
                    module,
                    modulesByPath,
                    record: transformSessionRecord,
                  }),
                },
              ])
            )
          );
      const preparationPromisesByPath = !compactUnitAuthority
        ? undefined
        : new Map(
            preparedMerged.modules.map((module) => [
              module.identity.path,
              ensurePersistentChunkPreparation({
                bindingPath: bindingPathsByPath.get(module.identity.path),
                canonicalEntryPath:
                  canonicalEntryPathByModulePath.get(module.identity.path) ?? null,
                directImports: directImportsByPath.get(module.identity.path) ?? [],
                module,
                modulesByPath,
                nativeSymbolLocatorsByPath,
                record: transformSessionRecord,
              }),
            ])
          );
      const preparationTopologyPromise = !compactUnitAuthority
        ? undefined
        : settleChunkUnitWork(
            [...preparationPromisesByPath].map(async ([path, preparation]) => [
              path,
              await preparation,
            ])
          ).then((entries) => createPreparationTopology(new Map(entries)));
      const rawTransformedPromises = preparedMerged.modules.map(async (module, slot) => {
        let preparationAuthoritiesByPath;
        if (compactUnitAuthority) {
          const ownPreparation = await preparationPromisesByPath.get(module.identity.path);
          const paths = new Set([
            module.identity.path,
            ...ownPreparation.preparation.dependencies.map(({ path }) => path),
          ]);
          preparationAuthoritiesByPath = new Map(
            await settleChunkUnitWork(
              [...paths].map(async (path) => [path, await preparationPromisesByPath.get(path)])
            )
          );
        } else {
          ({ preparationAuthoritiesByPath } = eagerPreparationTopology);
        }
        const preparationAuthority = preparationAuthoritiesByPath.get(module.identity.path);
        const executableDependencies = moduleExecutableDependencies(
          preparationAuthority.preparation,
          nativeSymbolLocatorsByPath,
          module
        );
        const dependencies = chunkUnitDependencies(
          { dependencies: executableDependencies },
          preparedSlotByPath,
          module.identity.path
        );
        let transformedUnit;
        if (compactUnitAuthority) {
          transformedUnit = await ensurePersistentChunkIdentity({
            dependencies,
            esbuild,
            esbuildVersion: preparedEsbuildVersion,
            module,
            onRawTransformCacheMiss() {
              claimFirstRawTransformCacheMiss(slot);
            },
            preparationAuthority,
            record: transformSessionRecord,
            slot,
            nativeSymbolLocatorsByPath,
          });
        } else {
          const transformInput = moduleTransformInputForSession({
            module,
            nativeSymbolLocatorsByPath,
            preparation: preparationAuthority.preparation,
            record: transformSessionRecord,
          });
          const transformed = await transformedModuleBaseForInput({
            esbuild,
            esbuildVersion: preparedEsbuildVersion,
            module,
            record: transformSessionRecord,
            transformInput,
          });
          if (transformed.persistentCacheMiss) claimFirstRawTransformCacheMiss(slot);
          transformedUnit = Object.freeze({
            identity: chunkUnitIdentity({
              dependencies,
              javascriptIdentity: transformed.javascriptIdentity,
              module,
              nativeSymbolLocator: preparationAuthority.preparation.nativeSymbolLocator,
              slot,
            }),
            javascript: transformed.javascript,
            kind: convexWasmOfficialOutputChunkUnitKind,
          });
          compactChunkUnitReadinessMaterial.set(transformedUnit, {
            javascript: transformed.javascript,
            persistentCacheMiss: transformed.persistentCacheMiss,
          });
        }
        if (readinessObserver === undefined) {
          compactChunkUnitReadinessMaterial.delete(transformedUnit);
        }
        return transformedUnit;
      });
      const rawTransformedSettlement = settleChunkUnitWork(rawTransformedPromises);
      // A unit needs only its direct preparation dependencies to transform. The complete
      // topology still gates outward readiness, and preparation failures retain precedence
      // over transform failures after all newly overlapping work has drained.
      const transformedSettlement = compactUnitAuthority
        ? settleChunkUnitWork([preparationTopologyPromise, rawTransformedSettlement]).then(
            ([, transformed]) => transformed
          )
        : rawTransformedSettlement;
      const preparedTransformedPromises = !compactUnitAuthority
        ? rawTransformedPromises
        : rawTransformedPromises.map(async (transformed) => {
            const [, unit] = await Promise.all([preparationTopologyPromise, transformed]);
            return unit;
          });
      for (const transformed of preparedTransformedPromises) {
        void transformed.catch(() => undefined);
      }
      // A transform can reject before the scheduled handoff resumes. Observe the aggregate
      // immediately; the authoritative await below drains every unit and preserves input-order
      // failure precedence even when no readiness observer owns the sibling promises.
      void transformedSettlement.catch(() => undefined);
      return {
        esbuildVersion: preparedEsbuildVersion,
        merged: preparedMerged,
        slotByPath: preparedSlotByPath,
        transformedPromises: preparedTransformedPromises,
        transformedSettlement,
      };
    });
  const reservesRawTransformCacheMiss =
    readinessObserver !== undefined && transformSessionRecord?.persistentCache !== undefined;
  const ordinaryLimit =
    readinessObserver === undefined
      ? 0
      : readinessObserver.limit - (reservesRawTransformCacheMiss ? 1 : 0);
  let ordinaryCount = 0;
  let deferredOrdinaryPhysicalUnit;
  const deferredCompactTransformHitPhysicalUnits = [];
  const readinessCallbacks = [];
  const startReadinessCallback = (physicalUnit) => {
    const callback = Promise.resolve().then(() => readinessObserver.onReady(physicalUnit));
    readinessCallbacks.push(callback);
    void callback.catch(() => undefined);
  };
  const readinessTasks =
    readinessObserver === undefined
      ? []
      : transformedPromises.map(async (transformedPromise, slot) => {
          const unit = await transformedPromise;
          const readinessMaterial = compactChunkUnitReadinessMaterial.get(unit);
          try {
            // An exact compact-record hit has no transformed source in memory. Do not turn
            // speculative preactivation back into eager hydration ahead of receipt admission.
            if (readinessMaterial?.javascript === undefined) return;
            const dependencySlots = unit.identity.dependencies.map(
              ({ slot: dependencySlot }) => dependencySlot
            );
            const dependencyUnits = await Promise.all(
              dependencySlots.map((dependencySlot) => transformedPromises[dependencySlot])
            );
            let deferOrdinary = false;
            let deferCompactTransformHit = false;
            if (slot !== firstRawTransformCacheMissSlot) {
              if (compactUnitAuthority && !readinessMaterial.persistentCacheMiss) {
                deferCompactTransformHit = true;
              } else if (ordinaryCount < ordinaryLimit) {
                ordinaryCount += 1;
              } else if (
                reservesRawTransformCacheMiss &&
                firstRawTransformCacheMissSlot === undefined &&
                deferredOrdinaryPhysicalUnit === undefined
              ) {
                deferOrdinary = true;
              } else {
                return;
              }
            }
            const intrinsicIdentitySha256 = (candidate) =>
              fingerprintJson({
                domain: "convex-wasm-official-output-chunk-intrinsic-code-v3",
                javascript: candidate.identity.javascript,
                kind: candidate.kind,
                nativeSymbolLocator: candidate.identity.nativeSymbolLocator,
                transform: candidate.identity.transform,
              });
            const dependencyPaths = new Set(
              dependencyUnits.map((dependency) => dependency.identity.module.path)
            );
            if (unit.identity.dependencies.some(({ path }) => !dependencyPaths.has(path))) {
              fail(`chunk ${unit.identity.module.path} dependency is absent`);
            }
            const reusableCodeIdentitySha256 = fingerprintJson({
              dependencies: unit.identity.dependencies
                .map(({ executableSpecifier, kind }) => ({ executableSpecifier, kind }))
                .sort((left, right) => compareStrings(canonicalJson(left), canonicalJson(right))),
              domain: "convex-wasm-official-output-chunk-reusable-code-v3",
              intrinsicIdentitySha256: intrinsicIdentitySha256(unit),
            });
            const nativeSymbolIdentitySha256 = convexWasmOfficialOutputNativeSymbolIdentitySha256({
              entryPublication: false,
              nativeSymbolLocator: unit.identity.nativeSymbolLocator,
            });
            const dependencies = Object.freeze(
              unit.identity.dependencies.map((dependency) => Object.freeze({ ...dependency }))
            );
            const physicalUnit = Object.freeze({
              applicationUnitSlot: slot,
              chunkSlot: slot,
              dependencies,
              entryPublication: false,
              entrySymbol: `sh_export_convex_wasm_official_chunk_${nativeSymbolIdentitySha256}`,
              exportedUnitName: `convex_wasm_official_chunk_${nativeSymbolIdentitySha256}`,
              identitySha256: unit.identity.sha256,
              javascript: Object.freeze(unit.identity.javascript),
              javascriptSource: readinessMaterial.javascript,
              kind: unit.kind,
              module: unit.identity.module,
              nativeSymbolIdentitySha256,
              nativeSymbolLocator: unit.identity.nativeSymbolLocator,
              publicationHandoffSlot: -1,
              reusableCodeIdentitySha256,
              transform: unit.identity.transform,
            });
            if (deferCompactTransformHit) {
              deferredCompactTransformHitPhysicalUnits.push({ physicalUnit, slot });
              return;
            }
            if (deferOrdinary) {
              deferredOrdinaryPhysicalUnit = physicalUnit;
              return;
            }
            startReadinessCallback(physicalUnit);
          } finally {
            // Readiness or the deferred physical unit now owns the source reference. The compact
            // unit's one-shot materialization promise independently owns the authoritative bytes.
            compactChunkUnitReadinessMaterial.delete(unit);
          }
        });
  // A readiness task mirrors its unit transform rejection. Observe the complete task set now so
  // an early failed unit cannot become unhandled while the transform aggregate drains a sibling.
  const readinessSettlement = Promise.allSettled(readinessTasks);
  let transformed;
  try {
    transformed = await transformedSettlement;
  } catch (error) {
    // A sibling transform can fail after an earlier unit started speculative readiness. Drain all
    // callbacks before preserving that authoritative transform failure so no late preactivation
    // races cohort cleanup or material-session finalization.
    await readinessSettlement;
    await Promise.allSettled(readinessCallbacks);
    throw error;
  }
  if (readinessTasks.length > 0) {
    // Finish selection before admitting compact transform-hit fallbacks or deciding whether the
    // reserved slot has a miss. Callback settlement is intentionally separate so deferred work can
    // start as soon as every authoritative transform has succeeded.
    await readinessSettlement;
  }
  if (deferredCompactTransformHitPhysicalUnits.length > 0) {
    deferredCompactTransformHitPhysicalUnits.sort((left, right) => left.slot - right.slot);
    for (const { physicalUnit } of deferredCompactTransformHitPhysicalUnits) {
      if (readinessCallbacks.length >= readinessObserver.limit) break;
      startReadinessCallback(physicalUnit);
    }
  } else if (
    reservesRawTransformCacheMiss &&
    firstRawTransformCacheMissSlot === undefined &&
    deferredOrdinaryPhysicalUnit !== undefined
  ) {
    startReadinessCallback(deferredOrdinaryPhysicalUnit);
  }
  if (readinessCallbacks.length > 0) {
    // Readiness is speculative and cannot replace the authoritative transform result. Drain every
    // callback here, but leave its failure for the later ordinary compiler path to retry.
    await Promise.allSettled(readinessCallbacks);
  }
  const entries = merged.entries.map((entry) => ({
    dependencyGraphSha256: entry.dependencyGraphSha256,
    entryModulePath: entry.entryModulePath,
    entryPath: entry.entryPath,
    entrySlot: slotByPath.get(entry.entryModulePath),
    modulePath: entry.modulePath,
    routes: entry.routes,
  }));
  const identity = {
    entries,
    esbuild: { version: esbuildVersion },
    initialization: {
      dynamicImport: "literal-require-after-promise-microtask",
      kind: "closed-numbered-namespace-slots-v1",
      publication: "selected-entry-namespaces-after-selected-closure-initialization",
    },
    kind: convexWasmOfficialOutputChunkUnitsKind,
    // The full source envelope admits the build. This persisted projection
    // binds the exact cohort only, so an unrelated cohort does not invalidate
    // these package and native-stage cache identities.
    sourceEnvelopeSha256: cohortSourceEnvelopeSha256({
      entries,
      esbuildVersion: merged.esbuildVersion,
      moduleIdentities: merged.modules.map(({ identity: moduleIdentity }) => moduleIdentity),
    }),
    units: transformed.map(({ identity: unit }) => unit),
  };
  if (compactUnitAuthority) {
    const compactEntries = Object.freeze(
      entries.map((entry) =>
        Object.freeze({
          ...entry,
          routes: Object.freeze(entry.routes.map((route) => Object.freeze({ ...route }))),
        })
      )
    );
    const compactIdentity = Object.freeze({
      ...identity,
      entries: compactEntries,
      esbuild: Object.freeze({ ...identity.esbuild }),
      initialization: Object.freeze({ ...identity.initialization }),
      sha256: fingerprintJson(identity),
      units: Object.freeze(identity.units),
    });
    const authenticated = Object.freeze({
      entries: compactEntries,
      identity: compactIdentity,
      kind: convexWasmOfficialOutputChunkUnitsKind,
      units: Object.freeze(transformed),
    });
    authenticatedChunkUnits.add(authenticated);
    compactAuthenticatedChunkUnits.add(authenticated);
    return authenticated;
  }
  return authenticateConvexWasmOfficialOutputChunkUnits({
    entries,
    identity: { ...identity, sha256: fingerprintJson(identity) },
    kind: convexWasmOfficialOutputChunkUnitsKind,
    units: transformed,
  });
}

export function createConvexWasmOfficialOutputChunkUnitInitializer({
  chunkUnits,
  destroyStore,
  executeChunk,
}) {
  const artifact = authenticateConvexWasmOfficialOutputChunkUnits(chunkUnits);
  if (compactAuthenticatedChunkUnits.has(artifact)) {
    fail("compact chunk units must materialize JavaScript before runtime initialization");
  }
  if (typeof destroyStore !== "function" || typeof executeChunk !== "function") {
    fail("chunk initialization requires executeChunk and destroyStore callbacks");
  }
  const states = artifact.units.map(() => ({
    namespace: undefined,
    published: false,
    status: "uninitialized",
  }));
  let destroyed = false;
  const destroy = (error) => {
    if (!destroyed) {
      destroyed = true;
      for (const state of states) {
        state.namespace = undefined;
        state.published = false;
        state.status = "destroyed";
      }
      destroyStore(error);
    }
  };
  const requireNamespace = (requestingSlot, specifier) => {
    if (destroyed) fail("chunk require attempted after Store destruction");
    const dependency = artifact.units[requestingSlot].identity.dependencies.find(
      (candidate) => candidate.executableSpecifier === specifier
    );
    if (dependency === undefined) {
      fail(
        `chunk slot ${requestingSlot} requested undeclared dependency ${JSON.stringify(specifier)}`
      );
    }
    return initializeSlot(dependency.slot);
  };
  const initializeSlot = (slot) => {
    if (destroyed) fail("chunk initialization attempted after Store destruction");
    const state = states[slot];
    if (state.status === "initialized") return state.namespace;
    if (state.status === "initializing") {
      if (state.namespace === undefined) {
        fail(`chunk slot ${slot} entered a cycle before it registered CommonJS exports`);
      }
      return state.namespace;
    }
    if (state.status !== "uninitialized") {
      fail(`chunk slot ${slot} has invalid initialization state ${state.status}`);
    }
    state.status = "initializing";
    try {
      const result = executeChunk({
        begin(namespace) {
          if (
            state.status !== "initializing" ||
            namespace === null ||
            (typeof namespace !== "object" && typeof namespace !== "function")
          ) {
            fail(`chunk slot ${slot} registered invalid CommonJS exports`);
          }
          state.namespace = namespace;
        },
        javascript: artifact.units[slot].javascript,
        publish(namespace) {
          if (
            state.status !== "initializing" ||
            state.namespace !== namespace ||
            state.published ||
            namespace === null ||
            (typeof namespace !== "object" && typeof namespace !== "function")
          ) {
            fail(`chunk slot ${slot} published an invalid namespace`);
          }
          state.published = true;
        },
        reportThrown() {},
        require(specifier) {
          return requireNamespace(slot, specifier);
        },
        slot,
        unit: artifact.units[slot],
      });
      if (result !== undefined && typeof result?.then === "function") {
        fail(`chunk slot ${slot} factory must initialize synchronously`);
      }
      if (!state.published || state.namespace === undefined) {
        fail(`chunk slot ${slot} returned without publishing its namespace`);
      }
      state.status = "initialized";
      return state.namespace;
    } catch (error) {
      destroy(error);
      throw error;
    }
  };
  return Object.freeze({
    initializeEntrySlot(entrySlot) {
      if (!Number.isSafeInteger(entrySlot) || entrySlot < 0 || entrySlot >= artifact.units.length) {
        fail("chunk entry initialization slot is invalid");
      }
      const entry = artifact.entries.find((candidate) => candidate.entrySlot === entrySlot);
      if (entry === undefined) {
        fail("chunk entry initialization slot is not authenticated");
      }
      try {
        const namespace = initializeSlot(entry.entrySlot);
        if (destroyed) fail("chunk initialization destroyed its Store before entry publication");
        return Object.freeze({ ...entry, namespace });
      } catch (error) {
        destroy(error);
        throw error;
      }
    },
  });
}

export function initializeConvexWasmOfficialOutputChunkUnits({
  chunkUnits,
  destroyStore,
  executeChunk,
}) {
  const artifact = authenticateConvexWasmOfficialOutputChunkUnits(chunkUnits);
  const initializer = createConvexWasmOfficialOutputChunkUnitInitializer({
    chunkUnits: artifact,
    destroyStore,
    executeChunk,
  });
  return Object.freeze(
    artifact.entries.map(({ entrySlot }) => initializer.initializeEntrySlot(entrySlot))
  );
}

export const convexWasmOfficialOutputChunkUnitTestHooks = Object.freeze({
  compactAuthorityReport(session) {
    const record = chunkTransformSessionRecords.get(session);
    if (
      record === undefined ||
      session?.kind !== convexWasmOfficialOutputChunkTransformSessionKind
    ) {
      fail("compact authority report requires a live transform session");
    }
    return Object.freeze({
      persistentIdentityCacheHits: record.persistentIdentityCacheHits,
      persistentIdentityCacheMisses: record.persistentIdentityCacheMisses,
      persistentPreparationCacheHits: record.persistentPreparationCacheHits,
      persistentPreparationCacheMisses: record.persistentPreparationCacheMisses,
      transformedJavascriptMaterializations: record.transformedJavascriptMaterializations,
    });
  },
  transformSessionReport(session) {
    const record = chunkTransformSessionRecords.get(session);
    if (
      record === undefined ||
      session?.kind !== convexWasmOfficialOutputChunkTransformSessionKind
    ) {
      fail("transform session report requires a live transform session");
    }
    return Object.freeze({
      dependencyAnalysisCacheHits: record.dependencyAnalysisCacheHits,
      dependencyAnalysisCacheMisses: record.dependencyAnalysisCacheMisses,
      moduleSourcePreparationCacheHits: record.moduleSourcePreparationCacheHits,
      moduleSourcePreparationCacheMisses: record.moduleSourcePreparationCacheMisses,
      transformInputCacheHits: record.transformInputCacheHits,
      transformInputCacheMisses: record.transformInputCacheMisses,
      transformedModuleBaseCacheHits: record.transformedModuleBaseCacheHits,
      transformedModuleBaseCacheMisses: record.transformedModuleBaseCacheMisses,
    });
  },
});
