import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join } from "node:path";

import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  fail,
  fingerprintJson,
  normalizeJson,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import {
  decodeUtf8,
  readPrivateRegularFile,
  requirePrivateDirectory,
} from "./convex-wasm-artifact-material.mjs";
import {
  convexWasmOfficialOutputChunkNativeSymbolLocator,
  convexWasmOfficialOutputChunkNativeSymbolAbi,
  convexWasmOfficialOutputChunkNativeSymbolLocatorKind,
} from "./convex-wasm-native-symbol-identity.mjs";
import { parseConvexWasmOfficialOutputExecutableDependencySpecifier } from "./convex-wasm-official-output-chunk-contract.mjs";

const COMPILER_DESCRIPTOR_CACHE_PROJECTION_KIND =
  "convex-wasm-official-output-module-graph-compiler-cache-descriptor-v2";
const COMPILER_OUTPUT_CACHE_IDENTITY_KIND =
  "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v8";
const COMPILER_OUTPUT_CACHE_IDENTITY_FIELDS = new Set([
  "cohortInputsSha256",
  "descriptorIdentitySha256",
  "engineCompatibilitySha256",
  "kind",
  "materialSessionSha256",
  "producerIdentitySha256",
  "topologyWitnessMaterialIdentitySha256",
]);
const COMPILER_TOPOLOGY_WITNESS_IDENTITY_KIND =
  "convex-wasm-official-output-module-graph-compiler-topology-witness-identity-v7";
const COMPILER_TOPOLOGY_WITNESS_POINTER_KIND =
  "convex-wasm-official-output-module-graph-compiler-topology-witness-pointer-v1";
const COMPILER_TOPOLOGY_WITNESS_STATE_DIRECTORY = "compiler-topology-witnesses";
const MAX_COMPILER_TOPOLOGY_WITNESS_POINTER_BYTES = 64 * 1024;
const compilerDescriptorTopologies = new WeakMap();
const normalizedCompilerDescriptorCacheProjections = new WeakSet();

function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
  }
  return value;
}

function projectRoutes(routes, description) {
  if (!Array.isArray(routes) || routes.length === 0) {
    fail(`${description} must contain routes`);
  }
  return routes.map((route, routeIndex) =>
    normalizeJson(route, `${description} route ${routeIndex}`)
  );
}

function projectEntry(entry, description) {
  assertPlainObject(entry, description);
  assertExactKeys(
    entry,
    new Set([
      "dependencyGraphSha256",
      "entryModulePath",
      "entryPath",
      "entryPublicationUnitSlot",
      "entrySlot",
      "handoffSlot",
      "modulePath",
      "routes",
    ]),
    description
  );
  return {
    entryModulePath: requireString(entry.entryModulePath, `${description} entry module path`),
    entryPath: requireString(entry.entryPath, `${description} entry path`),
    entryPublicationUnitSlot: entry.entryPublicationUnitSlot,
    entrySlot: entry.entrySlot,
    handoffSlot: entry.handoffSlot,
    modulePath: requireString(entry.modulePath, `${description} module path`),
    routes: projectRoutes(entry.routes, description),
  };
}

function projectChunkEntry(entry, description) {
  assertPlainObject(entry, description);
  assertExactKeys(
    entry,
    new Set([
      "dependencyGraphSha256",
      "entryModulePath",
      "entryPath",
      "entrySlot",
      "modulePath",
      "routes",
    ]),
    description
  );
  return {
    entryModulePath: requireString(entry.entryModulePath, `${description} entry module path`),
    entryPath: requireString(entry.entryPath, `${description} entry path`),
    entrySlot: entry.entrySlot,
    modulePath: requireString(entry.modulePath, `${description} module path`),
    routes: projectRoutes(entry.routes, description),
  };
}

function projectDependency(dependency, description) {
  assertPlainObject(dependency, description);
  assertExactKeys(
    dependency,
    new Set(["executableSpecifier", "kind", "path", "slot", "specifier"]),
    description
  );
  const executableSpecifier = requireString(
    dependency.executableSpecifier,
    `${description} executable specifier`
  );
  const executableIdentity =
    parseConvexWasmOfficialOutputExecutableDependencySpecifier(executableSpecifier);
  const kind = requireString(dependency.kind, `${description} kind`);
  if (executableIdentity.kind !== kind) {
    fail(`${description} executable specifier kind is invalid`);
  }
  return {
    executableOccurrence: executableIdentity.occurrence,
    kind,
    nativeSymbolIdentitySha256: executableIdentity.nativeSymbolIdentitySha256,
    path: requireString(dependency.path, `${description} path`),
    slot: dependency.slot,
    specifier: requireString(dependency.specifier, `${description} specifier`),
  };
}

function projectDescriptorUnit(unit, description) {
  assertPlainObject(unit, description);
  if (Object.hasOwn(unit, "dependencies")) {
    assertExactKeys(
      unit,
      new Set([
        "dependencies",
        "javascript",
        "kind",
        "module",
        "nativeSymbolLocator",
        "sha256",
        "slot",
        "transform",
      ]),
      description
    );
    if (!Array.isArray(unit.dependencies)) {
      fail(`${description} dependencies must be an array`);
    }
    assertPlainObject(unit.module, `${description} module`);
    assertExactKeys(
      unit.module,
      new Set([
        "environment",
        "moduleSha256",
        "path",
        "sourceMap",
        "sourceMembershipSha256",
        "sourceSha256",
        "sourceSize",
      ]),
      `${description} module`
    );
    assertPlainObject(unit.nativeSymbolLocator, `${description} native symbol locator`);
    assertExactKeys(
      unit.nativeSymbolLocator,
      new Set(["bindingPath", "canonicalEntryPath", "kind", "sourceMembershipSha256", "symbolAbi"]),
      `${description} native symbol locator`
    );
    if (unit.nativeSymbolLocator.kind !== convexWasmOfficialOutputChunkNativeSymbolLocatorKind) {
      fail(`${description} native symbol locator kind is unsupported`);
    }
    const sourceMembershipSha256 = requireSha256(
      unit.nativeSymbolLocator.sourceMembershipSha256,
      `${description} native symbol locator source-membership SHA-256`
    );
    if (unit.nativeSymbolLocator.symbolAbi !== convexWasmOfficialOutputChunkNativeSymbolAbi) {
      fail(`${description} native symbol locator ABI is unsupported`);
    }
    const canonicalEntryPath =
      unit.nativeSymbolLocator.canonicalEntryPath === null
        ? null
        : requireString(
            unit.nativeSymbolLocator.canonicalEntryPath,
            `${description} native symbol locator canonical entry path`
          );
    if (
      sourceMembershipSha256 !==
      requireSha256(
        unit.module.sourceMembershipSha256,
        `${description} module source-membership SHA-256`
      )
    ) {
      fail(`${description} native symbol locator disagrees with module provenance`);
    }
    const nativeSymbolLocator = convexWasmOfficialOutputChunkNativeSymbolLocator({
      bindingPath: unit.nativeSymbolLocator.bindingPath,
      canonicalEntryPath,
      sourceMembershipSha256,
      symbolAbi: unit.nativeSymbolLocator.symbolAbi,
    });
    return {
      dependencies: unit.dependencies.map((dependency, dependencyIndex) =>
        projectDependency(dependency, `${description} dependency ${dependencyIndex}`)
      ),
      kind: requireString(unit.kind, `${description} kind`),
      module: {
        environment: requireString(unit.module.environment, `${description} module environment`),
        path: requireString(unit.module.path, `${description} module path`),
      },
      // The witness selects reusable structural topology only. Exact source content remains in
      // generated-C, the full compiler record, and final cache authentication.
      nativeSymbolLocator,
      slot: unit.slot,
      transform: normalizeJson(unit.transform, `${description} transform`),
    };
  }
  assertExactKeys(unit, new Set(["entry", "javascript", "kind", "sha256", "slot"]), description);
  assertPlainObject(unit.entry, `${description} entry`);
  assertExactKeys(
    unit.entry,
    new Set(["entryPath", "entrySlot", "handoffSlot", "routes"]),
    `${description} entry`
  );
  return {
    entry: {
      entryPath: requireString(unit.entry.entryPath, `${description} entry path`),
      entrySlot: unit.entry.entrySlot,
      handoffSlot: unit.entry.handoffSlot,
      routes: projectRoutes(unit.entry.routes, `${description} entry`),
    },
    kind: requireString(unit.kind, `${description} kind`),
    slot: unit.slot,
  };
}

function validateProjectedNativeSymbolModuleIdentities({ description, entries, units }) {
  const canonicalEntryPathBySlot = new Map();
  const nativeSymbolLocators = new Set();
  for (const entry of entries) {
    if (canonicalEntryPathBySlot.has(entry.entrySlot)) {
      fail(`${description} entries reuse an entry module`);
    }
    canonicalEntryPathBySlot.set(entry.entrySlot, entry.entryPath);
  }
  for (const unit of units) {
    if (!Object.hasOwn(unit, "nativeSymbolLocator")) continue;
    if (
      unit.nativeSymbolLocator.canonicalEntryPath !==
      (canonicalEntryPathBySlot.get(unit.slot) ?? null)
    ) {
      fail(`${description} native symbol locator changed its module identity`);
    }
    const nativeSymbolLocator = canonicalJson(unit.nativeSymbolLocator);
    if (nativeSymbolLocators.has(nativeSymbolLocator)) {
      fail(`${description} repeats a native symbol locator`);
    }
    nativeSymbolLocators.add(nativeSymbolLocator);
  }
}

export function projectConvexWasmCompilerDescriptorTopology(rawDescriptor) {
  const cached = compilerDescriptorTopologies.get(rawDescriptor);
  if (cached !== undefined) return cached;
  assertPlainObject(rawDescriptor, "compiler topology witness descriptor");
  assertExactKeys(
    rawDescriptor,
    new Set([
      "applicationIdentity",
      "chunkUnitsIdentity",
      "identitySha256",
      "kind",
      "schemaVersion",
    ]),
    "compiler topology witness descriptor"
  );
  if (
    rawDescriptor.kind !== COMPILER_DESCRIPTOR_CACHE_PROJECTION_KIND ||
    rawDescriptor.schemaVersion !== 2
  ) {
    fail("compiler topology witness descriptor has an unsupported schema");
  }
  assertPlainObject(
    rawDescriptor.applicationIdentity,
    "compiler topology witness application identity"
  );
  assertExactKeys(
    rawDescriptor.applicationIdentity,
    new Set([
      "chunkUnits",
      "dependencyGraphSha256",
      "entries",
      "initialization",
      "kind",
      "nativeDescriptor",
      "unitCount",
      "units",
      "sha256",
    ]),
    "compiler topology witness application identity"
  );
  assertPlainObject(
    rawDescriptor.chunkUnitsIdentity,
    "compiler topology witness chunk-units identity"
  );
  assertExactKeys(
    rawDescriptor.chunkUnitsIdentity,
    new Set(["entries", "esbuild", "initialization", "kind", "units", "sha256"]),
    "compiler topology witness chunk-units identity"
  );
  const application = rawDescriptor.applicationIdentity;
  const chunkUnits = rawDescriptor.chunkUnitsIdentity;
  if (
    !Array.isArray(application.entries) ||
    !Array.isArray(application.units) ||
    !Array.isArray(chunkUnits.entries) ||
    !Array.isArray(chunkUnits.units)
  ) {
    fail("compiler topology witness descriptor arrays are invalid");
  }
  const topology = freezeAuthenticatedJsonTree(
    normalizeJson(
      {
        application: {
          entries: application.entries.map((entry, index) =>
            projectEntry(entry, `compiler topology witness application entry ${index}`)
          ),
          initialization: normalizeJson(
            application.initialization,
            "compiler topology witness application initialization"
          ),
          kind: requireString(application.kind, "compiler topology witness application kind"),
          nativeDescriptor: normalizeJson(
            application.nativeDescriptor,
            "compiler topology witness native descriptor"
          ),
          unitCount: application.unitCount,
          units: application.units.map((unit, index) =>
            projectDescriptorUnit(unit, `compiler topology witness application unit ${index}`)
          ),
        },
        chunkUnits: {
          entries: chunkUnits.entries.map((entry, index) =>
            projectChunkEntry(entry, `compiler topology witness chunk entry ${index}`)
          ),
          esbuild: normalizeJson(chunkUnits.esbuild, "compiler topology witness esbuild identity"),
          initialization: normalizeJson(
            chunkUnits.initialization,
            "compiler topology witness chunk initialization"
          ),
          kind: requireString(chunkUnits.kind, "compiler topology witness chunk kind"),
          units: chunkUnits.units.map((unit, index) =>
            projectDescriptorUnit(unit, `compiler topology witness chunk unit ${index}`)
          ),
        },
        kind: "convex-wasm-official-output-module-graph-compiler-structural-topology-v3",
      },
      "compiler structural topology"
    )
  );
  validateProjectedNativeSymbolModuleIdentities({
    description: "compiler topology witness application",
    entries: topology.application.entries,
    units: topology.application.units,
  });
  validateProjectedNativeSymbolModuleIdentities({
    description: "compiler topology witness chunk units",
    entries: topology.chunkUnits.entries,
    units: topology.chunkUnits.units,
  });
  if (normalizedCompilerDescriptorCacheProjections.has(rawDescriptor)) {
    compilerDescriptorTopologies.set(rawDescriptor, topology);
  }
  return topology;
}

export function normalizeConvexWasmCompilerDescriptorCacheProjection(rawDescriptor) {
  if (normalizedCompilerDescriptorCacheProjections.has(rawDescriptor)) return rawDescriptor;
  const normalized = freezeAuthenticatedJsonTree(
    normalizeJson(rawDescriptor, "compiler descriptor cache projection")
  );
  const topology = projectConvexWasmCompilerDescriptorTopology(normalized);
  normalizedCompilerDescriptorCacheProjections.add(normalized);
  compilerDescriptorTopologies.set(normalized, topology);
  return normalized;
}

export function normalizeConvexWasmCompilerOutputCacheIdentity(rawIdentity, description) {
  assertPlainObject(rawIdentity, description);
  assertExactKeys(rawIdentity, COMPILER_OUTPUT_CACHE_IDENTITY_FIELDS, description);
  if (rawIdentity.kind !== COMPILER_OUTPUT_CACHE_IDENTITY_KIND) {
    fail(`${description} has an unsupported schema`);
  }
  return normalizeJson(
    {
      cohortInputsSha256: requireSha256(
        rawIdentity.cohortInputsSha256,
        `${description} cohort inputs`
      ),
      descriptorIdentitySha256: requireSha256(
        rawIdentity.descriptorIdentitySha256,
        `${description} descriptor identity`
      ),
      engineCompatibilitySha256: requireSha256(
        rawIdentity.engineCompatibilitySha256,
        `${description} engine compatibility`
      ),
      kind: COMPILER_OUTPUT_CACHE_IDENTITY_KIND,
      materialSessionSha256: requireSha256(
        rawIdentity.materialSessionSha256,
        `${description} material session`
      ),
      producerIdentitySha256: requireSha256(
        rawIdentity.producerIdentitySha256,
        `${description} producer identity`
      ),
      topologyWitnessMaterialIdentitySha256: requireSha256(
        rawIdentity.topologyWitnessMaterialIdentitySha256,
        `${description} topology-witness material identity`
      ),
    },
    description
  );
}

export function createConvexWasmCompilerTopologyWitnessIdentity({
  compilerOutputCacheIdentity,
  descriptor,
  valueMode,
}) {
  const normalizedCompilerOutputCacheIdentity = normalizeConvexWasmCompilerOutputCacheIdentity(
    compilerOutputCacheIdentity,
    "compiler topology witness cache identity"
  );
  // The witness deliberately omits the cohort, descriptor, material-session, and producer fields.
  // Normalize the complete v8 identity first so no future shape can enter this narrower namespace
  // merely by retaining the fields that the witness projects.
  // The topology is already normalized and deeply frozen; all remaining fields are strings.
  // Keep that owned tree and freeze this identity so pointer consumers reuse its cached digest.
  return Object.freeze({
    engineCompatibilitySha256: normalizedCompilerOutputCacheIdentity.engineCompatibilitySha256,
    kind: COMPILER_TOPOLOGY_WITNESS_IDENTITY_KIND,
    physicalMaterialIdentitySha256:
      normalizedCompilerOutputCacheIdentity.topologyWitnessMaterialIdentitySha256,
    topology: projectConvexWasmCompilerDescriptorTopology(descriptor),
    valueMode: requireString(valueMode, "compiler topology witness value mode"),
  });
}

export function convexWasmCompilerTopologyWitnessPointerPath(cacheLayout, identity) {
  const identitySha256 = fingerprintJson(identity);
  return join(
    cacheLayout.state.root,
    COMPILER_TOPOLOGY_WITNESS_STATE_DIRECTORY,
    `${identitySha256}.json`
  );
}

export function normalizeConvexWasmCompilerTopologyWitnessPointer(rawPointer, identity) {
  assertPlainObject(rawPointer, "compiler topology witness pointer");
  assertExactKeys(
    rawPointer,
    new Set([
      "compilerOutputCacheKey",
      "compilerOutputCacheRecordSha256",
      "compilerOutputTopologyCertificateCacheKey",
      "kind",
      "schemaVersion",
      "topologyIdentitySha256",
    ]),
    "compiler topology witness pointer"
  );
  if (
    rawPointer.kind !== COMPILER_TOPOLOGY_WITNESS_POINTER_KIND ||
    rawPointer.schemaVersion !== 1
  ) {
    fail("compiler topology witness pointer has an unsupported schema");
  }
  const topologyIdentitySha256 = requireSha256(
    rawPointer.topologyIdentitySha256,
    "compiler topology witness pointer topology identity"
  );
  if (topologyIdentitySha256 !== fingerprintJson(identity)) {
    fail("compiler topology witness pointer moved to a different topology identity");
  }
  return normalizeJson(
    {
      compilerOutputCacheKey: requireSha256(
        rawPointer.compilerOutputCacheKey,
        "compiler topology witness compiler-output key"
      ),
      compilerOutputCacheRecordSha256: requireSha256(
        rawPointer.compilerOutputCacheRecordSha256,
        "compiler topology witness compiler-output record SHA-256"
      ),
      compilerOutputTopologyCertificateCacheKey: requireSha256(
        rawPointer.compilerOutputTopologyCertificateCacheKey,
        "compiler topology witness certificate key"
      ),
      kind: COMPILER_TOPOLOGY_WITNESS_POINTER_KIND,
      schemaVersion: 1,
      topologyIdentitySha256,
    },
    "compiler topology witness pointer"
  );
}

export function createConvexWasmCompilerTopologyWitnessPointer({
  compilerOutputCacheKey,
  compilerOutputCacheRecordSha256,
  compilerOutputTopologyCertificateCacheKey,
  identity,
}) {
  return normalizeConvexWasmCompilerTopologyWitnessPointer(
    {
      compilerOutputCacheKey,
      compilerOutputCacheRecordSha256,
      compilerOutputTopologyCertificateCacheKey,
      kind: COMPILER_TOPOLOGY_WITNESS_POINTER_KIND,
      schemaVersion: 1,
      topologyIdentitySha256: fingerprintJson(identity),
    },
    identity
  );
}

export async function readConvexWasmCompilerTopologyWitnessPointer({
  cacheLayout,
  cacheRoot,
  identity,
}) {
  const path = convexWasmCompilerTopologyWitnessPointerPath(cacheLayout, identity);
  const directory = dirname(path);
  if (!(await requirePrivateDirectory(directory, "compiler topology witness state directory"))) {
    return undefined;
  }
  await requirePrivateCacheDirectory(cacheRoot, directory);
  let contents;
  try {
    await requirePrivateCacheFile(cacheRoot, path);
    contents = await readPrivateRegularFile(
      path,
      MAX_COMPILER_TOPOLOGY_WITNESS_POINTER_BYTES,
      "compiler topology witness pointer"
    );
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  const source = decodeUtf8(contents, "compiler topology witness pointer");
  let pointer;
  try {
    pointer = JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm compiler topology witness pointer is not valid JSON", {
      cause: error,
    });
  }
  const normalized = normalizeConvexWasmCompilerTopologyWitnessPointer(pointer, identity);
  if (`${canonicalJson(normalized)}\n` !== source) {
    fail("compiler topology witness pointer is not canonical JSON");
  }
  return normalized;
}

async function writeNewFile(path, source) {
  const handle = await fs.open(path, "wx", 0o600);
  try {
    await handle.writeFile(source);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(path) {
  const handle = await fs.open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function writeConvexWasmCompilerTopologyWitnessPointer({
  cacheLayout,
  cacheRoot,
  identity,
  pointer: rawPointer,
}) {
  const pointer = normalizeConvexWasmCompilerTopologyWitnessPointer(rawPointer, identity);
  const existing = await readConvexWasmCompilerTopologyWitnessPointer({
    cacheLayout,
    cacheRoot,
    identity,
  });
  if (existing !== undefined && canonicalJson(existing) === canonicalJson(pointer)) {
    return existing;
  }
  const path = convexWasmCompilerTopologyWitnessPointerPath(cacheLayout, identity);
  const directory = dirname(path);
  await fs.mkdir(directory, { mode: 0o700, recursive: true });
  await requirePrivateCacheDirectory(cacheRoot, directory);
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    await writeNewFile(temporaryPath, `${canonicalJson(pointer)}\n`);
    await requirePrivateCacheFile(cacheRoot, temporaryPath);
    await fs.rename(temporaryPath, path);
    await syncDirectory(directory);
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
  return pointer;
}
