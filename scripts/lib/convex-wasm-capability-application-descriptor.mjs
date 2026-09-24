import { createHash } from "node:crypto";

import {
  convexWasmOfficialOutputChunkApplicationUnitKind as OFFICIAL_OUTPUT_CHUNK_APPLICATION_UNIT_KIND,
  convexWasmOfficialOutputChunkEntryPublicationUnitKind as OFFICIAL_OUTPUT_CHUNK_ENTRY_PUBLICATION_UNIT_KIND,
  convexWasmOfficialOutputChunkNativeApplicationDescriptorKind as OFFICIAL_OUTPUT_CHUNK_NATIVE_APPLICATION_DESCRIPTOR_KIND,
  convexWasmOfficialOutputChunkUnitKind as OFFICIAL_OUTPUT_CHUNK_UNIT_KIND,
  convexWasmOfficialOutputChunkUnitsKind as OFFICIAL_OUTPUT_CHUNK_UNITS_KIND,
  deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s,
  normalizeConvexWasmOfficialOutputChunkDependencies,
  validateConvexWasmOfficialOutputChunkDependencyTopology,
} from "./convex-wasm-official-output-chunk-contract.mjs";
import { isProjectedConvexWasmOfficialOutputChunkNativeApplicationDescriptor } from "./convex-wasm-official-output-chunk-projection-provenance.mjs";
import {
  convexWasmOfficialOutputChunkNativeSymbolLocator,
  convexWasmOfficialOutputNativeSymbolIdentitySha256,
} from "./convex-wasm-native-symbol-identity.mjs";
import { convexWasmStaticHermesEsbuildSupportedSyntax } from "./convex-wasm-static-hermes-syntax.mjs";
import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  fail,
  fingerprintJson,
  normalizeJson,
  requireBoolean,
  requireEnum,
  requireManifestString,
  requirePositiveInteger,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";

const MAX_MANIFEST_IDENTIFIER_BYTES = 256;
const MAX_MANIFEST_STRING_BYTES = 4 * 1024;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const OFFICIAL_OUTPUT_CHUNK_NATIVE_DESCRIPTOR_ABI_KIND =
  "convex-wasm-official-output-chunk-native-descriptor-abi-v3";
export const convexWasmOfficialOutputChunkTransform = Object.freeze({
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
const normalizedCapabilityChunkApplicationDescriptors = new WeakSet();

function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
  }
  return value;
}

export function normalizeConvexWasmOfficialOutputChunkModuleIdentity(rawModule, description) {
  assertPlainObject(rawModule, description);
  assertExactKeys(
    rawModule,
    new Set([
      "environment",
      "moduleSha256",
      "path",
      "sourceMap",
      "sourceMembershipSha256",
      "sourceSha256",
      "sourceSize",
    ]),
    description
  );
  const path = requireManifestString(
    rawModule.path,
    `${description} path`,
    MAX_MANIFEST_STRING_BYTES,
    false
  );
  if (
    path.startsWith("/") ||
    path.includes("\\") ||
    path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    fail(`${description} path is not normalized`);
  }
  assertPlainObject(rawModule.sourceMap, `${description} source-map identity`);
  assertExactKeys(
    rawModule.sourceMap,
    new Set(["sha256", "size", "sourcesContentCount", "sourcesCount"]),
    `${description} source-map identity`
  );
  if (
    !Number.isSafeInteger(rawModule.sourceMap.sourcesContentCount) ||
    rawModule.sourceMap.sourcesContentCount < 0 ||
    !Number.isSafeInteger(rawModule.sourceMap.sourcesCount) ||
    rawModule.sourceMap.sourcesCount < 0
  ) {
    fail(`${description} source-map counts are invalid`);
  }
  const sourceMap = {
    sha256: requireSha256(rawModule.sourceMap.sha256, `${description} source-map SHA-256`),
    size: requirePositiveInteger(rawModule.sourceMap.size, `${description} source-map size`),
    sourcesContentCount: rawModule.sourceMap.sourcesContentCount,
    sourcesCount: rawModule.sourceMap.sourcesCount,
  };
  if (rawModule.environment !== "isolate") {
    fail(`${description} environment is invalid`);
  }
  return {
    environment: rawModule.environment,
    moduleSha256: requireSha256(rawModule.moduleSha256, `${description} SHA-256`),
    path,
    sourceMap,
    sourceMembershipSha256: requireSha256(
      rawModule.sourceMembershipSha256,
      `${description} source-membership SHA-256`
    ),
    sourceSha256: requireSha256(rawModule.sourceSha256, `${description} source SHA-256`),
    sourceSize: requirePositiveInteger(rawModule.sourceSize, `${description} source size`),
  };
}

export function normalizeConvexWasmCapabilityChunkApplicationDescriptor(rawDescriptor) {
  if (normalizedCapabilityChunkApplicationDescriptors.has(rawDescriptor)) return rawDescriptor;
  if (isProjectedConvexWasmOfficialOutputChunkNativeApplicationDescriptor(rawDescriptor)) {
    normalizedCapabilityChunkApplicationDescriptors.add(rawDescriptor);
    return rawDescriptor;
  }
  assertPlainObject(rawDescriptor, "capability chunk application descriptor");
  assertExactKeys(
    rawDescriptor,
    new Set([
      "applicationIdentity",
      "chunkUnitsIdentity",
      "entries",
      "identitySha256",
      "initialization",
      "kind",
      "nativeDescriptor",
      "units",
    ]),
    "capability chunk application descriptor"
  );
  if (rawDescriptor.kind !== OFFICIAL_OUTPUT_CHUNK_NATIVE_APPLICATION_DESCRIPTOR_KIND) {
    fail("capability chunk application descriptor kind is unsupported");
  }
  const identitySha256 = requireSha256(
    rawDescriptor.identitySha256,
    "capability chunk application descriptor identity SHA-256"
  );
  assertPlainObject(rawDescriptor.initialization, "capability chunk application initialization");
  assertExactKeys(
    rawDescriptor.initialization,
    new Set(["chunkSlotCount", "entryPublicationUnitSlots", "kind", "namespaceSlotCount"]),
    "capability chunk application initialization"
  );
  if (
    rawDescriptor.initialization.kind !==
      "closed-numbered-chunk-slots-with-per-entry-publication-v1" ||
    !Number.isSafeInteger(rawDescriptor.initialization.chunkSlotCount) ||
    rawDescriptor.initialization.chunkSlotCount < 1 ||
    !Number.isSafeInteger(rawDescriptor.initialization.namespaceSlotCount) ||
    rawDescriptor.initialization.namespaceSlotCount < 1 ||
    rawDescriptor.initialization.chunkSlotCount !==
      rawDescriptor.initialization.namespaceSlotCount ||
    !Array.isArray(rawDescriptor.initialization.entryPublicationUnitSlots)
  ) {
    fail("capability chunk application initialization descriptor is invalid");
  }
  assertPlainObject(
    rawDescriptor.nativeDescriptor,
    "capability chunk application native descriptor"
  );
  assertExactKeys(
    rawDescriptor.nativeDescriptor,
    new Set(["destruction", "initialization", "kind", "publication", "slots"]),
    "capability chunk application native descriptor"
  );
  if (
    rawDescriptor.nativeDescriptor.kind !== OFFICIAL_OUTPUT_CHUNK_NATIVE_DESCRIPTOR_ABI_KIND ||
    rawDescriptor.nativeDescriptor.destruction !== "destroy-store-on-any-initialization-failure" ||
    rawDescriptor.nativeDescriptor.initialization !==
      "recursive-closed-literal-require-with-provisional-cjs-namespaces" ||
    rawDescriptor.nativeDescriptor.publication !==
      "authenticated-selected-entry-wrapper-validation-after-selected-closure-initialization" ||
    rawDescriptor.nativeDescriptor.slots !==
      "closed-numbered-namespace-slots-with-per-entry-publication-units"
  ) {
    fail("capability chunk application native descriptor is invalid");
  }
  if (!Array.isArray(rawDescriptor.units) || rawDescriptor.units.length < 2) {
    fail("capability chunk application descriptor must contain chunk and entry-publication units");
  }
  if (rawDescriptor.units.length > 1024) {
    fail("capability chunk application descriptor exceeds the bounded unit registry capacity");
  }
  if (
    rawDescriptor.units.length !==
    rawDescriptor.initialization.namespaceSlotCount +
      rawDescriptor.initialization.entryPublicationUnitSlots.length
  ) {
    fail("capability chunk application descriptor unit count disagrees with its namespace slots");
  }
  const units = rawDescriptor.units.map((rawUnit, index) => {
    assertPlainObject(rawUnit, `capability chunk application descriptor unit ${index}`);
    assertExactKeys(
      rawUnit,
      new Set([
        "applicationUnitSlot",
        "chunkSlot",
        "dependencies",
        "entryPublication",
        "entrySymbol",
        "exportedUnitName",
        "identitySha256",
        "javascript",
        "javascriptSource",
        "kind",
        "module",
        "nativeSymbolLocator",
        "nativeSymbolIdentitySha256",
        "publicationHandoffSlot",
        "reusableCodeIdentitySha256",
        "transform",
      ]),
      `capability chunk application descriptor unit ${index}`
    );
    const entryPublication = requireBoolean(
      rawUnit.entryPublication,
      `capability chunk application descriptor unit ${index} entry-publication flag`
    );
    if (
      rawUnit.applicationUnitSlot !== index ||
      !Number.isSafeInteger(rawUnit.applicationUnitSlot) ||
      (entryPublication
        ? rawUnit.kind !== OFFICIAL_OUTPUT_CHUNK_ENTRY_PUBLICATION_UNIT_KIND ||
          rawUnit.chunkSlot !== -1 ||
          index < rawDescriptor.initialization.namespaceSlotCount
        : rawUnit.kind !== OFFICIAL_OUTPUT_CHUNK_UNIT_KIND ||
          rawUnit.chunkSlot !== index ||
          index >= rawDescriptor.initialization.namespaceSlotCount)
    ) {
      fail(`capability chunk application descriptor unit ${index} is invalid`);
    }
    const dependencies = normalizeConvexWasmOfficialOutputChunkDependencies({
      dependencies: rawUnit.dependencies,
      namespaceSlotCount: rawDescriptor.initialization.namespaceSlotCount,
      unitDescription: `capability chunk application descriptor unit ${index}`,
    });
    if (entryPublication && dependencies.length !== 0) {
      fail(`capability chunk application descriptor unit ${index} dependencies are invalid`);
    }
    if (
      !Number.isSafeInteger(rawUnit.publicationHandoffSlot) ||
      (entryPublication
        ? rawUnit.publicationHandoffSlot !==
            index - rawDescriptor.initialization.namespaceSlotCount ||
          rawUnit.publicationHandoffSlot >=
            rawDescriptor.initialization.entryPublicationUnitSlots.length
        : rawUnit.publicationHandoffSlot !== -1)
    ) {
      fail(
        `capability chunk application descriptor unit ${index} publication handoff slot is invalid`
      );
    }
    assertPlainObject(
      rawUnit.javascript,
      `capability chunk application descriptor unit ${index} JavaScript`
    );
    assertExactKeys(
      rawUnit.javascript,
      new Set(["sha256", "size"]),
      `capability chunk application descriptor unit ${index} JavaScript`
    );
    const javascript = {
      sha256: requireSha256(
        rawUnit.javascript.sha256,
        `capability chunk application descriptor unit ${index} JavaScript SHA-256`
      ),
      size: requirePositiveInteger(
        rawUnit.javascript.size,
        `capability chunk application descriptor unit ${index} JavaScript size`
      ),
    };
    const javascriptSource = requireString(
      rawUnit.javascriptSource,
      `capability chunk application descriptor unit ${index} JavaScript source`
    );
    if (Buffer.byteLength(javascriptSource) > 16 * 1024 * 1024) {
      fail(
        `capability chunk application descriptor unit ${index} JavaScript source exceeds its ingress limit`
      );
    }
    if (
      javascript.sha256 !== createHash("sha256").update(javascriptSource).digest("hex") ||
      javascript.size !== Buffer.byteLength(javascriptSource)
    ) {
      fail(`capability chunk application descriptor unit ${index} JavaScript material changed`);
    }
    const module = entryPublication
      ? rawUnit.module
      : normalizeConvexWasmOfficialOutputChunkModuleIdentity(
          rawUnit.module,
          `capability chunk application descriptor unit ${index} module identity`
        );
    const transform = entryPublication
      ? rawUnit.transform
      : normalizeJson(
          rawUnit.transform,
          `capability chunk application descriptor unit ${index} transform identity`
        );
    if (
      entryPublication
        ? module !== null || transform !== null
        : canonicalJson(transform) !== canonicalJson(convexWasmOfficialOutputChunkTransform)
    ) {
      fail(`capability chunk application descriptor unit ${index} identity projection is invalid`);
    }
    const identitySha256 = requireSha256(
      rawUnit.identitySha256,
      `capability chunk application descriptor unit ${index} identity SHA-256`
    );
    const reusableCodeIdentitySha256 = requireSha256(
      rawUnit.reusableCodeIdentitySha256,
      `capability chunk application descriptor unit ${index} reusable-code identity SHA-256`
    );
    const nativeSymbolIdentitySha256 = requireSha256(
      rawUnit.nativeSymbolIdentitySha256,
      `capability chunk application descriptor unit ${index} native symbol identity SHA-256`
    );
    const entrySymbol = requireManifestString(
      rawUnit.entrySymbol,
      `capability chunk application descriptor unit ${index} entry symbol`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    const exportedUnitName = requireManifestString(
      rawUnit.exportedUnitName,
      `capability chunk application descriptor unit ${index} exported unit name`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (
      !IDENTIFIER_PATTERN.test(entrySymbol) ||
      !IDENTIFIER_PATTERN.test(exportedUnitName) ||
      entrySymbol !== `sh_export_convex_wasm_official_chunk_${nativeSymbolIdentitySha256}` ||
      exportedUnitName !== `convex_wasm_official_chunk_${nativeSymbolIdentitySha256}`
    ) {
      fail(`capability chunk application descriptor unit ${index} has an invalid native symbol`);
    }
    const nativeSymbolLocator = entryPublication
      ? rawUnit.nativeSymbolLocator
      : convexWasmOfficialOutputChunkNativeSymbolLocator(rawUnit.nativeSymbolLocator);
    if (
      entryPublication
        ? nativeSymbolLocator !== null
        : nativeSymbolLocator.sourceMembershipSha256 !== module.sourceMembershipSha256
    ) {
      fail(
        `capability chunk application descriptor unit ${index} native symbol locator is invalid`
      );
    }
    return {
      applicationUnitSlot: index,
      chunkSlot: rawUnit.chunkSlot,
      dependencies,
      entryPublication,
      entrySymbol,
      exportedUnitName,
      identitySha256,
      javascript,
      javascriptSource,
      kind: rawUnit.kind,
      module,
      nativeSymbolIdentitySha256,
      nativeSymbolLocator,
      publicationHandoffSlot: rawUnit.publicationHandoffSlot,
      reusableCodeIdentitySha256,
      transform,
    };
  });
  if (!Array.isArray(rawDescriptor.entries) || rawDescriptor.entries.length === 0) {
    fail("capability chunk application descriptor entries are invalid");
  }
  if (
    rawDescriptor.initialization.entryPublicationUnitSlots.length !==
      rawDescriptor.entries.length ||
    rawDescriptor.initialization.entryPublicationUnitSlots.some(
      (unitSlot, handoffSlot) =>
        !Number.isSafeInteger(unitSlot) ||
        unitSlot !== rawDescriptor.initialization.namespaceSlotCount + handoffSlot
    )
  ) {
    fail("capability chunk application publication slots are invalid");
  }
  const entries = rawDescriptor.entries.map((entry, index) => {
    assertPlainObject(entry, `capability chunk application descriptor entry ${index}`);
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
      `capability chunk application descriptor entry ${index}`
    );
    if (
      entry.handoffSlot !== index ||
      !Number.isSafeInteger(entry.entrySlot) ||
      entry.entrySlot < 0 ||
      entry.entrySlot >= rawDescriptor.initialization.namespaceSlotCount ||
      !Number.isSafeInteger(entry.entryPublicationUnitSlot) ||
      entry.entryPublicationUnitSlot !==
        rawDescriptor.initialization.entryPublicationUnitSlots[index]
    ) {
      fail(`capability chunk application descriptor entry ${index} slots are invalid`);
    }
    if (!Array.isArray(entry.routes) || entry.routes.length === 0) {
      fail(`capability chunk application descriptor entry ${index} routes are invalid`);
    }
    const routes = entry.routes.map((route, routeIndex) => {
      assertPlainObject(
        route,
        `capability chunk application descriptor entry ${index} route ${routeIndex}`
      );
      assertExactKeys(
        route,
        new Set(["exportName", "udfKind", "visibility"]),
        `capability chunk application descriptor entry ${index} route ${routeIndex}`
      );
      return {
        exportName: requireManifestString(
          route.exportName,
          `capability chunk application descriptor entry ${index} route ${routeIndex} export name`,
          MAX_MANIFEST_IDENTIFIER_BYTES,
          false
        ),
        udfKind: requireEnum(
          route.udfKind,
          new Set(["mutation", "query"]),
          `capability chunk application descriptor entry ${index} route ${routeIndex} UDF kind`
        ),
        visibility: requireEnum(
          route.visibility,
          new Set(["internal", "public"]),
          `capability chunk application descriptor entry ${index} route ${routeIndex} visibility`
        ),
      };
    });
    if (
      routes.some(({ exportName }) => !IDENTIFIER_PATTERN.test(exportName)) ||
      new Set(routes.map(({ exportName }) => exportName)).size !== routes.length
    ) {
      fail(`capability chunk application descriptor entry ${index} routes are invalid`);
    }
    return {
      dependencyGraphSha256: requireSha256(
        entry.dependencyGraphSha256,
        `capability chunk application descriptor entry ${index} dependency graph SHA-256`
      ),
      entryModulePath: requireManifestString(
        entry.entryModulePath,
        `capability chunk application descriptor entry ${index} module path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      entryPath: requireManifestString(
        entry.entryPath,
        `capability chunk application descriptor entry ${index} path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      entryPublicationUnitSlot: entry.entryPublicationUnitSlot,
      entrySlot: entry.entrySlot,
      handoffSlot: index,
      modulePath: requireManifestString(
        entry.modulePath,
        `capability chunk application descriptor entry ${index} source path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      routes,
    };
  });
  if (
    entries.some((entry, index) => index > 0 && entries[index - 1].entryPath >= entry.entryPath)
  ) {
    fail("capability chunk application descriptor entries are unordered");
  }
  validateConvexWasmOfficialOutputChunkDependencyTopology({
    chunkSlotCount: rawDescriptor.initialization.namespaceSlotCount,
    description: "capability chunk application descriptor",
    units,
  });
  if (entries.some((entry) => units[entry.entrySlot].module.path !== entry.entryModulePath)) {
    fail("capability chunk application descriptor entries do not bind their entry modules");
  }
  const canonicalEntryPathBySlot = new Map();
  for (const entry of entries) {
    if (canonicalEntryPathBySlot.has(entry.entrySlot)) {
      fail("capability chunk application descriptor entries reuse an entry module");
    }
    canonicalEntryPathBySlot.set(entry.entrySlot, entry.entryPath);
  }
  for (const [unitIndex, unit] of units.entries()) {
    if (
      !unit.entryPublication &&
      unit.nativeSymbolLocator.canonicalEntryPath !==
        (canonicalEntryPathBySlot.get(unit.chunkSlot) ?? null)
    ) {
      fail(
        `capability chunk application descriptor unit ${unitIndex} native symbol locator changed its module identity`
      );
    }
  }
  if (
    entries.some(
      (entry) =>
        units[entry.entryPublicationUnitSlot].entryPublication !== true ||
        units[entry.entryPublicationUnitSlot].publicationHandoffSlot !== entry.handoffSlot
    )
  ) {
    fail("capability chunk application descriptor entries do not bind their publication units");
  }
  const nativeSymbolIdentities = new Set();
  for (const [unitIndex, unit] of units.entries()) {
    const entry = unit.entryPublication ? entries[unit.publicationHandoffSlot] : undefined;
    const expectedNativeSymbolIdentitySha256 = convexWasmOfficialOutputNativeSymbolIdentitySha256({
      entryPath: entry?.entryPath,
      entryPublication: unit.entryPublication,
      nativeSymbolLocator: unit.nativeSymbolLocator,
    });
    if (unit.nativeSymbolIdentitySha256 !== expectedNativeSymbolIdentitySha256) {
      fail(
        `capability chunk application descriptor unit ${unitIndex} native symbol identity changed`
      );
    }
    if (nativeSymbolIdentities.has(unit.nativeSymbolIdentitySha256)) {
      fail(
        `capability chunk application descriptor unit ${unitIndex} reuses a native symbol identity`
      );
    }
    nativeSymbolIdentities.add(unit.nativeSymbolIdentitySha256);
  }
  const reusableCodeIdentitySha256ByUnit =
    deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
      chunkSlotCount: rawDescriptor.initialization.namespaceSlotCount,
      units,
    });
  for (const [unitIndex, unit] of units.entries()) {
    if (unit.reusableCodeIdentitySha256 !== reusableCodeIdentitySha256ByUnit[unitIndex]) {
      fail(
        `capability chunk application descriptor unit ${unitIndex} reusable-code identity changed`
      );
    }
  }
  const canonicalApplicationEntries = entries.map(
    ({
      dependencyGraphSha256,
      entryModulePath,
      entryPath,
      entryPublicationUnitSlot,
      entrySlot,
      handoffSlot,
      modulePath,
      routes,
    }) => ({
      dependencyGraphSha256,
      entryModulePath,
      entryPath,
      entryPublicationUnitSlot,
      entrySlot,
      handoffSlot,
      modulePath,
      routes,
    })
  );
  const unitIdentities = units.map((unit, index) => {
    const identity = unit.entryPublication
      ? {
          entry: (({ entryPath, entrySlot, handoffSlot, routes }) => ({
            entryPath,
            entrySlot,
            handoffSlot,
            routes,
          }))(entries[unit.publicationHandoffSlot]),
          javascript: unit.javascript,
          kind: OFFICIAL_OUTPUT_CHUNK_ENTRY_PUBLICATION_UNIT_KIND,
          slot: index,
        }
      : {
          dependencies: unit.dependencies,
          javascript: unit.javascript,
          kind: OFFICIAL_OUTPUT_CHUNK_UNIT_KIND,
          module: unit.module,
          nativeSymbolLocator: unit.nativeSymbolLocator,
          slot: unit.chunkSlot,
          transform: unit.transform,
        };
    const recomputed = { ...identity, sha256: fingerprintJson(identity) };
    if (unit.identitySha256 !== recomputed.sha256) {
      fail(`capability chunk application descriptor unit ${index} identity changed`);
    }
    return recomputed;
  });
  assertPlainObject(rawDescriptor.chunkUnitsIdentity, "capability chunk-units identity");
  assertExactKeys(
    rawDescriptor.chunkUnitsIdentity,
    new Set([
      "entries",
      "esbuild",
      "initialization",
      "kind",
      "sourceEnvelopeSha256",
      "units",
      "sha256",
    ]),
    "capability chunk-units identity"
  );
  assertPlainObject(
    rawDescriptor.chunkUnitsIdentity.esbuild,
    "capability chunk-units esbuild identity"
  );
  assertExactKeys(
    rawDescriptor.chunkUnitsIdentity.esbuild,
    new Set(["version"]),
    "capability chunk-units esbuild identity"
  );
  const chunkUnitsIdentity = {
    entries: entries.map(
      ({ dependencyGraphSha256, entryModulePath, entryPath, entrySlot, modulePath, routes }) => ({
        dependencyGraphSha256,
        entryModulePath,
        entryPath,
        entrySlot,
        modulePath,
        routes,
      })
    ),
    esbuild: {
      version: requireManifestString(
        rawDescriptor.chunkUnitsIdentity.esbuild.version,
        "capability chunk-units esbuild version",
        MAX_MANIFEST_IDENTIFIER_BYTES,
        false
      ),
    },
    initialization: {
      dynamicImport: "literal-require-after-promise-microtask",
      kind: "closed-numbered-namespace-slots-v1",
      publication: "selected-entry-namespaces-after-selected-closure-initialization",
    },
    kind: OFFICIAL_OUTPUT_CHUNK_UNITS_KIND,
    sourceEnvelopeSha256: requireSha256(
      rawDescriptor.chunkUnitsIdentity.sourceEnvelopeSha256,
      "capability chunk-units source-envelope SHA-256"
    ),
    units: unitIdentities.slice(0, rawDescriptor.initialization.namespaceSlotCount),
  };
  const authenticatedChunkUnitsIdentity = {
    ...chunkUnitsIdentity,
    sha256: fingerprintJson(chunkUnitsIdentity),
  };
  if (
    canonicalJson(rawDescriptor.chunkUnitsIdentity) !==
    canonicalJson(authenticatedChunkUnitsIdentity)
  ) {
    fail("capability chunk-units identity changed");
  }
  assertPlainObject(rawDescriptor.applicationIdentity, "capability chunk application identity");
  assertExactKeys(
    rawDescriptor.applicationIdentity,
    new Set([
      "chunkUnits",
      "dependencyGraphSha256",
      "entries",
      "initialization",
      "kind",
      "nativeDescriptor",
      "sourceEnvelopeSha256",
      "unitCount",
      "units",
      "sha256",
    ]),
    "capability chunk application identity"
  );
  const applicationIdentity = {
    chunkUnits: {
      kind: OFFICIAL_OUTPUT_CHUNK_UNITS_KIND,
      sha256: authenticatedChunkUnitsIdentity.sha256,
    },
    dependencyGraphSha256: fingerprintJson({
      domain: "convex-wasm-official-output-cohort-dependency-graph-v1",
      entries: entries.map(({ dependencyGraphSha256, entryPath }) => ({
        dependencyGraphSha256,
        entryPath,
      })),
    }),
    entries: canonicalApplicationEntries,
    initialization: {
      chunkSlotCount: rawDescriptor.initialization.chunkSlotCount,
      entryPublicationUnitSlots: [...rawDescriptor.initialization.entryPublicationUnitSlots],
      kind: rawDescriptor.initialization.kind,
      namespaceSlotCount: rawDescriptor.initialization.namespaceSlotCount,
    },
    kind: OFFICIAL_OUTPUT_CHUNK_APPLICATION_UNIT_KIND,
    nativeDescriptor: { ...rawDescriptor.nativeDescriptor },
    sourceEnvelopeSha256: authenticatedChunkUnitsIdentity.sourceEnvelopeSha256,
    unitCount: units.length,
    units: unitIdentities,
  };
  const authenticatedApplicationIdentity = {
    ...applicationIdentity,
    sha256: fingerprintJson(applicationIdentity),
  };
  if (
    identitySha256 !== authenticatedApplicationIdentity.sha256 ||
    canonicalJson(rawDescriptor.applicationIdentity) !==
      canonicalJson(authenticatedApplicationIdentity)
  ) {
    fail("capability chunk application identity changed");
  }
  const normalized = freezeAuthenticatedJsonTree({
    applicationIdentity: authenticatedApplicationIdentity,
    chunkUnitsIdentity: authenticatedChunkUnitsIdentity,
    entries,
    identitySha256,
    initialization: {
      chunkSlotCount: rawDescriptor.initialization.chunkSlotCount,
      entryPublicationUnitSlots: [...rawDescriptor.initialization.entryPublicationUnitSlots],
      kind: rawDescriptor.initialization.kind,
      namespaceSlotCount: rawDescriptor.initialization.namespaceSlotCount,
    },
    kind: rawDescriptor.kind,
    nativeDescriptor: { ...rawDescriptor.nativeDescriptor },
    units,
  });
  normalizedCapabilityChunkApplicationDescriptors.add(normalized);
  return normalized;
}

export function isNormalizedConvexWasmCapabilityChunkApplicationDescriptor(value) {
  return normalizedCapabilityChunkApplicationDescriptors.has(value);
}
