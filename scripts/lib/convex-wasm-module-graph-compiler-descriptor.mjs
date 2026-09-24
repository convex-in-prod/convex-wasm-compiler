import { createHash } from "node:crypto";
import { isOwnedConvexWasmCohortCapsuleWorkerResult } from "./convex-wasm-cohort-capsule-worker.mjs";

import {
  canonicalJson,
  fail,
  fingerprintJson,
  normalizeJson,
  requireBoolean,
  requireEnum,
  requireExactPlainObject,
  requireManifestString,
  requirePositiveInteger,
  requireSha256,
} from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmOfficialOutputChunkTransform,
  isNormalizedConvexWasmCapabilityChunkApplicationDescriptor,
  normalizeConvexWasmOfficialOutputChunkModuleIdentity,
} from "./convex-wasm-capability-application-descriptor.mjs";
import {
  convexWasmOfficialOutputChunkNativeSymbolLocator,
  convexWasmOfficialOutputNativeSymbolIdentitySha256,
} from "./convex-wasm-native-symbol-identity.mjs";
import {
  convexWasmModuleGraphCompilerDescriptorKind,
  convexWasmModuleGraphCompilerDescriptorSchemaVersion,
  convexWasmOfficialOutputChunkApplicationUnitKind,
  convexWasmOfficialOutputChunkEntryPublicationUnitKind,
  convexWasmOfficialOutputChunkNativeApplicationDescriptorKind,
  convexWasmOfficialOutputChunkUnitKind,
  convexWasmOfficialOutputChunkUnitsKind,
  deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s,
  normalizeConvexWasmOfficialOutputChunkDependencies,
  validateConvexWasmOfficialOutputChunkDependencyTopology,
} from "./convex-wasm-official-output-chunk-contract.mjs";

export {
  convexWasmModuleGraphCompilerDescriptorKind,
  convexWasmModuleGraphCompilerDescriptorSchemaVersion,
  convexWasmOfficialOutputChunkApplicationUnitKind,
  convexWasmOfficialOutputChunkEntryPublicationUnitKind,
  convexWasmOfficialOutputChunkNativeApplicationDescriptorKind,
  convexWasmOfficialOutputChunkUnitKind,
  convexWasmOfficialOutputChunkUnitsKind,
  deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s,
};

const MAX_MANIFEST_IDENTIFIER_BYTES = 256;
const MAX_MANIFEST_STRING_BYTES = 4 * 1024;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const authenticatedCompilerDescriptors = new WeakSet();

export function restoreConvexWasmModuleGraphCompilerDescriptorFromWorker(transferred) {
  if (!isOwnedConvexWasmCohortCapsuleWorkerResult(transferred)) {
    fail("compiler descriptor restoration requires an owned capsule worker result");
  }
  const descriptor = transferred.authority.descriptor;
  // The receiving pipeline froze this exact worker-owned tree before restoring its brands.
  if (!Object.isFrozen(descriptor)) fail("transferred compiler descriptor must be frozen");
  authenticatedCompilerDescriptors.add(descriptor);
  return descriptor;
}


function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
  }
  return value;
}

export function projectConvexWasmModuleGraphCompilerDescriptorFromCapabilityDescriptor(
  descriptor,
  description
) {
  if (!isNormalizedConvexWasmCapabilityChunkApplicationDescriptor(descriptor)) {
    fail(`${description} must be a validator-authenticated capability chunk descriptor`);
  }
  const units = Object.freeze(
    descriptor.units.map(({ javascriptSource: _javascriptSource, ...unit }) => Object.freeze(unit))
  );
  const projected = Object.freeze({
    applicationIdentity: descriptor.applicationIdentity,
    chunkUnitsIdentity: descriptor.chunkUnitsIdentity,
    entries: descriptor.entries,
    identitySha256: descriptor.identitySha256,
    initialization: descriptor.initialization,
    kind: convexWasmModuleGraphCompilerDescriptorKind,
    nativeApplicationDescriptorKind: descriptor.kind,
    nativeDescriptor: descriptor.nativeDescriptor,
    schemaVersion: convexWasmModuleGraphCompilerDescriptorSchemaVersion,
    units,
  });
  authenticatedCompilerDescriptors.add(projected);
  return projected;
}

export function authenticateConvexWasmModuleGraphCompilerDescriptor(value, description) {
  if (authenticatedCompilerDescriptors.has(value)) return value;
  const rawDescriptor = requireExactPlainObject(
    value,
    [
      "applicationIdentity",
      "chunkUnitsIdentity",
      "entries",
      "identitySha256",
      "initialization",
      "kind",
      "nativeApplicationDescriptorKind",
      "nativeDescriptor",
      "schemaVersion",
      "units",
    ],
    description
  );
  // Own one canonical JSON snapshot before validation. Every descriptor subtree below now has
  // plain data properties and canonical key order, so direct serialization preserves the digest
  // without repeating generic normalization. Derived expected identities still use canonicalJson.
  const descriptor = normalizeJson(rawDescriptor, `${description} authenticated descriptor`);
  if (
    descriptor.kind !== convexWasmModuleGraphCompilerDescriptorKind ||
    descriptor.schemaVersion !== convexWasmModuleGraphCompilerDescriptorSchemaVersion ||
    descriptor.nativeApplicationDescriptorKind !==
      convexWasmOfficialOutputChunkNativeApplicationDescriptorKind
  ) {
    fail(`${description} kind or schema version is unsupported`);
  }
  const identitySha256 = requireSha256(
    descriptor.identitySha256,
    `${description} identity SHA-256`
  );
  const initialization = requireExactPlainObject(
    descriptor.initialization,
    ["chunkSlotCount", "entryPublicationUnitSlots", "kind", "namespaceSlotCount"],
    `${description} initialization`
  );
  if (
    initialization.kind !== "closed-numbered-chunk-slots-with-per-entry-publication-v1" ||
    !Number.isSafeInteger(initialization.chunkSlotCount) ||
    initialization.chunkSlotCount < 1 ||
    !Number.isSafeInteger(initialization.namespaceSlotCount) ||
    initialization.namespaceSlotCount !== initialization.chunkSlotCount ||
    !Array.isArray(initialization.entryPublicationUnitSlots)
  ) {
    fail(`${description} initialization is invalid`);
  }
  if (
    !Array.isArray(descriptor.entries) ||
    descriptor.entries.length === 0 ||
    descriptor.entries.length !== initialization.entryPublicationUnitSlots.length
  ) {
    fail(`${description} entries are invalid`);
  }
  if (
    !Array.isArray(descriptor.units) ||
    descriptor.units.length < 2 ||
    descriptor.units.length !==
      initialization.namespaceSlotCount + initialization.entryPublicationUnitSlots.length
  ) {
    fail(`${description} units are invalid`);
  }
  if (
    initialization.entryPublicationUnitSlots.some(
      (unitSlot, handoffSlot) =>
        !Number.isSafeInteger(unitSlot) ||
        unitSlot !== initialization.namespaceSlotCount + handoffSlot
    )
  ) {
    fail(`${description} entry-publication slots are invalid`);
  }
  const entries = descriptor.entries.map((rawEntry, index) => {
    const entry = requireExactPlainObject(
      rawEntry,
      [
        "dependencyGraphSha256",
        "entryModulePath",
        "entryPath",
        "entryPublicationUnitSlot",
        "entrySlot",
        "handoffSlot",
        "modulePath",
        "routes",
      ],
      `${description} entry ${index}`
    );
    if (
      entry.handoffSlot !== index ||
      !Number.isSafeInteger(entry.entrySlot) ||
      entry.entrySlot < 0 ||
      entry.entrySlot >= initialization.namespaceSlotCount ||
      !Number.isSafeInteger(entry.entryPublicationUnitSlot) ||
      entry.entryPublicationUnitSlot !== initialization.entryPublicationUnitSlots[index]
    ) {
      fail(`${description} entry ${index} slots are invalid`);
    }
    if (!Array.isArray(entry.routes) || entry.routes.length === 0) {
      fail(`${description} entry ${index} routes are invalid`);
    }
    const routes = entry.routes.map((rawRoute, routeIndex) => {
      const route = requireExactPlainObject(
        rawRoute,
        ["exportName", "udfKind", "visibility"],
        `${description} entry ${index} route ${routeIndex}`
      );
      return {
        exportName: requireManifestString(
          route.exportName,
          `${description} entry ${index} route ${routeIndex} export name`,
          MAX_MANIFEST_IDENTIFIER_BYTES,
          false
        ),
        udfKind: requireEnum(
          route.udfKind,
          new Set(["mutation", "query"]),
          `${description} entry ${index} route ${routeIndex} UDF kind`
        ),
        visibility: requireEnum(
          route.visibility,
          new Set(["internal", "public"]),
          `${description} entry ${index} route ${routeIndex} visibility`
        ),
      };
    });
    if (
      routes.some(({ exportName }) => !IDENTIFIER_PATTERN.test(exportName)) ||
      new Set(routes.map(({ exportName }) => exportName)).size !== routes.length
    ) {
      fail(`${description} entry ${index} routes are invalid`);
    }
    return {
      dependencyGraphSha256: requireSha256(
        entry.dependencyGraphSha256,
        `${description} entry ${index} dependency graph SHA-256`
      ),
      entryModulePath: requireManifestString(
        entry.entryModulePath,
        `${description} entry ${index} module path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      entryPath: requireManifestString(
        entry.entryPath,
        `${description} entry ${index} path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      entryPublicationUnitSlot: entry.entryPublicationUnitSlot,
      entrySlot: entry.entrySlot,
      handoffSlot: index,
      modulePath: requireManifestString(
        entry.modulePath,
        `${description} entry ${index} source path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      routes,
    };
  });
  if (
    entries.some((entry, index) => index > 0 && entries[index - 1].entryPath >= entry.entryPath)
  ) {
    fail(`${description} entries are unordered`);
  }
  const nativeDescriptor = requireExactPlainObject(
    descriptor.nativeDescriptor,
    ["destruction", "initialization", "kind", "publication", "slots"],
    `${description} native descriptor`
  );
  if (
    nativeDescriptor.kind !== "convex-wasm-official-output-chunk-native-descriptor-abi-v3" ||
    nativeDescriptor.destruction !== "destroy-store-on-any-initialization-failure" ||
    nativeDescriptor.initialization !==
      "recursive-closed-literal-require-with-provisional-cjs-namespaces" ||
    nativeDescriptor.publication !==
      "authenticated-selected-entry-wrapper-validation-after-selected-closure-initialization" ||
    nativeDescriptor.slots !== "closed-numbered-namespace-slots-with-per-entry-publication-units"
  ) {
    fail(`${description} native descriptor is invalid`);
  }
  const applicationIdentity = requireExactPlainObject(
    descriptor.applicationIdentity,
    [
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
    ],
    `${description} application identity`
  );
  const applicationIdentitySha256 = requireSha256(
    applicationIdentity.sha256,
    `${description} application identity SHA-256`
  );
  const { sha256: _applicationIdentitySha256, ...applicationIdentityPayload } = applicationIdentity;
  if (
    applicationIdentitySha256 !==
    createHash("sha256").update(JSON.stringify(applicationIdentityPayload)).digest("hex")
  ) {
    fail(`${description} application identity changed`);
  }
  const applicationDependencyGraphSha256 = requireSha256(
    applicationIdentity.dependencyGraphSha256,
    `${description} application dependency graph SHA-256`
  );
  requireSha256(
    applicationIdentity.sourceEnvelopeSha256,
    `${description} application source-envelope SHA-256`
  );
  if (
    applicationIdentity.kind !== convexWasmOfficialOutputChunkApplicationUnitKind ||
    applicationDependencyGraphSha256 !==
      fingerprintJson({
        domain: "convex-wasm-official-output-cohort-dependency-graph-v1",
        entries: entries.map(({ dependencyGraphSha256, entryPath }) => ({
          dependencyGraphSha256,
          entryPath,
        })),
      }) ||
    applicationIdentity.unitCount !== descriptor.units.length ||
    identitySha256 !== applicationIdentitySha256 ||
    JSON.stringify(applicationIdentity.entries) !== canonicalJson(entries) ||
    JSON.stringify(applicationIdentity.initialization) !== JSON.stringify(initialization) ||
    JSON.stringify(applicationIdentity.nativeDescriptor) !==
      JSON.stringify(descriptor.nativeDescriptor)
  ) {
    fail(`${description} application identity does not match its descriptor`);
  }
  const chunkUnitsIdentity = requireExactPlainObject(
    descriptor.chunkUnitsIdentity,
    ["entries", "esbuild", "initialization", "kind", "sourceEnvelopeSha256", "units", "sha256"],
    `${description} chunk-units identity`
  );
  const chunkUnitsIdentitySha256 = requireSha256(
    chunkUnitsIdentity.sha256,
    `${description} chunk-units identity SHA-256`
  );
  const { sha256: _chunkUnitsIdentitySha256, ...chunkUnitsIdentityPayload } = chunkUnitsIdentity;
  if (
    chunkUnitsIdentitySha256 !==
    createHash("sha256").update(JSON.stringify(chunkUnitsIdentityPayload)).digest("hex")
  ) {
    fail(`${description} chunk-units identity changed`);
  }
  const chunkEsbuild = requireExactPlainObject(
    chunkUnitsIdentity.esbuild,
    ["version"],
    `${description} chunk-units esbuild identity`
  );
  requireManifestString(
    chunkEsbuild.version,
    `${description} chunk-units esbuild version`,
    MAX_MANIFEST_IDENTIFIER_BYTES,
    false
  );
  const chunkInitialization = requireExactPlainObject(
    chunkUnitsIdentity.initialization,
    ["dynamicImport", "kind", "publication"],
    `${description} chunk-units initialization`
  );
  requireSha256(
    chunkUnitsIdentity.sourceEnvelopeSha256,
    `${description} chunk-units source-envelope SHA-256`
  );
  const expectedChunkEntries = entries.map(
    ({ dependencyGraphSha256, entryModulePath, entryPath, entrySlot, modulePath, routes }) => ({
      dependencyGraphSha256,
      entryModulePath,
      entryPath,
      entrySlot,
      modulePath,
      routes,
    })
  );
  if (
    chunkUnitsIdentity.kind !== convexWasmOfficialOutputChunkUnitsKind ||
    chunkInitialization.dynamicImport !== "literal-require-after-promise-microtask" ||
    chunkInitialization.kind !== "closed-numbered-namespace-slots-v1" ||
    chunkInitialization.publication !==
      "selected-entry-namespaces-after-selected-closure-initialization" ||
    JSON.stringify(chunkUnitsIdentity.entries) !== canonicalJson(expectedChunkEntries)
  ) {
    fail(`${description} chunk-units identity is invalid`);
  }
  if (
    !Object.hasOwn(applicationIdentity, "chunkUnits") ||
    JSON.stringify(applicationIdentity.chunkUnits) !==
      canonicalJson({
        kind: convexWasmOfficialOutputChunkUnitsKind,
        sha256: chunkUnitsIdentitySha256,
      }) ||
    applicationIdentity.sourceEnvelopeSha256 !== chunkUnitsIdentity.sourceEnvelopeSha256
  ) {
    fail(`${description} application and chunk-units identities disagree`);
  }
  if (
    !Array.isArray(applicationIdentity.units) ||
    applicationIdentity.units.length !== descriptor.units.length ||
    !Array.isArray(chunkUnitsIdentity.units) ||
    chunkUnitsIdentity.units.length !== initialization.namespaceSlotCount
  ) {
    fail(`${description} unit identities are incomplete`);
  }
  const canonicalEntryPathBySlot = new Map();
  for (const entry of entries) {
    if (canonicalEntryPathBySlot.has(entry.entrySlot)) {
      fail(`${description} entries reuse an entry module`);
    }
    canonicalEntryPathBySlot.set(entry.entrySlot, entry.entryPath);
  }
  descriptor.units.forEach((unit, index) => {
    const normalized = requireExactPlainObject(
      unit,
      [
        "applicationUnitSlot",
        "chunkSlot",
        "dependencies",
        "entryPublication",
        "entrySymbol",
        "exportedUnitName",
        "identitySha256",
        "javascript",
        "kind",
        "module",
        "nativeSymbolLocator",
        "nativeSymbolIdentitySha256",
        "publicationHandoffSlot",
        "reusableCodeIdentitySha256",
        "transform",
      ],
      `${description} unit ${index}`
    );
    const entryPublication = requireBoolean(
      normalized.entryPublication,
      `${description} unit ${index} entry-publication flag`
    );
    const dependencies = normalizeConvexWasmOfficialOutputChunkDependencies({
      dependencies: normalized.dependencies,
      namespaceSlotCount: initialization.namespaceSlotCount,
      unitDescription: `${description} unit ${index}`,
    });
    if (
      normalized.applicationUnitSlot !== index ||
      !Number.isSafeInteger(normalized.applicationUnitSlot) ||
      (entryPublication
        ? normalized.kind !== convexWasmOfficialOutputChunkEntryPublicationUnitKind ||
          normalized.chunkSlot !== -1 ||
          index < initialization.namespaceSlotCount
        : normalized.kind !== convexWasmOfficialOutputChunkUnitKind ||
          normalized.chunkSlot !== index ||
          index >= initialization.namespaceSlotCount) ||
      (entryPublication && dependencies.length !== 0) ||
      !Number.isSafeInteger(normalized.publicationHandoffSlot) ||
      (entryPublication
        ? normalized.publicationHandoffSlot !== index - initialization.namespaceSlotCount ||
          normalized.publicationHandoffSlot >= initialization.entryPublicationUnitSlots.length
        : normalized.publicationHandoffSlot !== -1)
    ) {
      fail(`${description} unit ${index} topology is invalid`);
    }
    const javascript = requireExactPlainObject(
      normalized.javascript,
      ["sha256", "size"],
      `${description} unit ${index} JavaScript identity`
    );
    requireSha256(javascript.sha256, `${description} unit ${index} JavaScript SHA-256`);
    requirePositiveInteger(javascript.size, `${description} unit ${index} JavaScript size`);
    const nativeSymbolIdentitySha256 = requireSha256(
      normalized.nativeSymbolIdentitySha256,
      `${description} unit ${index} native symbol identity SHA-256`
    );
    const entrySymbol = requireManifestString(
      normalized.entrySymbol,
      `${description} unit ${index} entry symbol`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    const exportedUnitName = requireManifestString(
      normalized.exportedUnitName,
      `${description} unit ${index} exported unit name`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    const module = entryPublication
      ? normalized.module
      : normalizeConvexWasmOfficialOutputChunkModuleIdentity(
          normalized.module,
          `${description} unit ${index} module identity`
        );
    const transform = normalized.transform;
    if (
      entryPublication
        ? module !== null || transform !== null
        : JSON.stringify(transform) !== canonicalJson(convexWasmOfficialOutputChunkTransform)
    ) {
      fail(`${description} unit ${index} identity projection is invalid`);
    }
    const nativeSymbolLocator = entryPublication
      ? normalized.nativeSymbolLocator
      : convexWasmOfficialOutputChunkNativeSymbolLocator(normalized.nativeSymbolLocator);
    if (
      entryPublication
        ? nativeSymbolLocator !== null
        : nativeSymbolLocator.sourceMembershipSha256 !== module.sourceMembershipSha256 ||
          nativeSymbolLocator.canonicalEntryPath !==
            (canonicalEntryPathBySlot.get(normalized.chunkSlot) ?? null)
    ) {
      fail(`${description} unit ${index} native symbol locator is invalid`);
    }
    const expectedNativeSymbolIdentitySha256 = convexWasmOfficialOutputNativeSymbolIdentitySha256({
      entryPath: entryPublication
        ? entries[normalized.publicationHandoffSlot]?.entryPath
        : undefined,
      entryPublication,
      nativeSymbolLocator,
    });
    if (nativeSymbolIdentitySha256 !== expectedNativeSymbolIdentitySha256) {
      fail(`${description} unit ${index} native symbol identity changed`);
    }
    if (
      !IDENTIFIER_PATTERN.test(entrySymbol) ||
      !IDENTIFIER_PATTERN.test(exportedUnitName) ||
      entrySymbol !== `sh_export_convex_wasm_official_chunk_${nativeSymbolIdentitySha256}` ||
      exportedUnitName !== `convex_wasm_official_chunk_${nativeSymbolIdentitySha256}`
    ) {
      fail(`${description} unit ${index} has an invalid native symbol`);
    }
    const identity = entryPublication
      ? {
          entry: (({ entryPath, entrySlot, handoffSlot, routes }) => ({
            entryPath,
            entrySlot,
            handoffSlot,
            routes,
          }))(entries[normalized.publicationHandoffSlot]),
          javascript,
          kind: convexWasmOfficialOutputChunkEntryPublicationUnitKind,
          slot: index,
        }
      : {
          dependencies,
          javascript,
          kind: convexWasmOfficialOutputChunkUnitKind,
          module,
          nativeSymbolLocator,
          slot: normalized.chunkSlot,
          transform,
        };
    const expected = { ...identity, sha256: fingerprintJson(identity) };
    // Both persisted projections bind the same derived chunk identity. Serialize it once
    // here instead of serializing all expected chunk identities again after this loop.
    const expectedCanonical = canonicalJson(expected);
    if (
      requireSha256(normalized.identitySha256, `${description} unit ${index} identity SHA-256`) !==
        expected.sha256 ||
      JSON.stringify(applicationIdentity.units[index]) !== expectedCanonical
    ) {
      fail(`${description} unit ${index} identity changed`);
    }
    if (
      !entryPublication &&
      JSON.stringify(chunkUnitsIdentity.units[index]) !== expectedCanonical
    ) {
      fail(`${description} unit identities are incomplete`);
    }
  });
  const nativeSymbolIdentities = new Set(
    descriptor.units.map(({ nativeSymbolIdentitySha256 }) => nativeSymbolIdentitySha256)
  );
  if (nativeSymbolIdentities.size !== descriptor.units.length) {
    fail(`${description} reuses a native symbol identity`);
  }
  validateConvexWasmOfficialOutputChunkDependencyTopology({
    chunkSlotCount: initialization.namespaceSlotCount,
    description,
    units: descriptor.units,
  });
  if (
    entries.some((entry) => descriptor.units[entry.entrySlot].module.path !== entry.entryModulePath)
  ) {
    fail(`${description} entries do not bind their entry modules`);
  }
  if (
    entries.some(
      (entry) =>
        descriptor.units[entry.entryPublicationUnitSlot].entryPublication !== true ||
        descriptor.units[entry.entryPublicationUnitSlot].publicationHandoffSlot !==
          entry.handoffSlot
    )
  ) {
    fail(`${description} entries do not bind their publication units`);
  }
  const reusableCodeIdentitySha256s = deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
    chunkSlotCount: initialization.namespaceSlotCount,
    units: descriptor.units,
  });
  for (const [index, unit] of descriptor.units.entries()) {
    if (
      requireSha256(
        unit.reusableCodeIdentitySha256,
        `${description} unit ${index} reusable-code identity SHA-256`
      ) !== reusableCodeIdentitySha256s[index]
    ) {
      fail(`${description} unit ${index} reusable-code identity changed`);
    }
  }
  const authenticated = freezeAuthenticatedJsonTree(descriptor);
  authenticatedCompilerDescriptors.add(authenticated);
  return authenticated;
}
