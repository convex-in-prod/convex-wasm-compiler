import { createHash } from "node:crypto";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s } from "./convex-wasm-official-output-chunk-contract.mjs";
import {
  retainProjectedConvexWasmOfficialOutputChunkJavascriptLoader,
  retainProjectedConvexWasmOfficialOutputChunkNativeApplicationDescriptor,
} from "./convex-wasm-official-output-chunk-projection-provenance.mjs";
import {
  authenticateConvexWasmOfficialOutputChunkUnits,
  convexWasmOfficialOutputChunkUnitKind,
  convexWasmOfficialOutputChunkUnitsKind,
  createConvexWasmOfficialOutputChunkUnitInitializer,
  isConvexWasmOfficialOutputCompactChunkUnit,
  materializeConvexWasmOfficialOutputCompactChunkUnitJavascript,
} from "./convex-wasm-official-output-chunk-unit.mjs";
import { convexWasmOfficialOutputNativeSymbolIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";

export const convexWasmOfficialOutputChunkApplicationUnitKind =
  "convex-wasm-official-output-chunk-application-unit-v3";
export const convexWasmOfficialOutputChunkNativeApplicationDescriptorKind =
  "convex-wasm-official-output-chunk-native-application-descriptor-v3";
export const convexWasmOfficialOutputChunkApplicationMaximumUnits = 1024;

export const convexWasmOfficialOutputChunkNativeDescriptorAbi = Object.freeze({
  destruction: "destroy-store-on-any-initialization-failure",
  initialization: "recursive-closed-literal-require-with-provisional-cjs-namespaces",
  kind: "convex-wasm-official-output-chunk-native-descriptor-abi-v3",
  publication:
    "authenticated-selected-entry-wrapper-validation-after-selected-closure-initialization",
  slots: "closed-numbered-namespace-slots-with-per-entry-publication-units",
});

const entryPublicationUnitKind = "convex-wasm-official-output-chunk-entry-publication-unit-v2";
const authenticatedChunkApplicationUnits = new WeakSet();
const chunkLocalProfilesByApplicationUnit = new WeakMap();
const nativeDescriptorsByApplicationUnit = new WeakMap();

function fail(message) {
  throw new Error(`Convex Wasm official-output chunk application unit: ${message}`);
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

function requireArray(value, description) {
  if (!Array.isArray(value)) fail(`${description} must be an array`);
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

function canonicalEntries(chunkUnits) {
  return chunkUnits.entries.map((entry, handoffSlot) => ({
    dependencyGraphSha256: entry.dependencyGraphSha256,
    entryModulePath: entry.entryModulePath,
    entryPath: entry.entryPath,
    entrySlot: entry.entrySlot,
    handoffSlot,
    modulePath: entry.modulePath,
    routes: entry.routes.map(({ exportName, udfKind, visibility }) => ({
      exportName,
      udfKind,
      visibility,
    })),
  }));
}

function applicationEntries(chunkUnits) {
  const publicationUnitSlot = chunkUnits.units.length;
  return canonicalEntries(chunkUnits).map(
    (
      {
        dependencyGraphSha256,
        entryModulePath,
        entryPath,
        entrySlot,
        handoffSlot,
        modulePath,
        routes,
      },
      entryIndex
    ) => ({
      dependencyGraphSha256,
      entryModulePath,
      entryPath,
      entryPublicationUnitSlot: publicationUnitSlot + entryIndex,
      entrySlot,
      handoffSlot,
      modulePath,
      routes,
    })
  );
}

function renderWrapperValidation(route, handoffSlot, routeIndex) {
  const wrapper = `__convexWasmOfficialEntryWrapper${String(handoffSlot)}_${String(routeIndex)}`;
  const kindProperty = route.udfKind === "query" ? "isQuery" : "isMutation";
  const otherKindProperty = route.udfKind === "query" ? "isMutation" : "isQuery";
  const visibilityProperty = route.visibility === "public" ? "isPublic" : "isInternal";
  const otherVisibilityProperty = route.visibility === "public" ? "isInternal" : "isPublic";
  const invocationMethod = route.udfKind === "query" ? "invokeQuery" : "invokeMutation";
  const error = `Official Convex ${route.udfKind}/${route.visibility} registration wrapper ${route.entryPath}:${route.exportName} is invalid`;
  return `  const ${wrapper} = __convexWasmOfficialEntry[${JSON.stringify(route.exportName)}];
  if (
    typeof ${wrapper} !== "function" ||
    ${wrapper}.${kindProperty} !== true ||
    ${wrapper}.${otherKindProperty} !== undefined ||
    ${wrapper}.isAction !== undefined ||
    ${wrapper}.${visibilityProperty} !== true ||
    ${wrapper}.${otherVisibilityProperty} !== undefined ||
    typeof ${wrapper}.${invocationMethod} !== "function" ||
    typeof ${wrapper}.exportArgs !== "function" ||
    typeof ${wrapper}.exportReturns !== "function" ||
    typeof ${wrapper}._handler !== "function" ||
    typeof ${wrapper}.exportArgs() !== "string" ||
    typeof ${wrapper}.exportReturns() !== "string"
  ) {
    throw new Error(${JSON.stringify(error)});
  }`;
}

function renderEntryPublicationJavascript(entry) {
  const bindings =
    `  const __convexWasmOfficialEntry = __convexWasmOfficialChunkReadNamespace(${String(entry.entrySlot)});\n` +
    `  if (__convexWasmOfficialEntry === null || typeof __convexWasmOfficialEntry !== "object") {\n` +
    `    throw new Error(${JSON.stringify(`Official Convex deployment entry namespace ${String(entry.handoffSlot)} is invalid`)});\n` +
    "  }";
  const validations = entry.routes
    .map((route, routeIndex) => renderWrapperValidation(route, entry.handoffSlot, routeIndex))
    .join("\n");
  const publication = `  __convexWasmOfficialChunkPublishEntry(${String(entry.handoffSlot)}, __convexWasmOfficialEntry);`;
  return `(function(
  __convexWasmOfficialChunkReadNamespace,
  __convexWasmOfficialChunkPublishEntry,
  __convexWasmOfficialChunkReportThrown
) {
"use strict";
try {
  if (typeof __convexWasmOfficialChunkReadNamespace !== "function") {
    throw new Error("Convex Wasm official chunk namespace reader is invalid");
  }
  if (typeof __convexWasmOfficialChunkPublishEntry !== "function") {
    throw new Error("Convex Wasm official chunk entry publisher is invalid");
  }
  if (typeof __convexWasmOfficialChunkReportThrown !== "function") {
    throw new Error("Convex Wasm official chunk error reporter is invalid");
  }
${bindings}
${validations}
${publication}
} catch (__convexWasmOfficialChunkPublicationError) {
  __convexWasmOfficialChunkReportThrown(__convexWasmOfficialChunkPublicationError);
  throw __convexWasmOfficialChunkPublicationError;
}
})(
  globalThis.__convexWasmOfficialChunkReadNamespace,
  globalThis.__convexWasmOfficialChunkPublishEntry,
  globalThis.__convexWasmOfficialChunkReportThrown
);
`;
}

function entryPublicationDescriptor(entry, applicationUnitSlot) {
  const javascript = renderEntryPublicationJavascript(entry);
  const identity = {
    entry: Object.freeze(
      (({ entryPath, entrySlot, handoffSlot, routes }) => ({
        entryPath,
        entrySlot,
        handoffSlot,
        routes,
      }))(entry)
    ),
    javascript: Object.freeze({
      sha256: sha256(javascript),
      size: Buffer.byteLength(javascript),
    }),
    kind: entryPublicationUnitKind,
    slot: applicationUnitSlot,
  };
  return Object.freeze({
    identity: Object.freeze({ ...identity, sha256: fingerprintJson(identity) }),
    javascript,
    kind: entryPublicationUnitKind,
  });
}

function nativeUnitDescriptor(
  unit,
  applicationUnitSlot,
  publicationHandoffSlot,
  reusableCodeIdentitySha256,
  nativeSymbolIdentitySha256
) {
  const isChunk = unit.kind === convexWasmOfficialOutputChunkUnitKind;
  const identity = unit.identity;
  return {
    applicationUnitSlot,
    chunkSlot: isChunk ? identity.slot : -1,
    dependencies: isChunk ? identity.dependencies : [],
    entryPublication: !isChunk,
    entrySymbol: `sh_export_convex_wasm_official_chunk_${nativeSymbolIdentitySha256}`,
    exportedUnitName: `convex_wasm_official_chunk_${nativeSymbolIdentitySha256}`,
    identitySha256: identity.sha256,
    javascript: identity.javascript,
    ...(unit.javascript === undefined ? {} : { javascriptSource: unit.javascript }),
    kind: unit.kind,
    module: isChunk ? identity.module : null,
    nativeSymbolIdentitySha256,
    nativeSymbolLocator: isChunk ? identity.nativeSymbolLocator : null,
    publicationHandoffSlot,
    reusableCodeIdentitySha256,
    transform: isChunk ? identity.transform : null,
  };
}

export function authenticateConvexWasmOfficialOutputChunkApplicationUnit(applicationUnit) {
  if (authenticatedChunkApplicationUnits.has(applicationUnit)) return applicationUnit;
  const unit = requireExactKeys(
    applicationUnit,
    new Set(["chunkUnits", "identity", "kind", "units"]),
    "official-output chunk application unit"
  );
  if (unit.kind !== convexWasmOfficialOutputChunkApplicationUnitKind) {
    fail("official-output chunk application unit kind is unsupported");
  }
  const chunkUnits = authenticateConvexWasmOfficialOutputChunkUnits(unit.chunkUnits);
  const units = requireArray(unit.units, "official-output chunk application units");
  if (
    units.length < 2 ||
    units.length > convexWasmOfficialOutputChunkApplicationMaximumUnits ||
    units.length !== chunkUnits.units.length + chunkUnits.entries.length
  ) {
    fail("official-output chunk application unit count is invalid");
  }
  const entries = Object.freeze(
    applicationEntries(chunkUnits).map((entry) =>
      Object.freeze({
        ...entry,
        routes: Object.freeze(entry.routes.map((route) => Object.freeze(route))),
      })
    )
  );
  const expectedUnits = Object.freeze([
    ...chunkUnits.units,
    ...entries.map((entry) => entryPublicationDescriptor(entry, entry.entryPublicationUnitSlot)),
  ]);
  const chunkDescriptors = units.slice(0, chunkUnits.units.length);
  for (const [index, descriptor] of chunkDescriptors.entries()) {
    const normalized = requireExactKeys(
      descriptor,
      new Set(["identity", "javascript", "kind"]),
      `official-output chunk application chunk ${index}`
    );
    if (canonicalJson(normalized) !== canonicalJson(chunkUnits.units[index])) {
      fail(`official-output chunk application chunk ${index} disagrees with its exact chunk unit`);
    }
  }
  const identity = requireExactKeys(
    unit.identity,
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
    "official-output chunk application identity"
  );
  const { sha256: identitySha256 } = identity;
  const expectedDependencyGraphSha256 = fingerprintJson({
    domain: "convex-wasm-official-output-cohort-dependency-graph-v1",
    entries: entries.map(({ dependencyGraphSha256, entryPath }) => ({
      dependencyGraphSha256,
      entryPath,
    })),
  });
  const initialization = Object.freeze({
    chunkSlotCount: chunkUnits.units.length,
    entryPublicationUnitSlots: Object.freeze(
      entries.map(({ entryPublicationUnitSlot }) => entryPublicationUnitSlot)
    ),
    kind: "closed-numbered-chunk-slots-with-per-entry-publication-v1",
    namespaceSlotCount: chunkUnits.units.length,
  });
  const identityPayload = {
    chunkUnits: Object.freeze({
      kind: convexWasmOfficialOutputChunkUnitsKind,
      sha256: chunkUnits.identity.sha256,
    }),
    dependencyGraphSha256: expectedDependencyGraphSha256,
    entries,
    initialization,
    kind: convexWasmOfficialOutputChunkApplicationUnitKind,
    nativeDescriptor: convexWasmOfficialOutputChunkNativeDescriptorAbi,
    sourceEnvelopeSha256: chunkUnits.identity.sourceEnvelopeSha256,
    unitCount: expectedUnits.length,
    units: Object.freeze(expectedUnits.map(({ identity: unitIdentity }) => unitIdentity)),
  };
  const normalizedIdentity = Object.freeze({
    ...identityPayload,
    sha256: fingerprintJson(identityPayload),
  });
  if (
    identitySha256 !== normalizedIdentity.sha256 ||
    canonicalJson(identity) !== canonicalJson(normalizedIdentity)
  ) {
    fail("official-output chunk application identity is invalid");
  }
  for (const entry of entries) {
    const publicationUnit = requireExactKeys(
      units[entry.entryPublicationUnitSlot],
      new Set(["identity", "javascript", "kind"]),
      `official-output chunk application entry ${entry.handoffSlot} publication unit`
    );
    const expectedPublication = expectedUnits[entry.entryPublicationUnitSlot];
    if (canonicalJson(publicationUnit) !== canonicalJson(expectedPublication)) {
      fail("official-output chunk application entry publication unit is invalid");
    }
  }
  if (
    canonicalJson(normalizedIdentity.units) !==
    canonicalJson(units.map(({ identity: unitIdentity }) => unitIdentity))
  ) {
    fail("official-output chunk application unit identities are invalid");
  }
  const authenticated = Object.freeze({
    chunkUnits,
    identity: normalizedIdentity,
    kind: unit.kind,
    units: expectedUnits,
  });
  authenticatedChunkApplicationUnits.add(authenticated);
  return authenticated;
}

export function buildConvexWasmOfficialOutputChunkApplicationUnit({ chunkUnits }) {
  const authenticatedChunkUnits = authenticateConvexWasmOfficialOutputChunkUnits(chunkUnits);
  const entries = Object.freeze(
    applicationEntries(authenticatedChunkUnits).map((entry) =>
      Object.freeze({
        ...entry,
        routes: Object.freeze(entry.routes.map((route) => Object.freeze(route))),
      })
    )
  );
  const units = Object.freeze([
    ...authenticatedChunkUnits.units,
    ...entries.map((entry) => entryPublicationDescriptor(entry, entry.entryPublicationUnitSlot)),
  ]);
  const identityPayload = {
    chunkUnits: Object.freeze({
      kind: authenticatedChunkUnits.kind,
      sha256: authenticatedChunkUnits.identity.sha256,
    }),
    dependencyGraphSha256: fingerprintJson({
      domain: "convex-wasm-official-output-cohort-dependency-graph-v1",
      entries: entries.map(({ dependencyGraphSha256, entryPath }) => ({
        dependencyGraphSha256,
        entryPath,
      })),
    }),
    entries,
    initialization: Object.freeze({
      chunkSlotCount: authenticatedChunkUnits.units.length,
      entryPublicationUnitSlots: Object.freeze(
        entries.map(({ entryPublicationUnitSlot }) => entryPublicationUnitSlot)
      ),
      kind: "closed-numbered-chunk-slots-with-per-entry-publication-v1",
      namespaceSlotCount: authenticatedChunkUnits.units.length,
    }),
    kind: convexWasmOfficialOutputChunkApplicationUnitKind,
    nativeDescriptor: convexWasmOfficialOutputChunkNativeDescriptorAbi,
    sourceEnvelopeSha256: authenticatedChunkUnits.identity.sourceEnvelopeSha256,
    unitCount: units.length,
    units: Object.freeze(units.map(({ identity: unitIdentity }) => unitIdentity)),
  };
  const authenticated = Object.freeze({
    chunkUnits: authenticatedChunkUnits,
    identity: Object.freeze({ ...identityPayload, sha256: fingerprintJson(identityPayload) }),
    kind: convexWasmOfficialOutputChunkApplicationUnitKind,
    units,
  });
  authenticatedChunkApplicationUnits.add(authenticated);
  return authenticated;
}

export function projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor(applicationUnit) {
  const unit = authenticateConvexWasmOfficialOutputChunkApplicationUnit(applicationUnit);
  const cached = nativeDescriptorsByApplicationUnit.get(unit);
  if (cached !== undefined) return cached;
  const reusableCodeIdentitySha256ByUnit =
    deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
      chunkSlotCount: unit.identity.initialization.chunkSlotCount,
      units: unit.units.map((physicalUnit, applicationUnitSlot) => {
        const entryPublication = physicalUnit.kind === entryPublicationUnitKind;
        return {
          applicationUnitSlot,
          dependencies: entryPublication ? [] : physicalUnit.identity.dependencies,
          entryPublication,
          javascript: physicalUnit.identity.javascript,
          kind: physicalUnit.kind,
          module: entryPublication ? null : physicalUnit.identity.module,
          nativeSymbolLocator: entryPublication ? null : physicalUnit.identity.nativeSymbolLocator,
          transform: entryPublication ? null : physicalUnit.identity.transform,
        };
      }),
    });
  const units = unit.units.map((physicalUnit, applicationUnitSlot) =>
    nativeUnitDescriptor(
      physicalUnit,
      applicationUnitSlot,
      applicationUnitSlot < unit.identity.initialization.chunkSlotCount
        ? -1
        : applicationUnitSlot - unit.identity.initialization.chunkSlotCount,
      reusableCodeIdentitySha256ByUnit[applicationUnitSlot],
      convexWasmOfficialOutputNativeSymbolIdentitySha256({
        entryPath:
          applicationUnitSlot < unit.identity.initialization.chunkSlotCount
            ? undefined
            : unit.identity.entries[
                applicationUnitSlot - unit.identity.initialization.chunkSlotCount
              ].entryPath,
        entryPublication: applicationUnitSlot >= unit.identity.initialization.chunkSlotCount,
        nativeSymbolLocator:
          applicationUnitSlot < unit.identity.initialization.chunkSlotCount
            ? physicalUnit.identity.nativeSymbolLocator
            : undefined,
      })
    )
  );
  const nativeSymbolIdentities = new Set();
  for (const [index, descriptorUnit] of units.entries()) {
    if (nativeSymbolIdentities.has(descriptorUnit.nativeSymbolIdentitySha256)) {
      fail(`official-output chunk native descriptor unit ${index} reuses a native symbol identity`);
    }
    nativeSymbolIdentities.add(descriptorUnit.nativeSymbolIdentitySha256);
  }
  const descriptor = {
    applicationIdentity: unit.identity,
    chunkUnitsIdentity: unit.chunkUnits.identity,
    entries: unit.identity.entries,
    identitySha256: unit.identity.sha256,
    initialization: unit.identity.initialization,
    kind: convexWasmOfficialOutputChunkNativeApplicationDescriptorKind,
    nativeDescriptor: unit.identity.nativeDescriptor,
    units,
  };
  if (units.length !== unit.identity.unitCount) {
    fail("official-output chunk native descriptor is invalid");
  }
  const projected = Object.freeze({
    ...descriptor,
    units: Object.freeze(
      units.map((descriptorUnit) =>
        Object.freeze({
          ...descriptorUnit,
          dependencies: Object.freeze(descriptorUnit.dependencies),
          javascript: Object.freeze(descriptorUnit.javascript),
        })
      )
    ),
  });
  retainProjectedConvexWasmOfficialOutputChunkNativeApplicationDescriptor(projected);
  for (let slot = 0; slot < unit.chunkUnits.units.length; slot += 1) {
    const chunkUnit = unit.chunkUnits.units[slot];
    if (!isConvexWasmOfficialOutputCompactChunkUnit(chunkUnit)) continue;
    retainProjectedConvexWasmOfficialOutputChunkJavascriptLoader(
      projected,
      projected.units[slot],
      async () => await materializeConvexWasmOfficialOutputCompactChunkUnitJavascript(chunkUnit)
    );
  }
  nativeDescriptorsByApplicationUnit.set(unit, projected);
  return projected;
}

export function projectConvexWasmOfficialOutputChunkLocalProfiles(applicationUnit) {
  const unit = authenticateConvexWasmOfficialOutputChunkApplicationUnit(applicationUnit);
  const cached = chunkLocalProfilesByApplicationUnit.get(unit);
  if (cached !== undefined) return cached;
  const applicationUnitSource = canonicalJson(unit.identity);
  const sourceMapChunksSource = canonicalJson(
    unit.chunkUnits.units.map(({ identity }) => ({
      module: identity.module,
      slot: identity.slot,
    }))
  );
  const projected = Object.freeze(
    unit.identity.entries.map((entry) => {
      const publication = unit.units[entry.entryPublicationUnitSlot];
      const sourceMap = `{"chunks":${sourceMapChunksSource},"kind":"convex-wasm-official-output-chunk-application-source-map-manifest-v2","publication":${canonicalJson(publication.identity)}}\n`;
      const output = Object.freeze({
        javascript: Object.freeze({
          sha256: sha256(publication.javascript),
          size: Buffer.byteLength(publication.javascript),
        }),
        sourceMap: Object.freeze({ sha256: sha256(sourceMap), size: Buffer.byteLength(sourceMap) }),
      });
      const identityWithoutApplicationUnit = {
        dependencyGraphSha256: entry.dependencyGraphSha256,
        handoffSlot: entry.handoffSlot,
        kind: "convex-wasm-official-output-chunk-local-profile-identity-v2",
        metafileSha256: unit.identity.chunkUnits.sha256,
        mode: "authenticated-official-output-chunks",
        output,
        routes: entry.routes,
        selectedEntry: Object.freeze({ entryPath: entry.entryPath, modulePath: entry.modulePath }),
      };
      const identity = Object.freeze({
        applicationUnit: unit.identity,
        ...identityWithoutApplicationUnit,
      });
      const identityWithoutApplicationUnitSource = canonicalJson(identityWithoutApplicationUnit);
      return Object.freeze({
        identity,
        kind: "convex-wasm-local-compile-profile-v1",
        sha256: sha256(
          `{"applicationUnit":${applicationUnitSource},${identityWithoutApplicationUnitSource.slice(1)}`
        ),
      });
    })
  );
  chunkLocalProfilesByApplicationUnit.set(unit, projected);
  return projected;
}

export function createConvexWasmOfficialOutputChunkApplicationUnitInitializer({
  applicationUnit,
  destroyStore,
  executeChunk,
  executeEntryPublication,
}) {
  const unit = authenticateConvexWasmOfficialOutputChunkApplicationUnit(applicationUnit);
  if (
    typeof destroyStore !== "function" ||
    typeof executeChunk !== "function" ||
    typeof executeEntryPublication !== "function"
  ) {
    fail("chunk application initialization requires execution and destruction callbacks");
  }
  let destroyed = false;
  const destroy = (error) => {
    if (!destroyed) {
      destroyed = true;
      destroyStore(error);
    }
  };
  const chunkInitializer = createConvexWasmOfficialOutputChunkUnitInitializer({
    chunkUnits: unit.chunkUnits,
    destroyStore: destroy,
    executeChunk,
  });
  const publications = new Array(unit.identity.entries.length);
  return Object.freeze({
    initializeEntryHandoffSlot(handoffSlot) {
      if (
        !Number.isSafeInteger(handoffSlot) ||
        handoffSlot < 0 ||
        handoffSlot >= publications.length
      ) {
        fail("entry publication handoff slot is invalid");
      }
      if (destroyed) fail("entry publication attempted after Store destruction");
      const entry = unit.identity.entries[handoffSlot];
      if (publications[handoffSlot] !== undefined) return publications[handoffSlot];
      try {
        const initializedEntry = chunkInitializer.initializeEntrySlot(entry.entrySlot);
        const publication = unit.units[entry.entryPublicationUnitSlot];
        let published;
        const result = executeEntryPublication({
          javascript: publication.javascript,
          publishEntry(publishedHandoffSlot, namespace) {
            if (
              publishedHandoffSlot !== entry.handoffSlot ||
              published !== undefined ||
              namespace !== initializedEntry.namespace
            ) {
              fail("entry publication is invalid");
            }
            published = namespace;
          },
          readNamespace(chunkSlot) {
            if (chunkSlot !== entry.entrySlot) {
              fail("entry publication requested an unauthenticated chunk slot");
            }
            return initializedEntry.namespace;
          },
          reportThrown() {},
          unit: publication,
        });
        if (result !== undefined && typeof result?.then === "function") {
          fail("entry publication unit must initialize synchronously");
        }
        if (published === undefined) {
          fail("entry publication unit did not publish its authenticated entry namespace");
        }
        const initialized = Object.freeze({ ...entry, namespace: published });
        publications[handoffSlot] = initialized;
        return initialized;
      } catch (error) {
        destroy(error);
        throw error;
      }
    },
  });
}

export function initializeConvexWasmOfficialOutputChunkApplicationUnit({
  applicationUnit,
  destroyStore,
  executeChunk,
  executeEntryPublication,
}) {
  const unit = authenticateConvexWasmOfficialOutputChunkApplicationUnit(applicationUnit);
  const initializer = createConvexWasmOfficialOutputChunkApplicationUnitInitializer({
    applicationUnit: unit,
    destroyStore,
    executeChunk,
    executeEntryPublication,
  });
  return Object.freeze(
    unit.identity.entries.map(({ handoffSlot }) =>
      initializer.initializeEntryHandoffSlot(handoffSlot)
    )
  );
}
