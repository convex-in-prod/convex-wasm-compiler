import { createHash } from "node:crypto";

import {
  canonicalJson,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
  fingerprintJson,
} from "./convex-wasm-artifact-pipeline.mjs";
import {
  authenticateConvexWasmOfficialOutputSelectionSet,
  authenticateConvexWasmOfficialOutputCohortPrototype,
  authenticateConvexWasmOfficialOutputPrototype,
  convexWasmOfficialOutputPrototypeSourceAuthentication,
  convexWasmOfficialOutputCohortPrototypeGlobal,
  convexWasmOfficialOutputPrototypeGlobal,
} from "./convex-wasm-official-output-prototype.mjs";

export const convexWasmOfficialOutputApplicationUnitKind =
  "convex-wasm-official-output-application-unit-v1";
export const convexWasmOfficialOutputCohortApplicationUnitKind =
  "convex-wasm-official-output-cohort-application-unit-v1";
export const convexWasmOfficialOutputCohortGeneratedJavaScriptMaxBytes = 16 * 1024 * 1024;
export const convexWasmOfficialWrapperInvocationAbi =
  convexWasmCapabilityOfficialWrapperInvocationAbi;

function fail(message) {
  throw new Error(`Convex Wasm official-output application unit: ${message}`);
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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizeSelections(selections, prototype) {
  if (!Array.isArray(selections) || selections.length === 0) {
    fail("selections must contain at least one authenticated route");
  }
  const authenticatedSet = authenticateConvexWasmOfficialOutputSelectionSet(selections);
  if (
    authenticatedSet.sourceAuthentication !==
    convexWasmOfficialOutputPrototypeSourceAuthentication(prototype)
  ) {
    fail("application-unit selections do not share the prototype source authentication");
  }
  const normalized = authenticatedSet.selections
    .map((selection, index) => {
      const authenticatedSelection = selection;
      const route = requireObject(authenticatedSelection.route, `selection ${index} route`);
      const closure = requireObject(authenticatedSelection.closure, `selection ${index} closure`);
      const manifestMembership = requireObject(
        authenticatedSelection.manifestMembership,
        `selection ${index} manifest membership`
      );
      if (route.udfKind !== "query" && route.udfKind !== "mutation") {
        fail(`selection ${index} has an unsupported UDF kind`);
      }
      if (route.visibility !== "internal" && route.visibility !== "public") {
        fail(`selection ${index} has an unsupported visibility`);
      }
      if (
        closure.identity?.sha256 !== prototype.identity.closureSha256 ||
        closure.identity?.entryModulePath !== prototype.identity.entryModulePath
      ) {
        fail(`selection ${index} closure disagrees with the authenticated official output`);
      }
      if (manifestMembership.sourceEnvelopeSha256 !== prototype.identity.sourceEnvelopeSha256) {
        fail(`selection ${index} source envelope disagrees with the authenticated official output`);
      }
      return {
        entryPath: requireString(route.entryPath, `selection ${index} entry path`),
        exportName: requireString(route.exportName, `selection ${index} export name`),
        modulePath: requireString(route.modulePath, `selection ${index} module path`),
        runtimeModulePath: requireString(
          route.runtimeModulePath,
          `selection ${index} runtime module path`
        ),
        udfKind: route.udfKind,
        visibility: route.visibility,
      };
    })
    .sort((left, right) => compareStrings(left.exportName, right.exportName));
  for (let index = 0; index < normalized.length; index += 1) {
    const route = normalized[index];
    if (
      route.entryPath !== normalized[0].entryPath ||
      route.modulePath !== normalized[0].modulePath ||
      route.runtimeModulePath !== normalized[0].runtimeModulePath
    ) {
      fail("all selections must belong to one official deployment entry");
    }
    if (index > 0 && normalized[index - 1].exportName === route.exportName) {
      fail(`selections repeat export ${route.exportName}`);
    }
  }
  if (!normalized.some(({ exportName }) => exportName === prototype.identity.exportName)) {
    fail("the prototype route is absent from the application-unit selection");
  }
  return normalized;
}

function renderWrapperValidation(route, index) {
  const wrapper = `__convexWasmOfficialWrapper${index}`;
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

function renderApplicationJavascript(prototype, routes) {
  const wrapperValidation = routes.map(renderWrapperValidation).join("\n");
  return `(function(
  __convexWasmApplicationGlobalThis,
  __convexWasmApplicationPublishCompileProfile,
  __convexWasmApplicationReportThrown
) {
"use strict";
try {
  if (
    __convexWasmApplicationGlobalThis === null ||
    typeof __convexWasmApplicationGlobalThis !== "object" ||
    !Object.isExtensible(__convexWasmApplicationGlobalThis) ||
    Object.getPrototypeOf(__convexWasmApplicationGlobalThis) !== null
  ) {
    throw new Error("Convex Wasm application global facade is invalid");
  }
  if (typeof __convexWasmApplicationPublishCompileProfile !== "function") {
    throw new Error("Convex Wasm application output publisher is invalid");
  }
  if (typeof __convexWasmApplicationReportThrown !== "function") {
    throw new Error("Convex Wasm application error reporter is invalid");
  }
  const globalThis = __convexWasmApplicationGlobalThis;
${prototype.javascript}
  const __convexWasmOfficialEntry = ${convexWasmOfficialOutputPrototypeGlobal}.entry;
  if (
    __convexWasmOfficialEntry === null ||
    typeof __convexWasmOfficialEntry !== "object"
  ) {
    throw new Error("Official Convex deployment entry namespace is invalid");
  }
${wrapperValidation}
  // Retain the complete namespace. Runtime selection is constrained by the
  // authenticated route table and never derives authority from bytecode reachability.
  __convexWasmApplicationPublishCompileProfile(__convexWasmOfficialEntry);
} catch (__convexInitializationError) {
  if (typeof __convexWasmApplicationReportThrown === "function") {
    __convexWasmApplicationReportThrown(__convexInitializationError);
  }
  throw __convexInitializationError;
}
})(
  globalThis.__convexWasmApplicationGlobalThis,
  globalThis.__convexWasmApplicationPublishCompileProfile,
  globalThis.__convexWasmApplicationReportThrown
);
`;
}

function sourceMapManifest(selections) {
  const modules = selections[0].closure.modules.map(({ identity }) => ({
    path: identity.path,
    sourceMap: identity.sourceMap,
  }));
  return `${canonicalJson({
    kind: "convex-wasm-official-output-source-map-manifest-v1",
    modules,
  })}\n`;
}

export function authenticateConvexWasmOfficialOutputApplicationUnit(applicationUnit) {
  const unit = requireObject(applicationUnit, "application unit");
  if (unit.kind !== convexWasmOfficialOutputApplicationUnitKind) {
    fail("application unit kind is unsupported");
  }
  const identity = requireObject(unit.identity, "application unit identity");
  const { sha256: identitySha256, ...identityPayload } = identity;
  if (
    identity.kind !== convexWasmOfficialOutputApplicationUnitKind ||
    typeof identity.dependencyGraphSha256 !== "string" ||
    identity.invocationAbi !== convexWasmOfficialWrapperInvocationAbi ||
    identity.treeShaking !== true ||
    identity.retainedOutput !== "complete-official-entry-namespace" ||
    identitySha256 !== fingerprintJson(identityPayload)
  ) {
    fail("application unit identity is invalid");
  }
  requireString(unit.javascript, "application unit JavaScript");
  requireString(unit.sourceMap, "application unit source-map manifest");
  if (
    sha256(unit.javascript) !== identity.javascript.sha256 ||
    Buffer.byteLength(unit.javascript) !== identity.javascript.size ||
    sha256(unit.sourceMap) !== identity.sourceMap.sha256 ||
    Buffer.byteLength(unit.sourceMap) !== identity.sourceMap.size
  ) {
    fail("application unit emitted material changed after construction");
  }
  authenticateConvexWasmOfficialOutputPrototype(unit.prototype);
  if (unit.prototype.identity.sha256 !== identity.officialOutput.sha256) {
    fail("application unit official-output identity disagrees");
  }
  return unit;
}

export function buildConvexWasmOfficialOutputApplicationUnit({ prototype, selections }) {
  const authenticatedPrototype = authenticateConvexWasmOfficialOutputPrototype(prototype);
  const routes = normalizeSelections(selections, authenticatedPrototype);
  const dependencyGraphSha256 = requireString(
    selections[0].manifestMembership.dependencyGraphSha256,
    "application unit dependency graph SHA-256"
  );
  if (
    selections.some(
      ({ manifestMembership }) => manifestMembership.dependencyGraphSha256 !== dependencyGraphSha256
    )
  ) {
    fail("application-unit selections disagree on the dependency graph");
  }
  const javascript = renderApplicationJavascript(authenticatedPrototype, routes);
  const sourceMap = sourceMapManifest(selections);
  const identity = {
    closureSha256: authenticatedPrototype.identity.closureSha256,
    dependencyGraphSha256,
    entryModulePath: authenticatedPrototype.identity.entryModulePath,
    invocationAbi: convexWasmOfficialWrapperInvocationAbi,
    javascript: {
      sha256: sha256(javascript),
      size: Buffer.byteLength(javascript),
    },
    kind: convexWasmOfficialOutputApplicationUnitKind,
    officialOutput: {
      kind: authenticatedPrototype.identity.kind,
      sha256: authenticatedPrototype.identity.sha256,
    },
    retainedOutput: "complete-official-entry-namespace",
    routes,
    sourceMap: {
      sha256: sha256(sourceMap),
      size: Buffer.byteLength(sourceMap),
    },
    treeShaking: true,
  };
  const unit = {
    identity: { ...identity, sha256: fingerprintJson(identity) },
    javascript,
    kind: convexWasmOfficialOutputApplicationUnitKind,
    prototype: authenticatedPrototype,
    sourceMap,
  };
  return authenticateConvexWasmOfficialOutputApplicationUnit(unit);
}

export function projectConvexWasmOfficialOutputLocalProfile(applicationUnit) {
  const unit = authenticateConvexWasmOfficialOutputApplicationUnit(applicationUnit);
  const firstRoute = unit.identity.routes[0];
  const identity = Object.freeze({
    applicationUnit: unit.identity,
    dependencyGraphSha256: unit.identity.dependencyGraphSha256,
    kind: "convex-wasm-official-output-local-profile-identity-v1",
    metafileSha256: unit.prototype.identity.metafileSha256,
    mode: "authenticated-official-output",
    output: Object.freeze({
      javascript: Object.freeze({ ...unit.identity.javascript }),
      sourceMap: Object.freeze({ ...unit.identity.sourceMap }),
    }),
    routes: unit.identity.routes.map(({ exportName, udfKind, visibility }) => ({
      exportName,
      udfKind,
      visibility,
    })),
    selectedEntry: Object.freeze({
      entryPath: firstRoute.entryPath,
      modulePath: firstRoute.modulePath,
    }),
  });
  return Object.freeze({
    identity,
    kind: "convex-wasm-local-compile-profile-v1",
    sha256: fingerprintJson(identity),
  });
}

export function summarizeConvexWasmOfficialOutputLocalProfile(localProfile) {
  const profile = requireObject(localProfile, "official-output local profile");
  const identity = requireObject(profile.identity, "official-output local profile identity");
  if (
    profile.kind !== "convex-wasm-local-compile-profile-v1" ||
    profile.sha256 !== fingerprintJson(identity) ||
    identity.kind !== "convex-wasm-official-output-local-profile-identity-v1"
  ) {
    fail("official-output local profile identity is invalid");
  }
  return Object.freeze({
    dependencyGraphSha256: identity.dependencyGraphSha256,
    javascript: identity.output.javascript,
    metafileSha256: identity.metafileSha256,
    sha256: profile.sha256,
    sourceMap: identity.output.sourceMap,
  });
}

function renderCohortApplicationJavascript(prototype) {
  const entries = prototype.identity.entries;
  const validations = entries
    .flatMap((entry, entryIndex) =>
      entry.routes.map((route, routeIndex) =>
        renderWrapperValidation(
          { ...route, entryPath: entry.entryPath },
          `${entryIndex}_${routeIndex}`
        ).replaceAll("__convexWasmOfficialEntry", `__convexWasmOfficialEntry${entryIndex}`)
      )
    )
    .join("\n");
  const namespaceBindings = entries
    .map(
      (_, index) =>
        `  const __convexWasmOfficialEntry${index} = ${convexWasmOfficialOutputCohortPrototypeGlobal}.entry${index};\n` +
        `  if (__convexWasmOfficialEntry${index} === null || typeof __convexWasmOfficialEntry${index} !== "object") {\n` +
        `    throw new Error(${JSON.stringify(`Official Convex deployment entry namespace ${index} is invalid`)});\n` +
        "  }"
    )
    .join("\n");
  const publications = entries
    .map(
      ({ handoffSlot }, index) =>
        `  __convexWasmApplicationPublishCompileProfile(${handoffSlot}, __convexWasmOfficialEntry${index});`
    )
    .join("\n");
  return `(function(
  __convexWasmApplicationGlobalThis,
  __convexWasmApplicationPublishCompileProfile,
  __convexWasmApplicationReportThrown
) {
"use strict";
try {
  if (
    __convexWasmApplicationGlobalThis === null ||
    typeof __convexWasmApplicationGlobalThis !== "object" ||
    !Object.isExtensible(__convexWasmApplicationGlobalThis) ||
    Object.getPrototypeOf(__convexWasmApplicationGlobalThis) !== null
  ) {
    throw new Error("Convex Wasm application global facade is invalid");
  }
  if (typeof __convexWasmApplicationPublishCompileProfile !== "function") {
    throw new Error("Convex Wasm application output publisher is invalid");
  }
  if (typeof __convexWasmApplicationReportThrown !== "function") {
    throw new Error("Convex Wasm application error reporter is invalid");
  }
  const globalThis = __convexWasmApplicationGlobalThis;
${prototype.javascript}
${namespaceBindings}
${validations}
  // Each complete namespace crosses one host-owned scalar slot. No typed
  // bridge collection carries ordinary untyped application values.
${publications}
} catch (__convexInitializationError) {
  if (typeof __convexWasmApplicationReportThrown === "function") {
    __convexWasmApplicationReportThrown(__convexInitializationError);
  }
  throw __convexInitializationError;
}
})(
  globalThis.__convexWasmApplicationGlobalThis,
  globalThis.__convexWasmApplicationPublishCompileProfile,
  globalThis.__convexWasmApplicationReportThrown
);
`;
}

function cohortSourceMapManifest(prototype) {
  return `${canonicalJson({
    entries: prototype.identity.entries.map(({ closureSha256, entryPath, handoffSlot }) => ({
      closureSha256,
      entryPath,
      handoffSlot,
    })),
    kind: "convex-wasm-official-output-cohort-source-map-manifest-v1",
    union: prototype.closureUnion.modules.map(({ identity }) => ({
      path: identity.path,
      sourceMap: identity.sourceMap,
    })),
  })}\n`;
}

export function authenticateConvexWasmOfficialOutputCohortApplicationUnit(applicationUnit) {
  const unit = requireObject(applicationUnit, "cohort application unit");
  if (unit.kind !== convexWasmOfficialOutputCohortApplicationUnitKind) {
    fail("cohort application unit kind is unsupported");
  }
  const identity = requireObject(unit.identity, "cohort application unit identity");
  const { sha256: identitySha256, ...identityPayload } = identity;
  if (
    identity.kind !== convexWasmOfficialOutputCohortApplicationUnitKind ||
    identity.compilerMode !== "static-hermes-untyped-application" ||
    identity.invocationAbi !== convexWasmOfficialWrapperInvocationAbi ||
    identity.unitCount !== 1 ||
    identity.ingress.generatedJavaScriptMaxBytes !==
      convexWasmOfficialOutputCohortGeneratedJavaScriptMaxBytes ||
    identity.retainedOutput !== "complete-official-entry-namespaces-by-scalar-slot" ||
    !Array.isArray(identity.handoffSlots) ||
    identity.handoffSlots.length !== identity.entries.length ||
    identitySha256 !== fingerprintJson(identityPayload)
  ) {
    fail("cohort application unit identity is invalid");
  }
  if (
    identity.handoffSlots.some(
      (slot, index) =>
        slot.entryPath !== identity.entries[index].entryPath || slot.handoffSlot !== index
    )
  ) {
    fail("cohort application handoff slots do not match ordered entries");
  }
  requireString(unit.javascript, "cohort application JavaScript");
  requireString(unit.sourceMap, "cohort application source-map manifest");
  if (
    sha256(unit.javascript) !== identity.javascript.sha256 ||
    Buffer.byteLength(unit.javascript) !== identity.javascript.size ||
    sha256(unit.sourceMap) !== identity.sourceMap.sha256 ||
    Buffer.byteLength(unit.sourceMap) !== identity.sourceMap.size ||
    identity.javascript.size > identity.ingress.generatedJavaScriptMaxBytes
  ) {
    fail("cohort application emitted material changed after construction");
  }
  const prototype = authenticateConvexWasmOfficialOutputCohortPrototype(unit.prototype);
  if (prototype.identity.sha256 !== identity.officialOutput.sha256) {
    fail("cohort application official-output identity disagrees");
  }
  return unit;
}

export function buildConvexWasmOfficialOutputCohortApplicationUnit({ prototype }) {
  const authenticatedPrototype = authenticateConvexWasmOfficialOutputCohortPrototype(prototype);
  const javascript = renderCohortApplicationJavascript(authenticatedPrototype);
  const sourceMap = cohortSourceMapManifest(authenticatedPrototype);
  const identity = {
    closureUnion: authenticatedPrototype.identity.closureUnion,
    compilerMode: authenticatedPrototype.identity.compilerMode,
    dependencyGraphSha256: authenticatedPrototype.identity.dependencyGraphSha256,
    entries: authenticatedPrototype.identity.entries,
    esbuild: authenticatedPrototype.identity.esbuild,
    handoffSlots: authenticatedPrototype.identity.entries.map(({ entryPath, handoffSlot }) => ({
      binding: "__convexWasmApplicationPublishCompileProfile",
      entryPath,
      handoffSlot,
    })),
    ingress: {
      generatedJavaScriptMaxBytes: convexWasmOfficialOutputCohortGeneratedJavaScriptMaxBytes,
      kind: "identity-bound-official-output-cohort-ingress-v1",
    },
    invocationAbi: convexWasmOfficialWrapperInvocationAbi,
    javascript: { sha256: sha256(javascript), size: Buffer.byteLength(javascript) },
    kind: convexWasmOfficialOutputCohortApplicationUnitKind,
    officialOutput: {
      kind: authenticatedPrototype.identity.kind,
      sha256: authenticatedPrototype.identity.sha256,
    },
    retainedOutput: "complete-official-entry-namespaces-by-scalar-slot",
    sourceEnvelopeSha256: authenticatedPrototype.identity.sourceEnvelopeSha256,
    sourceMap: { sha256: sha256(sourceMap), size: Buffer.byteLength(sourceMap) },
    unitCount: 1,
  };
  return authenticateConvexWasmOfficialOutputCohortApplicationUnit({
    identity: { ...identity, sha256: fingerprintJson(identity) },
    javascript,
    kind: convexWasmOfficialOutputCohortApplicationUnitKind,
    prototype: authenticatedPrototype,
    sourceMap,
  });
}

export function projectConvexWasmOfficialOutputCohortLocalApplicationUnitIdentity(applicationUnit) {
  const unit = authenticateConvexWasmOfficialOutputCohortApplicationUnit(applicationUnit);
  // The source envelope authenticates the complete deployment at selection and publication
  // boundaries. Native cohort output instead depends on this cohort's exact inputs and emitted
  // bytes, so an unrelated entry cannot invalidate an unchanged physical application unit.
  const identity = {
    closureUnion: unit.identity.closureUnion,
    compilerMode: unit.identity.compilerMode,
    dependencyGraphSha256: unit.identity.dependencyGraphSha256,
    entries: unit.identity.entries,
    esbuild: unit.identity.esbuild,
    handoffSlots: unit.identity.handoffSlots,
    ingress: unit.identity.ingress,
    invocationAbi: unit.identity.invocationAbi,
    javascript: unit.identity.javascript,
    kind: "convex-wasm-official-output-cohort-local-application-unit-identity-v1",
    metafileSha256: unit.prototype.identity.metafileSha256,
    retainedOutput: unit.identity.retainedOutput,
    sourceMap: unit.identity.sourceMap,
    unitCount: unit.identity.unitCount,
  };
  return Object.freeze({ ...identity, sha256: fingerprintJson(identity) });
}

export function projectConvexWasmOfficialOutputCohortLocalProfiles(applicationUnit) {
  const unit = authenticateConvexWasmOfficialOutputCohortApplicationUnit(applicationUnit);
  const localApplicationUnit =
    projectConvexWasmOfficialOutputCohortLocalApplicationUnitIdentity(unit);
  return unit.identity.entries.map((entry) => {
    const identity = Object.freeze({
      applicationUnit: localApplicationUnit,
      dependencyGraphSha256: entry.dependencyGraphSha256,
      handoffSlot: entry.handoffSlot,
      kind: "convex-wasm-official-output-cohort-local-profile-identity-v1",
      metafileSha256: unit.prototype.identity.metafileSha256,
      mode: "authenticated-official-output-cohort",
      output: Object.freeze({
        javascript: Object.freeze({ ...unit.identity.javascript }),
        sourceMap: Object.freeze({ ...unit.identity.sourceMap }),
      }),
      routes: entry.routes,
      selectedEntry: Object.freeze({
        entryPath: entry.entryPath,
        modulePath: entry.modulePath,
      }),
    });
    return Object.freeze({
      identity,
      kind: "convex-wasm-local-compile-profile-v1",
      sha256: fingerprintJson(identity),
    });
  });
}
