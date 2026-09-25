import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const INVENTORY_KIND = "convex-wasm-static-hermes-global-inventory";
const GLOBAL_PROBE_REPORT_KIND = "convex-wasm-static-hermes-global-probe-report-v2";
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const globalProbeReportPath = new URL(
  "../convex-wasm-static-hermes-global-probe-report.json",
  import.meta.url
);
const globalProbeReportBytes = readFileSync(globalProbeReportPath);
const loadedGlobalProbeReport = JSON.parse(globalProbeReportBytes);
const semanticClasses = new Set([
  "ambient-global-object",
  "deterministic-ecmascript",
  "deterministic-web-like",
  "dynamic-code",
  "engine-internal",
  "gc-observable",
  "host-authority",
  "nondeterministic-random",
  "nondeterministic-time",
]);
const providers = new Set([
  "engine-runtime-untyped",
  "engine-runtime-untyped+shim",
  "engine-runtime-untyped+typed-bridge",
  "engine-typed",
  "mediated-host",
  "shared-untyped-runtime-support",
  "target-adapter",
  "typed-declaration-only",
  "unavailable",
]);
const readStates = new Set(["admitted", "gap", "rejected"]);
const ordinaryDeterministicClasses = new Set([
  "deterministic-ecmascript",
  "deterministic-web-like",
]);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

function freezeJson(value) {
  if (Array.isArray(value)) {
    for (const entry of value) freezeJson(entry);
  } else if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) freezeJson(entry);
  }
  return Object.freeze(value);
}

export function canonicalConvexWasmStaticHermesGlobalInventoryJson(value) {
  return JSON.stringify(canonicalize(value));
}

function assertExactKeys(value, keys, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${description} has unsupported or missing fields.`);
  }
}

function assertSortedUniqueNames(names, description, { allowEmpty = false } = {}) {
  if (
    !Array.isArray(names) ||
    (!allowEmpty && names.length === 0) ||
    names.some((name) => typeof name !== "string" || name.length === 0)
  ) {
    throw new Error(`${description} must be a non-empty array of names.`);
  }
  const sorted = [...new Set(names)].sort();
  if (sorted.length !== names.length || sorted.some((name, index) => name !== names[index])) {
    throw new Error(`${description} must be sorted and contain no duplicates.`);
  }
}

function assertSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new Error(`${description} must be a lowercase SHA-256 digest.`);
  }
}

function setDifference(left, right) {
  return [...left].filter((entry) => !right.has(entry)).sort();
}

function assertSameNames(actualNames, expectedNames, description) {
  const actual = new Set(actualNames);
  const expected = new Set(expectedNames);
  const added = setDifference(actual, expected);
  const removed = setDifference(expected, actual);
  const duplicated = Array.isArray(actualNames) && actual.size !== actualNames.length;
  if (duplicated || added.length !== 0 || removed.length !== 0) {
    throw new Error(
      `${description} drifted: added=${JSON.stringify(added)}, removed=${JSON.stringify(removed)}.`
    );
  }
}

function assertGlobalProbeSnapshot(snapshot, description) {
  assertExactKeys(snapshot, ["keys", "valueTypes"], description);
  assertSortedUniqueNames(snapshot.keys, `${description}.keys`);
  assertSameNames(Object.keys(snapshot.valueTypes), snapshot.keys, `${description} value types`);
  for (const [name, valueType] of Object.entries(snapshot.valueTypes)) {
    if (
      !["boolean", "function", "number", "object", "string", "symbol", "undefined"].includes(
        valueType
      )
    ) {
      throw new Error(`${description}.valueTypes.${name} is invalid.`);
    }
  }
}

function validateGlobalProbeReport(report, inventory) {
  assertExactKeys(
    report,
    [
      "build",
      "harness",
      "kind",
      "observation",
      "reportSha256",
      "runtime",
      "schemaVersion",
      "target",
      "tools",
      "typedDeclarations",
    ],
    "Static Hermes global probe report"
  );
  if (report.kind !== GLOBAL_PROBE_REPORT_KIND || report.schemaVersion !== 2) {
    throw new Error("Static Hermes global probe report kind or schema version changed.");
  }
  const reportPayload = { ...report };
  delete reportPayload.reportSha256;
  const recomputedReportSha256 = createHash("sha256")
    .update(canonicalConvexWasmStaticHermesGlobalInventoryJson(reportPayload))
    .digest("hex");
  if (recomputedReportSha256 !== report.reportSha256) {
    throw new Error("Static Hermes global probe report identity does not match its contents.");
  }
  const reportFileSha256 = createHash("sha256").update(globalProbeReportBytes).digest("hex");
  if (
    report.reportSha256 !== inventory.targetRuntimeProbe.reportSha256 ||
    reportFileSha256 !== inventory.targetRuntimeProbe.reportFileSha256
  ) {
    throw new Error("Static Hermes global probe report is not bound by the inventory.");
  }
  assertExactKeys(
    report.observation,
    ["effectiveFirst", "effectiveSecond", "raw"],
    "Static Hermes global probe observation"
  );
  for (const field of ["raw", "effectiveFirst", "effectiveSecond"]) {
    assertGlobalProbeSnapshot(report.observation[field], `global probe observation.${field}`);
  }
  const raw = canonicalConvexWasmStaticHermesGlobalInventoryJson(report.observation.raw);
  const effectiveFirst = canonicalConvexWasmStaticHermesGlobalInventoryJson(
    report.observation.effectiveFirst
  );
  const effectiveSecond = canonicalConvexWasmStaticHermesGlobalInventoryJson(
    report.observation.effectiveSecond
  );
  if (raw !== effectiveFirst || effectiveFirst !== effectiveSecond) {
    throw new Error("Static Hermes raw and reused effective global observations disagree.");
  }
  assertSameNames(
    report.observation.effectiveSecond.keys,
    inventory.targetRuntimeProbe.globals,
    "inventory globals derived from the exact target report"
  );
  assertSameNames(
    report.typedDeclarations.globals,
    inventory.staticHermesTypedDeclarations.globals,
    "inventory typed declarations derived from build-revision sources"
  );
  if (
    report.build.buildRevision !== inventory.sourceIdentity.buildRevision ||
    report.build.sourceRevision !== inventory.sourceIdentity.sourceRevision ||
    report.build.observedCheckoutRevision !== inventory.sourceIdentity.observedCheckoutRevision
  ) {
    throw new Error("Static Hermes global probe source revisions disagree with the inventory.");
  }
  const sourceHashFields = {
    globalObject: "globalObjectSourceSha256",
    libhermesDeclaration: "libhermesDeclarationSha256",
    typedArraysDeclaration: "typedArraysDeclarationSha256",
  };
  assertExactKeys(
    report.build.sourceMaterials,
    Object.keys(sourceHashFields),
    "Static Hermes global probe source materials"
  );
  for (const [reportField, inventoryField] of Object.entries(sourceHashFields)) {
    if (
      report.build.sourceMaterials[reportField].sha256 !== inventory.sourceIdentity[inventoryField]
    ) {
      throw new Error(`Static Hermes global probe source material ${reportField} drifted.`);
    }
  }
  if (
    report.build.cmake.host.identity.sha256 !== inventory.sourceIdentity.hostCmakeCacheSha256 ||
    report.build.cmake.wasm.identity.sha256 !== inventory.sourceIdentity.wasmCmakeCacheSha256 ||
    report.tools.shermes.sha256 !== inventory.sourceIdentity.hostShermesSha256 ||
    report.target.wasmLibhermesvmArchive.sha256 !==
      inventory.sourceIdentity.wasmLibhermesvmArchiveSha256
  ) {
    throw new Error("Static Hermes global probe build materials disagree with the inventory.");
  }
  const expectedFlags = {
    HERMES_ENABLE_CONTRIB_EXTENSIONS: inventory.buildConfiguration.contribExtensions,
    HERMES_ENABLE_CORE_EXTENSIONS: inventory.buildConfiguration.coreExtensions,
    HERMES_ENABLE_DEBUGGER: inventory.buildConfiguration.debugger,
    HERMES_ENABLE_INTL: inventory.buildConfiguration.intl,
  };
  if (
    canonicalConvexWasmStaticHermesGlobalInventoryJson(report.build.cmake.host.flags) !==
      canonicalConvexWasmStaticHermesGlobalInventoryJson(expectedFlags) ||
    canonicalConvexWasmStaticHermesGlobalInventoryJson(report.build.cmake.wasm.flags) !==
      canonicalConvexWasmStaticHermesGlobalInventoryJson(expectedFlags)
  ) {
    throw new Error("Static Hermes global probe CMake flags disagree with the inventory.");
  }
  if (
    report.runtime.initialization !== "_sh_init" ||
    report.runtime.reusedObservationCount !== 2 ||
    canonicalConvexWasmStaticHermesGlobalInventoryJson(report.runtime.arguments) !==
      canonicalConvexWasmStaticHermesGlobalInventoryJson([
        "--gc-init-heap=4MiB",
        "--gc-max-heap=64MiB",
        "--gc-alloc-young=true",
        "--gc-revert-to-yg-at-tti=false",
        "--max-register-stack=16384",
      ])
  ) {
    throw new Error("Static Hermes global probe runtime initialization changed.");
  }
  const repositoryRoot = new URL("../../", import.meta.url);
  for (const [field, path] of Object.entries({
    generator: "scripts/generate-convex-wasm-static-hermes-global-probe.mjs",
    guest: "scripts/test-fixtures/convex-wasm-runtime-surface/static-hermes-global-probe.js",
    runtimeMain: "scripts/lib/convex-wasm-static-hermes-global-probe-runtime-main.cpp",
  })) {
    const bytes = readFileSync(new URL(path, repositoryRoot));
    if (
      bytes.length !== report.harness[field].bytes ||
      createHash("sha256").update(bytes).digest("hex") !== report.harness[field].sha256
    ) {
      throw new Error(`Static Hermes global probe harness ${field} changed.`);
    }
  }
}

export function validateConvexWasmStaticHermesGlobalInventory(
  value,
  globalProbeReport = loadedGlobalProbeReport
) {
  assertExactKeys(
    value,
    [
      "accessPolicy",
      "buildConfiguration",
      "kind",
      "registrationConditions",
      "reviewedAbsentGlobals",
      "semantics",
      "sourceIdentity",
      "staticHermesTypedDeclarations",
      "targetRuntimeProbe",
    ],
    "Static Hermes global inventory"
  );
  if (value.kind !== INVENTORY_KIND) {
    throw new Error(`Static Hermes global inventory kind must be ${INVENTORY_KIND}.`);
  }

  assertExactKeys(
    value.sourceIdentity,
    [
      "buildRevision",
      "globalObjectSourceSha256",
      "hostCmakeCacheSha256",
      "hostShermesSha256",
      "libhermesDeclarationSha256",
      "observedCheckoutRevision",
      "sourceRevision",
      "typedArraysDeclarationSha256",
      "wasmCmakeCacheSha256",
      "wasmLibhermesvmArchiveSha256",
    ],
    "Static Hermes global inventory sourceIdentity"
  );
  for (const field of ["buildRevision", "observedCheckoutRevision", "sourceRevision"]) {
    if (!/^[a-f0-9]{40}$/u.test(value.sourceIdentity[field])) {
      throw new Error(`Static Hermes global inventory ${field} must be a Git revision.`);
    }
  }
  if (value.sourceIdentity.sourceRevision !== value.sourceIdentity.buildRevision) {
    throw new Error("Static Hermes source revision must match the authenticated build revision.");
  }
  for (const [name, digest] of Object.entries(value.sourceIdentity)) {
    if (!name.endsWith("Revision")) assertSha256(digest, `sourceIdentity.${name}`);
  }

  assertExactKeys(
    value.buildConfiguration,
    ["contribExtensions", "coreExtensions", "debugger", "intl"],
    "Static Hermes global inventory buildConfiguration"
  );
  if (Object.values(value.buildConfiguration).some((enabled) => typeof enabled !== "boolean")) {
    throw new Error("Static Hermes global inventory build flags must be booleans.");
  }
  if (
    value.buildConfiguration.coreExtensions !== true ||
    value.buildConfiguration.contribExtensions !== true ||
    value.buildConfiguration.debugger !== false ||
    value.buildConfiguration.intl !== false
  ) {
    throw new Error("Static Hermes global inventory build flags changed without review.");
  }

  assertExactKeys(
    value.registrationConditions,
    [
      "contribExtensions",
      "coreExtensions",
      "debuggerBuild",
      "es6Proxy",
      "hermesInternal",
      "intlBuildAndRuntime",
      "runtimeMicrotaskQueue",
      "workerIntegrator",
    ],
    "Static Hermes global inventory registrationConditions"
  );

  assertExactKeys(
    value.targetRuntimeProbe,
    ["globals", "kind", "reportFileSha256", "reportSha256"],
    "Static Hermes global inventory targetRuntimeProbe"
  );
  if (value.targetRuntimeProbe.kind !== "static-hermes-no-console-sh-init-global-probe") {
    throw new Error("Static Hermes global inventory must use the exact no-console target probe.");
  }
  assertSha256(value.targetRuntimeProbe.reportFileSha256, "targetRuntimeProbe.reportFileSha256");
  assertSha256(value.targetRuntimeProbe.reportSha256, "targetRuntimeProbe.reportSha256");
  assertSortedUniqueNames(value.targetRuntimeProbe.globals, "targetRuntimeProbe.globals");
  const targetRuntimeGlobalSet = new Set(value.targetRuntimeProbe.globals);
  for (const [conditionName, condition] of Object.entries(value.registrationConditions)) {
    const namesField = condition.enabled ? "globals" : "omittedGlobals";
    assertExactKeys(condition, ["enabled", namesField], `registrationConditions.${conditionName}`);
    if (typeof condition.enabled !== "boolean") {
      throw new Error(`registrationConditions.${conditionName}.enabled must be a boolean.`);
    }
    assertSortedUniqueNames(
      condition[namesField],
      `registrationConditions.${conditionName}.${namesField}`
    );
    for (const name of condition[namesField]) {
      if (condition.enabled !== targetRuntimeGlobalSet.has(name)) {
        throw new Error(
          `registrationConditions.${conditionName} contradicts target exposure for ${name}.`
        );
      }
    }
  }
  for (const [conditionName, buildFlag] of [
    ["contribExtensions", "contribExtensions"],
    ["coreExtensions", "coreExtensions"],
    ["debuggerBuild", "debugger"],
    ["intlBuildAndRuntime", "intl"],
  ]) {
    if (
      value.registrationConditions[conditionName].enabled !== value.buildConfiguration[buildFlag]
    ) {
      throw new Error(`registrationConditions.${conditionName} contradicts its build flag.`);
    }
  }
  assertExactKeys(
    value.staticHermesTypedDeclarations,
    ["globals", "kind"],
    "Static Hermes global inventory staticHermesTypedDeclarations"
  );
  if (
    value.staticHermesTypedDeclarations.kind !== "libhermes-runtime-declarations-plus-typed-arrays"
  ) {
    throw new Error("Static Hermes typed-declaration inventory kind changed without review.");
  }
  assertSortedUniqueNames(
    value.staticHermesTypedDeclarations.globals,
    "staticHermesTypedDeclarations.globals"
  );
  assertSortedUniqueNames(value.reviewedAbsentGlobals, "reviewedAbsentGlobals");

  assertExactKeys(
    value.accessPolicy,
    [
      "applicationGlobalFacade",
      "applicationGlobalFacadeComputedAccess",
      "applicationGlobalFacadeFlow",
      "globalBindingWrites",
      "rawGlobalObjectFlow",
    ],
    "Static Hermes global inventory accessPolicy"
  );
  const expectedAccessPolicy = {
    applicationGlobalFacade: "inventory-derived-extensible-null-prototype-immutable-builtins",
    applicationGlobalFacadeComputedAccess: "admitted",
    applicationGlobalFacadeFlow: "admitted",
    globalBindingWrites: "rejected",
    rawGlobalObjectFlow: "rejected",
  };
  if (
    canonicalConvexWasmStaticHermesGlobalInventoryJson(value.accessPolicy) !==
    canonicalConvexWasmStaticHermesGlobalInventoryJson(expectedAccessPolicy)
  ) {
    throw new Error("Static Hermes application-facade and raw-global access policies changed.");
  }

  const targetGlobals = new Set(value.targetRuntimeProbe.globals);
  const typedGlobals = new Set(value.staticHermesTypedDeclarations.globals);
  const reviewedAbsentGlobals = new Set(value.reviewedAbsentGlobals);
  const classifiedGlobals = new Set(Object.keys(value.semantics));
  const inventoriedGlobals = new Set([...targetGlobals, ...typedGlobals, ...reviewedAbsentGlobals]);
  assertSameNames(classifiedGlobals, inventoriedGlobals, "classified Static Hermes globals");
  for (const name of reviewedAbsentGlobals) {
    if (targetGlobals.has(name) || typedGlobals.has(name)) {
      throw new Error(`${name} cannot be both reviewed absent and engine-present.`);
    }
  }

  for (const [name, semantic] of Object.entries(value.semantics)) {
    assertExactKeys(semantic, ["class", "provider", "read"], `semantics.${name}`);
    if (!semanticClasses.has(semantic.class)) {
      throw new Error(`semantics.${name}.class is unclassified.`);
    }
    if (!providers.has(semantic.provider)) {
      throw new Error(`semantics.${name}.provider is unsupported.`);
    }
    if (
      semantic.read === null ||
      typeof semantic.read !== "object" ||
      Array.isArray(semantic.read) ||
      !readStates.has(semantic.read.state)
    ) {
      throw new Error(`semantics.${name}.read is invalid.`);
    }
    const readKeys = Object.keys(semantic.read).sort();
    const expectedReadKeys =
      semantic.read.state === "gap"
        ? ["gap", "state"]
        : semantic.read.state === "admitted" && semantic.read.restriction !== undefined
          ? ["restriction", "state"]
          : ["state"];
    if (
      readKeys.length !== expectedReadKeys.length ||
      readKeys.some((key, index) => key !== expectedReadKeys[index])
    ) {
      throw new Error(`semantics.${name}.read has unsupported or missing fields.`);
    }
    if (
      semantic.read.state === "gap" &&
      (typeof semantic.read.gap !== "string" || semantic.read.gap.length === 0)
    ) {
      throw new Error(`semantics.${name}.read gap must be named.`);
    }

    const targetPresent = targetGlobals.has(name);
    const typedPresent = typedGlobals.has(name);
    const validProvider =
      (semantic.provider === "engine-typed" && targetPresent && typedPresent) ||
      ((semantic.provider === "engine-runtime-untyped" ||
        semantic.provider === "engine-runtime-untyped+shim" ||
        semantic.provider === "engine-runtime-untyped+typed-bridge") &&
        targetPresent &&
        !typedPresent) ||
      (semantic.provider === "typed-declaration-only" && !targetPresent && typedPresent) ||
      (semantic.provider === "unavailable" && !targetPresent && !typedPresent) ||
      (semantic.provider === "shared-untyped-runtime-support" &&
        reviewedAbsentGlobals.has(name) &&
        !targetPresent &&
        !typedPresent) ||
      (semantic.provider === "target-adapter" && targetPresent) ||
      (semantic.provider === "mediated-host" && targetPresent);
    if (!validProvider) {
      throw new Error(`semantics.${name}.provider contradicts runtime or typed availability.`);
    }
    const ordinaryPinnedEngineGlobal = ordinaryDeterministicClasses.has(semantic.class);
    if (ordinaryPinnedEngineGlobal && targetPresent && semantic.read.state !== "admitted") {
      throw new Error(
        `semantics.${name} must admit the pinned runtime semantics for an ordinary engine-standard global.`
      );
    }
    if (
      ordinaryPinnedEngineGlobal &&
      targetPresent &&
      !typedPresent &&
      semantic.provider === "engine-runtime-untyped"
    ) {
      throw new Error(
        `semantics.${name} must use the mechanical typed bridge for an untyped runtime global.`
      );
    }
    if (
      semantic.read.state === "admitted" &&
      !targetPresent &&
      semantic.provider !== "shared-untyped-runtime-support"
    ) {
      throw new Error(`semantics.${name} cannot be admitted when absent from the target runtime.`);
    }
    if (
      semantic.provider === "shared-untyped-runtime-support" &&
      (!ordinaryDeterministicClasses.has(semantic.class) || semantic.read.state !== "admitted")
    ) {
      throw new Error(
        `semantics.${name} shared runtime support must be an admitted deterministic global.`
      );
    }
  }

  validateGlobalProbeReport(globalProbeReport, value);

  return value;
}

const inventoryPath = new URL("../convex-wasm-static-hermes-engine-globals.json", import.meta.url);
const loadedInventory = JSON.parse(readFileSync(inventoryPath, "utf8"));

export const convexWasmStaticHermesGlobalInventory = freezeJson(
  validateConvexWasmStaticHermesGlobalInventory(loadedInventory)
);
export const convexWasmStaticHermesGlobalInventorySha256 = createHash("sha256")
  .update(canonicalConvexWasmStaticHermesGlobalInventoryJson(convexWasmStaticHermesGlobalInventory))
  .digest("hex");
export const convexWasmStaticHermesTargetRuntimeGlobals = Object.freeze([
  ...convexWasmStaticHermesGlobalInventory.targetRuntimeProbe.globals,
]);
export const convexWasmStaticHermesTypedDeclarationGlobals = Object.freeze([
  ...convexWasmStaticHermesGlobalInventory.staticHermesTypedDeclarations.globals,
]);
export const convexWasmAdmittedStaticHermesGlobals = Object.freeze(
  Object.entries(convexWasmStaticHermesGlobalInventory.semantics)
    .filter(
      ([name, semantic]) =>
        semantic.read.state === "admitted" &&
        convexWasmStaticHermesGlobalInventory.targetRuntimeProbe.globals.includes(name)
    )
    .map(([name]) => name)
    .sort()
);
export const convexWasmApplicationGlobalFacadeEngineGlobals = Object.freeze(
  Object.entries(convexWasmStaticHermesGlobalInventory.semantics)
    .filter(
      ([name, semantic]) =>
        semantic.read.state === "admitted" &&
        ordinaryDeterministicClasses.has(semantic.class) &&
        convexWasmStaticHermesGlobalInventory.targetRuntimeProbe.globals.includes(name)
    )
    .map(([name]) => name)
    .sort()
);
export const convexWasmStaticHermesGlobalSemantics = new Map(
  Object.entries(convexWasmStaticHermesGlobalInventory.semantics)
);
export const convexWasmSharedRuntimeSupportGlobals = Object.freeze(
  Object.entries(convexWasmStaticHermesGlobalInventory.semantics)
    .filter(([, semantic]) => semantic.provider === "shared-untyped-runtime-support")
    .map(([name]) => name)
    .sort()
);
export const convexWasmQueryMutationVisibleDeterministicGlobals = Object.freeze(
  Object.entries(convexWasmStaticHermesGlobalInventory.semantics)
    .filter(
      ([, semantic]) =>
        semantic.read.state === "admitted" && ordinaryDeterministicClasses.has(semantic.class)
    )
    .map(([name]) => name)
    .sort()
);
export const convexWasmRoutingEligibleStaticHermesGlobals = Object.freeze(
  [...convexWasmAdmittedStaticHermesGlobals, ...convexWasmSharedRuntimeSupportGlobals].sort()
);

export function assertConvexWasmStaticHermesTargetRuntimeGlobals(actualGlobals) {
  assertSortedUniqueNames(actualGlobals, "observed target runtime globals");
  assertSameNames(
    actualGlobals,
    convexWasmStaticHermesTargetRuntimeGlobals,
    "Static Hermes target runtime globals"
  );
}

export function assertConvexWasmStaticHermesTypedDeclarationGlobals(actualGlobals) {
  assertSortedUniqueNames(actualGlobals, "observed Static Hermes typed declarations");
  assertSameNames(
    actualGlobals,
    convexWasmStaticHermesTypedDeclarationGlobals,
    "Static Hermes typed declarations"
  );
}

export function assertConvexWasmQueryMutationVisibleDeterministicGlobals(actualGlobals) {
  assertSortedUniqueNames(actualGlobals, "observed query/mutation-visible deterministic globals");
  assertSameNames(
    actualGlobals,
    convexWasmQueryMutationVisibleDeterministicGlobals,
    "query/mutation-visible deterministic globals"
  );
}
