import { createHash } from "node:crypto";

import {
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  requireExactPlainObject,
  requireManifestString,
  requirePositiveInteger,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";

export const convexWasmV8ExclusionManifestKind = "convex-wasm-v8-exclusion-manifest-v1";
export const convexWasmV8ExclusionBindingKind = "convex-wasm-v8-exclusion-binding-v1";
export const convexWasmV8ExclusionFallbackKind = "convex-wasm-operator-v8-fallback-v1";
export const convexWasmV8ExclusionFallbackReason = "operator-v8-exclusion-v1";

const SCHEMA_VERSION = 1;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_MODULE_PATH_BYTES = 1024;
const MAX_EXPORT_NAME_BYTES = 1024;
const MAX_REASON_BYTES = 4096;
const MAX_OPERATOR_REFERENCE_BYTES = 2048;

function selectorKey(selector) {
  return `${selector.modulePath}\0${selector.exportName ?? ""}`;
}

function targetKey(target) {
  return `${target.entryPath}\0${target.exportName}`;
}

function compareSelectors(left, right) {
  return compareStrings(selectorKey(left), selectorKey(right));
}

function requireCanonicalModulePath(value, description) {
  const modulePath = requireManifestString(value, description, MAX_MODULE_PATH_BYTES, false);
  if (
    modulePath.startsWith("/") ||
    modulePath.includes("\\") ||
    modulePath.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${description} must be a canonical generated API module path`);
  }
  return modulePath;
}

function requirePlainReason(value, description) {
  const reason = requireManifestString(value, description, MAX_REASON_BYTES, true);
  if (reason.trim().length === 0) {
    fail(`${description} must contain non-whitespace text`);
  }
  return reason;
}

function requireOperatorReference(value, description) {
  return requireManifestString(value, description, MAX_OPERATOR_REFERENCE_BYTES, false);
}

function normalizeSelector(value, description) {
  const selector = requireExactPlainObject(
    value,
    Object.hasOwn(value ?? {}, "exportName") ? ["exportName", "modulePath"] : ["modulePath"],
    description
  );
  return {
    ...(selector.exportName === undefined
      ? {}
      : {
          exportName: requireManifestString(
            selector.exportName,
            `${description} exportName`,
            MAX_EXPORT_NAME_BYTES,
            false
          ),
        }),
    modulePath: requireCanonicalModulePath(selector.modulePath, `${description} modulePath`),
  };
}

function normalizeManifestEntry(value, index) {
  const entry = requireExactPlainObject(
    value,
    ["operatorReference", "reason", "selector"],
    `V8 exclusion manifest entry ${index}`
  );
  return {
    operatorReference: requireOperatorReference(
      entry.operatorReference,
      `V8 exclusion manifest entry ${index} operatorReference`
    ),
    reason: requirePlainReason(entry.reason, `V8 exclusion manifest entry ${index} reason`),
    selector: normalizeSelector(entry.selector, `V8 exclusion manifest entry ${index} selector`),
  };
}

export function validateConvexWasmV8ExclusionManifest(value) {
  const manifest = requireExactPlainObject(
    value,
    ["entries", "kind", "manifestSha256", "schemaVersion"],
    "V8 exclusion manifest"
  );
  if (
    manifest.kind !== convexWasmV8ExclusionManifestKind ||
    manifest.schemaVersion !== SCHEMA_VERSION ||
    !Array.isArray(manifest.entries)
  ) {
    fail("V8 exclusion manifest kind or schema version is unsupported");
  }
  const entries = manifest.entries.map(normalizeManifestEntry);
  for (let index = 1; index < entries.length; index += 1) {
    const comparison = compareSelectors(entries[index - 1].selector, entries[index].selector);
    if (comparison === 0) {
      fail(`V8 exclusion manifest has duplicate selector ${selectorKey(entries[index].selector)}`);
    }
    if (comparison > 0) {
      fail("V8 exclusion manifest entries must be sorted by exact selector");
    }
  }
  const payload = {
    entries,
    kind: manifest.kind,
    schemaVersion: manifest.schemaVersion,
  };
  if (
    requireSha256(manifest.manifestSha256, "V8 exclusion manifest SHA-256") !==
    fingerprintJson(payload)
  ) {
    fail("V8 exclusion manifest SHA-256 does not authenticate its contents");
  }
  return { ...payload, manifestSha256: manifest.manifestSha256 };
}

export function parseConvexWasmV8ExclusionManifestBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) {
    fail(`V8 exclusion manifest bytes must contain 1 to ${MAX_MANIFEST_BYTES} bytes`);
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error("Convex Wasm artifact pipeline: V8 exclusion manifest is not UTF-8", {
      cause: error,
    });
  }
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm artifact pipeline: V8 exclusion manifest is not JSON", {
      cause: error,
    });
  }
  return validateConvexWasmV8ExclusionManifest(parsed);
}

export function createConvexWasmV8ExclusionManifestFileIdentity(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) {
    fail(`V8 exclusion manifest bytes must contain 1 to ${MAX_MANIFEST_BYTES} bytes`);
  }
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  };
}

function normalizeManifestFileIdentity(value) {
  const identity = requireExactPlainObject(
    value,
    ["sha256", "size"],
    "V8 exclusion manifest file identity"
  );
  return {
    sha256: requireSha256(identity.sha256, "V8 exclusion manifest file SHA-256"),
    size: requirePositiveInteger(identity.size, "V8 exclusion manifest file size"),
  };
}

function normalizedInventoryFunctions(functions) {
  if (!Array.isArray(functions)) {
    fail("V8 exclusion resolver functions must be an array");
  }
  const seen = new Set();
  return functions
    .map((value, index) => {
      const func = requireExactPlainObject(
        value,
        ["entryPath", "exportName", "modulePath", "udfKind", "visibility"],
        `V8 exclusion resolver function ${index}`
      );
      if (!new Set(["query", "mutation"]).has(func.udfKind)) {
        fail(`V8 exclusion resolver function ${index} must be a query or mutation`);
      }
      const normalized = {
        entryPath: requireString(
          func.entryPath,
          `V8 exclusion resolver function ${index} entryPath`
        ),
        exportName: requireManifestString(
          func.exportName,
          `V8 exclusion resolver function ${index} exportName`,
          MAX_EXPORT_NAME_BYTES,
          false
        ),
        modulePath: requireCanonicalModulePath(
          func.modulePath,
          `V8 exclusion resolver function ${index} modulePath`
        ),
        udfKind: func.udfKind,
        visibility: requireString(
          func.visibility,
          `V8 exclusion resolver function ${index} visibility`
        ),
      };
      const key = targetKey(normalized);
      if (seen.has(key)) {
        fail(
          `V8 exclusion resolver functions contain duplicate route ${normalized.modulePath}:${normalized.exportName}`
        );
      }
      seen.add(key);
      return normalized;
    })
    .sort((left, right) => {
      const moduleOrder = compareStrings(left.modulePath, right.modulePath);
      if (moduleOrder !== 0) return moduleOrder;
      const exportOrder = compareStrings(left.exportName, right.exportName);
      return exportOrder === 0 ? compareStrings(left.entryPath, right.entryPath) : exportOrder;
    });
}

/**
 * Resolve authenticated selectors to the exact current query/mutation routes before graph or
 * member compilation begins. The result is subtractive: it only identifies existing routes that
 * must not receive a Wasm artifact.
 */
export function resolveConvexWasmV8Exclusions({
  manifest: rawManifest,
  manifestFileIdentity,
  functions,
}) {
  if (rawManifest === undefined) {
    if (manifestFileIdentity !== undefined) {
      fail("V8 exclusion manifest file identity requires a manifest");
    }
    return undefined;
  }
  const manifest = validateConvexWasmV8ExclusionManifest(rawManifest);
  if (manifestFileIdentity === undefined) {
    fail("V8 exclusion manifest requires its exact file SHA-256 and size");
  }
  const file = normalizeManifestFileIdentity(manifestFileIdentity);
  const inventory = normalizedInventoryFunctions(functions);
  const matchedRoutes = new Map();
  const appliedSelectors = [];
  for (const entry of manifest.entries) {
    const matchingModule = inventory.filter(
      (func) => func.modulePath === entry.selector.modulePath
    );
    const matching =
      entry.selector.exportName === undefined
        ? matchingModule
        : matchingModule.filter((func) => func.exportName === entry.selector.exportName);
    if (matching.length === 0) {
      const target =
        entry.selector.exportName === undefined
          ? entry.selector.modulePath
          : `${entry.selector.modulePath}:${entry.selector.exportName}`;
      fail(`V8 exclusion selector does not match a query or mutation route: ${target}`);
    }
    appliedSelectors.push({
      operatorReference: entry.operatorReference,
      reason: entry.reason,
      selector: entry.selector,
    });
    for (const func of matching) {
      const key = targetKey(func);
      if (matchedRoutes.has(key)) {
        fail(
          `V8 exclusion selectors overlap at ${func.modulePath}:${func.exportName}; use one exact selector per route`
        );
      }
      matchedRoutes.set(key, { ...func, ...entry });
    }
  }
  const routes = [...matchedRoutes.values()]
    .map(({ entryPath, exportName, modulePath, operatorReference, reason, selector }) => ({
      entryPath,
      exportName,
      modulePath,
      operatorReference,
      reason,
      selector,
    }))
    .sort((left, right) => {
      const moduleOrder = compareStrings(left.modulePath, right.modulePath);
      return moduleOrder === 0 ? compareStrings(left.exportName, right.exportName) : moduleOrder;
    });
  const bindingPayload = {
    appliedRoutes: routes.map(({ entryPath, exportName, modulePath, selector }) => ({
      entryPath,
      exportName,
      modulePath,
      selector,
    })),
    appliedSelectors,
    file,
    kind: convexWasmV8ExclusionBindingKind,
    manifest: {
      kind: manifest.kind,
      sha256: manifest.manifestSha256,
    },
  };
  const binding = { ...bindingPayload, sha256: fingerprintJson(bindingPayload) };
  return {
    binding,
    excludedTargetKeys: new Set(routes.map(targetKey)),
    routes,
  };
}

function v8FallbackRecord(route, binding) {
  return {
    kind: convexWasmV8ExclusionFallbackKind,
    exclusionBinding: { kind: binding.kind, sha256: binding.sha256 },
    operatorReference: route.operatorReference,
    reason: route.reason,
    selector: route.selector,
  };
}

function routeCount(exports, decision, reason) {
  return exports.filter(
    (entry) =>
      entry.routing?.decision === decision &&
      (reason === undefined || entry.routing.reason === reason)
  ).length;
}

/**
 * Keep deployment authority complete while removing any prior Wasm receipt for resolved routes.
 * This intentionally cannot create a route or make an existing-runtime route eligible for Wasm.
 */
export function applyConvexWasmV8ExclusionsToDeploymentManifest({
  manifest: rawManifest,
  resolution,
}) {
  if (resolution === undefined) return rawManifest;
  const manifest = requireExactPlainObject(
    rawManifest,
    Object.keys(rawManifest ?? {}),
    "deployment manifest"
  );
  if (!Array.isArray(manifest.exports) || manifest.counts === undefined) {
    fail(
      "deployment manifest cannot record V8 exclusions without complete route and count records"
    );
  }
  if (Object.hasOwn(manifest, "v8Exclusions")) {
    fail("deployment manifest already contains a V8 exclusion binding");
  }
  const exportsByTarget = new Map();
  for (const [index, entry] of manifest.exports.entries()) {
    const route = requireExactPlainObject(
      entry,
      Object.keys(entry ?? {}),
      `deployment manifest export ${index}`
    );
    const key = targetKey({
      entryPath: requireString(route.entryPath, `deployment manifest export ${index} entryPath`),
      exportName: requireString(route.exportName, `deployment manifest export ${index} exportName`),
    });
    if (exportsByTarget.has(key)) {
      fail(`deployment manifest repeats route ${key}`);
    }
    exportsByTarget.set(key, index);
  }
  const exports = [...manifest.exports];
  const operatorV8FallbackEligibleTargets = new Set();
  for (const route of resolution.routes) {
    const index = exportsByTarget.get(targetKey(route));
    if (index === undefined) {
      fail(`deployment manifest omits excluded route ${route.modulePath}:${route.exportName}`);
    }
    const previous = exports[index];
    if (
      previous.routing?.decision === "wasm" ||
      (previous.routing?.decision === "existingRuntime" &&
        previous.routing.reason === "not-selected") ||
      (previous.routing?.decision === "v8Fallback" &&
        previous.routing.reason === "static-hermes-source-incompatibility-v1")
    ) {
      operatorV8FallbackEligibleTargets.add(targetKey(route));
    }
    const {
      artifact: ignoredArtifact,
      compilerLimits: ignoredCompilerLimits,
      packageReference: ignoredPackageReference,
      ...withoutWasmReceipt
    } = previous;
    exports[index] = {
      ...withoutWasmReceipt,
      artifact: null,
      packageReference: null,
      routing: { decision: "v8Fallback", reason: convexWasmV8ExclusionFallbackReason },
      v8Fallback: v8FallbackRecord(route, resolution.binding),
    };
  }
  const selectedWasm = routeCount(exports, "wasm");
  const artifactFallback = routeCount(
    exports,
    "v8Fallback",
    "static-hermes-source-incompatibility-v1"
  );
  const operatorV8Fallback = routeCount(exports, "v8Fallback", convexWasmV8ExclusionFallbackReason);
  const unselectedEligible = routeCount(exports, "existingRuntime", "not-selected");
  const total = exports.length;
  const eligible = manifest.counts.eligible;
  if (!Number.isSafeInteger(eligible) || eligible < 0 || eligible > total) {
    fail("deployment manifest has an invalid eligible route count");
  }
  const operatorV8FallbackEligible = operatorV8FallbackEligibleTargets.size;
  if (
    selectedWasm + artifactFallback + operatorV8FallbackEligible + unselectedEligible !==
    eligible
  ) {
    fail("V8 exclusions changed the deployment eligibility partition");
  }
  const counts = {
    ...manifest.counts,
    artifactFallback,
    eligible,
    ineligible: total - eligible,
    mutations: exports.filter((entry) => entry.udfKind === "mutation").length,
    operatorV8Fallback,
    operatorV8FallbackEligible,
    queries: exports.filter((entry) => entry.udfKind === "query").length,
    selectedWasm,
    total,
    unselectedEligible,
  };
  const { deploymentSha256: ignoredDeploymentSha256, ...withoutIdentity } = manifest;
  const payload = {
    ...withoutIdentity,
    counts,
    exports,
    v8Exclusions: resolution.binding,
  };
  return { ...payload, deploymentSha256: fingerprintJson(payload) };
}

export function renderConvexWasmV8ExclusionManifest({ entries }) {
  const normalizedEntries = entries
    .map(normalizeManifestEntry)
    .sort((left, right) => compareSelectors(left.selector, right.selector));
  for (let index = 1; index < normalizedEntries.length; index += 1) {
    if (
      compareSelectors(normalizedEntries[index - 1].selector, normalizedEntries[index].selector) ===
      0
    ) {
      fail(
        `V8 exclusion manifest has duplicate selector ${selectorKey(normalizedEntries[index].selector)}`
      );
    }
  }
  const payload = {
    entries: normalizedEntries,
    kind: convexWasmV8ExclusionManifestKind,
    schemaVersion: SCHEMA_VERSION,
  };
  return { ...payload, manifestSha256: fingerprintJson(payload) };
}

export function canonicalConvexWasmV8ExclusionManifest(manifest) {
  return `${canonicalJson(validateConvexWasmV8ExclusionManifest(manifest))}\n`;
}
