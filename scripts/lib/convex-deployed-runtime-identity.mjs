import { createHash } from "node:crypto";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmSourceEnvelopeKind,
  validateConvexWasmSourceEnvelope,
} from "./convex-wasm-source-envelope.mjs";

const AUTHORITY_KIND = "convex-deployed-runtime-binding-authority-v1";
const BINDING_DIAGNOSTIC_KIND = "convex-deployed-runtime-identity-diagnostic-v1";
const RUNTIME_IDENTITY_KIND = "convex-deployed-runtime-module-v2";
const SOURCE_PARITY_REPORT_KIND = "convex-wasm-source-parity-identity-v1";
const FROZEN_GRAPH_INPUT_KIND = "convex-isolated-full-frozen-graph-input-v1";
const FROZEN_GRAPH_BINDING_KIND = "convex-isolated-full-frozen-graph-binding-v1";
const SHA256 = /^[0-9a-f]{64}$/u;
const FROZEN_REQUEST_EVIDENCE_FIELDS = [
  "authoritativeDeploymentConfigurationModuleCount",
  "authoritativeDeploymentConfigurationModulesSha256",
  "authoritativeIsolateModuleCount",
  "authoritativeIsolateModulesSha256",
  "authoritativeModuleCount",
  "authoritativeModulesSha256",
  "authoritativeNodeModuleCount",
  "authoritativeNodeModulesSha256",
  "authoritativeUdfIsolateModuleCount",
  "authoritativeUdfIsolateModulesSha256",
  "requestModuleCount",
  "requestModulesSha256",
  "requestSha256",
  "requestSize",
  "selectedModuleCount",
  "selectedModules",
  "selectedModulesSha256",
  "selectedRouteCount",
];

function fail(message) {
  throw new Error(`Convex deployed runtime identity: ${message}`);
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

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function optionalSha256(value, description) {
  return value === null || value === undefined ? null : requireSha256(value, description);
}

function requireNonnegativeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a nonnegative safe integer`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireExactKeys(value, expectedKeys, description) {
  const keys = Object.keys(requireObject(value, description)).sort(compareStrings);
  const sortedExpectedKeys = [...expectedKeys].sort(compareStrings);
  if (
    keys.length !== sortedExpectedKeys.length ||
    keys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    fail(`${description} fields are invalid`);
  }
  return value;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// normalizeSourceMap returns either null or this fixed four-field identity. Keep equality checks
// scalar so binding validation does not repeatedly serialize module metadata.
function sourceMapIdentityEqual(left, right) {
  if (left === null || right === null) return left === right;
  return (
    left.sha256 === right.sha256 &&
    left.size === right.size &&
    left.sourcesContentCount === right.sourcesContentCount &&
    left.sourcesCount === right.sourcesCount
  );
}

function stringArrayIdentityEqual(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function normalizeSourceMap(value, description) {
  if (value === null) {
    return null;
  }
  const sourceMap = requireObject(value, description);
  if (
    sourceMap.sha256 === null &&
    sourceMap.size === 0 &&
    (sourceMap.sourcesContentCount ?? 0) === 0 &&
    (sourceMap.sourcesCount ?? 0) === 0
  ) {
    return null;
  }
  return {
    sha256: requireSha256(sourceMap.sha256, `${description} SHA-256`),
    size: requireNonnegativeInteger(sourceMap.size, `${description} size`),
    sourcesContentCount: requireNonnegativeInteger(
      sourceMap.sourcesContentCount ?? 0,
      `${description} sourcesContent count`
    ),
    sourcesCount: requireNonnegativeInteger(
      sourceMap.sourcesCount ?? 0,
      `${description} sources count`
    ),
  };
}

function normalizeAuthorityModule(value, index) {
  const module = requireObject(value, `authority module ${index}`);
  if (module.environment !== "isolate") {
    fail(`authority module ${index} must have isolate environment`);
  }
  const sourcePackageRuntimeContentSha256 = optionalSha256(
    module.sourcePackageRuntimeContentSha256,
    `authority module ${index} source-package runtime-content SHA-256`
  );
  return {
    environment: "isolate",
    moduleHashVerified: module.moduleHashVerified === true,
    moduleSha256: requireSha256(
      module.moduleSha256 ?? module.sha256,
      `authority module ${index} module SHA-256`
    ),
    path: requireString(module.path, `authority module ${index} path`),
    sourceMap: normalizeSourceMap(module.sourceMap ?? null, `authority module ${index} source map`),
    sourcePackageHashVerified: module.sourcePackageHashVerified === true,
    sourcePackageSha256: requireSha256(
      module.sourcePackageSha256,
      `authority module ${index} source-package SHA-256`
    ),
    ...(sourcePackageRuntimeContentSha256 === null ? {} : { sourcePackageRuntimeContentSha256 }),
    sourceSha256: optionalSha256(module.sourceSha256, `authority module ${index} source SHA-256`),
  };
}

function finishAuthority(modules, sourcePackageFileSha256) {
  const normalizedModules = modules
    .map(normalizeAuthorityModule)
    .sort((left, right) => compareStrings(left.path, right.path));
  const modulesByPath = new Map();
  for (const module of normalizedModules) {
    if (modulesByPath.has(module.path)) {
      const previous = modulesByPath.get(module.path);
      if (fingerprintJson(previous) !== fingerprintJson(module)) {
        fail(`authority contains conflicting material for ${module.path}`);
      }
      continue;
    }
    modulesByPath.set(module.path, module);
  }
  const packageDigests = [
    ...new Set(
      sourcePackageFileSha256.map((digest, index) =>
        requireSha256(digest, `source-package file SHA-256 ${index}`)
      )
    ),
  ].sort(compareStrings);
  if (packageDigests.length === 0) {
    fail("authority has no authenticated source-package files");
  }
  for (const module of modulesByPath.values()) {
    if (!packageDigests.includes(module.sourcePackageSha256)) {
      fail(
        `authority module ${module.path} references a source package without authenticated blob material`
      );
    }
  }
  const identity = {
    kind: AUTHORITY_KIND,
    modules: [...modulesByPath.values()],
    sourcePackageFileSha256: packageDigests,
  };
  return {
    identity,
    modulesByPath,
    sha256: fingerprintJson(identity),
    sourcePackageFileSha256: new Set(packageDigests),
  };
}

function normalizeFrozenSelectedModule(value, index) {
  const description = `frozen graph selected module ${index}`;
  const module = requireExactKeys(
    value,
    [
      "environment",
      "moduleSha256",
      "path",
      "sourceMap",
      "sourceMembershipSha256",
      "sourceSha256",
      "sourceSize",
    ],
    description
  );
  if (module.environment !== "isolate") {
    fail(`${description} must be an isolate module`);
  }
  if (module.sourceMap === null) {
    fail(`${description} must contain isolate source-map provenance`);
  }
  const sourceMap = normalizeSourceMap(
    requireExactKeys(
      module.sourceMap,
      ["sha256", "size", "sourcesContentCount", "sourcesCount"],
      `${description} source map`
    ),
    `${description} source map`
  );
  return {
    environment: "isolate",
    moduleSha256: requireSha256(module.moduleSha256, `${description} module SHA-256`),
    path: requireString(module.path, `${description} path`),
    sourceMap,
    sourceMembershipSha256: requireSha256(
      module.sourceMembershipSha256,
      `${description} source-membership SHA-256`
    ),
    sourceSha256: requireSha256(module.sourceSha256, `${description} source SHA-256`),
    sourceSize: requirePositiveInteger(module.sourceSize, `${description} source size`),
  };
}

function normalizeFrozenGraphInputAuthority(value) {
  const authority = requireExactKeys(
    value,
    ["inputAuthoritySha256", "kind", "request", "sourceEnvelope"],
    "frozen graph input authority"
  );
  if (authority.kind !== FROZEN_GRAPH_INPUT_KIND) {
    fail("frozen graph input authority kind is invalid");
  }
  const { inputAuthoritySha256, ...payload } = authority;
  if (
    requireSha256(inputAuthoritySha256, "frozen graph input authority SHA-256") !==
    fingerprintJson(payload)
  ) {
    fail("frozen graph input authority digest is invalid");
  }

  const request = requireExactKeys(
    authority.request,
    FROZEN_REQUEST_EVIDENCE_FIELDS,
    "frozen graph request evidence"
  );
  const normalizedRequest = {};
  for (const field of FROZEN_REQUEST_EVIDENCE_FIELDS) {
    if (field === "selectedModules") continue;
    normalizedRequest[field] = field.endsWith("Sha256")
      ? requireSha256(request[field], `frozen graph request ${field}`)
      : field === "requestSize"
        ? requirePositiveInteger(request[field], "frozen graph request size")
        : requireNonnegativeInteger(request[field], `frozen graph request ${field}`);
  }
  if (!Array.isArray(request.selectedModules) || request.selectedModules.length < 2) {
    fail("frozen graph input authority must select at least two runtime modules");
  }
  const selectedModules = request.selectedModules.map(normalizeFrozenSelectedModule);
  const selectedModulePaths = selectedModules.map(({ path }) => path);
  if (
    new Set(selectedModulePaths).size !== selectedModulePaths.length ||
    normalizedRequest.selectedModuleCount !== selectedModules.length ||
    normalizedRequest.selectedModulesSha256 !== fingerprintJson(selectedModules)
  ) {
    fail("frozen graph selected module identity set is invalid");
  }
  if (
    normalizedRequest.authoritativeModuleCount !== normalizedRequest.requestModuleCount ||
    normalizedRequest.authoritativeModuleCount !==
      normalizedRequest.authoritativeIsolateModuleCount +
        normalizedRequest.authoritativeNodeModuleCount ||
    normalizedRequest.authoritativeIsolateModuleCount !==
      normalizedRequest.authoritativeUdfIsolateModuleCount +
        normalizedRequest.authoritativeDeploymentConfigurationModuleCount ||
    normalizedRequest.authoritativeModulesSha256 !== normalizedRequest.requestModulesSha256 ||
    normalizedRequest.selectedRouteCount < normalizedRequest.selectedModuleCount
  ) {
    fail("frozen graph complete module census is inconsistent");
  }
  normalizedRequest.selectedModules = selectedModules;

  const sourceEnvelope = requireExactKeys(
    authority.sourceEnvelope,
    ["fileSha256", "fileSize", "graphSha256", "kind", "sha256"],
    "frozen graph source-envelope evidence"
  );
  if (sourceEnvelope.kind !== convexWasmSourceEnvelopeKind) {
    fail("frozen graph source-envelope kind is invalid");
  }
  return {
    inputAuthoritySha256,
    kind: FROZEN_GRAPH_INPUT_KIND,
    request: normalizedRequest,
    sourceEnvelope: {
      fileSha256: requireSha256(
        sourceEnvelope.fileSha256,
        "frozen graph source-envelope file SHA-256"
      ),
      fileSize: requirePositiveInteger(
        sourceEnvelope.fileSize,
        "frozen graph source-envelope file size"
      ),
      graphSha256: requireSha256(sourceEnvelope.graphSha256, "frozen graph source graph SHA-256"),
      kind: convexWasmSourceEnvelopeKind,
      sha256: requireSha256(sourceEnvelope.sha256, "frozen graph source-envelope SHA-256"),
    },
  };
}

function normalizeFrozenGraphBinding(value, normalizedAuthority) {
  const binding = requireExactKeys(
    value,
    [
      "bindingSha256",
      "deployedRuntimeAuthoritySha256",
      "inputAuthority",
      "kind",
      "runtimeModulePaths",
      "sourcePackage",
    ],
    "frozen graph binding"
  );
  if (binding.kind !== FROZEN_GRAPH_BINDING_KIND) {
    fail("frozen graph binding kind is invalid");
  }
  const { bindingSha256, ...payload } = binding;
  if (requireSha256(bindingSha256, "frozen graph binding SHA-256") !== fingerprintJson(payload)) {
    fail("frozen graph binding digest is invalid");
  }
  if (
    requireSha256(
      binding.deployedRuntimeAuthoritySha256,
      "frozen graph deployed-runtime authority SHA-256"
    ) !== normalizedAuthority.sha256
  ) {
    fail("frozen graph binding does not reference the normalized deployed-runtime authority");
  }

  const inputAuthority = normalizeFrozenGraphInputAuthority(binding.inputAuthority);
  if (!Array.isArray(binding.runtimeModulePaths)) {
    fail("frozen graph binding runtime module paths must be an array");
  }
  const runtimeModulePaths = binding.runtimeModulePaths.map((path, index) =>
    requireString(path, `frozen graph binding runtime module path ${index}`)
  );
  const expectedRuntimeModulePaths = inputAuthority.request.selectedModules
    .map(({ path }) => path)
    .sort(compareStrings);
  if (
    new Set(runtimeModulePaths).size !== runtimeModulePaths.length ||
    !stringArrayIdentityEqual(runtimeModulePaths, expectedRuntimeModulePaths)
  ) {
    fail("frozen graph binding runtime module paths differ from its input authority");
  }
  if (normalizedAuthority.identity.modules.length !== runtimeModulePaths.length) {
    fail("frozen graph binding does not cover exactly the normalized runtime authority modules");
  }

  for (const selectedModule of inputAuthority.request.selectedModules) {
    const runtimeModule = normalizedAuthority.modulesByPath.get(selectedModule.path);
    if (
      runtimeModule === undefined ||
      runtimeModule.environment !== "isolate" ||
      runtimeModule.moduleHashVerified !== true ||
      runtimeModule.sourcePackageHashVerified !== true ||
      runtimeModule.moduleSha256 !== selectedModule.moduleSha256 ||
      runtimeModule.sourceSha256 !== selectedModule.sourceSha256 ||
      !sourceMapIdentityEqual(runtimeModule.sourceMap, selectedModule.sourceMap)
    ) {
      fail(`frozen graph binding module ${selectedModule.path} differs from runtime authority`);
    }
  }

  const sourcePackage = requireExactKeys(
    binding.sourcePackage,
    ["sha256", "size"],
    "frozen graph binding source package"
  );
  const sourcePackageSha256 = requireSha256(
    sourcePackage.sha256,
    "frozen graph binding source-package SHA-256"
  );
  const sourcePackageSize = requirePositiveInteger(
    sourcePackage.size,
    "frozen graph binding source-package size"
  );
  if (
    normalizedAuthority.sourcePackageFileSha256.size !== 1 ||
    !normalizedAuthority.sourcePackageFileSha256.has(sourcePackageSha256) ||
    [...normalizedAuthority.modulesByPath.values()].some(
      (module) => module.sourcePackageSha256 !== sourcePackageSha256
    )
  ) {
    fail("frozen graph binding source package differs from runtime authority");
  }
  return {
    bindingSha256,
    deployedRuntimeAuthoritySha256: normalizedAuthority.sha256,
    inputAuthority,
    kind: FROZEN_GRAPH_BINDING_KIND,
    runtimeModulePaths,
    sourcePackage: { sha256: sourcePackageSha256, size: sourcePackageSize },
  };
}

export function verifyFrozenGraphBindingSourceEnvelope({
  normalizedAuthority,
  sourceEnvelope: sourceEnvelopeValue,
  sourceEnvelopeFileSha256,
  sourceEnvelopeFileSize,
}) {
  const binding = requireObject(
    normalizedAuthority,
    "normalized deployed-runtime authority"
  ).frozenGraphBinding;
  if (binding === null) return null;
  if (binding === undefined) {
    fail("normalized deployed-runtime authority has no frozen-graph binding state");
  }
  const sourceEnvelope = validateConvexWasmSourceEnvelope(sourceEnvelopeValue);
  const sourceEnvelopeBytes = Buffer.from(`${canonicalJson(sourceEnvelope)}\n`);
  const fileSha256 =
    sourceEnvelopeFileSha256 === undefined
      ? sha256(sourceEnvelopeBytes)
      : requireSha256(sourceEnvelopeFileSha256, "frozen graph source-envelope file SHA-256");
  const fileSize =
    sourceEnvelopeFileSize === undefined
      ? sourceEnvelopeBytes.length
      : requirePositiveInteger(sourceEnvelopeFileSize, "frozen graph source-envelope file size");
  const evidence = binding.inputAuthority.sourceEnvelope;
  const runtimeModulePaths = [
    ...new Set(sourceEnvelope.selectedRoutes.map(({ runtimeModulePath }) => runtimeModulePath)),
  ].sort(compareStrings);
  if (
    evidence.kind !== sourceEnvelope.kind ||
    evidence.sha256 !== sourceEnvelope.sourceEnvelopeSha256 ||
    evidence.graphSha256 !== sourceEnvelope.graph.sha256 ||
    evidence.fileSha256 !== fileSha256 ||
    evidence.fileSize !== fileSize ||
    !stringArrayIdentityEqual(runtimeModulePaths, binding.runtimeModulePaths)
  ) {
    fail("frozen graph binding source-envelope evidence is invalid");
  }
  return binding;
}

export function verifyFrozenGraphBindingRequestEvidence({
  normalizedAuthority,
  requestBytes,
  requestEvidence,
}) {
  const binding = requireObject(
    normalizedAuthority,
    "normalized deployed-runtime authority"
  ).frozenGraphBinding;
  if (binding === null) return null;
  if (binding === undefined) {
    fail("normalized deployed-runtime authority has no frozen-graph binding state");
  }
  if (!Buffer.isBuffer(requestBytes)) {
    fail("frozen graph request bytes must be a buffer");
  }
  if (
    requestBytes.length !== binding.inputAuthority.request.requestSize ||
    sha256(requestBytes) !== binding.inputAuthority.request.requestSha256 ||
    canonicalJson(requestEvidence) !== canonicalJson(binding.inputAuthority.request)
  ) {
    fail("frozen graph binding start-push evidence is invalid");
  }
  return binding;
}

function authorityFromSourceParityReport(report) {
  const { reportSha256: _reportSha256, ...payload } = report;
  if (report.reportSha256 !== fingerprintJson(payload)) {
    fail("source-parity report digest is invalid");
  }
  if (report.bindingAuthority !== undefined) {
    return normalizeDeployedRuntimeAuthority(report.bindingAuthority);
  }
  if (!Array.isArray(report.routeMatrix)) {
    fail("source-parity report routeMatrix must be an array");
  }
  const deployedAuthority = requireObject(
    requireObject(report.authority, "source-parity report authority").deployedRuntime,
    "source-parity deployed-runtime authority"
  );
  const backendMaterial = requireObject(
    deployedAuthority.backendMaterial,
    "source-parity backend material"
  );
  if (!Array.isArray(backendMaterial.sourcePackageFileSha256)) {
    fail("source-parity backend material must list source-package file SHA-256 values");
  }
  const modules = report.routeMatrix.map((row, index) => {
    requireObject(row, `source-parity route ${index}`);
    const runtime = requireObject(
      row.deployedRuntime,
      `source-parity route ${index} deployed runtime`
    );
    if (!Array.isArray(row.reasons)) {
      fail(`source-parity route ${index} reasons must be an array`);
    }
    const reasonCodes = new Set(
      row.reasons.map((reason, reasonIndex) =>
        requireString(
          requireObject(reason, `source-parity route ${index} reason ${reasonIndex}`).code,
          `source-parity route ${index} reason ${reasonIndex} code`
        )
      )
    );
    const sourcePackageRuntimeContentSha256 = runtime.sourcePackageRuntimeContentSha256 ?? null;
    return {
      environment: runtime.environment,
      moduleHashVerified: !reasonCodes.has("DEPLOYED_RUNTIME_MODULE_HASH_FAILED"),
      moduleSha256: runtime.moduleSha256,
      path: runtime.path,
      sourceMap: runtime.sourceMap,
      sourcePackageHashVerified: !reasonCodes.has("DEPLOYED_SOURCE_PACKAGE_HASH_FAILED"),
      sourcePackageSha256: runtime.sourcePackageSha256,
      ...(sourcePackageRuntimeContentSha256 === null ? {} : { sourcePackageRuntimeContentSha256 }),
      sourceSha256: runtime.sourceSha256 ?? null,
    };
  });
  return finishAuthority(modules, backendMaterial.sourcePackageFileSha256);
}

export function normalizeDeployedRuntimeAuthority(value) {
  const authority = requireObject(value, "authority");
  if (authority.kind === SOURCE_PARITY_REPORT_KIND) {
    return authorityFromSourceParityReport(authority);
  }
  if (authority.kind !== AUTHORITY_KIND) {
    fail(`unsupported authority kind ${JSON.stringify(authority.kind)}`);
  }
  if (!Array.isArray(authority.modules)) {
    fail("authority modules must be an array");
  }
  if (!Array.isArray(authority.sourcePackageFileSha256)) {
    fail("authority sourcePackageFileSha256 must be an array");
  }
  const normalized = finishAuthority(authority.modules, authority.sourcePackageFileSha256);
  if (authority.authoritySha256 !== undefined && authority.authoritySha256 !== normalized.sha256) {
    fail("authority digest is invalid");
  }
  const frozenGraphBinding =
    authority.frozenGraphBinding === undefined
      ? null
      : normalizeFrozenGraphBinding(authority.frozenGraphBinding, normalized);
  normalized.frozenGraphBinding = frozenGraphBinding;
  normalized.frozenGraphBindingIdentity =
    frozenGraphBinding === null
      ? null
      : { kind: frozenGraphBinding.kind, sha256: frozenGraphBinding.bindingSha256 };
  return normalized;
}

function diagnostic(code, detail) {
  return { code, detail };
}

function failedBinding(verdict, reasons) {
  return {
    diagnostic: {
      kind: BINDING_DIAGNOSTIC_KIND,
      reasons,
      verdict,
    },
    identity: null,
  };
}

export function bindDeployedRuntimeIdentity({ authority, bundleModule, runtimeModulePath }) {
  if (authority === undefined) {
    return failedBinding("unprovable", [
      diagnostic(
        "DEPLOYED_RUNTIME_AUTHORITY_NOT_PROVIDED",
        "no authenticated active or deployment source-package material was provided"
      ),
    ]);
  }
  if (bundleModule === undefined) {
    return failedBinding("unprovable", [
      diagnostic(
        "AUTHORITATIVE_BUNDLE_MODULE_NOT_FOUND",
        `the installed Convex bundler emitted no ${runtimeModulePath} module`
      ),
    ]);
  }
  const deployedModule = authority.modulesByPath.get(runtimeModulePath);
  if (deployedModule === undefined) {
    return failedBinding("unprovable", [
      diagnostic(
        "DEPLOYED_RUNTIME_AUTHORITY_MODULE_NOT_FOUND",
        `the authenticated deployed-runtime material contains no ${runtimeModulePath} module`
      ),
    ]);
  }
  const reasons = [];
  if (!deployedModule.moduleHashVerified) {
    reasons.push(
      diagnostic(
        "DEPLOYED_RUNTIME_MODULE_HASH_UNVERIFIED",
        "the selected source-package bytes did not authenticate the active module hash"
      )
    );
  }
  if (!deployedModule.sourcePackageHashVerified) {
    reasons.push(
      diagnostic(
        "DEPLOYED_SOURCE_PACKAGE_HASH_UNVERIFIED",
        "the selected source-package bytes did not authenticate the active package hash"
      )
    );
  }
  if (!authority.sourcePackageFileSha256.has(deployedModule.sourcePackageSha256)) {
    reasons.push(
      diagnostic(
        "DEPLOYED_SOURCE_PACKAGE_NOT_SELECTED",
        "the module source-package digest is absent from the authenticated selected package material"
      )
    );
  }
  if (bundleModule.environment !== deployedModule.environment) {
    reasons.push(
      diagnostic(
        "AUTHORITATIVE_BUNDLE_ENVIRONMENT_MISMATCH",
        "the installed Convex bundler output environment differs from the active module"
      )
    );
  }
  if (
    deployedModule.sourceSha256 !== null &&
    deployedModule.sourceSha256 !== bundleModule.sourceSha256
  ) {
    reasons.push(
      diagnostic(
        "AUTHORITATIVE_BUNDLE_JAVASCRIPT_MISMATCH",
        "the installed Convex bundler JavaScript bytes differ from the selected package"
      )
    );
  }
  const deployedMapSha256 = deployedModule.sourceMap?.sha256 ?? null;
  const bundleMapSha256 = bundleModule.sourceMap?.sha256 ?? null;
  if (deployedMapSha256 !== bundleMapSha256) {
    reasons.push(
      diagnostic(
        "AUTHORITATIVE_BUNDLE_SOURCE_MAP_MISMATCH",
        "the installed Convex bundler source-map bytes differ from the selected package"
      )
    );
  }
  if (deployedModule.moduleSha256 !== bundleModule.moduleSha256) {
    if (
      !reasons.some(
        ({ code }) =>
          code === "AUTHORITATIVE_BUNDLE_JAVASCRIPT_MISMATCH" ||
          code === "AUTHORITATIVE_BUNDLE_SOURCE_MAP_MISMATCH"
      )
    ) {
      reasons.push(
        diagnostic(
          "AUTHORITATIVE_BUNDLE_MODULE_MISMATCH",
          "the installed Convex bundle does not reproduce the active source-plus-map SHA-256"
        )
      );
    }
  }
  if (reasons.length > 0) {
    return failedBinding("mismatch", reasons);
  }
  const sourcePackageRuntimeContentSha256 =
    deployedModule.sourcePackageRuntimeContentSha256 ?? null;
  if (sourcePackageRuntimeContentSha256 === null) {
    return failedBinding("unprovable", [
      diagnostic(
        "DEPLOYED_SOURCE_PACKAGE_RUNTIME_CONTENT_DIGEST_NOT_FOUND",
        "the deployed SourcePackage predates the persisted runtime-content digest"
      ),
    ]);
  }
  return {
    diagnostic: null,
    identity: {
      kind: RUNTIME_IDENTITY_KIND,
      moduleSha256: bundleModule.moduleSha256,
      sourcePackageRuntimeContentSha256,
    },
  };
}

export function bindDeploymentRuntimeIdentities({
  authority: authorityValue,
  bundleModulesByPath,
  runtimeModulePaths,
}) {
  const authority =
    authorityValue === undefined ? undefined : normalizeDeployedRuntimeAuthority(authorityValue);
  const bindings = new Map();
  for (const runtimeModulePath of [...new Set(runtimeModulePaths)].sort(compareStrings)) {
    bindings.set(
      runtimeModulePath,
      bindDeployedRuntimeIdentity({
        authority,
        bundleModule: bundleModulesByPath?.get(runtimeModulePath),
        runtimeModulePath,
      })
    );
  }
  return bindings;
}

export const deployedRuntimeBindingAuthorityKind = AUTHORITY_KIND;
