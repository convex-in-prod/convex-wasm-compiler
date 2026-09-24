import { createHash } from "node:crypto";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { normalizeDeployedRuntimeAuthority } from "./convex-deployed-runtime-identity.mjs";
import { convexWasmSourceEnvelopeKind } from "./convex-wasm-source-envelope.mjs";

const FROZEN_GRAPH_INPUT_KIND = "convex-isolated-full-frozen-graph-input-v1";
const FROZEN_GRAPH_BINDING_KIND = "convex-isolated-full-frozen-graph-binding-v1";
const SHA256 = /^[a-f0-9]{64}$/u;

function fail(message) {
  throw new Error(`Convex Wasm frozen graph authority: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a nonempty string`);
  }
  return value;
}

function requireSha256(value, description) {
  const digest = requireString(value, description);
  if (!SHA256.test(digest)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return digest;
}

function requireExactKeys(value, expectedKeys, description) {
  if (
    canonicalJson(Object.keys(requireObject(value, description)).sort()) !==
    canonicalJson([...expectedKeys].sort())
  ) {
    fail(`${description} fields are invalid`);
  }
}

function requireNonnegativeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a nonnegative safe integer`);
  }
  return value;
}

function selectedSourcePackageIdentityForRuntimeModules({ authority, runtimeModulePaths }) {
  if (
    !Array.isArray(runtimeModulePaths) ||
    runtimeModulePaths.length === 0 ||
    runtimeModulePaths.some((path) => typeof path !== "string" || path.length === 0)
  ) {
    fail("selected runtime module paths must be a nonempty string array");
  }
  const uniqueRuntimeModulePaths = [...new Set(runtimeModulePaths)].sort();
  if (uniqueRuntimeModulePaths.length !== runtimeModulePaths.length) {
    fail("selected runtime module paths must be unique");
  }

  let selectedSourcePackageSha256;
  let selectedSourcePackageRuntimeContentSha256;
  for (const runtimeModulePath of uniqueRuntimeModulePaths) {
    const matches = authority.modules.filter((module) => module?.path === runtimeModulePath);
    if (matches.length !== 1) {
      fail(`Authenticated runtime binding authority has no unique selected module ${runtimeModulePath}`);
    }
    const module = requireObject(
      matches[0],
      `Authenticated selected runtime binding authority module ${runtimeModulePath}`
    );
    if (module.sourcePackageHashVerified !== true) {
      fail(`Authenticated selected runtime module ${runtimeModulePath} has no verified source package`);
    }
    const moduleSourcePackageSha256 = requireSha256(
      module.sourcePackageSha256,
      `Authenticated selected module ${runtimeModulePath} source-package SHA-256`
    );
    const moduleSourcePackageRuntimeContentSha256 = requireSha256(
      module.sourcePackageRuntimeContentSha256,
      `Authenticated selected module ${runtimeModulePath} source-package runtime-content SHA-256`
    );
    if (
      selectedSourcePackageSha256 !== undefined &&
      selectedSourcePackageSha256 !== moduleSourcePackageSha256
    ) {
      fail("Authenticated selected runtime modules do not authenticate one source package");
    }
    if (
      selectedSourcePackageRuntimeContentSha256 !== undefined &&
      selectedSourcePackageRuntimeContentSha256 !== moduleSourcePackageRuntimeContentSha256
    ) {
      fail("Authenticated selected runtime modules do not authenticate one runtime-content identity");
    }
    selectedSourcePackageSha256 = moduleSourcePackageSha256;
    selectedSourcePackageRuntimeContentSha256 = moduleSourcePackageRuntimeContentSha256;
  }
  return {
    sourcePackageRuntimeContentSha256: selectedSourcePackageRuntimeContentSha256,
    sourcePackageSha256: selectedSourcePackageSha256,
  };
}

export function verifySelectedRuntimeAuthority({ bindingAuthority, selectedModules }) {
  const authority = requireObject(bindingAuthority, "Authenticated runtime binding authority");
  if (!Array.isArray(authority.modules)) {
    fail("Authenticated runtime binding authority modules must be an array");
  }
  if (!Array.isArray(selectedModules) || selectedModules.length === 0) {
    fail("frozen selected modules must be a nonempty array");
  }
  const expectedModulesByPath = new Map();
  for (const [index, selectedModule] of selectedModules.entries()) {
    const selected = requireObject(selectedModule, `frozen selected module ${index}`);
    const path = requireString(selected.path, `frozen selected module ${index} path`);
    if (expectedModulesByPath.has(path)) {
      fail(`frozen selected modules contain duplicate path ${path}`);
    }
    expectedModulesByPath.set(path, selected);
  }
  if (authority.modules.length !== expectedModulesByPath.size) {
    fail("Authenticated runtime authority does not contain exactly the frozen selected modules");
  }

  const runtimeModulePaths = [...expectedModulesByPath.keys()].sort();
  for (const runtimeModulePath of runtimeModulePaths) {
    const expected = expectedModulesByPath.get(runtimeModulePath);
    const matches = authority.modules.filter((module) => module?.path === runtimeModulePath);
    if (matches.length !== 1) {
      fail(`Authenticated runtime authority has no unique frozen selected module ${runtimeModulePath}`);
    }
    const actual = requireObject(
      matches[0],
      `Authenticated runtime authority module ${runtimeModulePath}`
    );
    if (
      actual.environment !== "isolate" ||
      actual.moduleHashVerified !== true ||
      actual.sourcePackageHashVerified !== true ||
      requireSha256(actual.moduleSha256, `Authenticated runtime module ${runtimeModulePath} SHA-256`) !==
        expected.moduleSha256 ||
      requireSha256(
        actual.sourceSha256,
        `Authenticated runtime module ${runtimeModulePath} source SHA-256`
      ) !== expected.sourceSha256 ||
      canonicalJson(actual.sourceMap) !== canonicalJson(expected.sourceMap)
    ) {
      fail(`Authenticated runtime authority differs from frozen selected module ${runtimeModulePath}`);
    }
  }
  const selectedSourcePackageIdentity = selectedSourcePackageIdentityForRuntimeModules({
    authority,
    runtimeModulePaths,
  });
  return {
    runtimeModulePaths,
    ...selectedSourcePackageIdentity,
  };
}

export function createFullFrozenGraphBindingAuthority({
  bindingAuthority,
  frozenGraphInputAuthority: inputValue,
  sourceEnvelopeBytes,
  sourcePackage,
  startPushBytes,
}) {
  const inputAuthority = validateFrozenGraphInputAuthority(inputValue);
  if (!Buffer.isBuffer(startPushBytes)) {
    fail("frozen start-push bytes must be a buffer during final binding");
  }
  if (startPushBytes.length !== inputAuthority.request.requestSize) {
    fail("frozen start-push request size changed after current-graph authentication");
  }
  if (sha256(startPushBytes) !== inputAuthority.request.requestSha256) {
    fail("frozen start-push request digest changed after current-graph authentication");
  }
  if (!Buffer.isBuffer(sourceEnvelopeBytes)) {
    fail("source-envelope bytes must be a buffer during final binding");
  }
  if (sourceEnvelopeBytes.length !== inputAuthority.sourceEnvelope.fileSize) {
    fail("source-envelope file size changed after current-graph authentication");
  }
  if (sha256(sourceEnvelopeBytes) !== inputAuthority.sourceEnvelope.fileSha256) {
    fail("source-envelope file digest changed after current-graph authentication");
  }

  const normalizedRuntimeAuthority = normalizeDeployedRuntimeAuthority(bindingAuthority);
  if (
    requireSha256(bindingAuthority.authoritySha256, "deployed-runtime authority SHA-256") !==
    normalizedRuntimeAuthority.sha256
  ) {
    fail("deployed-runtime authority digest changed during final binding");
  }
  const selectedRuntimeAuthority = verifySelectedRuntimeAuthority({
    bindingAuthority,
    selectedModules: inputAuthority.request.selectedModules,
  });
  const sourcePackageDescriptor = requireObject(sourcePackage, "authenticated source package");
  requireExactKeys(
    sourcePackageDescriptor,
    ["path", "sha256", "size"],
    "authenticated source package"
  );
  requireString(sourcePackageDescriptor.path, "authenticated source-package path");
  const sourcePackageSha256 = requireSha256(
    sourcePackageDescriptor.sha256,
    "authenticated source-package SHA-256"
  );
  if (!Number.isSafeInteger(sourcePackageDescriptor.size) || sourcePackageDescriptor.size <= 0) {
    fail("authenticated source-package size must be a positive safe integer");
  }
  if (sourcePackageSha256 !== selectedRuntimeAuthority.sourcePackageSha256) {
    fail("authenticated source package differs from the selected runtime authority");
  }
  const expectedRuntimeModulePaths = inputAuthority.request.selectedModules
    .map(({ path }) => path)
    .sort();
  if (
    canonicalJson(selectedRuntimeAuthority.runtimeModulePaths) !==
    canonicalJson(expectedRuntimeModulePaths)
  ) {
    fail("selected runtime module paths changed during final binding");
  }
  if (Object.hasOwn(bindingAuthority, "frozenGraphBinding")) {
    fail("deployed-runtime authority already contains a frozen-graph binding");
  }

  const bindingPayload = {
    deployedRuntimeAuthoritySha256: normalizedRuntimeAuthority.sha256,
    inputAuthority: structuredClone(inputAuthority),
    kind: FROZEN_GRAPH_BINDING_KIND,
    runtimeModulePaths: selectedRuntimeAuthority.runtimeModulePaths,
    sourcePackage: {
      sha256: sourcePackageSha256,
      size: sourcePackageDescriptor.size,
    },
  };
  const frozenGraphBinding = {
    ...bindingPayload,
    bindingSha256: fingerprintJson(bindingPayload),
  };
  return {
    authority: { ...bindingAuthority, frozenGraphBinding },
    frozenGraphBinding,
    selectedRuntimeAuthority,
  };
}

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

function validateFrozenSelectedModule(value, index) {
  const description = `frozen graph selected module ${index}`;
  requireExactKeys(
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
  if (value.environment !== "isolate") {
    fail(`${description} must be an isolate module`);
  }
  requireSha256(value.moduleSha256, `${description} module SHA-256`);
  requireString(value.path, `${description} path`);
  requireSha256(value.sourceMembershipSha256, `${description} source-membership SHA-256`);
  requireSha256(value.sourceSha256, `${description} source SHA-256`);
  if (!Number.isSafeInteger(value.sourceSize) || value.sourceSize <= 0) {
    fail(`${description} source size must be a positive safe integer`);
  }
  if (value.sourceMap === null) {
    fail(`${description} must contain isolate source-map provenance`);
  }
  requireExactKeys(
    value.sourceMap,
    ["sha256", "size", "sourcesContentCount", "sourcesCount"],
    `${description} source map`
  );
  requireSha256(value.sourceMap.sha256, `${description} source-map SHA-256`);
  for (const field of ["size", "sourcesContentCount", "sourcesCount"]) {
    requireNonnegativeInteger(value.sourceMap[field], `${description} source-map ${field}`);
  }
  return value;
}

function validateFrozenGraphInputAuthority(value) {
  const authority = requireObject(value, "frozen graph input authority");
  requireExactKeys(
    authority,
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

  const request = requireObject(authority.request, "frozen graph request evidence");
  requireExactKeys(request, FROZEN_REQUEST_EVIDENCE_FIELDS, "frozen graph request evidence");
  for (const field of FROZEN_REQUEST_EVIDENCE_FIELDS.filter((field) => field.endsWith("Count"))) {
    requireNonnegativeInteger(request[field], `frozen graph request ${field}`);
  }
  if (!Number.isSafeInteger(request.requestSize) || request.requestSize <= 0) {
    fail("frozen graph request size must be a positive safe integer");
  }
  for (const field of FROZEN_REQUEST_EVIDENCE_FIELDS.filter((field) => field.endsWith("Sha256"))) {
    requireSha256(request[field], `frozen graph request ${field}`);
  }
  if (!Array.isArray(request.selectedModules) || request.selectedModules.length === 0) {
    fail("frozen graph input authority must select at least one runtime module");
  }
  const selectedModules = request.selectedModules.map(validateFrozenSelectedModule);
  const selectedModulePaths = selectedModules.map(({ path }) => path);
  if (
    new Set(selectedModulePaths).size !== selectedModulePaths.length ||
    request.selectedModuleCount !== selectedModules.length ||
    request.selectedModulesSha256 !== fingerprintJson(selectedModules)
  ) {
    fail("frozen graph selected module identity set is invalid");
  }
  if (
    request.authoritativeModuleCount !== request.requestModuleCount ||
    request.authoritativeModuleCount !==
      request.authoritativeIsolateModuleCount + request.authoritativeNodeModuleCount ||
    request.authoritativeIsolateModuleCount !==
      request.authoritativeUdfIsolateModuleCount +
        request.authoritativeDeploymentConfigurationModuleCount ||
    request.authoritativeModulesSha256 !== request.requestModulesSha256 ||
    request.selectedRouteCount < request.selectedModuleCount
  ) {
    fail("frozen graph complete module census is inconsistent");
  }

  const sourceEnvelope = requireObject(
    authority.sourceEnvelope,
    "frozen graph source-envelope evidence"
  );
  requireExactKeys(
    sourceEnvelope,
    ["fileSha256", "fileSize", "graphSha256", "kind", "sha256"],
    "frozen graph source-envelope evidence"
  );
  requireSha256(sourceEnvelope.fileSha256, "frozen graph source-envelope file SHA-256");
  requireSha256(sourceEnvelope.graphSha256, "frozen graph source graph SHA-256");
  if (sourceEnvelope.kind !== convexWasmSourceEnvelopeKind) {
    fail("frozen graph source-envelope kind is invalid");
  }
  requireSha256(sourceEnvelope.sha256, "frozen graph source-envelope SHA-256");
  if (!Number.isSafeInteger(sourceEnvelope.fileSize) || sourceEnvelope.fileSize <= 0) {
    fail("frozen graph source-envelope file size must be a positive safe integer");
  }
  return authority;
}

export function createFrozenGraphInputAuthority({ evidence, sourceEnvelope, sourceEnvelopeBytes }) {
  const payload = {
    kind: FROZEN_GRAPH_INPUT_KIND,
    request: structuredClone(evidence),
    sourceEnvelope: {
      fileSha256: sha256(sourceEnvelopeBytes),
      fileSize: sourceEnvelopeBytes.length,
      graphSha256: sourceEnvelope.graph.sha256,
      kind: sourceEnvelope.kind,
      sha256: sourceEnvelope.sourceEnvelopeSha256,
    },
  };
  return validateFrozenGraphInputAuthority({
    ...payload,
    inputAuthoritySha256: fingerprintJson(payload),
  });
}
