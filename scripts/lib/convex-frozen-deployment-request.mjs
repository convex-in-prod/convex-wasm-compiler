import { createHash } from "node:crypto";
import { promisify } from "node:util";
import zlib from "node:zlib";

import { validateAuthenticatedConvexOrigin } from "./convex-authenticated-origin.mjs";
import { validateTargetExternalDepsSelection } from "./convex-target-external-deps.mjs";
import { validateConvexMysqlDatabaseIdentity } from "./convex-local-backend-database.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmSourceEnvelopeKind,
  validateConvexWasmSourceEnvelope,
  verifyCurrentConvexWasmSourceEnvelope,
} from "./convex-wasm-source-envelope.mjs";
import {
  normalizeDeployedRuntimeAuthority,
  verifyFrozenGraphBindingRequestEvidence,
  verifyFrozenGraphBindingSourceEnvelope,
} from "./convex-deployed-runtime-identity.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { convexWasmSdkClientHeader } from "./convex-wasm-sdk-identity.mjs";

const FROZEN_PUSH_KIND = "convex-local-frozen-push-preflight-v1";
const FROZEN_PUSH_SOURCE_ENVELOPE_KIND = "convex-local-frozen-push-preflight-v2";
const FROZEN_PUSH_DEPLOYED_RUNTIME_KIND = "convex-local-frozen-push-preflight-v3";
const SUPPORTED_DEPLOYMENT_KINDS = new Set([
  "convex-wasm-deployment-v2",
  "convex-wasm-deployment-v4",
  "convex-wasm-deployment-v8",
]);
const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_REQUEST_BYTES = 256 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024 * 1024;
const START_PUSH_TIMEOUT_MS = 15 * 60 * 1000;
const WAIT_FOR_SCHEMA_REQUEST_TIMEOUT_MS = 30 * 1000;
const WAIT_FOR_SCHEMA_TOTAL_TIMEOUT_MS = 60 * 60 * 1000;
const FINISH_PUSH_TIMEOUT_MS = 5 * 60 * 1000;
const brotliCompress = promisify(zlib.brotliCompress);

function fail(message) {
  throw new Error(`Convex frozen deployment request: ${message}`);
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

function sourceKeyedRuntimeGeneration(value, description) {
  const generation = requireObject(value, description);
  requireExactKeys(
    generation,
    ["deploymentSha256", "generationManifestSha256", "generationSha256"],
    description
  );
  return Object.freeze({
    deploymentSha256: requireSha256(
      generation.deploymentSha256,
      `${description} deployment SHA-256`
    ),
    generationManifestSha256: requireSha256(
      generation.generationManifestSha256,
      `${description} generation manifest SHA-256`
    ),
    generationSha256: requireSha256(
      generation.generationSha256,
      `${description} generation SHA-256`
    ),
  });
}

function sourceKeyedRuntimeActivation(value) {
  const activation = requireObject(value, "source-keyed runtime activation");
  requireExactKeys(
    activation,
    ["expectedPrior", "targetGeneration"],
    "source-keyed runtime activation"
  );
  const expectedPrior = requireObject(
    activation.expectedPrior,
    "source-keyed runtime expected prior"
  );
  requireExactKeys(
    expectedPrior,
    [
      "runtimeGeneration",
      "sourcePackageId",
      "sourcePackageRuntimeContentSha256",
      "sourcePackageSha256",
    ],
    "source-keyed runtime expected prior"
  );
  return Object.freeze({
    expectedPrior: Object.freeze({
      runtimeGeneration:
        expectedPrior.runtimeGeneration === null
          ? null
          : sourceKeyedRuntimeGeneration(
              expectedPrior.runtimeGeneration,
              "source-keyed runtime expected-prior generation"
            ),
      sourcePackageId: requireString(
        expectedPrior.sourcePackageId,
        "source-keyed runtime expected-prior source package ID"
      ),
      sourcePackageRuntimeContentSha256:
        expectedPrior.sourcePackageRuntimeContentSha256 === null
          ? null
          : requireSha256(
              expectedPrior.sourcePackageRuntimeContentSha256,
              "source-keyed runtime expected-prior runtime-content SHA-256"
            ),
      sourcePackageSha256: requireSha256(
        expectedPrior.sourcePackageSha256,
        "source-keyed runtime expected-prior source package SHA-256"
      ),
    }),
    targetGeneration: sourceKeyedRuntimeGeneration(
      activation.targetGeneration,
      "source-keyed runtime target generation"
    ),
  });
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireExactKeys(value, allowedKeys, description) {
  const unknown = Object.keys(value).filter((key) => !allowedKeys.includes(key));
  if (unknown.length > 0) {
    fail(`${description} contains unsupported fields: ${unknown.sort().join(", ")}`);
  }
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseJsonBytes(bytes, maximumBytes, description) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > maximumBytes) {
    fail(`${description} must contain between 1 and ${maximumBytes} bytes`);
  }
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${description} is not valid UTF-8 JSON`);
  }
}

function sourceMapIdentity(sourceMap, description) {
  if (sourceMap === undefined) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(sourceMap);
  } catch {
    fail(`${description} source map is not valid JSON`);
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    parsed.version !== 3 ||
    !Array.isArray(parsed.sources)
  ) {
    fail(`${description} source map has invalid source-membership provenance`);
  }
  return {
    identity: {
      sha256: sha256(sourceMap),
      size: Buffer.byteLength(sourceMap),
      sourcesContentCount: Array.isArray(parsed.sourcesContent)
        ? parsed.sourcesContent.filter((source) => source !== null).length
        : 0,
      sourcesCount: parsed.sources.length,
    },
    sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
      sourceRoot: parsed.sourceRoot,
      sources: parsed.sources,
    }),
  };
}

function moduleIdentity(value, description) {
  const module = requireObject(value, description);
  requireExactKeys(module, ["environment", "nodePool", "path", "source", "sourceMap"], description);
  const pooledNodeEnvironment =
    typeof module.environment === "string" && module.environment.startsWith("node:pool:")
      ? module.environment.slice("node:pool:".length)
      : undefined;
  if (
    pooledNodeEnvironment !== undefined &&
    (!/^(?!default$)[a-z][a-z0-9_]{0,31}$/u.test(pooledNodeEnvironment) ||
      (module.nodePool !== undefined && module.nodePool !== pooledNodeEnvironment))
  ) {
    fail(`${description} Node pool metadata must match the module environment`);
  }
  if (pooledNodeEnvironment === undefined && module.nodePool !== undefined) {
    fail(`${description} Node pool metadata requires a pool-bearing Node environment`);
  }
  const environment = pooledNodeEnvironment === undefined ? module.environment : "node";
  if (environment !== "isolate" && environment !== "node") {
    fail(`${description} environment must be isolate or node`);
  }
  const path = requireString(module.path, `${description} path`);
  const source = requireString(module.source, `${description} source`);
  if (module.sourceMap !== undefined && typeof module.sourceMap !== "string") {
    fail(`${description} sourceMap must be a string when present`);
  }
  if (environment === "isolate" && module.sourceMap === undefined) {
    fail(`${description} isolate module must contain source-map provenance`);
  }
  const sourceMap = sourceMapIdentity(module.sourceMap, description);
  return {
    environment,
    moduleSha256: sha256(`${source}${module.sourceMap ?? ""}`),
    path,
    sourceMap: sourceMap?.identity ?? null,
    sourceMembershipSha256:
      environment === "isolate" ? (sourceMap?.sourceMembershipSha256 ?? null) : null,
    sourceSha256: sha256(source),
    sourceSize: Buffer.byteLength(source),
  };
}

function manifestPayload(manifest) {
  const { deploymentSha256: _deploymentSha256, ...payload } = manifest;
  return payload;
}

function validateDeploymentManifest(value) {
  const manifest = requireObject(value, "deployment manifest");
  if (!SUPPORTED_DEPLOYMENT_KINDS.has(manifest.kind) || manifest.mode !== "compile") {
    fail("deployment manifest must be a compiled convex-wasm-deployment-v2, v4, or v8 manifest");
  }
  if (manifest.deploymentSha256 !== fingerprintJson(manifestPayload(manifest))) {
    fail("deployment manifest digest is invalid");
  }
  requireSha256(manifest.graph?.sha256, "deployment graph SHA-256");
  if (!Array.isArray(manifest.exports) || manifest.exports.length === 0) {
    fail("deployment manifest exports must be a non-empty array");
  }
  const selectedRouteRuntimeModulePaths = manifest.exports
    .filter((entry) => entry.routing?.decision === "wasm")
    .map((entry, index) =>
      requireString(entry.runtimeModulePath, `selected deployment export ${index} runtime path`)
    )
    .sort(compareStrings);
  if (selectedRouteRuntimeModulePaths.length === 0) {
    fail("deployment manifest has no selected Wasm routes");
  }
  const artifactFallback =
    manifest.kind === "convex-wasm-deployment-v4" ? manifest.counts?.artifactFallback : 0;
  if (
    !Number.isSafeInteger(manifest.counts?.eligible) ||
    !Number.isSafeInteger(manifest.counts?.selectedWasm) ||
    !Number.isSafeInteger(manifest.counts?.unselectedEligible) ||
    !Number.isSafeInteger(artifactFallback) ||
    manifest.counts.eligible < 0 ||
    manifest.counts.selectedWasm < 0 ||
    manifest.counts.unselectedEligible < 0 ||
    artifactFallback < 0 ||
    manifest.counts.selectedWasm !== selectedRouteRuntimeModulePaths.length ||
    manifest.counts.eligible !==
      manifest.counts.selectedWasm + manifest.counts.unselectedEligible + artifactFallback
  ) {
    fail("deployment manifest has inconsistent eligible-selection counts");
  }
  return {
    manifest,
    selectedRouteCount: selectedRouteRuntimeModulePaths.length,
    selectedRuntimeModulePaths: [...new Set(selectedRouteRuntimeModulePaths)],
  };
}

function validateSourceAuthority(value, current = undefined) {
  if (value?.kind === convexWasmSourceEnvelopeKind) {
    const envelope =
      current === undefined
        ? validateConvexWasmSourceEnvelope(value)
        : verifyCurrentConvexWasmSourceEnvelope({ envelope: value, ...current });
    return {
      graphSha256: envelope.graph.sha256,
      identitySha256: envelope.sourceEnvelopeSha256,
      kind: envelope.kind,
      selectedRouteCount: envelope.selectedRoutes.length,
      selectedRuntimeModulePaths: [
        ...new Set(envelope.selectedRoutes.map(({ runtimeModulePath }) => runtimeModulePath)),
      ].sort(compareStrings),
    };
  }
  const { manifest, selectedRouteCount, selectedRuntimeModulePaths } =
    validateDeploymentManifest(value);
  return {
    graphSha256: manifest.graph.sha256,
    identitySha256: manifest.deploymentSha256,
    kind: manifest.kind,
    selectedRouteCount,
    selectedRuntimeModulePaths,
  };
}

function compareModuleIdentity(actual, expected, description) {
  if (
    actual.environment !== expected.environment ||
    actual.moduleSha256 !== expected.moduleSha256 ||
    actual.sourceMembershipSha256 !== expected.sourceMembershipSha256 ||
    actual.sourceSha256 !== expected.sourceSha256 ||
    actual.sourceSize !== expected.sourceSize ||
    fingerprintJson(actual.sourceMap) !== fingerprintJson(expected.sourceMap)
  ) {
    fail(`${description} does not match the installed Convex bundler output`);
  }
}

function compareModuleSets(actualModules, expectedModules, environment) {
  if (actualModules.length !== expectedModules.length) {
    fail(
      `start-push ${environment} module count ${actualModules.length} does not match installed deployment bundler count ${expectedModules.length}`
    );
  }
  for (let index = 0; index < expectedModules.length; index += 1) {
    const actual = actualModules[index];
    const expected = expectedModules[index];
    if (actual.path !== expected.path) {
      fail(
        `start-push ${environment} module path ${actual.path} does not match installed bundler path ${expected.path}`
      );
    }
    compareModuleIdentity(actual, expected, `start-push module ${actual.path}`);
  }
}

function inspectCompleteStartPushRequest(requestBytes) {
  const request = requireObject(
    parseJsonBytes(requestBytes, MAX_REQUEST_BYTES, "start-push request"),
    "start-push request"
  );
  requireExactKeys(
    request,
    [
      "adminKey",
      "appDefinition",
      "componentDefinitions",
      "dryRun",
      "externalDepsPackage",
      "forCodegen",
      "functions",
      "nodeDependencies",
      "nodeVersion",
    ],
    "start-push request"
  );
  requireString(request.adminKey, "start-push adminKey");
  requireString(request.functions, "start-push functions path");
  if (request.dryRun !== false) {
    fail("start-push request must not be a dry run");
  }
  if (request.forCodegen !== undefined && request.forCodegen !== false) {
    fail("start-push request must not be for code generation");
  }
  if (!Array.isArray(request.componentDefinitions) || request.componentDefinitions.length !== 0) {
    fail("component deployment requests are not supported");
  }
  if (!Array.isArray(request.nodeDependencies)) {
    fail("start-push nodeDependencies must be an array");
  }
  if (request.externalDepsPackage !== undefined) {
    validateTargetExternalDepsSelection(request.externalDepsPackage);
    if (request.nodeDependencies.length === 0)
      fail("selected dependency package requires declarations");
  }

  const appDefinition = requireObject(request.appDefinition, "start-push appDefinition");
  if (
    !Array.isArray(appDefinition.unchangedModuleHashes) ||
    appDefinition.unchangedModuleHashes.length !== 0
  ) {
    fail("start-push request must contain all modules and no unchanged module hashes");
  }
  if (!Array.isArray(appDefinition.changedModules) || appDefinition.changedModules.length === 0) {
    fail("start-push request changedModules must be a non-empty array");
  }

  const requestModules = appDefinition.changedModules
    .map((module, index) => moduleIdentity(module, `start-push module ${index}`))
    .sort((left, right) => compareStrings(left.path, right.path));
  const requestModulesByPath = new Map();
  for (const module of requestModules) {
    if (requestModulesByPath.has(module.path)) {
      fail(`start-push request contains duplicate module path ${module.path}`);
    }
    requestModulesByPath.set(module.path, module);
  }
  return { request, requestModules, requestModulesByPath };
}

function frozenSourceAuthorityIdentity(value) {
  requireExactKeys(
    value,
    [
      "authorityFileSha256",
      "authoritySha256",
      "bindingSha256",
      "sourcePackageSha256",
      "sourcePackageSize",
    ],
    "frozen deployed-runtime authority"
  );
  const authority = requireObject(value, "frozen deployed-runtime authority");
  return {
    authorityFileSha256: requireSha256(
      authority.authorityFileSha256,
      "frozen deployed-runtime authority file SHA-256"
    ),
    authoritySha256: requireSha256(
      authority.authoritySha256,
      "frozen deployed-runtime authority SHA-256"
    ),
    bindingSha256: requireSha256(
      authority.bindingSha256,
      "frozen deployed-runtime binding SHA-256"
    ),
    sourcePackageSha256: requireSha256(
      authority.sourcePackageSha256,
      "frozen deployed-runtime source-package SHA-256"
    ),
    sourcePackageSize: requirePositiveInteger(
      authority.sourcePackageSize,
      "frozen deployed-runtime source-package size"
    ),
  };
}

export function inspectFrozenStartPushRequestAgainstFrozenAuthority({
  deployedRuntimeAuthority,
  requestBytes,
  sourceAuthority,
  sourceAuthorityFileSha256,
  sourceAuthorityFileSize,
  sourcePackageBytes,
}) {
  if (sourceAuthority?.kind !== convexWasmSourceEnvelopeKind) {
    fail("frozen deployed-runtime authority requires a source envelope");
  }
  if (!Buffer.isBuffer(sourcePackageBytes) || sourcePackageBytes.length === 0) {
    fail("frozen source package must be a nonempty buffer");
  }

  const normalizedAuthority = normalizeDeployedRuntimeAuthority(deployedRuntimeAuthority);
  const binding = verifyFrozenGraphBindingSourceEnvelope({
    normalizedAuthority,
    sourceEnvelope: sourceAuthority,
    sourceEnvelopeFileSha256: sourceAuthorityFileSha256,
    sourceEnvelopeFileSize: sourceAuthorityFileSize,
  });
  if (binding === null) {
    fail("deployed-runtime authority has no frozen-graph binding");
  }
  if (
    sourcePackageBytes.length !== binding.sourcePackage.size ||
    sha256(sourcePackageBytes) !== binding.sourcePackage.sha256
  ) {
    fail("frozen source-package bytes do not match the deployed-runtime authority");
  }

  const { request, requestModules, requestModulesByPath } =
    inspectCompleteStartPushRequest(requestBytes);
  const requestEvidence = binding.inputAuthority.request;
  const requestModulesSha256 = fingerprintJson(requestModules);
  const isolateModules = requestModules.filter(({ environment }) => environment === "isolate");
  const nodeModules = requestModules.filter(({ environment }) => environment === "node");
  if (
    requestEvidence.requestModuleCount !== requestModules.length ||
    requestEvidence.requestModulesSha256 !== requestModulesSha256 ||
    requestEvidence.authoritativeModuleCount !== requestModules.length ||
    requestEvidence.authoritativeModulesSha256 !== requestModulesSha256 ||
    requestEvidence.authoritativeIsolateModuleCount !== isolateModules.length ||
    requestEvidence.authoritativeNodeModuleCount !== nodeModules.length
  ) {
    fail("frozen start-push module census differs from deployed-runtime authority");
  }
  const selectedModules = requestEvidence.selectedModules.map((expected, index) => {
    const module = requestModulesByPath.get(expected.path);
    if (module === undefined || canonicalJson(module) !== canonicalJson(expected)) {
      fail(`frozen start-push selected module ${index} differs from deployed-runtime authority`);
    }
    return module;
  });
  if (
    selectedModules.length !== requestEvidence.selectedModuleCount ||
    fingerprintJson(selectedModules) !== requestEvidence.selectedModulesSha256
  ) {
    fail("frozen start-push selected-module census differs from deployed-runtime authority");
  }
  verifyFrozenGraphBindingRequestEvidence({
    normalizedAuthority,
    requestBytes,
    requestEvidence,
  });
  return {
    binding,
    normalizedAuthority,
    request,
    requestEvidence,
  };
}

export function inspectFrozenStartPushRequest({
  deploymentManifest,
  graphSession,
  inventory,
  requestBytes,
  sourceAuthority = deploymentManifest,
}) {
  const { graphSha256, selectedRouteCount, selectedRuntimeModulePaths } = validateSourceAuthority(
    sourceAuthority,
    sourceAuthority?.kind === convexWasmSourceEnvelopeKind ? { graphSession, inventory } : undefined
  );
  const { request, requestModules, requestModulesByPath } =
    inspectCompleteStartPushRequest(requestBytes);

  if (!(graphSession?.bundleModulesByPath instanceof Map)) {
    fail("installed Convex graph session has no exact bundle module identities");
  }
  if (!(graphSession.deploymentConfigurationModulesByPath instanceof Map)) {
    fail("installed Convex graph session has no exact deployment-configuration module identities");
  }
  if (!(graphSession.nodeModulesByPath instanceof Map)) {
    fail("installed Convex graph session has no exact Node module identities");
  }
  if (graphSha256 !== graphSession.graphSha256) {
    fail("current installed Convex source graph does not match the deployment manifest");
  }
  const udfIsolateModules = [...graphSession.bundleModulesByPath.values()].sort((left, right) =>
    compareStrings(left.path, right.path)
  );
  const deploymentConfigurationModules = [
    ...graphSession.deploymentConfigurationModulesByPath.values(),
  ].sort((left, right) => compareStrings(left.path, right.path));
  const authoritativeIsolateModules = [
    ...udfIsolateModules,
    ...deploymentConfigurationModules,
  ].sort((left, right) => compareStrings(left.path, right.path));
  const authoritativeNodeModules = [...graphSession.nodeModulesByPath.values()].sort(
    (left, right) => compareStrings(left.path, right.path)
  );
  const authoritativeModules = [...authoritativeIsolateModules, ...authoritativeNodeModules].sort(
    (left, right) => compareStrings(left.path, right.path)
  );
  for (const module of authoritativeIsolateModules) {
    if (module.environment !== "isolate") {
      fail(`installed Convex isolate bundler emitted wrong environment for ${module.path}`);
    }
  }
  for (const module of authoritativeNodeModules) {
    if (module.environment !== "node") {
      fail(`installed Convex Node bundler emitted wrong environment for ${module.path}`);
    }
  }
  for (let index = 1; index < authoritativeModules.length; index += 1) {
    if (authoritativeModules[index - 1].path === authoritativeModules[index].path) {
      fail(
        `installed Convex bundlers emitted duplicate deployment module path ${authoritativeModules[index].path}`
      );
    }
  }
  const isolateRequestModules = requestModules.filter(
    ({ environment }) => environment === "isolate"
  );
  const nodeRequestModules = requestModules.filter(({ environment }) => environment === "node");
  compareModuleSets(isolateRequestModules, authoritativeIsolateModules, "isolate");
  compareModuleSets(nodeRequestModules, authoritativeNodeModules, "Node");
  const authoritativeModulesSha256 = fingerprintJson(authoritativeModules);
  const requestModulesSha256 = fingerprintJson(requestModules);
  if (requestModulesSha256 !== authoritativeModulesSha256) {
    fail("start-push complete module identity set does not match installed deployment bundlers");
  }

  const selectedModules = selectedRuntimeModulePaths.map((path) => {
    const module = requestModulesByPath.get(path);
    if (module === undefined) {
      fail(`start-push request is missing selected runtime module ${path}`);
    }
    if (module.environment !== "isolate") {
      fail(`selected runtime module ${path} is not an isolate module`);
    }
    return module;
  });
  return {
    evidence: {
      authoritativeDeploymentConfigurationModuleCount: deploymentConfigurationModules.length,
      authoritativeDeploymentConfigurationModulesSha256: fingerprintJson(
        deploymentConfigurationModules
      ),
      authoritativeModuleCount: authoritativeModules.length,
      authoritativeModulesSha256,
      authoritativeIsolateModuleCount: authoritativeIsolateModules.length,
      authoritativeIsolateModulesSha256: fingerprintJson(authoritativeIsolateModules),
      authoritativeNodeModuleCount: authoritativeNodeModules.length,
      authoritativeNodeModulesSha256: fingerprintJson(authoritativeNodeModules),
      authoritativeUdfIsolateModuleCount: udfIsolateModules.length,
      authoritativeUdfIsolateModulesSha256: fingerprintJson(udfIsolateModules),
      requestModuleCount: requestModules.length,
      requestModulesSha256,
      requestSha256: sha256(requestBytes),
      requestSize: requestBytes.length,
      selectedModuleCount: selectedModules.length,
      selectedModules,
      selectedModulesSha256: fingerprintJson(selectedModules),
      selectedRouteCount,
    },
    request,
  };
}

export function createFrozenPushPreflight({
  deploymentManifest,
  deploymentManifestFileSha256,
  frozenSourceAuthority = undefined,
  requestEvidence,
  sourceAuthority = deploymentManifest,
  sourceAuthorityFileSha256 = deploymentManifestFileSha256,
  target,
}) {
  const source = validateSourceAuthority(sourceAuthority);
  const frozenAuthority =
    frozenSourceAuthority === undefined
      ? undefined
      : frozenSourceAuthorityIdentity(frozenSourceAuthority);
  if (frozenAuthority !== undefined && source.kind !== convexWasmSourceEnvelopeKind) {
    fail("frozen deployed-runtime authority requires a source envelope");
  }
  const targetObject = requireObject(target, "frozen push target");
  validateConvexMysqlDatabaseIdentity(targetObject.backend);
  const payload = {
    kind:
      frozenAuthority !== undefined
        ? FROZEN_PUSH_DEPLOYED_RUNTIME_KIND
        : source.kind === convexWasmSourceEnvelopeKind
          ? FROZEN_PUSH_SOURCE_ENVELOPE_KIND
          : FROZEN_PUSH_KIND,
    source: {
      ...(frozenAuthority === undefined ? {} : { deployedRuntimeAuthority: frozenAuthority }),
      fileSha256: requireSha256(sourceAuthorityFileSha256, "source authority file SHA-256"),
      graphSha256: source.graphSha256,
      kind: source.kind,
      sha256: source.identitySha256,
    },
    request: requestEvidence,
    target: targetObject,
  };
  return { ...payload, preflightSha256: fingerprintJson(payload) };
}

export function validateFrozenPushPreflight(value) {
  const report = requireObject(value, "frozen push preflight");
  if (
    ![
      FROZEN_PUSH_KIND,
      FROZEN_PUSH_SOURCE_ENVELOPE_KIND,
      FROZEN_PUSH_DEPLOYED_RUNTIME_KIND,
    ].includes(report.kind)
  ) {
    fail(`unsupported frozen push preflight kind ${JSON.stringify(report.kind)}`);
  }
  const { preflightSha256: _preflightSha256, ...payload } = report;
  if (report.preflightSha256 !== fingerprintJson(payload)) {
    fail("frozen push preflight digest is invalid");
  }
  requireSha256(report.request?.requestSha256, "frozen request SHA-256");
  requireSha256(report.source?.fileSha256, "frozen source authority file SHA-256");
  requireSha256(report.source?.sha256, "frozen source authority SHA-256");
  requireSha256(report.source?.graphSha256, "frozen source graph SHA-256");
  if (report.kind === FROZEN_PUSH_DEPLOYED_RUNTIME_KIND) {
    requireExactKeys(
      report.source,
      ["deployedRuntimeAuthority", "fileSha256", "graphSha256", "kind", "sha256"],
      "frozen deployed-runtime preflight source"
    );
    if (report.source.kind !== convexWasmSourceEnvelopeKind) {
      fail("frozen deployed-runtime preflight requires a source envelope");
    }
    frozenSourceAuthorityIdentity(report.source.deployedRuntimeAuthority);
  }
  validateConvexMysqlDatabaseIdentity(report.target?.backend);
  return report;
}

export function rebindFrozenStartPushAdminKey({ adminKey, preflight, requestBytes }) {
  const storedPreflight = validateFrozenPushPreflight(preflight);
  requireString(adminKey, "replacement admin key");
  if (
    storedPreflight.request.requestSha256 !== sha256(requestBytes) ||
    storedPreflight.request.requestSize !== requestBytes.length
  ) {
    fail("frozen start-push bytes do not match their stored preflight");
  }
  const { request, requestModules, requestModulesByPath } =
    inspectCompleteStartPushRequest(requestBytes);
  const requestModulesSha256 = fingerprintJson(requestModules);
  const isolateModuleCount = requestModules.filter(
    ({ environment }) => environment === "isolate"
  ).length;
  const nodeModuleCount = requestModules.length - isolateModuleCount;
  if (
    !Array.isArray(storedPreflight.request.selectedModules) ||
    storedPreflight.request.selectedModuleCount !== storedPreflight.request.selectedModules.length
  ) {
    fail("frozen selected module census differs from its stored preflight");
  }
  const selectedModules = storedPreflight.request.selectedModules.map((selected, index) => {
    const selectedObject = requireObject(selected, `stored selected module ${index}`);
    const path = requireString(selectedObject.path, `stored selected module ${index} path`);
    const actual = requestModulesByPath.get(path);
    if (actual === undefined || canonicalJson(actual) !== canonicalJson(selectedObject)) {
      fail(`frozen selected module ${path} differs from its stored preflight`);
    }
    return actual;
  });
  if (
    new Set(selectedModules.map(({ path }) => path)).size !== selectedModules.length ||
    storedPreflight.request.selectedModulesSha256 !== fingerprintJson(selectedModules)
  ) {
    fail("frozen selected module census differs from its stored preflight");
  }
  if (
    storedPreflight.request.requestModuleCount !== requestModules.length ||
    storedPreflight.request.authoritativeModuleCount !== requestModules.length ||
    storedPreflight.request.authoritativeIsolateModuleCount !== isolateModuleCount ||
    storedPreflight.request.authoritativeNodeModuleCount !== nodeModuleCount ||
    storedPreflight.request.requestModulesSha256 !== requestModulesSha256 ||
    storedPreflight.request.authoritativeModulesSha256 !== requestModulesSha256
  ) {
    fail("frozen start-push module census differs from its stored preflight");
  }
  const reboundRequest = { ...request, adminKey };
  if (canonicalJson({ ...reboundRequest, adminKey: request.adminKey }) !== canonicalJson(request)) {
    fail("rebound start-push request changed fields other than the admin key");
  }
  const reboundRequestBytes = Buffer.from(canonicalJson(reboundRequest));
  return {
    evidence: {
      ...storedPreflight.request,
      requestSha256: sha256(reboundRequestBytes),
      requestSize: reboundRequestBytes.length,
    },
    request: reboundRequest,
    requestBytes: reboundRequestBytes,
  };
}

async function readLimitedJson(response, endpoint) {
  if (response.body === null) {
    fail(`${endpoint} returned no response body`);
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > MAX_RESPONSE_BYTES) {
      fail(`${endpoint} response exceeded ${MAX_RESPONSE_BYTES} bytes`);
    }
    chunks.push(chunk);
  }
  const parsed = parseJsonBytes(Buffer.concat(chunks), MAX_RESPONSE_BYTES, `${endpoint} response`);
  if (!response.ok) {
    const errorResponse = requireObject(parsed, `${endpoint} error response`);
    const code =
      typeof errorResponse.code === "string" && errorResponse.code.length <= 256
        ? errorResponse.code
        : "UNKNOWN";
    const message =
      typeof errorResponse.message === "string" && errorResponse.message.length <= 4_096
        ? errorResponse.message
        : "No structured error message";
    fail(
      `${endpoint} returned HTTP ${response.status} with code ${JSON.stringify(code)} and message ${JSON.stringify(message)}`
    );
  }
  return parsed;
}

async function post({
  adminKey,
  body,
  compressed,
  endpoint,
  fetchImplementation,
  origin,
  timeoutMs,
}) {
  const headers = {
    Authorization: `Convex ${adminKey}`,
    "Content-Type": "application/json",
    "Convex-Client": convexWasmSdkClientHeader,
  };
  if (compressed) {
    headers["Content-Encoding"] = "br";
  }
  let response;
  try {
    response = await fetchImplementation(new URL(endpoint, origin), {
      body,
      headers,
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail(`${endpoint} did not return a response; its mutation state is unknown`);
  }
  return readLimitedJson(response, endpoint);
}

function validateSchemaStatus(value) {
  const status = requireObject(value, "wait_for_schema response");
  if (!["complete", "failed", "inProgress", "raceDetected"].includes(status.type)) {
    fail(`wait_for_schema returned unsupported status ${JSON.stringify(status.type)}`);
  }
  return status;
}

export async function executeFrozenPushProtocol({
  adminKey,
  beforeStartPush,
  expectedSourcePackageRuntimeContentSha256,
  fetchImplementation = fetch,
  onStartPushAnalysisProjection = undefined,
  onPhase = async () => {},
  requestBytes,
  requestSha256,
  sourceKeyedRuntimeActivation: sourceKeyedRuntimeActivationValue = undefined,
  url,
}) {
  const origin = validateAuthenticatedConvexOrigin(url, "Convex frozen deployment URL");
  requireString(adminKey, "admin key");
  requireSha256(requestSha256, "confirmed request SHA-256");
  if (expectedSourcePackageRuntimeContentSha256 !== undefined) {
    requireSha256(expectedSourcePackageRuntimeContentSha256, "staged runtime-content SHA-256");
  }
  if (sha256(requestBytes) !== requestSha256) {
    fail("start-push request bytes do not match the confirmed digest");
  }
  const request = requireObject(
    parseJsonBytes(requestBytes, MAX_REQUEST_BYTES, "start-push request"),
    "start-push request"
  );
  if (request.adminKey !== adminKey) {
    fail("start-push request admin key does not match the inspected backend credential");
  }
  if (request.dryRun !== false) {
    fail("start-push request must not be a dry run");
  }
  if (typeof beforeStartPush !== "function") {
    fail("a final start-push precondition callback is required");
  }
  const activation =
    sourceKeyedRuntimeActivationValue === undefined
      ? undefined
      : sourceKeyedRuntimeActivation(sourceKeyedRuntimeActivationValue);
  if (
    onStartPushAnalysisProjection !== undefined &&
    typeof onStartPushAnalysisProjection !== "function"
  ) {
    fail("start-push analysis projection callback must be a function when provided");
  }

  const compressedStartRequest = await brotliCompress(requestBytes, {
    params: {
      [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
      [zlib.constants.BROTLI_PARAM_QUALITY]: 4,
    },
  });
  await onPhase({ phase: "sendingStartPush" });
  await beforeStartPush();
  const startPush = requireObject(
    await post({
      adminKey,
      body: compressedStartRequest,
      compressed: true,
      endpoint: "/api/deploy2/start_push",
      fetchImplementation,
      origin,
      timeoutMs: START_PUSH_TIMEOUT_MS,
    }),
    "start_push response"
  );
  const schemaChange = requireObject(startPush.schemaChange, "start_push schemaChange");
  // Admission and activation must retain the same exact dependency bytes. Check before schema
  // polling or finish_push; a ready generation for a different runtime digest grants no authority.
  if (expectedSourcePackageRuntimeContentSha256 !== undefined) {
    const encoded = startPush.componentDefinitionPackages?.[""]?.runtimeContentSha256?.$bytes;
    if (typeof encoded !== "string" || !/^[A-Za-z0-9+/]{43}=$/u.test(encoded)) {
      fail("start_push root runtime-content SHA-256 is missing or malformed");
    }
    const digest = Buffer.from(encoded, "base64");
    if (
      digest.length !== 32 ||
      digest.toString("base64") !== encoded ||
      digest.toString("hex") !== expectedSourcePackageRuntimeContentSha256
    ) {
      fail("start_push root runtime-content SHA-256 differs from the staged pair");
    }
  }
  const startPushSha256 = fingerprintJson(startPush);
  if (onStartPushAnalysisProjection !== undefined) {
    await onStartPushAnalysisProjection({
      analysis: startPush.analysis,
      requestSha256,
      startPushSha256,
    });
  }
  await onPhase({ phase: "startPushReturned", startPushSha256 });

  const schemaDeadline = Date.now() + WAIT_FOR_SCHEMA_TOTAL_TIMEOUT_MS;
  let schemaPollCount = 0;
  let schemaRequestBodyBytes = 0;
  while (true) {
    if (Date.now() >= schemaDeadline) {
      fail("wait_for_schema exceeded its total timeout after start_push");
    }
    schemaPollCount += 1;
    const schemaRequest = JSON.stringify({
      adminKey,
      dryRun: false,
      schemaChange,
      timeoutMs: 10_000,
    });
    schemaRequestBodyBytes += Buffer.byteLength(schemaRequest);
    const status = validateSchemaStatus(
      await post({
        adminKey,
        body: schemaRequest,
        compressed: false,
        endpoint: "/api/deploy2/wait_for_schema",
        fetchImplementation,
        origin,
        timeoutMs: WAIT_FOR_SCHEMA_REQUEST_TIMEOUT_MS,
      })
    );
    if (status.type === "complete") {
      break;
    }
    if (status.type === "failed") {
      fail("schema validation failed after start_push");
    }
    if (status.type === "raceDetected") {
      fail("schema was overwritten after start_push");
    }
  }
  await onPhase({ phase: "schemaReady", schemaPollCount });

  await onPhase({ phase: "sendingFinishPush" });
  const finishPayload = {
    adminKey,
    dryRun: false,
    message: null,
    startPush,
  };
  if (activation !== undefined) {
    finishPayload.sourceKeyedRuntimeActivation = activation;
  }
  const finishRequest = Buffer.from(JSON.stringify(finishPayload));
  const compressedFinishRequest = await brotliCompress(finishRequest, {
    params: {
      [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
      [zlib.constants.BROTLI_PARAM_QUALITY]: 4,
    },
  });
  const finishPush = requireObject(
    await post({
      adminKey,
      body: compressedFinishRequest,
      compressed: true,
      endpoint: "/api/deploy2/finish_push",
      fetchImplementation,
      origin,
      timeoutMs: FINISH_PUSH_TIMEOUT_MS,
    }),
    "finish_push response"
  );
  const result = {
    finishPushSha256: fingerprintJson(finishPush),
    // Count the actual encoded request bodies supplied to fetch, not source
    // sizes. HTTP/TLS overhead and response traffic are outside this boundary.
    requestBodyBytes: {
      startPush: compressedStartRequest.length,
      waitForSchema: schemaRequestBodyBytes,
      finishPush: compressedFinishRequest.length,
      total:
        compressedStartRequest.length + schemaRequestBodyBytes + compressedFinishRequest.length,
    },
    schemaPollCount,
    startPushSha256,
  };
  await onPhase({ phase: "finishPushReturned", ...result });
  return result;
}

export const convexFrozenPushPreflightKind = FROZEN_PUSH_KIND;
