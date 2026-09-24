import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, dirname, isAbsolute, resolve } from "node:path";

import {
  createFrozenGraphInputAuthority,
  createFullFrozenGraphBindingAuthority,
} from "./convex-wasm-frozen-graph-authority.mjs";
import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { validateConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";
import { validateTargetExternalDepsDescriptor } from "./convex-target-external-deps-contract.mjs";

export const convexRuntimeContentAlgorithm = "convex-source-package-runtime-content-v1";

const HELPER_AUTHORITY_KIND = "convex-source-package-preactivation-authority-v1";
const DEPLOYED_RUNTIME_AUTHORITY_KIND = "convex-deployed-runtime-binding-authority-v1";
const HELPER_TIMEOUT_MS = 30_000;
const HELPER_OUTPUT_MAX_BYTES = 8 * 1024 * 1024;
const SOURCE_PACKAGE_MAX_BYTES = 256 * 1024 * 1024;
const AUTH_CONFIG_MODULE_PATH = "auth.config.js";
const SHA256 = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex Wasm preactivation runtime authority: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  const object = requireObject(value, description);
  if (
    canonicalJson(Object.keys(object).sort(compareStrings)) !==
    canonicalJson([...expected].sort(compareStrings))
  ) {
    fail(`${description} fields are invalid`);
  }
  return object;
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

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireFileIdentity(value, description) {
  const identity = requireExactKeys(value, ["sha256", "size"], description);
  return {
    sha256: requireSha256(identity.sha256, `${description} SHA-256`),
    size: requirePositiveInteger(identity.size, `${description} size`),
  };
}

function requireNormalizedModulePath(value, description) {
  const path = requireString(value, description);
  if (
    path.startsWith("/") ||
    path.includes("\\") ||
    path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    fail(`${description} must be a normalized relative module path`);
  }
  return path;
}

function requireDependencies(value, description) {
  if (!Array.isArray(value)) fail(`${description} must be an array`);
  const dependencies = value.map((dependency, index) => {
    const item = requireExactKeys(
      dependency,
      ["package", "version"],
      `${description} item ${index}`
    );
    return {
      package: requireString(item.package, `${description} item ${index} package`),
      version: requireString(item.version, `${description} item ${index} version`),
    };
  });
  dependencies.sort(
    (left, right) =>
      compareStrings(left.package, right.package) || compareStrings(left.version, right.version)
  );
  if (new Set(dependencies.map((dependency) => dependency.package)).size !== dependencies.length) {
    fail(`${description} must not contain duplicate package names`);
  }
  return dependencies;
}

function normalizeSourceMap(value, description) {
  if (value === null) return null;
  const sourceMap = requireExactKeys(
    value,
    ["sha256", "size", "sourcesContentCount", "sourcesCount"],
    description
  );
  const size = sourceMap.size;
  const sourcesContentCount = sourceMap.sourcesContentCount;
  const sourcesCount = sourceMap.sourcesCount;
  if (
    !Number.isSafeInteger(size) ||
    size < 0 ||
    !Number.isSafeInteger(sourcesContentCount) ||
    sourcesContentCount < 0 ||
    !Number.isSafeInteger(sourcesCount) ||
    sourcesCount < 0
  ) {
    fail(`${description} counts must be nonnegative safe integers`);
  }
  return {
    sha256: requireSha256(sourceMap.sha256, `${description} SHA-256`),
    size,
    sourcesContentCount,
    sourcesCount,
  };
}

function normalizeRuntimeModule(value, index) {
  const description = `helper runtime module ${index}`;
  const module = requireExactKeys(
    value,
    [
      "environment",
      "moduleSha256",
      "nodePool",
      "path",
      "role",
      "sourceMap",
      "sourceSha256",
      "sourceSize",
    ],
    description
  );
  if (module.environment !== "isolate" && module.environment !== "node") {
    fail(`${description} environment is invalid`);
  }
  if (
    !["deploymentConfiguration", "node", "udfIsolate"].includes(module.role) ||
    (module.role === "node") !== (module.environment === "node") ||
    (module.role === "deploymentConfiguration" && module.environment !== "isolate")
  ) {
    fail(`${description} role is inconsistent with its environment`);
  }
  if (
    module.nodePool !== null &&
    (typeof module.nodePool !== "string" || module.nodePool.length === 0)
  ) {
    fail(`${description} node pool must be null or a nonempty string`);
  }
  if (module.nodePool !== null && module.environment !== "node") {
    fail(`${description} assigns a Node pool to a non-Node module`);
  }
  const path = requireNormalizedModulePath(module.path, `${description} path`);
  if ((module.role === "deploymentConfiguration") !== (path === AUTH_CONFIG_MODULE_PATH)) {
    fail(`${description} deployment-configuration role is inconsistent with its path`);
  }
  return {
    environment: module.environment,
    moduleSha256: requireSha256(module.moduleSha256, `${description} module SHA-256`),
    nodePool: module.nodePool,
    path,
    role: module.role,
    sourceMap: normalizeSourceMap(module.sourceMap, `${description} source map`),
    sourceSha256: requireSha256(module.sourceSha256, `${description} source SHA-256`),
    sourceSize: requirePositiveInteger(module.sourceSize, `${description} source size`),
  };
}

function frozenModuleIdentity(module) {
  return {
    environment: module.environment,
    moduleSha256: module.moduleSha256,
    path: module.path,
    sourceMap: module.sourceMap,
    sourceMembershipSha256: module.sourceMembershipSha256,
    sourceSha256: module.sourceSha256,
    sourceSize: module.sourceSize,
  };
}

function sourceMembershipByModulePath(startPushBytes) {
  let request;
  try {
    request = JSON.parse(startPushBytes.toString("utf8"));
  } catch {
    fail("helper request is not valid UTF-8 JSON");
  }
  const changedModules = request?.appDefinition?.changedModules;
  if (!Array.isArray(changedModules) || changedModules.length === 0) {
    fail("helper request has no complete changed-module set");
  }
  const memberships = new Map();
  for (const [index, module] of changedModules.entries()) {
    const description = `helper request module ${index}`;
    const path = requireString(module?.path, `${description} path`);
    if (memberships.has(path)) {
      fail(`helper request repeats module path ${path}`);
    }
    // Frozen requests encode the pool in the environment, while helper output separates it.
    const nodePool =
      typeof module.environment === "string" && module.environment.startsWith("node:pool:")
        ? module.environment.slice("node:pool:".length)
        : null;
    if (
      nodePool !== null &&
      (!/^(?!default$)[a-z][a-z0-9_]{0,31}$/u.test(nodePool) ||
        (module.nodePool !== undefined && module.nodePool !== nodePool))
    ) {
      fail(`${description} Node pool metadata must match the module environment`);
    }
    if (nodePool === null && module.nodePool !== undefined) {
      fail(`${description} Node pool metadata requires a pool-bearing Node environment`);
    }
    if (module.environment === "node" || nodePool !== null) {
      memberships.set(path, { nodePool, sourceMembershipSha256: null });
      continue;
    }
    if (module.environment !== "isolate" || typeof module.sourceMap !== "string") {
      fail(`${description} isolate source-map provenance is missing`);
    }
    let sourceMap;
    try {
      sourceMap = JSON.parse(module.sourceMap);
    } catch {
      fail(`${description} source map is not valid JSON`);
    }
    if (
      sourceMap === null ||
      typeof sourceMap !== "object" ||
      Array.isArray(sourceMap) ||
      sourceMap.version !== 3 ||
      !Array.isArray(sourceMap.sources)
    ) {
      fail(`${description} source map has invalid source-membership provenance`);
    }
    memberships.set(path, {
      nodePool,
      sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
        sourceRoot: sourceMap.sourceRoot,
        sources: sourceMap.sources,
      }),
    });
  }
  return memberships;
}

export function normalizePreactivationHelperAuthority(
  value,
  { producerCertificate, sourcePackage, startPushBytes, targetExternalDepsPackage }
) {
  const authority = requireExactKeys(
    value,
    [
      "externalDepsPackage",
      "kind",
      "nodeVersion",
      "packageModuleCount",
      "request",
      "runtimeContentAlgorithm",
      "runtimeContentSha256",
      "runtimeModuleCount",
      "runtimeModules",
      "sourcePackage",
    ],
    "helper authority"
  );
  if (
    authority.kind !== HELPER_AUTHORITY_KIND ||
    authority.runtimeContentAlgorithm !== convexRuntimeContentAlgorithm
  ) {
    fail("helper authority kind or runtime-content algorithm is invalid");
  }
  const request = requireFileIdentity(authority.request, "helper request");
  if (request.size !== startPushBytes.length || request.sha256 !== sha256(startPushBytes)) {
    fail("helper request identity differs from the authenticated start_push bytes");
  }
  const helperSourcePackage = requireFileIdentity(authority.sourcePackage, "helper source package");
  if (
    helperSourcePackage.size !== sourcePackage.size ||
    helperSourcePackage.sha256 !== sourcePackage.sha256
  ) {
    fail("helper source-package identity differs from its materialized bytes");
  }
  if (authority.nodeVersion !== null && !["18", "20", "22", "24"].includes(authority.nodeVersion)) {
    fail("helper Node version is invalid");
  }
  if (!Array.isArray(authority.runtimeModules)) {
    fail("helper runtime modules must be an array");
  }
  const sourceMemberships = sourceMembershipByModulePath(startPushBytes);
  const runtimeModules = authority.runtimeModules.map(normalizeRuntimeModule).map((module) => {
    if (!sourceMemberships.has(module.path)) {
      fail(`helper runtime module ${module.path} is absent from the authenticated request`);
    }
    const { nodePool, sourceMembershipSha256 } = sourceMemberships.get(module.path);
    if (module.nodePool !== nodePool) {
      fail(`helper runtime module ${module.path} has inconsistent Node pool metadata`);
    }
    if ((module.environment === "isolate") !== (sourceMembershipSha256 !== null)) {
      fail(`helper runtime module ${module.path} has inconsistent source-membership provenance`);
    }
    return { ...module, sourceMembershipSha256 };
  });
  runtimeModules.sort((left, right) => compareStrings(left.path, right.path));
  if (
    runtimeModules.length !==
      requirePositiveInteger(authority.runtimeModuleCount, "helper runtime-module count") ||
    new Set(runtimeModules.map(({ path }) => path)).size !== runtimeModules.length
  ) {
    fail("helper runtime-module census is invalid");
  }
  if (
    requirePositiveInteger(authority.packageModuleCount, "helper package-module count") <
    runtimeModules.length
  ) {
    fail("helper package-module count is smaller than its runtime-module count");
  }

  const externalDepsPackage =
    authority.externalDepsPackage === null
      ? null
      : (() => {
          const external = requireExactKeys(
            authority.externalDepsPackage,
            ["dependencies", "sha256", "size", "storageKey"],
            "helper external dependency package"
          );
          return {
            dependencies: requireDependencies(
              external.dependencies,
              "helper external dependency declarations"
            ),
            sha256: requireSha256(external.sha256, "helper external dependency package SHA-256"),
            size: requirePositiveInteger(external.size, "helper external dependency package size"),
            storageKey: requireString(
              external.storageKey,
              "helper external dependency package storage key"
            ),
          };
        })();
  const requestValue = JSON.parse(startPushBytes.toString("utf8"));
  if (requestValue.externalDepsPackage !== undefined) {
    const selected = validateTargetExternalDepsDescriptor(
      targetExternalDepsPackage,
      requestValue.nodeDependencies
    );
    if (
      canonicalJson(requestValue.externalDepsPackage) !==
      canonicalJson({ id: selected.id, sha256: selected.sha256 })
    ) {
      fail("target dependency selection differs from frozen request");
    }
  } else if (targetExternalDepsPackage !== undefined) {
    fail("target dependency material requires an explicitly bound request");
  }
  const certifiedExternal =
    targetExternalDepsPackage === undefined
      ? producerCertificate.externalDepsPackage
      : targetExternalDepsPackage;
  if (
    canonicalJson(externalDepsPackage) !==
      canonicalJson(
        certifiedExternal === null
          ? null
          : {
              dependencies: producerCertificate.identity.dependencies,
              sha256: certifiedExternal.sha256,
              size: certifiedExternal.size,
              storageKey: certifiedExternal.storageKey,
            }
      ) ||
    producerCertificate.identity.runtimeContentAlgorithm !== authority.runtimeContentAlgorithm
  ) {
    fail("helper dependency material differs from the admitted material or producer conformance");
  }
  return {
    externalDepsPackage,
    kind: HELPER_AUTHORITY_KIND,
    nodeVersion: authority.nodeVersion,
    packageModuleCount: authority.packageModuleCount,
    request,
    runtimeContentAlgorithm: convexRuntimeContentAlgorithm,
    runtimeContentSha256: requireSha256(
      authority.runtimeContentSha256,
      "helper runtime-content SHA-256"
    ),
    runtimeModuleCount: runtimeModules.length,
    runtimeModules,
    sourcePackage: helperSourcePackage,
  };
}

function createFrozenRequestEvidence({ derivation, sourceEnvelope, startPushBytes }) {
  const modules = derivation.runtimeModules.map(frozenModuleIdentity);
  const udfIsolateModules = derivation.runtimeModules
    .filter(({ role }) => role === "udfIsolate")
    .map(frozenModuleIdentity);
  const deploymentConfigurationModules = derivation.runtimeModules
    .filter(({ role }) => role === "deploymentConfiguration")
    .map(frozenModuleIdentity);
  const isolateModules = derivation.runtimeModules
    .filter(({ environment }) => environment === "isolate")
    .map(frozenModuleIdentity);
  const nodeModules = derivation.runtimeModules
    .filter(({ environment }) => environment === "node")
    .map(frozenModuleIdentity);
  const selectedModulePaths = [
    ...new Set(sourceEnvelope.selectedRoutes.map(({ runtimeModulePath }) => runtimeModulePath)),
  ].sort(compareStrings);
  const modulesByPath = new Map(modules.map((module) => [module.path, module]));
  const selectedModules = selectedModulePaths.map((path) => {
    const module = modulesByPath.get(path);
    if (module === undefined || module.environment !== "isolate") {
      fail(`authenticated start_push has no isolate module for selected runtime path ${path}`);
    }
    return module;
  });
  return {
    authoritativeDeploymentConfigurationModuleCount: deploymentConfigurationModules.length,
    authoritativeDeploymentConfigurationModulesSha256: fingerprintJson(
      deploymentConfigurationModules
    ),
    authoritativeIsolateModuleCount: isolateModules.length,
    authoritativeIsolateModulesSha256: fingerprintJson(isolateModules),
    authoritativeModuleCount: modules.length,
    authoritativeModulesSha256: fingerprintJson(modules),
    authoritativeNodeModuleCount: nodeModules.length,
    authoritativeNodeModulesSha256: fingerprintJson(nodeModules),
    authoritativeUdfIsolateModuleCount: udfIsolateModules.length,
    authoritativeUdfIsolateModulesSha256: fingerprintJson(udfIsolateModules),
    requestModuleCount: modules.length,
    requestModulesSha256: fingerprintJson(modules),
    requestSha256: sha256(startPushBytes),
    requestSize: startPushBytes.length,
    selectedModuleCount: selectedModules.length,
    selectedModules,
    selectedModulesSha256: fingerprintJson(selectedModules),
    selectedRouteCount: sourceEnvelope.selectedRoutes.length,
  };
}

async function readAndHashFile(path, description) {
  const bytes = await fs.readFile(path);
  if (bytes.length === 0) fail(`${description} must be nonempty`);
  return { bytes, sha256: sha256(bytes), size: bytes.length };
}

async function readAndHashPrivateOutputFile(path, description) {
  const status = await fs.lstat(path);
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.size <= 0 ||
    status.size > SOURCE_PACKAGE_MAX_BYTES ||
    (status.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && status.uid !== process.getuid())
  ) {
    fail(`${description} must be a bounded owner-only regular file`);
  }
  return await readAndHashFile(path, description);
}

export async function inspectRuntimeContentHelper(path) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) {
    fail("runtime-content helper path must be normalized and absolute");
  }
  const canonicalPath = await fs.realpath(path);
  const status = await fs.lstat(canonicalPath);
  if (
    canonicalPath !== path ||
    !status.isFile() ||
    status.isSymbolicLink() ||
    (status.mode & 0o022) !== 0 ||
    (status.mode & 0o100) === 0 ||
    (typeof process.getuid === "function" && status.uid !== process.getuid())
  ) {
    fail("runtime-content helper must be a canonical owner-controlled executable file");
  }
  const identity = await readAndHashFile(canonicalPath, "runtime-content helper");
  return { path: canonicalPath, sha256: identity.sha256, size: identity.size };
}

async function runHelperProcess(command, arguments_) {
  const child = spawn(command, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
  const stdout = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let outputLimitExceeded = false;
  let timedOut = false;
  child.stdout.on("data", (chunk) => {
    stdoutBytes += chunk.length;
    if (stdoutBytes <= HELPER_OUTPUT_MAX_BYTES) {
      stdout.push(chunk);
    } else {
      outputLimitExceeded = true;
      child.kill("SIGKILL");
    }
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > HELPER_OUTPUT_MAX_BYTES) {
      outputLimitExceeded = true;
      child.kill("SIGKILL");
    }
  });
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, HELPER_TIMEOUT_MS);
  let result;
  try {
    result = await new Promise((resolveResult, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolveResult({ code, signal }));
    });
  } finally {
    clearTimeout(timeout);
  }
  if (timedOut) {
    fail(`runtime-content helper exceeded its ${HELPER_TIMEOUT_MS} ms timeout`);
  }
  if (result.code !== 0 || result.signal !== null || stdoutBytes === 0 || outputLimitExceeded) {
    fail(
      `runtime-content helper failed with exit ${String(result.code)}, signal ${String(result.signal)}, stdout bytes ${stdoutBytes}, and stderr bytes ${stderrBytes}`
    );
  }
  try {
    return JSON.parse(Buffer.concat(stdout).toString("utf8"));
  } catch (error) {
    throw new Error("Convex Wasm preactivation runtime authority: helper returned invalid JSON", {
      cause: error,
    });
  }
}

async function executeHelper({
  externalDepsPackagePath,
  externalDepsStorageKey,
  helperPath,
  sourcePackageOutputPath,
  startPushPath,
}) {
  return runHelperProcess(helperPath, [
    "--start-push",
    startPushPath,
    "--source-package-output",
    sourcePackageOutputPath,
    ...(externalDepsPackagePath === undefined
      ? []
      : [
          "--external-deps-package",
          externalDepsPackagePath,
          "--external-deps-storage-key",
          externalDepsStorageKey,
        ]),
  ]);
}

export async function executeRuntimeContentHelperInBackendImage({
  backendImageId,
  externalDepsPackagePath,
  externalDepsStorageKey,
  sourcePackageOutputPath,
  startPushPath,
}) {
  if (typeof backendImageId !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(backendImageId)) {
    fail("backend image ID must be an immutable SHA-256 identity");
  }
  for (const [path, description] of [
    [startPushPath, "start_push input"],
    [sourcePackageOutputPath, "source-package output"],
    ...(externalDepsPackagePath === undefined
      ? []
      : [[externalDepsPackagePath, "external dependency archive"]]),
  ]) {
    if (
      typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path ||
      /[:,\r\n]/u.test(path)
    ) {
      fail(`${description} must be a normalized absolute path without Docker mount delimiters`);
    }
  }
  if (externalDepsPackagePath !== undefined && typeof externalDepsStorageKey !== "string") {
    fail("external dependency storage key is missing");
  }
  if (typeof process.getuid !== "function" || typeof process.getgid !== "function") {
    fail("image-backed helper requires a Unix user identity");
  }
  const containerName = `convex-source-helper-${randomBytes(8).toString("hex")}`;
  const arguments_ = [
    "run", "--rm", "--name", containerName,
    "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges=true", "--memory", "1g",
    "--cpus", "1", "--pids-limit", "64",
    "--user", `${process.getuid()}:${process.getgid()}`,
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
    "--mount", `type=bind,src=${startPushPath},dst=/input/start-push.json,readonly`,
    ...(externalDepsPackagePath === undefined
      ? []
      : ["--mount", `type=bind,src=${externalDepsPackagePath},dst=/input/external-deps.zip,readonly`]),
    "--mount", `type=bind,src=${dirname(sourcePackageOutputPath)},dst=/output`,
    "--entrypoint", "/convex/source_package_preactivation_authority",
    backendImageId,
    "--start-push", "/input/start-push.json",
    "--source-package-output", `/output/${basename(sourcePackageOutputPath)}`,
    ...(externalDepsPackagePath === undefined
      ? []
      : [
          "--external-deps-package", "/input/external-deps.zip",
          "--external-deps-storage-key", externalDepsStorageKey,
        ]),
  ];
  try {
    return await runHelperProcess("docker", arguments_);
  } finally {
    // A timed-out Docker client can leave its container running. The name is
    // unique to this call, so removal cannot affect another authority run.
    spawnSync("docker", ["rm", "--force", containerName], {
      stdio: "ignore",
      timeout: 10_000,
    });
  }
}

async function writePrivateJson(path, value) {
  const handle = await fs.open(path, "wx", 0o600);
  try {
    await handle.writeFile(`${canonicalJson(value)}\n`);
    await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function createPreactivationRuntimeAuthority(
  {
    authorityOutputPath,
    externalDepsPackagePath,
    helper,
    producerCertificate,
    sourceEnvelope: sourceEnvelopeValue,
    sourceEnvelopeBytes,
    sourcePackageOutputPath,
    startPushBytes,
    startPushPath,
    targetExternalDepsPackage,
  },
  { executeHelperImplementation = executeHelper } = {}
) {
  const sourceEnvelope = validateConvexWasmSourceEnvelope(sourceEnvelopeValue);
  if (sourceEnvelopeBytes.toString("utf8") !== `${canonicalJson(sourceEnvelope)}\n`) {
    fail("source-envelope bytes are not canonical");
  }
  if (!Buffer.isBuffer(startPushBytes) || startPushBytes.length === 0) {
    fail("start_push bytes must be a nonempty buffer");
  }
  const certifiedExternal =
    targetExternalDepsPackage === undefined
      ? producerCertificate.externalDepsPackage
      : targetExternalDepsPackage;
  if ((certifiedExternal === null) !== (externalDepsPackagePath === undefined)) {
    fail("certified external dependency material is incomplete");
  }
  const authenticatedHelper = requireExactKeys(
    helper,
    ["path", "sha256", "size"],
    "authenticated runtime-content helper"
  );
  const helperIdentity = requireFileIdentity(
    { sha256: authenticatedHelper.sha256, size: authenticatedHelper.size },
    "authenticated runtime-content helper"
  );
  const helperPath = requireString(
    authenticatedHelper.path,
    "authenticated runtime-content helper path"
  );
  if (!isAbsolute(helperPath) || resolve(helperPath) !== helperPath) {
    fail("authenticated runtime-content helper path must be normalized and absolute");
  }
  if (canonicalJson(helperIdentity) !== canonicalJson(producerCertificate.identity.helper)) {
    fail("authenticated runtime-content helper differs from the producer certificate");
  }
  const helperValue = await executeHelperImplementation({
    externalDepsPackagePath,
    externalDepsStorageKey: certifiedExternal?.storageKey,
    helperPath,
    sourcePackageOutputPath,
    startPushPath,
  });
  const sourcePackage = await readAndHashPrivateOutputFile(
    sourcePackageOutputPath,
    "derived source package"
  );
  const derivation = normalizePreactivationHelperAuthority(helperValue, {
    producerCertificate,
    sourcePackage,
    startPushBytes,
    targetExternalDepsPackage,
  });
  const frozenGraphInputAuthority = createFrozenGraphInputAuthority({
    evidence: createFrozenRequestEvidence({ derivation, sourceEnvelope, startPushBytes }),
    sourceEnvelope,
    sourceEnvelopeBytes,
  });
  const sourcePackageSha256 = sourcePackage.sha256;
  const bindingPayload = {
    kind: DEPLOYED_RUNTIME_AUTHORITY_KIND,
    modules: frozenGraphInputAuthority.request.selectedModules.map((module) => ({
      environment: module.environment,
      moduleHashVerified: true,
      moduleSha256: module.moduleSha256,
      path: module.path,
      sourceMap: module.sourceMap,
      sourcePackageHashVerified: true,
      sourcePackageRuntimeContentSha256: derivation.runtimeContentSha256,
      sourcePackageSha256,
      sourceSha256: module.sourceSha256,
    })),
    sourcePackageFileSha256: [sourcePackageSha256],
  };
  const bindingAuthority = {
    ...bindingPayload,
    authoritySha256: fingerprintJson(bindingPayload),
  };
  const complete = createFullFrozenGraphBindingAuthority({
    bindingAuthority,
    frozenGraphInputAuthority,
    sourceEnvelopeBytes,
    sourcePackage: {
      path: sourcePackageOutputPath,
      sha256: sourcePackageSha256,
      size: sourcePackage.size,
    },
    startPushBytes,
  });
  await writePrivateJson(authorityOutputPath, complete.authority);
  return {
    authoritySha256: complete.authority.authoritySha256,
    derivation,
    frozenGraphBindingSha256: complete.frozenGraphBinding.bindingSha256,
    sourcePackageSha256,
    sourcePackageSize: sourcePackage.size,
    sourcePackageRuntimeContentSha256: derivation.runtimeContentSha256,
  };
}
