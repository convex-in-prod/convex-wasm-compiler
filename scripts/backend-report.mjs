#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { canonicalJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  MAX_ANALYSIS_ENVIRONMENT_BYTES,
  parseSyntheticAnalysisEnvironment,
} from "./lib/convex-wasm-analysis-environment.mjs";
import {
  createFrozenPushPreflight,
  executeFrozenPushProtocol,
  rebindFrozenStartPushAdminKey,
} from "./lib/convex-frozen-deployment-request.mjs";
import {
  createFrozenGraphInputAuthority,
  createFullFrozenGraphBindingAuthority,
  verifySelectedRuntimeAuthority,
} from "./lib/convex-wasm-frozen-graph-authority.mjs";
import { deriveConvexMysqlDatabaseName } from "./lib/convex-local-backend-database.mjs";
import { inspectRuntimeContentHelper } from "./lib/convex-wasm-preactivation-runtime-authority.mjs";
import { validateConvexWasmSourceEnvelope, convexWasmSourceEnvelopeKind } from "./lib/convex-wasm-source-envelope.mjs";
import { convexWasmSdkClientHeader } from "./lib/convex-wasm-sdk-identity.mjs";
import { parseProjectConfig } from "./lib/convex-wasm-project-build-inputs.mjs";
import { collectSqliteRuntimeBindingAuthority } from "./convex-wasm-source-parity-identity.mjs";

const MAX_INPUT_BYTES = 256 * 1024 * 1024;
const MAX_DOCKER_OUTPUT_BYTES = 4 * 1024 * 1024;
const DOCKER_TIMEOUT_MS = 60_000;
const START_TIMEOUT_MS = 90_000;
const RESPONSE_MAX_BYTES = 16 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;
const LOOPBACK_PROXY_IMAGE =
  "alpine/socat@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e";
const LOOPBACK_PROXY_COMMAND = ["TCP4-LISTEN:3210,fork,reuseaddr", "TCP4:backend:3210"];
const CONVEX_CLIENT_HEADER = convexWasmSdkClientHeader;
const ISOLATED_NODE_EXECUTOR_ENVIRONMENT = Object.freeze({
  LOCAL_NODE_EXECUTOR_MAX_RSS_BYTES: String(3 * 1024 * 1024 * 1024),
  LOCAL_NODE_EXECUTOR_POOL_POLICIES: "{}",
  LOCAL_NODE_EXECUTOR_TOTAL_RSS_BUDGET_BYTES: String(64 * 1024 * 1024 * 1024),
});

function fail(message) {
  throw new Error(`Isolated deployed-runtime authority: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function readStableFile(path, description, maximumBytes, requiredMode) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail(`${description} reads require O_NOFOLLOW`);
  }
  const [canonical, beforePath] = await Promise.all([fs.realpath(path), fs.lstat(path)]);
  if (
    canonical !== path ||
    !beforePath.isFile() ||
    beforePath.size === 0 ||
    beforePath.size > maximumBytes ||
    (requiredMode !== undefined &&
      ((beforePath.mode & 0o777) !== requiredMode ||
        (typeof process.getuid === "function" && beforePath.uid !== process.getuid())))
  ) {
    fail(`${description} must be a canonical, nonempty, bounded regular file`);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!sameFileState(beforePath, opened)) {
      fail(`${description} changed while it was opened`);
    }
    const bytes = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) fail(`${description} changed while it was read`);
      offset += read.bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    const trailing = await handle.read(extra, 0, 1, offset);
    const [after, afterPath, afterCanonical] = await Promise.all([
      handle.stat(),
      fs.lstat(path),
      fs.realpath(path),
    ]);
    if (
      trailing.bytesRead !== 0 ||
      !sameFileState(opened, after) ||
      !sameFileState(opened, afterPath) ||
      afterCanonical !== path
    ) {
      fail(`${description} changed while it was read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function writePrivateFile(path, bytes) {
  const handle = await fs.open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600
  );
  try {
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const directoryHandle = await fs.open(dirname(path), "r");
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
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


function runDocker(arguments_, { allowFailure = false, description, input } = {}) {
  const result = spawnSync("docker", arguments_, {
    encoding: "utf8",
    input,
    maxBuffer: MAX_DOCKER_OUTPUT_BYTES,
    timeout: DOCKER_TIMEOUT_MS,
  });
  if (result.error !== undefined) {
    if (allowFailure) return null;
    fail(`${description ?? `docker ${arguments_[0]}`} did not complete`);
  }
  if (result.status !== 0) {
    if (allowFailure) return null;
    fail(`${description ?? `docker ${arguments_[0]}`} failed with status ${String(result.status)}`);
  }
  return result.stdout;
}

function dockerJson(arguments_, description) {
  let parsed;
  try {
    parsed = JSON.parse(runDocker(arguments_, { description: `Docker ${description}` }));
  } catch (error) {
    if (error instanceof SyntaxError) {
      fail(`Docker returned invalid ${description} JSON`);
    }
    throw error;
  }
  return parsed;
}

function assertLocalDockerDaemon() {
  const configuredHost = process.env.DOCKER_HOST;
  if (
    configuredHost !== undefined &&
    !configuredHost.startsWith("unix://") &&
    !configuredHost.startsWith("npipe://")
  ) {
    fail("Docker daemon is not local");
  }
  const inspected = dockerJson(
    ["context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
    "daemon endpoint"
  );
  if (
    typeof inspected !== "string" ||
    (!inspected.startsWith("unix://") && !inspected.startsWith("npipe://"))
  ) {
    fail("Docker daemon is not local");
  }
}

async function readInput(path, description) {
  return readStableFile(path, description, MAX_INPUT_BYTES);
}

function parseJson(bytes, description) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`${description} is not valid JSON`);
  }
}

export async function validateOutputPath(path, description = "output") {
  const parent = await fs.realpath(dirname(path));
  if (parent !== dirname(path)) {
    fail(`${description} parent path must be canonical`);
  }
  const parentStat = await fs.lstat(parent);
  if (!parentStat.isDirectory() || (parentStat.mode & 0o777) !== 0o700) {
    fail(`${description} parent must be an owner-only directory`);
  }
  try {
    await fs.lstat(path);
    fail(`output already exists: ${path}`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function validateWorkRoot(path) {
  const canonical = await fs.realpath(path);
  if (canonical !== path) {
    fail("work root path must be canonical");
  }
  const stat = await fs.lstat(path);
  if (!stat.isDirectory() || (stat.mode & 0o777) !== 0o700) {
    fail("work root must be an owner-only directory");
  }
}

async function writePrivateJson(path, value) {
  await writePrivateFile(path, Buffer.from(`${canonicalJson(value)}\n`));
}


export async function copyAuthenticatedSourcePackage({
  bindingAuthority,
  evidence,
  outputPath,
  selectedModules,
  storageRoot,
}) {
  const authority = requireObject(bindingAuthority, "SQLite runtime binding authority");
  const backendMaterial = requireObject(
    requireObject(requireObject(evidence, "SQLite runtime evidence").authority, "SQLite authority")
      .backendMaterial,
    "SQLite authority backend material"
  );
  const v8LoadPackage = requireObject(backendMaterial.v8LoadPackage, "SQLite V8 load package");
  const expectedSha256 = requireSha256(
    v8LoadPackage.packageSha256,
    "SQLite V8 load-package SHA-256"
  );
  const storageKey = requireString(v8LoadPackage.storageKey, "SQLite V8 load-package storage key");
  if (!/^[A-Za-z0-9-]+$/u.test(storageKey)) {
    fail("SQLite V8 load-package storage key is invalid");
  }
  if (!Array.isArray(authority.modules)) {
    fail("SQLite runtime binding authority modules must be an array");
  }
  const selectedSourcePackageIdentity = verifySelectedRuntimeAuthority({
    bindingAuthority: authority,
    selectedModules,
  });
  const expectedRuntimeContentSha256 = requireSha256(
    v8LoadPackage.runtimeContentSha256,
    "SQLite V8 load-package runtime-content SHA-256"
  );
  if (
    selectedSourcePackageIdentity.sourcePackageSha256 !== expectedSha256 ||
    selectedSourcePackageIdentity.sourcePackageRuntimeContentSha256 !==
      expectedRuntimeContentSha256 ||
    !Array.isArray(authority.sourcePackageFileSha256) ||
    authority.sourcePackageFileSha256.length !== 1 ||
    authority.sourcePackageFileSha256[0] !== expectedSha256
  ) {
    fail("SQLite selected runtime modules do not authenticate the V8 source package");
  }

  const canonicalStorageRoot = await fs.realpath(storageRoot);
  if (canonicalStorageRoot !== storageRoot) {
    fail("SQLite source-package storage root must be canonical");
  }
  const sourcePackagePath = join(canonicalStorageRoot, "modules", `${storageKey}.blob`);
  const canonicalSourcePackagePath = await fs.realpath(sourcePackagePath);
  if (canonicalSourcePackagePath !== sourcePackagePath) {
    fail("SQLite source-package blob path must be canonical");
  }
  const sourcePackageBytes = await readStableFile(
    canonicalSourcePackagePath,
    "SQLite source-package blob",
    MAX_INPUT_BYTES
  );
  if (sha256(sourcePackageBytes) !== expectedSha256) {
    fail("SQLite source-package blob differs from its authenticated V8 load package");
  }

  await writePrivateFile(outputPath, sourcePackageBytes);
  const outputStat = await fs.lstat(outputPath);
  if (!outputStat.isFile() || (outputStat.mode & 0o777) !== 0o600) {
    fail("source-package output must be an owner-only regular file");
  }
  const copiedBytes = await readStableFile(
    outputPath,
    "source-package output",
    MAX_INPUT_BYTES,
    0o600
  );
  if (copiedBytes.length !== sourcePackageBytes.length || sha256(copiedBytes) !== expectedSha256) {
    fail("source-package output differs from the authenticated V8 load package");
  }
  return {
    path: outputPath,
    sha256: expectedSha256,
    size: copiedBytes.length,
  };
}

async function readSourcePackageMetadata(sourcePackagePath, expectedSha256, expectedSize) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("authenticated source-package metadata reads require O_NOFOLLOW");
  }
  const [canonical, beforePath] = await Promise.all([
    fs.realpath(sourcePackagePath),
    fs.lstat(sourcePackagePath),
  ]);
  if (
    canonical !== sourcePackagePath ||
    !beforePath.isFile() ||
    (beforePath.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && beforePath.uid !== process.getuid()) ||
    beforePath.size !== expectedSize ||
    beforePath.size <= 0 ||
    beforePath.size > MAX_INPUT_BYTES
  ) {
    fail("authenticated source package must be a canonical owner-only bounded regular file");
  }
  const handle = await fs.open(sourcePackagePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!sameFileState(beforePath, opened)) {
      fail("authenticated source package changed while it was opened");
    }
    const bytes = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) {
        fail("authenticated source package changed while it was read");
      }
      offset += read.bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    const trailing = await handle.read(extra, 0, 1, offset);
    if (trailing.bytesRead !== 0 || sha256(bytes) !== expectedSha256) {
      fail("authenticated source package differs from its retained identity");
    }

    // Child fd 3 is the authenticated descriptor. Path replacement cannot
    // change which source-package bytes unzip reads.
    const result = spawnSync("unzip", ["-p", "/dev/fd/3", "metadata.json"], {
      encoding: "utf8",
      maxBuffer: MAX_DOCKER_OUTPUT_BYTES,
      stdio: ["ignore", "pipe", "pipe", handle.fd],
      timeout: DOCKER_TIMEOUT_MS,
    });
    const [after, afterPath, afterCanonical] = await Promise.all([
      handle.stat(),
      fs.lstat(sourcePackagePath),
      fs.realpath(sourcePackagePath),
    ]);
    if (
      !sameFileState(opened, after) ||
      !sameFileState(opened, afterPath) ||
      afterCanonical !== sourcePackagePath
    ) {
      fail("authenticated source package changed during metadata extraction");
    }
    if (result.error !== undefined || result.status !== 0) {
      fail("authenticated source-package metadata extraction failed");
    }
    return requireObject(
      parseJson(Buffer.from(result.stdout), "authenticated source-package metadata"),
      "authenticated source-package metadata"
    );
  } finally {
    await handle.close();
  }
}

export async function copyCertifiedExternalDepsPackage({
  outputPath,
  sourcePackageSha256,
  sourcePackageSize,
  sourcePackagePath,
  storageRoot,
}) {
  if (!Number.isSafeInteger(sourcePackageSize) || sourcePackageSize <= 0) {
    fail("authenticated source-package size must be a positive safe integer");
  }
  const metadata = await readSourcePackageMetadata(
    sourcePackagePath,
    requireSha256(sourcePackageSha256, "authenticated source-package SHA-256"),
    sourcePackageSize
  );
  const storageKey = requireString(
    metadata.externalDepsStorageKey,
    "authenticated external dependency storage key"
  );
  if (!/^[A-Za-z0-9-]+$/u.test(storageKey)) {
    fail("authenticated external dependency storage key is invalid");
  }
  const canonicalStorageRoot = await fs.realpath(storageRoot);
  if (canonicalStorageRoot !== storageRoot) {
    fail("external dependency storage root must be canonical");
  }
  const packagePath = join(canonicalStorageRoot, "modules", `${storageKey}.blob`);
  const canonicalPackagePath = await fs.realpath(packagePath);
  if (canonicalPackagePath !== packagePath || !canonicalPackagePath.startsWith(`${storageRoot}/`)) {
    fail("external dependency package path is outside its authenticated storage root");
  }
  const bytes = await readStableFile(
    canonicalPackagePath,
    "external dependency package",
    MAX_INPUT_BYTES
  );
  await writePrivateFile(outputPath, bytes);
  const copied = await readStableFile(
    outputPath,
    "external dependency package output",
    MAX_INPUT_BYTES,
    0o600
  );
  if (copied.length !== bytes.length || sha256(copied) !== sha256(bytes)) {
    fail("external dependency package output changed while it was copied");
  }
  return { path: outputPath, sha256: sha256(bytes), size: bytes.length, storageKey };
}

function imageIdentity(image) {
  const records = dockerJson(["image", "inspect", image], "image inspection");
  if (!Array.isArray(records) || records.length !== 1) {
    fail("backend image inspection must return one image");
  }
  const record = requireObject(records[0], "backend image inspection");
  const id = requireString(record.Id, "backend image ID");
  if (!/^sha256:[0-9a-f]{64}$/u.test(id)) {
    fail("backend image ID is invalid");
  }
  return id;
}

export async function ensureRuntimeContentHelper({ backendImageId, buildDirectory, helperPath }) {
  try {
    await fs.lstat(helperPath);
    return inspectRuntimeContentHelper(helperPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const suffix = randomBytes(8).toString("hex");
  const containerName = `convex-authority-helper-${suffix}`;
  const extractedPath = join(buildDirectory, `.backend-helper-${suffix}`);
  const installPath = join(dirname(helperPath), `.backend-helper-install-${suffix}`);
  let containerCreated = false;
  try {
    runDocker(["create", "--name", containerName, "--network", "none", backendImageId]);
    containerCreated = true;
    runDocker(
      ["cp", `${containerName}:/convex/source_package_preactivation_authority`, extractedPath],
      { description: "backend image source-package helper extraction" }
    );
    await fs.chmod(extractedPath, 0o700);
    const extracted = await inspectRuntimeContentHelper(extractedPath);
    await fs.mkdir(dirname(helperPath), { recursive: true, mode: 0o700 });
    await validateWorkRoot(dirname(helperPath));
    await writePrivateFile(
      installPath,
      await readStableFile(extractedPath, "backend image helper", MAX_INPUT_BYTES, 0o700)
    );
    await fs.chmod(installPath, 0o700);
    await fs.link(installPath, helperPath);
    const installed = await inspectRuntimeContentHelper(helperPath);
    if (installed.sha256 !== extracted.sha256 || installed.size !== extracted.size) {
      fail("installed source-package helper differs from the backend image");
    }
    return installed;
  } finally {
    try {
      if (containerCreated) runDocker(["rm", "--force", containerName]);
    } finally {
      await Promise.all([
        fs.rm(extractedPath, { force: true }),
        fs.rm(installPath, { force: true }),
      ]);
    }
  }
}

function loopbackProxyImageIdentity() {
  const records = dockerJson(
    ["image", "inspect", LOOPBACK_PROXY_IMAGE],
    "loopback proxy image inspection"
  );
  if (!Array.isArray(records) || records.length !== 1) {
    fail("loopback proxy image inspection must return one image");
  }
  const id = requireString(records[0]?.Id, "loopback proxy image ID");
  if (!/^sha256:[0-9a-f]{64}$/u.test(id)) {
    fail("loopback proxy image ID is invalid");
  }
  return id;
}

function inspectBackendContainer(containerName, imageId, expectedNetworkNames, dataRoot) {
  const records = dockerJson(["inspect", containerName], "isolated backend inspection");
  if (!Array.isArray(records) || records.length !== 1) {
    fail("isolated backend inspection must return one container");
  }
  const record = requireObject(records[0], "isolated backend inspection");
  const hostConfig = requireObject(record.HostConfig, "isolated backend host config");
  if (record.Image !== imageId || record.State?.Running !== true) {
    fail("isolated backend container identity changed");
  }
  const networks = Object.keys(record.NetworkSettings?.Networks ?? {});
  const publishedPorts = Object.values(record.NetworkSettings?.Ports ?? {});
  const dataMount = record.Mounts?.find((mount) => mount.Destination === "/convex/data");
  if (
    canonicalJson(networks.sort()) !== canonicalJson([...expectedNetworkNames].sort()) ||
    publishedPorts.some((bindings) => bindings !== null) ||
    Object.keys(record.HostConfig?.PortBindings ?? {}).length !== 0 ||
    record.Config?.User !== "0:0" ||
    canonicalJson(hostConfig.CapDrop) !== canonicalJson(["ALL"]) ||
    canonicalJson(hostConfig.SecurityOpt) !== canonicalJson(["no-new-privileges=true"]) ||
    dataMount?.Type !== "bind" ||
    dataMount.Source !== dataRoot ||
    dataMount.RW !== true ||
    record.Mounts.length !== 1
  ) {
    fail("isolated backend escaped its unique internal network or data root");
  }
  return record;
}

function inspectLoopbackProxy(proxyName, proxyImageId, internalNetworkName, publishNetworkName) {
  const records = dockerJson(["inspect", proxyName], "loopback proxy inspection");
  if (!Array.isArray(records) || records.length !== 1) {
    fail("isolated loopback proxy inspection must return one container");
  }
  const record = requireObject(records[0], "isolated loopback proxy inspection");
  const hostConfig = requireObject(record.HostConfig, "isolated loopback proxy host config");
  const networks = Object.keys(record.NetworkSettings?.Networks ?? {}).sort();
  if (
    record.Image !== proxyImageId ||
    record.State?.Running !== true ||
    record.Config?.User !== "65534:65534" ||
    canonicalJson(record.Config?.Cmd) !== canonicalJson(LOOPBACK_PROXY_COMMAND) ||
    hostConfig.ReadonlyRootfs !== true ||
    canonicalJson(hostConfig.CapDrop) !== canonicalJson(["ALL"]) ||
    canonicalJson(hostConfig.SecurityOpt) !== canonicalJson(["no-new-privileges=true"]) ||
    record.Mounts?.length !== 0 ||
    canonicalJson(networks) !== canonicalJson([internalNetworkName, publishNetworkName].sort())
  ) {
    fail("isolated loopback proxy sandbox or network identity changed");
  }
  return record;
}

function publishedOrigin(proxyName, proxyImageId, internalNetworkName, publishNetworkName) {
  const record = inspectLoopbackProxy(
    proxyName,
    proxyImageId,
    internalNetworkName,
    publishNetworkName
  );
  const ports = record.NetworkSettings?.Ports?.["3210/tcp"];
  if (
    !Array.isArray(ports) ||
    ports.length !== 1 ||
    ports[0]?.HostIp !== "127.0.0.1" ||
    !/^[0-9]+$/u.test(ports[0]?.HostPort ?? "")
  ) {
    fail("isolated loopback proxy has no unique deployment port");
  }
  return `http://127.0.0.1:${ports[0].HostPort}`;
}

async function waitForBackend(origin, inspectTopology) {
  const deadline = Date.now() + START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    inspectTopology();
    try {
      const response = await fetch(`${origin}/version`, {
        redirect: "error",
        signal: AbortSignal.timeout(2_000),
      });
      if (response.ok) return;
    } catch {
      // A fresh local backend may refuse loopback connections until initialization completes.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  fail("isolated backend did not become ready");
}

function readEphemeralAdminKey(containerName) {
  const adminKey = runDocker([
    "exec",
    containerName,
    "/bin/sh",
    "-c",
    'exec ./generate_key "$(cat /convex/data/credentials/instance_name)" "$(cat /convex/data/credentials/instance_secret)"',
  ]).trim();
  if (
    adminKey.length === 0 ||
    adminKey.includes("\r") ||
    adminKey.includes("\n") ||
    adminKey.includes("\u0000")
  ) {
    fail("isolated backend returned an invalid admin key");
  }
  return adminKey;
}

async function readJsonResponse(response, description) {
  if (!response.ok) {
    const bytes = await readBoundedResponse(response, description);
    let code;
    try {
      code = JSON.parse(bytes.toString("utf8"))?.code;
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
    const safeCode = typeof code === "string" && /^[A-Za-z][A-Za-z0-9_]{0,100}$/u.test(code)
      ? ` with code ${code}`
      : "";
    fail(`${description} returned HTTP ${response.status}${safeCode}`);
  }
  const bytes = await readBoundedResponse(response, description);
  if (bytes.length === 0 || bytes.length > RESPONSE_MAX_BYTES) {
    fail(`${description} returned an invalid response size`);
  }
  return parseJson(bytes, `${description} response`);
}

async function readBoundedResponse(response, description) {
  const contentLength = response.headers.get("content-length");
  if (
    contentLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength) || Number(contentLength) > RESPONSE_MAX_BYTES)
  ) {
    fail(`${description} returned an invalid response size`);
  }
  if (response.body === null) return Buffer.alloc(0);
  const chunks = [];
  let totalBytes = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > RESPONSE_MAX_BYTES) {
        await reader.cancel();
        fail(`${description} returned an invalid response size`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, totalBytes);
}

async function applySyntheticAnalysisEnvironment({ adminKey, origin, values }) {
  const headers = {
    Authorization: `Convex ${adminKey}`,
    "Content-Type": "application/json",
    "Convex-Client": CONVEX_CLIENT_HEADER,
  };
  const listEnvironment = async () => {
    const response = await fetch(new URL("/api/list_environment_variables", origin), {
      headers,
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    const result = requireObject(
      await readJsonResponse(response, "list_environment_variables"),
      "list_environment_variables response"
    );
    return requireObject(
      result.environmentVariables,
      "list_environment_variables environmentVariables"
    );
  };
  if (Object.keys(await listEnvironment()).length !== 0) {
    fail("fresh isolated deployment already contains environment variables");
  }
  const response = await fetch(new URL("/api/update_environment_variables", origin), {
    body: JSON.stringify({
      changes: Object.keys(values).sort().map((name) => ({ name, value: values[name] })),
    }),
    headers,
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) fail(`update_environment_variables returned HTTP ${response.status}`);
  await readBoundedResponse(response, "update_environment_variables");
  if (canonicalJson(await listEnvironment()) !== canonicalJson(values)) {
    fail("isolated analysis environment differs after authenticated update");
  }
}


async function verifyActiveModules({ adminKey, moduleIdentities, origin }) {
  const response = await fetch(`${origin}/api/get_config_hashes`, {
    body: JSON.stringify({ adminKey }),
    headers: {
      Authorization: `Convex ${adminKey}`,
      "Content-Type": "application/json",
      "Convex-Client": CONVEX_CLIENT_HEADER,
    },
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  const config = requireObject(
    await readJsonResponse(response, "get_config_hashes"),
    "get_config_hashes response"
  );
  if (!Array.isArray(config.moduleHashes)) {
    fail("get_config_hashes response has no module hashes");
  }
  for (const moduleIdentity of moduleIdentities) {
    const matches = config.moduleHashes.filter(({ path }) => path === moduleIdentity.path);
    if (
      matches.length !== 1 ||
      matches[0].hash !== moduleIdentity.moduleSha256 ||
      matches[0].environment !== "isolate"
    ) {
      fail(`active isolated module ${moduleIdentity.path} differs from its frozen identity`);
    }
  }
}

function stopContainer(containerName) {
  runDocker(["stop", "--time", "30", containerName]);
}

export async function executeWithTemporaryNodeDependencyEgress({
  connect,
  disconnect,
  execute,
  inspectEgressTopology,
  inspectInternalTopology,
}) {
  for (const [callback, description] of [
    [connect, "connect callback"],
    [disconnect, "disconnect callback"],
    [execute, "protocol callback"],
    [inspectEgressTopology, "egress topology callback"],
    [inspectInternalTopology, "internal topology callback"],
  ]) {
    if (typeof callback !== "function") {
      fail(`temporary dependency egress ${description} is required`);
    }
  }
  let connected = false;
  const closeEgress = async () => {
    await disconnect();
    connected = false;
    await inspectInternalTopology();
  };
  try {
    return await execute({
      beforeStartPush: async () => {
        await connect();
        connected = true;
        await inspectEgressTopology();
      },
      onPhase: async ({ phase }) => {
        if (phase === "startPushReturned") await closeEgress();
      },
    });
  } catch (operationError) {
    if (!connected) throw operationError;
    try {
      await closeEgress();
    } catch (cleanupError) {
      throw new AggregateError(
        [operationError, cleanupError],
        "frozen push and dependency-egress cleanup both failed"
      );
    }
    throw operationError;
  }
}

function makeIsolatedAuthorityDataHostAccessible(
  { backendImageId, temporaryRoot },
  runDockerImplementation = runDocker
) {
  runDockerImplementation([
    "run",
    "--rm",
    "--network",
    "none",
    "--read-only",
    "--user",
    "0:0",
    "--memory",
    "64m",
    "--cpus",
    "0.25",
    "--pids-limit",
    "32",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges=true",
    "--mount",
    `type=bind,src=${join(temporaryRoot, "data")},dst=/data`,
    "--entrypoint",
    "/bin/sh",
    backendImageId,
    "-c",
    "find /data -mindepth 1 -type d -exec chmod a+rwx {} + && exec find /data -mindepth 1 -type f -exec chmod a+rw {} +",
  ]);
}

export async function removeIsolatedAuthorityResources(
  {
    backendImageId,
    backendName,
    dataHostAccessible,
    internalNetworkName,
    proxyName,
    publishNetworkName,
    temporaryRoot,
  },
  { removeImplementation = fs.rm, runDockerImplementation = runDocker } = {}
) {
  runDockerImplementation(["rm", "--force", proxyName], { allowFailure: true });
  runDockerImplementation(["rm", "--force", backendName], { allowFailure: true });
  let normalizationError;
  let normalizationFailed = false;
  try {
    if (!dataHostAccessible) {
      makeIsolatedAuthorityDataHostAccessible(
        { backendImageId, temporaryRoot },
        runDockerImplementation
      );
    }
  } catch (error) {
    normalizationFailed = true;
    normalizationError = error;
  }
  runDockerImplementation(["network", "rm", internalNetworkName], { allowFailure: true });
  runDockerImplementation(["network", "rm", publishNetworkName], { allowFailure: true });
  let removalError;
  let removalFailed = false;
  try {
    await removeImplementation(temporaryRoot, { force: true, recursive: true });
  } catch (error) {
    removalFailed = true;
    removalError = error;
  }
  if (normalizationFailed && removalFailed) {
    throw new AggregateError(
      [normalizationError, removalError],
      "isolated data normalization and temporary-root removal both failed"
    );
  }
  if (normalizationFailed) throw normalizationError;
  if (removalFailed) throw removalError;
}

export async function withIsolatedAuthorityCleanup(
  resources,
  operation,
  { removeImplementation = fs.rm, runDockerImplementation = runDocker } = {}
) {
  if (typeof operation !== "function") {
    fail("isolated authority operation callback is required");
  }
  let stoppedAndDataHostAccessible = false;
  let operationResult;
  let operationError;
  let operationFailed = false;
  try {
    operationResult = await operation(() => {
      // The stopped backend cannot create more inaccessible files after collection preparation.
      stoppedAndDataHostAccessible = true;
    });
  } catch (error) {
    operationFailed = true;
    operationError = error;
  }
  let cleanupError;
  let cleanupFailed = false;
  try {
    if (!stoppedAndDataHostAccessible) {
      runDockerImplementation(["stop", "--time", "30", resources.proxyName], {
        allowFailure: true,
      });
      runDockerImplementation(["stop", "--time", "30", resources.backendName], {
        allowFailure: true,
      });
    }
    await removeIsolatedAuthorityResources(
      { ...resources, dataHostAccessible: stoppedAndDataHostAccessible },
      { removeImplementation, runDockerImplementation }
    );
  } catch (error) {
    cleanupFailed = true;
    cleanupError = error;
  }
  if (operationFailed && cleanupFailed) {
    throw new AggregateError(
      [operationError, cleanupError],
      "isolated authority operation and cleanup both failed"
    );
  }
  if (operationFailed) throw operationError;
  if (cleanupFailed) throw cleanupError;
  return operationResult;
}

export function createIsolatedRuntimeAuthorityReport({
  analysisEnvironment,
  authoritySha256,
  backendImageId,
  completeBinding,
  currentGraphPreflight,
  dependencyEgressUsed,
  ephemeralPreflight,
  externalDepsPackage,
  frozenGraphInputAuthority,
  nodeDependencySpecs,
  sourceEnvelope,
  sourcePackage,
}) {
  return {
    authoritySha256,
    backendImageId,
    frozenGraphBindingSha256: completeBinding.frozenGraphBinding.bindingSha256,
    frozenGraphInputAuthoritySha256: frozenGraphInputAuthority.inputAuthoritySha256,
    currentGraphPreflightSha256: currentGraphPreflight.preflightSha256,
    ephemeralPreflightSha256: ephemeralPreflight.preflightSha256,
    dependencyEgressUsed,
    ...(externalDepsPackage === undefined ? {} : { externalDepsPackage }),
    nodeDependencySpecs,
    requestModulesSha256: frozenGraphInputAuthority.request.requestModulesSha256,
    requestSha256: frozenGraphInputAuthority.request.requestSha256,
    requestSize: frozenGraphInputAuthority.request.requestSize,
    runtimeModulePaths: completeBinding.selectedRuntimeAuthority.runtimeModulePaths,
    selectedModulesSha256: frozenGraphInputAuthority.request.selectedModulesSha256,
    sourcePackageRuntimeContentSha256:
      completeBinding.selectedRuntimeAuthority.sourcePackageRuntimeContentSha256,
    sourceEnvelopeFileSha256: frozenGraphInputAuthority.sourceEnvelope.fileSha256,
    sourceEnvelopeSha256: sourceEnvelope.sourceEnvelopeSha256,
    sourceGraphSha256: sourceEnvelope.graph.sha256,
    sourceScope: "current-complete-frozen-graph-v1",
    sourcePackage,
    ...(analysisEnvironment === undefined
      ? { environmentScope: "fresh-empty" }
      : {
          analysisEnvironmentFileSha256: analysisEnvironment.evidence.fileSha256,
          analysisEnvironmentNames: analysisEnvironment.evidence.names,
          analysisEnvironmentValueSha256: analysisEnvironment.evidence.values,
          environmentScope: "synthetic-analysis-only",
        }),
  };
}

export async function createProjectBackendReport({ artifactReportPath, configPath }) {
  const config = parseProjectConfig(JSON.parse(await fs.readFile(configPath, "utf8")), configPath);
  if (config.sourceAuthority === undefined) {
    fail("project config requires sourceAuthority");
  }
  const analysisEnvironment = config.sourceAuthority.analysisEnvironmentPath === undefined
    ? undefined
    : parseSyntheticAnalysisEnvironment(await readStableFile(
        config.sourceAuthority.analysisEnvironmentPath,
        "analysis environment",
        MAX_ANALYSIS_ENVIRONMENT_BYTES,
        0o600
      ));
  const buildDirectory = dirname(artifactReportPath);
  await validateWorkRoot(buildDirectory);
  const reportBytes = await readStableFile(artifactReportPath, "project artifact report", MAX_INPUT_BYTES, 0o600);
  const report = requireObject(parseJson(reportBytes, "project artifact report"), "project artifact report");
  if (
    report.kind !== "convex-wasm-project-artifact-report-v1" ||
    typeof report.sourceEnvelope?.path !== "string" ||
    typeof report.startPush?.path !== "string"
  ) {
    fail("project artifact report lacks complete source inputs");
  }
  const [sourceEnvelopeBytes, startPushBytes] = await Promise.all([
    readInput(report.sourceEnvelope.path, "project source envelope"),
    readInput(report.startPush.path, "project source request"),
  ]);
  for (const [bytes, expected, description] of [
    [sourceEnvelopeBytes, report.sourceEnvelope, "project source envelope"],
    [startPushBytes, report.startPush, "project source request"],
  ]) {
    if (bytes.length !== expected.size || sha256(bytes) !== expected.sha256) {
      fail(`${description} differs from the build report`);
    }
  }
  const sourceEnvelope = validateConvexWasmSourceEnvelope(
    parseJson(sourceEnvelopeBytes, "project source envelope")
  );
  if (
    sourceEnvelope.kind !== convexWasmSourceEnvelopeKind ||
    sourceEnvelopeBytes.toString("utf8") !== `${canonicalJson(sourceEnvelope)}\n`
  ) {
    fail("project source envelope is not canonical");
  }
  const selectedRuntimeModulePaths = [
    ...new Set(sourceEnvelope.selectedRoutes.map(({ runtimeModulePath }) => runtimeModulePath)),
  ].sort();
  const evidence = requireObject(report.frozenRequestEvidence, "build request evidence");
  if (
    canonicalJson(evidence.selectedModules?.map(({ path }) => path)) !==
    canonicalJson(selectedRuntimeModulePaths)
  ) {
    fail("build request selected modules differ from the source envelope");
  }
  const frozenGraphInputAuthority = createFrozenGraphInputAuthority({
    evidence,
    sourceEnvelope,
    sourceEnvelopeBytes,
  });
  const startPush = requireObject(parseJson(startPushBytes, "project source request"), "project source request");
  if (!Array.isArray(startPush.nodeDependencies)) {
    fail("project source request lacks Node dependency declarations");
  }
  const nodeDependencyNames = new Set();
  const nodeDependencySpecs = startPush.nodeDependencies.map((dependency, index) => {
    const item = requireObject(dependency, `Node dependency ${index}`);
    requireExactKeys(item, ["name", "version"], `Node dependency ${index}`);
    const name = requireString(item.name, `Node dependency ${index} name`);
    if (nodeDependencyNames.has(name)) fail(`duplicate Node dependency ${name}`);
    nodeDependencyNames.add(name);
    return `${name}@${requireString(item.version, `Node dependency ${index} version`)}`;
  }).sort();
  const dependencyEgressUsed = nodeDependencySpecs.length > 0;
  if (dependencyEgressUsed && !config.sourceAuthority.allowNodeDependencyEgress) {
    fail("Node dependencies require sourceAuthority.allowNodeDependencyEgress");
  }
  if (!dependencyEgressUsed && config.sourceAuthority.externalDepsPackagePath !== undefined) {
    fail("an external dependency output was configured without Node dependencies");
  }
  const gatePolicy = requireObject(
    JSON.parse(await fs.readFile(config.gatePolicyPath, "utf8")),
    "project gate policy"
  );
  const platformExecutionTimeMs = gatePolicy.platformLimits?.executionTimeMs;
  if (
    !Number.isSafeInteger(platformExecutionTimeMs) ||
    platformExecutionTimeMs <= 0 ||
    platformExecutionTimeMs % 1_000 !== 0
  ) {
    fail("gate policy platform execution time must be a positive whole number of seconds");
  }
  const authorityPath = join(buildDirectory, "backend-source-authority.json");
  const sourcePackagePath = join(buildDirectory, "backend-source-package.zip");
  const backendReportPath = join(buildDirectory, "backend-source-package-report.json");
  const externalDepsPackagePath = dependencyEgressUsed
    ? (config.sourceAuthority.externalDepsPackagePath ?? join(buildDirectory, "external-deps-package.zip"))
    : undefined;
  await Promise.all([
    validateOutputPath(authorityPath, "backend authority output"),
    validateOutputPath(sourcePackagePath, "backend source-package output"),
    validateOutputPath(backendReportPath, "backend report output"),
    ...(externalDepsPackagePath === undefined
      ? []
      : [validateOutputPath(externalDepsPackagePath, "backend external-dependency output")]),
  ]);

  assertLocalDockerDaemon();
  const imageId = imageIdentity(config.sourceAuthority.backendImageId);
  if (imageId !== config.sourceAuthority.backendImageId) {
    fail("configured backend image ID differs from Docker's immutable image ID");
  }
  await ensureRuntimeContentHelper({
    backendImageId: imageId,
    buildDirectory,
    helperPath: config.sourceAuthority.helperPath,
  });
  const proxyImageId = loopbackProxyImageIdentity();
  const suffix = randomBytes(8).toString("hex");
  const backendName = `convex-authority-backend-${suffix}`;
  const proxyName = `convex-authority-proxy-${suffix}`;
  const internalNetworkName = `convex-authority-internal-${suffix}`;
  const publishNetworkName = `convex-authority-publish-${suffix}`;
  const instanceName = `convex-authority-${suffix}`;
  const temporaryRoot = await fs.mkdtemp(join(buildDirectory, `convex-authority-${suffix}-`));
  await fs.chmod(temporaryRoot, 0o700);
  const dataRoot = join(temporaryRoot, "data");
  await fs.mkdir(dataRoot, { mode: 0o777 });
  await fs.chmod(dataRoot, 0o777);
  const resources = {
    backendImageId: imageId,
    backendName,
    internalNetworkName,
    proxyName,
    publishNetworkName,
    temporaryRoot,
  };
  const result = await withIsolatedAuthorityCleanup(resources, async (markStoppedAndDataHostAccessible) => {
    runDocker(["network", "create", "--internal", internalNetworkName]);
    runDocker(["network", "create", publishNetworkName]);
    runDocker([
      "run", "--detach", "--rm", "--name", backendName,
      "--network", internalNetworkName, "--network-alias", "backend",
      "--user", "0:0", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges=true",
      "--mount", `type=bind,src=${dataRoot},dst=/convex/data`,
      "--env", `INSTANCE_NAME=${instanceName}`,
      "--env", "DISABLE_BEACON=1",
      "--env", "CONVEX_CLOUD_ORIGIN=http://127.0.0.1:3210",
      "--env", "CONVEX_SITE_ORIGIN=http://127.0.0.1:3211",
      "--env", "CONVEX_STATIC_HERMES_WASM_GATE_ENABLED=0",
      "--env", "CONVEX_STATIC_HERMES_WASM_GATE_DISABLE_BACKGROUND_EXECUTORS=1",
      "--env", "CONVEX_STATIC_HERMES_WASM_GATE_REUSE_INSTANCES=0",
      "--env", `DATABASE_UDF_USER_TIMEOUT_SECONDS=${String(platformExecutionTimeMs / 1_000)}`,
      ...Object.entries(ISOLATED_NODE_EXECUTOR_ENVIRONMENT).flatMap(([name, value]) => ["--env", `${name}=${value}`]),
      imageId, "--interface", "0.0.0.0",
    ]);
    runDocker([
      "run", "--detach", "--rm", "--name", proxyName,
      "--network", publishNetworkName, "--publish", "127.0.0.1::3210",
      "--read-only", "--user", "65534:65534",
      "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64",
      "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
      LOOPBACK_PROXY_IMAGE, ...LOOPBACK_PROXY_COMMAND,
    ]);
    runDocker(["network", "connect", internalNetworkName, proxyName]);
    const inspectInternalTopology = () => {
      inspectBackendContainer(backendName, imageId, [internalNetworkName], dataRoot);
      inspectLoopbackProxy(proxyName, proxyImageId, internalNetworkName, publishNetworkName);
    };
    const inspectEgressTopology = () => {
      inspectBackendContainer(backendName, imageId, [internalNetworkName, publishNetworkName], dataRoot);
      inspectLoopbackProxy(proxyName, proxyImageId, internalNetworkName, publishNetworkName);
    };
    const origin = publishedOrigin(proxyName, proxyImageId, internalNetworkName, publishNetworkName);
    await waitForBackend(origin, inspectInternalTopology);
    const adminKey = readEphemeralAdminKey(backendName);
    if (analysisEnvironment !== undefined) {
      inspectInternalTopology();
      await applySyntheticAnalysisEnvironment({
        adminKey,
        origin,
        values: analysisEnvironment.values,
      });
      inspectInternalTopology();
    }
    const target = {
      backend: {
        database: deriveConvexMysqlDatabaseName(instanceName),
        databaseKind: "sqlite",
        directDeploymentUrl: origin,
        instanceName,
      },
      isolation: { backendImageId: imageId, kind: "fresh-disposable-sqlite-v1" },
    };
    const currentGraphPreflight = createFrozenPushPreflight({
      requestEvidence: evidence,
      sourceAuthority: sourceEnvelope,
      sourceAuthorityFileSha256: sha256(sourceEnvelopeBytes),
      target,
    });
    const ephemeralRequest = rebindFrozenStartPushAdminKey({
      adminKey,
      preflight: currentGraphPreflight,
      requestBytes: startPushBytes,
    });
    const ephemeralPreflight = createFrozenPushPreflight({
      requestEvidence: ephemeralRequest.evidence,
      sourceAuthority: sourceEnvelope,
      sourceAuthorityFileSha256: sha256(sourceEnvelopeBytes),
      target,
    });
    const execute = ({ beforeStartPush, onPhase }) => executeFrozenPushProtocol({
      adminKey,
      beforeStartPush,
      onPhase,
      requestBytes: ephemeralRequest.requestBytes,
      requestSha256: ephemeralPreflight.request.requestSha256,
      url: origin,
    });
    if (dependencyEgressUsed) {
      await executeWithTemporaryNodeDependencyEgress({
        connect: async () => runDocker(["network", "connect", publishNetworkName, backendName]),
        disconnect: async () => runDocker(["network", "disconnect", publishNetworkName, backendName]),
        execute,
        inspectEgressTopology,
        inspectInternalTopology,
      });
    } else {
      await execute({ beforeStartPush: async () => inspectInternalTopology(), onPhase: async () => {} });
    }
    await verifyActiveModules({ adminKey, moduleIdentities: evidence.selectedModules, origin });
    stopContainer(proxyName);
    stopContainer(backendName);
    makeIsolatedAuthorityDataHostAccessible(resources);
    markStoppedAndDataHostAccessible();
    const collected = await collectSqliteRuntimeBindingAuthority({
      databasePath: join(dataRoot, "db.sqlite3"),
      instanceName,
      runtimeModulePaths: selectedRuntimeModulePaths,
      storageRoot: join(dataRoot, "storage"),
    });
    const sourcePackage = await copyAuthenticatedSourcePackage({
      bindingAuthority: collected.bindingAuthority,
      evidence: collected.evidence,
      outputPath: sourcePackagePath,
      selectedModules: evidence.selectedModules,
      storageRoot: join(dataRoot, "storage"),
    });
    const externalDepsPackage = externalDepsPackagePath === undefined
      ? undefined
      : await copyCertifiedExternalDepsPackage({
          outputPath: externalDepsPackagePath,
          sourcePackagePath: sourcePackage.path,
          sourcePackageSha256: sourcePackage.sha256,
          sourcePackageSize: sourcePackage.size,
          storageRoot: join(dataRoot, "storage"),
        });
    const completeBinding = createFullFrozenGraphBindingAuthority({
      bindingAuthority: collected.bindingAuthority,
      frozenGraphInputAuthority,
      sourceEnvelopeBytes,
      sourcePackage,
      startPushBytes,
    });
    await writePrivateJson(authorityPath, completeBinding.authority);
    const backendReport = createIsolatedRuntimeAuthorityReport({
      analysisEnvironment,
      authoritySha256: collected.bindingAuthority.authoritySha256,
      backendImageId: imageId,
      completeBinding,
      currentGraphPreflight,
      dependencyEgressUsed,
      ephemeralPreflight,
      externalDepsPackage,
      frozenGraphInputAuthority,
      nodeDependencySpecs,
      sourceEnvelope,
      sourcePackage,
    });
    await writePrivateJson(backendReportPath, { ...backendReport, output: authorityPath });
    return { backendReport: backendReportPath, authority: authorityPath, sourcePackage: sourcePackagePath };
  });
  return result;
}

if (import.meta.main) {
  const argv = process.argv.slice(2);
  if (argv.length !== 4 || argv[0] !== "--config" || argv[2] !== "--artifact-report") {
    throw new Error("usage: convex-wasm-backend-report --config PROJECT.json --artifact-report REPORT.json");
  }
  const result = await createProjectBackendReport({
    configPath: resolve(argv[1]),
    artifactReportPath: resolve(argv[3]),
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}
