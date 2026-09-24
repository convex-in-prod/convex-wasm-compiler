import { createHash, randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import {
  normalizeDeployedRuntimeAuthority,
  verifyFrozenGraphBindingSourceEnvelope,
} from "./convex-deployed-runtime-identity.mjs";
import {
  decodeUtf8,
  readAndHashPrivateRegularFile,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheDirectoryFileIdentities,
} from "./convex-wasm-private-cache.mjs";
import { validateConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";

const CACHE_ENTRY_KIND = "convex-wasm-isolated-runtime-authority-cache-entry-v1";
const CACHE_IDENTITY_KIND = "convex-wasm-isolated-runtime-authority-cache-key-v1";
const CACHE_ROOT_VERSION = "v1";
const PRODUCER_CERTIFICATE_KIND = "convex-runtime-content-producer-certificate-v1";
const PRODUCER_IDENTITY_KIND = "convex-runtime-content-producer-cache-key-v1";
const PRODUCER_ROOT_VERSION = "v1";
const COMPLETE_MAX_BYTES = 65;
const AUTHORITY_MAX_BYTES = 16 * 1024 * 1024;
const SOURCE_PACKAGE_MAX_BYTES = 256 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex Wasm isolated runtime-authority cache: ${message}`);
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
  const keys = Object.keys(requireObject(value, description)).sort(compareStrings);
  if (canonicalJson(keys) !== canonicalJson([...expected].sort(compareStrings))) {
    fail(`${description} fields are invalid`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
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

function requireDependencyIdentities(value, description) {
  if (!Array.isArray(value)) {
    fail(`${description} must be an array`);
  }
  const dependencies = value.map((dependency, index) => {
    const item = requireExactKeys(
      dependency,
      ["package", "version"],
      `${description} item ${index}`
    );
    if (
      typeof item.package !== "string" ||
      item.package.length === 0 ||
      typeof item.version !== "string" ||
      item.version.length === 0
    ) {
      fail(`${description} item ${index} fields must be nonempty strings`);
    }
    return { package: item.package, version: item.version };
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

function requireBackendImageId(value) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/u.test(value)) {
    fail("backend image ID is invalid");
  }
  return value;
}

function requireCanonicalCacheRoot(value) {
  if (typeof value !== "string" || value.length === 0 || resolve(value) !== value) {
    fail("cache root must be a normalized absolute path");
  }
  return value;
}

function cacheIdentityPath(cacheRoot) {
  return join(
    requireCanonicalCacheRoot(cacheRoot),
    "convex-wasm",
    "state",
    "v1",
    "isolated-runtime-authority",
    CACHE_ROOT_VERSION
  );
}

function producerIdentityPath(cacheRoot) {
  return join(
    requireCanonicalCacheRoot(cacheRoot),
    "convex-wasm",
    "state",
    "v1",
    "runtime-content-producer",
    PRODUCER_ROOT_VERSION
  );
}

function parseCanonicalJson(bytes, description) {
  const source = decodeUtf8(bytes, description);
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new Error(
      `Convex Wasm isolated runtime-authority cache: ${description} is invalid JSON`,
      {
        cause: error,
      }
    );
  }
  if (source !== `${canonicalJson(value)}\n`) {
    fail(`${description} is not canonical JSON`);
  }
  return value;
}

function sourceEnvelopeIdentity({ sourceEnvelope, sourceEnvelopeBytes }) {
  if (!Buffer.isBuffer(sourceEnvelopeBytes) || sourceEnvelopeBytes.length === 0) {
    fail("source-envelope bytes must be a nonempty buffer");
  }
  const normalized = validateConvexWasmSourceEnvelope(sourceEnvelope);
  if (sourceEnvelopeBytes.toString("utf8") !== `${canonicalJson(normalized)}\n`) {
    fail("source-envelope bytes are not canonical");
  }
  return { sha256: sha256(sourceEnvelopeBytes), size: sourceEnvelopeBytes.length };
}

function frozenStartPushIdentity(startPushBytes) {
  if (!Buffer.isBuffer(startPushBytes) || startPushBytes.length === 0) {
    fail("frozen start-push bytes must be a nonempty buffer");
  }
  return { sha256: sha256(startPushBytes), size: startPushBytes.length };
}

export function createIsolatedRuntimeAuthorityCacheIdentity({
  analysisEnvironment,
  backendImageId,
  dependencyEgressUsed,
  sourceEnvelope,
  sourceEnvelopeBytes,
  startPushBytes,
}) {
  if (dependencyEgressUsed !== true && dependencyEgressUsed !== false) {
    fail("dependency-egress use must be boolean");
  }
  const payload = {
    backendImageId: requireBackendImageId(backendImageId),
    dependencyEgressUsed,
    kind: CACHE_IDENTITY_KIND,
    sourceEnvelope: sourceEnvelopeIdentity({ sourceEnvelope, sourceEnvelopeBytes }),
    startPush: frozenStartPushIdentity(startPushBytes),
    ...(analysisEnvironment === undefined
      ? { analysisEnvironment: null }
      : { analysisEnvironment: requireFileIdentity(analysisEnvironment, "analysis environment") }),
  };
  return { ...payload, cacheKey: fingerprintJson(payload) };
}

export function createRuntimeContentProducerCacheIdentity({
  backendImageId,
  dependencies,
  helper,
  runtimeContentAlgorithm,
}) {
  const payload = {
    backendImageId: requireBackendImageId(backendImageId),
    dependencies: requireDependencyIdentities(
      dependencies,
      "runtime-content producer dependencies"
    ),
    helper: requireFileIdentity(helper, "runtime-content producer helper"),
    kind: PRODUCER_IDENTITY_KIND,
    runtimeContentAlgorithm: requireString(
      runtimeContentAlgorithm,
      "runtime-content producer algorithm"
    ),
  };
  return { ...payload, cacheKey: fingerprintJson(payload) };
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a nonempty string`);
  }
  return value;
}

function validateProducerIdentity(value) {
  const identity = requireExactKeys(
    value,
    ["backendImageId", "cacheKey", "dependencies", "helper", "kind", "runtimeContentAlgorithm"],
    "runtime-content producer identity"
  );
  const { cacheKey, ...payload } = identity;
  if (
    identity.kind !== PRODUCER_IDENTITY_KIND ||
    requireSha256(cacheKey, "runtime-content producer cache key") !== fingerprintJson(payload)
  ) {
    fail("runtime-content producer identity is invalid");
  }
  return {
    ...payload,
    backendImageId: requireBackendImageId(identity.backendImageId),
    cacheKey,
    dependencies: requireDependencyIdentities(
      identity.dependencies,
      "runtime-content producer dependencies"
    ),
    helper: requireFileIdentity(identity.helper, "runtime-content producer helper"),
    runtimeContentAlgorithm: requireString(
      identity.runtimeContentAlgorithm,
      "runtime-content producer algorithm"
    ),
  };
}

function validateCacheIdentity(value) {
  const identity = requireExactKeys(
    value,
    [
      "analysisEnvironment",
      "backendImageId",
      "cacheKey",
      "dependencyEgressUsed",
      "kind",
      "sourceEnvelope",
      "startPush",
    ],
    "runtime-authority cache identity"
  );
  const { cacheKey, ...payload } = identity;
  if (
    identity.kind !== CACHE_IDENTITY_KIND ||
    requireSha256(cacheKey, "runtime-authority cache key") !== fingerprintJson(payload)
  ) {
    fail("runtime-authority cache identity is invalid");
  }
  if (identity.dependencyEgressUsed !== true && identity.dependencyEgressUsed !== false) {
    fail("runtime-authority cache dependency-egress use is invalid");
  }
  return {
    ...payload,
    analysisEnvironment:
      identity.analysisEnvironment === null
        ? null
        : requireFileIdentity(
            identity.analysisEnvironment,
            "runtime-authority cache analysis environment"
          ),
    backendImageId: requireBackendImageId(identity.backendImageId),
    cacheKey,
    sourceEnvelope: requireFileIdentity(
      identity.sourceEnvelope,
      "runtime-authority cache source envelope"
    ),
    startPush: requireFileIdentity(identity.startPush, "runtime-authority cache start-push"),
  };
}

function validateEntry(value, expectedIdentity) {
  const entry = requireExactKeys(
    value,
    ["authority", "cacheKey", "identity", "kind", "sourcePackage"],
    "runtime-authority cache entry"
  );
  if (entry.kind !== CACHE_ENTRY_KIND) {
    fail("runtime-authority cache entry kind is invalid");
  }
  const identity = validateCacheIdentity(entry.identity);
  if (
    entry.cacheKey !== expectedIdentity.cacheKey ||
    canonicalJson(identity) !== canonicalJson(expectedIdentity)
  ) {
    fail("runtime-authority cache entry identity differs from the current authority inputs");
  }
  return {
    authority: requireFileIdentity(entry.authority, "runtime-authority cache authority"),
    cacheKey: requireSha256(entry.cacheKey, "runtime-authority cache entry key"),
    identity,
    kind: CACHE_ENTRY_KIND,
    sourcePackage: requireFileIdentity(
      entry.sourcePackage,
      "runtime-authority cache source package"
    ),
  };
}

function entryPath(cacheRoot, cacheKey) {
  return join(cacheIdentityPath(cacheRoot), cacheKey);
}

async function ensureCacheRoot(cacheRoot) {
  const root = cacheIdentityPath(cacheRoot);
  await fs.mkdir(root, { mode: 0o700, recursive: true });
  await fs.chmod(root, 0o700);
  await requirePrivateCacheDirectory(cacheRoot, root);
  return root;
}

async function syncFile(path) {
  const handle = await fs.open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(path) {
  const handle = await fs.open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readOutputFile(path, maximumBytes, description) {
  const status = await fs.lstat(path);
  if (
    status.isSymbolicLink() ||
    !status.isFile() ||
    (status.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && status.uid !== process.getuid())
  ) {
    fail(`${description} must be an owner-only regular file`);
  }
  return await readAndHashPrivateRegularFile(path, maximumBytes, description);
}

// Output paths can be removed as soon as a caller observes failure. Drain sibling reads and writes
// before returning that failure so candidate cleanup cannot race cache publication/materialization.
async function settleOutputOperations(operations) {
  const results = await Promise.allSettled(operations);
  const failure = results.find((result) => result.status === "rejected");
  if (failure !== undefined) throw failure.reason;
  return results.map((result) => result.value);
}

function validateAuthorityContents({
  authorityBytes,
  expectedIdentity,
  sourceEnvelope,
  sourceEnvelopeBytes,
  sourcePackage,
  startPushBytes,
}) {
  const authority = parseCanonicalJson(authorityBytes, "runtime-authority cache authority");
  const normalizedAuthority = normalizeDeployedRuntimeAuthority(authority);
  const binding = verifyFrozenGraphBindingSourceEnvelope({
    normalizedAuthority,
    sourceEnvelope,
    sourceEnvelopeFileSha256: expectedIdentity.sourceEnvelope.sha256,
    sourceEnvelopeFileSize: expectedIdentity.sourceEnvelope.size,
  });
  if (binding === null) {
    fail("runtime-authority cache authority has no frozen-graph binding");
  }
  if (
    sourceEnvelopeBytes.length !== expectedIdentity.sourceEnvelope.size ||
    sha256(sourceEnvelopeBytes) !== expectedIdentity.sourceEnvelope.sha256 ||
    startPushBytes.length !== expectedIdentity.startPush.size ||
    sha256(startPushBytes) !== expectedIdentity.startPush.sha256 ||
    binding.inputAuthority.request.requestSize !== expectedIdentity.startPush.size ||
    binding.inputAuthority.request.requestSha256 !== expectedIdentity.startPush.sha256 ||
    binding.sourcePackage.sha256 !== sourcePackage.sha256 ||
    binding.sourcePackage.size !== sourcePackage.size
  ) {
    fail("runtime-authority cache authority does not bind the current frozen inputs");
  }
  const runtimeContentIdentities = new Set();
  for (const runtimeModulePath of binding.runtimeModulePaths) {
    const module = normalizedAuthority.modulesByPath.get(runtimeModulePath);
    if (
      module === undefined ||
      module.sourcePackageSha256 !== sourcePackage.sha256 ||
      module.sourcePackageRuntimeContentSha256 === undefined
    ) {
      fail(
        `runtime-authority cache module ${runtimeModulePath} lacks exact source-package authority`
      );
    }
    runtimeContentIdentities.add(module.sourcePackageRuntimeContentSha256);
  }
  if (runtimeContentIdentities.size !== 1) {
    fail("runtime-authority cache selected modules disagree on runtime-content identity");
  }
  return {
    authority,
    authoritySha256: normalizedAuthority.sha256,
    sourcePackageRuntimeContentSha256: [...runtimeContentIdentities][0],
  };
}

async function readEntry({
  cacheRoot,
  expectedIdentity,
  sourceEnvelope,
  sourceEnvelopeBytes,
  startPushBytes,
}) {
  const path = entryPath(cacheRoot, expectedIdentity.cacheKey);
  const authenticatedFiles = await requirePrivateCacheDirectoryFileIdentities(cacheRoot, path);
  if (authenticatedFiles === undefined) return undefined;
  const names = authenticatedFiles.names;
  const expectedNames = ["COMPLETE", "authority.json", "entry.json", "source-package.zip"];
  if (canonicalJson(names) !== canonicalJson(expectedNames)) {
    fail(`runtime-authority cache entry has unexpected contents: ${path}`);
  }
  const [completeBytes, entryBytes, authority, sourcePackage] = await Promise.all([
    readPrivateRegularFile(
      join(path, "COMPLETE"),
      COMPLETE_MAX_BYTES,
      "runtime-authority cache completion marker",
      authenticatedFiles.fileIdentities.get("COMPLETE")
    ),
    readPrivateRegularFile(
      join(path, "entry.json"),
      AUTHORITY_MAX_BYTES,
      "runtime-authority cache entry",
      authenticatedFiles.fileIdentities.get("entry.json")
    ),
    readAndHashPrivateRegularFile(
      join(path, "authority.json"),
      AUTHORITY_MAX_BYTES,
      "runtime-authority cache authority",
      authenticatedFiles.fileIdentities.get("authority.json")
    ),
    readAndHashPrivateRegularFile(
      join(path, "source-package.zip"),
      SOURCE_PACKAGE_MAX_BYTES,
      "runtime-authority cache source package",
      authenticatedFiles.fileIdentities.get("source-package.zip")
    ),
  ]);
  if (
    decodeUtf8(completeBytes, "runtime-authority cache completion marker") !==
    `${expectedIdentity.cacheKey}\n`
  ) {
    fail(`runtime-authority cache completion marker is invalid: ${path}`);
  }
  const entry = validateEntry(
    parseCanonicalJson(entryBytes, "runtime-authority cache entry"),
    expectedIdentity
  );
  if (
    canonicalJson(entry.authority) !==
      canonicalJson({ sha256: authority.sha256, size: authority.size }) ||
    canonicalJson(entry.sourcePackage) !==
      canonicalJson({ sha256: sourcePackage.sha256, size: sourcePackage.size })
  ) {
    fail(`runtime-authority cache entry payload digests differ: ${path}`);
  }
  const validatedAuthority = validateAuthorityContents({
    authorityBytes: authority.contents,
    expectedIdentity,
    sourceEnvelope,
    sourceEnvelopeBytes,
    sourcePackage,
    startPushBytes,
  });
  await authenticatedFiles.verify();
  return {
    authority: authority.contents,
    authoritySha256: validatedAuthority.authoritySha256,
    cacheKey: expectedIdentity.cacheKey,
    sourcePackage: sourcePackage.contents,
    sourcePackageRuntimeContentSha256: validatedAuthority.sourcePackageRuntimeContentSha256,
  };
}

async function materialize(path, contents, description) {
  await fs.writeFile(path, contents, { flag: "wx", mode: 0o600 });
  await fs.chmod(path, 0o600);
  await syncFile(path);
  await syncDirectory(dirname(path));
  const verified = await readOutputFile(path, contents.length, description);
  if (verified.size !== contents.length || verified.sha256 !== sha256(contents)) {
    fail(`${description} changed while materializing a runtime-authority cache entry`);
  }
}

async function publishEntry({
  authorityPath,
  cacheRoot,
  expectedIdentity,
  sourceEnvelope,
  sourceEnvelopeBytes,
  sourcePackagePath,
  startPushBytes,
}) {
  const [authority, sourcePackage] = await settleOutputOperations([
    readOutputFile(authorityPath, AUTHORITY_MAX_BYTES, "fresh runtime authority"),
    readOutputFile(sourcePackagePath, SOURCE_PACKAGE_MAX_BYTES, "fresh source package"),
  ]);
  const validatedAuthority = validateAuthorityContents({
    authorityBytes: authority.contents,
    expectedIdentity,
    sourceEnvelope,
    sourceEnvelopeBytes,
    sourcePackage,
    startPushBytes,
  });
  const root = await ensureCacheRoot(cacheRoot);
  const finalPath = entryPath(cacheRoot, expectedIdentity.cacheKey);
  const temporaryPath = join(
    root,
    `.publish-${expectedIdentity.cacheKey}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  await fs.mkdir(temporaryPath, { mode: 0o700 });
  try {
    const entry = {
      authority: { sha256: authority.sha256, size: authority.size },
      cacheKey: expectedIdentity.cacheKey,
      identity: expectedIdentity,
      kind: CACHE_ENTRY_KIND,
      sourcePackage: { sha256: sourcePackage.sha256, size: sourcePackage.size },
    };
    const files = [
      ["authority.json", authority.contents],
      ["source-package.zip", sourcePackage.contents],
      ["entry.json", Buffer.from(`${canonicalJson(entry)}\n`)],
      ["COMPLETE", Buffer.from(`${expectedIdentity.cacheKey}\n`)],
    ];
    for (const [name, contents] of files) {
      const path = join(temporaryPath, name);
      await fs.writeFile(path, contents, { flag: "wx", mode: 0o600 });
      await fs.chmod(path, 0o600);
      await syncFile(path);
    }
    await syncDirectory(temporaryPath);
    try {
      await fs.rename(temporaryPath, finalPath);
      await syncDirectory(root);
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY")
        )
      ) {
        throw error;
      }
    }
  } finally {
    await fs.rm(temporaryPath, { force: true, recursive: true });
  }
  return {
    authoritySha256: validatedAuthority.authoritySha256,
    sourcePackageRuntimeContentSha256: validatedAuthority.sourcePackageRuntimeContentSha256,
  };
}

export async function materializeCachedIsolatedRuntimeAuthority({
  authorityOutputPath,
  cacheRoot,
  expectedIdentity,
  sourceEnvelope,
  sourceEnvelopeBytes,
  sourcePackageOutputPath,
  startPushBytes,
}) {
  const cached = await readEntry({
    cacheRoot,
    expectedIdentity: validateCacheIdentity(expectedIdentity),
    sourceEnvelope,
    sourceEnvelopeBytes,
    startPushBytes,
  });
  if (cached === undefined) return undefined;
  await settleOutputOperations([
    materialize(authorityOutputPath, cached.authority, "cached runtime authority output"),
    materialize(sourcePackageOutputPath, cached.sourcePackage, "cached source-package output"),
  ]);
  return { ...cached, cache: "hit" };
}

export async function publishIsolatedRuntimeAuthorityCacheEntry({
  authorityPath,
  cacheRoot,
  expectedIdentity,
  sourceEnvelope,
  sourceEnvelopeBytes,
  sourcePackagePath,
  startPushBytes,
}) {
  const identity = validateCacheIdentity(expectedIdentity);
  const published = await publishEntry({
    authorityPath,
    cacheRoot,
    expectedIdentity: identity,
    sourceEnvelope,
    sourceEnvelopeBytes,
    sourcePackagePath,
    startPushBytes,
  });
  return { ...published, cache: "miss", cacheKey: identity.cacheKey };
}

export function validateProducerCertificate(value, expectedIdentity, externalDepsPackage) {
  const certificate = requireExactKeys(
    value,
    [
      "backendAuthoritySha256",
      "certificateSha256",
      "externalDepsPackage",
      "identity",
      "kind",
      "request",
      "runtimeContentSha256",
      "sourcePackage",
    ],
    "runtime-content producer certificate"
  );
  const identity = validateProducerIdentity(certificate.identity);
  if (
    certificate.kind !== PRODUCER_CERTIFICATE_KIND ||
    identity.cacheKey !== expectedIdentity.cacheKey ||
    canonicalJson(identity) !== canonicalJson(expectedIdentity)
  ) {
    fail("runtime-content producer certificate identity differs from the current producer");
  }
  const normalizedExternalDepsPackage =
    certificate.externalDepsPackage === null
      ? null
      : (() => {
          const externalPackage = requireExactKeys(
            certificate.externalDepsPackage,
            ["sha256", "size", "storageKey"],
            "runtime-content producer external dependency package"
          );
          return {
            sha256: requireSha256(
              externalPackage.sha256,
              "runtime-content producer external dependency package SHA-256"
            ),
            size: requirePositiveInteger(
              externalPackage.size,
              "runtime-content producer external dependency package size"
            ),
            storageKey: requireString(
              externalPackage.storageKey,
              "runtime-content producer external dependency storage key"
            ),
          };
        })();
  if (
    (normalizedExternalDepsPackage === null) !== (externalDepsPackage === null) ||
    (normalizedExternalDepsPackage !== null &&
      (normalizedExternalDepsPackage.sha256 !== externalDepsPackage.sha256 ||
        normalizedExternalDepsPackage.size !== externalDepsPackage.size))
  ) {
    fail("runtime-content producer certificate dependency archive differs from its payload");
  }
  const { certificateSha256, ...payload } = certificate;
  if (
    requireSha256(certificateSha256, "runtime-content producer certificate SHA-256") !==
    fingerprintJson(payload)
  ) {
    fail("runtime-content producer certificate digest is invalid");
  }
  if (
    normalizedExternalDepsPackage !== null &&
    !/^[A-Za-z0-9-]+$/u.test(normalizedExternalDepsPackage.storageKey)
  ) {
    fail("runtime-content producer external dependency storage key is invalid");
  }
  return {
    backendAuthoritySha256: requireSha256(
      certificate.backendAuthoritySha256,
      "runtime-content producer backend authority SHA-256"
    ),
    certificateSha256,
    externalDepsPackage: normalizedExternalDepsPackage,
    identity,
    kind: PRODUCER_CERTIFICATE_KIND,
    request: requireFileIdentity(certificate.request, "runtime-content producer request"),
    runtimeContentSha256: requireSha256(
      certificate.runtimeContentSha256,
      "runtime-content producer runtime-content SHA-256"
    ),
    sourcePackage: requireFileIdentity(
      certificate.sourcePackage,
      "runtime-content producer source package"
    ),
  };
}

function producerEntryPath(cacheRoot, cacheKey) {
  return join(producerIdentityPath(cacheRoot), cacheKey);
}

async function ensureProducerCacheRoot(cacheRoot) {
  const root = producerIdentityPath(cacheRoot);
  await fs.mkdir(root, { mode: 0o700, recursive: true });
  await fs.chmod(root, 0o700);
  await requirePrivateCacheDirectory(cacheRoot, root);
  return root;
}

export async function materializeRuntimeContentProducerCertificate({
  cacheRoot,
  expectedIdentity,
  externalDepsPackageOutputPath,
}) {
  const identity = validateProducerIdentity(expectedIdentity);
  const path = producerEntryPath(cacheRoot, identity.cacheKey);
  const authenticatedFiles = await requirePrivateCacheDirectoryFileIdentities(cacheRoot, path);
  if (authenticatedFiles === undefined) return undefined;
  const expectsExternalDepsPackage = identity.dependencies.length > 0;
  const expectedNames = expectsExternalDepsPackage
    ? ["COMPLETE", "certificate.json", "external-deps-package.zip"]
    : ["COMPLETE", "certificate.json"];
  if (canonicalJson(authenticatedFiles.names) !== canonicalJson(expectedNames)) {
    fail(`runtime-content producer cache entry has unexpected contents: ${path}`);
  }
  // Target-bound consumers need conformance evidence, not a copy of the isolated archive.
  // Isolated-only consumers still request materialization explicitly.
  if (!expectsExternalDepsPackage && externalDepsPackageOutputPath !== undefined) {
    fail("runtime-content producer dependency output does not match the certified dependency set");
  }
  const [completeBytes, certificateBytes, externalDepsPackage] = await Promise.all([
    readPrivateRegularFile(
      join(path, "COMPLETE"),
      COMPLETE_MAX_BYTES,
      "runtime-content producer completion marker",
      authenticatedFiles.fileIdentities.get("COMPLETE")
    ),
    readPrivateRegularFile(
      join(path, "certificate.json"),
      AUTHORITY_MAX_BYTES,
      "runtime-content producer certificate",
      authenticatedFiles.fileIdentities.get("certificate.json")
    ),
    expectsExternalDepsPackage
      ? readAndHashPrivateRegularFile(
          join(path, "external-deps-package.zip"),
          SOURCE_PACKAGE_MAX_BYTES,
          "runtime-content producer external dependency package",
          authenticatedFiles.fileIdentities.get("external-deps-package.zip")
        )
      : null,
  ]);
  if (
    decodeUtf8(completeBytes, "runtime-content producer completion marker") !==
    `${identity.cacheKey}\n`
  ) {
    fail(`runtime-content producer completion marker is invalid: ${path}`);
  }
  const certificate = validateProducerCertificate(
    parseCanonicalJson(certificateBytes, "runtime-content producer certificate"),
    identity,
    externalDepsPackage
  );
  if (externalDepsPackage !== null && externalDepsPackageOutputPath !== undefined) {
    await materialize(
      externalDepsPackageOutputPath,
      externalDepsPackage.contents,
      "certified external dependency package output"
    );
  }
  await authenticatedFiles.verify();
  return { ...certificate, cache: "hit", cacheKey: identity.cacheKey };
}

export async function publishRuntimeContentProducerCertificate({
  backendAuthoritySha256,
  cacheRoot,
  expectedIdentity,
  externalDepsPackagePath,
  externalDepsStorageKey,
  request,
  runtimeContentSha256,
  sourcePackage,
}) {
  const identity = validateProducerIdentity(expectedIdentity);
  const expectsExternalDepsPackage = identity.dependencies.length > 0;
  if (expectsExternalDepsPackage !== (externalDepsPackagePath !== undefined)) {
    fail("runtime-content producer dependency archive does not match its dependency set");
  }
  if (!expectsExternalDepsPackage && externalDepsStorageKey !== undefined) {
    fail("runtime-content producer storage key is invalid without a dependency archive");
  }
  const externalDepsPackage = expectsExternalDepsPackage
    ? await readOutputFile(
        externalDepsPackagePath,
        SOURCE_PACKAGE_MAX_BYTES,
        "fresh external dependency package"
      )
    : null;
  const externalDepsDescriptor =
    externalDepsPackage === null
      ? null
      : {
          sha256: externalDepsPackage.sha256,
          size: externalDepsPackage.size,
          storageKey: requireString(
            externalDepsStorageKey,
            "runtime-content producer external dependency storage key"
          ),
        };
  if (
    externalDepsDescriptor !== null &&
    !/^[A-Za-z0-9-]+$/u.test(externalDepsDescriptor.storageKey)
  ) {
    fail("runtime-content producer external dependency storage key is invalid");
  }
  const payload = {
    backendAuthoritySha256: requireSha256(
      backendAuthoritySha256,
      "runtime-content producer backend authority SHA-256"
    ),
    externalDepsPackage: externalDepsDescriptor,
    identity,
    kind: PRODUCER_CERTIFICATE_KIND,
    request: requireFileIdentity(request, "runtime-content producer request"),
    runtimeContentSha256: requireSha256(
      runtimeContentSha256,
      "runtime-content producer runtime-content SHA-256"
    ),
    sourcePackage: requireFileIdentity(sourcePackage, "runtime-content producer source package"),
  };
  const certificate = { ...payload, certificateSha256: fingerprintJson(payload) };
  const root = await ensureProducerCacheRoot(cacheRoot);
  const finalPath = producerEntryPath(cacheRoot, identity.cacheKey);
  const temporaryPath = join(
    root,
    `.publish-${identity.cacheKey}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  let existingEntry = false;
  await fs.mkdir(temporaryPath, { mode: 0o700 });
  try {
    const files = [
      ["certificate.json", Buffer.from(`${canonicalJson(certificate)}\n`)],
      ["COMPLETE", Buffer.from(`${identity.cacheKey}\n`)],
      ...(externalDepsPackage === null
        ? []
        : [["external-deps-package.zip", externalDepsPackage.contents]]),
    ];
    for (const [name, contents] of files) {
      const filePath = join(temporaryPath, name);
      await fs.writeFile(filePath, contents, { flag: "wx", mode: 0o600 });
      await fs.chmod(filePath, 0o600);
      await syncFile(filePath);
    }
    await syncDirectory(temporaryPath);
    try {
      await fs.rename(temporaryPath, finalPath);
      await syncDirectory(root);
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY")
        )
      ) {
        throw error;
      }
      existingEntry = true;
    }
  } finally {
    await fs.rm(temporaryPath, { force: true, recursive: true });
  }
  if (existingEntry) {
    // One producer identity can certify later source requests, but a fresh backend can assign a
    // different storage key or archive bytes to the same dependency set. Keep its new certificate
    // for the caller without replacing the retained cache entry under this producer key.
    const retained = await materializeRuntimeContentProducerCertificate({
      cacheRoot,
      expectedIdentity: identity,
    });
    if (retained === undefined) {
      fail("runtime-content producer certificate disappeared after publication collision");
    }
    return canonicalJson(retained.externalDepsPackage) === canonicalJson(externalDepsDescriptor)
      ? retained
      : { ...certificate, cache: "uncached", cacheKey: identity.cacheKey };
  }
  return { ...certificate, cache: "miss", cacheKey: identity.cacheKey };
}
