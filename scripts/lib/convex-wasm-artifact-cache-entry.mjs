import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import {
  assertExactKeys,
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  normalizeJson,
  requirePositiveInteger,
} from "./convex-wasm-artifact-contract.mjs";
import {
  ConvexWasmArtifactByteLimitError,
  decodeUtf8,
  hashPrivateRegularFile,
  readAndHashPrivateRegularFile,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheDirectoryFileIdentities,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";

const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const CACHE_ENTRY_KIND = "convex-wasm-artifact-cache-entry-v5";
const MAX_CACHE_ENTRY_METADATA_BYTES = 16 * 1024 * 1024;
const MAX_COMPLETION_MARKER_BYTES = 65;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const immutableArtifactCacheValidationFlights = new Map();
const artifactCacheEntryPhysicalStateFlightsByValidationMemo = new WeakMap();
const authenticatedArtifactCacheEntryPhysicalStatesByValidationMemo = new WeakMap();
const authenticatedArtifactCacheEntryJson = new WeakMap();
const artifactCachePayloadPhysicalStateChanged = Object.freeze({
  kind: "artifact-cache-payload-physical-state-changed",
});

export async function admitArtifactCacheEntryPublication({
  artifactPath,
  artifactFile,
  identity,
  key,
  maxArtifactBytes,
  metadata,
  readContents,
  stage,
}) {
  // Hash the owned completed payload, not its source followed by another post-rename hash.
  const before = artifactCacheEntryPhysicalStatus(await fs.lstat(artifactPath, { bigint: true }));
  const digest = await (readContents ? readAndHashPrivateRegularFile : hashPrivateRegularFile)(
    artifactPath,
    maxArtifactBytes,
    `${stage} produced artifact`
  );
  const after = artifactCacheEntryPhysicalStatus(await fs.lstat(artifactPath, { bigint: true }));
  // A collision loser can add and remove its link during this fresh hash, leaving only ctime
  // changed. Unlike retained-digest reuse, admission just authenticated the bytes itself.
  if (!sameArtifactCachePayloadStableStatus(before, after)) {
    fail(`${stage} produced artifact changed during admission`);
  }
  if (digest.size === 0) fail(`${stage} produced an empty artifact`);
  if (fingerprintJson({ kind: PIPELINE_KIND, stage, identity }) !== key) {
    fail(`${stage} publication identity does not match its key`);
  }
  const entry = {
    artifactFile,
    artifactSha256: digest.sha256,
    artifactSize: digest.size,
    identity: normalizeJson(identity, `${stage} publication identity`),
    key,
    kind: CACHE_ENTRY_KIND,
    metadata: normalizeJson(metadata, `${stage} publication metadata`),
    stage,
  };
  entry.admission = { entrySha256: fingerprintJson(entry), payload: after };
  const entrySource = `${canonicalJson(entry)}\n`;
  const metadataBytes = Buffer.byteLength(entrySource);
  if (metadataBytes > MAX_CACHE_ENTRY_METADATA_BYTES) {
    throw new ConvexWasmArtifactByteLimitError(
      "artifact cache metadata has",
      metadataBytes,
      MAX_CACHE_ENTRY_METADATA_BYTES
    );
  }
  return {
    entrySource,
    entry: retainAuthenticatedArtifactCacheEntryJson({
      ...entry,
      artifactPath,
      ...(readContents ? { artifactContents: digest.contents } : {}),
    }),
  };
}

export async function publishArtifactCacheEntry({
  artifactPath,
  cacheLayout,
  cacheRoot,
  extension,
  identity,
  immutableCacheValidationMemo,
  key,
  maxArtifactBytes,
  metadata,
  readPublishedArtifactContents = false,
  stage,
}) {
  const layout = normalizeConvexWasmCacheLayout(cacheLayout);
  if (layout.cacheRoot !== resolve(cacheRoot)) {
    fail("artifact publication cache root does not match its layout");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(stage)) {
    fail("artifact publication stage must be a path component");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(extension)) {
    fail("artifact publication extension must be a path component");
  }
  if (!SHA256_PATTERN.test(key)) fail("artifact publication key must be a SHA-256 digest");
  requirePositiveInteger(maxArtifactBytes, "artifact publication byte limit");
  const sourceSize = (await fs.stat(artifactPath)).size;
  if (sourceSize === 0) fail(`${stage} produced an empty artifact`);
  if (sourceSize > maxArtifactBytes) {
    throw new ConvexWasmArtifactByteLimitError(`${stage} produced`, sourceSize, maxArtifactBytes);
  }
  const stageRoot = dirname(cacheStagePath(layout, stage, key));
  await fs.mkdir(stageRoot, { recursive: true, mode: 0o700 });
  for (const directory of [layout.immutable.root, layout.immutable.artifacts, stageRoot]) {
    await requirePrivateCacheDirectory(cacheRoot, directory);
  }
  const publicationPath = join(
    stageRoot,
    `.publish-${key}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  await fs.mkdir(publicationPath, { mode: 0o700 });
  const artifactFile = `artifact.${extension}`;
  try {
    // Admission owns the exact copy that successful rename moves to the final immutable path.
    const publishedArtifactPath = join(publicationPath, artifactFile);
    await fs.copyFile(artifactPath, publishedArtifactPath);
    await fs.chmod(publishedArtifactPath, 0o600);
    const { entry, entrySource } = await admitArtifactCacheEntryPublication({
      artifactPath: publishedArtifactPath,
      artifactFile,
      identity,
      key,
      maxArtifactBytes,
      metadata,
      readContents: readPublishedArtifactContents,
      stage,
    });
    const writes = await Promise.allSettled([
      fs.writeFile(join(publicationPath, "entry.json"), entrySource, { flag: "wx", mode: 0o600 }),
      fs.writeFile(join(publicationPath, "COMPLETE"), `${key}\n`, { flag: "wx", mode: 0o600 }),
    ]);
    const failedWrite = writes.find(({ status }) => status === "rejected");
    if (failedWrite !== undefined) throw failedWrite.reason;
    await requirePrivateCacheDirectory(cacheRoot, publicationPath);
    const verifiedFiles = await Promise.allSettled(
      [artifactFile, "entry.json", "COMPLETE"].map((name) =>
        requirePrivateCacheFile(cacheRoot, join(publicationPath, name))
      )
    );
    const failedFile = verifiedFiles.find(({ status }) => status === "rejected");
    if (failedFile !== undefined) throw failedFile.reason;
    const finalPath = cacheStagePath(layout, stage, key);
    try {
      await fs.rename(publicationPath, finalPath);
    } catch (error) {
      if (
        !(error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY"))
      ) {
        throw error;
      }
      // The initial miss may still be memoized. Authenticate the winner through a fresh read.
      const concurrentEntry = await (readPublishedArtifactContents
        ? readAndValidateArtifactCacheEntryFresh(
            cacheRoot, layout, stage, key, extension, maxArtifactBytes
          )
        : immutableCacheValidationMemo === undefined
          ? validateArtifactCacheEntryFresh(
              cacheRoot, layout, stage, key, extension, maxArtifactBytes
            )
          : validateArtifactCacheEntryInValidationScope(
              immutableCacheValidationMemo,
              cacheRoot,
              layout,
              stage,
              key,
              extension,
              maxArtifactBytes
            ));
      if (concurrentEntry === undefined) fail(`concurrent cache publication disappeared: ${finalPath}`);
      if (
        concurrentEntry.artifactSha256 !== entry.artifactSha256 ||
        concurrentEntry.artifactSize !== entry.artifactSize ||
        canonicalJson(concurrentEntry.metadata) !== canonicalJson(metadata)
      ) {
        fail(`${stage} produced different bytes for the same cache identity`);
      }
      return concurrentEntry;
    }
    entry.artifactPath = join(finalPath, artifactFile);
    return entry;
  } finally {
    await fs.rm(publicationPath, { recursive: true, force: true });
  }
}

// A control entry gives authenticated material a different identity while retaining its bytes.
// Resolve the source through cache validation so a caller cannot grant authority to an arbitrary
// path, then admit the hard-linked payload under the control key before making it visible.
export async function publishArtifactCacheEntryFromMaterial({
  cacheLayout,
  cacheRoot,
  extension,
  identity,
  immutableCacheValidationMemo,
  key,
  maxArtifactBytes,
  sourceEntry,
  stage,
}) {
  const layout = normalizeConvexWasmCacheLayout(cacheLayout);
  if (layout.cacheRoot !== resolve(cacheRoot)) {
    fail("artifact publication cache root does not match its layout");
  }
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(stage) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(sourceEntry.stage) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(extension) ||
    !SHA256_PATTERN.test(key) ||
    !SHA256_PATTERN.test(sourceEntry.key) ||
    sourceEntry.artifactFile !== `artifact.${extension}`
  ) {
    fail("material-to-control publication has an invalid stage, key, or extension");
  }
  if (fingerprintJson({ kind: PIPELINE_KIND, stage, identity }) !== key) {
    fail("material-to-control publication identity does not match its key");
  }
  requirePositiveInteger(maxArtifactBytes, "material-to-control publication byte limit");
  const validate = async (entryStage, entryKey, fresh = false) =>
    immutableCacheValidationMemo === undefined
      ? await (fresh ? validateArtifactCacheEntryFresh : validateArtifactCacheEntry)(
          cacheRoot, layout, entryStage, entryKey, extension, maxArtifactBytes
        )
      : await validateArtifactCacheEntryInValidationScope(
          immutableCacheValidationMemo,
          cacheRoot,
          layout,
          entryStage,
          entryKey,
          extension,
          maxArtifactBytes
        );
  const material = await validate(sourceEntry.stage, sourceEntry.key, true);
  if (
    material === undefined ||
    material.artifactSha256 !== sourceEntry.artifactSha256 ||
    material.artifactSize !== sourceEntry.artifactSize ||
    canonicalJson(material.metadata) !== canonicalJson(sourceEntry.metadata)
  ) {
    fail(`${stage} material cache entry changed before control publication`);
  }
  const matchesMaterial = (entry) =>
    entry.artifactSha256 === material.artifactSha256 &&
    entry.artifactSize === material.artifactSize &&
    canonicalJson(entry.metadata) === canonicalJson(material.metadata);
  const existing = await validate(stage, key);
  if (existing !== undefined) {
    if (!matchesMaterial(existing)) fail(`${stage} control entry conflicts with its material`);
    return { entry: existing, publication: "existing" };
  }

  const stageRoot = dirname(cacheStagePath(layout, stage, key));
  await fs.mkdir(stageRoot, { recursive: true, mode: 0o700 });
  for (const directory of [layout.immutable.root, layout.immutable.artifacts, stageRoot]) {
    await requirePrivateCacheDirectory(cacheRoot, directory);
  }
  const publicationPath = join(
    stageRoot,
    `.publish-${key}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  await fs.mkdir(publicationPath, { mode: 0o700 });
  try {
    const linkedPath = join(publicationPath, material.artifactFile);
    await fs.link(material.artifactPath, linkedPath);
    const { entry, entrySource } = await admitArtifactCacheEntryPublication({
      artifactPath: linkedPath,
      artifactFile: material.artifactFile,
      identity,
      key,
      maxArtifactBytes,
      metadata: material.metadata,
      readContents: false,
      stage,
    });
    if (!matchesMaterial(entry)) {
      fail(`${stage} linked material changed during control admission`);
    }
    const writes = await Promise.allSettled([
      fs.writeFile(join(publicationPath, "entry.json"), entrySource, { flag: "wx", mode: 0o600 }),
      fs.writeFile(join(publicationPath, "COMPLETE"), `${key}\n`, { flag: "wx", mode: 0o600 }),
    ]);
    const failedWrite = writes.find(({ status }) => status === "rejected");
    if (failedWrite !== undefined) throw failedWrite.reason;
    await requirePrivateCacheDirectory(cacheRoot, publicationPath);
    const verifiedFiles = await Promise.allSettled(
      [material.artifactFile, "entry.json", "COMPLETE"].map((name) =>
        requirePrivateCacheFile(cacheRoot, join(publicationPath, name))
      )
    );
    const failedFile = verifiedFiles.find(({ status }) => status === "rejected");
    if (failedFile !== undefined) throw failedFile.reason;
    const finalPath = cacheStagePath(layout, stage, key);
    try {
      await fs.rename(publicationPath, finalPath);
      entry.artifactPath = join(finalPath, material.artifactFile);
      return { entry, publication: "published" };
    } catch (error) {
      if (
        !(error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY"))
      ) {
        throw error;
      }
      // Remove our temporary link before authenticating the winner's physical state.
      await fs.rm(publicationPath, { recursive: true, force: true });
      const winner = await validate(stage, key, true);
      if (winner === undefined || !matchesMaterial(winner)) {
        fail(`${stage} concurrent control publication differs from its material`);
      }
      return { entry: winner, publication: "existing" };
    }
  } finally {
    await fs.rm(publicationPath, { recursive: true, force: true });
  }
}

function freezeJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeJsonTree(nested);
    Object.freeze(value);
  }
  return value;
}

function retainAuthenticatedArtifactCacheEntryJson(entry) {
  freezeJsonTree(entry.identity);
  freezeJsonTree(entry.metadata);
  authenticatedArtifactCacheEntryJson.set(entry, {
    // Intermediate artifacts need admitted JSON, but not standalone publication digests.
    // Compute those only for a consumer that requests them; copies share this record.
    digests: undefined,
    identity: entry.identity,
    // Both admission producers already verified the identity/stage/key binding. Retain it so
    // package publication can check mutable outer fields without hashing the identity again.
    key: entry.key,
    metadata: entry.metadata,
    stage: entry.stage,
  });
  return entry;
}

function copyAuthenticatedArtifactCacheEntry(entry) {
  const copy = { ...entry };
  const authentication = authenticatedArtifactCacheEntryJson.get(entry);
  if (authentication === undefined) {
    fail("artifact cache entry copy lacks authenticated JSON authority");
  }
  authenticatedArtifactCacheEntryJson.set(copy, authentication);
  return copy;
}

function requireAuthenticatedArtifactCacheEntryJsonDigests(entry) {
  const authentication = authenticatedArtifactCacheEntryJson.get(entry);
  if (
    authentication === undefined ||
    entry.identity !== authentication.identity ||
    entry.metadata !== authentication.metadata ||
    entry.key !== authentication.key ||
    entry.stage !== authentication.stage
  ) {
    fail("artifact cache entry lacks authenticated immutable identity and metadata");
  }
  if (authentication.digests === undefined) {
    authentication.digests = Object.freeze({
      identitySha256: fingerprintJson(authentication.identity),
      metadataSha256: fingerprintJson(authentication.metadata),
    });
  }
  return authentication.digests;
}

function cacheStagePath(cacheLayout, stage, key) {
  return join(cacheLayout.immutable.artifacts, stage, key);
}

function artifactCacheEntryPhysicalStatus(status) {
  return {
    ctimeNs: status.ctimeNs.toString(),
    dev: status.dev.toString(),
    gid: status.gid.toString(),
    ino: status.ino.toString(),
    mode: status.mode.toString(),
    mtimeNs: status.mtimeNs.toString(),
    nlink: status.nlink.toString(),
    size: status.size.toString(),
    uid: status.uid.toString(),
  };
}

function sameArtifactCacheEntryPhysicalStatus(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sameArtifactCachePayloadStableStatus(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.gid === right.gid &&
    left.mode === right.mode &&
    left.mtimeNs === right.mtimeNs &&
    left.size === right.size &&
    left.uid === right.uid
  );
}

function sameArtifactCachePayloadContentStatus(left, right) {
  if (!sameArtifactCachePayloadStableStatus(left, right)) return false;
  // Creating or removing another immutable hard link changes both ctime and nlink without
  // changing this path's bytes. A ctime-only change still requires fresh authentication so an
  // ordinary same-size rewrite with a restored mtime cannot reuse the retained digest.
  return (
    (left.ctimeNs === right.ctimeNs && left.nlink === right.nlink) || left.nlink !== right.nlink
  );
}

export function requireAuthenticatedArtifactCacheEntryPhysicalState({
  validationMemo,
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
}) {
  const authenticatedStateKey = [
    resolve(cacheRoot),
    resolve(cacheStagePath(cacheLayout, stage, key)),
    stage,
    key,
    expectedExtension,
  ].join("\0");
  const retained = authenticatedArtifactCacheEntryPhysicalStatesByValidationMemo
    .get(validationMemo)
    ?.get(authenticatedStateKey);
  if (
    retained === undefined ||
    validationMemo.get(retained.validationKey) !== retained.validation
  ) {
    fail("artifact cache entry lacks authenticated physical state in its validation scope");
  }
  // Return the immutable snapshot admitted by the verifier, not a new observation of the path.
  return retained.state;
}

function artifactCacheEntryPhysicalStateRetainsAuthenticatedBytes(previousState, currentState) {
  if (previousState === currentState) return true;
  if (typeof previousState !== "string" || typeof currentState !== "string") return false;
  const previous = JSON.parse(previousState);
  const current = JSON.parse(currentState);
  if (
    !sameArtifactCacheEntryPhysicalStatus(previous.directory, current.directory) ||
    previous.files.length !== current.files.length
  ) {
    return false;
  }
  return previous.files.every(([previousName, previousStatus], index) => {
    const [currentName, currentStatus] = current.files[index];
    if (previousName !== currentName) return false;
    return previousName.startsWith("artifact.")
      ? sameArtifactCachePayloadContentStatus(previousStatus, currentStatus)
      : sameArtifactCacheEntryPhysicalStatus(previousStatus, currentStatus);
  });
}

function isMissingArtifactCachePhysicalStateError(error) {
  return (
    error instanceof Error &&
    "code" in error &&
    (error.code === "ENOENT" || error.code === "ENOTDIR" || error.code === "ELOOP")
  );
}

async function settleArtifactCachePhysicalStateReads(reads) {
  const settlements = await Promise.allSettled(reads);
  const failures = settlements.filter((settlement) => settlement.status === "rejected");
  // Missing cache material is an ordinary retained-authority miss, but it must not hide a
  // non-missing filesystem failure from a sibling read that started in the same state capture.
  const failure =
    failures.find((settlement) => !isMissingArtifactCachePhysicalStateError(settlement.reason)) ??
    failures[0];
  if (failure !== undefined) throw failure.reason;
  return settlements.map((settlement) => settlement.value);
}

async function artifactCacheEntryPhysicalState(cacheRoot, entryPath) {
  try {
    // A retained state must continue to name an entry through the private no-symlink cache tree.
    // Entry/member metadata alone would remain equal if a stage ancestor became a symlink to the
    // same directory, allowing a completed scoped validation to bypass the full path check.
    await requirePrivateCacheDirectory(cacheRoot, entryPath);
    const beforeDirectory = await fs.lstat(entryPath, { bigint: true });
    if (beforeDirectory.isSymbolicLink() || !beforeDirectory.isDirectory()) return undefined;
    const names = (await fs.readdir(entryPath)).sort(compareStrings);
    const files = await settleArtifactCachePhysicalStateReads(
      names.map(async (name) => {
        const status = await fs.lstat(join(entryPath, name), { bigint: true });
        if (status.isSymbolicLink() || !status.isFile()) return undefined;
        return [name, artifactCacheEntryPhysicalStatus(status)];
      })
    );
    if (files.some((file) => file === undefined)) return undefined;
    const afterDirectory = await fs.lstat(entryPath, { bigint: true });
    if (
      afterDirectory.isSymbolicLink() ||
      !afterDirectory.isDirectory() ||
      !sameArtifactCacheEntryPhysicalStatus(
        artifactCacheEntryPhysicalStatus(beforeDirectory),
        artifactCacheEntryPhysicalStatus(afterDirectory)
      )
    ) {
      return undefined;
    }
    return JSON.stringify({
      directory: artifactCacheEntryPhysicalStatus(afterDirectory),
      files,
    });
  } catch (error) {
    if (isMissingArtifactCachePhysicalStateError(error)) {
      return undefined;
    }
    throw error;
  }
}

function singleFlightImmutableCacheValidation(flights, key, validate) {
  let flight = flights.get(key);
  if (flight === undefined) {
    flight = Promise.resolve().then(validate);
    flights.set(key, flight);
    const clearFlight = () => {
      if (flights.get(key) === flight) flights.delete(key);
    };
    void flight.then(clearFlight, clearFlight);
  }
  return flight;
}

function artifactCacheEntryPhysicalStateInValidationScope(validationMemo, cacheRoot, entryPath) {
  let flights = artifactCacheEntryPhysicalStateFlightsByValidationMemo.get(validationMemo);
  if (flights === undefined) {
    flights = new Map();
    artifactCacheEntryPhysicalStateFlightsByValidationMemo.set(validationMemo, flights);
  }
  // Share only a pending filesystem read. The single-flight removes completed work before its
  // callers resume, so sequential before/after fences and later scoped calls always read again.
  return singleFlightImmutableCacheValidation(
    flights,
    `${resolve(cacheRoot)}\0${resolve(entryPath)}`,
    async () => await artifactCacheEntryPhysicalState(cacheRoot, entryPath)
  );
}

function memoizeImmutableCacheValidation(memo, key, validate) {
  let validation = memo.get(key);
  if (validation === undefined) {
    validation = Promise.resolve().then(validate);
    memo.set(key, validation);
    const clearFailedValidation = () => {
      if (memo.get(key) === validation) memo.delete(key);
    };
    void validation.then(undefined, clearFailedValidation);
  }
  return validation;
}

async function hashPrivateRegularFileInValidationScope(
  validationMemo,
  cacheRoot,
  path,
  maximumBytes,
  description,
  authenticatedFileIdentity
) {
  if (validationMemo === undefined) {
    return await hashPrivateRegularFile(path, maximumBytes, description, authenticatedFileIdentity);
  }
  const before = await fs.lstat(path, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile()) {
    fail(`${description} is not a nonsymlink regular file: ${path}`);
  }
  if (before.size > BigInt(maximumBytes)) {
    throw new ConvexWasmArtifactByteLimitError(
      `${description} has`,
      Number(before.size),
      maximumBytes
    );
  }
  const validationKey = [
    "payload",
    resolve(cacheRoot),
    before.dev.toString(),
    before.ino.toString(),
    before.size.toString(),
    before.mtimeNs.toString(),
    before.ctimeNs.toString(),
    before.nlink.toString(),
    before.uid.toString(),
    before.gid.toString(),
    before.mode.toString(),
  ].join("\0");
  const validation = memoizeImmutableCacheValidation(
    validationMemo,
    validationKey,
    async () =>
      await hashPrivateRegularFile(path, maximumBytes, description, authenticatedFileIdentity)
  );
  const digest = await validation;
  const after = await fs.lstat(path, { bigint: true });
  if (
    after.isSymbolicLink() ||
    !after.isFile() ||
    // Cohort publication may add or remove immutable hard links while this hash is pending.
    // Use the entry fence's content rule so publication does not discard the verified digest.
    !sameArtifactCachePayloadContentStatus(
      artifactCacheEntryPhysicalStatus(before),
      artifactCacheEntryPhysicalStatus(after)
    )
  ) {
    if (validationMemo.get(validationKey) === validation) {
      validationMemo.delete(validationKey);
    }
    return artifactCachePayloadPhysicalStateChanged;
  }
  return digest;
}

async function validateArtifactCacheEntry(
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes
) {
  return await validateArtifactCacheEntryWithMode(
    "hash",
    cacheRoot,
    cacheLayout,
    stage,
    key,
    expectedExtension,
    maxArtifactBytes
  );
}

async function validateArtifactCacheEntryFresh(
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes,
  payloadValidationMemo
) {
  return await validateArtifactCacheEntryUncached(
    "hash",
    cacheRoot,
    cacheLayout,
    stage,
    key,
    expectedExtension,
    maxArtifactBytes,
    payloadValidationMemo
  );
}

async function readAndValidateArtifactCacheEntry(
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes
) {
  return await validateArtifactCacheEntryWithMode(
    "read",
    cacheRoot,
    cacheLayout,
    stage,
    key,
    expectedExtension,
    maxArtifactBytes
  );
}

async function readAndValidateArtifactCacheEntryFresh(
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes
) {
  return await validateArtifactCacheEntryUncached(
    "read",
    cacheRoot,
    cacheLayout,
    stage,
    key,
    expectedExtension,
    maxArtifactBytes
  );
}

async function validateArtifactCacheEntryWithMode(
  mode,
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes
) {
  const entry = await singleFlightImmutableCacheValidation(
    immutableArtifactCacheValidationFlights,
    `${mode}\0${cacheRoot}\0${stage}\0${key}\0${expectedExtension}\0${String(maxArtifactBytes)}`,
    async () =>
      await validateArtifactCacheEntryUncached(
        mode,
        cacheRoot,
        cacheLayout,
        stage,
        key,
        expectedExtension,
        maxArtifactBytes
      )
  );
  // Read-mode callers consume and release their buffer independently. Return a distinct outer
  // object so overlapping callers can share one authenticated read without sharing that mutation.
  return entry === undefined || mode === "hash"
    ? entry
    : copyAuthenticatedArtifactCacheEntry(entry);
}

async function validateArtifactCacheEntryInValidationScope(
  validationMemo,
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes,
  maximumAttempts = 4,
  payloadValidationMemo
) {
  requirePositiveInteger(maximumAttempts, "artifact cache scoped validation attempt limit");
  const entryPath = cacheStagePath(cacheLayout, stage, key);
  // The operational byte limit is checked at each caller's tail, but every logical entry
  // expectation must match the authentication that produced a retained success.
  const authenticatedStateKey = [
    resolve(cacheRoot),
    resolve(entryPath),
    stage,
    key,
    expectedExtension,
  ].join("\0");
  let authenticatedPhysicalStates =
    authenticatedArtifactCacheEntryPhysicalStatesByValidationMemo.get(validationMemo);
  if (authenticatedPhysicalStates === undefined) {
    authenticatedPhysicalStates = new Map();
    authenticatedArtifactCacheEntryPhysicalStatesByValidationMemo.set(
      validationMemo,
      authenticatedPhysicalStates
    );
  }
  // Four attempts remain the generic contract. A package builder may supply its finite
  // cohort-publication budget because these inner state windows can observe the same hard-link
  // wave as the package verifier that owns them.
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const before = await artifactCacheEntryPhysicalStateInValidationScope(
      validationMemo,
      cacheRoot,
      entryPath
    );
    const retainedPhysicalState = authenticatedPhysicalStates.get(authenticatedStateKey);
    const canReuseRetainedValidation =
      retainedPhysicalState !== undefined &&
      artifactCacheEntryPhysicalStateRetainsAuthenticatedBytes(retainedPhysicalState.state, before);
    if (retainedPhysicalState !== undefined && !canReuseRetainedValidation) {
      if (
        validationMemo.get(retainedPhysicalState.validationKey) === retainedPhysicalState.validation
      ) {
        validationMemo.delete(retainedPhysicalState.validationKey);
      }
      authenticatedPhysicalStates.delete(authenticatedStateKey);
    }
    const validationKey = canReuseRetainedValidation
      ? retainedPhysicalState.validationKey
      : `artifact\0${cacheRoot}\0${stage}\0${key}\0${expectedExtension}\0${String(maxArtifactBytes)}\0${before ?? "absent-or-changing"}`;
    // Full entry authentication remains keyed by its logical path and captured directory state.
    // The retained-state check below decides whether payload-only hard-link churn can reuse it.
    const validation = memoizeImmutableCacheValidation(
      validationMemo,
      validationKey,
      async () =>
        await validateArtifactCacheEntryFresh(
          cacheRoot,
          cacheLayout,
          stage,
          key,
          expectedExtension,
          maxArtifactBytes,
          payloadValidationMemo
        )
    );
    const entry = await validation;
    if (entry === artifactCachePayloadPhysicalStateChanged) {
      if (validationMemo.get(validationKey) === validation) {
        validationMemo.delete(validationKey);
      }
      authenticatedPhysicalStates.delete(authenticatedStateKey);
      continue;
    }
    const after = await artifactCacheEntryPhysicalStateInValidationScope(
      validationMemo,
      cacheRoot,
      entryPath
    );
    const stableTransition = artifactCacheEntryPhysicalStateRetainsAuthenticatedBytes(
      before,
      after
    );
    if (stableTransition && (entry === undefined) === (after === undefined)) {
      // A missing entry can be published later in this build (for example, by the first cohort of
      // a cold collection), so only retain authenticated entries in the scope memo.
      if (entry === undefined && validationMemo.get(validationKey) === validation) {
        validationMemo.delete(validationKey);
        authenticatedPhysicalStates.delete(authenticatedStateKey);
      } else if (entry !== undefined) {
        // Only payload ctime/nlink churn from an actual link-count change can retain this
        // validation. Directory, metadata-file, and content-relevant payload state remain exact.
        authenticatedPhysicalStates.set(authenticatedStateKey, {
          state: after,
          validation,
          validationKey,
        });
      }
      // A retained validation authenticates bytes independently of the operational limit that
      // first populated the scope. Enforce the current caller's limit after the stable-state fence.
      if (entry !== undefined && entry.artifactSize > maxArtifactBytes) {
        throw new ConvexWasmArtifactByteLimitError(
          `${stage} cached artifact has`,
          entry.artifactSize,
          maxArtifactBytes
        );
      }
      return entry;
    }
    if (validationMemo.get(validationKey) === validation) {
      validationMemo.delete(validationKey);
    }
    authenticatedPhysicalStates.delete(authenticatedStateKey);
  }
  fail(`cache entry changed repeatedly during scoped validation: ${entryPath}`);
}

async function validateArtifactCacheEntryUncached(
  mode,
  cacheRoot,
  cacheLayout,
  stage,
  key,
  expectedExtension,
  maxArtifactBytes,
  payloadValidationMemo
) {
  const entryPath = cacheStagePath(cacheLayout, stage, key);
  const authenticatedFiles = await requirePrivateCacheDirectoryFileIdentities(cacheRoot, entryPath);
  if (authenticatedFiles === undefined) return undefined;
  const names = authenticatedFiles.names;
  if (!names.includes("COMPLETE")) {
    fail(`cache entry is partial: ${entryPath}`);
  }
  const [completeRead, entrySourceRead] = await Promise.allSettled([
    (async () => {
      const complete = decodeUtf8(
        await readPrivateRegularFile(
          join(entryPath, "COMPLETE"),
          MAX_COMPLETION_MARKER_BYTES,
          "artifact cache completion marker",
          authenticatedFiles.fileIdentities.get("COMPLETE")
        ),
        "artifact cache completion marker"
      );
      if (complete !== `${key}\n`) {
        fail(`cache entry completion marker is corrupt: ${entryPath}`);
      }
    })(),
    (async () =>
      decodeUtf8(
        await readPrivateRegularFile(
          join(entryPath, "entry.json"),
          MAX_CACHE_ENTRY_METADATA_BYTES,
          "artifact cache metadata",
          authenticatedFiles.fileIdentities.get("entry.json")
        ),
        "artifact cache metadata"
      ))(),
  ]);
  // Both required reads are unconditional. Drain them together, then preserve marker-first
  // failure precedence so parallel I/O does not make corruption reporting timing-dependent.
  const readFailure = [completeRead, entrySourceRead].find(
    (settlement) => settlement.status === "rejected"
  );
  if (readFailure !== undefined) throw readFailure.reason;
  const entrySource = entrySourceRead.value;
  let entry;
  try {
    entry = JSON.parse(entrySource);
  } catch (error) {
    throw new Error(`Convex Wasm artifact pipeline: cache entry is corrupt: ${entryPath}`, {
      cause: error,
    });
  }
  if (
    typeof entry !== "object" ||
    entry === null ||
    Array.isArray(entry) ||
    entry.kind !== CACHE_ENTRY_KIND ||
    entry.stage !== stage ||
    entry.key !== key ||
    entry.artifactFile !== `artifact.${expectedExtension}` ||
    typeof entry.artifactSha256 !== "string" ||
    !SHA256_PATTERN.test(entry.artifactSha256) ||
    !Number.isSafeInteger(entry.artifactSize) ||
    entry.artifactSize <= 0 ||
    !Object.hasOwn(entry, "metadata")
  ) {
    fail(`cache entry is corrupt: ${entryPath}`);
  }
  assertExactKeys(
    entry,
    new Set([
      ...(Object.hasOwn(entry, "admission") ? ["admission"] : []),
      "artifactFile",
      "artifactSha256",
      "artifactSize",
      "identity",
      "key",
      "kind",
      "metadata",
      "stage",
    ]),
    `cache entry ${entryPath}`
  );
  if (`${canonicalJson(entry)}\n` !== entrySource) {
    fail(`cache entry metadata is not canonical JSON: ${entryPath}`);
  }
  if (
    canonicalJson(names) !==
    canonicalJson(["COMPLETE", entry.artifactFile, "entry.json"].sort(compareStrings))
  ) {
    fail(`cache entry has unexpected files: ${entryPath}`);
  }
  if (fingerprintJson({ kind: PIPELINE_KIND, stage, identity: entry.identity }) !== key) {
    fail(`cache entry identity does not match its key: ${entryPath}`);
  }
  const artifactPath = join(entryPath, entry.artifactFile);
  const { admission, ...unadmittedEntry } = entry;
  // Cooperative publishers leave completed payloads immutable. The checksum binds this local
  // admission to exact entry metadata; the physical fingerprint excludes copies and changed
  // files, using the same content rule as scoped admission for package hard-link publication.
  // Legacy/imported entries without matching admission still require full SHA-256.
  // This is not authentication against an arbitrary same-user metadata author.
  const reuseAdmission =
    mode === "hash" &&
    admission !== undefined &&
    admission !== null &&
    typeof admission === "object" &&
    admission.payload !== null &&
    typeof admission.payload === "object" &&
    // These two fields can differ during legitimate hard-link publication. Require their
    // recorded values so incomplete admission cannot look like a link-count transition.
    typeof admission.payload.ctimeNs === "string" &&
    /^\d+$/u.test(admission.payload.ctimeNs) &&
    typeof admission.payload.nlink === "string" &&
    /^[1-9]\d*$/u.test(admission.payload.nlink) &&
    admission.entrySha256 === fingerprintJson(unadmittedEntry) &&
    sameArtifactCachePayloadContentStatus(
      admission.payload,
      artifactCacheEntryPhysicalStatus(await fs.lstat(artifactPath, { bigint: true }))
    );
  if (entry.artifactSize > maxArtifactBytes) {
    throw new ConvexWasmArtifactByteLimitError(
      `${stage} cached artifact has`,
      entry.artifactSize,
      maxArtifactBytes
    );
  }
  const digest = reuseAdmission
    ? { sha256: entry.artifactSha256, size: entry.artifactSize }
    : mode === "read"
      ? await readAndHashPrivateRegularFile(
          artifactPath,
          maxArtifactBytes,
          `${stage} cached artifact`,
          authenticatedFiles.fileIdentities.get(entry.artifactFile)
        )
      : await hashPrivateRegularFileInValidationScope(
          payloadValidationMemo,
          cacheRoot,
          artifactPath,
          maxArtifactBytes,
          `${stage} cached artifact`,
          authenticatedFiles.fileIdentities.get(entry.artifactFile)
        );
  if (digest === artifactCachePayloadPhysicalStateChanged) {
    return artifactCachePayloadPhysicalStateChanged;
  }
  if (digest.sha256 !== entry.artifactSha256 || digest.size !== entry.artifactSize) {
    fail(`cache artifact digest or size does not match metadata: ${entryPath}`);
  }
  await authenticatedFiles.verify();
  return retainAuthenticatedArtifactCacheEntryJson({
    ...entry,
    artifactPath,
    ...(mode === "read" ? { artifactContents: digest.contents } : {}),
  });
}

export {
  copyAuthenticatedArtifactCacheEntry,
  artifactCacheEntryPhysicalState,
  artifactCacheEntryPhysicalStateInValidationScope,
  artifactCacheEntryPhysicalStateRetainsAuthenticatedBytes,
  readAndValidateArtifactCacheEntry,
  readAndValidateArtifactCacheEntryFresh,
  requireAuthenticatedArtifactCacheEntryJsonDigests,
  validateArtifactCacheEntry,
  validateArtifactCacheEntryFresh,
  validateArtifactCacheEntryInValidationScope,
};
