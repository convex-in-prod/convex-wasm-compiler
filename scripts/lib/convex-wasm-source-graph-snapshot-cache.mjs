import { randomBytes } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  authenticateConvexWasmSourceGraphSnapshot,
  convexWasmSourceGraphSnapshotKind,
  createConvexWasmSourceGraphSnapshotLookupIdentity,
} from "./convex-wasm-source-graph-snapshot.mjs";
import { validateConvexWasmGitSourceSnapshot } from "./convex-wasm-git-source-snapshot.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import { ensureCreatedPrivateDirectoryPath } from "./private-directory.mjs";

const SNAPSHOT_CACHE_VERSION = "v1";
const SNAPSHOT_CACHE_MAX_BYTES = 256 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const TREE_OID_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SNAPSHOT_INDEX_KIND = "convex-wasm-source-graph-snapshot-index-v1";

function fail(message) {
  throw new Error(`Convex Wasm source graph snapshot cache: ${message}`);
}

function requireAbsoluteDirectory(value, description) {
  if (typeof value !== "string" || value.length === 0 || !isAbsolute(value)) {
    fail(`${description} must be an absolute path`);
  }
  const normalized = resolve(value);
  if (normalized !== value) fail(`${description} must be normalized`);
  return normalized;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireTreeOid(value, description) {
  if (typeof value !== "string" || !TREE_OID_PATTERN.test(value)) {
    fail(`${description} must be a Git tree object ID`);
  }
  return value;
}

function snapshotPath(cacheDirectory, snapshotSha256) {
  const path = join(cacheDirectory, SNAPSHOT_CACHE_VERSION, `${snapshotSha256}.json`);
  const fromRoot = relative(cacheDirectory, path);
  if (fromRoot.startsWith("..") || isAbsolute(fromRoot)) {
    fail("snapshot cache path escapes its root");
  }
  return path;
}

function snapshotIndexPath(cacheDirectory, scopeSha256, treeOid) {
  const path = join(
    cacheDirectory,
    SNAPSHOT_CACHE_VERSION,
    "index",
    scopeSha256,
    `${treeOid}.json`
  );
  const fromRoot = relative(cacheDirectory, path);
  if (fromRoot.startsWith("..") || isAbsolute(fromRoot)) {
    fail("snapshot cache index path escapes its root");
  }
  return path;
}

function normalizeEntryPaths(entryPaths) {
  if (!Array.isArray(entryPaths)) {
    fail("snapshot cache scope entry paths must be an array");
  }
  const normalized = entryPaths.map((path, index) => {
    if (
      typeof path !== "string" ||
      path.length === 0 ||
      path.startsWith("/") ||
      path.includes("\\") ||
      path.includes("\0") ||
      path === "." ||
      path === ".." ||
      path.startsWith("../") ||
      path.includes("/../") ||
      path.endsWith("/..")
    ) {
      fail(`snapshot cache scope entry path ${index} is invalid`);
    }
    return path;
  });
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1] >= normalized[index]) {
      fail("snapshot cache scope entry paths must be sorted and unique");
    }
  }
  return normalized;
}

function sourceGraphSnapshotScopePayload({ gitSourceSnapshot, entryPaths, lookupIdentity }) {
  validateConvexWasmGitSourceSnapshot(gitSourceSnapshot, "snapshot cache scope Git authority");
  return {
    authority: {
      objectFormat: gitSourceSnapshot.objectFormat,
      pathspecs: [...gitSourceSnapshot.pathspecs],
    },
    entryPaths: normalizeEntryPaths(entryPaths),
    lookupIdentity: createConvexWasmSourceGraphSnapshotLookupIdentity(lookupIdentity),
    kind: "convex-wasm-source-graph-snapshot-scope-v1",
  };
}

export function convexWasmSourceGraphSnapshotScopeSha256(snapshot) {
  const authenticated = authenticateConvexWasmSourceGraphSnapshot(snapshot);
  return convexWasmSourceGraphSnapshotLookupScopeSha256({
    entryPaths: authenticated.dependencyGraphs.map(({ entryPath }) => entryPath),
    gitSourceSnapshot: authenticated.authority,
    lookupIdentity: authenticated.lookupIdentity,
  });
}

export function convexWasmSourceGraphSnapshotLookupScopeSha256({
  entryPaths,
  gitSourceSnapshot,
  lookupIdentity,
} = {}) {
  return fingerprintJson(
    sourceGraphSnapshotScopePayload({ entryPaths, gitSourceSnapshot, lookupIdentity })
  );
}

function snapshotIndexIdentity({ scopeSha256, snapshotSha256, treeOid }) {
  return {
    kind: SNAPSHOT_INDEX_KIND,
    schemaVersion: 1,
    scopeSha256,
    snapshotSha256,
    treeOid,
  };
}

function authenticateSnapshotIndex(value, { expectedScopeSha256, expectedTreeOid } = {}) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("snapshot cache index entry must be an object");
  }
  const expectedKeys = [
    "kind",
    "schemaVersion",
    "scopeSha256",
    "snapshotSha256",
    "treeOid",
    "sha256",
  ];
  const actualKeys = Object.keys(value).sort();
  if (canonicalJson(actualKeys) !== canonicalJson([...expectedKeys].sort())) {
    fail("snapshot cache index entry has an unexpected shape");
  }
  if (value.kind !== SNAPSHOT_INDEX_KIND || value.schemaVersion !== 1) {
    fail("snapshot cache index entry kind or schema version is unsupported");
  }
  const scopeSha256 = requireSha256(value.scopeSha256, "snapshot cache index scope SHA-256");
  requireSha256(value.snapshotSha256, "snapshot cache index snapshot SHA-256");
  const treeOid = requireTreeOid(value.treeOid, "snapshot cache index tree OID");
  const { sha256, ...identity } = value;
  if (requireSha256(sha256, "snapshot cache index SHA-256") !== fingerprintJson(identity)) {
    fail("snapshot cache index SHA-256 does not match its contents");
  }
  if (expectedScopeSha256 !== undefined && scopeSha256 !== expectedScopeSha256) {
    fail("snapshot cache index scope disagrees with its path");
  }
  if (expectedTreeOid !== undefined && treeOid !== expectedTreeOid) {
    fail("snapshot cache index tree disagrees with its path");
  }
  return Object.freeze({ ...identity, sha256 });
}

async function syncDirectory(path) {
  const handle = await fs.open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function ensureCacheDirectory(cacheDirectory) {
  await ensureCreatedPrivateDirectoryPath(cacheDirectory, "snapshot cache directory");
  await requirePrivateCacheDirectory(cacheDirectory, cacheDirectory);
  const versionDirectory = join(cacheDirectory, SNAPSHOT_CACHE_VERSION);
  await ensureCreatedPrivateDirectoryPath(versionDirectory, "snapshot cache version directory");
  await requirePrivateCacheDirectory(cacheDirectory, versionDirectory);
  return versionDirectory;
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

async function readCanonicalCacheFile(path, description) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("snapshot cache reads require O_NOFOLLOW");
  }
  const beforePath = await fs.lstat(path);
  if (beforePath.isSymbolicLink() || !beforePath.isFile()) {
    fail(`${description} is not a regular file: ${path}`);
  }
  if ((beforePath.mode & 0o777) !== 0o600) {
    fail(`${description} is not private: ${path}`);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileState(beforePath, opened)) {
      fail(`${description} changed while it was opened: ${path}`);
    }
    if (opened.size > SNAPSHOT_CACHE_MAX_BYTES) {
      fail(`${description} exceeds ${SNAPSHOT_CACHE_MAX_BYTES} bytes: ${path}`);
    }
    // Read only the size authenticated by the opened descriptor. A same-user writer can grow a
    // private cache entry while it is being read; FileHandle.readFile() would otherwise allocate
    // the whole replacement before the later identity check rejects it.
    const contents = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < contents.length) {
      const { bytesRead } = await handle.read(contents, offset, contents.length - offset, offset);
      if (bytesRead === 0) {
        fail(`${description} changed while it was read: ${path}`);
      }
      offset += bytesRead;
    }
    const overflow = Buffer.allocUnsafe(1);
    if ((await handle.read(overflow, 0, 1, contents.length)).bytesRead !== 0) {
      fail(`${description} changed while it was read: ${path}`);
    }
    const [after, afterPath] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (
      contents.length !== opened.size ||
      !sameFileState(opened, after) ||
      afterPath.isSymbolicLink() ||
      !afterPath.isFile() ||
      !sameFileState(opened, afterPath)
    ) {
      fail(`${description} changed while it was read: ${path}`);
    }
    let value;
    try {
      value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents));
    } catch (error) {
      throw new Error(`${description} is not valid JSON: ${path}`, { cause: error });
    }
    if (`${canonicalJson(value)}\n` !== contents.toString("utf8")) {
      fail(`${description} is not canonical JSON: ${path}`);
    }
    return value;
  } finally {
    await handle.close();
  }
}

async function readSnapshotFile(path, expectedSha256) {
  const value = await readCanonicalCacheFile(path, "snapshot cache entry");
  const snapshot = authenticateConvexWasmSourceGraphSnapshot(value);
  if (snapshot.kind !== convexWasmSourceGraphSnapshotKind || snapshot.sha256 !== expectedSha256) {
    fail(`snapshot cache entry identity disagrees: ${path}`);
  }
  return snapshot;
}

async function readSnapshotIndexFile(path, expectedScopeSha256, expectedTreeOid) {
  const value = await readCanonicalCacheFile(path, "snapshot cache index entry");
  return authenticateSnapshotIndex(value, { expectedScopeSha256, expectedTreeOid });
}

async function publishImmutableCacheFile({
  cacheRoot,
  directory,
  finalPath,
  source,
  readExisting,
  description,
}) {
  if (Buffer.byteLength(source) > SNAPSHOT_CACHE_MAX_BYTES) {
    fail(`${description} exceeds ${SNAPSHOT_CACHE_MAX_BYTES} bytes`);
  }
  const temporaryPath = join(
    directory,
    `.publish-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  const handle = await fs.open(temporaryPath, "wx", 0o600);
  try {
    // Normalize through the open descriptor before linking the immutable record. A restrictive
    // daemon umask would otherwise publish a mode-000 cache file that later authentication must
    // reject, even though the temporary inode was created by this writer.
    await handle.chmod(0o600);
    await handle.writeFile(source);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    try {
      // Linking, rather than renaming, keeps an existing immutable cache record intact when two
      // deploys publish the same identity concurrently.
      await fs.link(temporaryPath, finalPath);
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) {
        throw error;
      }
      await requirePrivateCacheFile(cacheRoot, finalPath);
      const existing = await readExisting(finalPath);
      if (canonicalJson(existing) !== source.trimEnd()) {
        fail(`concurrent ${description} publication disagrees: ${finalPath}`);
      }
    }
    return finalPath;
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
}

export function convexWasmSourceGraphSnapshotCachePath(cacheDirectory, snapshotSha256) {
  const normalizedDirectory = requireAbsoluteDirectory(cacheDirectory, "snapshot cache directory");
  return snapshotPath(normalizedDirectory, requireSha256(snapshotSha256, "snapshot SHA-256"));
}

export function convexWasmSourceGraphSnapshotCacheIndexPath(cacheDirectory, scopeSha256, treeOid) {
  const normalizedDirectory = requireAbsoluteDirectory(cacheDirectory, "snapshot cache directory");
  return snapshotIndexPath(
    normalizedDirectory,
    requireSha256(scopeSha256, "snapshot cache scope SHA-256"),
    requireTreeOid(treeOid, "snapshot cache tree OID")
  );
}

export async function publishConvexWasmSourceGraphSnapshot({ cacheDirectory, snapshot } = {}) {
  const normalizedDirectory = requireAbsoluteDirectory(cacheDirectory, "snapshot cache directory");
  const authenticated = authenticateConvexWasmSourceGraphSnapshot(snapshot);
  const versionDirectory = await ensureCacheDirectory(normalizedDirectory);
  const scopeSha256 = convexWasmSourceGraphSnapshotScopeSha256(authenticated);
  const indexRoot = join(versionDirectory, "index");
  await ensureCreatedPrivateDirectoryPath(indexRoot, "snapshot cache index root");
  await requirePrivateCacheDirectory(normalizedDirectory, indexRoot);
  const indexDirectory = join(indexRoot, scopeSha256);
  await ensureCreatedPrivateDirectoryPath(indexDirectory, "snapshot cache index directory");
  await requirePrivateCacheDirectory(normalizedDirectory, indexDirectory);
  // Validate every directory needed by the index before publishing the content record. A known
  // unusable index path must not leave an unreachable immutable snapshot behind.
  const finalPath = snapshotPath(normalizedDirectory, authenticated.sha256);
  await publishImmutableCacheFile({
    cacheRoot: normalizedDirectory,
    directory: versionDirectory,
    finalPath,
    source: `${canonicalJson(authenticated)}\n`,
    readExisting: (path) => readSnapshotFile(path, authenticated.sha256),
    description: "snapshot cache entry",
  });
  // Make the referenced snapshot and the scope-directory path durable before the index record.
  // Otherwise a crash could preserve a synced index entry while losing its snapshot link.
  await syncDirectory(indexRoot);
  await syncDirectory(versionDirectory);

  const indexPath = snapshotIndexPath(
    normalizedDirectory,
    scopeSha256,
    authenticated.authority.treeOid
  );
  const indexIdentity = snapshotIndexIdentity({
    scopeSha256,
    snapshotSha256: authenticated.sha256,
    treeOid: authenticated.authority.treeOid,
  });
  await publishImmutableCacheFile({
    cacheRoot: normalizedDirectory,
    directory: indexDirectory,
    finalPath: indexPath,
    source: `${canonicalJson({ ...indexIdentity, sha256: fingerprintJson(indexIdentity) })}\n`,
    readExisting: (path) =>
      readSnapshotIndexFile(path, scopeSha256, authenticated.authority.treeOid),
    description: "snapshot cache index entry",
  });
  await syncDirectory(indexDirectory);
  await syncDirectory(indexRoot);
  await syncDirectory(versionDirectory);
  await syncDirectory(normalizedDirectory);
  return finalPath;
}

export async function loadConvexWasmSourceGraphSnapshot({ cacheDirectory, snapshotSha256 } = {}) {
  const normalizedDirectory = requireAbsoluteDirectory(cacheDirectory, "snapshot cache directory");
  const expectedSha256 = requireSha256(snapshotSha256, "snapshot SHA-256");
  const finalPath = snapshotPath(normalizedDirectory, expectedSha256);
  try {
    await requirePrivateCacheDirectory(normalizedDirectory, normalizedDirectory);
    await requirePrivateCacheDirectory(
      normalizedDirectory,
      join(normalizedDirectory, SNAPSHOT_CACHE_VERSION)
    );
    await requirePrivateCacheFile(normalizedDirectory, finalPath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  return await readSnapshotFile(finalPath, expectedSha256);
}

async function probeSnapshotReferenceByTree({
  normalizedDirectory,
  expectedScopeSha256,
  expectedTreeOid,
}) {
  const versionDirectory = join(normalizedDirectory, SNAPSHOT_CACHE_VERSION);
  const indexDirectory = join(versionDirectory, "index", expectedScopeSha256);
  const indexPath = snapshotIndexPath(normalizedDirectory, expectedScopeSha256, expectedTreeOid);
  try {
    await requirePrivateCacheDirectory(normalizedDirectory, normalizedDirectory);
    await requirePrivateCacheDirectory(normalizedDirectory, versionDirectory);
    await requirePrivateCacheDirectory(normalizedDirectory, join(versionDirectory, "index"));
    await requirePrivateCacheDirectory(normalizedDirectory, indexDirectory);
    await requirePrivateCacheFile(normalizedDirectory, indexPath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  const index = await readSnapshotIndexFile(indexPath, expectedScopeSha256, expectedTreeOid);
  const referencedSnapshotPath = snapshotPath(normalizedDirectory, index.snapshotSha256);
  try {
    await requirePrivateCacheFile(normalizedDirectory, referencedSnapshotPath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      fail(`snapshot cache index points to a missing snapshot: ${indexPath}`);
    }
    throw error;
  }
  return Object.freeze({ ...index, path: referencedSnapshotPath });
}

export async function probeConvexWasmSourceGraphSnapshotByTree({
  cacheDirectory,
  scopeSha256,
  treeOid,
} = {}) {
  const normalizedDirectory = requireAbsoluteDirectory(cacheDirectory, "snapshot cache directory");
  const expectedScopeSha256 = requireSha256(scopeSha256, "snapshot cache scope SHA-256");
  const expectedTreeOid = requireTreeOid(treeOid, "snapshot cache tree OID");
  return await probeSnapshotReferenceByTree({
    expectedScopeSha256,
    expectedTreeOid,
    normalizedDirectory,
  });
}

export async function loadConvexWasmSourceGraphSnapshotByTree({
  cacheDirectory,
  scopeSha256,
  treeOid,
} = {}) {
  const normalizedDirectory = requireAbsoluteDirectory(cacheDirectory, "snapshot cache directory");
  const expectedScopeSha256 = requireSha256(scopeSha256, "snapshot cache scope SHA-256");
  const expectedTreeOid = requireTreeOid(treeOid, "snapshot cache tree OID");
  const reference = await probeSnapshotReferenceByTree({
    expectedScopeSha256,
    expectedTreeOid,
    normalizedDirectory,
  });
  if (reference === undefined) return undefined;
  const snapshot = await loadConvexWasmSourceGraphSnapshot({
    cacheDirectory: normalizedDirectory,
    snapshotSha256: reference.snapshotSha256,
  });
  if (snapshot === undefined) {
    fail(`snapshot cache index points to a missing snapshot: ${reference.path}`);
  }
  if (
    convexWasmSourceGraphSnapshotScopeSha256(snapshot) !== expectedScopeSha256 ||
    snapshot.authority.treeOid !== expectedTreeOid
  ) {
    fail(`snapshot cache index points to a snapshot with a different authority: ${reference.path}`);
  }
  return snapshot;
}

export async function probeConvexWasmSourceGraphSnapshotForLookup({
  cacheDirectory,
  entryPaths,
  gitSourceSnapshot,
  lookupIdentity,
} = {}) {
  validateConvexWasmGitSourceSnapshot(gitSourceSnapshot, "snapshot cache lookup Git authority");
  const scopeSha256 = convexWasmSourceGraphSnapshotLookupScopeSha256({
    entryPaths,
    gitSourceSnapshot,
    lookupIdentity,
  });
  return await probeConvexWasmSourceGraphSnapshotByTree({
    cacheDirectory,
    scopeSha256,
    treeOid: gitSourceSnapshot.treeOid,
  });
}

export async function loadConvexWasmSourceGraphSnapshotForLookup({
  cacheDirectory,
  entryPaths,
  gitSourceSnapshot,
  lookupIdentity,
} = {}) {
  validateConvexWasmGitSourceSnapshot(gitSourceSnapshot, "snapshot cache lookup Git authority");
  const scopeSha256 = convexWasmSourceGraphSnapshotLookupScopeSha256({
    entryPaths,
    gitSourceSnapshot,
    lookupIdentity,
  });
  return await loadConvexWasmSourceGraphSnapshotByTree({
    cacheDirectory,
    scopeSha256,
    treeOid: gitSourceSnapshot.treeOid,
  });
}

export const convexWasmSourceGraphSnapshotCacheTestHooks = Object.freeze({
  SNAPSHOT_CACHE_MAX_BYTES,
  SNAPSHOT_CACHE_VERSION,
});
