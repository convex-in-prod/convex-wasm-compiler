import { createHash } from "node:crypto";
import { constants as fsConstants, createReadStream, promises as fs } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";

class ConvexWasmArtifactByteLimitError extends Error {
  constructor(description, actualBytes, maximumBytes) {
    super(
      `Convex Wasm artifact pipeline: ${description} ${actualBytes} bytes, above the ${maximumBytes}-byte limit`
    );
    this.name = "ConvexWasmArtifactByteLimitError";
    this.actualBytes = actualBytes;
    this.description = description;
    this.maximumBytes = maximumBytes;
  }
}

export const immutableCacheHashBufferBytes = 64 * 1024;
const materialDirectoryReadConcurrency = 4;
// Material categories contain independent toolchain trees. Admit a few together so their state
// walks and hashes overlap, while the per-directory bound below keeps nested file reads finite.
const materialPathHashConcurrency = 4;
// Keep memo contents private so a caller cannot seed a digest without the matching state scan.
const materialPathVerificationMemos = new WeakMap();

function createMaterialPathVerificationMemo() {
  const token = Object.freeze({});
  materialPathVerificationMemos.set(token, new Map());
  return token;
}

async function hashFile(path) {
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(path)) {
    size += chunk.length;
    hash.update(chunk);
  }
  return { sha256: hash.digest("hex"), size };
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

// Linking an immutable payload into another cache entry legitimately changes its
// ctime (the inode's link count changes) while the bytes remain untouched. Do
// not reject a concurrent hard-link publication merely because of that metadata
// change; the content hash and the stable inode/size/mtime still authenticate
// the regular file itself.
function sameFileContentState(left, right) {
  return (
    sameFileIdentity(left, right) && left.size === right.size && left.mtimeMs === right.mtimeMs
  );
}

function sameFileAccessState(left, right) {
  return left.uid === right.uid && left.mode === right.mode;
}

function requireAuthenticatedFileIdentity(identity, description) {
  if (
    typeof identity !== "object" ||
    identity === null ||
    !["dev", "ino", "mode", "mtimeMs", "size", "uid"].every(
      (field) => typeof identity[field] === "number"
    )
  ) {
    fail(`${description} authenticated file identity is invalid`);
  }
  return identity;
}

async function requirePrivateDirectory(path, description) {
  let status;
  try {
    status = await fs.lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
  if (status.isSymbolicLink() || !status.isDirectory()) {
    fail(`${description} is not a nonsymlink directory: ${path}`);
  }
  return true;
}

async function readPrivateRegularFile(path, maximumBytes, description, authenticatedFileIdentity) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
    fail(`${description} maximum byte limit is invalid`);
  }
  const beforePath =
    authenticatedFileIdentity === undefined
      ? await fs.lstat(path)
      : requireAuthenticatedFileIdentity(authenticatedFileIdentity, description);
  if (
    authenticatedFileIdentity === undefined &&
    (beforePath.isSymbolicLink() || !beforePath.isFile())
  ) {
    fail(`${description} is not a nonsymlink regular file: ${path}`);
  }
  if (beforePath.size > maximumBytes) {
    throw new ConvexWasmArtifactByteLimitError(`${description} has`, beforePath.size, maximumBytes);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      !sameFileIdentity(beforePath, before) ||
      (authenticatedFileIdentity !== undefined &&
        (!sameFileContentState(beforePath, before) || !sameFileAccessState(beforePath, before)))
    ) {
      fail(`${description} changed before it could be read: ${path}`);
    }
    // Read only the authenticated pre-read extent. An EOF-driven read could consume unbounded
    // appended data before the post-read state check rejects the changed external file.
    const contents = Buffer.allocUnsafe(before.size);
    // Regular cache records are normally served from the page cache. Request the complete
    // extent in one read to avoid scheduling one libuv operation per 64 KiB chunk; retain the
    // loop only for filesystems that legally return a short read.
    let size = (await handle.read(contents, 0, before.size, 0)).bytesRead;
    while (size < before.size) {
      const { bytesRead } = await handle.read(contents, size, before.size - size, size);
      if (bytesRead === 0) {
        fail(`${description} changed while it was read: ${path}`);
      }
      size += bytesRead;
    }
    const [after, afterPath] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (
      size !== before.size ||
      !sameFileContentState(before, after) ||
      !sameFileAccessState(before, after) ||
      afterPath.isSymbolicLink() ||
      !afterPath.isFile() ||
      !sameFileIdentity(after, afterPath) ||
      !sameFileAccessState(after, afterPath)
    ) {
      fail(`${description} changed while it was read: ${path}`);
    }
    return contents;
  } finally {
    await handle.close();
  }
}

async function readAndHashPrivateRegularFile(
  path,
  maximumBytes,
  description,
  authenticatedFileIdentity
) {
  const contents = await readPrivateRegularFile(
    path,
    maximumBytes,
    description,
    authenticatedFileIdentity
  );
  return {
    contents,
    sha256: createHash("sha256").update(contents).digest("hex"),
    size: contents.length,
  };
}

async function readAndHashMaterialFile(label, inputPath, maximumBytes, description) {
  const path = resolve(requireString(inputPath, `material path ${label}`));
  let status;
  try {
    status = await fs.lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      fail(`material path does not exist: ${label} (${path})`);
    }
    throw error;
  }
  if (!status.isSymbolicLink()) {
    if (!status.isFile()) {
      fail(`${description} is not a regular file or symbolic link to a regular file: ${path}`);
    }
    const { contents, sha256, size } = await readAndHashPrivateRegularFile(
      path,
      maximumBytes,
      description,
      status
    );
    return {
      contents,
      fingerprint: Object.freeze({ label, sha256, size, type: "file" }),
    };
  }

  let targetPath;
  try {
    targetPath = await fs.realpath(path);
  } catch (error) {
    throw new Error(
      `Convex Wasm artifact pipeline: material symbolic link cannot be resolved: ${label} (${path})`,
      { cause: error }
    );
  }
  const targetStatus = await fs.lstat(targetPath);
  if (targetStatus.isSymbolicLink() || !targetStatus.isFile()) {
    fail(`${description} symbolic link target is not a regular file: ${path}`);
  }
  const { contents, sha256, size } = await readAndHashPrivateRegularFile(
    targetPath,
    maximumBytes,
    description,
    targetStatus
  );
  const [afterLinkStatus, afterTargetPath] = await Promise.all([fs.lstat(path), fs.realpath(path)]);
  if (
    !afterLinkStatus.isSymbolicLink() ||
    !sameFileContentState(status, afterLinkStatus) ||
    !sameFileAccessState(status, afterLinkStatus) ||
    afterTargetPath !== targetPath
  ) {
    fail(`${description} symbolic link changed while it was read: ${path}`);
  }
  return {
    contents,
    fingerprint: Object.freeze({ label, sha256, size, type: "symbolic-link-to-file" }),
  };
}

async function hashPrivateRegularFile(path, maximumBytes, description, authenticatedFileIdentity) {
  const beforePath =
    authenticatedFileIdentity === undefined
      ? await fs.lstat(path)
      : requireAuthenticatedFileIdentity(authenticatedFileIdentity, description);
  if (
    authenticatedFileIdentity === undefined &&
    (beforePath.isSymbolicLink() || !beforePath.isFile())
  ) {
    fail(`${description} is not a nonsymlink regular file: ${path}`);
  }
  if (beforePath.size > maximumBytes) {
    throw new ConvexWasmArtifactByteLimitError(`${description} has`, beforePath.size, maximumBytes);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      !sameFileIdentity(beforePath, before) ||
      (authenticatedFileIdentity !== undefined &&
        (!sameFileContentState(beforePath, before) || !sameFileAccessState(beforePath, before)))
    ) {
      fail(`${description} changed before it could be read: ${path}`);
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(
      Math.max(1, Math.min(immutableCacheHashBufferBytes, before.size))
    );
    let size = 0;
    while (size < before.size) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, before.size - size),
        size
      );
      if (bytesRead === 0) {
        fail(`${description} changed while it was read: ${path}`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      size += bytesRead;
    }
    const [after, afterPath] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (
      size !== before.size ||
      !sameFileContentState(before, after) ||
      !sameFileAccessState(before, after) ||
      afterPath.isSymbolicLink() ||
      !afterPath.isFile() ||
      !sameFileIdentity(after, afterPath) ||
      !sameFileAccessState(after, afterPath)
    ) {
      fail(`${description} changed while it was read: ${path}`);
    }
    return { sha256: hash.digest("hex"), size };
  } finally {
    await handle.close();
  }
}

function decodeUtf8(contents, description) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(contents);
  } catch (error) {
    throw new Error(`Convex Wasm artifact pipeline: ${description} is not valid UTF-8`, {
      cause: error,
    });
  }
}

async function walkMaterialDirectory(root, current, entries) {
  const directoryEntries = await fs.readdir(current, { withFileTypes: true });
  directoryEntries.sort((left, right) => compareStrings(left.name, right.name));
  for (const entry of directoryEntries) {
    const path = join(current, entry.name);
    const relativePath = relative(root, path).split(sep).join("/");
    if (entry.isSymbolicLink()) {
      fail(`material directory contains a symbolic link: ${path}`);
    }
    if (entry.isDirectory()) {
      entries.push({ path: `${relativePath}/`, type: "directory" });
      await walkMaterialDirectory(root, path, entries);
      continue;
    }
    if (!entry.isFile()) {
      fail(`material directory contains an unsupported filesystem entry: ${path}`);
    }
    entries.push({ absolutePath: path, path: relativePath, type: "file" });
  }
}

export async function mapBounded(values, concurrency, callback) {
  const results = new Array(values.length);
  const failures = new Map();
  let nextIndex = 0;
  let stopped = false;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, values.length) }, async () => {
      while (!stopped && nextIndex < values.length) {
        const index = nextIndex;
        nextIndex += 1;
        try {
          results[index] = await callback(values[index]);
        } catch (error) {
          failures.set(index, error);
          stopped = true;
        }
      }
    })
  );
  if (failures.size > 0) {
    const firstFailureIndex = Math.min(...failures.keys());
    throw failures.get(firstFailureIndex);
  }
  return results;
}

export function createBoundedOperationRunner(concurrency) {
  const pending = new Set();
  let active = 0;
  const start = () => {
    while (active < concurrency && pending.size > 0) {
      const operation = pending.values().next().value;
      pending.delete(operation);
      active += 1;
      void Promise.resolve()
        .then(operation.callback)
        .then(
          (value) => {
            active -= 1;
            operation.resolve(value);
            start();
          },
          (error) => {
            active -= 1;
            operation.reject(error);
            start();
          }
        );
    }
  };
  return (callback) =>
    new Promise((resolvePromise, rejectPromise) => {
      pending.add({ callback, reject: rejectPromise, resolve: resolvePromise });
      start();
    });
}

async function fingerprintMaterialDirectory(label, unverifiedEntries) {
  // Toolchain trees can contain thousands of immutable headers and libraries. Bound hashing so a
  // changed-leaf session does not serialize every file, while keeping one deterministic entry per
  // path and avoiding unbounded descriptor or file-handle pressure.
  const entries = await mapBounded(
    unverifiedEntries,
    materialDirectoryReadConcurrency,
    async (entry) => {
      if (entry.type === "directory") return entry;
      const { absolutePath, ...materialEntry } = entry;
      return { ...materialEntry, ...(await hashFile(absolutePath)) };
    }
  );
  const size = entries.reduce((sum, entry) => sum + (entry.size ?? 0), 0);
  return {
    label,
    type: "directory",
    fileCount: entries.filter((entry) => entry.type === "file").length,
    size,
    sha256: fingerprintJson(entries),
  };
}

function materialFilesystemState(status, type) {
  return {
    changeTimeNanoseconds: status.ctimeNs.toString(),
    device: status.dev.toString(),
    group: status.gid.toString(),
    inode: status.ino.toString(),
    mode: status.mode.toString(),
    modificationTimeNanoseconds: status.mtimeNs.toString(),
    owner: status.uid.toString(),
    size: status.size.toString(),
    type,
  };
}

function sameMaterialFilesystemState(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

async function materialPathState(path, runFilesystemOperation) {
  const before = await runFilesystemOperation(() => fs.lstat(path, { bigint: true }));
  if (before.isSymbolicLink()) {
    let targetPath;
    try {
      targetPath = await runFilesystemOperation(() => fs.realpath(path));
    } catch (error) {
      throw new Error(`Convex Wasm artifact pipeline: material symbolic link changed: ${path}`, {
        cause: error,
      });
    }
    const target = await materialPathState(targetPath, runFilesystemOperation);
    const after = await runFilesystemOperation(() => fs.lstat(path, { bigint: true }));
    const link = materialFilesystemState(before, "symbolic-link");
    if (
      !after.isSymbolicLink() ||
      !sameMaterialFilesystemState(link, materialFilesystemState(after, "symbolic-link"))
    ) {
      fail(`material symbolic link changed while its state was read: ${path}`);
    }
    return { link, target, targetPath, type: "symbolic-link" };
  }
  if (before.isFile()) {
    return materialFilesystemState(before, "file");
  }
  if (!before.isDirectory()) {
    fail(`material path is not a regular file or directory: ${path}`);
  }
  const entries = await runFilesystemOperation(() => fs.readdir(path, { withFileTypes: true }));
  entries.sort((left, right) => compareStrings(left.name, right.name));
  // Recursive callbacks retain their parent worker while a subtree drains, so a nested map alone
  // would multiply filesystem concurrency at every level. The shared operation runner supplies one
  // overall bound without holding a permit across recursion, which would deadlock on directory-only
  // trees. mapBounded still returns siblings in sorted order and drains every admitted subtree.
  const children = await mapBounded(entries, materialDirectoryReadConcurrency, async (entry) => {
    const childPath = join(path, entry.name);
    if (entry.isSymbolicLink()) {
      fail(`material directory contains a symbolic link: ${childPath}`);
    }
    if (!entry.isDirectory() && !entry.isFile()) {
      fail(`material directory contains an unsupported filesystem entry: ${childPath}`);
    }
    return {
      name: entry.name,
      state: await materialPathState(childPath, runFilesystemOperation),
    };
  });
  const after = await runFilesystemOperation(() => fs.lstat(path, { bigint: true }));
  const directory = materialFilesystemState(before, "directory");
  if (
    !after.isDirectory() ||
    !sameMaterialFilesystemState(directory, materialFilesystemState(after, "directory"))
  ) {
    fail(`material directory changed while its state was read: ${path}`);
  }
  return { children, directory, type: "directory" };
}

function collectMaterialDirectoryEntries(root, current, state, entries) {
  for (const child of state.children) {
    const path = join(current, child.name);
    const relativePath = relative(root, path).split(sep).join("/");
    if (child.state.type === "directory") {
      entries.push({ path: `${relativePath}/`, type: "directory" });
      collectMaterialDirectoryEntries(root, path, child.state, entries);
      continue;
    }
    if (child.state.type !== "file") {
      fail(`material directory state contains an unsupported filesystem entry: ${path}`);
    }
    entries.push({ absolutePath: path, path: relativePath, type: "file" });
  }
}

async function fingerprintMaterialPathFromState(label, path, state) {
  if (state.type === "symbolic-link") {
    const target = await fingerprintMaterialPathFromState(label, state.targetPath, state.target);
    return {
      ...target,
      type: `symbolic-link-to-${target.type}`,
    };
  }
  if (state.type === "file") {
    return { label, type: "file", ...(await hashFile(path)) };
  }
  if (state.type !== "directory") {
    fail(`material path state is invalid: ${label} (${path})`);
  }
  // The pre-state already contains the same sorted tree inventory that a second readdir walk would
  // produce. Derive only path projections here; the complete post-hash state walk remains the
  // mutation fence.
  const unverifiedEntries = [];
  collectMaterialDirectoryEntries(path, path, state, unverifiedEntries);
  return await fingerprintMaterialDirectory(label, unverifiedEntries);
}

async function fingerprintMaterialPath(label, inputPath) {
  const path = resolve(requireString(inputPath, `material path ${label}`));
  let status;
  try {
    status = await fs.lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      fail(`material path does not exist: ${label} (${path})`);
    }
    throw error;
  }
  if (status.isSymbolicLink()) {
    let targetPath;
    try {
      targetPath = await fs.realpath(path);
    } catch (error) {
      throw new Error(
        `Convex Wasm artifact pipeline: material symbolic link cannot be resolved: ${label} (${path})`,
        { cause: error }
      );
    }
    const target = await fingerprintMaterialPath(label, targetPath);
    return {
      ...target,
      type: `symbolic-link-to-${target.type}`,
    };
  }
  if (status.isFile()) {
    return { label, type: "file", ...(await hashFile(path)) };
  }
  if (!status.isDirectory()) {
    fail(`material path is not a regular file or directory: ${label} (${path})`);
  }
  const unverifiedEntries = [];
  await walkMaterialDirectory(path, path, unverifiedEntries);
  return await fingerprintMaterialDirectory(label, unverifiedEntries);
}

async function fingerprintMaterialPaths(materialPaths, description, verificationMemo) {
  if (!Array.isArray(materialPaths)) {
    fail(`${description} must be an array`);
  }
  const verificationMemoRecord =
    verificationMemo === undefined
      ? undefined
      : materialPathVerificationMemos.get(verificationMemo);
  if (verificationMemo !== undefined && verificationMemoRecord === undefined) {
    fail(`${description} verification memo is invalid`);
  }
  const labels = new Set();
  const normalized = materialPaths.map((material, index) => {
    assertPlainObject(material, `${description}[${index}]`);
    assertExactKeys(material, new Set(["label", "path"]), `${description}[${index}]`);
    const label = requireString(material.label, `${description}[${index}].label`);
    if (labels.has(label)) {
      fail(`${description} contains duplicate label ${label}`);
    }
    labels.add(label);
    return {
      label,
      path: requireString(material.path, `${description}[${index}].path`),
    };
  });
  normalized.sort((left, right) => compareStrings(left.label, right.label));
  const runMaterialStateOperation = createBoundedOperationRunner(materialDirectoryReadConcurrency);
  const fingerprints = await mapBounded(
    normalized,
    materialPathHashConcurrency,
    async (material) => {
      if (verificationMemo === undefined) {
        return await fingerprintMaterialPath(material.label, material.path);
      }
      const path = resolve(material.path);
      const key = `${material.label}\0${path}`;
      const before = await materialPathState(path, runMaterialStateOperation);
      const cached = verificationMemoRecord.get(key);
      if (cached !== undefined) {
        assertPlainObject(cached, `${description} verification memo entry ${material.label}`);
        assertExactKeys(
          cached,
          new Set(["fingerprint", "label", "path", "state"]),
          `${description} verification memo entry ${material.label}`
        );
        if (cached.path !== path || cached.label !== material.label) {
          fail(`${description} verification memo entry ${material.label} is inconsistent`);
        }
        if (!Object.isFrozen(cached.fingerprint)) {
          fail(`${description} verification memo entry ${material.label} is corrupt`);
        }
        if (sameMaterialFilesystemState(cached.state, before)) {
          return cached.fingerprint;
        }
      }
      const fingerprint = Object.freeze(
        await fingerprintMaterialPathFromState(material.label, path, before)
      );
      const after = await materialPathState(path, runMaterialStateOperation);
      if (!sameMaterialFilesystemState(before, after)) {
        fail(`material path changed while it was fingerprinted: ${material.label} (${path})`);
      }
      verificationMemoRecord.set(key, {
        fingerprint,
        label: material.label,
        path,
        state: after,
      });
      return fingerprint;
    }
  );
  return {
    entries: fingerprints,
    sha256: fingerprintJson(fingerprints),
  };
}

export const convexWasmArtifactMaterialTestHooks = Object.freeze({ mapBounded });

export {
  ConvexWasmArtifactByteLimitError,
  createMaterialPathVerificationMemo,
  decodeUtf8,
  fingerprintMaterialPath,
  fingerprintMaterialPaths,
  hashFile,
  hashPrivateRegularFile,
  readAndHashMaterialFile,
  readAndHashPrivateRegularFile,
  readPrivateRegularFile,
  requirePrivateDirectory,
  sameFileContentState,
  sameFileIdentity,
};
