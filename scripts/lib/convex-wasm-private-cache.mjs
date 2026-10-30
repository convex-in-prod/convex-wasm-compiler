import { AsyncLocalStorage } from "node:async_hooks";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

const PRIVATE_CACHE_FILE_IDENTITY_CONCURRENCY = 4;
const pendingPrivateDirectoryChecks = new Map();
const privateAncestorValidation = new AsyncLocalStorage();

export function withPrivateCacheAncestorValidation(operation) {
  return privateAncestorValidation.run(new Map(), operation);
}

function fail(message) {
  throw new Error(`Convex Wasm private cache: ${message}`);
}

function requireNormalizedAbsolutePath(path, description) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) {
    fail(`${description} must be a normalized absolute path`);
  }
}

function isInside(root, path) {
  const fromRoot = relative(root, path);
  return (
    fromRoot === "" ||
    (fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot))
  );
}

function currentUserId() {
  if (typeof process.getuid !== "function") {
    fail("private cache validation requires process.getuid()");
  }
  return process.getuid();
}

function sameEntry(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function privateFileIdentity(status) {
  return Object.freeze({
    dev: status.dev,
    ino: status.ino,
    mode: status.mode,
    mtimeMs: status.mtimeMs,
    size: status.size,
    uid: status.uid,
  });
}

function samePrivateDirectory(left, right) {
  return (
    sameEntry(left, right) &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.uid === right.uid &&
    (left.mode & 0o7777) === (right.mode & 0o7777)
  );
}

function samePrivateFile(left, right) {
  return (
    sameEntry(left, right) &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.uid === right.uid &&
    left.mode === right.mode
  );
}

async function mapPrivateCacheFiles(names, operation) {
  const results = new Array(names.length);
  const failures = new Map();
  let nextIndex = 0;
  let stopped = false;
  await Promise.all(
    Array.from(
      { length: Math.min(PRIVATE_CACHE_FILE_IDENTITY_CONCURRENCY, names.length) },
      async () => {
        while (!stopped && nextIndex < names.length) {
          const index = nextIndex;
          nextIndex += 1;
          try {
            results[index] = await operation(names[index], index);
          } catch (error) {
            failures.set(index, error);
            stopped = true;
          }
        }
      }
    )
  );
  if (failures.size > 0) throw failures.get(Math.min(...failures.keys()));
  return results;
}

function requireEntry(status, path, type, mode, uid) {
  const validType = type === "directory" ? status.isDirectory() : status.isFile();
  if (status.isSymbolicLink() || !validType) {
    fail(`${path} must be a non-symlink ${type}`);
  }
  if (status.uid !== uid) {
    fail(`${path} must be owned by the current user`);
  }
  if ((status.mode & 0o7777) !== mode) {
    fail(`${path} must have mode ${mode.toString(8).padStart(4, "0")}`);
  }
}

function requireStablePrivateEntry(path, type, mode, uid) {
  if (type !== "directory") return checkStablePrivateEntry(path, type, mode, uid);
  const key = `${uid}\0${mode}\0${path}`;
  let pending = pendingPrivateDirectoryChecks.get(key);
  if (pending === undefined) {
    // Parallel artifact readers walk the same ancestors. Share only an in-flight directory
    // check, never a completed result: subsequent before/after fences must reopen the path.
    pending = Promise.resolve().then(() => checkStablePrivateEntry(path, type, mode, uid));
    pendingPrivateDirectoryChecks.set(key, pending);
    const clear = () => {
      if (pendingPrivateDirectoryChecks.get(key) === pending) pendingPrivateDirectoryChecks.delete(key);
    };
    void pending.then(clear, clear);
  }
  return pending;
}

async function checkStablePrivateEntry(path, type, mode, uid) {
  const beforePath = await fs.lstat(path);
  requireEntry(beforePath, path, type, mode, uid);
  if (fsConstants.O_NOFOLLOW === undefined || fsConstants.O_DIRECTORY === undefined) {
    fail("private cache validation requires O_NOFOLLOW and O_DIRECTORY");
  }
  const typeFlag = type === "directory" ? fsConstants.O_DIRECTORY : 0;
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | typeFlag);
  try {
    const opened = await handle.stat();
    requireEntry(opened, path, type, mode, uid);
    if (beforePath.dev !== opened.dev || beforePath.ino !== opened.ino) {
      fail(`${path} changed while it was opened`);
    }
    const afterPath = await fs.lstat(path);
    requireEntry(afterPath, path, type, mode, uid);
    if (opened.dev !== afterPath.dev || opened.ino !== afterPath.ino) {
      fail(`${path} changed during validation`);
    }
    return afterPath;
  } finally {
    await handle.close();
  }
}

async function requirePrivateAncestor(path, uid) {
  const scope = privateAncestorValidation.getStore();
  if (scope === undefined) return requireStablePrivateEntry(path, "directory", 0o700, uid);
  const current = await fs.lstat(path);
  requireEntry(current, path, "directory", 0o700, uid);
  const previous = scope.get(path);
  // A locked inventory repeatedly traverses the same few ancestors. Every traversal still
  // checks current inode, ownership, mode and timestamps; only an unchanged directory can
  // reuse its earlier open/fstat/path proof. Leaf directories and files keep their full checks.
  if (previous !== undefined && samePrivateDirectory(previous, current)) return;
  scope.set(path, await requireStablePrivateEntry(path, "directory", 0o700, uid));
}

async function requireNoSymlinkAncestors(path) {
  const { root } = parse(path);
  let current = root;
  for (const component of path.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, component);
    const status = await fs.lstat(current);
    if (status.isSymbolicLink()) {
      fail(`${path} traverses a symbolic link at ${current}`);
    }
    if (!status.isDirectory()) {
      fail(`${path} has a non-directory ancestor at ${current}`);
    }
  }
}

async function requirePrivateDirectories(cacheRoot, directory, uid) {
  if (!isInside(cacheRoot, directory)) {
    fail(`${directory} escapes cache root ${cacheRoot}`);
  }
  await requireNoSymlinkAncestors(dirname(cacheRoot));
  let current = cacheRoot;
  if (current === directory) await requireStablePrivateEntry(current, "directory", 0o700, uid);
  else await requirePrivateAncestor(current, uid);
  for (const component of relative(cacheRoot, directory).split(sep).filter(Boolean)) {
    current = join(current, component);
    if (current === directory) await requireStablePrivateEntry(current, "directory", 0o700, uid);
    else await requirePrivateAncestor(current, uid);
  }
}

export async function requirePrivateCacheDirectory(cacheRoot, directory) {
  requireNormalizedAbsolutePath(cacheRoot, "cache root");
  requireNormalizedAbsolutePath(directory, "cache directory");
  await requirePrivateDirectories(cacheRoot, directory, currentUserId());
}

export async function requirePrivateCacheFile(cacheRoot, path) {
  requireNormalizedAbsolutePath(cacheRoot, "cache root");
  requireNormalizedAbsolutePath(path, "cache file");
  if (!isInside(cacheRoot, path) || path === cacheRoot) {
    fail(`${path} escapes cache root ${cacheRoot}`);
  }
  const uid = currentUserId();
  await requirePrivateDirectories(cacheRoot, dirname(path), uid);
  await requireStablePrivateEntry(path, "file", 0o600, uid);
}

// Authenticate the directory and direct file inventory before reads, then verify the same
// identities afterward so replacements cannot survive the cache validation boundary.
export async function requirePrivateCacheDirectoryFileIdentities(cacheRoot, directory) {
  requireNormalizedAbsolutePath(cacheRoot, "cache root");
  requireNormalizedAbsolutePath(directory, "cache directory");
  if (!isInside(cacheRoot, directory) || directory === cacheRoot) {
    fail(`${directory} escapes cache root ${cacheRoot}`);
  }
  const uid = currentUserId();
  let initialDirectory;
  try {
    initialDirectory = await fs.lstat(directory);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      try {
        await requirePrivateDirectories(cacheRoot, dirname(directory), uid);
      } catch (ancestorError) {
        if (
          !(ancestorError instanceof Error && "code" in ancestorError && ancestorError.code === "ENOENT")
        ) {
          throw ancestorError;
        }
      }
      return undefined;
    }
    throw error;
  }
  requireEntry(initialDirectory, directory, "directory", 0o700, uid);
  await requirePrivateDirectories(cacheRoot, directory, uid);
  const authenticatedDirectory = await fs.lstat(directory);
  requireEntry(authenticatedDirectory, directory, "directory", 0o700, uid);
  if (!samePrivateDirectory(initialDirectory, authenticatedDirectory)) {
    fail(`${directory} changed during validation`);
  }
  const names = (await fs.readdir(directory)).sort();
  const identityPairs = await mapPrivateCacheFiles(names, async (name) => {
    const path = join(directory, name);
    const status = await fs.lstat(path);
    requireEntry(status, path, "file", 0o600, uid);
    return [name, privateFileIdentity(status)];
  });
  const fileIdentities = new Map(identityPairs);
  const verify = async () => {
    // A failed directory read must not let a caller release the cache lock while admitted
    // member checks are still reading that tree.
    const checks = await Promise.allSettled([
      fs.lstat(directory),
      mapPrivateCacheFiles(names, async (name) => {
        const path = join(directory, name);
        const status = await fs.lstat(path);
        requireEntry(status, path, "file", 0o600, uid);
        if (!samePrivateFile(fileIdentities.get(name), status)) {
          fail(`${path} changed during file authentication`);
        }
      }),
    ]);
    const failure = checks.find(({ status }) => status === "rejected");
    if (failure !== undefined) throw failure.reason;
    const currentDirectory = checks[0].value;
    requireEntry(currentDirectory, directory, "directory", 0o700, uid);
    if (!samePrivateDirectory(authenticatedDirectory, currentDirectory)) {
      fail(`${directory} changed during file authentication`);
    }
  };
  return { fileIdentities, names, verify };
}
