import { constants as fsConstants, promises as fs } from "node:fs";

// Node does not expose O_PATH in fs.constants, but Linux supports it for opening a directory
// whose owner bits were completely masked by an inherited umask. The normal path uses O_RDONLY;
// O_PATH is only a compatibility fallback for that mode-000 case.
const LINUX_O_PATH = 0x200000;

function isCode(error, code) {
  return error instanceof Error && "code" in error && error.code === code;
}

function requireOwnedDirectoryState(state, directory, description, ownerUid) {
  if (!state.isDirectory() || state.isSymbolicLink()) {
    throw new Error(`${description} is not a directory: ${directory}`);
  }
  if (state.uid !== ownerUid) {
    throw new Error(`${description} is not owned by the current user: ${directory}`);
  }
}

/**
 * Normalize one directory through an opened no-follow descriptor and fence the pathname against
 * replacement. Callers should pass the lstat result taken before opening; this keeps chmod scoped
 * to the inode whose creation or authority they just established.
 */
export async function normalizePrivateDirectoryMode(
  initialState,
  directory,
  description = "directory",
  ownerUid = process.getuid()
) {
  requireOwnedDirectoryState(initialState, directory, description, ownerUid);
  let handle;
  let pathOnly = false;
  try {
    handle = await fs.open(
      directory,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
    );
  } catch (error) {
    // A mode-000 directory cannot be opened read-only even by its owner. O_PATH pins the inode
    // without requiring read/execute permission; chmod through its procfd link remains anchored
    // to that descriptor and therefore cannot follow a replacement at the requested pathname.
    if (process.platform !== "linux" || !isCode(error, "EACCES")) throw error;
    handle = await fs.open(
      directory,
      LINUX_O_PATH | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
    );
    pathOnly = true;
  }
  try {
    const opened = await handle.stat();
    if (
      !opened.isDirectory() ||
      opened.isSymbolicLink() ||
      opened.uid !== ownerUid ||
      opened.dev !== initialState.dev ||
      opened.ino !== initialState.ino
    ) {
      throw new Error(`${description} changed while it was opened: ${directory}`);
    }
    if ((opened.mode & 0o777) !== 0o700) {
      if (pathOnly) {
        await fs.chmod(`/proc/self/fd/${handle.fd}`, 0o700);
      } else {
        await handle.chmod(0o700);
      }
    }
    const normalized = await handle.stat();
    const pathState = await fs.lstat(directory);
    if (
      !normalized.isDirectory() ||
      normalized.isSymbolicLink() ||
      normalized.uid !== ownerUid ||
      (normalized.mode & 0o777) !== 0o700 ||
      pathState.isSymbolicLink() ||
      !pathState.isDirectory() ||
      pathState.uid !== ownerUid ||
      pathState.dev !== normalized.dev ||
      pathState.ino !== normalized.ino ||
      pathState.mode !== normalized.mode
    ) {
      throw new Error(`${description} changed while its mode was normalized: ${directory}`);
    }
    return normalized;
  } finally {
    await handle.close();
  }
}

/**
 * Create each missing component of an absolute directory path and normalize only components for
 * which this call received the successful mkdir result. Existing caller-owned parents are never
 * chmoded, while a restrictive umask cannot strand a newly-created component at mode 000 before
 * the next child is created.
 */
export async function ensureCreatedPrivateDirectoryPath(directory, description = "directory") {
  if (typeof directory !== "string" || !directory.startsWith("/")) {
    throw new Error(`${description} must be an absolute path`);
  }
  const components = directory.split("/").filter((component) => component.length > 0);
  let current = "";
  for (const component of components) {
    current += `/${component}`;
    try {
      await fs.mkdir(current, { mode: 0o700 });
    } catch (error) {
      if (isCode(error, "EEXIST")) continue;
      throw error;
    }
    const state = await fs.lstat(current);
    await normalizePrivateDirectoryMode(state, current, description);
  }
}
