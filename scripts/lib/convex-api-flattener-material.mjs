import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function toPosix(path) {
  return path.split(sep).join("/");
}

function canonicalPathForHost(path, platform) {
  const canonicalPath = realpathSync(path);
  return platform === "darwin" || platform === "win32"
    ? canonicalPath.toLowerCase()
    : canonicalPath;
}

export function convexApiPathsIdentifySameFile(left, right, platform = process.platform) {
  return canonicalPathForHost(left, platform) === canonicalPathForHost(right, platform);
}

function checkedMaterialPath(path) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    isAbsolute(path) ||
    path.includes("\\") ||
    path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw new Error(`Invalid installed generator material path: ${String(path)}`);
  }
  return path;
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function capturedInstalledState(status) {
  return Object.freeze({
    dev: status.dev,
    ino: status.ino,
    mode: status.mode,
    uid: status.uid,
    gid: status.gid,
    nlink: status.nlink,
    size: status.size,
    mtimeNs: status.mtimeNs,
    ctimeNs: status.ctimeNs,
  });
}

function readStableInstalledFile(path, captureDigest) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error(`Installed generator material is not a regular file: ${path}`);
  }
  if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`Installed generator material is too large to capture: ${path}`);
  }
  if (fsConstants.O_NOFOLLOW === undefined) {
    throw new Error("Installed generator material validation requires O_NOFOLLOW");
  }
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameFileState(before, opened)) {
      throw new Error(`Installed generator material changed while it was opened: ${path}`);
    }
    const contents = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const afterPath = lstatSync(path, { bigint: true });
    if (
      !afterPath.isFile() ||
      afterPath.isSymbolicLink() ||
      !sameFileState(opened, after) ||
      !sameFileState(after, afterPath) ||
      BigInt(contents.length) !== after.size
    ) {
      throw new Error(`Installed generator material changed while it was read: ${path}`);
    }
    const result = {
      contents,
      // Special permission bits are authority too. Masking them out would let a complete
      // authority-free recapture match an identity produced before a setuid/setgid/sticky change.
      mode: Number(after.mode & 0o7777n),
      size: Number(after.size),
      state: capturedInstalledState(after),
    };
    if (captureDigest) {
      result.sha256 = createHash("sha256").update(contents).digest("hex");
    }
    return result;
  } finally {
    closeSync(descriptor);
  }
}

function readStableInstalledSymlink(path) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isSymbolicLink()) {
    throw new Error(`Installed generator material is not a symbolic link: ${path}`);
  }
  const target = readlinkSync(path);
  const after = lstatSync(path, { bigint: true });
  if (!sameFileState(before, after)) {
    throw new Error(`Installed generator material changed while it was read: ${path}`);
  }
  return { state: capturedInstalledState(after), target };
}

function readStableInstalledDirectory(path) {
  const before = lstatSync(path, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new Error(`Installed generator material is not a directory: ${path}`);
  }
  const entries = readdirSync(path, { withFileTypes: true })
    .map((entry) => {
      const kind = entry.isDirectory()
        ? "directory"
        : entry.isFile()
          ? "file"
          : entry.isSymbolicLink()
            ? "symlink"
            : undefined;
      if (kind === undefined) {
        throw new Error(`Unsupported installed generator material at ${join(path, entry.name)}`);
      }
      return { kind, name: entry.name };
    })
    .sort((left, right) => compareStrings(left.name, right.name));
  const after = lstatSync(path, { bigint: true });
  if (!sameFileState(before, after)) {
    throw new Error(`Installed generator material changed while it was read: ${path}`);
  }
  return { entries, state: capturedInstalledState(after) };
}

export function convexApiInstalledLayoutSha256({ nodeModulesRoot }) {
  const { contents } = readStableInstalledFile(
    join(resolve(nodeModulesRoot), ".package-lock.json")
  );
  return createHash("sha256").update(contents).digest("hex");
}

function treeMaterialPaths(root, current, paths, activeDirectories = new Set()) {
  const canonicalDirectory = realpathSync(current);
  if (activeDirectories.has(canonicalDirectory)) {
    throw new Error(`Installed generator material contains a directory cycle at ${current}`);
  }
  activeDirectories.add(canonicalDirectory);
  try {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) =>
      compareStrings(left.name, right.name)
    )) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        // Directory modes are installed-material authority too. Retain every traversed
        // directory as a material record so a writable compiler ancestor cannot reuse an
        // identity produced for a protected tree with the same file bytes.
        paths.push(toPosix(relative(root, path)));
        treeMaterialPaths(root, path, paths, activeDirectories);
      } else if (entry.isFile()) {
        paths.push(toPosix(relative(root, path)));
      } else if (entry.isSymbolicLink()) {
        paths.push(toPosix(relative(root, path)));
        const targetStatus = statSync(path, { bigint: true });
        if (targetStatus.isDirectory()) {
          treeMaterialPaths(root, path, paths, activeDirectories);
        } else if (!targetStatus.isFile()) {
          throw new Error(`Unsupported installed generator material at ${path}`);
        }
      } else {
        throw new Error(`Unsupported installed generator material at ${path}`);
      }
    }
  } finally {
    activeDirectories.delete(canonicalDirectory);
  }
}

export function convexApiCompilerMaterialPaths({
  arch = process.arch,
  nodeModulesRoot,
  platform = process.platform,
}) {
  const root = resolve(nodeModulesRoot);
  const paths = [];
  for (const packagePath of [
    "typescript",
    "typescript-native",
    `@typescript/typescript-${platform}-${arch}`,
  ]) {
    const packageRoot = join(root, packagePath);
    // The package root itself is not encountered by treeMaterialPaths. Include either its
    // directory state or its symlink/target state before walking descendants.
    paths.push(packagePath);
    treeMaterialPaths(root, packageRoot, paths);
  }
  return [...new Set(paths)].sort(compareStrings);
}

export function convexApiProgramMaterialPaths({ nodeModulesRoot, sourceFileNames }) {
  const root = resolve(nodeModulesRoot);
  const paths = [];
  const directoryPaths = new Set();
  const packageJsonPaths = new Set();
  for (const sourceFileName of sourceFileNames) {
    const sourcePath = resolve(sourceFileName);
    const materialPath = relative(root, sourcePath);
    if (materialPath === ".." || materialPath.startsWith(`..${sep}`) || isAbsolute(materialPath)) {
      continue;
    }
    paths.push(toPosix(materialPath));
    let current = dirname(sourcePath);
    while (current !== root && current.startsWith(`${root}${sep}`)) {
      directoryPaths.add(toPosix(relative(root, current)));
      const packageJsonPath = join(current, "package.json");
      try {
        if (lstatSync(packageJsonPath, { bigint: true }).isFile()) {
          packageJsonPaths.add(toPosix(relative(root, packageJsonPath)));
          break;
        }
      } catch (error) {
        if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
          throw error;
        }
      }
      current = dirname(current);
    }
  }
  return [...new Set([...paths, ...directoryPaths, ...packageJsonPaths])].sort(compareStrings);
}

function walkConvexApiInstalledMaterial({
  captureRegularFiles,
  arch = process.arch,
  materialPaths,
  nodeModulesRoot,
  nodeVersion = process.version,
  platform = process.platform,
}) {
  const root = resolve(nodeModulesRoot);
  const rootBefore = lstatSync(root, { bigint: true });
  let rootAuthority;
  if (!rootBefore.isSymbolicLink() && rootBefore.isDirectory()) {
    const { entries, state } = readStableInstalledDirectory(root);
    if (!sameFileState(rootBefore, state)) {
      throw new Error(`Installed generator material root changed while it was read: ${root}`);
    }
    rootAuthority = {
      entries: Object.freeze(entries.map((entry) => Object.freeze({ ...entry }))),
      kind: "directory",
      state,
    };
  } else if (rootBefore.isSymbolicLink()) {
    const { state, target } = readStableInstalledSymlink(root);
    const targetPath = realpathSync(root);
    const targetState = lstatSync(targetPath, { bigint: true });
    if (targetState.isSymbolicLink() || !targetState.isDirectory()) {
      throw new Error(`Installed generator material root has an unsupported target: ${root}`);
    }
    rootAuthority = {
      kind: "symlink",
      state,
      target,
      targetKind: "directory",
      targetPath,
      targetState: capturedInstalledState(targetState),
    };
  } else {
    throw new Error(`Installed generator material root is not a directory: ${root}`);
  }
  const normalizedPaths = [...new Set(materialPaths.map(checkedMaterialPath))].sort(compareStrings);
  const hash = createHash("sha256");
  hash.update("convex-api-installed-material-v1\0");
  hash.update(`${rootAuthority.kind}-root\0`);
  hash.update(Number(rootAuthority.state.mode & 0o7777n).toString(8));
  hash.update("\0");
  if (rootAuthority.kind === "symlink") {
    hash.update(rootAuthority.target);
    hash.update("\0");
    hash.update(Number(rootAuthority.targetState.mode & 0o7777n).toString(8));
    hash.update("\0");
  }
  let bytes = 0;
  const regularFiles = [];
  const verificationRecords = [];
  for (const materialPath of normalizedPaths) {
    const path = join(root, materialPath);
    const status = lstatSync(path, { bigint: true });
    if (status.isFile()) {
      // The compatibility identity only needs the aggregate hash; capture the per-file digest
      // when the producer explicitly requests reusable records.
      const { contents, mode, sha256, size, state } = readStableInstalledFile(
        path,
        captureRegularFiles
      );
      bytes += contents.length;
      hash.update("file\0");
      hash.update(materialPath);
      hash.update("\0");
      hash.update(mode.toString(8));
      hash.update("\0");
      hash.update(contents);
      hash.update("\0");
      if (captureRegularFiles) {
        regularFiles.push({
          materialPath,
          path,
          sha256,
          size,
          state: Object.freeze(state),
        });
        verificationRecords.push({ kind: "file", path, state });
      }
    } else if (status.isDirectory()) {
      const { entries, state } = readStableInstalledDirectory(path);
      hash.update("directory\0");
      hash.update(materialPath);
      hash.update("\0");
      hash.update(Number(state.mode & 0o7777n).toString(8));
      hash.update("\0");
      for (const entry of entries) {
        bytes += Buffer.byteLength(entry.name);
        hash.update(entry.kind);
        hash.update("\0");
        hash.update(entry.name);
        hash.update("\0");
      }
      if (captureRegularFiles) {
        verificationRecords.push({
          entries: Object.freeze(entries.map((entry) => Object.freeze({ ...entry }))),
          kind: "directory",
          path,
          state,
        });
      }
    } else if (status.isSymbolicLink()) {
      const { state: linkState, target } = readStableInstalledSymlink(path);
      bytes += Buffer.byteLength(target);
      hash.update("symlink\0");
      hash.update(materialPath);
      hash.update("\0");
      hash.update(target);
      hash.update("\0");
      hash.update(Number(linkState.mode & 0o7777n).toString(8));
      hash.update("\0");
      const targetPath = realpathSync(path);
      const targetStatus = lstatSync(targetPath, { bigint: true });
      if (targetStatus.isFile()) {
        const { contents, mode, state } = readStableInstalledFile(targetPath, false);
        bytes += contents.length;
        hash.update("file-target\0");
        hash.update(mode.toString(8));
        hash.update("\0");
        hash.update(contents);
        hash.update("\0");
        if (captureRegularFiles) {
          verificationRecords.push({
            kind: "symlink",
            path,
            state: linkState,
            target,
            targetKind: "file",
            targetPath,
            targetState: state,
          });
        }
      } else if (targetStatus.isDirectory()) {
        hash.update("directory-target\0");
        hash.update(Number(targetStatus.mode & 0o7777n).toString(8));
        hash.update("\0");
        if (captureRegularFiles) {
          verificationRecords.push({
            kind: "symlink",
            path,
            state: linkState,
            target,
            targetKind: "directory",
            targetPath,
            targetState: capturedInstalledState(targetStatus),
          });
        }
      } else {
        throw new Error(`Unsupported installed generator material at ${path}`);
      }
      const finalLinkState = lstatSync(path, { bigint: true });
      if (
        !finalLinkState.isSymbolicLink() ||
        !sameFileState(linkState, finalLinkState) ||
        readlinkSync(path) !== target
      ) {
        throw new Error(`Installed generator material changed while it was read: ${path}`);
      }
    } else {
      throw new Error(`Installed generator material is not a file: ${path}`);
    }
  }
  const finalRootState = lstatSync(root, { bigint: true });
  if (rootAuthority.kind === "directory") {
    if (
      finalRootState.isSymbolicLink() ||
      !finalRootState.isDirectory() ||
      !sameFileState(rootAuthority.state, finalRootState)
    ) {
      throw new Error(`Installed generator material root changed while it was read: ${root}`);
    }
  } else {
    const finalTargetPath = realpathSync(root);
    const finalTargetState = lstatSync(finalTargetPath, { bigint: true });
    if (
      !finalRootState.isSymbolicLink() ||
      !sameFileState(rootAuthority.state, finalRootState) ||
      readlinkSync(root) !== rootAuthority.target ||
      finalTargetPath !== rootAuthority.targetPath ||
      finalTargetState.isSymbolicLink() ||
      !finalTargetState.isDirectory() ||
      !sameFileState(rootAuthority.targetState, finalTargetState)
    ) {
      throw new Error(`Installed generator material root changed while it was read: ${root}`);
    }
  }
  return {
    identity: Object.freeze({
      arch,
      bytes,
      fileCount: normalizedPaths.length,
      kind: "convex-api-installed-material-v1",
      nodeModulesSha256: hash.digest("hex"),
      nodeVersion,
      platform,
    }),
    regularFiles: Object.freeze(
      regularFiles
        .sort((left, right) => compareStrings(left.materialPath, right.materialPath))
        .map((record) => Object.freeze(record))
    ),
    rootAuthority: Object.freeze({ ...rootAuthority, path: root }),
    rootKind: rootAuthority.kind,
    verificationRecords: Object.freeze(verificationRecords.map((record) => Object.freeze(record))),
  };
}

export function captureConvexApiInstalledMaterial(options) {
  return walkConvexApiInstalledMaterial({ ...options, captureRegularFiles: true });
}

export function convexApiInstalledMaterialIdentity(options) {
  return walkConvexApiInstalledMaterial({ ...options, captureRegularFiles: false }).identity;
}

export function convexApiFlattenerInputIdentity({
  configPath,
  installedMaterialIdentity,
  repositoryInputSha256,
}) {
  const identity = {
    configPath,
    generator: "scripts/flatten-convex-api.mjs",
    installedMaterialIdentity,
    kind: "convex-api-flattener-input-v1",
    repositoryInputSha256,
  };
  const inputSha256 = createHash("sha256").update(JSON.stringify(identity)).digest("hex");
  return {
    identity: { ...identity, inputSha256 },
    inputSha256,
  };
}
