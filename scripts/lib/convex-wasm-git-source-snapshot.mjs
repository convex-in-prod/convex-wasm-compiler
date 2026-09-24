import { execFile as execFileCallback } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";

const execFile = promisify(execFileCallback);

export const convexWasmGitSourceSnapshotKind = "convex-wasm-git-source-snapshot-v1";

const TREE_OID_PATTERN = /^[0-9a-f]{40,64}$/u;
const OBJECT_FORMATS = new Set(["sha1", "sha256"]);
const MODE_PATTERN = /^[0-7]{6}$/u;
const OID_PATTERN = /^[0-9a-f]{40,64}$/u;
const SOURCE_SNAPSHOT_MAX_BYTES = 64 * 1024 * 1024;

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function fail(message) {
  throw new Error(`Convex Wasm Git source snapshot: ${message}`);
}

async function settleSnapshotParallel(promises, description) {
  const results = await Promise.allSettled(promises);
  const failures = results.filter((result) => result.status === "rejected");
  if (failures.length === 1) throw failures[0].reason;
  if (failures.length > 1) {
    throw new AggregateError(
      failures.map(({ reason }) => reason),
      description
    );
  }
  return results.map((result) => result.value);
}

function normalizeRepoRoot(repoRoot) {
  if (typeof repoRoot !== "string" || repoRoot.length === 0) {
    fail("repoRoot must be a non-empty path");
  }
  return resolve(repoRoot);
}

function normalizePathspecs(pathspecs, repoRoot) {
  if (!Array.isArray(pathspecs)) {
    fail("pathspecs must be an array");
  }
  const normalized = pathspecs.map((pathspec, index) => {
    if (typeof pathspec !== "string" || pathspec.length === 0 || pathspec.startsWith(":")) {
      fail(`pathspec ${index} must be a non-empty relative path`);
    }
    if (isAbsolute(pathspec)) {
      fail(`pathspec ${index} must be relative to repoRoot`);
    }
    const absolute = resolve(repoRoot, pathspec);
    const fromRoot = relative(repoRoot, absolute);
    if (
      fromRoot === ".." ||
      fromRoot.startsWith(`..${sep}`) ||
      isAbsolute(fromRoot) ||
      fromRoot.length === 0
    ) {
      fail(`pathspec ${index} escapes repoRoot`);
    }
    return fromRoot.split(sep).join("/");
  });
  return [...new Set(normalized)].sort();
}

function normalizeRelativePath(path, description) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("\0") ||
    path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    fail(`${description} must be a normalized non-empty relative path`);
  }
  return path;
}

function requirePlainArray(value, description) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    fail(`${description} must be an ordinary array`);
  }
  const keys = Reflect.ownKeys(value);
  const elementKeys = keys.slice(0, -1);
  if (
    keys.length !== value.length + 1 ||
    keys.at(-1) !== "length" ||
    elementKeys.some((key, index) => {
      if (key !== String(index)) return true;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor === undefined || !descriptor.enumerable || !("value" in descriptor);
    })
  ) {
    fail(`${description} must contain only dense enumerable data elements`);
  }
  return value;
}

function hasOnlyEnumerableDataFields(value) {
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== "string") return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && descriptor.enumerable && "value" in descriptor;
  });
}

function hasExactEnumerableDataKeys(value, keys) {
  return (
    hasOnlyEnumerableDataFields(value) &&
    Reflect.ownKeys(value).sort(compareStrings).join("\0") ===
      [...keys].sort(compareStrings).join("\0")
  );
}

function freezeSnapshotTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeSnapshotTree(nested);
    Object.freeze(value);
  }
  return value;
}

export function detachConvexWasmGitSourceSnapshot(snapshot, description = "source snapshot") {
  validateConvexWasmGitSourceSnapshot(snapshot, description);
  return freezeSnapshotTree(structuredClone(snapshot));
}

async function runGit(repoRoot, arguments_, description, maxBuffer = 16 * 1024 * 1024) {
  try {
    const result = await execFile("git", arguments_, {
      cwd: repoRoot,
      encoding: "utf8",
      maxBuffer,
    });
    return result.stdout;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    fail(`${description} failed: ${detail}`);
  }
}

export function convexWasmGitLiteralPathArguments(pathspecs) {
  if (!Array.isArray(pathspecs)) fail("Git literal pathspecs must be an array");
  // `--` ends option parsing but does not disable Git pathspec patterns. Keep normalized names in
  // snapshot identity while forcing literal semantics at every Git command boundary.
  return [
    "--",
    ...pathspecs.map(
      (path, index) => `:(literal)${normalizeRelativePath(path, `Git literal pathspec ${index}`)}`
    ),
  ];
}

function parseNulPaths(output, description) {
  const paths = output.split("\0").filter((path) => path.length > 0);
  return paths
    .map((path, index) => normalizeRelativePath(path, `${description} path ${index}`))
    .sort(compareStrings);
}

function parseIndexEntries(output) {
  const entries = output
    .split("\0")
    .filter((record) => record.length > 0)
    .map((record, index) => {
      const separator = record.indexOf("\t");
      if (separator <= 0 || separator === record.length - 1) {
        fail(`index record ${index} is malformed`);
      }
      const header = record.slice(0, separator).split(" ");
      if (header.length !== 3) {
        fail(`index record ${index} has an invalid header`);
      }
      const [mode, oid, stageText] = header;
      if (!MODE_PATTERN.test(mode) || !OID_PATTERN.test(oid)) {
        fail(`index record ${index} has an invalid mode or object ID`);
      }
      const stage = Number(stageText);
      if (!Number.isInteger(stage) || stage < 0 || stage > 3) {
        fail(`index record ${index} has an invalid merge stage`);
      }
      return {
        mode,
        oid,
        path: normalizeRelativePath(record.slice(separator + 1), `index record ${index}`),
        stage,
      };
    });
  entries.sort((left, right) =>
    left.path === right.path
      ? left.stage - right.stage ||
        compareStrings(left.mode, right.mode) ||
        compareStrings(left.oid, right.oid)
      : compareStrings(left.path, right.path)
  );
  for (let index = 1; index < entries.length; index += 1) {
    if (
      entries[index - 1].path === entries[index].path &&
      entries[index - 1].stage === entries[index].stage
    ) {
      fail(`index contains duplicate path/stage ${entries[index].path}`);
    }
  }
  return entries;
}

async function readTreeEntries(repoRoot, snapshot, description) {
  const output = await runGit(
    repoRoot,
    [
      "ls-tree",
      "-r",
      "-z",
      "--full-tree",
      snapshot.treeOid,
      ...convexWasmGitLiteralPathArguments(snapshot.pathspecs),
    ],
    description,
    SOURCE_SNAPSHOT_MAX_BYTES
  );
  const indexOutput = output
    .split("\0")
    .filter((record) => record.length > 0)
    .map((record, index) => {
      const separator = record.indexOf("\t");
      const header = separator === -1 ? [] : record.slice(0, separator).split(" ");
      if (
        header.length !== 3 ||
        separator === record.length - 1 ||
        (header[1] !== "blob" && header[1] !== "commit")
      ) {
        fail(`${description} returned malformed entry ${index}`);
      }
      return `${header[0]} ${header[2]} 0\t${record.slice(separator + 1)}`;
    })
    .join("\0");
  const entries = parseIndexEntries(indexOutput);
  const expectedOidLength = snapshot.objectFormat === "sha1" ? 40 : 64;
  if (entries.some((entry) => entry.oid.length !== expectedOidLength)) {
    fail(`${description} returned an object ID with the wrong length`);
  }
  return entries;
}

export function validateConvexWasmGitSourceSnapshot(snapshot, description = "source snapshot") {
  if (
    typeof snapshot !== "object" ||
    snapshot === null ||
    Array.isArray(snapshot) ||
    Object.getPrototypeOf(snapshot) !== Object.prototype
  ) {
    fail(`${description} must be an object`);
  }
  const expectedKeys = [
    "entries",
    "kind",
    "objectFormat",
    "pathspecs",
    "treeOid",
    "untrackedPaths",
    "unstagedPaths",
  ];
  const ownKeys = Reflect.ownKeys(snapshot);
  if (!hasOnlyEnumerableDataFields(snapshot)) {
    fail(`${description} must contain only enumerable data fields`);
  }
  const keys = ownKeys.sort();
  if (JSON.stringify(keys) !== JSON.stringify([...expectedKeys].sort())) {
    fail(`${description} has an unexpected shape`);
  }
  if (snapshot.kind !== convexWasmGitSourceSnapshotKind) {
    fail(`${description} kind is unsupported`);
  }
  if (!OBJECT_FORMATS.has(snapshot.objectFormat)) {
    fail(`${description} object format is unsupported`);
  }
  const expectedOidLength = snapshot.objectFormat === "sha1" ? 40 : 64;
  if (!TREE_OID_PATTERN.test(snapshot.treeOid) || snapshot.treeOid.length !== expectedOidLength) {
    fail(`${description} tree object ID is invalid`);
  }
  for (const [name, values] of [
    ["pathspecs", snapshot.pathspecs],
    ["unstagedPaths", snapshot.unstagedPaths],
    ["untrackedPaths", snapshot.untrackedPaths],
  ]) {
    requirePlainArray(values, `${description} ${name}`);
    for (const [index, value] of values.entries()) {
      normalizeRelativePath(value, `${description} ${name} ${index}`);
      if (name === "pathspecs" && value.startsWith(":")) {
        fail(`${description} pathspecs ${index} must not use Git pathspec magic`);
      }
    }
    for (let index = 1; index < values.length; index += 1) {
      if (values[index - 1] >= values[index]) {
        fail(`${description} ${name} must be sorted and unique`);
      }
    }
  }
  requirePlainArray(snapshot.entries, `${description} entries`);
  const parsedEntries = parseIndexEntries(
    snapshot.entries
      .map((entry, index) => {
        if (
          typeof entry !== "object" ||
          entry === null ||
          Array.isArray(entry) ||
          Object.getPrototypeOf(entry) !== Object.prototype ||
          !hasExactEnumerableDataKeys(entry, ["mode", "oid", "path", "stage"])
        ) {
          fail(`${description} entry ${index} must be an object`);
        }
        if (
          typeof entry.mode !== "string" ||
          typeof entry.oid !== "string" ||
          !Number.isInteger(entry.stage) ||
          typeof entry.path !== "string"
        ) {
          fail(`${description} entry ${index} has invalid fields`);
        }
        return `${entry.mode} ${entry.oid} ${entry.stage}\t${entry.path}`;
      })
      .join("\0")
  );
  if (canonicalJson(parsedEntries) !== canonicalJson(snapshot.entries)) {
    fail(`${description} entries must be sorted, unique, and canonical`);
  }
  if (parsedEntries.some((entry) => entry.oid.length !== expectedOidLength)) {
    fail(`${description} contains an object ID with the wrong length`);
  }
  return snapshot;
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

export async function readConvexWasmGitSourceSnapshotFile(path) {
  const normalizedPath = resolve(path);
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("source snapshot reads require O_NOFOLLOW");
  }
  const beforePath = await fs.lstat(normalizedPath);
  if (beforePath.isSymbolicLink() || !beforePath.isFile()) {
    fail(`source snapshot file is not a regular file: ${normalizedPath}`);
  }
  if ((beforePath.mode & 0o777) !== 0o600) {
    fail(`source snapshot file is not owner-only: ${normalizedPath}`);
  }
  if (typeof process.getuid === "function" && beforePath.uid !== process.getuid()) {
    fail(`source snapshot file is not owned by the current user: ${normalizedPath}`);
  }
  const handle = await fs.open(normalizedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileState(beforePath, opened)) {
      fail(`source snapshot file changed while it was opened: ${normalizedPath}`);
    }
    if (opened.size === 0 || opened.size > SOURCE_SNAPSHOT_MAX_BYTES) {
      fail(`source snapshot file exceeds its byte boundary: ${normalizedPath}`);
    }
    const contents = await handle.readFile();
    const [after, afterPath] = await settleSnapshotParallel(
      [handle.stat(), fs.lstat(normalizedPath)],
      "Convex Wasm Git source snapshot file-state verification failed"
    );
    if (
      contents.length !== opened.size ||
      !sameFileState(opened, after) ||
      afterPath.isSymbolicLink() ||
      !afterPath.isFile() ||
      !sameFileState(opened, afterPath)
    ) {
      fail(`source snapshot file changed while it was read: ${normalizedPath}`);
    }
    let snapshot;
    try {
      snapshot = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents));
    } catch (error) {
      throw new Error(`Convex Wasm Git source snapshot: source snapshot file is not JSON`, {
        cause: error,
      });
    }
    if (!contents.equals(Buffer.from(`${canonicalJson(snapshot)}\n`))) {
      fail("source snapshot file must contain canonical JSON followed by one newline");
    }
    validateConvexWasmGitSourceSnapshot(snapshot);
    return freezeSnapshotTree(snapshot);
  } finally {
    await handle.close();
  }
}

export async function publishConvexWasmGitSourceSnapshotFile({ outputPath, snapshot }) {
  // Encode a detached value before the first await. A caller mutation while the output directory
  // is being prepared must not change the authority that passed validation above this boundary.
  const authenticatedSnapshot = detachConvexWasmGitSourceSnapshot(snapshot, "source snapshot");
  const finalPath = resolve(outputPath);
  const directory = dirname(finalPath);
  const source = `${canonicalJson(authenticatedSnapshot)}\n`;
  if (Buffer.byteLength(source) > SOURCE_SNAPSHOT_MAX_BYTES) {
    fail("source snapshot exceeds its byte boundary");
  }
  await fs.mkdir(directory, { mode: 0o700, recursive: true });
  const temporaryPath = join(
    directory,
    `.${basename(finalPath)}.publish-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  try {
    const handle = await fs.open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(source);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await fs.link(temporaryPath, finalPath);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "EEXIST") {
        fail(`source snapshot output already exists: ${finalPath}`);
      }
      throw error;
    }
    const directoryHandle = await fs.open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
    return finalPath;
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
}

function sameArray(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameEntries(left, right) {
  return sameArray(left, right);
}

async function readWorktreeState(repoRoot, pathspecs) {
  const arguments_ = convexWasmGitLiteralPathArguments(pathspecs);
  const [unstagedOutput, untrackedOutput] = await settleSnapshotParallel(
    [
      runGit(repoRoot, ["diff", "--name-only", "-z", ...arguments_], "unstaged path inspection"),
      runGit(
        repoRoot,
        ["ls-files", "--others", "--exclude-standard", "-z", ...arguments_],
        "untracked path inspection"
      ),
    ],
    "Convex Wasm Git source snapshot worktree inspection failed"
  );
  return {
    untrackedPaths: parseNulPaths(untrackedOutput, "untracked"),
    unstagedPaths: parseNulPaths(unstagedOutput, "unstaged"),
  };
}

async function captureOnce(repoRoot, pathspecs) {
  const objectFormat = (
    await runGit(
      repoRoot,
      ["rev-parse", "--show-object-format=storage"],
      "object-format inspection",
      1024 * 1024
    )
  ).trim();
  if (!OBJECT_FORMATS.has(objectFormat)) {
    fail(`Git reported unsupported object format ${JSON.stringify(objectFormat)}`);
  }
  const treeOid = (
    await runGit(repoRoot, ["write-tree"], "staged tree capture", 1024 * 1024)
  ).trim();
  const expectedOidLength = objectFormat === "sha1" ? 40 : 64;
  if (!TREE_OID_PATTERN.test(treeOid) || treeOid.length !== expectedOidLength) {
    fail("Git returned an invalid staged tree object ID");
  }
  // Derive entries from the captured immutable tree, not a later read of the index.
  // A subsequent git add belongs to another capture and cannot change these entries.
  const entries = await readTreeEntries(
    repoRoot,
    { objectFormat, pathspecs, treeOid },
    "staged tree identity inspection"
  );
  return { entries, objectFormat, treeOid };
}

export async function captureConvexWasmGitSourceSnapshot({
  pathspecs = [],
  repoRoot,
  requireClean = true,
} = {}) {
  const normalizedRoot = normalizeRepoRoot(repoRoot);
  const normalizedPathspecs = normalizePathspecs(pathspecs, normalizedRoot);
  if (typeof requireClean !== "boolean") fail("requireClean must be a boolean");
  const topLevel = (
    await runGit(
      normalizedRoot,
      ["rev-parse", "--show-toplevel"],
      "repository-root inspection",
      1024 * 1024
    )
  ).trim();
  if (resolve(topLevel) !== normalizedRoot) {
    fail(`repoRoot is not the Git worktree root: ${normalizedRoot}`);
  }
  const beforeState = await readWorktreeState(normalizedRoot, normalizedPathspecs);
  if (
    requireClean &&
    (beforeState.unstagedPaths.length > 0 || beforeState.untrackedPaths.length > 0)
  ) {
    fail("deploy-input worktree has unstaged or untracked paths");
  }
  const captured = await captureOnce(normalizedRoot, normalizedPathspecs);
  const afterState = await readWorktreeState(normalizedRoot, normalizedPathspecs);
  if (
    !sameArray(beforeState.unstagedPaths, afterState.unstagedPaths) ||
    !sameArray(beforeState.untrackedPaths, afterState.untrackedPaths)
  ) {
    fail("the worktree changed while the staged source snapshot was captured");
  }
  const snapshot = {
    entries: captured.entries,
    kind: convexWasmGitSourceSnapshotKind,
    objectFormat: captured.objectFormat,
    pathspecs: normalizedPathspecs,
    treeOid: captured.treeOid,
    untrackedPaths: beforeState.untrackedPaths,
    unstagedPaths: beforeState.unstagedPaths,
  };
  validateConvexWasmGitSourceSnapshot(snapshot);
  return freezeSnapshotTree(snapshot);
}

export async function verifyConvexWasmGitSourceSnapshot(snapshot, { repoRoot } = {}) {
  const authenticatedSnapshot = detachConvexWasmGitSourceSnapshot(snapshot, "source snapshot");
  if (
    authenticatedSnapshot.unstagedPaths.length > 0 ||
    authenticatedSnapshot.untrackedPaths.length > 0
  ) {
    fail("cannot verify a snapshot that was captured with dirty deploy inputs");
  }
  // A scoped current-index comparison cannot by itself authenticate the recorded full-tree OID.
  // Read that immutable tree object as well so a stale or foreign OID cannot enter certificate,
  // source-graph, or high-fanout identity while unrelated staged paths remain deliberately free.
  const [current, admittedTreeEntries] = await settleSnapshotParallel(
    [
      captureConvexWasmGitSourceSnapshot({
        pathspecs: authenticatedSnapshot.pathspecs,
        repoRoot,
        requireClean: true,
      }),
      readTreeEntries(repoRoot, authenticatedSnapshot, "admitted tree identity inspection"),
    ],
    "Convex Wasm Git source snapshot verification failed"
  );
  if (!sameEntries(admittedTreeEntries, authenticatedSnapshot.entries)) {
    fail("the admitted tree object disagrees with its source snapshot entries");
  }
  if (
    current.objectFormat !== authenticatedSnapshot.objectFormat ||
    !sameArray(current.pathspecs, authenticatedSnapshot.pathspecs) ||
    !sameEntries(current.entries, authenticatedSnapshot.entries)
  ) {
    fail("the staged source snapshot changed before publication");
  }
  // A scoped snapshot is used for deploy inputs, whose guard intentionally permits unrelated
  // staged changes. The full tree object remains useful for tree diffs, but those unrelated paths
  // must not invalidate the scoped material cache.
  if (
    authenticatedSnapshot.pathspecs.length === 0 &&
    current.treeOid !== authenticatedSnapshot.treeOid
  ) {
    fail("the staged source snapshot changed before publication");
  }
  return current;
}

export async function diffConvexWasmGitSourceSnapshots({
  fromSnapshot,
  pathspecs,
  repoRoot,
  toSnapshot,
}) {
  const authenticatedFromSnapshot = detachConvexWasmGitSourceSnapshot(
    fromSnapshot,
    "from source snapshot"
  );
  const authenticatedToSnapshot = detachConvexWasmGitSourceSnapshot(
    toSnapshot,
    "to source snapshot"
  );
  if (authenticatedFromSnapshot.objectFormat !== authenticatedToSnapshot.objectFormat) {
    fail("cannot diff snapshots with different Git object formats");
  }
  if (
    authenticatedFromSnapshot.pathspecs.join("\0") !== authenticatedToSnapshot.pathspecs.join("\0")
  ) {
    fail("cannot diff snapshots captured with different pathspecs");
  }
  const normalizedRoot = normalizeRepoRoot(repoRoot);
  const normalizedPathspecs =
    pathspecs === undefined
      ? authenticatedFromSnapshot.pathspecs
      : normalizePathspecs(pathspecs, normalizedRoot);
  if (normalizedPathspecs.join("\0") !== authenticatedFromSnapshot.pathspecs.join("\0")) {
    fail("diff pathspecs do not match the source snapshots");
  }
  const output = await runGit(
    normalizedRoot,
    [
      "diff-tree",
      "--no-commit-id",
      "--name-status",
      "-r",
      "-z",
      authenticatedFromSnapshot.treeOid,
      authenticatedToSnapshot.treeOid,
      ...convexWasmGitLiteralPathArguments(normalizedPathspecs),
    ],
    "staged tree diff"
  );
  const tokens = output.split("\0").filter((token) => token.length > 0);
  const changes = [];
  for (let index = 0; index < tokens.length; ) {
    const status = tokens[index++];
    if (!/^[ACDMRTUXB][0-9]*$/u.test(status)) {
      fail("tree diff returned an invalid change status");
    }
    if (index >= tokens.length) {
      fail("tree diff returned a status without a path");
    }
    const path = normalizeRelativePath(tokens[index++], "tree diff path");
    const change = { path, status };
    if (status.startsWith("R") || status.startsWith("C")) {
      change.previousPath = path;
      if (index >= tokens.length) {
        fail("tree diff returned a rename or copy without a destination path");
      }
      change.path = normalizeRelativePath(tokens[index++], "tree diff destination path");
    }
    changes.push(change);
  }
  return changes.sort((left, right) =>
    left.path === right.path
      ? left.status.localeCompare(right.status)
      : left.path.localeCompare(right.path)
  );
}

export const convexWasmGitSourceSnapshotTestHooks = Object.freeze({
  parseIndexEntries,
  validateSnapshot: validateConvexWasmGitSourceSnapshot,
});
