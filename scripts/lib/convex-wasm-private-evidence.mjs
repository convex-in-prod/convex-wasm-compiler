import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";

export const convexWasmPrivateEvidenceMaxBytes = 64 * 1024 * 1024;

function fail(description, message) {
  throw new Error(`${description}: ${message}`);
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function requireOwnerControlledParent(path, description) {
  if (typeof process.getuid !== "function") fail(description, "requires ownership checks");
  const currentUid = BigInt(process.getuid());
  let current = dirname(path);
  if ((await fs.realpath(current)) !== current) fail(description, "parent path must be canonical");
  while (true) {
    const status = await fs.lstat(current, { bigint: true });
    const rootOwnedStickyDirectory =
      status.uid === 0n && (status.mode & 0o1000n) !== 0n && (status.mode & 0o022n) !== 0n;
    if (
      !status.isDirectory() ||
      (await fs.realpath(current)) !== current ||
      ![0n, currentUid].includes(status.uid) ||
      ((status.mode & 0o022n) !== 0n && !rootOwnedStickyDirectory)
    ) {
      fail(description, "parent path is not canonical and owner-controlled");
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return currentUid;
}

export async function readConvexWasmPrivateEvidence(
  path,
  description,
  maximumBytes = convexWasmPrivateEvidenceMaxBytes
) {
  if (
    typeof path !== "string" ||
    resolve(path) !== path ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes <= 0
  ) {
    fail(description, "requires an absolute normalized path and a positive size limit");
  }
  if (fsConstants.O_NOFOLLOW === undefined) fail(description, "requires O_NOFOLLOW");
  const currentUid = await requireOwnerControlledParent(path, description);
  const [canonicalPath, initial] = await Promise.all([
    fs.realpath(path),
    fs.lstat(path, { bigint: true }),
  ]);
  if (
    canonicalPath !== path ||
    !initial.isFile() ||
    initial.uid !== currentUid ||
    (initial.mode & 0o7777n) !== 0o600n ||
    initial.size <= 0n ||
    initial.size > BigInt(maximumBytes)
  ) {
    fail(description, "must be a current-user-owned canonical bounded mode-0600 file");
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameFileState(initial, opened)) {
      fail(description, "changed before it was read");
    }
    const bytes = Buffer.allocUnsafe(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) fail(description, "changed while it was read");
      offset += read.bytesRead;
    }
    const trailing = await handle.read(Buffer.allocUnsafe(1), 0, 1, offset);
    const [after, finalPath, finalCanonicalPath] = await Promise.all([
      handle.stat({ bigint: true }),
      fs.lstat(path, { bigint: true }),
      fs.realpath(path),
    ]);
    if (
      trailing.bytesRead !== 0 ||
      !sameFileState(opened, after) ||
      !finalPath.isFile() ||
      !sameFileState(opened, finalPath) ||
      finalCanonicalPath !== path
    ) {
      fail(description, "changed while it was read");
    }
    return Object.freeze({
      bytes,
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.length,
    });
  } finally {
    await handle.close();
  }
}

export async function readConvexWasmPrivateEvidenceJson(
  path,
  description,
  maximumBytes = convexWasmPrivateEvidenceMaxBytes
) {
  const evidence = await readConvexWasmPrivateEvidence(path, description, maximumBytes);
  let value;
  try {
    value = JSON.parse(evidence.bytes.toString("utf8"));
  } catch {
    fail(description, "is not JSON");
  }
  if (!evidence.bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) {
    fail(description, "is not canonical JSON followed by one newline");
  }
  return Object.freeze({ ...evidence, value });
}
