import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";

import { fail, requireSha256 } from "./convex-wasm-artifact-contract.mjs";
import {
  immutableCacheHashBufferBytes,
  sameFileContentState,
} from "./convex-wasm-artifact-material.mjs";

const WASM_ARCHIVE_MAGIC = Buffer.from("!<arch>\n", "ascii");
const MEMBER_NAME_PATTERN = /^member-[0-9]{5}\.o$/u;

function archiveField(value, width) {
  const text = String(value);
  if (text.length > width) {
    fail(`Wasm archive field ${JSON.stringify(text)} exceeds its ${String(width)}-byte width`);
  }
  return Buffer.from(text.padEnd(width, " "), "ascii");
}

function archiveMemberHeader(name, size) {
  // Fixed short member names need neither a long-name table nor a mutable symbol index.
  // GNU ar numeric fields contain decimal digits followed by spaces. LLVM rejects right-aligned
  // values even though some general ar readers accept them.
  return Buffer.concat([
    archiveField(`${name}/`, 16),
    archiveField(0, 12),
    archiveField(0, 6),
    archiveField(0, 6),
    archiveField("100644", 8),
    archiveField(size, 10),
    Buffer.from("`\n", "ascii"),
  ]);
}

export async function writeConvexWasmStaticHermesMemberArchive(
  outputPath,
  memberObjects,
  objectNames,
  { identifyOutput = false } = {}
) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("Static Hermes C bundle member archive reads require O_NOFOLLOW");
  }
  if (
    !Array.isArray(memberObjects) ||
    !Array.isArray(objectNames) ||
    memberObjects.length !== objectNames.length ||
    memberObjects.length === 0
  ) {
    fail("Static Hermes C bundle archive members and names are inconsistent");
  }
  for (const [index, objectName] of objectNames.entries()) {
    const expectedName = `member-${String(index).padStart(5, "0")}.o`;
    if (objectName !== expectedName || !MEMBER_NAME_PATTERN.test(objectName)) {
      fail(`Static Hermes C bundle archive member name is not canonical: ${String(objectName)}`);
    }
  }
  const output = await fs.open(
    outputPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600
  );
  const outputHash = identifyOutput ? createHash("sha256") : undefined;
  let outputSize = 0;
  let constructed = false;
  const write = async (bytes) => {
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await output.write(bytes, offset);
      if (bytesWritten <= 0) fail("Static Hermes C bundle archive write made no progress");
      offset += bytesWritten;
    }
    outputHash?.update(bytes);
    outputSize += bytes.length;
  };
  try {
    await write(WASM_ARCHIVE_MAGIC);
    for (const [index, memberObject] of memberObjects.entries()) {
      const objectName = objectNames[index];
      if (
        typeof memberObject !== "object" ||
        memberObject === null ||
        typeof memberObject.path !== "string" ||
        memberObject.path.length === 0 ||
        !Number.isSafeInteger(memberObject.size) ||
        memberObject.size <= 0 ||
        typeof memberObject.sha256 !== "string"
      ) {
        fail(`Static Hermes C bundle archive member object metadata is invalid: ${objectName}`);
      }
      requireSha256(
        memberObject.sha256,
        `Static Hermes C bundle member object ${objectName} SHA-256`
      );
      const beforePath = await fs.lstat(memberObject.path);
      if (
        beforePath.isSymbolicLink() ||
        !beforePath.isFile() ||
        beforePath.size !== memberObject.size
      ) {
        fail(
          `Static Hermes C bundle member object is not the authenticated file: ${memberObject.path}`
        );
      }
      const input = await fs.open(memberObject.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
      try {
        const before = await input.stat();
        if (
          !before.isFile() ||
          !sameFileContentState(beforePath, before) ||
          before.size !== memberObject.size
        ) {
          fail(`Static Hermes C bundle member object changed before archiving: ${objectName}`);
        }
        await write(archiveMemberHeader(objectName, memberObject.size));
        const hash = createHash("sha256");
        const buffer = Buffer.allocUnsafe(
          Math.max(1, Math.min(immutableCacheHashBufferBytes, memberObject.size))
        );
        let copied = 0;
        while (copied < memberObject.size) {
          const { bytesRead } = await input.read(
            buffer,
            0,
            Math.min(buffer.length, memberObject.size - copied),
            copied
          );
          if (bytesRead <= 0) {
            fail(`Static Hermes C bundle member object changed while archiving: ${objectName}`);
          }
          const chunk = buffer.subarray(0, bytesRead);
          hash.update(chunk);
          await write(chunk);
          copied += bytesRead;
        }
        const [after, afterPath] = await Promise.all([input.stat(), fs.lstat(memberObject.path)]);
        if (
          copied !== memberObject.size ||
          !sameFileContentState(before, after) ||
          after.uid !== before.uid ||
          after.mode !== before.mode ||
          afterPath.isSymbolicLink() ||
          !afterPath.isFile() ||
          !sameFileContentState(after, afterPath) ||
          hash.digest("hex") !== memberObject.sha256
        ) {
          fail(`Static Hermes C bundle member object changed while archiving: ${objectName}`);
        }
      } finally {
        await input.close();
      }
      if (memberObject.size % 2 !== 0) await write(Buffer.from("\n", "ascii"));
    }
    await output.sync();
    constructed = true;
  } finally {
    let closed = false;
    try {
      await output.close();
      closed = true;
    } finally {
      // O_EXCL guarantees this path was created by this writer. Remove an incomplete archive so
      // callers that retain a failed scratch directory cannot mistake it for a usable artifact.
      if (!constructed || !closed) await fs.rm(outputPath, { force: true });
    }
  }
  return outputHash === undefined
    ? undefined
    : { sha256: outputHash.digest("hex"), size: outputSize };
}
