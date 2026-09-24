import { execFile } from "node:child_process";
import { createHash } from "node:crypto";

// Read object IDs, never mutable index paths. Raw blobs deliberately do not apply checkout
// filters, working-tree encodings, or line-ending conversion.
export async function readConvexWasmGitBlobMaterials(repoRoot, blobOids) {
  if (
    blobOids.length === 0 ||
    blobOids.some((oid) => !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(oid))
  ) {
    throw new Error("Convex Wasm Git blob request must contain complete object IDs");
  }
  const bytes = await new Promise((resolve, reject) => {
    const child = execFile(
      "git",
      ["--no-replace-objects", "cat-file", "--batch"],
      { cwd: repoRoot, encoding: "buffer", maxBuffer: 256 * 1024 * 1024, timeout: 30_000 },
      (error, stdout) => (error === null ? resolve(stdout) : reject(error))
    );
    child.stdin.on("error", reject);
    child.stdin.end(`${blobOids.join("\n")}\n`);
  });
  const materials = new Map();
  let offset = 0;
  for (const blobOid of blobOids) {
    const headerEnd = bytes.indexOf(10, offset);
    const header = bytes.subarray(offset, headerEnd).toString("ascii");
    const match = /^([0-9a-f]+) blob (0|[1-9][0-9]*)$/u.exec(header);
    if (headerEnd < offset || match === null || match[1] !== blobOid) {
      throw new Error("Convex Wasm Git blob response has an invalid object header");
    }
    const size = Number(match[2]);
    const end = headerEnd + 1 + size;
    if (!Number.isSafeInteger(size) || end >= bytes.length || bytes[end] !== 10) {
      throw new Error("Convex Wasm Git blob response has an invalid object size");
    }
    const contents = Buffer.from(bytes.subarray(headerEnd + 1, end));
    const objectOid = createHash(blobOid.length === 40 ? "sha1" : "sha256")
      .update(`blob ${size}\0`)
      .update(contents)
      .digest("hex");
    if (objectOid !== blobOid) {
      throw new Error("Convex Wasm Git blob content does not match its object ID");
    }
    materials.set(blobOid, {
      contents,
      gitBlobOid: blobOid,
      sha256: createHash("sha256").update(contents).digest("hex"),
      size,
    });
    offset = end + 1;
  }
  if (offset !== bytes.length) {
    throw new Error("Convex Wasm Git blob response contains unexpected trailing data");
  }
  return materials;
}
