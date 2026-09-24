import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readConvexWasmGitBlobMaterials } from "./convex-wasm-git-blob-material.mjs";

test("Git blob batches preserve raw bytes, digest empty files, and ignore replacement refs", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-git-blobs-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  execFileSync("git", ["init", "--quiet", root]);
  const sources = [Buffer.from("a\0b\r\nc\n"), Buffer.alloc(0), Buffer.from("replacement")];
  const oids = sources.map((input) =>
    execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: root,
      encoding: "utf8",
      input,
    }).trim()
  );
  execFileSync("git", ["replace", oids[0], oids[2]], { cwd: root });
  const materials = await readConvexWasmGitBlobMaterials(root, oids);
  assert.equal(materials.size, 3);
  for (const [index, oid] of oids.entries()) {
    assert.deepEqual(materials.get(oid), {
      contents: sources[index],
      gitBlobOid: oid,
      sha256: createHash("sha256").update(sources[index]).digest("hex"),
      size: sources[index].length,
    });
  }
  await assert.rejects(
    readConvexWasmGitBlobMaterials(root, ["0".repeat(40)]),
    /invalid object header/u
  );
  await assert.rejects(
    readConvexWasmGitBlobMaterials(root, ["HEAD:file.ts"]),
    /complete object IDs/u
  );
});

test("Git blob batches reject corrupted stored objects", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-git-blob-corruption-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  execFileSync("git", ["init", "--quiet", root]);
  const oids = ["original", "modified"].map((input) =>
    execFileSync("git", ["hash-object", "-w", "--stdin"], {
      cwd: root,
      encoding: "utf8",
      input,
    }).trim()
  );
  const paths = oids.map((oid) => join(root, ".git", "objects", oid.slice(0, 2), oid.slice(2)));
  await fs.chmod(paths[0], 0o600);
  await fs.copyFile(paths[1], paths[0]);
  await assert.rejects(
    readConvexWasmGitBlobMaterials(root, [oids[0]]),
    /does not match its object ID/u
  );
});
