import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { writeConvexWasmStaticHermesMemberArchive } from "./convex-wasm-static-hermes-member-archive.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("writes a deterministic archive with canonical member names and padding", async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-member-archive-"));
  context.after(() => fs.rm(directory, { force: true, recursive: true }));
  const members = [Buffer.from("abc"), Buffer.from("defg")];
  const paths = members.map((_, index) => join(directory, `input-${String(index)}.o`));
  await Promise.all(paths.map((path, index) => fs.writeFile(path, members[index], { mode: 0o600 })));
  const archivePath = join(directory, "members.a");
  const identity = await writeConvexWasmStaticHermesMemberArchive(
    archivePath,
    paths.map((path, index) => ({ path, sha256: sha256(members[index]), size: members[index].length })),
    ["member-00000.o", "member-00001.o"],
    { identifyOutput: true }
  );
  const archive = await fs.readFile(archivePath);
  assert.deepEqual(identity, { sha256: sha256(archive), size: archive.length });
  assert.equal(archive.subarray(0, 8).toString("ascii"), "!<arch>\n");
  assert.equal(archive.subarray(8, 24).toString("ascii").trim(), "member-00000.o/");
  assert.equal(archive.subarray(68, 71).toString("ascii"), "abc");
  assert.equal(archive[71], 10);
  assert.equal(archive.subarray(72, 88).toString("ascii").trim(), "member-00001.o/");
  assert.equal(archive.subarray(132, 136).toString("ascii"), "defg");
});

test("removes an incomplete archive when member bytes do not match their identity", async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-member-archive-"));
  context.after(() => fs.rm(directory, { force: true, recursive: true }));
  const memberPath = join(directory, "input.o");
  const archivePath = join(directory, "members.a");
  await fs.writeFile(memberPath, "bad", { mode: 0o600 });
  await assert.rejects(
    writeConvexWasmStaticHermesMemberArchive(
      archivePath,
      [{ path: memberPath, sha256: sha256("abc"), size: 3 }],
      ["member-00000.o"]
    ),
    /changed while archiving/u
  );
  await assert.rejects(fs.lstat(archivePath), { code: "ENOENT" });
});
