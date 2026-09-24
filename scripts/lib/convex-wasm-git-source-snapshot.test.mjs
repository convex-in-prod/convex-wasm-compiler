import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  captureConvexWasmGitSourceSnapshot,
  diffConvexWasmGitSourceSnapshots,
  publishConvexWasmGitSourceSnapshotFile,
  readConvexWasmGitSourceSnapshotFile,
  verifyConvexWasmGitSourceSnapshot,
  convexWasmGitSourceSnapshotTestHooks,
} from "./convex-wasm-git-source-snapshot.mjs";

async function createGitFixture({ objectFormat = "sha1" } = {}) {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-git-source-snapshot-"));
  execFileSync(
    "git",
    ["init", "-q", ...(objectFormat === "sha1" ? [] : [`--object-format=${objectFormat}`])],
    { cwd: root }
  );
  execFileSync("git", ["config", "user.email", "snapshot@example.invalid"], { cwd: root });
  execFileSync("git", ["config", "user.name", "Snapshot Test"], { cwd: root });
  await fs.mkdir(join(root, "convex"));
  await fs.writeFile(join(root, "convex", "a.ts"), "export const a = 1;\n");
  await fs.writeFile(join(root, "convex", "b.ts"), "export const b = 1;\n");
  execFileSync("git", ["add", "convex"], { cwd: root });
  return root;
}

test("captures and verifies a clean staged tree with mode and blob identities", async () => {
  const root = await createGitFixture();
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  assert.equal(snapshot.kind, "convex-wasm-git-source-snapshot-v1");
  assert.equal(snapshot.objectFormat, "sha1");
  assert.deepEqual(snapshot.pathspecs, ["convex"]);
  assert.deepEqual(snapshot.unstagedPaths, []);
  assert.deepEqual(snapshot.untrackedPaths, []);
  assert.equal(Object.isFrozen(snapshot.entries), true);
  assert.equal(Object.isFrozen(snapshot.entries[0]), true);
  assert.equal(Object.isFrozen(snapshot.pathspecs), true);
  assert.deepEqual(
    snapshot.entries.map(({ mode, path, stage }) => ({ mode, path, stage })),
    [
      { mode: "100644", path: "convex/a.ts", stage: 0 },
      { mode: "100644", path: "convex/b.ts", stage: 0 },
    ]
  );
  await verifyConvexWasmGitSourceSnapshot(snapshot, { repoRoot: root });
});

test("captures and verifies a SHA-256 Git object-format snapshot", async (t) => {
  const root = await createGitFixture({ objectFormat: "sha256" });
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });

  assert.equal(snapshot.objectFormat, "sha256");
  assert.equal(snapshot.treeOid.length, 64);
  assert.ok(snapshot.entries.every(({ oid: entryOid }) => entryOid.length === 64));
  await verifyConvexWasmGitSourceSnapshot(snapshot, { repoRoot: root });
});

test("rejects unstaged and untracked deploy inputs", async () => {
  const root = await createGitFixture();
  await fs.writeFile(join(root, "convex", "a.ts"), "export const a = 2;\n");
  await assert.rejects(
    captureConvexWasmGitSourceSnapshot({ pathspecs: ["convex"], repoRoot: root }),
    /unstaged or untracked paths/u
  );
  execFileSync("git", ["add", "convex/a.ts"], { cwd: root });
  await fs.writeFile(join(root, "convex", "untracked.ts"), "export const u = 1;\n");
  await assert.rejects(
    captureConvexWasmGitSourceSnapshot({ pathspecs: ["convex"], repoRoot: root }),
    /unstaged or untracked paths/u
  );
});

test("diffs staged trees to the changed-path oracle", async () => {
  const root = await createGitFixture();
  const before = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  await fs.writeFile(join(root, "convex", "a.ts"), "export const a = 2;\n");
  await fs.rm(join(root, "convex", "b.ts"));
  await fs.writeFile(join(root, "convex", "c.ts"), "export const c = 1;\n");
  execFileSync("git", ["add", "-A", "convex"], { cwd: root });
  const after = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  assert.deepEqual(
    await diffConvexWasmGitSourceSnapshots({
      fromSnapshot: before,
      repoRoot: root,
      toSnapshot: after,
    }),
    [
      { path: "convex/a.ts", status: "M" },
      { path: "convex/b.ts", status: "D" },
      { path: "convex/c.ts", status: "A" },
    ]
  );
});

test("treats normalized pathspecs as literal repository paths", async (t) => {
  const root = await createGitFixture();
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const literalPath = "convex/source*.ts";
  const matchingTrackedPath = "convex/source-match.ts";
  await fs.writeFile(join(root, literalPath), "export const literal = 1;\n");
  await fs.writeFile(join(root, matchingTrackedPath), "export const matching = 1;\n");
  execFileSync("git", ["add", literalPath, matchingTrackedPath], { cwd: root });
  await fs.writeFile(join(root, "convex/source-untracked.ts"), "unrelated\n");

  const before = await captureConvexWasmGitSourceSnapshot({
    pathspecs: [literalPath],
    repoRoot: root,
  });
  assert.deepEqual(before.pathspecs, [literalPath]);
  assert.deepEqual(
    before.entries.map(({ path }) => path),
    [literalPath],
    "Git glob syntax in a repository name must not widen the captured index scope"
  );
  assert.deepEqual(before.untrackedPaths, []);

  await fs.writeFile(join(root, literalPath), "export const literal = 2;\n");
  await fs.writeFile(join(root, matchingTrackedPath), "export const matching = 2;\n");
  execFileSync("git", ["add", literalPath, matchingTrackedPath], { cwd: root });
  const after = await captureConvexWasmGitSourceSnapshot({
    pathspecs: [literalPath],
    repoRoot: root,
  });
  assert.deepEqual(
    after.entries.map(({ path }) => path),
    [literalPath]
  );
  assert.deepEqual(
    await diffConvexWasmGitSourceSnapshots({
      fromSnapshot: before,
      repoRoot: root,
      toSnapshot: after,
    }),
    [{ path: literalPath, status: "M" }]
  );

  await fs.writeFile(join(root, matchingTrackedPath), "export const matching = 3;\n");
  execFileSync("git", ["add", matchingTrackedPath], { cwd: root });
  await verifyConvexWasmGitSourceSnapshot(after, { repoRoot: root });
});

test("fails closed when the staged tree changes before publication", async () => {
  const root = await createGitFixture();
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  await fs.writeFile(join(root, "convex", "a.ts"), "export const a = 2;\n");
  execFileSync("git", ["add", "convex/a.ts"], { cwd: root });
  await assert.rejects(
    verifyConvexWasmGitSourceSnapshot(snapshot, { repoRoot: root }),
    /staged source snapshot changed/u
  );
});

test("rejects non-canonical path and index identities before Git verification", async () => {
  const root = await createGitFixture();
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  assert.throws(
    () =>
      convexWasmGitSourceSnapshotTestHooks.validateSnapshot({
        ...snapshot,
        pathspecs: ["convex/a.ts", "convex"],
      }),
    /pathspecs must be sorted and unique/u
  );
  assert.throws(
    () =>
      convexWasmGitSourceSnapshotTestHooks.validateSnapshot({
        ...snapshot,
        pathspecs: [":(exclude)convex"],
      }),
    /must not use Git pathspec magic/u
  );
  assert.throws(
    () =>
      convexWasmGitSourceSnapshotTestHooks.validateSnapshot({
        ...snapshot,
        entries: [...snapshot.entries].reverse(),
      }),
    /entries must be sorted, unique, and canonical/u
  );
  assert.throws(
    () =>
      convexWasmGitSourceSnapshotTestHooks.validateSnapshot({
        ...snapshot,
        entries: snapshot.entries.map((entry) => ({ ...entry, extra: true })),
      }),
    /entry 0 must be an object/u
  );
  assert.throws(
    () =>
      convexWasmGitSourceSnapshotTestHooks.validateSnapshot(
        Object.assign(Object.create({ inherited: true }), snapshot)
      ),
    /source snapshot must be an object/u
  );
  const nonEnumerableExtra = { ...snapshot };
  Object.defineProperty(nonEnumerableExtra, "extra", { value: true });
  assert.throws(
    () => convexWasmGitSourceSnapshotTestHooks.validateSnapshot(nonEnumerableExtra),
    /only enumerable data fields/u
  );
  const accessorPathspecs = [];
  Object.defineProperty(accessorPathspecs, "0", {
    enumerable: true,
    get() {
      return "convex";
    },
  });
  accessorPathspecs.length = 1;
  assert.throws(
    () =>
      convexWasmGitSourceSnapshotTestHooks.validateSnapshot({
        ...snapshot,
        pathspecs: accessorPathspecs,
      }),
    /dense enumerable data elements/u,
    "an accessor must not change snapshot authority between validation and detachment"
  );
});

test("scoped verification permits unrelated staged paths", async () => {
  const root = await createGitFixture();
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  await fs.writeFile(join(root, "README.md"), "unrelated staged input\n");
  execFileSync("git", ["add", "README.md"], { cwd: root });
  await verifyConvexWasmGitSourceSnapshot(snapshot, { repoRoot: root });
});

test("scoped verification rejects a tree OID whose covered entries belong to another tree", async (t) => {
  const root = await createGitFixture();
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  await fs.writeFile(join(root, "convex", "a.ts"), "export const a = 2;\n");
  execFileSync("git", ["add", "convex/a.ts"], { cwd: root });
  const otherTree = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  await fs.writeFile(join(root, "convex", "a.ts"), "export const a = 1;\n");
  execFileSync("git", ["add", "convex/a.ts"], { cwd: root });

  await assert.rejects(
    verifyConvexWasmGitSourceSnapshot(
      { ...structuredClone(snapshot), treeOid: otherTree.treeOid },
      { repoRoot: root }
    ),
    /admitted tree object disagrees with its source snapshot entries/u
  );
  await assert.rejects(
    verifyConvexWasmGitSourceSnapshot(
      { ...structuredClone(snapshot), treeOid: "f".repeat(40) },
      { repoRoot: root }
    ),
    /admitted tree identity inspection failed/u,
    "an unknown but well-formed tree OID must not grant snapshot authority"
  );
});

test("publishes and reads one private canonical source-snapshot authority", async (t) => {
  const root = await createGitFixture();
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const snapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: ["convex"],
    repoRoot: root,
  });
  const outputPath = join(root, "snapshot-authority.json");
  const mutableSnapshot = structuredClone(snapshot);
  const expectedSnapshot = structuredClone(snapshot);
  const publication = publishConvexWasmGitSourceSnapshotFile({
    outputPath,
    snapshot: mutableSnapshot,
  });
  mutableSnapshot.entries[0].oid = "f".repeat(40);
  mutableSnapshot.pathspecs[0] = "convex/a.ts";
  await publication;

  const publishedSnapshot = await readConvexWasmGitSourceSnapshotFile(outputPath);
  assert.deepEqual(publishedSnapshot, expectedSnapshot);
  assert.equal(Object.isFrozen(publishedSnapshot.entries), true);
  assert.equal(Object.isFrozen(publishedSnapshot.entries[0]), true);
  assert.equal(Object.isFrozen(publishedSnapshot.pathspecs), true);
  assert.equal((await fs.stat(outputPath)).mode & 0o777, 0o600);
  await assert.rejects(
    publishConvexWasmGitSourceSnapshotFile({ outputPath, snapshot }),
    /output already exists/u
  );

  await fs.chmod(outputPath, 0o644);
  await assert.rejects(readConvexWasmGitSourceSnapshotFile(outputPath), /not owner-only/u);
});
