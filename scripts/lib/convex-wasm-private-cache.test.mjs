import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  requirePrivateCacheDirectory,
  requirePrivateCacheDirectoryFileIdentities,
  requirePrivateCacheFile,
  withPrivateCacheAncestorValidation,
} from "./convex-wasm-private-cache.mjs";

async function createPrivateEntry(context) {
  const parent = await fs.realpath(tmpdir());
  const cacheRoot = await fs.mkdtemp(join(parent, "convex-wasm-private-cache-"));
  context.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const directory = join(cacheRoot, "entry");
  await fs.mkdir(directory, { mode: 0o700 });
  return { cacheRoot, directory };
}

test("authenticates private cache directories and files without following symlinks", async (context) => {
  const parent = await fs.realpath(tmpdir());
  const cacheRoot = await fs.mkdtemp(join(parent, "convex-wasm-private-cache-"));
  context.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const entryDirectory = join(cacheRoot, "profiles", "entry");
  await fs.mkdir(entryDirectory, { mode: 0o700, recursive: true });
  const materialPath = join(entryDirectory, "profile.js");
  await fs.writeFile(materialPath, "export default 1;\n", { mode: 0o600 });
  await requirePrivateCacheDirectory(cacheRoot, entryDirectory);
  await requirePrivateCacheFile(cacheRoot, materialPath);

  const linkedFile = join(entryDirectory, "linked.js");
  await fs.symlink(materialPath, linkedFile);
  await assert.rejects(
    requirePrivateCacheFile(cacheRoot, linkedFile),
    /must be a non-symlink file/u
  );
  const linkedDirectory = join(cacheRoot, "linked");
  await fs.symlink(entryDirectory, linkedDirectory, "dir");
  await assert.rejects(
    requirePrivateCacheDirectory(cacheRoot, linkedDirectory),
    /must be a non-symlink directory/u
  );
  await assert.rejects(
    requirePrivateCacheFile(cacheRoot, join(parent, "outside.js")),
    /escapes cache root/u
  );
  await fs.chmod(materialPath, 0o644);
  await assert.rejects(requirePrivateCacheFile(cacheRoot, materialPath), /must have mode 0600/u);
  assert.equal((await fs.stat(cacheRoot)).mode & 0o777, 0o700);
});

test("overlapping directory checks share only pending work and later calls check again", async (context) => {
  const { cacheRoot, directory } = await createPrivateEntry(context);
  const open = fs.open;
  let opens = 0;
  fs.open = async function (path, ...args) {
    if (path === cacheRoot) {
      opens += 1;
      // Hold the open long enough for sibling readers to reach the same ancestor check.
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return await open.call(this, path, ...args);
  };
  try {
    await Promise.all(Array.from({ length: 4 }, () =>
      requirePrivateCacheDirectory(cacheRoot, directory)
    ));
    assert.equal(opens, 1);
    await requirePrivateCacheDirectory(cacheRoot, directory);
    assert.equal(opens, 2);
    await fs.chmod(cacheRoot, 0o755);
    const failures = await Promise.allSettled(Array.from({ length: 4 }, () =>
      requirePrivateCacheDirectory(cacheRoot, directory)
    ));
    assert.ok(failures.every(({ status, reason }) =>
      status === "rejected" && /must have mode 0700/u.test(reason.message)
    ));
    await fs.chmod(cacheRoot, 0o700);
    await requirePrivateCacheDirectory(cacheRoot, directory);
    assert.equal(opens, 3);
  } finally {
    fs.open = open;
    await fs.chmod(cacheRoot, 0o700);
  }
});

test("binds direct file identities across a cache-entry read", async (context) => {
  const { cacheRoot, directory } = await createPrivateEntry(context);
  const materialPath = join(directory, "entry.json");
  await fs.writeFile(materialPath, "{}\n", { mode: 0o600 });
  const authenticated = await requirePrivateCacheDirectoryFileIdentities(cacheRoot, directory);
  assert.deepEqual(authenticated.names, ["entry.json"]);
  await authenticated.verify();
  await fs.writeFile(materialPath, '{"changed":true}\n');
  await assert.rejects(authenticated.verify(), /changed during file authentication/u);
});

test("inventory ancestor reuse rechecks permissions, replacements and later scopes", async (context) => {
  const { cacheRoot, directory } = await createPrivateEntry(context);
  const leaf = join(directory, "leaf");
  await fs.mkdir(leaf, { mode: 0o700 });
  const originalOpen = fs.open;
  let ancestorOpens = 0;
  fs.open = async function (path, ...args) {
    if (path === directory) ancestorOpens += 1;
    return await originalOpen.call(this, path, ...args);
  };
  try {
    await withPrivateCacheAncestorValidation(async () => {
      await requirePrivateCacheDirectory(cacheRoot, leaf);
      await requirePrivateCacheDirectory(cacheRoot, leaf);
      assert.equal(ancestorOpens, 1);
      await fs.chmod(directory, 0o755);
      await assert.rejects(requirePrivateCacheDirectory(cacheRoot, leaf), /must have mode 0700/u);
      await fs.chmod(directory, 0o700);
      await requirePrivateCacheDirectory(cacheRoot, leaf);
      assert.equal(ancestorOpens, 2);
      const prior = join(cacheRoot, "prior");
      await fs.rename(directory, prior);
      await fs.symlink(prior, directory);
      await assert.rejects(requirePrivateCacheDirectory(cacheRoot, leaf), /non-symlink directory/u);
      await fs.unlink(directory);
      await fs.mkdir(leaf, { recursive: true, mode: 0o700 });
      await requirePrivateCacheDirectory(cacheRoot, leaf);
      assert.equal(ancestorOpens, 3);
    });
    await withPrivateCacheAncestorValidation(() => requirePrivateCacheDirectory(cacheRoot, leaf));
    assert.equal(ancestorOpens, 4);
  } finally {
    fs.open = originalOpen;
  }
});

test("file identity verification drains member reads before returning a directory failure", async (context) => {
  const { cacheRoot, directory } = await createPrivateEntry(context);
  const materialPath = join(directory, "entry.json");
  await fs.writeFile(materialPath, "{}\n", { mode: 0o600 });
  const authenticated = await requirePrivateCacheDirectoryFileIdentities(cacheRoot, directory);
  const originalLstat = fs.lstat;
  const memberRead = Promise.withResolvers();
  const directoryFailure = new Error("synthetic directory read failure");
  let settled = false;
  fs.lstat = async (path, ...args) => {
    if (path === directory) throw directoryFailure;
    if (path === materialPath) await memberRead.promise;
    return await originalLstat(path, ...args);
  };
  const verification = authenticated.verify().then(
    () => { settled = true; },
    (error) => { settled = true; return error; }
  );
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
  } finally {
    memberRead.resolve();
    assert.equal(await verification, directoryFailure);
    fs.lstat = originalLstat;
  }
});

test("rejects a cache directory changed while its file inventory is captured", async (context) => {
  const { cacheRoot, directory } = await createPrivateEntry(context);
  await fs.writeFile(join(directory, "entry.json"), "{}\n", { mode: 0o600 });
  const originalReaddir = fs.readdir;
  let changed = false;
  fs.readdir = async (path, ...argumentsList) => {
    const names = await originalReaddir(path, ...argumentsList);
    if (!changed && path === directory) {
      changed = true;
      await fs.chmod(directory, 0o755);
    }
    return names;
  };
  try {
    await assert.rejects(
      async () => {
        const authenticated = await requirePrivateCacheDirectoryFileIdentities(cacheRoot, directory);
        await authenticated.verify();
      },
      /must have mode 0700/u
    );
  } finally {
    fs.readdir = originalReaddir;
  }
  assert.equal(changed, true);
});
