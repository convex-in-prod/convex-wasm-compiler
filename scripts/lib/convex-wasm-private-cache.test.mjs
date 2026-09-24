import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  requirePrivateCacheDirectory,
  requirePrivateCacheDirectoryFileIdentities,
  requirePrivateCacheFile,
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
