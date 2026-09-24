import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmArtifactMaterialTestHooks,
  createMaterialPathVerificationMemo,
  fingerprintMaterialPath,
  fingerprintMaterialPaths,
  hashPrivateRegularFile,
  immutableCacheHashBufferBytes,
  readAndHashMaterialFile,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";

function deferred() {
  let reject;
  let resolve;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    reject = rejectPromise;
    resolve = resolvePromise;
  });
  return { promise, reject, resolve };
}

test("reads and hashes a private regular file across fixed-size buffers", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-artifact-material-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const path = join(root, "artifact.bin");
  const contents = Buffer.alloc(immutableCacheHashBufferBytes * 2 + 17, 0xa5);
  await fs.writeFile(path, contents, { mode: 0o600 });

  assert.deepEqual(await readPrivateRegularFile(path, contents.length, "test artifact"), contents);
  assert.deepEqual(await hashPrivateRegularFile(path, contents.length, "test artifact"), {
    sha256: createHash("sha256").update(contents).digest("hex"),
    size: contents.length,
  });
});

test("bounds a retained file read to its authenticated pre-read size", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-artifact-growing-material-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const path = join(root, "artifact.bin");
  const contents = Buffer.from("bounded");
  await fs.writeFile(path, contents, { mode: 0o600 });

  const originalOpen = fs.open;
  let appended = false;
  let eofDrivenRead = false;
  fs.open = async (openedPath, ...argumentsList) => {
    const handle = await originalOpen(openedPath, ...argumentsList);
    if (openedPath !== path) return handle;
    return {
      close: (...closeArguments) => handle.close(...closeArguments),
      async read(...readArguments) {
        if (!appended) {
          appended = true;
          await fs.appendFile(path, Buffer.alloc(1024 * 1024));
        }
        return await handle.read(...readArguments);
      },
      readFile() {
        eofDrivenRead = true;
        throw new Error("retained material used an EOF-driven read");
      },
      stat: (...statArguments) => handle.stat(...statArguments),
    };
  };
  try {
    await assert.rejects(
      readPrivateRegularFile(path, contents.length, "growing retained material"),
      /changed while it was read/u
    );
    assert.equal(appended, true);
    assert.equal(eofDrivenRead, false);
  } finally {
    fs.open = originalOpen;
  }
});

test("rejects a symbolic link as private regular-file material", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-artifact-symlink-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const target = join(root, "target.bin");
  const link = join(root, "artifact.bin");
  await fs.writeFile(target, "authenticated bytes", { mode: 0o600 });
  await fs.symlink(target, link);

  await assert.rejects(
    readPrivateRegularFile(link, 1024, "test artifact"),
    /is not a nonsymlink regular file/u
  );
  await assert.rejects(
    hashPrivateRegularFile(link, 1024, "test artifact"),
    /is not a nonsymlink regular file/u
  );
});

test("retains a bounded material file through its safe symbolic-link representation", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-retained-material-link-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const target = join(root, "target.a");
  const link = join(root, "runtime.a");
  const contents = Buffer.from("authenticated archive bytes");
  await fs.writeFile(target, contents, { mode: 0o600 });
  await fs.symlink(target, link);

  const retained = await readAndHashMaterialFile(
    "runtime-archive-0",
    link,
    contents.length,
    "retained runtime archive"
  );
  assert.deepEqual(retained.contents, contents);
  assert.deepEqual(retained.fingerprint, {
    label: "runtime-archive-0",
    sha256: createHash("sha256").update(contents).digest("hex"),
    size: contents.length,
    type: "symbolic-link-to-file",
  });
  await assert.rejects(
    readAndHashMaterialFile(
      "runtime-archive-0",
      link,
      contents.length - 1,
      "retained runtime archive"
    ),
    /above the .*byte limit/u
  );
});

test("fingerprints material paths in canonical label order", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-paths-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const first = join(root, "first.txt");
  const second = join(root, "second.txt");
  await Promise.all([fs.writeFile(first, "first"), fs.writeFile(second, "second")]);

  const fingerprint = await fingerprintMaterialPaths(
    [
      { label: "z", path: second },
      { label: "a", path: first },
    ],
    "test materials"
  );
  assert.deepEqual(
    fingerprint.entries.map(({ label }) => label),
    ["a", "z"]
  );
  assert.match(fingerprint.sha256, /^[0-9a-f]{64}$/u);
});

test("fingerprints at most four top-level material paths without changing canonical output", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-concurrent-material-paths-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const labels = ["a", "b", "c", "d", "e"];
  const pathsByLabel = Object.fromEntries(
    labels.map((label) => [label, join(root, `${label}.txt`)])
  );
  await Promise.all(labels.map((label) => fs.writeFile(pathsByLabel[label], label)));

  const labelsByPath = new Map(labels.map((label) => [pathsByLabel[label], label]));
  const firstWaveStarted = deferred();
  const releaseFirstWave = deferred();
  const originalLstat = fs.lstat;
  const startedLabels = new Set();
  fs.lstat = async (path, ...argumentsList) => {
    const label = labelsByPath.get(path);
    if (label !== undefined && !startedLabels.has(label)) {
      startedLabels.add(label);
      if (startedLabels.size === 4) firstWaveStarted.resolve();
      if (label !== "e") await releaseFirstWave.promise;
    }
    return await originalLstat(path, ...argumentsList);
  };
  const fingerprintPromise = fingerprintMaterialPaths(
    labels.toReversed().map((label) => ({ label, path: pathsByLabel[label] })),
    "concurrent test materials",
    createMaterialPathVerificationMemo()
  );
  let timeout;
  let observationError;
  try {
    await Promise.race([
      firstWaveStarted.promise,
      new Promise((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error("four top-level material paths did not start")),
          2_000
        );
      }),
    ]);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual([...startedLabels], ["a", "b", "c", "d"]);
  } catch (error) {
    observationError = error;
  } finally {
    clearTimeout(timeout);
    releaseFirstWave.resolve();
    await Promise.allSettled([fingerprintPromise]);
    fs.lstat = originalLstat;
  }
  const fingerprint = await fingerprintPromise;
  if (observationError !== undefined) throw observationError;
  const entries = labels.map((label) => ({
    label,
    sha256: createHash("sha256").update(label).digest("hex"),
    size: 1,
    type: "file",
  }));
  assert.deepEqual(fingerprint, { entries, sha256: fingerprintJson(entries) });
});

test("derives the canonical directory fingerprint from the pre-state inventory", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-directory-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const directoryLink = join(root, "tree-link");
  const nested = join(directory, "nested");
  await fs.mkdir(nested, { recursive: true });
  await Promise.all([
    fs.writeFile(join(directory, "alpha.txt"), "alpha"),
    fs.writeFile(join(nested, "beta.txt"), "beta"),
  ]);
  await fs.symlink(directory, directoryLink);
  const alpha = Buffer.from("alpha");
  const beta = Buffer.from("beta");
  const entries = [
    {
      path: "alpha.txt",
      sha256: createHash("sha256").update(alpha).digest("hex"),
      size: alpha.length,
      type: "file",
    },
    { path: "nested/", type: "directory" },
    {
      path: "nested/beta.txt",
      sha256: createHash("sha256").update(beta).digest("hex"),
      size: beta.length,
      type: "file",
    },
  ];

  const expected = {
    fileCount: 2,
    label: "tree",
    sha256: fingerprintJson(entries),
    size: alpha.length + beta.length,
    type: "directory",
  };
  assert.deepEqual(await fingerprintMaterialPath("tree", directory), expected);
  const expectedLink = { ...expected, type: "symbolic-link-to-directory" };
  assert.deepEqual(await fingerprintMaterialPath("tree", directoryLink), expectedLink);

  const originalReaddir = fs.readdir;
  let directoryReadCount = 0;
  fs.readdir = async (path, ...argumentsList) => {
    if (path === directory) directoryReadCount += 1;
    return await originalReaddir(path, ...argumentsList);
  };
  let fingerprint;
  try {
    fingerprint = await fingerprintMaterialPaths(
      [{ label: "tree", path: directoryLink }],
      "pre-state inventory materials",
      createMaterialPathVerificationMemo()
    );
  } finally {
    fs.readdir = originalReaddir;
  }
  assert.deepEqual(fingerprint, {
    entries: [expectedLink],
    sha256: fingerprintJson([expectedLink]),
  });
  assert.equal(directoryReadCount, 2);
});

test("captures sibling material state with a concurrency-four bound and canonical order", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-state-siblings-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const labels = ["a", "b", "c", "d", "e"];
  await fs.mkdir(directory);
  const pathsByLabel = Object.fromEntries(
    labels.map((label) => [label, join(directory, `${label}.txt`)])
  );
  await Promise.all(labels.map((label) => fs.writeFile(pathsByLabel[label], label)));

  const labelsByPath = new Map(labels.map((label) => [pathsByLabel[label], label]));
  const firstWaveStarted = deferred();
  const releaseFirstWave = deferred();
  const originalLstat = fs.lstat;
  const startedLabels = new Set();
  fs.lstat = async (path, ...argumentsList) => {
    const label = labelsByPath.get(path);
    if (label !== undefined && !startedLabels.has(label)) {
      startedLabels.add(label);
      if (startedLabels.size === 4) firstWaveStarted.resolve();
      if (label !== "e") await releaseFirstWave.promise;
    }
    return await originalLstat(path, ...argumentsList);
  };
  const fingerprintPromise = fingerprintMaterialPaths(
    [{ label: "tree", path: directory }],
    "bounded sibling materials",
    createMaterialPathVerificationMemo()
  );
  let timeout;
  let observationError;
  try {
    await Promise.race([
      firstWaveStarted.promise,
      new Promise((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error("four sibling material states did not start")),
          2_000
        );
      }),
    ]);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual([...startedLabels], ["a", "b", "c", "d"]);
  } catch (error) {
    observationError = error;
  } finally {
    clearTimeout(timeout);
    releaseFirstWave.resolve();
    await Promise.allSettled([fingerprintPromise]);
    fs.lstat = originalLstat;
  }
  const fingerprint = await fingerprintPromise;
  if (observationError !== undefined) throw observationError;
  const entries = labels.map((label) => ({
    path: `${label}.txt`,
    sha256: createHash("sha256").update(label).digest("hex"),
    size: 1,
    type: "file",
  }));
  const directoryFingerprint = {
    fileCount: labels.length,
    label: "tree",
    sha256: fingerprintJson(entries),
    size: labels.length,
    type: "directory",
  };
  assert.deepEqual(fingerprint, {
    entries: [directoryFingerprint],
    sha256: fingerprintJson([directoryFingerprint]),
  });
});

test("shares one filesystem-state read bound across recursive sibling levels", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-recursive-material-state-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const directoryNames = ["a", "b", "c", "d"];
  const fileNames = ["a", "b", "c", "d"];
  await Promise.all(
    directoryNames.map((name) => fs.mkdir(join(directory, name), { recursive: true }))
  );
  const files = directoryNames.flatMap((directoryName) =>
    fileNames.map((fileName) => ({
      contents: `${directoryName}-${fileName}`,
      path: join(directory, directoryName, `${fileName}.txt`),
    }))
  );
  await Promise.all(files.map(({ contents, path }) => fs.writeFile(path, contents)));

  const filePaths = new Set(files.map(({ path }) => path));
  const firstWaveStarted = deferred();
  const releaseFirstWave = deferred();
  const originalLstat = fs.lstat;
  const startedPaths = [];
  let activeReads = 0;
  let blockReads = true;
  let maximumActiveReads = 0;
  fs.lstat = async (path, ...argumentsList) => {
    if (blockReads && filePaths.has(path)) {
      startedPaths.push(path);
      activeReads += 1;
      maximumActiveReads = Math.max(maximumActiveReads, activeReads);
      if (activeReads === 4) firstWaveStarted.resolve();
      await releaseFirstWave.promise;
      activeReads -= 1;
    }
    return await originalLstat(path, ...argumentsList);
  };
  const fingerprintPromise = fingerprintMaterialPaths(
    [{ label: "tree", path: directory }],
    "recursively bounded materials",
    createMaterialPathVerificationMemo()
  );
  let timeout;
  let observationError;
  try {
    await Promise.race([
      firstWaveStarted.promise,
      new Promise((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error("four recursive material-state reads did not start")),
          2_000
        );
      }),
    ]);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(startedPaths.length, 4);
    assert.equal(maximumActiveReads, 4);
  } catch (error) {
    observationError = error;
  } finally {
    clearTimeout(timeout);
    blockReads = false;
    releaseFirstWave.resolve();
    await Promise.allSettled([fingerprintPromise]);
    fs.lstat = originalLstat;
  }
  const fingerprint = await fingerprintPromise;
  if (observationError !== undefined) throw observationError;
  const entries = directoryNames.flatMap((directoryName) => [
    { path: `${directoryName}/`, type: "directory" },
    ...fileNames.map((fileName) => {
      const contents = `${directoryName}-${fileName}`;
      return {
        path: `${directoryName}/${fileName}.txt`,
        sha256: createHash("sha256").update(contents).digest("hex"),
        size: Buffer.byteLength(contents),
        type: "file",
      };
    }),
  ]);
  const directoryFingerprint = {
    fileCount: files.length,
    label: "tree",
    sha256: fingerprintJson(entries),
    size: files.reduce((sum, { contents }) => sum + Buffer.byteLength(contents), 0),
    type: "directory",
  };
  assert.deepEqual(fingerprint, {
    entries: [directoryFingerprint],
    sha256: fingerprintJson([directoryFingerprint]),
  });
});

test("recursive material-state failures retain deterministic depth-first precedence", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-state-failure-order-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const earlierPath = join(directory, "a", "failed.txt");
  const laterPath = join(directory, "b", "failed.txt");
  await Promise.all([
    fs.mkdir(join(directory, "a"), { recursive: true }),
    fs.mkdir(join(directory, "b"), { recursive: true }),
  ]);
  await Promise.all([fs.writeFile(earlierPath, "earlier"), fs.writeFile(laterPath, "later")]);

  const earlierStarted = deferred();
  const laterFailed = deferred();
  const earlierFailure = new Error("earlier depth-first material-state failure");
  const laterFailure = new Error("later depth-first material-state failure");
  const originalLstat = fs.lstat;
  fs.lstat = async (path, ...argumentsList) => {
    if (path === earlierPath) {
      earlierStarted.resolve();
      await laterFailed.promise;
      throw earlierFailure;
    }
    if (path === laterPath) {
      await earlierStarted.promise;
      laterFailed.resolve();
      throw laterFailure;
    }
    return await originalLstat(path, ...argumentsList);
  };
  try {
    await assert.rejects(
      fingerprintMaterialPaths(
        [{ label: "tree", path: directory }],
        "ordered recursive failures",
        createMaterialPathVerificationMemo()
      ),
      (error) => error === earlierFailure
    );
  } finally {
    laterFailed.resolve();
    fs.lstat = originalLstat;
  }
});

test("retains the complete final material-state mutation fence", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-final-state-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const path = join(directory, "material.txt");
  await fs.mkdir(directory);
  await fs.writeFile(path, "before");

  const originalLstat = fs.lstat;
  let directoryLstatCount = 0;
  fs.lstat = async (lstatPath, ...argumentsList) => {
    if (lstatPath === directory) {
      directoryLstatCount += 1;
      // A directory state capture reads the root before and after its children. The third root read
      // begins the final state walk, after the fingerprint hash has completed.
      if (directoryLstatCount === 3) {
        await fs.writeFile(path, "changed after hashing");
      }
    }
    return await originalLstat(lstatPath, ...argumentsList);
  };
  try {
    await assert.rejects(
      fingerprintMaterialPaths(
        [{ label: "tree", path: directory }],
        "mutated materials",
        createMaterialPathVerificationMemo()
      ),
      /material path changed while it was fingerprinted/u
    );
  } finally {
    fs.lstat = originalLstat;
  }
  assert.equal(directoryLstatCount, 4);
});

test("rejects a symbolic link inside a memoized material directory", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-state-symlink-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const target = join(root, "target.txt");
  await fs.mkdir(directory);
  await fs.writeFile(target, "target");
  await fs.symlink(target, join(directory, "material.txt"));

  await assert.rejects(
    fingerprintMaterialPaths(
      [{ label: "tree", path: directory }],
      "linked materials",
      createMaterialPathVerificationMemo()
    ),
    /material directory contains a symbolic link/u
  );
});

test("bounded material hashing drains admitted reads and preserves input failure precedence", async () => {
  const earlierReadStarted = deferred();
  const laterReadFailed = deferred();
  const releaseEarlierRead = deferred();
  const started = [];
  const result = convexWasmArtifactMaterialTestHooks.mapBounded(
    ["earlier", "later", "not-started"],
    2,
    async (value) => {
      started.push(value);
      if (value === "earlier") {
        earlierReadStarted.resolve();
        await laterReadFailed.promise;
        await releaseEarlierRead.promise;
        throw undefined;
      }
      if (value === "later") {
        laterReadFailed.resolve();
        throw new Error("later material read failed");
      }
      return value;
    }
  );
  await Promise.all([earlierReadStarted.promise, laterReadFailed.promise]);
  await new Promise((resolve) => setImmediate(resolve));

  let settled = false;
  void result.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);

  releaseEarlierRead.resolve();
  assert.deepEqual(await Promise.allSettled([result]), [{ reason: undefined, status: "rejected" }]);
  assert.deepEqual(started, ["earlier", "later"]);
});

test("reuses material digests only while exact file and tree state is unchanged", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-material-path-memo-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const directory = join(root, "tree");
  const path = join(directory, "material.txt");
  await fs.mkdir(directory);
  await fs.writeFile(path, "first");
  const materials = [{ label: "tree", path: directory }];
  const verificationMemo = createMaterialPathVerificationMemo();

  const first = await fingerprintMaterialPaths(materials, "memoized materials", verificationMemo);
  const unchanged = await fingerprintMaterialPaths(
    materials,
    "memoized materials",
    verificationMemo
  );
  assert.strictEqual(unchanged.entries[0], first.entries[0]);
  assert.equal(unchanged.sha256, first.sha256);

  await fs.writeFile(path, "other");
  const changed = await fingerprintMaterialPaths(materials, "memoized materials", verificationMemo);
  assert.notStrictEqual(changed.entries[0], first.entries[0]);
  assert.notEqual(changed.sha256, first.sha256);

  const settled = await fingerprintMaterialPaths(materials, "memoized materials", verificationMemo);
  assert.strictEqual(settled.entries[0], changed.entries[0]);
  await assert.rejects(
    fingerprintMaterialPaths(materials, "memoized materials", new Map()),
    /verification memo is invalid/u
  );
});
