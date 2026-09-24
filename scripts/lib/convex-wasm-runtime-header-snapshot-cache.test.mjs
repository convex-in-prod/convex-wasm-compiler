import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { fingerprintMaterialPaths } from "./convex-wasm-artifact-material.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry,
  convexWasmRuntimeHeaderSnapshotCacheStage,
  convexWasmRuntimeHeaderSnapshotCacheKey,
  convexWasmRuntimeHeaderSnapshotCacheTestHooks,
  createConvexWasmRuntimeHeaderSnapshotIdentity,
  loadOrCreateConvexWasmRuntimeHeaderSnapshotCache,
  readConvexWasmRuntimeHeaderSnapshotState,
  verifyConvexWasmRuntimeHeaderSnapshotState,
} from "./convex-wasm-runtime-header-snapshot-cache.mjs";

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function fixture(t, name) {
  const root = await fs.mkdtemp(join(tmpdir(), `convex-wasm-runtime-header-${name}-`));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheRoot = join(root, "cache");
  const includeDirectories = [join(root, "include-a"), join(root, "include-b")];
  await Promise.all([
    fs.mkdir(join(includeDirectories[0], "nested"), { recursive: true }),
    fs.mkdir(includeDirectories[1]),
    fs.mkdir(cacheRoot, { mode: 0o700 }),
  ]);
  await Promise.all([
    fs.writeFile(join(includeDirectories[0], "root.h"), "root header\n"),
    fs.writeFile(join(includeDirectories[0], "nested", "nested.h"), "nested header\n"),
    fs.writeFile(join(includeDirectories[1], "other.h"), "other header\n"),
  ]);
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: name,
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: root,
  });
  await fs.mkdir(cacheLayout.immutable.artifacts, { mode: 0o700, recursive: true });
  await Promise.all(
    [
      cacheRoot,
      join(cacheRoot, "immutable"),
      cacheLayout.immutable.root,
      cacheLayout.immutable.artifacts,
    ].map((path) => fs.chmod(path, 0o700))
  );
  const runtimeHeaderMaterials = await fingerprintMaterialPaths(
    [
      ...includeDirectories.map((path, index) => ({
        label: `runtime-include-directory-${index}`,
        path,
      })),
      { label: "unrelated-runtime-material", path: join(includeDirectories[0], "root.h") },
    ],
    "runtime header cache fixture"
  );
  return { cacheLayout, includeDirectories, root, runtimeHeaderMaterials };
}

function cacheArguments(value) {
  return {
    cacheLayout: value.cacheLayout,
    includeDirectories: value.includeDirectories,
    runtimeHeaderMaterials: value.runtimeHeaderMaterials,
  };
}

test("runtime header snapshots persist across sessions and share concurrent creation", async (t) => {
  const value = await fixture(t, "persistent-single-flight");
  const originalCopy = fs.cp;
  let copyCount = 0;
  fs.cp = async (...argumentsList) => {
    copyCount += 1;
    return await originalCopy(...argumentsList);
  };
  try {
    const [first, concurrent] = await Promise.all([
      loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
      loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
    ]);
    assert.strictEqual(first, concurrent);
    assert.equal(copyCount, value.includeDirectories.length);
    const reused = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
    assert.equal(reused.inputRoot, first.inputRoot);
    assert.equal(copyCount, value.includeDirectories.length);
    assert.equal((await fs.stat(reused.inputRoot)).mode & 0o7777, 0o700);
    assert.equal(
      (await fs.stat(join(reused.inputRoot, "include-0", "root.h"))).mode & 0o7777,
      0o600
    );
    assert.deepEqual((await fs.readdir(reused.path)).sort(), ["COMPLETE", "entry.json", "inputs"]);
  } finally {
    fs.cp = originalCopy;
  }
});

test("runtime header snapshot cache hits perform one metadata walk without rehashing payloads", async (t) => {
  const value = await fixture(t, "metadata-only-hit");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const originalLstat = fs.lstat;
  const originalReaddir = fs.readdir;
  let inputLstatCount = 0;
  let inputReaddirCount = 0;
  fs.lstat = async (path, ...argumentsList) => {
    if (path === cached.inputRoot || path.startsWith(`${cached.inputRoot}/`)) {
      inputLstatCount += 1;
    }
    return await originalLstat(path, ...argumentsList);
  };
  fs.readdir = async (path, ...argumentsList) => {
    if (path === cached.inputRoot || path.startsWith(`${cached.inputRoot}/`)) {
      inputReaddirCount += 1;
    }
    return await originalReaddir(path, ...argumentsList);
  };
  try {
    const reused = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
    const directoryCount = cached.state.filter(({ type }) => type === "directory").length;
    const fileCount = cached.state.filter(({ type }) => type === "file").length;
    assert.equal(reused.inputRoot, cached.inputRoot);
    assert.equal(inputLstatCount, directoryCount * 2 + fileCount);
    assert.equal(inputReaddirCount, directoryCount);
  } finally {
    fs.lstat = originalLstat;
    fs.readdir = originalReaddir;
  }
});

test("runtime header snapshot cache hits reauthenticate ctime-only permission normalization", async (t) => {
  const value = await fixture(t, "ctime-only-permission-normalization");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const headerPath = join(cached.inputRoot, "include-0", "root.h");
  const before = cached.state.find(({ path }) => path === "include-0/root.h");
  assert.notEqual(before, undefined);
  const metadataPaths = [join(cached.path, "entry.json"), join(cached.path, "COMPLETE")];
  const persistedBefore = await Promise.all(metadataPaths.map((path) => fs.readFile(path)));
  const metadataBefore = await Promise.all(
    metadataPaths.map((path) => fs.lstat(path, { bigint: true }))
  );

  await Promise.all([
    fs.chmod(headerPath, 0o600),
    fs.chmod(cached.inputRoot, 0o700),
    fs.chmod(join(cached.inputRoot, "include-0", "nested"), 0o700),
  ]);
  const currentState = await readConvexWasmRuntimeHeaderSnapshotState(cached.inputRoot);
  const after = currentState.find(({ path }) => path === before.path);
  assert.notEqual(after.changeTimeNanoseconds, before.changeTimeNanoseconds);
  assert.deepEqual({ ...after, changeTimeNanoseconds: before.changeTimeNanoseconds }, before);

  const reused = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  assert.equal(reused.inputRoot, cached.inputRoot);
  assert.deepEqual(reused.state, currentState);
  await verifyConvexWasmRuntimeHeaderSnapshotState(reused.inputRoot, reused.state);
  assert.deepEqual(reused.entry.state, cached.state);
  assert.deepEqual(
    await Promise.all(metadataPaths.map((path) => fs.readFile(path))),
    persistedBefore
  );
  const metadataAfter = await Promise.all(
    metadataPaths.map((path) => fs.lstat(path, { bigint: true }))
  );
  assert.deepEqual(
    metadataAfter.map(({ ino, mtimeNs, ctimeNs }) => ({ ino, mtimeNs, ctimeNs })),
    metadataBefore.map(({ ino, mtimeNs, ctimeNs }) => ({ ino, mtimeNs, ctimeNs }))
  );
});

test("ctime-only recovery rehashes before admitting snapshot bytes", async (t) => {
  const value = await fixture(t, "ctime-only-content-authentication");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const headerRelativePath = "include-0/root.h";
  const headerPath = join(cached.inputRoot, headerRelativePath);
  await fs.writeFile(headerPath, "evil header\n");
  const currentState = await readConvexWasmRuntimeHeaderSnapshotState(cached.inputRoot);
  const priorHeaderState = cached.state.find(({ path }) => path === headerRelativePath);
  const currentHeaderState = currentState.find(({ path }) => path === headerRelativePath);
  assert.notEqual(priorHeaderState, undefined);
  assert.notEqual(currentHeaderState, undefined);
  assert.equal(currentHeaderState.size, priorHeaderState.size);

  const entryPath = join(cached.path, "entry.json");
  const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
  entry.state = currentState.map((state) =>
    state.path === headerRelativePath
      ? { ...state, changeTimeNanoseconds: priorHeaderState.changeTimeNanoseconds }
      : state
  );
  await Promise.all([
    fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
    fs.writeFile(join(cached.path, "COMPLETE"), `${fingerprintJson(entry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
    /runtime header snapshot does not match its authenticated material identity/u
  );
});

test("ctime-only recovery retains the metadata scan that selected recovery", async (t) => {
  const value = await fixture(t, "ctime-recovery-state-fence");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const headerPath = join(cached.inputRoot, "include-0", "root.h");
  await fs.chmod(headerPath, 0o600);
  const originalReaddir = fs.readdir;
  let inputRootReads = 0;
  fs.readdir = async (path, ...args) => {
    if (path === cached.inputRoot && ++inputRootReads === 2) {
      // Change metadata after the ctime-only scan, before recovery starts hashing unchanged bytes.
      await fs.utimes(headerPath, new Date(0), new Date(0));
    }
    return await originalReaddir(path, ...args);
  };
  try {
    await assert.rejects(
      loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
      /runtime header snapshot changed while it was authenticated/u
    );
  } finally {
    fs.readdir = originalReaddir;
  }
});

test("runtime header state walks overlap bounded reads and preserve persisted preorder", async (t) => {
  const value = await fixture(t, "parallel-state-order");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const originalLstat = fs.lstat;
  const originalReaddir = fs.readdir;
  let active = 0;
  let maximumActive = 0;
  const observe =
    (operation) =>
    async (...args) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      try {
        await new Promise((resolvePromise) => setImmediate(resolvePromise));
        return await operation(...args);
      } finally {
        active -= 1;
      }
    };
  fs.lstat = observe(originalLstat);
  fs.readdir = observe(originalReaddir);
  try {
    const state = await readConvexWasmRuntimeHeaderSnapshotState(cached.inputRoot);
    assert.deepEqual(state, cached.state);
    assert.deepEqual(
      state.map(({ path }) => path),
      [
        "",
        "include-0",
        "include-0/nested",
        "include-0/nested/nested.h",
        "include-0/root.h",
        "include-1",
        "include-1/other.h",
      ]
    );
    assert.ok(maximumActive > 1);
    assert.ok(maximumActive <= 4);
    assert.equal(active, 0);
  } finally {
    fs.lstat = originalLstat;
    fs.readdir = originalReaddir;
  }
});

test(
  "runtime header state failures drain other admitted subtrees",
  { timeout: 5_000 },
  async (t) => {
    const value = await fixture(t, "parallel-state-drain");
    const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
    const originalLstat = fs.lstat;
    const siblingStarted = deferred();
    const releaseSibling = deferred();
    const failureRaised = deferred();
    const failure = new Error("fixture header state read failure");
    let siblingFinished = false;
    let settled = false;
    fs.lstat = async (path, ...args) => {
      if (path === join(cached.inputRoot, "include-0", "root.h")) {
        await siblingStarted.promise;
        failureRaised.resolve();
        throw failure;
      }
      if (path === join(cached.inputRoot, "include-1", "other.h")) {
        siblingStarted.resolve();
        await releaseSibling.promise;
        const result = await originalLstat(path, ...args);
        siblingFinished = true;
        return result;
      }
      return await originalLstat(path, ...args);
    };
    const walk = readConvexWasmRuntimeHeaderSnapshotState(cached.inputRoot);
    void walk.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      }
    );
    try {
      await failureRaised.promise;
      await new Promise((resolvePromise) => setImmediate(resolvePromise));
      assert.equal(settled, false);
      releaseSibling.resolve();
      await assert.rejects(walk, (error) => error === failure);
      assert.equal(siblingFinished, true);
    } finally {
      releaseSibling.resolve();
      await walk.catch(() => undefined);
      fs.lstat = originalLstat;
    }
  }
);

test("runtime header snapshot keys exclude unrelated runtime materials", async (t) => {
  const value = await fixture(t, "identity-scope");
  const baseline = createConvexWasmRuntimeHeaderSnapshotIdentity({
    includeDirectories: value.includeDirectories,
    runtimeHeaderMaterials: value.runtimeHeaderMaterials,
  });
  const changedMaterials = structuredClone(value.runtimeHeaderMaterials);
  changedMaterials.sha256 = "e".repeat(64);
  const unrelated = changedMaterials.entries.find(
    ({ label }) => label === "unrelated-runtime-material"
  );
  unrelated.sha256 = "f".repeat(64);
  unrelated.size += 1;
  const changed = createConvexWasmRuntimeHeaderSnapshotIdentity({
    includeDirectories: ["/different/origin-a", "/different/origin-b"],
    runtimeHeaderMaterials: changedMaterials,
  });
  assert.equal(canonicalJson(changed), canonicalJson(baseline));
  assert.equal(
    convexWasmRuntimeHeaderSnapshotCacheKey(changed),
    convexWasmRuntimeHeaderSnapshotCacheKey(baseline)
  );
  const linkedMaterials = structuredClone(value.runtimeHeaderMaterials);
  linkedMaterials.entries.find(({ label }) => label === "runtime-include-directory-0").type =
    "symbolic-link-to-directory";
  assert.equal(
    canonicalJson(
      createConvexWasmRuntimeHeaderSnapshotIdentity({
        includeDirectories: value.includeDirectories,
        runtimeHeaderMaterials: linkedMaterials,
      })
    ),
    canonicalJson(baseline)
  );
});

test("runtime header snapshot authentication retains previous-stage cleanup support", async (t) => {
  const value = await fixture(t, "legacy-retention");
  const current = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const identity = createConvexWasmRuntimeHeaderSnapshotIdentity({
    includeDirectories: value.includeDirectories,
    runtimeHeaderMaterials: value.runtimeHeaderMaterials,
  });
  const stage = "runtime-header-snapshot-v1";
  const key = fingerprintJson({
    identity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage,
  });
  const path = join(value.cacheLayout.immutable.artifacts, stage, key);
  await fs.mkdir(path, { mode: 0o700, recursive: true });
  await fs.cp(current.inputRoot, join(path, "inputs"), { recursive: true });
  const entry = {
    identity,
    key,
    kind: "convex-wasm-runtime-header-snapshot-cache-entry-v1",
    stage,
  };
  await Promise.all([
    fs.writeFile(join(path, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
    fs.writeFile(join(path, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
  ]);
  const authenticated = await authenticateConvexWasmRuntimeHeaderSnapshotCacheEntry({
    cacheLayout: value.cacheLayout,
    key,
    stage,
  });
  assert.equal(authenticated.inputRoot, join(path, "inputs"));
  assert.deepEqual(authenticated.identity, identity);

  await fs.rm(current.path, { recursive: true });
  const compiled = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  assert.equal(compiled.stage, convexWasmRuntimeHeaderSnapshotCacheStage);
  assert.notEqual(compiled.path, path);
  await fs.lstat(path);
});

test("runtime header snapshot creators publish one exact collision winner", async (t) => {
  const value = await fixture(t, "collision");
  const identity = createConvexWasmRuntimeHeaderSnapshotIdentity({
    includeDirectories: value.includeDirectories,
    runtimeHeaderMaterials: value.runtimeHeaderMaterials,
  });
  const key = convexWasmRuntimeHeaderSnapshotCacheKey(identity);
  const stageRoot = join(
    value.cacheLayout.immutable.artifacts,
    convexWasmRuntimeHeaderSnapshotCacheStage
  );
  await fs.mkdir(stageRoot, { mode: 0o700 });
  const allCopiesStarted = deferred();
  const releaseCopies = deferred();
  const originalCopy = fs.cp;
  let copyCount = 0;
  fs.cp = async (...argumentsList) => {
    copyCount += 1;
    if (copyCount === value.includeDirectories.length * 2) allCopiesStarted.resolve();
    await releaseCopies.promise;
    return await originalCopy(...argumentsList);
  };
  const creators = [
    convexWasmRuntimeHeaderSnapshotCacheTestHooks.createRuntimeHeaderSnapshotCacheEntry({
      cacheLayout: value.cacheLayout,
      identity,
      includeDirectories: value.includeDirectories,
      key,
    }),
    convexWasmRuntimeHeaderSnapshotCacheTestHooks.createRuntimeHeaderSnapshotCacheEntry({
      cacheLayout: value.cacheLayout,
      identity,
      includeDirectories: value.includeDirectories,
      key,
    }),
  ];
  try {
    await allCopiesStarted.promise;
    releaseCopies.resolve();
    const [first, second] = await Promise.all(creators);
    assert.equal(first.inputRoot, second.inputRoot);
    assert.equal(first.key, key);
    assert.equal(copyCount, value.includeDirectories.length * 2);
    assert.deepEqual(
      (await fs.readdir(stageRoot)).filter((name) => name.startsWith(".publish-")),
      []
    );
  } finally {
    releaseCopies.resolve();
    await Promise.allSettled(creators);
    fs.cp = originalCopy;
  }
});

test("runtime header snapshot creation rejects a nested symlink introduced after admission", async (t) => {
  const value = await fixture(t, "nested-symlink-mutation");
  const admittedHeaderPath = join(value.includeDirectories[0], "nested", "nested.h");
  const replacementHeaderPath = join(value.root, "replacement-nested.h");
  await fs.writeFile(replacementHeaderPath, "nested header\n");
  const originalCopy = fs.cp;
  let mutationApplied = false;
  fs.cp = async (sourcePath, destinationPath, options) => {
    if (!mutationApplied && sourcePath === value.includeDirectories[0]) {
      mutationApplied = true;
      await fs.rm(admittedHeaderPath);
      await fs.symlink(replacementHeaderPath, admittedHeaderPath);
    }
    return await originalCopy(sourcePath, destinationPath, options);
  };
  try {
    await assert.rejects(
      loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
      /runtime header snapshot contains an unsupported filesystem entry/u
    );
    assert.equal(mutationApplied, true);
  } finally {
    fs.cp = originalCopy;
  }
});

test("runtime header snapshot creation authenticates copied bytes against the admitted identity", async (t) => {
  const value = await fixture(t, "copied-byte-authentication");
  await fs.writeFile(join(value.includeDirectories[0], "root.h"), "evil header\n");
  const identity = createConvexWasmRuntimeHeaderSnapshotIdentity({
    includeDirectories: value.includeDirectories,
    runtimeHeaderMaterials: value.runtimeHeaderMaterials,
  });
  const key = convexWasmRuntimeHeaderSnapshotCacheKey(identity);
  await assert.rejects(
    loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
    /runtime header snapshot does not match its authenticated material identity/u
  );
  const stageRoot = join(
    value.cacheLayout.immutable.artifacts,
    convexWasmRuntimeHeaderSnapshotCacheStage
  );
  assert.deepEqual(await fs.readdir(stageRoot), []);
  await assert.rejects(fs.lstat(join(stageRoot, key)), { code: "ENOENT" });
});

test("runtime header snapshot creation bounds mode-normalization filesystem work", async (t) => {
  const value = await fixture(t, "bounded-mode-normalization");
  await Promise.all(
    Array.from({ length: 16 }, (_, index) =>
      fs.writeFile(join(value.includeDirectories[0], `additional-${String(index)}.h`), "header\n")
    )
  );
  value.runtimeHeaderMaterials = await fingerprintMaterialPaths(
    value.includeDirectories.map((path, index) => ({
      label: `runtime-include-directory-${index}`,
      path,
    })),
    "bounded mode-normalization fixture"
  );
  const originalChmod = fs.chmod;
  let activeChmods = 0;
  let maximumActiveChmods = 0;
  fs.chmod = async (...argumentsList) => {
    const [path, mode] = argumentsList;
    assert.notEqual((await fs.lstat(path)).mode & 0o7777, mode);
    activeChmods += 1;
    maximumActiveChmods = Math.max(maximumActiveChmods, activeChmods);
    await new Promise((resolvePromise) => setImmediate(resolvePromise));
    try {
      return await originalChmod(...argumentsList);
    } finally {
      activeChmods -= 1;
    }
  };
  try {
    await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
    assert.ok(maximumActiveChmods > 1);
    assert.ok(maximumActiveChmods <= 4);
  } finally {
    fs.chmod = originalChmod;
  }
});

for (const [corruption, expectedError] of [
  ["contents", /runtime header snapshot does not match its authenticated material identity/u],
  ["metadata", /runtime header snapshot completion marker is invalid/u],
  ["partial", /runtime header snapshot cache entry has unexpected contents/u],
]) {
  test(`present ${corruption} runtime header snapshots fail closed`, async (t) => {
    const value = await fixture(t, `corrupt-${corruption}`);
    const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
    if (corruption === "contents") {
      await fs.writeFile(join(cached.inputRoot, "include-0", "root.h"), "corrupt header\n");
    } else if (corruption === "metadata") {
      const entryPath = join(cached.path, "entry.json");
      const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
      entry.state[0].size = `${BigInt(entry.state[0].size) + 1n}`;
      await fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 });
    } else {
      await fs.rm(join(cached.path, "COMPLETE"));
    }
    await assert.rejects(
      loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
      expectedError
    );
    await fs.lstat(cached.path);
  });
}

test("runtime header snapshot state rejects mutation after authentication", async (t) => {
  const value = await fixture(t, "state-mutation");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  await fs.writeFile(join(cached.inputRoot, "include-1", "other.h"), "changed header\n");
  await assert.rejects(
    verifyConvexWasmRuntimeHeaderSnapshotState(cached.inputRoot, cached.state),
    /runtime header snapshot does not match its authenticated material identity/u
  );
});

test("runtime header snapshot cache hits reject same-size file replacement", async (t) => {
  const value = await fixture(t, "same-size-replacement");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const headerPath = join(cached.inputRoot, "include-0", "root.h");
  const replacementPath = join(cached.inputRoot, "include-0", "replacement.h");
  await fs.writeFile(replacementPath, "evil header\n", { mode: 0o600 });
  await fs.rename(replacementPath, headerPath);
  await assert.rejects(
    loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
    /runtime header snapshot does not match its authenticated material identity/u
  );
});

test("runtime header snapshot cache hits reject payload metadata changes", async (t) => {
  const value = await fixture(t, "payload-metadata-change");
  const cached = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value));
  const headerPath = join(cached.inputRoot, "include-1", "other.h");
  await fs.utimes(headerPath, new Date(0), new Date(0));
  await assert.rejects(
    loadOrCreateConvexWasmRuntimeHeaderSnapshotCache(cacheArguments(value)),
    /runtime header snapshot does not match its authenticated material identity/u
  );
});
