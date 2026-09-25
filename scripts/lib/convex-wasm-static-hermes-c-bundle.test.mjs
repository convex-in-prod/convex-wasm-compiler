import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";
import {
  C_BUNDLE_CACHE_ENTRY_KIND,
  C_BUNDLE_KIND,
  C_BUNDLE_MANIFEST_PATH,
  authenticateStaticHermesCBundle,
  convexWasmStaticHermesCBundleMemberCompilationPolicy,
  isStaticHermesCBundleEntry,
  normalizeStaticHermesCBundleOutput,
  staticHermesCBundleEnabled,
  staticHermesCBundleMemberCompilation,
  staticHermesCBundleMemberCompilationBaselinePolicy,
  staticHermesCBundleMemberCompilationIdentity,
  staticHermesCBundlePackageCompilationSha256,
  staticHermesCBundleTranslationUnitBytes,
  staticHermesLargeCBundleTranslationUnitBytesThreshold,
  staticHermesPrecompileProcessIdentity,
} from "./convex-wasm-static-hermes-c-bundle.mjs";

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function bundleFixture({ functionCount = 1 } = {}) {
  const sources = new Map([
    ["unit.h", "#define SH_UNIT 1\n"],
    ["metadata.c", "const int metadata = 1;\n"],
    ...Array.from({ length: functionCount }, (_, index) => [
      `function-${String(index)}.c`,
      `int f${String(index)}(void) { return ${String(index)}; }\n`,
    ]),
  ]);
  const member = (path, role, extra = {}) => {
    const source = sources.get(path);
    return { path, role, sha256: sha256(source), size: Buffer.byteLength(source), ...extra };
  };
  const header = member("unit.h", "header");
  const translationUnits = [
    member("metadata.c", "metadata"),
    ...Array.from({ length: functionCount }, (_, index) =>
      member(`function-${String(index)}.c`, "function", {
        firstFunctionId: index,
        functionCount: 1,
        lastFunctionId: index,
        oversize: false,
        targetBytes: 2_097_152,
      })
    ),
  ];
  const manifestValue = { header, kind: C_BUNDLE_KIND, schemaVersion: 1, translationUnits };
  const manifestSource = `${canonicalJson(manifestValue)}\n`;
  return {
    bundle: {
      ...manifestValue,
      manifest: {
        path: C_BUNDLE_MANIFEST_PATH,
        sha256: sha256(manifestSource),
        size: Buffer.byteLength(manifestSource),
      },
    },
    manifestSource,
    sources,
  };
}

function fragmentedBundleFixture() {
  const sources = new Map([
    ["unit.h", "#define SH_UNIT 1\n"],
    ["metadata.c", "const int metadata = 1;\n"],
    ["function-0-wrapper.c", "int f0(void) { helper0(); helper1(); return 0; }\n"],
    ["function-0-helpers-0.c", "void helper0(void) {}\nvoid helper1(void) {}\n"],
    ["function-0-helpers-1.c", "void helper2(void) {}\nvoid helper3(void) {}\n"],
  ]);
  const member = (path, role, extra = {}) => {
    const source = sources.get(path);
    return { path, role, sha256: sha256(source), size: Buffer.byteLength(source), ...extra };
  };
  const fragmentPaths = [
    "function-0-wrapper.c",
    "function-0-helpers-0.c",
    "function-0-helpers-1.c",
  ];
  const header = member("unit.h", "header");
  const translationUnits = [
    member("metadata.c", "metadata"),
    ...fragmentPaths.map((path, functionFragmentIndex) =>
      member(path, "function", {
        ...(functionFragmentIndex === 0 ? { cOptimizationLevel: 0 } : {}),
        firstFunctionId: 0,
        functionCount: 1,
        functionFragmentCount: fragmentPaths.length,
        functionFragmentIndex,
        lastFunctionId: 0,
        oversize: false,
        targetBytes: 2_097_152,
      })
    ),
  ];
  const manifestValue = { header, kind: C_BUNDLE_KIND, schemaVersion: 1, translationUnits };
  const manifestSource = `${canonicalJson(manifestValue)}\n`;
  return {
    bundle: {
      ...manifestValue,
      manifest: {
        path: C_BUNDLE_MANIFEST_PATH,
        sha256: sha256(manifestSource),
        size: Buffer.byteLength(manifestSource),
      },
    },
    manifestSource,
    sources,
  };
}

test("recognizes only the exact Static Hermes C-bundle compiler flags", () => {
  assert.equal(staticHermesCBundleEnabled(["-emit-c"]), false);
  assert.equal(
    staticHermesCBundleEnabled(["-emit-c", "-Xemit-c-bundle", "-Xemit-c-shard-size=2097152"]),
    true
  );
  assert.throws(
    () => staticHermesCBundleEnabled(["-emit-c", "-Xemit-c-bundle"]),
    /must contain exactly one -Xemit-c-bundle/u
  );
  assert.equal(isStaticHermesCBundleEntry({ kind: C_BUNDLE_CACHE_ENTRY_KIND }), true);
});

test("normalizes and authenticates a canonical C-bundle material set", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-c-bundle-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const fixture = bundleFixture();
  await Promise.all([
    fs.writeFile(join(root, C_BUNDLE_MANIFEST_PATH), fixture.manifestSource),
    ...[...fixture.sources].map(([path, source]) => fs.writeFile(join(root, path), source)),
  ]);

  assert.deepEqual(
    normalizeStaticHermesCBundleOutput(fixture.bundle, "test bundle"),
    fixture.bundle
  );
  const authenticated = await authenticateStaticHermesCBundle(root, fixture.bundle, 1024 * 1024);
  assert.equal(authenticated.artifactSha256, fixture.bundle.manifest.sha256);
  assert.equal(
    authenticated.artifactSize,
    [...fixture.sources.values()].reduce((size, source) => size + Buffer.byteLength(source), 0)
  );
});

test("rejects material that disagrees with the authenticated bundle", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-c-bundle-mismatch-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const fixture = bundleFixture();
  await Promise.all([
    fs.writeFile(join(root, C_BUNDLE_MANIFEST_PATH), fixture.manifestSource),
    ...[...fixture.sources].map(([path, source]) =>
      fs.writeFile(
        join(root, path),
        path === "function-0.c" ? source.replace("return 0", "return 1") : source
      )
    ),
  ]);

  await assert.rejects(
    authenticateStaticHermesCBundle(root, fixture.bundle, 1024 * 1024),
    /member function-0\.c does not match its identity/u
  );
});

test("authenticates packed function helpers and applies O0 only to their wrapper", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-c-bundle-fragments-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const fixture = fragmentedBundleFixture();
  await Promise.all([
    fs.writeFile(join(root, C_BUNDLE_MANIFEST_PATH), fixture.manifestSource),
    ...[...fixture.sources].map(([path, source]) => fs.writeFile(join(root, path), source)),
  ]);

  const authenticated = await authenticateStaticHermesCBundle(root, fixture.bundle, 1024 * 1024);
  const identity = staticHermesCBundleMemberCompilationIdentity(
    authenticated.bundle,
    { compileExportMember: { executable: "emcc", args: ["-O2", "-c"] } },
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );
  assert.deepEqual(
    identity.memberCompilations.map(({ effectiveArguments }) =>
      effectiveArguments.filter((argument) => argument.startsWith("-O"))
    ),
    [["-O2"], ["-O0"], ["-O2"], ["-O2"]]
  );
  assert.deepEqual(
    identity.memberCompilations.map(({ stage }) => stage),
    [
      "ordinary-object",
      convexWasmStaticHermesCBundleMemberCompilationPolicy.cOptimizationLevelZero.stage,
      "ordinary-object",
      "ordinary-object",
    ]
  );

  await fs.writeFile(
    join(root, "function-0-helpers-0.c"),
    fixture.sources.get("function-0-helpers-0.c").replace("helper0", "tamper0")
  );
  await assert.rejects(
    authenticateStaticHermesCBundle(root, fixture.bundle, 1024 * 1024),
    /member function-0-helpers-0\.c does not match its identity/u
  );
});

test("keeps function helper fragments at ordinary optimization in a large bundle", () => {
  const fixture = fragmentedBundleFixture();
  const translationUnitBytes = staticHermesCBundleTranslationUnitBytes(fixture.bundle);
  const bundle = {
    ...fixture.bundle,
    translationUnits: fixture.bundle.translationUnits.map((member, index) =>
      index === fixture.bundle.translationUnits.length - 1
        ? {
            ...member,
            size:
              member.size +
              staticHermesLargeCBundleTranslationUnitBytesThreshold -
              translationUnitBytes,
          }
        : member
    ),
  };
  const identity = staticHermesCBundleMemberCompilationIdentity(
    bundle,
    { compileExportMember: { executable: "emcc", args: ["-O2", "-c"] } },
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );

  assert.deepEqual(
    identity.memberCompilations.map(({ optimization }) => optimization),
    ["-O2", "-O0", "-O2", "-O2"]
  );
});

test("retains unfragmented O0 function admission", () => {
  const fixture = bundleFixture();
  assert.doesNotThrow(() =>
    normalizeStaticHermesCBundleOutput(
      {
        ...fixture.bundle,
        translationUnits: [
          fixture.bundle.translationUnits[0],
          { ...fixture.bundle.translationUnits[1], cOptimizationLevel: 0 },
        ],
      },
      "test bundle"
    )
  );
});

test("rejects O0 on a physical helper fragment", () => {
  const fixture = fragmentedBundleFixture();
  const helperAtO0 = {
    ...fixture.bundle,
    translationUnits: fixture.bundle.translationUnits.map((member, index) =>
      index === 2 ? { ...member, cOptimizationLevel: 0 } : member
    ),
  };
  assert.throws(
    () => normalizeStaticHermesCBundleOutput(helperAtO0, "test bundle"),
    /cOptimizationLevel=0 function fragment must be the wrapper at index 0/u
  );
});

test("rejects producer-impossible function fragment metadata", () => {
  const fragmentedFixture = fragmentedBundleFixture();
  const singleFragment = {
    ...fragmentedFixture.bundle,
    translationUnits: [
      fragmentedFixture.bundle.translationUnits[0],
      {
        ...fragmentedFixture.bundle.translationUnits[1],
        functionFragmentCount: 1,
      },
    ],
  };
  assert.throws(
    () => normalizeStaticHermesCBundleOutput(singleFragment, "test bundle"),
    /function fragment identity is invalid/u
  );

  const impossibleOversizeReason = {
    ...fragmentedFixture.bundle,
    translationUnits: fragmentedFixture.bundle.translationUnits.map((member, index) =>
      index === 2
        ? {
            ...member,
            oversize: true,
            oversizeReason: "no-outlineable-run",
            size: member.targetBytes + 1,
          }
        : member
    ),
  };
  assert.throws(
    () => normalizeStaticHermesCBundleOutput(impossibleOversizeReason, "test bundle"),
    /function fragment oversizeReason must be single-instruction/u
  );

  const understatedOversize = {
    ...fragmentedFixture.bundle,
    translationUnits: fragmentedFixture.bundle.translationUnits.map((member, index) =>
      index === 2 ? { ...member, size: member.targetBytes + 1 } : member
    ),
  };
  assert.throws(
    () => normalizeStaticHermesCBundleOutput(understatedOversize, "test bundle"),
    /oversize marker does not match its size and function count/u
  );

  const ordinaryFixture = bundleFixture();
  const missingInitialRange = {
    ...ordinaryFixture.bundle,
    translationUnits: [
      ordinaryFixture.bundle.translationUnits[0],
      {
        ...ordinaryFixture.bundle.translationUnits[1],
        firstFunctionId: 1,
        lastFunctionId: 1,
      },
    ],
  };
  assert.throws(
    () => normalizeStaticHermesCBundleOutput(missingInitialRange, "test bundle"),
    /function ranges must start at zero/u
  );
});

test("accepts no-outlineable-run for an oversized fragmented wrapper", () => {
  const fixture = fragmentedBundleFixture();
  const oversizedWrapper = {
    ...fixture.bundle,
    translationUnits: fixture.bundle.translationUnits.map((member, index) =>
      index === 1
        ? {
            ...member,
            oversize: true,
            oversizeReason: "no-outlineable-run",
            size: member.targetBytes + 1,
          }
        : member
    ),
  };

  assert.doesNotThrow(() => normalizeStaticHermesCBundleOutput(oversizedWrapper, "test bundle"));
});

test("rejects noncontiguous physical helper fragments", () => {
  const fixture = fragmentedBundleFixture();
  const separatedHelpers = {
    ...fixture.bundle,
    translationUnits: [
      fixture.bundle.translationUnits[0],
      fixture.bundle.translationUnits[1],
      {
        ...fixture.bundle.translationUnits[2],
        firstFunctionId: 1,
        lastFunctionId: 1,
      },
      fixture.bundle.translationUnits[3],
    ],
  };
  assert.throws(
    () => normalizeStaticHermesCBundleOutput(separatedHelpers, "test bundle"),
    /function fragment sequence is incomplete/u
  );
});

test("overlaps bounded C-bundle member authentication", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-c-bundle-parallel-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const fixture = bundleFixture({ functionCount: 4 });
  await Promise.all([
    fs.writeFile(join(root, C_BUNDLE_MANIFEST_PATH), fixture.manifestSource),
    ...[...fixture.sources].map(([path, source]) => fs.writeFile(join(root, path), source)),
  ]);

  const memberPaths = new Set([...fixture.sources.keys()].map((path) => join(root, path)));
  const release = deferred();
  const overlap = deferred();
  const originalOpen = fs.open;
  let activeReads = 0;
  let maximumActiveReads = 0;
  fs.open = async (path, ...argumentsList) => {
    const handle = await originalOpen(path, ...argumentsList);
    if (!memberPaths.has(path)) return handle;
    return new Proxy(handle, {
      get(target, property) {
        if (property === "read") {
          return async (...readArguments) => {
            activeReads += 1;
            maximumActiveReads = Math.max(maximumActiveReads, activeReads);
            if (activeReads >= 2) overlap.resolve();
            try {
              await release.promise;
              return await target.read(...readArguments);
            } finally {
              activeReads -= 1;
            }
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  const authentication = authenticateStaticHermesCBundle(root, fixture.bundle, 1024 * 1024);
  let overlapped = false;
  try {
    overlapped = await Promise.race([
      overlap.promise.then(() => true),
      new Promise((resolveTimeout) => setTimeout(() => resolveTimeout(false), 250)),
    ]);
  } finally {
    release.resolve();
  }
  try {
    await authentication;
  } finally {
    fs.open = originalOpen;
  }
  assert.equal(overlapped, true);
  assert.ok(maximumActiveReads > 1);
});

test("stops queued member reads after tamper and drains admitted authentication", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-c-bundle-fail-stop-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const fixture = bundleFixture({ functionCount: 5 });
  await Promise.all([
    fs.writeFile(join(root, C_BUNDLE_MANIFEST_PATH), fixture.manifestSource),
    ...[...fixture.sources].map(([path, source]) =>
      fs.writeFile(
        join(root, path),
        path === "metadata.c" ? source.replace("metadata = 1", "metadata = 2") : source
      )
    ),
  ]);

  const release = deferred();
  const blockedStarted = deferred();
  const metadataRead = deferred();
  const blockedPaths = new Set(
    ["unit.h", "function-0.c", "function-1.c"].map((path) => join(root, path))
  );
  const laterPaths = new Set(
    ["function-2.c", "function-3.c", "function-4.c"].map((path) => join(root, path))
  );
  const openedPaths = new Set();
  const originalOpen = fs.open;
  let blockedReadCount = 0;
  fs.open = async (path, ...argumentsList) => {
    const handle = await originalOpen(path, ...argumentsList);
    if (!fixture.sources.has(path.slice(root.length + 1))) return handle;
    openedPaths.add(path);
    return new Proxy(handle, {
      get(target, property) {
        if (property === "read") {
          return async (...readArguments) => {
            if (blockedPaths.has(path)) {
              blockedReadCount += 1;
              if (blockedReadCount === blockedPaths.size) blockedStarted.resolve();
              await release.promise;
            }
            const result = await target.read(...readArguments);
            if (path === join(root, "metadata.c")) metadataRead.resolve();
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  const authentication = authenticateStaticHermesCBundle(root, fixture.bundle, 1024 * 1024);
  let settled = false;
  void authentication.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    }
  );
  try {
    await Promise.all([blockedStarted.promise, metadataRead.promise]);
    await new Promise((resolveImmediate) => setImmediate(resolveImmediate));
    assert.equal(settled, false);
    assert.deepEqual(
      [...openedPaths].filter((path) => laterPaths.has(path)),
      []
    );
    release.resolve();
    await assert.rejects(authentication, /member metadata\.c does not match its identity/u);
  } finally {
    release.resolve();
    fs.open = originalOpen;
  }
});

test("derives member commands and their stable compilation identity", () => {
  const fixture = bundleFixture();
  const translationUnitBytes = staticHermesCBundleTranslationUnitBytes(fixture.bundle);
  const ordinary = staticHermesCBundleMemberCompilation(
    fixture.bundle.translationUnits[1],
    { executable: "emcc", args: ["-O2", "-c", "function-0.c"] },
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    translationUnitBytes
  );
  assert.equal(ordinary.optimization, "-O2");
  assert.equal(ordinary.stage, "ordinary-object");
  assert.deepEqual(ordinary.command.args, ["-O2", "-c", "function-0.c"]);

  const exceptionalMember = {
    ...fixture.bundle.translationUnits[1],
    cOptimizationLevel: 0,
  };
  const exceptional = staticHermesCBundleMemberCompilation(
    exceptionalMember,
    { executable: "emcc", args: ["-O2", "-c", "function-0.c"] },
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    translationUnitBytes
  );
  assert.equal(exceptional.optimization, "-O0");
  assert.equal(
    exceptional.stage,
    convexWasmStaticHermesCBundleMemberCompilationPolicy.cOptimizationLevelZero.stage
  );

  const commands = {
    compileExportMember: { executable: "emcc", args: ["-O2", "-c"] },
  };
  const identity = staticHermesCBundleMemberCompilationIdentity(
    fixture.bundle,
    commands,
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );
  assert.equal(identity.memberCompilations.length, 2);
  assert.equal(identity.memberCompilations[1].optimization, "-O2");
  assert.deepEqual(identity.memberArchive, {
    format: "gnu-ar",
    kind: "convex-wasm-static-hermes-c-bundle-member-archive-v1",
    memberNames: ["member-00000.o", "member-00001.o"],
  });
  assert.equal(identity.kind, "convex-wasm-static-hermes-c-bundle-member-command-identity-v3");
  assert.deepEqual(
    identity.memberCompilationPolicy,
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );
  assert.equal(
    identity.memberCompilationPolicy.largeBundleFunction.appliesToFunctionFragments,
    false
  );
  assert.equal(staticHermesCBundleMemberCompilationBaselinePolicy.normalOptimizationFlag, "-O2");

  assert.throws(
    () =>
      staticHermesCBundleMemberCompilation(
        exceptionalMember,
        { executable: "emcc", args: ["-c", "function-0.c"] },
        "ordinary-object",
        convexWasmStaticHermesCBundleMemberCompilationPolicy,
        translationUnitBytes
      ),
    /must start with exactly one -O2 flag/u
  );
  assert.throws(
    () =>
      staticHermesCBundleMemberCompilation(
        exceptionalMember,
        { executable: "emcc", args: ["-O2", "-Oz", "-c", "function-0.c"] },
        "ordinary-object",
        convexWasmStaticHermesCBundleMemberCompilationPolicy,
        translationUnitBytes
      ),
    /must start with exactly one -O2 flag/u
  );
});

test("keeps large-bundle function members at size-aware optimization", () => {
  const fixture = bundleFixture();
  const atBoundary = {
    ...fixture.bundle,
    translationUnits: [
      { ...fixture.bundle.translationUnits[0], size: 1 },
      {
        ...fixture.bundle.translationUnits[1],
        size: staticHermesLargeCBundleTranslationUnitBytesThreshold - 1,
      },
    ],
  };
  assert.equal(
    staticHermesCBundleTranslationUnitBytes(atBoundary),
    staticHermesLargeCBundleTranslationUnitBytesThreshold
  );
  const command = { executable: "emcc", args: ["-O2", "-c", "member.c"] };
  const metadata = staticHermesCBundleMemberCompilation(
    atBoundary.translationUnits[0],
    command,
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    staticHermesCBundleTranslationUnitBytes(atBoundary)
  );
  const functionMember = staticHermesCBundleMemberCompilation(
    atBoundary.translationUnits[1],
    command,
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    staticHermesCBundleTranslationUnitBytes(atBoundary)
  );
  assert.deepEqual(
    { optimization: metadata.optimization, stage: metadata.stage },
    { optimization: "-O2", stage: "ordinary-object" }
  );
  assert.deepEqual(
    { optimization: functionMember.optimization, stage: functionMember.stage },
    { optimization: "-Oz", stage: "ordinary-object" }
  );

  const belowBoundary = {
    ...atBoundary,
    translationUnits: [
      atBoundary.translationUnits[0],
      { ...atBoundary.translationUnits[1], size: atBoundary.translationUnits[1].size - 1 },
    ],
  };
  const belowBoundaryFunction = staticHermesCBundleMemberCompilation(
    belowBoundary.translationUnits[1],
    command,
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    staticHermesCBundleTranslationUnitBytes(belowBoundary)
  );
  assert.equal(belowBoundaryFunction.optimization, "-O2");

  const explicitLevelZero = staticHermesCBundleMemberCompilation(
    { ...belowBoundary.translationUnits[1], cOptimizationLevel: 0 },
    command,
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy,
    staticHermesCBundleTranslationUnitBytes(belowBoundary)
  );
  assert.deepEqual(
    { optimization: explicitLevelZero.optimization, stage: explicitLevelZero.stage },
    {
      optimization: "-O0",
      stage: convexWasmStaticHermesCBundleMemberCompilationPolicy.cOptimizationLevelZero.stage,
    }
  );
});

test("binds the large-bundle threshold and flag into member compilation identity", () => {
  const fixture = bundleFixture();
  const bundle = {
    ...fixture.bundle,
    translationUnits: [
      { ...fixture.bundle.translationUnits[0], size: 1 },
      {
        ...fixture.bundle.translationUnits[1],
        size: staticHermesLargeCBundleTranslationUnitBytesThreshold - 1,
      },
    ],
  };
  const commands = { compileExportMember: { executable: "emcc", args: ["-O2", "-c"] } };
  const identity = staticHermesCBundleMemberCompilationIdentity(
    bundle,
    commands,
    "ordinary-object",
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );
  const changedThresholdPolicy = {
    ...convexWasmStaticHermesCBundleMemberCompilationPolicy,
    largeBundleFunction: {
      ...convexWasmStaticHermesCBundleMemberCompilationPolicy.largeBundleFunction,
      minimumTranslationUnitBytes: staticHermesLargeCBundleTranslationUnitBytesThreshold + 1,
    },
  };
  const changedFlagPolicy = {
    ...convexWasmStaticHermesCBundleMemberCompilationPolicy,
    largeBundleFunction: {
      ...convexWasmStaticHermesCBundleMemberCompilationPolicy.largeBundleFunction,
      optimizationFlag: "-Og",
    },
  };
  const changedThresholdIdentity = staticHermesCBundleMemberCompilationIdentity(
    bundle,
    commands,
    "ordinary-object",
    changedThresholdPolicy
  );
  const changedFlagIdentity = staticHermesCBundleMemberCompilationIdentity(
    bundle,
    commands,
    "ordinary-object",
    changedFlagPolicy
  );
  assert.equal(identity.memberCompilations[1].optimization, "-Oz");
  assert.equal(changedThresholdIdentity.memberCompilations[1].optimization, "-O2");
  assert.equal(changedFlagIdentity.memberCompilations[1].optimization, "-Og");
  assert.deepEqual(identity.memberCompilationPolicy.largeBundleFunction, {
    appliesToFunctionFragments: false,
    minimumTranslationUnitBytes: 64 * 1024 * 1024,
    optimizationFlag: "-Oz",
    role: "function",
  });
  assert.notEqual(canonicalJson(identity), canonicalJson(changedThresholdIdentity));
  assert.notEqual(canonicalJson(identity), canonicalJson(changedFlagIdentity));
});

test("authenticates C-bundle precompile and package identity inputs", () => {
  const processIdentity = staticHermesPrecompileProcessIdentity(
    {
      args: [
        "--compiler",
        "/material/compiler",
        "--",
        "-emit-c",
        "-Xemit-c-bundle",
        "-Xemit-c-shard-size=2097152",
      ],
    },
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );
  assert.deepEqual(
    processIdentity.cBundleMemberCompilationPolicy,
    convexWasmStaticHermesCBundleMemberCompilationPolicy
  );
  assert.match(processIdentity.compilerArgumentsSha256, /^[0-9a-f]{64}$/u);

  assert.equal(staticHermesCBundlePackageCompilationSha256({ cohortMembers: [] }), undefined);
  const packageSha256 = staticHermesCBundlePackageCompilationSha256({
    cohortMembers: [
      {
        assignment: { routeId: "route" },
        memberIdentities: {
          exportObject: { staticHermesCBundleMemberCompilation: { kind: "object" } },
          generatedC: {
            staticHermes: {
              precompileProcess: {
                cBundleMemberCompilationPolicy:
                  convexWasmStaticHermesCBundleMemberCompilationPolicy,
                kind: "process",
              },
            },
          },
        },
      },
    ],
  });
  assert.match(packageSha256, /^[0-9a-f]{64}$/u);
  const changedPolicy = {
    ...convexWasmStaticHermesCBundleMemberCompilationPolicy,
    largeBundleFunction: {
      ...convexWasmStaticHermesCBundleMemberCompilationPolicy.largeBundleFunction,
      minimumTranslationUnitBytes: staticHermesLargeCBundleTranslationUnitBytesThreshold + 1,
    },
  };
  const changedPackageSha256 = staticHermesCBundlePackageCompilationSha256({
    cohortMembers: [
      {
        assignment: { routeId: "route" },
        memberIdentities: {
          exportObject: {
            staticHermesCBundleMemberCompilation: {
              kind: "object",
              memberCompilationPolicy: changedPolicy,
            },
          },
          generatedC: {
            staticHermes: {
              precompileProcess: {
                cBundleMemberCompilationPolicy: changedPolicy,
                kind: "process",
              },
            },
          },
        },
      },
    ],
  });
  assert.notEqual(changedPackageSha256, packageSha256);
});
