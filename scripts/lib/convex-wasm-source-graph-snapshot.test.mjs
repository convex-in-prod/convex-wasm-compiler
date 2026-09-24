import assert from "node:assert/strict";
import test from "node:test";

import {
  authenticateConvexWasmSourceGraphSnapshot,
  createConvexWasmSourceGraphSnapshotLookupIdentity,
  createConvexWasmSourceGraphSnapshot,
  diffConvexWasmSourceGraphSnapshots,
  convexWasmSourceGraphSnapshotKind,
} from "./convex-wasm-source-graph-snapshot.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmSourceGraphSnapshotLookupScopeSha256 } from "./convex-wasm-source-graph-snapshot-cache.mjs";

const digest = (character) => character.repeat(64);

function contextReuseAnalysisIdentity(entries) {
  return {
    entries,
    kind: "convex-context-reuse-analysis",
    policyFingerprint: "d".repeat(64),
    resultSha256: "e".repeat(64),
  };
}

function gitSourceSnapshot(entries) {
  return {
    entries,
    kind: "convex-wasm-git-source-snapshot-v1",
    objectFormat: "sha1",
    pathspecs: ["convex"],
    treeOid: "1".repeat(40),
    untrackedPaths: [],
    unstagedPaths: [],
  };
}

function graphSession({ sourceDigest = digest("a"), sourceOid = "a" } = {}) {
  return {
    contextReuseAnalysisIdentity: contextReuseAnalysisIdentity(["convex/a.ts"]),
    contextReusePolicy: {
      entries: [{ enabled: true, entryPath: "convex/a.ts" }],
      kind: "convex-wasm-context-reuse-policy",
      sha256: digest("1"),
    },
    dependencyGraphByEntry: new Map([
      [
        "convex/a.ts",
        {
          inputPaths: ["convex/a.ts", "convex/shared.ts"],
          sha256: digest("c"),
        },
      ],
      [
        "convex/b.ts",
        {
          inputPaths: ["convex/b.ts", "convex/shared.ts"],
          sha256: digest("d"),
        },
      ],
    ]),
    graphTemplate: {
      assumptions: { format: "esm", platform: "browser" },
      dependencyAdapter: { kind: "fixture-dependency-adapter-v1" },
      registrationAdapter: { kind: "fixture-registration-adapter-v1" },
    },
    inputMaterials: {
      "convex/a.ts": {
        imports: [{ external: false, kind: "import-statement", path: "convex/shared.ts" }],
        sha256: sourceDigest,
        size: 1,
        virtual: false,
      },
      "convex/b.ts": { imports: [], sha256: digest("b"), size: 1, virtual: false },
      "convex/shared.ts": { imports: [], sha256: digest("c"), size: 1, virtual: false },
      "generated/runtime.js": { imports: [], virtual: true },
    },
    sourceGraphSnapshotLookupIdentity: {
      assumptions: { format: "esm", platform: "browser" },
      bundleEntryPaths: ["convex/a.ts", "convex/b.ts"],
      bundlerMaterials: { "bundler.js": { sha256: digest("2") } },
      config: { sha256: digest("3"), size: 1 },
      contextReuseAnalysis: contextReuseAnalysisIdentity(["convex/a.ts"]),
      contextReusePolicy: {
        entries: [{ enabled: true, entryPath: "convex/a.ts" }],
        kind: "convex-wasm-context-reuse-policy",
        sha256: digest("1"),
      },
      dependencyAdapterDescriptor: { kind: "fixture-dependency-adapter-descriptor-v1" },
      deploymentConfigurationEntryPath: "convex/auth.config.ts",
      effectExecutionMode: "blocking-fiber",
      kind: "convex-wasm-source-graph-snapshot-lookup-identity-v2",
      nodeEntryPaths: [],
      registrationAdapter: { kind: "fixture-registration-adapter-v1" },
      toolchain: { convex: "fixture-convex", esbuild: "fixture-esbuild" },
    },
    sourceGraphSnapshotSession: {
      activeDependencyAdapters: { kind: "fixture-active-dependency-adapters-v1" },
      authoritativeInputMaterials: {},
      bundleModulesByPath: {},
      deploymentConfigurationInputMaterials: {},
      deploymentConfigurationModulesByPath: {},
      deploymentOutputModulesByPath: {},
      metafile: { inputs: {}, outputs: {} },
      nodeInputMaterials: {},
      nodeModulesByPath: {},
    },
    toolchain: { convex: "fixture-convex", esbuild: "fixture-esbuild" },
    sourceOid,
  };
}

test("creates and authenticates a graph snapshot without changing Git authority", () => {
  const session = graphSession();
  const snapshot = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: gitSourceSnapshot([
      { mode: "100644", oid: session.sourceOid.repeat(40), path: "convex/a.ts", stage: 0 },
      { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
      { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
    ]),
    graphSession: session,
  });
  assert.equal(snapshot.kind, convexWasmSourceGraphSnapshotKind);
  assert.equal(snapshot.authority.treeOid, "1".repeat(40));
  assert.equal(snapshot.inputs["generated/runtime.js"].virtual, true);
  assert.equal(authenticateConvexWasmSourceGraphSnapshot(snapshot), snapshot);
  assert.equal(Object.isFrozen(snapshot.inputs["convex/a.ts"].imports[0]), true);
  assert.equal(Object.isFrozen(snapshot.session.metafile), true);
  assert.throws(() => {
    snapshot.inputs["convex/a.ts"].sha256 = digest("f");
  }, TypeError);
  const parsedSnapshot = authenticateConvexWasmSourceGraphSnapshot(
    JSON.parse(JSON.stringify(snapshot))
  );
  assert.deepEqual(parsedSnapshot, snapshot);
  assert.equal(authenticateConvexWasmSourceGraphSnapshot(parsedSnapshot), parsedSnapshot);
  const tampered = structuredClone(snapshot);
  tampered.inputs["convex/a.ts"].sha256 = digest("f");
  assert.throws(
    () => authenticateConvexWasmSourceGraphSnapshot(tampered),
    /snapshot SHA-256 does not match its payload/u
  );
});

test("materializes accessor authority and rejects sparse arrays before branding", () => {
  const session = graphSession();
  const authority = gitSourceSnapshot([
    { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
    { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
    { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
  ]);
  let kindReads = 0;
  Object.defineProperty(authority, "kind", {
    enumerable: true,
    get() {
      kindReads += 1;
      return kindReads === 1 ? "convex-wasm-git-source-snapshot-v1" : "tampered";
    },
  });
  const snapshot = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: authority,
    graphSession: session,
  });
  assert.equal(snapshot.authority.kind, "convex-wasm-git-source-snapshot-v1");

  const sparse = structuredClone(snapshot);
  sparse.session.metafile.sparse = new Array(1);
  const { sha256: _sha256, ...payload } = sparse;
  sparse.sha256 = fingerprintJson(payload);
  assert.throws(
    () => authenticateConvexWasmSourceGraphSnapshot(sparse),
    /cannot retain sparse arrays/u
  );
});

test("rejects graph identity that disagrees with its persisted lookup authority", () => {
  const session = graphSession();
  const snapshot = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: gitSourceSnapshot([
      { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
      { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
      { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
    ]),
    graphSession: session,
  });
  const mismatched = structuredClone(snapshot);
  mismatched.identity.registrationAdapter = { kind: "foreign-registration-adapter-v1" };
  const { sha256: _sha256, ...payload } = mismatched;
  mismatched.sha256 = fingerprintJson(payload);

  assert.throws(
    () => authenticateConvexWasmSourceGraphSnapshot(mismatched),
    /identity registrationAdapter disagrees with its lookup identity/u
  );
});

test("diff invalidates only entries whose recorded closures contain changed paths", () => {
  const beforeSession = graphSession();
  const beforeAuthority = gitSourceSnapshot([
    { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
    { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
    { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
  ]);
  const before = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: beforeAuthority,
    graphSession: beforeSession,
  });
  const afterSession = graphSession({ sourceDigest: digest("e"), sourceOid: "e" });
  const after = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: gitSourceSnapshot([
      { mode: "100644", oid: "e".repeat(40), path: "convex/a.ts", stage: 0 },
      { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
      { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
    ]),
    graphSession: afterSession,
  });
  assert.deepEqual(
    diffConvexWasmSourceGraphSnapshots({ fromSnapshot: before, toSnapshot: after }),
    {
      changedPaths: ["convex/a.ts"],
      globalInvalidation: false,
      invalidatedEntries: ["convex/a.ts"],
      invalidatedInputPaths: ["convex/a.ts", "convex/shared.ts"],
    }
  );
});

test("identity changes force global invalidation even when Git entries are unchanged", () => {
  const authority = gitSourceSnapshot([
    { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
    { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
    { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
  ]);
  const before = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: authority,
    graphSession: graphSession(),
  });
  const changedSession = graphSession();
  changedSession.graphTemplate.assumptions = { format: "cjs", platform: "browser" };
  changedSession.sourceGraphSnapshotLookupIdentity.assumptions = {
    format: "cjs",
    platform: "browser",
  };
  const after = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: authority,
    graphSession: changedSession,
  });
  const result = diffConvexWasmSourceGraphSnapshots({ fromSnapshot: before, toSnapshot: after });
  assert.equal(result.globalInvalidation, true);
  assert.deepEqual(result.invalidatedEntries, ["convex/a.ts", "convex/b.ts"]);
});

test("graph assumptions rotate source-graph lookup scope", () => {
  const session = graphSession();
  const authority = gitSourceSnapshot([
    { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
  ]);
  const baseAssumptions = {
    ...session.sourceGraphSnapshotLookupIdentity.assumptions,
    graphConstructionSemanticRevision: "source-graph-fixture",
  };
  const baseLookup = createConvexWasmSourceGraphSnapshotLookupIdentity({
    ...session.sourceGraphSnapshotLookupIdentity,
    assumptions: baseAssumptions,
  });
  const changedLookup = createConvexWasmSourceGraphSnapshotLookupIdentity({
    ...session.sourceGraphSnapshotLookupIdentity,
    assumptions: {
      ...baseAssumptions,
      graphConstructionSemanticRevision: "source-graph-fixture-changed",
    },
  });
  const scope = (lookupIdentity) =>
    convexWasmSourceGraphSnapshotLookupScopeSha256({
      entryPaths: ["convex/a.ts"],
      gitSourceSnapshot: authority,
      lookupIdentity,
    });

  assert.notEqual(scope(changedLookup), scope(baseLookup));
});

test("diff treats added and removed input materials as changed paths", () => {
  const authority = gitSourceSnapshot([
    { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
    { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
    { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
  ]);
  const before = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: authority,
    graphSession: graphSession(),
  });
  const addedSession = graphSession();
  addedSession.inputMaterials["convex/new.ts"] = {
    imports: [],
    sha256: digest("e"),
    size: 1,
    virtual: false,
  };
  const added = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: authority,
    graphSession: addedSession,
  });
  assert.deepEqual(
    diffConvexWasmSourceGraphSnapshots({ fromSnapshot: before, toSnapshot: added }),
    {
      changedPaths: ["convex/new.ts"],
      globalInvalidation: false,
      invalidatedEntries: [],
      invalidatedInputPaths: ["convex/new.ts"],
    }
  );

  const removedSession = graphSession();
  removedSession.inputMaterials = { ...removedSession.inputMaterials };
  delete removedSession.inputMaterials["convex/b.ts"];
  removedSession.dependencyGraphByEntry = new Map([
    ["convex/a.ts", removedSession.dependencyGraphByEntry.get("convex/a.ts")],
    [
      "convex/b.ts",
      {
        inputPaths: ["convex/shared.ts"],
        sha256: digest("d"),
      },
    ],
  ]);
  const removed = createConvexWasmSourceGraphSnapshot({
    gitSourceSnapshot: authority,
    graphSession: removedSession,
  });
  assert.deepEqual(
    diffConvexWasmSourceGraphSnapshots({ fromSnapshot: before, toSnapshot: removed }).changedPaths,
    ["convex/b.ts"]
  );
});

test("rejects a dependency closure that omits its authenticated input record", () => {
  const authority = gitSourceSnapshot([
    { mode: "100644", oid: "a".repeat(40), path: "convex/a.ts", stage: 0 },
    { mode: "100644", oid: "b".repeat(40), path: "convex/b.ts", stage: 0 },
    { mode: "100644", oid: "c".repeat(40), path: "convex/shared.ts", stage: 0 },
  ]);
  const session = graphSession();
  session.dependencyGraphByEntry.get("convex/a.ts").inputPaths = ["convex/a.ts", "missing.ts"];
  assert.throws(
    () =>
      createConvexWasmSourceGraphSnapshot({
        gitSourceSnapshot: authority,
        graphSession: session,
      }),
    /references missing input missing\.ts/u
  );
});
