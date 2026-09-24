import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson, normalizeJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  convexWasmCompilerTopologyWitnessPointerPath,
  createConvexWasmCompilerTopologyWitnessIdentity,
  createConvexWasmCompilerTopologyWitnessPointer,
  normalizeConvexWasmCompilerDescriptorCacheProjection,
  projectConvexWasmCompilerDescriptorTopology,
  readConvexWasmCompilerTopologyWitnessPointer,
  writeConvexWasmCompilerTopologyWitnessPointer,
} from "./convex-wasm-compiler-topology-witness.mjs";

const sha256 = (character) => character.repeat(64);

function descriptor({
  dependencyPath = "shared.js",
  dependencySlot = 1,
  executableSpecifier = `./__convex_wasm_dependency_import_statement_${sha256("e")}_00000000.js`,
  specifier = "./shared.js",
} = {}) {
  const routes = [{ exportName: "run", udfKind: "query", visibility: "public" }];
  const sourceMembershipSha256 = sha256("d");
  const sourceSha256 = sha256("3");
  const chunkUnit = {
    dependencies: [
      {
        executableSpecifier,
        kind: "import-statement",
        path: dependencyPath,
        slot: dependencySlot,
        specifier,
      },
    ],
    javascript: { sha256: sha256("1"), size: 10 },
    kind: "convex-wasm-official-output-chunk-v1",
    module: {
      environment: "isolate",
      moduleSha256: sha256("2"),
      path: "entry.js",
      sourceMap: {
        sha256: sha256("0"),
        size: 10,
        sourcesContentCount: 1,
        sourcesCount: 1,
      },
      sourceMembershipSha256,
      sourceSha256,
      sourceSize: 10,
    },
    nativeSymbolLocator: {
      bindingPath: { entryPath: "functions/entry.ts", imports: [] },
      canonicalEntryPath: "functions/entry.ts",
      kind: "convex-wasm-official-output-chunk-native-symbol-locator-v5",
      sourceMembershipSha256,
      symbolAbi: "convex-wasm-official-output-chunk-native-symbol-abi-v1",
    },
    sha256: sha256("4"),
    slot: 0,
    transform: { format: "cjs" },
  };
  const dependencySourceMembershipSha256 = sha256("f");
  const dependencyChunkUnit = {
    ...chunkUnit,
    dependencies: [],
    module: {
      ...chunkUnit.module,
      path: dependencyPath,
      sourceMembershipSha256: dependencySourceMembershipSha256,
    },
    nativeSymbolLocator: {
      ...chunkUnit.nativeSymbolLocator,
      bindingPath: {
        entryPath: `source-membership:${dependencySourceMembershipSha256}`,
        imports: [],
      },
      canonicalEntryPath: null,
      sourceMembershipSha256: dependencySourceMembershipSha256,
    },
    slot: 1,
  };
  const publicationUnit = {
    entry: { entryPath: "functions/entry.ts", entrySlot: 0, handoffSlot: 0, routes },
    javascript: { sha256: sha256("5"), size: 10 },
    kind: "convex-wasm-official-output-entry-publication-v1",
    sha256: sha256("6"),
    slot: 2,
  };
  const applicationEntry = {
    dependencyGraphSha256: sha256("7"),
    entryModulePath: "entry.js",
    entryPath: "functions/entry.ts",
    entryPublicationUnitSlot: 2,
    entrySlot: 0,
    handoffSlot: 0,
    modulePath: "entry",
    routes,
  };
  return {
    applicationIdentity: {
      chunkUnits: { kind: "chunks", sha256: sha256("8") },
      dependencyGraphSha256: sha256("9"),
      entries: [applicationEntry],
      initialization: {
        chunkSlotCount: 2,
        entryPublicationUnitSlots: [2],
        kind: "closed-slots",
        namespaceSlotCount: 2,
      },
      kind: "application",
      nativeDescriptor: { initialization: "recursive" },
      sha256: sha256("a"),
      unitCount: 3,
      units: [chunkUnit, dependencyChunkUnit, publicationUnit],
    },
    chunkUnitsIdentity: {
      entries: [
        {
          dependencyGraphSha256: applicationEntry.dependencyGraphSha256,
          entryModulePath: applicationEntry.entryModulePath,
          entryPath: applicationEntry.entryPath,
          entrySlot: applicationEntry.entrySlot,
          modulePath: applicationEntry.modulePath,
          routes,
        },
      ],
      esbuild: { version: "1.0.0" },
      initialization: { kind: "closed-numbered-slots" },
      kind: "chunks",
      sha256: sha256("b"),
      units: [chunkUnit, dependencyChunkUnit],
    },
    identitySha256: sha256("c"),
    kind: "convex-wasm-official-output-module-graph-compiler-cache-descriptor-v2",
    schemaVersion: 2,
  };
}

function cacheIdentity({ engine = "d", material = "e", producer = "f" } = {}) {
  return {
    cohortInputsSha256: sha256("1"),
    descriptorIdentitySha256: sha256("2"),
    engineCompatibilitySha256: sha256(engine),
    kind: "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v8",
    materialSessionSha256: sha256(material),
    producerIdentitySha256: sha256(producer),
    topologyWitnessMaterialIdentitySha256: sha256(material),
  };
}

test("compiler topology witness ignores producer rotation but binds physical topology, material, and engine", () => {
  const originalDescriptor = descriptor();
  const sourceMapChangedDescriptor = structuredClone(originalDescriptor);
  sourceMapChangedDescriptor.applicationIdentity.units[0].module.moduleSha256 = sha256("0");
  sourceMapChangedDescriptor.applicationIdentity.units[0].module.sourceMap = {
    sha256: sha256("0"),
    size: 20,
    sourcesContentCount: 0,
    sourcesCount: 1,
  };
  sourceMapChangedDescriptor.chunkUnitsIdentity.units[0] = structuredClone(
    sourceMapChangedDescriptor.applicationIdentity.units[0]
  );
  const contentChangedDescriptor = structuredClone(originalDescriptor);
  contentChangedDescriptor.applicationIdentity.units[0].javascript = {
    sha256: sha256("0"),
    size: 20,
  };
  contentChangedDescriptor.applicationIdentity.units[0].module.sourceSha256 = sha256("0");
  contentChangedDescriptor.applicationIdentity.units[0].sha256 = sha256("0");
  contentChangedDescriptor.chunkUnitsIdentity.units[0] = structuredClone(
    contentChangedDescriptor.applicationIdentity.units[0]
  );
  contentChangedDescriptor.applicationIdentity.sha256 = sha256("0");
  contentChangedDescriptor.chunkUnitsIdentity.sha256 = sha256("0");
  contentChangedDescriptor.identitySha256 = sha256("0");
  const identity = createConvexWasmCompilerTopologyWitnessIdentity({
    compilerOutputCacheIdentity: cacheIdentity(),
    descriptor: originalDescriptor,
    valueMode: "guest-native-json",
  });
  assert.equal(
    identity.kind,
    "convex-wasm-official-output-module-graph-compiler-topology-witness-identity-v7"
  );
  assert.deepEqual(
    createConvexWasmCompilerTopologyWitnessIdentity({
      compilerOutputCacheIdentity: cacheIdentity(),
      descriptor: sourceMapChangedDescriptor,
      valueMode: "guest-native-json",
    }),
    identity
  );

  const dependencyContentChangedDescriptor = structuredClone(originalDescriptor);
  dependencyContentChangedDescriptor.applicationIdentity.units[1].javascript = {
    sha256: sha256("0"),
    size: 20,
  };
  dependencyContentChangedDescriptor.applicationIdentity.units[1].module.moduleSha256 = sha256("0");
  dependencyContentChangedDescriptor.applicationIdentity.units[1].module.sourceSha256 = sha256("0");
  dependencyContentChangedDescriptor.applicationIdentity.units[1].sha256 = sha256("0");
  dependencyContentChangedDescriptor.chunkUnitsIdentity.units[1] = structuredClone(
    dependencyContentChangedDescriptor.applicationIdentity.units[1]
  );
  assert.deepEqual(
    createConvexWasmCompilerTopologyWitnessIdentity({
      compilerOutputCacheIdentity: cacheIdentity(),
      descriptor: dependencyContentChangedDescriptor,
      valueMode: "guest-native-json",
    }),
    identity
  );
  assert.deepEqual(
    createConvexWasmCompilerTopologyWitnessIdentity({
      compilerOutputCacheIdentity: cacheIdentity(),
      descriptor: contentChangedDescriptor,
      valueMode: "guest-native-json",
    }),
    identity
  );

  const membershipChangedDescriptor = structuredClone(originalDescriptor);
  membershipChangedDescriptor.applicationIdentity.units[0].module.sourceMembershipSha256 =
    sha256("0");
  membershipChangedDescriptor.applicationIdentity.units[0].nativeSymbolLocator.sourceMembershipSha256 =
    sha256("0");
  membershipChangedDescriptor.chunkUnitsIdentity.units[0] = structuredClone(
    membershipChangedDescriptor.applicationIdentity.units[0]
  );
  assert.notDeepEqual(
    createConvexWasmCompilerTopologyWitnessIdentity({
      compilerOutputCacheIdentity: cacheIdentity(),
      descriptor: membershipChangedDescriptor,
      valueMode: "guest-native-json",
    }),
    identity
  );
  assert.deepEqual(
    createConvexWasmCompilerTopologyWitnessIdentity({
      compilerOutputCacheIdentity: cacheIdentity({ producer: "0" }),
      descriptor: originalDescriptor,
      valueMode: "guest-native-json",
    }),
    identity
  );

  assert.notDeepEqual(
    createConvexWasmCompilerTopologyWitnessIdentity({
      compilerOutputCacheIdentity: cacheIdentity(),
      descriptor: descriptor({
        executableSpecifier: `./__convex_wasm_dependency_import_statement_${sha256("f")}_00000000.js`,
      }),
      valueMode: "guest-native-json",
    }),
    identity
  );

  for (const changed of [
    { descriptor: descriptor({ specifier: "./renamed.js" }) },
    {
      descriptor: descriptor({
        executableSpecifier: `./__convex_wasm_dependency_import_statement_${sha256("e")}_00000001.js`,
      }),
    },
    { descriptor: descriptor({ dependencyPath: "renamed.js" }) },
    { descriptor: descriptor({ dependencySlot: 0 }) },
    { compilerOutputCacheIdentity: cacheIdentity({ engine: "0" }) },
    { compilerOutputCacheIdentity: cacheIdentity({ material: "0" }) },
    { valueMode: "different-value-mode" },
  ]) {
    assert.notDeepEqual(
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: changed.compilerOutputCacheIdentity ?? cacheIdentity(),
        descriptor: changed.descriptor ?? originalDescriptor,
        valueMode: changed.valueMode ?? "guest-native-json",
      }),
      identity
    );
  }
});

test("compiler topology witness retains owned immutable topology without changing identity bytes", () => {
  const rawDescriptor = descriptor();
  const normalizedDescriptor = normalizeConvexWasmCompilerDescriptorCacheProjection(rawDescriptor);
  const topology = projectConvexWasmCompilerDescriptorTopology(normalizedDescriptor);
  const compilerOutputCacheIdentity = cacheIdentity();
  const identity = createConvexWasmCompilerTopologyWitnessIdentity({
    compilerOutputCacheIdentity,
    descriptor: normalizedDescriptor,
    valueMode: "guest-native-json",
  });
  const normalizedCopy = normalizeJson(identity, "test witness identity");
  const source = canonicalJson(normalizedCopy);
  const digest = fingerprintJson(normalizedCopy);
  assert.strictEqual(identity.topology, topology);
  assert.equal(JSON.stringify(identity), source);
  assert.equal(fingerprintJson(identity), digest);
  assert.throws(() => {
    identity.valueMode = "changed";
  }, TypeError);
  assert.throws(() => {
    identity.topology.application.entries[0].routes[0].exportName = "changed";
  }, TypeError);

  rawDescriptor.applicationIdentity.entries[0].routes[0].exportName = "changed";
  compilerOutputCacheIdentity.engineCompatibilitySha256 = sha256("0");
  assert.equal(canonicalJson(identity), source);
  assert.equal(fingerprintJson(identity), digest);
  assert.equal(
    createConvexWasmCompilerTopologyWitnessPointer({
      compilerOutputCacheKey: sha256("1"),
      compilerOutputCacheRecordSha256: sha256("2"),
      compilerOutputTopologyCertificateCacheKey: sha256("3"),
      identity,
    }).topologyIdentitySha256,
    digest
  );
});

test("compiler topology witness validates omitted identity fields and full native locators", () => {
  const originalDescriptor = descriptor();
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: {
          ...cacheIdentity(),
          kind: "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v7",
        },
        descriptor: originalDescriptor,
        valueMode: "guest-native-json",
      }),
    /cache identity has an unsupported schema/u
  );
  const invalidLocatorDescriptor = structuredClone(originalDescriptor);
  invalidLocatorDescriptor.applicationIdentity.units[0].nativeSymbolLocator.symbolAbi =
    "invalid-abi";
  invalidLocatorDescriptor.chunkUnitsIdentity.units[0] = structuredClone(
    invalidLocatorDescriptor.applicationIdentity.units[0]
  );
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: cacheIdentity(),
        descriptor: invalidLocatorDescriptor,
        valueMode: "guest-native-json",
      }),
    /native symbol locator ABI is unsupported/u
  );
  const invalidBindingPathDescriptor = structuredClone(originalDescriptor);
  invalidBindingPathDescriptor.applicationIdentity.units[1].nativeSymbolLocator.bindingPath = {
    entryPath: "functions/entry.ts",
    imports: [{ kind: "unsupported", occurrence: 0 }],
  };
  invalidBindingPathDescriptor.chunkUnitsIdentity.units[1] = structuredClone(
    invalidBindingPathDescriptor.applicationIdentity.units[1]
  );
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: cacheIdentity(),
        descriptor: invalidBindingPathDescriptor,
        valueMode: "guest-native-json",
      }),
    /binding path import 0 kind is unsupported/u
  );
  const redirectedModuleIdentityDescriptor = structuredClone(originalDescriptor);
  redirectedModuleIdentityDescriptor.applicationIdentity.units[0].nativeSymbolLocator.canonicalEntryPath =
    null;
  redirectedModuleIdentityDescriptor.chunkUnitsIdentity.units[0] = structuredClone(
    redirectedModuleIdentityDescriptor.applicationIdentity.units[0]
  );
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: cacheIdentity(),
        descriptor: redirectedModuleIdentityDescriptor,
        valueMode: "guest-native-json",
      }),
    /native symbol locator changed its module identity/u
  );
  const legacyLocatorDescriptor = structuredClone(originalDescriptor);
  const legacyLocator = legacyLocatorDescriptor.applicationIdentity.units[0].nativeSymbolLocator;
  legacyLocator.executableSourceSha256 = sha256("3");
  delete legacyLocator.symbolAbi;
  legacyLocatorDescriptor.chunkUnitsIdentity.units[0] = structuredClone(
    legacyLocatorDescriptor.applicationIdentity.units[0]
  );
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: cacheIdentity(),
        descriptor: legacyLocatorDescriptor,
        valueMode: "guest-native-json",
      }),
    /native symbol locator has unknown field\(s\): executableSourceSha256/u
  );

  const missingProducerIdentity = cacheIdentity();
  delete missingProducerIdentity.producerIdentitySha256;
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: missingProducerIdentity,
        descriptor: originalDescriptor,
        valueMode: "guest-native-json",
      }),
    /producer identity/u
  );
  assert.throws(
    () =>
      createConvexWasmCompilerTopologyWitnessIdentity({
        compilerOutputCacheIdentity: { ...cacheIdentity(), unexpected: sha256("0") },
        descriptor: originalDescriptor,
        valueMode: "guest-native-json",
      }),
    /unknown field\(s\): unexpected/u
  );
});

test("compiler topology witness pointer replacement is atomic and never crosses topology keys", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-compiler-topology-witness-"));
  await fs.chmod(cacheRoot, 0o700);
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "compiler-topology-witness",
    cacheRoot,
    scope: "isolated-test",
    repositoryRoot: dirname(cacheRoot),
  });
  const identity = createConvexWasmCompilerTopologyWitnessIdentity({
    compilerOutputCacheIdentity: cacheIdentity(),
    descriptor: descriptor(),
    valueMode: "guest-native-json",
  });
  const pointers = ["1", "2"].map((character) =>
    createConvexWasmCompilerTopologyWitnessPointer({
      compilerOutputCacheKey: sha256(character),
      compilerOutputCacheRecordSha256: sha256(character),
      compilerOutputTopologyCertificateCacheKey: sha256(character),
      identity,
    })
  );
  await Promise.all(
    Array.from({ length: 16 }, (_, index) =>
      writeConvexWasmCompilerTopologyWitnessPointer({
        cacheLayout,
        cacheRoot,
        identity,
        pointer: pointers[index % pointers.length],
      })
    )
  );
  const selected = await readConvexWasmCompilerTopologyWitnessPointer({
    cacheLayout,
    cacheRoot,
    identity,
  });
  assert.ok(pointers.some((pointer) => canonicalJson(pointer) === canonicalJson(selected)));

  const path = convexWasmCompilerTopologyWitnessPointerPath(cacheLayout, identity);
  const moved = { ...selected, topologyIdentitySha256: sha256("0") };
  await fs.writeFile(path, `${canonicalJson(moved)}\n`);
  await assert.rejects(
    readConvexWasmCompilerTopologyWitnessPointer({ cacheLayout, cacheRoot, identity }),
    /moved to a different topology identity/u
  );

  const changedMaterialIdentity = createConvexWasmCompilerTopologyWitnessIdentity({
    compilerOutputCacheIdentity: cacheIdentity({ material: "0" }),
    descriptor: descriptor(),
    valueMode: "guest-native-json",
  });
  const changedMaterialPath = convexWasmCompilerTopologyWitnessPointerPath(
    cacheLayout,
    changedMaterialIdentity
  );
  await fs.writeFile(changedMaterialPath, `${canonicalJson(selected)}\n`);
  await fs.chmod(changedMaterialPath, 0o600);
  await assert.rejects(
    readConvexWasmCompilerTopologyWitnessPointer({
      cacheLayout,
      cacheRoot,
      identity: changedMaterialIdentity,
    }),
    /moved to a different topology identity/u
  );
});
