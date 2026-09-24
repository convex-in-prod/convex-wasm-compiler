import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { acquireConvexWasmCacheLock } from "./convex-wasm-cache-lock.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { fingerprintMaterialPaths } from "./convex-wasm-artifact-material.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "./convex-wasm-module-graph-package.mjs";
import {
  C_BUNDLE_CACHE_ENTRY_KIND,
  C_BUNDLE_KIND,
  C_BUNDLE_MANIFEST_PATH,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import {
  convexWasmBuildWorkRecordName,
  createConvexWasmBuildWorkLease,
  maintainConvexWasmCache,
  measureConvexWasmCacheOccupancy,
  recordConvexWasmSuccessfulCacheUse,
} from "./convex-wasm-cache-retention.mjs";
import {
  planConvexWasmImmutableGc,
  sweepConvexWasmImmutableGc,
} from "./convex-wasm-cache-retention-immutable.mjs";
import { loadOrCreateConvexWasmRuntimeHeaderSnapshotCache } from "./convex-wasm-runtime-header-snapshot-cache.mjs";

async function fixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-cache-retention-"));
  await fs.chmod(root, 0o700);
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheRoot = join(root, "cache");
  const environment = {
    CONVEX_WASM_CACHE_LOCK_DB: join(root, "cache-lock.sqlite"),
  };
  const layout = (buildId) =>
    deriveConvexWasmCacheLayout({
      buildId,
      cacheRoot, scope: "isolated-test",
      repositoryRoot: root,
    });
  return { cacheRoot, environment, layout, root };
}

async function withHeavyLock(environment, operation) {
  const release = await acquireConvexWasmCacheLock({ environment });
  try {
    return await operation();
  } finally {
    release();
  }
}

function maintenanceOptions(fixtureValue, overrides = {}) {
  return {
    abandonedRecoveryMilliseconds: 1_000,
    cacheRoot: fixtureValue.cacheRoot,
    completedRetentionMilliseconds: 1_000,
    environment: fixtureValue.environment,
    includeImmutableOccupancy: false,
    quiescentMilliseconds: 1_000,
    ...overrides,
  };
}

async function writeGenericArtifact({
  cacheLayout,
  extension,
  identity: rawIdentity,
  metadata,
  payload,
  stage,
}) {
  const identity = rawIdentity ?? { fixture: "cache-retention", stage };
  const key = fingerprintJson({
    identity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage,
  });
  const artifact = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const entry = {
    artifactFile: `artifact.${extension}`,
    artifactSha256: createHash("sha256").update(artifact).digest("hex"),
    artifactSize: artifact.length,
    identity,
    key,
    kind: "convex-wasm-artifact-cache-entry-v5",
    metadata,
    stage,
  };
  const root = join(cacheLayout.immutable.artifacts, stage, key);
  await fs.mkdir(root, { mode: 0o700, recursive: true });
  await fs.chmod(join(cacheLayout.immutable.artifacts, stage), 0o700);
  await fs.chmod(root, 0o700);
  await Promise.all([
    fs.writeFile(join(root, entry.artifactFile), artifact, { mode: 0o600 }),
    fs.writeFile(join(root, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
    fs.writeFile(join(root, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
  ]);
  return { entry, key, stage };
}

async function ageGenericArtifact(cacheLayout, { key, stage }) {
  const root = join(cacheLayout.immutable.artifacts, stage, key);
  await Promise.all(
    (await fs.readdir(root)).map((name) => fs.utimes(join(root, name), new Date(0), new Date(0)))
  );
  await fs.utimes(root, new Date(0), new Date(0));
}

function packageFileMaterial(value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`);
  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  };
}

async function writeLegacyV2ModuleGraphPackage(cacheLayout) {
  const coreWasmContract = { fixture: "legacy-v2-core-wasm-contract" };
  const coreWasm = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { contract: coreWasmContract },
    payload: "legacy-v2-core-wasm",
    stage: "legacy-v2-core-wasm",
  });
  const aot = await writeGenericArtifact({
    cacheLayout,
    extension: "cwasm",
    metadata: { fixture: "legacy-v2-aot" },
    payload: "legacy-v2-aot",
    stage: "legacy-v2-aot",
  });
  const producerImplementation = {
    kind: "convex-wasm-artifact-producer-identity-v1",
    sha256: "a".repeat(64),
  };
  const artifacts = {
    aot: {
      cacheKey: aot.key,
      sha256: aot.entry.artifactSha256,
      size: aot.entry.artifactSize,
      stage: aot.stage,
    },
    coreWasm: {
      cacheKey: coreWasm.key,
      sha256: coreWasm.entry.artifactSha256,
      size: coreWasm.entry.artifactSize,
      stage: coreWasm.stage,
    },
  };
  const common = {
    engine: { fixture: "legacy-v2-engine" },
    hostAbi: { fixture: "legacy-v2-host-abi" },
    routing: { fixture: "legacy-v2-routing" },
    sharedShards: { fixture: "legacy-v2-shared-shards" },
    toolchain: { fixture: "legacy-v2-toolchain" },
  };
  const manifestPayload = {
    ...common,
    initialization: { fixture: "legacy-v2-initialization" },
    kind: "convex-wasm-module-graph-manifest-v2",
    modules: [{ artifacts, contract: coreWasmContract, role: "base" }],
    producerImplementation,
    replacement: { fixture: "legacy-v2-replacement" },
    schemaVersion: 2,
  };
  const key = fingerprintJson(manifestPayload);
  const manifest = { ...manifestPayload, graphManifestSha256: key };
  const provenance = {
    ...common,
    identities: {
      base: {
        aot: aot.entry.identity,
        coreWasm: coreWasm.entry.identity,
      },
    },
    kind: "convex-wasm-module-graph-provenance-v2",
    producerIdentity: {
      ...producerImplementation,
      manifest: { fixture: "legacy-v2-producer-manifest" },
    },
    schemaVersion: 2,
  };
  const entry = {
    artifacts: { base: artifacts },
    key,
    kind: "convex-wasm-module-graph-package-v2",
    manifest: packageFileMaterial(manifest),
    provenance: packageFileMaterial(provenance),
  };
  const root = join(cacheLayout.immutable.packages, key);
  await fs.mkdir(root, { mode: 0o700, recursive: true });
  for (const directory of [
    cacheLayout.cacheRoot,
    join(cacheLayout.cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.packages,
    root,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  await Promise.all([
    fs.writeFile(join(root, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
    fs.writeFile(join(root, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
      mode: 0o600,
    }),
    fs.writeFile(join(root, "graph-manifest.json"), `${canonicalJson(manifest)}\n`, {
      mode: 0o600,
    }),
    fs.writeFile(join(root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    }),
  ]);
  return { aot, artifacts, coreWasm, entry, key, manifest, provenance, root };
}

async function writeCBundleArtifact({ cacheLayout, complete = true, functionCount = 1, stage }) {
  const sources = new Map([
    ["unit.h", "#define SH_UNIT 1\n"],
    ["metadata.c", "const int metadata = 1;\n"],
  ]);
  for (let index = 0; index < functionCount; index += 1) {
    sources.set(`function-${String(index)}.c`, `int f${String(index)}(void) { return 0; }\n`);
  }
  const member = (path, role, extra = {}) => {
    const source = sources.get(path);
    return {
      path,
      role,
      sha256: createHash("sha256").update(source).digest("hex"),
      size: Buffer.byteLength(source),
      ...extra,
    };
  };
  const header = member("unit.h", "header");
  const translationUnits = [member("metadata.c", "metadata")];
  for (let index = 0; index < functionCount; index += 1) {
    translationUnits.push(
      member(`function-${String(index)}.c`, "function", {
        firstFunctionId: index,
        functionCount: 1,
        lastFunctionId: index,
        oversize: false,
        targetBytes: 2_097_152,
      })
    );
  }
  const manifest = {
    header,
    kind: C_BUNDLE_KIND,
    schemaVersion: 1,
    translationUnits,
  };
  const manifestSource = `${canonicalJson(manifest)}\n`;
  const bundle = {
    ...manifest,
    manifest: {
      path: C_BUNDLE_MANIFEST_PATH,
      sha256: createHash("sha256").update(manifestSource).digest("hex"),
      size: Buffer.byteLength(manifestSource),
    },
  };
  const identity = { fixture: "cache-retention-c-bundle", stage };
  const key = fingerprintJson({
    identity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage,
  });
  const entry = {
    artifactSha256: bundle.manifest.sha256,
    artifactSize: [...sources.values()].reduce(
      (size, source) => size + Buffer.byteLength(source),
      0
    ),
    bundle,
    identity,
    key,
    kind: C_BUNDLE_CACHE_ENTRY_KIND,
    metadata: { fixture: true },
    stage,
  };
  const root = join(cacheLayout.immutable.artifacts, stage, key);
  await fs.mkdir(root, { mode: 0o700, recursive: true });
  for (const directory of [
    cacheLayout.cacheRoot,
    join(cacheLayout.cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.artifacts,
    join(cacheLayout.immutable.artifacts, stage),
    root,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  await Promise.all([
    fs.writeFile(join(root, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
    fs.writeFile(join(root, C_BUNDLE_MANIFEST_PATH), manifestSource, { mode: 0o600 }),
    ...[...sources].map(([path, source]) =>
      fs.writeFile(join(root, path), source, { mode: 0o600 })
    ),
    ...(complete ? [fs.writeFile(join(root, "COMPLETE"), `${key}\n`, { mode: 0o600 })] : []),
  ]);
  return { entry, key, root, stage };
}

function compilerOutputReference({ entry, extension, key, stage }) {
  return { entry, extension, report: { cacheKey: key, stage } };
}

function compilerOutputCacheIdentity(descriptorIdentitySha256 = "a".repeat(64)) {
  return {
    cohortInputsSha256: "1".repeat(64),
    descriptorIdentitySha256,
    engineCompatibilitySha256: "3".repeat(64),
    kind: "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v8",
    materialSessionSha256: "4".repeat(64),
    producerIdentitySha256: "5".repeat(64),
    topologyWitnessMaterialIdentitySha256: "6".repeat(64),
  };
}

function compilerOutputDescriptorFixture({ historicalPreTransport = false } = {}) {
  const chunkKind = historicalPreTransport
    ? "convex-wasm-official-output-chunk-units-v2"
    : "convex-wasm-official-output-chunk-units-v3";
  const module = {
    environment: "isolate",
    moduleSha256: "1".repeat(64),
    path: "fixture.js",
    sourceMap: { sha256: "2".repeat(64), size: 1, sourcesContentCount: 0, sourcesCount: 1 },
    sourceMembershipSha256: "3".repeat(64),
    sourceSha256: "4".repeat(64),
    sourceSize: 1,
  };
  const transform = {
    format: "cjs",
    kind: historicalPreTransport
      ? "convex-wasm-esbuild-closed-chunk-transform-v1"
      : "convex-wasm-esbuild-closed-chunk-transform-v2",
    minifyIdentifiers: true,
    minifySyntax: true,
    minifyWhitespace: false,
    platform: "browser",
    sourcemap: false,
    supported: {
      "async-generator": false,
      "class-static-blocks": false,
      "dynamic-import": false,
      "logical-assignment": false,
      "object-rest-spread": false,
    },
    target: "esnext",
    treeShaking: false,
  };
  const chunkUnitPayload = {
    dependencies: [],
    javascript: { sha256: "5".repeat(64), size: 1 },
    kind: historicalPreTransport
      ? "convex-wasm-official-output-chunk-unit-v1"
      : "convex-wasm-official-output-chunk-unit-v2",
    module,
    nativeSymbolLocator: historicalPreTransport
      ? {
          kind: "convex-wasm-official-output-chunk-native-symbol-locator-v1",
          sourceMembershipSha256: module.sourceMembershipSha256,
          sourceSha256: module.sourceSha256,
        }
      : {
          bindingPath: { entryPath: "fixture.ts", imports: [] },
          canonicalEntryPath: "fixture.ts",
          kind: "convex-wasm-official-output-chunk-native-symbol-locator-v5",
          sourceMembershipSha256: module.sourceMembershipSha256,
          symbolAbi: "convex-wasm-official-output-chunk-native-symbol-abi-v1",
        },
    slot: 0,
    transform,
  };
  const chunkUnit = { ...chunkUnitPayload, sha256: fingerprintJson(chunkUnitPayload) };
  const routes = [{ exportName: "fixture", udfKind: "query", visibility: "public" }];
  const publicationUnitPayload = {
    entry: { entryPath: "fixture.ts", entrySlot: 0, handoffSlot: 0, routes },
    javascript: { sha256: "7".repeat(64), size: 1 },
    kind: "convex-wasm-official-output-chunk-entry-publication-unit-v2",
    slot: 1,
  };
  const publicationUnit = {
    ...publicationUnitPayload,
    sha256: fingerprintJson(publicationUnitPayload),
  };
  const chunkEntries = [
    {
      dependencyGraphSha256: "8".repeat(64),
      entryModulePath: module.path,
      entryPath: "fixture.ts",
      entrySlot: 0,
      modulePath: "fixture",
      routes,
    },
  ];
  const applicationEntries = [{ ...chunkEntries[0], entryPublicationUnitSlot: 1, handoffSlot: 0 }];
  const chunkUnitsPayload = {
    entries: chunkEntries,
    esbuild: { version: "fixture" },
    initialization: {
      dynamicImport: "literal-require-after-promise-microtask",
      kind: "closed-numbered-namespace-slots-v1",
      publication: "selected-entry-namespaces-after-selected-closure-initialization",
    },
    kind: chunkKind,
    units: [chunkUnit],
  };
  const chunkUnitsIdentity = {
    ...chunkUnitsPayload,
    sha256: fingerprintJson(chunkUnitsPayload),
  };
  const applicationPayload = {
    chunkUnits: { kind: chunkKind, sha256: chunkUnitsIdentity.sha256 },
    dependencyGraphSha256: "9".repeat(64),
    entries: applicationEntries,
    initialization: {
      chunkSlotCount: 1,
      entryPublicationUnitSlots: [1],
      kind: "closed-numbered-chunk-slots-with-per-entry-publication-v1",
      namespaceSlotCount: 1,
    },
    kind: historicalPreTransport
      ? "convex-wasm-official-output-chunk-application-unit-v2"
      : "convex-wasm-official-output-chunk-application-unit-v3",
    nativeDescriptor: {
      destruction: "destroy-store-on-any-initialization-failure",
      initialization: "recursive-closed-literal-require-with-provisional-cjs-namespaces",
      kind: historicalPreTransport
        ? "convex-wasm-official-output-chunk-native-descriptor-abi-v2"
        : "convex-wasm-official-output-chunk-native-descriptor-abi-v3",
      publication:
        "authenticated-selected-entry-wrapper-validation-after-selected-closure-initialization",
      slots: "closed-numbered-namespace-slots-with-per-entry-publication-units",
    },
    unitCount: 2,
    units: [chunkUnit, publicationUnit],
  };
  const applicationIdentity = {
    ...applicationPayload,
    sha256: fingerprintJson(applicationPayload),
  };
  return {
    applicationIdentity,
    chunkUnitsIdentity,
    identitySha256: applicationIdentity.sha256,
    kind: "convex-wasm-official-output-module-graph-compiler-cache-descriptor-v2",
    schemaVersion: 2,
  };
}

function compilerOutputTopologyDescriptor(descriptor) {
  return {
    applicationIdentitySha256: descriptor.applicationIdentity.sha256,
    chunkUnitsIdentitySha256: descriptor.chunkUnitsIdentity.sha256,
    descriptorSha256: fingerprintJson(descriptor),
    identitySha256: descriptor.identitySha256,
    kind: "convex-wasm-official-output-module-graph-compiler-output-topology-descriptor-v1",
    schemaVersion: 1,
  };
}

async function writeCompilerOutputFixture(
  cacheLayout,
  { historicalPreTransport = false, recordSchemaVersion = 5 } = {}
) {
  const generatedC = await writeGenericArtifact({
    cacheLayout,
    extension: "c",
    metadata: { fixture: "compiler-output-generated-c" },
    payload: "compiler-output-generated-c",
    stage: "aaa-compiler-output-generated-c",
  });
  const picObject = await writeGenericArtifact({
    cacheLayout,
    extension: "o",
    metadata: { fixture: "compiler-output-pic-object" },
    payload: "compiler-output-pic-object",
    stage: "aab-compiler-output-pic-object",
  });
  const engineProbe = await writeGenericArtifact({
    cacheLayout,
    extension: "cwasm",
    metadata: { fixture: "compiler-output-engine-probe" },
    payload: "compiler-output-engine-probe",
    stage: "aac-compiler-output-engine-probe",
  });
  const generatedCReference = compilerOutputReference({ ...generatedC, extension: "c" });
  const picObjectReference = compilerOutputReference({ ...picObject, extension: "o" });
  const descriptor = compilerOutputDescriptorFixture({ historicalPreTransport });
  const compactRecord = recordSchemaVersion === 5;
  assert.ok(compactRecord || recordSchemaVersion === 4);
  assert.ok(!historicalPreTransport || !compactRecord);
  const record = {
    applicationUnits: Array.from({ length: 2 }, () => ({
      generatedC: generatedCReference,
      picObject: picObjectReference,
    })),
    bridge: {
      generatedC: generatedCReference,
      generatedCIdentity: generatedC.entry.identity,
      generatedSource: {
        sha256: generatedC.entry.artifactSha256,
        size: generatedC.entry.artifactSize,
      },
      object: picObjectReference,
      objectIdentity: picObject.entry.identity,
      requestEnvelope: { fixture: "request-envelope" },
      valueCodec: { fixture: "value-codec" },
    },
    descriptor: compactRecord ? compilerOutputTopologyDescriptor(descriptor) : descriptor,
    engine: {
      compatibilitySha256: "3".repeat(64),
      config: { fixture: "engine-config" },
      configurationSha256: fingerprintJson({ fixture: "engine-config" }),
      package: { fixture: "engine-package" },
      revision: "fixture-revision",
      target: { cpu: "fixture-cpu", triple: "fixture-triple" },
      wasmtimeMaterialsSha256: "7".repeat(64),
    },
    engineProbe: compilerOutputReference({ ...engineProbe, extension: "cwasm" }),
    formatter: {
      generatedC: generatedCReference,
      generatedCIdentity: generatedC.entry.identity,
      generatedSource: {
        sha256: generatedC.entry.artifactSha256,
        size: generatedC.entry.artifactSize,
      },
      object: picObjectReference,
      objectIdentity: picObject.entry.identity,
    },
    kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    ...(compactRecord
      ? {
          reusableCodeIdentitySha256s: ["8".repeat(64), "9".repeat(64)],
          structuralTopologySha256: "c".repeat(64),
        }
      : {}),
    schemaVersion: recordSchemaVersion,
  };
  const compilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: compilerOutputCacheIdentity(descriptor.identitySha256),
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  return { compilerOutput, dependencies: [generatedC, picObject, engineProbe], record };
}

async function writeCohortCapsuleFixture(cacheLayout, compilerOutput, record) {
  const topologyStageCertificate = (reference, extension, includeIdentity) => ({
    artifactSha256: reference.entry.artifactSha256,
    artifactSize: reference.entry.artifactSize,
    cacheKey: reference.report.cacheKey,
    extension,
    ...(includeIdentity ? { identity: reference.entry.identity } : {}),
    identitySha256: fingerprintJson(reference.entry.identity),
    stage: reference.report.stage,
  });
  const topologyCacheIdentity = {
    compilerOutputCacheIdentity: compilerOutput.entry.identity,
    compilerOutputCacheKey: compilerOutput.key,
    kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
  };
  const cacheRecordSha256 = createHash("sha256")
    .update(Buffer.from(canonicalJson(record)))
    .digest("hex");
  assert.notEqual(cacheRecordSha256, compilerOutput.entry.artifactSha256);
  const descriptor =
    record.schemaVersion === 5
      ? record.descriptor
      : compilerOutputTopologyDescriptor(record.descriptor);
  const certificate = {
    applicationUnits: record.applicationUnits.map((unit) => ({
      generatedC: topologyStageCertificate(unit.generatedC, "c", false),
      picObject: topologyStageCertificate(unit.picObject, "o", false),
    })),
    bridge: {
      generatedC: topologyStageCertificate(record.bridge.generatedC, "c", true),
      object: topologyStageCertificate(record.bridge.object, "o", true),
    },
    cacheKey: compilerOutput.key,
    // Topology certificates bind canonical record bytes without the artifact file's trailing
    // newline. This mirrors publishModuleGraphCompilerOutputCache exactly.
    cacheRecordSha256,
    descriptor,
    engine: record.engine,
    engineProbe: topologyStageCertificate(record.engineProbe, "cwasm", false),
    formatter: {
      generatedC: topologyStageCertificate(record.formatter.generatedC, "c", true),
      object: topologyStageCertificate(record.formatter.object, "o", true),
    },
    kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
    schemaVersion: 4,
  };
  const topologyCertificate = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: topologyCacheIdentity,
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
    },
    payload: `${canonicalJson(certificate)}\n`,
    stage: "module-graph-compiler-output-topology",
  });
  const capsuleIdentityPayload = {
    chunkBindingSha256: "b".repeat(64),
    cohort: { cohortId: "1".repeat(64), entries: [{ fixture: "entry" }], entryCount: 1 },
    esbuild: { version: "fixture" },
    kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
    policies: { fixture: "policies" },
    schemaVersion: 6,
    sourceEnvelope: { fixture: "source-envelope" },
  };
  const capsuleIdentity = {
    ...capsuleIdentityPayload,
    sha256: fingerprintJson(capsuleIdentityPayload),
  };
  const capsule = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: {
      capsuleIdentity,
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      schemaVersion: 6,
    },
    metadata: {
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      schemaVersion: 6,
    },
    payload: `${canonicalJson({
      identity: capsuleIdentity,
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      planning: {
        topology: {
          cacheIdentity: compilerOutput.entry.identity,
          cacheKey: compilerOutput.key,
          cacheRecordSha256,
          certificateCacheKey: topologyCertificate.key,
          descriptor: certificate.descriptor,
        },
      },
      schemaVersion: 6,
      sourceEnvelopeSha256: "2".repeat(64),
    })}\n`,
    stage: "module-graph-cohort-planning-capsule",
  });
  return { capsule, topologyCertificate };
}

async function materializeModuleGraphPackageFixture(value) {
  const source = JSON.parse(
    await fs.readFile(
      new URL("../test-fixtures/convex-wasm-module-graph-registry/fixture.json", import.meta.url),
      "utf8"
    )
  );
  const moduleGraph = source.material.moduleGraph;
  const cacheLayout = value.layout("retention-closure");
  const writeFiles = async (directory, files) => {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    for (const file of files) {
      await fs.writeFile(join(directory, file.name), Buffer.from(file.base64, "base64"), {
        mode: 0o600,
      });
    }
  };
  await writeFiles(
    join(cacheLayout.immutable.packages, moduleGraph.graphManifestSha256),
    moduleGraph.packageFiles
  );
  for (const artifact of moduleGraph.artifactEntries) {
    await writeFiles(
      join(cacheLayout.immutable.artifacts, artifact.stage, artifact.cacheKey),
      artifact.files
    );
  }
  const manifestPath = join(value.root, source.material.deployment.name);
  await fs.writeFile(
    manifestPath,
    Buffer.from(source.material.deployment.base64, "base64"),
    { mode: 0o600 }
  );
  const graphManifestSha256 = moduleGraph.graphManifestSha256;
  const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout,
    cacheRoot: value.cacheRoot,
    graphManifestSha256,
    packagePath: join(cacheLayout.immutable.packages, graphManifestSha256),
  });
  return {
    cacheLayout,
    graphManifest: verified.graphManifest,
    graphManifestSha256,
    manifest: JSON.parse(await fs.readFile(manifestPath, "utf8")),
    packageMaterial: verified.packageMaterial,
  };
}

async function writeLegacyDeploymentResultCertificate({
  cacheLayout,
  graphManifest,
  graphManifestSha256,
  manifest,
  packageMaterial,
  schemaVersion = 3,
}) {
  assert.ok(schemaVersion === 1 || schemaVersion === 3 || schemaVersion === 4);
  if (schemaVersion === 1) assert.notEqual(graphManifest, undefined);
  const lookupIdentity = { fixture: "cache-retention-legacy-certificate" };
  const payload = {
    kind: "convex-wasm-deployment-result-certificate-v2",
    lookupIdentity,
    manifest,
    ...(schemaVersion === 3 || schemaVersion === 4
      ? { packageReferences: [{ graphManifestSha256, packageMaterial }] }
      : { packageGraphs: [{ graphManifest, graphManifestSha256 }] }),
    schemaVersion,
  };
  const certificate = { ...payload, certificateSha256: fingerprintJson(payload) };
  const root = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    fingerprintJson(lookupIdentity)
  );
  const path = join(root, certificate.certificateSha256);
  await fs.mkdir(path, { mode: 0o700, recursive: true });
  for (const directory of [
    cacheLayout.immutable.root,
    cacheLayout.immutable.packages,
    join(cacheLayout.immutable.packages, "deployment-results"),
    join(cacheLayout.immutable.packages, "deployment-results", "v1"),
    root,
    path,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  await Promise.all([
    fs.writeFile(join(path, "certificate.json"), `${canonicalJson(certificate)}\n`, {
      mode: 0o600,
    }),
    fs.writeFile(join(path, "COMPLETE"), `${certificate.certificateSha256}\n`, {
      mode: 0o600,
    }),
  ]);
  return certificate;
}

test("successful builds remove their object-level work root", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("successful-build");
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await fs.mkdir(layout.work.scratch, { mode: 0o700 });
    await fs.writeFile(join(layout.work.scratch, "recoverable-object"), "object", {
      mode: 0o600,
    });
    await lease.complete(2_000);
  });
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("failed work has bounded recovery and is removed after expiry", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("failed-build");
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await fs.mkdir(layout.work.reports, { mode: 0o700 });
    await fs.writeFile(join(layout.work.reports, "failure-evidence.json"), "{}\n", {
      mode: 0o600,
    });
    await lease.fail(2_000);
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 1_000_000 })
  );
  assert.deepEqual(report.work.roots, [
    {
      action: "retain",
      buildId: "failed-build",
      reason: "failed-build-recovery-window-open",
      recoverableUntilMs: 604802000,
      status: "failed",
    },
  ]);
  const record = JSON.parse(
    await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
  );
  assert.equal(record.status, "failed");
  assert.deepEqual(record.outcome, {
    failedAtMs: 2_000,
    kind: "deployment-failed",
    recoverableUntilMs: 604802000,
  });
  assert.equal(
    await fs.readFile(join(layout.work.reports, "failure-evidence.json"), "utf8"),
    "{}\n"
  );
  const expired = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 604802000 })
  );
  assert.equal(expired.work.roots[0].action, "remove");
  assert.equal(expired.work.roots[0].status, "failed");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("legacy failed records receive a deadline before any removal", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("legacy-failed-build");
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await lease.fail(2_000);
    const recordPath = join(layout.work.buildRoot, convexWasmBuildWorkRecordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    await fs.writeFile(
      recordPath,
      `${JSON.stringify({
        ...record,
        outcome: { failedAtMs: 2_000, kind: "deployment-failed", recoverable: true },
      })}\n`,
      { mode: 0o600 }
    );
  });
  const first = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 1_000_000 })
  );
  assert.equal(first.work.roots[0].action, "set-recovery-deadline");
  assert.equal(first.work.roots[0].recoverableUntilMs, 604_802_000);
  assert.equal(
    JSON.parse(
      await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
    ).outcome.recoverableUntilMs,
    604_802_000
  );
});

test("interrupted work is abandoned under quiescence and removed only after recovery", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("interrupted-build");
  await withHeavyLock(value.environment, async () => {
    await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    await fs.mkdir(layout.work.timings, { mode: 0o700 });
    await fs.writeFile(join(layout.work.timings, "phase.json"), "{}\n", { mode: 0o600 });
  });

  const dryRun = await maintainConvexWasmCache(maintenanceOptions(value, { nowMs: 3_000 }));
  assert.equal(dryRun.work.roots[0].action, "mark-abandoned");
  assert.equal(
    JSON.parse(
      await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
    ).status,
    "active"
  );

  const first = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_000 })
  );
  assert.equal(first.work.roots[0].action, "mark-abandoned");
  assert.equal(first.work.roots[0].recoverableUntilMs, 4_000);
  assert.equal(
    JSON.parse(
      await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8")
    ).status,
    "abandoned"
  );

  const recoverable = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_999 })
  );
  assert.equal(recoverable.work.roots[0].action, "retain");
  assert.equal(await fs.readFile(join(layout.work.timings, "phase.json"), "utf8"), "{}\n");

  const expired = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 4_000 })
  );
  assert.equal(expired.work.roots[0].action, "remove");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("completed work left by an interrupted cleanup is removed after retention", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("completed-build");
  await withHeavyLock(value.environment, async () => {
    await createConvexWasmBuildWorkLease({
      cacheLayout: layout,
      environment: value.environment,
      nowMs: 1_000,
    });
    const recordPath = join(layout.work.buildRoot, convexWasmBuildWorkRecordName);
    const record = JSON.parse(await fs.readFile(recordPath, "utf8"));
    await fs.writeFile(
      recordPath,
      `${JSON.stringify({
        ...record,
        outcome: { completedAtMs: 2_000, kind: "deployment-completed" },
        status: "completed",
        updatedAtMs: 2_000,
      })}\n`
    );
  });

  const retained = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 2_999 })
  );
  assert.equal(retained.work.roots[0].action, "retain");
  const removed = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_000 })
  );
  assert.equal(removed.work.roots[0].action, "remove");
  assert.equal(removed.work.roots[0].status, "completed");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("invalid work records are reported and never removed", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("invalid-build");
  await fs.mkdir(layout.work.buildRoot, { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "work"),
    layout.work.root,
    layout.work.buildRoot,
  ]) {
    await fs.chmod(path, 0o700);
  }
  await fs.writeFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "not-json\n", {
    mode: 0o600,
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 1_000_000 })
  );
  assert.deepEqual(report.work.roots, [
    {
      action: "retain",
      buildId: "invalid-build",
      reason: "invalid-build-work-record",
      status: "invalid",
    },
  ]);
  assert.equal(
    await fs.readFile(join(layout.work.buildRoot, convexWasmBuildWorkRecordName), "utf8"),
    "not-json\n"
  );
});

test("legacy roots use the same two-phase abandonment protocol", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("legacy-build");
  await fs.mkdir(layout.work.buildRoot, { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "work"),
    layout.work.root,
    layout.work.buildRoot,
  ]) {
    await fs.chmod(path, 0o700);
  }
  await fs.writeFile(join(layout.work.buildRoot, "old-output"), "old", { mode: 0o600 });
  await fs.utimes(layout.work.buildRoot, new Date(1_000), new Date(1_000));

  const marked = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 3_000 })
  );
  assert.equal(marked.work.roots[0].action, "mark-abandoned");
  assert.equal(marked.work.roots[0].status, "legacy");
  assert.equal(await fs.readFile(join(layout.work.buildRoot, "old-output"), "utf8"), "old");

  const removed = await maintainConvexWasmCache(
    maintenanceOptions(value, { apply: true, nowMs: 4_000 })
  );
  assert.equal(removed.work.roots[0].action, "remove");
  await assert.rejects(fs.lstat(layout.work.buildRoot), { code: "ENOENT" });
});

test("dry-run reports immutable root candidates and hard-linked physical occupancy", async (t) => {
  const value = await fixture(t);
  const artifacts = join(value.cacheRoot, "immutable", "v6", "artifacts", "stage", "entry");
  const packages = join(value.cacheRoot, "immutable", "v6", "packages", "package", "payload");
  await fs.mkdir(dirname(artifacts), { mode: 0o700, recursive: true });
  await fs.mkdir(dirname(packages), { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "immutable"),
    join(value.cacheRoot, "immutable", "v6"),
    join(value.cacheRoot, "immutable", "v6", "artifacts"),
    join(value.cacheRoot, "immutable", "v6", "artifacts", "stage"),
    join(value.cacheRoot, "immutable", "v6", "packages"),
    join(value.cacheRoot, "immutable", "v6", "packages", "package"),
  ]) {
    await fs.chmod(path, 0o700);
  }
  await fs.writeFile(artifacts, Buffer.alloc(8_192, 1), { mode: 0o600 });
  await fs.link(artifacts, packages);

  const occupancy = await measureConvexWasmCacheOccupancy(value.cacheRoot);
  assert.equal(occupancy.regularFileCount, 2);
  assert.equal(occupancy.logicalRegularFileBytes, 16_384);
  assert.equal(occupancy.hardLinkedRegularFileReferences, 2);
  assert.ok(occupancy.allocatedBytes > occupancy.uniqueAllocatedBytes);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, { includeImmutableOccupancy: true, nowMs: 3_000 })
  );
  assert.equal(report.mode, "dry-run");
  assert.equal(report.immutable.sweepAuthorized, false);
  assert.deepEqual(
    report.immutable.rootMarkers.map(({ kind }) => kind),
    [
      "immutable-artifact-object-store",
      "immutable-package-root",
      "deployment-result-certificate-root",
    ]
  );
  assert.equal(report.occupancy.scope, "entire-cache");
  assert.equal(report.occupancy.logicalRegularFileBytes, 16_384);
  assert.ok(report.occupancy.allocatedBytes > report.occupancy.uniqueAllocatedBytes);
});

test("build leases and maintenance reject missing or inherited lock authority", async (t) => {
  const value = await fixture(t);
  await assert.rejects(
    createConvexWasmBuildWorkLease({
      cacheLayout: value.layout("unlocked-build"),
      environment: value.environment,
      nowMs: 1_000,
    }),
    /holds the cache lock/u
  );
  await withHeavyLock(value.environment, async () => {
    await assert.rejects(
      maintainConvexWasmCache(maintenanceOptions(value, { nowMs: 1_000 })),
      /must acquire the top-level cache lock/u
    );
  });
});

test("successful cache-use authority is bounded and immutable GC is dry-run only", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("authority-build");
  const deployment = {
    manifest: {
      moduleGraphBinding: { cohorts: [{ graphManifestSha256: "b".repeat(64) }] },
    },
  };
  deployment.manifest.deploymentSha256 = fingerprintJson(deployment.manifest);
  const emptyPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({ cacheLayout: layout, environment: value.environment, nowMs: 0 })
  );
  assert.equal(emptyPlan.evictions.length, 0);
  await withHeavyLock(value.environment, async () => {
    for (let index = 0; index < 10; index += 1) {
      const manifest = {
        fixtureIndex: index,
        moduleGraphBinding: deployment.manifest.moduleGraphBinding,
      };
      manifest.deploymentSha256 = fingerprintJson(manifest);
      await recordConvexWasmSuccessfulCacheUse({
        buildId: `authority-${index}`,
        cacheLayout: layout,
        deployment: { manifest },
        environment: value.environment,
        recordedAtMs: index,
      });
    }
  });
  const snapshots = await fs.readdir(
    join(value.cacheRoot, "state", "v1", "cache-retention", "v1", "recent-success")
  );
  assert.equal(snapshots.filter((name) => name.endsWith(".json")).length, 8);
});

test("successful-cache snapshot publication rejects a redirected state ancestor", async (t) => {
  const value = await fixture(t);
  const outsideState = join(value.root, "outside-snapshot-state");
  await fs.mkdir(outsideState, { mode: 0o700 });
  await fs.mkdir(value.cacheRoot, { mode: 0o700 });
  await fs.symlink(outsideState, join(value.cacheRoot, "state"), "dir");
  const manifest = {
    fixture: "snapshot-state-redirect",
    moduleGraphBinding: { cohorts: [{ graphManifestSha256: "c".repeat(64) }] },
  };
  manifest.deploymentSha256 = fingerprintJson(manifest);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      recordConvexWasmSuccessfulCacheUse({
        buildId: "snapshot-state-redirect",
        cacheLayout: value.layout("snapshot-state-redirect"),
        deployment: { manifest },
        environment: value.environment,
        recordedAtMs: 1_000,
      })
    ),
    /symlink/u
  );
  await assert.rejects(fs.lstat(join(outsideState, "v1")), { code: "ENOENT" });
});

test("immutable GC retains a coherent legacy module graph v2 package triple", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("legacy-v2-package");
  const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.candidates, 1);
  assert.deepEqual(plan.evictions, []);
  assert.deepEqual(
    plan.retained.artifacts,
    [
      `${legacy.aot.stage}\0${legacy.aot.key}`,
      `${legacy.coreWasm.stage}\0${legacy.coreWasm.key}`,
    ].sort()
  );
});

test("immutable GC rejects a legacy v2 package whose provenance identity does not match its artifact", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("legacy-v2-provenance-identity-mismatch");
  const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
  const provenance = {
    ...legacy.provenance,
    identities: {
      ...legacy.provenance.identities,
      base: {
        ...legacy.provenance.identities.base,
        aot: { fixture: "unmatched-legacy-v2-aot-identity" },
      },
    },
  };
  const entry = { ...legacy.entry, provenance: packageFileMaterial(provenance) };
  await Promise.all([
    fs.writeFile(join(legacy.root, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
      mode: 0o600,
    }),
    fs.writeFile(join(legacy.root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
    ),
    /recent immutable authority is corrupt/u
  );
});

test("immutable GC rejects every mixed module graph package triple version", async (t) => {
  await t.test("v2 manifest with v3 provenance", async (t) => {
    const value = await fixture(t);
    const cacheLayout = value.layout("mixed-v2-manifest-v3-provenance");
    const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
    const provenance = {
      ...legacy.provenance,
      kind: "convex-wasm-module-graph-provenance-v3",
      schemaVersion: 3,
    };
    const entry = { ...legacy.entry, provenance: packageFileMaterial(provenance) };
    await Promise.all([
      fs.writeFile(join(legacy.root, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
        mode: 0o600,
      }),
      fs.writeFile(join(legacy.root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
        mode: 0o600,
      }),
    ]);

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });

  await t.test("v2 manifest and provenance with v3 package entry", async (t) => {
    const value = await fixture(t);
    const cacheLayout = value.layout("mixed-v2-triple-v3-package");
    const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
    const entry = { ...legacy.entry, kind: "convex-wasm-module-graph-package-v3" };
    await fs.writeFile(join(legacy.root, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    });

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });

  await t.test("v3 manifest with v2 provenance", async (t) => {
    const value = await fixture(t);
    const { cacheLayout, graphManifestSha256 } = await materializeModuleGraphPackageFixture(value);
    const path = join(cacheLayout.immutable.packages, graphManifestSha256);
    const provenance = JSON.parse(await fs.readFile(join(path, "build-provenance.json"), "utf8"));
    provenance.kind = "convex-wasm-module-graph-provenance-v2";
    provenance.schemaVersion = 2;
    await fs.writeFile(join(path, "build-provenance.json"), `${canonicalJson(provenance)}\n`, {
      mode: 0o600,
    });

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });

  await t.test("v3 manifest and provenance with v2 package entry", async (t) => {
    const value = await fixture(t);
    const { cacheLayout, graphManifestSha256 } = await materializeModuleGraphPackageFixture(value);
    const path = join(cacheLayout.immutable.packages, graphManifestSha256);
    const entry = JSON.parse(await fs.readFile(join(path, "package-entry.json"), "utf8"));
    entry.kind = "convex-wasm-module-graph-package-v2";
    await fs.writeFile(join(path, "package-entry.json"), `${canonicalJson(entry)}\n`, {
      mode: 0o600,
    });

    await assert.rejects(
      withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({ cacheLayout, environment: value.environment })
      ),
      /recent immutable authority is corrupt/u
    );
  });
});

test("recent successful use retains its legacy certificate and complete immutable closure", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  const {
    compilerOutput,
    dependencies: [generatedC, picObject, engineProbe],
  } = await writeCompilerOutputFixture(cacheLayout);

  const snapshot = await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "closure-build",
      cacheLayout,
      deployment: {
        buildReport: {
          artifacts: [
            {
              buildReport: {
                compilerOutputCache: { cache: "hit", cacheKey: compilerOutput.key },
              },
            },
          ],
          cache: { certificateSha256: certificate.certificateSha256, deploymentResult: "hit" },
        },
        manifest,
      },
      environment: value.environment,
      recordedAtMs: 1_000,
    })
  );
  assert.equal(snapshot.schemaVersion, 2);
  assert.deepEqual(snapshot.certificateSha256s, [certificate.certificateSha256]);
  assert.deepEqual(snapshot.compilerOutputKeys, [compilerOutput.key]);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.pressure.active, true);
  assert.deepEqual(plan.retained.certificates, [certificate.certificateSha256]);
  assert.deepEqual(
    plan.retained.artifacts,
    [
      `${engineProbe.stage}\0${engineProbe.key}`,
      `${generatedC.stage}\0${generatedC.key}`,
      `${picObject.stage}\0${picObject.key}`,
      `${compilerOutput.stage}\0${compilerOutput.key}`,
      ...packageMaterial.artifactReferences.flatMap((reference) => [
        `${reference.aot.artifact.stage}\0${reference.aot.artifact.cacheKey}`,
        `${reference.coreWasm.artifact.stage}\0${reference.coreWasm.artifact.cacheKey}`,
      ]),
    ].sort()
  );
  assert.deepEqual(plan.evictions, []);

  const compilerOutputEntryPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key,
    "entry.json"
  );
  const compilerOutputEntry = JSON.parse(await fs.readFile(compilerOutputEntryPath, "utf8"));
  compilerOutputEntry.metadata = { kind: "invalid-compiler-output-cache-metadata" };
  await fs.writeFile(compilerOutputEntryPath, `${canonicalJson(compilerOutputEntry)}\n`, {
    mode: 0o600,
  });
  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /retained compiler-output cache entry is unavailable/u
  );
});

test("missing package material makes an older success snapshot stale without authorizing its certificate", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "stale-success",
      cacheLayout,
      deployment: {
        buildReport: {
          cache: { certificateSha256: certificate.certificateSha256, deploymentResult: "hit" },
        },
        manifest,
      },
      environment: value.environment,
    })
  );
  await fs.rm(join(cacheLayout.immutable.packages, graphManifestSha256), { recursive: true });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.staleSnapshots, 1);
  assert.equal(plan.authenticated.retainedSnapshots, 0);
  assert.deepEqual(plan.retained.certificates, []);
});

test("recent successful use retains an older certificate after compact preference changes", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifest, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const olderCertificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifest,
    graphManifestSha256,
    manifest,
    packageMaterial,
    schemaVersion: 1,
  });
  const preferredCertificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  assert.notEqual(olderCertificate.certificateSha256, preferredCertificate.certificateSha256);
  const lookupRoot = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    fingerprintJson({ fixture: "cache-retention-legacy-certificate" })
  );
  await fs.writeFile(join(lookupRoot, "PREFERRED"), `${preferredCertificate.certificateSha256}\n`, {
    mode: 0o600,
  });
  await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "older-certificate-success",
      cacheLayout,
      deployment: {
        buildReport: {
          cache: {
            certificateSha256: olderCertificate.certificateSha256,
            deploymentResult: "hit",
          },
        },
        manifest,
      },
      environment: value.environment,
      recordedAtMs: 1_000,
    })
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.deepEqual(plan.retained.certificates, [olderCertificate.certificateSha256]);
  assert.deepEqual(plan.retained.packages, [graphManifestSha256]);
});

test("immutable GC retains a recently modified schema-4 certificate root", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifest, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifest,
    graphManifestSha256,
    manifest,
    packageMaterial,
    schemaVersion: 4,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
    })
  );
  assert.deepEqual(plan.retained.certificates, [certificate.certificateSha256]);
  assert.deepEqual(plan.evictions, []);
});

test("immutable GC rejects a non-private preferred certificate pointer", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, manifest, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);
  const certificate = await writeLegacyDeploymentResultCertificate({
    cacheLayout,
    graphManifestSha256,
    manifest,
    packageMaterial,
  });
  const lookupRoot = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    fingerprintJson({ fixture: "cache-retention-legacy-certificate" })
  );
  const preferredPointer = join(lookupRoot, "PREFERRED");
  await fs.writeFile(preferredPointer, `${certificate.certificateSha256}\n`, { mode: 0o600 });
  await fs.chmod(preferredPointer, 0o644);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 1);
  assert.deepEqual(plan.retained.certificates, []);
  assert.deepEqual(plan.evictions, []);
});

test("immutable GC bounds certificate candidates before reading their contents", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("certificate-candidate-bound");
  const lookupRoot = join(
    cacheLayout.immutable.packages,
    "deployment-results",
    "v1",
    "a".repeat(64)
  );
  await fs.mkdir(lookupRoot, { mode: 0o700, recursive: true });
  for (const directory of [
    value.cacheRoot,
    join(value.cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.packages,
    join(cacheLayout.immutable.packages, "deployment-results"),
    join(cacheLayout.immutable.packages, "deployment-results", "v1"),
    lookupRoot,
  ]) {
    await fs.chmod(directory, 0o700);
  }
  await Promise.all(
    Array.from({ length: 257 }, (_, index) =>
      fs.mkdir(join(lookupRoot, `${index.toString(16).padStart(64, "0")}`), { mode: 0o700 })
    )
  );

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        nowMs: Date.now(),
      })
    ),
    /recent immutable authority is corrupt/u
  );
});

test("rotated compiler-output schemas remain ordinary age-bounded artifacts", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, manifest } = await materializeModuleGraphPackageFixture(value);
  const legacyCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v3",
    },
    payload: `${canonicalJson({
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v3",
      schemaVersion: 3,
    })}\n`,
    stage: "module-graph-compiler-output",
  });
  await withHeavyLock(value.environment, () =>
    recordConvexWasmSuccessfulCacheUse({
      buildId: "rotated-compiler-output",
      cacheLayout,
      deployment: {
        buildReport: {
          artifacts: [
            {
              buildReport: {
                compilerOutputCache: { cache: "hit", cacheKey: legacyCompilerOutput.key },
              },
            },
          ],
        },
        manifest,
      },
      environment: value.environment,
      recordedAtMs: 1_000,
    })
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      nowMs: Date.now(),
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(
    plan.retained.artifacts.includes(`${legacyCompilerOutput.stage}\0${legacyCompilerOutput.key}`)
  );
  assert.deepEqual(plan.evictions, []);
});

test("schema-4/v8 and schema-5/v8 compiler-output records retain their strict closure", async (t) => {
  for (const recordSchemaVersion of [4, 5]) {
    await t.test(`schema ${String(recordSchemaVersion)}`, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout(`compiler-output-schema-${String(recordSchemaVersion)}`);
      const { compilerOutput, dependencies } = await writeCompilerOutputFixture(cacheLayout, {
        recordSchemaVersion,
      });

      const plan = await withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 5_000,
        })
      );

      assert.equal(plan.authenticated.invalid, 0);
      assert.ok(
        [compilerOutput, ...dependencies].every(({ key, stage }) =>
          plan.retained.artifacts.includes(`${stage}\0${key}`)
        )
      );
      assert.deepEqual(plan.evictions, []);
    });
  }
});

test("pre-transport schema-4/v8 compiler-output records remain age-bounded", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-schema-4-pre-transport");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout, {
    historicalPreTransport: true,
    recordSchemaVersion: 4,
  });
  await Promise.all(
    [compilerOutput, ...dependencies].map((artifact) => ageGenericArtifact(cacheLayout, artifact))
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(
    [compilerOutput, ...dependencies].every(
      ({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`)
    )
  );

  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  await ageGenericArtifact(cacheLayout, capsule);
  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 2_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cohort capsule compiler-output cache record has an unsupported descriptor family/u
  );
});

test("schema-5 compiler-output compact authority corruption cannot retain dependencies", async (t) => {
  for (const { mutate, name } of [
    {
      mutate: (record) => {
        record.descriptor.chunkUnitsIdentitySha256 = "invalid";
      },
      name: "compact descriptor",
    },
    {
      mutate: (record) => {
        record.reusableCodeIdentitySha256s.pop();
      },
      name: "reusable-code identities",
    },
    {
      mutate: (record) => {
        record.structuralTopologySha256 = "invalid";
      },
      name: "structural topology",
    },
  ]) {
    await t.test(name, async (t) => {
      const value = await fixture(t);
      const cacheLayout = value.layout(`compiler-output-corrupt-${name.replaceAll(" ", "-")}`);
      const { compilerOutput, dependencies, record } =
        await writeCompilerOutputFixture(cacheLayout);
      mutate(record);
      const source = Buffer.from(`${canonicalJson(record)}\n`);
      const root = join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key);
      const entryPath = join(root, "entry.json");
      const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
      entry.artifactSha256 = createHash("sha256").update(source).digest("hex");
      entry.artifactSize = source.length;
      await Promise.all([
        fs.writeFile(join(root, entry.artifactFile), source, { mode: 0o600 }),
        fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
      ]);

      const plan = await withHeavyLock(value.environment, () =>
        planConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      );

      assert.equal(plan.authenticated.invalid, 1);
      assert.ok(
        dependencies.every(
          ({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`)
        )
      );
    });
  }
});

test("artifact-only sweep keeps every planning-only package loadable", async (t) => {
  const value = await fixture(t);
  const { cacheLayout, graphManifestSha256, packageMaterial } =
    await materializeModuleGraphPackageFixture(value);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: Date.now() + 15 * 24 * 60 * 60 * 1_000,
    })
  );

  assert.deepEqual(report.immutable.plan.retained.packages, []);
  assert.deepEqual(report.immutable.sweep.removed, []);
  assert.equal(report.immutable.plan.incomplete, true);
  assert.equal(report.immutable.plan.categories.planningOnlyCandidates.count, 1);
  assert.equal(report.immutable.plan.categories.sweepableCandidates.count, 0);
  assert.deepEqual(
    report.immutable.plan.retained.artifacts,
    packageMaterial.artifactReferences
      .flatMap((reference) => [
        `${reference.aot.artifact.stage}\0${reference.aot.artifact.cacheKey}`,
        `${reference.coreWasm.artifact.stage}\0${reference.coreWasm.artifact.cacheKey}`,
      ])
      .sort()
  );
  await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout,
    cacheRoot: value.cacheRoot,
    graphManifestSha256,
    packagePath: join(cacheLayout.immutable.packages, graphManifestSha256),
  });
});

test("artifact-only sweep removes a compiler-output root before its strict dependencies", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-root-sweep");
  const { compilerOutput, dependencies } = await writeCompilerOutputFixture(cacheLayout);
  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [compilerOutput.key]
  );
  await assert.rejects(
    fs.lstat(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key)),
    { code: "ENOENT" }
  );
  await Promise.all(
    dependencies.map(({ key, stage }) =>
      fs.lstat(join(cacheLayout.immutable.artifacts, stage, key))
    )
  );
});

test("artifact-only sweep removes a topology certificate before its full-record prerequisite", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-topology-root-sweep");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  await fs.rm(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key), {
    recursive: true,
  });
  await Promise.all(
    [compilerOutput, topologyCertificate, ...dependencies].map((artifact) =>
      ageGenericArtifact(cacheLayout, artifact)
    )
  );

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [topologyCertificate.key]
  );
  await assert.rejects(
    fs.lstat(
      join(cacheLayout.immutable.artifacts, topologyCertificate.stage, topologyCertificate.key)
    ),
    { code: "ENOENT" }
  );
  await Promise.all(
    [compilerOutput, ...dependencies].map(({ key, stage }) =>
      fs.lstat(join(cacheLayout.immutable.artifacts, stage, key))
    )
  );
});

test("v6 topology material is age-bounded only after complete authentication", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("rotated-compiler-output-topology-identity");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout, {
    recordSchemaVersion: 4,
  });
  const legacyCompilerOutputIdentity = structuredClone(compilerOutput.entry.identity);
  legacyCompilerOutputIdentity.kind =
    "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v6";
  delete legacyCompilerOutputIdentity.topologyWitnessMaterialIdentitySha256;
  const legacyCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: legacyCompilerOutputIdentity,
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    legacyCompilerOutput,
    record
  );
  await fs.rm(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key), {
    recursive: true,
  });
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });
  await Promise.all(
    [legacyCompilerOutput, ...dependencies].map((artifact) =>
      ageGenericArtifact(cacheLayout, artifact)
    )
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 60_000,
    })
  );

  assert.equal(plan.authenticated.invalid, 0);
  assert.ok(
    plan.retained.artifacts.includes(`${topologyCertificate.stage}\0${topologyCertificate.key}`)
  );
  assert.ok(
    [legacyCompilerOutput, ...dependencies].every(
      ({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`)
    )
  );

  const topologyRoot = join(
    cacheLayout.immutable.artifacts,
    topologyCertificate.stage,
    topologyCertificate.key
  );
  const topologyEntryPath = join(topologyRoot, "entry.json");
  const topologyEntry = JSON.parse(await fs.readFile(topologyEntryPath, "utf8"));
  const partialCertificate = JSON.parse(
    await fs.readFile(join(topologyRoot, topologyEntry.artifactFile), "utf8")
  );
  delete partialCertificate.bridge.object.identitySha256;
  const partialSource = Buffer.from(`${canonicalJson(partialCertificate)}\n`);
  topologyEntry.artifactSha256 = createHash("sha256").update(partialSource).digest("hex");
  topologyEntry.artifactSize = partialSource.length;
  await Promise.all([
    fs.writeFile(join(topologyRoot, topologyEntry.artifactFile), partialSource, { mode: 0o600 }),
    fs.writeFile(topologyEntryPath, `${canonicalJson(topologyEntry)}\n`, { mode: 0o600 }),
  ]);

  const partialPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(partialPlan.authenticated.invalid, 1);
  assert.ok(
    !partialPlan.retained.artifacts.includes(
      `${topologyCertificate.stage}\0${topologyCertificate.key}`
    )
  );
});

test("v6 compiler-output records authenticate descriptor and engine facts before legacy classification", async (t) => {
  for (const { field, value } of [
    { field: "descriptorIdentitySha256", value: "f".repeat(64) },
    { field: "engineCompatibilitySha256", value: "e".repeat(64) },
  ]) {
    await t.test(field, async (t) => {
      const fixtureValue = await fixture(t);
      const cacheLayout = fixtureValue.layout(`rotated-compiler-output-${field}`);
      const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout, {
        recordSchemaVersion: 4,
      });
      const legacyIdentity = structuredClone(compilerOutput.entry.identity);
      legacyIdentity.kind =
        "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v6";
      delete legacyIdentity.topologyWitnessMaterialIdentitySha256;
      legacyIdentity[field] = value;
      const legacyCompilerOutput = await writeGenericArtifact({
        cacheLayout,
        extension: "json",
        identity: legacyIdentity,
        metadata: {
          kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
        },
        payload: `${canonicalJson(record)}\n`,
        stage: "module-graph-compiler-output",
      });
      await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
        recursive: true,
      });
      await ageGenericArtifact(cacheLayout, legacyCompilerOutput);

      const plan = await withHeavyLock(fixtureValue.environment, () =>
        planConvexWasmImmutableGc({
          cacheLayout,
          environment: fixtureValue.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      );

      assert.equal(plan.authenticated.invalid, 1);
      assert.ok(
        !plan.retained.artifacts.includes(
          `${legacyCompilerOutput.stage}\0${legacyCompilerOutput.key}`
        )
      );
    });
  }
});

test("immutable GC rejects compiler-output closure authority from an extended v8 identity", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("extended-compiler-output-cache-identity");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const extendedCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: { ...compilerOutput.entry.identity, unexpected: "field" },
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(
    !plan.retained.artifacts.includes(
      `${extendedCompilerOutput.stage}\0${extendedCompilerOutput.key}`
    )
  );
  assert.ok(
    dependencies.every(({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`))
  );
});

test("immutable GC rejects a v8 identity relabeled onto a different compiler output", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("relabeled-compiler-output-cache-identity");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const relabeledCompilerOutput = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: { ...compilerOutput.entry.identity, descriptorIdentitySha256: "f".repeat(64) },
    metadata: {
      kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v4",
    },
    payload: `${canonicalJson(record)}\n`,
    stage: "module-graph-compiler-output",
  });
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(
    !plan.retained.artifacts.includes(
      `${relabeledCompilerOutput.stage}\0${relabeledCompilerOutput.key}`
    )
  );
  assert.ok(
    dependencies.every(({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`))
  );
});

test("immutable GC rejects a compiler-output closure with a disagreeing stage entry", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-closure-mismatch");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const compilerOutputPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key
  );
  const tamperedRecord = structuredClone(record);
  tamperedRecord.bridge.generatedC.entry.artifactSha256 = "f".repeat(64);
  const source = Buffer.from(`${canonicalJson(tamperedRecord)}\n`);
  const entryPath = join(compilerOutputPath, "entry.json");
  const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
  entry.artifactSha256 = createHash("sha256").update(source).digest("hex");
  entry.artifactSize = source.length;
  await Promise.all([
    fs.writeFile(join(compilerOutputPath, entry.artifactFile), source, { mode: 0o600 }),
    fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        maxEstimatedReclaimBytes: 1_000_000,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /compiler-output cache closure artifact disagrees with its record/u
  );
});

test("immutable GC rejects compiler-output retention authority for a different artifact family", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("compiler-output-closure-family-mismatch");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const compilerOutputPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key
  );
  const tamperedRecord = structuredClone(record);
  tamperedRecord.bridge.generatedC.extension = "o";
  const source = Buffer.from(`${canonicalJson(tamperedRecord)}\n`);
  const entryPath = join(compilerOutputPath, "entry.json");
  const entry = JSON.parse(await fs.readFile(entryPath, "utf8"));
  entry.artifactSha256 = createHash("sha256").update(source).digest("hex");
  entry.artifactSize = source.length;
  await Promise.all([
    fs.writeFile(join(compilerOutputPath, entry.artifactFile), source, { mode: 0o600 }),
    fs.writeFile(entryPath, `${canonicalJson(entry)}\n`, { mode: 0o600 }),
  ]);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(
    dependencies.every(({ key, stage }) => !plan.retained.artifacts.includes(`${stage}\0${key}`))
  );
});

test("artifact-only sweep removes a cohort capsule before its strict compiler closure", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-root-sweep");
  const { compilerOutput, dependencies, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  await Promise.all(
    [compilerOutput, topologyCertificate, ...dependencies].map((artifact) =>
      ageGenericArtifact(cacheLayout, artifact)
    )
  );

  const recentPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 5_000,
    })
  );
  const strictClosure = [compilerOutput, topologyCertificate, ...dependencies].map(
    ({ key, stage }) => `${stage}\0${key}`
  );
  assert.ok(strictClosure.every((key) => recentPlan.retained.artifacts.includes(key)));
  assert.equal(recentPlan.evictions.length, 0);

  await ageGenericArtifact(cacheLayout, capsule);
  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [capsule.key]
  );
  await assert.rejects(
    fs.lstat(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key)),
    { code: "ENOENT" }
  );
  await Promise.all(
    [compilerOutput, topologyCertificate, ...dependencies].map(({ key, stage }) =>
      fs.lstat(join(cacheLayout.immutable.artifacts, stage, key))
    )
  );
});

test("immutable GC removes an old capsule whose compiler-output record is already absent", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("orphaned-cohort-capsule");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  await fs.rm(join(cacheLayout.immutable.artifacts, compilerOutput.stage, compilerOutput.key), {
    recursive: true,
  });
  await ageGenericArtifact(cacheLayout, capsule);

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: 1,
      nowMs: Date.now() + 1_000,
    })
  );

  assert.equal(result.plan.authenticated.orphanedCapsules, 1);
  assert.equal(result.plan.authenticated.orphanedTopologyCertificates, 1);
  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [capsule.key]
  );
  await assert.rejects(
    fs.lstat(join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key)),
    { code: "ENOENT" }
  );
  await fs.lstat(
    join(cacheLayout.immutable.artifacts, topologyCertificate.stage, topologyCertificate.key)
  );
});

test("immutable GC treats rotated v2 through v5 cohort capsules as age-bounded artifacts", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("legacy-cohort-capsule");
  const capsules = [];
  for (const schemaVersion of [2, 3, 4, 5]) {
    const kind = `convex-wasm-official-output-cohort-planning-capsule-v${String(schemaVersion)}`;
    const capsule = await writeGenericArtifact({
      cacheLayout,
      extension: "json",
      identity: { capsuleIdentity: { fixture: "legacy" }, kind, schemaVersion },
      metadata: { kind, schemaVersion },
      payload: "{}\n",
      stage: "module-graph-cohort-planning-capsule",
    });
    await ageGenericArtifact(cacheLayout, capsule);
    capsules.push(capsule);
  }

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key).sort(),
    capsules.map(({ key }) => key).sort()
  );
});

test("immutable GC does not classify a current capsule as legacy from metadata alone", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("current-cohort-capsule-legacy-metadata");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleEntryPath = join(
    cacheLayout.immutable.artifacts,
    capsule.stage,
    capsule.key,
    "entry.json"
  );
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.metadata = {
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  await fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cohort capsule legacy metadata does not match its cache identity/u
  );
});

test("immutable GC authenticates the outer key before classifying a capsule as legacy", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("current-cohort-capsule-rewritten-legacy-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleEntryPath = join(
    cacheLayout.immutable.artifacts,
    capsule.stage,
    capsule.key,
    "entry.json"
  );
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  const currentCapsuleIdentity = structuredClone(capsuleEntry.identity.capsuleIdentity);
  delete currentCapsuleIdentity.sha256;
  const legacyCapsuleIdentityPayload = {
    ...currentCapsuleIdentity,
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  capsuleEntry.identity = {
    capsuleIdentity: {
      ...legacyCapsuleIdentityPayload,
      sha256: fingerprintJson(legacyCapsuleIdentityPayload),
    },
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  capsuleEntry.metadata = {
    kind: "convex-wasm-official-output-cohort-planning-capsule-v4",
    schemaVersion: 4,
  };
  await fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cache entry identity does not match its key/u
  );
});

test("immutable GC rejects a corrupted rotated v3 capsule before legacy classification", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("malformed-legacy-v3-cohort-capsule");
  const kind = "convex-wasm-official-output-cohort-planning-capsule-v3";
  const capsule = await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: { capsuleIdentity: { fixture: "legacy" }, kind, schemaVersion: 3 },
    metadata: { kind, schemaVersion: 3 },
    payload: "{}\n",
    stage: "module-graph-cohort-planning-capsule",
  });
  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  await fs.writeFile(join(capsuleRoot, capsule.entry.artifactFile), "corrupt\n", { mode: 0o600 });
  await ageGenericArtifact(cacheLayout, capsule);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        maxEstimatedReclaimBytes: 1_000_000,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cache artifact digest or size does not match metadata/u
  );
});

test("immutable GC fails closed for a non-JSON artifact in the cohort capsule stage", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-family-mismatch");
  const capsule = await writeCBundleArtifact({
    cacheLayout,
    stage: "module-graph-cohort-planning-capsule",
  });
  await ageGenericArtifact(cacheLayout, capsule);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        maxEstimatedReclaimBytes: 1_000_000,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /cohort capsule cache entry has an unsupported artifact family/u
  );
});

test("immutable GC rejects a capsule bound to a rotated compiler-output schema", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-legacy-compiler-output");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const compilerOutputEntryPath = join(
    cacheLayout.immutable.artifacts,
    compilerOutput.stage,
    compilerOutput.key,
    "entry.json"
  );
  const compilerOutputEntry = JSON.parse(await fs.readFile(compilerOutputEntryPath, "utf8"));
  compilerOutputEntry.metadata = {
    kind: "convex-wasm-official-output-module-graph-compiler-output-cache-v1",
  };
  await fs.writeFile(compilerOutputEntryPath, `${canonicalJson(compilerOutputEntry)}\n`, {
    mode: 0o600,
  });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        maxEstimatedReclaimBytes: 1_000_000,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output cache record has an unsupported schema/u
  );
});

test("immutable GC rejects a capsule bound to a pre-v8 compiler-output identity", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-legacy-compiler-output-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  const capsulePayloadPath = join(capsuleRoot, capsule.entry.artifactFile);
  const capsulePayload = JSON.parse(await fs.readFile(capsulePayloadPath, "utf8"));
  capsulePayload.planning.topology.cacheIdentity.kind =
    "convex-wasm-official-output-module-graph-compiler-output-cache-identity-v7";
  capsulePayload.planning.topology.cacheKey = fingerprintJson({
    identity: capsulePayload.planning.topology.cacheIdentity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output",
  });
  capsulePayload.planning.topology.certificateCacheKey = fingerprintJson({
    identity: {
      compilerOutputCacheIdentity: capsulePayload.planning.topology.cacheIdentity,
      compilerOutputCacheKey: capsulePayload.planning.topology.cacheKey,
      kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
    },
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output-topology",
  });
  const capsuleSource = Buffer.from(`${canonicalJson(capsulePayload)}\n`);
  const capsuleEntryPath = join(capsuleRoot, "entry.json");
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.artifactSha256 = createHash("sha256").update(capsuleSource).digest("hex");
  capsuleEntry.artifactSize = capsuleSource.length;
  await Promise.all([
    fs.writeFile(capsulePayloadPath, capsuleSource, { mode: 0o600 }),
    fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output cache identity has an unsupported schema/u
  );
});

test("immutable GC closes the exact v8 capsule identity before following references", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-extended-compiler-output-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  const capsulePayloadPath = join(capsuleRoot, capsule.entry.artifactFile);
  const capsulePayload = JSON.parse(await fs.readFile(capsulePayloadPath, "utf8"));
  capsulePayload.planning.topology.cacheIdentity.unexpected = "7".repeat(64);
  capsulePayload.planning.topology.cacheKey = fingerprintJson({
    identity: capsulePayload.planning.topology.cacheIdentity,
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output",
  });
  capsulePayload.planning.topology.certificateCacheKey = fingerprintJson({
    identity: {
      compilerOutputCacheIdentity: capsulePayload.planning.topology.cacheIdentity,
      compilerOutputCacheKey: capsulePayload.planning.topology.cacheKey,
      kind: "convex-wasm-official-output-module-graph-compiler-output-topology-cache-v4",
    },
    kind: "convex-wasm-artifact-pipeline-v9",
    stage: "module-graph-compiler-output-topology",
  });
  const capsuleSource = Buffer.from(`${canonicalJson(capsulePayload)}\n`);
  const capsuleEntryPath = join(capsuleRoot, "entry.json");
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.artifactSha256 = createHash("sha256").update(capsuleSource).digest("hex");
  capsuleEntry.artifactSize = capsuleSource.length;
  await Promise.all([
    fs.writeFile(capsulePayloadPath, capsuleSource, { mode: 0o600 }),
    fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output cache identity has unknown field\(s\): unexpected/u
  );
});

test("immutable GC shares exact v6 capsule identity normalization", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-extended-v5-identity");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule } = await writeCohortCapsuleFixture(cacheLayout, compilerOutput, record);
  const capsulePayload = JSON.parse(
    await fs.readFile(
      join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key, capsule.entry.artifactFile),
      "utf8"
    )
  );
  const { sha256: _sha256, ...identityPayload } = capsulePayload.identity;
  const extendedIdentityPayload = {
    ...identityPayload,
    unexpectedAuthority: "9".repeat(64),
  };
  const extendedIdentity = {
    ...extendedIdentityPayload,
    sha256: fingerprintJson(extendedIdentityPayload),
  };
  capsulePayload.identity = extendedIdentity;
  await writeGenericArtifact({
    cacheLayout,
    extension: "json",
    identity: {
      capsuleIdentity: extendedIdentity,
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      schemaVersion: 6,
    },
    metadata: {
      kind: "convex-wasm-official-output-cohort-planning-capsule-v6",
      schemaVersion: 6,
    },
    payload: `${canonicalJson(capsulePayload)}\n`,
    stage: "module-graph-cohort-planning-capsule",
  });

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule identity has unsupported fields/u
  );
});

test("immutable GC rejects a capsule topology certificate that disagrees with its record", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-topology-mismatch");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  const topologyRoot = join(
    cacheLayout.immutable.artifacts,
    topologyCertificate.stage,
    topologyCertificate.key
  );
  const topologyPayloadPath = join(topologyRoot, topologyCertificate.entry.artifactFile);
  const tamperedCertificate = JSON.parse(await fs.readFile(topologyPayloadPath, "utf8"));
  tamperedCertificate.bridge.object.cacheKey = "0".repeat(64);
  const topologySource = Buffer.from(`${canonicalJson(tamperedCertificate)}\n`);
  const topologyEntryPath = join(topologyRoot, "entry.json");
  const topologyEntry = JSON.parse(await fs.readFile(topologyEntryPath, "utf8"));
  topologyEntry.artifactSha256 = createHash("sha256").update(topologySource).digest("hex");
  topologyEntry.artifactSize = topologySource.length;

  await Promise.all([
    fs.writeFile(topologyPayloadPath, topologySource, { mode: 0o600 }),
    fs.writeFile(topologyEntryPath, `${canonicalJson(topologyEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        maxEstimatedReclaimBytes: 1_000_000,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output topology bridge object disagrees/u
  );
});

test("immutable GC rejects a capsule topology descriptor that disagrees with its record", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("cohort-capsule-descriptor-mismatch");
  const { compilerOutput, record } = await writeCompilerOutputFixture(cacheLayout);
  const { capsule, topologyCertificate } = await writeCohortCapsuleFixture(
    cacheLayout,
    compilerOutput,
    record
  );
  const topologyRoot = join(
    cacheLayout.immutable.artifacts,
    topologyCertificate.stage,
    topologyCertificate.key
  );
  const topologyPayloadPath = join(topologyRoot, topologyCertificate.entry.artifactFile);
  const tamperedCertificate = JSON.parse(await fs.readFile(topologyPayloadPath, "utf8"));
  tamperedCertificate.descriptor.descriptorSha256 = "9".repeat(64);
  const topologySource = Buffer.from(`${canonicalJson(tamperedCertificate)}\n`);
  const topologyEntryPath = join(topologyRoot, "entry.json");
  const topologyEntry = JSON.parse(await fs.readFile(topologyEntryPath, "utf8"));
  topologyEntry.artifactSha256 = createHash("sha256").update(topologySource).digest("hex");
  topologyEntry.artifactSize = topologySource.length;

  const capsuleRoot = join(cacheLayout.immutable.artifacts, capsule.stage, capsule.key);
  const capsulePayloadPath = join(capsuleRoot, capsule.entry.artifactFile);
  const capsulePayload = JSON.parse(await fs.readFile(capsulePayloadPath, "utf8"));
  capsulePayload.planning.topology.descriptor = tamperedCertificate.descriptor;
  const capsuleSource = Buffer.from(`${canonicalJson(capsulePayload)}\n`);
  const capsuleEntryPath = join(capsuleRoot, "entry.json");
  const capsuleEntry = JSON.parse(await fs.readFile(capsuleEntryPath, "utf8"));
  capsuleEntry.artifactSha256 = createHash("sha256").update(capsuleSource).digest("hex");
  capsuleEntry.artifactSize = capsuleSource.length;
  await Promise.all([
    fs.writeFile(topologyPayloadPath, topologySource, { mode: 0o600 }),
    fs.writeFile(topologyEntryPath, `${canonicalJson(topologyEntry)}\n`, { mode: 0o600 }),
    fs.writeFile(capsulePayloadPath, capsuleSource, { mode: 0o600 }),
    fs.writeFile(capsuleEntryPath, `${canonicalJson(capsuleEntry)}\n`, { mode: 0o600 }),
  ]);

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      planConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        maxEstimatedReclaimBytes: 1_000_000,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 60_000,
      })
    ),
    /cohort capsule compiler-output topology descriptor disagrees/u
  );
});

test("immutable GC authenticates every generic artifact extension before listing it", async (t) => {
  const value = await fixture(t);
  const layout = value.layout("gc-build");
  const extensions = ["a", "c", "cwasm", "json", "o", "pch", "wasm"];
  const keys = [];
  for (const extension of extensions) {
    const stage = `gc-${extension}-stage`;
    const identity = { extension, fixture: "old-artifact" };
    const key = fingerprintJson({ kind: "convex-wasm-artifact-pipeline-v9", stage, identity });
    keys.push(key);
    const entryPath = join(layout.immutable.artifacts, stage, key);
    await fs.mkdir(entryPath, { mode: 0o700, recursive: true });
    for (const directory of [
      value.cacheRoot,
      join(value.cacheRoot, "immutable"),
      layout.immutable.root,
      layout.immutable.artifacts,
      join(layout.immutable.artifacts, stage),
    ])
      await fs.chmod(directory, 0o700);
    const artifact = Buffer.from(`old-${extension}-artifact-payload`);
    const artifactSha256 = createHash("sha256").update(artifact).digest("hex");
    const artifactFile = `artifact.${extension}`;
    const entry = {
      artifactFile,
      artifactSha256,
      artifactSize: artifact.length,
      identity,
      key,
      kind: "convex-wasm-artifact-cache-entry-v5",
      metadata: { fixture: true },
      stage,
    };
    await Promise.all([
      fs.writeFile(join(entryPath, artifactFile), artifact, { mode: 0o600 }),
      fs.writeFile(join(entryPath, "entry.json"), `${canonicalJson(entry)}\n`, { mode: 0o600 }),
      fs.writeFile(join(entryPath, "COMPLETE"), `${key}\n`, { mode: 0o600 }),
    ]);
    await Promise.all([
      fs.utimes(entryPath, new Date(0), new Date(0)),
      fs.utimes(join(entryPath, artifactFile), new Date(0), new Date(0)),
      fs.utimes(join(entryPath, "entry.json"), new Date(0), new Date(0)),
      fs.utimes(join(entryPath, "COMPLETE"), new Date(0), new Date(0)),
    ]);
  }
  const ageOnlyPlan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout: layout,
      environment: value.environment,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: extensions.length,
      nowMs: 2_000_000_000,
    })
  );
  assert.equal(ageOnlyPlan.pressure.active, false);
  assert.deepEqual(ageOnlyPlan.evictions, []);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout: layout,
      environment: value.environment,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: extensions.length,
      highWatermarkAllocatedBytes: 1,
      nowMs: 2_000_000_000,
    })
  );
  assert.equal(plan.candidates, extensions.length);
  assert.ok(plan.evictions.length > 0);
  assert.ok(plan.evictions.every(({ type }) => type === "artifact"));
  assert.ok(plan.evictions.every(({ key }) => keys.includes(key)));
  await Promise.all(plan.evictions.map(({ path }) => fs.lstat(path)));
});

test("immutable GC authenticates maintained JavaScript transform entries", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("raw-transform-retention");
  const transform = await writeGenericArtifact({
    cacheLayout,
    extension: "js",
    identity: { kind: "convex-wasm-official-output-chunk-transform-cache-identity-v5" },
    metadata: {
      kind: "convex-wasm-official-output-chunk-transform-cache-record-v3",
      requireSpecifiers: [],
      schemaVersion: 3,
    },
    payload: "module.exports = 1;\n",
    stage: "official-output-chunk-transform",
  });
  await ageGenericArtifact(cacheLayout, transform);

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      maxPlannedEvictions: 1,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(plan.authenticated.invalid, 0);
  assert.equal(plan.candidates, 1);
  assert.deepEqual(
    plan.evictions.map(({ key, stage, type }) => ({ key, stage, type })),
    [{ key: transform.key, stage: transform.stage, type: "artifact" }]
  );
});

test("immutable GC authenticates and evicts only valid runtime header snapshots", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("runtime-header-snapshots");
  await fs.mkdir(cacheLayout.immutable.artifacts, { mode: 0o700, recursive: true });
  for (const path of [
    value.cacheRoot,
    join(value.cacheRoot, "immutable"),
    cacheLayout.immutable.root,
    cacheLayout.immutable.artifacts,
  ]) {
    await fs.chmod(path, 0o700);
  }
  const includeDirectory = join(value.root, "runtime-headers");
  await fs.mkdir(join(includeDirectory, "nested"), { recursive: true });
  await Promise.all([
    fs.writeFile(join(includeDirectory, "runtime.h"), "first runtime header\n"),
    fs.writeFile(join(includeDirectory, "nested", "nested.h"), "nested runtime header\n"),
  ]);
  const createSnapshot = async () => {
    const runtimeHeaderMaterials = await fingerprintMaterialPaths(
      [{ label: "runtime-include-directory-0", path: includeDirectory }],
      "retention runtime header materials"
    );
    return await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache({
      cacheLayout,
      includeDirectories: [includeDirectory],
      runtimeHeaderMaterials,
    });
  };
  const valid = await createSnapshot();
  await fs.writeFile(join(includeDirectory, "runtime.h"), "second runtime header\n");
  const corrupt = await createSnapshot();
  assert.notEqual(valid.key, corrupt.key);
  await fs.writeFile(join(corrupt.inputRoot, "include-0", "runtime.h"), "corrupt snapshot\n");

  const options = {
    cacheLayout,
    environment: value.environment,
    highWatermarkAllocatedBytes: 1,
    maxEstimatedReclaimBytes: 1_000_000,
    nowMs: Date.now() + 60_000,
    recentRetentionMilliseconds: 0,
  };
  const plan = await withHeavyLock(value.environment, () => planConvexWasmImmutableGc(options));
  assert.equal(plan.authenticated.invalid, 1);
  assert.ok(plan.evictions.some(({ key }) => key === valid.key));
  assert.ok(plan.evictions.every(({ key }) => key !== corrupt.key));

  const report = await withHeavyLock(value.environment, () => sweepConvexWasmImmutableGc(options));
  assert.ok(report.removed.some(({ key }) => key === valid.key));
  await assert.rejects(fs.lstat(valid.path), { code: "ENOENT" });
  await fs.lstat(corrupt.path);
});

test("immutable GC ignores stale artifact publication scratch", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("stale-artifact-publication");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "stale-artifact-publication" },
    payload: "stale-artifact-publication",
    stage: "stale-artifact-publication",
  });
  await fs.mkdir(
    join(cacheLayout.immutable.artifacts, artifact.stage, ".publish-crashed-artifact"),
    { mode: 0o700 }
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.deepEqual(
    plan.evictions.map(({ key }) => key),
    [artifact.key]
  );
});

test("immutable GC ignores stale package publication scratch", async (t) => {
  const value = await fixture(t);
  const { cacheLayout } = await materializeModuleGraphPackageFixture(value);
  await fs.mkdir(join(cacheLayout.immutable.packages, ".publish-crashed-package"), {
    mode: 0o700,
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 0);
  assert.deepEqual(plan.evictions, []);
  assert.deepEqual(plan.retained.packages, []);
  assert.equal(plan.categories.planningOnlyCandidates.count, 1);
  assert.ok(plan.categories.planningOnlyCandidates.allocatedBytes > 0);
  assert.equal(plan.categories.sweepableCandidates.count, 0);
  assert.ok(plan.retained.artifacts.length > 0);
});

test("immutable GC never selects an incomplete C bundle as authenticated garbage", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("incomplete-c-bundle");
  const artifact = await writeCBundleArtifact({
    cacheLayout,
    complete: false,
    stage: "incomplete-c-bundle",
  });

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(plan.authenticated.invalid, 1);
  assert.equal(plan.candidates, 0);
  assert.ok(plan.evictions.every(({ key }) => key !== artifact.key));
  await fs.lstat(artifact.root);
});

test("immutable GC does not claim blocks held by a surviving hardlink as reclaimable", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("hardlink-reclaim-estimate");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "hardlink-reclaim-estimate" },
    payload: Buffer.alloc(16_384, 1),
    stage: "hardlink-reclaim-estimate",
  });
  await fs.link(
    join(
      cacheLayout.immutable.artifacts,
      artifact.stage,
      artifact.key,
      artifact.entry.artifactFile
    ),
    join(value.root, "surviving-artifact-hardlink")
  );

  const plan = await withHeavyLock(value.environment, () =>
    planConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 1_000_000,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  const candidate = plan.evictions.find(({ key }) => key === artifact.key);
  assert.notEqual(candidate, undefined);
  assert.ok(candidate.allocationBytes > candidate.estimatedReclaimBytes);
  assert.equal(plan.estimatedReclaimBytes, candidate.estimatedReclaimBytes);
});

test("immutable sweep uses a compact quarantine identity for a large C bundle", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-oversized-quarantine-record");
  const bundle = await writeCBundleArtifact({
    cacheLayout,
    functionCount: 2_800,
    stage: "oversized-quarantine-record",
  });
  const bundlePath = bundle.root;
  await Promise.all(
    [
      bundlePath,
      ...["COMPLETE", "entry.json", C_BUNDLE_MANIFEST_PATH].map((name) => join(bundlePath, name)),
      ...[...bundle.entry.bundle.translationUnits, bundle.entry.bundle.header].map(({ path }) =>
        join(bundlePath, path)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 1_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [bundle.key]
  );
  await assert.rejects(fs.lstat(bundlePath), { code: "ENOENT" });
});

test("immutable sweep rejects a redirected state ancestor before quarantine", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-state-redirect");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "state-redirect" },
    payload: "state-redirect",
    stage: "state-redirect",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const outsideState = join(value.root, "outside-state");
  await fs.mkdir(outsideState, { mode: 0o700 });
  await fs.symlink(outsideState, join(value.cacheRoot, "state"), "dir");

  await assert.rejects(
    withHeavyLock(value.environment, () =>
      sweepConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: Date.now() + 1_000,
        recentRetentionMilliseconds: 0,
      })
    ),
    /symlink/u
  );
  await fs.lstat(artifactPath);
  await assert.rejects(fs.lstat(join(outsideState, "cache-retention")), { code: "ENOENT" });
});

test("explicit immutable sweep removes only old unretained authenticated artifact entries", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "sweep-candidate" },
    payload: "old-sweep-candidate",
    stage: "sweep-candidate-stage",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.sweepAuthorized, true);
  assert.deepEqual(
    report.immutable.sweep.removed.map(({ key }) => key),
    [artifact.key]
  );
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweeping needs a caller-selected high watermark", async (t) => {
  const value = await fixture(t);
  for (const sweep of [{ immutableSweep: true }, { automaticImmutableSweep: true }]) {
    await assert.rejects(
      maintainConvexWasmCache(maintenanceOptions(value, { apply: true, ...sweep })),
      /requires an explicit high watermark/u
    );
  }
  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      environment: {
        ...value.environment,
        CONVEX_WASM_CACHE_HIGH_WATERMARK_BYTES: "1",
      },
    })
  );
  assert.equal(report.immutable.automaticSweep.highWatermarkAllocatedBytes, 1);
});

test("automatic maintenance skips immutable authentication below its high watermark", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("automatic-below-high-watermark");
  const malformedPath = join(
    cacheLayout.immutable.artifacts,
    "malformed-stage",
    "not-an-artifact-key"
  );
  await fs.mkdir(malformedPath, { mode: 0o700, recursive: true });
  const unexpectedFile = join(malformedPath, "unexpected");
  await fs.writeFile(unexpectedFile, "not an immutable entry", {
    mode: 0o600,
  });
  await fs.link(unexpectedFile, join(malformedPath, "duplicate-hardlink"));
  const occupancy = await measureConvexWasmCacheOccupancy(cacheLayout.immutable.root);
  assert.ok(occupancy.allocatedBytes > occupancy.uniqueAllocatedBytes);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      immutableHighWatermarkAllocatedBytes: occupancy.uniqueAllocatedBytes,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.automaticSweep.triggered, false);
  assert.equal(report.immutable.plan, undefined);
  await fs.lstat(malformedPath);
});

test("automatic maintenance sweeps old immutable artifacts above its high watermark", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("automatic-above-high-watermark");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "automatic-sweep" },
    payload: "old-automatic-sweep-candidate",
    stage: "automatic-sweep-candidate",
  });
  await ageGenericArtifact(cacheLayout, artifact);
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      automaticImmutableSweep: true,
      immutableHighWatermarkAllocatedBytes: 1,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.automaticSweep.triggered, true);
  assert.equal(report.immutable.sweep.trigger, "above-high-watermark");
  assert.deepEqual(
    report.immutable.sweep.removed.map(({ key }) => key),
    [artifact.key]
  );
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweep uses remaining byte budget after an oversized candidate", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("bounded-sweep");
  const large = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    identity: { fixture: "bounded-sweep-large" },
    metadata: { fixture: "bounded-sweep" },
    payload: Buffer.alloc(1024 * 1024),
    stage: "bounded-sweep",
  });
  const small = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    identity: { fixture: "bounded-sweep-small" },
    metadata: { fixture: "bounded-sweep" },
    payload: Buffer.alloc(4096),
    stage: "bounded-sweep",
  });
  await Promise.all([
    ageGenericArtifact(cacheLayout, large),
    ageGenericArtifact(cacheLayout, small),
  ]);

  const result = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      maxEstimatedReclaimBytes: 128 * 1024,
      maxPlannedEvictions: 2,
      nowMs: 2_000_000_000_000,
      recentRetentionMilliseconds: 0,
    })
  );

  assert.deepEqual(
    result.removed.map(({ key }) => key),
    [small.key]
  );
  await fs.lstat(join(cacheLayout.immutable.artifacts, large.stage, large.key));
  await assert.rejects(fs.lstat(join(cacheLayout.immutable.artifacts, small.stage, small.key)), {
    code: "ENOENT",
  });
});

test("immutable sweep quarantines a selected root before fallible recursive removal", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-removal-failure");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "sweep-removal-failure" },
    payload: "old-sweep-removal-failure",
    stage: "sweep-removal-failure",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const originalRm = fs.rm;
  let removalAttempted = false;
  fs.rm = async (path, options) => {
    if (path.includes("immutable-sweep-trash")) {
      removalAttempted = true;
      throw Object.assign(new Error("synthetic immutable trash removal failure"), {
        code: "EIO",
      });
    }
    return await originalRm(path, options);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /synthetic immutable trash removal failure/u
    );
  } finally {
    fs.rm = originalRm;
  }
  assert.equal(removalAttempted, true);
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
  const trashRoot = join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash");
  const planRoots = await fs.readdir(trashRoot);
  assert.equal(planRoots.length, 1);
  const quarantineEntries = await fs.readdir(join(trashRoot, planRoots[0]));
  // The base marker and the post-authentication removal marker both remain durable while the
  // recursive delete is in progress, so recovery can distinguish a partial delete from an
  // unverified replacement.
  assert.equal(quarantineEntries.length, 3);
  const quarantinedRoot = quarantineEntries.find((name) => /^[0-9a-f]{64}$/u.test(name));
  assert.notEqual(quarantinedRoot, undefined);
  assert.equal(
    await fs.readFile(
      join(trashRoot, planRoots[0], quarantinedRoot, artifact.entry.artifactFile),
      "utf8"
    ),
    "old-sweep-removal-failure"
  );
  const retry = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(retry.recovered.length, 1);
  assert.equal(retry.recovered[0].status, "removed-quarantined-root");
  assert.deepEqual(retry.removed, []);
  await assert.rejects(fs.lstat(trashRoot), { code: "ENOENT" });
});

test("immutable sweep does not delete a candidate mutated after reauthentication", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-mutation-race");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "mutation-race" },
    payload: "original-mutation-race",
    stage: "mutation-race",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  const payloadPath = join(artifactPath, artifact.entry.artifactFile);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const originalRename = fs.rename;
  fs.rename = async (from, to) => {
    if (from === artifactPath) {
      // Simulate a same-user writer changing the authenticated inode after planning but before
      // the quarantine rename. Restore mtime to exercise the nanosecond/ctime state binding.
      await fs.writeFile(payloadPath, "mutated-after-authentication", { mode: 0o600 });
      await fs.utimes(payloadPath, new Date(0), new Date(0));
    }
    return await originalRename(from, to);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: 2_000_000_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /candidate changed while it was quarantined/u
    );
  } finally {
    fs.rename = originalRename;
  }
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
  const trashRoot = join(cacheLayout.state.root, "cache-retention", "v1", "immutable-sweep-trash");
  const planRoots = await fs.readdir(trashRoot);
  assert.equal(planRoots.length, 1);
  const quarantineRoot = join(
    trashRoot,
    planRoots[0],
    (await fs.readdir(join(trashRoot, planRoots[0]))).find((name) => /^[0-9a-f]{64}$/u.test(name))
  );
  assert.equal(
    await fs.readFile(join(quarantineRoot, artifact.entry.artifactFile), "utf8"),
    "mutated-after-authentication"
  );

  // The failed post-rename verification left only an unverified marker. Recovery must reject the
  // changed tree rather than treating it as a partial removal and deleting it.
  await assert.rejects(
    withHeavyLock(value.environment, () =>
      sweepConvexWasmImmutableGc({
        cacheLayout,
        environment: value.environment,
        highWatermarkAllocatedBytes: 1,
        nowMs: 2_000_000_001,
        recentRetentionMilliseconds: 0,
      })
    ),
    /candidate changed before recovery/u
  );
  await fs.lstat(quarantineRoot);
});

test("immutable sweep recovers a partially removed quarantine root", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-partial-removal");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "partial-removal" },
    payload: "partial-removal",
    stage: "partial-removal",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const originalRm = fs.rm;
  let partialRemoval = true;
  fs.rm = async (path, options) => {
    if (partialRemoval && path.includes("immutable-sweep-trash") && options?.recursive) {
      partialRemoval = false;
      await originalRm(join(path, "entry.json"), { force: true });
      throw Object.assign(new Error("synthetic partial immutable trash removal failure"), {
        code: "EIO",
      });
    }
    return await originalRm(path, options);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /synthetic partial immutable trash removal failure/u
    );
  } finally {
    fs.rm = originalRm;
  }

  const retry = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(retry.recovered.length, 1);
  assert.equal(retry.recovered[0].status, "removed-quarantined-root");
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweep recovers a fully removed quarantine root", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("immutable-sweep-full-removal");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "full-removal" },
    payload: "full-removal",
    stage: "full-removal",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  const originalRm = fs.rm;
  let fullRemoval = true;
  fs.rm = async (path, options) => {
    if (fullRemoval && path.includes("immutable-sweep-trash") && options?.recursive) {
      fullRemoval = false;
      await originalRm(path, options);
      throw Object.assign(new Error("synthetic full immutable trash removal failure"), {
        code: "EIO",
      });
    }
    return await originalRm(path, options);
  };
  try {
    await assert.rejects(
      withHeavyLock(value.environment, () =>
        sweepConvexWasmImmutableGc({
          cacheLayout,
          environment: value.environment,
          highWatermarkAllocatedBytes: 1,
          nowMs: Date.now() + 1_000,
          recentRetentionMilliseconds: 0,
        })
      ),
      /synthetic full immutable trash removal failure/u
    );
  } finally {
    fs.rm = originalRm;
  }

  const retry = await withHeavyLock(value.environment, () =>
    sweepConvexWasmImmutableGc({
      cacheLayout,
      environment: value.environment,
      highWatermarkAllocatedBytes: 1,
      nowMs: Date.now() + 2_000,
      recentRetentionMilliseconds: 0,
    })
  );
  assert.equal(retry.recovered.length, 1);
  assert.equal(retry.recovered[0].status, "cleared-completed-marker");
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
});

test("immutable sweep waits for an active build lease to enter bounded recovery", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("active-lease-sweep");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "active-lease-candidate" },
    payload: "old-active-lease-candidate",
    stage: "active-lease-candidate-stage",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  await withHeavyLock(value.environment, async () => {
    await createConvexWasmBuildWorkLease({
      cacheLayout,
      environment: value.environment,
      nowMs: 0,
    });
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: 2_000_000_000,
    })
  );

  assert.equal(report.immutable.sweepAuthorized, false);
  assert.deepEqual(report.immutable.sweep.removed, []);
  assert.deepEqual(report.immutable.sweep.blockedWorkRoots, [
    { buildId: "active-lease-sweep", status: "active" },
  ]);
  await fs.lstat(artifactPath);
});

test("immutable sweep reclaims artifacts while retaining a failed build work root", async (t) => {
  const value = await fixture(t);
  const cacheLayout = value.layout("failed-lease-sweep");
  const artifact = await writeGenericArtifact({
    cacheLayout,
    extension: "wasm",
    metadata: { fixture: "failed-lease-candidate" },
    payload: "old-failed-lease-candidate",
    stage: "failed-lease-candidate-stage",
  });
  const artifactPath = join(cacheLayout.immutable.artifacts, artifact.stage, artifact.key);
  await Promise.all(
    [
      artifactPath,
      ...["COMPLETE", artifact.entry.artifactFile, "entry.json"].map((name) =>
        join(artifactPath, name)
      ),
    ].map(async (path) => await fs.utimes(path, new Date(0), new Date(0)))
  );
  await withHeavyLock(value.environment, async () => {
    const lease = await createConvexWasmBuildWorkLease({
      cacheLayout,
      environment: value.environment,
      nowMs: 0,
    });
    await lease.fail(0);
  });

  const report = await maintainConvexWasmCache(
    maintenanceOptions(value, {
      apply: true,
      immutableHighWatermarkAllocatedBytes: 1,
      immutableSweep: true,
      nowMs: 2 * 24 * 60 * 60 * 1_000,
    })
  );

  assert.equal(report.immutable.sweepAuthorized, true);
  assert.deepEqual(
    report.immutable.sweep.removed.map(({ key }) => key),
    [artifact.key]
  );
  assert.deepEqual(report.immutable.sweep.blockedWorkRoots, []);
  await assert.rejects(fs.lstat(artifactPath), { code: "ENOENT" });
  await fs.lstat(cacheLayout.work.buildRoot);
});
