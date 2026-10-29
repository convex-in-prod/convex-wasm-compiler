import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { canonicalJson, fingerprintJson } from "../lib/convex-wasm-artifact-contract.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "../lib/convex-wasm-module-graph-package.mjs";
import { C_BUNDLE_CACHE_ENTRY_KIND, C_BUNDLE_KIND, C_BUNDLE_MANIFEST_PATH } from "../lib/convex-wasm-static-hermes-c-bundle.mjs";

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

async function ageTree(path) {
  const status = await fs.lstat(path);
  if (status.isDirectory()) {
    for (const name of await fs.readdir(path)) await ageTree(join(path, name));
  }
  await fs.utimes(path, new Date(0), new Date(0));
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

async function writeCBundleArtifact({ cacheLayout, complete = true, functionCount = 1, identity: rawIdentity, retainedLayout, stage }) {
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
  if (retainedLayout !== undefined) {
    const path = "sh_this_unit_layout.json";
    sources.set(path, retainedLayout);
    manifest.layout = { path, sha256: createHash("sha256").update(retainedLayout).digest("hex"), size: Buffer.byteLength(retainedLayout) };
  }
  const manifestSource = `${canonicalJson(manifest)}\n`;
  const bundle = {
    ...manifest,
    manifest: {
      path: C_BUNDLE_MANIFEST_PATH,
      sha256: createHash("sha256").update(manifestSource).digest("hex"),
      size: Buffer.byteLength(manifestSource),
    },
  };
  const identity = rawIdentity ?? { fixture: "cache-retention-c-bundle", stage };
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
      new URL("./convex-wasm-module-graph-registry/fixture.json", import.meta.url),
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
  assert.ok([1, 2, 3, 4].includes(schemaVersion));
  if (schemaVersion <= 2) assert.notEqual(graphManifest, undefined);
  const lookupIdentity = { fixture: "cache-retention-legacy-certificate" };
  const payload = {
    kind: "convex-wasm-deployment-result-certificate-v2",
    lookupIdentity,
    manifest,
    ...(schemaVersion === 3 || schemaVersion === 4
      ? { packageReferences: [{ graphManifestSha256, packageMaterial }] }
      : {
          packageGraphs: [{
            graphManifest,
            graphManifestSha256,
            ...(schemaVersion === 2 ? { packageMaterial } : {}),
          }],
        }),
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

export {
  writeGenericArtifact,
  ageGenericArtifact,
  ageTree,
  packageFileMaterial,
  writeLegacyV2ModuleGraphPackage,
  writeCBundleArtifact,
  compilerOutputReference,
  compilerOutputCacheIdentity,
  writeCompilerOutputFixture,
  writeCohortCapsuleFixture,
  materializeModuleGraphPackageFixture,
  writeLegacyDeploymentResultCertificate
};
