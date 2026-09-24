import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createFullFrozenGraphBindingAuthority,
  createFrozenGraphInputAuthority,
} from "./convex-wasm-frozen-graph-authority.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import {
  createIsolatedRuntimeAuthorityCacheIdentity,
  createRuntimeContentProducerCacheIdentity,
  materializeCachedIsolatedRuntimeAuthority,
  materializeRuntimeContentProducerCertificate,
  publishIsolatedRuntimeAuthorityCacheEntry,
  publishRuntimeContentProducerCertificate,
} from "./source-authority-cache.mjs";
import { createConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function withTemporaryDirectory(execute) {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-authority-cache-"));
  try {
    return await execute(directory);
  } finally {
    await fs.rm(directory, { force: true, recursive: true });
  }
}

function fixture() {
  const routes = [
    {
      entryPath: "convex/first.ts",
      exportName: "first",
      modulePath: "first",
      runtimeModulePath: "first.js",
      udfKind: "query",
      visibility: "public",
    },
    {
      entryPath: "convex/second.ts",
      exportName: "second",
      modulePath: "second",
      runtimeModulePath: "second.js",
      udfKind: "mutation",
      visibility: "internal",
    },
  ];
  const requestModules = routes.map((route) => {
    const source = `export const ${route.modulePath} = true;\n`;
    const sources = [`../${route.entryPath}`];
    const sourceMap = JSON.stringify({ sources, version: 3 });
    return { environment: "isolate", path: route.runtimeModulePath, source, sourceMap };
  });
  const graphSession = {
    bundleModulesByPath: new Map(
      requestModules.map((module) => [
        module.path,
        {
          environment: module.environment,
          moduleSha256: digest(`${module.source}${module.sourceMap}`),
          path: module.path,
          sourceMap: {
            sha256: digest(module.sourceMap),
            size: Buffer.byteLength(module.sourceMap),
            sourcesContentCount: 0,
            sourcesCount: 1,
          },
          sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
            sources: JSON.parse(module.sourceMap).sources,
          }),
          sourceSha256: digest(module.source),
          sourceSize: Buffer.byteLength(module.source),
        },
      ])
    ),
    contextReuseAnalysisIdentity: {
      entries: routes.map(({ entryPath }) => entryPath).sort(),
      kind: "convex-context-reuse-analysis",
      policyFingerprint: digest("context-reuse policy"),
      resultSha256: digest("context-reuse result"),
    },
    contextReuseEnabledByEntry: new Map(routes.map(({ entryPath }) => [entryPath, true])),
    dependencyGraphByEntry: new Map(
      routes.map((route) => [route.entryPath, { sha256: digest(`graph:${route.entryPath}`) }])
    ),
    deploymentConfigurationModulesByPath: new Map(),
    effectExecutionMode: "guest-promise-event-loop",
    graphSha256: digest("fixture graph"),
    inputCount: routes.length,
    nodeModulesByPath: new Map(),
    runtimeModulePathByEntry: new Map(
      routes.map((route) => [route.entryPath, route.runtimeModulePath])
    ),
    toolchain: { convex: "fixture", esbuild: "fixture" },
    verifyBundleEntryPaths: async () => {},
    verifyInputMaterials: async () => {},
  };
  const inventory = {
    actions: [],
    functions: routes,
    kind: "convex-generated-api-inventory-v1",
    snapshot: { sha256: digest("fixture inventory") },
  };
  const sourceEnvelope = createConvexWasmSourceEnvelope({
    graphSession,
    inventory,
    selectedExports: routes.map(({ exportName, modulePath }) => ({ exportName, modulePath })),
  });
  const sourceEnvelopeBytes = Buffer.from(`${canonicalJson(sourceEnvelope)}\n`);
  const startPushBytes = Buffer.from(
    JSON.stringify({
      adminKey: "frozen-fixture-admin-key",
      appDefinition: { changedModules: requestModules, unchangedModuleHashes: [] },
      componentDefinitions: [],
      dryRun: false,
      forCodegen: false,
      functions: "convex",
      nodeDependencies: [],
      nodeVersion: "22",
    })
  );
  return { graphSession, inventory, sourceEnvelope, sourceEnvelopeBytes, startPushBytes };
}

async function completeAuthority(directory, value, sourcePackage) {
  const selectedModules = [...value.graphSession.bundleModulesByPath.values()].sort((left, right) =>
    left.path.localeCompare(right.path)
  );
  const emptySha256 = fingerprintJson([]);
  const selectedModulesSha256 = fingerprintJson(selectedModules);
  const frozenGraphInputAuthority = createFrozenGraphInputAuthority({
    evidence: {
      authoritativeDeploymentConfigurationModuleCount: 0,
      authoritativeDeploymentConfigurationModulesSha256: emptySha256,
      authoritativeIsolateModuleCount: selectedModules.length,
      authoritativeIsolateModulesSha256: selectedModulesSha256,
      authoritativeModuleCount: selectedModules.length,
      authoritativeModulesSha256: selectedModulesSha256,
      authoritativeNodeModuleCount: 0,
      authoritativeNodeModulesSha256: emptySha256,
      authoritativeUdfIsolateModuleCount: selectedModules.length,
      authoritativeUdfIsolateModulesSha256: selectedModulesSha256,
      requestModuleCount: selectedModules.length,
      requestModulesSha256: selectedModulesSha256,
      requestSha256: digest(value.startPushBytes),
      requestSize: value.startPushBytes.length,
      selectedModuleCount: selectedModules.length,
      selectedModules,
      selectedModulesSha256,
      selectedRouteCount: value.sourceEnvelope.selectedRoutes.length,
    },
    sourceEnvelope: value.sourceEnvelope,
    sourceEnvelopeBytes: value.sourceEnvelopeBytes,
  });
  const sourcePackageSha256 = digest(sourcePackage);
  const runtimeContentSha256 = digest("fixture runtime content");
  const bindingPayload = {
    kind: "convex-deployed-runtime-binding-authority-v1",
    modules: selectedModules.map((module) => ({
      environment: module.environment,
      moduleHashVerified: true,
      moduleSha256: module.moduleSha256,
      path: module.path,
      sourceMap: module.sourceMap,
      sourcePackageHashVerified: true,
      sourcePackageRuntimeContentSha256: runtimeContentSha256,
      sourcePackageSha256,
      sourceSha256: module.sourceSha256,
    })),
    sourcePackageFileSha256: [sourcePackageSha256],
  };
  const bindingAuthority = {
    ...bindingPayload,
    authoritySha256: fingerprintJson(bindingPayload),
  };
  return createFullFrozenGraphBindingAuthority({
    bindingAuthority,
    frozenGraphInputAuthority,
    sourceEnvelopeBytes: value.sourceEnvelopeBytes,
    sourcePackage: {
      path: join(directory, "source-package.zip"),
      sha256: sourcePackageSha256,
      size: sourcePackage.length,
    },
    startPushBytes: value.startPushBytes,
  }).authority;
}

test("target selection changes exact authority identity", () => {
  const value = fixture();
  const request = JSON.parse(value.startPushBytes);
  request.nodeDependencies = [{ name: "impers", version: "0.0.9" }];
  const identity = (selection) =>
    createIsolatedRuntimeAuthorityCacheIdentity({
      backendImageId: `sha256:${"a".repeat(64)}`,
      dependencyEgressUsed: true,
      sourceEnvelope: value.sourceEnvelope,
      sourceEnvelopeBytes: value.sourceEnvelopeBytes,
      startPushBytes: Buffer.from(canonicalJson({ ...request, externalDepsPackage: selection })),
    });
  const first = { id: "old-package", sha256: "1".repeat(64) };
  assert.equal(identity(first).cacheKey, identity({ ...first }).cacheKey);
  assert.notEqual(identity(first).cacheKey, identity({ ...first, id: "new-package" }).cacheKey);
  assert.notEqual(
    identity(first).cacheKey,
    identity({ ...first, sha256: "2".repeat(64) }).cacheKey
  );
});

test("isolated runtime-authority cache reuses only the exact frozen source and start-push identity", async () => {
  await withTemporaryDirectory(async (directory) => {
    const value = fixture();
    const sourcePackage = Buffer.from("504b0506000000000000000000000000000000000000", "hex");
    const authority = await completeAuthority(directory, value, sourcePackage);
    const cacheRoot = join(directory, "cache");
    const authorityPath = join(directory, "authority.json");
    const sourcePackagePath = join(directory, "source-package.zip");
    await fs.mkdir(cacheRoot, { mode: 0o700 });
    await fs.writeFile(authorityPath, `${canonicalJson(authority)}\n`, { mode: 0o600 });
    await fs.writeFile(sourcePackagePath, sourcePackage, { mode: 0o600 });
    const identity = createIsolatedRuntimeAuthorityCacheIdentity({
      backendImageId: `sha256:${"a".repeat(64)}`,
      dependencyEgressUsed: false,
      sourceEnvelope: value.sourceEnvelope,
      sourceEnvelopeBytes: value.sourceEnvelopeBytes,
      startPushBytes: value.startPushBytes,
    });
    const published = await publishIsolatedRuntimeAuthorityCacheEntry({
      authorityPath,
      cacheRoot,
      expectedIdentity: identity,
      sourceEnvelope: value.sourceEnvelope,
      sourceEnvelopeBytes: value.sourceEnvelopeBytes,
      sourcePackagePath,
      startPushBytes: value.startPushBytes,
    });
    assert.equal(published.cache, "miss");

    const restoredAuthorityPath = join(directory, "restored-authority.json");
    const restoredSourcePackagePath = join(directory, "restored-source-package.zip");
    const cached = await materializeCachedIsolatedRuntimeAuthority({
      authorityOutputPath: restoredAuthorityPath,
      cacheRoot,
      expectedIdentity: identity,
      sourceEnvelope: value.sourceEnvelope,
      sourceEnvelopeBytes: value.sourceEnvelopeBytes,
      sourcePackageOutputPath: restoredSourcePackagePath,
      startPushBytes: value.startPushBytes,
    });
    assert.equal(cached.cache, "hit");
    assert.equal(cached.sourcePackageRuntimeContentSha256, digest("fixture runtime content"));
    assert.deepEqual(await fs.readFile(restoredAuthorityPath), await fs.readFile(authorityPath));
    assert.deepEqual(await fs.readFile(restoredSourcePackagePath), sourcePackage);

    const changedStartPushBytes = Buffer.concat([value.startPushBytes, Buffer.from(" ")]);
    const changedIdentity = createIsolatedRuntimeAuthorityCacheIdentity({
      backendImageId: `sha256:${"a".repeat(64)}`,
      dependencyEgressUsed: false,
      sourceEnvelope: value.sourceEnvelope,
      sourceEnvelopeBytes: value.sourceEnvelopeBytes,
      startPushBytes: changedStartPushBytes,
    });
    assert.equal(
      await materializeCachedIsolatedRuntimeAuthority({
        authorityOutputPath: join(directory, "wrong-authority.json"),
        cacheRoot,
        expectedIdentity: changedIdentity,
        sourceEnvelope: value.sourceEnvelope,
        sourceEnvelopeBytes: value.sourceEnvelopeBytes,
        sourcePackageOutputPath: join(directory, "wrong-source-package.zip"),
        startPushBytes: changedStartPushBytes,
      }),
      undefined
    );

    const failedAuthorityPath = join(directory, "failed-authority.json");
    const delayedSourcePackagePath = join(directory, "delayed-source-package.zip");
    const originalWriteFile = fs.writeFile;
    let markSourcePackageWriteStarted;
    const sourcePackageWriteStarted = new Promise((resolveStarted) => {
      markSourcePackageWriteStarted = resolveStarted;
    });
    let releaseSourcePackageWrite;
    const sourcePackageWriteRelease = new Promise((resolveRelease) => {
      releaseSourcePackageWrite = resolveRelease;
    });
    fs.writeFile = async (path, ...arguments_) => {
      if (path === failedAuthorityPath) {
        throw new Error("synthetic authority materialization failure");
      }
      if (path === delayedSourcePackagePath) {
        markSourcePackageWriteStarted();
        await sourcePackageWriteRelease;
      }
      return originalWriteFile(path, ...arguments_);
    };
    try {
      const failedMaterialization = materializeCachedIsolatedRuntimeAuthority({
        authorityOutputPath: failedAuthorityPath,
        cacheRoot,
        expectedIdentity: identity,
        sourceEnvelope: value.sourceEnvelope,
        sourceEnvelopeBytes: value.sourceEnvelopeBytes,
        sourcePackageOutputPath: delayedSourcePackagePath,
        startPushBytes: value.startPushBytes,
      });
      await sourcePackageWriteStarted;
      assert.equal(
        await Promise.race([
          failedMaterialization.then(
            () => "settled",
            () => "settled"
          ),
          new Promise((resolvePending) => setImmediate(() => resolvePending("pending"))),
        ]),
        "pending"
      );
      releaseSourcePackageWrite();
      await assert.rejects(failedMaterialization, /synthetic authority materialization failure/u);
      assert.deepEqual(await fs.readFile(delayedSourcePackagePath), sourcePackage);
    } finally {
      releaseSourcePackageWrite();
      fs.writeFile = originalWriteFile;
    }
  });
});

test("runtime-content producer certificates bind the backend, helper, dependencies, and archive", async () => {
  await withTemporaryDirectory(async (directory) => {
    const cacheRoot = join(directory, "cache");
    const externalDepsPackagePath = join(directory, "external-deps-package.zip");
    const externalDepsPackage = Buffer.from("certified external dependency archive");
    await fs.mkdir(cacheRoot, { mode: 0o700 });
    await fs.writeFile(externalDepsPackagePath, externalDepsPackage, { mode: 0o600 });
    const base = {
      backendImageId: `sha256:${"a".repeat(64)}`,
      dependencies: [
        { package: "proxy-agent", version: "8.0.2" },
        { package: "impers", version: "0.0.9" },
      ],
      helper: { sha256: "b".repeat(64), size: 4096 },
      runtimeContentAlgorithm: "convex-source-package-runtime-content-v1",
    };
    const identity = createRuntimeContentProducerCacheIdentity(base);
    assert.throws(
      () =>
        createRuntimeContentProducerCacheIdentity({
          ...base,
          dependencies: [
            { package: "proxy-agent", version: "8.0.2" },
            { package: "proxy-agent", version: "9.0.0" },
          ],
        }),
      /must not contain duplicate package names/u
    );
    const published = await publishRuntimeContentProducerCertificate({
      backendAuthoritySha256: "c".repeat(64),
      cacheRoot,
      expectedIdentity: identity,
      externalDepsPackagePath,
      externalDepsStorageKey: "external-deps-storage-key",
      request: { sha256: "d".repeat(64), size: 55_553_033 },
      runtimeContentSha256: "e".repeat(64),
      sourcePackage: { sha256: "f".repeat(64), size: 12_550_000 },
    });
    assert.equal(published.cache, "miss");
    const retainedOnSecondRequest = await publishRuntimeContentProducerCertificate({
      backendAuthoritySha256: "1".repeat(64),
      cacheRoot,
      expectedIdentity: identity,
      externalDepsPackagePath,
      externalDepsStorageKey: "external-deps-storage-key",
      request: { sha256: "2".repeat(64), size: 66 },
      runtimeContentSha256: "3".repeat(64),
      sourcePackage: { sha256: "4".repeat(64), size: 77 },
    });
    assert.equal(retainedOnSecondRequest.cache, "hit");
    assert.equal(retainedOnSecondRequest.certificateSha256, published.certificateSha256);
    assert.deepEqual(retainedOnSecondRequest.request, published.request);

    const changedArchivePath = join(directory, "changed-external-deps-package.zip");
    await fs.writeFile(changedArchivePath, Buffer.from("different archive"), { mode: 0o600 });
    await assert.rejects(
      publishRuntimeContentProducerCertificate({
        backendAuthoritySha256: "1".repeat(64),
        cacheRoot,
        expectedIdentity: identity,
        externalDepsPackagePath: changedArchivePath,
        externalDepsStorageKey: "external-deps-storage-key",
        request: { sha256: "2".repeat(64), size: 66 },
        runtimeContentSha256: "3".repeat(64),
        sourcePackage: { sha256: "4".repeat(64), size: 77 },
      }),
      /dependency archive changed under the same producer identity/u
    );

    const materializedPath = join(directory, "materialized-external-deps.zip");
    const evidenceOnly = await materializeRuntimeContentProducerCertificate({
      cacheRoot,
      expectedIdentity: identity,
    });
    assert.equal(evidenceOnly.certificateSha256, published.certificateSha256);
    await assert.rejects(fs.access(materializedPath), { code: "ENOENT" });
    const materialized = await materializeRuntimeContentProducerCertificate({
      cacheRoot,
      expectedIdentity: identity,
      externalDepsPackageOutputPath: materializedPath,
    });
    assert.equal(materialized.cache, "hit");
    assert.equal(materialized.certificateSha256, published.certificateSha256);
    assert.deepEqual(await fs.readFile(materializedPath), externalDepsPackage);
    assert.deepEqual(identity.dependencies, [
      { package: "impers", version: "0.0.9" },
      { package: "proxy-agent", version: "8.0.2" },
    ]);

    for (const [name, changed] of [
      ["backend", { ...base, backendImageId: `sha256:${"1".repeat(64)}` }],
      ["helper", { ...base, helper: { sha256: "2".repeat(64), size: 4096 } }],
      [
        "dependencies",
        {
          ...base,
          dependencies: [{ package: "proxy-agent", version: "9.0.0" }],
        },
      ],
    ]) {
      assert.equal(
        await materializeRuntimeContentProducerCertificate({
          cacheRoot,
          expectedIdentity: createRuntimeContentProducerCacheIdentity(changed),
          externalDepsPackageOutputPath: join(directory, `${name}-miss.zip`),
        }),
        undefined
      );
    }

    const entryRoot = join(
      cacheRoot,
      "convex-wasm",
      "state",
      "v1",
      "runtime-content-producer",
      "v1",
      identity.cacheKey
    );
    const cachedArchivePath = join(entryRoot, "external-deps-package.zip");
    await fs.writeFile(cachedArchivePath, Buffer.from("tampered archive"), { mode: 0o600 });
    await assert.rejects(
      materializeRuntimeContentProducerCertificate({
        cacheRoot,
        expectedIdentity: identity,
        externalDepsPackageOutputPath: join(directory, "tampered-output.zip"),
      }),
      /dependency archive differs from its payload/u
    );

    await fs.writeFile(cachedArchivePath, externalDepsPackage, { mode: 0o600 });
    const certificatePath = join(entryRoot, "certificate.json");
    const certificate = JSON.parse(await fs.readFile(certificatePath, "utf8"));
    certificate.runtimeContentSha256 = "0".repeat(64);
    await fs.writeFile(certificatePath, `${canonicalJson(certificate)}\n`, { mode: 0o600 });
    await assert.rejects(
      materializeRuntimeContentProducerCertificate({
        cacheRoot,
        expectedIdentity: identity,
        externalDepsPackageOutputPath: join(directory, "tampered-certificate-output.zip"),
      }),
      /certificate digest is invalid/u
    );
  });
});

test("runtime-content producer certificates represent the no-dependency case without an archive", async () => {
  await withTemporaryDirectory(async (directory) => {
    const cacheRoot = join(directory, "cache");
    await fs.mkdir(cacheRoot, { mode: 0o700 });
    const identity = createRuntimeContentProducerCacheIdentity({
      backendImageId: `sha256:${"a".repeat(64)}`,
      dependencies: [],
      helper: { sha256: "b".repeat(64), size: 4096 },
      runtimeContentAlgorithm: "convex-source-package-runtime-content-v1",
    });
    const input = {
      backendAuthoritySha256: "c".repeat(64),
      cacheRoot,
      expectedIdentity: identity,
      request: { sha256: "d".repeat(64), size: 100 },
      runtimeContentSha256: "e".repeat(64),
      sourcePackage: { sha256: "f".repeat(64), size: 200 },
    };
    await assert.rejects(
      publishRuntimeContentProducerCertificate({
        ...input,
        externalDepsStorageKey: "unexpected-storage-key",
      }),
      /storage key is invalid without a dependency archive/u
    );
    const published = await publishRuntimeContentProducerCertificate(input);
    const materialized = await materializeRuntimeContentProducerCertificate({
      cacheRoot,
      expectedIdentity: identity,
    });
    assert.equal(published.externalDepsPackage, null);
    assert.equal(materialized.externalDepsPackage, null);
  });
});
