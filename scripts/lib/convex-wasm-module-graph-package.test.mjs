import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  buildConvexWasmModuleGraphModuleArtifacts,
  buildConvexWasmModuleGraphPackage,
} from "./convex-wasm-module-graph-build.mjs";
import {
  createConvexWasmModuleGraphPackageValidationScope,
  loadAndVerifyConvexWasmModuleGraphPackage,
} from "./convex-wasm-module-graph-package.mjs";

const fixturePath = new URL("../test-fixtures/convex-wasm-module-graph-registry/fixture.json", import.meta.url);

async function materializeFixture(context) {
  const fixture = JSON.parse(await fs.readFile(fixturePath, "utf8"));
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-module-package-"));
  context.after(() => fs.rm(root, { force: true, recursive: true }));
  const cacheRoot = join(root, "cache");
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "package-fixture",
    cacheRoot,
    repositoryRoot: join(root, "project"),
    scope: "isolated-test",
  });
  const graph = fixture.material.moduleGraph;
  const packagePath = join(cacheLayout.immutable.packages, graph.graphManifestSha256);
  for (const entry of graph.artifactEntries) {
    const entryPath = join(cacheLayout.immutable.artifacts, entry.stage, entry.cacheKey);
    await fs.mkdir(entryPath, { mode: 0o700, recursive: true });
    for (const file of entry.files) {
      await fs.writeFile(join(entryPath, file.name), Buffer.from(file.base64, "base64"), {
        mode: 0o600,
      });
    }
  }
  await fs.mkdir(packagePath, { mode: 0o700, recursive: true });
  for (const file of graph.packageFiles) {
    await fs.writeFile(join(packagePath, file.name), Buffer.from(file.base64, "base64"), {
      mode: 0o600,
    });
  }
  return { cacheLayout, cacheRoot, graph, packagePath };
}

test("authenticates a complete synthetic module-graph package from an isolated cache", async (context) => {
  const { cacheLayout, cacheRoot, graph, packagePath } = await materializeFixture(context);
  const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout,
    cacheRoot,
    graphManifestSha256: graph.graphManifestSha256,
    packagePath,
  });
  assert.equal(verified.package.cacheKey, graph.graphManifestSha256);
  assert.equal(verified.graphManifest.graphManifestSha256, graph.graphManifestSha256);
  assert.equal(
    verified.packageMaterial.artifactReferences.length,
    verified.graphManifest.modules.length
  );
  const artifactFile = graph.artifactEntries[0].files.find((file) => file.name.startsWith("artifact."));
  assert.ok(artifactFile);
  const artifactPath = join(
    cacheLayout.immutable.artifacts,
    graph.artifactEntries[0].stage,
    graph.artifactEntries[0].cacheKey,
    artifactFile.name
  );
  await fs.writeFile(artifactPath, "changed payload\n");
  await assert.rejects(
    loadAndVerifyConvexWasmModuleGraphPackage({
      cacheLayout,
      cacheRoot,
      graphManifestSha256: graph.graphManifestSha256,
      packagePath,
    }),
    /digest|size|changed/u
  );
});

test("module-graph artifacts reuse material across distinct leaf control identities", async (context) => {
  const { cacheLayout, cacheRoot, graph, packagePath } = await materializeFixture(context);
  const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout,
    cacheRoot,
    graphManifestSha256: graph.graphManifestSha256,
    packagePath,
  });
  const manifest = verified.graphManifest;
  const module = manifest.modules.at(-1);
  let coreBuilds = 0;
  let aotBuilds = 0;
  const options = {
    async buildAot({ coreWasm, workPath }) {
      aotBuilds += 1;
      const outputPath = join(workPath, "leaf.cwasm");
      await fs.writeFile(outputPath, `aot:${await fs.readFile(coreWasm.path, "utf8")}`);
      return {
        engineIdentity: {
          engineCompatibilitySha256: manifest.engine.compatibilitySha256,
          engineConfig: manifest.engine.config,
          kind: "convex-wasm-wasmtime-engine-identity",
          target: manifest.engine.target,
        },
        outputPath,
        timing: null,
      };
    },
    async buildCoreWasm({ workPath }) {
      coreBuilds += 1;
      const outputPath = join(workPath, "leaf.wasm");
      await fs.writeFile(outputPath, "synthetic leaf wasm");
      return { contract: module.contract, outputPath, timing: null };
    },
    cacheLayout,
    cacheRoot,
    coreWasmInput: { sha256: "a".repeat(64), size: 1 },
    engine: manifest.engine,
    leafInvalidation: { changed: "first" },
    leafInvalidationSha256: fingerprintJson({ changed: "first" }),
    limits: { aotBytes: 1024, wasmBytes: 1024 },
    module,
    routing: manifest.routing,
    toolchain: manifest.toolchain,
  };
  const first = await buildConvexWasmModuleGraphModuleArtifacts(options);
  const second = await buildConvexWasmModuleGraphModuleArtifacts({
    ...options,
    leafInvalidation: { changed: true },
    leafInvalidationSha256: fingerprintJson({ changed: true }),
  });
  assert.equal(coreBuilds, 1);
  assert.equal(aotBuilds, 1);
  assert.notEqual(first.coreWasm.report.cacheKey, second.coreWasm.report.cacheKey);
  assert.notEqual(first.aot.report.cacheKey, second.aot.report.cacheKey);
  assert.equal(first.coreWasm.entry.artifactSha256, second.coreWasm.entry.artifactSha256);
  assert.equal(first.aot.entry.artifactSha256, second.aot.entry.artifactSha256);
});

test("constructs and authenticates a module-graph package from generic build callbacks", async (context) => {
  const { cacheLayout, cacheRoot, graph, packagePath } = await materializeFixture(context);
  const input = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout,
    cacheRoot,
    graphManifestSha256: graph.graphManifestSha256,
    packagePath,
  });
  const manifest = input.graphManifest;
  const buildCacheRoot = join(cacheRoot, "build-cache");
  const buildCacheLayout = deriveConvexWasmCacheLayout({
    buildId: "package-build",
    cacheRoot: buildCacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  let coreBuilds = 0;
  let aotBuilds = 0;
  const options = {
    artifactLimits: { aotBytes: 1024, wasmBytes: 1024 },
    async buildAot({ coreWasm, module, workPath }) {
      aotBuilds += 1;
      const outputPath = join(workPath, `${module.role}.cwasm`);
      await fs.writeFile(outputPath, `aot:${module.role}:${await fs.readFile(coreWasm.path, "utf8")}`);
      return {
        engineIdentity: {
          engineCompatibilitySha256: manifest.engine.compatibilitySha256,
          engineConfig: manifest.engine.config,
          kind: "convex-wasm-wasmtime-engine-identity",
          target: manifest.engine.target,
        },
        outputPath,
        timing: null,
      };
    },
    async buildCoreWasm({ module, workPath }) {
      coreBuilds += 1;
      const outputPath = join(workPath, `${module.role}.wasm`);
      await fs.writeFile(outputPath, `wasm:${module.role}`);
      return { contract: module.contract, outputPath, timing: null };
    },
    cacheLayout: buildCacheLayout,
    cacheRoot: buildCacheRoot,
    concurrency: 2,
    contextReuseAnalysisIdentity: manifest.contextReuseAnalysis,
    engine: manifest.engine,
    hostAbi: manifest.hostAbi,
    initialization: (({ finalMemoryCursor: _memory, finalTableCursor: _table, ...input }) => input)(
      manifest.initialization
    ),
    modules: manifest.modules.map(({ artifacts: _artifacts, ...module }) => module),
    producerIdentity: input.provenance.producerIdentity,
    routing: manifest.routing,
    toolchain: manifest.toolchain,
  };
  const first = await buildConvexWasmModuleGraphPackage(options);
  assert.equal(coreBuilds, manifest.modules.length);
  assert.equal(aotBuilds, manifest.modules.length);
  assert.equal(first.buildReport.package.cache, "miss");
  const independentlyVerified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout: buildCacheLayout,
    cacheRoot: buildCacheRoot,
    graphManifestSha256: first.graphManifest.graphManifestSha256,
    packagePath: first.package.path,
  });
  assert.equal(independentlyVerified.graphManifest.graphManifestSha256, first.graphManifest.graphManifestSha256);
  await first.verifyMaterials(createConvexWasmModuleGraphPackageValidationScope());
  const second = await buildConvexWasmModuleGraphPackage(options);
  assert.equal(second.buildReport.package.cache, "hit");
  assert.equal(coreBuilds, manifest.modules.length);
  assert.equal(aotBuilds, manifest.modules.length);
});
