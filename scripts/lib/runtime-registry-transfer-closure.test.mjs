import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  createRuntimeRegistrySourceCatalog,
  deriveRuntimeRegistryTransferPlan,
} from "./runtime-registry-transfer-closure.mjs";

function transferClosureFixture(registryRoot = "/registry") {
  const deploymentSha256 = "1".repeat(64);
  const generationSha256 = "2".repeat(64);
  const generationManifestSha256 = "3".repeat(64);
  const sourcePackageRuntimeContentSha256 = "4".repeat(64);
  const graphManifestSha256 = "5".repeat(64);
  const coreCacheKey = "6".repeat(64);
  const aotCacheKey = "7".repeat(64);
  const coreStage = "module-graph-leaf-core-wasm";
  const aotStage = "module-graph-leaf-wasmtime-aot";
  const graphPackageRoot = `${registryRoot}/module-graph-cache/immutable/v6/packages/${graphManifestSha256}`;
  const artifactRoot = `${registryRoot}/module-graph-cache/immutable/v6/artifacts`;
  const moduleArtifacts = {
    aot: {
      cacheKey: aotCacheKey,
      path: `${artifactRoot}/${aotStage}/${aotCacheKey}/artifact.cwasm`,
      sha256: "8".repeat(64),
      size: 456,
      stage: aotStage,
    },
    coreWasm: {
      cacheKey: coreCacheKey,
      path: `${artifactRoot}/${coreStage}/${coreCacheKey}/artifact.wasm`,
      sha256: "9".repeat(64),
      size: 123,
      stage: coreStage,
    },
  };
  return {
    aotCacheKey,
    aotStage,
    coreCacheKey,
    coreStage,
    deploymentSha256,
    generationSha256,
    graphManifestSha256,
    preflight: {
      runtimeRegistry: {
        generationReferences: [
          {
            current: true,
            deploymentSha256,
            generation: { sha256: generationManifestSha256, size: 123 },
            generationSha256,
            moduleGraphs: [
              {
                artifacts: { base: moduleArtifacts, leaf: moduleArtifacts, shared: [] },
                graphManifestPath: `${graphPackageRoot}/graph-manifest.json`,
                graphManifestSha256,
                packagePath: graphPackageRoot,
              },
            ],
            sourcePackageRuntimeContentSha256,
          },
        ],
        path: registryRoot,
        sourceCatalog: {
          entries: [
            {
              deploymentSha256,
              generation: { sha256: generationManifestSha256, size: 123 },
              generationSha256,
              sourcePackageRuntimeContentSha256,
            },
          ],
        },
      },
    },
  };
}

test("selective transfer includes compatible AOT and excludes stale generations", () => {
  const fixture = transferClosureFixture();
  const stale = {
    deploymentSha256: "a".repeat(64),
    generation: { sha256: "b".repeat(64), size: 321 },
    generationSha256: "c".repeat(64),
    sourcePackageRuntimeContentSha256: "d".repeat(64),
  };
  fixture.preflight.runtimeRegistry.sourceCatalog.entries.push(stale);

  const plan = deriveRuntimeRegistryTransferPlan(fixture.preflight);
  assert.ok(plan.paths.includes(
    `module-graph-cache/immutable/v6/artifacts/${fixture.coreStage}/${fixture.coreCacheKey}/artifact.wasm`
  ));
  assert.ok(plan.paths.includes(
    `module-graph-cache/immutable/v6/artifacts/${fixture.aotStage}/${fixture.aotCacheKey}/artifact.cwasm`
  ));
  assert.ok(!plan.paths.includes(
    `generations/${stale.deploymentSha256}/${stale.generationSha256}/generation.json`
  ));
  assert.ok(!plan.paths.includes("current"));
  assert.deepEqual(
    JSON.parse(plan.sourceCatalogBytes.toString("utf8")).entries,
    fixture.preflight.runtimeRegistry.sourceCatalog.entries.slice(0, 1)
  );
});

test("transfer CLI matches the backend preflight projection to local registry controls", () => {
  const registryRoot = mkdtempSync(join(tmpdir(), "convex-wasm-registry-transfer-"));
  try {
    const fixture = transferClosureFixture(registryRoot);
    const generationBytes = Buffer.from(`${canonicalJson({ kind: "fixture-generation" })}\n`);
    const generationIdentity = {
      sha256: createHash("sha256").update(generationBytes).digest("hex"),
      size: generationBytes.length,
    };
    const reference = fixture.preflight.runtimeRegistry.generationReferences[0];
    reference.generation = generationIdentity;
    fixture.preflight.runtimeRegistry.sourceCatalog.entries[0].generation = generationIdentity;
    const catalog = createRuntimeRegistrySourceCatalog(
      fixture.preflight.runtimeRegistry.sourceCatalog.entries
    ).manifest;
    fixture.preflight.runtimeRegistry.sourceCatalog = {
      catalogSha256: catalog.catalogSha256,
      entries: catalog.entries,
    };
    const currentContent = {
      deploymentSha256: reference.deploymentSha256,
      generation: generationIdentity,
      generationSha256: reference.generationSha256,
      kind: "convex-wasm-runtime-registry-current-v1",
    };
    const current = {
      ...currentContent,
      currentSha256: fingerprintJson(currentContent),
    };
    fixture.preflight.runtimeRegistry.currentSha256 = current.currentSha256;
    const generationRoot = join(
      registryRoot,
      "generations",
      reference.deploymentSha256,
      reference.generationSha256
    );
    mkdirSync(generationRoot, { recursive: true });
    writeFileSync(join(generationRoot, "generation.json"), generationBytes);
    writeFileSync(join(registryRoot, "source-catalog.json"), `${canonicalJson(catalog)}\n`);
    writeFileSync(join(registryRoot, "current"), `${canonicalJson(current)}\n`);
    const preflightPath = join(registryRoot, "preflight.json");
    writeFileSync(preflightPath, `${canonicalJson(fixture.preflight)}\n`);
    const run = () =>
      spawnSync(
        process.execPath,
        [
          resolve("scripts/plan-registry-transfer.mjs"),
          "--registry-root", registryRoot,
          "--preflight", preflightPath,
          "--hardlinks-output", join(registryRoot, "hardlinks"),
          "--source-catalog-output", join(registryRoot, "merged-catalog"),
          "--selected-current-output", join(registryRoot, "selected-current"),
        ],
        { cwd: resolve("."), encoding: "utf8" }
      );
    const accepted = run();
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(accepted.stdout, /artifact\.cwasm/);
    fixture.preflight.runtimeRegistry.sourceCatalog.catalogSha256 = "a".repeat(64);
    writeFileSync(preflightPath, `${canonicalJson(fixture.preflight)}\n`);
    const rejected = run();
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /source catalog differs from the preflight/);
  } finally {
    rmSync(registryRoot, { recursive: true, force: true });
  }
});

test("retained destination catalog is additive without transferring its payloads", () => {
  const fixture = transferClosureFixture();
  const retained = {
    deploymentSha256: "a".repeat(64),
    generation: { sha256: "b".repeat(64), size: 321 },
    generationSha256: "c".repeat(64),
    sourcePackageRuntimeContentSha256: "d".repeat(64),
  };
  const retainedSourceCatalog = createRuntimeRegistrySourceCatalog([retained]).manifest;
  const plan = deriveRuntimeRegistryTransferPlan(fixture.preflight, { retainedSourceCatalog });
  assert.deepEqual(
    JSON.parse(plan.sourceCatalogBytes.toString("utf8")).entries,
    createRuntimeRegistrySourceCatalog([
      fixture.preflight.runtimeRegistry.sourceCatalog.entries[0],
      retained,
    ]).manifest.entries
  );
  assert.ok(!plan.paths.includes(
    `generations/${retained.deploymentSha256}/${retained.generationSha256}/generation.json`
  ));

  const conflicting = {
    ...fixture.preflight.runtimeRegistry.sourceCatalog.entries[0],
    sourcePackageRuntimeContentSha256: "e".repeat(64),
  };
  assert.throws(
    () => deriveRuntimeRegistryTransferPlan(fixture.preflight, {
      retainedSourceCatalog: createRuntimeRegistrySourceCatalog([conflicting]).manifest,
    }),
    /conflicts with the local catalog/
  );
});

test("transfer rejects a payload path outside the authenticated registry layout", () => {
  const fixture = transferClosureFixture();
  fixture.preflight.runtimeRegistry.generationReferences[0].moduleGraphs[0].artifacts.leaf.aot.path =
    "/other-registry/artifact.cwasm";
  assert.throws(
    () => deriveRuntimeRegistryTransferPlan(fixture.preflight),
    /outside its authenticated registry layout/
  );
});
