import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { acquireConvexWasmCacheLock } from "./convex-wasm-cache-lock.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { clearConvexWasmDeploymentSnapshot, recordConvexWasmSuccessfulDeployment } from "./convex-wasm-cache-retention.mjs";
import { maintainConvexWasmImmutableGc } from "./convex-wasm-cache-retention-immutable.mjs";
import { materializeModuleGraphPackageFixture, writeCompilerOutputFixture, writeGenericArtifact, writeLegacyDeploymentResultCertificate, writeLegacyV2ModuleGraphPackage } from "../test-fixtures/cache-retention.mjs";

test("only the last deployed snapshot retains artifacts, including immediately after publication", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "latest-deployment-retention-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheRoot = join(root, "cache");
  const environment = { CONVEX_WASM_CACHE_LOCK_DB: join(root, "cache-lock.sqlite") };
  const value = { root, cacheRoot, environment,
    layout: (buildId) => deriveConvexWasmCacheLayout({ buildId, cacheRoot, scope: "isolated-test", repositoryRoot: root }) };
  const { cacheLayout, manifest, graphManifestSha256 } = await materializeModuleGraphPackageFixture(value);
  const { compilerOutput, dependencies } = await writeCompilerOutputFixture(cacheLayout);
  const release = await acquireConvexWasmCacheLock({ environment });
  try {
    await recordConvexWasmSuccessfulDeployment({ buildId: "first-deploy", cacheLayout, environment,
      deployment: { manifest, buildReport: { artifacts: [{ buildReport: { compilerOutputCache: { cacheKey: compilerOutput.key } } }] } } });
    const first = await maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 });
    assert.ok(first.plan.retained.artifacts.includes(`${compilerOutput.stage}\0${compilerOutput.key}`));
    await recordConvexWasmSuccessfulDeployment({ buildId: "same-deploy-cache-hit", cacheLayout, environment,
      deployment: { manifest, buildReport: { cache: { deploymentResult: "hit" } } } });
    const sameDeployment = await maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 });
    assert.ok(sameDeployment.plan.retained.artifacts.includes(`${compilerOutput.stage}\0${compilerOutput.key}`));
    const { deploymentSha256: ignored, ...payload } = manifest;
    const next = { ...payload, fixtureRevision: 2 };
    next.deploymentSha256 = fingerprintJson(next);
    await recordConvexWasmSuccessfulDeployment({ buildId: "second-deploy", cacheLayout, environment,
      deployment: { manifest: next } });
    const preparedOnly = await writeGenericArtifact({ cacheLayout, extension: "wasm", metadata: {}, payload: "unpublished candidate", stage: "unpublished" });
    const swept = await maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 });
    assert.deepEqual(swept.plan.retained.packages, [graphManifestSha256]);
    assert.deepEqual(swept.plan.retained.snapshots, ["current.json"]);
    assert.ok(swept.removed.some((entry) => entry.key === compilerOutput.key));
    assert.ok(swept.removed.some((entry) => entry.key === preparedOnly.key));
    for (const dependency of dependencies) assert.ok(swept.removed.some((entry) => entry.key === dependency.key));
    assert.deepEqual(await fs.readdir(join(cacheRoot, "state/v1/cache-retention/v1/deployed-success")), ["current.json"]);
    const current = JSON.parse(await fs.readFile(join(cacheRoot, "state/v1/cache-retention/v1/deployed-success/current.json"), "utf8"));
    assert.equal(current.deploymentSha256, next.deploymentSha256);
    await assert.rejects(recordConvexWasmSuccessfulDeployment({ buildId: "failed-deploy", cacheLayout, environment,
      deployment: { manifest: { ...next, deploymentSha256: "f".repeat(64) } } }), /does not authenticate/u);
    assert.equal(JSON.parse(await fs.readFile(join(cacheRoot, "state/v1/cache-retention/v1/deployed-success/current.json"), "utf8")).deploymentSha256, next.deploymentSha256);
    await clearConvexWasmDeploymentSnapshot({ cacheRoot, environment });
    const withoutLocalDeployment = await maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 });
    assert.deepEqual(withoutLocalDeployment.plan.retained.snapshots, []);
    assert.ok(withoutLocalDeployment.removed.some(({ type, key }) => type === "package" && key === graphManifestSha256));
  } finally { release(); }
});

test("failed and abandoned work is immediately removable under the cache lock", async (t) => {
  const { createConvexWasmBuildWorkLease, maintainConvexWasmCache } = await import("./convex-wasm-cache-retention.mjs");
  const root = await fs.mkdtemp(join(tmpdir(), "latest-deployment-work-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheRoot = join(root, "cache");
  const environment = { CONVEX_WASM_CACHE_LOCK_DB: join(root, "cache-lock.sqlite") };
  const layout = (buildId) => deriveConvexWasmCacheLayout({ buildId, cacheRoot, scope: "isolated-test", repositoryRoot: root });
  const release = await acquireConvexWasmCacheLock({ environment });
  try {
    const failed = await createConvexWasmBuildWorkLease({ cacheLayout: layout("failed"), environment });
    await failed.fail();
    await assert.rejects(fs.lstat(failed.buildRoot), { code: "ENOENT" });
    const interrupted = await createConvexWasmBuildWorkLease({ cacheLayout: layout("interrupted"), environment });
    await fs.writeFile(join(interrupted.buildRoot, "scratch"), "interrupted build", { mode: 0o600 });
    const oldRoot = layout("old-diagnostic").work.buildRoot;
    await fs.mkdir(oldRoot, { mode: 0o700 });
    await fs.writeFile(join(oldRoot, "build-work.json"), JSON.stringify({ status: "abandoned", recoverableUntilMs: Date.now() + 7 * 86400000 }), { mode: 0o600 });
    await assert.rejects(maintainConvexWasmCache({ cacheRoot, environment, apply: true }), /must acquire the top-level cache lock/u);
    await fs.lstat(interrupted.buildRoot);
  } finally { release(); }
  const report = await maintainConvexWasmCache({ cacheRoot, environment, apply: true, includeImmutableOccupancy: false });
  assert.deepEqual(report.work.roots.map(({ action, buildId }) => ({ action, buildId })), [
    { action: "remove", buildId: "interrupted" }, { action: "remove", buildId: "old-diagnostic" },
  ]);
  assert.deepEqual(await fs.readdir(join(cacheRoot, "work/v1")), []);
});


test("superseded certificates beside the deployed certificate release their package closures", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "latest-deployment-certificates-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheRoot = join(root, "cache");
  const environment = { CONVEX_WASM_CACHE_LOCK_DB: join(root, "cache-lock.sqlite") };
  const value = { root, cacheRoot, environment,
    layout: (buildId) => deriveConvexWasmCacheLayout({ buildId, cacheRoot, scope: "isolated-test", repositoryRoot: root }) };
  const fixture = await materializeModuleGraphPackageFixture(value);
  const { cacheLayout, manifest } = fixture;
  const deployed = await writeLegacyDeploymentResultCertificate(fixture);
  const legacy = await writeLegacyV2ModuleGraphPackage(cacheLayout);
  const superseded = await writeLegacyDeploymentResultCertificate({ cacheLayout,
    graphManifest: legacy.manifest, graphManifestSha256: legacy.key,
    manifest: { moduleGraphBinding: { cohorts: [{ graphManifestSha256: legacy.key }] } }, schemaVersion: 1 });
  const lookupRoot = join(cacheLayout.immutable.packages, "deployment-results/v1", fingerprintJson(deployed.lookupIdentity));
  await fs.writeFile(join(lookupRoot, "PREFERRED"), `${superseded.certificateSha256}\n`, { mode: 0o600 });
  const release = await acquireConvexWasmCacheLock({ environment });
  try {
    await recordConvexWasmSuccessfulDeployment({ buildId: "deployed", cacheLayout, environment,
      deployment: { manifest, buildReport: { cache: { certificateSha256: deployed.certificateSha256 } } } });
    const rename = fs.rename;
    fs.rename = async (source, destination) => {
      await rename(source, destination);
      if (source === join(lookupRoot, superseded.certificateSha256)) throw new Error("interrupted certificate entry retirement");
    };
    try {
      await assert.rejects(maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 }), /interrupted certificate entry retirement/u);
    } finally { fs.rename = rename; }
    const result = await maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 });
    assert.deepEqual(result.plan.retained.certificates, [deployed.certificateSha256]);
    assert.equal(result.recovered.length, 1);
    assert.ok(result.removed.some(({ type, key }) => type === "package" && key === legacy.key));
    assert.deepEqual(await fs.readdir(lookupRoot), [deployed.certificateSha256]);
    // Losing a required active root must stop cleanup, never silently discard the deployment.
    await fs.rm(join(cacheLayout.immutable.packages, fixture.graphManifestSha256), { recursive: true });
    await assert.rejects(maintainConvexWasmImmutableGc({ cacheLayout, environment, highWatermarkAllocatedBytes: 1 }), /deployed snapshot references an unavailable package/u);
  } finally { release(); }
});
