import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "./convex-wasm-compiler-contract.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";
import {
  convexWasmSourceEnvelopeKind,
  publishConvexWasmSourceEnvelopePublication,
  validateConvexWasmSourceEnvelope,
} from "./convex-wasm-source-envelope.mjs";

function syntheticEnvelope() {
  const route = {
    entryPath: "functions/example.ts",
    exportName: "read",
    modulePath: "functions/example",
    runtimeModulePath: "functions/example.js",
    udfKind: "query",
    visibility: "public",
  };
  const payload = {
    actions: [],
    contextReuseAnalysis: {
      entries: [route.entryPath],
      kind: "convex-context-reuse-analysis",
      policyFingerprint: "a".repeat(64),
      resultSha256: "b".repeat(64),
    },
    entryPaths: [route.entryPath],
    graph: {
      effectExecutionMode: convexWasmGuestPromiseEffectExecutionMode,
      inputCount: 1,
      sha256: "c".repeat(64),
      toolchain: { convex: "fixture-sdk", esbuild: "fixture-bundler" },
    },
    inventoryAuthority: { kind: "synthetic-inventory", snapshot: { sha256: "d".repeat(64) } },
    kind: convexWasmSourceEnvelopeKind,
    routes: [route],
    schemaVersion: 2,
    selectedRoutes: [{ dependencyGraphSha256: "e".repeat(64), ...route }],
  };
  return { ...payload, sourceEnvelopeSha256: fingerprintJson(payload) };
}

test("authenticates and publishes a synthetic source envelope", async (context) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-envelope-"));
  context.after(() => fs.rm(root, { force: true, recursive: true }));
  const envelope = validateConvexWasmSourceEnvelope(syntheticEnvelope());
  assert.ok(Object.isFrozen(envelope));
  assert.ok(Object.isFrozen(envelope.selectedRoutes[0]));

  const outputPath = join(root, "nested", "source-envelope.json");
  const publication = await publishConvexWasmSourceEnvelopePublication({ envelope, outputPath });
  assert.equal(publication.file.path, outputPath);
  assert.equal((await fs.stat(outputPath)).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(await fs.readFile(outputPath, "utf8")), envelope);

  const changed = syntheticEnvelope();
  changed.selectedRoutes[0].dependencyGraphSha256 = "f".repeat(64);
  assert.throws(() => validateConvexWasmSourceEnvelope(changed), /digest is invalid/u);
});

test("result identity binds sorted analyzed entries to the selected graph", () => {
  const identity = {
    entries: ["functions/a.ts", "functions/b.ts"],
    kind: "convex-context-reuse-analysis",
    policyFingerprint: "a".repeat(64),
    resultSha256: "b".repeat(64),
  };
  const authenticated = authenticateConvexContextReuseResultIdentity(identity, {
    expectedEntries: [...identity.entries],
  });
  assert.ok(Object.isFrozen(authenticated.entries));
  assert.throws(
    () => authenticateConvexContextReuseResultIdentity(identity, { expectedEntries: ["functions/a.ts"] }),
    /do not match the selected graph/u
  );
  assert.throws(
    () => authenticateConvexContextReuseResultIdentity({ ...identity, entries: [...identity.entries].reverse() }),
    /sorted and unique/u
  );
});
