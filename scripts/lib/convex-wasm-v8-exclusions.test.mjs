import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  applyConvexWasmV8ExclusionsToDeploymentManifest,
  createConvexWasmV8ExclusionManifestFileIdentity,
  parseConvexWasmV8ExclusionManifestBytes,
  renderConvexWasmV8ExclusionManifest,
  resolveConvexWasmV8Exclusions,
  validateConvexWasmV8ExclusionManifest,
} from "./convex-wasm-v8-exclusions.mjs";

const digest = (character) => character.repeat(64);

const functions = [
  {
    entryPath: "convex/orders.ts",
    exportName: "list",
    modulePath: "orders",
    udfKind: "query",
    visibility: "public",
  },
  {
    entryPath: "convex/orders.ts",
    exportName: "place",
    modulePath: "orders",
    udfKind: "mutation",
    visibility: "public",
  },
  {
    entryPath: "convex/profile.ts",
    exportName: "read",
    modulePath: "profile",
    udfKind: "query",
    visibility: "internal",
  },
];

function parsedManifest(entries) {
  const manifest = renderConvexWasmV8ExclusionManifest({ entries });
  const bytes = Buffer.from(canonicalJson(manifest));
  return {
    fileIdentity: createConvexWasmV8ExclusionManifestFileIdentity(bytes),
    manifest: parseConvexWasmV8ExclusionManifestBytes(bytes),
  };
}

test("module and export selectors resolve only their exact inventory routes", () => {
  const { fileIdentity, manifest } = parsedManifest([
    {
      operatorReference: "OPS-42",
      reason: "Uses an unsupported host API",
      selector: { modulePath: "orders" },
    },
    {
      operatorReference: "OPS-43",
      reason: "Awaiting an ABI update",
      selector: { exportName: "read", modulePath: "profile" },
    },
  ]);
  const resolution = resolveConvexWasmV8Exclusions({
    functions,
    manifest,
    manifestFileIdentity: fileIdentity,
  });

  assert.deepEqual(
    resolution.routes.map(({ modulePath, exportName, selector }) => ({
      exportName,
      modulePath,
      selector,
    })),
    [
      { exportName: "list", modulePath: "orders", selector: { modulePath: "orders" } },
      { exportName: "place", modulePath: "orders", selector: { modulePath: "orders" } },
      {
        exportName: "read",
        modulePath: "profile",
        selector: { exportName: "read", modulePath: "profile" },
      },
    ]
  );
  assert.equal(resolution.binding.file.sha256, fileIdentity.sha256);
  assert.equal(resolution.binding.appliedSelectors.length, 2);
  assert.deepEqual(
    resolution.binding.appliedRoutes.map(({ modulePath, exportName }) => ({
      modulePath,
      exportName,
    })),
    [
      { exportName: "list", modulePath: "orders" },
      { exportName: "place", modulePath: "orders" },
      { exportName: "read", modulePath: "profile" },
    ]
  );
  assert.equal(resolution.excludedTargetKeys.has("convex/orders.ts\0place"), true);
});

test("missing, malformed, duplicate, and overlapping selectors fail closed", () => {
  const duplicate = renderConvexWasmV8ExclusionManifest({
    entries: [
      {
        operatorReference: "OPS-1",
        reason: "First",
        selector: { exportName: "list", modulePath: "orders" },
      },
    ],
  });
  duplicate.entries.push(structuredClone(duplicate.entries[0]));
  const { manifestSha256: ignoredManifestSha256, ...duplicatePayload } = duplicate;
  duplicate.manifestSha256 = fingerprintJson(duplicatePayload);
  assert.throws(() => validateConvexWasmV8ExclusionManifest(duplicate), /duplicate selector/u);

  const malformedPayload = {
    entries: [
      {
        operatorReference: "OPS-2",
        reason: "  ",
        selector: { modulePath: "orders" },
      },
    ],
    kind: "convex-wasm-v8-exclusion-manifest-v1",
    schemaVersion: 1,
  };
  const malformed = {
    ...malformedPayload,
    manifestSha256: fingerprintJson(malformedPayload),
  };
  assert.throws(() => validateConvexWasmV8ExclusionManifest(malformed), /non-whitespace/u);

  const { fileIdentity, manifest } = parsedManifest([
    {
      operatorReference: "OPS-3",
      reason: "No longer exported",
      selector: { exportName: "missing", modulePath: "orders" },
    },
  ]);
  assert.throws(
    () =>
      resolveConvexWasmV8Exclusions({
        functions,
        manifest,
        manifestFileIdentity: fileIdentity,
      }),
    /does not match a query or mutation route/u
  );

  const overlapping = parsedManifest([
    {
      operatorReference: "OPS-4",
      reason: "Module exclusion",
      selector: { modulePath: "orders" },
    },
    {
      operatorReference: "OPS-5",
      reason: "Function exclusion",
      selector: { exportName: "list", modulePath: "orders" },
    },
  ]);
  assert.throws(
    () =>
      resolveConvexWasmV8Exclusions({
        functions,
        manifest: overlapping.manifest,
        manifestFileIdentity: overlapping.fileIdentity,
      }),
    /selectors overlap/u
  );
});

test("an exclusion removes a Wasm receipt and binds bytes plus selectors into deployment identity", () => {
  const { fileIdentity, manifest } = parsedManifest([
    {
      operatorReference: "OPS-9",
      reason: "Requires the V8 runtime",
      selector: { exportName: "place", modulePath: "orders" },
    },
  ]);
  const resolution = resolveConvexWasmV8Exclusions({
    functions,
    manifest,
    manifestFileIdentity: fileIdentity,
  });
  const basePayload = {
    counts: {
      actionsOnExistingRuntime: 0,
      artifactFallback: 0,
      eligible: 2,
      ineligible: 1,
      mutations: 1,
      queries: 2,
      selectedWasm: 2,
      total: 3,
      unselectedEligible: 0,
    },
    exports: functions.map((func, index) => ({
      artifact: index < 2 ? { executionManifest: { receipt: "wasm" } } : null,
      ...(index < 2 ? { compilerLimits: { maxMemory: 1 } } : {}),
      entryPath: func.entryPath,
      exportName: func.exportName,
      packageReference: index < 2 ? { package: "receipt" } : null,
      routing:
        index < 2
          ? { decision: "wasm", reason: "runtimeCapability" }
          : { decision: "existingRuntime", reason: "not-analyzed" },
      udfKind: func.udfKind,
      visibility: func.visibility,
    })),
    kind: "convex-wasm-deployment-v5",
    mode: "compile",
  };
  const base = { ...basePayload, deploymentSha256: fingerprintJson(basePayload) };
  const applied = applyConvexWasmV8ExclusionsToDeploymentManifest({ manifest: base, resolution });
  const excluded = applied.exports[1];

  assert.equal(excluded.artifact, null);
  assert.equal(excluded.packageReference, null);
  assert.equal(Object.hasOwn(excluded, "compilerLimits"), false);
  assert.deepEqual(excluded.routing, {
    decision: "v8Fallback",
    reason: "operator-v8-exclusion-v1",
  });
  assert.deepEqual(excluded.v8Fallback.selector, { exportName: "place", modulePath: "orders" });
  assert.equal(excluded.v8Fallback.operatorReference, "OPS-9");
  assert.equal(applied.counts.operatorV8Fallback, 1);
  assert.equal(applied.counts.operatorV8FallbackEligible, 1);
  assert.equal(applied.counts.eligible, 2);
  assert.notEqual(applied.deploymentSha256, base.deploymentSha256);
  assert.equal(applied.v8Exclusions.file.size, fileIdentity.size);
  assert.equal(
    applied.deploymentSha256,
    fingerprintJson(
      Object.fromEntries(Object.entries(applied).filter(([key]) => key !== "deploymentSha256"))
    )
  );
  assert.notEqual(fileIdentity.sha256, digest("f"));
});

test("no manifest retains the existing deployment object", () => {
  const manifest = { deploymentSha256: digest("a"), exports: [], counts: {} };
  assert.equal(
    applyConvexWasmV8ExclusionsToDeploymentManifest({ manifest, resolution: undefined }),
    manifest
  );
  assert.equal(
    resolveConvexWasmV8Exclusions({
      functions,
      manifest: undefined,
      manifestFileIdentity: undefined,
    }),
    undefined
  );
});
