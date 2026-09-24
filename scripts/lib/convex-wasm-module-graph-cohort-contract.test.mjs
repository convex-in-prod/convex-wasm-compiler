import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  createConvexWasmModuleGraphCohortContract,
  validateConvexWasmModuleGraphCohortContract,
} from "./convex-wasm-module-graph-cohort-contract.mjs";
import { convexWasmTargetRuntimeSurfacePolicyIdentity } from "./convex-wasm-runtime-surface.mjs";
import { convexWasmCapabilityLegacyInvocationAbi } from "./convex-wasm-selector-source.mjs";

const digest = (character) => character.repeat(64);

test("creates the committed deployment-v8 cohort from its authenticated compiler contract", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("../test-fixtures/convex-wasm-module-graph-registry/fixture.json", import.meta.url)
    )
  );
  const deployment = JSON.parse(Buffer.from(fixture.material.deployment.base64, "base64"));
  const cohort = deployment.moduleGraphCohorts[0];
  const {
    cohortContractSha256: ignoredCohortContractSha256,
    cohortId,
    compilerSourceEnvelopeSha256,
    scheduleSha256,
    sourceEnvelopeSha256,
    ...compilerFields
  } = cohort;
  const compilerPayload = {
    ...compilerFields,
    kind: "convex-wasm-official-output-module-graph-cohort-contract-v2",
    sourceEnvelopeSha256: compilerSourceEnvelopeSha256,
  };
  const compilerContract = {
    ...compilerPayload,
    contractId: fingerprintJson(compilerPayload),
  };
  assert.deepEqual(
    createConvexWasmModuleGraphCohortContract({
      cohortId,
      compilerContract,
      scheduleSha256,
      sourceEnvelopeSha256,
    }),
    cohort
  );

  assert.throws(
    () =>
      createConvexWasmModuleGraphCohortContract({
        cohortId,
        compilerContract: { ...compilerContract, contractId: digest("0") },
        scheduleSha256,
        sourceEnvelopeSha256,
      }),
    /compiler cohort contract identity is invalid/u
  );
});

test("validates the committed deployment-v8 cohort and its nested value identities", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("../test-fixtures/convex-wasm-module-graph-registry/fixture.json", import.meta.url)
    )
  );
  const deployment = JSON.parse(Buffer.from(fixture.material.deployment.base64, "base64"));
  const cohort = deployment.moduleGraphCohorts[0];
  assert.equal(
    validateConvexWasmModuleGraphCohortContract(cohort).cohortContractSha256,
    cohort.cohortContractSha256
  );

  const invalidCodec = structuredClone(cohort);
  invalidCodec.execution.valueCodec.canonicalVectorCorpus.producer.kind = "unknown";
  assert.throws(
    () => validateConvexWasmModuleGraphCohortContract(invalidCodec),
    /canonical vector corpus\.producer\.kind is unsupported/u
  );

  const invalidEnvelope = structuredClone(cohort);
  invalidEnvelope.execution.requestEnvelope.canonicalVectorCorpus.producer.kind = "unknown";
  assert.throws(
    () => validateConvexWasmModuleGraphCohortContract(invalidEnvelope),
    /requestEnvelope\.canonicalVectorCorpus\.producer\.kind is unsupported/u
  );
});

function contextReuseCohortIdentity(entryPath, dependencyGraphSha256) {
  const payload = {
    entries: [entryPath],
    entryGraphSha256s: [dependencyGraphSha256],
    kind: "convex-context-reuse-cohort-analysis",
    policyFingerprint: digest("b"),
    sharedAnalysisSha256: digest("c"),
    thirdPartyMaterialFingerprints: {},
  };
  return { ...payload, resultSha256: fingerprintJson(payload) };
}

test("cohort validation rejects an entry outside its authenticated analysis", () => {
  const localProfile = {
    dependencyGraphSha256: digest("1"),
    javascript: { sha256: digest("2"), size: 1 },
    metafileSha256: digest("3"),
    sha256: digest("4"),
    sourceMap: { sha256: digest("5"), size: 1 },
  };
  const entryPath = "convex/substituted.ts";
  const modulePath = "substituted";
  const entryId = fingerprintJson({
    domain: "convex-wasm-capability-entry-v1",
    invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
    localProfileSha256: localProfile.sha256,
    selectedEntry: { entryPath, modulePath },
  });
  const entrySymbol = `sh_export_convex_wasm_entry_${entryId}`;
  const route = {
    entryId,
    entrySelectorId: "",
    entrySymbol,
    exportName: "read",
    routeId: "",
    udfKind: "query",
    visibility: "public",
  };
  route.routeId = fingerprintJson({
    domain: "convex-wasm-capability-route-v1",
    entryId,
    exportName: route.exportName,
    udfKind: route.udfKind,
    visibility: route.visibility,
  });
  route.entrySelectorId = route.routeId.slice(0, 16);

  assert.throws(
    () =>
      validateConvexWasmModuleGraphCohortContract({
        cohortContractSha256: digest("6"),
        cohortId: digest("7"),
        compiler: {
          artifactPipelineSha256: digest("8"),
          loweringPipelineSha256: digest("9"),
          staticHermesGlobalPolicy: convexWasmTargetRuntimeSurfacePolicyIdentity,
          staticHermesRevision: "fixture",
        },
        compilerSourceEnvelopeSha256: digest("a"),
        contextReuseAnalysis: contextReuseCohortIdentity("convex/alpha.ts", digest("1")),
        descriptorIdentitySha256: digest("d"),
        engine: {},
        entries: [
          {
            entryId,
            entryPath,
            entrySymbol,
            invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
            localProfile,
            modulePath,
            source: {
              exportName: "read",
              exportSha256: digest("2"),
              modulePath: entryPath,
              resolvedGraphSha256: digest("1"),
              runtimeModulePath: "substituted.js",
              udfKind: "query",
            },
          },
        ],
        execution: {},
        kind: "convex-wasm-module-graph-cohort-contract-v2",
        precompilerMaterialIdentity: {},
        producerImplementation: {},
        routes: [route],
        runtimeSurfacePolicySha256: digest("e"),
        scheduleSha256: digest("f"),
        schemaVersion: 2,
        sourceEnvelopeSha256: digest("0"),
        sourcePipelineSha256: digest("1"),
      }),
    /cohort analysis identity has the wrong entry graph/u
  );
});

test("cohort validation rejects an opaque entry source identity", () => {
  const localProfile = {
    dependencyGraphSha256: digest("1"),
    javascript: { sha256: digest("2"), size: 1 },
    metafileSha256: digest("3"),
    sha256: digest("4"),
    sourceMap: { sha256: digest("5"), size: 1 },
  };
  const entryPath = "convex/read.ts";
  const modulePath = "read";
  const entryId = fingerprintJson({
    domain: "convex-wasm-capability-entry-v1",
    invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
    localProfileSha256: localProfile.sha256,
    selectedEntry: { entryPath, modulePath },
  });
  const entrySymbol = `sh_export_convex_wasm_entry_${entryId}`;
  const route = {
    entryId,
    entrySelectorId: "",
    entrySymbol,
    exportName: "read",
    routeId: "",
    udfKind: "query",
    visibility: "public",
  };
  route.routeId = fingerprintJson({
    domain: "convex-wasm-capability-route-v1",
    entryId,
    exportName: route.exportName,
    udfKind: route.udfKind,
    visibility: route.visibility,
  });
  route.entrySelectorId = route.routeId.slice(0, 16);

  assert.throws(
    () =>
      validateConvexWasmModuleGraphCohortContract({
        cohortContractSha256: digest("6"),
        cohortId: digest("7"),
        compiler: {},
        compilerSourceEnvelopeSha256: digest("8"),
        contextReuseAnalysis: {},
        descriptorIdentitySha256: digest("9"),
        engine: {},
        entries: [
          {
            entryId,
            entryPath,
            entrySymbol,
            invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
            localProfile,
            modulePath,
            source: { opaque: true },
          },
        ],
        execution: {},
        kind: "convex-wasm-module-graph-cohort-contract-v2",
        precompilerMaterialIdentity: {},
        producerImplementation: {},
        routes: [route],
        runtimeSurfacePolicySha256: digest("a"),
        scheduleSha256: digest("b"),
        schemaVersion: 2,
        sourceEnvelopeSha256: digest("c"),
        sourcePipelineSha256: digest("d"),
      }),
    /source has unknown field\(s\): opaque/u
  );
});

test("cohort validation rejects a source identity from a different local profile", () => {
  const localProfile = {
    dependencyGraphSha256: digest("1"),
    javascript: { sha256: digest("2"), size: 1 },
    metafileSha256: digest("3"),
    sha256: digest("4"),
    sourceMap: { sha256: digest("5"), size: 1 },
  };
  const entryPath = "convex/read.ts";
  const modulePath = "read";
  const entryId = fingerprintJson({
    domain: "convex-wasm-capability-entry-v1",
    invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
    localProfileSha256: localProfile.sha256,
    selectedEntry: { entryPath, modulePath },
  });
  const entrySymbol = `sh_export_convex_wasm_entry_${entryId}`;
  const route = {
    entryId,
    entrySelectorId: "",
    entrySymbol,
    exportName: "read",
    routeId: "",
    udfKind: "query",
    visibility: "public",
  };
  route.routeId = fingerprintJson({
    domain: "convex-wasm-capability-route-v1",
    entryId,
    exportName: route.exportName,
    udfKind: route.udfKind,
    visibility: route.visibility,
  });
  route.entrySelectorId = route.routeId.slice(0, 16);

  assert.throws(
    () =>
      validateConvexWasmModuleGraphCohortContract({
        cohortContractSha256: digest("6"),
        cohortId: digest("7"),
        compiler: {},
        compilerSourceEnvelopeSha256: digest("8"),
        contextReuseAnalysis: {},
        descriptorIdentitySha256: digest("9"),
        engine: {},
        entries: [
          {
            entryId,
            entryPath,
            entrySymbol,
            invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
            localProfile,
            modulePath,
            source: {
              exportName: "read",
              exportSha256: digest("a"),
              modulePath: entryPath,
              resolvedGraphSha256: localProfile.dependencyGraphSha256,
              runtimeModulePath: `${modulePath}.js`,
              udfKind: "query",
            },
          },
        ],
        execution: {},
        kind: "convex-wasm-module-graph-cohort-contract-v2",
        precompilerMaterialIdentity: {},
        producerImplementation: {},
        routes: [route],
        runtimeSurfacePolicySha256: digest("b"),
        scheduleSha256: digest("c"),
        schemaVersion: 2,
        sourceEnvelopeSha256: digest("d"),
        sourcePipelineSha256: digest("e"),
      }),
    /source identity or route table is inconsistent/u
  );
});
