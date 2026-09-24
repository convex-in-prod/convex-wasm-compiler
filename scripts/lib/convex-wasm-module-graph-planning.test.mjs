import assert from "node:assert/strict";
import { promises as fs, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmModuleGraphCompilerDescriptorKind,
  convexWasmModuleGraphCompilerDescriptorSchemaVersion,
} from "./convex-wasm-official-output-chunk-contract.mjs";
import {
  authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs,
  createConvexWasmOfficialOutputModuleGraphPhysicalShardReport,
  publishConvexWasmOfficialOutputModuleGraphPhysicalShardReport,
} from "./convex-wasm-module-graph-planning.mjs";
import {
  authenticateConvexWasmOfficialOutputCohortSchedule,
  createConvexWasmOfficialOutputCohortSchedule,
} from "./convex-wasm-official-output-cohort-schedule.mjs";
import { convexWasmSourceEnvelopeKind } from "./convex-wasm-source-envelope.mjs";
import {
  convexWasmTargetRuntimeSurfacePolicyIdentity,
  convexWasmTargetRuntimeSurfacePolicySha256,
} from "./convex-wasm-runtime-surface.mjs";

function digest(character) {
  return character.repeat(64);
}

function reportFixture() {
  const sharedComponent = digest("a");
  const residualComponent = digest("b");
  return {
    cohortContracts: [
      {
        cohortContractSha256: digest("c"),
        cohortId: digest("d"),
        compilerSourceEnvelopeSha256: digest("e"),
        descriptorIdentitySha256: digest("f"),
        sourceEnvelopeSha256: digest("e"),
      },
    ],
    physicalShardPlanning: {
      componentOccurrences: [
        {
          componentSha256: sharedComponent,
          occurrences: [
            {
              cohortId: digest("d"),
              picObject: { byteWeight: 11, sha256: digest("1") },
            },
          ],
        },
        {
          componentSha256: residualComponent,
          occurrences: [
            {
              cohortId: digest("d"),
              picObject: { byteWeight: 7, sha256: digest("2") },
            },
            {
              cohortId: digest("3"),
              picObject: { byteWeight: 7, sha256: digest("2") },
            },
          ],
        },
      ],
      plan: {
        components: [
          {
            codeIdentitySha256s: [digest("4")],
            componentSha256: sharedComponent,
            dependencies: [],
            logicalUnitSha256s: [digest("5")],
            occurrenceCohortSha256s: [digest("d")],
            picObjectByteWeight: 11,
            shareable: true,
            sharedEligible: true,
          },
          {
            codeIdentitySha256s: [digest("6"), digest("7")],
            componentSha256: residualComponent,
            dependencies: [],
            logicalUnitSha256s: [digest("8"), digest("9")],
            occurrenceCohortSha256s: [digest("d"), digest("3")],
            picObjectByteWeight: 14,
            shareable: false,
            sharedEligible: false,
          },
        ],
        planSha256: digest("a"),
        policy: { kind: "convex-wasm-physical-shard-policy-v1", targetShardWeight: 12 },
        residualComponents: [
          { componentSha256: residualComponent, reason: "contains-non-shareable-logical-unit" },
        ],
        shardOrder: [digest("b")],
        sharedShards: [
          {
            componentSha256s: [sharedComponent],
            dependencies: [],
            kind: "convex-wasm-physical-shard-v1",
            oversize: false,
            picObjectByteWeight: 11,
            shardSha256: digest("b"),
          },
        ],
      },
    },
    producerIdentity: { kind: "fixture-producer-v1", sha256: digest("c") },
    schedule: { identity: { sha256: digest("d") }, kind: "fixture-schedule-v1" },
    sourceEnvelope: { kind: "fixture-source-envelope-v1", sourceEnvelopeSha256: digest("e") },
  };
}

function planningInputFixture() {
  const fixturePath = new URL(
    "../test-fixtures/convex-wasm-module-graph-registry/fixture.json",
    import.meta.url
  );
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const deployment = JSON.parse(
    Buffer.from(fixture.material.deployment.base64, "base64").toString("utf8")
  );
  const promoted = deployment.moduleGraphCohorts[0];
  const entry = promoted.entries[0];
  const route = promoted.routes[0];
  const routeAuthority = {
    entryPath: entry.entryPath,
    exportName: route.exportName,
    modulePath: entry.modulePath,
    runtimeModulePath: entry.source.runtimeModulePath,
    udfKind: route.udfKind,
    visibility: route.visibility,
  };
  const sourceEnvelopePayload = {
    actions: [],
    contextReuseAnalysis: deployment.contextReuseAnalysis,
    entryPaths: [entry.entryPath],
    graph: {
      effectExecutionMode: "guest-promise-event-loop",
      inputCount: 1,
      sha256: digest("a"),
      toolchain: { convex: "fixture-convex", esbuild: "fixture-esbuild" },
    },
    inventoryAuthority: { kind: "fixture-inventory-v1", snapshot: { revision: 1 } },
    kind: convexWasmSourceEnvelopeKind,
    routes: [routeAuthority],
    schemaVersion: 2,
    selectedRoutes: [
      {
        ...routeAuthority,
        dependencyGraphSha256: entry.localProfile.dependencyGraphSha256,
      },
    ],
  };
  const sourceEnvelope = {
    ...sourceEnvelopePayload,
    sourceEnvelopeSha256: fingerprintJson(sourceEnvelopePayload),
  };
  const sourceEnvelopeFileSha256 = digest("b");
  const sourceEnvelopeFileSize = 123;
  const schedule = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope,
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize,
  });
  const physicalProjectionSha256 = digest("f");
  const compilerContractPayload = {
    compiler: {
      ...promoted.compiler,
      staticHermesGlobalPolicy: convexWasmTargetRuntimeSurfacePolicyIdentity,
    },
    contextReuseAnalysis: promoted.contextReuseAnalysis,
    descriptorIdentitySha256: promoted.descriptorIdentitySha256,
    engine: promoted.engine,
    entries: promoted.entries,
    execution: promoted.execution,
    kind: "convex-wasm-official-output-module-graph-cohort-contract-v2",
    precompilerMaterialIdentity: promoted.precompilerMaterialIdentity,
    producerImplementation: promoted.producerImplementation,
    routes: promoted.routes,
    runtimeSurfacePolicySha256: convexWasmTargetRuntimeSurfacePolicySha256,
    schemaVersion: 2,
    sourceEnvelopeSha256: physicalProjectionSha256,
    sourcePipelineSha256: promoted.sourcePipelineSha256,
  };
  const producerIdentity = {
    kind: "convex-wasm-artifact-producer-identity-v1",
    manifest: {
      path: "fixture/producer-source-manifest.json",
      sha256: digest("1"),
      size: 1,
    },
    nodeVersion: "fixture-node-v1",
    sha256: digest("2"),
    sources: [{ path: "fixture/producer.mjs", sha256: digest("3"), size: 1 }],
  };
  assert.deepEqual(promoted.producerImplementation, {
    kind: producerIdentity.kind,
    sha256: producerIdentity.sha256,
  });
  return {
    artifactConfig: { producerIdentity },
    cohortSchedule: schedule,
    compilerOutputs: [
      {
        cohortContract: {
          ...compilerContractPayload,
          contractId: fingerprintJson(compilerContractPayload),
        },
        descriptor: {
          applicationIdentity: { sourceEnvelopeSha256: physicalProjectionSha256 },
          identitySha256: promoted.descriptorIdentitySha256,
          kind: convexWasmModuleGraphCompilerDescriptorKind,
          schemaVersion: convexWasmModuleGraphCompilerDescriptorSchemaVersion,
          units: [],
        },
        options: { producerIdentity },
      },
    ],
    sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize,
    sourceEnvelope,
  };
}

test("physical-shard report keeps shared and residual logical-unit PIC evidence separate", () => {
  const report = createConvexWasmOfficialOutputModuleGraphPhysicalShardReport(reportFixture());

  assert.equal(report.shared.componentCount, 1);
  assert.equal(report.shared.logicalUnitCount, 1);
  assert.deepEqual(report.shared.logicalUnits, [
    {
      codeIdentitySha256: digest("4"),
      componentSha256: digest("a"),
      logicalUnitSha256: digest("5"),
    },
  ]);
  assert.equal(report.shared.picObjectBytes, 11);
  assert.equal(report.shared.occurrencePicObjectBytes, 11);
  assert.equal(report.residual.componentCount, 1);
  assert.equal(report.residual.logicalUnitCount, 2);
  assert.equal(report.residual.logicalUnits.length, 2);
  assert.equal(report.residual.picObjectBytes, 14);
  assert.equal(report.residual.occurrenceCount, 2);
  assert.equal(report.residual.occurrencePicObjectBytes, 14);
  assert.equal(report.residual.components[0].reason, "contains-non-shareable-logical-unit");
  assert.equal(report.reportSha256.length, 64);
});

test("planning keeps physical-cohort and global source-envelope provenance separate", () => {
  const inputs = planningInputFixture();
  const authenticated = authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(inputs);
  const [contract] = authenticated.cohortContracts;

  assert.equal(contract.sourceEnvelopeSha256, inputs.sourceEnvelope.sourceEnvelopeSha256);
  assert.equal(
    contract.compilerSourceEnvelopeSha256,
    inputs.compilerOutputs[0].descriptor.applicationIdentity.sourceEnvelopeSha256
  );
  assert.notEqual(contract.compilerSourceEnvelopeSha256, contract.sourceEnvelopeSha256);

  const mismatchedCompilerContract = structuredClone(inputs);
  mismatchedCompilerContract.compilerOutputs[0].cohortContract.sourceEnvelopeSha256 = digest("d");
  const { contractId: ignoredContractId, ...mismatchedCompilerContractPayload } =
    mismatchedCompilerContract.compilerOutputs[0].cohortContract;
  mismatchedCompilerContract.compilerOutputs[0].cohortContract.contractId = fingerprintJson(
    mismatchedCompilerContractPayload
  );
  assert.throws(
    () => authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(mismatchedCompilerContract),
    /physical cohort projection/u
  );

  const mismatchedProjection = structuredClone(inputs);
  mismatchedProjection.compilerOutputs[0].descriptor.applicationIdentity.sourceEnvelopeSha256 =
    digest("e");
  assert.throws(
    () => authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(mismatchedProjection),
    /physical cohort projection/u
  );

  const nonCompactDescriptor = structuredClone(inputs);
  nonCompactDescriptor.compilerOutputs[0].descriptor.kind =
    "convex-wasm-official-output-chunk-native-application-descriptor-v2";
  assert.throws(
    () => authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(nonCompactDescriptor),
    /compact authenticated descriptor/u
  );

  const forgedFileIdentity = structuredClone(inputs);
  forgedFileIdentity.cohortSchedule.identity.provenance.sourceEnvelope.file = {
    sha256: digest("c"),
    size: inputs.sourceEnvelopeFileSize + 1,
  };
  const { sha256: ignoredScheduleSha256, ...forgedIdentityPayload } =
    forgedFileIdentity.cohortSchedule.identity;
  forgedFileIdentity.cohortSchedule.identity.sha256 = fingerprintJson(forgedIdentityPayload);
  assert.throws(
    () => authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(forgedFileIdentity),
    /does not match the authenticated source envelope/u
  );

  const inheritedFileIdentity = structuredClone(inputs);
  delete inheritedFileIdentity.sourceEnvelopeFileSha256;
  delete inheritedFileIdentity.sourceEnvelopeFileSize;
  Object.setPrototypeOf(inheritedFileIdentity, {
    sourceEnvelopeFileSha256: inputs.sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize: inputs.sourceEnvelopeFileSize,
  });
  inheritedFileIdentity.cohortSchedule = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: inheritedFileIdentity.cohortSchedule,
    sourceEnvelope: inheritedFileIdentity.sourceEnvelope,
    sourceEnvelopeFileSha256: inputs.sourceEnvelopeFileSha256,
    sourceEnvelopeFileSize: inputs.sourceEnvelopeFileSize,
  });
  assert.throws(
    () => authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(inheritedFileIdentity),
    /source-envelope file identity/u
  );
});

test("physical-shard report publication is canonical, private, and non-overwriting", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-physical-shard-plan-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const outputPath = join(directory, "report.json");
  const report = createConvexWasmOfficialOutputModuleGraphPhysicalShardReport(reportFixture());

  assert.equal(
    await publishConvexWasmOfficialOutputModuleGraphPhysicalShardReport({ outputPath, report }),
    outputPath
  );
  assert.equal((await fs.lstat(outputPath)).mode & 0o777, 0o600);
  await assert.rejects(
    publishConvexWasmOfficialOutputModuleGraphPhysicalShardReport({ outputPath, report }),
    /already exists/u
  );
});
