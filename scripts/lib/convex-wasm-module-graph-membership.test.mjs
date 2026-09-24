import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmOfficialOutputModuleGraphMembership } from "./convex-wasm-module-graph-membership.mjs";

const digest = (character) => character.repeat(64);
const emptyCommonAuthority = {
  content: { units: [] },
  kind: "convex-wasm-static-hermes-common-partition-authority-v1",
  layout: {
    kind: "convex-wasm-static-hermes-common-partition-layout-v1",
    layoutEpoch: 1,
    maximumSlots: 1_024,
    slots: [],
  },
};

function officialModuleGraphMembershipFixture(commonJavaScriptSha256 = "a".repeat(64)) {
  const logicalUnit = (slot, path, dependencies = []) => ({
    applicationUnitSlot: slot,
    chunkSlot: slot,
    dependencies,
    entryPublication: false,
    entrySymbol: `sh_export_chunk_${String(slot)}`,
    identitySha256: fingerprintJson({ commonJavaScriptSha256, path, slot }),
    javascript: {
      sha256: path === "shared.js" ? commonJavaScriptSha256 : fingerprintJson({ path }),
      size: 1,
    },
    module: {
      environment: "isolate",
      moduleSha256: fingerprintJson({ module: path }),
      path,
      sourceMap: null,
      sourceMembershipSha256: fingerprintJson({ membership: path }),
      sourceSha256: fingerprintJson({ source: path }),
      sourceSize: 1,
    },
  });
  const dependency = {
    kind: "import-statement",
    path: "shared.js",
    slot: 0,
    specifier: "./shared.js",
  };
  const entries = [
    { entryPath: "convex/a.ts", entrySlot: 1, handoffSlot: 0, entryPublicationUnitSlot: 3 },
    { entryPath: "convex/b.ts", entrySlot: 2, handoffSlot: 1, entryPublicationUnitSlot: 4 },
  ];
  const units = [
    logicalUnit(0, "shared.js"),
    logicalUnit(1, "a.js", [dependency]),
    logicalUnit(2, "b.js", [dependency]),
    {
      applicationUnitSlot: 3,
      chunkSlot: -1,
      dependencies: [],
      entryPublication: true,
      entrySymbol: "sh_export_publication",
      identitySha256: "f".repeat(64),
      javascript: { sha256: "e".repeat(64), size: 1 },
      module: null,
    },
    {
      applicationUnitSlot: 4,
      chunkSlot: -1,
      dependencies: [],
      entryPublication: true,
      entrySymbol: "sh_export_publication_b",
      identitySha256: "c".repeat(64),
      javascript: { sha256: "d".repeat(64), size: 1 },
      module: null,
    },
  ];
  const cohortId = "c".repeat(64);
  const scheduleSha256 = "d".repeat(64);
  return {
    commonPartitionAuthority: emptyCommonAuthority,
    cohortSchedule: {
      cohorts: [
        {
          cohortId,
          entries: entries.map(({ entryPath }, index) => ({
            entryId: fingerprintJson({ entryPath, index }),
            entryPath,
          })),
        },
      ],
      identity: { sha256: scheduleSha256 },
    },
    compilerOutputs: [
      {
        nativeApplication: {
          entries,
          initialization: {
            chunkSlotCount: 3,
            entryPublicationUnitSlots: [3, 4],
            namespaceSlotCount: 3,
          },
          routeLocalReachability: { ignored: ["shared.js"] },
          units,
        },
      },
    ],
  };
}

test("retains complete entry units in leaves without reviewed common content", () => {
  const membership = deriveConvexWasmOfficialOutputModuleGraphMembership(
    officialModuleGraphMembershipFixture()
  );
  assert.deepEqual(membership.common, []);
  assert.deepEqual(
    membership.cohorts[0].leafUnits.map(({ module }) => module?.path ?? "entry-publication"),
    ["shared.js", "a.js", "b.js", "entry-publication", "entry-publication"]
  );
  assert.equal(Object.hasOwn(membership, "routeLocalReachability"), false);
});

test("admits common content only with an explicit matching authority", () => {
  const fixture = officialModuleGraphMembershipFixture();
  const sharedUnit = fixture.compilerOutputs[0].nativeApplication.units[0];
  const { sourceMembershipSha256: ignoredSourceMembershipSha256, ...module } = sharedUnit.module;
  const logical = {
    dependencies: [],
    javascript: sharedUnit.javascript,
    module,
    modulePath: sharedUnit.module.path,
  };
  const engine = {
    compatibilitySha256: digest("1"),
    precompilerPackageId: digest("2"),
    wasmtimeRevision: "3".repeat(40),
  };
  fixture.commonPartitionAuthority = {
    content: {
      units: [{
        aotEvidence: {
          artifact: { sha256: digest("4"), size: 1 },
          coreWasm: { sha256: digest("5"), size: 1 },
          memoryPeakBytes: 1,
          reportSha256: digest("6"),
        },
        engine,
        generatedC: {
          aggregate: { sha256: digest("7"), size: 1 },
          compilation: {
            exceptionalFunctionCount: 0,
            exceptionalOptimizationFlag: "-O0",
            normalOptimizationFlag: "-Oz",
            pic: true,
          },
          translationUnitCount: 1,
        },
        logical,
        logicalUnitIdentitySha256: fingerprintJson(logical),
        officialUnitIdentitySha256: sharedUnit.identitySha256,
        picObjectAggregateBytes: 1,
        slot: 0,
      }],
    },
    kind: emptyCommonAuthority.kind,
    layout: {
      ...emptyCommonAuthority.layout,
      slots: [{
        factorySymbol: `convex_wasm_common_application_factory_${fingerprintJson({
          domain: "convex-wasm-static-hermes-common-factory-slot-v1",
          layoutEpoch: 1,
          slot: 0,
        })}`,
        slot: 0,
      }],
    },
  };
  Object.assign(fixture, {
    engineCompatibilitySha256: engine.compatibilitySha256,
    precompilerPackageId: engine.precompilerPackageId,
    wasmtimeRevision: engine.wasmtimeRevision,
  });
  const membership = deriveConvexWasmOfficialOutputModuleGraphMembership(fixture);
  assert.equal(membership.common.length, 1);
  assert.deepEqual(
    membership.cohorts[0].leafUnits.map(({ module }) => module?.path ?? "entry-publication"),
    ["a.js", "b.js", "entry-publication", "entry-publication"]
  );
});

test("rejects a schedule whose entry path differs from the compiler descriptor", () => {
  const fixture = officialModuleGraphMembershipFixture();
  fixture.cohortSchedule.cohorts[0].entries[0].entryPath = "convex/different.ts";
  assert.throws(
    () => deriveConvexWasmOfficialOutputModuleGraphMembership(fixture),
    /does not match its scheduled cohort/u
  );
});

test("rejects a logical unit that changes across scheduled cohorts", () => {
  const fixture = officialModuleGraphMembershipFixture();
  const secondOutput = structuredClone(fixture.compilerOutputs[0]);
  secondOutput.nativeApplication.units[0].module.sourceSha256 = digest("b");
  fixture.compilerOutputs.push(secondOutput);
  fixture.cohortSchedule.cohorts.push({
    ...structuredClone(fixture.cohortSchedule.cohorts[0]),
    cohortId: digest("e"),
  });
  assert.throws(
    () => deriveConvexWasmOfficialOutputModuleGraphMembership(fixture),
    /changed across scheduled cohorts/u
  );
});
