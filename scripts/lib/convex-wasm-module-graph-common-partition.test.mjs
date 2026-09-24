import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  normalizeConvexWasmStaticHermesCommonPartitionAuthority,
  requireConvexWasmStaticHermesCommonGeneratedC,
  selectConvexWasmStaticHermesCommonPartition,
} from "./convex-wasm-module-graph-common-partition.mjs";

const sha256 = (character) => character.repeat(64);
const engineCompatibilitySha256 = sha256("a");
const precompilerPackageId = sha256("b");
const officialUnitIdentitySha256 = sha256("c");
const wasmtimeRevision = "d".repeat(40);
const logical = { dependencies: [], modulePath: "shared.js" };
const generatedC = {
  aggregate: { sha256: sha256("e"), size: 100 },
  compilation: {
    exceptionalFunctionCount: 0,
    exceptionalOptimizationFlag: "-O0",
    normalOptimizationFlag: "-Oz",
    pic: true,
  },
  translationUnitCount: 2,
};

function authority(units = [
  {
    aotEvidence: {
      artifact: { sha256: sha256("f"), size: 120 },
      coreWasm: { sha256: sha256("0"), size: 80 },
      memoryPeakBytes: 1_024,
      reportSha256: sha256("1"),
    },
    engine: { compatibilitySha256: engineCompatibilitySha256, precompilerPackageId, wasmtimeRevision },
    generatedC,
    logical,
    logicalUnitIdentitySha256: fingerprintJson(logical),
    officialUnitIdentitySha256,
    picObjectAggregateBytes: 90,
    slot: 0,
  },
]) {
  const layoutEpoch = 1;
  return {
    content: { units },
    kind: "convex-wasm-static-hermes-common-partition-authority-v1",
    layout: {
      kind: "convex-wasm-static-hermes-common-partition-layout-v1",
      layoutEpoch,
      maximumSlots: 1_024,
      slots: units.map((_, slot) => ({
        factorySymbol: `convex_wasm_common_application_factory_${fingerprintJson({
          domain: "convex-wasm-static-hermes-common-factory-slot-v1",
          layoutEpoch,
          slot,
        })}`,
        slot,
      })),
    },
  };
}

function candidate() {
  return {
    entryIds: new Set(["entry-b", "entry-a"]),
    logical: structuredClone(logical),
    occurrences: [
      { cohortIndex: 1, unit: { applicationUnitSlot: 4, identitySha256: officialUnitIdentitySha256 } },
      { cohortIndex: 0, unit: { applicationUnitSlot: 7, identitySha256: officialUnitIdentitySha256 } },
    ],
  };
}

function select(reviewed, candidateUnits = [candidate()]) {
  return selectConvexWasmStaticHermesCommonPartition({
    authority: reviewed,
    candidateUnits,
    engineCompatibilitySha256,
    precompilerPackageId,
    scheduleSha256: sha256("2"),
    wasmtimeRevision,
  });
}

test("an empty explicit authority admits no common content", () => {
  const reviewed = normalizeConvexWasmStaticHermesCommonPartitionAuthority(authority([]));
  assert.deepEqual(select(reviewed), {
    common: [],
    kind: "convex-wasm-static-hermes-common-partition-selection-v1",
  });
  assert.throws(
    () => requireConvexWasmStaticHermesCommonGeneratedC({ authority: reviewed, aggregateSha256: sha256("e"), aggregateSize: 100, translationUnitCount: 2 }),
    /no reviewed common generated C/u
  );
});

test("reviewed synthetic content binds the engine, logical unit, slot, and generated C", () => {
  const reviewed = normalizeConvexWasmStaticHermesCommonPartitionAuthority(authority());
  assert.equal(Object.isFrozen(reviewed.content.units[0].logical), true);
  const selected = select(reviewed);
  assert.equal(selected.common.length, 1);
  assert.deepEqual(selected.common[0].membershipProof.entryIds, ["entry-a", "entry-b"]);
  assert.deepEqual(selected.common[0].membershipProof.occurrences, [
    { applicationUnitSlot: 7, cohortIndex: 0, officialUnitIdentitySha256 },
    { applicationUnitSlot: 4, cohortIndex: 1, officialUnitIdentitySha256 },
  ]);
  assert.equal(selected.common[0].factorySymbol, reviewed.layout.slots[0].factorySymbol);
  assert.deepEqual(
    requireConvexWasmStaticHermesCommonGeneratedC({
      authority: reviewed,
      aggregateSha256: generatedC.aggregate.sha256,
      aggregateSize: generatedC.aggregate.size,
      translationUnitCount: generatedC.translationUnitCount,
    }),
    generatedC
  );
  const changed = candidate();
  changed.logical.modulePath = "different.js";
  assert.throws(() => select(reviewed, [changed]), /logical unit does not match/u);
  assert.throws(
    () => selectConvexWasmStaticHermesCommonPartition({
      authority: reviewed,
      candidateUnits: [candidate()],
      engineCompatibilitySha256: sha256("3"),
      precompilerPackageId,
      scheduleSha256: sha256("2"),
      wasmtimeRevision,
    }),
    /engine compatibility identity/u
  );
});

test("reviewed authority rejects identity and layout drift", () => {
  const changedLogical = authority();
  changedLogical.content.units[0].logical.modulePath = "different.js";
  assert.throws(
    () => normalizeConvexWasmStaticHermesCommonPartitionAuthority(changedLogical),
    /authenticated identity/u
  );
  const changedSymbol = authority();
  changedSymbol.layout.slots[0].factorySymbol = "wrong";
  assert.throws(
    () => normalizeConvexWasmStaticHermesCommonPartitionAuthority(changedSymbol),
    /factory symbol/u
  );
  const changedGeneratedC = authority();
  changedGeneratedC.content.units[0].generatedC.aggregate.size = 0;
  assert.throws(
    () => normalizeConvexWasmStaticHermesCommonPartitionAuthority(changedGeneratedC),
    /positive safe integer/u
  );
});
