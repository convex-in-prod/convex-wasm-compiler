import {
  fingerprintJson,
  normalizeJson,
  requireExactPlainObject,
  requirePositiveInteger,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";

const FACTORY_SYMBOL_PREFIX = "convex_wasm_common_application_factory_";
const AUTHORITY_KIND = "convex-wasm-static-hermes-common-partition-authority-v1";
const LAYOUT_KIND = "convex-wasm-static-hermes-common-partition-layout-v1";

function fail(message) {
  throw new Error(`Convex Wasm common-partition authority: ${message}`);
}

function freezeJson(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeJson(nested);
    Object.freeze(value);
  }
  return value;
}

function requireArtifact(value, description) {
  requireExactPlainObject(value, ["sha256", "size"], description);
  requireSha256(value.sha256, `${description} SHA-256`);
  requirePositiveInteger(value.size, `${description} size`);
  return Object.freeze({ sha256: value.sha256, size: value.size });
}

export function normalizeConvexWasmStaticHermesCommonPartitionAuthority(value) {
  requireExactPlainObject(value, ["content", "kind", "layout"], "common partition authority");
  if (value.kind !== AUTHORITY_KIND) fail("common partition authority kind is unsupported");
  requireExactPlainObject(value.content, ["units"], "common partition content");
  requireExactPlainObject(
    value.layout,
    ["kind", "layoutEpoch", "maximumSlots", "slots"],
    "common partition layout"
  );
  if (value.layout.kind !== LAYOUT_KIND) fail("common partition layout kind is unsupported");
  const layoutEpoch = requirePositiveInteger(value.layout.layoutEpoch, "layout epoch");
  const maximumSlots = requirePositiveInteger(value.layout.maximumSlots, "maximum slots");
  if (maximumSlots > 1_024) fail("maximum slots exceeds the supported bound");
  if (!Array.isArray(value.content.units) || value.content.units.length > 1) {
    fail("common partition authority supports at most one reviewed unit");
  }
  if (!Array.isArray(value.layout.slots) || value.layout.slots.length !== value.content.units.length) {
    fail("common partition layout must match reviewed units");
  }
  const units = value.content.units.map((unit) => {
    requireExactPlainObject(
      unit,
      [
        "aotEvidence",
        "engine",
        "generatedC",
        "logical",
        "logicalUnitIdentitySha256",
        "officialUnitIdentitySha256",
        "picObjectAggregateBytes",
        "slot",
      ],
      "reviewed common unit"
    );
    if (unit.slot !== 0) fail("reviewed common unit must occupy slot zero");
    requireSha256(unit.officialUnitIdentitySha256, "reviewed official unit identity");
    requireSha256(unit.logicalUnitIdentitySha256, "reviewed logical unit identity");
    const logical = freezeJson(normalizeJson(unit.logical, "reviewed logical unit"));
    if (fingerprintJson(logical) !== unit.logicalUnitIdentitySha256) {
      fail("reviewed logical unit does not match its authenticated identity");
    }
    requireExactPlainObject(
      unit.engine,
      ["compatibilitySha256", "precompilerPackageId", "wasmtimeRevision"],
      "reviewed engine"
    );
    requireSha256(unit.engine.compatibilitySha256, "reviewed engine compatibility");
    requireSha256(unit.engine.precompilerPackageId, "reviewed precompiler package");
    if (!/^[0-9a-f]{40}$/u.test(unit.engine.wasmtimeRevision)) {
      fail("reviewed Wasmtime revision must be a 40-character commit ID");
    }
    requireExactPlainObject(
      unit.generatedC,
      ["aggregate", "compilation", "translationUnitCount"],
      "reviewed generated C"
    );
    const aggregate = requireArtifact(unit.generatedC.aggregate, "reviewed generated C aggregate");
    requirePositiveInteger(unit.generatedC.translationUnitCount, "reviewed translation unit count");
    requireExactPlainObject(
      unit.generatedC.compilation,
      [
        "exceptionalFunctionCount",
        "exceptionalOptimizationFlag",
        "normalOptimizationFlag",
        "pic",
      ],
      "reviewed compilation policy"
    );
    const compilation = unit.generatedC.compilation;
    if (
      !Number.isSafeInteger(compilation.exceptionalFunctionCount) ||
      compilation.exceptionalFunctionCount < 0 ||
      typeof compilation.pic !== "boolean"
    ) {
      fail("reviewed compilation policy has invalid counts or PIC mode");
    }
    requireString(compilation.exceptionalOptimizationFlag, "exceptional optimization flag");
    requireString(compilation.normalOptimizationFlag, "normal optimization flag");
    requireExactPlainObject(
      unit.aotEvidence,
      ["artifact", "coreWasm", "memoryPeakBytes", "reportSha256"],
      "reviewed AOT evidence"
    );
    const artifact = requireArtifact(unit.aotEvidence.artifact, "reviewed AOT artifact");
    const coreWasm = requireArtifact(unit.aotEvidence.coreWasm, "reviewed Core Wasm");
    requirePositiveInteger(unit.aotEvidence.memoryPeakBytes, "reviewed AOT memory peak");
    requireSha256(unit.aotEvidence.reportSha256, "reviewed AOT report");
    requirePositiveInteger(unit.picObjectAggregateBytes, "reviewed PIC object aggregate bytes");
    return Object.freeze({
      ...unit,
      aotEvidence: Object.freeze({ ...unit.aotEvidence, artifact, coreWasm }),
      engine: Object.freeze({ ...unit.engine }),
      generatedC: Object.freeze({
        aggregate,
        compilation: Object.freeze({ ...compilation }),
        translationUnitCount: unit.generatedC.translationUnitCount,
      }),
      logical,
    });
  });
  const slots = value.layout.slots.map((slot) => {
    requireExactPlainObject(slot, ["factorySymbol", "slot"], "common partition slot");
    if (slot.slot !== 0) fail("common partition slot must be zero");
    const expectedSymbol = `${FACTORY_SYMBOL_PREFIX}${fingerprintJson({
      domain: "convex-wasm-static-hermes-common-factory-slot-v1",
      layoutEpoch,
      slot: slot.slot,
    })}`;
    if (slot.factorySymbol !== expectedSymbol) {
      fail("common partition factory symbol does not match its layout identity");
    }
    return Object.freeze({ factorySymbol: expectedSymbol, slot: slot.slot });
  });
  return Object.freeze({
    content: Object.freeze({ units: Object.freeze(units) }),
    kind: AUTHORITY_KIND,
    layout: Object.freeze({
      kind: LAYOUT_KIND,
      layoutEpoch,
      maximumSlots,
      slots: Object.freeze(slots),
    }),
  });
}

function entryIdsOf(candidate) {
  const values = candidate.entryIds instanceof Set ? [...candidate.entryIds] : candidate.entryIds;
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string" || value.length === 0)) {
    fail("reviewed common candidate entry IDs must be non-empty strings");
  }
  const sorted = [...values].sort();
  if (new Set(sorted).size !== sorted.length) fail("reviewed common candidate repeats an entry ID");
  return sorted;
}

// Repetition discovers a candidate; only an explicitly supplied reviewed authority admits it.
export function selectConvexWasmStaticHermesCommonPartition({
  authority,
  candidateUnits,
  engineCompatibilitySha256,
  precompilerPackageId,
  scheduleSha256,
  wasmtimeRevision,
}) {
  const reviewed = normalizeConvexWasmStaticHermesCommonPartitionAuthority(authority);
  if (!Array.isArray(candidateUnits)) fail("candidateUnits must be an array");
  requireSha256(scheduleSha256, "schedule SHA-256");
  const content = reviewed.content.units[0];
  if (content === undefined) {
    return { common: [], kind: "convex-wasm-static-hermes-common-partition-selection-v1" };
  }
  const matches = candidateUnits.filter((candidate) =>
    candidate?.occurrences?.some(
      ({ unit }) => unit?.identitySha256 === content.officialUnitIdentitySha256
    )
  );
  if (matches.length === 0) {
    return { common: [], kind: "convex-wasm-static-hermes-common-partition-selection-v1" };
  }
  if (matches.length !== 1) fail("reviewed official unit occurs in more than one logical candidate");
  if (engineCompatibilitySha256 !== content.engine.compatibilitySha256) {
    fail("reviewed common content has not been admitted for this engine compatibility identity");
  }
  if (
    precompilerPackageId !== content.engine.precompilerPackageId ||
    wasmtimeRevision !== content.engine.wasmtimeRevision
  ) {
    fail("reviewed common content has not been admitted for this precompiler package");
  }
  const candidate = matches[0];
  const entryIds = entryIdsOf(candidate);
  if (entryIds.length < 2) fail("reviewed common candidate must reach at least two complete entries");
  if (fingerprintJson(candidate.logical) !== content.logicalUnitIdentitySha256) {
    fail("reviewed common candidate logical unit does not match the admitted content");
  }
  if (!Array.isArray(candidate.occurrences) || candidate.occurrences.length === 0) {
    fail("reviewed common candidate has no official-output occurrence");
  }
  if (
    candidate.occurrences.some(
      ({ cohortIndex, unit }) =>
        !Number.isSafeInteger(cohortIndex) ||
        cohortIndex < 0 ||
        unit?.identitySha256 !== content.officialUnitIdentitySha256
    )
  ) {
    fail("reviewed common candidate occurrences do not bind the exact official unit");
  }
  const occurrences = [...candidate.occurrences].sort((left, right) => {
    const leftSlot = left.unit.applicationUnitSlot;
    const rightSlot = right.unit.applicationUnitSlot;
    return left.cohortIndex - right.cohortIndex || leftSlot - rightSlot;
  });
  return {
    common: [
      {
        commonSlot: content.slot,
        entryCount: entryIds.length,
        factorySymbol: reviewed.layout.slots[content.slot].factorySymbol,
        logical: candidate.logical,
        membershipProof: {
          entryIds,
          kind: "convex-wasm-static-hermes-common-deployment-membership-v1",
          occurrences: occurrences.map(({ cohortIndex, unit }) => ({
            applicationUnitSlot: unit.applicationUnitSlot,
            cohortIndex,
            officialUnitIdentitySha256: unit.identitySha256,
          })),
          scheduleSha256,
        },
        occurrence: occurrences[0],
        occurrences,
      },
    ],
    kind: "convex-wasm-static-hermes-common-partition-selection-v1",
  };
}

export function requireConvexWasmStaticHermesCommonGeneratedC({
  authority,
  aggregateSha256,
  aggregateSize,
  translationUnitCount,
}) {
  const reviewed = normalizeConvexWasmStaticHermesCommonPartitionAuthority(authority);
  const admitted = reviewed.content.units[0]?.generatedC;
  if (admitted === undefined) fail("no reviewed common generated C was supplied");
  if (
    aggregateSha256 !== admitted.aggregate.sha256 ||
    aggregateSize !== admitted.aggregate.size ||
    translationUnitCount !== admitted.translationUnitCount
  ) {
    fail("common generated C does not match the exact reviewed content");
  }
  return admitted;
}
