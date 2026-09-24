import {
  assertPlainObject,
  normalizeJson,
  requireExactPlainObject,
  requirePositiveInteger,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import { selectConvexWasmStaticHermesCommonPartition } from "./convex-wasm-module-graph-common-partition.mjs";

function fail(message) {
  throw new Error(`Convex Wasm module graph membership: ${message}`);
}

function moduleGraphLogicalUnit(unit, description) {
  assertPlainObject(unit, description);
  const module = requireExactPlainObject(
    unit.module,
    [
      "environment",
      "moduleSha256",
      "path",
      "sourceMap",
      "sourceMembershipSha256",
      "sourceSha256",
      "sourceSize",
    ],
    `${description}.module`
  );
  if (module.environment !== "isolate") {
    fail(`${description}.module.environment must be isolate`);
  }
  requireSha256(module.sourceMembershipSha256, `${description}.module.sourceMembershipSha256`);
  const modulePath = requireString(module.path, `${description}.module.path`);
  const dependencies = unit.dependencies.map((dependency, index) => {
    const dependencyDescription = `${description}.dependencies[${index}]`;
    assertPlainObject(dependency, dependencyDescription);
    return {
      kind: requireString(dependency.kind, `${dependencyDescription}.kind`),
      path: requireString(dependency.path, `${dependencyDescription}.path`),
      specifier: requireString(dependency.specifier, `${dependencyDescription}.specifier`),
    };
  });
  return {
    dependencies,
    javascript: {
      sha256: requireSha256(unit.javascript.sha256, `${description}.javascript.sha256`),
      size: requirePositiveInteger(unit.javascript.size, `${description}.javascript.size`),
    },
    module: normalizeJson(
      (({ sourceMembershipSha256: _sourceMembershipSha256, ...logicalModule }) => logicalModule)(
        module
      ),
      `${description}.module`
    ),
    modulePath,
  };
}

// Both logical units have passed the fixed-shape descriptor validator above. Compare their
// primitive identities directly so repeated modules across cohorts do not allocate canonical JSON
// strings merely to prove that the authenticated chunk is unchanged.
function moduleGraphLogicalUnitEqual(left, right) {
  if (
    left.modulePath !== right.modulePath ||
    left.javascript.sha256 !== right.javascript.sha256 ||
    left.javascript.size !== right.javascript.size
  ) {
    return false;
  }
  const leftModule = left.module;
  const rightModule = right.module;
  if (
    leftModule.environment !== rightModule.environment ||
    leftModule.moduleSha256 !== rightModule.moduleSha256 ||
    leftModule.path !== rightModule.path ||
    leftModule.sourceSha256 !== rightModule.sourceSha256 ||
    leftModule.sourceSize !== rightModule.sourceSize
  ) {
    return false;
  }
  const leftSourceMap = leftModule.sourceMap;
  const rightSourceMap = rightModule.sourceMap;
  if (leftSourceMap === null || rightSourceMap === null) {
    if (leftSourceMap !== rightSourceMap) return false;
  } else if (
    leftSourceMap.sha256 !== rightSourceMap.sha256 ||
    leftSourceMap.size !== rightSourceMap.size ||
    leftSourceMap.sourcesContentCount !== rightSourceMap.sourcesContentCount ||
    leftSourceMap.sourcesCount !== rightSourceMap.sourcesCount
  ) {
    return false;
  }
  if (left.dependencies.length !== right.dependencies.length) return false;
  for (let index = 0; index < left.dependencies.length; index += 1) {
    const leftDependency = left.dependencies[index];
    const rightDependency = right.dependencies[index];
    if (
      leftDependency.kind !== rightDependency.kind ||
      leftDependency.path !== rightDependency.path ||
      leftDependency.specifier !== rightDependency.specifier
    ) {
      return false;
    }
  }
  return true;
}

// Follow complete-entry chunk dependencies; route-local reachability cannot grant sharing.
export function deriveConvexWasmOfficialOutputModuleGraphMembership({
  cohortSchedule,
  commonPartitionAuthority,
  compilerOutputs,
  engineCompatibilitySha256,
  precompilerPackageId,
  wasmtimeRevision,
}) {
  assertPlainObject(cohortSchedule, "official-output module graph cohort schedule");
  if (!Array.isArray(cohortSchedule.cohorts) || cohortSchedule.cohorts.length === 0) {
    fail("official-output module graph cohort schedule must contain cohorts");
  }
  if (!Array.isArray(compilerOutputs) || compilerOutputs.length !== cohortSchedule.cohorts.length) {
    fail("official-output module graph compiler outputs must cover every scheduled cohort once");
  }
  const scheduleSha256 = requireSha256(
    cohortSchedule.identity?.sha256,
    "official-output module graph schedule SHA-256"
  );
  const logicalUnits = new Map();
  const normalizedCohorts = compilerOutputs.map((compilerOutput, cohortIndex) => {
    assertPlainObject(compilerOutput, `official-output compiler output ${cohortIndex}`);
    const descriptor = compilerOutput.nativeApplication;
    assertPlainObject(descriptor, `official-output compiler output ${cohortIndex} descriptor`);
    if (!Array.isArray(descriptor.units) || !Array.isArray(descriptor.entries)) {
      fail(`official-output compiler output ${cohortIndex} has no native chunk descriptor`);
    }
    const scheduled = cohortSchedule.cohorts[cohortIndex];
    const scheduledEntryPaths = scheduled.entries.map(({ entryPath }, entryIndex) =>
      requireString(
        entryPath,
        `official-output module graph cohort ${cohortIndex} scheduled entry ${entryIndex} path`
      )
    );
    const descriptorEntryPaths = descriptor.entries.map(({ entryPath }, entryIndex) =>
      requireString(
        entryPath,
        `official-output module graph descriptor ${cohortIndex} entry ${entryIndex} path`
      )
    );
    if (
      scheduledEntryPaths.length !== descriptorEntryPaths.length ||
      scheduledEntryPaths.some(
        (entryPath, entryIndex) => entryPath !== descriptorEntryPaths[entryIndex]
      )
    ) {
      fail(`official-output compiler output ${cohortIndex} does not match its scheduled cohort`);
    }
    if (
      descriptor.units.length < 2 ||
      descriptor.units.length !==
        descriptor.initialization.chunkSlotCount + descriptor.entries.length ||
      descriptor.units
        .slice(0, descriptor.initialization.chunkSlotCount)
        .some(({ entryPublication }) => entryPublication !== false) ||
      descriptor.units
        .slice(descriptor.initialization.chunkSlotCount)
        .some(({ entryPublication }) => entryPublication !== true)
    ) {
      fail(`official-output compiler output ${cohortIndex} has an invalid publication boundary`);
    }
    const unitByPath = new Map();
    for (const [unitIndex, unit] of descriptor.units
      .slice(0, descriptor.initialization.chunkSlotCount)
      .entries()) {
      if (unit.applicationUnitSlot !== unitIndex || unit.chunkSlot !== unitIndex) {
        fail(`official-output compiler output ${cohortIndex} changed its numbered chunk slots`);
      }
      const logical = moduleGraphLogicalUnit(
        unit,
        `official-output compiler output ${cohortIndex} unit ${unitIndex}`
      );
      if (unitByPath.has(logical.modulePath)) {
        fail(`official-output compiler output ${cohortIndex} repeats ${logical.modulePath}`);
      }
      unitByPath.set(logical.modulePath, { logical, unit });
      const existing = logicalUnits.get(logical.modulePath);
      if (existing === undefined) {
        logicalUnits.set(logical.modulePath, {
          entryIds: new Set(),
          logical,
          occurrences: [],
        });
      } else if (!moduleGraphLogicalUnitEqual(existing.logical, logical)) {
        fail(`official-output chunk ${logical.modulePath} changed across scheduled cohorts`);
      }
      logicalUnits.get(logical.modulePath).occurrences.push({ cohortIndex, unit });
    }
    for (const [entryIndex, entry] of descriptor.entries.entries()) {
      if (
        entry.handoffSlot !== entryIndex ||
        entry.entryPublicationUnitSlot !==
          descriptor.initialization.entryPublicationUnitSlots[entryIndex]
      ) {
        fail(`official-output compiler output ${cohortIndex} changed its entry handoff slots`);
      }
      const scheduledEntry = scheduled.entries[entryIndex];
      const pending = [entry.entrySlot];
      const visited = new Set();
      while (pending.length > 0) {
        const slot = pending.pop();
        if (visited.has(slot)) continue;
        const unit = descriptor.units[slot];
        if (unit === undefined || unit.entryPublication) {
          fail(`official-output compiler output ${cohortIndex} entry closure has an invalid slot`);
        }
        visited.add(slot);
        logicalUnits.get(unit.module.path).entryIds.add(scheduledEntry.entryId);
        pending.push(...unit.dependencies.map(({ slot: dependencySlot }) => dependencySlot));
      }
    }
    return {
      cohortId: requireSha256(scheduled.cohortId, `official-output cohort ${cohortIndex} ID`),
      cohortIndex,
      compilerOutput,
      descriptor,
      scheduled,
      unitByPath,
    };
  });
  const { common } = selectConvexWasmStaticHermesCommonPartition({
    authority: commonPartitionAuthority,
    candidateUnits: [...logicalUnits.values()],
    engineCompatibilitySha256,
    precompilerPackageId,
    scheduleSha256,
    wasmtimeRevision,
  });
  const commonByPath = new Map(common.map((unit) => [unit.logical.modulePath, unit]));
  const cohorts = normalizedCohorts.map((cohort) => ({
    ...cohort,
    leafUnits: cohort.descriptor.units.filter(
      (unit) => unit.entryPublication || !commonByPath.has(unit.module.path)
    ),
  }));
  if (cohorts.some(({ leafUnits }) => !leafUnits.at(-1).entryPublication)) {
    fail("official-output module graph leaf membership lost its entry-publication unit");
  }
  return {
    common,
    cohorts,
    kind: "convex-wasm-official-output-module-graph-membership-v1",
    scheduleSha256,
  };
}
