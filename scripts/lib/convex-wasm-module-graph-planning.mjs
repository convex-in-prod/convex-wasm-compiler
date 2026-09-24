import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

import {
  canonicalJson,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import { createConvexWasmModuleGraphCohortContract } from "./convex-wasm-module-graph-cohort-contract.mjs";
import {
  convexWasmModuleGraphCompilerDescriptorKind,
  convexWasmModuleGraphCompilerDescriptorSchemaVersion,
} from "./convex-wasm-official-output-chunk-contract.mjs";
import { authenticateConvexWasmOfficialOutputCohortSchedule } from "./convex-wasm-official-output-cohort-schedule.mjs";
import { normalizeConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import { validateConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";

export const convexWasmOfficialOutputModuleGraphPhysicalShardReportKind =
  "convex-wasm-official-output-module-graph-physical-shard-report-v1";

function fail(message) {
  throw new Error(`Convex Wasm official-output module graph physical-shard planning: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requirePlainObject(value, description) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${description} must be a plain object`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function addSafeIntegers(left, right, description) {
  if (!Number.isSafeInteger(right) || right < 0 || right > Number.MAX_SAFE_INTEGER - left) {
    fail(`${description} exceeds the safe integer range`);
  }
  return left + right;
}

function producerImplementation(identity) {
  return { kind: identity.kind, sha256: identity.sha256 };
}

export function authenticateConvexWasmOfficialOutputModuleGraphPlanningInputs(options) {
  const source = validateConvexWasmSourceEnvelope(options.sourceEnvelope);
  const producerIdentity = normalizeConvexWasmProducerIdentity(
    requirePlainObject(options.artifactConfig, "artifact config").producerIdentity
  );
  const schedule = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: options.cohortSchedule,
    sourceEnvelope: source,
    ...(Object.hasOwn(options, "sourceEnvelopeFileSha256")
      ? { sourceEnvelopeFileSha256: options.sourceEnvelopeFileSha256 }
      : {}),
    ...(Object.hasOwn(options, "sourceEnvelopeFileSize")
      ? { sourceEnvelopeFileSize: options.sourceEnvelopeFileSize }
      : {}),
  });
  const compilerOutputs = options.compilerOutputs;
  if (!Array.isArray(compilerOutputs) || compilerOutputs.length !== schedule.cohorts.length) {
    fail("compiler outputs must cover every authenticated cohort exactly once");
  }
  const expectedProducerImplementation = producerImplementation(producerIdentity);
  const cohortContracts = compilerOutputs.map((compilerOutput, index) => {
    const output = requirePlainObject(compilerOutput, `compiler output ${index}`);
    const outputProducerIdentity = normalizeConvexWasmProducerIdentity(
      requirePlainObject(output.options, `compiler output ${index} options`).producerIdentity
    );
    if (canonicalJson(outputProducerIdentity) !== canonicalJson(producerIdentity)) {
      fail(`compiler output ${index} producer identity differs from the planning producer`);
    }
    const descriptor = requirePlainObject(output.descriptor, `compiler output ${index} descriptor`);
    if (
      descriptor.kind !== convexWasmModuleGraphCompilerDescriptorKind ||
      descriptor.schemaVersion !== convexWasmModuleGraphCompilerDescriptorSchemaVersion ||
      !Array.isArray(descriptor.units) ||
      descriptor.units.some((unit) =>
        Object.hasOwn(
          requirePlainObject(unit, `compiler output ${index} descriptor unit`),
          "javascriptSource"
        )
      )
    ) {
      fail(`compiler output ${index} does not contain a compact authenticated descriptor`);
    }
    const cohort = schedule.cohorts[index];
    const contract = createConvexWasmModuleGraphCohortContract({
      cohortId: cohort.cohortId,
      compilerContract: output.cohortContract,
      scheduleSha256: schedule.identity.sha256,
      sourceEnvelopeSha256: source.sourceEnvelopeSha256,
    });
    if (
      contract.compilerSourceEnvelopeSha256 !==
        requireSha256(
          requirePlainObject(
            descriptor.applicationIdentity,
            `compiler output ${index} descriptor application identity`
          ).sourceEnvelopeSha256,
          `compiler output ${index} descriptor physical source-envelope SHA-256`
        ) ||
      contract.sourceEnvelopeSha256 !== source.sourceEnvelopeSha256 ||
      canonicalJson(contract.producerImplementation) !==
        canonicalJson(expectedProducerImplementation)
    ) {
      fail(
        `compiler output ${index} does not bind its physical cohort projection, global source envelope, or planning producer`
      );
    }
    if (descriptor.identitySha256 !== contract.descriptorIdentitySha256) {
      fail(`compiler output ${index} descriptor differs from its cohort contract`);
    }
    const scheduledEntries = cohort.entries.map((entry) => ({
      dependencyGraphSha256: entry.dependencyGraphSha256,
      entryPath: entry.entryPath,
      modulePath: entry.modulePath,
      routes: entry.routes,
    }));
    const contractEntries = contract.entries.map((entry) => ({
      dependencyGraphSha256: entry.localProfile.dependencyGraphSha256,
      entryPath: entry.entryPath,
      modulePath: entry.modulePath,
      routes: contract.routes
        .filter((route) => route.entryId === entry.entryId)
        .map(({ exportName, udfKind, visibility }) => ({ exportName, udfKind, visibility }))
        .sort((left, right) => compareStrings(left.exportName, right.exportName)),
    }));
    if (canonicalJson(contractEntries) !== canonicalJson(scheduledEntries)) {
      fail(`compiler output ${index} does not match its authenticated cohort membership`);
    }
    return contract;
  });
  return { cohortContracts, producerIdentity, schedule, source };
}

function componentOccurrenceMap(physicalShardPlanning) {
  if (!Array.isArray(physicalShardPlanning.componentOccurrences)) {
    fail("physical shard planning omits component occurrences");
  }
  const occurrences = new Map();
  for (const component of physicalShardPlanning.componentOccurrences) {
    const value = requirePlainObject(component, "physical shard component occurrence");
    const componentSha256 = requireSha256(
      value.componentSha256,
      "physical shard component occurrence identity"
    );
    if (!Array.isArray(value.occurrences) || occurrences.has(componentSha256)) {
      fail("physical shard component occurrences are invalid or repeated");
    }
    occurrences.set(componentSha256, value.occurrences);
  }
  return occurrences;
}

function summarizeComponents({ components, occurrenceMap, residualReasons }) {
  let occurrencePicObjectBytes = 0;
  let picObjectBytes = 0;
  let logicalUnitCount = 0;
  let occurrenceCount = 0;
  const records = components.map((component) => {
    const occurrences = occurrenceMap.get(component.componentSha256);
    if (occurrences === undefined) {
      fail(`physical shard component ${component.componentSha256} has no occurrence evidence`);
    }
    picObjectBytes = addSafeIntegers(
      picObjectBytes,
      component.picObjectByteWeight,
      "unique component PIC bytes"
    );
    logicalUnitCount = addSafeIntegers(
      logicalUnitCount,
      component.logicalUnitSha256s.length,
      "logical unit count"
    );
    occurrenceCount = addSafeIntegers(occurrenceCount, occurrences.length, "PIC occurrence count");
    for (const occurrence of occurrences) {
      const picObject = requirePlainObject(occurrence.picObject, "PIC occurrence object");
      occurrencePicObjectBytes = addSafeIntegers(
        occurrencePicObjectBytes,
        picObject.byteWeight,
        "PIC occurrence bytes"
      );
    }
    return {
      codeIdentitySha256s: component.codeIdentitySha256s,
      componentSha256: component.componentSha256,
      dependencies: component.dependencies,
      logicalUnitSha256s: component.logicalUnitSha256s,
      occurrenceCohortSha256s: component.occurrenceCohortSha256s,
      occurrences,
      picObjectByteWeight: component.picObjectByteWeight,
      ...(residualReasons === undefined
        ? {}
        : { reason: residualReasons.get(component.componentSha256) }),
      shareable: component.shareable,
      sharedEligible: component.sharedEligible,
    };
  });
  const logicalUnits = records.flatMap(
    ({ codeIdentitySha256s, componentSha256, logicalUnitSha256s }) =>
      logicalUnitSha256s.map((logicalUnitSha256, index) => ({
        codeIdentitySha256: codeIdentitySha256s[index],
        componentSha256,
        logicalUnitSha256,
      }))
  );
  if (logicalUnits.some(({ codeIdentitySha256 }) => codeIdentitySha256 === undefined)) {
    fail("physical shard component logical-unit identity mapping is incomplete");
  }
  return {
    componentCount: records.length,
    components: records,
    logicalUnitCount,
    logicalUnits,
    occurrenceCount,
    occurrencePicObjectBytes,
    picObjectBytes,
  };
}

export function createConvexWasmOfficialOutputModuleGraphPhysicalShardReport({
  cohortContracts,
  physicalShardPlanning,
  producerIdentity,
  schedule,
  sourceEnvelope,
}) {
  const planning = requirePlainObject(physicalShardPlanning, "physical shard planning");
  const plan = requirePlainObject(planning.plan, "physical shard plan");
  const components = plan.components;
  if (
    !Array.isArray(components) ||
    !Array.isArray(plan.sharedShards) ||
    !Array.isArray(plan.residualComponents)
  ) {
    fail("physical shard plan is incomplete");
  }
  const occurrenceMap = componentOccurrenceMap(planning);
  const componentsBySha256 = new Map(
    components.map((component) => [component.componentSha256, component])
  );
  if (componentsBySha256.size !== components.length || occurrenceMap.size !== components.length) {
    fail("physical shard plan component identities are inconsistent");
  }
  const sharedComponentSha256s = new Set(
    plan.sharedShards.flatMap((shard) => shard.componentSha256s)
  );
  const residualReasons = new Map(
    plan.residualComponents.map(({ componentSha256, reason }) => [componentSha256, reason])
  );
  if (
    sharedComponentSha256s.size + residualReasons.size !== components.length ||
    [...sharedComponentSha256s].some(
      (componentSha256) =>
        !componentsBySha256.has(componentSha256) || residualReasons.has(componentSha256)
    ) ||
    [...residualReasons].some(([componentSha256]) => !componentsBySha256.has(componentSha256))
  ) {
    fail("physical shard plan does not classify every component exactly once");
  }
  const sharedComponents = components.filter(({ componentSha256 }) =>
    sharedComponentSha256s.has(componentSha256)
  );
  const residualComponents = components.filter(({ componentSha256 }) =>
    residualReasons.has(componentSha256)
  );
  const reportPayload = {
    cohorts: cohortContracts.map((contract) => ({
      cohortContractSha256: contract.cohortContractSha256,
      cohortId: contract.cohortId,
      compilerSourceEnvelopeSha256: contract.compilerSourceEnvelopeSha256,
      descriptorIdentitySha256: contract.descriptorIdentitySha256,
      sourceEnvelopeSha256: contract.sourceEnvelopeSha256,
    })),
    kind: convexWasmOfficialOutputModuleGraphPhysicalShardReportKind,
    physicalShardPlan: {
      planSha256: plan.planSha256,
      policy: plan.policy,
      shardOrder: plan.shardOrder,
      sharedShards: plan.sharedShards,
    },
    producerIdentity,
    residual: summarizeComponents({
      components: residualComponents,
      occurrenceMap,
      residualReasons,
    }),
    schedule: {
      kind: schedule.kind,
      sha256: schedule.identity.sha256,
    },
    shared: summarizeComponents({ components: sharedComponents, occurrenceMap }),
    sourceEnvelope: {
      kind: sourceEnvelope.kind,
      sha256: sourceEnvelope.sourceEnvelopeSha256,
    },
  };
  return Object.freeze({
    ...reportPayload,
    reportSha256: fingerprintJson(reportPayload),
  });
}

async function requireAbsentOutput(path) {
  try {
    await fs.lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`physical-shard report path already exists: ${path}`);
}

export async function publishConvexWasmOfficialOutputModuleGraphPhysicalShardReport({
  outputPath,
  report,
}) {
  const finalPath = resolve(outputPath);
  const directory = dirname(finalPath);
  const temporaryPath = join(
    directory,
    `.${basename(finalPath)}.publish-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  await fs.mkdir(directory, { mode: 0o700, recursive: true });
  await requireAbsentOutput(finalPath);
  try {
    const handle = await fs.open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(`${canonicalJson(report)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await fs.link(temporaryPath, finalPath);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "EEXIST") {
        throw new Error(`physical-shard report path already exists: ${finalPath}`, {
          cause: error,
        });
      }
      throw error;
    }
    const directoryHandle = await fs.open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
    return finalPath;
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
}

