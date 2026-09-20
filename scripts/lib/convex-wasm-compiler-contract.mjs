import { createHash } from "node:crypto";

export const convexWasmCompilerOutputKind = "convex-wasm-compiler-output";
export const convexWasmCompilerAbiVersion = "convex-wasm-opaque";
export const convexWasmCompilerOpaqueValueAbiVersion = 3;
export const convexWasmCompilerAdmittedLanguageVersion = 29;
export const convexWasmCompilerModuleSummarySchema = "convex-wasm-module-summary";
export const convexWasmCompilerOxcVersion = "0.150.0";
export const convexWasmBlockingEffectExecutionMode = "blocking-fiber";
export const convexWasmGuestPromiseEffectExecutionMode = "guest-promise-event-loop";

export const convexWasmCompilerOutputContract = Object.freeze({
  abiVersion: convexWasmCompilerAbiVersion,
  admittedLanguageVersion: convexWasmCompilerAdmittedLanguageVersion,
  moduleSummarySchema: convexWasmCompilerModuleSummarySchema,
  opaqueValueAbiVersion: convexWasmCompilerOpaqueValueAbiVersion,
  outputKind: convexWasmCompilerOutputKind,
  oxcVersion: convexWasmCompilerOxcVersion,
  provedDirectAsyncBatchAnalysisVersion: 2,
});

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const COMMON_OUTPUT_FIELDS = [
  "compiler",
  "diagnostics",
  "eligible",
  "exportFingerprint",
  "kind",
  "moduleCache",
  "phaseTimingsUs",
  "provedDirectAsyncBatches",
  "routing",
  "source",
  "sourceGraphFingerprint",
];
const ANALYSIS_OUTPUT_FIELDS = ["analysisSummary"];
const COMPILE_OUTPUT_FIELDS = [
  "abiVersion",
  "argumentFields",
  "arrayArgumentFields",
  "directAsyncBatches",
  "documentProperties",
  "generatedJavascriptArtifact",
  "intrinsics",
  "limits",
  "opaqueValueAbiVersion",
  "operations",
  "operationsSha256",
  "reachableModules",
  "reachableUnits",
  "resolvedImports",
  "runtimeInputs",
  "target",
  "toolchain",
  "valueMode",
];
const OPTIONAL_COMPILE_OUTPUT_FIELDS = ["effectExecutionMode"];
const PHASE_TIMING_FIELDS = [
  "admission",
  "cacheLookup",
  "esbuildGraph",
  "graphRead",
  "lowering",
  "parse",
  "reachability",
  "semantic",
  "sourceRead",
  "totalRust",
];
const COMPILER_LIMIT_FIELDS = [
  "argumentBytes",
  "documentsRead",
  "documentsWritten",
  "executionTimeMs",
  "readBytes",
  "resultBytes",
  "scheduledArgumentBytes",
  "scheduledFunctions",
  "writeBytes",
];

function fail(message) {
  throw new Error(`Convex Wasm compiler output contract: ${message}`);
}

function requireObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertExactKeys(value, expectedKeys, description) {
  const actual = Object.keys(requireObject(value, description)).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    const unsupported = actual.filter((key) => !expected.includes(key));
    const missing = expected.filter((key) => !actual.includes(key));
    fail(
      `${description} has unsupported fields; unsupported=${JSON.stringify(unsupported)} missing=${JSON.stringify(missing)}`
    );
  }
}

function requireNonNegativeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a non-negative safe integer`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireNullableString(value, description) {
  if (value !== null) {
    requireString(value, description);
  }
  return value;
}

function validateOperations(operations) {
  const expectedKeys = [
    "algorithm",
    "column",
    "contractVersion",
    "end",
    "file",
    "functionReference",
    "id",
    "index",
    "indexConstraints",
    "kind",
    "limit",
    "limitArgumentIndex",
    "line",
    "order",
    "selector",
    "source",
    "stableKey",
    "start",
    "table",
    "terminal",
  ];
  const ids = new Set();
  const supportedKinds = new Set([
    "authenticationGetUserIdentity",
    "databaseDelete",
    "databaseGet",
    "databaseIndexQuery",
    "databaseInsert",
    "databaseNormalizeId",
    "databasePatch",
    "databaseReplace",
    "functionHandleCreate",
    "schedulerRunAfter",
    "schedulerRunAt",
    "sha256",
    "hostSecretVerify",
  ]);
  for (const [index, operation] of operations.entries()) {
    const description = `operation ${index}`;
    assertExactKeys(operation, expectedKeys, description);
    const limitArgumentIndex = operation.limitArgumentIndex;
    const id = requirePositiveInteger(operation.id, `${description} id`);
    if (id > 65_535 || id !== index + 1 || ids.has(id)) {
      fail(`${description} id is out of range, non-canonical, or duplicated`);
    }
    ids.add(id);
    if (!supportedKinds.has(operation.kind)) {
      fail(`${description} kind is unsupported`);
    }
    if (
      typeof operation.stableKey !== "string" ||
      !/^op_[0-9a-f]{16}$/u.test(operation.stableKey)
    ) {
      fail(`${description} stableKey is invalid`);
    }
    requireString(operation.file, `${description} file`);
    requireString(operation.source, `${description} source`);
    requirePositiveInteger(operation.line, `${description} line`);
    requirePositiveInteger(operation.column, `${description} column`);
    requireNonNegativeInteger(operation.start, `${description} start`);
    requireNonNegativeInteger(operation.end, `${description} end`);
    if (operation.start >= operation.end) {
      fail(`${description} span is invalid`);
    }
    for (const field of ["algorithm", "functionReference", "index", "order", "table", "terminal"]) {
      requireNullableString(operation[field], `${description} ${field}`);
    }
    if (operation.kind === "hostSecretVerify") {
      if (
        operation.contractVersion !== 1 ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(operation.selector) ||
        [
          operation.algorithm,
          operation.functionReference,
          operation.index,
          operation.limit,
          limitArgumentIndex,
          operation.order,
          operation.table,
          operation.terminal,
        ].some((value) => value !== null)
      ) {
        fail(`${description} host-secret descriptor has unsupported metadata`);
      }
    } else if (operation.contractVersion !== null || operation.selector !== null) {
      fail(`${description} non-host-secret descriptor must not have host-secret metadata`);
    }
    if (operation.kind === "databaseIndexQuery") {
      if (!Array.isArray(operation.indexConstraints) || operation.indexConstraints.length === 0) {
        fail(`${description} index constraints must be a non-empty array`);
      }
      const fields = new Set();
      let sawRange = false;
      for (const [constraintIndex, constraint] of operation.indexConstraints.entries()) {
        const constraintDescription = `${description} index constraint ${constraintIndex}`;
        assertExactKeys(constraint, ["field", "operator", "valueSource"], constraintDescription);
        const field = requireString(constraint.field, `${constraintDescription} field`);
        requireString(constraint.valueSource, `${constraintDescription} valueSource`);
        if (fields.has(field)) fail(`${description} index constraint fields must be unique`);
        fields.add(field);
        if (!["eq", "gt", "gte", "lt", "lte"].includes(constraint.operator)) {
          fail(`${constraintDescription} operator is unsupported`);
        }
        if (constraint.operator === "eq") {
          if (sawRange) fail(`${description} equality constraints must precede the range`);
        } else {
          if (sawRange || constraintIndex + 1 !== operation.indexConstraints.length) {
            fail(`${description} supports at most one final range constraint`);
          }
          sawRange = true;
        }
      }
      if (operation.order !== "ascending" && operation.order !== "descending") {
        fail(`${description} index order is not canonical`);
      }
      if (!["collect", "first", "stream", "unique"].includes(operation.terminal)) {
        fail(`${description} index terminal is unsupported`);
      }
      if (operation.terminal === "collect") {
        if (operation.limit !== null) {
          const limit = requirePositiveInteger(operation.limit, `${description} limit`);
          if (limit > 100_000) fail(`${description} limit is out of range`);
        }
        if (limitArgumentIndex !== null) {
          const validatedLimitArgumentIndex = requireNonNegativeInteger(
            limitArgumentIndex,
            `${description} limitArgumentIndex`
          );
          if (validatedLimitArgumentIndex !== operation.indexConstraints.length) {
            fail(`${description} dynamic limit must follow all index constraints`);
          }
          if (operation.limit !== null) {
            fail(`${description} static and dynamic limits are mutually exclusive`);
          }
        }
      } else if (operation.limit !== null || limitArgumentIndex !== null) {
        fail(`${description} non-collect index descriptor must not have a limit`);
      }
    } else if (
      operation.limit !== null ||
      limitArgumentIndex !== null ||
      !Array.isArray(operation.indexConstraints) ||
      operation.indexConstraints.length !== 0
    ) {
      fail(`${description} non-index descriptor must not have index metadata`);
    }
    if (
      ["authenticationGetUserIdentity", "functionHandleCreate"].includes(operation.kind) &&
      [
        operation.algorithm,
        operation.functionReference,
        operation.index,
        operation.order,
        operation.table,
        operation.terminal,
      ].some((value) => value !== null)
    ) {
      fail(`${description} ${operation.kind} descriptor has unsupported metadata`);
    }
    if (
      [
        "databaseDelete",
        "databaseGet",
        "databaseInsert",
        "databaseNormalizeId",
        "databasePatch",
        "databaseReplace",
      ].includes(operation.kind) &&
      (operation.table === null ||
        [
          operation.algorithm,
          operation.functionReference,
          operation.index,
          operation.order,
          operation.terminal,
        ].some((value) => value !== null))
    ) {
      fail(`${description} ${operation.kind} descriptor has unsupported metadata`);
    }
    if (
      ["schedulerRunAfter", "schedulerRunAt"].includes(operation.kind) &&
      (operation.functionReference === null ||
        [
          operation.algorithm,
          operation.index,
          operation.order,
          operation.table,
          operation.terminal,
        ].some((value) => value !== null))
    ) {
      fail(`${description} ${operation.kind} descriptor has unsupported metadata`);
    }
    if (
      operation.kind === "sha256" &&
      (operation.algorithm !== "SHA-256" ||
        [
          operation.functionReference,
          operation.index,
          operation.order,
          operation.table,
          operation.terminal,
        ].some((value) => value !== null))
    ) {
      fail(`${description} SHA-256 descriptor has unsupported metadata`);
    }
    if (
      operation.kind === "databaseIndexQuery" &&
      (operation.table === null ||
        operation.index === null ||
        operation.algorithm !== null ||
        operation.functionReference !== null)
    ) {
      fail(`${description} database index descriptor has unsupported metadata`);
    }
  }
  return new Map(operations.map((operation) => [operation.id, operation]));
}

function canonicalCompilerJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalCompilerJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalCompilerJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function convexWasmCompilerOperationsSha256(operations) {
  return createHash("sha256").update(canonicalCompilerJson(operations)).digest("hex");
}

function validateOperationsIdentity(operations, operationsSha256) {
  requireSha256(operationsSha256, "operationsSha256");
  const actual = convexWasmCompilerOperationsSha256(operations);
  if (actual !== operationsSha256) {
    fail(
      `operationsSha256 does not bind the exact ordered operation descriptors: expected ${operationsSha256}, recomputed ${actual}`
    );
  }
}

const DIRECT_BATCH_ARGUMENT_KEYS = [
  "generatedEnd",
  "generatedSha256",
  "generatedStart",
  "source",
  "sourceEnd",
  "sourceSha256",
  "sourceStart",
];

function directBatchResultKind(operation) {
  if (operation.kind === "databaseIndexQuery" && operation.terminal === "collect") {
    return "hostArray";
  }
  if (["databaseDelete", "databasePatch", "databaseReplace"].includes(operation.kind)) {
    return "undefined";
  }
  return "hostValue";
}

function directBatchArgumentCount(operation) {
  if (operation.kind === "databaseIndexQuery") {
    return (
      operation.indexConstraints.length +
      (operation.limitArgumentIndex === undefined || operation.limitArgumentIndex === null ? 0 : 1)
    );
  }
  return ["databasePatch", "databaseReplace", "schedulerRunAfter", "schedulerRunAt"].includes(
    operation.kind
  )
    ? 2
    : 1;
}

function requireAuthorizedDirectBatchOperation({
  description,
  end,
  file,
  id,
  kind,
  operationsById,
  start,
}) {
  const operation = operationsById.get(id);
  if (
    operation === undefined ||
    operation.kind !== kind ||
    operation.file !== file ||
    operation.start !== start ||
    operation.end !== end
  ) {
    fail(`${description} does not bind its exact admitted operation`);
  }
  if (
    operation.kind === "authenticationGetUserIdentity" ||
    operation.kind === "databaseNormalizeId"
  ) {
    fail(`${description} operation kind is not authorized for direct source batching`);
  }
  return operation;
}

function validateDirectBatchArguments({
  allowExactDuplicates = false,
  argumentsValue,
  description,
  generatedEnd,
  generatedStart,
  operationEnd,
  operationStart,
}) {
  let previousArgument;
  for (const [argumentIndex, argument] of argumentsValue.entries()) {
    const argumentDescription = `${description} dynamic argument ${argumentIndex}`;
    assertExactKeys(argument, DIRECT_BATCH_ARGUMENT_KEYS, argumentDescription);
    requireString(argument.source, `${argumentDescription} source`);
    requireSha256(argument.sourceSha256, `${argumentDescription} sourceSha256`);
    requireSha256(argument.generatedSha256, `${argumentDescription} generatedSha256`);
    for (const field of ["sourceStart", "sourceEnd", "generatedStart", "generatedEnd"]) {
      requireNonNegativeInteger(argument[field], `${argumentDescription} ${field}`);
    }
    const exactDuplicate =
      allowExactDuplicates &&
      previousArgument !== undefined &&
      previousArgument.sourceStart === argument.sourceStart &&
      previousArgument.sourceEnd === argument.sourceEnd &&
      previousArgument.source === argument.source &&
      previousArgument.sourceSha256 === argument.sourceSha256 &&
      previousArgument.generatedStart === argument.generatedStart &&
      previousArgument.generatedEnd === argument.generatedEnd &&
      previousArgument.generatedSha256 === argument.generatedSha256;
    if (
      argument.sourceStart < operationStart ||
      argument.sourceStart >= argument.sourceEnd ||
      argument.sourceEnd > operationEnd ||
      argument.generatedStart < generatedStart ||
      argument.generatedStart >= argument.generatedEnd ||
      argument.generatedEnd > generatedEnd ||
      (!exactDuplicate &&
        previousArgument !== undefined &&
        (previousArgument.sourceEnd > argument.sourceStart ||
          previousArgument.generatedEnd > argument.generatedStart)) ||
      createHash("sha256").update(argument.source).digest("hex") !== argument.sourceSha256
    ) {
      fail(`${argumentDescription} does not match its authorization`);
    }
    previousArgument = argument;
  }
}

function validateDirectAsyncBatches(batches, operationsById) {
  const commonKeys = [
    "column",
    "end",
    "file",
    "generatedEnd",
    "generatedSourceSha256",
    "generatedStart",
    "id",
    "kind",
    "line",
    "source",
    "sourceSha256",
    "start",
  ];
  const singleEffectMapKeys = [
    "argumentField",
    "callbackEnd",
    "callbackParameter",
    "callbackStart",
    "dynamicArguments",
    "generatedIteratorEnd",
    "generatedIteratorSha256",
    "generatedIteratorStart",
    "helperContinuationPrebound",
    "operationEnd",
    "operationId",
    "operationKind",
    "operationStart",
    "resultKind",
  ];
  const fixedChildKeys = [
    "dynamicArguments",
    "end",
    "generatedEnd",
    "generatedSourceSha256",
    "generatedStart",
    "helperContinuationPrebound",
    "operationEnd",
    "operationId",
    "operationKind",
    "operationStart",
    "resultKind",
    "source",
    "sourceSha256",
    "start",
  ];
  const ids = new Set();
  for (const [index, batch] of batches.entries()) {
    const description = `direct async batch ${index}`;
    const shapeKeys =
      batch.kind === "singleEffectMap"
        ? singleEffectMapKeys
        : batch.kind === "fixedEffectArray"
          ? ["children"]
          : [];
    assertExactKeys(batch, [...commonKeys, ...shapeKeys], description);
    if (
      typeof batch.id !== "string" ||
      !/^batch_[0-9a-f]{16}$/u.test(batch.id) ||
      ids.has(batch.id)
    ) {
      fail(`${description} id is invalid or duplicated`);
    }
    ids.add(batch.id);
    if (batch.kind !== "singleEffectMap" && batch.kind !== "fixedEffectArray") {
      fail(`${description} kind is unsupported`);
    }
    requireString(batch.file, `${description} file`);
    requireString(batch.source, `${description} source`);
    requireSha256(batch.sourceSha256, `${description} sourceSha256`);
    requireSha256(batch.generatedSourceSha256, `${description} generatedSourceSha256`);
    requirePositiveInteger(batch.line, `${description} line`);
    requirePositiveInteger(batch.column, `${description} column`);
    for (const field of ["start", "end", "generatedStart", "generatedEnd"]) {
      requireNonNegativeInteger(batch[field], `${description} ${field}`);
    }
    if (
      batch.start >= batch.end ||
      batch.generatedStart >= batch.generatedEnd ||
      createHash("sha256").update(batch.source).digest("hex") !== batch.sourceSha256
    ) {
      fail(`${description} source metadata is inconsistent`);
    }

    if (batch.kind === "singleEffectMap") {
      const operation = requireAuthorizedDirectBatchOperation({
        description,
        end: batch.operationEnd,
        file: batch.file,
        id: batch.operationId,
        kind: batch.operationKind,
        operationsById,
        start: batch.operationStart,
      });
      if (batch.resultKind !== directBatchResultKind(operation)) {
        fail(`${description} result kind disagrees with its operation`);
      }
      if (
        !Array.isArray(batch.dynamicArguments) ||
        batch.dynamicArguments.length !== directBatchArgumentCount(operation)
      ) {
        fail(`${description} dynamic argument count disagrees with its operation`);
      }
      requireNullableString(batch.argumentField, `${description} argumentField`);
      requireString(batch.callbackParameter, `${description} callbackParameter`);
      if (typeof batch.helperContinuationPrebound !== "boolean") {
        fail(`${description} helperContinuationPrebound must be a boolean`);
      }
      requireSha256(batch.generatedIteratorSha256, `${description} generatedIteratorSha256`);
      for (const field of [
        "callbackStart",
        "callbackEnd",
        "operationStart",
        "operationEnd",
        "generatedIteratorStart",
        "generatedIteratorEnd",
      ]) {
        requireNonNegativeInteger(batch[field], `${description} ${field}`);
      }
      if (
        batch.callbackStart < batch.start ||
        batch.callbackStart >= batch.callbackEnd ||
        batch.callbackEnd > batch.end ||
        batch.operationStart < batch.callbackStart ||
        batch.operationStart >= batch.operationEnd ||
        batch.operationEnd > batch.callbackEnd ||
        batch.generatedIteratorStart < batch.generatedStart ||
        batch.generatedIteratorStart >= batch.generatedIteratorEnd ||
        batch.generatedIteratorEnd > batch.generatedEnd
      ) {
        fail(`${description} source metadata is inconsistent`);
      }
      validateDirectBatchArguments({
        allowExactDuplicates: batch.helperContinuationPrebound,
        argumentsValue: batch.dynamicArguments,
        description,
        generatedEnd: batch.generatedEnd,
        generatedStart: batch.generatedStart,
        operationEnd: batch.operationEnd,
        operationStart: batch.operationStart,
      });
      continue;
    }

    if (!Array.isArray(batch.children) || batch.children.length === 0) {
      fail(`${description} children must be a non-empty array`);
    }
    let previousChild;
    for (const [childIndex, child] of batch.children.entries()) {
      const childDescription = `${description} fixed child ${childIndex}`;
      assertExactKeys(child, fixedChildKeys, childDescription);
      requireString(child.source, `${childDescription} source`);
      if (typeof child.helperContinuationPrebound !== "boolean") {
        fail(`${childDescription} helperContinuationPrebound must be a boolean`);
      }
      requireSha256(child.sourceSha256, `${childDescription} sourceSha256`);
      requireSha256(child.generatedSourceSha256, `${childDescription} generatedSourceSha256`);
      for (const field of [
        "start",
        "end",
        "operationStart",
        "operationEnd",
        "generatedStart",
        "generatedEnd",
      ]) {
        requireNonNegativeInteger(child[field], `${childDescription} ${field}`);
      }
      if (
        child.start < batch.start ||
        child.start >= child.end ||
        child.end > batch.end ||
        child.operationStart < child.start ||
        child.operationStart >= child.operationEnd ||
        child.operationEnd > child.end ||
        child.generatedStart < batch.generatedStart ||
        child.generatedStart >= child.generatedEnd ||
        child.generatedEnd > batch.generatedEnd ||
        createHash("sha256").update(child.source).digest("hex") !== child.sourceSha256 ||
        (previousChild !== undefined &&
          (previousChild.end > child.start || previousChild.generatedEnd > child.generatedStart))
      ) {
        fail(`${childDescription} source metadata is inconsistent`);
      }
      const operation = requireAuthorizedDirectBatchOperation({
        description: childDescription,
        end: child.operationEnd,
        file: batch.file,
        id: child.operationId,
        kind: child.operationKind,
        operationsById,
        start: child.operationStart,
      });
      if (child.resultKind !== directBatchResultKind(operation)) {
        fail(`${childDescription} result kind disagrees with its operation`);
      }
      if (
        !Array.isArray(child.dynamicArguments) ||
        child.dynamicArguments.length !== directBatchArgumentCount(operation)
      ) {
        fail(`${childDescription} dynamic argument count disagrees with its operation`);
      }
      validateDirectBatchArguments({
        allowExactDuplicates: child.helperContinuationPrebound,
        argumentsValue: child.dynamicArguments,
        description: childDescription,
        generatedEnd: child.generatedEnd,
        generatedStart: child.generatedStart,
        operationEnd: child.operationEnd,
        operationStart: child.operationStart,
      });
      previousChild = child;
    }
  }
  return new Map(batches.map((batch) => [batch.id, batch]));
}

function validateProvedDirectAsyncBatches(batches) {
  if (!Array.isArray(batches)) {
    fail("provedDirectAsyncBatches must be an array");
  }
  const commonKeys = [
    "column",
    "dependencyChain",
    "end",
    "file",
    "id",
    "kind",
    "line",
    "source",
    "sourceSha256",
    "start",
  ];
  const singleEffectMapKeys = [
    "argumentField",
    "callbackEnd",
    "callbackParameter",
    "callbackStart",
    "dynamicArguments",
    "helperContinuationPrebound",
    "operationEnd",
    "operationId",
    "operationKind",
    "operationStableKey",
    "operationStart",
    "resultKind",
  ];
  const fixedChildKeys = [
    "dynamicArguments",
    "end",
    "helperContinuationPrebound",
    "operationEnd",
    "operationId",
    "operationKind",
    "operationStableKey",
    "operationStart",
    "resultKind",
    "source",
    "sourceSha256",
    "start",
  ];
  const argumentKeys = ["source", "sourceEnd", "sourceSha256", "sourceStart"];
  const ids = new Set();
  const supportedOperationKinds = new Set([
    "databaseDelete",
    "databaseGet",
    "databaseIndexQuery",
    "databaseInsert",
    "databasePatch",
    "databaseReplace",
    "schedulerRunAfter",
    "schedulerRunAt",
  ]);
  for (const [index, batch] of batches.entries()) {
    const description = `proved direct async batch ${index}`;
    const shapeKeys =
      batch.kind === "singleEffectMap"
        ? singleEffectMapKeys
        : batch.kind === "fixedEffectArray"
          ? ["children"]
          : [];
    assertExactKeys(batch, [...commonKeys, ...shapeKeys], description);
    if (
      typeof batch.id !== "string" ||
      !/^batch_[0-9a-f]{16}$/u.test(batch.id) ||
      ids.has(batch.id)
    ) {
      fail(`${description} id is invalid or duplicated`);
    }
    ids.add(batch.id);
    if (batch.kind !== "singleEffectMap" && batch.kind !== "fixedEffectArray") {
      fail(`${description} kind is unsupported`);
    }
    requireString(batch.file, `${description} file`);
    requireString(batch.source, `${description} source`);
    requireSha256(batch.sourceSha256, `${description} sourceSha256`);
    requirePositiveInteger(batch.line, `${description} line`);
    requirePositiveInteger(batch.column, `${description} column`);
    requireNonNegativeInteger(batch.start, `${description} start`);
    requireNonNegativeInteger(batch.end, `${description} end`);
    if (
      batch.start >= batch.end ||
      createHash("sha256").update(batch.source).digest("hex") !== batch.sourceSha256
    ) {
      fail(`${description} source metadata is inconsistent`);
    }
    if (
      !Array.isArray(batch.dependencyChain) ||
      batch.dependencyChain.length === 0 ||
      batch.dependencyChain.some(
        (dependency) => typeof dependency !== "string" || dependency.length === 0
      )
    ) {
      fail(`${description} dependency chain is invalid`);
    }
    if (batch.kind === "fixedEffectArray") {
      if (!Array.isArray(batch.children) || batch.children.length === 0) {
        fail(`${description} children must be a non-empty array`);
      }
      let previousChild;
      for (const [childIndex, child] of batch.children.entries()) {
        const childDescription = `${description} fixed child ${childIndex}`;
        assertExactKeys(child, fixedChildKeys, childDescription);
        if (
          typeof child.operationStableKey !== "string" ||
          !/^op_[0-9a-f]{16}$/u.test(child.operationStableKey)
        ) {
          fail(`${childDescription} operation stable key is invalid`);
        }
        if (!supportedOperationKinds.has(child.operationKind)) {
          fail(`${childDescription} operation kind is unsupported`);
        }
        const expectedResultKinds =
          child.operationKind === "databaseIndexQuery"
            ? new Set(["hostArray", "hostValue"])
            : new Set([
                ["databaseDelete", "databasePatch", "databaseReplace"].includes(child.operationKind)
                  ? "undefined"
                  : "hostValue",
              ]);
        if (!expectedResultKinds.has(child.resultKind)) {
          fail(`${childDescription} result kind disagrees with its operation`);
        }
        const expectedArgumentCount = [
          "databasePatch",
          "databaseReplace",
          "schedulerRunAfter",
          "schedulerRunAt",
        ].includes(child.operationKind)
          ? 2
          : 1;
        if (
          !Array.isArray(child.dynamicArguments) ||
          (child.operationKind === "databaseIndexQuery"
            ? child.dynamicArguments.length < 1
            : child.dynamicArguments.length !== expectedArgumentCount)
        ) {
          fail(`${childDescription} dynamic argument count disagrees with its operation`);
        }
        const operationId = requirePositiveInteger(
          child.operationId,
          `${childDescription} operationId`
        );
        if (operationId > 65_535) fail(`${childDescription} operationId is out of range`);
        for (const field of ["start", "end", "operationStart", "operationEnd"]) {
          requireNonNegativeInteger(child[field], `${childDescription} ${field}`);
        }
        requireString(child.source, `${childDescription} source`);
        requireSha256(child.sourceSha256, `${childDescription} sourceSha256`);
        if (typeof child.helperContinuationPrebound !== "boolean") {
          fail(`${childDescription} helperContinuationPrebound must be a boolean`);
        }
        if (
          child.start < batch.start ||
          child.start >= child.end ||
          child.end > batch.end ||
          child.operationStart < child.start ||
          child.operationStart >= child.operationEnd ||
          child.operationEnd > child.end ||
          createHash("sha256").update(child.source).digest("hex") !== child.sourceSha256 ||
          (previousChild !== undefined && previousChild.end > child.start)
        ) {
          fail(`${childDescription} source metadata is inconsistent`);
        }
        let previousArgument;
        for (const [argumentIndex, argument] of child.dynamicArguments.entries()) {
          const argumentDescription = `${childDescription} dynamic argument ${argumentIndex}`;
          assertExactKeys(argument, argumentKeys, argumentDescription);
          requireString(argument.source, `${argumentDescription} source`);
          requireSha256(argument.sourceSha256, `${argumentDescription} sourceSha256`);
          requireNonNegativeInteger(argument.sourceStart, `${argumentDescription} sourceStart`);
          requireNonNegativeInteger(argument.sourceEnd, `${argumentDescription} sourceEnd`);
          const exactDuplicate =
            child.helperContinuationPrebound &&
            previousArgument !== undefined &&
            previousArgument.sourceStart === argument.sourceStart &&
            previousArgument.sourceEnd === argument.sourceEnd &&
            previousArgument.source === argument.source &&
            previousArgument.sourceSha256 === argument.sourceSha256;
          if (
            argument.sourceStart < child.operationStart ||
            argument.sourceStart >= argument.sourceEnd ||
            argument.sourceEnd > child.operationEnd ||
            (!exactDuplicate &&
              previousArgument !== undefined &&
              previousArgument.sourceEnd > argument.sourceStart) ||
            createHash("sha256").update(argument.source).digest("hex") !== argument.sourceSha256
          ) {
            fail(`${argumentDescription} source metadata is inconsistent`);
          }
          previousArgument = argument;
        }
        previousChild = child;
      }
      continue;
    }
    if (
      typeof batch.operationStableKey !== "string" ||
      !/^op_[0-9a-f]{16}$/u.test(batch.operationStableKey)
    ) {
      fail(`${description} operation stable key is invalid`);
    }
    if (!supportedOperationKinds.has(batch.operationKind)) {
      fail(`${description} operation kind is unsupported`);
    }
    const expectedResultKinds =
      batch.operationKind === "databaseIndexQuery"
        ? new Set(["hostArray", "hostValue"])
        : new Set([
            ["databaseDelete", "databasePatch", "databaseReplace"].includes(batch.operationKind)
              ? "undefined"
              : "hostValue",
          ]);
    if (!expectedResultKinds.has(batch.resultKind)) {
      fail(`${description} result kind disagrees with its operation`);
    }
    const expectedArgumentCount = [
      "databasePatch",
      "databaseReplace",
      "schedulerRunAfter",
      "schedulerRunAt",
    ].includes(batch.operationKind)
      ? 2
      : 1;
    if (
      !Array.isArray(batch.dynamicArguments) ||
      (batch.operationKind === "databaseIndexQuery"
        ? batch.dynamicArguments.length < 1
        : batch.dynamicArguments.length !== expectedArgumentCount)
    ) {
      fail(`${description} dynamic argument count disagrees with its operation`);
    }
    requireNullableString(batch.argumentField, `${description} argumentField`);
    requireString(batch.callbackParameter, `${description} callbackParameter`);
    if (typeof batch.helperContinuationPrebound !== "boolean") {
      fail(`${description} helperContinuationPrebound must be a boolean`);
    }
    const operationId = requirePositiveInteger(batch.operationId, `${description} operationId`);
    if (operationId > 65_535) {
      fail(`${description} operationId is out of range`);
    }
    for (const field of ["callbackStart", "callbackEnd", "operationStart", "operationEnd"]) {
      requireNonNegativeInteger(batch[field], `${description} ${field}`);
    }
    if (
      batch.callbackStart < batch.start ||
      batch.callbackStart >= batch.callbackEnd ||
      batch.callbackEnd > batch.end ||
      batch.operationStart < batch.callbackStart ||
      batch.operationStart >= batch.operationEnd ||
      batch.operationEnd > batch.callbackEnd ||
      createHash("sha256").update(batch.source).digest("hex") !== batch.sourceSha256
    ) {
      fail(`${description} source metadata is inconsistent`);
    }
    let previousArgument;
    for (const [argumentIndex, argument] of batch.dynamicArguments.entries()) {
      const argumentDescription = `${description} dynamic argument ${argumentIndex}`;
      assertExactKeys(argument, argumentKeys, argumentDescription);
      requireString(argument.source, `${argumentDescription} source`);
      requireSha256(argument.sourceSha256, `${argumentDescription} sourceSha256`);
      requireNonNegativeInteger(argument.sourceStart, `${argumentDescription} sourceStart`);
      requireNonNegativeInteger(argument.sourceEnd, `${argumentDescription} sourceEnd`);
      const exactDuplicate =
        batch.helperContinuationPrebound &&
        previousArgument !== undefined &&
        previousArgument.sourceStart === argument.sourceStart &&
        previousArgument.sourceEnd === argument.sourceEnd &&
        previousArgument.source === argument.source &&
        previousArgument.sourceSha256 === argument.sourceSha256;
      if (
        argument.sourceStart < batch.operationStart ||
        argument.sourceStart >= argument.sourceEnd ||
        argument.sourceEnd > batch.operationEnd ||
        (!exactDuplicate &&
          previousArgument !== undefined &&
          previousArgument.sourceEnd > argument.sourceStart) ||
        createHash("sha256").update(argument.source).digest("hex") !== argument.sourceSha256
      ) {
        fail(`${argumentDescription} source metadata is inconsistent`);
      }
      previousArgument = argument;
    }
  }
  return new Map(batches.map((batch) => [batch.id, batch]));
}

function validateCommonEnvelope(output) {
  assertExactKeys(
    output.source,
    ["exportName", "exportSha256", "modulePath", "resolvedGraphSha256", "udfKind"],
    "source identity"
  );
  requireString(output.source.modulePath, "source modulePath");
  requireString(output.source.exportName, "source exportName");
  if (output.source.udfKind !== "query" && output.source.udfKind !== "mutation") {
    fail(`source udfKind is unsupported: ${JSON.stringify(output.source.udfKind)}`);
  }
  if (Object.hasOwn(output, "appliedRegistrationAdapter")) {
    validateAppliedRegistrationAdapter(output.appliedRegistrationAdapter, output.source.udfKind);
  }
  if (Object.hasOwn(output, "appliedDependencyAdapters")) {
    validateAppliedDependencyAdapters(output.appliedDependencyAdapters);
  }
  requireSha256(output.source.resolvedGraphSha256, "source resolvedGraphSha256");
  requireSha256(output.source.exportSha256, "source exportSha256");
  requireSha256(output.sourceGraphFingerprint, "sourceGraphFingerprint");
  requireSha256(output.exportFingerprint, "exportFingerprint");
  if (
    output.source.resolvedGraphSha256 !== output.sourceGraphFingerprint ||
    output.source.exportSha256 !== output.exportFingerprint
  ) {
    fail("source identities disagree with their top-level fingerprints");
  }

  assertExactKeys(
    output.compiler,
    ["admittedLanguageVersion", "compilerRevision", "pipelineSha256", "staticHermesGlobalPolicy"],
    "compiler identity"
  );
  if (output.compiler.admittedLanguageVersion !== convexWasmCompilerAdmittedLanguageVersion) {
    fail(
      `unsupported admitted language version ${JSON.stringify(output.compiler.admittedLanguageVersion)}`
    );
  }
  requireString(output.compiler.compilerRevision, "compiler revision");
  requireSha256(output.compiler.pipelineSha256, "compiler pipeline SHA-256");
  assertExactKeys(
    output.compiler.staticHermesGlobalPolicy,
    ["inventorySha256", "kind", "runtimeSurfacePolicySha256"],
    "compiler Static Hermes global policy identity"
  );
  if (
    output.compiler.staticHermesGlobalPolicy.kind !==
    "convex-wasm-runtime-surface-policy-identity"
  ) {
    fail("compiler Static Hermes global policy identity kind is unsupported");
  }
  requireSha256(
    output.compiler.staticHermesGlobalPolicy.inventorySha256,
    "compiler Static Hermes global inventory SHA-256"
  );
  requireSha256(
    output.compiler.staticHermesGlobalPolicy.runtimeSurfacePolicySha256,
    "compiler runtime-surface policy SHA-256"
  );

  assertExactKeys(output.routing, ["decision"], "routing decision");
  if (output.routing.decision !== "wasm" && output.routing.decision !== "v8Fallback") {
    fail(`unsupported routing decision ${JSON.stringify(output.routing.decision)}`);
  }
  if (
    typeof output.eligible !== "boolean" ||
    output.eligible !== (output.routing.decision === "wasm")
  ) {
    fail("eligibility disagrees with the routing decision");
  }
  if (!Array.isArray(output.diagnostics)) {
    fail("diagnostics must be an array");
  }

  assertExactKeys(output.moduleCache, ["hits", "misses", "summarySchema"], "module cache");
  requireNonNegativeInteger(output.moduleCache.hits, "module cache hits");
  requireNonNegativeInteger(output.moduleCache.misses, "module cache misses");
  if (output.moduleCache.summarySchema !== convexWasmCompilerModuleSummarySchema) {
    fail(`unsupported module summary schema ${JSON.stringify(output.moduleCache.summarySchema)}`);
  }

  assertExactKeys(output.phaseTimingsUs, PHASE_TIMING_FIELDS, "phase timings");
  for (const field of PHASE_TIMING_FIELDS) {
    requireNonNegativeInteger(output.phaseTimingsUs[field], `phase timing ${field}`);
  }
}

function validateRegistrationAdapterUnit(value, description) {
  requireObject(value, description);
  assertExactKeys(value, ["exportName", "modulePath", "unitSourceSha256"], description);
  requireString(value.modulePath, `${description} modulePath`);
  if (
    value.modulePath.startsWith("/") ||
    value.modulePath.includes("\\") ||
    value.modulePath.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${description} modulePath is invalid`);
  }
  requireString(value.exportName, `${description} exportName`);
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(value.exportName)) {
    fail(`${description} exportName is invalid`);
  }
  requireSha256(value.unitSourceSha256, `${description} unitSourceSha256`);
}

function validateAppliedRegistrationAdapter(value, udfKind) {
  requireObject(value, "applied registration adapter");
  assertExactKeys(
    value,
    ["adapterId", "authentication", "registrationKind", "wrapper"],
    "applied registration adapter"
  );
  requireString(value.adapterId, "applied registration adapter adapterId");
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(value.adapterId)) {
    fail("applied registration adapter adapterId is invalid");
  }
  if (!new Set(["mutation", "query"]).has(value.registrationKind)) {
    fail("applied registration adapter registrationKind is unsupported");
  }
  if (value.registrationKind !== udfKind) {
    fail("applied registration adapter registrationKind disagrees with source udfKind");
  }
  validateRegistrationAdapterUnit(value.wrapper, "applied registration adapter wrapper");
  requireObject(value.authentication, "applied registration adapter authentication");
  assertExactKeys(
    value.authentication,
    ["helper", "resultKind", "resultParameters"],
    "applied registration adapter authentication"
  );
  validateRegistrationAdapterUnit(
    value.authentication.helper,
    "applied registration adapter authentication helper"
  );
  if (!new Set(["object", "value"]).has(value.authentication.resultKind)) {
    fail("applied registration adapter authentication resultKind is unsupported");
  }
  if (!Array.isArray(value.authentication.resultParameters)) {
    fail("applied registration adapter authentication resultParameters must be an array");
  }
  const indexes = new Set();
  for (const [index, parameter] of value.authentication.resultParameters.entries()) {
    const description = `applied registration adapter result parameter ${index}`;
    requireObject(parameter, description);
    assertExactKeys(parameter, ["callbackParameterIndex", "property"], description);
    if (
      !Number.isSafeInteger(parameter.callbackParameterIndex) ||
      parameter.callbackParameterIndex < 2 ||
      indexes.has(parameter.callbackParameterIndex)
    ) {
      fail(`${description} callbackParameterIndex is invalid or duplicated`);
    }
    indexes.add(parameter.callbackParameterIndex);
    if (value.authentication.resultKind === "object") {
      requireString(parameter.property, `${description} property`);
      if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(parameter.property)) {
        fail(`${description} property is invalid`);
      }
    } else if (parameter.property !== null) {
      fail(`${description} value projection property must be null`);
    }
  }
  const sortedIndexes = [...indexes].sort((left, right) => left - right);
  if (
    sortedIndexes.some((callbackParameterIndex, offset) => callbackParameterIndex !== offset + 2)
  ) {
    fail("applied registration adapter result parameter indexes must be contiguous from 2");
  }
  if (
    value.authentication.resultKind === "value" &&
    value.authentication.resultParameters.length !== 1
  ) {
    fail("applied registration adapter value projection must contain one result parameter");
  }
}

function validateDependencyAdapterPath(value, description) {
  requireString(value, description);
  if (
    value.startsWith("/") ||
    value.includes("\\") ||
    value.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${description} is invalid`);
  }
}

function validateDependencyAdapterLock(value, description) {
  assertExactKeys(value, ["entrySha256", "packageKey", "path"], description);
  validateDependencyAdapterPath(value.path, `${description} path`);
  validateDependencyAdapterPath(value.packageKey, `${description} packageKey`);
  requireSha256(value.entrySha256, `${description} entrySha256`);
}

function validateAppliedDependencyAdapters(adapters) {
  if (!Array.isArray(adapters) || adapters.length === 0) {
    fail("appliedDependencyAdapters must be a non-empty array");
  }
  let previousAdapterId;
  const semanticKinds = new Set([
    "databaseGetBatch",
    "databaseGetBatchOrThrow",
    "databaseIndexCollect",
    "databaseIndexUnique",
    "databaseIndexUniqueOrThrow",
    "functionHandleCreate",
  ]);
  for (const [index, adapter] of adapters.entries()) {
    const description = `applied dependency adapter ${index}`;
    requireObject(adapter, description);
    const hasSubstitution = Object.hasOwn(adapter, "substitution");
    assertExactKeys(
      adapter,
      [
        "adapterId",
        "material",
        "resolvedExport",
        "semanticKind",
        ...(hasSubstitution ? ["substitution"] : []),
      ],
      description
    );
    requireString(adapter.adapterId, `${description} adapterId`);
    if (
      !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(adapter.adapterId) ||
      (previousAdapterId !== undefined && previousAdapterId >= adapter.adapterId)
    ) {
      fail(`${description} adapterId is invalid, duplicated, or unsorted`);
    }
    previousAdapterId = adapter.adapterId;
    if (!semanticKinds.has(adapter.semanticKind)) {
      fail(`${description} semanticKind is unsupported`);
    }
    validateRegistrationAdapterUnit(adapter.resolvedExport, `${description} resolvedExport`);
    if ((adapter.semanticKind === "functionHandleCreate") !== hasSubstitution) {
      fail(`${description} substitution must be present only for functionHandleCreate`);
    }
    if (hasSubstitution) {
      assertExactKeys(
        adapter.substitution,
        ["exportName", "moduleSpecifier", "unitSourceSha256"],
        `${description} substitution`
      );
      validateDependencyAdapterPath(
        adapter.substitution.moduleSpecifier,
        `${description} substitution moduleSpecifier`
      );
      requireString(adapter.substitution.exportName, `${description} substitution exportName`);
      if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(adapter.substitution.exportName)) {
        fail(`${description} substitution exportName is invalid`);
      }
      requireSha256(
        adapter.substitution.unitSourceSha256,
        `${description} substitution unitSourceSha256`
      );
    }
    assertExactKeys(
      adapter.material,
      ["installedLock", "moduleSourceSha256", "packageJson", "packageLock", "semanticSources"],
      `${description} material`
    );
    requireSha256(
      adapter.material.moduleSourceSha256,
      `${description} material moduleSourceSha256`
    );
    assertExactKeys(
      adapter.material.packageJson,
      ["path", "sha256", "version"],
      `${description} packageJson`
    );
    validateDependencyAdapterPath(
      adapter.material.packageJson.path,
      `${description} packageJson path`
    );
    requireSha256(adapter.material.packageJson.sha256, `${description} packageJson sha256`);
    requireString(adapter.material.packageJson.version, `${description} packageJson version`);
    validateDependencyAdapterLock(adapter.material.packageLock, `${description} packageLock`);
    validateDependencyAdapterLock(adapter.material.installedLock, `${description} installedLock`);
    if (!Array.isArray(adapter.material.semanticSources)) {
      fail(`${description} semanticSources must be an array`);
    }
    let previousSourcePath;
    for (const [sourceIndex, source] of adapter.material.semanticSources.entries()) {
      const sourceDescription = `${description} semantic source ${sourceIndex}`;
      assertExactKeys(source, ["path", "sourceSha256", "units"], sourceDescription);
      validateDependencyAdapterPath(source.path, `${sourceDescription} path`);
      if (previousSourcePath !== undefined && previousSourcePath >= source.path) {
        fail(`${description} semantic sources must be sorted and unique`);
      }
      previousSourcePath = source.path;
      requireSha256(source.sourceSha256, `${sourceDescription} sourceSha256`);
      if (!Array.isArray(source.units) || source.units.length === 0) {
        fail(`${sourceDescription} units must be a non-empty array`);
      }
      let previousUnitName;
      for (const [unitIndex, unit] of source.units.entries()) {
        const unitDescription = `${sourceDescription} unit ${unitIndex}`;
        assertExactKeys(unit, ["unitName", "unitSourceSha256"], unitDescription);
        requireString(unit.unitName, `${unitDescription} unitName`);
        if (
          !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(unit.unitName) ||
          (previousUnitName !== undefined && previousUnitName >= unit.unitName)
        ) {
          fail(`${sourceDescription} unit names must be valid, sorted, and unique`);
        }
        previousUnitName = unit.unitName;
        requireSha256(unit.unitSourceSha256, `${unitDescription} unitSourceSha256`);
      }
    }
  }
}

function validateCompileEnvelope(output, expectedGraphToolchain, provedBatchesById) {
  if (output.abiVersion !== convexWasmCompilerAbiVersion) {
    fail(`unsupported compiler ABI ${JSON.stringify(output.abiVersion)}`);
  }
  if (output.opaqueValueAbiVersion !== convexWasmCompilerOpaqueValueAbiVersion) {
    fail(`unsupported opaque value ABI ${JSON.stringify(output.opaqueValueAbiVersion)}`);
  }
  if (!new Set(["opaque", "guest-native-json"]).has(output.valueMode)) {
    fail(`unsupported compiler value mode ${JSON.stringify(output.valueMode)}`);
  }
  const effectExecutionMode = output.effectExecutionMode ?? convexWasmBlockingEffectExecutionMode;
  if (
    effectExecutionMode !== convexWasmBlockingEffectExecutionMode &&
    effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode
  ) {
    fail(`unsupported effect execution mode ${JSON.stringify(effectExecutionMode)}`);
  }
  for (const field of [
    "argumentFields",
    "arrayArgumentFields",
    "directAsyncBatches",
    "documentProperties",
    "intrinsics",
    "operations",
    "reachableModules",
    "reachableUnits",
    "resolvedImports",
    "runtimeInputs",
  ]) {
    if (!Array.isArray(output[field])) {
      fail(`${field} must be an array`);
    }
  }
  const supportedRuntimeInputs = new Set(["invocationUnixTimestampMs"]);
  if (
    output.runtimeInputs.some(
      (runtimeInput, index) =>
        typeof runtimeInput !== "string" ||
        !supportedRuntimeInputs.has(runtimeInput) ||
        (index > 0 && output.runtimeInputs[index - 1] >= runtimeInput)
    )
  ) {
    fail("runtimeInputs must contain supported values in sorted unique order");
  }
  if (output.reachableModules.some((modulePath) => typeof modulePath !== "string")) {
    fail("reachableModules must contain only strings");
  }
  const operationsById = validateOperations(output.operations);
  validateOperationsIdentity(output.operations, output.operationsSha256);
  const authorizationsById = validateDirectAsyncBatches(output.directAsyncBatches, operationsById);
  if (
    effectExecutionMode === convexWasmGuestPromiseEffectExecutionMode &&
    (authorizationsById.size !== 0 || provedBatchesById.size !== 0)
  ) {
    fail("guest Promise execution must not contain direct batch authorizations");
  }
  if (!output.eligible && authorizationsById.size !== 0) {
    fail("fallback compiler output must not contain executable direct batch authorizations");
  }
  if (output.eligible && authorizationsById.size !== provedBatchesById.size) {
    fail("eligible compiler output direct batch proof and authorization counts disagree");
  }
  for (const proof of provedBatchesById.values()) {
    if (proof.kind === "fixedEffectArray") {
      const authorization = output.eligible ? authorizationsById.get(proof.id) : undefined;
      if (
        output.eligible &&
        (authorization === undefined ||
          authorization.kind !== proof.kind ||
          authorization.file !== proof.file ||
          authorization.start !== proof.start ||
          authorization.end !== proof.end ||
          authorization.source !== proof.source ||
          authorization.sourceSha256 !== proof.sourceSha256 ||
          authorization.children.length !== proof.children.length)
      ) {
        fail("proved direct async batch disagrees with its executable authorization");
      }
      for (const [childIndex, provedChild] of proof.children.entries()) {
        const operation = operationsById.get(provedChild.operationId);
        if (
          operation === undefined ||
          operation.stableKey !== provedChild.operationStableKey ||
          operation.kind !== provedChild.operationKind ||
          operation.file !== proof.file ||
          operation.start !== provedChild.operationStart ||
          operation.end !== provedChild.operationEnd
        ) {
          fail("proved direct async batch child does not bind its exact admitted operation");
        }
        if (!output.eligible) continue;
        const authorizedChild = authorization.children[childIndex];
        if (
          authorizedChild.start !== provedChild.start ||
          authorizedChild.end !== provedChild.end ||
          authorizedChild.operationStart !== provedChild.operationStart ||
          authorizedChild.operationEnd !== provedChild.operationEnd ||
          authorizedChild.operationId !== provedChild.operationId ||
          authorizedChild.operationKind !== provedChild.operationKind ||
          authorizedChild.resultKind !== provedChild.resultKind ||
          authorizedChild.helperContinuationPrebound !== provedChild.helperContinuationPrebound ||
          authorizedChild.source !== provedChild.source ||
          authorizedChild.sourceSha256 !== provedChild.sourceSha256 ||
          authorizedChild.dynamicArguments.length !== provedChild.dynamicArguments.length ||
          authorizedChild.dynamicArguments.some((argument, argumentIndex) => {
            const provedArgument = provedChild.dynamicArguments[argumentIndex];
            return (
              argument.sourceStart !== provedArgument.sourceStart ||
              argument.sourceEnd !== provedArgument.sourceEnd ||
              argument.source !== provedArgument.source ||
              argument.sourceSha256 !== provedArgument.sourceSha256
            );
          })
        ) {
          fail("proved direct async batch child disagrees with its executable authorization");
        }
      }
      continue;
    }
    const operation = operationsById.get(proof.operationId);
    if (
      operation === undefined ||
      operation.stableKey !== proof.operationStableKey ||
      operation.kind !== proof.operationKind ||
      operation.file !== proof.file ||
      operation.start !== proof.operationStart ||
      operation.end !== proof.operationEnd
    ) {
      fail("proved direct async batch does not bind its exact admitted operation");
    }
    if (output.eligible) {
      const authorization = authorizationsById.get(proof.id);
      if (
        authorization === undefined ||
        authorization.file !== proof.file ||
        authorization.start !== proof.start ||
        authorization.end !== proof.end ||
        authorization.callbackStart !== proof.callbackStart ||
        authorization.callbackEnd !== proof.callbackEnd ||
        authorization.callbackParameter !== proof.callbackParameter ||
        authorization.operationId !== proof.operationId ||
        authorization.operationKind !== proof.operationKind ||
        authorization.resultKind !== proof.resultKind ||
        authorization.helperContinuationPrebound !== proof.helperContinuationPrebound ||
        authorization.argumentField !== proof.argumentField ||
        authorization.source !== proof.source ||
        authorization.sourceSha256 !== proof.sourceSha256 ||
        authorization.dynamicArguments.length !== proof.dynamicArguments.length ||
        authorization.dynamicArguments.some((argument, index) => {
          const provedArgument = proof.dynamicArguments[index];
          return (
            argument.sourceStart !== provedArgument.sourceStart ||
            argument.sourceEnd !== provedArgument.sourceEnd ||
            argument.source !== provedArgument.source ||
            argument.sourceSha256 !== provedArgument.sourceSha256
          );
        })
      ) {
        fail("proved direct async batch disagrees with its executable authorization");
      }
    }
  }

  assertExactKeys(output.limits, COMPILER_LIMIT_FIELDS, "compiler platform limits");
  for (const field of COMPILER_LIMIT_FIELDS) {
    requirePositiveInteger(output.limits[field], `compiler platform limit ${field}`);
  }

  assertExactKeys(output.toolchain, ["abi", "compiler", "convex", "esbuild", "oxc"], "toolchain");
  if (
    output.toolchain.abi !== convexWasmCompilerAbiVersion ||
    output.toolchain.compiler !== convexWasmCompilerOutputKind ||
    output.toolchain.oxc !== convexWasmCompilerOxcVersion
  ) {
    fail("compiler toolchain does not match the output contract");
  }
  requireString(output.toolchain.convex, "toolchain convex version");
  requireString(output.toolchain.esbuild, "toolchain esbuild version");
  if (
    expectedGraphToolchain !== undefined &&
    (output.toolchain.convex !== expectedGraphToolchain.convex ||
      output.toolchain.esbuild !== expectedGraphToolchain.esbuild)
  ) {
    fail("compiler toolchain does not match the source graph toolchain");
  }

  assertExactKeys(
    output.target,
    ["entry", "export", "handlerSource", "registrationKind"],
    "compiler target"
  );
  requireString(output.target.entry, "compiler target entry");
  requireString(output.target.export, "compiler target export");
  if (typeof output.target.handlerSource !== "string") {
    fail("compiler target handlerSource must be a string");
  }
  if (
    !["internalMutation", "internalQuery", "mutation", "query"].includes(
      output.target.registrationKind
    )
  ) {
    fail(
      `compiler target registrationKind is unsupported: ${JSON.stringify(output.target.registrationKind)}`
    );
  }

  const artifact = output.generatedJavascriptArtifact;
  if (!output.eligible) {
    if (artifact !== null) {
      fail("fallback compiler output must not contain generated JavaScript");
    }
    return;
  }
  assertExactKeys(
    artifact,
    ["bytes", "cachePath", "sha256", "source", "suggestedPath"],
    "generated JavaScript artifact"
  );
  const bytes = requirePositiveInteger(artifact.bytes, "generated JavaScript artifact bytes");
  const sha256 = requireSha256(artifact.sha256, "generated JavaScript artifact sha256");
  requireString(artifact.suggestedPath, "generated JavaScript artifact suggestedPath");
  if (typeof artifact.source === "string") {
    if (
      artifact.cachePath !== null ||
      Buffer.byteLength(artifact.source) !== bytes ||
      createHash("sha256").update(artifact.source).digest("hex") !== sha256
    ) {
      fail("generated JavaScript bytes do not match its identity");
    }
    return;
  }
  const expectedCachePath = `generated-sources/${sha256.slice(0, 2)}/${sha256}.js`;
  if (artifact.source !== null || artifact.cachePath !== expectedCachePath) {
    fail("cached generated JavaScript has an invalid content-addressed path");
  }
}

export function validateConvexWasmCompilerOutputContract(output, { expectedGraphToolchain, mode }) {
  requireObject(output, "compiler output");
  if (output.kind !== convexWasmCompilerOutputKind) {
    fail(`unsupported output kind ${JSON.stringify(output.kind)}`);
  }
  if (mode !== "analysis" && mode !== "compile") {
    fail(`validation mode is unsupported: ${JSON.stringify(mode)}`);
  }
  if (mode === "analysis") {
    for (const field of [...COMPILE_OUTPUT_FIELDS, ...OPTIONAL_COMPILE_OUTPUT_FIELDS]) {
      if (Object.hasOwn(output, field)) {
        fail(`analysis compiler output must omit compile-only field ${field}`);
      }
    }
  } else if (Object.hasOwn(output, "analysisSummary")) {
    fail("compile compiler output must omit analysis-only field analysisSummary");
  }
  const expectedFields = [
    ...COMMON_OUTPUT_FIELDS,
    ...(mode === "analysis" ? ANALYSIS_OUTPUT_FIELDS : COMPILE_OUTPUT_FIELDS),
    ...(mode === "compile" && Object.hasOwn(output, "effectExecutionMode")
      ? ["effectExecutionMode"]
      : []),
    ...(Object.hasOwn(output, "diagnosticCensusIds") ? ["diagnosticCensusIds"] : []),
    ...(Object.hasOwn(output, "appliedDependencyAdapters") ? ["appliedDependencyAdapters"] : []),
    ...(Object.hasOwn(output, "appliedRegistrationAdapter") ? ["appliedRegistrationAdapter"] : []),
  ];
  assertExactKeys(output, expectedFields, `${mode} compiler output`);
  validateCommonEnvelope(output);
  const provedBatchesById = validateProvedDirectAsyncBatches(output.provedDirectAsyncBatches);
  if (Object.hasOwn(output, "diagnosticCensusIds") && !Array.isArray(output.diagnosticCensusIds)) {
    fail("diagnosticCensusIds must be an array");
  }
  if (mode === "compile") {
    validateCompileEnvelope(output, expectedGraphToolchain, provedBatchesById);
  }
  return output;
}
