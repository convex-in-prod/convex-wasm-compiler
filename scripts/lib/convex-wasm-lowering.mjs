import { createHash } from "node:crypto";

import {
  convexWasmIntrinsicHardeningPolicy,
  convexWasmIntrinsicHardeningPolicySha256,
  convexWasmIntrinsicHardeningSourceSha256,
  renderConvexWasmIntrinsicHardeningPrelude,
} from "./convex-wasm-intrinsic-hardening.mjs";
import {
  assertConvexWasmTargetRuntimeSurface,
  convexWasmApplicationGlobalThisBinding,
  convexWasmApplicationInstallRuntimeSupportBinding,
  convexWasmTargetRuntimeSurfacePolicy,
  convexWasmTargetRuntimeSurfacePolicySha256,
  renderConvexWasmApplicationGlobalFacade,
  renderConvexWasmTargetRuntimeGlobalPrelude,
} from "./convex-wasm-runtime-surface.mjs";
import { renderConvexWasmRuntimeSupportUnit } from "./convex-wasm-runtime-support.mjs";

const LOWERING_FORMAT = "convex-wasm-lowered-guest-v37";
const COMMIT_TS_PLACEHOLDER_EXPORT_NAME = "__convexWasmSdkCommitTsPlaceholder";
const OPAQUE_ABI_VERSION = 3;
const CAPABILITY_REQUEST_ABI_VERSION = 4;
const BLOCKING_EFFECT_EXECUTION_MODE = "blocking-fiber";
const GUEST_PROMISE_EFFECT_EXECUTION_MODE = "guest-promise-event-loop";
const EFFECT_EXECUTION_MODES = new Set([
  BLOCKING_EFFECT_EXECUTION_MODE,
  GUEST_PROMISE_EFFECT_EXECUTION_MODE,
]);
const SUPPORTED_RUNTIME_INPUTS = new Set(["invocationUnixTimestampMs"]);
const DATABASE_WRITE_OPERATION_KINDS = new Set([
  "databaseDelete",
  "databaseInsert",
  "databasePatch",
  "databaseReplace",
]);
const ESBUILD_IDENTIFIER_SOURCE = String.raw`[A-Za-z_$][A-Za-z0-9_$]*`;
const ESBUILD_COPY_PROPERTIES_HELPER_PROVENANCE_PATTERN = new RegExp(
  String.raw`(?:\bvar\s+|,\s*)${ESBUILD_IDENTIFIER_SOURCE}\s*=\s*\(\s*${ESBUILD_IDENTIFIER_SOURCE}\s*,\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*,\s*${ESBUILD_IDENTIFIER_SOURCE}\s*,\s*${ESBUILD_IDENTIFIER_SOURCE}\s*\)\s*=>\s*\{(?:[^\r\n]*\r?\n\s*){0,3}for\s*\(\s*let\s+${ESBUILD_IDENTIFIER_SOURCE}\s+of\s+${ESBUILD_IDENTIFIER_SOURCE}\(\s*\1\s*\)\s*\)`,
  "gu"
);
const ESBUILD_COPY_PROPERTIES_GETTER_PATTERNS = Object.freeze([
  Object.freeze({
    candidate: new RegExp(
      String.raw`for\s*\(\s*let\s+(${ESBUILD_IDENTIFIER_SOURCE})\s+of\s+${ESBUILD_IDENTIFIER_SOURCE}\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*\)\s*\)\s*\r?\n\s*if\s*\(\s*!${ESBUILD_IDENTIFIER_SOURCE}\.call\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*,\s*\1\s*\)\s*&&\s*\1\s*!==\s*${ESBUILD_IDENTIFIER_SOURCE}\s*\)\s*\r?\n\s*${ESBUILD_IDENTIFIER_SOURCE}\(\s*\3\s*,\s*\1\s*,\s*\{\s*get\s*:`,
      "gu"
    ),
    rewrite: new RegExp(
      String.raw`(for\s*\(\s*let\s+(${ESBUILD_IDENTIFIER_SOURCE})\s+of\s+${ESBUILD_IDENTIFIER_SOURCE}\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*\)\s*\)\s*\r?\n\s*if\s*\(\s*!${ESBUILD_IDENTIFIER_SOURCE}\.call\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*,\s*\2\s*\)\s*&&\s*\2\s*!==\s*${ESBUILD_IDENTIFIER_SOURCE}\s*\)\s*\r?\n\s*${ESBUILD_IDENTIFIER_SOURCE}\(\s*\4\s*,\s*\2\s*,\s*\{\s*get\s*:\s*)\(\)\s*=>\s*\3\[\s*\2\s*\]`,
      "gu"
    ),
  }),
  Object.freeze({
    candidate: new RegExp(
      String.raw`for\s*\(\s*let\s+(${ESBUILD_IDENTIFIER_SOURCE})\s+of\s+${ESBUILD_IDENTIFIER_SOURCE}\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*\)\s*\)\s*\r?\n\s*!${ESBUILD_IDENTIFIER_SOURCE}\.call\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*,\s*\1\s*\)\s*&&\s*\1\s*!==\s*${ESBUILD_IDENTIFIER_SOURCE}\s*&&\s*${ESBUILD_IDENTIFIER_SOURCE}\(\s*\3\s*,\s*\1\s*,\s*\{\s*get\s*:`,
      "gu"
    ),
    rewrite: new RegExp(
      String.raw`(for\s*\(\s*let\s+(${ESBUILD_IDENTIFIER_SOURCE})\s+of\s+${ESBUILD_IDENTIFIER_SOURCE}\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*\)\s*\)\s*\r?\n\s*!${ESBUILD_IDENTIFIER_SOURCE}\.call\(\s*(${ESBUILD_IDENTIFIER_SOURCE})\s*,\s*\2\s*\)\s*&&\s*\2\s*!==\s*${ESBUILD_IDENTIFIER_SOURCE}\s*&&\s*${ESBUILD_IDENTIFIER_SOURCE}\(\s*\4\s*,\s*\2\s*,\s*\{\s*get\s*:\s*)\(\)\s*=>\s*\3\[\s*\2\s*\]`,
      "gu"
    ),
  }),
]);
const COMPILE_PROFILE_SOURCE_MAP_COMMENT =
  "//# sourceMappingURL=convex-wasm-compile-profile.js.map";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertIdentifier(value, description) {
  if (
    typeof value !== "string" ||
    !/^[$_\p{ID_Start}](?:[$_\p{ID_Continue}]|\u{200c}|\u{200d})*$/u.test(value)
  ) {
    throw new Error(
      `${description} must be a JavaScript identifier, received ${JSON.stringify(value)}.`
    );
  }
}

function assertStringArray(values, description) {
  if (!Array.isArray(values) || values.some((value) => typeof value !== "string")) {
    throw new Error(`${description} must be an array of strings.`);
  }
}

function preserveEsbuildLiveExportBindings(compileProfileJavascript) {
  const helperCount = [
    ...compileProfileJavascript.matchAll(ESBUILD_COPY_PROPERTIES_HELPER_PROVENANCE_PATTERN),
  ].length;
  const candidateCount = ESBUILD_COPY_PROPERTIES_GETTER_PATTERNS.reduce(
    (count, { candidate }) => count + [...compileProfileJavascript.matchAll(candidate)].length,
    0
  );
  let replacementCount = 0;
  let transformed = compileProfileJavascript;
  for (const { rewrite } of ESBUILD_COPY_PROPERTIES_GETTER_PATTERNS) {
    transformed = transformed.replace(rewrite, (_match, prefix, propertyName, sourceObject) => {
      replacementCount += 1;
      return (
        prefix +
        `((__convexWasmObject, __convexWasmProperty) => ` +
        `() => __convexWasmObject[__convexWasmProperty])(${sourceObject}, ${propertyName})`
      );
    });
  }
  if (helperCount !== candidateCount) {
    throw new Error(
      `compileProfileJavascript contains ${helperCount} esbuild live-export helper declarations ` +
        `but ${candidateCount} canonical getter candidates; helper shape must remain canonical.`
    );
  }
  if (candidateCount !== replacementCount) {
    throw new Error(
      `compileProfileJavascript contains ${candidateCount} esbuild live-export helper candidates ` +
        `but ${replacementCount} recognized getters; helper shape must remain canonical.`
    );
  }
  if (replacementCount > 1) {
    throw new Error(
      `compileProfileJavascript must contain at most one recognized esbuild live-export helper; ` +
        `received ${replacementCount}.`
    );
  }
  if (
    compileProfileJavascript.includes(COMPILE_PROFILE_SOURCE_MAP_COMMENT) &&
    replacementCount !== 1
  ) {
    throw new Error(
      `compileProfileJavascript must contain exactly one recognized esbuild live-export helper; ` +
        `received ${replacementCount}.`
    );
  }
  return transformed;
}

function normalizeRuntimeInputs(runtimeInputs) {
  assertStringArray(runtimeInputs, "runtimeInputs");
  const normalized = [...new Set(runtimeInputs)].sort();
  if (normalized.length !== runtimeInputs.length) {
    throw new Error("runtimeInputs must not contain duplicates.");
  }
  for (const runtimeInput of normalized) {
    if (!SUPPORTED_RUNTIME_INPUTS.has(runtimeInput)) {
      throw new Error(`Unsupported runtime input ${JSON.stringify(runtimeInput)}.`);
    }
  }
  return normalized;
}

function normalizeIdentityValue(value, description) {
  if (Array.isArray(value)) {
    return value.map((entry, index) => normalizeIdentityValue(entry, `${description}[${index}]`));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, normalizeIdentityValue(value[key], `${description}.${key}`)])
    );
  }
  if (["boolean", "number", "string"].includes(typeof value) || value === null) return value;
  throw new Error(`${description} contains a non-JSON identity value.`);
}

function directBatchResultKind(operation) {
  if (
    operation.kind === "databaseIndexQuery" &&
    (operation.terminal === "collect" || operation.terminal === "take")
  ) {
    return "hostArray";
  }
  if (
    operation.kind === "databasePatch" ||
    operation.kind === "databaseReplace" ||
    operation.kind === "databaseDelete"
  ) {
    return "undefined";
  }
  return "hostValue";
}

function directBatchArgumentCount(operation) {
  if (operation.kind === "authenticationGetUserIdentity") {
    return 0;
  }
  if (
    operation.kind === "databasePatch" ||
    operation.kind === "databaseReplace" ||
    operation.kind === "schedulerRunAfter" ||
    operation.kind === "schedulerRunAt"
  ) {
    return 2;
  }
  if (operation.kind === "databaseIndexQuery") {
    return operation.constraints.length + (operation.limitArgumentIndex === null ? 0 : 1);
  }
  return 1;
}

function normalizeDirectAsyncBatches(batches, operations) {
  if (!Array.isArray(batches)) {
    throw new Error("directAsyncBatches must be an array.");
  }
  const operationsById = new Map(operations.map((operation) => [operation.id, operation]));
  const ids = new Set();
  const generatedSpans = new Set();
  const normalized = batches.map((batch, index) => {
    if (batch === null || typeof batch !== "object" || Array.isArray(batch)) {
      throw new Error(`directAsyncBatches[${index}] must be an object.`);
    }
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
    const shapeKeys =
      batch.kind === "singleEffectMap"
        ? [
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
          ]
        : batch.kind === "fixedEffectArray"
          ? ["children"]
          : [];
    const expectedKeys = [...commonKeys, ...shapeKeys].sort();
    if (
      Object.keys(batch).length !== expectedKeys.length ||
      Object.keys(batch)
        .sort()
        .some((key, keyIndex) => key !== expectedKeys[keyIndex])
    ) {
      throw new Error(`directAsyncBatches[${index}] has unsupported fields.`);
    }
    if (
      typeof batch.id !== "string" ||
      !/^batch_[0-9a-f]{16}$/u.test(batch.id) ||
      ids.has(batch.id)
    ) {
      throw new Error(`directAsyncBatches[${index}].id is invalid or duplicated.`);
    }
    ids.add(batch.id);
    if (batch.kind !== "singleEffectMap" && batch.kind !== "fixedEffectArray") {
      throw new Error(`directAsyncBatches[${index}].kind is unsupported.`);
    }
    for (const field of ["start", "end", "generatedStart", "generatedEnd"]) {
      if (!Number.isSafeInteger(batch[field]) || batch[field] < 0) {
        throw new Error(`directAsyncBatches[${index}].${field} must be a byte offset.`);
      }
    }
    if (batch.start >= batch.end || batch.generatedStart >= batch.generatedEnd) {
      throw new Error(`directAsyncBatches[${index}] has inconsistent source spans.`);
    }
    for (const field of ["line", "column"]) {
      if (!Number.isSafeInteger(batch[field]) || batch[field] < 1) {
        throw new Error(`directAsyncBatches[${index}].${field} must be one-based.`);
      }
    }
    if (typeof batch.file !== "string" || batch.file.length === 0) {
      throw new Error(`directAsyncBatches[${index}].file must be a non-empty string.`);
    }
    if (
      typeof batch.source !== "string" ||
      batch.source.length === 0 ||
      sha256(batch.source) !== batch.sourceSha256 ||
      Buffer.byteLength(batch.source) !== batch.end - batch.start
    ) {
      throw new Error(
        `directAsyncBatches[${index}] original source does not match its compiler authorization.`
      );
    }
    for (const field of ["sourceSha256", "generatedSourceSha256"]) {
      if (typeof batch[field] !== "string" || !/^[0-9a-f]{64}$/u.test(batch[field])) {
        throw new Error(`directAsyncBatches[${index}].${field} must be a SHA-256 digest.`);
      }
    }
    // generated* fields authenticate the compiler's pre-lowering source. Rust consumes that
    // source before returning bundleCode, so only their schema and internal containment apply here.
    const sourceBytes = Buffer.from(batch.source);
    let shape;
    if (batch.kind === "singleEffectMap") {
      for (const field of [
        "callbackStart",
        "callbackEnd",
        "operationStart",
        "operationEnd",
        "generatedIteratorStart",
        "generatedIteratorEnd",
      ]) {
        if (!Number.isSafeInteger(batch[field]) || batch[field] < 0) {
          throw new Error(`directAsyncBatches[${index}].${field} must be a byte offset.`);
        }
      }
      if (
        batch.callbackStart >= batch.callbackEnd ||
        batch.operationStart >= batch.operationEnd ||
        batch.start >= batch.callbackStart ||
        batch.callbackStart > batch.operationStart ||
        batch.operationEnd > batch.callbackEnd ||
        batch.callbackEnd > batch.end ||
        batch.generatedIteratorStart >= batch.generatedIteratorEnd ||
        batch.generatedStart > batch.generatedIteratorStart ||
        batch.generatedIteratorEnd > batch.generatedEnd
      ) {
        throw new Error(`directAsyncBatches[${index}] has inconsistent mapped source spans.`);
      }
      if (typeof batch.callbackParameter !== "string" || batch.callbackParameter.length === 0) {
        throw new Error(
          `directAsyncBatches[${index}].callbackParameter must be a non-empty string.`
        );
      }
      if (typeof batch.helperContinuationPrebound !== "boolean") {
        throw new Error(
          `directAsyncBatches[${index}].helperContinuationPrebound must be a boolean.`
        );
      }
      assertIdentifier(batch.callbackParameter, `directAsyncBatches[${index}].callbackParameter`);
      if (
        batch.argumentField !== null &&
        (typeof batch.argumentField !== "string" || batch.argumentField.length === 0)
      ) {
        throw new Error(
          `directAsyncBatches[${index}].argumentField must be null or a non-empty string.`
        );
      }
      if (
        typeof batch.generatedIteratorSha256 !== "string" ||
        !/^[0-9a-f]{64}$/u.test(batch.generatedIteratorSha256)
      ) {
        throw new Error(
          `directAsyncBatches[${index}].generatedIteratorSha256 must be a SHA-256 digest.`
        );
      }
      const operation = requireDirectBatchOperation(
        operationsById,
        batch.operationId,
        batch.operationKind,
        `directAsyncBatches[${index}]`
      );
      if (
        batch.resultKind !== directBatchResultKind(operation) ||
        !Array.isArray(batch.dynamicArguments) ||
        batch.dynamicArguments.length !== directBatchArgumentCount(operation)
      ) {
        throw new Error(
          `directAsyncBatches[${index}] result or argument contract disagrees with its operation descriptor.`
        );
      }
      shape = {
        dynamicArguments: normalizeDirectBatchArguments({
          allowExactDuplicates: batch.helperContinuationPrebound,
          argumentsValue: batch.dynamicArguments,
          description: `directAsyncBatches[${index}].dynamicArguments`,
          generatedEnd: batch.generatedEnd,
          generatedStart: batch.generatedStart,
          operationEnd: batch.operationEnd,
          operationStart: batch.operationStart,
          sourceBytes,
          sourceStart: batch.start,
        }),
      };
    } else {
      if (!Array.isArray(batch.children) || batch.children.length === 0) {
        throw new Error(`directAsyncBatches[${index}].children must be a non-empty array.`);
      }
      const children = batch.children.map((child, childIndex) =>
        normalizeFixedDirectBatchChild({
          batch,
          child,
          description: `directAsyncBatches[${index}].children[${childIndex}]`,
          operationsById,
          sourceBytes,
        })
      );
      for (let childIndex = 1; childIndex < children.length; childIndex += 1) {
        if (
          children[childIndex - 1].end > children[childIndex].start ||
          children[childIndex - 1].generatedEnd > children[childIndex].generatedStart
        ) {
          throw new Error(`directAsyncBatches[${index}] fixed children overlap or changed order.`);
        }
      }
      shape = { children };
    }
    const generatedSpan = `${batch.generatedStart}:${batch.generatedEnd}`;
    if (generatedSpans.has(generatedSpan)) {
      throw new Error(`directAsyncBatches[${index}] duplicates a generated source span.`);
    }
    generatedSpans.add(generatedSpan);
    return { ...batch, ...shape };
  });
  normalized.sort(
    (left, right) =>
      left.generatedStart - right.generatedStart || left.generatedEnd - right.generatedEnd
  );
  return normalized;
}

function requireDirectBatchOperation(operationsById, operationId, operationKind, description) {
  const operation = operationsById.get(operationId);
  if (operation === undefined || operation.kind !== operationKind) {
    throw new Error(`${description} does not identify its admitted operation descriptor.`);
  }
  if (
    operation.kind === "authenticationGetUserIdentity" ||
    operation.kind === "databaseNormalizeId"
  ) {
    throw new Error(
      `${description} operation kind is not authorized for source Promise.all lowering.`
    );
  }
  return operation;
}

function normalizeDirectBatchArguments({
  allowExactDuplicates = false,
  argumentsValue,
  description,
  generatedEnd,
  generatedStart,
  operationEnd,
  operationStart,
  sourceBytes,
  sourceStart,
}) {
  const normalized = argumentsValue.map((argument, argumentIndex) => {
    const argumentDescription = `${description}[${argumentIndex}]`;
    if (
      argument === null ||
      typeof argument !== "object" ||
      Array.isArray(argument) ||
      Object.keys(argument).sort().join(",") !==
        [
          "generatedEnd",
          "generatedSha256",
          "generatedStart",
          "source",
          "sourceEnd",
          "sourceSha256",
          "sourceStart",
        ].join(",")
    ) {
      throw new Error(`${argumentDescription} has unsupported fields.`);
    }
    for (const field of ["sourceStart", "sourceEnd", "generatedStart", "generatedEnd"]) {
      if (!Number.isSafeInteger(argument[field]) || argument[field] < 0) {
        throw new Error(`${argumentDescription}.${field} must be a byte offset.`);
      }
    }
    if (
      argument.sourceStart < operationStart ||
      argument.sourceStart >= argument.sourceEnd ||
      argument.sourceEnd > operationEnd ||
      argument.generatedStart < generatedStart ||
      argument.generatedStart >= argument.generatedEnd ||
      argument.generatedEnd > generatedEnd
    ) {
      throw new Error(`${argumentDescription} has inconsistent spans.`);
    }
    for (const field of ["sourceSha256", "generatedSha256"]) {
      if (typeof argument[field] !== "string" || !/^[0-9a-f]{64}$/u.test(argument[field])) {
        throw new Error(`${argumentDescription}.${field} must be a SHA-256 digest.`);
      }
    }
    if (
      typeof argument.source !== "string" ||
      argument.source.length === 0 ||
      sha256(argument.source) !== argument.sourceSha256 ||
      sha256(
        sourceBytes.subarray(argument.sourceStart - sourceStart, argument.sourceEnd - sourceStart)
      ) !== argument.sourceSha256
    ) {
      throw new Error(`${argumentDescription} source does not match its authorization.`);
    }
    return { ...argument };
  });
  for (let argumentIndex = 1; argumentIndex < normalized.length; argumentIndex += 1) {
    const previous = normalized[argumentIndex - 1];
    const current = normalized[argumentIndex];
    const exactDuplicate =
      allowExactDuplicates &&
      previous.sourceStart === current.sourceStart &&
      previous.sourceEnd === current.sourceEnd &&
      previous.source === current.source &&
      previous.sourceSha256 === current.sourceSha256 &&
      previous.generatedStart === current.generatedStart &&
      previous.generatedEnd === current.generatedEnd &&
      previous.generatedSha256 === current.generatedSha256;
    if (
      !exactDuplicate &&
      (previous.sourceEnd > current.sourceStart || previous.generatedEnd > current.generatedStart)
    ) {
      throw new Error(`${description} changed source or generated argument order.`);
    }
  }
  return normalized;
}

function normalizeFixedDirectBatchChild({
  batch,
  child,
  description,
  operationsById,
  sourceBytes,
}) {
  if (
    child === null ||
    typeof child !== "object" ||
    Array.isArray(child) ||
    Object.keys(child).sort().join(",") !==
      [
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
      ].join(",")
  ) {
    throw new Error(`${description} has unsupported fields.`);
  }
  if (typeof child.helperContinuationPrebound !== "boolean") {
    throw new Error(`${description}.helperContinuationPrebound must be a boolean.`);
  }
  for (const field of [
    "start",
    "end",
    "operationStart",
    "operationEnd",
    "generatedStart",
    "generatedEnd",
  ]) {
    if (!Number.isSafeInteger(child[field]) || child[field] < 0) {
      throw new Error(`${description}.${field} must be a byte offset.`);
    }
  }
  if (
    child.start >= child.end ||
    child.operationStart < child.start ||
    child.operationStart >= child.operationEnd ||
    child.operationEnd > child.end ||
    child.start < batch.start ||
    child.end > batch.end ||
    child.generatedStart >= child.generatedEnd ||
    child.generatedStart < batch.generatedStart ||
    child.generatedEnd > batch.generatedEnd
  ) {
    throw new Error(`${description} has inconsistent spans.`);
  }
  for (const field of ["sourceSha256", "generatedSourceSha256"]) {
    if (typeof child[field] !== "string" || !/^[0-9a-f]{64}$/u.test(child[field])) {
      throw new Error(`${description}.${field} must be a SHA-256 digest.`);
    }
  }
  if (
    typeof child.source !== "string" ||
    child.source.length === 0 ||
    sha256(child.source) !== child.sourceSha256 ||
    sha256(sourceBytes.subarray(child.start - batch.start, child.end - batch.start)) !==
      child.sourceSha256
  ) {
    throw new Error(`${description} source does not match its authorization.`);
  }
  const operation = requireDirectBatchOperation(
    operationsById,
    child.operationId,
    child.operationKind,
    description
  );
  if (
    child.resultKind !== directBatchResultKind(operation) ||
    !Array.isArray(child.dynamicArguments) ||
    child.dynamicArguments.length !== directBatchArgumentCount(operation)
  ) {
    throw new Error(`${description} result or argument contract disagrees with its operation.`);
  }
  return {
    ...child,
    dynamicArguments: normalizeDirectBatchArguments({
      allowExactDuplicates: child.helperContinuationPrebound,
      argumentsValue: child.dynamicArguments,
      description: `${description}.dynamicArguments`,
      generatedEnd: child.generatedEnd,
      generatedStart: child.generatedStart,
      operationEnd: child.operationEnd,
      operationStart: child.operationStart,
      sourceBytes,
      sourceStart: batch.start,
    }),
  };
}

function normalizeOperations(operations) {
  if (!Array.isArray(operations)) {
    throw new Error("operations must be an array.");
  }
  const ids = new Set();
  const normalized = operations.map((operation, index) => {
    if (operation === null || typeof operation !== "object" || Array.isArray(operation)) {
      throw new Error(`operations[${index}] must be an object.`);
    }
    const { id, kind } = operation;
    if (!Number.isSafeInteger(id) || id < 1 || id > 65_535) {
      throw new Error(`operations[${index}].id must be between 1 and 65535.`);
    }
    if (ids.has(id)) {
      throw new Error(`Duplicate operation ID ${id}.`);
    }
    ids.add(id);
    if (kind === "authenticationGetUserIdentity") {
      if (Object.keys(operation).some((key) => !["id", "kind"].includes(key))) {
        throw new Error(
          `operations[${index}] is not a valid authenticationGetUserIdentity operation.`
        );
      }
      return { id, kind };
    }
    if (kind === "functionHandleCreate") {
      if (Object.keys(operation).some((key) => !["id", "kind"].includes(key))) {
        throw new Error(`operations[${index}] is not a valid functionHandleCreate operation.`);
      }
      return { id, kind };
    }
    if (kind === "hostSecretVerify") {
      if (
        operation.contractVersion !== 1 ||
        typeof operation.selector !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(operation.selector) ||
        Object.keys(operation).some(
          (key) => !["contractVersion", "id", "kind", "selector"].includes(key)
        )
      ) {
        throw new Error(`operations[${index}] is not a valid hostSecretVerify operation.`);
      }
      return { contractVersion: 1, id, kind, selector: operation.selector };
    }
    if (kind === "databaseNormalizeId") {
      if (
        typeof operation.table !== "string" ||
        operation.table.length === 0 ||
        Object.keys(operation).some((key) => !["id", "kind", "table"].includes(key))
      ) {
        throw new Error(`operations[${index}] is not a valid databaseNormalizeId operation.`);
      }
      return { id, kind, table: operation.table };
    }
    if (kind === "databaseGet") {
      if (
        typeof operation.table !== "string" ||
        operation.table.length === 0 ||
        Object.keys(operation).some((key) => !["id", "kind", "table"].includes(key))
      ) {
        throw new Error(`operations[${index}] is not a valid databaseGet operation.`);
      }
      return { id, kind, table: operation.table };
    }
    if (DATABASE_WRITE_OPERATION_KINDS.has(kind)) {
      if (
        typeof operation.table !== "string" ||
        operation.table.length === 0 ||
        Object.keys(operation).some((key) => !["id", "kind", "table"].includes(key))
      ) {
        throw new Error(`operations[${index}] is not a valid ${kind} operation.`);
      }
      return { id, kind, table: operation.table };
    }
    if (kind === "schedulerRunAfter" || kind === "schedulerRunAt") {
      if (
        typeof operation.functionReference !== "string" ||
        operation.functionReference.length === 0 ||
        Object.keys(operation).some((key) => !["functionReference", "id", "kind"].includes(key))
      ) {
        throw new Error(`operations[${index}] is not a valid ${kind} operation.`);
      }
      return { functionReference: operation.functionReference, id, kind };
    }
    if (kind !== "databaseIndexQuery") {
      throw new Error(`operations[${index}].kind is unsupported.`);
    }
    const {
      table,
      index: indexName,
      constraints,
      limit,
      limitArgumentIndex,
      order,
      terminal,
    } = operation;
    const normalizedLimitArgumentIndex =
      limitArgumentIndex === undefined ? null : limitArgumentIndex;
    for (const [name, value] of [
      ["table", table],
      ["index", indexName],
    ]) {
      if (typeof value !== "string" || value.length === 0) {
        throw new Error(`operations[${index}].${name} must be a non-empty string.`);
      }
    }
    if (!Array.isArray(constraints) || constraints.length === 0) {
      throw new Error(`operations[${index}].constraints must be a non-empty array.`);
    }
    const fields = new Set();
    let sawRange = false;
    const normalizedConstraints = constraints.map((constraint, constraintIndex) => {
      if (
        constraint === null ||
        typeof constraint !== "object" ||
        Array.isArray(constraint) ||
        Object.keys(constraint).sort().join(",") !== "field,operator" ||
        typeof constraint.field !== "string" ||
        constraint.field.length === 0 ||
        !["eq", "gt", "gte", "lt", "lte"].includes(constraint.operator)
      ) {
        throw new Error(`operations[${index}].constraints[${constraintIndex}] is invalid.`);
      }
      if (fields.has(constraint.field)) {
        throw new Error(`operations[${index}].constraint fields must be unique.`);
      }
      fields.add(constraint.field);
      if (constraint.operator === "eq") {
        if (sawRange) {
          throw new Error(`operations[${index}] equality constraints must precede the range.`);
        }
      } else {
        if (sawRange || constraintIndex + 1 !== constraints.length) {
          throw new Error(`operations[${index}] supports at most one final range constraint.`);
        }
        sawRange = true;
      }
      return { ...constraint };
    });
    if (order !== "ascending" && order !== "descending") {
      throw new Error(`operations[${index}].order must be "ascending" or "descending".`);
    }
    if (
      terminal !== "collect" &&
      terminal !== "first" &&
      terminal !== "stream" &&
      terminal !== "unique"
    ) {
      throw new Error(
        `operations[${index}].terminal must be "collect", "first", "stream", or "unique".`
      );
    }
    if (terminal === "collect") {
      if (limit !== null && (!Number.isSafeInteger(limit) || limit < 1 || limit > 100_000)) {
        throw new Error(
          `operations[${index}].limit must be null or between 1 and 100000 for collect.`
        );
      }
      if (
        normalizedLimitArgumentIndex !== null &&
        (!Number.isSafeInteger(normalizedLimitArgumentIndex) ||
          normalizedLimitArgumentIndex !== normalizedConstraints.length ||
          limit !== null)
      ) {
        throw new Error(
          `operations[${index}].limitArgumentIndex must follow constraints as the only collect limit.`
        );
      }
    } else if (limit !== null || normalizedLimitArgumentIndex !== null) {
      throw new Error(`operations[${index}] must not have a limit for a non-collect terminal.`);
    }
    if (
      Object.keys(operation).some(
        (key) =>
          ![
            "constraints",
            "id",
            "index",
            "kind",
            "limit",
            "limitArgumentIndex",
            "order",
            "table",
            "terminal",
          ].includes(key)
      )
    ) {
      throw new Error(`operations[${index}] has unsupported fields.`);
    }
    return {
      constraints: normalizedConstraints,
      id,
      kind,
      table,
      index: indexName,
      limit,
      limitArgumentIndex: normalizedLimitArgumentIndex,
      order,
      terminal,
    };
  });
  normalized.sort((left, right) => left.id - right.id);
  return normalized;
}

function renderOperationLookup(operations) {
  const indexBranches = operations
    .filter((operation) => operation.kind === "databaseIndexQuery")
    .map((operation) => {
      const comparisons = [
        `table === ${JSON.stringify(operation.table)}`,
        `index === ${JSON.stringify(operation.index)}`,
        `constraintFields.length === ${operation.constraints.length}`,
        `constraintOperators.length === ${operation.constraints.length}`,
        ...operation.constraints.flatMap((constraint, index) => [
          `constraintFields[${index}] === ${JSON.stringify(constraint.field)}`,
          `constraintOperators[${index}] === ${JSON.stringify(constraint.operator)}`,
        ]),
        `normalizedOrder === ${JSON.stringify(operation.order)}`,
        `normalizedTerminal === ${JSON.stringify(operation.terminal)}`,
        operation.limitArgumentIndex === null
          ? `limit === ${JSON.stringify(operation.limit)}`
          : `terminal === "take" && Number.isSafeInteger(limit) && limit >= 1 && limit <= 100000`,
      ];
      return `  if (${comparisons.join(" && ")}) return ${operation.id};`;
    });
  const getBranches = operations
    .filter((operation) => operation.kind === "databaseGet")
    .map(
      (operation) => `  if (table === ${JSON.stringify(operation.table)}) return ${operation.id};`
    );
  const authenticationBranches = operations
    .filter((operation) => operation.kind === "authenticationGetUserIdentity")
    .map((operation) => `  return ${operation.id};`);
  const functionHandleCreateBranches = operations
    .filter((operation) => operation.kind === "functionHandleCreate")
    .map((operation) => `  return ${operation.id};`);
  const normalizeIdBranches = operations
    .filter((operation) => operation.kind === "databaseNormalizeId")
    .map(
      (operation) => `  if (table === ${JSON.stringify(operation.table)}) return ${operation.id};`
    );
  const writeBranches = operations
    .filter((operation) => DATABASE_WRITE_OPERATION_KINDS.has(operation.kind))
    .map(
      (operation) =>
        `  if (kind === ${JSON.stringify(operation.kind)} && table === ${JSON.stringify(operation.table)}) return ${operation.id};`
    );
  const schedulerBranches = operations
    .filter(
      (operation) => operation.kind === "schedulerRunAfter" || operation.kind === "schedulerRunAt"
    )
    .map(
      (operation) =>
        `  if (kind === ${JSON.stringify(operation.kind)} && reference === ${JSON.stringify(operation.functionReference)}) return ${operation.id};`
    );
  const batchArgumentCountBranches = operations.map(
    (operation) =>
      `  if (operationId === ${operation.id}) return ${directBatchArgumentCount(operation)};`
  );
  const batchResultKindBranches = operations.map(
    (operation) =>
      `  if (operationId === ${operation.id}) return ${JSON.stringify(
        directBatchResultKind(operation)
      )};`
  );
  return `function __convexIndexQueryOperationId(
  table: string,
  index: string,
  constraintFields: string[],
  constraintOperators: string[],
  order: ?string,
  terminal: string,
  limit: ?number,
): number {
  let normalizedOrder: string;
  if (order === null || order === "asc") normalizedOrder = "ascending";
  else if (order === "desc") normalizedOrder = "descending";
  else throw new Error("Convex operation was not admitted by the execution manifest");
  const normalizedTerminal: string = terminal === "take" ? "collect" : terminal;
${indexBranches.join("\n")}
  throw new Error("Convex operation was not admitted by the execution manifest");
}
function __convexDatabaseGetOperationId(table) {
${getBranches.join("\n")}
  throw new Error("Convex database get was not admitted by the execution manifest");
}
function __convexAuthenticationGetUserIdentityOperationId() {
${authenticationBranches.join("\n")}
  throw new Error("Convex authentication identity operation was not admitted by the execution manifest");
}
function __convexFunctionHandleCreateOperationId() {
${functionHandleCreateBranches.join("\n")}
  throw new Error("Convex function-handle creation was not admitted by the execution manifest");
}
function __convexDatabaseNormalizeIdOperationId(table) {
${normalizeIdBranches.join("\n")}
  throw new Error("Convex database normalizeId operation was not admitted by the execution manifest");
}
function __convexDatabaseWriteOperationId(kind, table) {
${writeBranches.join("\n")}
  throw new Error("Convex database write was not admitted by the execution manifest");
}
function __convexSchedulerOperationId(kind, functionReference) {
  const reference = __convexInternalFunctionReference(functionReference);
${schedulerBranches.join("\n")}
  throw new Error("Convex scheduler operation was not admitted by the execution manifest");
}
function __convexAsyncBatchArgumentCount(operationId) {
${batchArgumentCountBranches.join("\n")}
  throw new Error("Convex batch operation was not admitted by the execution manifest");
}
function __convexAsyncBatchResultKind(operationId) {
${batchResultKindBranches.join("\n")}
  throw new Error("Convex batch operation was not admitted by the execution manifest");
}
function __convexFunctionHandleAddress(functionReference) {
  if (typeof functionReference === "string") {
    if (functionReference.startsWith("function://")) {
      return {functionHandle: functionReference};
    }
    return {name: functionReference};
  }
  if (functionReference === null || typeof functionReference !== "object") {
    throw new Error(String(functionReference) + " is not a functionReference");
  }
  const name = functionReference[Symbol.for("functionName")];
  if (name) return {name};
  const reference = functionReference[Symbol.for("toReferencePath")];
  if (reference) return {reference};
  const internalReference = __convexInternalFunctionReference(functionReference);
  if (typeof internalReference === "string") return {reference: internalReference};
  throw new Error(String(functionReference) + " is not a functionReference");
}`;
}

function renderInternalFunctionReferences(operations) {
  const root = new Map();
  for (const operation of operations) {
    if (operation.kind !== "schedulerRunAfter" && operation.kind !== "schedulerRunAt") {
      continue;
    }
    const match = operation.functionReference.match(
      /^_reference\/function\/([^:]+):([A-Za-z_$][A-Za-z0-9_$]*)$/u
    );
    if (match === null) {
      throw new Error(
        `Unsupported scheduler function reference ${JSON.stringify(operation.functionReference)}.`
      );
    }
    const path = [...match[1].split("/"), match[2]];
    let current = root;
    for (const [index, segment] of path.entries()) {
      assertIdentifier(segment, "Scheduler function reference segment");
      const last = index === path.length - 1;
      const existing = current.get(segment);
      if (last) {
        if (existing !== undefined && existing !== operation.functionReference) {
          throw new Error(`Conflicting scheduler function reference segment ${segment}.`);
        }
        current.set(segment, operation.functionReference);
      } else {
        if (typeof existing === "string") {
          throw new Error(`Conflicting scheduler function reference path ${segment}.`);
        }
        if (existing === undefined) {
          current.set(segment, new Map());
        }
        current = current.get(segment);
      }
    }
  }
  const render = (node, indentation) =>
    `{${[...node.entries()]
      .map(([segment, value]) => {
        const rendered =
          typeof value === "string"
            ? `__convexFunctionReference(${JSON.stringify(value)})`
            : render(value, `${indentation}  `);
        return `\n${indentation}  ${JSON.stringify(segment)}: ${rendered},`;
      })
      .join("")}\n${indentation}}`;
  return `const __convexFunctionReferenceBrand = Symbol();
function __convexInternalFunctionReference(functionReference) {
  if (functionReference === null || typeof functionReference !== "object") return undefined;
  return functionReference[__convexFunctionReferenceBrand];
}
function __convexFunctionReference(reference) {
  return {[__convexFunctionReferenceBrand]: reference};
}
const internal = ${render(root, "")};`;
}

const ARRAY_PUSH_HELPER = `function __convexArrayPush(values: any[], value: any): void {
  // Static Hermes lowers this typed boundary to its FastArray push primitive.
  values.push(value);
}`;

function renderDocumentWrapper(documentFields, recognizeVmArrays) {
  const getters = documentFields.map(
    (field) =>
      `    get ${JSON.stringify(field)}() { return __convexReadField(handle, ${JSON.stringify(field)}); },`
  );
  return `${ARRAY_PUSH_HELPER}

let __convexLiveOpaqueValues = [];
let __convexKnownArrays = [];

function __convexMarkArray(value) {
  __convexArrayPush(__convexKnownArrays, value);
  return value;
}

function __convexFilter(values, predicate) {
  const result = [];
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (predicate(value, index, values)) __convexArrayPush(result, value);
  }
  return result;
}

function __convexIsKnownArray(value) {
${recognizeVmArrays ? "  if (__convexDynamicArrayIsArray(value)) return true;\n" : ""}  for (let index = 0; index < __convexKnownArrays.length; index += 1) {
    if (__convexKnownArrays[index] === value) return true;
  }
  return false;
}

function __convexTrackOpaqueValue(value) {
  __convexArrayPush(__convexLiveOpaqueValues, value);
  return value;
}

function __convexReleaseLiveOpaqueValues() {
  for (let index = 0; index < __convexLiveOpaqueValues.length; index += 1) {
    const value = __convexLiveOpaqueValues[index];
    const handle = value.__convexOpaqueHandle;
    if (handle > 0) {
      value.__convexOpaqueHandle = 0;
      __convexValueRelease(handle);
    }
  }
  __convexLiveOpaqueValues = [];
  __convexKnownArrays = [];
}

function __convexWrapObject(handle) {
  return __convexTrackOpaqueValue({
    __convexOpaqueHandle: handle,
${getters.join("\n")}
  });
}`;
}

function renderRequestArguments(argumentFields, arrayArgumentFields) {
  const arrayFields = new Set(arrayArgumentFields);
  const entries = argumentFields.map(
    (field) =>
      `    ${JSON.stringify(field)}: ${
        arrayFields.has(field) ? "__convexReadRequestArrayField" : "__convexReadRequestField"
      }(${JSON.stringify(field)}),`
  );
  return `const __convexArgs = {
${entries.join("\n")}
  };`;
}

function renderIntrinsicMap(intrinsics) {
  if (intrinsics === undefined) {
    return new Map();
  }
  if (intrinsics === null || typeof intrinsics !== "object" || Array.isArray(intrinsics)) {
    throw new Error("intrinsics must be an object.");
  }
  const result = new Map();
  for (const [name, intrinsic] of Object.entries(intrinsics)) {
    assertIdentifier(name, "Intrinsic function name");
    if (
      intrinsic === null ||
      typeof intrinsic !== "object" ||
      Array.isArray(intrinsic) ||
      intrinsic.kind !== "sha256" ||
      !Number.isSafeInteger(intrinsic.operationId) ||
      intrinsic.operationId < 1 ||
      intrinsic.operationId > 65_535 ||
      Object.keys(intrinsic).some((key) => key !== "kind" && key !== "operationId")
    ) {
      throw new Error(`Invalid SHA-256 intrinsic descriptor for ${name}.`);
    }
    result.set(name, {
      kind: intrinsic.kind,
      operationId: intrinsic.operationId,
    });
  }
  return result;
}

export function lowerConvexWasmExport({
  bundleCode,
  bundleSourceName,
  handlerIdentifier,
  argumentFields,
  arrayArgumentFields,
  documentFields,
  operations,
  operationsSha256,
  intrinsics,
  directAsyncBatches,
  appliedDependencyAdapters,
  sourceGraphFingerprint,
  runtimeInputs,
  effectExecutionMode = BLOCKING_EFFECT_EXECUTION_MODE,
  valueMode,
}) {
  if (typeof bundleCode !== "string" || bundleCode.length === 0) {
    throw new Error("bundleCode must be a non-empty string.");
  }
  if (typeof bundleSourceName !== "string" || bundleSourceName.length === 0) {
    throw new Error("bundleSourceName must be a non-empty string.");
  }
  assertIdentifier(handlerIdentifier, "handlerIdentifier");
  assertStringArray(argumentFields, "argumentFields");
  assertStringArray(arrayArgumentFields, "arrayArgumentFields");
  assertStringArray(documentFields, "documentFields");
  if (valueMode !== "opaque" && valueMode !== "guest-native-json") {
    throw new Error("valueMode must be opaque or guest-native-json.");
  }
  if (!EFFECT_EXECUTION_MODES.has(effectExecutionMode)) {
    throw new Error(`Unsupported effectExecutionMode ${JSON.stringify(effectExecutionMode)}.`);
  }
  if (!Array.isArray(appliedDependencyAdapters)) {
    throw new Error("appliedDependencyAdapters must be an array.");
  }
  const normalizedDependencyAdapters = normalizeIdentityValue(
    appliedDependencyAdapters,
    "appliedDependencyAdapters"
  );
  if (
    typeof sourceGraphFingerprint !== "string" ||
    !/^[a-f0-9]{64}$/.test(sourceGraphFingerprint)
  ) {
    throw new Error("sourceGraphFingerprint must be a lowercase SHA-256 digest.");
  }
  const normalizedOperations = normalizeOperations(operations);
  if (typeof operationsSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(operationsSha256)) {
    throw new Error("operationsSha256 must be a lowercase SHA-256 digest.");
  }
  const uniqueArgumentFields = [...new Set(argumentFields)].sort();
  const uniqueArrayArgumentFields = [...new Set(arrayArgumentFields)].sort();
  if (uniqueArrayArgumentFields.some((field) => !uniqueArgumentFields.includes(field))) {
    throw new Error("arrayArgumentFields must be a subset of argumentFields.");
  }
  const uniqueDocumentFields = [...new Set(documentFields)].sort();
  const normalizedDirectAsyncBatches = normalizeDirectAsyncBatches(
    directAsyncBatches,
    normalizedOperations
  );
  if (
    effectExecutionMode === GUEST_PROMISE_EFFECT_EXECUTION_MODE &&
    normalizedDirectAsyncBatches.length !== 0
  ) {
    throw new Error("guest Promise execution does not accept directAsyncBatches.");
  }
  const normalizedRuntimeInputs = normalizeRuntimeInputs(runtimeInputs);
  const normalizedIntrinsics = renderIntrinsicMap(intrinsics);
  const loweredBundle = bundleCode;
  const hasDatabaseIndexQuery = normalizedOperations.some(
    (operation) => operation.kind === "databaseIndexQuery"
  );
  const hasDatabaseQueryStream = normalizedOperations.some(
    (operation) => operation.kind === "databaseIndexQuery" && operation.terminal === "stream"
  );
  const hasHostSecretVerify = normalizedOperations.some(
    (operation) => operation.kind === "hostSecretVerify"
  );
  const requestArguments =
    valueMode === "opaque"
      ? renderRequestArguments(uniqueArgumentFields, uniqueArrayArgumentFields)
      : "const __convexArgs = __convexReadGuestRequest();";
  const setFunctionResult =
    valueMode === "opaque"
      ? "__convexSetFunctionResult(__convexResult);"
      : "__convexSetGuestFunctionResult(__convexResult);";
  const invocationRuntimeParts =
    effectExecutionMode === GUEST_PROMISE_EFFECT_EXECUTION_MODE
      ? [
          requestArguments,
          "let __convexInvocationDone = false;",
          "let __convexInvocationStatus = 0;",
          "function __convexWasmInvocationDone(): boolean { return __convexInvocationDone; }",
          "function __convexWasmInvocationStatus(): number { return __convexInvocationStatus; }",
          "globalThis.__convexWasmInvocationDone = __convexWasmInvocationDone;",
          "globalThis.__convexWasmInvocationStatus = __convexWasmInvocationStatus;",
          "try {",
          "  __convexProfileMark(15);",
          `  const __convexHandlerResult = ${handlerIdentifier}(__convexContext, __convexArgs);`,
          "  __convexGuestPromise.resolve(__convexHandlerResult).then(",
          "    (__convexResult) => {",
          "      try {",
          "        __convexProfileMark(16);",
          `        ${setFunctionResult}`,
          "        __convexProfileMark(17);",
          "      } catch (__convexError) {",
          "        __convexReleaseLiveOpaqueValues();",
          "        __convexReportThrown(__convexError);",
          "      } finally {",
          "        __convexInvocationDone = true;",
          "      }",
          "    },",
          "    (__convexError) => {",
          "      try {",
          "        __convexReleaseLiveOpaqueValues();",
          "        __convexReportThrown(__convexError);",
          "      } finally {",
          "        __convexInvocationDone = true;",
          "      }",
          "    },",
          "  );",
          "} catch (__convexError) {",
          "  try {",
          "    __convexReleaseLiveOpaqueValues();",
          "    __convexReportThrown(__convexError);",
          "  } finally {",
          "    __convexInvocationStatus = 1;",
          "    __convexInvocationDone = true;",
          "  }",
          "}",
        ]
      : [
          "try {",
          requestArguments,
          "  __convexProfileMark(15);",
          `  const __convexResult = ${handlerIdentifier}(__convexContext, __convexArgs);`,
          "  __convexProfileMark(16);",
          valueMode === "opaque"
            ? "  __convexSetFunctionResult(__convexResult);"
            : "  __convexSetGuestFunctionResult(__convexResult);",
          "  __convexProfileMark(17);",
          "} catch (__convexError) {",
          "  __convexReleaseLiveOpaqueValues();",
          "  __convexReportThrown(__convexError);",
          "}",
        ];
  const runtimeParts = [
    renderConvexWasmIntrinsicHardeningPrelude(),
    renderValueModeAbiPrelude(
      hasDatabaseIndexQuery,
      hasDatabaseQueryStream,
      hasHostSecretVerify,
      normalizedRuntimeInputs.includes("invocationUnixTimestampMs"),
      effectExecutionMode,
      valueMode
    ),
    renderOperationLookup(normalizedOperations),
    renderInternalFunctionReferences(normalizedOperations),
    renderDocumentWrapper(
      uniqueDocumentFields,
      effectExecutionMode === GUEST_PROMISE_EFFECT_EXECUTION_MODE
    ),
    loweredBundle,
    ...invocationRuntimeParts,
    "",
  ];
  const runtime = runtimeParts.join("\n");
  const bundleOffset = runtimeParts.slice(0, 4).join("\n").length + 1;
  const bundleStartLine = runtime.slice(0, bundleOffset).split("\n").length;
  const bundleEndLine = bundleStartLine + (loweredBundle.match(/\n/gu) ?? []).length;
  const loweringInputs = {
    format: LOWERING_FORMAT,
    abiVersion: OPAQUE_ABI_VERSION,
    sourceGraphFingerprint,
    handlerIdentifier,
    argumentFields: uniqueArgumentFields,
    arrayArgumentFields: uniqueArrayArgumentFields,
    documentFields: uniqueDocumentFields,
    operations: normalizedOperations,
    operationsSha256,
    runtimeInputs: normalizedRuntimeInputs,
    intrinsicHardening: {
      kind: convexWasmIntrinsicHardeningPolicy.kind,
      policySha256: convexWasmIntrinsicHardeningPolicySha256,
      sourceSha256: convexWasmIntrinsicHardeningSourceSha256,
    },
    intrinsics: Object.fromEntries([...normalizedIntrinsics].sort()),
    directAsyncBatches: normalizedDirectAsyncBatches,
    appliedDependencyAdapters: normalizedDependencyAdapters,
    valueMode,
    effectExecutionMode,
  };
  const loweringFingerprint = sha256(JSON.stringify(loweringInputs));
  return {
    bundleLayout: {
      endLine: bundleEndLine,
      sourceSha256: sha256(loweredBundle),
      startLine: bundleStartLine,
    },
    code: runtime,
    loweringFingerprint,
    loweringInputs,
    codeSha256: sha256(runtime),
  };
}

export function renderOpaqueAbiHeader() {
  return `#ifndef CONVEX_WASM_OPAQUE_ABI_V3_H
#define CONVEX_WASM_OPAQUE_ABI_V3_H

#ifdef __cplusplus
extern "C" {
#endif

#define CONVEX_WASM_IMPORT(name) \
  __attribute__((import_module("convex"), import_name(name)))

CONVEX_WASM_IMPORT("convex_invocation_unix_timestamp_ms")
double convex_invocation_unix_timestamp_ms(void);
CONVEX_WASM_IMPORT("convex_request_field")
long long convex_request_field(const char *name, int name_len);
CONVEX_WASM_IMPORT("convex_db_get")
long long convex_db_get(int operation_id, long long id_handle);
CONVEX_WASM_IMPORT("convex_db_normalize_id")
long long convex_db_normalize_id(int operation_id, long long consuming_value_handle);
CONVEX_WASM_IMPORT("convex_async_batch_take")
long long convex_async_batch_take(long long invocations);
CONVEX_WASM_IMPORT("convex_async_operation_start_take")
int convex_async_operation_start_take(int operation_id, long long arguments_handle);
CONVEX_WASM_IMPORT("convex_async_operation_wait_any")
int convex_async_operation_wait_any(void);
CONVEX_WASM_IMPORT("convex_async_operation_poll_ready")
int convex_async_operation_poll_ready(void);
CONVEX_WASM_IMPORT("convex_async_operation_completion_status")
int convex_async_operation_completion_status(int operation_handle);
CONVEX_WASM_IMPORT("convex_async_operation_completion_take")
long long convex_async_operation_completion_take(int operation_handle);
CONVEX_WASM_IMPORT("convex_async_operation_cancel_all")
int convex_async_operation_cancel_all(void);
CONVEX_WASM_IMPORT("convex_capability_current")
long long convex_capability_current(void);
CONVEX_WASM_IMPORT("convex_console_message")
int convex_console_message(
    long long capability_identity,
    int level,
    const char *messages_json,
    int messages_json_len);
CONVEX_WASM_IMPORT("convex_capability_request_decode")
long long convex_capability_request_decode(const char *request, int request_len);
CONVEX_WASM_IMPORT("convex_capability_request_release")
void convex_capability_request_release(long long request_handle);
CONVEX_WASM_IMPORT("convex_capability_start_take")
int convex_capability_start_take(
    long long capability_identity,
    long long request_handle);
CONVEX_WASM_IMPORT("convex_capability_query_stream_open_take")
int convex_capability_query_stream_open_take(
    long long capability_identity,
    long long request_handle);
CONVEX_WASM_IMPORT("convex_capability_sync_take")
long long convex_capability_sync_take(
    long long capability_identity,
    long long request_handle);
CONVEX_WASM_IMPORT("convex_crypto_subtle_digest_sha256")
void convex_crypto_subtle_digest_sha256(
    long long capability_identity,
    const char *input,
    int input_len,
    char *output,
    int output_len);
CONVEX_WASM_IMPORT("convex_crypto_get_random_values")
void convex_crypto_get_random_values(
    long long capability_identity,
    char *output,
    int output_len);
CONVEX_WASM_IMPORT("convex_crypto_random_uuid")
void convex_crypto_random_uuid(
    long long capability_identity,
    char *output,
    int output_len);
CONVEX_WASM_IMPORT("convex_math_random")
double convex_math_random(long long capability_identity);
CONVEX_WASM_IMPORT("convex_async_query_stream_open_take")
int convex_async_query_stream_open_take(int operation_id, long long arguments_handle);
CONVEX_WASM_IMPORT("convex_async_query_stream_next")
int convex_async_query_stream_next(int stream_handle);
CONVEX_WASM_IMPORT("convex_async_query_stream_close")
void convex_async_query_stream_close(int stream_handle);
CONVEX_WASM_IMPORT("convex_db_write")
long long convex_db_write(
    int operation_id,
    long long first_handle,
    long long second_handle);
CONVEX_WASM_IMPORT("convex_scheduler_schedule")
long long convex_scheduler_schedule(
    int operation_id,
    double time_ms,
    long long args_handle);
CONVEX_WASM_IMPORT("convex_host_secret_verify")
int convex_host_secret_verify(
    int operation_id,
    const char *value,
    int value_len);
CONVEX_WASM_IMPORT("convex_sha256_value")
long long convex_sha256_value(int operation_id, const char *input, int input_len);
CONVEX_WASM_IMPORT("convex_query_start_value")
long long convex_query_start_value(int operation_id, long long value_handle);
CONVEX_WASM_IMPORT("convex_query_start_utf8")
long long convex_query_start_utf8(int operation_id, const char *value, int value_len);
CONVEX_WASM_IMPORT("convex_query_next")
long long convex_query_next(long long query_id);
CONVEX_WASM_IMPORT("convex_value_type")
int convex_value_type(long long handle);
CONVEX_WASM_IMPORT("convex_value_bool")
int convex_value_bool(long long handle);
CONVEX_WASM_IMPORT("convex_value_number")
double convex_value_number(long long handle);
CONVEX_WASM_IMPORT("convex_value_string_len")
int convex_value_string_len(long long handle);
CONVEX_WASM_IMPORT("convex_value_string_copy")
int convex_value_string_copy(long long handle, char *destination, int capacity);
CONVEX_WASM_IMPORT("convex_value_field")
long long convex_value_field(long long handle, const char *name, int name_len);
CONVEX_WASM_IMPORT("convex_value_release")
void convex_value_release(long long handle);
CONVEX_WASM_IMPORT("convex_value_null_new")
long long convex_value_null_new(void);
CONVEX_WASM_IMPORT("convex_value_bool_new")
long long convex_value_bool_new(int value);
CONVEX_WASM_IMPORT("convex_value_number_new")
long long convex_value_number_new(double value);
CONVEX_WASM_IMPORT("convex_value_string_new")
long long convex_value_string_new(const char *value, int value_len);
CONVEX_WASM_IMPORT("convex_value_array_new")
long long convex_value_array_new(void);
CONVEX_WASM_IMPORT("convex_value_array_push")
void convex_value_array_push(long long array_handle, long long value_handle);
CONVEX_WASM_IMPORT("convex_value_array_len")
int convex_value_array_len(long long array_handle);
CONVEX_WASM_IMPORT("convex_value_array_get")
long long convex_value_array_get(long long array_handle, int index);
CONVEX_WASM_IMPORT("convex_value_object_new")
long long convex_value_object_new(void);
CONVEX_WASM_IMPORT("convex_value_object_insert")
void convex_value_object_insert(
    long long object_handle,
    const char *name,
    int name_len,
    long long value_handle);
CONVEX_WASM_IMPORT("convex_guest_value_request_len")
int convex_guest_value_request_len(void);
CONVEX_WASM_IMPORT("convex_guest_value_request_copy")
int convex_guest_value_request_copy(char *destination, int capacity);
CONVEX_WASM_IMPORT("convex_guest_value_decode")
long long convex_guest_value_decode(const char *value, int value_len);
CONVEX_WASM_IMPORT("convex_guest_value_encode")
long long convex_guest_value_encode(long long consuming_value_handle);
CONVEX_WASM_IMPORT("convex_guest_value_payload_len")
int convex_guest_value_payload_len(long long payload_handle);
CONVEX_WASM_IMPORT("convex_guest_value_payload_copy")
int convex_guest_value_payload_copy(
    long long payload_handle,
    char *destination,
    int capacity);
CONVEX_WASM_IMPORT("convex_guest_value_payload_release")
void convex_guest_value_payload_release(long long payload_handle);
CONVEX_WASM_IMPORT("convex_guest_value_result")
void convex_guest_value_result(const char *value, int value_len);
CONVEX_WASM_IMPORT("convex_function_result")
void convex_function_result(long long value_handle);
CONVEX_WASM_IMPORT("convex_developer_error")
void convex_developer_error(
    const char *message,
    int message_len,
    int host_operation_error_handle);
CONVEX_WASM_IMPORT("convex_has_developer_error")
int convex_has_developer_error(void);
CONVEX_WASM_IMPORT("convex_profile_mark")
void convex_profile_mark(int phase);

#undef CONVEX_WASM_IMPORT

#ifdef __cplusplus
}
#endif

#endif
`;
}

function renderIndexQueryRuntime(queryTerminalMethods) {
  return String.raw`
function __convexCreateIndexRange(
  states: any[],
  fields: any[],
  operators: any[],
  values: any[],
): any {
  let range: any;
  function add(operator: any, field: any, value: any): any {
    if (typeof field !== "string" || typeof operator !== "string") {
      throw new Error("Index constraint field and operator must be strings");
    }
    const length = fields.length;
    if (length > 0 && operators[length - 1] !== "eq") {
      throw new Error("Index equality constraints must precede the range constraint");
    }
    for (let index = 0; index < length; index += 1) {
      if (fields[index] === field) {
        throw new Error("Index constraint fields must be unique");
      }
    }
    const nextFields: any[] = [];
    const nextOperators: any[] = [];
    const nextValues: any[] = [];
    for (let index = 0; index < length; index += 1) {
      __convexArrayPush(nextFields, fields[index]);
      __convexArrayPush(nextOperators, operators[index]);
      __convexArrayPush(nextValues, values[index]);
    }
    __convexArrayPush(nextFields, field);
    __convexArrayPush(nextOperators, operator);
    __convexArrayPush(nextValues, value);
    return __convexCreateIndexRange(states, nextFields, nextOperators, nextValues);
  }
  range = {
    eq(field: any, value: any): any { return add("eq", field, value); },
    gt(field: any, value: any): any { return add("gt", field, value); },
    gte(field: any, value: any): any { return add("gte", field, value); },
    lt(field: any, value: any): any { return add("lt", field, value); },
    lte(field: any, value: any): any { return add("lte", field, value); },
  };
  __convexArrayPush(states, {range, fields, operators, values});
  return range;
}

function __convexCreateQuery(
  table: string,
  index: any,
  constraintFields: any,
  constraintOperators: any,
  constraintValues: any,
  orderValue: any,
): any {
  function withIndex(nextIndex: any, rangeBuilder: any): any {
    if (index !== undefined) throw new Error("withIndex was already called");
    const states: any[] = [];
    const root = __convexCreateIndexRange(states, [], [], []);
    const returnedRange = rangeBuilder(root);
    let selectedState: any = null;
    for (let stateIndex = 0; stateIndex < states.length; stateIndex += 1) {
      if (states[stateIndex].range === returnedRange) {
        selectedState = states[stateIndex];
        break;
      }
    }
    if (selectedState === null || selectedState.fields.length === 0) {
      throw new Error("Unsupported index range expression");
    }
    return __convexCreateQuery(
      table,
      nextIndex,
      selectedState.fields,
      selectedState.operators,
      selectedState.values,
      orderValue,
    );
  }
  function order(nextOrder: any): any {
    if (nextOrder !== "asc" && nextOrder !== "desc") {
      throw new Error("Invalid query order");
    }
    return __convexCreateQuery(
      table,
      index,
      constraintFields,
      constraintOperators,
      constraintValues,
      nextOrder,
    );
  }
  function operation(terminal: any, limit: any): any {
    if (
      index === undefined ||
      constraintFields === undefined ||
      constraintOperators === undefined ||
      constraintValues === undefined
    ) {
      throw new Error("Only indexed constraint queries are admitted");
    }
    const operationId = __convexIndexQueryOperationId(
      table,
      index,
      constraintFields,
      constraintOperators,
      orderValue,
      terminal,
      limit,
    );
    const operationArguments: any[] = __convexMarkArray([]);
    for (let valueIndex = 0; valueIndex < constraintValues.length; valueIndex += 1) {
      __convexArrayPush(operationArguments, constraintValues[valueIndex]);
    }
    if (__convexAsyncBatchArgumentCount(operationId) > constraintValues.length) {
      __convexArrayPush(operationArguments, limit);
    }
    return {operationId, operationArguments};
  }
  return {
    withIndex,
    order,
${queryTerminalMethods}
  };
}`;
}

function renderOpaqueAbiPrelude(
  hasDatabaseIndexQuery,
  hasHostSecretVerify,
  hasInvocationUnixTimestampMs
) {
  const indexQueryBindings = hasDatabaseIndexQuery
    ? String.raw`
const __convexHostQueryStartValue = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_query_start_value(
    operationId: c_int,
    valueHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostQueryNext = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_query_next(queryId: c_longlong): c_longlong { throw 0; },
);`
    : "";
  const indexQueryStartRuntime = String.raw`function __convexStartQuery(
  operationId: number,
  values: any[],
): number {
  // Execution manifest schema 6 binds constraints first and an optional dynamic limit last.
  let valuesHandle = __convexToHost(__convexMarkArray(values));
  try {
    // Ownership transfers at host call entry, including an import trap or developer error.
    const transferredValuesHandle = valuesHandle;
    valuesHandle = 0;
    const queryId = __convexHostQueryStartValue(operationId, transferredValuesHandle);
    if (queryId < 0) throw new Error("Convex query start failed");
    return queryId;
  } finally {
    if (valuesHandle > 0) __convexValueRelease(valuesHandle);
  }
}`;
  const indexQueryRuntime = hasDatabaseIndexQuery
    ? String.raw`
// Static Hermes only preserves extern_c value conversion for statically direct calls.
// Query object methods must call ordinary JavaScript closures rather than captured C pointers.
function __convexQueryNext(queryId: number): number {
  return __convexHostQueryNext(queryId);
}

${indexQueryStartRuntime}

${renderIndexQueryRuntime(String.raw`
    collect(): any {
      const selected = operation("collect", null);
      const queryId = __convexStartQuery(selected.operationId, selected.operationArguments);
      let arrayHandle = __convexValueArrayNew();
      try {
        while (true) {
          const valueHandle = __convexQueryNext(queryId);
          if (valueHandle < 0) throw new Error("Convex query read failed");
          if (valueHandle === 0) {
            const transferredArrayHandle = arrayHandle;
            arrayHandle = 0;
            return __convexFromHostArrayTake(transferredArrayHandle, -1);
          }
          __convexValueArrayPush(arrayHandle, valueHandle);
        }
      } finally {
        if (arrayHandle > 0) __convexValueRelease(arrayHandle);
      }
    },
    first(): any {
      const selected = operation("first", null);
      const queryId = __convexStartQuery(selected.operationId, selected.operationArguments);
      const firstHandle = __convexQueryNext(queryId);
      if (firstHandle < 0) throw new Error("Convex query read failed");
      if (firstHandle === 0) return null;
      return __convexFromHost(firstHandle);
    },
    unique(): any {
      const selected = operation("unique", null);
      const queryId = __convexStartQuery(selected.operationId, selected.operationArguments);
      const firstHandle = __convexQueryNext(queryId);
      if (firstHandle < 0) throw new Error("Convex query read failed");
      if (firstHandle === 0) return null;
      const first = __convexFromHost(firstHandle);
      const secondHandle = __convexQueryNext(queryId);
      if (secondHandle < 0) throw new Error("Convex query read failed");
      if (secondHandle === 0) return first;
      const second = __convexFromHost(secondHandle);
      throw new Error(
        "unique() query returned more than one result from table " +
          table +
          ":\n [" +
          String(first._id) +
          ", " +
          String(second._id) +
          ", ...]",
      );
    },
    take(limit: any): any {
      const selected = operation("take", limit);
      const queryId = __convexStartQuery(selected.operationId, selected.operationArguments);
      let arrayHandle = __convexValueArrayNew();
      try {
        while (true) {
          const valueHandle = __convexQueryNext(queryId);
          if (valueHandle < 0) throw new Error("Convex query read failed");
          if (valueHandle === 0) {
            const transferredArrayHandle = arrayHandle;
            arrayHandle = 0;
            return __convexFromHostArrayTake(transferredArrayHandle, -1);
          }
          __convexValueArrayPush(arrayHandle, valueHandle);
        }
      } finally {
        if (arrayHandle > 0) __convexValueRelease(arrayHandle);
      }
    },
`)}`
    : "";
  const hostSecretBinding = hasHostSecretVerify
    ? String.raw`
const __convexHostSecretVerify = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_host_secret_verify(
    operationId: c_int,
    value: c_ptr,
    valueLength: c_int,
  ): c_int { throw 0; },
);`
    : "";
  const hostSecretRuntime = hasHostSecretVerify
    ? String.raw`
function __convexVerifyHostSecret(operationId: number, providedValue: any): number {
  if (typeof providedValue !== "string") {
    return __convexHostSecretVerify(operationId, __convexNullPointer, 0);
  }
  const pointer = __convexAllocateUtf8(providedValue);
  try {
    const length = __convexWriteUtf8(providedValue, pointer);
    return __convexHostSecretVerify(operationId, pointer, length);
  } finally {
    __convexFree(pointer);
  }
}`
    : "";
  const invocationTimeBinding = hasInvocationUnixTimestampMs
    ? String.raw`
const __convexHostInvocationUnixTimestampMs = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_invocation_unix_timestamp_ms(): c_double { throw 0; },
);`
    : "";
  const invocationTimeRuntime = hasInvocationUnixTimestampMs
    ? String.raw`
function __convexInvocationUnixTimestampMs(): number {
  return __convexHostInvocationUnixTimestampMs();
}`
    : "";
  const indexQueryContextMethod = hasDatabaseIndexQuery
    ? String.raw`
    query(table) {
      return __convexCreateQuery(table, undefined, undefined, undefined, undefined, null);
    },`
    : "";
  return String.raw`
const __convexMalloc = $SHBuiltin.extern_c(
  {include: "stdlib.h"},
  function malloc(size: c_size_t): c_ptr { throw 0; },
);
const __convexFree = $SHBuiltin.extern_c(
  {include: "stdlib.h"},
  function free(pointer: c_ptr): void {},
);
const __convexPtrWriteChar = $SHBuiltin.extern_c(
  {declared: true},
  function _sh_ptr_write_char(
    pointer: c_ptr,
    offset: c_int,
    value: c_char,
  ): void {},
);
const __convexPtrReadUChar = $SHBuiltin.extern_c(
  {declared: true},
  function _sh_ptr_read_uchar(pointer: c_ptr, offset: c_int): c_uchar { throw 0; },
);
const __convexAsciizToString = $SHBuiltin.extern_c(
  {declared: true, hv: true},
  function _sh_asciiz_to_string(
    runtime: c_ptr,
    bytes: c_ptr,
    length: c_ptrdiff_t,
  ): string { throw 0; },
);
${hostSecretBinding}
${invocationTimeBinding}
const __convexHostRequestField = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_request_field(name: c_ptr, nameLength: c_int): c_longlong { throw 0; },
);
const __convexHostDatabaseGet = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_db_get(
    operationId: c_int,
    idHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostDatabaseNormalizeId = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_db_normalize_id(
    operationId: c_int,
    consumingValueHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostAsyncBatchTake = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_batch_take(
    invocations: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostDatabaseWrite = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_db_write(
    operationId: c_int,
    firstHandle: c_longlong,
    secondHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostSchedulerSchedule = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_scheduler_schedule(
    operationId: c_int,
    timeMs: c_double,
    argsHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostSha256 = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_sha256_value(
    operationId: c_int,
    input: c_ptr,
    inputLength: c_int,
  ): c_longlong { throw 0; },
);
${indexQueryBindings}
const __convexHostValueType = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_type(handle: c_longlong): c_int { throw 0; },
);
const __convexHostValueBool = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_bool(handle: c_longlong): c_int { throw 0; },
);
const __convexHostValueNumber = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_number(handle: c_longlong): c_double { throw 0; },
);
const __convexHostValueStringLen = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_string_len(handle: c_longlong): c_int { throw 0; },
);
const __convexHostValueStringCopy = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_string_copy(
    handle: c_longlong,
    destination: c_ptr,
    capacity: c_int,
  ): c_int { throw 0; },
);
const __convexHostValueField = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_field(
    handle: c_longlong,
    name: c_ptr,
    nameLength: c_int,
  ): c_longlong { throw 0; },
);
const __convexHostValueRelease = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_release(handle: c_longlong): void {},
);
const __convexHostValueNullNew = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_null_new(): c_longlong { throw 0; },
);
const __convexHostValueBoolNew = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_bool_new(value: c_int): c_longlong { throw 0; },
);
const __convexHostValueNumberNew = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_number_new(value: c_double): c_longlong { throw 0; },
);
const __convexHostValueStringNew = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_string_new(value: c_ptr, valueLength: c_int): c_longlong { throw 0; },
);
const __convexHostValueArrayNew = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_array_new(): c_longlong { throw 0; },
);
const __convexHostValueArrayPush = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_array_push(
    arrayHandle: c_longlong,
    valueHandle: c_longlong,
  ): void {},
);
const __convexHostValueArrayLen = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_array_len(arrayHandle: c_longlong): c_int { throw 0; },
);
const __convexHostValueArrayGet = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_array_get(
    arrayHandle: c_longlong,
    index: c_int,
  ): c_longlong { throw 0; },
);
const __convexHostValueObjectNew = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_object_new(): c_longlong { throw 0; },
);
const __convexHostValueObjectInsert = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_value_object_insert(
    objectHandle: c_longlong,
    name: c_ptr,
    nameLength: c_int,
    valueHandle: c_longlong,
  ): void {},
);
const __convexHostFunctionResult = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_function_result(valueHandle: c_longlong): void {},
);
const __convexHostDeveloperError = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_developer_error(
    message: c_ptr,
    messageLength: c_int,
    hostOperationErrorHandle: c_int,
  ): void {},
);
const __convexHostHasDeveloperError = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_has_developer_error(): c_int { throw 0; },
);
const __convexProfileMark = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_profile_mark(phase: c_int): void {},
);
const __convexNullPointer = $SHBuiltin.c_null();
${hostSecretRuntime}
${invocationTimeRuntime}

function __convexValueArrayNew(): number {
  return __convexHostValueArrayNew();
}

function __convexValueArrayPush(arrayHandle: number, valueHandle: number): void {
  __convexHostValueArrayPush(arrayHandle, valueHandle);
}

function __convexValueArrayLen(arrayHandle: number): number {
  return __convexHostValueArrayLen(arrayHandle);
}

function __convexValueArrayGet(arrayHandle: number, index: number): number {
  return __convexHostValueArrayGet(arrayHandle, index);
}

function __convexAsyncBatchTake(invocations: number): number {
  return __convexHostAsyncBatchTake(invocations);
}

function __convexValueRelease(handle: number): void {
  __convexHostValueRelease(handle);
}

function __convexAllocateUtf8(value: any): c_ptr {
  const pointer = __convexMalloc(value.length * 3 + 1);
  if (pointer === __convexNullPointer) {
    throw new Error("Static Hermes native allocation failed");
  }
  return pointer;
}

function __convexWriteUtf8(value: any, pointer: c_ptr): number {
  let offset = 0;
  for (let index = 0; index < value.length; index += 1) {
    let codePoint = value.charCodeAt(index) | 0;
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      let next = 0;
      if (index + 1 < value.length) next = value.charCodeAt(index + 1) | 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (next - 0xdc00);
        index += 1;
      } else {
        codePoint = 0xfffd;
      }
    } else if (codePoint >= 0xdc00 && codePoint <= 0xdfff) {
      codePoint = 0xfffd;
    }
    if (codePoint <= 0x7f) {
      __convexPtrWriteChar(pointer, offset, codePoint);
      offset += 1;
    } else if (codePoint <= 0x7ff) {
      __convexPtrWriteChar(pointer, offset, 0xc0 | (codePoint >> 6));
      __convexPtrWriteChar(pointer, offset + 1, 0x80 | (codePoint & 0x3f));
      offset += 2;
    } else if (codePoint <= 0xffff) {
      __convexPtrWriteChar(pointer, offset, 0xe0 | (codePoint >> 12));
      __convexPtrWriteChar(pointer, offset + 1, 0x80 | ((codePoint >> 6) & 0x3f));
      __convexPtrWriteChar(pointer, offset + 2, 0x80 | (codePoint & 0x3f));
      offset += 3;
    } else {
      __convexPtrWriteChar(pointer, offset, 0xf0 | (codePoint >> 18));
      __convexPtrWriteChar(pointer, offset + 1, 0x80 | ((codePoint >> 12) & 0x3f));
      __convexPtrWriteChar(pointer, offset + 2, 0x80 | ((codePoint >> 6) & 0x3f));
      __convexPtrWriteChar(pointer, offset + 3, 0x80 | (codePoint & 0x3f));
      offset += 4;
    }
  }
  return offset;
}

function __convexReadHostString(handle: number): string {
  const length = __convexHostValueStringLen(handle);
  if (length < 0) throw new Error("Invalid host string length");
  const pointer = __convexMalloc(length + 1);
  if (pointer === __convexNullPointer) {
    throw new Error("Static Hermes native allocation failed");
  }
  try {
    if (__convexHostValueStringCopy(handle, pointer, length) !== length) {
      throw new Error("Host string copy failed");
    }
    return __convexAsciizToString($SHBuiltin.c_native_runtime(), pointer, length);
  } finally {
    __convexFree(pointer);
  }
}

function __convexFromHost(handle: number): any {
  if (handle <= 0) throw new Error("Invalid opaque host value handle");
  const type = __convexHostValueType(handle);
  if (type === 5 || type === 6) return __convexWrapObject(handle);
  try {
    switch (type) {
      case 0: return null;
      case 1: return false;
      case 2: return true;
      case 3: return __convexHostValueNumber(handle);
      case 4: return __convexReadHostString(handle);
      default: throw new Error("Unsupported opaque host value type");
    }
  } finally {
    __convexValueRelease(handle);
  }
}

function __convexReadField(valueHandle: number, field: string): any {
  if (valueHandle <= 0) throw new Error("Opaque host value was already consumed");
  const pointer = __convexAllocateUtf8(field);
  try {
    const length = __convexWriteUtf8(field, pointer);
    const fieldHandle = __convexHostValueField(valueHandle, pointer, length);
    if (fieldHandle === 0) return undefined;
    return __convexFromHost(fieldHandle);
  } finally {
    __convexFree(pointer);
  }
}

function __convexReadRequestField(field: string): any {
  const pointer = __convexAllocateUtf8(field);
  try {
    const length = __convexWriteUtf8(field, pointer);
    const handle = __convexHostRequestField(pointer, length);
    if (handle === 0) return undefined;
    return __convexFromHost(handle);
  } finally {
    __convexFree(pointer);
  }
}

function __convexFromHostArrayTake(arrayHandle: number, expectedLength: number): any[] {
  if (arrayHandle <= 0) throw new Error("Invalid opaque host array handle");
  try {
    const length = __convexValueArrayLen(arrayHandle);
    if (length < 0) throw new Error("Invalid opaque host array length");
    if (expectedLength >= 0 && length !== expectedLength) {
      throw new Error("Opaque host array has an invalid element count");
    }
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const elementHandle = __convexValueArrayGet(arrayHandle, index);
      if (elementHandle <= 0) throw new Error("Opaque host array element is missing");
      __convexArrayPush(result, __convexFromHost(elementHandle));
    }
    return __convexMarkArray(result);
  } finally {
    __convexValueRelease(arrayHandle);
  }
}

function __convexReadRequestArrayField(field: string): any {
  const pointer = __convexAllocateUtf8(field);
  let arrayHandle = 0;
  try {
    const length = __convexWriteUtf8(field, pointer);
    arrayHandle = __convexHostRequestField(pointer, length);
    if (arrayHandle <= 0) throw new Error("Validated Convex array argument is missing");
    const transferredArrayHandle = arrayHandle;
    arrayHandle = 0;
    return __convexFromHostArrayTake(transferredArrayHandle, -1);
  } finally {
    if (arrayHandle > 0) __convexValueRelease(arrayHandle);
    __convexFree(pointer);
  }
}

function __convexSha256(operationId: number, value: string): any {
  const pointer = __convexAllocateUtf8(value);
  try {
    const length = __convexWriteUtf8(value, pointer);
    const handle = __convexHostSha256(operationId, pointer, length);
    if (handle <= 0) throw new Error("Convex SHA-256 operation failed");
    return __convexFromHost(handle);
  } finally {
    __convexFree(pointer);
  }
}

${indexQueryRuntime}

function __convexObjectInsertTake(
  objectHandle: number,
  name: string,
  valueHandle: number,
): void {
  const pointer = __convexAllocateUtf8(name);
  try {
    const length = __convexWriteUtf8(name, pointer);
    __convexHostValueObjectInsert(objectHandle, pointer, length, valueHandle);
  } finally {
    __convexFree(pointer);
  }
}

function __convexBatchUndefinedTake(handle: number): void {
  if (handle <= 0) throw new Error("Opaque batch void result is missing");
  try {
    if (__convexHostValueType(handle) !== 6) {
      throw new Error("Convex batch void result has an invalid sentinel type");
    }
    if (__convexReadField(handle, "$convexWasmBatchUndefined") !== true) {
      throw new Error("Convex batch void result has an invalid sentinel");
    }
    return;
  } finally {
    __convexValueRelease(handle);
  }
}

function __convexFromBatchResultArrayTake(
  arrayHandle: number,
  expectedLength: number,
  resultKind: string,
): any[] {
  if (arrayHandle <= 0) throw new Error("Invalid opaque batch result array handle");
  try {
    const length = __convexValueArrayLen(arrayHandle);
    if (length !== expectedLength) {
      throw new Error("Opaque batch result array has an invalid element count");
    }
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const elementHandle = __convexValueArrayGet(arrayHandle, index);
      if (elementHandle <= 0) throw new Error("Opaque batch result array element is missing");
      __convexArrayPush(result, __convexBatchResultTake(elementHandle, resultKind));
    }
    return __convexMarkArray(result);
  } finally {
    __convexValueRelease(arrayHandle);
  }
}

function __convexBatchResultTake(elementHandle: number, resultKind: string): any {
  if (resultKind === "hostArray") {
    return __convexFromHostArrayTake(elementHandle, -1);
  }
  if (resultKind === "hostValue") return __convexFromHost(elementHandle);
  if (resultKind === "undefined") return __convexBatchUndefinedTake(elementHandle);
  __convexValueRelease(elementHandle);
  throw new Error("Convex batch result kind is invalid");
}

function __convexFromFixedBatchResultArrayTake(
  arrayHandle: number,
  operationIds: number[],
): any[] {
  if (arrayHandle <= 0) throw new Error("Invalid opaque fixed batch result array handle");
  try {
    const length = __convexValueArrayLen(arrayHandle);
    if (length !== operationIds.length) {
      throw new Error("Opaque fixed batch result array has an invalid element count");
    }
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const elementHandle = __convexValueArrayGet(arrayHandle, index);
      if (elementHandle <= 0) throw new Error("Opaque fixed batch result element is missing");
      __convexArrayPush(
        result,
        __convexBatchResultTake(
          elementHandle,
          __convexAsyncBatchResultKind(operationIds[index]),
        ),
      );
    }
    return __convexMarkArray(result);
  } finally {
    __convexValueRelease(arrayHandle);
  }
}

function __convexBatchPushInvocation(
  invocationsHandle: number,
  operationId: number,
  dynamicArguments: any[],
): void {
  const expectedArgumentCount = __convexAsyncBatchArgumentCount(operationId);
  if (dynamicArguments.length !== expectedArgumentCount) {
    throw new Error("Convex batch invocation has an invalid argument count");
  }
  let descriptorHandle = __convexHostValueObjectNew();
  let argumentsHandle = 0;
  try {
    let operationIdHandle = __convexHostValueNumberNew(operationId);
    try {
      __convexObjectInsertTake(descriptorHandle, "operationId", operationIdHandle);
      operationIdHandle = 0;
    } finally {
      if (operationIdHandle > 0) __convexValueRelease(operationIdHandle);
    }
    argumentsHandle = __convexValueArrayNew();
    for (let argumentIndex = 0; argumentIndex < dynamicArguments.length; argumentIndex += 1) {
      let argumentHandle = __convexToHost(dynamicArguments[argumentIndex]);
      try {
        __convexValueArrayPush(argumentsHandle, argumentHandle);
        argumentHandle = 0;
      } finally {
        if (argumentHandle > 0) __convexValueRelease(argumentHandle);
      }
    }
    __convexObjectInsertTake(descriptorHandle, "arguments", argumentsHandle);
    argumentsHandle = 0;
    __convexValueArrayPush(invocationsHandle, descriptorHandle);
    descriptorHandle = 0;
  } finally {
    if (argumentsHandle > 0) __convexValueRelease(argumentsHandle);
    if (descriptorHandle > 0) __convexValueRelease(descriptorHandle);
  }
}

function __convexAsyncBatch(
  values: any[],
  operationId: number,
  projectArguments: (value: any) => any[],
): any[] {
  const expectedArgumentCount = __convexAsyncBatchArgumentCount(operationId);
  const resultKind = __convexAsyncBatchResultKind(operationId);
  let invocationsHandle = __convexValueArrayNew();
  try {
    for (let index = 0; index < values.length; index += 1) {
      const dynamicArguments = projectArguments(values[index]);
      if (dynamicArguments.length !== expectedArgumentCount) {
        throw new Error("Convex batch projection returned an invalid argument count");
      }
      __convexBatchPushInvocation(invocationsHandle, operationId, dynamicArguments);
    }

    // Ownership transfers at host call entry, including an import trap or developer error.
    const transferredInvocationsHandle = invocationsHandle;
    invocationsHandle = 0;
    const resultArrayHandle = __convexAsyncBatchTake(transferredInvocationsHandle);
    if (resultArrayHandle === -1) throw new Error("Convex batched operation failed");
    if (resultArrayHandle <= 0) {
      throw new Error("Convex batched operation returned an invalid handle");
    }
    return __convexFromBatchResultArrayTake(resultArrayHandle, values.length, resultKind);
  } finally {
    if (invocationsHandle > 0) __convexValueRelease(invocationsHandle);
  }
}

function __convexAsyncFixedBatch(
  operationIds: number[],
  argumentLists: any[][],
): any[] {
  if (operationIds.length !== argumentLists.length) {
    throw new Error("Convex fixed batch descriptor lengths disagree");
  }
  let invocationsHandle = __convexValueArrayNew();
  try {
    for (let index = 0; index < operationIds.length; index += 1) {
      __convexBatchPushInvocation(invocationsHandle, operationIds[index], argumentLists[index]);
    }
    // Ownership transfers at host call entry, including an import trap or developer error.
    const transferredInvocationsHandle = invocationsHandle;
    invocationsHandle = 0;
    const resultArrayHandle = __convexAsyncBatchTake(transferredInvocationsHandle);
    if (resultArrayHandle === -1) throw new Error("Convex fixed batch operation failed");
    if (resultArrayHandle <= 0) {
      throw new Error("Convex fixed batch returned an invalid handle");
    }
    return __convexFromFixedBatchResultArrayTake(resultArrayHandle, operationIds);
  } finally {
    if (invocationsHandle > 0) __convexValueRelease(invocationsHandle);
  }
}

function __convexDependencyIterableValues(ids: any): any[] {
  const values = [];
  for (const id of ids) __convexArrayPush(values, id);
  return __convexMarkArray(values);
}

function __convexDependencyDatabaseGetBatchFromValues(table: string, values: any[]): any[] {
  const operationId = __convexDatabaseGetOperationId(table);
  return __convexAsyncBatch(values, operationId, (id) => [id]);
}

function __convexDependencyDatabaseGetBatch(table: string, ids: any): any[] {
  return __convexDependencyDatabaseGetBatchFromValues(
    table,
    __convexDependencyIterableValues(ids),
  );
}

function __convexDatabaseGet(table: string, id: any): any {
  const operationId = __convexDatabaseGetOperationId(table);
  const resultHandle = __convexHostDatabaseGet(operationId, __convexToHost(id));
  if (resultHandle === -1) throw new Error("Convex database get failed");
  if (resultHandle <= 0) throw new Error("Convex database get returned an invalid handle");
  return __convexFromHost(resultHandle);
}

function __convexAuthenticationGetUserIdentity(): any {
  const operationId = __convexAuthenticationGetUserIdentityOperationId();
  const results = __convexAsyncBatch([null], operationId, () => []);
  return results[0];
}

function __convexCreateFunctionHandle(functionReference: any): string {
  const operationId = __convexFunctionHandleCreateOperationId();
  const address = __convexFunctionHandleAddress(functionReference);
  const results = __convexAsyncBatch([address], operationId, (value) => [value]);
  const result = results[0];
  if (typeof result !== "string") {
    throw new Error("Convex function-handle creation returned a non-string result");
  }
  return result;
}

function __convexDatabaseNormalizeId(table: string, value: any): any {
  const operationId = __convexDatabaseNormalizeIdOperationId(table);
  let valueHandle = __convexToHost(value);
  try {
    // Ownership transfers at host call entry, including an import trap or developer error.
    const transferredValueHandle = valueHandle;
    valueHandle = 0;
    const resultHandle = __convexHostDatabaseNormalizeId(operationId, transferredValueHandle);
    if (resultHandle === -1) throw new Error("Convex database normalizeId failed");
    if (resultHandle <= 0) {
      throw new Error("Convex database normalizeId returned an invalid handle");
    }
    return __convexFromHost(resultHandle);
  } finally {
    if (valueHandle > 0) __convexValueRelease(valueHandle);
  }
}

function __convexDatabaseWrite(
  kind: string,
  table: string,
  id: any,
  value: any,
): any {
  const operationId = __convexDatabaseWriteOperationId(kind, table);
  let firstHandle = 0;
  let secondHandle = 0;
  try {
    if (kind === "databaseInsert") {
      secondHandle = __convexToHost(value);
    } else {
      firstHandle = __convexToHost(id);
      if (kind !== "databaseDelete") {
        secondHandle = __convexToHost(value);
      }
    }
    const resultHandle = __convexHostDatabaseWrite(
      operationId,
      firstHandle,
      secondHandle,
    );
    firstHandle = 0;
    secondHandle = 0;
    if (resultHandle === -1) throw new Error("Convex database write failed");
    if (kind === "databaseInsert") {
      if (resultHandle <= 0) {
        throw new Error("Convex database insert returned an invalid handle");
      }
      return __convexFromHost(resultHandle);
    }
    if (resultHandle !== 0) {
      throw new Error("Convex database write returned an unexpected handle");
    }
    return undefined;
  } finally {
    if (firstHandle > 0) __convexValueRelease(firstHandle);
    if (secondHandle > 0) __convexValueRelease(secondHandle);
  }
}

function __convexSchedule(
  kind: string,
  timeMilliseconds: number,
  functionReference: any,
  args: any,
): any {
  const operationId = __convexSchedulerOperationId(kind, functionReference);
  const resultHandle = __convexHostSchedulerSchedule(
    operationId,
    timeMilliseconds,
    __convexToHost(args),
  );
  if (resultHandle === -1) throw new Error("Convex scheduler operation failed");
  if (resultHandle <= 0) throw new Error("Convex scheduler returned an invalid handle");
  return __convexFromHost(resultHandle);
}

const __convexContext = {
  auth: {
    getUserIdentity() {
      return __convexAuthenticationGetUserIdentity();
    },
  },
  db: {
    delete(table, id) {
      return __convexDatabaseWrite("databaseDelete", table, id, undefined);
    },
    get(table, id) {
      return __convexDatabaseGet(table, id);
    },
    insert(table, value) {
      return __convexDatabaseWrite("databaseInsert", table, undefined, value);
    },
    normalizeId(table, value) {
      return __convexDatabaseNormalizeId(table, value);
    },
    patch(table, id, value) {
      return __convexDatabaseWrite("databasePatch", table, id, value);
    },
${indexQueryContextMethod}
    replace(table, id, value) {
      return __convexDatabaseWrite("databaseReplace", table, id, value);
    },
  },
  scheduler: {
    runAfter(delayMilliseconds, functionReference, args) {
      return __convexSchedule(
        "schedulerRunAfter",
        delayMilliseconds,
        functionReference,
        args,
      );
    },
    runAt(timestampMilliseconds, functionReference, args) {
      return __convexSchedule(
        "schedulerRunAt",
        timestampMilliseconds,
        functionReference,
        args,
      );
    },
  },
};

function __convexNewHostString(value: string): number {
  const pointer = __convexAllocateUtf8(value);
  try {
    const length = __convexWriteUtf8(value, pointer);
    return __convexHostValueStringNew(pointer, length);
  } finally {
    __convexFree(pointer);
  }
}

function __convexToHost(value: any): number {
  if (
    value !== null &&
    typeof value === "object" &&
    typeof value.__convexOpaqueHandle === "number"
  ) {
    const handle = value.__convexOpaqueHandle;
    if (handle <= 0) throw new Error("Opaque host value was already consumed");
    value.__convexOpaqueHandle = 0;
    return handle;
  }
  if (value === null || value === undefined) return __convexHostValueNullNew();
  if (value === false) return __convexHostValueBoolNew(0);
  if (value === true) return __convexHostValueBoolNew(1);
  if (typeof value === "number") return __convexHostValueNumberNew(value);
  if (typeof value === "string") return __convexNewHostString(value);
  if (__convexIsKnownArray(value)) {
    const arrayHandle = __convexValueArrayNew();
    try {
      for (let index = 0; index < value.length; index += 1) {
        let elementHandle = __convexToHost(value[index]);
        try {
          __convexValueArrayPush(arrayHandle, elementHandle);
          elementHandle = 0;
        } finally {
          if (elementHandle > 0) __convexValueRelease(elementHandle);
        }
      }
      return arrayHandle;
    } catch (error) {
      __convexValueRelease(arrayHandle);
      throw error;
    }
  }
  if (typeof value === "object") {
    const objectHandle = __convexHostValueObjectNew();
    try {
      const keys = Object.keys(value);
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        const pointer = __convexAllocateUtf8(key);
        try {
          const length = __convexWriteUtf8(key, pointer);
          __convexHostValueObjectInsert(
            objectHandle,
            pointer,
            length,
            __convexToHost(value[key]),
          );
        } finally {
          __convexFree(pointer);
        }
      }
      return objectHandle;
    } catch (error) {
      __convexValueRelease(objectHandle);
      throw error;
    }
  }
  throw new Error("Unsupported Convex result value");
}

function __convexSetFunctionResult(value: any): void {
  const resultHandle = __convexToHost(value);
  __convexReleaseLiveOpaqueValues();
  __convexHostFunctionResult(resultHandle);
}

function __convexReportThrown(error: any): void {
  if (__convexHostHasDeveloperError() !== 0) return;
  const hostOperationErrorHandle = __convexHostOperationErrorHandle(error);
  const message =
    error instanceof Error
      ? "Uncaught " + error.name + ": " + error.message
      : "Uncaught " + String(error);
  const pointer = __convexAllocateUtf8(message);
  try {
    const length = __convexWriteUtf8(message, pointer);
    __convexHostDeveloperError(pointer, length, hostOperationErrorHandle);
  } finally {
    __convexFree(pointer);
  }
}

const __convexHostOperationErrorCandidates: any = new WeakMap();

function __convexHostOperationErrorHandle(error: any): number {
  let current = error;
  const visited: any = new WeakSet();
  for (let depth = 0; depth < 8; depth += 1) {
    if (!(current instanceof Error) || visited.has(current)) return 0;
    visited.add(current);
    const handle = __convexHostOperationErrorCandidates.get(current);
    if (handle !== undefined) return handle;
    const cause = Object.getOwnPropertyDescriptor(current, "cause");
    if (cause === undefined || !Object.hasOwn(cause, "value")) return 0;
    current = cause.value;
  }
  return 0;
}
`.trim();
}

function removeGeneratedSection(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  if (start < 0 || end < 0 || end <= start) {
    throw new Error(`Lowering prelude section is missing: ${startMarker}.`);
  }
  return source.slice(0, start) + source.slice(end);
}

export function assertNativeCapabilityHelperDefinitions(runtime) {
  if (typeof runtime !== "string" || runtime.length === 0) {
    throw new Error("Native capability runtime must be a non-empty string.");
  }
  const definitions = new Set(
    [...runtime.matchAll(/\b(?:class|const|function|let|var)\s+(__convex[A-Za-z0-9_$]*)\b/gu)].map(
      (match) => match[1]
    )
  );
  // The target prelude captures this binding outside the capability-runtime block.
  definitions.add("__convexTargetGlobal");
  const missing = new Set();
  for (const match of runtime.matchAll(/\b(__convex[A-Za-z0-9_$]*)\b/gu)) {
    const name = match[1];
    if (definitions.has(name)) continue;
    let previousIndex = match.index - 1;
    while (previousIndex >= 0 && /\s/u.test(runtime[previousIndex])) previousIndex -= 1;
    const suffix = runtime.slice(match.index + name.length);
    const isProperty = runtime[previousIndex] === "." || /^\s*:/u.test(suffix);
    const isObjectMethod = /^\s*\([^)]*\)\s*\{/u.test(suffix);
    if (!isProperty && !isObjectMethod) missing.add(name);
  }
  if (missing.size !== 0) {
    throw new Error(
      `Native capability runtime references undefined helpers: ${[...missing].sort().join(", ")}.`
    );
  }
}

function renderGuestPromiseEffectRuntime(hasDatabaseIndexQuery, hasDatabaseQueryStream) {
  const queryStreamMethod = hasDatabaseQueryStream
    ? String.raw`
    __stream(): any {
      const selected = operation("stream", null);
      return __convexCreateQueryIterator(
        selected.operationId,
        selected.operationArguments,
      );
    },
    [__convexDynamicGlobal.Symbol.asyncIterator](): any {
      const selected = operation("stream", null);
      return __convexCreateQueryIterator(
        selected.operationId,
        selected.operationArguments,
      );
    },`
    : "";
  const queryRuntime = hasDatabaseIndexQuery
    ? renderIndexQueryRuntime(String.raw`
    collect(): any {
      const selected = operation("collect", null);
      return __convexStartAsyncOperation(
        selected.operationId,
        selected.operationArguments,
      );
    },
    first(): any {
      const selected = operation("first", null);
      return __convexStartAsyncOperation(selected.operationId, selected.operationArguments);
    },
    unique(): any {
      const selected = operation("unique", null);
      return __convexStartAsyncOperation(selected.operationId, selected.operationArguments);
    },
    take(limit: any): any {
      const selected = operation("take", limit);
      return __convexStartAsyncOperation(selected.operationId, selected.operationArguments);
    },
${queryStreamMethod}
`)
    : "";
  const queryContextMethod = hasDatabaseIndexQuery
    ? String.raw`
    query(table) {
      return __convexCreateQuery(table, undefined, undefined, undefined, undefined, null);
    },`
    : "";
  const queryStreamBindings = hasDatabaseQueryStream
    ? String.raw`
const __convexHostAsyncQueryStreamOpenTake = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_query_stream_open_take(
    operationId: c_int,
    argumentsHandle: c_longlong,
  ): c_int { throw 0; },
);
const __convexHostAsyncQueryStreamNext = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_query_stream_next(streamHandle: c_int): c_int { throw 0; },
);
const __convexHostAsyncQueryStreamClose = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_query_stream_close(streamHandle: c_int): void {},
);`
    : "";
  const queryStreamRuntime = hasDatabaseQueryStream
    ? String.raw`
function __convexOpenQueryStream(operationId: number, dynamicArguments: any[]): number {
  let argumentsHandle = __convexValueArrayNew();
  try {
    for (let index = 0; index < dynamicArguments.length; index += 1) {
      let argumentHandle = __convexToHost(dynamicArguments[index]);
      try {
        __convexValueArrayPush(argumentsHandle, argumentHandle);
        argumentHandle = 0;
      } finally {
        if (argumentHandle > 0) __convexValueRelease(argumentHandle);
      }
    }
    const transferredArgumentsHandle = argumentsHandle;
    argumentsHandle = 0;
    const streamHandle = __convexHostAsyncQueryStreamOpenTake(
      operationId,
      transferredArgumentsHandle,
    );
    if (streamHandle <= 0) throw new Error("Convex query stream returned an invalid handle");
    return streamHandle;
  } finally {
    if (argumentsHandle > 0) __convexValueRelease(argumentsHandle);
  }
}

function __convexStartQueryStreamNext(operationId: number, streamHandle: number): any {
  return new __convexDynamicPromise((resolve, reject) => {
    const operationHandle = __convexHostAsyncQueryStreamNext(streamHandle);
    __convexRegisterPendingOperation(operationId, operationHandle, resolve, reject);
  });
}

function __convexCreateQueryIterator(operationId: number, operationArguments: any[]): any {
  let streamHandle = __convexOpenQueryStream(operationId, operationArguments);
  let done = false;
  let pending = false;
  let iterator: any;
  iterator = {
    next(): any {
      if (done) {
        return __convexDynamicPromise.resolve({ done: true, value: undefined });
      }
      if (pending) {
        return __convexDynamicPromise.reject(
          new Error("Convex query stream already has a pending read"),
        );
      }
      pending = true;
      return __convexStartQueryStreamNext(operationId, streamHandle).then(
        (result) => {
          pending = false;
          if (
            result === null ||
            typeof result !== "object" ||
            typeof result.done !== "boolean" ||
            !("value" in result)
          ) {
            throw new Error("Convex query stream returned an invalid iteration result");
          }
          if (result.done) {
            if (result.value !== null) {
              throw new Error("Convex query stream completion returned a value");
            }
            done = true;
            streamHandle = 0;
            return { done: true, value: undefined };
          }
          return { done: false, value: result.value };
        },
        (error) => {
          pending = false;
          done = true;
          streamHandle = 0;
          throw error;
        },
      );
    },
    return(): any {
      if (pending) {
        return __convexDynamicPromise.reject(
          new Error("Convex query stream cannot close during a pending read"),
        );
      }
      if (!done) {
        __convexHostAsyncQueryStreamClose(streamHandle);
        done = true;
        streamHandle = 0;
      }
      return __convexDynamicPromise.resolve({ done: true, value: undefined });
    },
  };
  iterator[__convexDynamicGlobal.Symbol.asyncIterator] = function(): any {
    return iterator;
  };
  return iterator;
}`
    : "";
  return String.raw`
const __convexHostAsyncOperationStartTake = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_operation_start_take(
    operationId: c_int,
    argumentsHandle: c_longlong,
  ): c_int { throw 0; },
);
${queryStreamBindings}

const __convexPendingOperationIds: Array<?number> = [];
const __convexPendingOperationResolves: Array<any> = [];
const __convexPendingOperationRejects: Array<any> = [];
const __convexDynamicGlobal: any = globalThis;
const __convexDynamicArrayIsArray: any = __convexDynamicGlobal.Array.isArray;
const __convexDynamicPromise: any = __convexDynamicGlobal.Promise;

function __convexPendingOperationSlot(operationHandle: number, create: boolean): number {
  if (operationHandle <= 0) throw new Error("Convex async operation returned an invalid handle");
  const slot = operationHandle - 1;
  if (create) {
    while (__convexPendingOperationIds.length <= slot) {
      __convexPendingOperationIds.push(undefined);
      __convexPendingOperationResolves.push(undefined);
      __convexPendingOperationRejects.push(undefined);
    }
  } else if (slot >= __convexPendingOperationIds.length) {
    throw new Error("Convex async completion has no pending Promise");
  }
  return slot;
}

function __convexVmPromiseValues(values: any): any {
  const dynamicValues: any = __convexDynamicGlobal.Array();
  for (let index = 0; index < values.length; index += 1) {
    dynamicValues.push(values[index]);
  }
  return dynamicValues;
}

const __convexGuestPromise: any = function(executor: any): any {
  return new __convexDynamicPromise(executor);
};
__convexGuestPromise.prototype = __convexDynamicPromise.prototype;
__convexGuestPromise.all = function(values: any): any {
  return __convexDynamicPromise.all(__convexVmPromiseValues(values));
};
__convexGuestPromise.race = function(values: any): any {
  return __convexDynamicPromise.race(__convexVmPromiseValues(values));
};
__convexGuestPromise.resolve = function(value: any): any {
  return __convexDynamicPromise.resolve(value);
};
__convexGuestPromise.reject = function(value: any): any {
  return __convexDynamicPromise.reject(value);
};

function __convexRegisterPendingOperation(
  operationId: number,
  operationHandle: number,
  resolve: any,
  reject: any,
): void {
  const slot = __convexPendingOperationSlot(operationHandle, true);
  if (__convexPendingOperationResolves[slot] !== undefined) {
    throw new Error("Convex async operation handle was reused");
  }
  __convexPendingOperationIds[slot] = operationId;
  __convexPendingOperationResolves[slot] = resolve;
  __convexPendingOperationRejects[slot] = reject;
}

function __convexWasmInvocationCleanup(): number {
  if (
    __convexPendingOperationIds.length !== __convexPendingOperationResolves.length ||
    __convexPendingOperationIds.length !== __convexPendingOperationRejects.length
  ) {
    throw new Error("Convex async operation registries have inconsistent lengths");
  }
  let abandoned = 0;
  for (let slot = 0; slot < __convexPendingOperationIds.length; slot += 1) {
    const operationId = __convexPendingOperationIds[slot];
    const resolve = __convexPendingOperationResolves[slot];
    const reject = __convexPendingOperationRejects[slot];
    if (operationId === undefined) {
      if (resolve !== undefined || reject !== undefined) {
        throw new Error("Convex async operation registry contains a partial slot");
      }
    } else {
      if (typeof resolve !== "function" || typeof reject !== "function") {
        throw new Error("Convex async operation registry contains an invalid pending slot");
      }
      abandoned += 1;
    }
    __convexPendingOperationIds[slot] = undefined;
    __convexPendingOperationResolves[slot] = undefined;
    __convexPendingOperationRejects[slot] = undefined;
  }
  __convexPendingOperationIds.length = 0;
  __convexPendingOperationResolves.length = 0;
  __convexPendingOperationRejects.length = 0;
  return abandoned;
}

globalThis.__convexWasmInvocationCleanup = __convexWasmInvocationCleanup;

function __convexStartAsyncOperation(operationId: number, dynamicArguments: any[]): any {
  let argumentsHandle = __convexValueArrayNew();
  try {
    for (let index = 0; index < dynamicArguments.length; index += 1) {
      let argumentHandle = __convexToHost(dynamicArguments[index]);
      try {
        __convexValueArrayPush(argumentsHandle, argumentHandle);
        argumentHandle = 0;
      } finally {
        if (argumentHandle > 0) __convexValueRelease(argumentHandle);
      }
    }
    return new __convexDynamicPromise((resolve, reject) => {
      const transferredArgumentsHandle = argumentsHandle;
      argumentsHandle = 0;
      const operationHandle = __convexHostAsyncOperationStartTake(
        operationId,
        transferredArgumentsHandle,
      );
      __convexRegisterPendingOperation(operationId, operationHandle, resolve, reject);
    });
  } finally {
    if (argumentsHandle > 0) __convexValueRelease(argumentsHandle);
  }
}

${queryStreamRuntime}

function __convexWasmSettle(
  operationHandle: number,
  completionStatus: number,
  payloadHandle: number,
): void {
  const slot = __convexPendingOperationSlot(operationHandle, false);
  const operationId = __convexPendingOperationIds[slot];
  const resolve = __convexPendingOperationResolves[slot];
  const reject = __convexPendingOperationRejects[slot];
  if (
    operationId === undefined ||
    typeof resolve !== "function" ||
    typeof reject !== "function"
  ) {
    throw new Error("Convex async completion has no pending Promise");
  }

  let completion: any;
  if (completionStatus === 1) {
    if (payloadHandle <= 0) throw new Error("Convex async rejection has no payload");
    const message = __convexFromHost(payloadHandle);
    if (typeof message !== "string") throw new Error("Convex async rejection payload is invalid");
    completion = new Error(message);
    __convexHostOperationErrorCandidates.set(completion, operationHandle);
  } else if (completionStatus === 0) {
    const resultKind = __convexAsyncBatchResultKind(operationId);
    if (resultKind === "undefined") {
      if (payloadHandle !== 0) throw new Error("Convex void completion returned a payload");
      completion = undefined;
    } else if (resultKind === "hostArray") {
      completion = __convexFromHostArrayTake(payloadHandle, -1);
    } else if (resultKind === "hostValue") {
      completion = __convexFromHost(payloadHandle);
    } else {
      throw new Error("Convex async completion result kind is invalid");
    }
  } else throw new Error("Convex async completion status is invalid");

  __convexPendingOperationIds[slot] = undefined;
  __convexPendingOperationResolves[slot] = undefined;
  __convexPendingOperationRejects[slot] = undefined;
  if (completionStatus === 1) reject(completion);
  else resolve(completion);
}

globalThis.__convexWasmSettle = __convexWasmSettle;

function __convexDatabaseGet(table: string, id: any): any {
  return __convexStartAsyncOperation(__convexDatabaseGetOperationId(table), [id]);
}

function __convexAuthenticationGetUserIdentity(): any {
  return __convexStartAsyncOperation(__convexAuthenticationGetUserIdentityOperationId(), []);
}

function __convexCreateFunctionHandle(functionReference: any): any {
  return __convexStartAsyncOperation(
    __convexFunctionHandleCreateOperationId(),
    [__convexFunctionHandleAddress(functionReference)],
  ).then((result) => {
    if (typeof result !== "string") {
      throw new Error("Convex function-handle creation returned a non-string result");
    }
    return result;
  });
}

function __convexDatabaseWrite(kind: string, table: string, id: any, value: any): any {
  const operationId = __convexDatabaseWriteOperationId(kind, table);
  if (kind === "databaseInsert") return __convexStartAsyncOperation(operationId, [value]);
  if (kind === "databaseDelete") return __convexStartAsyncOperation(operationId, [id]);
  return __convexStartAsyncOperation(operationId, [id, value]);
}

function __convexSchedule(
  kind: string,
  timeMilliseconds: number,
  functionReference: any,
  args: any,
): any {
  return __convexStartAsyncOperation(
    __convexSchedulerOperationId(kind, functionReference),
    [timeMilliseconds, args],
  );
}

function __convexDependencyIterableValues(ids: any): any[] {
  const values = [];
  for (const id of ids) __convexArrayPush(values, id);
  return __convexMarkArray(values);
}

function __convexDependencyDatabaseGetBatchFromValues(table: string, values: any[]): any {
  const promises = [];
  for (let index = 0; index < values.length; index += 1) {
    __convexArrayPush(promises, __convexDatabaseGet(table, values[index]));
  }
  return __convexGuestPromise.all(promises);
}

function __convexDependencyDatabaseGetBatch(table: string, ids: any): any {
  return __convexDependencyDatabaseGetBatchFromValues(
    table,
    __convexDependencyIterableValues(ids),
  );
}

${queryRuntime}

const __convexContext = {
  auth: {
    getUserIdentity() { return __convexAuthenticationGetUserIdentity(); },
  },
  db: {
    delete(table, id) { return __convexDatabaseWrite("databaseDelete", table, id, undefined); },
    get(table, id) { return __convexDatabaseGet(table, id); },
    insert(table, value) { return __convexDatabaseWrite("databaseInsert", table, undefined, value); },
    normalizeId(table, value) { return __convexDatabaseNormalizeId(table, value); },
    patch(table, id, value) { return __convexDatabaseWrite("databasePatch", table, id, value); },
${queryContextMethod}
    replace(table, id, value) { return __convexDatabaseWrite("databaseReplace", table, id, value); },
  },
  scheduler: {
    runAfter(delayMilliseconds, functionReference, args) {
      return __convexSchedule("schedulerRunAfter", delayMilliseconds, functionReference, args);
    },
    runAt(timestampMilliseconds, functionReference, args) {
      return __convexSchedule("schedulerRunAt", timestampMilliseconds, functionReference, args);
    },
  },
};
`;
}

function renderGuestPromiseAbiPrelude(
  hasDatabaseIndexQuery,
  hasDatabaseQueryStream,
  hasHostSecretVerify,
  hasInvocationUnixTimestampMs
) {
  let prelude = renderOpaqueAbiPrelude(false, hasHostSecretVerify, hasInvocationUnixTimestampMs);
  prelude = removeGeneratedSection(
    prelude,
    "const __convexHostDatabaseGet = $SHBuiltin.extern_c(",
    "const __convexHostDatabaseNormalizeId = $SHBuiltin.extern_c("
  );
  prelude = removeGeneratedSection(
    prelude,
    "const __convexHostAsyncBatchTake = $SHBuiltin.extern_c(",
    "const __convexHostDatabaseWrite = $SHBuiltin.extern_c("
  );
  prelude = removeGeneratedSection(
    prelude,
    "const __convexHostDatabaseWrite = $SHBuiltin.extern_c(",
    "const __convexHostSha256 = $SHBuiltin.extern_c("
  );
  prelude = removeGeneratedSection(
    prelude,
    "function __convexAsyncBatchTake(invocations: number): number {",
    "function __convexValueRelease(handle: number): void {"
  );
  prelude = removeGeneratedSection(
    prelude,
    "function __convexBatchUndefinedTake(handle: number): void {",
    "function __convexDatabaseNormalizeId(table: string, value: any): any {"
  );
  prelude = removeGeneratedSection(
    prelude,
    "function __convexDatabaseWrite(",
    "const __convexContext = {"
  );
  prelude = removeGeneratedSection(
    prelude,
    "const __convexContext = {",
    "function __convexNewHostString(value: string): number {"
  );
  return `${prelude}\n${renderGuestPromiseEffectRuntime(
    hasDatabaseIndexQuery,
    hasDatabaseQueryStream
  )}`;
}

function renderValueModeAbiPrelude(
  hasDatabaseIndexQuery,
  hasDatabaseQueryStream,
  hasHostSecretVerify,
  hasInvocationUnixTimestampMs,
  effectExecutionMode,
  valueMode
) {
  const opaquePrelude =
    effectExecutionMode === GUEST_PROMISE_EFFECT_EXECUTION_MODE
      ? renderGuestPromiseAbiPrelude(
          hasDatabaseIndexQuery,
          hasDatabaseQueryStream,
          hasHostSecretVerify,
          hasInvocationUnixTimestampMs
        )
      : renderOpaqueAbiPrelude(
          hasDatabaseIndexQuery,
          hasHostSecretVerify,
          hasInvocationUnixTimestampMs
        );
  if (valueMode === "opaque") {
    return opaquePrelude;
  }
  let guestPrelude = removeGeneratedSection(
    opaquePrelude,
    "const __convexHostFunctionResult = $SHBuiltin.extern_c(",
    "const __convexHostDeveloperError = $SHBuiltin.extern_c("
  );
  guestPrelude = guestPrelude
    .replaceAll("__convexFromHost(", "__convexGuestFromHost(")
    .replaceAll("__convexToHost(", "__convexGuestToHost(")
    .replace(
      "function __convexGuestFromHost(handle: number): any",
      "function __convexFromHost(handle: number): any"
    )
    .replace(
      "function __convexGuestToHost(value: any): number",
      "function __convexToHost(value: any): number"
    );
  guestPrelude = removeGeneratedSection(
    guestPrelude,
    "function __convexSetFunctionResult(value: any): void {",
    "function __convexReportThrown(error: any): void {"
  );
  return `${guestPrelude}

const __convexHostGuestRequestLen = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_request_len(): c_int { throw 0; },
);
const __convexHostGuestRequestCopy = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_request_copy(
    destination: c_ptr,
    capacity: c_int,
  ): c_int { throw 0; },
);
const __convexHostGuestValueDecode = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_decode(
    value: c_ptr,
    valueLength: c_int,
  ): c_longlong { throw 0; },
);
const __convexHostGuestValueEncode = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_encode(
    consumingValueHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostGuestPayloadLen = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_payload_len(
    payloadHandle: c_longlong,
  ): c_int { throw 0; },
);
const __convexHostGuestPayloadCopy = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_payload_copy(
    payloadHandle: c_longlong,
    destination: c_ptr,
    capacity: c_int,
  ): c_int { throw 0; },
);
const __convexHostGuestPayloadRelease = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_payload_release(
    payloadHandle: c_longlong,
  ): void {},
);
const __convexHostGuestResult = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_guest_value_result(
    value: c_ptr,
    valueLength: c_int,
  ): void {},
);

const __convexCommitTsUnresolved =
  "This commit timestamp is unresolved: its value is assigned when the " +
  "mutation commits. Read the document after the mutation completes to get " +
  "its value.";
let __convexCommitTsPlaceholder: any = {
  valueOf() {
    throw new Error(__convexCommitTsUnresolved);
  },
  toJSON() {
    throw new Error(__convexCommitTsUnresolved);
  },
  toString() {
    return "[unresolved commit timestamp]";
  },
};
Object.defineProperty(__convexCommitTsPlaceholder, Symbol.toPrimitive, {
  configurable: false,
  enumerable: false,
  value(hint) {
    if (hint === "string") return "[unresolved commit timestamp]";
    throw new Error(__convexCommitTsUnresolved);
  },
  writable: false,
});
Object.freeze(__convexCommitTsPlaceholder);

function __convexGuestEncodeInteger(value: any): string {
  const zero = BigInt("0");
  const minimum = BigInt("-9223372036854775808");
  const maximum = BigInt("9223372036854775807");
  if (value < minimum || maximum < value) {
    throw new Error("guest-native int64 value is outside the signed 64-bit range");
  }
  let unsignedValue = value;
  if (unsignedValue < zero) unsignedValue -= minimum + minimum;
  const byteMask = BigInt("255");
  const byteShift = BigInt("8");
  let bytes = "";
  for (let index = 0; index < 8; index += 1) {
    bytes += String.fromCharCode(Number(unsignedValue & byteMask));
    unsignedValue >>= byteShift;
  }
  return btoa(bytes);
}

function __convexGuestDecodeBase64(encoded: any, tag: string): any {
  if (typeof encoded !== "string") throw new Error("Invalid guest-native " + tag + " encoding");
  // Static Hermes does not model charCodeAt on its typed string surface. atob is
  // an untyped engine global, so validate its result at this boundary.
  let bytes: any;
  try {
    bytes = atob(encoded);
  } catch {
    throw new Error("Invalid guest-native " + tag + " encoding");
  }
  if (typeof bytes !== "string") {
    throw new Error("Invalid guest-native " + tag + " encoding");
  }
  return bytes;
}

function __convexGuestRestoreInteger(encoded: any): any {
  const bytes = __convexGuestDecodeBase64(encoded, "$integer");
  if (bytes.length !== 8) throw new Error("Invalid guest-native $integer encoding");
  const zero = BigInt("0");
  const byteBase = BigInt("256");
  const maximum = BigInt("9223372036854775807");
  const signedOffset = BigInt("-18446744073709551616");
  let value = zero;
  let multiplier = BigInt("1");
  for (let index = 0; index < bytes.length; index += 1) {
    value += BigInt(bytes.charCodeAt(index)) * multiplier;
    multiplier *= byteBase;
  }
  return value > maximum ? value + signedOffset : value;
}

function __convexGuestEncodeBytes(value: any): string {
  const input = new Uint8Array(value);
  const chunks: any[] = [];
  let chunk = "";
  for (let index = 0; index < input.length; index += 1) {
    chunk += String.fromCharCode(input[index]);
    if (chunk.length === 16384) {
      __convexArrayPush(chunks, chunk);
      chunk = "";
    }
  }
  if (chunk.length !== 0) __convexArrayPush(chunks, chunk);
  return btoa(chunks.join(""));
}

function __convexGuestRestoreBytes(encoded: any): any {
  const source = __convexGuestDecodeBase64(encoded, "$bytes");
  const buffer = new ArrayBuffer(source.length);
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < source.length; index += 1) {
    bytes[index] = source.charCodeAt(index);
  }
  return buffer;
}

function __convexGuestEncodeFloat(value: number): string {
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setFloat64(0, value, true);
  return __convexGuestEncodeBytes(buffer);
}

function __convexGuestRestoreFloat(encoded: any): number {
  const source = __convexGuestDecodeBase64(encoded, "$float");
  if (source.length !== 8) throw new Error("Invalid guest-native $float encoding");
  const buffer = new ArrayBuffer(8);
  const bytes = new Uint8Array(buffer);
  for (let index = 0; index < source.length; index += 1) {
    bytes[index] = source.charCodeAt(index);
  }
  const value = new DataView(buffer).getFloat64(0, true);
  if (
    value !== value ||
    value === Infinity ||
    value === -Infinity ||
    1 / value === -Infinity
  ) {
    return value;
  }
  throw new Error("Invalid guest-native $float encoding");
}

function __convexGuestContainsIdentity(values: any[], target: any): boolean {
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === target) return true;
  }
  return false;
}

function __convexGuestIsArray(value: any): boolean {
  // Static Hermes' typed Array class omits isArray, but the runtime builtin is present.
  return globalThis.Array.isArray(value);
}

function __convexGuestValidateObjectField(key: string): void {
  if (key.length > 1024) throw new Error("Convex object field name is too long");
  if (key.charAt(0) === "$") throw new Error("Convex object field name uses a reserved prefix");
  for (let index = 0; index < key.length; index += 1) {
    const character = key.charAt(index);
    if (character < " " || character > "~") {
      throw new Error("Convex object field name must contain only non-control ASCII characters");
    }
  }
}

function __convexGuestDefineObjectField(output: any, key: string, value: any): void {
  // Assignment would invoke Object.prototype.__proto__ instead of creating the valid Convex field.
  Object.defineProperty(output, key, {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

function __convexGuestEncodeTagged(value: any, ancestors: any[]): any {
  if (value === __convexCommitTsPlaceholder) return {$commitTs: null};
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (value !== value || value === Infinity || value === -Infinity || 1 / value === -Infinity) {
      return {$float: __convexGuestEncodeFloat(value)};
    }
    return value;
  }
  if (value === undefined) throw new Error("undefined is not a Convex value");
  if (typeof value === "bigint") {
    return {$integer: __convexGuestEncodeInteger(value)};
  }
  if (typeof value === "function" || typeof value === "symbol") {
    throw new Error("Functions and symbols are not Convex values");
  }
  if (typeof value !== "object") throw new Error("Unsupported Convex value");
  if (value instanceof ArrayBuffer) {
    return {$bytes: __convexGuestEncodeBytes(value)};
  }
  if (__convexGuestContainsIdentity(ancestors, value)) {
    throw new Error("Cyclic objects are not Convex values");
  }
  __convexArrayPush(ancestors, value);
  try {
    if (__convexGuestIsArray(value)) {
      const output = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) throw new Error("Sparse arrays are not Convex values");
        __convexArrayPush(output, __convexGuestEncodeTagged(value[index], ancestors));
      }
      return output;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Only plain objects are Convex values");
    }
    if (
      typeof Object.getOwnPropertySymbols === "function" &&
      Object.getOwnPropertySymbols(value).length !== 0
    ) {
      throw new Error("Symbol properties are not Convex values");
    }
    const output: any = {};
    const keys = Object.keys(value).sort();
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        typeof descriptor.get === "function" ||
        typeof descriptor.set === "function"
      ) {
        throw new Error("Accessor properties are not Convex values");
      }
      if (descriptor.value === undefined) continue;
      __convexGuestValidateObjectField(key);
      __convexGuestDefineObjectField(
        output,
        key,
        __convexGuestEncodeTagged(descriptor.value, ancestors),
      );
    }
    return output;
  } finally {
    ancestors.pop();
  }
}

function __convexGuestRestoreTagged(value: any): any {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return value;
  }
  if (__convexGuestIsArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      value[index] = __convexGuestRestoreTagged(value[index]);
    }
    return value;
  }
  if (typeof value !== "object") throw new Error("Invalid guest-native Convex JSON");
  const keys = Object.keys(value);
  if (keys.length === 1) {
    if (keys[0] === "$commitTs") {
      if (value.$commitTs !== null) {
        throw new Error("Invalid guest-native $commitTs encoding");
      }
      return __convexCommitTsPlaceholder;
    }
    if (keys[0] === "$float") return __convexGuestRestoreFloat(value.$float);
    if (keys[0] === "$integer") return __convexGuestRestoreInteger(value.$integer);
    if (keys[0] === "$bytes") {
      return __convexGuestRestoreBytes(value.$bytes);
    }
    if (keys[0] === "$map" || keys[0] === "$set") {
      throw new Error("Map and Set are not Convex boundary values");
    }
  }
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    __convexGuestValidateObjectField(key);
    __convexGuestDefineObjectField(value, key, __convexGuestRestoreTagged(value[key]));
  }
  return value;
}

let __convexGuestTransferScratchPointer: c_ptr = __convexNullPointer;
let __convexGuestTransferScratchCapacity = 0;

function __convexGuestTransferScratch(minimumCapacity: number): c_ptr {
  if (minimumCapacity <= __convexGuestTransferScratchCapacity) {
    return __convexGuestTransferScratchPointer;
  }
  // Scratch contents never survive a bridge call. Release the old high-water
  // allocation before growth so the guest does not need both capacities live.
  if (__convexGuestTransferScratchPointer !== __convexNullPointer) {
    __convexFree(__convexGuestTransferScratchPointer);
    __convexGuestTransferScratchPointer = __convexNullPointer;
    __convexGuestTransferScratchCapacity = 0;
  }
  const pointer = __convexMalloc(minimumCapacity);
  if (pointer === __convexNullPointer) throw new Error("Static Hermes native allocation failed");
  __convexGuestTransferScratchPointer = pointer;
  __convexGuestTransferScratchCapacity = minimumCapacity;
  return pointer;
}

function __convexReadGuestRequestJson(): string {
  const length = __convexHostGuestRequestLen();
  if (length < 0) throw new Error("Invalid guest-native request length");
  const pointer = __convexGuestTransferScratch(length + 1);
  if (__convexHostGuestRequestCopy(pointer, length) !== length) {
    throw new Error("Guest-native request copy failed");
  }
  return __convexAsciizToString($SHBuiltin.c_native_runtime(), pointer, length);
}

function __convexReadGuestRequest(): any {
  const value = __convexGuestRestoreTagged(JSON.parse(__convexReadGuestRequestJson()));
  if (value === null || typeof value !== "object" || __convexGuestIsArray(value)) {
    throw new Error("Guest-native request must be an argument object");
  }
  return value;
}

function __convexReadGuestRequestTaggedJson(): string {
  const source = __convexReadGuestRequestJson();
  // The host supplied canonical Convex JSON; the SDK parses the complete
  // argument object when it invokes the registration wrapper.
  if (source.charAt(0) !== "{" || source.charAt(source.length - 1) !== "}") {
    throw new Error("Guest-native request must be an argument object");
  }
  return source;
}

function __convexGuestToHost(value: any): number {
  const source = JSON.stringify(__convexGuestEncodeTagged(value, []));
  const pointer = __convexGuestTransferScratch(source.length * 3 + 1);
  const length = __convexWriteUtf8(source, pointer);
  const handle = __convexHostGuestValueDecode(pointer, length);
  if (handle <= 0) throw new Error("Guest-native Convex value decode failed");
  return handle;
}

function __convexGuestFromHost(consumingValueHandle: number): any {
  return __convexGuestRestoreTagged(
    JSON.parse(__convexGuestTaggedJsonFromHost(consumingValueHandle)),
  );
}

function __convexGuestTaggedJsonFromHost(consumingValueHandle: number): string {
  if (consumingValueHandle <= 0) throw new Error("Invalid guest-native host value handle");
  const payloadHandle = __convexHostGuestValueEncode(consumingValueHandle);
  if (payloadHandle <= 0) throw new Error("Guest-native Convex value encode failed");
  try {
    const length = __convexHostGuestPayloadLen(payloadHandle);
    if (length < 0) throw new Error("Invalid guest-native payload length");
    const pointer = __convexGuestTransferScratch(length + 1);
    if (__convexHostGuestPayloadCopy(payloadHandle, pointer, length) !== length) {
      throw new Error("Guest-native payload copy failed");
    }
    return __convexAsciizToString($SHBuiltin.c_native_runtime(), pointer, length);
  } finally {
    __convexHostGuestPayloadRelease(payloadHandle);
  }
}

function __convexSetGuestFunctionResult(value: any): void {
  const source = JSON.stringify(__convexGuestEncodeTagged(value, []));
  const pointer = __convexGuestTransferScratch(source.length * 3 + 1);
  const length = __convexWriteUtf8(source, pointer);
  __convexHostGuestResult(pointer, length);
}

function __convexSetGuestFunctionTaggedJsonResult(source: string): void {
  const pointer = __convexGuestTransferScratch(source.length * 3 + 1);
  const length = __convexWriteUtf8(source, pointer);
  __convexHostGuestResult(pointer, length);
}`;
}

function renderNativeCapabilityGuestValuePrelude() {
  let prelude = renderValueModeAbiPrelude(
    false,
    false,
    false,
    false,
    GUEST_PROMISE_EFFECT_EXECUTION_MODE,
    "guest-native-json"
  );
  prelude = removeGeneratedSection(
    prelude,
    "const __convexHostAsyncOperationStartTake = $SHBuiltin.extern_c(",
    "const __convexHostGuestRequestLen = $SHBuiltin.extern_c("
  );
  prelude = removeGeneratedSection(
    prelude,
    "const __convexHostRequestField = $SHBuiltin.extern_c(",
    "const __convexHostValueRelease = $SHBuiltin.extern_c("
  );
  prelude = removeGeneratedSection(
    prelude,
    "const __convexHostValueNullNew = $SHBuiltin.extern_c(",
    "const __convexHostDeveloperError = $SHBuiltin.extern_c("
  );
  prelude = removeGeneratedSection(
    prelude,
    "function __convexValueArrayNew(): number {",
    "function __convexValueRelease(handle: number): void {"
  );
  prelude = removeGeneratedSection(
    prelude,
    "function __convexReadHostString(handle: number): string {",
    "function __convexReportThrown(error: any): void {"
  );
  return `${ARRAY_PUSH_HELPER}\n\n${prelude}`;
}

function renderNativeCapabilityRequestEnvelopeHostImports() {
  return String.raw`
const __convexHostCapabilityRequestDecode = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_request_decode(
    request: c_ptr,
    requestLength: c_int,
  ): c_longlong { throw 0; },
);
const __convexHostCapabilityRequestRelease = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_request_release(requestHandle: c_longlong): void {},
);`;
}

function renderNativeCapabilityRuntimeHostImports() {
  return String.raw`
const __convexHostCapabilityCurrent = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_current(): c_longlong { throw 0; },
);
const __convexHostConsoleMessage = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_console_message(
    capabilityIdentity: c_longlong,
    level: c_int,
    messagesJson: c_ptr,
    messagesJsonLength: c_int,
  ): c_int { throw 0; },
);
const __convexHostCapabilitySyncTake = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_sync_take(
    capabilityIdentity: c_longlong,
    requestHandle: c_longlong,
  ): c_longlong { throw 0; },
);
const __convexHostCapabilityStartTake = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_start_take(
    capabilityIdentity: c_longlong,
    requestHandle: c_longlong,
  ): c_int { throw 0; },
);
const __convexHostCapabilityQueryStreamOpenTake = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_query_stream_open_take(
    capabilityIdentity: c_longlong,
    requestHandle: c_longlong,
  ): c_int { throw 0; },
);
const __convexHostAsyncQueryStreamNext = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_query_stream_next(streamHandle: c_int): c_int { throw 0; },
);
const __convexHostAsyncQueryStreamClose = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_async_query_stream_close(streamHandle: c_int): void {},
);
const __convexHostCryptoSubtleDigestSha256 = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_crypto_subtle_digest_sha256(
    capabilityIdentity: c_longlong,
    input: c_ptr,
    inputLength: c_int,
    output: c_ptr,
    outputLength: c_int,
  ): void {},
);
const __convexHostCryptoGetRandomValues = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_crypto_get_random_values(
    capabilityIdentity: c_longlong,
    output: c_ptr,
    outputLength: c_int,
  ): void {},
);
const __convexHostCryptoRandomUuid = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_crypto_random_uuid(
    capabilityIdentity: c_longlong,
    output: c_ptr,
    outputLength: c_int,
  ): void {},
);`;
}

function renderNativeConvexSdkFacade(sdkPackageVersion) {
  if (
    typeof sdkPackageVersion !== "string" ||
    sdkPackageVersion.length === 0 ||
    /[\r\n\0]/u.test(sdkPackageVersion)
  ) {
    throw new Error("sdkPackageVersion must be a non-empty package version");
  }
  return String.raw`
let __convexSdkActiveUdfKind: ?string = null;
let __convexSdkQueryStreams: Array<any> = [];

function __convexSdkActivate(udfKind: any): void {
  if (udfKind !== "query" && udfKind !== "mutation") {
    throw new Error("Invocation UDF kind is invalid");
  }
  if (__convexSdkActiveUdfKind !== null) {
    throw new Error("Invocation SDK facade is already active");
  }
  __convexSdkActiveUdfKind = udfKind;
}

function __convexSdkRequireActive(): string {
  const udfKind = __convexSdkActiveUdfKind;
  if (udfKind !== "query" && udfKind !== "mutation") {
    throw new Error("Invocation SDK facade is unavailable");
  }
  return udfKind;
}

function __convexSdkParseArguments(jsonArguments: any): any {
  if (typeof jsonArguments !== "string") {
    throw new Error("Convex SDK syscall arguments must be a JSON string");
  }
  let parsed: any;
  try {
    parsed = JSON.parse(jsonArguments);
  } catch {
    throw new Error("Convex SDK syscall arguments are not valid JSON");
  }
  __convexCapabilityOwnDataKeys(parsed, "Convex SDK syscall arguments");
  return parsed;
}

function __convexSdkRequireInstalledVersion(version: any, description: string): void {
  if (version !== ${JSON.stringify(sdkPackageVersion)}) {
    throw new Error(description + " version is invalid");
  }
}

function __convexSdkRestorePatch(value: any): any {
  const keys = __convexCapabilityOwnDataKeys(value, "Convex SDK shallowMerge value");
  const patch: any = {};
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    __convexGuestValidateObjectField(key);
    const encoded = value[key];
    if (
      encoded !== null &&
      typeof encoded === "object" &&
      !__convexGuestIsArray(encoded)
    ) {
      const encodedKeys = __convexCapabilityOwnDataKeys(
        encoded,
        "Convex SDK shallowMerge field",
      );
      if (encodedKeys.length === 1 && encodedKeys[0] === "$undefined") {
        if (encoded.$undefined !== null) {
          throw new Error("Convex SDK shallowMerge deletion marker is invalid");
        }
        __convexGuestDefineObjectField(patch, key, undefined);
        continue;
      }
    }
    __convexGuestDefineObjectField(patch, key, __convexCapabilityTaggedValue(encoded));
  }
  return patch;
}

function __convexSdkRestoreOptionalQueryValue(value: any, description: string): any {
  if (value !== null && typeof value === "object" && !__convexGuestIsArray(value)) {
    const keys = __convexCapabilityOwnDataKeys(value, description);
    if (keys.length === 1 && keys[0] === "$undefined") {
      if (value.$undefined !== null) {
        throw new Error(description + " undefined marker is invalid");
      }
      return undefined;
    }
  }
  return __convexCapabilityTaggedValue(value);
}

function __convexSdkRestoreQueryExpression(expression: any): any {
  const keys = __convexCapabilityOwnDataKeys(expression, "Convex SDK query expression");
  if (keys.length !== 1) throw new Error("Convex SDK query expression has invalid fields");
  const kind = keys[0];
  const value = expression[kind];
  if (kind === "$literal") {
    return __convexCapabilitySingleFieldObject(
      kind,
      __convexSdkRestoreOptionalQueryValue(value, "Convex SDK query literal"),
    );
  }
  if (kind === "$field") {
    if (typeof value !== "string") throw new Error("Convex SDK query field is invalid");
    return __convexCapabilitySingleFieldObject(kind, value);
  }
  if (kind === "$neg" || kind === "$not") {
    return __convexCapabilitySingleFieldObject(kind, __convexSdkRestoreQueryExpression(value));
  }
  if (kind === "$and" || kind === "$or") {
    if (!__convexGuestIsArray(value)) {
      throw new Error("Convex SDK query logical operands are invalid");
    }
    const operands = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new Error("Convex SDK query operands must not be sparse");
      __convexArrayPush(operands, __convexSdkRestoreQueryExpression(value[index]));
    }
    return __convexCapabilitySingleFieldObject(kind, operands);
  }
  if (
    kind === "$eq" ||
    kind === "$neq" ||
    kind === "$lt" ||
    kind === "$lte" ||
    kind === "$gt" ||
    kind === "$gte" ||
    kind === "$add" ||
    kind === "$sub" ||
    kind === "$mul" ||
    kind === "$div" ||
    kind === "$mod"
  ) {
    if (!__convexGuestIsArray(value) || value.length !== 2 || !(0 in value) || !(1 in value)) {
      throw new Error("Convex SDK query binary operands are invalid");
    }
    return __convexCapabilitySingleFieldObject(kind, [
      __convexSdkRestoreQueryExpression(value[0]),
      __convexSdkRestoreQueryExpression(value[1]),
    ]);
  }
  throw new Error("Convex SDK query expression is unsupported");
}

function __convexSdkQueryIndexIdentity(indexName: any): any {
  if (typeof indexName !== "string") throw new Error("Convex SDK query index is invalid");
  const separator = indexName.indexOf(".");
  if (
    separator <= 0 ||
    separator + 1 >= indexName.length ||
    indexName.indexOf(".", separator + 1) !== -1
  ) {
    throw new Error("Convex SDK query index is invalid");
  }
  const table = indexName.slice(0, separator);
  return {
    table: __convexCapabilityRequireTable(table, table.charAt(0) === "_", "query"),
    index: indexName.slice(separator + 1),
  };
}

function __convexSdkRestoreQuerySource(source: any): any {
  __convexCapabilityOwnDataKeys(source, "Convex SDK query source");
  if (source.type === "FullTableScan") {
    __convexCapabilityRequireExactKeys(
      source,
      ["order", "tableName", "type"],
      "Convex SDK query source",
    );
    const table = __convexCapabilityRequireTable(
      source.tableName,
      typeof source.tableName === "string" && source.tableName.charAt(0) === "_",
      "query",
    );
    return {table, source: {type: "fullTableScan"}, order: source.order};
  }
  if (source.type === "IndexRange") {
    __convexCapabilityRequireExactKeys(
      source,
      ["indexName", "order", "range", "type"],
      "Convex SDK query source",
    );
    if (!__convexGuestIsArray(source.range)) {
      throw new Error("Convex SDK query range is invalid");
    }
    const constraints = [];
    for (let index = 0; index < source.range.length; index += 1) {
      if (!(index in source.range)) throw new Error("Convex SDK query range must not be sparse");
      const constraint = source.range[index];
      __convexCapabilityRequireExactKeys(
        constraint,
        ["fieldPath", "type", "value"],
        "Convex SDK query constraint",
      );
      if (typeof constraint.fieldPath !== "string") {
        throw new Error("Convex SDK query constraint field is invalid");
      }
      let operator: string;
      if (constraint.type === "Eq") operator = "eq";
      else if (constraint.type === "Gt") operator = "gt";
      else if (constraint.type === "Gte") operator = "gte";
      else if (constraint.type === "Lt") operator = "lt";
      else if (constraint.type === "Lte") operator = "lte";
      else {
        throw new Error("Convex SDK query constraint operator is unsupported");
      }
      __convexArrayPush(constraints, {
        field: constraint.fieldPath,
        operator,
        value: __convexSdkRestoreOptionalQueryValue(
          constraint.value,
          "Convex SDK query constraint value",
        ),
      });
    }
    const identity = __convexSdkQueryIndexIdentity(source.indexName);
    return {
      table: identity.table,
      source: {type: "indexRange", index: identity.index, constraints},
      order: source.order,
    };
  }
  if (source.type !== "Search") throw new Error("Convex SDK query source type is unsupported");
  __convexCapabilityRequireExactKeys(
    source,
    ["filters", "indexName", "type"],
    "Convex SDK query source",
  );
  if (!__convexGuestIsArray(source.filters) || source.filters.length === 0) {
    throw new Error("Convex SDK query search filters are invalid");
  }
  const filters = [];
  for (let index = 0; index < source.filters.length; index += 1) {
    if (!(index in source.filters)) {
      throw new Error("Convex SDK query search filters must not be sparse");
    }
    const filter = source.filters[index];
    __convexCapabilityRequireExactKeys(
      filter,
      ["fieldPath", "type", "value"],
      "Convex SDK query search filter",
    );
    if (typeof filter.fieldPath !== "string") {
      throw new Error("Convex SDK query search filter field is invalid");
    }
    if (index === 0) {
      if (filter.type !== "Search" || typeof filter.value !== "string") {
        throw new Error("Convex SDK query search filters must begin with a search filter");
      }
      __convexArrayPush(filters, {
        field: filter.fieldPath,
        type: "search",
        value: filter.value,
      });
      continue;
    }
    if (filter.type !== "Eq") {
      throw new Error("Convex SDK query search equality filter is invalid");
    }
    __convexArrayPush(filters, {
      field: filter.fieldPath,
      type: "eq",
      value: __convexSdkRestoreOptionalQueryValue(
        filter.value,
        "Convex SDK query search equality value",
      ),
    });
  }
  const identity = __convexSdkQueryIndexIdentity(source.indexName);
  return {
    table: identity.table,
    source: {type: "search", index: identity.index, filters},
    order: null,
  };
}

function __convexSdkRestoreQuery(query: any): any {
  __convexCapabilityRequireExactKeys(query, ["operators", "source"], "Convex SDK query");
  if (!__convexGuestIsArray(query.operators) || query.operators.length > 256) {
    throw new Error("Convex SDK query operators are invalid");
  }
  const operators = [];
  for (let index = 0; index < query.operators.length; index += 1) {
    if (!(index in query.operators)) {
      throw new Error("Convex SDK query operators must not be sparse");
    }
    const operator = query.operators[index];
    const keys = __convexCapabilityOwnDataKeys(operator, "Convex SDK query operator");
    if (keys.length !== 1) throw new Error("Convex SDK query operator has invalid fields");
    if (keys[0] === "filter") {
      __convexArrayPush(operators, {
        type: "filter",
        expression: __convexSdkRestoreQueryExpression(operator.filter),
      });
      continue;
    }
    if (keys[0] !== "limit" || !Number.isSafeInteger(operator.limit) || operator.limit < 0) {
      throw new Error("Convex SDK query operator is unsupported");
    }
    __convexArrayPush(operators, {type: "limit", limit: operator.limit});
  }
  const mappedSource = __convexSdkRestoreQuerySource(query.source);
  if (
    mappedSource.order !== null &&
    mappedSource.order !== "asc" &&
    mappedSource.order !== "desc"
  ) {
    throw new Error("Convex SDK query order is invalid");
  }
  return {
    table: mappedSource.table,
    source: mappedSource.source,
    operators,
    order: mappedSource.order,
  };
}

function __convexSdkQueryRequest(query: any, terminal: string, pagination: any): any {
  const mapped = __convexSdkRestoreQuery(query);
  const request: any = {
    version: ${CAPABILITY_REQUEST_ABI_VERSION},
    kind: "dbQuery",
    table: mapped.table,
    source: mapped.source,
    operators: mapped.operators,
    order: mapped.order,
    terminal,
  };
  if (pagination !== null) request.pagination = pagination;
  return request;
}

function __convexSdkQueryPagePagination(args: any): any {
  const keys = __convexCapabilityOwnDataKeys(args, "Convex SDK queryPage arguments");
  const allowed = [
    "cursor",
    "endCursor",
    "maximumBytesRead",
    "maximumRowsRead",
    "pageSize",
    "query",
    "version",
  ];
  const required = ["endCursor", "maximumRowsRead", "pageSize", "query", "version"];
  for (let index = 0; index < keys.length; index += 1) {
    if (allowed.indexOf(keys[index]) === -1) {
      throw new Error("Convex SDK queryPage arguments have invalid fields");
    }
  }
  for (let index = 0; index < required.length; index += 1) {
    if (keys.indexOf(required[index]) === -1) {
      throw new Error("Convex SDK queryPage arguments have invalid fields");
    }
  }
  function requireNullableString(value: any, description: string): any {
    if (value !== null && typeof value !== "string") throw new Error(description + " is invalid");
    return value;
  }
  function requireNullableLimit(value: any, description: string): any {
    if (value !== null && (!Number.isSafeInteger(value) || value < 0)) {
      throw new Error(description + " is invalid");
    }
    return value;
  }
  if (typeof args.pageSize !== "number" || !isFinite(args.pageSize) || args.pageSize < 0) {
    throw new Error("Convex SDK queryPage page size is invalid");
  }
  return {
    cursor: requireNullableString(
      keys.indexOf("cursor") === -1 ? null : args.cursor,
      "Convex SDK queryPage cursor",
    ),
    endCursor: requireNullableString(args.endCursor, "Convex SDK queryPage end cursor"),
    maximumBytesRead: requireNullableLimit(
      keys.indexOf("maximumBytesRead") === -1 ? null : args.maximumBytesRead,
      "Convex SDK queryPage maximum bytes read",
    ),
    maximumRowsRead: requireNullableLimit(
      args.maximumRowsRead,
      "Convex SDK queryPage maximum rows read",
    ),
    pageSize: args.pageSize,
  };
}

function __convexSdkRequireQueryId(queryId: any): number {
  if (!Number.isSafeInteger(queryId) || queryId < 1) {
    throw new Error("Convex SDK query ID is invalid");
  }
  return queryId;
}

function __convexSdkRequireQueryStream(queryId: any): any {
  const checkedQueryId = __convexSdkRequireQueryId(queryId);
  const state = __convexSdkQueryStreams[checkedQueryId - 1];
  if (state === undefined) throw new Error("Convex SDK query stream is unavailable");
  return state;
}

function __convexSdkReleaseQueryStream(state: any, closeHost: boolean): void {
  if (state.done) return;
  if (closeHost) __convexHostAsyncQueryStreamClose(state.streamHandle);
  state.done = true;
  state.streamHandle = 0;
  __convexReleaseOpenQueryStream(state.cleanupSlot);
  state.cleanupSlot = -1;
}

function __convexSdkOpenQueryStream(request: any): number {
  const state: any = {
    cleanupSlot: -1,
    done: false,
    pending: false,
    streamHandle: __convexCapabilityOpenQueryStream(request),
  };
  state.cleanupSlot = __convexRegisterOpenQueryStream(() => {
    state.done = true;
    state.streamHandle = 0;
    state.cleanupSlot = -1;
  });
  __convexSdkQueryStreams.push(state);
  return __convexSdkQueryStreams.length;
}

function __convexSdkQueryStreamNext(queryId: any): any {
  const state = __convexSdkRequireQueryStream(queryId);
  if (state.done) throw new Error("Convex SDK query stream is closed");
  if (state.pending) throw new Error("Convex SDK query stream already has a pending read");
  state.pending = true;
  return __convexStartCapabilityQueryStreamNext(state.streamHandle, "taggedJson").then(
    (result) => {
      state.pending = false;
      let completed = false;
      try {
        // The host creates and validates the canonical envelope. Inspect its
        // fixed prefix here so the SDK alone parses the returned document.
        if (result === '{"done":true,"value":null}') {
          completed = true;
          __convexSdkReleaseQueryStream(state, false);
        } else if (typeof result !== "string" || !result.startsWith('{"done":false,"value":')) {
          throw new Error("Convex SDK query stream result is invalid");
        }
        return result;
      } catch (error) {
        __convexSdkReleaseQueryStream(
          state,
          !completed,
        );
        throw error;
      }
    },
    (error) => {
      state.pending = false;
      __convexSdkReleaseQueryStream(state, false);
      throw error;
    },
  );
}

function __convexSdkCountQuery(request: any): any {
  const iterator = __convexCreateCapabilityQueryIterator(request);
  function readNext(count: number): any {
    return iterator.next().then((result) => {
      if (result.done) return count;
      if (count === Number.MAX_SAFE_INTEGER) {
        throw new Error("Convex SDK count result exceeds the safe integer range");
      }
      return readNext(count + 1);
    });
  }
  return readNext(0);
}

function __convexSdkScheduleRequest(args: any): any {
  const keys = __convexCapabilityOwnDataKeys(args, "Convex SDK schedule arguments");
  let functionAddress: any;
  if (keys.indexOf("functionHandle") !== -1) {
    __convexCapabilityRequireExactKeys(
      args,
      ["args", "functionHandle", "ts", "version"],
      "Convex SDK schedule arguments",
    );
    functionAddress = {functionHandle: args.functionHandle};
  } else if (keys.indexOf("name") !== -1) {
    __convexCapabilityRequireExactKeys(
      args,
      ["args", "name", "ts", "version"],
      "Convex SDK schedule arguments",
    );
    functionAddress = {name: args.name};
  } else if (keys.indexOf("reference") !== -1) {
    __convexCapabilityRequireExactKeys(
      args,
      ["args", "reference", "ts", "version"],
      "Convex SDK schedule arguments",
    );
    functionAddress = {reference: args.reference};
  } else {
    throw new Error("Convex SDK schedule arguments have invalid fields");
  }
  __convexSdkRequireInstalledVersion(args.version, "Convex SDK schedule");
  const timestampSeconds = __convexCapabilityRequireFiniteNumber(
    args.ts,
    "Convex SDK schedule timestamp",
  );
  const timestampMilliseconds = __convexCapabilityRequireFiniteNumber(
    timestampSeconds * 1000,
    "Convex SDK schedule timestamp",
  );
  const functionArgs = __convexCapabilityTaggedValue(args.args);
  return {
    version: ${CAPABILITY_REQUEST_ABI_VERSION},
    kind: "schedulerRunAt",
    timestampMilliseconds,
    functionAddress: __convexCapabilityEncodeFunctionAddress(functionAddress),
    args: functionArgs,
  };
}

function __convexSdkFunctionAddressFromArguments(
  args: any,
  envelopeFields: string[],
  description: string,
): any {
  const keys = __convexCapabilityOwnDataKeys(args, description);
  let addressField: string;
  let functionAddress: any;
  if (keys.indexOf("functionHandle") !== -1) {
    addressField = "functionHandle";
    functionAddress = {functionHandle: args.functionHandle};
  } else if (keys.indexOf("name") !== -1) {
    addressField = "name";
    functionAddress = {name: args.name};
  } else if (keys.indexOf("reference") !== -1) {
    addressField = "reference";
    functionAddress = {reference: args.reference};
  } else {
    throw new Error(description + " have invalid fields");
  }
  const exactFields = envelopeFields.slice();
  exactFields.push(addressField);
  __convexCapabilityRequireExactKeys(args, exactFields, description);
  return __convexCapabilityEncodeFunctionAddress(functionAddress);
}

function __convexSdkStartAsync(request: any, resultKind: string): any {
  const capabilityIdentity = __convexHostCapabilityCurrent();
  if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
  return __convexCapabilityStartAsync(
    (requestHandle: number): number =>
      __convexHostCapabilityStartTake(capabilityIdentity, requestHandle),
    request,
    resultKind,
  );
}

function __convexSdkRunSync(request: any): any {
  const capabilityIdentity = __convexHostCapabilityCurrent();
  if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
  return __convexCapabilityRunSync(
    (requestHandle: number): number =>
      __convexHostCapabilitySyncTake(capabilityIdentity, requestHandle),
    request,
  );
}

function __convexSdkEncodeResult(value: any): string {
  return JSON.stringify(__convexGuestEncodeTagged(value, []));
}

function __convexSdkEncodeInsertedId(id: any): string {
  if (typeof id !== "string") {
    throw new Error("Convex SDK insert returned an invalid document ID");
  }
  return JSON.stringify({_id: id});
}

function __convexSdkEncodeScheduledId(id: any): string {
  if (typeof id !== "string") {
    throw new Error("Convex SDK schedule returned an invalid scheduled function ID");
  }
  return JSON.stringify(id);
}

function __convexSdkEncodeFunctionHandle(handle: any): string {
  if (typeof handle !== "string") {
    throw new Error("Convex SDK createFunctionHandle returned an invalid function handle");
  }
  return JSON.stringify(handle);
}

function __convexSdkAsyncSyscall(operation: any, jsonArguments: any): any {
  const udfKind = __convexSdkRequireActive();
  if (typeof operation !== "string") {
    throw new Error("Convex SDK async syscall operation must be a string");
  }
  if (operation === "1.0/getUserIdentity") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["requestId"],
      "Convex SDK getUserIdentity arguments",
    );
    if (args.requestId !== "") {
      throw new Error("Convex SDK getUserIdentity arguments are invalid");
    }
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "authGetUserIdentity"},
      "taggedJson",
    );
  }
  if (operation === "1.0/getFunctionMetadata") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      [],
      "Convex SDK getFunctionMetadata arguments",
    );
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "getFunctionMetadata"},
      "taggedJson",
    );
  }
  if (operation === "1.0/getDeploymentMetadata") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      [],
      "Convex SDK getDeploymentMetadata arguments",
    );
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "getDeploymentMetadata"},
      "taggedJson",
    );
  }
  if (operation === "1.0/getTransactionMetrics") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      [],
      "Convex SDK getTransactionMetrics arguments",
    );
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "getTransactionMetrics"},
      "taggedJson",
    );
  }
  if (operation === "1.0/getRequestMetadata") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK getRequestMetadata is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      [],
      "Convex SDK getRequestMetadata arguments",
    );
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "getRequestMetadata"},
      "taggedJson",
    );
  }
  if (operation === "1.0/createFunctionHandle") {
    const args = __convexSdkParseArguments(jsonArguments);
    const functionAddress = __convexSdkFunctionAddressFromArguments(
      args,
      ["version"],
      "Convex SDK createFunctionHandle arguments",
    );
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK createFunctionHandle");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "functionHandleCreate",
        functionAddress,
      },
      "hostValue",
    ).then(__convexSdkEncodeFunctionHandle);
  }
  if (operation === "1.0/runUdf") {
    const args = __convexSdkParseArguments(jsonArguments);
    const envelopeFields = ["args", "udfType"];
    if (Object.prototype.hasOwnProperty.call(args, "transactionLimits")) {
      envelopeFields.push("transactionLimits");
    }
    const functionAddress = __convexSdkFunctionAddressFromArguments(
      args,
      envelopeFields,
      "Convex SDK runUdf arguments",
    );
    if (
      args.udfType !== "mutation" &&
      args.udfType !== "query" &&
      args.udfType !== "snapshotQuery"
    ) {
      throw new Error("Convex SDK nested UDF type is unsupported");
    }
    if (udfKind === "query" && args.udfType !== "query") {
      throw new Error("Convex SDK nested mutation and snapshotQuery are unavailable in queries");
    }
    const functionArgumentKeys = __convexCapabilityOwnDataKeys(
      args.args,
      "Convex SDK runUdf function arguments",
    );
    for (let index = 0; index < functionArgumentKeys.length; index += 1) {
      __convexGuestValidateObjectField(functionArgumentKeys[index]);
    }
    const functionArgs = __convexCapabilityTaggedValue(args.args);
    const transactionLimits = Object.prototype.hasOwnProperty.call(args, "transactionLimits")
      ? __convexCapabilityEncodeTransactionLimits(args.transactionLimits)
      : null;
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "runUdf",
        udfType: args.udfType,
        functionAddress,
        args: functionArgs,
        transactionLimits,
      },
      "taggedJson",
    );
  }
  if (operation === "1.0/auditLog") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["body", "version"],
      "Convex SDK auditLog arguments",
    );
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK auditLog");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "auditLog",
        body: __convexCapabilityEncodeAuditBody(args.body),
      },
      "undefined",
    ).then((): string => "null");
  }
  if (operation === "1.0/count") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(args, ["table"], "Convex SDK count arguments");
    const table = __convexCapabilityRequireTable(
      args.table,
      typeof args.table === "string" && args.table.charAt(0) === "_",
      "query",
    );
    return __convexSdkCountQuery({
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
      kind: "dbQuery",
      table,
      source: {type: "fullTableScan"},
      operators: [],
      order: null,
      terminal: "stream",
    }).then(__convexSdkEncodeResult);
  }
  if (operation === "1.0/queryCollect") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["query", "version"],
      "Convex SDK collect query arguments",
    );
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK collect query");
    return __convexSdkStartAsync(
      __convexSdkQueryRequest(args.query, "collect", null),
      "taggedJson",
    );
  }
  if (operation === "1.0/queryPage") {
    const args = __convexSdkParseArguments(jsonArguments);
    const pagination = __convexSdkQueryPagePagination(args);
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK queryPage");
    return __convexSdkStartAsync(
      __convexSdkQueryRequest(args.query, "paginate", pagination),
      "taggedJson",
    );
  }
  if (operation === "1.0/queryStreamNext") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["queryId"],
      "Convex SDK queryStreamNext arguments",
    );
    return __convexSdkQueryStreamNext(args.queryId);
  }
  if (operation === "1.0/get") {
    const args = __convexSdkParseArguments(jsonArguments);
    const hasTable = args.table !== undefined;
    __convexCapabilityRequireExactKeys(
      args,
      hasTable ? ["id", "isSystem", "table", "version"] : ["id", "isSystem", "version"],
      "Convex SDK get arguments",
    );
    if (typeof args.isSystem !== "boolean") {
      throw new Error("Convex SDK get isSystem field is invalid");
    }
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK get");
    const id = __convexGuestRestoreTagged(args.id);
    if (typeof id !== "string") {
      throw new Error("Convex SDK get document ID is invalid");
    }
    if (hasTable) {
      const table = __convexCapabilityRequireTable(args.table, args.isSystem, "get");
      return __convexSdkStartAsync(
        {
          version: ${CAPABILITY_REQUEST_ABI_VERSION},
          kind: args.isSystem ? "dbSystemGet" : "dbGet",
          id,
          table,
        },
        "taggedJson",
      );
    }
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: args.isSystem ? "dbSystemGet" : "dbGet",
        id,
      },
      "taggedJson",
    );
  }
  if (operation === "1.0/insert") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK insert is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(args, ["table", "value"], "Convex SDK insert arguments");
    const table = __convexCapabilityRequireTable(args.table, false, "insert");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbInsert",
        table,
        value: __convexCapabilityTaggedValue(args.value),
      },
      "hostValue",
    ).then(__convexSdkEncodeInsertedId);
  }
  if (operation === "1.0/shallowMerge") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK shallowMerge is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["id", "table", "value"],
      "Convex SDK shallowMerge arguments",
    );
    const table = __convexCapabilityRequireTable(args.table, false, "patch");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbPatch",
        table,
        id: __convexGuestRestoreTagged(args.id),
        patch: __convexSdkRestorePatch(args.value),
      },
      "undefined",
    ).then((): string => "null");
  }
  if (operation === "1.0/replace") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK replace is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["id", "table", "value"],
      "Convex SDK replace arguments",
    );
    const table = __convexCapabilityRequireTable(args.table, false, "replace");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbReplace",
        table,
        id: __convexGuestRestoreTagged(args.id),
        value: __convexCapabilityTaggedValue(args.value),
      },
      "undefined",
    ).then((): string => "null");
  }
  if (operation === "1.0/remove") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK remove is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(args, ["id", "table"], "Convex SDK remove arguments");
    const table = __convexCapabilityRequireTable(args.table, false, "delete");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbDelete",
        table,
        id: __convexGuestRestoreTagged(args.id),
      },
      "undefined",
    ).then((): string => "null");
  }
  if (operation === "1.0/schedule") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK schedule is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    return __convexSdkStartAsync(__convexSdkScheduleRequest(args), "hostValue").then(
      __convexSdkEncodeScheduledId,
    );
  }
  if (operation === "1.0/cancel_job") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK cancel_job is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(args, ["id"], "Convex SDK cancel_job arguments");
    const id = __convexGuestRestoreTagged(args.id);
    if (typeof id !== "string") {
      throw new Error("Convex SDK cancel_job scheduled function ID is invalid");
    }
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "schedulerCancel", id},
      "undefined",
    ).then((): string => "null");
  }
  if (operation === "1.0/storageDelete") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK storageDelete is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["requestId", "storageId", "version"],
      "Convex SDK storageDelete arguments",
    );
    if (args.requestId !== "" || typeof args.storageId !== "string") {
      throw new Error("Convex SDK storageDelete arguments are invalid");
    }
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK storageDelete");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "storageDelete",
        storageId: args.storageId,
      },
      "undefined",
    ).then((): string => "null");
  }
  if (operation === "1.0/storageGenerateUploadUrl") {
    if (udfKind !== "mutation") {
      throw new Error("Convex SDK storageGenerateUploadUrl is unavailable in queries");
    }
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["requestId", "version"],
      "Convex SDK storageGenerateUploadUrl arguments",
    );
    if (args.requestId !== "") {
      throw new Error("Convex SDK storageGenerateUploadUrl arguments are invalid");
    }
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK storageGenerateUploadUrl");
    return __convexSdkStartAsync(
      {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "storageGenerateUploadUrl"},
      "taggedJson",
    );
  }
  if (operation === "1.0/storageGetMetadata") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["requestId", "storageId", "version"],
      "Convex SDK storageGetMetadata arguments",
    );
    if (args.requestId !== "" || typeof args.storageId !== "string") {
      throw new Error("Convex SDK storageGetMetadata arguments are invalid");
    }
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK storageGetMetadata");
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "storageGetMetadata",
        storageId: args.storageId,
      },
      "taggedJson",
    );
  }
  if (operation === "1.0/storageGetUrl") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["requestId", "storageId", "version"],
      "Convex SDK storageGetUrl arguments",
    );
    if (
      args.requestId !== "" ||
      typeof args.storageId !== "string" ||
      typeof args.version !== "string" ||
      args.version.length === 0
    ) {
      throw new Error("Convex SDK storageGetUrl arguments are invalid");
    }
    return __convexSdkStartAsync(
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "storageGetUrl",
        storageId: args.storageId,
      },
      "taggedJson",
    );
  }
  throw new Error("Convex SDK async syscall operation is unsupported");
}

function __convexSdkSyscall(operation: any, jsonArguments: any): string {
  __convexSdkRequireActive();
  if (typeof operation !== "string") {
    throw new Error("Convex SDK syscall operation must be a string");
  }
  if (operation === "1.0/queryStream") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["query", "version"],
      "Convex SDK queryStream arguments",
    );
    __convexSdkRequireInstalledVersion(args.version, "Convex SDK queryStream");
    const queryId = __convexSdkOpenQueryStream(
      __convexSdkQueryRequest(args.query, "stream", null),
    );
    return JSON.stringify({queryId});
  }
  if (operation === "1.0/queryCleanup") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["queryId"],
      "Convex SDK queryCleanup arguments",
    );
    const queryId = __convexSdkRequireQueryId(args.queryId);
    const state = __convexSdkRequireQueryStream(queryId);
    if (state.pending) throw new Error("Convex SDK query stream has a pending read");
    __convexSdkReleaseQueryStream(state, !state.done);
    __convexSdkQueryStreams[queryId - 1] = undefined;
    return "null";
  }
  if (operation === "1.0/db/normalizeId") {
    const args = __convexSdkParseArguments(jsonArguments);
    __convexCapabilityRequireExactKeys(
      args,
      ["idString", "table"],
      "Convex SDK normalizeId arguments",
    );
    if (typeof args.idString !== "string" || typeof args.table !== "string") {
      throw new Error("Convex SDK normalizeId arguments are invalid");
    }
    const table = __convexCapabilityRequireTable(
      args.table,
      args.table.charAt(0) === "_",
      "normalizeId",
    );
    const id = __convexSdkRunSync({
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
      kind: "dbNormalizeId",
      table,
      value: args.idString,
    });
    if (id !== null && typeof id !== "string") {
      throw new Error("Convex SDK normalizeId returned an invalid document ID");
    }
    return JSON.stringify({id});
  }
  throw new Error("Convex SDK synchronous syscall operation is unsupported");
}

function __convexSdkJsSyscall(operation: any, _arguments: any): any {
  __convexSdkRequireActive();
  if (typeof operation !== "string") {
    throw new Error("Convex SDK JS syscall operation must be a string");
  }
  throw new Error("Convex SDK JS syscall operation is unsupported");
}

Object.freeze(__convexSdkAsyncSyscall);
Object.freeze(__convexSdkSyscall);
Object.freeze(__convexSdkJsSyscall);
const __convexSdkFacade: any = Object.freeze({
  asyncSyscall: __convexSdkAsyncSyscall,
  queryCollect: true,
  jsSyscall: __convexSdkJsSyscall,
  syscall: __convexSdkSyscall,
});
Object.defineProperty(__convexTargetGlobal, "Convex", {
  configurable: false,
  enumerable: false,
  value: __convexSdkFacade,
  writable: false,
});
`;
}

export function renderNativeRuntimeSupportUnit() {
  return `(function() {
"use strict";
const __convexWasmBridgeInstallRuntimeSupport =
  globalThis.${convexWasmApplicationInstallRuntimeSupportBinding};
if (typeof __convexWasmBridgeInstallRuntimeSupport !== "function") {
  throw new Error("Convex Wasm runtime-support installer is unavailable");
}
function __convexWasmFormatterHardenConstructor(constructor) {
  const prototype = constructor.prototype;
  if (prototype === null || typeof prototype !== "object") {
    throw new Error("Convex Wasm runtime-support constructor prototype is invalid");
  }
  const values = [prototype, constructor];
  for (let valueIndex = 0; valueIndex < values.length; valueIndex += 1) {
    const value = values[valueIndex];
    const keys = Reflect.ownKeys(value);
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, keys[keyIndex]);
      if (descriptor === undefined) {
        throw new Error("Convex Wasm runtime-support descriptor disappeared");
      }
      if ("value" in descriptor && typeof descriptor.value === "function") {
        Object.freeze(descriptor.value);
      } else {
        if (typeof descriptor.get === "function") Object.freeze(descriptor.get);
        if (typeof descriptor.set === "function") Object.freeze(descriptor.set);
      }
    }
    Object.freeze(value);
  }
}
function __convexWasmFormatterInstallRuntimeSupport(support) {
  if (
    arguments.length !== 1 ||
    support === null ||
    typeof support !== "object" ||
    !Object.isFrozen(support)
  ) {
    throw new Error("Convex Wasm runtime support is invalid");
  }
  const supportKeys = Reflect.ownKeys(support);
  if (
    supportKeys.length !== 5 ||
    !Object.hasOwn(support, "consoleFormatter") ||
    !Object.hasOwn(support, "DOMException") ||
    !Object.hasOwn(support, "Intl") ||
    !Object.hasOwn(support, "URL") ||
    !Object.hasOwn(support, "URLSearchParams")
  ) {
    throw new Error("Convex Wasm runtime support has an invalid surface");
  }
  if (
    typeof support.consoleFormatter !== "function" ||
    typeof support.DOMException !== "function" ||
    support.Intl === null ||
    typeof support.Intl !== "object" ||
    Reflect.ownKeys(support.Intl).length !== 2 ||
    !Object.hasOwn(support.Intl, "DateTimeFormat") ||
    !Object.hasOwn(support.Intl, "NumberFormat") ||
    typeof support.Intl.DateTimeFormat !== "function" ||
    typeof support.Intl.NumberFormat !== "function" ||
    typeof support.URL !== "function" ||
    typeof support.URLSearchParams !== "function"
  ) {
    throw new Error("Convex Wasm runtime support has invalid members");
  }
  Object.freeze(support.consoleFormatter);
  __convexWasmFormatterHardenConstructor(support.DOMException);
  __convexWasmFormatterHardenConstructor(support.Intl.DateTimeFormat);
  __convexWasmFormatterHardenConstructor(support.Intl.NumberFormat);
  Object.freeze(support.Intl);
  __convexWasmFormatterHardenConstructor(support.URL);
  __convexWasmFormatterHardenConstructor(support.URLSearchParams);
  __convexWasmBridgeInstallRuntimeSupport(support);
}
Object.freeze(__convexWasmFormatterInstallRuntimeSupport);
Object.defineProperty(
  globalThis,
  ${JSON.stringify(convexWasmApplicationInstallRuntimeSupportBinding)},
  {
    configurable: true,
    enumerable: false,
    value: __convexWasmFormatterInstallRuntimeSupport,
    writable: false,
  },
);
${renderConvexWasmRuntimeSupportUnit()}
})();
`;
}

export function renderNativeRuntimeSupportAdapter() {
  return String.raw`let __convexConsoleFormatter: any = null;
let __convexRuntimeSupportInstalled: boolean = false;

function ${convexWasmApplicationInstallRuntimeSupportBinding}(support: any): void {
  if (
    arguments.length !== 1 ||
    support === null ||
    typeof support !== "object" ||
    !Object.isFrozen(support)
  ) {
    throw new Error("Convex Wasm runtime support is invalid");
  }
  if (__convexRuntimeSupportInstalled) {
    throw new Error("Convex Wasm runtime support is already installed");
  }
  if (typeof support.consoleFormatter !== "function") {
    throw new Error("Convex Wasm runtime support has an invalid consoleFormatter");
  }
  if (typeof support.DOMException !== "function") {
    throw new Error("Convex Wasm runtime support has an invalid DOMException");
  }
  if (
    support.Intl === null ||
    typeof support.Intl !== "object" ||
    typeof support.Intl.DateTimeFormat !== "function" ||
    typeof support.Intl.NumberFormat !== "function"
  ) {
    throw new Error("Convex Wasm runtime support has an invalid Intl");
  }
  if (typeof support.URL !== "function") {
    throw new Error("Convex Wasm runtime support has an invalid URL");
  }
  if (typeof support.URLSearchParams !== "function") {
    throw new Error("Convex Wasm runtime support has an invalid URLSearchParams");
  }
  if (Object.getOwnPropertyDescriptor(__convexTargetGlobal, "DOMException") !== undefined) {
    throw new Error("Convex Wasm runtime-support global is unexpectedly present");
  }
  if (Object.getOwnPropertyDescriptor(__convexTargetGlobal, "Intl") !== undefined) {
    throw new Error("Convex Wasm runtime-support global is unexpectedly present");
  }
  if (Object.getOwnPropertyDescriptor(__convexTargetGlobal, "URL") !== undefined) {
    throw new Error("Convex Wasm runtime-support global is unexpectedly present");
  }
  if (Object.getOwnPropertyDescriptor(__convexTargetGlobal, "URLSearchParams") !== undefined) {
    throw new Error("Convex Wasm runtime-support global is unexpectedly present");
  }
  if (
    !Object.isFrozen(support.consoleFormatter) ||
    !Object.isFrozen(support.DOMException) ||
    !Object.isFrozen(support.DOMException.prototype) ||
    !Object.isFrozen(support.Intl) ||
    !Object.isFrozen(support.Intl.DateTimeFormat) ||
    !Object.isFrozen(support.Intl.DateTimeFormat.prototype) ||
    !Object.isFrozen(support.Intl.NumberFormat) ||
    !Object.isFrozen(support.Intl.NumberFormat.prototype) ||
    !Object.isFrozen(support.URL) ||
    !Object.isFrozen(support.URL.prototype) ||
    !Object.isFrozen(support.URLSearchParams) ||
    !Object.isFrozen(support.URLSearchParams.prototype)
  ) {
    throw new Error("Convex Wasm runtime support was not hardened");
  }
  Object.defineProperty(__convexTargetGlobal, "DOMException", {
    configurable: false,
    value: support.DOMException,
    writable: false,
  });
  Object.defineProperty(__convexTargetGlobal, "Intl", {
    configurable: false,
    value: support.Intl,
    writable: false,
  });
  Object.defineProperty(__convexTargetGlobal, "URL", {
    configurable: false,
    value: support.URL,
    writable: false,
  });
  Object.defineProperty(__convexTargetGlobal, "URLSearchParams", {
    configurable: false,
    value: support.URLSearchParams,
    writable: false,
  });
  Object.defineProperty(${convexWasmApplicationGlobalThisBinding}, "DOMException", {
    enumerable: true,
    value: support.DOMException,
  });
  Object.defineProperty(${convexWasmApplicationGlobalThisBinding}, "Intl", {
    enumerable: true,
    value: support.Intl,
  });
  Object.defineProperty(${convexWasmApplicationGlobalThisBinding}, "URL", {
    enumerable: true,
    value: support.URL,
  });
  Object.defineProperty(${convexWasmApplicationGlobalThisBinding}, "URLSearchParams", {
    enumerable: true,
    value: support.URLSearchParams,
  });
  __convexConsoleFormatter = support.consoleFormatter;
  __convexRuntimeSupportInstalled = true;
  if (!delete __convexTargetGlobal.${convexWasmApplicationInstallRuntimeSupportBinding}) {
    throw new Error("Convex Wasm runtime-support handoff could not be cleared");
  }
}
Object.freeze(${convexWasmApplicationInstallRuntimeSupportBinding});
Object.defineProperty(
  __convexTargetGlobal,
  ${JSON.stringify(convexWasmApplicationInstallRuntimeSupportBinding)},
  {
    configurable: true,
    enumerable: false,
    value: ${convexWasmApplicationInstallRuntimeSupportBinding},
    writable: false,
  },
);

function __convexConsoleMessage(level: number, args: Array<any>): void {
  const capabilityIdentity = __convexHostCapabilityCurrent();
  if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
  const formatter = __convexConsoleFormatter;
  if (typeof formatter !== "function") {
    throw new Error("Convex Wasm console formatter is unavailable");
  }
  const messages: Array<string> = args.map((value: any): string =>
    formatter(value, {
      maxStringLength: 32768,
      indent: 2,
      customInspect: true,
    }),
  );
  const source = JSON.stringify(messages);
  const pointer = __convexAllocateUtf8(source);
  try {
    const length = __convexWriteUtf8(source, pointer);
    const result = __convexHostConsoleMessage(capabilityIdentity, level, pointer, length);
    if (result === -1) throw new Error("Invocation capability is stale");
    if (result !== 0) throw new Error("Console host import returned an invalid status");
  } finally {
    __convexFree(pointer);
  }
}

function __convexConsoleDebug(...args: any[]): void { __convexConsoleMessage(0, args); }
function __convexConsoleError(...args: any[]): void { __convexConsoleMessage(1, args); }
function __convexConsoleInfo(...args: any[]): void { __convexConsoleMessage(2, args); }
function __convexConsoleLog(...args: any[]): void { __convexConsoleMessage(3, args); }
function __convexConsoleWarn(...args: any[]): void { __convexConsoleMessage(4, args); }
Object.defineProperty(__convexConsoleDebug, "name", {value: "debug"});
Object.defineProperty(__convexConsoleError, "name", {value: "error"});
Object.defineProperty(__convexConsoleInfo, "name", {value: "info"});
Object.defineProperty(__convexConsoleLog, "name", {value: "log"});
Object.defineProperty(__convexConsoleWarn, "name", {value: "warn"});
Object.freeze(__convexConsoleDebug);
Object.freeze(__convexConsoleError);
Object.freeze(__convexConsoleInfo);
Object.freeze(__convexConsoleLog);
Object.freeze(__convexConsoleWarn);
const __convexConsolePrototype: any = Object.freeze({});
const __convexConsole: any = Object.assign(Object.create(__convexConsolePrototype), {
  debug: __convexConsoleDebug,
  error: __convexConsoleError,
  info: __convexConsoleInfo,
  log: __convexConsoleLog,
  warn: __convexConsoleWarn,
});
Object.defineProperty(__convexConsole, Symbol.toStringTag, {value: "console"});
Object.freeze(__convexConsole);
const console: any = __convexConsole;
Object.defineProperty(__convexTargetGlobal, "console", {
  configurable: false,
  enumerable: false,
  value: __convexConsole,
  writable: false,
});
`;
}

function renderNativeDatabaseUdfTimerAdapter() {
  return String.raw`
function __convexDatabaseUdfTimerDeveloperError(message: string): number {
  // Database UDF timer scheduling has no successful path. The host latch remains terminal even
  // when application code catches the defensive local exception, so no timer registry is needed.
  const pointer = __convexAllocateUtf8(message);
  try {
    const length = __convexWriteUtf8(message, pointer);
    __convexHostDeveloperError(pointer, length, 0);
  } finally {
    __convexFree(pointer);
  }
  throw new Error(message);
}

function __convexDatabaseUdfScheduleTimer(
  name: string,
  handler: any,
  timeoutMs: any,
): number {
  if (typeof handler === "string") {
    return __convexDatabaseUdfTimerDeveloperError(
      "Not implemented: code string argument for " +
        name +
        ". Consider calling an action defined in Node.js instead (https://docs.convex.dev/functions/actions).",
    );
  }
  timeoutMs = timeoutMs ? Number(timeoutMs) : 0;
  if (timeoutMs < 0) timeoutMs = 0;
  return __convexDatabaseUdfTimerDeveloperError(
    "Can't use " +
      name +
      " in queries and mutations. Please consider using an action. See https://docs.convex.dev/functions/actions for more details.",
  );
}

const setTimeout: any = (
  handler: any,
  timeoutMs: any,
  ..._args: any[]
): number => {
  return __convexDatabaseUdfScheduleTimer("setTimeout", handler, timeoutMs);
};
const setInterval: any = (
  handler: any,
  timeoutMs: any,
  ..._args: any[]
): number => {
  return __convexDatabaseUdfScheduleTimer("setInterval", handler, timeoutMs);
};
const clearTimeout: any = (_id: any): void => {};
const clearInterval: any = (_id: any): void => {};
Object.freeze(setTimeout);
Object.freeze(setInterval);
Object.freeze(clearTimeout);
Object.freeze(clearInterval);
`;
}

function renderNativeCryptoAdapter() {
  return String.raw`
const __convexCryptoDigestBytes = 32;
const __convexCryptoMaximumRandomBytes = 65536;
const __convexCryptoRandomUuidBytes = 36;
const __convexCryptoDomException: any = function DOMException(
  message: string,
  name: string,
): any {
  const error: any = new Error(message);
  Object.setPrototypeOf(error, __convexCryptoDomException.prototype);
  error.name = name;
  return error;
};
__convexCryptoDomException.prototype = Object.create(Error.prototype, {
  constructor: {value: __convexCryptoDomException},
});
Object.freeze(__convexCryptoDomException.prototype);
Object.freeze(__convexCryptoDomException);

function __convexCryptoDigestAlgorithmName(algorithm: any): string {
  let name: any;
  if (typeof algorithm === "string") {
    name = algorithm;
  } else if (algorithm !== null && typeof algorithm === "object") {
    if (!("name" in algorithm)) {
      throw new TypeError("Digest algorithm objects require a name");
    }
    name = algorithm.name;
  } else {
    name = algorithm;
  }
  const normalized = String(name).toUpperCase();
  if (normalized !== "SHA-256") {
    throw new __convexCryptoDomException("The requested algorithm is not supported", "NotSupportedError");
  }
  return normalized;
}

function __convexCryptoBufferSourceBytes(data: any): any {
  if (data instanceof __convexTargetGlobal.ArrayBuffer) {
    return new __convexTargetGlobal.Uint8Array(data);
  }
  if (__convexTargetGlobal.ArrayBuffer.isView(data)) {
    return new __convexTargetGlobal.Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError("Digest input must be an ArrayBuffer or an ArrayBuffer view");
}

function __convexCryptoSubtleDigest(algorithm: any, data: any): any {
  return new __convexTargetGlobal.Promise((resolve) => {
    let inputPointer = __convexNullPointer;
    let outputPointer = __convexNullPointer;
    try {
      __convexCryptoDigestAlgorithmName(algorithm);
      const bytes = __convexCryptoBufferSourceBytes(data);
      const inputLength = bytes.byteLength;
      inputPointer = __convexMalloc(inputLength === 0 ? 1 : inputLength);
      outputPointer = __convexMalloc(__convexCryptoDigestBytes);
      if (
        inputPointer === __convexNullPointer ||
        outputPointer === __convexNullPointer
      ) {
        throw new Error("Static Hermes native allocation failed");
      }
      // Copy before returning the Promise so later mutations cannot change the digest input.
      for (let index = 0; index < inputLength; index += 1) {
        __convexPtrWriteChar(inputPointer, index, bytes[index]);
      }
      const capabilityIdentity = __convexHostCapabilityCurrent();
      if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
      __convexHostCryptoSubtleDigestSha256(
        capabilityIdentity,
        inputPointer,
        inputLength,
        outputPointer,
        __convexCryptoDigestBytes,
      );
      const output = new __convexTargetGlobal.Uint8Array(__convexCryptoDigestBytes);
      for (let index = 0; index < __convexCryptoDigestBytes; index += 1) {
        output[index] = __convexPtrReadUChar(outputPointer, index);
      }
      resolve(output.buffer);
    } finally {
      if (inputPointer !== __convexNullPointer) __convexFree(inputPointer);
      if (outputPointer !== __convexNullPointer) __convexFree(outputPointer);
    }
  });
}

function __convexCryptoIntegerArray(view: any): boolean {
  return (
    view instanceof __convexTargetGlobal.Int8Array ||
    view instanceof __convexTargetGlobal.Uint8Array ||
    view instanceof __convexTargetGlobal.Uint8ClampedArray ||
    view instanceof __convexTargetGlobal.Int16Array ||
    view instanceof __convexTargetGlobal.Uint16Array ||
    view instanceof __convexTargetGlobal.Int32Array ||
    view instanceof __convexTargetGlobal.Uint32Array ||
    view instanceof __convexTargetGlobal.BigInt64Array ||
    view instanceof __convexTargetGlobal.BigUint64Array
  );
}

function __convexCryptoGetRandomValues(view: any): any {
  if (!__convexCryptoIntegerArray(view)) {
    throw new TypeError("getRandomValues requires an integer typed-array view");
  }
  const byteLength = view.byteLength;
  if (byteLength > __convexCryptoMaximumRandomBytes) {
    throw new __convexCryptoDomException(
      "The requested byte length exceeds the getRandomValues limit",
      "QuotaExceededError",
    );
  }
  const outputPointer = __convexMalloc(byteLength === 0 ? 1 : byteLength);
  if (outputPointer === __convexNullPointer) {
    throw new Error("Static Hermes native allocation failed");
  }
  try {
    const capabilityIdentity = __convexHostCapabilityCurrent();
    if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
    __convexHostCryptoGetRandomValues(capabilityIdentity, outputPointer, byteLength);
    const bytes = new __convexTargetGlobal.Uint8Array(
      view.buffer,
      view.byteOffset,
      byteLength,
    );
    for (let index = 0; index < byteLength; index += 1) {
      bytes[index] = __convexPtrReadUChar(outputPointer, index);
    }
    return view;
  } finally {
    __convexFree(outputPointer);
  }
}

function __convexCryptoRandomUuid(): string {
  const outputPointer = __convexMalloc(__convexCryptoRandomUuidBytes);
  if (outputPointer === __convexNullPointer) {
    throw new Error("Static Hermes native allocation failed");
  }
  try {
    const capabilityIdentity = __convexHostCapabilityCurrent();
    if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
    __convexHostCryptoRandomUuid(
      capabilityIdentity,
      outputPointer,
      __convexCryptoRandomUuidBytes,
    );
    let uuid = "";
    for (let index = 0; index < __convexCryptoRandomUuidBytes; index += 1) {
      uuid += String.fromCharCode(__convexPtrReadUChar(outputPointer, index));
    }
    return uuid;
  } finally {
    __convexFree(outputPointer);
  }
}

Object.freeze(__convexCryptoSubtleDigest);
Object.freeze(__convexCryptoGetRandomValues);
Object.freeze(__convexCryptoRandomUuid);
const __convexCryptoSubtle: any = Object.freeze({digest: __convexCryptoSubtleDigest});
const __convexCrypto: any = Object.freeze({
  getRandomValues: __convexCryptoGetRandomValues,
  randomUUID: __convexCryptoRandomUuid,
  subtle: __convexCryptoSubtle,
});
const crypto: any = __convexCrypto;
Object.defineProperty(__convexTargetGlobal, "crypto", {
  configurable: false,
  enumerable: false,
  value: __convexCrypto,
  writable: false,
});
`;
}

function renderNativeProcessEnvironmentAdapter() {
  return String.raw`
function __convexEnvironmentVariableGet(name: string): any {
  let requestHandle = __convexCapabilityRequestToHost({
    version: ${CAPABILITY_REQUEST_ABI_VERSION},
    kind: "environmentVariableGet",
    name,
  });
  try {
    // Resolve the lease for every property read. A module-retained Proxy must
    // never retain the capability identity from the invocation that created it.
    const capabilityIdentity = __convexHostCapabilityCurrent();
    const resultHandle = __convexHostCapabilitySyncTake(capabilityIdentity, requestHandle);
    if (resultHandle === -2) throw new Error("Invocation capability is stale");
    requestHandle = 0;
    if (resultHandle <= 0) {
      throw new Error("Environment variable capability returned an invalid result");
    }
    const response = __convexGuestFromHost(resultHandle);
    if (response === null || typeof response !== "object") {
      throw new Error("Environment variable capability returned an invalid response");
    }
    const keys = Object.keys(response);
    if (keys.length !== 1) {
      throw new Error("Environment variable capability returned an invalid response");
    }
    if (keys[0] === "error" && typeof response.error === "string") {
      throw new Error(response.error);
    }
    if (keys[0] !== "value") {
      throw new Error("Environment variable capability returned an invalid response");
    }
    if (response.value === null) return undefined;
    if (typeof response.value !== "string") {
      throw new Error("Environment variable capability returned an invalid value");
    }
    return response.value;
  } finally {
    if (requestHandle > 0) __convexCapabilityRequestRelease(requestHandle);
  }
}

const __convexProcessEnvironmentTarget: any = Object.freeze({});
const __convexProcessEnvironmentHandler: any = Object.freeze({
  get(target, property, receiver) {
    if (typeof property === "string") {
      const value = __convexEnvironmentVariableGet(property);
      if (value === undefined && property === "inspect") {
        return function __convexInspectProcessEnvironment(): string { return "[process.env]"; };
      }
      return value;
    }
    return Reflect.get(target, property, receiver);
  },
});
const __convexProcessEnvironment: any = Object.freeze(
  new Proxy(__convexProcessEnvironmentTarget, __convexProcessEnvironmentHandler),
);
const __convexProcess: any = Object.freeze({env: __convexProcessEnvironment});
Object.defineProperty(__convexTargetGlobal, "process", {
  configurable: false,
  enumerable: false,
  value: __convexProcess,
  writable: false,
});
`;
}

function renderNativePerformanceAdapter() {
  return String.raw`
function __convexPerformanceNow(): number {
  let requestHandle = __convexCapabilityRequestToHost({
    version: ${CAPABILITY_REQUEST_ABI_VERSION},
    kind: "performanceNow",
  });
  try {
    const capabilityIdentity = __convexHostCapabilityCurrent();
    if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
    const resultHandle = __convexHostCapabilitySyncTake(capabilityIdentity, requestHandle);
    if (resultHandle === -2) throw new Error("Invocation capability is stale");
    requestHandle = 0;
    if (resultHandle <= 0) {
      throw new Error("Performance capability returned an invalid result");
    }
    const value = __convexGuestFromHost(resultHandle);
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new Error("Performance capability returned an invalid value");
    }
    return value;
  } finally {
    if (requestHandle > 0) __convexCapabilityRequestRelease(requestHandle);
  }
}

Object.freeze(__convexPerformanceNow);
const __convexPerformance: any = Object.freeze({now: __convexPerformanceNow});
const performance: any = __convexPerformance;
Object.defineProperty(__convexTargetGlobal, "performance", {
  configurable: false,
  enumerable: false,
  value: __convexPerformance,
  writable: false,
});
`;
}

function renderNativeCapabilityRequestEnvelopeRuntime() {
  return String.raw`
function __convexCapabilityOwnDataKeys(value: any, description: string, sortKeys: boolean = true): any {
  if (
    value === null ||
    typeof value !== "object" ||
    __convexGuestIsArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new Error(description + " must be a plain object");
  }
  if (
    typeof Object.getOwnPropertySymbols === "function" &&
    Object.getOwnPropertySymbols(value).length !== 0
  ) {
    throw new Error(description + " must not contain symbol properties");
  }
  const keys = Object.keys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, keys[index]);
    if (
      descriptor === undefined ||
      typeof descriptor.get === "function" ||
      typeof descriptor.set === "function"
    ) {
      throw new Error(description + " must not contain accessor properties");
    }
  }
  if (sortKeys) keys.sort();
  return keys;
}

function __convexCapabilityRequireExactKeys(
  value: any,
  keys: string[],
  description: string,
  checkedKeys?: string[],
): void {
  const actual = checkedKeys === undefined
    ? __convexCapabilityOwnDataKeys(value, description)
    : checkedKeys;
  if (actual.length !== keys.length) {
    throw new Error(description + " has invalid fields");
  }
  for (let actualIndex = 0; actualIndex < actual.length; actualIndex += 1) {
    let found = false;
    for (let expectedIndex = 0; expectedIndex < keys.length; expectedIndex += 1) {
      if (actual[actualIndex] === keys[expectedIndex]) found = true;
    }
    if (!found) {
      throw new Error(description + " has invalid fields");
    }
  }
}

function __convexCapabilitySortedObject(fields: any): any {
  const output: any = {};
  const keys = Object.keys(fields).sort();
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    __convexGuestDefineObjectField(output, key, fields[key]);
  }
  return output;
}

function __convexCapabilitySingleFieldObject(key: string, value: any): any {
  const output: any = {};
  __convexGuestDefineObjectField(output, key, value);
  return output;
}

function __convexCapabilityRequireFiniteNumber(value: any, description: string): number {
  if (typeof value !== "number" || !isFinite(value)) {
    throw new Error(description + " must be a finite number");
  }
  return value;
}

function __convexCapabilityContainsPendingCommitTs(value: any): boolean {
  if (__convexGuestIsArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (__convexCapabilityContainsPendingCommitTs(value[index])) return true;
    }
    return false;
  }
  if (value === null || typeof value !== "object") return false;
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === "$commitTs") return true;
  for (let index = 0; index < keys.length; index += 1) {
    if (__convexCapabilityContainsPendingCommitTs(value[keys[index]])) return true;
  }
  return false;
}

const __convexCapabilityTaggedValueBrand = {};

function __convexCapabilityTaggedValue(value: any): any {
  return {brand: __convexCapabilityTaggedValueBrand, value};
}

function __convexCapabilityEncodeTaggedOrGuest(value: any): any {
  if (value !== null && typeof value === "object") {
    const brand = Object.getOwnPropertyDescriptor(value, "brand");
    if (brand !== undefined && brand.value === __convexCapabilityTaggedValueBrand) {
      // The SDK already encoded this subtree. The host validates the complete
      // request after envelope translation and before any capability starts.
      return value.value;
    }
  }
  return __convexGuestEncodeTagged(value, []);
}

function __convexCapabilityEncodeCommittedValue(value: any): any {
  const encoded = __convexCapabilityEncodeTaggedOrGuest(value);
  if (__convexCapabilityContainsPendingCommitTs(encoded)) {
    throw new Error("Pending commit timestamp is not allowed in this capability request position");
  }
  return encoded;
}

function __convexCapabilityEncodePatch(patch: any): any {
  const keys = __convexCapabilityOwnDataKeys(patch, "Patch");
  const output: any = {};
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    __convexGuestValidateObjectField(key);
    const descriptor = Object.getOwnPropertyDescriptor(patch, key);
    if (descriptor === undefined) throw new Error("Patch field is missing");
    __convexGuestDefineObjectField(
      output,
      key,
      descriptor.value === undefined
        ? __convexCapabilitySortedObject({$undefined: null})
        : __convexCapabilityEncodeTaggedOrGuest(descriptor.value),
    );
  }
  return output;
}

function __convexCapabilityAuditContainsIdentity(ancestors: any[], target: any): boolean {
  for (let index = 0; index < ancestors.length; index += 1) {
    if (ancestors[index] === target) return true;
  }
  return false;
}

function __convexCapabilityEncodeAuditValue(value: any, ancestors: any[]): any {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return value;
  }
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("Audit log numbers must be finite");
    return value;
  }
  if (typeof value !== "object") {
    throw new Error("Audit log values must be JSON values or audit variable sentinels");
  }
  if (__convexCapabilityAuditContainsIdentity(ancestors, value)) {
    throw new Error("Audit log values must not be cyclic");
  }
  __convexArrayPush(ancestors, value);
  try {
    if (__convexGuestIsArray(value)) {
      if (
        typeof Object.getOwnPropertySymbols === "function" &&
        Object.getOwnPropertySymbols(value).length !== 0
      ) {
        throw new Error("Audit log arrays must not contain symbol properties");
      }
      const output = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor === undefined) throw new Error("Audit log arrays must not be sparse");
        if (typeof descriptor.get === "function" || typeof descriptor.set === "function") {
          throw new Error("Audit log arrays must not contain accessor properties");
        }
        __convexArrayPush(
          output,
          __convexCapabilityEncodeAuditValue(descriptor.value, ancestors),
        );
      }
      const names = Object.getOwnPropertyNames(value);
      if (names.length !== value.length + 1) {
        throw new Error("Audit log arrays must not contain extra properties");
      }
      return output;
    }
    const keys = __convexCapabilityOwnDataKeys(value, "Audit log value");
    if (keys.length === 1 && keys[0] === "$var") {
      const name = value.$var;
      if (
        name !== "requestId" &&
        name !== "ip" &&
        name !== "userAgent" &&
        name !== "now" &&
        name !== "convexActor"
      ) {
        throw new Error("Audit log variable sentinel is invalid");
      }
      return __convexCapabilitySortedObject({$var: name});
    }
    const output: any = {};
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (key.charAt(0) === "$") {
        throw new Error("Audit log body keys must not start with $");
      }
      __convexGuestDefineObjectField(
        output,
        key,
        __convexCapabilityEncodeAuditValue(value[key], ancestors),
      );
    }
    return output;
  } finally {
    ancestors.pop();
  }
}

function __convexCapabilityEncodeAuditBody(body: any): any {
  const keys = __convexCapabilityOwnDataKeys(body, "Audit log body");
  const output: any = {};
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key.charAt(0) === "$") {
      throw new Error("Audit log body keys must not start with $");
    }
    __convexGuestDefineObjectField(
      output,
      key,
      __convexCapabilityEncodeAuditValue(body[key], [body]),
    );
  }
  return output;
}

function __convexCapabilityEncodeExpression(expression: any): any {
  const keys = __convexCapabilityOwnDataKeys(expression, "Query expression");
  if (keys.length !== 1) throw new Error("Query expression must have one node");
  const kind = keys[0];
  const value = expression[kind];
  if (kind === "$literal") {
    return __convexCapabilitySortedObject({
      $literal: value === undefined
        ? __convexCapabilitySortedObject({$undefined: null})
        : __convexCapabilityEncodeCommittedValue(value),
    });
  }
  if (kind === "$field") {
    if (typeof value !== "string") throw new Error("Query field must be a string");
    return __convexCapabilitySortedObject({$field: value});
  }
  if (kind === "$neg" || kind === "$not") {
    return __convexCapabilitySingleFieldObject(
      kind,
      __convexCapabilityEncodeExpression(value),
    );
  }
  if (kind === "$and" || kind === "$or") {
    if (!__convexGuestIsArray(value)) {
      throw new Error("Query logical expression operands must be an array");
    }
    const operands = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new Error("Query logical expression operands must not be sparse");
      __convexArrayPush(operands, __convexCapabilityEncodeExpression(value[index]));
    }
    return __convexCapabilitySingleFieldObject(kind, operands);
  }
  if (
    kind === "$eq" ||
    kind === "$neq" ||
    kind === "$lt" ||
    kind === "$lte" ||
    kind === "$gt" ||
    kind === "$gte" ||
    kind === "$add" ||
    kind === "$sub" ||
    kind === "$mul" ||
    kind === "$div" ||
    kind === "$mod"
  ) {
    if (!__convexGuestIsArray(value) || value.length !== 2 || !(0 in value) || !(1 in value)) {
      throw new Error("Query binary expression must have two operands");
    }
    return __convexCapabilitySingleFieldObject(
      kind,
      [
        __convexCapabilityEncodeExpression(value[0]),
        __convexCapabilityEncodeExpression(value[1]),
      ],
    );
  }
  throw new Error("Query expression node is unsupported");
}

function __convexCapabilityEncodeQuerySource(source: any): any {
  __convexCapabilityOwnDataKeys(source, "Query source");
  if (source.type === "fullTableScan") {
    __convexCapabilityRequireExactKeys(source, ["type"], "Query source");
    return __convexCapabilitySortedObject({type: "fullTableScan"});
  }
  if (source.type === "search") {
    __convexCapabilityRequireExactKeys(source, ["filters", "index", "type"], "Query source");
    if (typeof source.index !== "string") throw new Error("Query search index must be a string");
    if (!__convexGuestIsArray(source.filters)) {
      throw new Error("Query search filters must be an array");
    }
    if (source.filters.length === 0) {
      throw new Error("Query search filters must begin with a search filter");
    }
    const filters = [];
    for (let index = 0; index < source.filters.length; index += 1) {
      if (!(index in source.filters)) throw new Error("Query search filters must not be sparse");
      const filter = source.filters[index];
      __convexCapabilityRequireExactKeys(
        filter,
        ["field", "type", "value"],
        "Query search filter",
      );
      if (typeof filter.field !== "string") {
        throw new Error("Query search filter field must be a string");
      }
      if (index === 0) {
        if (filter.type !== "search" || typeof filter.value !== "string") {
          throw new Error("Query search filters must begin with one search filter");
        }
        __convexArrayPush(
          filters,
          __convexCapabilitySortedObject({
            field: filter.field,
            type: "search",
            value: filter.value,
          }),
        );
        continue;
      }
      if (filter.type !== "eq") {
        throw new Error("Query search filters after the search filter must be equality filters");
      }
      __convexArrayPush(
        filters,
        __convexCapabilitySortedObject({
          field: filter.field,
          type: "eq",
          value: filter.value === undefined
            ? __convexCapabilitySortedObject({$undefined: null})
            : __convexCapabilityEncodeCommittedValue(filter.value),
        }),
      );
    }
    return __convexCapabilitySortedObject({
      filters,
      index: source.index,
      type: "search",
    });
  }
  if (source.type !== "indexRange") throw new Error("Query source type is unsupported");
  __convexCapabilityRequireExactKeys(source, ["constraints", "index", "type"], "Query source");
  if (typeof source.index !== "string") throw new Error("Query index must be a string");
  if (!__convexGuestIsArray(source.constraints)) {
    throw new Error("Query constraints must be an array");
  }
  const constraints = [];
  for (let index = 0; index < source.constraints.length; index += 1) {
    if (!(index in source.constraints)) throw new Error("Query constraints must not be sparse");
    const constraint = source.constraints[index];
    __convexCapabilityRequireExactKeys(
      constraint,
      ["field", "operator", "value"],
      "Query constraint",
    );
    if (
      constraint.operator !== "eq" &&
      constraint.operator !== "gt" &&
      constraint.operator !== "gte" &&
      constraint.operator !== "lt" &&
      constraint.operator !== "lte"
    ) {
      throw new Error("Query constraint operator is unsupported");
    }
    if (typeof constraint.field !== "string") {
      throw new Error("Query constraint field must be a string");
    }
    __convexArrayPush(
      constraints,
      __convexCapabilitySortedObject({
        field: constraint.field,
        operator: constraint.operator,
        value: constraint.value === undefined
          ? __convexCapabilitySortedObject({$undefined: null})
          : __convexCapabilityEncodeTaggedOrGuest(constraint.value),
      }),
    );
  }
  return __convexCapabilitySortedObject({
    constraints,
    index: source.index,
    type: "indexRange",
  });
}

function __convexCapabilityEncodeQueryOperators(operators: any): any[] {
  if (!__convexGuestIsArray(operators)) throw new Error("Query operators must be an array");
  const output = [];
  for (let index = 0; index < operators.length; index += 1) {
    if (!(index in operators)) throw new Error("Query operators must not be sparse");
    const operator = operators[index];
    __convexCapabilityOwnDataKeys(operator, "Query operator");
    if (operator.type === "filter") {
      __convexCapabilityRequireExactKeys(operator, ["expression", "type"], "Query operator");
      __convexArrayPush(
        output,
        __convexCapabilitySortedObject({
          expression: __convexCapabilityEncodeExpression(operator.expression),
          type: "filter",
        }),
      );
      continue;
    }
    __convexCapabilityRequireExactKeys(operator, ["limit", "type"], "Query operator");
    if (operator.type !== "limit") throw new Error("Query operator type is unsupported");
    __convexArrayPush(
      output,
      __convexCapabilitySortedObject({
        limit: __convexCapabilityRequireFiniteNumber(operator.limit, "Query limit"),
        type: "limit",
      }),
    );
  }
  return output;
}

function __convexCapabilityEncodePagination(pagination: any): any {
  __convexCapabilityRequireExactKeys(
    pagination,
    ["cursor", "endCursor", "maximumBytesRead", "maximumRowsRead", "pageSize"],
    "Query pagination",
  );
  return __convexCapabilitySortedObject({
    cursor: pagination.cursor,
    endCursor: pagination.endCursor,
    maximumBytesRead: pagination.maximumBytesRead,
    maximumRowsRead: pagination.maximumRowsRead,
    pageSize: pagination.pageSize,
  });
}

function __convexCapabilityEncodeFunctionAddress(functionAddress: any): any {
  const keys = __convexCapabilityOwnDataKeys(functionAddress, "Function address");
  if (keys.length !== 1) throw new Error("Function address must have one field");
  const key = keys[0];
  if (key !== "functionHandle" && key !== "name" && key !== "reference") {
    throw new Error("Function address field is unsupported");
  }
  if (typeof functionAddress[key] !== "string") {
    throw new Error("Function address must be a string");
  }
  return __convexCapabilitySingleFieldObject(key, functionAddress[key]);
}

function __convexCapabilityEncodeTransactionLimits(limits: any): any {
  if (limits === null) return null;
  if (typeof limits !== "object" || __convexGuestIsArray(limits)) {
    throw new Error("Transaction limits must be an object or null");
  }
  const keys = Object.keys(limits).sort();
  const allowed = [
    "bytesRead",
    "bytesWritten",
    "databaseQueries",
    "documentsRead",
    "documentsWritten",
    "functionsScheduled",
    "scheduledFunctionArgsBytes",
  ];
  const output: any = {};
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (allowed.indexOf(key) === -1) throw new Error("Transaction limit field is unsupported");
    const value = limits[key];
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Transaction limit must be a non-negative safe integer");
    }
    __convexGuestDefineObjectField(output, key, value);
  }
  return output;
}

function __convexCapabilityEncodeRequest(request: any): any {
  const requestKeys = __convexCapabilityOwnDataKeys(request, "Capability request", false);
  if (request.version !== ${CAPABILITY_REQUEST_ABI_VERSION} || typeof request.kind !== "string") {
    throw new Error("Capability request has an invalid version or kind");
  }
  const kind = request.kind;
  if (
    kind === "authGetUserIdentity" ||
    kind === "getDeploymentMetadata" ||
    kind === "getFunctionMetadata" ||
    kind === "getRequestMetadata" ||
    kind === "getTransactionMetrics" ||
    kind === "performanceNow"
  ) {
    __convexCapabilityRequireExactKeys(request, ["kind", "version"], "Capability request", requestKeys);
    return {kind, version: ${CAPABILITY_REQUEST_ABI_VERSION}};
  }
  if (kind === "auditLog") {
    __convexCapabilityRequireExactKeys(request, ["body", "kind", "version"], "Capability request", requestKeys);
    return {
      body: __convexCapabilityEncodeAuditBody(request.body),
      kind,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "environmentVariableGet") {
    __convexCapabilityRequireExactKeys(request, ["kind", "name", "version"], "Capability request", requestKeys);
    if (typeof request.name !== "string") throw new Error("Environment variable name must be a string");
    return {kind, name: request.name, version: ${CAPABILITY_REQUEST_ABI_VERSION}};
  }
  if (kind === "dbNormalizeId") {
    __convexCapabilityRequireExactKeys(request, ["kind", "table", "value", "version"], "Capability request", requestKeys);
    if (typeof request.table !== "string" || typeof request.value !== "string") {
      throw new Error("Normalize ID request fields must be strings");
    }
    return {
      kind,
      table: request.table,
      value: request.value,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "dbGet" || kind === "dbSystemGet") {
    const hasTable = request.table !== undefined;
    __convexCapabilityRequireExactKeys(
      request,
      hasTable ? ["id", "kind", "table", "version"] : ["id", "kind", "version"],
      "Capability request",
      requestKeys,
    );
    if (hasTable) {
      if (typeof request.table !== "string") throw new Error("Database table must be a string");
      return {
        id: __convexCapabilityEncodeCommittedValue(request.id),
        kind,
        table: request.table,
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
      };
    }
    return {
      id: __convexCapabilityEncodeCommittedValue(request.id),
      kind,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "dbDelete") {
    __convexCapabilityRequireExactKeys(request, ["id", "kind", "table", "version"], "Capability request", requestKeys);
    if (typeof request.table !== "string") throw new Error("Database table must be a string");
    return {
      id: __convexCapabilityEncodeCommittedValue(request.id),
      kind,
      table: request.table,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (
    kind === "storageGetUrl" ||
    kind === "storageGetMetadata" ||
    kind === "storageDelete"
  ) {
    __convexCapabilityRequireExactKeys(
      request,
      ["kind", "storageId", "version"],
      "Capability request",
      requestKeys,
    );
    if (typeof request.storageId !== "string") throw new Error("Storage ID must be a string");
    return {
      kind,
      storageId: __convexCapabilityEncodeCommittedValue(request.storageId),
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "storageGenerateUploadUrl") {
    __convexCapabilityRequireExactKeys(request, ["kind", "version"], "Capability request", requestKeys);
    return {kind, version: ${CAPABILITY_REQUEST_ABI_VERSION}};
  }
  if (kind === "dbInsert") {
    __convexCapabilityRequireExactKeys(request, ["kind", "table", "value", "version"], "Capability request", requestKeys);
    if (typeof request.table !== "string") throw new Error("Database table must be a string");
    return {
      kind,
      table: request.table,
      value: __convexCapabilityEncodeTaggedOrGuest(request.value),
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "dbPatch") {
    __convexCapabilityRequireExactKeys(request, ["id", "kind", "patch", "table", "version"], "Capability request", requestKeys);
    if (typeof request.table !== "string") throw new Error("Database table must be a string");
    return {
      id: __convexCapabilityEncodeCommittedValue(request.id),
      kind,
      patch: __convexCapabilityEncodePatch(request.patch),
      table: request.table,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "dbReplace") {
    __convexCapabilityRequireExactKeys(request, ["id", "kind", "table", "value", "version"], "Capability request", requestKeys);
    if (typeof request.table !== "string") throw new Error("Database table must be a string");
    return {
      id: __convexCapabilityEncodeCommittedValue(request.id),
      kind,
      table: request.table,
      value: __convexCapabilityEncodeTaggedOrGuest(request.value),
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "dbQuery") {
    const paginate = request.terminal === "paginate";
    __convexCapabilityRequireExactKeys(
      request,
      paginate
        ? ["kind", "operators", "order", "pagination", "source", "table", "terminal", "version"]
        : ["kind", "operators", "order", "source", "table", "terminal", "version"],
      "Capability request",
      requestKeys,
    );
    if (typeof request.table !== "string") throw new Error("Query table must be a string");
    if (request.order !== null && request.order !== "asc" && request.order !== "desc") {
      throw new Error("Query order is invalid");
    }
    if (
      request.terminal !== "collect" &&
      request.terminal !== "first" &&
      request.terminal !== "paginate" &&
      request.terminal !== "stream" &&
      request.terminal !== "unique"
    ) {
      throw new Error("Query terminal is invalid");
    }
    const source = __convexCapabilityEncodeQuerySource(request.source);
    if (source.type === "search" && request.order !== null) {
      throw new Error("Search queries must always use relevance order");
    }
    const operators = __convexCapabilityEncodeQueryOperators(request.operators);
    return paginate
      ? ({
          kind,
          operators,
          order: request.order,
          pagination: __convexCapabilityEncodePagination(request.pagination),
          source,
          table: request.table,
          terminal: request.terminal,
          version: ${CAPABILITY_REQUEST_ABI_VERSION},
        })
      : ({
          kind,
          operators,
          order: request.order,
          source,
          table: request.table,
          terminal: request.terminal,
          version: ${CAPABILITY_REQUEST_ABI_VERSION},
        });
  }
  if (kind === "functionHandleCreate") {
    __convexCapabilityRequireExactKeys(
      request,
      ["functionAddress", "kind", "version"],
      "Capability request",
      requestKeys,
    );
    return {
      functionAddress: __convexCapabilityEncodeFunctionAddress(request.functionAddress),
      kind,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "runUdf") {
    __convexCapabilityRequireExactKeys(
      request,
      ["args", "functionAddress", "kind", "transactionLimits", "udfType", "version"],
      "Capability request",
      requestKeys,
    );
    if (
      request.udfType !== "mutation" &&
      request.udfType !== "query" &&
      request.udfType !== "snapshotQuery"
    ) {
      throw new Error("Nested UDF type is unsupported");
    }
    return {
      args: __convexCapabilityEncodeTaggedOrGuest(request.args),
      functionAddress: __convexCapabilityEncodeFunctionAddress(request.functionAddress),
      kind,
      transactionLimits: __convexCapabilityEncodeTransactionLimits(request.transactionLimits),
      udfType: request.udfType,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  if (kind === "schedulerRunAfter" || kind === "schedulerRunAt") {
    const timeField = kind === "schedulerRunAfter" ? "delayMilliseconds" : "timestampMilliseconds";
    __convexCapabilityRequireExactKeys(
      request,
      ["args", "functionAddress", "kind", timeField, "version"],
      "Capability request",
      requestKeys,
    );
    const fields: any = {
      args: __convexCapabilityEncodeCommittedValue(request.args),
      functionAddress: __convexCapabilityEncodeFunctionAddress(request.functionAddress),
      kind,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
    __convexGuestDefineObjectField(
      fields,
      timeField,
      __convexCapabilityRequireFiniteNumber(request[timeField], "Schedule time"),
    );
    return __convexCapabilitySortedObject(fields);
  }
  if (kind === "schedulerCancel") {
    __convexCapabilityRequireExactKeys(request, ["id", "kind", "version"], "Capability request", requestKeys);
    return {
      id: __convexCapabilityEncodeCommittedValue(request.id),
      kind,
      version: ${CAPABILITY_REQUEST_ABI_VERSION},
    };
  }
  throw new Error("Capability request kind is unsupported");
}

function __convexCapabilityRequestToHost(request: any): number {
  const source = JSON.stringify(__convexCapabilityEncodeRequest(request));
  const pointer = __convexGuestTransferScratch(source.length * 3 + 1);
  const length = __convexWriteUtf8(source, pointer);
  const handle = __convexHostCapabilityRequestDecode(pointer, length);
  if (handle <= 0) throw new Error("Capability request envelope decode failed");
  return handle;
}

function __convexCapabilityRequestRelease(requestHandle: number): void {
  if (requestHandle <= 0) throw new Error("Capability request handle is invalid");
  __convexHostCapabilityRequestRelease(requestHandle);
}
`;
}

export function renderNativeCapabilityRequestEnvelopePrelude() {
  return [
    renderNativeCapabilityGuestValuePrelude(),
    renderNativeCapabilityRequestEnvelopeHostImports(),
    renderNativeCapabilityRequestEnvelopeRuntime(),
  ].join("\n");
}

function renderNativeCapabilityPromiseRuntime() {
  return String.raw`
const __convexDynamicGlobal: any = __convexTargetGlobal;
const __convexDynamicArrayIsArray: any = __convexDynamicGlobal.Array.isArray;
const __convexDynamicPromise: any = __convexDynamicGlobal.Promise;
let __convexPendingOperationKinds: Array<?string> = [];
let __convexPendingOperationResolves: Array<any> = [];
let __convexPendingOperationRejects: Array<any> = [];
let __convexOpenQueryStreamCleanups: Array<any> = [];
let __convexInvocationDone = false;
let __convexInvocationStatus = 0;

function __convexPendingOperationSlot(operationHandle: number, create: boolean): number {
  if (operationHandle <= 0) throw new Error("Convex async operation returned an invalid handle");
  const slot = operationHandle - 1;
  if (create) {
    while (__convexPendingOperationKinds.length <= slot) {
      __convexPendingOperationKinds.push(undefined);
      __convexPendingOperationResolves.push(undefined);
      __convexPendingOperationRejects.push(undefined);
    }
  } else if (slot >= __convexPendingOperationKinds.length) {
    throw new Error("Convex async completion has no pending Promise");
  }
  return slot;
}

function __convexRegisterCapabilityOperation(
  operationHandle: number,
  resultKind: string,
  resolve: any,
  reject: any,
): void {
  const slot = __convexPendingOperationSlot(operationHandle, true);
  if (__convexPendingOperationResolves[slot] !== undefined) {
    throw new Error("Convex async operation handle was reused");
  }
  if (resultKind !== "hostValue" && resultKind !== "taggedJson" && resultKind !== "undefined") {
    throw new Error("Convex capability result kind is invalid");
  }
  __convexPendingOperationKinds[slot] = resultKind;
  __convexPendingOperationResolves[slot] = resolve;
  __convexPendingOperationRejects[slot] = reject;
}

function __convexCapabilityStartAsync(
  start: any,
  request: any,
  resultKind: string,
): any {
  if (typeof start !== "function") throw new Error("Native capability start is missing");
  let requestHandle = __convexCapabilityRequestToHost(request);
  try {
    const operationHandle = start(requestHandle);
    if (operationHandle === -1) {
      return __convexDynamicPromise.reject(new Error("Invocation capability is stale"));
    }
    if (operationHandle <= 0) {
      throw new Error("Capability returned an invalid operation handle");
    }
    requestHandle = 0;
    return new __convexDynamicPromise((resolve, reject) => {
      __convexRegisterCapabilityOperation(operationHandle, resultKind, resolve, reject);
    });
  } finally {
    if (requestHandle > 0) __convexCapabilityRequestRelease(requestHandle);
  }
}

function __convexCapabilityRunSync(sync: any, request: any): any {
  if (typeof sync !== "function") throw new Error("Native synchronous capability is missing");
  let requestHandle = __convexCapabilityRequestToHost(request);
  try {
    const resultHandle = sync(requestHandle);
    if (resultHandle === -2) throw new Error("Invocation capability is stale");
    requestHandle = 0;
    if (resultHandle === -1) return null;
    if (resultHandle <= 0) throw new Error("Synchronous capability returned an invalid result");
    return __convexGuestFromHost(resultHandle);
  } finally {
    if (requestHandle > 0) __convexCapabilityRequestRelease(requestHandle);
  }
}

function __convexCapabilityOpenQueryStream(request: any): number {
  const capabilityIdentity = __convexHostCapabilityCurrent();
  if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
  let requestHandle = __convexCapabilityRequestToHost(request);
  try {
    const streamHandle = __convexHostCapabilityQueryStreamOpenTake(
      capabilityIdentity,
      requestHandle,
    );
    if (streamHandle === -1) throw new Error("Invocation capability is stale");
    if (streamHandle <= 0) throw new Error("Capability returned an invalid query stream handle");
    requestHandle = 0;
    return streamHandle;
  } finally {
    if (requestHandle > 0) __convexCapabilityRequestRelease(requestHandle);
  }
}

function __convexRegisterOpenQueryStream(cleanup: any): number {
  if (typeof cleanup !== "function") throw new Error("Query stream cleanup is invalid");
  const slot = __convexOpenQueryStreamCleanups.length;
  __convexOpenQueryStreamCleanups.push(cleanup);
  return slot;
}

function __convexReleaseOpenQueryStream(slot: number): void {
  if (
    slot < 0 ||
    slot >= __convexOpenQueryStreamCleanups.length ||
    typeof __convexOpenQueryStreamCleanups[slot] !== "function"
  ) {
    throw new Error("Query stream cleanup slot is invalid");
  }
  __convexOpenQueryStreamCleanups[slot] = undefined;
}

function __convexCapabilityRequireTable(table: any, isSystem: boolean, method: string): string {
  if (typeof table !== "string") throw new Error(method + " table must be a string");
  const accessingSystemTable = table.charAt(0) === "_";
  if (accessingSystemTable !== isSystem) {
    throw new Error(
      (accessingSystemTable ? "System" : "User") +
        " tables can only be accessed from db." +
        (isSystem ? "" : "system.") +
        method + "().",
    );
  }
  return table;
}

function __convexCapabilityFunctionAddress(functionReference: any): any {
  if (typeof functionReference === "string") {
    if (functionReference.indexOf("function://") === 0) {
      return {functionHandle: functionReference};
    }
    return {name: functionReference};
  }
  if (functionReference === null || typeof functionReference !== "object") {
    throw new Error(String(functionReference) + " is not a functionReference");
  }
  const functionName = functionReference[__convexDynamicGlobal.Symbol.for("functionName")];
  if (functionName) return {name: functionName};
  const reference = functionReference[__convexDynamicGlobal.Symbol.for("toReferencePath")];
  if (!reference) throw new Error(String(functionReference) + " is not a functionReference");
  return {reference};
}

function __convexCapabilityFunctionArgs(args: any): any {
  const functionArgs = args === undefined ? {} : args;
  if (
    functionArgs === null ||
    typeof functionArgs !== "object" ||
    __convexDynamicArrayIsArray(functionArgs)
  ) {
    throw new Error("The arguments to a Convex function must be an object");
  }
  return functionArgs;
}

function __convexCapabilityTransactionLimits(options: any): any {
  if (options === undefined || options === null || options.transactionLimits === undefined) {
    return null;
  }
  return __convexCapabilityEncodeTransactionLimits(options.transactionLimits);
}

function __convexCapabilityRangeBuilder(constraints: any[]): any {
  let consumed = false;
  function append(operator: string, field: any, value: any): any {
    if (consumed) throw new Error("IndexRangeBuilder has already been used");
    if (typeof field !== "string") throw new Error("Index field must be a string");
    consumed = true;
    const next = constraints.slice();
    next.push({operator, field, value});
    return __convexCapabilityRangeBuilder(next);
  }
  return {
    eq(field, value) { return append("eq", field, value); },
    gt(field, value) { return append("gt", field, value); },
    gte(field, value) { return append("gte", field, value); },
    lt(field, value) { return append("lt", field, value); },
    lte(field, value) { return append("lte", field, value); },
    __convexCapabilityExportRange() {
      if (consumed) throw new Error("IndexRangeBuilder has already been used");
      consumed = true;
      return constraints;
    },
  };
}

function __convexCapabilitySearchFilterBuilder(filters: any[], hasSearch: boolean): any {
  let consumed = false;
  function append(type: string, field: any, value: any): any {
    if (consumed) throw new Error("SearchFilterBuilder has already been used");
    if (typeof field !== "string") throw new Error("Search filter field must be a string");
    if (type === "search") {
      if (hasSearch) throw new Error("Search filters may contain only one search filter");
      if (typeof value !== "string") throw new Error("Search query must be a string");
    } else if (!hasSearch) {
      throw new Error("Search filters must begin with a search filter");
    }
    consumed = true;
    const next = filters.slice();
    next.push({type, field, value});
    return __convexCapabilitySearchFilterBuilder(next, hasSearch || type === "search");
  }
  return {
    search(field, query) { return append("search", field, query); },
    eq(field, value) { return append("eq", field, value); },
    __convexCapabilityExportSearchFilters() {
      if (consumed) throw new Error("SearchFilterBuilder has already been used");
      if (!hasSearch) throw new Error("Search filters must begin with a search filter");
      consumed = true;
      return filters;
    },
  };
}

function __convexCapabilityExpression(value: any): any {
  return {
    __convexCapabilitySerializeExpression() { return value; },
  };
}

function __convexCapabilitySerializeExpression(value: any): any {
  if (
    value !== null &&
    typeof value === "object" &&
    typeof value.__convexCapabilitySerializeExpression === "function"
  ) {
    return value.__convexCapabilitySerializeExpression();
  }
  return {$literal: value === undefined ? {$undefined: null} : value};
}

function __convexCapabilityFilterBuilder(): any {
  function binary(operator: string, left: any, right: any): any {
    const operands = [
      __convexCapabilitySerializeExpression(left),
      __convexCapabilitySerializeExpression(right),
    ];
    const expression: any = {};
    expression[operator] = operands;
    return __convexCapabilityExpression(expression);
  }
  return {
    eq(left, right) { return binary("$eq", left, right); },
    neq(left, right) { return binary("$neq", left, right); },
    lt(left, right) { return binary("$lt", left, right); },
    lte(left, right) { return binary("$lte", left, right); },
    gt(left, right) { return binary("$gt", left, right); },
    gte(left, right) { return binary("$gte", left, right); },
    add(left, right) { return binary("$add", left, right); },
    sub(left, right) { return binary("$sub", left, right); },
    mul(left, right) { return binary("$mul", left, right); },
    div(left, right) { return binary("$div", left, right); },
    mod(left, right) { return binary("$mod", left, right); },
    neg(value) {
      return __convexCapabilityExpression({
        $neg: __convexCapabilitySerializeExpression(value),
      });
    },
    and(...values) {
      return __convexCapabilityExpression({
        $and: values.map(__convexCapabilitySerializeExpression),
      });
    },
    or(...values) {
      return __convexCapabilityExpression({
        $or: values.map(__convexCapabilitySerializeExpression),
      });
    },
    not(value) {
      return __convexCapabilityExpression({
        $not: __convexCapabilitySerializeExpression(value),
      });
    },
    field(field) { return __convexCapabilityExpression({$field: field}); },
  };
}

function __convexCapabilityRequireTakeLimit(limit: any): number {
  if (
    typeof limit !== "number" ||
    !isFinite(limit) ||
    limit < 0 ||
    Math.floor(limit) !== limit
  ) {
    throw new Error("take() requires a non-negative integer");
  }
  return limit;
}

function __convexCapabilityPaginationOptions(options: any): any {
  const numItems: any =
    options === null || options === undefined ? undefined : options.numItems;
  if (typeof numItems !== "number" || numItems < 0) {
    throw new Error("options.numItems must be a positive number. Received " + String(numItems) + ".");
  }
  function nullIfNullish(value: any): any {
    return value === null || value === undefined ? null : value;
  }
  return {
    cursor: nullIfNullish(options.cursor),
    endCursor: nullIfNullish(options.endCursor),
    maximumBytesRead: nullIfNullish(options.maximumBytesRead),
    maximumRowsRead: nullIfNullish(options.maximumRowsRead),
    pageSize: numItems,
  };
}

function __convexStartCapabilityQueryStreamNext(streamHandle: number, resultKind: string): any {
  return new __convexDynamicPromise((resolve, reject) => {
    const operationHandle = __convexHostAsyncQueryStreamNext(streamHandle);
    __convexRegisterCapabilityOperation(operationHandle, resultKind, resolve, reject);
  });
}

function __convexCreateCapabilityQueryIterator(request: any): any {
  let streamHandle = __convexCapabilityOpenQueryStream(request);
  let done = false;
  let pending = false;
  let cleanupSlot = -1;
  function releaseStream(closeHost: boolean): void {
    if (done) return;
    if (closeHost) __convexHostAsyncQueryStreamClose(streamHandle);
    done = true;
    streamHandle = 0;
    __convexReleaseOpenQueryStream(cleanupSlot);
    cleanupSlot = -1;
  }
  cleanupSlot = __convexRegisterOpenQueryStream(() => {
    done = true;
    streamHandle = 0;
    cleanupSlot = -1;
  });
  const iterator: any = {
    next(): any {
      if (done) {
        return __convexDynamicPromise.resolve({done: true, value: undefined});
      }
      if (pending) {
        return __convexDynamicPromise.reject(
          new Error("Convex query stream already has a pending read"),
        );
      }
      pending = true;
      return __convexStartCapabilityQueryStreamNext(streamHandle, "hostValue").then(
        (result) => {
          pending = false;
          if (
            result === null ||
            typeof result !== "object" ||
            typeof result.done !== "boolean" ||
            !("value" in result)
          ) {
            throw new Error("Convex query stream returned an invalid iteration result");
          }
          if (result.done) {
            if (result.value !== null) {
              throw new Error("Convex query stream completion returned a value");
            }
            releaseStream(false);
            return {done: true, value: undefined};
          }
          return {done: false, value: result.value};
        },
        (error) => {
          pending = false;
          releaseStream(false);
          throw error;
        },
      );
    },
    return(): any {
      if (pending) {
        return __convexDynamicPromise.reject(
          new Error("Convex query stream cannot close during a pending read"),
        );
      }
      releaseStream(true);
      return __convexDynamicPromise.resolve({done: true, value: undefined});
    },
  };
  iterator[__convexDynamicGlobal.Symbol.asyncIterator] = function(): any {
    return iterator;
  };
  return iterator;
}

function __convexCapabilityQuery(
  start: any,
  table: string,
  source: any,
  operators: any[],
  order: any,
): any {
  let consumed = false;
  let iterator: any = null;
  function takeQuery(): void {
    if (consumed) throw new Error("This query is closed");
    consumed = true;
  }
  function request(terminal: string, takeLimit: any, pagination: any): any {
    takeQuery();
    const terminalOperators = operators.slice();
    if (takeLimit !== null) {
      terminalOperators.push({type: "limit", limit: takeLimit});
    }
    const request = pagination === null
      ? {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbQuery",
        table,
        source,
        operators: terminalOperators,
        order,
        terminal,
      }
      : {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbQuery",
        table,
        source,
        operators: terminalOperators,
        order,
        pagination,
        terminal,
      };
    return request;
  }
  function run(terminal: string, takeLimit: any, pagination: any): any {
    return __convexCapabilityStartAsync(start, request(terminal, takeLimit, pagination), "hostValue");
  }
  function startIteration(): any {
    if (iterator !== null) throw new Error("Iteration can only begin on a query once");
    iterator = __convexCreateCapabilityQueryIterator(request("stream", null, null));
    return iterator;
  }
  return {
    order(nextOrder) {
      if (nextOrder !== "asc" && nextOrder !== "desc") {
        throw new Error("Query order must be 'asc' or 'desc'");
      }
      if (source.type === "search") {
        takeQuery();
        throw new Error("Search queries must always be in relevance order");
      }
      if (order !== null) throw new Error("Queries may only specify order at most once");
      takeQuery();
      return __convexCapabilityQuery(start, table, source, operators, nextOrder);
    },
    filter(predicate) {
      if (typeof predicate !== "function") throw new Error("Query filter must be a function");
      if (operators.length >= 256) {
        throw new Error("Can't construct query with more than 256 operators");
      }
      takeQuery();
      const expression = __convexCapabilitySerializeExpression(
        predicate(__convexCapabilityFilterBuilder()),
      );
      const nextOperators = operators.slice();
      nextOperators.push({type: "filter", expression});
      return __convexCapabilityQuery(start, table, source, nextOperators, order);
    },
    limit(limit) {
      if (typeof limit !== "number") throw new Error("Query limit must be a number");
      takeQuery();
      const nextOperators = operators.slice();
      nextOperators.push({type: "limit", limit});
      return __convexCapabilityQuery(start, table, source, nextOperators, order);
    },
    collect() { return run("collect", null, null); },
    first() { return run("first", 1, null); },
    paginate(options) {
      return run("paginate", null, __convexCapabilityPaginationOptions(options));
    },
    take(limit) { return run("collect", __convexCapabilityRequireTakeLimit(limit), null); },
    unique() { return run("unique", 2, null); },
    next() { return (iterator === null ? startIteration() : iterator).next(); },
    return() {
      if (iterator !== null) return iterator.return();
      takeQuery();
      return __convexDynamicPromise.resolve({done: true, value: undefined});
    },
    [__convexDynamicGlobal.Symbol.asyncIterator]() { return startIteration(); },
  };
}

function __convexCapabilityQueryInitializer(start: any, table: string): any {
  function fullTableScan(): any {
    return __convexCapabilityQuery(start, table, {type: "fullTableScan"}, [], null);
  }
  return {
    fullTableScan,
    withIndex(index, indexRange) {
      if (typeof index !== "string") throw new Error("Index name must be a string");
      let constraints = [];
      if (indexRange !== undefined) {
        if (typeof indexRange !== "function") throw new Error("Index range must be a function");
        const range = indexRange(__convexCapabilityRangeBuilder([]));
        if (
          range === null ||
          typeof range !== "object" ||
          typeof range.__convexCapabilityExportRange !== "function"
        ) {
          throw new Error("Index range returned an invalid builder");
        }
        constraints = range.__convexCapabilityExportRange();
      }
      return __convexCapabilityQuery(
        start,
        table,
        {type: "indexRange", index, constraints},
        [],
        null,
      );
    },
    withSearchIndex(index, searchFilter) {
      if (typeof index !== "string") throw new Error("Search index name must be a string");
      if (typeof searchFilter !== "function") {
        throw new Error("Search filter must be a function");
      }
      const filter = searchFilter(__convexCapabilitySearchFilterBuilder([], false));
      if (
        filter === null ||
        typeof filter !== "object" ||
        typeof filter.__convexCapabilityExportSearchFilters !== "function"
      ) {
        throw new Error("Search filter returned an invalid builder");
      }
      return __convexCapabilityQuery(
        start,
        table,
        {
          type: "search",
          index,
          filters: filter.__convexCapabilityExportSearchFilters(),
        },
        [],
        null,
      );
    },
    order(order) { return fullTableScan().order(order); },
    filter(predicate) { return fullTableScan().filter(predicate); },
    limit(limit) { return fullTableScan().limit(limit); },
    collect() { return fullTableScan().collect(); },
    first() { return fullTableScan().first(); },
    paginate(options) { return fullTableScan().paginate(options); },
    take(limit) { return fullTableScan().take(limit); },
    unique() { return fullTableScan().unique(); },
    [__convexDynamicGlobal.Symbol.asyncIterator]() {
      return fullTableScan()[__convexDynamicGlobal.Symbol.asyncIterator]();
    },
  };
}

function __convexCapabilityReader(start: any, sync: any, isSystem: boolean): any {
  return {
    get(arg0, arg1) {
      const hasTable = arg1 !== undefined;
      if (hasTable) {
        const table = __convexCapabilityRequireTable(arg0, isSystem, "get");
        return __convexCapabilityStartAsync(
          start,
          {
            version: ${CAPABILITY_REQUEST_ABI_VERSION},
            kind: isSystem ? "dbSystemGet" : "dbGet",
            id: arg1,
            table,
          },
          "hostValue",
        );
      }
      return __convexCapabilityStartAsync(
        start,
        {
          version: ${CAPABILITY_REQUEST_ABI_VERSION},
          kind: isSystem ? "dbSystemGet" : "dbGet",
          id: arg0,
        },
        "hostValue",
      );
    },
    normalizeId(table, value) {
      const checkedTable = __convexCapabilityRequireTable(table, isSystem, "normalizeId");
      if (typeof value !== "string") throw new Error("normalizeId value must be a string");
      return __convexCapabilityRunSync(sync, {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "dbNormalizeId",
        table: checkedTable,
        value,
      });
    },
    query(table) {
      const checkedTable = __convexCapabilityRequireTable(table, isSystem, "query");
      return __convexCapabilityQueryInitializer(start, checkedTable);
    },
  };
}

function __convexCapabilityCreateContext(
  start: any,
  sync: any,
  udfKind: any,
  commitTsPlaceholder: any,
): any {
  if (udfKind !== "query" && udfKind !== "mutation") {
    throw new Error("Invocation UDF kind is invalid");
  }
  if (commitTsPlaceholder === null || typeof commitTsPlaceholder !== "object") {
    throw new Error("Invocation SDK commit timestamp placeholder is invalid");
  }
  // The typed bridge is shared by application units. Link the selected unit's
  // authenticated SDK placeholder only for the current serial invocation.
  __convexCommitTsPlaceholder = commitTsPlaceholder;
  const reader = __convexCapabilityReader(start, sync, false);
  reader.system = __convexCapabilityReader(start, sync, true);
  const storage: any = {
    getUrl(storageId) {
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "storageGetUrl", storageId},
        "hostValue",
      );
    },
    getMetadata(storageId) {
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "storageGetMetadata", storageId},
        "hostValue",
      );
    },
  };
  const context: any = {
    auth: {
      getUserIdentity() {
        return __convexCapabilityStartAsync(
          start,
          {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "authGetUserIdentity"},
          "hostValue",
        );
      },
    },
    db: reader,
    storage,
  };
  context.runQuery = function(functionReference, args, options): any {
    const useStaleSnapshot = options !== undefined && options !== null
      ? options.useStaleSnapshot
      : undefined;
    if (useStaleSnapshot && udfKind === "query") {
      throw new Error(${JSON.stringify(
        "`useStaleSnapshot` is only supported in mutations, not queries."
      )});
    }
    return __convexCapabilityStartAsync(
      start,
      {
        version: ${CAPABILITY_REQUEST_ABI_VERSION},
        kind: "runUdf",
        udfType: useStaleSnapshot ? "snapshotQuery" : "query",
        functionAddress: __convexCapabilityFunctionAddress(functionReference),
        args: __convexCapabilityFunctionArgs(args),
        transactionLimits: __convexCapabilityTransactionLimits(options),
      },
      "hostValue",
    );
  };
  if (udfKind === "mutation") {
    storage.generateUploadUrl = function(): any {
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "storageGenerateUploadUrl"},
        "hostValue",
      );
    };
    storage.delete = function(storageId): any {
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "storageDelete", storageId},
        "undefined",
      );
    };
    reader.vars = {commitTs: __convexCommitTsPlaceholder};
    reader.insert = function(table, value): any {
      const checkedTable = __convexCapabilityRequireTable(table, false, "insert");
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "dbInsert", table: checkedTable, value},
        "hostValue",
      );
    };
    reader.patch = function(table, id, patch): any {
      const checkedTable = __convexCapabilityRequireTable(table, false, "patch");
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "dbPatch", table: checkedTable, id, patch},
        "undefined",
      );
    };
    reader.replace = function(table, id, value): any {
      const checkedTable = __convexCapabilityRequireTable(table, false, "replace");
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "dbReplace", table: checkedTable, id, value},
        "undefined",
      );
    };
    reader.delete = function(table, id): any {
      const checkedTable = __convexCapabilityRequireTable(table, false, "delete");
      return __convexCapabilityStartAsync(
        start,
        {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "dbDelete", table: checkedTable, id},
        "undefined",
      );
    };
    context.runMutation = function(functionReference, args, options): any {
      return __convexCapabilityStartAsync(
        start,
        {
          version: ${CAPABILITY_REQUEST_ABI_VERSION},
          kind: "runUdf",
          udfType: "mutation",
          functionAddress: __convexCapabilityFunctionAddress(functionReference),
          args: __convexCapabilityFunctionArgs(args),
          transactionLimits: __convexCapabilityTransactionLimits(options),
        },
        "hostValue",
      );
    };
    context.scheduler = {
      runAfter(delayMilliseconds, functionReference, args) {
        if (typeof delayMilliseconds !== "number") throw new Error("delayMs must be a number");
        if (!isFinite(delayMilliseconds)) throw new Error("delayMs must be a finite number");
        if (delayMilliseconds < 0) throw new Error("delayMs must be non-negative");
        return __convexCapabilityStartAsync(
          start,
          {
            version: ${CAPABILITY_REQUEST_ABI_VERSION},
            kind: "schedulerRunAfter",
            delayMilliseconds,
            functionAddress: __convexCapabilityFunctionAddress(functionReference),
            args: __convexCapabilityFunctionArgs(args),
          },
          "hostValue",
        );
      },
      runAt(invokeTime, functionReference, args) {
        let timestampMilliseconds;
        if (invokeTime instanceof __convexDynamicGlobal.Date) {
          timestampMilliseconds = invokeTime.valueOf();
        } else if (typeof invokeTime === "number") {
          timestampMilliseconds = invokeTime;
        } else {
          throw new Error("The invoke time must a Date or a timestamp");
        }
        return __convexCapabilityStartAsync(
          start,
          {
            version: ${CAPABILITY_REQUEST_ABI_VERSION},
            kind: "schedulerRunAt",
            timestampMilliseconds,
            functionAddress: __convexCapabilityFunctionAddress(functionReference),
            args: __convexCapabilityFunctionArgs(args),
          },
          "hostValue",
        );
      },
      cancel(id) {
        return __convexCapabilityStartAsync(
          start,
          {version: ${CAPABILITY_REQUEST_ABI_VERSION}, kind: "schedulerCancel", id},
          "undefined",
        );
      },
    };
  }
  return context;
}

function __convexCapabilityReadRequest(): any {
  return __convexReadGuestRequest();
}

function __convexCapabilityTrackInvocationResult(result: any, taggedJsonResult: boolean): void {
  // Both terminal callbacks are non-throwing, so the derived Promise cannot
  // become an unobserved rejection after the host sees invocationDone.
  __convexDynamicPromise.resolve(result)
    .then((value) => {
      if (taggedJsonResult) {
        if (typeof value !== "string") {
          throw new Error("Convex SDK registration wrapper returned a non-string result");
        }
        // The SDK serialized this result; the host codec validates the tagged
        // value before it records the final result.
        __convexSetGuestFunctionTaggedJsonResult(value);
      } else {
        __convexSetGuestFunctionResult(value === undefined ? null : value);
      }
    })
    .then(
      () => { __convexInvocationDone = true; },
      (error) => {
        try {
          __convexReportThrown(error);
        } catch {
          __convexInvocationStatus = 1;
        } finally {
          __convexInvocationDone = true;
        }
      },
    );
}

function __convexCapabilityInvoke(handler: any, context: any, args: any): void {
  if (typeof handler !== "function") throw new Error("Selected handler is missing");
  __convexInvocationDone = false;
  __convexInvocationStatus = 0;
  try {
    __convexCapabilityTrackInvocationResult(handler(context, args), false);
  } catch (error) {
    try {
      __convexReportThrown(error);
    } finally {
      __convexInvocationStatus = 1;
      __convexInvocationDone = true;
    }
  }
}

function __convexCapabilityInvokeRegisteredWrapper(wrapper: any, taggedArgs: any): void {
  if (typeof wrapper !== "function" || typeof wrapper._handler !== "function") {
    throw new Error("Selected Convex registration wrapper is invalid");
  }
  const udfKind = __convexSdkRequireActive();
  const invocationMethod = udfKind === "query" ? "invokeQuery" : "invokeMutation";
  const kindProperty = udfKind === "query" ? "isQuery" : "isMutation";
  const otherKindProperty = udfKind === "query" ? "isMutation" : "isQuery";
  if (
    wrapper[kindProperty] !== true ||
    wrapper[otherKindProperty] !== undefined ||
    wrapper.isAction !== undefined ||
    (wrapper.isPublic !== true && wrapper.isInternal !== true) ||
    (wrapper.isPublic === true && wrapper.isInternal === true) ||
    typeof wrapper[invocationMethod] !== "function"
  ) {
    throw new Error("Selected Convex registration wrapper metadata is invalid");
  }
  __convexInvocationDone = false;
  __convexInvocationStatus = 0;
  try {
    if (typeof taggedArgs !== "string") {
      throw new Error("Selected Convex registration wrapper arguments are invalid");
    }
    const argsStr = "[" + taggedArgs + "]";
    __convexCapabilityTrackInvocationResult(wrapper[invocationMethod](argsStr), true);
  } catch (error) {
    try {
      __convexReportThrown(error);
    } finally {
      __convexInvocationStatus = 1;
      __convexInvocationDone = true;
    }
  }
}

function __convexCapabilityDone(): boolean { return __convexInvocationDone; }
function __convexCapabilityStatus(): number { return __convexInvocationStatus; }

function __convexCapabilityCleanup(): number {
  let abandoned = 0;
  // Invalidate guest handles only. The runtime calls host cancel_all next to
  // release abandoned cursors without inventing application queryCleanup calls.
  // Explicit iterator return and successful exhaustion retain their own closes.
  for (let slot = 0; slot < __convexOpenQueryStreamCleanups.length; slot += 1) {
    const cleanup = __convexOpenQueryStreamCleanups[slot];
    if (cleanup !== undefined) {
      if (typeof cleanup !== "function") {
        throw new Error("Query stream cleanup registry contains an invalid slot");
      }
      cleanup();
      __convexOpenQueryStreamCleanups[slot] = undefined;
    }
  }
  __convexOpenQueryStreamCleanups = [];
  for (let slot = 0; slot < __convexPendingOperationKinds.length; slot += 1) {
    const kind = __convexPendingOperationKinds[slot];
    const resolve = __convexPendingOperationResolves[slot];
    const reject = __convexPendingOperationRejects[slot];
    if (kind === undefined) {
      if (resolve !== undefined || reject !== undefined) {
        throw new Error("Convex async operation registry contains a partial slot");
      }
    } else {
      if (
        (kind !== "hostValue" && kind !== "taggedJson" && kind !== "undefined") ||
        typeof resolve !== "function" ||
        typeof reject !== "function"
      ) {
        throw new Error("Convex async operation registry contains an invalid pending slot");
      }
      abandoned += 1;
    }
    __convexPendingOperationKinds[slot] = undefined;
    __convexPendingOperationResolves[slot] = undefined;
    __convexPendingOperationRejects[slot] = undefined;
  }
  __convexPendingOperationKinds = [];
  __convexPendingOperationResolves = [];
  __convexPendingOperationRejects = [];
  __convexSdkQueryStreams = [];
  __convexSdkActiveUdfKind = null;
  return abandoned;
}

function __convexCapabilitySettle(
  operationHandle: number,
  completionStatus: number,
  payloadHandle: number,
): void {
  const slot = __convexPendingOperationSlot(operationHandle, false);
  const kind = __convexPendingOperationKinds[slot];
  const resolve = __convexPendingOperationResolves[slot];
  const reject = __convexPendingOperationRejects[slot];
  if (
    (kind !== "hostValue" && kind !== "taggedJson" && kind !== "undefined") ||
    typeof resolve !== "function" ||
    typeof reject !== "function"
  ) {
    throw new Error("Convex async completion has no pending Promise");
  }
  let completion: any;
  if (completionStatus === 1) {
    if (payloadHandle <= 0) throw new Error("Convex async rejection has no payload");
    const message = __convexGuestFromHost(payloadHandle);
    if (typeof message !== "string") throw new Error("Convex async rejection payload is invalid");
    completion = new Error(message);
    __convexHostOperationErrorCandidates.set(completion, operationHandle);
  } else if (completionStatus === 0) {
    if (kind === "undefined") {
      if (payloadHandle !== 0) throw new Error("Convex void completion returned a payload");
      completion = undefined;
    } else {
      if (payloadHandle <= 0) throw new Error("Convex completion has no payload");
      completion = kind === "taggedJson"
        ? __convexGuestTaggedJsonFromHost(payloadHandle)
        : __convexGuestFromHost(payloadHandle);
    }
  } else {
    throw new Error("Convex async completion status is invalid");
  }
  __convexPendingOperationKinds[slot] = undefined;
  __convexPendingOperationResolves[slot] = undefined;
  __convexPendingOperationRejects[slot] = undefined;
  if (completionStatus === 1) reject(completion);
  else resolve(completion);
}

function __convexWasmCapabilityBootstrap(install: any): void {
  if (typeof install !== "function") throw new Error("Native capability installer is missing");
  install(
    __convexCapabilityCreateContext,
    __convexCapabilityReadRequest,
    __convexCapabilityInvoke,
    __convexCapabilityDone,
    __convexCapabilityCleanup,
    __convexCapabilitySettle,
    __convexCapabilityStatus,
    __convexSdkActivate,
    __convexCapabilityInvokeRegisteredWrapper,
    __convexReadGuestRequestTaggedJson,
  );
}

Object.defineProperty(__convexTargetGlobal, "__convexWasmCapabilityBootstrap", {
  configurable: true,
  enumerable: false,
  value: __convexWasmCapabilityBootstrap,
  writable: true,
});
`;
}

export function renderNativeDbGetCapabilityTarget({
  argumentFields,
  compileProfileJavascript,
  sdkPackageVersion,
}) {
  assertStringArray(argumentFields, "argumentFields");
  const runtimeSurface = assertConvexWasmTargetRuntimeSurface(compileProfileJavascript);
  const staticHermesCompileProfileJavascript = preserveEsbuildLiveExportBindings(
    runtimeSurface.javascript
  );
  const requestEnvelopePrelude = renderNativeCapabilityRequestEnvelopePrelude();
  const capabilityRuntimeHostImports = renderNativeCapabilityRuntimeHostImports();
  const capabilityPromiseRuntime = renderNativeCapabilityPromiseRuntime();
  const capabilityRuntime = [
    requestEnvelopePrelude,
    capabilityRuntimeHostImports,
    `const ${convexWasmApplicationGlobalThisBinding}: any = null;`,
    renderNativeRuntimeSupportAdapter(),
    renderNativeConvexSdkFacade(sdkPackageVersion),
    capabilityPromiseRuntime,
  ].join("\n");
  assertNativeCapabilityHelperDefinitions(capabilityRuntime);
  return [
    renderConvexWasmTargetRuntimeGlobalPrelude(),
    renderConvexWasmIntrinsicHardeningPrelude(),
    "{",
    requestEnvelopePrelude,
    capabilityRuntimeHostImports,
    renderNativeRuntimeSupportAdapter(),
    renderNativeDatabaseUdfTimerAdapter(),
    renderNativeCryptoAdapter(),
    renderNativePerformanceAdapter(),
    renderNativeProcessEnvironmentAdapter(),
    renderNativeConvexSdkFacade(sdkPackageVersion),
    renderConvexWasmApplicationGlobalFacade(),
    `let __convexApplicationCompileProfile: any;
try {
  __convexApplicationCompileProfile = (function(): any {
"use strict";
${staticHermesCompileProfileJavascript}
return __convexWasmCompileProfile;
  })();
} catch (__convexInitializationError) {
  __convexReportThrown(__convexInitializationError);
  throw __convexInitializationError;
}
const __convexLinkedCommitTsPlaceholder: any =
  __convexApplicationCompileProfile[${JSON.stringify(
    COMMIT_TS_PLACEHOLDER_EXPORT_NAME
  )}];
if (
  __convexLinkedCommitTsPlaceholder === null ||
  typeof __convexLinkedCommitTsPlaceholder !== "object"
) {
  throw new Error("Convex Wasm compile profile is missing the SDK commit timestamp placeholder");
}
__convexCommitTsPlaceholder = __convexLinkedCommitTsPlaceholder;
__convexTargetGlobal.__convexWasmCompileProfile = __convexApplicationCompileProfile;`,
    capabilityPromiseRuntime,
    "}",
    "",
  ].join("\n");
}

export function renderNativeDbGetCapabilityTargetUnits({
  argumentFields,
  compileProfileJavascript,
  sdkPackageVersion,
}) {
  assertStringArray(argumentFields, "argumentFields");
  const runtimeSurface = assertConvexWasmTargetRuntimeSurface(compileProfileJavascript);
  const staticHermesCompileProfileJavascript = preserveEsbuildLiveExportBindings(
    runtimeSurface.javascript
  );
  const requestEnvelopePrelude = renderNativeCapabilityRequestEnvelopePrelude();
  const capabilityRuntimeHostImports = renderNativeCapabilityRuntimeHostImports();
  const capabilityPromiseRuntime = renderNativeCapabilityPromiseRuntime();
  const capabilityRuntime = [
    requestEnvelopePrelude,
    capabilityRuntimeHostImports,
    `const ${convexWasmApplicationGlobalThisBinding}: any = null;`,
    renderNativeRuntimeSupportAdapter(),
    renderNativeConvexSdkFacade(sdkPackageVersion),
    capabilityPromiseRuntime,
  ].join("\n");
  assertNativeCapabilityHelperDefinitions(capabilityRuntime);

  const bridgeJavascript = [
    renderConvexWasmTargetRuntimeGlobalPrelude(),
    renderConvexWasmIntrinsicHardeningPrelude(),
    "{",
    requestEnvelopePrelude,
    capabilityRuntimeHostImports,
    renderNativeRuntimeSupportAdapter(),
    renderNativeDatabaseUdfTimerAdapter(),
    renderNativeCryptoAdapter(),
    renderNativePerformanceAdapter(),
    renderNativeProcessEnvironmentAdapter(),
    renderNativeConvexSdkFacade(sdkPackageVersion),
    renderConvexWasmApplicationGlobalFacade(),
    `function __convexWasmApplicationReportThrown(error: any): void {
  __convexReportThrown(error);
}
Object.freeze(__convexWasmApplicationReportThrown);
Object.defineProperty(__convexTargetGlobal, "__convexWasmApplicationGlobalThis", {
  configurable: true,
  enumerable: false,
  value: __convexWasmApplicationGlobalThis,
  writable: false,
});
Object.defineProperty(__convexTargetGlobal, "__convexWasmApplicationReportThrown", {
  configurable: true,
  enumerable: false,
  value: __convexWasmApplicationReportThrown,
  writable: false,
});`,
    capabilityPromiseRuntime,
    "}",
    "",
  ].join("\n");

  const applicationJavascript = `(function(
  __convexWasmApplicationGlobalThis,
  __convexWasmApplicationPublishCompileProfile,
  __convexWasmApplicationReportThrown
) {
"use strict";
try {
  if (
    __convexWasmApplicationGlobalThis === null ||
    typeof __convexWasmApplicationGlobalThis !== "object" ||
    !Object.isExtensible(__convexWasmApplicationGlobalThis) ||
    Object.getPrototypeOf(__convexWasmApplicationGlobalThis) !== null
  ) {
    throw new Error("Convex Wasm application global facade is invalid");
  }
  if (typeof __convexWasmApplicationPublishCompileProfile !== "function") {
    throw new Error("Convex Wasm application profile publisher is invalid");
  }
  if (typeof __convexWasmApplicationReportThrown !== "function") {
    throw new Error("Convex Wasm application error reporter is invalid");
  }
  const __convexApplicationCompileProfile = (function() {
"use strict";
${staticHermesCompileProfileJavascript}
return __convexWasmCompileProfile;
  })();
  __convexWasmApplicationPublishCompileProfile(__convexApplicationCompileProfile);
} catch (__convexInitializationError) {
  if (typeof __convexWasmApplicationReportThrown === "function") {
    __convexWasmApplicationReportThrown(__convexInitializationError);
  }
  throw __convexInitializationError;
}
})(
  globalThis.__convexWasmApplicationGlobalThis,
  globalThis.__convexWasmApplicationPublishCompileProfile,
  globalThis.__convexWasmApplicationReportThrown
);
`;

  return {
    applicationJavascript,
    bridgeJavascript,
    formatterJavascript: renderNativeRuntimeSupportUnit(),
  };
}

export const convexWasmLoweringFormat = LOWERING_FORMAT;
export const convexWasmOpaqueAbiVersion = OPAQUE_ABI_VERSION;
export const convexWasmCapabilityRequestAbiVersion = CAPABILITY_REQUEST_ABI_VERSION;
export const convexWasmBlockingEffectExecutionMode = BLOCKING_EFFECT_EXECUTION_MODE;
export const convexWasmGuestPromiseEffectExecutionMode = GUEST_PROMISE_EFFECT_EXECUTION_MODE;
export {
  convexWasmIntrinsicHardeningPolicy,
  convexWasmIntrinsicHardeningPolicySha256,
  convexWasmIntrinsicHardeningSourceSha256,
};
export { convexWasmTargetRuntimeSurfacePolicy, convexWasmTargetRuntimeSurfacePolicySha256 };
