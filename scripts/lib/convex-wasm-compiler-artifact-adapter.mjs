import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  compileConvexWasmArtifact,
  compileConvexWasmArtifactInMaterialSession,
  compileConvexWasmCohortsInMaterialSession,
  createConvexWasmArtifactMaterialSession,
  createV8FallbackManifest,
  finalizeConvexWasmArtifactMaterialSession,
  fingerprintJson,
} from "./convex-wasm-artifact-pipeline.mjs";
import {
  convexWasmBlockingEffectExecutionMode,
  convexWasmCompilerAbiVersion,
  convexWasmCompilerOpaqueValueAbiVersion,
  convexWasmGuestPromiseEffectExecutionMode,
  validateConvexWasmCompilerOutputContract,
} from "./convex-wasm-compiler-contract.mjs";
import { convexWasmTargetRuntimeSurfacePolicyIdentity } from "./convex-wasm-runtime-surface.mjs";
import {
  convexWasmLoweringFormat,
  convexWasmOpaqueAbiVersion,
  lowerConvexWasmExport,
  renderOpaqueAbiHeader,
} from "./convex-wasm-lowering.mjs";

const OPAQUE_ABI_HEADER_NAME = "convex_wasm_opaque_abi_v3.h";
const GUEST_PROMISE_JSI_HEADER_NAME = "jsi/jsi.h";
const GUEST_PROMISE_RUNTIME_MAIN_PATH = fileURLToPath(
  new URL("./convex-wasm-runtime-main.cpp", import.meta.url)
);
const GUEST_SOURCE_PROVENANCE_KIND = "convex-wasm-guest-source-provenance-v1";
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const compilerArtifactTransformPreactivationRecords = new WeakMap();
const TOP_LEVEL_DECLARATION_PATTERN =
  /^(?:(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=)/gmu;

function fail(message) {
  throw new Error(`Convex Wasm compiler artifact adapter: ${message}`);
}

function assertObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireArray(value, description) {
  if (!Array.isArray(value)) {
    fail(`${description} must be an array`);
  }
  return value;
}

function requireValueMode(value) {
  if (value !== "opaque" && value !== "guest-native-json") {
    fail("compiler output valueMode must be opaque or guest-native-json");
  }
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function normalizeReachableUnit(unit, index) {
  const description = `compiler reachable unit ${index}`;
  assertObject(unit, description);
  const expectedKeys = [
    "column",
    "dependencyChain",
    "end",
    "id",
    "kind",
    "line",
    "module",
    "name",
    "sourceHash",
    "start",
  ];
  if (JSON.stringify(Object.keys(unit).sort()) !== JSON.stringify(expectedKeys)) {
    fail(`${description} has unsupported fields`);
  }
  const name = requireString(unit.name, `${description} name`);
  if (!IDENTIFIER_PATTERN.test(name)) {
    fail(`${description} name is not a JavaScript identifier`);
  }
  if (unit.kind !== "function" && unit.kind !== "handler" && unit.kind !== "variable") {
    fail(`${description} kind is unsupported`);
  }
  const start = requirePositiveInteger(unit.start + 1, `${description} start plus one`) - 1;
  const end = requirePositiveInteger(unit.end, `${description} end`);
  if (end <= start) {
    fail(`${description} source range is invalid`);
  }
  const dependencyChain = requireArray(unit.dependencyChain, `${description} dependencyChain`).map(
    (entry) => requireString(entry, `${description} dependency chain entry`)
  );
  const expectedId =
    unit.kind === "handler" ? `${unit.module}#${unit.name}:handler` : `${unit.module}#${unit.name}`;
  if (unit.id !== expectedId) {
    fail(`${description} ID does not match its module, name, and kind`);
  }
  const dependencyUnitId = unit.kind === "handler" ? `${unit.module}#${unit.name}` : unit.id;
  if (dependencyChain.length !== 0 && dependencyChain.at(-1) !== dependencyUnitId) {
    fail(`${description} dependency chain does not end at its unit ID`);
  }
  return {
    column: requirePositiveInteger(unit.column, `${description} column`),
    dependencyChain,
    end,
    id: requireString(unit.id, `${description} id`),
    kind: unit.kind,
    line: requirePositiveInteger(unit.line, `${description} line`),
    module: requireString(unit.module, `${description} module`),
    name,
    sourceHash: requireSha256(unit.sourceHash, `${description} sourceHash`),
    start,
  };
}

function compilerBundleDeclarations(bundleCode) {
  const declarations = [...bundleCode.matchAll(TOP_LEVEL_DECLARATION_PATTERN)].map((match) => ({
    line: bundleCode.slice(0, match.index).split("\n").length,
    name: match[1] ?? match[2],
  }));
  const names = new Set();
  for (const declaration of declarations) {
    if (names.has(declaration.name)) {
      fail(`compiler generated duplicate top-level declaration ${declaration.name}`);
    }
    names.add(declaration.name);
  }
  return declarations.map((declaration, index) => ({
    ...declaration,
    endLine:
      index + 1 === declarations.length
        ? bundleCode.split("\n").length
        : declarations[index + 1].line - 1,
  }));
}

function createGuestSourceProvenance(compilerOutput, generatedSource, lowering) {
  const reachableUnits = requireArray(
    compilerOutput.reachableUnits,
    "compiler output reachableUnits"
  ).map(normalizeReachableUnit);
  const reachableByDeclaration = new Map();
  for (const unit of reachableUnits) {
    const declarationName = unit.kind === "handler" ? "__convexWasmHandler" : unit.name;
    if (reachableByDeclaration.has(declarationName)) {
      fail(`compiler reachable units ambiguously map declaration ${declarationName}`);
    }
    reachableByDeclaration.set(declarationName, unit);
  }
  const declarations = compilerBundleDeclarations(generatedSource);
  const mapped = [];
  for (const declaration of declarations) {
    const original = reachableByDeclaration.get(declaration.name);
    if (original === undefined) {
      continue;
    }
    reachableByDeclaration.delete(declaration.name);
    mapped.push({
      generatedRange: {
        endLine: lowering.bundleLayout.startLine + declaration.endLine - 1,
        startLine: lowering.bundleLayout.startLine + declaration.line - 1,
      },
      original,
    });
  }
  if (reachableByDeclaration.size !== 0) {
    fail(
      `compiler reachable units are absent from generated JavaScript: ${[...reachableByDeclaration.keys()].sort().join(", ")}`
    );
  }
  return {
    compilerBundle: {
      endLine: lowering.bundleLayout.endLine,
      sha256: sha256(generatedSource),
      size: Buffer.byteLength(generatedSource),
      startLine: lowering.bundleLayout.startLine,
    },
    generatedSource: {
      sha256: lowering.codeSha256,
      size: Buffer.byteLength(lowering.code),
    },
    kind: GUEST_SOURCE_PROVENANCE_KIND,
    schemaVersion: 1,
    units: mapped,
  };
}

async function verifyOpaqueAbiHeader(artifactConfig) {
  assertObject(artifactConfig.runtime, "artifact config runtime");
  const includeDirectories = requireArray(
    artifactConfig.runtime.includeDirectories,
    "artifact config runtime includeDirectories"
  );
  const expected = renderOpaqueAbiHeader();
  for (const includeDirectory of includeDirectories) {
    const directory = resolve(
      requireString(includeDirectory, "artifact config runtime include directory")
    );
    const headerPath = join(directory, OPAQUE_ABI_HEADER_NAME);
    let actual;
    try {
      actual = await fs.readFile(headerPath, "utf8");
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        (error.code === "ENOENT" || error.code === "ENOTDIR")
      ) {
        continue;
      }
      throw error;
    }
    if (actual !== expected) {
      fail(`resolved ${OPAQUE_ABI_HEADER_NAME} does not match the lowering ABI: ${headerPath}`);
    }
    return;
  }
  fail(`artifact config does not resolve ${OPAQUE_ABI_HEADER_NAME}`);
}

async function verifyGuestPromiseRuntimeHeaders(artifactConfig, effectExecutionMode) {
  if (effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode) {
    return;
  }
  const includeDirectories = requireArray(
    artifactConfig.runtime.includeDirectories,
    "artifact config runtime includeDirectories"
  );
  for (const includeDirectory of includeDirectories) {
    const headerPath = join(
      resolve(requireString(includeDirectory, "artifact config runtime include directory")),
      GUEST_PROMISE_JSI_HEADER_NAME
    );
    try {
      const header = await fs.stat(headerPath);
      if (header.isFile()) {
        return;
      }
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        (error.code === "ENOENT" || error.code === "ENOTDIR")
      ) {
        continue;
      }
      throw error;
    }
  }
  fail(`guest Promise runtime artifact config does not resolve ${GUEST_PROMISE_JSI_HEADER_NAME}`);
}

function validateCompilerEnvelope(compilerOutput) {
  validateConvexWasmCompilerOutputContract(compilerOutput, { mode: "compile" });
  if (compilerOutput.abiVersion !== convexWasmCompilerAbiVersion) {
    fail(`unsupported compiler ABI ${JSON.stringify(compilerOutput.abiVersion)}`);
  }
  if (convexWasmOpaqueAbiVersion !== convexWasmCompilerOpaqueValueAbiVersion) {
    fail("lowering and compiler contract opaque ABI versions disagree");
  }
  if (compilerOutput.opaqueValueAbiVersion !== convexWasmOpaqueAbiVersion) {
    fail(
      `compiler opaque ABI ${String(compilerOutput.opaqueValueAbiVersion)} does not match lowering ABI ${convexWasmOpaqueAbiVersion}`
    );
  }
  assertObject(compilerOutput.source, "compiler output source");
  assertObject(compilerOutput.compiler, "compiler output compiler identity");
  assertConvexWasmCompilerRuntimeSurfacePolicyIdentity(compilerOutput.compiler);
  assertObject(compilerOutput.routing, "compiler output routing");
  if (Object.hasOwn(compilerOutput.routing, "diagnostics")) {
    fail("compiler routing must not duplicate top-level diagnostics");
  }
  if (
    compilerOutput.source.resolvedGraphSha256 !== compilerOutput.sourceGraphFingerprint ||
    compilerOutput.source.exportSha256 !== compilerOutput.exportFingerprint
  ) {
    fail("compiler source identities disagree with their top-level fingerprints");
  }
  const wasm = compilerOutput.routing.decision === "wasm";
  const fallback = compilerOutput.routing.decision === "v8Fallback";
  if (!wasm && !fallback) {
    fail(`unsupported routing decision ${JSON.stringify(compilerOutput.routing.decision)}`);
  }
  if (compilerOutput.eligible !== wasm) {
    fail("compiler eligibility disagrees with its routing decision");
  }
}

export function assertConvexWasmCompilerRuntimeSurfacePolicyIdentity(compiler) {
  assertObject(compiler, "compiler identity");
  if (
    fingerprintJson(compiler.staticHermesGlobalPolicy) !==
    fingerprintJson(convexWasmTargetRuntimeSurfacePolicyIdentity)
  ) {
    fail("compiler and Node runtime-surface policy identities disagree");
  }
}

export function createCompilerImportedOperation(operation) {
  assertObject(operation, "compiler operation");
  if (!Number.isSafeInteger(operation.id) || operation.id < 1 || operation.id > 65_535) {
    fail("compiler operation ID must be between 1 and 65535");
  }
  const debugName = requireString(operation.stableKey, "compiler operation stableKey");
  if (operation.kind === "sha256") {
    return {
      debugName,
      id: operation.id,
      operation: { kind: "sha256" },
    };
  }
  if (operation.kind === "authenticationGetUserIdentity") {
    return {
      debugName,
      id: operation.id,
      operation: { kind: "authenticationGetUserIdentity" },
    };
  }
  if (operation.kind === "hostSecretVerify") {
    return {
      debugName,
      id: operation.id,
      operation: {
        contractVersion:
          operation.contractVersion === 1
            ? 1
            : fail("host-secret operation contractVersion must be 1"),
        kind: "hostSecretVerify",
        selector: requireString(operation.selector, "host-secret operation selector"),
      },
    };
  }
  if (operation.kind === "databaseNormalizeId") {
    return {
      debugName,
      id: operation.id,
      operation: {
        kind: "databaseNormalizeId",
        tableName: requireString(operation.table, "database normalizeId operation table"),
      },
    };
  }
  if (operation.kind === "databaseGet") {
    return {
      debugName,
      id: operation.id,
      operation: {
        kind: "databaseGet",
        tableName: requireString(operation.table, "database get operation table"),
      },
    };
  }
  if (
    operation.kind === "databaseInsert" ||
    operation.kind === "databasePatch" ||
    operation.kind === "databaseReplace" ||
    operation.kind === "databaseDelete"
  ) {
    return {
      debugName,
      id: operation.id,
      operation: {
        kind: operation.kind,
        tableName: requireString(operation.table, "database write operation table"),
      },
    };
  }
  if (operation.kind === "schedulerRunAfter" || operation.kind === "schedulerRunAt") {
    return {
      debugName,
      id: operation.id,
      operation: {
        functionReference: requireString(
          operation.functionReference,
          "scheduler operation functionReference"
        ),
        kind: operation.kind,
      },
    };
  }
  if (operation.kind !== "databaseIndexQuery") {
    fail(`unsupported admitted operation kind ${JSON.stringify(operation.kind)}`);
  }
  const terminal = ["collect", "first", "stream", "unique"].includes(operation.terminal)
    ? operation.terminal
    : fail(`unsupported database operation terminal ${JSON.stringify(operation.terminal)}`);
  const limit =
    terminal === "collect"
      ? operation.limit === null ||
        (Number.isSafeInteger(operation.limit) &&
          operation.limit >= 1 &&
          operation.limit <= 100_000)
        ? operation.limit
        : fail(`unsupported database operation limit ${JSON.stringify(operation.limit)}`)
      : operation.limit === null
        ? null
        : fail(`unexpected database operation limit ${JSON.stringify(operation.limit)}`);
  const indexConstraints = requireArray(
    operation.indexConstraints,
    "database operation indexConstraints"
  );
  const compilerLimitArgumentIndex =
    operation.limitArgumentIndex === undefined ? null : operation.limitArgumentIndex;
  const limitArgumentIndex =
    compilerLimitArgumentIndex === null
      ? null
      : terminal === "collect" &&
          limit === null &&
          Number.isSafeInteger(compilerLimitArgumentIndex) &&
          compilerLimitArgumentIndex === indexConstraints.length
        ? compilerLimitArgumentIndex
        : fail(
            `unsupported database operation limitArgumentIndex ${JSON.stringify(compilerLimitArgumentIndex)}`
          );
  return {
    debugName,
    id: operation.id,
    operation: {
      constraints: indexConstraints.map((constraint, index) => {
        assertObject(constraint, `database operation index constraint ${index}`);
        if (!["eq", "gt", "gte", "lt", "lte"].includes(constraint.operator)) {
          fail(`unsupported database operation constraint ${JSON.stringify(constraint.operator)}`);
        }
        return {
          fieldPath: requireString(
            constraint.field,
            `database operation index constraint ${index} field`
          ),
          operator: constraint.operator,
        };
      }),
      indexName: requireString(operation.index, "database operation index"),
      kind: "databaseIndexQuery",
      limit,
      limitArgumentIndex,
      order:
        operation.order === "ascending" || operation.order === "descending"
          ? operation.order
          : fail(`unsupported database operation order ${JSON.stringify(operation.order)}`),
      tableName: requireString(operation.table, "database operation table"),
      terminal,
    },
  };
}

function loweringOperation(importedOperation) {
  const { id, operation } = importedOperation;
  if (operation.kind === "sha256") {
    return undefined;
  }
  if (operation.kind === "authenticationGetUserIdentity") {
    return { id, kind: operation.kind };
  }
  if (operation.kind === "hostSecretVerify") {
    return {
      contractVersion: operation.contractVersion,
      id,
      kind: operation.kind,
      selector: operation.selector,
    };
  }
  if (operation.kind === "databaseNormalizeId") {
    return {
      id,
      kind: operation.kind,
      table: operation.tableName,
    };
  }
  if (operation.kind === "databaseGet") {
    return {
      id,
      kind: operation.kind,
      table: operation.tableName,
    };
  }
  if (
    operation.kind === "databaseInsert" ||
    operation.kind === "databasePatch" ||
    operation.kind === "databaseReplace" ||
    operation.kind === "databaseDelete"
  ) {
    return {
      id,
      kind: operation.kind,
      table: operation.tableName,
    };
  }
  if (operation.kind === "schedulerRunAfter" || operation.kind === "schedulerRunAt") {
    return {
      functionReference: operation.functionReference,
      id,
      kind: operation.kind,
    };
  }
  if (operation.kind !== "databaseIndexQuery") {
    fail(`unsupported lowering operation kind ${JSON.stringify(operation.kind)}`);
  }
  return {
    constraints: operation.constraints.map(({ fieldPath, operator }) => ({
      field: fieldPath,
      operator,
    })),
    id,
    index: operation.indexName,
    kind: operation.kind,
    limit: operation.limit,
    limitArgumentIndex: operation.limitArgumentIndex,
    order: operation.order,
    table: operation.tableName,
    terminal: operation.terminal,
  };
}

function intrinsicMap(compilerOutput) {
  const result = {};
  const operationKinds = new Map(
    compilerOutput.operations.map((operation) => [operation.id, operation.kind])
  );
  for (const intrinsic of requireArray(compilerOutput.intrinsics, "compiler output intrinsics")) {
    assertObject(intrinsic, "compiler intrinsic");
    if (
      intrinsic.kind !== "sha256" ||
      !Number.isSafeInteger(intrinsic.operationId) ||
      operationKinds.get(intrinsic.operationId) !== "sha256"
    ) {
      fail("compiler intrinsic does not identify an admitted SHA-256 operation");
    }
    const functionName = requireString(intrinsic.functionName, "compiler intrinsic functionName");
    if (Object.hasOwn(result, functionName)) {
      fail(`compiler emitted duplicate intrinsic function ${functionName}`);
    }
    result[functionName] = {
      kind: "sha256",
      operationId: intrinsic.operationId,
    };
  }
  return result;
}

function compilerDirectBatchResultKind(operation) {
  if (operation.kind === "databaseIndexQuery" && operation.terminal === "collect") {
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

function compilerDirectBatchArgumentCount(operation) {
  if (operation.kind === "databaseIndexQuery") {
    return (
      operation.indexConstraints.length +
      (operation.limitArgumentIndex === undefined || operation.limitArgumentIndex === null ? 0 : 1)
    );
  }
  return operation.kind === "databasePatch" ||
    operation.kind === "databaseReplace" ||
    operation.kind === "schedulerRunAfter" ||
    operation.kind === "schedulerRunAt"
    ? 2
    : 1;
}

function validateCompilerDirectBatchArguments({
  allowExactDuplicates = false,
  argumentsValue,
  description,
  operationEnd,
  operationStart,
  sourceBytes,
  sourceStart,
}) {
  let previousArgument;
  for (const [argumentIndex, argument] of argumentsValue.entries()) {
    const argumentDescription = `${description} dynamic argument ${argumentIndex}`;
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
      (!exactDuplicate &&
        previousArgument !== undefined &&
        (previousArgument.sourceEnd > argument.sourceStart ||
          previousArgument.generatedEnd > argument.generatedStart)) ||
      sha256(
        sourceBytes.subarray(argument.sourceStart - sourceStart, argument.sourceEnd - sourceStart)
      ) !== argument.sourceSha256
    ) {
      fail(`${argumentDescription} does not bind its exact source`);
    }
    previousArgument = argument;
  }
}

function directAsyncBatchAuthorizations(compilerOutput, operations) {
  const operationsById = new Map(operations.map((operation) => [operation.id, operation]));
  return requireArray(
    compilerOutput.directAsyncBatches,
    "compiler direct async batch authorizations"
  ).map((authorization, index) => {
    assertObject(authorization, `compiler direct async batch authorization ${index}`);
    const description = `compiler direct async batch authorization ${index}`;
    const authorizationSourceBytes = Buffer.from(authorization.source);
    if (sha256(authorizationSourceBytes) !== authorization.sourceSha256) {
      fail(`${description} does not bind its exact original source`);
    }
    if (authorization.kind === "fixedEffectArray") {
      let previousChild;
      for (const [childIndex, child] of authorization.children.entries()) {
        const childDescription = `${description} fixed child ${childIndex}`;
        const operation = operationsById.get(child.operationId);
        if (
          operation === undefined ||
          operation.kind !== child.operationKind ||
          operation.file !== authorization.file ||
          operation.start !== child.operationStart ||
          operation.end !== child.operationEnd
        ) {
          fail(`${childDescription} does not match its exact operation`);
        }
        if (
          child.start < authorization.start ||
          child.start >= child.end ||
          child.end > authorization.end ||
          child.operationStart < child.start ||
          child.operationStart >= child.operationEnd ||
          child.operationEnd > child.end ||
          child.generatedStart < authorization.generatedStart ||
          child.generatedStart >= child.generatedEnd ||
          child.generatedEnd > authorization.generatedEnd ||
          (previousChild !== undefined &&
            (previousChild.end > child.start ||
              previousChild.generatedEnd > child.generatedStart)) ||
          sha256(
            authorizationSourceBytes.subarray(
              child.start - authorization.start,
              child.end - authorization.start
            )
          ) !== child.sourceSha256
        ) {
          fail(`${childDescription} has inconsistent source spans`);
        }
        if (
          child.resultKind !== compilerDirectBatchResultKind(operation) ||
          child.dynamicArguments.length !== compilerDirectBatchArgumentCount(operation)
        ) {
          fail(`${childDescription} contract disagrees with its operation`);
        }
        if (typeof child.helperContinuationPrebound !== "boolean") {
          fail(`${childDescription} helperContinuationPrebound must be a boolean`);
        }
        validateCompilerDirectBatchArguments({
          allowExactDuplicates: child.helperContinuationPrebound,
          argumentsValue: child.dynamicArguments,
          description: childDescription,
          operationEnd: child.operationEnd,
          operationStart: child.operationStart,
          sourceBytes: authorizationSourceBytes,
          sourceStart: authorization.start,
        });
        previousChild = child;
      }
      return authorization;
    }
    if (authorization.kind !== "singleEffectMap") {
      fail(`${description} kind is unsupported`);
    }
    const operation = operationsById.get(authorization.operationId);
    if (
      operation === undefined ||
      operation.kind !== authorization.operationKind ||
      operation.file !== authorization.file ||
      operation.start !== authorization.operationStart ||
      operation.end !== authorization.operationEnd
    ) {
      fail(`${description} does not match its exact operation`);
    }
    if (
      authorization.start >= authorization.callbackStart ||
      authorization.callbackStart >= authorization.operationStart ||
      authorization.operationEnd > authorization.callbackEnd ||
      authorization.callbackEnd > authorization.end
    ) {
      fail(`${description} has inconsistent source spans`);
    }
    requireString(authorization.callbackParameter, `${description} callbackParameter`);
    if (
      authorization.resultKind !== compilerDirectBatchResultKind(operation) ||
      authorization.dynamicArguments.length !== compilerDirectBatchArgumentCount(operation)
    ) {
      fail(`${description} contract disagrees with its operation`);
    }
    validateCompilerDirectBatchArguments({
      argumentsValue: authorization.dynamicArguments,
      description,
      operationEnd: authorization.operationEnd,
      operationStart: authorization.operationStart,
      sourceBytes: authorizationSourceBytes,
      sourceStart: authorization.start,
    });
    return authorization;
  });
}

function backendDiagnostic(diagnostic) {
  assertObject(diagnostic, "compiler diagnostic");
  const code = {
    "capability-helper-binding-write": "unsupportedConstruct",
    "generated-function-reference-escape": "unsupportedConstruct",
    "global-write": "unsupportedGlobal",
    "indirect-capability-callsite": "unsupportedConstruct",
    "missing-runtime-export": "unsupportedImport",
    "mixed-capability-callsite": "unsupportedConstruct",
    "module-state-write": "unsupportedGlobal",
    "non-runtime-export": "unsupportedImport",
    "runtime-type-only-import": "unsupportedImport",
    "unproved-generated-function-reference": "unsupportedConstruct",
    "unsupported-argument-validator-shape": "unsupportedConstruct",
    "unsupported-array-filter": "unsupportedConstruct",
    "unsupported-array-filter-lowering": "unsupportedConstruct",
    "unsupported-array-for-of-lowering": "unsupportedConstruct",
    "unsupported-construct": "unsupportedConstruct",
    "unsupported-convex-effect": "unsupportedConstruct",
    "unsupported-authentication-get-user-identity-shape": "unsupportedConstruct",
    "unsupported-database-normalize-id-shape": "unsupportedConstruct",
    "unsupported-dependency-adapter-binding": "unsupportedConstruct",
    "unsupported-dependency-adapter-call-shape": "unsupportedConstruct",
    "unsupported-dependency-adapter-capability": "unsupportedConstruct",
    "unsupported-dependency-adapter-iterable": "unsupportedConstruct",
    "unsupported-dependency-adapter-suspension": "unsupportedConstruct",
    "unsupported-direct-promise-all": "unsupportedConstruct",
    "unsupported-document-collection-flow": "unsupportedConstruct",
    "unsupported-generated-function-reference": "unsupportedConstruct",
    "unsupported-module-initialization-cycle": "unsupportedConstruct",
    "unsupported-nondeterminism": "unsupportedConstruct",
    "unsupported-registration-builder": "unsupportedConstruct",
    "unsupported-runtime-capability-flow": "unsupportedConstruct",
    "unsupported-runtime-capability-member": "unsupportedConstruct",
    "unsupported-sha256-intrinsic-shape": "unsupportedConstruct",
    "unsupported-global": "unsupportedGlobal",
    "unsupported-runtime-import": "unsupportedImport",
  }[diagnostic.code];
  if (code === undefined) {
    fail(`compiler diagnostic code has no backend mapping: ${JSON.stringify(diagnostic.code)}`);
  }
  const line = diagnostic.line;
  const column = diagnostic.column;
  if (!Number.isSafeInteger(line) || line < 1 || !Number.isSafeInteger(column) || column < 1) {
    fail("compiler diagnostic position must be one-based");
  }
  const source = requireString(diagnostic.source, "compiler diagnostic source");
  const sourceLines = source.split("\n");
  const endLine = line + sourceLines.length - 1;
  const endColumn =
    sourceLines.length === 1
      ? column + source.length
      : sourceLines[sourceLines.length - 1].length + 1;
  return {
    code,
    dependencyChain: requireArray(
      diagnostic.dependencyChain,
      "compiler diagnostic dependencyChain"
    ).map((entry) => requireString(entry, "compiler diagnostic dependency chain entry")),
    message: requireString(diagnostic.message, "compiler diagnostic message"),
    modulePath: requireString(diagnostic.file, "compiler diagnostic file"),
    sourceSpan: {
      endColumn,
      endLine,
      startColumn: column,
      startLine: line,
    },
    subject:
      typeof diagnostic.construct === "string" && diagnostic.construct.length > 0
        ? diagnostic.construct
        : source,
  };
}

export function createCompilerArtifactIdentity(compiler) {
  const sourcePipelineSha256 = compiler.pipelineSha256;
  return {
    admittedLanguageVersion: compiler.admittedLanguageVersion,
    compilerRevision: compiler.compilerRevision,
    loweringPipelineSha256: fingerprintJson({
      loweringFormat: convexWasmLoweringFormat,
      sourcePipelineSha256,
    }),
    sourcePipelineSha256,
    staticHermesGlobalPolicy: compiler.staticHermesGlobalPolicy,
  };
}

export function prepareCompilerArtifact({ artifactConfig, compilerOutput, runtimeModulePath }) {
  validateCompilerEnvelope(compilerOutput);
  assertObject(artifactConfig, "artifact config");
  assertObject(artifactConfig.toolchain, "artifact config toolchain");
  assertObject(artifactConfig.toolchain.staticHermes, "artifact config Static Hermes tool");
  assertObject(artifactConfig.limits, "artifact config limits");
  const compiler = createCompilerArtifactIdentity(compilerOutput.compiler);
  const valueMode = requireValueMode(compilerOutput.valueMode);
  const effectExecutionMode =
    compilerOutput.effectExecutionMode ?? convexWasmBlockingEffectExecutionMode;
  const source = {
    ...compilerOutput.source,
    runtimeModulePath: requireString(runtimeModulePath, "runtime module path"),
  };

  if (compilerOutput.routing.decision === "v8Fallback") {
    if (compilerOutput.generatedJavascriptArtifact !== null) {
      fail("ineligible compiler output must not contain generated JavaScript");
    }
    return {
      executionManifest: createV8FallbackManifest({
        compiler,
        diagnostics: requireArray(compilerOutput.diagnostics, "compiler output diagnostics").map(
          backendDiagnostic
        ),
        effectExecutionMode,
        limits: artifactConfig.limits.execution,
        opaqueValueAbiVersion: compilerOutput.opaqueValueAbiVersion,
        platformLimits: compilerOutput.limits,
        source,
        staticHermesRevision: artifactConfig.toolchain.staticHermes.revision,
        valueMode,
      }),
      kind: "v8Fallback",
    };
  }

  assertObject(
    compilerOutput.generatedJavascriptArtifact,
    "eligible compiler generated JavaScript artifact"
  );
  const generatedSource = requireString(
    compilerOutput.generatedJavascriptArtifact.source,
    "eligible compiler generated JavaScript source"
  );
  if (
    Buffer.byteLength(generatedSource) !== compilerOutput.generatedJavascriptArtifact.bytes ||
    sha256(generatedSource) !== compilerOutput.generatedJavascriptArtifact.sha256
  ) {
    fail("compiler generated JavaScript bytes do not match its identity");
  }
  if (requireArray(compilerOutput.diagnostics, "compiler output diagnostics").length !== 0) {
    fail("eligible compiler output must not contain admission diagnostics");
  }

  const operations = requireArray(compilerOutput.operations, "compiler output operations");
  const importedOperations = operations.map(createCompilerImportedOperation);
  const directAsyncBatches = directAsyncBatchAuthorizations(compilerOutput, operations);
  const lowering = lowerConvexWasmExport({
    appliedDependencyAdapters:
      compilerOutput.appliedDependencyAdapters === undefined
        ? []
        : requireArray(
            compilerOutput.appliedDependencyAdapters,
            "compiler applied dependency adapters"
          ),
    argumentFields: requireArray(compilerOutput.argumentFields, "compiler argument fields"),
    arrayArgumentFields: requireArray(
      compilerOutput.arrayArgumentFields,
      "compiler array argument fields"
    ),
    bundleCode: generatedSource,
    bundleSourceName: compilerOutput.generatedJavascriptArtifact.suggestedPath,
    documentFields: requireArray(
      compilerOutput.documentProperties,
      "compiler document properties"
    ).map((property) => requireString(property.property, "compiler document property")),
    handlerIdentifier: "__convexWasmHandler",
    intrinsics: intrinsicMap(compilerOutput),
    operations: importedOperations
      .map(loweringOperation)
      .filter((operation) => operation !== undefined),
    operationsSha256: compilerOutput.operationsSha256,
    directAsyncBatches,
    effectExecutionMode,
    runtimeInputs: requireArray(compilerOutput.runtimeInputs, "compiler runtime inputs"),
    sourceGraphFingerprint: compilerOutput.source.resolvedGraphSha256,
    valueMode,
  });
  const guestSourceProvenance = createGuestSourceProvenance(
    compilerOutput,
    generatedSource,
    lowering
  );
  return {
    artifactOptions: {
      ...artifactConfig,
      compiler,
      effectExecutionMode,
      generatedJavaScript: lowering.code,
      guestSourceProvenance,
      importedOperations,
      opaqueValueAbiVersion: compilerOutput.opaqueValueAbiVersion,
      platformLimits: compilerOutput.limits,
      routingDecision: { decision: "wasm" },
      runtime:
        effectExecutionMode === convexWasmGuestPromiseEffectExecutionMode
          ? { ...artifactConfig.runtime, mainSourcePath: GUEST_PROMISE_RUNTIME_MAIN_PATH }
          : artifactConfig.runtime,
      source,
      valueMode,
    },
    kind: "wasm",
    lowering,
  };
}

export function startCompilerArtifactTransformPreactivation(input, payloadSha256) {
  if (!SHA256_PATTERN.test(payloadSha256)) {
    fail("compiler artifact transform preactivation payload SHA-256 is invalid");
  }
  const prepared = prepareCompilerArtifact(input);
  if (prepared.kind !== "wasm") {
    fail("compiler artifact transform preactivation requires an eligible compiler output");
  }
  const token = Object.freeze({ kind: "convex-wasm-compiler-artifact-transform-preactivation-v1" });
  compilerArtifactTransformPreactivationRecords.set(token, {
    claimed: false,
    payloadSha256,
    prepared,
    retainedBytes: Buffer.byteLength(prepared.lowering.code),
  });
  return token;
}

function requireCompilerArtifactTransformPreactivationRecord(token) {
  const record = compilerArtifactTransformPreactivationRecords.get(token);
  if (
    record === undefined ||
    token?.kind !== "convex-wasm-compiler-artifact-transform-preactivation-v1"
  ) {
    fail("compiler artifact transform preactivation is invalid");
  }
  return record;
}

export function compilerArtifactTransformPreactivationRetainedBytes(token) {
  return requireCompilerArtifactTransformPreactivationRecord(token).retainedBytes;
}

export function revokeCompilerArtifactTransformPreactivation(token) {
  const record = requireCompilerArtifactTransformPreactivationRecord(token);
  if (record.claimed) {
    fail("compiler artifact transform preactivation was already claimed");
  }
  compilerArtifactTransformPreactivationRecords.delete(token);
}

export function settleCompilerArtifactTransformPreactivation(token) {
  requireCompilerArtifactTransformPreactivationRecord(token);
  // Adoption transfers the prepared value, not the token record. Delete both claimed and
  // unclaimed records once the owning deployment has drained so neither path relies on GC.
  compilerArtifactTransformPreactivationRecords.delete(token);
}

function claimCompilerArtifactTransformPreactivation(token, payloadSha256) {
  const record = requireCompilerArtifactTransformPreactivationRecord(token);
  if (record.claimed) {
    fail("compiler artifact transform preactivation was already claimed");
  }
  if (record.payloadSha256 !== payloadSha256) {
    fail("compiler artifact transform preactivation payload changed before adoption");
  }
  record.claimed = true;
  return record.prepared;
}

function staticHermesFallbackDiagnostics(sourceRejection) {
  assertObject(sourceRejection, "Static Hermes source rejection");
  return requireArray(
    sourceRejection.diagnostics,
    "Static Hermes source rejection diagnostics"
  ).map((diagnostic) => {
    assertObject(diagnostic, "Static Hermes source rejection diagnostic");
    assertObject(diagnostic.originalUnit, "Static Hermes source rejection original unit");
    const original = diagnostic.originalUnit;
    const message =
      diagnostic.category === "flow-type-spread-argument-not-exact-object"
        ? "Static Hermes flow checking requires an exact object type for this spread argument"
        : diagnostic.category === "flow-type-constructor-arity-mismatch"
          ? "Static Hermes does not support this constructor argument count"
          : diagnostic.category === "flow-type-generic-method-inference"
            ? "Static Hermes could not infer this generic method invocation"
            : diagnostic.category === "flow-type-spread-argument-not-array"
              ? "Static Hermes requires an array value for this spread argument"
              : "Static Hermes flow checking rejected an incompatible binary operation";
    return {
      code: "staticHermesSourceIncompatibility",
      dependencyChain: requireArray(
        original.dependencyChain,
        "Static Hermes source rejection dependency chain"
      ).map((entry) => requireString(entry, "Static Hermes dependency chain entry")),
      message,
      modulePath: requireString(original.module, "Static Hermes source rejection module"),
      sourceSpan: {
        endColumn: requirePositiveInteger(
          original.column,
          "Static Hermes source rejection original column"
        ),
        endLine: requirePositiveInteger(
          original.line,
          "Static Hermes source rejection original line"
        ),
        startColumn: original.column,
        startLine: original.line,
      },
      subject: requireString(original.id, "Static Hermes source rejection original unit ID"),
    };
  });
}

function adaptArtifactPipelineResult(prepared, artifactResult) {
  if (artifactResult.kind !== "v8Fallback") {
    return {
      artifact: artifactResult,
      kind: prepared.kind,
      lowering: prepared.lowering,
    };
  }
  const options = prepared.artifactOptions;
  return {
    buildReport: artifactResult.buildReport,
    executionManifest: createV8FallbackManifest({
      compiler: options.compiler,
      diagnostics: staticHermesFallbackDiagnostics(artifactResult.sourceRejection),
      effectExecutionMode: options.effectExecutionMode,
      limits: options.limits.execution,
      opaqueValueAbiVersion: options.opaqueValueAbiVersion,
      platformLimits: options.platformLimits,
      source: options.source,
      staticHermesRevision: options.toolchain.staticHermes.revision,
      valueMode: options.valueMode,
    }),
    kind: "v8Fallback",
    lowering: prepared.lowering,
    sourceRejection: artifactResult.sourceRejection,
  };
}

export async function compileCompilerArtifact(input) {
  const prepared = prepareCompilerArtifact(input);
  if (prepared.kind === "v8Fallback") {
    return prepared;
  }
  await verifyOpaqueAbiHeader(input.artifactConfig);
  await verifyGuestPromiseRuntimeHeaders(
    input.artifactConfig,
    prepared.artifactOptions.effectExecutionMode
  );
  return adaptArtifactPipelineResult(
    prepared,
    await compileConvexWasmArtifact(prepared.artifactOptions)
  );
}

function artifactCompilationSessionIdentity(artifactOptions) {
  return fingerprintJson({
    compiler: artifactOptions.compiler,
    effectExecutionMode: artifactOptions.effectExecutionMode,
    opaqueValueAbiVersion: artifactOptions.opaqueValueAbiVersion,
  });
}

export function createCompilerArtifactMaterialSessionInput(artifactOptions) {
  const {
    effectExecutionMode,
    generatedJavaScript,
    generatedJavaScriptPath,
    guestSourceProvenance,
    importedOperations,
    platformLimits,
    routingDecision,
    source,
    valueMode,
  } = artifactOptions;
  return {
    effectExecutionMode,
    generatedJavaScript,
    generatedJavaScriptPath,
    guestSourceProvenance,
    importedOperations,
    platformLimits,
    routingDecision,
    source,
    valueMode,
  };
}

function nativePhaseSchedulingFromArtifactCompilation(artifactCompilation) {
  const launchPolicy = artifactCompilation?.launchPolicy;
  return launchPolicy === undefined
    ? undefined
    : {
        launchPolicy,
        ...(artifactCompilation.nativePhaseScheduler === undefined
          ? {}
          : { nativePhaseScheduler: artifactCompilation.nativePhaseScheduler }),
      };
}

export async function createCompilerArtifactCompilationSession(initialInput, artifactCompilation) {
  const initialPrepared = prepareCompilerArtifact(initialInput);
  if (initialPrepared.kind !== "wasm") {
    fail("artifact compilation session requires an eligible initial compiler output");
  }
  await verifyOpaqueAbiHeader(initialInput.artifactConfig);
  await verifyGuestPromiseRuntimeHeaders(
    initialInput.artifactConfig,
    initialPrepared.artifactOptions.effectExecutionMode
  );
  const materialSession = await createConvexWasmArtifactMaterialSession(
    initialPrepared.artifactOptions,
    nativePhaseSchedulingFromArtifactCompilation(artifactCompilation)
  );
  const sharedIdentity = artifactCompilationSessionIdentity(initialPrepared.artifactOptions);
  let initialAvailable = true;
  let finalized = false;
  return {
    async compile(input) {
      if (finalized) {
        fail("artifact compilation session was already finalized");
      }
      const prepared =
        initialAvailable && input === initialInput
          ? initialPrepared
          : prepareCompilerArtifact({
              artifactConfig: initialInput.artifactConfig,
              compilerOutput: input.compilerOutput,
              runtimeModulePath: input.runtimeModulePath,
            });
      initialAvailable = false;
      if (prepared.kind !== "wasm") {
        fail("artifact compilation session received an ineligible compiler output");
      }
      if (artifactCompilationSessionIdentity(prepared.artifactOptions) !== sharedIdentity) {
        fail("artifact compilation session received different shared build inputs");
      }
      return adaptArtifactPipelineResult(
        prepared,
        await compileConvexWasmArtifactInMaterialSession(
          materialSession,
          createCompilerArtifactMaterialSessionInput(prepared.artifactOptions)
        )
      );
    },
    async finalize() {
      if (finalized) {
        fail("artifact compilation session was already finalized");
      }
      finalized = true;
      return finalizeConvexWasmArtifactMaterialSession(materialSession);
    },
    kind: "convex-wasm-compiler-artifact-compilation-session-v1",
  };
}

export async function createCompilerCohortArtifactCompilationSession(
  initialInput,
  artifactCompilation
) {
  const transformPreactivations = artifactCompilation?.compilerArtifactTransformPreactivations;
  if (
    transformPreactivations !== undefined &&
    (!Array.isArray(transformPreactivations) ||
      transformPreactivations.some(
        (preactivation) =>
          typeof preactivation !== "object" ||
          preactivation === null ||
          !SHA256_PATTERN.test(preactivation.payloadSha256)
      ))
  ) {
    fail("compiler artifact transform preactivations are invalid");
  }
  const initialPrepared =
    transformPreactivations?.[0] === undefined
      ? prepareCompilerArtifact(initialInput)
      : claimCompilerArtifactTransformPreactivation(
          transformPreactivations[0].token,
          transformPreactivations[0].payloadSha256
        );
  if (initialPrepared.kind !== "wasm") {
    fail("cohort artifact compilation session requires an eligible initial compiler output");
  }
  await verifyOpaqueAbiHeader(initialInput.artifactConfig);
  await verifyGuestPromiseRuntimeHeaders(
    initialInput.artifactConfig,
    initialPrepared.artifactOptions.effectExecutionMode
  );
  const materialSession = await createConvexWasmArtifactMaterialSession(
    initialPrepared.artifactOptions,
    nativePhaseSchedulingFromArtifactCompilation(artifactCompilation)
  );
  const sharedIdentity = artifactCompilationSessionIdentity(initialPrepared.artifactOptions);
  let finalized = false;
  return {
    async compileAll(inputs) {
      if (finalized) {
        fail("cohort artifact compilation session was already finalized");
      }
      if (!Array.isArray(inputs) || inputs.length === 0 || inputs[0] !== initialInput) {
        fail("cohort artifact compilation session requires its initial input first");
      }
      if (
        transformPreactivations !== undefined &&
        transformPreactivations.length !== inputs.length
      ) {
        fail("compiler artifact transform preactivations do not cover the cohort inputs");
      }
      const preparedInputs = inputs.map((input, index) =>
        index === 0
          ? initialPrepared
          : transformPreactivations?.[index] === undefined
            ? prepareCompilerArtifact({
                artifactConfig: initialInput.artifactConfig,
                compilerOutput: input.compilerOutput,
                runtimeModulePath: input.runtimeModulePath,
              })
            : claimCompilerArtifactTransformPreactivation(
                transformPreactivations[index].token,
                transformPreactivations[index].payloadSha256
              )
      );
      for (const prepared of preparedInputs) {
        if (prepared.kind !== "wasm") {
          fail("cohort artifact compilation session received an ineligible compiler output");
        }
        if (artifactCompilationSessionIdentity(prepared.artifactOptions) !== sharedIdentity) {
          fail("cohort artifact compilation session received different shared build inputs");
        }
      }
      const cohortResult = await compileConvexWasmCohortsInMaterialSession(
        materialSession,
        preparedInputs.map(({ artifactOptions }) =>
          createCompilerArtifactMaterialSessionInput(artifactOptions)
        )
      );
      return {
        cohorts: cohortResult.cohorts,
        results: preparedInputs.map((prepared, index) =>
          adaptArtifactPipelineResult(prepared, cohortResult.artifacts[index])
        ),
      };
    },
    async finalize() {
      if (finalized) {
        fail("cohort artifact compilation session was already finalized");
      }
      finalized = true;
      return finalizeConvexWasmArtifactMaterialSession(materialSession);
    },
    kind: "convex-wasm-compiler-cohort-artifact-compilation-session-v1",
  };
}
