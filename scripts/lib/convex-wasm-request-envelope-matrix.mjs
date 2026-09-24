import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CommitTsPlaceholder, jsonToConvex } from "convex/values";

import {
  convexWasmCapabilityRequestAbiVersion,
  renderNativeCapabilityRequestEnvelopePrelude,
} from "./convex-wasm-lowering.mjs";

export const convexWasmRequestEnvelopeMatrixKind =
  "convex-wasm-capability-request-envelope-matrix-v4";

export { convexWasmCapabilityRequestAbiVersion };
export const convexWasmRequestEnvelopeMatrixTarget = "static-hermes-wasmtime-optimized";
export const convexWasmRequestEnvelopeMatrixRunnerExport =
  "convex_wasm_request_envelope_matrix_run";
export const convexWasmRequestEnvelopeMatrixRuntimeInitialization = "_sh_init";
export const convexWasmRequestEnvelopeMatrixRuntimeProgram = "convex-wasm-request-envelope-matrix";
export const convexWasmRequestEnvelopeMatrixRuntimeArguments = Object.freeze([
  "--gc-init-heap=4MiB",
  "--gc-max-heap=32MiB",
  "--gc-alloc-young=true",
  "--gc-revert-to-yg-at-tti=false",
  "--max-register-stack=16384",
]);

const canonicalVectorCorpusKind =
  "convex-wasm-canonical-capability-request-envelope-vector-corpus-v4";
const canonicalProducerKind = "convex-sdk-backend-capability-request-envelope-producer-v4";
const legacyWholeRequestControl = Object.freeze({
  expectedMessage: "Error: Convex object field name uses a reserved prefix",
  kind: "convex-wasm-legacy-whole-request-committed-value-control-v1",
  reasonCode: "reserved-object-field-prefix",
  schemaVersion: 1,
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export const convexWasmRequestEnvelopeLegacyWholeRequestControlSha256 = sha256(
  JSON.stringify(legacyWholeRequestControl)
);

function canonicalizeJson(value) {
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalizeJson(value[key])])
  );
}

const convexPackageRoot = dirname(fileURLToPath(import.meta.resolve("convex/package.json")));
const canonicalProducerSources = Object.freeze({
  "database-impl.ts": readFileSync(join(convexPackageRoot, "src/server/impl/database_impl.ts")),
  "filter-builder-impl.ts": readFileSync(
    join(convexPackageRoot, "src/server/impl/filter_builder_impl.ts")
  ),
  "query-impl.ts": readFileSync(join(convexPackageRoot, "src/server/impl/query_impl.ts")),
  "search-filter-builder-impl.ts": readFileSync(
    join(convexPackageRoot, "src/server/impl/search_filter_builder_impl.ts")
  ),
  "scheduler-impl.ts": readFileSync(join(convexPackageRoot, "src/server/impl/scheduler_impl.ts")),
  "storage-impl.ts": readFileSync(join(convexPackageRoot, "src/server/impl/storage_impl.ts")),
  "value.ts": readFileSync(join(convexPackageRoot, "src/values/value.ts")),
  "vectors.json": readFileSync(
    fileURLToPath(
      new URL(
        "../test-fixtures/convex-wasm-request-envelope/canonical-vectors.json",
        import.meta.url
      )
    )
  ),
});
const canonicalProducerSourceSha256 = sha256(
  JSON.stringify(
    Object.fromEntries(
      Object.entries(canonicalProducerSources).map(([name, source]) => [name, sha256(source)])
    )
  )
);

function canonicalVectorCorpus(canonicalVectorsJson) {
  const payload = {
    canonicalVectorsJson,
    corpusSchema: convexWasmRequestEnvelopeMatrixKind,
    schemaVersion: 1,
  };
  return Object.freeze({
    kind: canonicalVectorCorpusKind,
    producer: {
      kind: canonicalProducerKind,
      sourceSha256: canonicalProducerSourceSha256,
    },
    schemaVersion: 1,
    sha256: sha256(JSON.stringify(payload)),
  });
}

function canonicalRequests() {
  const vectors = canonicalizeJson(
    JSON.parse(canonicalProducerSources["vectors.json"].toString("utf8"))
  );
  if (
    vectors.kind !== "convex-wasm-canonical-capability-request-envelope-vectors-v4" ||
    vectors.schemaVersion !== 1 ||
    !Array.isArray(vectors.requests) ||
    !Array.isArray(vectors.pendingValueNegativeControls) ||
    !Array.isArray(vectors.requestNegativeControls) ||
    !Array.isArray(vectors.reservedSyntaxNegativeControls)
  ) {
    throw new Error("canonical request-envelope vectors are invalid");
  }
  const byName = new Map(vectors.requests.map((record) => [record.name, record.envelope]));
  const patch = byName.get("db-patch-top-level-deletion");
  const query = byName.get("db-query-filter-expression");
  const search = byName.get("db-query-search");
  const pagination = byName.get("db-query-paginate");
  const storageDelete = byName.get("storage-delete");
  const storageGenerateUploadUrl = byName.get("storage-generate-upload-url");
  const storageGetMetadata = byName.get("storage-get-metadata");
  const storageGetUrl = byName.get("storage-get-url");
  if (
    patch === undefined ||
    query === undefined ||
    search === undefined ||
    pagination === undefined ||
    storageDelete === undefined ||
    storageGenerateUploadUrl === undefined ||
    storageGetMetadata === undefined ||
    storageGetUrl === undefined ||
    byName.size !== 24 ||
    vectors.pendingValueNegativeControls.length !== 10 ||
    vectors.requestNegativeControls.length !== 5
  ) {
    throw new Error("canonical request-envelope vectors omit implemented request variants");
  }
  return { patch, query, vectors };
}

function canonicalExpressionInput(expression) {
  const keys = Object.keys(expression);
  if (keys.length !== 1) throw new Error("canonical query expression is invalid");
  const key = keys[0];
  if (key === "$field") return { $field: expression.$field };
  if (key === "$literal") return { $literal: jsonToConvex(expression.$literal) };
  const operand = expression[key];
  return {
    [key]: Array.isArray(operand)
      ? operand.map(canonicalExpressionInput)
      : canonicalExpressionInput(operand),
  };
}

function isUndefinedTag(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    value.$undefined === null
  );
}

function isCommitTsTag(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    value.$commitTs === null
  );
}

function canonicalRuntimeRequest(envelope) {
  const request = { ...envelope };
  if (request.kind === "dbGet" || request.kind === "dbSystemGet" || request.kind === "dbDelete") {
    request.id = jsonToConvex(request.id);
  } else if (
    request.kind === "storageGetUrl" ||
    request.kind === "storageGetMetadata" ||
    request.kind === "storageDelete"
  ) {
    if (isCommitTsTag(request.storageId)) request.storageId = jsonToConvex(request.storageId);
  } else if (request.kind === "dbInsert" || request.kind === "dbReplace") {
    if (request.kind === "dbReplace") request.id = jsonToConvex(request.id);
    request.value = jsonToConvex(request.value);
  } else if (request.kind === "dbPatch") {
    request.id = jsonToConvex(request.id);
    request.patch = Object.fromEntries(
      Object.entries(request.patch).map(([field, value]) => [
        field,
        isUndefinedTag(value) ? undefined : jsonToConvex(value),
      ])
    );
  } else if (request.kind === "dbQuery") {
    request.operators = request.operators.map((operator) =>
      operator.type === "filter"
        ? { expression: canonicalExpressionInput(operator.expression), type: "filter" }
        : { limit: operator.limit, type: "limit" }
    );
    if (request.source.type === "indexRange") {
      request.source = {
        constraints: request.source.constraints.map((constraint) => ({
          field: constraint.field,
          operator: constraint.operator,
          value: jsonToConvex(constraint.value),
        })),
        index: request.source.index,
        type: "indexRange",
      };
    } else if (request.source.type === "search") {
      request.source = {
        filters: request.source.filters.map((filter) => ({
          field: filter.field,
          type: filter.type,
          value:
            filter.type === "search"
              ? filter.value
              : isUndefinedTag(filter.value)
                ? undefined
                : jsonToConvex(filter.value),
        })),
        index: request.source.index,
        type: "search",
      };
    } else {
      request.source = { type: "fullTableScan" };
    }
  } else if (request.kind === "runUdf") {
    request.args = jsonToConvex(request.args);
  } else if (request.kind === "schedulerRunAfter" || request.kind === "schedulerRunAt") {
    request.args = jsonToConvex(request.args);
  } else if (request.kind === "schedulerCancel") {
    request.id = jsonToConvex(request.id);
  }
  return request;
}

function renderJavascriptValue(value) {
  if (value instanceof CommitTsPlaceholder) return "__convexCommitTsPlaceholder";
  if (typeof value === "bigint") return `BigInt(${JSON.stringify(String(value))})`;
  if (value === undefined) return "undefined";
  if (Array.isArray(value)) return `[${value.map(renderJavascriptValue).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .map(([key, fieldValue]) => `${JSON.stringify(key)}:${renderJavascriptValue(fieldValue)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function renderInputArray(name, value) {
  const bytes = Buffer.from(value, "utf8");
  const rows = [];
  for (let index = 0; index < bytes.length; index += 16) {
    rows.push(Array.from(bytes.subarray(index, index + 16)).join(", "));
  }
  return `static const unsigned char ${name}[] = {
${rows.map((row) => `  ${row},`).join("\n")}
};
static const unsigned long long ${name}_len = ${String(bytes.length)}ULL;
`;
}

export function renderConvexWasmRequestEnvelopeInputHeader(canonicalVectorsJson) {
  const vectors = JSON.parse(canonicalVectorsJson);
  if (!Array.isArray(vectors.requests) || vectors.requests.length !== 24) {
    throw new Error("canonical request-envelope input header requires 24 requests");
  }
  const arrays = vectors.requests.map(({ envelope }, index) =>
    renderInputArray(
      `convex_wasm_request_envelope_matrix_request_${String(index)}`,
      JSON.stringify(envelope)
    )
  );
  const entries = vectors.requests.map(
    (_record, index) =>
      `  {convex_wasm_request_envelope_matrix_request_${String(index)}, convex_wasm_request_envelope_matrix_request_${String(index)}_len},`
  );
  return `#ifndef CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_INPUT_H
#define CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_INPUT_H

${arrays.join("\n")}
struct ConvexWasmRequestEnvelopeMatrixInput {
  const unsigned char *data;
  unsigned long long length;
};
static const ConvexWasmRequestEnvelopeMatrixInput convex_wasm_request_envelope_matrix_requests[] = {
${entries.join("\n")}
};
static const unsigned long long convex_wasm_request_envelope_matrix_request_count = ${String(vectors.requests.length)}ULL;

#endif
`;
}

export function renderConvexWasmRequestEnvelopeRuntimeContractHeader() {
  const argumentsWithProgram = [
    convexWasmRequestEnvelopeMatrixRuntimeProgram,
    ...convexWasmRequestEnvelopeMatrixRuntimeArguments,
  ];
  const declarations = argumentsWithProgram.map(
    (argument, index) =>
      `static char convex_wasm_request_envelope_matrix_runtime_argument_${String(index)}[] = ${JSON.stringify(argument)};`
  );
  const entries = argumentsWithProgram.map(
    (_argument, index) => `  convex_wasm_request_envelope_matrix_runtime_argument_${String(index)},`
  );
  return `#ifndef CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_RUNTIME_CONTRACT_H
#define CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_RUNTIME_CONTRACT_H

${declarations.join("\n")}
static char *convex_wasm_request_envelope_matrix_runtime_arguments[] = {
${entries.join("\n")}
};
static const int convex_wasm_request_envelope_matrix_runtime_argument_count = ${String(argumentsWithProgram.length)};

#endif
`;
}

function replaceExactly(source, before, after, description) {
  const first = source.indexOf(before);
  if (first === -1 || first !== source.lastIndexOf(before)) {
    throw new Error(`guest-native lowering omitted the ${description} arm`);
  }
  return source.replace(before, after);
}

function renderMatrixProgram({
  canonicalNegativeControlContextsJavascript,
  canonicalNegativeControlValuesJavascript,
  canonicalPendingNegativeControlInputsJavascript,
  canonicalPendingNegativeControlNamesJavascript,
  canonicalRequestNegativeControlExpectedMessagesJavascript,
  canonicalRequestNegativeControlInputsJavascript,
  canonicalRequestNegativeControlNamesJavascript,
  canonicalRequestExpectedJavascript,
  canonicalRequestInputsJavascript,
  canonicalRequestNamesJavascript,
  executionIdentity,
  legacyWholeRequestRejector,
  prelude,
}) {
  const matrixProgram = `function __convexRequestEnvelopeMatrixRequire(condition: any, message: string): void {
  if (!condition) throw new Error("Request-envelope matrix failed: " + message);
}

function __convexRequestEnvelopeMatrixCaughtMessage(callback: any): string {
  try {
    callback();
    return "";
  } catch (error) {
    return String(error);
  }
}

function __convexRequestEnvelopeMatrixNegativeControl(context: string, value: any): string {
  if (context === "ordinary-argument" || context === "ordinary-document") {
    return __convexRequestEnvelopeMatrixCaughtMessage(function() {
      __convexGuestEncodeTagged(value, []);
    });
  }
  if (context === "patch-nested-value") {
    return __convexRequestEnvelopeMatrixCaughtMessage(function() {
      __convexCapabilityEncodeRequest({
        id: "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y",
        kind: "dbPatch",
        patch: {nested: value},
        table: "documents",
        version: ${convexWasmCapabilityRequestAbiVersion},
      });
    });
  }
  if (context === "unrelated-request-field") {
    return __convexRequestEnvelopeMatrixCaughtMessage(function() {
      __convexCapabilityEncodeRequest({
        kind: "dbInsert",
        table: "documents",
        value: {unrelated: value},
        version: ${convexWasmCapabilityRequestAbiVersion},
      });
    });
  }
  throw new Error("Canonical negative-control context is unsupported");
}

function __convexRequestEnvelopeMatrixRun(): any {
  const executionIdentity = ${JSON.stringify(executionIdentity)};
  const canonicalRequestNames: string[] = ${canonicalRequestNamesJavascript};
  const canonicalRequestInputs: any[] = ${canonicalRequestInputsJavascript};
  const canonicalRequestExpected: any[] = ${canonicalRequestExpectedJavascript};
  __convexRequestEnvelopeMatrixRequire(
    canonicalRequestInputs.length === canonicalRequestNames.length &&
      canonicalRequestExpected.length === canonicalRequestNames.length,
    "canonical request columns have different lengths"
  );
  if (${legacyWholeRequestRejector ? "true" : "false"}) {
    __convexRequestEnvelopeMatrixFailureStage = "legacy-whole-request-control";
    let queryRequest: any;
    for (let index = 0; index < canonicalRequestNames.length; index += 1) {
      if (canonicalRequestNames[index] === "db-query-filter-expression") {
        queryRequest = canonicalRequestInputs[index];
      }
    }
    __convexRequestEnvelopeMatrixRequire(queryRequest !== undefined, "legacy query input is missing");
    const message = __convexRequestEnvelopeMatrixCaughtMessage(function() {
      __convexCapabilityRequestToHost(queryRequest);
    });
    __convexRequestEnvelopeMatrixRequire(
      message === ${JSON.stringify(legacyWholeRequestControl.expectedMessage)},
      "legacy whole-request rejection reason drifted"
    );
    return {
      executionIdentity,
      legacyWholeRequestRejection: {
        messageSha256: ${JSON.stringify(sha256(legacyWholeRequestControl.expectedMessage))},
        reasonCode: ${JSON.stringify(legacyWholeRequestControl.reasonCode)},
      },
      ok: true,
      scope: "request-envelope-legacy-control",
    };
  }

  __convexRequestEnvelopeMatrixFailureStage = "canonical-request-variants";
  for (let requestIndex = 0; requestIndex < canonicalRequestNames.length; requestIndex += 1) {
    const name = canonicalRequestNames[requestIndex];
    const input = canonicalRequestInputs[requestIndex];
    const encoded = __convexCapabilityEncodeRequest(input);
    __convexRequestEnvelopeMatrixRequire(
      JSON.stringify(encoded) === JSON.stringify(canonicalRequestExpected[requestIndex]),
      "canonical request variant drifted: " + name
    );
    const requestHandle = __convexCapabilityRequestToHost(input);
    __convexRequestEnvelopeMatrixRequire(
      requestHandle === requestIndex + 1,
      "canonical request handle drifted: " + name
    );
    __convexCapabilityRequestRelease(requestHandle);
  }

  __convexRequestEnvelopeMatrixFailureStage = "pending-value-negative-controls";
  const pendingNegativeControlNames: string[] = ${canonicalPendingNegativeControlNamesJavascript};
  const pendingNegativeControlInputs: any[] = ${canonicalPendingNegativeControlInputsJavascript};
  __convexRequestEnvelopeMatrixRequire(
    pendingNegativeControlInputs.length === pendingNegativeControlNames.length,
    "pending-value negative-control columns have different lengths"
  );
  for (let controlIndex = 0; controlIndex < pendingNegativeControlNames.length; controlIndex += 1) {
    const name = pendingNegativeControlNames[controlIndex];
    const message = __convexRequestEnvelopeMatrixCaughtMessage(function() {
      __convexCapabilityEncodeRequest(pendingNegativeControlInputs[controlIndex]);
    });
    __convexRequestEnvelopeMatrixRequire(
      message === "Error: Pending commit timestamp is not allowed in this capability request position",
      "pending-value negative control drifted: " + name
    );
  }

  __convexRequestEnvelopeMatrixFailureStage = "request-negative-controls";
  const requestNegativeControlNames: string[] = ${canonicalRequestNegativeControlNamesJavascript};
  const requestNegativeControlInputs: any[] = ${canonicalRequestNegativeControlInputsJavascript};
  const requestNegativeControlExpectedMessages: string[] = ${canonicalRequestNegativeControlExpectedMessagesJavascript};
  __convexRequestEnvelopeMatrixRequire(
    requestNegativeControlInputs.length === requestNegativeControlNames.length &&
      requestNegativeControlExpectedMessages.length === requestNegativeControlNames.length,
    "request negative-control columns have different lengths"
  );
  for (let controlIndex = 0; controlIndex < requestNegativeControlNames.length; controlIndex += 1) {
    const name = requestNegativeControlNames[controlIndex];
    const message = __convexRequestEnvelopeMatrixCaughtMessage(function() {
      __convexCapabilityEncodeRequest(requestNegativeControlInputs[controlIndex]);
    });
    __convexRequestEnvelopeMatrixRequire(
      message === requestNegativeControlExpectedMessages[controlIndex],
      "request negative control drifted: " + name
    );
  }

  __convexRequestEnvelopeMatrixFailureStage = "committed-value-negative-controls";
  const negativeControlContexts: string[] = ${canonicalNegativeControlContextsJavascript};
  const negativeControlValues: any[] = ${canonicalNegativeControlValuesJavascript};
  __convexRequestEnvelopeMatrixRequire(
    negativeControlValues.length === negativeControlContexts.length,
    "canonical negative-control columns have different lengths"
  );
  for (let controlIndex = 0; controlIndex < negativeControlContexts.length; controlIndex += 1) {
    const context = negativeControlContexts[controlIndex];
    const message = __convexRequestEnvelopeMatrixNegativeControl(
      context,
      negativeControlValues[controlIndex]
    );
    const expectedMessage = "Error: Convex object field name uses a reserved prefix";
    __convexRequestEnvelopeMatrixRequire(
      message === expectedMessage,
      "canonical negative control drifted: " + context
    );
  }
  return {
    canonicalRequestCount: canonicalRequestNames.length,
    executionIdentity,
    guestRequestEncode: true,
    guestRequestHandleBoundary: true,
    ok: true,
    pendingValueNegativeControlCount: pendingNegativeControlNames.length,
    productionHostDecoderExercised: false,
    requestHandleRelease: true,
    requestNegativeControlCount: requestNegativeControlNames.length,
    reservedSyntaxNegativeControlCount: negativeControlContexts.length,
    scope: "request-envelope",
  };
}

let __convexRequestEnvelopeMatrixFailureStage = "initialization";
let __convexRequestEnvelopeMatrixReport: any;
try {
  __convexRequestEnvelopeMatrixReport = __convexRequestEnvelopeMatrixRun();
} catch (__convexRequestEnvelopeMatrixError) {
  __convexRequestEnvelopeMatrixReport = {
    error: String(__convexRequestEnvelopeMatrixError),
    failureStage: __convexRequestEnvelopeMatrixFailureStage,
    ok: false,
  };
}
Object.defineProperty(globalThis, "__convexWasmRequestEnvelopeMatrixReport", {
  configurable: true,
  enumerable: false,
  value: __convexRequestEnvelopeMatrixReport,
  writable: false,
});
`;
  return `{\n${prelude}\n${matrixProgram}}\n`;
}

function renderMatrix(legacyWholeRequestRejector) {
  const { patch, query, vectors } = canonicalRequests();
  const canonicalPatchJson = JSON.stringify(patch);
  const canonicalQueryJson = JSON.stringify(query);
  const canonicalVectorsJson = JSON.stringify(vectors);
  const canonicalNegativeControlsJson = JSON.stringify(vectors.reservedSyntaxNegativeControls);
  const canonicalPendingNegativeControlsJson = JSON.stringify(vectors.pendingValueNegativeControls);
  const canonicalRequestNegativeControlsJson = JSON.stringify(vectors.requestNegativeControls);
  const canonicalRequestRecords = vectors.requests.map((record) => ({
    expected: record.envelope,
    input: canonicalRuntimeRequest(record.envelope),
    name: record.name,
  }));
  const canonicalPendingNegativeControlRecords = vectors.pendingValueNegativeControls.map(
    (record) => ({
      input: canonicalRuntimeRequest(record.envelope),
      name: record.name,
    })
  );
  const canonicalRequestNegativeControlRecords = vectors.requestNegativeControls.map((record) => ({
    expectedMessage: record.expectedMessage,
    input: canonicalRuntimeRequest(record.envelope),
    name: record.name,
  }));
  const productionPrelude = renderNativeCapabilityRequestEnvelopePrelude();
  const prelude = legacyWholeRequestRejector
    ? replaceExactly(
        productionPrelude,
        "const source = JSON.stringify(__convexCapabilityEncodeRequest(request));",
        "const source = JSON.stringify(__convexGuestEncodeTagged(request, []));",
        "former whole-request committed-value serialization"
      )
    : productionPrelude;
  const corpus = canonicalVectorCorpus(canonicalVectorsJson);
  const executionIdentity = Object.freeze({
    canonicalNegativeControlsSha256: sha256(canonicalNegativeControlsJson),
    canonicalPendingNegativeControlsSha256: sha256(canonicalPendingNegativeControlsJson),
    canonicalRequestNegativeControlsSha256: sha256(canonicalRequestNegativeControlsJson),
    canonicalRequestCount: vectors.requests.length,
    canonicalVectorCorpusSha256: corpus.sha256,
    canonicalVectorsSha256: sha256(canonicalVectorsJson),
    executedRequestEnvelopePreludeSha256: sha256(prelude),
    legacyWholeRequestControlSha256: convexWasmRequestEnvelopeLegacyWholeRequestControlSha256,
    mode: legacyWholeRequestRejector ? "legacy-whole-request-control" : "current",
    pendingValueNegativeControlCount: vectors.pendingValueNegativeControls.length,
    productionRequestEnvelopePreludeSha256: sha256(productionPrelude),
    requestNegativeControlCount: vectors.requestNegativeControls.length,
    reservedSyntaxNegativeControlCount: vectors.reservedSyntaxNegativeControls.length,
    schemaVersion: 1,
  });
  const source = renderMatrixProgram({
    canonicalNegativeControlContextsJavascript: renderJavascriptValue(
      vectors.reservedSyntaxNegativeControls.map(({ context }) => context)
    ),
    canonicalNegativeControlValuesJavascript: renderJavascriptValue(
      vectors.reservedSyntaxNegativeControls.map(({ value }) => value)
    ),
    canonicalPendingNegativeControlInputsJavascript: renderJavascriptValue(
      canonicalPendingNegativeControlRecords.map(({ input }) => input)
    ),
    canonicalPendingNegativeControlNamesJavascript: renderJavascriptValue(
      canonicalPendingNegativeControlRecords.map(({ name }) => name)
    ),
    canonicalRequestNegativeControlExpectedMessagesJavascript: renderJavascriptValue(
      canonicalRequestNegativeControlRecords.map(({ expectedMessage }) => expectedMessage)
    ),
    canonicalRequestNegativeControlInputsJavascript: renderJavascriptValue(
      canonicalRequestNegativeControlRecords.map(({ input }) => input)
    ),
    canonicalRequestNegativeControlNamesJavascript: renderJavascriptValue(
      canonicalRequestNegativeControlRecords.map(({ name }) => name)
    ),
    canonicalRequestExpectedJavascript: renderJavascriptValue(
      canonicalRequestRecords.map(({ expected }) => expected)
    ),
    canonicalRequestInputsJavascript: renderJavascriptValue(
      canonicalRequestRecords.map(({ input }) => input)
    ),
    canonicalRequestNamesJavascript: renderJavascriptValue(
      canonicalRequestRecords.map(({ name }) => name)
    ),
    executionIdentity,
    legacyWholeRequestRejector,
    prelude,
  });
  return Object.freeze({
    canonicalNegativeControlsJson,
    canonicalPendingNegativeControlsJson,
    canonicalRequestNegativeControlsJson,
    canonicalPatchJson,
    canonicalQueryJson,
    canonicalVectorCorpus: corpus,
    canonicalVectorsJson,
    executionIdentity,
    legacyWholeRequestRejector,
    requestEnvelopePreludeSha256: sha256(productionPrelude),
    source,
    sourceSha256: sha256(source),
  });
}

export function renderConvexWasmRequestEnvelopeMatrix() {
  return renderMatrix(false);
}

export function renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector() {
  return renderMatrix(true);
}

export function assertConvexWasmRequestEnvelopeMatrixReport(report) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("request-envelope matrix report must be an object");
  }
  if (report.ok !== true) {
    throw new Error(`request-envelope matrix rejected: ${JSON.stringify(report.error)}`);
  }
  const expected = {
    canonicalRequestCount: 24,
    executionIdentity: renderConvexWasmRequestEnvelopeMatrix().executionIdentity,
    guestRequestEncode: true,
    guestRequestHandleBoundary: true,
    ok: true,
    pendingValueNegativeControlCount: 10,
    productionHostDecoderExercised: false,
    requestHandleRelease: true,
    requestNegativeControlCount: 5,
    reservedSyntaxNegativeControlCount: 6,
    scope: "request-envelope",
  };
  const keys = Object.keys(report).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    JSON.stringify(report) !== JSON.stringify(expected)
  ) {
    throw new Error("request-envelope matrix report does not match the required result");
  }
}

export function assertConvexWasmRequestEnvelopeLegacyWholeRequestReport(report) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("legacy request-envelope control report must be an object");
  }
  if (report.ok !== true) {
    throw new Error(`legacy request-envelope control rejected: ${JSON.stringify(report.error)}`);
  }
  const expected = {
    executionIdentity:
      renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector().executionIdentity,
    legacyWholeRequestRejection: {
      messageSha256: sha256(legacyWholeRequestControl.expectedMessage),
      reasonCode: legacyWholeRequestControl.reasonCode,
    },
    ok: true,
    scope: "request-envelope-legacy-control",
  };
  if (JSON.stringify(report) !== JSON.stringify(expected)) {
    throw new Error("legacy request-envelope control report does not match the required result");
  }
}
