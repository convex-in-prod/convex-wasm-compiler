import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  renderNativeCapabilityRequestEnvelopePrelude,
  renderNativeDbGetCapabilityTarget,
} from "./convex-wasm-lowering.mjs";
import {
  assertConvexWasmRequestEnvelopeLegacyWholeRequestReport,
  assertConvexWasmRequestEnvelopeMatrixReport,
  convexWasmCapabilityRequestAbiVersion,
  convexWasmRequestEnvelopeMatrixKind,
  convexWasmRequestEnvelopeMatrixRuntimeArguments,
  convexWasmRequestEnvelopeMatrixRuntimeProgram,
  renderConvexWasmRequestEnvelopeInputHeader,
  renderConvexWasmRequestEnvelopeMatrix,
  renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector,
  renderConvexWasmRequestEnvelopeRuntimeContractHeader,
} from "./convex-wasm-request-envelope-matrix.mjs";
import { parseArguments } from "../run-convex-wasm-request-envelope-matrix.mjs";

const currentMatrix = renderConvexWasmRequestEnvelopeMatrix();
const legacyMatrix = renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector();
const expectedReport = Object.freeze({
  canonicalRequestCount: 24,
  executionIdentity: currentMatrix.executionIdentity,
  guestRequestEncode: true,
  guestRequestHandleBoundary: true,
  ok: true,
  pendingValueNegativeControlCount: 10,
  productionHostDecoderExercised: false,
  requestHandleRelease: true,
  requestNegativeControlCount: 5,
  reservedSyntaxNegativeControlCount: 6,
  scope: "request-envelope",
});
const expectedLegacyReport = Object.freeze({
  executionIdentity: legacyMatrix.executionIdentity,
  legacyWholeRequestRejection: {
    messageSha256: "b3cadb15120317bcf1c0a6e82ce2517d370a761cf18961e399bb7a0d354c599a",
    reasonCode: "reserved-object-field-prefix",
  },
  ok: true,
  scope: "request-envelope-legacy-control",
});

test("renders canonical request-envelope vectors without folding them into committed values", () => {
  const rendered = renderConvexWasmRequestEnvelopeMatrix();
  const vectors = JSON.parse(rendered.canonicalVectorsJson);
  assert.equal(
    convexWasmRequestEnvelopeMatrixKind,
    "convex-wasm-capability-request-envelope-matrix-v4"
  );
  assert.equal(convexWasmCapabilityRequestAbiVersion, 4);
  assert.equal(vectors.requests.length, 24);
  assert.equal(vectors.pendingValueNegativeControls.length, 10);
  assert.equal(vectors.requestNegativeControls.length, 5);
  assert.equal(vectors.reservedSyntaxNegativeControls.length, 6);
  assert.deepEqual(vectors.reservedSyntaxNegativeControls.at(-1), {
    context: "ordinary-document",
    value: { $commitTs: null },
  });
  assert.deepEqual(vectors.requests.find(({ name }) => name === "db-insert")?.envelope.value, {
    commitTs: { $commitTs: null },
    counter: { $integer: "BAAAAAAAAAA=" },
    status: "ready",
  });
  assert.deepEqual(
    vectors.requests.find(({ name }) => name === "db-query-filter-expression")?.envelope.source,
    {
      constraints: [
        { field: "status", operator: "eq", value: "ready" },
        { field: "commitTs", operator: "eq", value: { $commitTs: null } },
      ],
      index: "by_status_commit_ts",
      type: "indexRange",
    }
  );
  assert.deepEqual(
    vectors.requests.find(({ name }) => name === "db-query-search")?.envelope.source,
    {
      filters: [
        { field: "body", type: "search", value: "needle phrase" },
        { field: "tenant", type: "eq", value: "tenant-a" },
        { field: "category", type: "eq", value: { $undefined: null } },
      ],
      index: "by_content",
      type: "search",
    }
  );
  assert.deepEqual(
    vectors.requests.find(({ name }) => name === "db-query-paginate")?.envelope.pagination,
    {
      cursor: "current-cursor",
      endCursor: "end-cursor",
      maximumBytesRead: 4096,
      maximumRowsRead: 7,
      pageSize: 2,
    }
  );
  assert.deepEqual(
    vectors.requests.map(({ name }) => name),
    [
      "auth-get-user-identity",
      "performance-now",
      "environment-variable-get",
      "db-normalize-id",
      "db-get",
      "db-system-get",
      "db-delete",
      "storage-get-url",
      "storage-get-metadata",
      "storage-generate-upload-url",
      "storage-delete",
      "db-insert",
      "db-patch-top-level-deletion",
      "db-replace",
      "db-query-filter-expression",
      "db-query-search",
      "db-query-paginate",
      "db-query-stream",
      "run-mutation",
      "run-query",
      "run-snapshot-query",
      "scheduler-run-after",
      "scheduler-run-at",
      "scheduler-cancel",
    ]
  );
  assert.deepEqual(
    vectors.pendingValueNegativeControls.map(({ name }) => name),
    [
      "db-get-pending-id",
      "db-system-get-pending-id",
      "db-patch-pending-id",
      "db-replace-pending-id",
      "db-delete-pending-id",
      "db-query-pending-filter-literal",
      "db-query-search-pending-equality",
      "scheduler-run-after-pending-args",
      "scheduler-run-at-pending-args",
      "scheduler-cancel-pending-id",
    ]
  );
  assert.deepEqual(
    JSON.parse(rendered.canonicalPendingNegativeControlsJson),
    vectors.pendingValueNegativeControls
  );
  assert.deepEqual(
    vectors.requestNegativeControls.map(({ name }) => name),
    [
      "storage-get-url-non-string-storage-id",
      "storage-get-metadata-pending-storage-id",
      "storage-delete-reserved-syntax-storage-id",
      "storage-get-url-extra-field",
      "storage-generate-upload-url-extra-field",
    ]
  );
  assert.deepEqual(
    JSON.parse(rendered.canonicalRequestNegativeControlsJson),
    vectors.requestNegativeControls
  );
  assert.equal(rendered.executionIdentity.pendingValueNegativeControlCount, 10);
  assert.equal(rendered.executionIdentity.requestNegativeControlCount, 5);
  assert.match(
    rendered.executionIdentity.canonicalPendingNegativeControlsSha256,
    /^[a-f0-9]{64}$/u
  );
  assert.match(
    rendered.executionIdentity.canonicalRequestNegativeControlsSha256,
    /^[a-f0-9]{64}$/u
  );
  assert.match(rendered.canonicalPatchJson, /\$undefined/u);
  assert.match(rendered.canonicalPatchJson, /\$commitTs/u);
  assert.match(rendered.canonicalQueryJson, /\$literal/u);
  assert.match(rendered.canonicalQueryJson, /\$field/u);
  assert.match(rendered.source, /__convexCapabilityEncodeRequest/u);
  assert.match(rendered.source, /__convexCapabilityRequestToHost/u);
  assert.match(rendered.source, /convex_capability_request_decode/u);
  assert.match(rendered.source, /productionHostDecoderExercised: false/u);
  assert.match(rendered.source, /const keys = Object\.keys\(value\)\.sort\(\);/u);
  for (const { name } of vectors.requests) assert.match(rendered.source, new RegExp(name, "u"));
  for (const { name } of vectors.pendingValueNegativeControls) {
    assert.match(rendered.source, new RegExp(name, "u"));
  }
  for (const { name } of vectors.requestNegativeControls) {
    assert.match(rendered.source, new RegExp(name, "u"));
  }
  for (const { context } of vectors.reservedSyntaxNegativeControls) {
    assert.match(rendered.source, new RegExp(context, "u"));
  }
  const inputHeader = renderConvexWasmRequestEnvelopeInputHeader(rendered.canonicalVectorsJson);
  assert.match(inputHeader, /request_count = 24ULL/u);
  assert.match(
    rendered.source,
    /function __convexCapabilityRequestToHost[\s\S]*function __convexRequestEnvelopeMatrixRun[\s\S]*\n\}\n$/u
  );
  assert.doesNotMatch(rendered.source, /timeField, "version"\]\.sort\(\)/u);
  assert.match(
    rendered.source,
    /kind: "dbInsert",\s*table: "documents",\s*value: \{unrelated: value\}/u
  );
  assert.match(rendered.source, /const canonicalRequestNames: string\[\]/u);
  assert.match(rendered.source, /const canonicalRequestInputs: any\[\]/u);
  assert.match(rendered.source, /const canonicalRequestExpected: any\[\]/u);
  assert.match(rendered.source, /const pendingNegativeControlNames: string\[\]/u);
  assert.match(rendered.source, /const pendingNegativeControlInputs: any\[\]/u);
  assert.match(rendered.source, /const requestNegativeControlNames: string\[\]/u);
  assert.match(rendered.source, /const requestNegativeControlInputs: any\[\]/u);
  assert.match(rendered.source, /const requestNegativeControlExpectedMessages: string\[\]/u);
  assert.match(rendered.source, /const negativeControlContexts: string\[\]/u);
  assert.match(rendered.source, /const negativeControlValues: any\[\]/u);
  assert.doesNotMatch(rendered.source, /canonicalRecords/u);
  assert.match(rendered.source, /Capability request has invalid fields/u);
  assert.match(
    rendered.source,
    /const requestKeys = __convexCapabilityOwnDataKeys\(request, "Capability request", false\);/u
  );
  assert.match(
    rendered.source,
    /if \(hasTable\) \{[\s\S]*table: request\.table,[\s\S]*return \{[\s\S]*id: __convexCapabilityEncodeCommittedValue\(request\.id\),[\s\S]*kind,[\s\S]*version: 4,[\s\S]*\};/u
  );
  assert.doesNotMatch(rendered.source, /envelope\.table = request\.table/u);
  assert.doesNotMatch(rendered.source, /\.every\(/u);
  assert.deepEqual(Object.keys(rendered.canonicalVectorCorpus).sort(), [
    "kind",
    "producer",
    "schemaVersion",
    "sha256",
  ]);
  assert.equal(
    rendered.canonicalVectorCorpus.producer.kind,
    "convex-sdk-backend-capability-request-envelope-producer-v4"
  );
  const producerSources = {
    "database-impl.ts": readFileSync(
      new URL("../../node_modules/convex/src/server/impl/database_impl.ts", import.meta.url)
    ),
    "filter-builder-impl.ts": readFileSync(
      new URL("../../node_modules/convex/src/server/impl/filter_builder_impl.ts", import.meta.url)
    ),
    "query-impl.ts": readFileSync(
      new URL("../../node_modules/convex/src/server/impl/query_impl.ts", import.meta.url)
    ),
    "search-filter-builder-impl.ts": readFileSync(
      new URL(
        "../../node_modules/convex/src/server/impl/search_filter_builder_impl.ts",
        import.meta.url
      )
    ),
    "scheduler-impl.ts": readFileSync(
      new URL("../../node_modules/convex/src/server/impl/scheduler_impl.ts", import.meta.url)
    ),
    "storage-impl.ts": readFileSync(
      new URL("../../node_modules/convex/src/server/impl/storage_impl.ts", import.meta.url)
    ),
    "value.ts": readFileSync(
      new URL("../../node_modules/convex/src/values/value.ts", import.meta.url)
    ),
    "vectors.json": readFileSync(
      new URL(
        "../test-fixtures/convex-wasm-request-envelope/canonical-vectors.json",
        import.meta.url
      )
    ),
  };
  const sourceDigests = Object.fromEntries(
    Object.entries(producerSources).map(([name, source]) => [
      name,
      createHash("sha256").update(source).digest("hex"),
    ])
  );
  assert.equal(
    rendered.canonicalVectorCorpus.producer.sourceSha256,
    createHash("sha256").update(JSON.stringify(sourceDigests)).digest("hex")
  );
});

test("generates the Static Hermes runtime arguments consumed by the C++ harness", () => {
  const header = renderConvexWasmRequestEnvelopeRuntimeContractHeader();
  const runtimeMain = readFileSync(
    new URL("./convex-wasm-request-envelope-matrix-runtime-main.cpp", import.meta.url),
    "utf8"
  );
  const argumentsWithProgram = [
    convexWasmRequestEnvelopeMatrixRuntimeProgram,
    ...convexWasmRequestEnvelopeMatrixRuntimeArguments,
  ];

  assert.equal(argumentsWithProgram.length, 6);
  for (const argument of argumentsWithProgram) {
    assert.ok(header.includes(JSON.stringify(argument)));
  }
  assert.match(header, /runtime_argument_count = 6;/u);
  assert.match(runtimeMain, /#include "convex_wasm_request_envelope_matrix_runtime_contract\.h"/u);
  assert.match(
    runtimeMain,
    /_sh_init\(\s*convex_wasm_request_envelope_matrix_runtime_argument_count,\s*convex_wasm_request_envelope_matrix_runtime_arguments\)/u
  );
  assert.doesNotMatch(runtimeMain, /_sh_init\(\s*6\s*,\s*argv\s*\)/u);
  for (const argument of argumentsWithProgram) assert.ok(!runtimeMain.includes(argument));
});

test("uses only the exact production request-envelope prelude", () => {
  const requestEnvelopePrelude = renderNativeCapabilityRequestEnvelopePrelude();
  const rendered = renderConvexWasmRequestEnvelopeMatrix();
  const productionTarget = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript:
      "var __convexWasmCompileProfile = { matrix: async (_ctx, args) => args };",
    sdkPackageVersion: JSON.parse(
      readFileSync(fileURLToPath(import.meta.resolve("convex/package.json")), "utf8")
    ).version,
  });

  assert.ok(rendered.source.includes(requestEnvelopePrelude));
  assert.ok(productionTarget.includes(requestEnvelopePrelude));
  assert.match(requestEnvelopePrelude, /function __convexCapabilityEncodeRequest/u);
  assert.match(requestEnvelopePrelude, /function __convexCapabilityEncodeCommittedValue/u);
  assert.match(requestEnvelopePrelude, /function __convexCapabilityContainsPendingCommitTs/u);
  assert.equal(
    requestEnvelopePrelude.match(
      /function __convexCapabilityEncodeTransactionLimits\(limits: any\): any/gu
    )?.length,
    1
  );
  assert.match(requestEnvelopePrelude, /function __convexCapabilityRequestToHost/u);
  assert.match(requestEnvelopePrelude, /function __convexCapabilityRequestRelease/u);
  for (const nestedUdfName of ["run-mutation", "run-query", "run-snapshot-query"]) {
    assert.match(rendered.source, new RegExp(nestedUdfName, "u"));
  }

  for (const unrelatedRuntime of [
    /__convexTargetRuntimeSurfacePolicySha256/u,
    /__convexIntrinsicPolicySha256/u,
    /__convexDatabaseUdfTimerDeveloperError/u,
    /__convexCryptoDigestBytes/u,
    /__convexPerformanceNow/u,
    /__convexEnvironmentVariableGet/u,
    /__convexApplicationGlobalThis/u,
    /__convexApplicationCompileProfile/u,
    /__convexPendingOperationKinds/u,
    /__convexWasmCapabilityBootstrap/u,
    /convex_capability_current/u,
    /convex_capability_sync_take/u,
    /convex_crypto_/u,
  ]) {
    assert.doesNotMatch(rendered.source, unrelatedRuntime);
  }
});

test("accepts only exact guest request-envelope target evidence", () => {
  assert.doesNotThrow(() => assertConvexWasmRequestEnvelopeMatrixReport(expectedReport));
  assert.throws(
    () =>
      assertConvexWasmRequestEnvelopeMatrixReport({
        ...expectedReport,
        productionHostDecoderExercised: true,
      }),
    /does not match/u
  );
  assert.throws(
    () =>
      assertConvexWasmRequestEnvelopeMatrixReport({
        ...expectedReport,
        canonicalRequestCount: 13,
      }),
    /does not match/u
  );
  assert.doesNotThrow(() =>
    assertConvexWasmRequestEnvelopeLegacyWholeRequestReport(expectedLegacyReport)
  );
  assert.throws(
    () =>
      assertConvexWasmRequestEnvelopeLegacyWholeRequestReport({
        ...expectedLegacyReport,
        legacyWholeRequestRejection: {
          ...expectedLegacyReport.legacyWholeRequestRejection,
          reasonCode: "allocation-failure",
        },
      }),
    /does not match/u
  );
});

test("renders the historical whole-request committed-value control", () => {
  const fixed = renderConvexWasmRequestEnvelopeMatrix();
  const legacy = renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector();
  assert.equal(legacy.legacyWholeRequestRejector, true);
  assert.equal(fixed.legacyWholeRequestRejector, false);
  assert.equal(legacy.canonicalVectorsJson, fixed.canonicalVectorsJson);
  assert.notEqual(legacy.sourceSha256, fixed.sourceSha256);
  assert.match(legacy.source, /__convexGuestEncodeTagged\(request, \[\]\)/u);
  assert.doesNotMatch(fixed.source, /__convexGuestEncodeTagged\(request, \[\]\)/u);
});

test("requires explicit toolchain paths for optimized Wasmtime request-envelope execution", () => {
  const common = [
    "--emcc",
    "/tools/emcc",
    "--hermes-source",
    "/tools/hermes",
    "--output",
    "/reports/matrix.json",
    "--runner",
    "/tools/runner",
    "--shermes",
    "/tools/shermes",
    "--wasm-build",
    "/tools/wasm-build",
  ];
  assert.deepEqual(parseArguments(common), {
    emccPath: "/tools/emcc",
    hermesSourcePath: "/tools/hermes",
    outputPath: "/reports/matrix.json",
    runnerPath: "/tools/runner",
    shermesPath: "/tools/shermes",
    wasmBuildPath: "/tools/wasm-build",
  });
  assert.throws(() => parseArguments(common.slice(2)), /missing required option/u);
});
