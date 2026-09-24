import assert from "node:assert/strict";
import test from "node:test";

import {
  assertConvexWasmCommittedValueCodecMatrixReport,
  convexWasmCommittedValueCodecMatrixKind,
  renderConvexWasmCommittedValueCodecMatrix,
  renderConvexWasmCommittedValueCodecMatrixLegacyIntegerRejector,
} from "./convex-wasm-committed-value-codec-matrix.mjs";
import { parseArguments } from "../run-convex-wasm-committed-value-codec-matrix.mjs";

const expectedReport = Object.freeze({
  canonicalRoundTrip: true,
  committedValueRejectsPatchUndefined: true,
  hostGuestBoundary: true,
  largeByteLength: 196_609,
  noncanonicalNaNInputTag: "AQAAAAAA+H8=",
  noncanonicalNaNTag: "AAAAAAAA+H8=",
  ok: true,
  rejectedCaseCount: 16,
  scope: "committed-value",
});

test("renders the current guest prelude with committed-value boundary coverage", () => {
  const rendered = renderConvexWasmCommittedValueCodecMatrix();
  assert.equal(
    convexWasmCommittedValueCodecMatrixKind,
    "convex-wasm-committed-value-codec-matrix-v1"
  );
  assert.match(rendered.canonicalInputJson, /AQAAAAAA\+H8=/u);
  assert.match(rendered.canonicalOutputJson, /AAAAAAAA\+H8=/u);
  assert.notEqual(rendered.canonicalInputJson, rendered.canonicalOutputJson);
  assert.match(rendered.canonicalInputJson, /\$bytes/u);
  assert.match(rendered.canonicalInputJson, /\$integer/u);
  assert.match(rendered.source, /function __convexGuestEncodeTagged\(/u);
  assert.match(rendered.source, /function __convexGuestRestoreTagged\(/u);
  assert.match(rendered.source, /__convexReadGuestRequest\(\)/u);
  assert.match(rendered.source, /__convexGuestToHost\(restored\)/u);
  assert.match(rendered.source, /__convexGuestFromHost\(hostValueHandle\)/u);
  assert.match(rendered.source, /__convexSetGuestFunctionResult\(returnedFromHost\)/u);
  assert.match(rendered.source, /\{ \$undefined: null \}/u);
  assert.match(rendered.source, /\{ \$integer: null \}/u);
  assert.match(rendered.source, /9223372036854775808/u);
  assert.match(rendered.source, /-9223372036854775809/u);
  assert.match(rendered.source, /scope: "committed-value"/u);
  assert.deepEqual(Object.keys(rendered.canonicalVectorCorpus).sort(), [
    "kind",
    "producer",
    "schemaVersion",
    "sha256",
  ]);
  assert.deepEqual(
    rendered.canonicalVectorCorpus.producer.kind,
    "convex-sdk-backend-canonical-value-producer-v1"
  );
  assert.match(rendered.canonicalVectorCorpus.producer.sourceSha256, /^[a-f0-9]{64}$/u);
  assert.match(rendered.canonicalVectorCorpus.sha256, /^[a-f0-9]{64}$/u);
});

test("accepts only the exact committed-value codec matrix result", () => {
  assert.doesNotThrow(() => assertConvexWasmCommittedValueCodecMatrixReport(expectedReport));
  assert.throws(
    () =>
      assertConvexWasmCommittedValueCodecMatrixReport({
        ...expectedReport,
        ok: false,
        error: "old codec accepted a malformed value",
      }),
    /rejected/u
  );
  assert.throws(
    () =>
      assertConvexWasmCommittedValueCodecMatrixReport({
        ...expectedReport,
        noncanonicalNaNTag: "AQAAAAAA+H8=",
      }),
    /does not match/u
  );
  assert.throws(
    () =>
      assertConvexWasmCommittedValueCodecMatrixReport({
        ...expectedReport,
        largeByteLength: 196_608,
      }),
    /does not match/u
  );
  assert.throws(
    () =>
      assertConvexWasmCommittedValueCodecMatrixReport({
        ...expectedReport,
        hostGuestBoundary: false,
      }),
    /does not match/u
  );
});

test("renders the exact former integer rejection as a discriminating control", () => {
  const fixed = renderConvexWasmCommittedValueCodecMatrix();
  const legacy = renderConvexWasmCommittedValueCodecMatrixLegacyIntegerRejector();
  assert.equal(legacy.legacyIntegerRejector, true);
  assert.equal(fixed.legacyIntegerRejector, false);
  assert.equal(legacy.canonicalInputJson, fixed.canonicalInputJson);
  assert.notEqual(legacy.sourceSha256, fixed.sourceSha256);
  assert.match(
    legacy.source,
    /guest-native integer values are not supported by this Static Hermes target/u
  );
  assert.doesNotMatch(
    fixed.source,
    /guest-native integer values are not supported by this Static Hermes target/u
  );
});

test("requires explicit toolchain paths for four-target matrix execution", () => {
  const common = [
    "--cxx",
    "/tools/c++",
    "--emcc",
    "/tools/emcc",
    "--hermes-source",
    "/tools/hermes",
    "--host-build",
    "/tools/host-build",
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
    cxxPath: "/tools/c++",
    emccPath: "/tools/emcc",
    hermesSourcePath: "/tools/hermes",
    hostBuildPath: "/tools/host-build",
    outputPath: "/reports/matrix.json",
    runnerPath: "/tools/runner",
    shermesPath: "/tools/shermes",
    wasmBuildPath: "/tools/wasm-build",
  });
  assert.throws(() => parseArguments(common.slice(2)), /missing required option/u);
});
