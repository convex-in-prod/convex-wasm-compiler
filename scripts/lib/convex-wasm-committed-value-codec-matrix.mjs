import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { convexToJson, jsonToConvex } from "convex/values";

import { lowerConvexWasmExport } from "./convex-wasm-lowering.mjs";

export const convexWasmCommittedValueCodecMatrixKind =
  "convex-wasm-committed-value-codec-matrix-v1";

const matrixSourceFingerprint = "0".repeat(64);
const largeByteLength = 196_609;
const canonicalVectorCorpusKind = "convex-wasm-canonical-convex-value-vector-corpus-v1";
const canonicalProducerKind = "convex-sdk-backend-canonical-value-producer-v1";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const canonicalProducerSource = readFileSync(
  fileURLToPath(new URL("./value.js", import.meta.resolve("convex/values")))
);
const canonicalProducerSourceSha256 = sha256(canonicalProducerSource);

function canonicalVectorCorpus(canonicalInputJson, canonicalOutputJson) {
  const corpusPayload = {
    canonicalInputJson,
    canonicalOutputJson,
    corpusSchema: "convex-wasm-committed-value-codec-matrix-v1",
    largeByteLength,
    schemaVersion: 1,
  };
  return Object.freeze({
    kind: canonicalVectorCorpusKind,
    producer: {
      kind: canonicalProducerKind,
      sourceSha256: canonicalProducerSourceSha256,
    },
    schemaVersion: 1,
    sha256: sha256(JSON.stringify(corpusPayload)),
  });
}

function matrixValue() {
  const bytes = new Uint8Array(largeByteLength);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = (index * 37 + 11) & 0xff;
  }
  return {
    array: [null, true, false, "nested", -123.5, BigInt("2")],
    bytes: bytes.buffer,
    emptyBytes: new ArrayBuffer(0),
    finite: 42.5,
    id: "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y",
    maximumInteger: BigInt("9223372036854775807"),
    minimumInteger: BigInt("-9223372036854775808"),
    negativeOneInteger: BigInt("-1"),
    negativeInfinity: -Infinity,
    negativeZero: -0,
    nested: {
      id: "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y",
      omitted: undefined,
      text: "nested object",
    },
    noncanonicalNaN: jsonToConvex({ $float: "AQAAAAAA+H8=" }),
    nullValue: null,
    positiveInfinity: Infinity,
    undefinedObject: { kept: "value", omitted: undefined },
    zeroInteger: BigInt("0"),
  };
}

function canonicalizeJson(value) {
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (value === null || typeof value !== "object") return value;
  const output = {};
  for (const key of Object.keys(value).sort()) {
    Object.defineProperty(output, key, {
      configurable: true,
      enumerable: true,
      value: canonicalizeJson(value[key]),
      writable: true,
    });
  }
  return output;
}

function replaceExactly(source, before, after, description) {
  const first = source.indexOf(before);
  if (first === -1 || first !== source.lastIndexOf(before)) {
    throw new Error(`guest-native lowering omitted the ${description} arm`);
  }
  return source.replace(before, after);
}

function renderMatrixProgram(canonicalInputJson, canonicalOutputJson, legacyIntegerRejector) {
  const operations = [];
  const lowered = lowerConvexWasmExport({
    appliedDependencyAdapters: [],
    argumentFields: [],
    arrayArgumentFields: [],
    bundleCode: "function admittedHandler(_ctx, args) { return args; }",
    bundleSourceName: "committed-value-codec-matrix.js",
    directAsyncBatches: [],
    documentFields: [],
    handlerIdentifier: "admittedHandler",
    intrinsics: {},
    operations,
    operationsSha256: sha256(JSON.stringify(operations)),
    runtimeInputs: [],
    sourceGraphFingerprint: matrixSourceFingerprint,
    valueMode: "guest-native-json",
  });
  const invocationStart = lowered.code.lastIndexOf(
    "\ntry {\nconst __convexArgs = __convexReadGuestRequest();"
  );
  if (invocationStart === -1) {
    throw new Error("guest-native lowering omitted the terminal invocation block");
  }
  let prelude = lowered.code.slice(0, invocationStart);
  if (legacyIntegerRejector) {
    prelude = replaceExactly(
      prelude,
      `if (typeof value === "bigint") {
    return {$integer: __convexGuestEncodeInteger(value)};
  }`,
      `if (typeof value === "bigint") {
    throw new Error("guest-native integer values are not supported by this Static Hermes target");
  }`,
      "former integer encoder rejection"
    );
    prelude = replaceExactly(
      prelude,
      `if (keys[0] === "$integer") return __convexGuestRestoreInteger(value.$integer);`,
      `if (keys[0] === "$integer") {
      throw new Error("guest-native integer values are not supported by this Static Hermes target");
    }`,
      "former integer decoder rejection"
    );
  }
  const encodedInput = JSON.stringify(canonicalInputJson);
  const encodedOutput = JSON.stringify(canonicalOutputJson);
  return `${prelude}

function __convexCodecMatrixRequire(condition: any, message: string): void {
  if (!condition) throw new Error("Committed-value codec matrix failed: " + message);
}

function __convexCodecMatrixReject(callback: any): boolean {
  try {
    callback();
    return false;
  } catch {
    return true;
  }
}

function __convexCodecMatrixRun(): any {
  const expectedInbound = JSON.parse(${encodedInput});
  const expectedOutbound = JSON.parse(${encodedOutput});
  __convexCodecMatrixRequire(
    expectedInbound.vectors.noncanonicalNaN.$float === "AQAAAAAA+H8=",
    "canonical corpus must contain the noncanonical NaN input vector"
  );
  __convexCodecMatrixFailureStage = "inbound-request";
  const restored = __convexReadGuestRequest();
  __convexCodecMatrixFailureStage = "canonical-reencode";
  const reencoded = __convexGuestEncodeTagged(restored, []);
  if (JSON.stringify(reencoded) !== JSON.stringify(expectedOutbound)) {
    __convexCodecMatrixFailureStage = "canonical-nan-tag";
    __convexCodecMatrixRequire(
      reencoded.vectors.noncanonicalNaN.$float === expectedOutbound.vectors.noncanonicalNaN.$float,
      "noncanonical NaN payload changed"
    );
    __convexCodecMatrixFailureStage = "canonical-large-bytes";
    __convexCodecMatrixRequire(
      reencoded.vectors.bytes.$bytes === expectedOutbound.vectors.bytes.$bytes,
      "large byte payload changed"
    );
    __convexCodecMatrixFailureStage = "canonical-special-floats";
    __convexCodecMatrixRequire(
      reencoded.vectors.negativeInfinity.$float === expectedOutbound.vectors.negativeInfinity.$float &&
        reencoded.vectors.negativeZero.$float === expectedOutbound.vectors.negativeZero.$float &&
        reencoded.vectors.positiveInfinity.$float === expectedOutbound.vectors.positiveInfinity.$float,
      "special float payload changed"
    );
    __convexCodecMatrixFailureStage = "canonical-integers";
    __convexCodecMatrixRequire(
      reencoded.vectors.maximumInteger.$integer === expectedOutbound.vectors.maximumInteger.$integer &&
        reencoded.vectors.minimumInteger.$integer === expectedOutbound.vectors.minimumInteger.$integer &&
        reencoded.vectors.negativeOneInteger.$integer === expectedOutbound.vectors.negativeOneInteger.$integer &&
        reencoded.vectors.zeroInteger.$integer === expectedOutbound.vectors.zeroInteger.$integer,
      "integer payload changed"
    );
    __convexCodecMatrixFailureStage = "canonical-object-order";
    __convexCodecMatrixRequire(false, "canonical inbound value must re-encode exactly");
  }
  __convexCodecMatrixFailureStage = "canonical-vectors";
  const vectors = restored.vectors;
  __convexCodecMatrixRequire(vectors.nullValue === null, "null must restore");
  __convexCodecMatrixRequire(vectors.array[1] === true, "boolean must restore");
  __convexCodecMatrixRequire(vectors.array[3] === "nested", "string must restore");
  __convexCodecMatrixRequire(vectors.finite === 42.5, "ordinary number must restore");
  __convexCodecMatrixRequire(vectors.negativeZero === 0 && 1 / vectors.negativeZero === -Infinity, "negative zero must restore");
  __convexCodecMatrixRequire(vectors.positiveInfinity === Infinity, "positive infinity must restore");
  __convexCodecMatrixRequire(vectors.negativeInfinity === -Infinity, "negative infinity must restore");
  __convexCodecMatrixRequire(vectors.noncanonicalNaN !== vectors.noncanonicalNaN, "noncanonical NaN must restore");
  __convexCodecMatrixRequire(vectors.minimumInteger === BigInt("-9223372036854775808"), "minimum int64 must restore");
  __convexCodecMatrixRequire(vectors.maximumInteger === BigInt("9223372036854775807"), "maximum int64 must restore");
  __convexCodecMatrixRequire(vectors.negativeOneInteger === BigInt("-1"), "negative one int64 must restore");
  __convexCodecMatrixRequire(vectors.zeroInteger === BigInt("0"), "zero int64 must restore");
  __convexCodecMatrixRequire(vectors.bytes instanceof ArrayBuffer, "bytes must restore as ArrayBuffer");
  __convexCodecMatrixRequire(vectors.bytes.byteLength === ${largeByteLength}, "large bytes must preserve length");
  __convexCodecMatrixRequire(vectors.emptyBytes.byteLength === 0, "empty bytes must restore");
  __convexCodecMatrixRequire(vectors.id === "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y", "IDs must remain strings");
  __convexCodecMatrixRequire(
    !Object.prototype.hasOwnProperty.call(vectors.nested, "omitted") &&
      !Object.prototype.hasOwnProperty.call(vectors.undefinedObject, "omitted"),
    "nested undefined properties must be omitted"
  );
  __convexCodecMatrixRequire(
    reencoded.vectors.noncanonicalNaN.$float === expectedOutbound.vectors.noncanonicalNaN.$float,
    "noncanonical NaN must use the engine-normalized outbound tag"
  );
  __convexCodecMatrixFailureStage = "guest-to-host-decode";
  const hostValueHandle = __convexGuestToHost(restored);
  __convexCodecMatrixRequire(
    hostValueHandle === 1,
    "guest-native outbound bridge must return the canonical host handle"
  );
  __convexCodecMatrixFailureStage = "host-to-guest-payload";
  const returnedFromHost = __convexGuestFromHost(hostValueHandle);
  const returnedFromHostJson = __convexGuestEncodeTagged(returnedFromHost, []);
  __convexCodecMatrixRequire(
    JSON.stringify(returnedFromHostJson) === JSON.stringify(expectedOutbound),
    "host bridge payload must restore and re-encode exactly"
  );

  __convexCodecMatrixFailureStage = "direct-codec-vectors";
  __convexCodecMatrixFailureStage = "direct-prototype-field";
  const prototypeField = JSON.parse('{"__proto__":{"safe":true}}');
  const restoredPrototypeField = __convexGuestRestoreTagged(
    __convexGuestEncodeTagged(prototypeField, [])
  );
  __convexCodecMatrixRequire(
    Object.getPrototypeOf(restoredPrototypeField) === Object.prototype &&
      Object.prototype.hasOwnProperty.call(restoredPrototypeField, "__proto__") &&
      restoredPrototypeField.__proto__.safe === true,
    "own __proto__ fields must not change object prototypes"
  );

  __convexCodecMatrixFailureStage = "direct-object-undefined";
  const omittedObject = __convexGuestEncodeTagged({ kept: 1, omitted: undefined }, []);
  __convexCodecMatrixRequire(
    omittedObject.kept === 1 && !Object.prototype.hasOwnProperty.call(omittedObject, "omitted"),
    "outbound undefined object properties must be omitted"
  );

  __convexCodecMatrixFailureStage = "direct-rejections";
  __convexCodecMatrixFailureStage = "direct-rejection-execution";
  const rejected = [
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $unknown: null }); }),
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $undefined: null }); }),
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $float: "AAAAAAAA8D8=" }); }),
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $float: "AAAA" }); }),
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $integer: null }); }),
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $integer: "AAAA" }); }),
    __convexCodecMatrixReject(function() { __convexGuestRestoreTagged({ $bytes: null }); }),
    __convexCodecMatrixReject(function() { __convexGuestEncodeTagged(undefined, []); }),
    __convexCodecMatrixReject(function() { __convexGuestEncodeTagged([undefined], []); }),
    __convexCodecMatrixReject(function() {
      const invalidField: any = {};
      Object.defineProperty(invalidField, "$invalid", { enumerable: true, value: 1 });
      __convexGuestEncodeTagged(invalidField, []);
    }),
    __convexCodecMatrixReject(function() {
      const sparse = [];
      sparse[1] = 1;
      __convexGuestEncodeTagged(sparse, []);
    }),
    __convexCodecMatrixReject(function() { __convexGuestEncodeTagged(new Uint8Array([1]), []); }),
    __convexCodecMatrixReject(function() {
      const cyclic: any = {};
      cyclic.self = cyclic;
      __convexGuestEncodeTagged(cyclic, []);
    }),
    __convexCodecMatrixReject(function() {
      const accessor: any = {};
      Object.defineProperty(accessor, "value", { enumerable: true, get: function() { return 1; } });
      __convexGuestEncodeTagged(accessor, []);
    }),
    __convexCodecMatrixReject(function() { __convexGuestEncodeTagged(BigInt("9223372036854775808"), []); }),
    __convexCodecMatrixReject(function() { __convexGuestEncodeTagged(BigInt("-9223372036854775809"), []); }),
  ];
  __convexCodecMatrixFailureStage = "direct-rejection-unknown-tag";
  __convexCodecMatrixRequire(rejected[0], "unknown tagged value must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-patch-undefined";
  __convexCodecMatrixRequire(rejected[1], "patch undefined must reject as a committed value");
  __convexCodecMatrixFailureStage = "direct-rejection-finite-float";
  __convexCodecMatrixRequire(rejected[2], "finite float tag must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-malformed-float";
  __convexCodecMatrixRequire(rejected[3], "malformed float tag must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-integer-type";
  __convexCodecMatrixRequire(rejected[4], "integer type must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-integer-length";
  __convexCodecMatrixRequire(rejected[5], "integer length must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-bytes";
  __convexCodecMatrixRequire(rejected[6], "bytes tag must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-top-level-undefined";
  __convexCodecMatrixRequire(rejected[7], "top-level undefined must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-array-undefined";
  __convexCodecMatrixRequire(rejected[8], "array undefined must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-reserved-field";
  __convexCodecMatrixRequire(rejected[9], "reserved field must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-sparse-array";
  __convexCodecMatrixRequire(rejected[10], "sparse array must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-typed-array";
  __convexCodecMatrixRequire(rejected[11], "typed array must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-cycle";
  __convexCodecMatrixRequire(rejected[12], "cycle must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-accessor";
  __convexCodecMatrixRequire(rejected[13], "accessor must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-integer-overflow";
  __convexCodecMatrixRequire(rejected[14], "positive integer overflow must reject");
  __convexCodecMatrixFailureStage = "direct-rejection-integer-underflow";
  __convexCodecMatrixRequire(rejected[15], "negative integer underflow must reject");
  __convexCodecMatrixFailureStage = "guest-result";
  __convexSetGuestFunctionResult(returnedFromHost);
  return {
    canonicalRoundTrip: true,
    committedValueRejectsPatchUndefined: true,
    hostGuestBoundary: true,
    largeByteLength: vectors.bytes.byteLength,
    noncanonicalNaNInputTag: expectedInbound.vectors.noncanonicalNaN.$float,
    noncanonicalNaNTag: reencoded.vectors.noncanonicalNaN.$float,
    ok: true,
    rejectedCaseCount: rejected.length,
    scope: "committed-value",
  };
}

let __convexCodecMatrixFailureStage = "initialization";
let __convexCodecMatrixReport: any;
try {
  __convexCodecMatrixReport = __convexCodecMatrixRun();
} catch (__convexCodecMatrixError) {
  __convexCodecMatrixReport = {
    error: String(__convexCodecMatrixError),
    failureStage: __convexCodecMatrixFailureStage,
    ok: false,
  };
}
Object.defineProperty(globalThis, "__convexWasmCommittedValueCodecMatrixReport", {
  configurable: true,
  enumerable: false,
  value: __convexCodecMatrixReport,
  writable: false,
});
`;
}

function renderMatrix(legacyIntegerRejector) {
  // The guest encoder emits object fields in lexical order. Normalize the SDK
  // producer's value to that protocol order before requiring byte-exact hops.
  const canonicalInput = canonicalizeJson(convexToJson({ vectors: matrixValue() }));
  const canonicalInputJson = JSON.stringify(canonicalInput);
  const canonicalOutput = structuredClone(canonicalInput);
  canonicalOutput.vectors.noncanonicalNaN.$float = "AAAAAAAA+H8=";
  const canonicalOutputJson = JSON.stringify(canonicalOutput);
  const source = renderMatrixProgram(
    canonicalInputJson,
    canonicalOutputJson,
    legacyIntegerRejector
  );
  return Object.freeze({
    canonicalInputJson,
    canonicalOutputJson,
    canonicalVectorCorpus: canonicalVectorCorpus(canonicalInputJson, canonicalOutputJson),
    legacyIntegerRejector,
    largeByteLength,
    source,
    sourceSha256: sha256(source),
  });
}

export function renderConvexWasmCommittedValueCodecMatrix() {
  return renderMatrix(false);
}

export function renderConvexWasmCommittedValueCodecMatrixLegacyIntegerRejector() {
  return renderMatrix(true);
}

export function assertConvexWasmCommittedValueCodecMatrixReport(report) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    throw new Error("committed-value codec matrix report must be an object");
  }
  if (report.ok !== true) {
    throw new Error(`committed-value codec matrix rejected: ${JSON.stringify(report.error)}`);
  }
  const expected = {
    canonicalRoundTrip: true,
    committedValueRejectsPatchUndefined: true,
    hostGuestBoundary: true,
    largeByteLength,
    noncanonicalNaNInputTag: "AQAAAAAA+H8=",
    noncanonicalNaNTag: "AAAAAAAA+H8=",
    ok: true,
    rejectedCaseCount: 16,
    scope: "committed-value",
  };
  const keys = Object.keys(report).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    JSON.stringify(report) !== JSON.stringify(expected)
  ) {
    throw new Error("committed-value codec matrix report does not match the required result");
  }
}
