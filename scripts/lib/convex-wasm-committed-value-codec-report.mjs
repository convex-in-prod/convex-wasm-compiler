import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";

import {
  canonicalJson,
  createConvexWasmGuestNativeJsonCodecInput,
  fingerprintJson,
} from "./convex-wasm-artifact-pipeline.mjs";
import {
  assertConvexWasmCommittedValueCodecMatrixReport,
  convexWasmCommittedValueCodecMatrixKind,
  renderConvexWasmCommittedValueCodecMatrix,
} from "./convex-wasm-committed-value-codec-matrix.mjs";

const REPORT_KIND = "convex-wasm-committed-value-codec-matrix-report-v1";
const TARGET_NAMES = [
  "static-hermes-native-optimized",
  "static-hermes-native-unoptimized",
  "static-hermes-wasmtime-optimized",
  "static-hermes-wasmtime-unoptimized",
];
const LEGACY_INTEGER_REJECTION_WRAPPER_EXIT_STATUS = Object.freeze({
  "static-hermes-native-optimized": 3,
  "static-hermes-native-unoptimized": 3,
  "static-hermes-wasmtime-optimized": 1,
  "static-hermes-wasmtime-unoptimized": 1,
});
const MATRIX_REPORT_MAX_BYTES = 64 * 1024 * 1024;

function fail(message) {
  throw new Error(`Convex Wasm committed-value codec matrix report: ${message}`);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireExactKeys(value, keys, description) {
  requireObject(value, description);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    fail(`${description} has missing or unknown fields`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireFileIdentity(value, description) {
  requireExactKeys(value, ["bytes", "sha256"], description);
  if (!Number.isSafeInteger(value.bytes) || value.bytes <= 0) {
    fail(`${description}.bytes must be a positive safe integer`);
  }
  return { bytes: value.bytes, sha256: requireSha256(value.sha256, `${description}.sha256`) };
}

function requireTargets(value, description, expectedTarget) {
  requireObject(value, description);
  const names = Object.keys(value).sort();
  if (
    names.length !== TARGET_NAMES.length ||
    names.some((name, index) => name !== TARGET_NAMES[index])
  ) {
    fail(`${description} must contain exactly the four required targets`);
  }
  for (const name of TARGET_NAMES) {
    expectedTarget(value[name], `${description}.${name}`, name);
  }
}

function requireSuccessfulTarget(value, description) {
  requireExactKeys(value, ["artifact", "codec", "generatedObject", "runtimeObject"], description);
  requireFileIdentity(value.artifact, `${description}.artifact`);
  requireFileIdentity(value.generatedObject, `${description}.generatedObject`);
  requireFileIdentity(value.runtimeObject, `${description}.runtimeObject`);
  try {
    assertConvexWasmCommittedValueCodecMatrixReport(value.codec);
  } catch (error) {
    fail(`${description}.codec is invalid: ${error.message}`);
  }
}

function requireLegacyIntegerRejectionTarget(value, description, targetName) {
  requireExactKeys(
    value,
    ["artifact", "generatedObject", "legacyIntegerRejection", "runtimeObject"],
    description
  );
  requireFileIdentity(value.artifact, `${description}.artifact`);
  requireFileIdentity(value.generatedObject, `${description}.generatedObject`);
  requireFileIdentity(value.runtimeObject, `${description}.runtimeObject`);
  const rejection = requireExactKeys(
    value.legacyIntegerRejection,
    ["exitStatus", "reportOk", "stage"],
    `${description}.legacyIntegerRejection`
  );
  if (
    rejection.exitStatus !== LEGACY_INTEGER_REJECTION_WRAPPER_EXIT_STATUS[targetName] ||
    rejection.reportOk !== false ||
    rejection.stage !== "guest-value-boundary"
  ) {
    fail(`${description}.legacyIntegerRejection is invalid`);
  }
}

export function createConvexWasmValueCodecInputFromMatrixReport(report) {
  requireExactKeys(
    report,
    [
      "harness",
      "kind",
      "legacyIntegerRejector",
      "matrix",
      "reportSha256",
      "runtime",
      "schemaVersion",
      "targets",
      "tools",
    ],
    "report"
  );
  const { reportSha256, ...payload } = report;
  if (requireSha256(reportSha256, "report.reportSha256") !== fingerprintJson(payload)) {
    fail("report.reportSha256 does not authenticate the report payload");
  }
  if (report.kind !== REPORT_KIND || report.schemaVersion !== 1) {
    fail("report kind or schema version is unsupported");
  }

  const harness = requireExactKeys(
    report.harness,
    ["matrix", "runnerExport", "runtimeMain", "source"],
    "report.harness"
  );
  requireFileIdentity(harness.matrix, "report.harness.matrix");
  requireFileIdentity(harness.runtimeMain, "report.harness.runtimeMain");
  requireFileIdentity(harness.source, "report.harness.source");
  if (typeof harness.runnerExport !== "string" || harness.runnerExport.length === 0) {
    fail("report.harness.runnerExport must be a nonempty string");
  }

  const matrix = requireExactKeys(
    report.matrix,
    [
      "canonicalInputSha256",
      "canonicalOutputSha256",
      "canonicalVectorCorpus",
      "inputHeader",
      "kind",
      "largeByteLength",
      "opaqueAbiHeader",
      "sourceSha256",
    ],
    "report.matrix"
  );
  requireSha256(matrix.canonicalInputSha256, "report.matrix.canonicalInputSha256");
  requireSha256(matrix.canonicalOutputSha256, "report.matrix.canonicalOutputSha256");
  requireSha256(matrix.sourceSha256, "report.matrix.sourceSha256");
  requireFileIdentity(matrix.inputHeader, "report.matrix.inputHeader");
  requireFileIdentity(matrix.opaqueAbiHeader, "report.matrix.opaqueAbiHeader");
  if (
    matrix.kind !== convexWasmCommittedValueCodecMatrixKind ||
    matrix.largeByteLength !== 196_609
  ) {
    fail("report.matrix kind or canonical vector size is unsupported");
  }
  const currentMatrix = renderConvexWasmCommittedValueCodecMatrix();
  if (
    matrix.sourceSha256 !== currentMatrix.sourceSha256 ||
    matrix.canonicalInputSha256 !== sha256(currentMatrix.canonicalInputJson) ||
    matrix.canonicalOutputSha256 !== sha256(currentMatrix.canonicalOutputJson) ||
    canonicalJson(matrix.canonicalVectorCorpus) !==
      canonicalJson(currentMatrix.canonicalVectorCorpus)
  ) {
    fail("report.matrix does not match the current committed-value codec lowering");
  }

  const runtime = requireExactKeys(
    report.runtime,
    ["arguments", "initialization", "runnerExport"],
    "report.runtime"
  );
  if (
    !Array.isArray(runtime.arguments) ||
    runtime.arguments.some((argument) => typeof argument !== "string") ||
    typeof runtime.initialization !== "string" ||
    runtime.initialization.length === 0 ||
    runtime.runnerExport !== harness.runnerExport
  ) {
    fail("report.runtime is invalid");
  }

  const tools = requireExactKeys(
    report.tools,
    ["cxx", "emcc", "runner", "shermes"],
    "report.tools"
  );
  for (const [name, identity] of Object.entries(tools)) {
    requireFileIdentity(identity, `report.tools.${name}`);
  }
  requireTargets(report.targets, "report.targets", requireSuccessfulTarget);

  const legacyIntegerRejector = requireExactKeys(
    report.legacyIntegerRejector,
    ["sourceSha256", "targets"],
    "report.legacyIntegerRejector"
  );
  requireSha256(legacyIntegerRejector.sourceSha256, "report.legacyIntegerRejector.sourceSha256");
  requireTargets(
    legacyIntegerRejector.targets,
    "report.legacyIntegerRejector.targets",
    requireLegacyIntegerRejectionTarget
  );

  return createConvexWasmGuestNativeJsonCodecInput({
    canonicalVectorCorpus: matrix.canonicalVectorCorpus,
  });
}

export async function readConvexWasmValueCodecMatrixReport(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("matrix report reads require O_NOFOLLOW");
  }
  const [realPath, beforePath] = await Promise.all([fs.realpath(path), fs.lstat(path)]);
  if (
    realPath !== path ||
    !beforePath.isFile() ||
    beforePath.size <= 0 ||
    beforePath.size > MATRIX_REPORT_MAX_BYTES ||
    beforePath.uid !== process.getuid()
  ) {
    fail("matrix report must be a current-user-owned canonical bounded regular file");
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let bytes;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileState(beforePath, opened)) {
      fail("matrix report changed while it was opened");
    }
    bytes = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) fail("matrix report changed while it was read");
      offset += read.bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    const trailing = await handle.read(extra, 0, 1, offset);
    const [after, afterPath, afterRealPath] = await Promise.all([
      handle.stat(),
      fs.lstat(path),
      fs.realpath(path),
    ]);
    if (
      trailing.bytesRead !== 0 ||
      !sameFileState(opened, after) ||
      afterRealPath !== path ||
      !afterPath.isFile() ||
      !sameFileState(opened, afterPath) ||
      afterPath.uid !== process.getuid()
    ) {
      fail("matrix report changed while it was read");
    }
  } finally {
    await handle.close();
  }
  const source = bytes.toString("utf8");
  let report;
  try {
    report = JSON.parse(source);
  } catch {
    fail("committed-value codec matrix report is invalid JSON");
  }
  if (source !== `${JSON.stringify(report, null, 2)}\n`) {
    fail("report must use the matrix runner's stable JSON format followed by one newline");
  }
  createConvexWasmValueCodecInputFromMatrixReport(report);
  return report;
}
