import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs, readFileSync } from "node:fs";

import {
  canonicalJson,
  createConvexWasmCapabilityRequestEnvelopeInput,
  fingerprintJson,
} from "./convex-wasm-artifact-pipeline.mjs";
import {
  convexWasmCommittedValueCodecMatrixKind,
  renderConvexWasmCommittedValueCodecMatrix,
} from "./convex-wasm-committed-value-codec-matrix.mjs";
import {
  assertConvexWasmRequestEnvelopeLegacyWholeRequestReport,
  assertConvexWasmRequestEnvelopeMatrixReport,
  convexWasmCapabilityRequestAbiVersion,
  convexWasmRequestEnvelopeMatrixKind,
  convexWasmRequestEnvelopeMatrixRunnerExport,
  convexWasmRequestEnvelopeMatrixRuntimeArguments,
  convexWasmRequestEnvelopeMatrixRuntimeInitialization,
  convexWasmRequestEnvelopeMatrixTarget,
  renderConvexWasmRequestEnvelopeInputHeader,
  renderConvexWasmRequestEnvelopeMatrix,
  renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector,
  renderConvexWasmRequestEnvelopeRuntimeContractHeader,
} from "./convex-wasm-request-envelope-matrix.mjs";
import { renderOpaqueAbiHeader } from "./convex-wasm-lowering.mjs";

const REPORT_KIND = "convex-wasm-request-envelope-matrix-report-v4";
const EVIDENCE_AUTHORITY_KIND = "convex-wasm-request-envelope-evidence-authority-v1";
const TARGET_NAME = convexWasmRequestEnvelopeMatrixTarget;
const MATRIX_REPORT_MAX_BYTES = 64 * 1024 * 1024;

function fail(message) {
  throw new Error(`Convex Wasm request-envelope matrix report: ${message}`);
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

function fileIdentity(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
  return { bytes: bytes.length, sha256: sha256(bytes) };
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

function requireMatchingIdentity(value, expected, description) {
  requireFileIdentity(value, description);
  if (value.bytes !== expected.bytes || value.sha256 !== expected.sha256) {
    fail(`${description} does not match the current input`);
  }
}

function currentHarnessIdentity() {
  return {
    matrix: fileIdentity(
      readFileSync(new URL("./convex-wasm-request-envelope-matrix.mjs", import.meta.url))
    ),
    runnerExport: convexWasmRequestEnvelopeMatrixRunnerExport,
    runtimeMain: fileIdentity(
      readFileSync(
        new URL("./convex-wasm-request-envelope-matrix-runtime-main.cpp", import.meta.url)
      )
    ),
    source: fileIdentity(
      readFileSync(new URL("../run-convex-wasm-request-envelope-matrix.mjs", import.meta.url))
    ),
  };
}

function requireRuntimeInputs(value, description) {
  requireExactKeys(value, ["hermesHeaders", "wasmArchives", "wasmConfigHeader"], description);
  const hermesHeaders = requireExactKeys(
    value.hermesHeaders,
    ["jsi", "staticHermes"],
    `${description}.hermesHeaders`
  );
  const wasmArchives = requireExactKeys(
    value.wasmArchives,
    ["hermesVm", "jsi"],
    `${description}.wasmArchives`
  );
  requireFileIdentity(hermesHeaders.jsi, `${description}.hermesHeaders.jsi`);
  requireFileIdentity(hermesHeaders.staticHermes, `${description}.hermesHeaders.staticHermes`);
  requireFileIdentity(wasmArchives.hermesVm, `${description}.wasmArchives.hermesVm`);
  requireFileIdentity(wasmArchives.jsi, `${description}.wasmArchives.jsi`);
  requireFileIdentity(value.wasmConfigHeader, `${description}.wasmConfigHeader`);
}

function requireEvidenceOutputIdentity(value, description) {
  requireExactKeys(
    value,
    ["artifact", "generatedC", "generatedObject", "runtimeObject"],
    description
  );
  for (const field of ["artifact", "generatedC", "generatedObject", "runtimeObject"]) {
    requireFileIdentity(value[field], `${description}.${field}`);
  }
}

function requireEvidenceAuthority(value) {
  const authority = requireExactKeys(
    value,
    ["kind", "reportSha256", "runtimeInputs", "schemaVersion", "targets", "tools"],
    "evidence authority"
  );
  if (authority.kind !== EVIDENCE_AUTHORITY_KIND || authority.schemaVersion !== 1) {
    fail("evidence authority kind or schema version is unsupported");
  }
  requireSha256(authority.reportSha256, "evidence authority.reportSha256");
  requireRuntimeInputs(authority.runtimeInputs, "evidence authority.runtimeInputs");
  const tools = requireExactKeys(
    authority.tools,
    ["emcc", "runner", "shermes"],
    "evidence authority.tools"
  );
  for (const [name, identity] of Object.entries(tools)) {
    requireFileIdentity(identity, `evidence authority.tools.${name}`);
  }
  const targets = requireExactKeys(
    authority.targets,
    ["current", "legacyWholeRequestRejector"],
    "evidence authority.targets"
  );
  requireEvidenceOutputIdentity(targets.current, "evidence authority.targets.current");
  requireEvidenceOutputIdentity(
    targets.legacyWholeRequestRejector,
    "evidence authority.targets.legacyWholeRequestRejector"
  );
  return authority;
}

function evidenceOutputIdentity(target) {
  return {
    artifact: target.artifact,
    generatedC: target.generatedC,
    generatedObject: target.generatedObject,
    runtimeObject: target.runtimeObject,
  };
}

function requireTarget(value, description, expectedTarget) {
  requireObject(value, description);
  const names = Object.keys(value).sort();
  if (names.length !== 1 || names[0] !== TARGET_NAME) {
    fail(`${description} must contain exactly the optimized Wasmtime target`);
  }
  expectedTarget(value[TARGET_NAME], `${description}.${TARGET_NAME}`);
}

function requireEvidenceTarget(value, description, expected, assertEnvelope) {
  requireExactKeys(
    value,
    [
      "artifact",
      "envelope",
      "generatedC",
      "generatedObject",
      "generatedSource",
      "inputHeader",
      "opaqueAbiHeader",
      "runtimeInputs",
      "runtimeMain",
      "runtimeObject",
      "runtimeContractHeader",
    ],
    description
  );
  requireFileIdentity(value.artifact, `${description}.artifact`);
  requireFileIdentity(value.generatedC, `${description}.generatedC`);
  requireFileIdentity(value.generatedObject, `${description}.generatedObject`);
  requireMatchingIdentity(
    value.generatedSource,
    expected.generatedSource,
    `${description}.generatedSource`
  );
  requireMatchingIdentity(value.inputHeader, expected.inputHeader, `${description}.inputHeader`);
  requireMatchingIdentity(
    value.opaqueAbiHeader,
    expected.opaqueAbiHeader,
    `${description}.opaqueAbiHeader`
  );
  requireMatchingIdentity(value.runtimeMain, expected.runtimeMain, `${description}.runtimeMain`);
  requireFileIdentity(value.runtimeObject, `${description}.runtimeObject`);
  requireMatchingIdentity(
    value.runtimeContractHeader,
    expected.runtimeContractHeader,
    `${description}.runtimeContractHeader`
  );
  requireRuntimeInputs(value.runtimeInputs, `${description}.runtimeInputs`);
  if (canonicalJson(value.runtimeInputs) !== canonicalJson(expected.runtimeInputs)) {
    fail(`${description}.runtimeInputs do not match the report runtime inputs`);
  }
  try {
    assertEnvelope(value.envelope);
  } catch (error) {
    fail(`${description}.envelope is invalid: ${error.message}`);
  }
}

function validateConvexWasmRequestEnvelopeMatrixReport(report) {
  requireExactKeys(
    report,
    [
      "committedValueCodec",
      "harness",
      "kind",
      "legacyWholeRequestRejector",
      "matrix",
      "reportSha256",
      "runtime",
      "runtimeInputs",
      "schemaVersion",
      "targets",
      "tools",
    ],
    "report"
  );
  const { reportSha256, ...payload } = report;
  // This detects accidental or stale local evidence. It is an integrity fingerprint, not a
  // signature or an authorization boundary, because a caller can recompute it after editing.
  if (requireSha256(reportSha256, "report.reportSha256") !== fingerprintJson(payload)) {
    fail("report.reportSha256 integrity fingerprint does not match the report payload");
  }
  if (report.kind !== REPORT_KIND || report.schemaVersion !== 4) {
    fail("report kind or schema version is unsupported");
  }
  const harness = requireExactKeys(
    report.harness,
    ["matrix", "runnerExport", "runtimeMain", "source"],
    "report.harness"
  );
  const currentHarness = currentHarnessIdentity();
  requireMatchingIdentity(harness.matrix, currentHarness.matrix, "report.harness.matrix");
  requireMatchingIdentity(
    harness.runtimeMain,
    currentHarness.runtimeMain,
    "report.harness.runtimeMain"
  );
  requireMatchingIdentity(harness.source, currentHarness.source, "report.harness.source");
  if (harness.runnerExport !== currentHarness.runnerExport) {
    fail("report.harness.runnerExport does not match the current runner export");
  }

  const matrix = requireExactKeys(
    report.matrix,
    [
      "capabilityRequestAbiVersion",
      "canonicalNegativeControlsSha256",
      "canonicalRequestNegativeControlsSha256",
      "canonicalVectorsSha256",
      "canonicalVectorCorpus",
      "inputHeader",
      "kind",
      "opaqueAbiHeader",
      "requestEnvelopePreludeSha256",
      "runtimeContractHeader",
      "sourceSha256",
    ],
    "report.matrix"
  );
  if (matrix.capabilityRequestAbiVersion !== convexWasmCapabilityRequestAbiVersion) {
    fail("report.matrix capability request ABI version is unsupported");
  }
  requireSha256(
    matrix.canonicalNegativeControlsSha256,
    "report.matrix.canonicalNegativeControlsSha256"
  );
  requireSha256(
    matrix.canonicalRequestNegativeControlsSha256,
    "report.matrix.canonicalRequestNegativeControlsSha256"
  );
  requireSha256(matrix.canonicalVectorsSha256, "report.matrix.canonicalVectorsSha256");
  requireSha256(matrix.requestEnvelopePreludeSha256, "report.matrix.requestEnvelopePreludeSha256");
  requireSha256(matrix.sourceSha256, "report.matrix.sourceSha256");
  if (matrix.kind !== convexWasmRequestEnvelopeMatrixKind) {
    fail("report.matrix kind is unsupported");
  }
  const currentMatrix = renderConvexWasmRequestEnvelopeMatrix();
  const currentInputHeader = fileIdentity(
    renderConvexWasmRequestEnvelopeInputHeader(currentMatrix.canonicalVectorsJson)
  );
  const currentOpaqueAbiHeader = fileIdentity(renderOpaqueAbiHeader());
  const currentRuntimeContractHeader = fileIdentity(
    renderConvexWasmRequestEnvelopeRuntimeContractHeader()
  );
  requireMatchingIdentity(matrix.inputHeader, currentInputHeader, "report.matrix.inputHeader");
  requireMatchingIdentity(
    matrix.opaqueAbiHeader,
    currentOpaqueAbiHeader,
    "report.matrix.opaqueAbiHeader"
  );
  requireMatchingIdentity(
    matrix.runtimeContractHeader,
    currentRuntimeContractHeader,
    "report.matrix.runtimeContractHeader"
  );
  if (
    matrix.sourceSha256 !== currentMatrix.sourceSha256 ||
    matrix.canonicalNegativeControlsSha256 !==
      sha256(currentMatrix.canonicalNegativeControlsJson) ||
    matrix.canonicalRequestNegativeControlsSha256 !==
      sha256(currentMatrix.canonicalRequestNegativeControlsJson) ||
    matrix.canonicalVectorsSha256 !== sha256(currentMatrix.canonicalVectorsJson) ||
    matrix.requestEnvelopePreludeSha256 !== currentMatrix.requestEnvelopePreludeSha256 ||
    canonicalJson(matrix.canonicalVectorCorpus) !==
      canonicalJson(currentMatrix.canonicalVectorCorpus)
  ) {
    fail("report.matrix does not match the current request-envelope lowering");
  }

  const committedValueCodec = requireExactKeys(
    report.committedValueCodec,
    ["canonicalVectorCorpus", "matrixKind", "sourceSha256"],
    "report.committedValueCodec"
  );
  requireSha256(committedValueCodec.sourceSha256, "report.committedValueCodec.sourceSha256");
  const currentCommittedValueCodec = renderConvexWasmCommittedValueCodecMatrix();
  if (
    committedValueCodec.matrixKind !== convexWasmCommittedValueCodecMatrixKind ||
    committedValueCodec.sourceSha256 !== currentCommittedValueCodec.sourceSha256 ||
    canonicalJson(committedValueCodec.canonicalVectorCorpus) !==
      canonicalJson(currentCommittedValueCodec.canonicalVectorCorpus)
  ) {
    fail("report.committedValueCodec does not match the current committed-value codec");
  }

  const runtime = requireExactKeys(
    report.runtime,
    ["arguments", "initialization", "runnerExport"],
    "report.runtime"
  );
  if (
    canonicalJson(runtime.arguments) !==
      canonicalJson(convexWasmRequestEnvelopeMatrixRuntimeArguments) ||
    runtime.initialization !== convexWasmRequestEnvelopeMatrixRuntimeInitialization ||
    runtime.runnerExport !== convexWasmRequestEnvelopeMatrixRunnerExport ||
    runtime.runnerExport !== harness.runnerExport
  ) {
    fail("report.runtime does not match the current runtime contract");
  }

  requireRuntimeInputs(report.runtimeInputs, "report.runtimeInputs");

  const tools = requireExactKeys(report.tools, ["emcc", "runner", "shermes"], "report.tools");
  for (const [name, identity] of Object.entries(tools)) {
    requireFileIdentity(identity, `report.tools.${name}`);
  }
  const commonTargetExpected = {
    inputHeader: currentInputHeader,
    opaqueAbiHeader: currentOpaqueAbiHeader,
    runtimeInputs: report.runtimeInputs,
    runtimeMain: currentHarness.runtimeMain,
    runtimeContractHeader: currentRuntimeContractHeader,
  };
  requireTarget(report.targets, "report.targets", (value, description) =>
    requireEvidenceTarget(
      value,
      description,
      {
        ...commonTargetExpected,
        generatedSource: fileIdentity(currentMatrix.source),
      },
      assertConvexWasmRequestEnvelopeMatrixReport
    )
  );

  const legacyWholeRequestRejector = requireExactKeys(
    report.legacyWholeRequestRejector,
    ["executionIdentity", "sourceSha256", "targets"],
    "report.legacyWholeRequestRejector"
  );
  requireSha256(
    legacyWholeRequestRejector.sourceSha256,
    "report.legacyWholeRequestRejector.sourceSha256"
  );
  const currentLegacyWholeRequestRejector =
    renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector();
  if (
    legacyWholeRequestRejector.sourceSha256 !== currentLegacyWholeRequestRejector.sourceSha256 ||
    canonicalJson(legacyWholeRequestRejector.executionIdentity) !==
      canonicalJson(currentLegacyWholeRequestRejector.executionIdentity)
  ) {
    fail("report.legacyWholeRequestRejector does not match the current negative control");
  }
  requireTarget(
    legacyWholeRequestRejector.targets,
    "report.legacyWholeRequestRejector.targets",
    (value, description) =>
      requireEvidenceTarget(
        value,
        description,
        {
          ...commonTargetExpected,
          generatedSource: fileIdentity(currentLegacyWholeRequestRejector.source),
        },
        assertConvexWasmRequestEnvelopeLegacyWholeRequestReport
      )
  );
  const currentTarget = report.targets[TARGET_NAME];
  const legacyTarget = legacyWholeRequestRejector.targets[TARGET_NAME];
  return {
    capabilityRequestInput: createConvexWasmCapabilityRequestEnvelopeInput({
      capabilityRequestAbiVersion: matrix.capabilityRequestAbiVersion,
      canonicalVectorCorpus: matrix.canonicalVectorCorpus,
    }),
    reportSha256,
    runtimeInputs: report.runtimeInputs,
    targets: {
      current: evidenceOutputIdentity(currentTarget),
      legacyWholeRequestRejector: evidenceOutputIdentity(legacyTarget),
    },
    tools,
  };
}

export function createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReport(report) {
  const validated = validateConvexWasmRequestEnvelopeMatrixReport(report);
  return {
    kind: EVIDENCE_AUTHORITY_KIND,
    reportSha256: validated.reportSha256,
    runtimeInputs: structuredClone(validated.runtimeInputs),
    schemaVersion: 1,
    targets: structuredClone(validated.targets),
    tools: structuredClone(validated.tools),
  };
}

export function createConvexWasmRequestEnvelopeInputFromMatrixReport(report, rawEvidenceAuthority) {
  const validated = validateConvexWasmRequestEnvelopeMatrixReport(report);
  const evidenceAuthority = requireEvidenceAuthority(rawEvidenceAuthority);
  if (evidenceAuthority.reportSha256 !== validated.reportSha256) {
    fail("report is not approved by the supplied evidence authority");
  }
  if (
    canonicalJson(validated.tools) !== canonicalJson(evidenceAuthority.tools) ||
    canonicalJson(validated.runtimeInputs) !== canonicalJson(evidenceAuthority.runtimeInputs)
  ) {
    fail("report tool or runtime inputs are not approved by the supplied evidence authority");
  }
  if (
    canonicalJson(validated.targets.current) !== canonicalJson(evidenceAuthority.targets.current) ||
    canonicalJson(validated.targets.legacyWholeRequestRejector) !==
      canonicalJson(evidenceAuthority.targets.legacyWholeRequestRejector)
  ) {
    fail("report target outputs are not approved by the supplied evidence authority");
  }
  return validated.capabilityRequestInput;
}

async function readStableConvexWasmRequestEnvelopeMatrixReport(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("matrix report reads require O_NOFOLLOW");
  }
  const [realPath, beforePath] = await Promise.all([fs.realpath(path), fs.lstat(path)]);
  if (
    realPath !== path ||
    !beforePath.isFile() ||
    beforePath.size <= 0 ||
    beforePath.size > MATRIX_REPORT_MAX_BYTES ||
    beforePath.uid !== process.getuid() ||
    (beforePath.mode & 0o777) !== 0o600
  ) {
    fail("matrix report must be a current-user-owned canonical bounded 0600 file");
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
      afterPath.uid !== process.getuid() ||
      (afterPath.mode & 0o777) !== 0o600
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
    fail("request-envelope matrix report is invalid JSON");
  }
  if (source !== `${JSON.stringify(report, null, 2)}\n`) {
    fail("report must use the matrix runner's stable JSON format followed by one newline");
  }
  return report;
}

export async function createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile(path) {
  const report = await readStableConvexWasmRequestEnvelopeMatrixReport(path);
  return createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReport(report);
}

export async function readConvexWasmRequestEnvelopeMatrixReport(path, evidenceAuthority) {
  const report = await readStableConvexWasmRequestEnvelopeMatrixReport(path);
  createConvexWasmRequestEnvelopeInputFromMatrixReport(report, evidenceAuthority);
  return report;
}
