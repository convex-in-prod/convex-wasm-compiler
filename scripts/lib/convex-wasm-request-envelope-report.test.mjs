import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReport,
  createConvexWasmRequestEnvelopeInputFromMatrixReport,
  readConvexWasmRequestEnvelopeMatrixReport,
} from "./convex-wasm-request-envelope-report.mjs";
import {
  main as createEvidenceAuthority,
  parseArguments as parseEvidenceAuthorityArguments,
} from "../create-convex-wasm-request-envelope-evidence-authority.mjs";
import { renderConvexWasmCommittedValueCodecMatrix } from "./convex-wasm-committed-value-codec-matrix.mjs";
import {
  convexWasmCapabilityRequestAbiVersion,
  convexWasmRequestEnvelopeMatrixRunnerExport,
  convexWasmRequestEnvelopeMatrixRuntimeArguments,
  convexWasmRequestEnvelopeMatrixRuntimeInitialization,
  renderConvexWasmRequestEnvelopeInputHeader,
  renderConvexWasmRequestEnvelopeMatrix,
  renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector,
  renderConvexWasmRequestEnvelopeRuntimeContractHeader,
} from "./convex-wasm-request-envelope-matrix.mjs";
import { renderOpaqueAbiHeader } from "./convex-wasm-lowering.mjs";

const digest = (character) => character.repeat(64);
const targetName = "static-hermes-wasmtime-optimized";
function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function fileIdentity(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

function artifactIdentity(seed) {
  return { bytes: 2, sha256: digest(seed) };
}

function runtimeInputsFixture() {
  return {
    hermesHeaders: {
      jsi: artifactIdentity("1"),
      staticHermes: artifactIdentity("2"),
    },
    wasmArchives: {
      hermesVm: artifactIdentity("3"),
      jsi: artifactIdentity("4"),
    },
    wasmConfigHeader: artifactIdentity("5"),
  };
}

function refingerprint(report) {
  const { reportSha256: _reportSha256, ...payload } = report;
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

function evidenceOutputIdentity(target) {
  return {
    artifact: target.artifact,
    generatedC: target.generatedC,
    generatedObject: target.generatedObject,
    runtimeObject: target.runtimeObject,
  };
}

function evidenceAuthorityFixture(report) {
  return {
    kind: "convex-wasm-request-envelope-evidence-authority-v1",
    reportSha256: report.reportSha256,
    runtimeInputs: structuredClone(report.runtimeInputs),
    schemaVersion: 1,
    targets: {
      current: evidenceOutputIdentity(report.targets[targetName]),
      legacyWholeRequestRejector: evidenceOutputIdentity(
        report.legacyWholeRequestRejector.targets[targetName]
      ),
    },
    tools: structuredClone(report.tools),
  };
}

function approveMutatedReportFingerprint(authority, report) {
  return { ...structuredClone(authority), reportSha256: report.reportSha256 };
}

function validateMutatedReport(report, authority) {
  const changed = refingerprint(report);
  return createConvexWasmRequestEnvelopeInputFromMatrixReport(
    changed,
    approveMutatedReportFingerprint(authority, changed)
  );
}

function reportFixture() {
  const requestMatrix = renderConvexWasmRequestEnvelopeMatrix();
  const legacyWholeRequestRejector =
    renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector();
  const committedValueCodec = renderConvexWasmCommittedValueCodecMatrix();
  const inputHeader = fileIdentity(
    renderConvexWasmRequestEnvelopeInputHeader(requestMatrix.canonicalVectorsJson)
  );
  const opaqueAbiHeader = fileIdentity(renderOpaqueAbiHeader());
  const runtimeMain = fileIdentity(
    readFileSync(new URL("./convex-wasm-request-envelope-matrix-runtime-main.cpp", import.meta.url))
  );
  const runtimeInputs = runtimeInputsFixture();
  const runtimeContractHeader = fileIdentity(
    renderConvexWasmRequestEnvelopeRuntimeContractHeader()
  );
  const target = (matrix, envelope, seed) => ({
    artifact: artifactIdentity(seed),
    envelope,
    generatedC: artifactIdentity("6"),
    generatedObject: artifactIdentity("7"),
    generatedSource: fileIdentity(matrix.source),
    inputHeader,
    opaqueAbiHeader,
    runtimeInputs,
    runtimeMain,
    runtimeObject: artifactIdentity("8"),
    runtimeContractHeader,
  });
  const matrixResult = {
    canonicalRequestCount: 24,
    executionIdentity: requestMatrix.executionIdentity,
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
  const legacyResult = {
    executionIdentity: legacyWholeRequestRejector.executionIdentity,
    legacyWholeRequestRejection: {
      messageSha256: sha256("Error: Convex object field name uses a reserved prefix"),
      reasonCode: "reserved-object-field-prefix",
    },
    ok: true,
    scope: "request-envelope-legacy-control",
  };
  const targets = {
    [targetName]: target(requestMatrix, matrixResult, "9"),
  };
  const legacyTargets = {
    [targetName]: target(legacyWholeRequestRejector, legacyResult, "a"),
  };
  const payload = {
    committedValueCodec: {
      canonicalVectorCorpus: committedValueCodec.canonicalVectorCorpus,
      matrixKind: "convex-wasm-committed-value-codec-matrix-v1",
      sourceSha256: committedValueCodec.sourceSha256,
    },
    harness: {
      matrix: fileIdentity(
        readFileSync(new URL("./convex-wasm-request-envelope-matrix.mjs", import.meta.url))
      ),
      runnerExport: convexWasmRequestEnvelopeMatrixRunnerExport,
      runtimeMain,
      source: fileIdentity(
        readFileSync(new URL("../run-convex-wasm-request-envelope-matrix.mjs", import.meta.url))
      ),
    },
    kind: "convex-wasm-request-envelope-matrix-report-v4",
    legacyWholeRequestRejector: {
      executionIdentity: legacyWholeRequestRejector.executionIdentity,
      sourceSha256: legacyWholeRequestRejector.sourceSha256,
      targets: legacyTargets,
    },
    matrix: {
      capabilityRequestAbiVersion: convexWasmCapabilityRequestAbiVersion,
      canonicalNegativeControlsSha256: sha256(requestMatrix.canonicalNegativeControlsJson),
      canonicalRequestNegativeControlsSha256: sha256(
        requestMatrix.canonicalRequestNegativeControlsJson
      ),
      canonicalVectorCorpus: requestMatrix.canonicalVectorCorpus,
      canonicalVectorsSha256: sha256(requestMatrix.canonicalVectorsJson),
      inputHeader,
      kind: "convex-wasm-capability-request-envelope-matrix-v4",
      opaqueAbiHeader,
      requestEnvelopePreludeSha256: requestMatrix.requestEnvelopePreludeSha256,
      runtimeContractHeader,
      sourceSha256: requestMatrix.sourceSha256,
    },
    runtime: {
      arguments: convexWasmRequestEnvelopeMatrixRuntimeArguments,
      initialization: convexWasmRequestEnvelopeMatrixRuntimeInitialization,
      runnerExport: convexWasmRequestEnvelopeMatrixRunnerExport,
    },
    runtimeInputs,
    schemaVersion: 4,
    targets,
    tools: {
      emcc: artifactIdentity("b"),
      runner: artifactIdentity("c"),
      shermes: artifactIdentity("d"),
    },
  };
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

test("validates scoped request-envelope evidence and its integrity fingerprint", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-request-envelope-report-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const path = join(directory, "matrix-report.json");
  const report = reportFixture();
  const evidenceAuthority =
    createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReport(report);
  assert.deepEqual(evidenceAuthority, evidenceAuthorityFixture(report));
  await fs.writeFile(path, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });

  const loaded = await readConvexWasmRequestEnvelopeMatrixReport(path, evidenceAuthority);
  assert.deepEqual(loaded, report);
  assert.deepEqual(
    createConvexWasmRequestEnvelopeInputFromMatrixReport(loaded, evidenceAuthority),
    {
      capabilityRequestAbiVersion: convexWasmCapabilityRequestAbiVersion,
      canonicalVectorCorpus: report.matrix.canonicalVectorCorpus,
    }
  );
  assert.throws(
    () => createConvexWasmRequestEnvelopeInputFromMatrixReport(loaded),
    /evidence authority must be an object/u
  );

  for (const [index, field] of [
    "artifact",
    "generatedC",
    "generatedObject",
    "runtimeObject",
  ].entries()) {
    const fabricatedOutput = structuredClone(report);
    fabricatedOutput.targets[targetName][field] = artifactIdentity("0123456789abcdef"[index]);
    const refingerprintedFabrication = refingerprint(fabricatedOutput);
    assert.throws(
      () =>
        createConvexWasmRequestEnvelopeInputFromMatrixReport(
          refingerprintedFabrication,
          evidenceAuthority
        ),
      /not approved by the supplied evidence authority/u
    );
    assert.throws(
      () =>
        createConvexWasmRequestEnvelopeInputFromMatrixReport(
          refingerprintedFabrication,
          approveMutatedReportFingerprint(evidenceAuthority, refingerprintedFabrication)
        ),
      /target outputs are not approved/u
    );
  }

  const fabricatedLegacyOutput = structuredClone(report);
  fabricatedLegacyOutput.legacyWholeRequestRejector.targets[targetName].artifact =
    artifactIdentity("0");
  assert.throws(
    () => validateMutatedReport(fabricatedLegacyOutput, evidenceAuthority),
    /target outputs are not approved/u
  );

  const fabricatedRuntimeInputs = structuredClone(report);
  const changedRuntimeInputs = structuredClone(fabricatedRuntimeInputs.runtimeInputs);
  changedRuntimeInputs.wasmArchives.hermesVm = artifactIdentity("f");
  fabricatedRuntimeInputs.runtimeInputs = changedRuntimeInputs;
  fabricatedRuntimeInputs.targets[targetName].runtimeInputs = structuredClone(changedRuntimeInputs);
  fabricatedRuntimeInputs.legacyWholeRequestRejector.targets[targetName].runtimeInputs =
    structuredClone(changedRuntimeInputs);
  assert.throws(
    () => validateMutatedReport(fabricatedRuntimeInputs, evidenceAuthority),
    /tool or runtime inputs are not approved/u
  );

  const fabricatedTool = structuredClone(report);
  fabricatedTool.tools.emcc = artifactIdentity("0");
  assert.throws(
    () => validateMutatedReport(fabricatedTool, evidenceAuthority),
    /tool or runtime inputs are not approved/u
  );

  const staleOldReport = structuredClone(report);
  staleOldReport.kind = "convex-wasm-request-envelope-matrix-report-v1";
  staleOldReport.schemaVersion = 1;
  assert.throws(() => {
    const changed = refingerprint(staleOldReport);
    createConvexWasmRequestEnvelopeInputFromMatrixReport(
      changed,
      approveMutatedReportFingerprint(evidenceAuthority, changed)
    );
  }, /kind or schema version is unsupported/u);

  const unrefingerprintedCorpusDrift = structuredClone(report);
  unrefingerprintedCorpusDrift.matrix.canonicalVectorCorpus.sha256 = digest("5");
  await fs.writeFile(path, `${JSON.stringify(unrefingerprintedCorpusDrift, null, 2)}\n`);
  await assert.rejects(
    readConvexWasmRequestEnvelopeMatrixReport(path, evidenceAuthority),
    /integrity fingerprint/u
  );

  const arbitraryOneByteHarness = structuredClone(report);
  arbitraryOneByteHarness.harness.matrix = { bytes: 1, sha256: digest("a") };
  assert.throws(() => {
    const changed = refingerprint(arbitraryOneByteHarness);
    createConvexWasmRequestEnvelopeInputFromMatrixReport(
      changed,
      approveMutatedReportFingerprint(evidenceAuthority, changed)
    );
  }, /does not match the current input/u);

  const committedCodecDrift = structuredClone(report);
  committedCodecDrift.committedValueCodec.sourceSha256 = digest("6");
  assert.throws(
    () => validateMutatedReport(committedCodecDrift, evidenceAuthority),
    /does not match the current committed-value codec/u
  );

  const hostClaimDrift = structuredClone(report);
  hostClaimDrift.targets[targetName].envelope.productionHostDecoderExercised = true;
  assert.throws(
    () => validateMutatedReport(hostClaimDrift, evidenceAuthority),
    /envelope is invalid/u
  );

  const extraTarget = structuredClone(report);
  extraTarget.targets["static-hermes-native-optimized"] = structuredClone(
    extraTarget.targets[targetName]
  );
  assert.throws(
    () => validateMutatedReport(extraTarget, evidenceAuthority),
    /exactly the optimized Wasmtime target/u
  );

  const controlReasonDrift = structuredClone(report);
  controlReasonDrift.legacyWholeRequestRejector.targets[
    targetName
  ].envelope.legacyWholeRequestRejection.reasonCode = "allocation-failure";
  assert.throws(
    () => validateMutatedReport(controlReasonDrift, evidenceAuthority),
    /envelope is invalid/u
  );

  const controlSourceDrift = structuredClone(report);
  controlSourceDrift.legacyWholeRequestRejector.sourceSha256 = digest("8");
  assert.throws(
    () => validateMutatedReport(controlSourceDrift, evidenceAuthority),
    /does not match the current negative control/u
  );

  const staleLowering = structuredClone(report);
  staleLowering.matrix.sourceSha256 = digest("7");
  assert.throws(
    () => validateMutatedReport(staleLowering, evidenceAuthority),
    /does not match the current request-envelope lowering/u
  );

  const requestNegativeControlDrift = structuredClone(report);
  requestNegativeControlDrift.matrix.canonicalRequestNegativeControlsSha256 = digest("8");
  assert.throws(
    () => validateMutatedReport(requestNegativeControlDrift, evidenceAuthority),
    /does not match the current request-envelope lowering/u
  );

  const executedIdentityDrift = structuredClone(report);
  executedIdentityDrift.targets[targetName].envelope.executionIdentity.canonicalRequestCount = 13;
  assert.throws(
    () => validateMutatedReport(executedIdentityDrift, evidenceAuthority),
    /envelope is invalid/u
  );

  const generatedSourceDrift = structuredClone(report);
  generatedSourceDrift.targets[targetName].generatedSource = artifactIdentity("e");
  assert.throws(
    () => validateMutatedReport(generatedSourceDrift, evidenceAuthority),
    /generatedSource does not match the current input/u
  );

  const runtimeContractDrift = structuredClone(report);
  runtimeContractDrift.runtime.arguments = ["--gc-init-heap=8MiB"];
  assert.throws(
    () => validateMutatedReport(runtimeContractDrift, evidenceAuthority),
    /runtime contract/u
  );

  const runtimeContractHeaderDrift = structuredClone(report);
  runtimeContractHeaderDrift.matrix.runtimeContractHeader = artifactIdentity("0");
  runtimeContractHeaderDrift.targets[targetName].runtimeContractHeader = artifactIdentity("0");
  runtimeContractHeaderDrift.legacyWholeRequestRejector.targets[targetName].runtimeContractHeader =
    artifactIdentity("0");
  assert.throws(
    () => validateMutatedReport(runtimeContractHeaderDrift, evidenceAuthority),
    /runtimeContractHeader does not match the current input/u
  );

  const targetRuntimeInputDrift = structuredClone(report);
  targetRuntimeInputDrift.targets[targetName].runtimeInputs = structuredClone(
    targetRuntimeInputDrift.targets[targetName].runtimeInputs
  );
  targetRuntimeInputDrift.targets[targetName].runtimeInputs.wasmArchives.hermesVm =
    artifactIdentity("f");
  assert.throws(
    () => validateMutatedReport(targetRuntimeInputDrift, evidenceAuthority),
    /runtimeInputs do not match/u
  );

  await fs.writeFile(path, `${JSON.stringify(report)}\n`);
  await assert.rejects(
    readConvexWasmRequestEnvelopeMatrixReport(path, evidenceAuthority),
    /stable JSON format/u
  );
});

test("creates stable request-envelope evidence authority atomically without replacement", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-request-envelope-authority-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const reportPath = join(directory, "matrix-report.json");
  const outputPath = join(directory, "evidence-authority.json");
  const report = reportFixture();
  const reportSource = `${JSON.stringify(report, null, 2)}\n`;
  await fs.writeFile(reportPath, reportSource, { mode: 0o600 });

  assert.deepEqual(
    parseEvidenceAuthorityArguments(["--report", reportPath, "--output", outputPath]),
    { outputPath, reportPath }
  );
  const result = await createEvidenceAuthority(["--report", reportPath, "--output", outputPath]);
  const expected = evidenceAuthorityFixture(report);
  assert.deepEqual(result.authority, expected);
  assert.equal(result.authority.reportSha256, report.reportSha256);
  assert.notEqual(result.authority.reportSha256, sha256(reportSource));
  assert.equal(await fs.readFile(outputPath, "utf8"), `${JSON.stringify(expected, null, 2)}\n`);
  assert.equal((await fs.stat(outputPath)).mode & 0o777, 0o600);
  assert.deepEqual((await fs.readdir(directory)).sort(), [
    "evidence-authority.json",
    "matrix-report.json",
  ]);

  await assert.rejects(
    createEvidenceAuthority(["--report", reportPath, "--output", outputPath]),
    /output already exists/u
  );
  assert.equal(await fs.readFile(outputPath, "utf8"), `${JSON.stringify(expected, null, 2)}\n`);
  assert.deepEqual((await fs.readdir(directory)).sort(), [
    "evidence-authority.json",
    "matrix-report.json",
  ]);

  const tamperedReport = structuredClone(report);
  tamperedReport.tools.runner = artifactIdentity("f");
  await fs.writeFile(reportPath, `${JSON.stringify(tamperedReport, null, 2)}\n`);
  await assert.rejects(
    createEvidenceAuthority([
      "--report",
      reportPath,
      "--output",
      join(directory, "tampered-authority.json"),
    ]),
    /integrity fingerprint/u
  );
  await assert.rejects(fs.access(join(directory, "tampered-authority.json")));

  await fs.writeFile(reportPath, `${JSON.stringify(report)}\n`);
  await assert.rejects(
    createEvidenceAuthority([
      "--report",
      reportPath,
      "--output",
      join(directory, "compact-authority.json"),
    ]),
    /stable JSON format/u
  );
  await assert.rejects(fs.access(join(directory, "compact-authority.json")));

  const linkedReportPath = join(directory, "linked-report.json");
  await fs.symlink(reportPath, linkedReportPath);
  await assert.rejects(
    createEvidenceAuthority([
      "--report",
      linkedReportPath,
      "--output",
      join(directory, "linked-authority.json"),
    ]),
    /current-user-owned canonical bounded 0600 file/u
  );
  await assert.rejects(fs.access(join(directory, "linked-authority.json")));

  const oversizedReportPath = join(directory, "oversized-report.json");
  await fs.writeFile(oversizedReportPath, "{}\n", { mode: 0o600 });
  await fs.truncate(oversizedReportPath, 64 * 1024 * 1024 + 1);
  await assert.rejects(
    createEvidenceAuthority([
      "--report",
      oversizedReportPath,
      "--output",
      join(directory, "oversized-authority.json"),
    ]),
    /current-user-owned canonical bounded 0600 file/u
  );
  await assert.rejects(fs.access(join(directory, "oversized-authority.json")));
});
