import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fingerprintJson } from "../../lib/convex-wasm-artifact-contract.mjs";
import { renderConvexWasmCommittedValueCodecMatrix } from "../../lib/convex-wasm-committed-value-codec-matrix.mjs";
import {
  convexWasmCapabilityRequestAbiVersion,
  convexWasmRequestEnvelopeMatrixRunnerExport,
  convexWasmRequestEnvelopeMatrixRuntimeArguments,
  convexWasmRequestEnvelopeMatrixRuntimeInitialization,
  renderConvexWasmRequestEnvelopeInputHeader,
  renderConvexWasmRequestEnvelopeMatrix,
  renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector,
  renderConvexWasmRequestEnvelopeRuntimeContractHeader,
} from "../../lib/convex-wasm-request-envelope-matrix.mjs";
import { renderOpaqueAbiHeader } from "../../lib/convex-wasm-lowering.mjs";

// Synthetic outputs for report-validator and consumer-adapter tests. This fixture
// is not native execution evidence and must never authorize an artifact build.
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
      icu: artifactIdentity("6"),
    },
    wasmConfigHeader: artifactIdentity("5"),
  };
}

function evidenceOutputIdentity(target) {
  return {
    artifact: target.artifact,
    generatedC: target.generatedC,
    generatedObject: target.generatedObject,
    runtimeObject: target.runtimeObject,
  };
}

export function requestEnvelopeEvidenceAuthorityFixture(report) {
  return {
    kind: "convex-wasm-request-envelope-evidence-authority-v2",
    reportSha256: report.reportSha256,
    runtimeInputs: structuredClone(report.runtimeInputs),
    schemaVersion: 2,
    targets: {
      current: evidenceOutputIdentity(report.targets[targetName]),
      legacyWholeRequestRejector: evidenceOutputIdentity(
        report.legacyWholeRequestRejector.targets[targetName]
      ),
    },
    tools: structuredClone(report.tools),
  };
}

export function requestEnvelopeMatrixReportFixture() {
  const requestMatrix = renderConvexWasmRequestEnvelopeMatrix();
  const legacyWholeRequestRejector =
    renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector();
  const committedValueCodec = renderConvexWasmCommittedValueCodecMatrix();
  const inputHeader = fileIdentity(
    renderConvexWasmRequestEnvelopeInputHeader(requestMatrix.canonicalVectorsJson)
  );
  const opaqueAbiHeader = fileIdentity(renderOpaqueAbiHeader());
  const runtimeMain = fileIdentity(
    readFileSync(new URL("../../lib/convex-wasm-request-envelope-matrix-runtime-main.cpp", import.meta.url))
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
        readFileSync(new URL("../../lib/convex-wasm-request-envelope-matrix.mjs", import.meta.url))
      ),
      runnerExport: convexWasmRequestEnvelopeMatrixRunnerExport,
      runtimeMain,
      source: fileIdentity(
        readFileSync(new URL("../../run-convex-wasm-request-envelope-matrix.mjs", import.meta.url))
      ),
    },
    kind: "convex-wasm-request-envelope-matrix-report-v5",
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
    schemaVersion: 5,
    targets,
    tools: {
      emcc: artifactIdentity("b"),
      runner: artifactIdentity("c"),
      shermes: artifactIdentity("d"),
    },
  };
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

