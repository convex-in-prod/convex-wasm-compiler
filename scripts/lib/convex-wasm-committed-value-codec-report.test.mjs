import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  createConvexWasmValueCodecInputFromMatrixReport,
  readConvexWasmValueCodecMatrixReport,
} from "./convex-wasm-committed-value-codec-report.mjs";
import { renderConvexWasmCommittedValueCodecMatrix } from "./convex-wasm-committed-value-codec-matrix.mjs";

const digest = (character) => character.repeat(64);
const targetNames = [
  "static-hermes-native-optimized",
  "static-hermes-native-unoptimized",
  "static-hermes-wasmtime-optimized",
  "static-hermes-wasmtime-unoptimized",
];
const matrixResult = Object.freeze({
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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function fileIdentity(seed) {
  return { bytes: 1, sha256: digest(seed) };
}

function fixtureSeed(index) {
  return "0123456789abcdef"[index % 16];
}

function legacyIntegerRejection(targetName) {
  return {
    exitStatus: targetName.includes("wasmtime") ? 1 : 3,
    reportOk: false,
    stage: "guest-value-boundary",
  };
}

function refingerprint(report) {
  const { reportSha256: _reportSha256, ...payload } = report;
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

function reportFixture() {
  const renderedMatrix = renderConvexWasmCommittedValueCodecMatrix();
  const targets = Object.fromEntries(
    targetNames.map((name, index) => [
      name,
      {
        artifact: fileIdentity(fixtureSeed(index)),
        codec: matrixResult,
        generatedObject: fileIdentity(fixtureSeed(index + 4)),
        runtimeObject: fileIdentity(fixtureSeed(index + 8)),
      },
    ])
  );
  const legacyIntegerRejectorTargets = Object.fromEntries(
    targetNames.map((name, index) => [
      name,
      {
        artifact: fileIdentity(fixtureSeed(index + 12)),
        generatedObject: fileIdentity(fixtureSeed(index + 16)),
        legacyIntegerRejection: legacyIntegerRejection(name),
        runtimeObject: fileIdentity(fixtureSeed(index + 20)),
      },
    ])
  );
  const payload = {
    harness: {
      matrix: fileIdentity("c"),
      runnerExport: "convex_wasm_committed_value_codec_matrix",
      runtimeMain: fileIdentity("d"),
      source: fileIdentity("e"),
    },
    kind: "convex-wasm-committed-value-codec-matrix-report-v1",
    legacyIntegerRejector: {
      sourceSha256: digest("f"),
      targets: legacyIntegerRejectorTargets,
    },
    matrix: {
      canonicalInputSha256: sha256(renderedMatrix.canonicalInputJson),
      canonicalOutputSha256: sha256(renderedMatrix.canonicalOutputJson),
      canonicalVectorCorpus: renderedMatrix.canonicalVectorCorpus,
      inputHeader: fileIdentity("3"),
      kind: "convex-wasm-committed-value-codec-matrix-v1",
      largeByteLength: 196_609,
      opaqueAbiHeader: fileIdentity("4"),
      sourceSha256: renderedMatrix.sourceSha256,
    },
    runtime: {
      arguments: ["--fixture"],
      initialization: "_sh_init",
      runnerExport: "convex_wasm_committed_value_codec_matrix",
    },
    schemaVersion: 1,
    targets,
    tools: {
      cxx: fileIdentity("6"),
      emcc: fileIdentity("7"),
      runner: fileIdentity("8"),
      shermes: fileIdentity("9"),
    },
  };
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

test("reads a fingerprinted matrix report and rejects identity drift", async (t) => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-codec-report-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  const path = join(directory, "matrix-report.json");
  const report = reportFixture();
  await fs.writeFile(path, `${JSON.stringify(report, null, 2)}\n`);

  const loaded = await readConvexWasmValueCodecMatrixReport(path);
  assert.deepEqual(loaded, report);
  assert.deepEqual(createConvexWasmValueCodecInputFromMatrixReport(loaded), {
    canonicalVectorCorpus: report.matrix.canonicalVectorCorpus,
  });

  const corpusDrift = structuredClone(report);
  corpusDrift.matrix.canonicalVectorCorpus.sha256 = digest("c");
  await fs.writeFile(path, `${JSON.stringify(corpusDrift, null, 2)}\n`);
  await assert.rejects(readConvexWasmValueCodecMatrixReport(path), /does not authenticate/u);

  const provenanceDrift = structuredClone(report);
  provenanceDrift.targets["static-hermes-native-optimized"].artifact.sha256 = digest("d");
  await fs.writeFile(path, `${JSON.stringify(provenanceDrift, null, 2)}\n`);
  await assert.rejects(readConvexWasmValueCodecMatrixReport(path), /does not authenticate/u);

  const wrapperStatusDrift = structuredClone(report);
  wrapperStatusDrift.legacyIntegerRejector.targets[
    "static-hermes-wasmtime-optimized"
  ].legacyIntegerRejection.exitStatus = 3;
  assert.throws(
    () => createConvexWasmValueCodecInputFromMatrixReport(refingerprint(wrapperStatusDrift)),
    /legacyIntegerRejection is invalid/u
  );

  const guestReportDrift = structuredClone(report);
  guestReportDrift.legacyIntegerRejector.targets[
    "static-hermes-native-optimized"
  ].legacyIntegerRejection.stage = "runtime";
  assert.throws(
    () => createConvexWasmValueCodecInputFromMatrixReport(refingerprint(guestReportDrift)),
    /legacyIntegerRejection is invalid/u
  );

  const staleLoweringReport = structuredClone(report);
  staleLoweringReport.matrix.sourceSha256 = digest("e");
  assert.throws(
    () => createConvexWasmValueCodecInputFromMatrixReport(refingerprint(staleLoweringReport)),
    /does not match the current committed-value codec lowering/u
  );

  await fs.writeFile(path, `${JSON.stringify(report)}\n`);
  await assert.rejects(readConvexWasmValueCodecMatrixReport(path), /stable JSON format/u);

  const linkedPath = join(directory, "linked-report.json");
  await fs.symlink(path, linkedPath);
  await assert.rejects(
    readConvexWasmValueCodecMatrixReport(linkedPath),
    /current-user-owned canonical bounded regular file/u
  );

  const oversizedPath = join(directory, "oversized-report.json");
  await fs.writeFile(oversizedPath, "{}\n");
  await fs.truncate(oversizedPath, 64 * 1024 * 1024 + 1);
  await assert.rejects(
    readConvexWasmValueCodecMatrixReport(oversizedPath),
    /current-user-owned canonical bounded regular file/u
  );
});
