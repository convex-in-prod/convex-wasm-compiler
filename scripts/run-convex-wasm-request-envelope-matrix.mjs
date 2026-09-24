#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import { fingerprintJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  assertConvexWasmRequestEnvelopeLegacyWholeRequestReport,
  assertConvexWasmRequestEnvelopeMatrixReport,
  convexWasmCapabilityRequestAbiVersion,
  convexWasmRequestEnvelopeMatrixKind,
  convexWasmRequestEnvelopeMatrixRunnerExport,
  convexWasmRequestEnvelopeMatrixRuntimeArguments,
  convexWasmRequestEnvelopeMatrixRuntimeInitialization,
  convexWasmRequestEnvelopeMatrixTarget,
  renderConvexWasmRequestEnvelopeMatrix,
  renderConvexWasmRequestEnvelopeInputHeader,
  renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector,
  renderConvexWasmRequestEnvelopeRuntimeContractHeader,
} from "./lib/convex-wasm-request-envelope-matrix.mjs";
import {
  convexWasmCommittedValueCodecMatrixKind,
  renderConvexWasmCommittedValueCodecMatrix,
} from "./lib/convex-wasm-committed-value-codec-matrix.mjs";
import { renderOpaqueAbiHeader } from "./lib/convex-wasm-lowering.mjs";

const kind = "convex-wasm-request-envelope-matrix-report-v4";
const runnerExport = convexWasmRequestEnvelopeMatrixRunnerExport;
const target = convexWasmRequestEnvelopeMatrixTarget;
const unitExport = "sh_export_convex_wasm_request_envelope_matrix_optimized";
const runtimeArguments = convexWasmRequestEnvelopeMatrixRuntimeArguments;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function parseArguments(argumentsList) {
  const supported = new Set([
    "--emcc",
    "--hermes-source",
    "--output",
    "--runner",
    "--shermes",
    "--wasm-build",
  ]);
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!supported.has(option) || value === undefined || values.has(option)) {
      throw new Error("invalid request-envelope matrix arguments");
    }
    values.set(option, value);
  }
  for (const option of supported) {
    if (!values.has(option)) throw new Error(`missing required option ${option}`);
  }
  return {
    emccPath: resolve(values.get("--emcc")),
    hermesSourcePath: resolve(values.get("--hermes-source")),
    outputPath: resolve(values.get("--output")),
    runnerPath: resolve(values.get("--runner")),
    shermesPath: resolve(values.get("--shermes")),
    wasmBuildPath: resolve(values.get("--wasm-build")),
  };
}

function run(executable, argumentsList, options = {}) {
  const result = spawnSync(executable, argumentsList, {
    cwd: options.cwd,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error !== undefined) {
    throw new Error(`failed to start ${basename(executable)}`, { cause: result.error });
  }
  if (result.status !== 0) {
    let matrixFailure = "";
    try {
      const report = JSON.parse(result.stdout.toString("utf8"));
      if (
        report !== null &&
        typeof report === "object" &&
        typeof report.failureStage === "string" &&
        typeof report.error === "string"
      ) {
        matrixFailure = ` (${report.failureStage}) ${report.error.slice(0, 512)}`;
      }
    } catch {
      // Compiler, linker, and signal failures do not use the matrix report format.
    }
    const termination =
      result.status === null
        ? `signal ${result.signal ?? "unknown"}`
        : `status ${String(result.status)}`;
    throw new Error(
      `${basename(executable)} failed with ${termination}${matrixFailure}: ${result.stderr.toString().trim()}`
    );
  }
  return result.stdout;
}

async function fileIdentity(path) {
  const bytes = await fs.readFile(path);
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

async function requireFile(path, description) {
  try {
    const stats = await fs.stat(path);
    if (!stats.isFile()) throw new Error(`${description} is not a file`);
  } catch (error) {
    throw new Error(`${description} is unavailable at ${path}`, { cause: error });
  }
}

async function compileWasmtimeTarget({
  emccPath,
  generatedCPath,
  generatedSourcePath,
  hermesSourcePath,
  inputHeaderPath,
  legacyWholeRequestRejector,
  opaqueAbiHeaderPath,
  runnerPath,
  runtimeContractHeaderPath,
  runtimeMainPath,
  temporaryDirectory,
  wasmBuildPath,
}) {
  const generatedObjectPath = resolve(temporaryDirectory, `${target}.generated.o`);
  const runtimeObjectPath = resolve(temporaryDirectory, `${target}.runtime.o`);
  const wasmPath = resolve(temporaryDirectory, `${target}.wasm`);
  const includes = [
    `-I${temporaryDirectory}`,
    `-I${resolve(wasmBuildPath, "lib/config")}`,
    `-I${resolve(hermesSourcePath, "include")}`,
    `-I${resolve(hermesSourcePath, "API/jsi")}`,
  ];
  const objectFlags = [
    "-O2",
    "-DNDEBUG",
    "-fno-strict-aliasing",
    "-fno-strict-overflow",
    "-fwasm-exceptions",
    "-sWASM_LEGACY_EXCEPTIONS=0",
    ...includes,
  ];
  run(emccPath, ["-c", generatedCPath, "-o", generatedObjectPath, ...objectFlags]);
  run(emccPath, [
    "-c",
    runtimeMainPath,
    "-o",
    runtimeObjectPath,
    `-DCONVEX_WASM_REQUEST_ENVELOPE_MATRIX_EXPORTED_UNIT=${unitExport}`,
    ...(legacyWholeRequestRejector
      ? ["-DCONVEX_WASM_REQUEST_ENVELOPE_MATRIX_LEGACY_WHOLE_REQUEST_REJECTOR"]
      : []),
    ...objectFlags,
  ]);
  const archives = [
    resolve(wasmBuildPath, "lib/libhermesvm_a.a"),
    resolve(wasmBuildPath, "jsi/libjsi.a"),
  ];
  const hermesHeaders = {
    jsi: resolve(hermesSourcePath, "API/jsi/jsi/jsi.h"),
    staticHermes: resolve(hermesSourcePath, "include/hermes/VM/static_h.h"),
  };
  const wasmConfigHeader = resolve(wasmBuildPath, "lib/config/libhermesvm-config.h");
  await Promise.all([
    ...archives.map((path) => requireFile(path, "Static Hermes Wasm archive")),
    ...Object.values(hermesHeaders).map((path) =>
      requireFile(path, "Static Hermes runtime header")
    ),
    requireFile(wasmConfigHeader, "Static Hermes Wasm configuration header"),
  ]);
  run(emccPath, [
    generatedObjectPath,
    runtimeObjectPath,
    ...archives,
    "-o",
    wasmPath,
    "-O2",
    "--profiling-funcs",
    "--no-entry",
    "-fwasm-exceptions",
    "-sWASM_LEGACY_EXCEPTIONS=0",
    "-sSUPPORT_LONGJMP=wasm",
    "-sSTANDALONE_WASM=1",
    "-sALLOW_MEMORY_GROWTH=1",
    "-sSTACK_SIZE=2MB",
    `-Wl,--export=${runnerExport}`,
  ]);
  const envelope = JSON.parse(run(runnerPath, [wasmPath, runnerExport]).toString("utf8"));
  if (legacyWholeRequestRejector) {
    assertConvexWasmRequestEnvelopeLegacyWholeRequestReport(envelope);
  } else {
    assertConvexWasmRequestEnvelopeMatrixReport(envelope);
  }
  const runtimeInputs = Object.freeze({
    hermesHeaders: {
      jsi: await fileIdentity(hermesHeaders.jsi),
      staticHermes: await fileIdentity(hermesHeaders.staticHermes),
    },
    wasmArchives: {
      hermesVm: await fileIdentity(archives[0]),
      jsi: await fileIdentity(archives[1]),
    },
    wasmConfigHeader: await fileIdentity(wasmConfigHeader),
  });
  return Object.freeze({
    artifact: await fileIdentity(wasmPath),
    envelope,
    generatedC: await fileIdentity(generatedCPath),
    generatedObject: await fileIdentity(generatedObjectPath),
    generatedSource: await fileIdentity(generatedSourcePath),
    inputHeader: await fileIdentity(inputHeaderPath),
    opaqueAbiHeader: await fileIdentity(opaqueAbiHeaderPath),
    runtimeContractHeader: await fileIdentity(runtimeContractHeaderPath),
    runtimeInputs,
    runtimeMain: await fileIdentity(runtimeMainPath),
    runtimeObject: await fileIdentity(runtimeObjectPath),
  });
}

export async function runConvexWasmRequestEnvelopeMatrix(options) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const runtimeMainPath = resolve(
    repositoryRoot,
    "scripts/lib/convex-wasm-request-envelope-matrix-runtime-main.cpp"
  );
  const matrixPath = resolve(repositoryRoot, "scripts/lib/convex-wasm-request-envelope-matrix.mjs");
  const harnessPath = resolve(
    repositoryRoot,
    "scripts/run-convex-wasm-request-envelope-matrix.mjs"
  );
  await Promise.all([
    requireFile(options.emccPath, "Emscripten compiler"),
    requireFile(options.runnerPath, "Wasmtime runner"),
    requireFile(options.shermesPath, "Static Hermes compiler"),
    requireFile(runtimeMainPath, "request-envelope matrix runtime"),
  ]);
  const rendered = renderConvexWasmRequestEnvelopeMatrix();
  const legacyWholeRequestRejector =
    renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector();
  const committedValueCodec = renderConvexWasmCommittedValueCodecMatrix();
  const opaqueAbiHeader = renderOpaqueAbiHeader();
  const inputHeader = renderConvexWasmRequestEnvelopeInputHeader(rendered.canonicalVectorsJson);
  const runtimeContractHeader = renderConvexWasmRequestEnvelopeRuntimeContractHeader();
  const temporaryDirectory = await fs.mkdtemp(
    resolve(tmpdir(), "convex-wasm-request-envelope-matrix-")
  );
  try {
    const sourcePath = resolve(temporaryDirectory, "matrix.js");
    const legacySourcePath = resolve(temporaryDirectory, "matrix-legacy-whole-request.js");
    const opaqueAbiHeaderPath = resolve(temporaryDirectory, "convex_wasm_opaque_abi_v3.h");
    const inputHeaderPath = resolve(
      temporaryDirectory,
      "convex_wasm_request_envelope_matrix_input.h"
    );
    const runtimeContractHeaderPath = resolve(
      temporaryDirectory,
      "convex_wasm_request_envelope_matrix_runtime_contract.h"
    );
    await Promise.all([
      fs.writeFile(sourcePath, rendered.source, { mode: 0o600 }),
      fs.writeFile(legacySourcePath, legacyWholeRequestRejector.source, { mode: 0o600 }),
      fs.writeFile(opaqueAbiHeaderPath, opaqueAbiHeader, { mode: 0o600 }),
      fs.writeFile(inputHeaderPath, inputHeader, { mode: 0o600 }),
      fs.writeFile(runtimeContractHeaderPath, runtimeContractHeader, { mode: 0o600 }),
    ]);
    const generatedCPath = resolve(temporaryDirectory, "matrix-optimized.c");
    const legacyGeneratedCPath = resolve(
      temporaryDirectory,
      "matrix-legacy-whole-request-optimized.c"
    );
    run(options.shermesPath, [
      "-typed",
      "-O",
      "-Xenable-tdz",
      "-emit-c",
      "-exported-unit=convex_wasm_request_envelope_matrix_optimized",
      sourcePath,
      "-o",
      generatedCPath,
    ]);
    const targets = {
      [target]: await compileWasmtimeTarget({
        emccPath: options.emccPath,
        generatedCPath,
        generatedSourcePath: sourcePath,
        hermesSourcePath: options.hermesSourcePath,
        inputHeaderPath,
        legacyWholeRequestRejector: false,
        opaqueAbiHeaderPath,
        runnerPath: options.runnerPath,
        runtimeContractHeaderPath,
        runtimeMainPath,
        temporaryDirectory,
        wasmBuildPath: options.wasmBuildPath,
      }),
    };
    run(options.shermesPath, [
      "-typed",
      "-O",
      "-Xenable-tdz",
      "-emit-c",
      "-exported-unit=convex_wasm_request_envelope_matrix_optimized",
      legacySourcePath,
      "-o",
      legacyGeneratedCPath,
    ]);
    const legacyTargets = {
      [target]: await compileWasmtimeTarget({
        emccPath: options.emccPath,
        generatedCPath: legacyGeneratedCPath,
        generatedSourcePath: legacySourcePath,
        hermesSourcePath: options.hermesSourcePath,
        inputHeaderPath,
        legacyWholeRequestRejector: true,
        opaqueAbiHeaderPath,
        runnerPath: options.runnerPath,
        runtimeContractHeaderPath,
        runtimeMainPath,
        temporaryDirectory,
        wasmBuildPath: options.wasmBuildPath,
      }),
    };
    const payload = {
      committedValueCodec: {
        canonicalVectorCorpus: committedValueCodec.canonicalVectorCorpus,
        matrixKind: convexWasmCommittedValueCodecMatrixKind,
        sourceSha256: committedValueCodec.sourceSha256,
      },
      harness: {
        matrix: await fileIdentity(matrixPath),
        runtimeMain: await fileIdentity(runtimeMainPath),
        runnerExport,
        source: await fileIdentity(harnessPath),
      },
      kind,
      legacyWholeRequestRejector: {
        executionIdentity: legacyWholeRequestRejector.executionIdentity,
        sourceSha256: legacyWholeRequestRejector.sourceSha256,
        targets: legacyTargets,
      },
      matrix: {
        capabilityRequestAbiVersion: convexWasmCapabilityRequestAbiVersion,
        canonicalNegativeControlsSha256: sha256(rendered.canonicalNegativeControlsJson),
        canonicalRequestNegativeControlsSha256: sha256(
          rendered.canonicalRequestNegativeControlsJson
        ),
        canonicalVectorsSha256: sha256(rendered.canonicalVectorsJson),
        canonicalVectorCorpus: rendered.canonicalVectorCorpus,
        inputHeader: { bytes: Buffer.byteLength(inputHeader), sha256: sha256(inputHeader) },
        kind: convexWasmRequestEnvelopeMatrixKind,
        opaqueAbiHeader: {
          bytes: Buffer.byteLength(opaqueAbiHeader),
          sha256: sha256(opaqueAbiHeader),
        },
        requestEnvelopePreludeSha256: rendered.requestEnvelopePreludeSha256,
        runtimeContractHeader: {
          bytes: Buffer.byteLength(runtimeContractHeader),
          sha256: sha256(runtimeContractHeader),
        },
        sourceSha256: rendered.sourceSha256,
      },
      runtime: {
        arguments: runtimeArguments,
        initialization: convexWasmRequestEnvelopeMatrixRuntimeInitialization,
        runnerExport,
      },
      runtimeInputs: targets[target].runtimeInputs,
      schemaVersion: 4,
      targets,
      tools: {
        emcc: await fileIdentity(options.emccPath),
        runner: await fileIdentity(options.runnerPath),
        shermes: await fileIdentity(options.shermesPath),
      },
    };
    return Object.freeze({ ...payload, reportSha256: fingerprintJson(payload) });
  } finally {
    await fs.rm(temporaryDirectory, { force: true, recursive: true });
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const options = parseArguments(process.argv.slice(2));
  const report = await runConvexWasmRequestEnvelopeMatrix(options);
  await fs.mkdir(dirname(options.outputPath), { mode: 0o700, recursive: true });
  await fs.writeFile(options.outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(
    `${JSON.stringify({ output: options.outputPath, reportSha256: report.reportSha256 })}\n`
  );
}
