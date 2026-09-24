#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import { fingerprintJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  assertConvexWasmCommittedValueCodecMatrixReport,
  convexWasmCommittedValueCodecMatrixKind,
  renderConvexWasmCommittedValueCodecMatrix,
  renderConvexWasmCommittedValueCodecMatrixLegacyIntegerRejector,
} from "./lib/convex-wasm-committed-value-codec-matrix.mjs";
import { renderOpaqueAbiHeader } from "./lib/convex-wasm-lowering.mjs";

const kind = "convex-wasm-committed-value-codec-matrix-report-v1";
const runnerExport = "convex_wasm_committed_value_codec_matrix_run";
const runtimeArguments = Object.freeze([
  "--gc-init-heap=4MiB",
  "--gc-max-heap=32MiB",
  "--gc-alloc-young=true",
  "--gc-revert-to-yg-at-tti=false",
  "--max-register-stack=16384",
]);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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

function renderInputHeader(requestValue, expectedValue) {
  return `#ifndef CONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_INPUT_H
#define CONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_INPUT_H

${renderInputArray("convex_wasm_committed_value_codec_matrix_request", requestValue)}
${renderInputArray("convex_wasm_committed_value_codec_matrix_expected", expectedValue)}

#endif
`;
}

export function parseArguments(argumentsList) {
  const supported = new Set([
    "--cxx",
    "--emcc",
    "--hermes-source",
    "--host-build",
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
      throw new Error("invalid committed-value codec matrix arguments");
    }
    values.set(option, value);
  }
  for (const option of supported) {
    if (!values.has(option)) {
      throw new Error(`missing required option ${option}`);
    }
  }
  return {
    cxxPath: resolve(values.get("--cxx")),
    emccPath: resolve(values.get("--emcc")),
    hermesSourcePath: resolve(values.get("--hermes-source")),
    hostBuildPath: resolve(values.get("--host-build")),
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
    let matrixFailureStage = "";
    let matrixFailureMessage = "";
    try {
      const report = JSON.parse(result.stdout.toString("utf8"));
      if (
        report !== null &&
        typeof report === "object" &&
        typeof report.failureStage === "string"
      ) {
        matrixFailureStage = ` (${report.failureStage})`;
      }
      if (
        report !== null &&
        typeof report === "object" &&
        typeof report.error === "string" &&
        report.error.startsWith("Error: Committed-value codec matrix failed: ")
      ) {
        matrixFailureMessage = ` ${report.error}`;
      }
    } catch {
      // Compiler and linker failures do not use the matrix report format.
    }
    throw new Error(
      `${basename(executable)} failed with status ${String(result.status)}${matrixFailureStage}:${matrixFailureMessage} ${result.stderr.toString().trim()}`
    );
  }
  return result.stdout;
}

function observeExpectedIntegerRejection(executable, argumentsList, expectedExitStatus) {
  const result = spawnSync(executable, argumentsList, {
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error !== undefined) {
    throw new Error(`failed to start ${basename(executable)}`, { cause: result.error });
  }
  if (result.status !== expectedExitStatus) {
    throw new Error(
      `${basename(executable)} did not fail at the guest-value boundary: ${String(result.status)}`
    );
  }
  const report = JSON.parse(result.stdout.toString("utf8"));
  if (
    report === null ||
    typeof report !== "object" ||
    report.ok !== false ||
    report.failureStage !== "inbound-request" ||
    report.error !==
      "Error: guest-native integer values are not supported by this Static Hermes target"
  ) {
    throw new Error("former integer rejection did not produce the required boundary failure");
  }
  return Object.freeze({
    exitStatus: expectedExitStatus,
    reportOk: false,
    stage: "guest-value-boundary",
  });
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

async function hostBoostContextArchive(hostBuildPath) {
  const boostRoot = resolve(hostBuildPath, "external/boost");
  let versionDirectories;
  try {
    versionDirectories = await fs.readdir(boostRoot, { withFileTypes: true });
  } catch (error) {
    throw new Error("Static Hermes host build omitted Boost context", { cause: error });
  }
  const candidates = versionDirectories
    .filter((entry) => entry.isDirectory())
    .map((entry) => resolve(boostRoot, entry.name, "libs/context/libboost_context.a"));
  const available = [];
  for (const candidate of candidates) {
    try {
      const stats = await fs.stat(candidate);
      if (stats.isFile()) available.push(candidate);
    } catch {
      // This Boost version does not provide the required archive.
    }
  }
  if (available.length !== 1) {
    throw new Error("Static Hermes host build must provide exactly one Boost context archive");
  }
  return available[0];
}

function targetName(runtime, optimization) {
  return `static-hermes-${runtime}-${optimization}`;
}

function unitExportName(optimization) {
  return `sh_export_convex_wasm_committed_value_codec_matrix_${optimization}`;
}

async function compileNativeTarget({
  cxxPath,
  generatedCPath,
  hermesSourcePath,
  hostBuildPath,
  optimization,
  expectedIntegerRejection,
  runtimeMainPath,
  temporaryDirectory,
}) {
  const target = targetName("native", optimization);
  const generatedObjectPath = resolve(temporaryDirectory, `${target}.generated.o`);
  const runtimeObjectPath = resolve(temporaryDirectory, `${target}.runtime.o`);
  const executablePath = resolve(temporaryDirectory, target);
  const includes = [
    `-I${temporaryDirectory}`,
    `-I${resolve(hostBuildPath, "lib/config")}`,
    `-I${resolve(hermesSourcePath, "include")}`,
    `-I${resolve(hermesSourcePath, "API/jsi")}`,
  ];
  const objectFlags = [
    "-O2",
    "-DNDEBUG",
    "-fno-strict-aliasing",
    "-fno-strict-overflow",
    "-ffunction-sections",
    "-fdata-sections",
    ...includes,
  ];
  run(cxxPath, ["-x", "c", "-c", generatedCPath, "-o", generatedObjectPath, ...objectFlags]);
  run(cxxPath, [
    "-std=c++17",
    "-c",
    runtimeMainPath,
    "-o",
    runtimeObjectPath,
    `-DCONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_EXPORTED_UNIT=${unitExportName(optimization)}`,
    "-DCONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_HOST_MAIN",
    ...objectFlags,
  ]);
  const archives = [
    resolve(hostBuildPath, "lib/libhermesvm_a.a"),
    resolve(hostBuildPath, "lib/VM/libhermesVMRuntime.a"),
    resolve(hostBuildPath, "API/hermes/libhermesapi.a"),
    resolve(hostBuildPath, "public/hermes/Public/libhermesPublic.a"),
    await hostBoostContextArchive(hostBuildPath),
    resolve(hostBuildPath, "jsi/libjsi.a"),
  ];
  await Promise.all(archives.map((path) => requireFile(path, "Static Hermes host archive")));
  run(cxxPath, [
    generatedObjectPath,
    runtimeObjectPath,
    ...archives,
    "-licuuc",
    "-licui18n",
    "-licudata",
    "-Wl,--gc-sections",
    "-o",
    executablePath,
  ]);
  const observation = expectedIntegerRejection
    ? observeExpectedIntegerRejection(executablePath, [], 3)
    : null;
  const report = observation === null ? JSON.parse(run(executablePath, []).toString("utf8")) : null;
  if (report !== null) assertConvexWasmCommittedValueCodecMatrixReport(report);
  return Object.freeze({
    artifact: await fileIdentity(executablePath),
    ...(observation === null ? { codec: report } : { legacyIntegerRejection: observation }),
    generatedObject: await fileIdentity(generatedObjectPath),
    runtimeObject: await fileIdentity(runtimeObjectPath),
  });
}

async function compileWasmtimeTarget({
  emccPath,
  generatedCPath,
  hermesSourcePath,
  optimization,
  expectedIntegerRejection,
  runnerPath,
  runtimeMainPath,
  temporaryDirectory,
  wasmBuildPath,
}) {
  const target = targetName("wasmtime", optimization);
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
    `-DCONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_EXPORTED_UNIT=${unitExportName(optimization)}`,
    ...objectFlags,
  ]);
  const archives = [
    resolve(wasmBuildPath, "lib/libhermesvm_a.a"),
    resolve(wasmBuildPath, "jsi/libjsi.a"),
  ];
  await Promise.all(archives.map((path) => requireFile(path, "Static Hermes Wasm archive")));
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
  const observation = expectedIntegerRejection
    ? observeExpectedIntegerRejection(runnerPath, [wasmPath, runnerExport], 1)
    : null;
  const report =
    observation === null
      ? JSON.parse(run(runnerPath, [wasmPath, runnerExport]).toString("utf8"))
      : null;
  if (report !== null) assertConvexWasmCommittedValueCodecMatrixReport(report);
  return Object.freeze({
    artifact: await fileIdentity(wasmPath),
    ...(observation === null ? { codec: report } : { legacyIntegerRejection: observation }),
    generatedObject: await fileIdentity(generatedObjectPath),
    runtimeObject: await fileIdentity(runtimeObjectPath),
  });
}

export async function runConvexWasmCommittedValueCodecMatrix(options) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const runtimeMainPath = resolve(
    repositoryRoot,
    "scripts/lib/convex-wasm-committed-value-codec-matrix-runtime-main.cpp"
  );
  const matrixPath = resolve(
    repositoryRoot,
    "scripts/lib/convex-wasm-committed-value-codec-matrix.mjs"
  );
  const harnessPath = resolve(
    repositoryRoot,
    "scripts/run-convex-wasm-committed-value-codec-matrix.mjs"
  );
  await Promise.all([
    requireFile(options.cxxPath, "C++ compiler"),
    requireFile(options.emccPath, "Emscripten compiler"),
    requireFile(options.runnerPath, "Wasmtime runner"),
    requireFile(options.shermesPath, "Static Hermes compiler"),
    requireFile(runtimeMainPath, "codec matrix runtime"),
  ]);
  const rendered = renderConvexWasmCommittedValueCodecMatrix();
  const legacyIntegerRejector = renderConvexWasmCommittedValueCodecMatrixLegacyIntegerRejector();
  const opaqueAbiHeader = renderOpaqueAbiHeader();
  const inputHeader = renderInputHeader(rendered.canonicalInputJson, rendered.canonicalOutputJson);
  const temporaryDirectory = await fs.mkdtemp(
    resolve(tmpdir(), "convex-wasm-committed-value-codec-matrix-")
  );
  try {
    const sourcePath = resolve(temporaryDirectory, "matrix.js");
    const legacySourcePath = resolve(temporaryDirectory, "matrix-legacy-integer-rejection.js");
    const opaqueAbiHeaderPath = resolve(temporaryDirectory, "convex_wasm_opaque_abi_v3.h");
    const inputHeaderPath = resolve(
      temporaryDirectory,
      "convex_wasm_committed_value_codec_matrix_input.h"
    );
    await Promise.all([
      fs.writeFile(sourcePath, rendered.source, { mode: 0o600 }),
      fs.writeFile(legacySourcePath, legacyIntegerRejector.source, { mode: 0o600 }),
      fs.writeFile(opaqueAbiHeaderPath, opaqueAbiHeader, { mode: 0o600 }),
      fs.writeFile(inputHeaderPath, inputHeader, { mode: 0o600 }),
    ]);
    const targets = {};
    const legacyIntegerRejectorTargets = {};
    for (const optimization of ["optimized", "unoptimized"]) {
      const shermesOptimization = optimization === "optimized" ? "-O" : "-O0";
      const generatedCPath = resolve(temporaryDirectory, `matrix-${optimization}.c`);
      const legacyGeneratedCPath = resolve(
        temporaryDirectory,
        `matrix-legacy-integer-rejection-${optimization}.c`
      );
      run(options.shermesPath, [
        "-typed",
        shermesOptimization,
        "-Xenable-tdz",
        "-emit-c",
        `-exported-unit=convex_wasm_committed_value_codec_matrix_${optimization}`,
        sourcePath,
        "-o",
        generatedCPath,
      ]);
      targets[targetName("native", optimization)] = await compileNativeTarget({
        cxxPath: options.cxxPath,
        generatedCPath,
        hermesSourcePath: options.hermesSourcePath,
        hostBuildPath: options.hostBuildPath,
        optimization,
        expectedIntegerRejection: false,
        runtimeMainPath,
        temporaryDirectory,
      });
      targets[targetName("wasmtime", optimization)] = await compileWasmtimeTarget({
        emccPath: options.emccPath,
        generatedCPath,
        hermesSourcePath: options.hermesSourcePath,
        optimization,
        expectedIntegerRejection: false,
        runnerPath: options.runnerPath,
        runtimeMainPath,
        temporaryDirectory,
        wasmBuildPath: options.wasmBuildPath,
      });
      run(options.shermesPath, [
        "-typed",
        shermesOptimization,
        "-Xenable-tdz",
        "-emit-c",
        `-exported-unit=convex_wasm_committed_value_codec_matrix_${optimization}`,
        legacySourcePath,
        "-o",
        legacyGeneratedCPath,
      ]);
      legacyIntegerRejectorTargets[targetName("native", optimization)] = await compileNativeTarget({
        cxxPath: options.cxxPath,
        expectedIntegerRejection: true,
        generatedCPath: legacyGeneratedCPath,
        hermesSourcePath: options.hermesSourcePath,
        hostBuildPath: options.hostBuildPath,
        optimization,
        runtimeMainPath,
        temporaryDirectory,
      });
      legacyIntegerRejectorTargets[targetName("wasmtime", optimization)] =
        await compileWasmtimeTarget({
          emccPath: options.emccPath,
          expectedIntegerRejection: true,
          generatedCPath: legacyGeneratedCPath,
          hermesSourcePath: options.hermesSourcePath,
          optimization,
          runnerPath: options.runnerPath,
          runtimeMainPath,
          temporaryDirectory,
          wasmBuildPath: options.wasmBuildPath,
        });
    }
    const payload = {
      harness: {
        matrix: await fileIdentity(matrixPath),
        runtimeMain: await fileIdentity(runtimeMainPath),
        runnerExport,
        source: await fileIdentity(harnessPath),
      },
      kind,
      legacyIntegerRejector: {
        sourceSha256: legacyIntegerRejector.sourceSha256,
        targets: legacyIntegerRejectorTargets,
      },
      matrix: {
        canonicalInputSha256: sha256(rendered.canonicalInputJson),
        canonicalOutputSha256: sha256(rendered.canonicalOutputJson),
        canonicalVectorCorpus: rendered.canonicalVectorCorpus,
        kind: convexWasmCommittedValueCodecMatrixKind,
        largeByteLength: 196_609,
        inputHeader: { bytes: Buffer.byteLength(inputHeader), sha256: sha256(inputHeader) },
        opaqueAbiHeader: {
          bytes: Buffer.byteLength(opaqueAbiHeader),
          sha256: sha256(opaqueAbiHeader),
        },
        sourceSha256: rendered.sourceSha256,
      },
      runtime: {
        arguments: runtimeArguments,
        initialization: "_sh_init",
        runnerExport,
      },
      schemaVersion: 1,
      targets,
      tools: {
        cxx: await fileIdentity(options.cxxPath),
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
  const report = await runConvexWasmCommittedValueCodecMatrix(options);
  await fs.mkdir(dirname(options.outputPath), { mode: 0o700, recursive: true });
  await fs.writeFile(options.outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(
    `${JSON.stringify({ output: options.outputPath, reportSha256: report.reportSha256 })}\n`
  );
}
