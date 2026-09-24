#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import { fingerprintJson } from "./lib/convex-wasm-artifact-contract.mjs";

const KIND = "convex-wasm-static-hermes-global-probe-report-v2";
const runtimeArguments = Object.freeze([
  "--gc-init-heap=4MiB",
  "--gc-max-heap=32MiB",
  "--gc-alloc-young=true",
  "--gc-revert-to-yg-at-tti=false",
  "--max-register-stack=16384",
]);
const sourcePaths = Object.freeze({
  globalObject: "lib/VM/JSLib/GlobalObject.cpp",
  libhermesDeclaration: "include/hermes/Runtime/Libhermes.h",
  typedArraysDeclaration: "include/hermes/VM/TypedArrays.def",
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArguments(argumentsList) {
  const supported = new Set([
    "--build-revision",
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
      throw new Error("invalid Static Hermes global probe arguments");
    }
    values.set(option, value);
  }
  for (const option of supported) {
    if (!values.has(option)) throw new Error(`missing required option ${option}`);
  }
  const buildRevision = values.get("--build-revision");
  if (!/^[a-f0-9]{40}$/u.test(buildRevision)) throw new Error("invalid build revision");
  return {
    buildRevision,
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
    throw new Error(
      `${basename(executable)} failed with status ${String(result.status)}: ${result.stderr.toString().trim()}`
    );
  }
  return result.stdout;
}

async function fileIdentity(path) {
  const bytes = await fs.readFile(path);
  return { bytes: bytes.length, sha256: sha256(bytes) };
}

function gitObject(sourceRoot, revision, path) {
  return run("git", ["show", `${revision}:${path}`], { cwd: sourceRoot });
}

function parseCmakeFlags(source) {
  const values = {};
  for (const name of [
    "HERMES_ENABLE_CONTRIB_EXTENSIONS",
    "HERMES_ENABLE_CORE_EXTENSIONS",
    "HERMES_ENABLE_DEBUGGER",
    "HERMES_ENABLE_INTL",
  ]) {
    const match = source.match(new RegExp(`^${name}:BOOL=(ON|OFF)$`, "mu"));
    if (match === null) throw new Error(`CMake cache omitted ${name}`);
    values[name] = match[1] === "ON";
  }
  return values;
}

function extractTypedDeclarations(libhermesSource, typedArraysSource) {
  const names = [];
  for (const match of libhermesSource.matchAll(
    /"(?:var|function) ([A-Za-z_$][A-Za-z0-9_$]*)[;(]/gu
  )) {
    names.push(match[1]);
  }
  for (const match of typedArraysSource.matchAll(/^TYPED_ARRAY\(([^,]+),/gmu)) {
    names.push(`${match[1]}Array`);
  }
  return [...new Set(names)].sort();
}

function assertObservation(value) {
  for (const field of ["effectiveFirst", "effectiveSecond", "raw"]) {
    const snapshot = value[field];
    if (
      snapshot === null ||
      typeof snapshot !== "object" ||
      !Array.isArray(snapshot.keys) ||
      snapshot.valueTypes === null ||
      typeof snapshot.valueTypes !== "object"
    ) {
      throw new Error(`Static Hermes global probe ${field} is invalid`);
    }
    const sortedKeys = [...new Set(snapshot.keys)].sort();
    if (
      sortedKeys.length !== snapshot.keys.length ||
      sortedKeys.some((name, index) => name !== snapshot.keys[index])
    ) {
      throw new Error(`Static Hermes global probe ${field} keys must be sorted and unique`);
    }
    if (JSON.stringify(Object.keys(snapshot.valueTypes).sort()) !== JSON.stringify(sortedKeys)) {
      throw new Error(`Static Hermes global probe ${field} value-type keys disagree`);
    }
    if (
      Object.values(snapshot.valueTypes).some(
        (valueType) =>
          !["boolean", "function", "number", "object", "string", "symbol", "undefined"].includes(
            valueType
          )
      )
    ) {
      throw new Error(`Static Hermes global probe ${field} contains an invalid value type`);
    }
  }
  if (JSON.stringify(value.raw) !== JSON.stringify(value.effectiveFirst)) {
    throw new Error("Static Hermes effective globals differ from raw _sh_init globals");
  }
  if (JSON.stringify(value.effectiveFirst) !== JSON.stringify(value.effectiveSecond)) {
    throw new Error("Static Hermes reused-runtime global observations differ");
  }
}

function normalizeObservation(value) {
  return Object.fromEntries(
    ["effectiveFirst", "effectiveSecond", "raw"].map((field) => {
      const keys = [...value[field].keys].sort();
      return [
        field,
        {
          keys,
          valueTypes: Object.fromEntries(keys.map((name) => [name, value[field].valueTypes[name]])),
        },
      ];
    })
  );
}

export async function generateConvexWasmStaticHermesGlobalProbe(options) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const runtimeMainPath = resolve(
    repositoryRoot,
    "scripts/lib/convex-wasm-static-hermes-global-probe-runtime-main.cpp"
  );
  const guestPath = resolve(
    repositoryRoot,
    "scripts/test-fixtures/convex-wasm-runtime-surface/static-hermes-global-probe.js"
  );
  const generatorPath = resolve(
    repositoryRoot,
    "scripts/generate-convex-wasm-static-hermes-global-probe.mjs"
  );
  const temporaryDirectory = await fs.mkdtemp(
    resolve(tmpdir(), "convex-wasm-static-hermes-global-probe-")
  );
  try {
    const generatedCPath = resolve(temporaryDirectory, "probe.c");
    const generatedObjectPath = resolve(temporaryDirectory, "probe.o");
    const runtimeObjectPath = resolve(temporaryDirectory, "runtime.o");
    const wasmPath = resolve(temporaryDirectory, "probe.wasm");
    run(options.shermesPath, [
      "-typed",
      "-O",
      "-Xenable-tdz",
      "-emit-c",
      "-exported-unit=global_probe_unit",
      guestPath,
      "-o",
      generatedCPath,
    ]);
    const includes = [
      `-I${resolve(options.wasmBuildPath, "lib/config")}`,
      `-I${resolve(options.hermesSourcePath, "include")}`,
      `-I${resolve(options.hermesSourcePath, "API/jsi")}`,
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
    run(options.emccPath, ["-c", generatedCPath, "-o", generatedObjectPath, ...objectFlags]);
    run(options.emccPath, [
      "-c",
      runtimeMainPath,
      "-o",
      runtimeObjectPath,
      "-DCONVEX_WASM_GLOBAL_PROBE_EXPORTED_UNIT=sh_export_global_probe_unit",
      ...objectFlags,
    ]);
    const wasmArchivePath = resolve(options.wasmBuildPath, "lib/libhermesvm_a.a");
    const jsiArchivePath = resolve(options.wasmBuildPath, "jsi/libjsi.a");
    const linkFlags = [
      "-O2",
      "--profiling-funcs",
      "--no-entry",
      "-fwasm-exceptions",
      "-sWASM_LEGACY_EXCEPTIONS=0",
      "-sSUPPORT_LONGJMP=wasm",
      "-sSTANDALONE_WASM=1",
      "-sALLOW_MEMORY_GROWTH=1",
      "-sSTACK_SIZE=2MB",
      "-Wl,--export=convex_wasm_static_hermes_global_probe_run",
    ];
    run(options.emccPath, [
      generatedObjectPath,
      runtimeObjectPath,
      wasmArchivePath,
      jsiArchivePath,
      "-o",
      wasmPath,
      ...linkFlags,
    ]);
    const observationBytes = run(options.runnerPath, [wasmPath]);
    const observation = normalizeObservation(JSON.parse(observationBytes.toString("utf8")));
    assertObservation(observation);
    const sourceMaterials = Object.fromEntries(
      Object.entries(sourcePaths).map(([name, path]) => {
        const bytes = gitObject(options.hermesSourcePath, options.buildRevision, path);
        return [name, { path, sha256: sha256(bytes) }];
      })
    );
    const libhermesSource = gitObject(
      options.hermesSourcePath,
      options.buildRevision,
      sourcePaths.libhermesDeclaration
    ).toString("utf8");
    const typedArraysSource = gitObject(
      options.hermesSourcePath,
      options.buildRevision,
      sourcePaths.typedArraysDeclaration
    ).toString("utf8");
    const hostCmakePath = resolve(options.hostBuildPath, "CMakeCache.txt");
    const wasmCmakePath = resolve(options.wasmBuildPath, "CMakeCache.txt");
    const [hostCmakeSource, wasmCmakeSource, checkoutRevisionBytes] = await Promise.all([
      fs.readFile(hostCmakePath, "utf8"),
      fs.readFile(wasmCmakePath, "utf8"),
      Promise.resolve(run("git", ["rev-parse", "HEAD"], { cwd: options.hermesSourcePath })),
    ]);
    const payload = {
      build: {
        buildRevision: options.buildRevision,
        cmake: {
          host: {
            flags: parseCmakeFlags(hostCmakeSource),
            identity: await fileIdentity(hostCmakePath),
          },
          wasm: {
            flags: parseCmakeFlags(wasmCmakeSource),
            identity: await fileIdentity(wasmCmakePath),
          },
        },
        observedCheckoutRevision: checkoutRevisionBytes.toString("utf8").trim(),
        sourceMaterials,
        sourceRevision: options.buildRevision,
      },
      harness: {
        generatedC: await fileIdentity(generatedCPath),
        generator: await fileIdentity(generatorPath),
        guest: await fileIdentity(guestPath),
        runtimeMain: await fileIdentity(runtimeMainPath),
      },
      kind: KIND,
      observation,
      runtime: {
        arguments: runtimeArguments,
        initialization: "_sh_init",
        reusedObservationCount: 2,
      },
      schemaVersion: 2,
      target: {
        jsiArchive: await fileIdentity(jsiArchivePath),
        wasm: await fileIdentity(wasmPath),
        wasmLibhermesvmArchive: await fileIdentity(wasmArchivePath),
      },
      tools: {
        emcc: await fileIdentity(options.emccPath),
        runner: await fileIdentity(options.runnerPath),
        shermes: await fileIdentity(options.shermesPath),
      },
      typedDeclarations: {
        globals: extractTypedDeclarations(libhermesSource, typedArraysSource),
        kind: "libhermes-runtime-declarations-plus-typed-arrays-v1",
      },
    };
    return Object.freeze({ ...payload, reportSha256: fingerprintJson(payload) });
  } finally {
    await fs.rm(temporaryDirectory, { force: true, recursive: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const options = parseArguments(process.argv.slice(2));
  const report = await generateConvexWasmStaticHermesGlobalProbe(options);
  await fs.mkdir(dirname(options.outputPath), { mode: 0o700, recursive: true });
  await fs.writeFile(options.outputPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(
    `${JSON.stringify({ output: options.outputPath, reportSha256: report.reportSha256 })}\n`
  );
}
