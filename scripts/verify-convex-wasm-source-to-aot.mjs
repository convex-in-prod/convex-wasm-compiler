#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { availableParallelism } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { fingerprintMaterialPaths } from "./lib/convex-wasm-artifact-material.mjs";
import { deriveConvexWasmCacheLayout } from "./lib/convex-wasm-cache-layout.mjs";
import { acquireConvexWasmCacheLock } from "./lib/convex-wasm-cache-lock.mjs";
import { createConvexWasmBuildWorkLease } from "./lib/convex-wasm-cache-retention.mjs";
import { buildConvexWasmGeneratedCLinkInput } from "./lib/convex-wasm-generated-c-build.mjs";
import { buildConvexWasmCoreWasmAndAot } from "./lib/convex-wasm-native-artifact-build.mjs";
import { createConvexWasmNativeCommandRunner } from "./lib/convex-wasm-native-command-runner.mjs";
import { buildConvexWasmNativeObject } from "./lib/convex-wasm-native-object-build.mjs";
import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";
import {
  staticHermesCBundleMemberCompilationBaselinePolicy,
  staticHermesCBundleShardTargetBytes,
} from "./lib/convex-wasm-static-hermes-c-bundle.mjs";

const scriptRoot = dirname(fileURLToPath(import.meta.url));
const TARGET = { cpu: "baseline", triple: "x86_64-unknown-linux-gnu" };
const ENGINE_CONFIG = {
  consumeFuel: true,
  epochInterruption: true,
  profilingStrategy: "perf-map",
  wasmExceptions: true,
};
const requiredOptions = new Set([
  "--aot-workers",
  "--cache-root",
  "--emcc",
  "--emsdk-root",
  "--hermes-source",
  "--mode",
  "--precompiler-package",
  "--shermes",
  "--wasm-build",
]);

function parseArguments(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!requiredOptions.has(name) || value === undefined || value.length === 0 || values.has(name)) {
      throw new Error(`invalid or duplicate source-to-AOT verification option: ${String(name)}`);
    }
    values.set(name, value);
  }
  for (const option of requiredOptions) {
    if (!values.has(option)) throw new Error(`source-to-AOT verification requires ${option}`);
  }
  const mode = values.get("--mode");
  if (mode !== "single" && mode !== "bundle") {
    throw new Error("source-to-AOT verification mode must be single or bundle");
  }
  const aotWorkers = Number(values.get("--aot-workers"));
  if (!Number.isSafeInteger(aotWorkers) || aotWorkers <= 0 || aotWorkers > availableParallelism()) {
    throw new Error("source-to-AOT verification worker count must fit the available CPU count");
  }
  return {
    aotWorkers,
    cacheRoot: resolve(values.get("--cache-root")),
    emcc: resolve(values.get("--emcc")),
    emsdkRoot: resolve(values.get("--emsdk-root")),
    hermesSource: resolve(values.get("--hermes-source")),
    mode,
    precompilerPackage: resolve(values.get("--precompiler-package")),
    shermes: resolve(values.get("--shermes")),
    wasmBuild: resolve(values.get("--wasm-build")),
  };
}

async function fingerprintInput(name, path) {
  const bytes = await fs.readFile(path);
  return {
    name,
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  };
}

async function verifyConvexWasmSourceToAotUnderLease(config, cacheLayout) {
  if (process.env.HOME === undefined || process.env.PATH === undefined) {
    throw new Error("source-to-AOT verification requires HOME and PATH");
  }
  const emsdkConfig = join(config.emsdkRoot, ".emscripten");
  const shPaths = [{ label: "static-hermes-executable", path: config.shermes }];
  const emPaths = [
    { label: "emcc-executable", path: config.emcc },
    { label: "emscripten-config", path: emsdkConfig },
    { label: "clang", path: join(config.emsdkRoot, "upstream/bin/clang") },
    { label: "wasm-emscripten-finalize", path: join(config.emsdkRoot, "upstream/bin/wasm-emscripten-finalize") },
    { label: "wasm-ld", path: join(config.emsdkRoot, "upstream/bin/wasm-ld") },
    { label: "wasm-opt", path: join(config.emsdkRoot, "upstream/bin/wasm-opt") },
  ];
  const includes = [
    join(config.wasmBuild, "lib/config"),
    join(config.hermesSource, "include"),
    join(config.hermesSource, "API/jsi"),
  ];
  const runtimePaths = includes.map((path, index) => ({ label: `runtime-include-${index}`, path }));
  const [staticHermes, emscripten, runtime, precompiler] = await Promise.all([
    fingerprintMaterialPaths(shPaths, "Static Hermes verification material"),
    fingerprintMaterialPaths(emPaths, "Emscripten verification material"),
    fingerprintMaterialPaths(runtimePaths, "runtime verification headers"),
    loadAndVerifyPrecompilerPackage(config.precompilerPackage),
  ]);
  const verifyStaticHermes = async () => {
    const current = await fingerprintMaterialPaths(shPaths, "Static Hermes verification material");
    if (current.sha256 !== staticHermes.sha256) throw new Error("Static Hermes verification material changed");
  };
  const verifyEmscripten = async () => {
    const [currentEm, currentRuntime] = await Promise.all([
      fingerprintMaterialPaths(emPaths, "Emscripten verification material"),
      fingerprintMaterialPaths(runtimePaths, "runtime verification headers"),
    ]);
    if (currentEm.sha256 !== emscripten.sha256 || currentRuntime.sha256 !== runtime.sha256) {
      throw new Error("Emscripten or runtime verification material changed");
    }
  };
  const runCommand = createConvexWasmNativeCommandRunner({
    environment: {
      EM_CONFIG: emsdkConfig,
      EMSDK: config.emsdkRoot,
      HOME: process.env.HOME,
      PATH: process.env.PATH,
    },
    maxOutputBytes: 16 * 1024 * 1024,
    timeoutMs: 15 * 60 * 1000,
  });
  const source = await fs.readFile(
    join(scriptRoot, "test-fixtures/convex-wasm-runtime-surface/static-hermes-global-probe.js"),
    "utf8"
  );
  const objectFlags = [
    "-O2", "-DNDEBUG", "-fno-strict-aliasing", "-fno-strict-overflow",
    "-fwasm-exceptions", "-sWASM_LEGACY_EXCEPTIONS=0",
    ...includes.map((path) => `-I${path}`),
  ];
  const bundle = config.mode === "bundle";
  const linkInputName = bundle ? "probe.a" : "probe.o";
  const generatedOptions = {
    cacheLayout,
    cacheRoot: config.cacheRoot,
    commands: {
      staticHermes: {
        executable: join(scriptRoot, "run-convex-wasm-static-hermes-precompiler.mjs"),
        args: [
          "--compiler", config.shermes,
          "--max-output-bytes", String(16 * 1024 * 1024),
          "--request", "request.json", "--response", "response.json", "--",
          "-typed", "-O", "-Xenable-tdz", "-emit-c",
          ...(bundle
            ? ["-Xemit-c-bundle", `-Xemit-c-shard-size=${String(staticHermesCBundleShardTargetBytes)}`]
            : []),
          "-exported-unit=global_probe_unit",
          "-o", bundle ? "unit.c.json" : "unit.c", "input.js",
        ],
      },
      compileExport: {
        executable: config.emcc,
        args: [...objectFlags, "-c", "unit.c", "-o", "unit.o"],
      },
      compileExportMember: { executable: config.emcc, args: [...objectFlags, "-c"] },
    },
    generatedJavaScript: source,
    identities: {
      archive: { kind: "public-verification-archive", emscriptenSha256: emscripten.sha256 },
      object: { kind: "public-verification-object", emscriptenSha256: emscripten.sha256, runtimeSha256: runtime.sha256 },
    },
    limits: {
      archiveBytes: 64 * 1024 * 1024,
      generatedCBytes: 64 * 1024 * 1024,
      objectBytes: 64 * 1024 * 1024,
    },
    linkInputName,
    materials: { staticHermes },
    memberCompilationPolicy: staticHermesCBundleMemberCompilationBaselinePolicy,
    memberJobs: config.aotWorkers,
    runCommand,
    verifyEmscriptenMaterials: verifyEmscripten,
    verifyStaticHermesMaterials: verifyStaticHermes,
  };
  const generatedFirst = await buildConvexWasmGeneratedCLinkInput(generatedOptions);
  const generatedSecond = await buildConvexWasmGeneratedCLinkInput(generatedOptions);
  if (generatedFirst.kind !== "success" || generatedSecond.kind !== "success") {
    throw new Error("generic Static Hermes probe source was rejected");
  }
  const runtimePath = join(scriptRoot, "lib/convex-wasm-static-hermes-global-probe-runtime-main.cpp");
  const runtimeInput = await fingerprintInput("runtime_main.cpp", runtimePath);
  const runtimeOptions = {
    cacheLayout,
    cacheRoot: config.cacheRoot,
    command: {
      executable: config.emcc,
      args: [
        ...objectFlags,
        "-DCONVEX_WASM_GLOBAL_PROBE_EXPORTED_UNIT=sh_export_global_probe_unit",
        "-c", "runtime_main.cpp", "-o", "runtime_main.o",
      ],
    },
    identity: { kind: "public-verification-runtime-object", emscriptenSha256: emscripten.sha256, runtimeSha256: runtime.sha256 },
    inputs: [runtimeInput],
    maxObjectBytes: 64 * 1024 * 1024,
    outputName: "runtime_main.o",
    runCommand,
    sourceName: "runtime_main.cpp",
    stage: "runtime-main-object",
    verifyMaterials: verifyEmscripten,
  };
  const runtimeFirst = await buildConvexWasmNativeObject(runtimeOptions);
  const runtimeSecond = await buildConvexWasmNativeObject(runtimeOptions);
  const archiveInputs = await Promise.all([
    fingerprintInput("libhermesvm_a.a", join(config.wasmBuild, "lib/libhermesvm_a.a")),
    fingerprintInput("libjsi.a", join(config.wasmBuild, "jsi/libjsi.a")),
  ]);
  const nativeOptions = {
    cacheLayout,
    cacheRoot: config.cacheRoot,
    commands: {
      link: {
        executable: config.emcc,
        args: [
          "-O2", "--profiling-funcs", "--no-entry", "-fwasm-exceptions",
          "-sWASM_LEGACY_EXCEPTIONS=0", "-sSUPPORT_LONGJMP=wasm",
          "-sSTANDALONE_WASM=1", "-sALLOW_MEMORY_GROWTH=1", "-sSTACK_SIZE=2MB",
          "-Wl,--export=convex_wasm_static_hermes_global_probe_run",
          ...(bundle ? ["-Wl,--whole-archive", linkInputName, "-Wl,--no-whole-archive"] : [linkInputName]),
          "runtime_main.o", "libhermesvm_a.a", "libjsi.a", "-o", "module.wasm",
        ],
      },
      precompile: {
        executable: join(scriptRoot, "run-packaged-convex-wasm-precompiler.mjs"),
        args: [
          "--package", config.precompilerPackage, "--", "module.wasm", "module.cwasm",
          "--engine-identity", "engine-identity.json",
          "--consume-fuel", "true", "--epoch-interruption", "true",
          "--wasm-exceptions", "true", "--profiling-strategy", "perf-map",
          "--target-triple", TARGET.triple, "--target-cpu", TARGET.cpu,
          "--parallel-compilation-workers", String(config.aotWorkers),
        ],
      },
    },
    engineConfig: ENGINE_CONFIG,
    identities: {
      coreWasm: { kind: "public-verification-core-wasm", emscriptenSha256: emscripten.sha256, runtimeSha256: runtime.sha256 },
      wasmtimeAot: { kind: "public-verification-aot", precompilerPackageId: precompiler.manifest.packageId },
    },
    limits: { coreWasmBytes: 320 * 1024 * 1024, aotBytes: 640 * 1024 * 1024 },
    linkInputs: [
      generatedFirst.linkInput,
      {
        name: "runtime_main.o",
        path: runtimeFirst.entry.artifactPath,
        sha256: runtimeFirst.entry.artifactSha256,
        size: runtimeFirst.entry.artifactSize,
      },
      ...archiveInputs,
    ],
    runCommand,
    target: TARGET,
    verifyMaterials: async (stage) => {
      if (stage === "link") {
        await verifyEmscripten();
      } else {
        const current = await loadAndVerifyPrecompilerPackage(config.precompilerPackage);
        if (current.manifest.packageId !== precompiler.manifest.packageId) {
          throw new Error("precompiler package changed during verification");
        }
      }
    },
  };
  const nativeFirst = await buildConvexWasmCoreWasmAndAot(nativeOptions);
  const nativeSecond = await buildConvexWasmCoreWasmAndAot(nativeOptions);
  return {
    mode: config.mode,
    generatedLinkInput: [
      bundle ? generatedFirst.archive.report.cache : generatedFirst.object.report.cache,
      bundle ? generatedSecond.archive.report.cache : generatedSecond.object.report.cache,
    ],
    runtimeObject: [runtimeFirst.report.cache, runtimeSecond.report.cache],
    coreWasm: [nativeFirst.coreWasm.report.cache, nativeSecond.coreWasm.report.cache],
    aot: [nativeFirst.wasmtimeAot.report.cache, nativeSecond.wasmtimeAot.report.cache],
    coreWasmBytes: nativeFirst.coreWasm.entry.artifactSize,
    aotBytes: nativeFirst.wasmtimeAot.entry.artifactSize,
    engineCompatibilitySha256: nativeFirst.engineIdentity.engineCompatibilitySha256,
  };
}

export async function verifyConvexWasmSourceToAot(config) {
  await fs.mkdir(config.cacheRoot, { recursive: true, mode: 0o700 });
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: `source-to-aot-verification-${randomUUID()}`,
    cacheRoot: config.cacheRoot,
    repositoryRoot: scriptRoot,
    scope: "isolated-test",
  });
  const releaseLock = await acquireConvexWasmCacheLock();
  try {
    const lease = await createConvexWasmBuildWorkLease({ cacheLayout });
    try {
      const report = await verifyConvexWasmSourceToAotUnderLease(config, cacheLayout);
      await lease.complete();
      return report;
    } catch (error) {
      await lease.fail();
      throw error;
    }
  } finally {
    releaseLock();
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.stdout.write(`${JSON.stringify(await verifyConvexWasmSourceToAot(
    parseArguments(process.argv.slice(2))
  ))}\n`);
}
