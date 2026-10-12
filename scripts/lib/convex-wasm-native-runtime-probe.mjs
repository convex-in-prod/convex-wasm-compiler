import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { renderConvexWasmIntrinsicHardeningPrelude } from "./convex-wasm-intrinsic-hardening.mjs";
import { renderOpaqueAbiHeader } from "./convex-wasm-lowering.mjs";
import { renderConvexWasmTargetRuntimeGlobalPrelude } from "./convex-wasm-runtime-surface.mjs";

export function nativeRuntimeProbeConfiguration(environment = process.env) {
  const names = [
    "CONVEX_HERMES_TEST_SOURCE_ROOT", "CONVEX_HERMES_TEST_BUILD_ROOT",
    "CONVEX_HERMES_TEST_WASM_BUILD_ROOT", "CONVEX_WASM_EMCC", "CONVEX_WASM_RUNNER",
  ];
  if (names.slice(2).every((name) => environment[name] === undefined)) return undefined;
  for (const name of names) {
    if (typeof environment[name] !== "string" || environment[name].length === 0) {
      throw new Error(`Missing native runtime probe configuration: ${name}`);
    }
  }
  const [source, hostBuild, wasmBuild, emcc, runner] = names.map((name) => environment[name]);
  return { source, hostBuild, wasmBuild, emcc, runner };
}

// The caller owns resource admission. Both probes use the same production
// runtime flags, archives and guest memory settings.
async function withNativeProbeBuild({ configuration, fixtureName, program, exportedFunctions }, consume) {
  const { source, hostBuild, wasmBuild, emcc } = configuration;
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const temporary = await fs.mkdtemp(join(tmpdir(), "convex-native-runtime-probe-"));
  const run = (command, args) => {
    const result = spawnSync(command, args, {
      encoding: "utf8", timeout: 180_000, maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error || result.status !== 0) {
      throw new Error(`Native runtime probe command failed: ${command}\n${result.stdout}\n${result.stderr}`,
        { cause: result.error });
    }
    return result.stdout;
  };
  try {
    const fixture = join(root, "scripts/test-fixtures/native-values", fixtureName);
    await fs.writeFile(join(temporary, "convex_wasm_opaque_abi_v3.h"), renderOpaqueAbiHeader());
    const flags = [
      "-O2", "-DNDEBUG", "-fno-strict-aliasing", "-fno-strict-overflow",
      "-fwasm-exceptions", "-sWASM_LEGACY_EXCEPTIONS=0",
      ...[
        temporary, join(wasmBuild, "lib/config"), join(source, "include"),
        join(source, "API"), join(source, "API/jsi"), join(source, "public"),
        join(root, "scripts/vendor/flatbuffers/include"),
      ].map((path) => `-I${path}`),
    ];
    const objects = [];
    if (program !== null) {
      await fs.writeFile(join(temporary, "probe.js"), program);
      run(join(hostBuild, "bin/shermes"), [
        "-typed", "-O", "-Xenable-tdz", "-emit-c", "-exported-unit=native_runtime_probe",
        "-o", join(temporary, "probe.c"), join(temporary, "probe.js"),
      ]);
      run(emcc, [...flags, "-c", join(temporary, "probe.c"), "-o", join(temporary, "probe.o")]);
      objects.push(join(temporary, "probe.o"));
    }
    run(emcc, [
      ...flags, "-std=c++17", "-DCONVEX_WASM_BRIDGE_EXPORTED_UNIT=unused_bridge",
      "-DCONVEX_WASM_FORMATTER_EXPORTED_UNIT=unused_formatter",
      "-c", fixture, "-o", join(temporary, "runtime.o"),
    ]);
    objects.push(join(temporary, "runtime.o"));
    const module = join(temporary, "probe.wasm");
    const archives = [
      join(wasmBuild, "lib/libhermesvm_a.a"), join(wasmBuild, "jsi/libjsi.a"),
      join(wasmBuild, "external/icu-small/libhermesStaticIcu.a"),
    ];
    run(emcc, [
      ...flags, ...objects, ...archives,
      "--no-entry", "-sSTANDALONE_WASM=1", "-sSUPPORT_LONGJMP=wasm", "-sFILESYSTEM=0",
      "-sALLOW_MEMORY_GROWTH=1", "-sSTACK_SIZE=512KB", "-sINITIAL_HEAP=2MB",
      "-sMAXIMUM_MEMORY=134217728",
      ...exportedFunctions.map((name) => `-Wl,--export=${name}`), "-o", module,
    ]);
    const hashes = await Promise.all([module, ...archives, fixture].map(async (path) =>
      createHash("sha256").update(await fs.readFile(path)).digest("hex")));
    return await consume({ module, run, identity: {
      ...(program === null ? {} : { sourceSha256: createHash("sha256").update(program).digest("hex") }),
      moduleSha256: hashes[0], hermesArchiveSha256: hashes[1], jsiArchiveSha256: hashes[2],
      icuArchiveSha256: hashes[3], fixtureSha256: hashes[4],
    } });
  } finally {
    await fs.rm(temporary, { recursive: true, force: true });
  }
}

// Source defines a synchronous globalThis.__convexNativeRuntimeProbe returning
// a JSON-serializable result.
export async function runNativeRuntimeProbe({ javascript, configuration }) {
  if (typeof javascript !== "string" || javascript.length === 0) {
    throw new Error("Native runtime probe requires JavaScript source");
  }
  const program = [
    renderConvexWasmTargetRuntimeGlobalPrelude(),
    renderConvexWasmIntrinsicHardeningPrelude({ nativeDescriptorValidation: true }),
    `const __probeValidator: any = globalThis.__convexWasmValidateIntrinsicDescriptorState;
      if (!delete globalThis.__convexWasmValidateIntrinsicDescriptorState) {
        throw new Error("Native probe validator handoff failed");
      }`,
    javascript,
    `const __probeBody: any = globalThis.__convexNativeRuntimeProbe;
      globalThis.__convexNativeRuntimeProbe = function(): string {
        if (!__probeValidator()) throw new Error("Native probe began with dirty intrinsics");
        const result: any = __probeBody(__probeValidator);
        if (!__probeValidator()) throw new Error("Native probe left dirty intrinsics");
        return JSON.stringify(result);
      };`,
  ].join("\n");
  const exportedFunctions = ["convex_wasm_native_runtime_probe_run"];
  return withNativeProbeBuild({ configuration, fixtureName: "runtime-probe.cpp", program, exportedFunctions },
    ({ module, run, identity }) => {
      const output = run(configuration.runner, [module, exportedFunctions[0]]);
      const prefix = "CONVEX_NATIVE_RUNTIME_PROBE:";
      const lines = output.trimEnd().split("\n");
      if (lines.length !== 9 || lines.some((line) => !line.startsWith(prefix))) {
        throw new Error(`Native runtime probe did not return nine results: ${output}`);
      }
      return { results: lines.map((line) => JSON.parse(line.slice(prefix.length))), identity };
    });
}

export async function runNativeResourceProbe({ configuration }) {
  const cases = ["control", "malloc", "realloc", "cpp"];
  const exportedFunctions = cases.map((name) => `convex_wasm_resource_probe_${name}`);
  return withNativeProbeBuild({ configuration, fixtureName: "resource-probe.cpp", program: null, exportedFunctions },
    ({ module, run, identity }) => ({
      identity,
      results: Object.fromEntries(cases.map((name, index) => [name, JSON.parse(run(configuration.runner, [
        "--resource-probe", module, exportedFunctions[index], String(64 * 1024 * 1024), "10000000000",
      ]))])),
    }));
}
