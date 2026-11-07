import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { availableParallelism } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import {
  renderNativeDbGetCapabilityTargetUnits,
  renderOpaqueAbiHeader,
} from "../../lib/convex-wasm-lowering.mjs";
import {
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
  renderConvexWasmCapabilityCohortSelector,
} from "../../lib/convex-wasm-selector-source.mjs";
import { convexWasmNativeUrlSupportObjectInputs } from "../../lib/convex-wasm-native-url-support.mjs";
import { convexWasmCompileProfileBuildOptions } from "../../lib/convex-wasm-compile-profile.mjs";
import { convexWasmApplicationGlobalThisBinding } from "../../lib/convex-wasm-runtime-surface.mjs";
import { capabilityApplicationStaticHermesFlags } from "../../lib/convex-wasm-artifact-commands.mjs";
import { loadAndVerifyPrecompilerPackage } from "../../lib/convex-wasm-precompiler-package.mjs";

async function main(argumentsList) {
  // Runtime integration fixture, deliberately without registry publication.
  // Precompile with the release tool so a debug backend test need only load AOT.
  const [gateArgument, sdkArgument, precompilerArgument, outputArgument] = argumentsList;
  if (argumentsList.length !== 4 || !gateArgument || !sdkArgument || !precompilerArgument || !outputArgument) {
    throw new Error("usage: node build.mjs GATE_ROOT SDK_SOURCE_ROOT PRECOMPILER_PACKAGE OUTPUT_DIRECTORY");
  }
  const gate = resolve(gateArgument);
  const sdk = resolve(sdkArgument);
  const precompiler = await loadAndVerifyPrecompilerPackage(resolve(precompilerArgument));
  const output = resolve(outputArgument);
  const fixture = dirname(fileURLToPath(import.meta.url));
  const library = resolve(fixture, "../../lib");
  const sdkPackageVersion = JSON.parse(readFileSync(join(sdk, "package.json"), "utf8")).version;
  mkdirSync(output, { recursive: true });
  const alias = {
    "convex/server": join(sdk, "src/server/index.ts"),
    "convex/values": join(sdk, "src/values/index.ts"),
    "sdk-value": join(sdk, "src/values/value.ts"),
  };
  for (const name of ["root", "child"]) {
    buildSync({
      entryPoints: [join(fixture, `${name}.js`)], alias,
      bundle: true, format: "esm", target: "es2022",
      outfile: join(output, `${name}.js`),
    });
  }
  const members = [];
  const units = [];
  for (const [index, abi] of ["sdk", "direct"].entries()) {
    const profile = buildSync({
      ...convexWasmCompileProfileBuildOptions,
      sourcemap: false,
      stdin: {
        contents: `
          import { read, write } from "./root.js";
          export { commitTsPlaceholder as __convexWasmSdkCommitTsPlaceholder } from "sdk-value";
          export { ConvexError as __convexWasmSdkConvexError } from "convex/values";
          const selectedRead = read${abi === "direct" ? "._handler" : ""};
          const selectedWrite = write${abi === "direct" ? "._handler" : ""};
          export { selectedRead as read, selectedWrite as write };
        `,
        resolveDir: fixture,
      },
      alias,
      define: {
        ...convexWasmCompileProfileBuildOptions.define,
        globalThis: convexWasmApplicationGlobalThisBinding,
        // The complete SDK retains action storage and browser guards. Resolve
        // their ambient lookups through the facade; these routes use neither
        // surface, and the fixture does not add either global to the runtime.
        Blob: `${convexWasmApplicationGlobalThisBinding}.Blob`,
        window: `${convexWasmApplicationGlobalThisBinding}.window`,
      },
    }).outputFiles[0].text;
    const rendered = renderNativeDbGetCapabilityTargetUnits({
      argumentFields: [], compileProfileJavascript: profile, sdkPackageVersion,
    });
    if (index === 0) {
      units.push(["bridge", rendered.bridgeJavascript], ["formatter", rendered.formatterJavascript]);
    }
    units.push([abi, rendered.applicationJavascript]);
    for (const [offset, kind] of ["query", "mutation"].entries()) {
      members.push({
        entrySelectorId: (index * 2 + offset).toString(16).padStart(16, "0"),
        entrySymbol: `sh_export_component_${abi}`,
        handlerExportName: kind === "query" ? "read" : "write",
        handlerUdfKind: kind,
        invocationAbi: abi === "sdk"
          ? convexWasmCapabilityOfficialWrapperInvocationAbi
          : convexWasmCapabilityLegacyInvocationAbi,
      });
    }
  }
  writeFileSync(join(output, "convex_wasm_opaque_abi_v3.h"), renderOpaqueAbiHeader());
  writeFileSync(join(output, "selector.c"), renderConvexWasmCapabilityCohortSelector(members));
  const environment = {
    ...process.env, EM_CONFIG: join(gate, "emsdk/.emscripten"),
    EMSDK: join(gate, "emsdk"), EM_BINARYEN_ROOT: join(gate, "binaryen-tools"),
  };
  const run = (command, args) => {
    const result = spawnSync(command, args, {
      cwd: output, env: environment, encoding: "utf8",
      timeout: 600_000, maxBuffer: 16 * 1024 * 1024,
    });
    if (result.status !== 0) {
      throw new Error(`${command}: ${result.error ?? result.status}\n${result.stdout}\n${result.stderr}`);
    }
  };
  const flags = [
    "-O2", "-DNDEBUG", "-fno-strict-aliasing", "-fno-strict-overflow",
    "-fwasm-exceptions", "-sWASM_LEGACY_EXCEPTIONS=0",
    ...[
      output, library, resolve(library, "../vendor/flatbuffers/include"),
      join(gate, "build-wasm/lib/config"), join(gate, "hermes/include"),
      join(gate, "hermes/API"), join(gate, "hermes/API/jsi"), join(gate, "hermes/public"),
    ].map((path) => `-I${path}`),
  ];
  const emcc = join(gate, "emsdk/upstream/emscripten/emcc");
  const objects = [];
  for (const [name, javascript] of units) {
    writeFileSync(join(output, `${name}.js`), javascript);
    const compilerFlags = ["-typed", "-O", "-Xenable-tdz"];
    run(join(gate, "build-host/bin/shermes"), [
      ...(name === "bridge" ? compilerFlags : capabilityApplicationStaticHermesFlags(compilerFlags)),
      "-emit-c",
      `-exported-unit=component_${name}`, "-o", `${name}.c`, `${name}.js`,
    ]);
    run(emcc, [...flags, "-c", `${name}.c`, "-o", `${name}.o`]);
    objects.push(`${name}.o`);
  }
  for (const input of convexWasmNativeUrlSupportObjectInputs(flags)) {
    writeFileSync(join(output, input.fileName), input.source);
    run(emcc, [...input.flags, "-c", input.fileName, "-o", `${input.fileName}.o`]);
    objects.push(`${input.fileName}.o`);
  }
  run(emcc, [...flags, "-std=c++17", "-DSTATIC_HERMES",
    "-DCONVEX_WASM_BRIDGE_EXPORTED_UNIT=sh_export_component_bridge",
    "-DCONVEX_WASM_FORMATTER_EXPORTED_UNIT=sh_export_component_formatter",
    "-c", join(library, "convex-wasm-native-capability-runtime-main.cpp"), "-o", "runtime.o",
  ]);
  run(emcc, [...flags, "-c", "selector.c", "-o", "selector.o"]);
  run(emcc, [
    "-O2", "--profiling-funcs", "--no-entry", "-fwasm-exceptions",
    "-sWASM_LEGACY_EXCEPTIONS=0", "-sSUPPORT_LONGJMP=wasm", "-sSTANDALONE_WASM=1",
    "-sALLOW_MEMORY_GROWTH=1", "-sMALLOC=none", "-sSTACK_SIZE=512KB", "-sINITIAL_HEAP=2MB",
    ...["select_entry", "udf_prepare_selected_entry", "udf_memory_maintenance", "udf_run", "udf_destroy_runtime"]
      .map((name) => `-Wl,--export=convex_wasm_${name}`),
    ...objects, "runtime.o", "selector.o",
    ...["lib/libhermesvm_a.a", "jsi/libjsi.a", "external/icu-small/libhermesStaticIcu.a", "lib/libconvex_wasm_allocator.a"]
      .map((path) => join(gate, "build-wasm", path)),
    "-o", "component.wasm",
  ]);
  for (const name of ["component.cwasm", "engine-identity.json"]) {
    rmSync(join(output, name), { force: true });
  }
  run(process.execPath, [
    resolve(library, "../run-packaged-convex-wasm-precompiler.mjs"),
    "--package", resolve(precompilerArgument), "--", "component.wasm", "component.cwasm",
    "--engine-identity", "engine-identity.json", "--consume-fuel", "true",
    "--epoch-interruption", "true", "--wasm-exceptions", "true",
    "--profiling-strategy", "perf-map", "--target-triple", precompiler.manifest.platform.targetTriple,
    "--target-cpu", "baseline", "--parallel-compilation-workers", String(Math.min(4, availableParallelism())),
  ]);
  console.log(`Component delegation fixture: ${output}`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
