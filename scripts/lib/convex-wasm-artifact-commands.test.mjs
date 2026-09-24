import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import { buildArtifactCommands } from "./convex-wasm-artifact-commands.mjs";
import { convexWasmNativeCommandArguments } from "./convex-wasm-native-launch-scheduling.mjs";

test("constructs argv-safe commands with the proven exception and AOT stages", () => {
  const config = {
    command: { maxOutputBytes: 65_536 },
    runtime: {
      archives: ["/tool chain/lib hermes.a"],
      compileFlags: ["-O2", "-fwasm-exceptions"],
      includeDirectories: ["/tool chain/include directory"],
      linkFlags: ["--no-entry", "-sWASM_LEGACY_EXCEPTIONS=0", "-sSUPPORT_LONGJMP=wasm"],
      mainCompileFlags: ["-DPERSIST=1"],
      mainSourcePath: "/sources/runtime_main.c",
    },
    toolchain: {
      emscripten: {
        executable: "/tool chain/emcc",
        materialInputs: [{ label: "wasm-ld", path: "/tool chain/wasm-ld" }],
      },
      staticHermes: {
        executable: "/tool chain/shermes",
        flags: ["-typed", "-O", "-Xenable-tdz", "-Xes6-block-scoping", "-emit-c"],
      },
      wasmtime: {
        engineConfig: {
          consumeFuel: true,
          epochInterruption: true,
          profilingStrategy: "perf-map",
          wasmExceptions: true,
        },
        executable: "/tool chain/precompile",
        packageDirectory: "/packages/precompiler",
        target: {
          cpu: "baseline",
          triple: "x86_64-unknown-linux-gnu",
        },
      },
    },
  };
  const commands = buildArtifactCommands(config);
  assert.deepEqual(commands.staticHermes, {
    executable: resolve("scripts/run-convex-wasm-static-hermes-precompiler.mjs"),
    args: [
      "--compiler",
      "/tool chain/shermes",
      "--max-output-bytes",
      "65536",
      "--request",
      "static-hermes-request.json",
      "--response",
      "static-hermes-response.json",
      "--",
      "-typed",
      "-O",
      "-Xenable-tdz",
      "-Xes6-block-scoping",
      "-emit-c",
      "-exported-unit=convex_wasm_udf_unit",
      "-o",
      "unit.c",
      "input.js",
    ],
  });
  assert.ok(commands.compileExport.args.includes("-I/tool chain/include directory"));
  assert.ok(
    commands.compileMain.args.includes("-DCONVEX_WASM_EXPORTED_UNIT=sh_export_convex_wasm_udf_unit")
  );
  assert.ok(commands.compileMain.args.includes("runtime_main.c"));
  const capabilityCommands = buildArtifactCommands({
    ...config,
    applicationEntrySelectorSymbol: "convex_wasm_selected_exported_unit",
    applicationExportedUnitName: "convex_wasm_application_fixture",
    exportedUnitName: "convex_wasm_capability_bridge",
  });
  assert.ok(capabilityCommands.staticHermes.args.includes("-typed"));
  assert.ok(capabilityCommands.staticHermes.args.includes("-Xes6-block-scoping"));
  assert.deepEqual(
    capabilityCommands.staticHermesApplication.args.filter((arg) =>
      ["-O", "-Xenable-tdz", "-Xes6-block-scoping", "-emit-c", "-typed"].includes(arg)
    ),
    ["-O", "-Xenable-tdz", "-Xes6-block-scoping", "-emit-c"]
  );
  assert.ok(
    capabilityCommands.staticHermesApplication.args.includes(
      "-exported-unit=convex_wasm_application_fixture"
    )
  );
  assert.ok(
    capabilityCommands.compileMain.args.includes(
      "-DCONVEX_WASM_BRIDGE_EXPORTED_UNIT=sh_export_convex_wasm_capability_bridge"
    )
  );
  assert.ok(
    capabilityCommands.compileMain.args.includes(
      "-DCONVEX_WASM_FORMATTER_EXPORTED_UNIT=sh_export_convex_wasm_console_formatter"
    )
  );
  assert.ok(
    capabilityCommands.compileMain.args.includes(
      "-DCONVEX_WASM_APPLICATION_EXPORTED_UNIT=convex_wasm_selected_exported_unit"
    )
  );
  const cxxCommands = buildArtifactCommands({
    ...config,
    runtime: { ...config.runtime, mainSourcePath: "/sources/runtime_main.cpp" },
  });
  assert.ok(cxxCommands.compileMain.args.includes("runtime_main.cpp"));
  assert.ok(!cxxCommands.compileMain.args.includes("runtime_main.c"));
  assert.deepEqual(commands.link.args.slice(-4), [
    "runtime_main.o",
    "/tool chain/lib hermes.a",
    "-o",
    "module.wasm",
  ]);
  assert.deepEqual(commands.precompile.args, [
    "--package",
    "/packages/precompiler",
    "--",
    "module.wasm",
    "module.cwasm",
    "--engine-identity",
    "engine-identity.json",
    "--consume-fuel",
    "true",
    "--epoch-interruption",
    "true",
    "--wasm-exceptions",
    "true",
    "--profiling-strategy",
    "perf-map",
    "--target-triple",
    "x86_64-unknown-linux-gnu",
    "--target-cpu",
    "baseline",
  ]);
  assert.deepEqual(
    convexWasmNativeCommandArguments(
      commands.precompile,
      { aggregateMemoryMaxBytes: 5 * 1024 * 1024 * 1024, aotWorkers: 6, jobs: 6 }
    ).slice(-2),
    ["--parallel-compilation-workers", "6"]
  );
  const bundleCommands = buildArtifactCommands({
    ...config,
    toolchain: {
      ...config.toolchain,
      staticHermes: {
        ...config.toolchain.staticHermes,
        flags: [
          ...config.toolchain.staticHermes.flags,
          "-Xemit-c-bundle",
          "-Xemit-c-shard-size=2097152",
        ],
      },
    },
  });
  assert.deepEqual(bundleCommands.staticHermes.args.slice(-3), ["-o", "unit.c.json", "input.js"]);
  const bundleExportIndex = bundleCommands.link.args.indexOf("unit.o");
  assert.deepEqual(bundleCommands.link.args.slice(bundleExportIndex - 1, bundleExportIndex + 2), [
    "-Wl,--whole-archive",
    "unit.o",
    "-Wl,--no-whole-archive",
  ]);
});
