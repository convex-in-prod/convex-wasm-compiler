import { extname, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  C_BUNDLE_MANIFEST_PATH,
  staticHermesCBundleEnabled,
} from "./convex-wasm-static-hermes-c-bundle.mjs";

const STATIC_HERMES_PRECOMPILER_LAUNCHER = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "run-convex-wasm-static-hermes-precompiler.mjs"
);
const EXPORTED_UNIT_NAME = "convex_wasm_udf_unit";
const CAPABILITY_BRIDGE_ENTRY_SYMBOL = "sh_export_convex_wasm_capability_bridge";
const CAPABILITY_FORMATTER_ENTRY_SYMBOL = "sh_export_convex_wasm_console_formatter";

function fail(message) {
  throw new Error(`Convex Wasm artifact commands: ${message}`);
}

function capabilityApplicationStaticHermesFlags(flags) {
  const applicationFlags = flags.filter((flag) => flag !== "-typed");
  if (applicationFlags.length !== flags.length - 1) {
    fail("capability application compilation requires exactly one -typed flag");
  }
  return applicationFlags;
}

export function buildArtifactCommands(config) {
  const includeArguments = config.runtime.includeDirectories.map((directory) => `-I${directory}`);
  const exportedUnitName = config.exportedUnitName ?? EXPORTED_UNIT_NAME;
  const exportObjectFiles = config.exportObjectFiles ?? ["unit.o"];
  const selectorObjectFiles =
    config.selectorObjectFile === undefined ? [] : [config.selectorObjectFile];
  const runtimeMainFileName = runtimeMainSourceFileName(config.runtime.mainSourcePath);
  const applicationStaticHermesFlags =
    config.applicationExportedUnitName === undefined
      ? undefined
      : capabilityApplicationStaticHermesFlags(config.toolchain.staticHermes.flags);
  const staticHermesCBundle = staticHermesCBundleEnabled(config.toolchain.staticHermes.flags);
  const applicationStaticHermesCBundle =
    applicationStaticHermesFlags === undefined
      ? undefined
      : staticHermesCBundleEnabled(applicationStaticHermesFlags);
  const linkExportObjectFiles = staticHermesCBundle
    ? ["-Wl,--whole-archive", ...exportObjectFiles, "-Wl,--no-whole-archive"]
    : exportObjectFiles;
  const staticHermesOutputArguments = staticHermesCBundle
    ? ["-o", C_BUNDLE_MANIFEST_PATH]
    : ["-o", "unit.c"];
  const applicationStaticHermesOutputArguments = applicationStaticHermesCBundle
    ? ["-o", C_BUNDLE_MANIFEST_PATH]
    : ["-o", "unit.c"];
  return {
    staticHermes: {
      executable: STATIC_HERMES_PRECOMPILER_LAUNCHER,
      args: [
        "--compiler",
        config.toolchain.staticHermes.executable,
        "--max-output-bytes",
        String(config.command.maxOutputBytes),
        "--request",
        "static-hermes-request.json",
        "--response",
        "static-hermes-response.json",
        "--",
        ...config.toolchain.staticHermes.flags,
        `-exported-unit=${exportedUnitName}`,
        ...staticHermesOutputArguments,
        "input.js",
      ],
    },
    ...(applicationStaticHermesFlags === undefined
      ? {}
      : {
          staticHermesApplication: {
            executable: STATIC_HERMES_PRECOMPILER_LAUNCHER,
            args: [
              "--compiler",
              config.toolchain.staticHermes.executable,
              "--max-output-bytes",
              String(config.command.maxOutputBytes),
              "--request",
              "application-static-hermes-request.json",
              "--response",
              "application-static-hermes-response.json",
              "--",
              ...applicationStaticHermesFlags,
              `-exported-unit=${config.applicationExportedUnitName}`,
              ...applicationStaticHermesOutputArguments,
              "input.js",
            ],
          },
        }),
    compileExport: {
      executable: config.toolchain.emscripten.executable,
      args: [...config.runtime.compileFlags, ...includeArguments, "-c", "unit.c", "-o", "unit.o"],
    },
    compileExportMember: {
      executable: config.toolchain.emscripten.executable,
      args: [...config.runtime.compileFlags, ...includeArguments, "-c"],
    },
    ...(applicationStaticHermesFlags === undefined
      ? {}
      : {
          compileApplicationExport: {
            executable: config.toolchain.emscripten.executable,
            args: [
              ...config.runtime.compileFlags,
              ...includeArguments,
              "-c",
              "unit.c",
              "-o",
              "unit.o",
            ],
          },
        }),
    compileMain: {
      executable: config.toolchain.emscripten.executable,
      args: [
        ...config.runtime.compileFlags,
        ...config.runtime.mainCompileFlags,
        `-DCONVEX_WASM_EXPORTED_UNIT=${config.entrySelectorSymbol ?? `sh_export_${exportedUnitName}`}`,
        ...(config.applicationEntrySelectorSymbol === undefined
          ? []
          : [
              `-DCONVEX_WASM_BRIDGE_EXPORTED_UNIT=${CAPABILITY_BRIDGE_ENTRY_SYMBOL}`,
              `-DCONVEX_WASM_FORMATTER_EXPORTED_UNIT=${CAPABILITY_FORMATTER_ENTRY_SYMBOL}`,
              `-DCONVEX_WASM_APPLICATION_EXPORTED_UNIT=${config.applicationEntrySelectorSymbol}`,
            ]),
        ...includeArguments,
        "-c",
        runtimeMainFileName,
        "-o",
        "runtime_main.o",
      ],
    },
    compileSelector: {
      executable: config.toolchain.emscripten.executable,
      args: [
        ...config.runtime.compileFlags,
        ...includeArguments,
        "-c",
        "cohort_selector.c",
        "-o",
        "cohort_selector.o",
      ],
    },
    link: {
      executable: config.toolchain.emscripten.executable,
      args: [
        ...config.runtime.linkFlags,
        ...linkExportObjectFiles,
        ...selectorObjectFiles,
        "runtime_main.o",
        ...config.runtime.archives,
        ...(config.entrySelectorSymbol === undefined
          ? []
          : ["-Wl,--export=convex_wasm_select_entry"]),
        "-o",
        "module.wasm",
      ],
    },
    precompile: {
      executable: config.toolchain.wasmtime.executable,
      args: [
        "--package",
        config.toolchain.wasmtime.packageDirectory,
        "--",
        "module.wasm",
        "module.cwasm",
        "--engine-identity",
        "engine-identity.json",
        "--consume-fuel",
        String(config.toolchain.wasmtime.engineConfig.consumeFuel),
        "--epoch-interruption",
        String(config.toolchain.wasmtime.engineConfig.epochInterruption),
        "--wasm-exceptions",
        String(config.toolchain.wasmtime.engineConfig.wasmExceptions),
        "--profiling-strategy",
        config.toolchain.wasmtime.engineConfig.profilingStrategy,
        "--target-triple",
        config.toolchain.wasmtime.target.triple,
        "--target-cpu",
        config.toolchain.wasmtime.target.cpu,
      ],
    },
  };
}

function runtimeMainSourceFileName(sourcePath) {
  const extension = extname(sourcePath).toLowerCase();
  if (extension === ".c") return "runtime_main.c";
  if (new Set([".cc", ".cpp", ".cxx"]).has(extension)) return "runtime_main.cpp";
  fail(`runtime.mainSourcePath must name a C or C++ source file, got ${sourcePath}`);
}
