import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import test from "node:test";
import ts from "typescript";
import { buildSync } from "esbuild";

import { renderConvexWasmIntrinsicHardeningPrelude } from "./convex-wasm-intrinsic-hardening.mjs";
import { renderOpaqueAbiHeader } from "./convex-wasm-lowering.mjs";
import { renderConvexWasmTargetRuntimeGlobalPrelude } from "./convex-wasm-runtime-surface.mjs";

// This executes the actual adapter with a built host Hermes runtime. Run under
// the same native-build resource guard used for the Hermes build.
test("native adapter materializes packed values and validates hardened intrinsics", (context) => {
  const source = process.env.CONVEX_HERMES_TEST_SOURCE_ROOT;
  const build = process.env.CONVEX_HERMES_TEST_BUILD_ROOT;
  if (source === undefined || build === undefined) {
    context.skip(
      "set CONVEX_HERMES_TEST_SOURCE_ROOT and CONVEX_HERMES_TEST_BUILD_ROOT",
    );
    return;
  }
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const sdkRoot =
    process.env.CONVEX_SDK_TEST_SOURCE_ROOT ??
    dirname(createRequire(import.meta.url).resolve("convex/package.json"));
  const temporary = mkdtempSync(join(tmpdir(), "convex-native-values-"));
  const run = (command, args) => {
    const result = spawnSync(command, args, {
      encoding: "utf8",
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
    });
    assert.equal(
      result.status,
      0,
      `${result.error ?? ""}\n${result.stdout}\n${result.stderr}`,
    );
    return result.stdout;
  };
  const archives = (directory) =>
    readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory()
        ? archives(path)
        : entry.name.endsWith(".a")
          ? [path]
          : [];
    });
  try {
    const sdkFixture = join(temporary, "sdk.js");
    buildSync({
      entryPoints: [join(root, "scripts/test-fixtures/native-values/sdk.js")],
      alias: { "sdk-database": join(sdkRoot, "src/server/impl/database_impl.ts") },
      bundle: true,
      format: "iife",
      target: "es2022",
      outfile: sdkFixture,
    });
    writeFileSync(
      join(temporary, "convex_wasm_opaque_abi_v3.h"),
      renderOpaqueAbiHeader(),
    );
    writeFileSync(
      join(temporary, "hardening.js"),
      ts.transpileModule(
        [
          "globalThis.__convexTestHostImports = {extern_c: () => () => 1};",
          // The host evaluator cannot compile Static Hermes extern_c syntax;
          // substitute the import provider, retaining the actual global setup.
          renderConvexWasmTargetRuntimeGlobalPrelude().replaceAll(
            "$SHBuiltin.extern_c",
            "__convexTestHostImports.extern_c",
          ),
          renderConvexWasmIntrinsicHardeningPrelude({
            nativeDescriptorValidation: true,
          }),
        ].join("\n"),
        { compilerOptions: { target: ts.ScriptTarget.ES2022 } },
      ).outputText,
    );
    const executable = join(temporary, "native-values");
    run(process.env.CXX ?? "c++", [
      "-std=c++17",
      "-O1",
      "-ffunction-sections",
      "-fdata-sections",
      "-Wno-attributes",
      "-DSTATIC_HERMES",
      "-DFLATBUFFERS_LOCALE_INDEPENDENT=0",
      "-DCONVEX_WASM_BRIDGE_EXPORTED_UNIT=test_bridge",
      "-DCONVEX_WASM_FORMATTER_EXPORTED_UNIT=test_formatter",
      ...[
        temporary,
        join(build, "lib/config"),
        join(source, "include"),
        join(source, "API"),
        join(source, "API/jsi"),
        join(source, "public"),
        join(root, "scripts/vendor/flatbuffers/include"),
      ].map((path) => `-I${path}`),
      join(root, "scripts/test-fixtures/native-values/main.cpp"),
      "-o",
      executable,
      "-Wl,--gc-sections",
      "-Wl,--start-group",
      ...archives(join(build, "lib")),
      join(build, "API/hermes/libhermesapi.a"),
      join(build, "public/hermes/Public/libhermesPublic.a"),
      join(build, "jsi/libjsi.a"),
      join(build, "external/dtoa/libdtoa.a"),
      join(build, "external/llvh/lib/Support/libLLVHSupport.a"),
      join(build, "external/llvh/lib/Demangle/libLLVHDemangle.a"),
      ...archives(join(build, "external/boost")),
      "-Wl,--end-group",
      "-licui18n",
      "-licuuc",
      "-licudata",
      "-ldl",
      "-lpthread",
    ]);
    assert.match(
      run(executable, [
        join(temporary, "hardening.js"),
        sdkFixture,
        process.env.CONVEX_SDK_TEST_SOURCE_ROOT === undefined
          ? "legacy-allowed"
          : "require-records",
      ]),
      /native values and intrinsic validation passed/u,
    );
  } finally {
    rmSync(temporary, { force: true, recursive: true });
  }
});
