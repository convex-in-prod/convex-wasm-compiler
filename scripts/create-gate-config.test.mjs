import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { allocatorInputSha256, verifyAllocatorGate } from "./setup-gate.mjs";

import {
  createStaticHermesGateArtifactConfig,
  normalizeGatePolicy,
  parseArguments,
} from "./create-gate-config.mjs";

const wasmtimeRevision = "a".repeat(40);
const execFile = promisify(execFileCallback);
const policy = {
  command: {
    environment: { HOME: "/home/build", PATH: "/usr/bin:/bin" },
    maxOutputBytes: 64 * 1024 * 1024,
    phaseTimeoutMs: 45 * 60 * 1_000,
    timeExecutable: "/usr/bin/time",
  },
  executionLimits: {
    executionFuel: 10_000_000_000_000,
    maxGuestMemoryBytes: 128 * 1024 * 1024,
    maxHostOwnedBytes: 16 * 1024 * 1024,
    maxOperationCount: 10_000,
    maxResultBytes: 8 * 1024 * 1024,
    maxValueHandles: 1_024,
    timeoutMilliseconds: 1_000,
  },
  guestInitializationDiagnostics: "verbose-local",
  platformLimits: {
    argumentBytes: 16 * 1024 * 1024,
    documentsRead: 32_000,
    documentsWritten: 16_000,
    executionTimeMs: 1_000,
    readBytes: 16 * 1024 * 1024,
    resultBytes: 16 * 1024 * 1024,
    scheduledArgumentBytes: 16 * 1024 * 1024,
    scheduledFunctions: 1_000,
    writeBytes: 16 * 1024 * 1024,
  },
};

test("Static Hermes gate config requires distinct explicit outputs", () => {
  const parsed = parseArguments([
    "--gate-root",
    "/toolchain",
    "--precompiler-package",
    "/package",
    "--policy",
    "project-policy.json",
    "--artifact-config-output",
    "artifact.json",
    "--platform-limits-output",
    "limits.json",
  ]);
  assert.equal(parsed.gateRoot, "/toolchain");
  assert.equal(parsed.precompilerPackageDirectory, "/package");
  assert.match(parsed.policyPath, /project-policy\.json$/u);
  assert.match(parsed.artifactConfigOutputPath, /artifact\.json$/u);
  assert.match(parsed.platformLimitsOutputPath, /limits\.json$/u);
  assert.throws(
    () =>
      parseArguments([
        "--gate-root",
        "/toolchain",
        "--precompiler-package",
        "/package",
        "--policy",
        "project-policy.json",
        "--artifact-config-output",
        "same.json",
        "--platform-limits-output",
        "same.json",
      ]),
    /must differ/u,
  );
  assert.throws(
    () =>
      normalizeGatePolicy({
        ...policy,
        executionLimits: {
          ...policy.executionLimits,
          maxResultBytes: 32 * 1024 * 1024,
        },
      }),
    /exceed platform limits/u,
  );
  assert.throws(
    () =>
      normalizeGatePolicy({
        ...policy,
        guestInitializationDiagnostics: "verbose",
      }),
    /production-class-only or verbose-local/u,
  );
});

test("Static Hermes gate config separates total linear memory from the Hermes GC heap", async () => {
  const config = createStaticHermesGateArtifactConfig({
    gateRoot: "/toolchain",
    policy,
    precompilerPackageDirectory: "/package",
    wasmtimeRevision,
  });
  assert.deepEqual(config.toolchain.staticHermes.flags, [
    "-typed",
    "-O",
    "-Xenable-tdz",
    "-Xes6-block-scoping",
    "-emit-c",
    "-Xemit-c-bundle",
    "-Xemit-c-shard-size=2097152",
    "-Xemit-c-layout",
    "-Xsplit-c-exceptions",
    "-fguarded-byte-array-loops",
    "-fnative-integer-registers",
    "-fguarded-data-property-definitions",
    "-fscoped-normalization-reuse",
    "-fasync-frame-arguments",
    "-fasync-generator-results",
  ]);
  assert.equal(config.toolchain.wasmtime.packageDirectory, "/package");
  assert.equal(config.toolchain.wasmtime.revision, wasmtimeRevision);
  assert.equal(config.command.environment.HOME, "/home/build");
  assert.equal(config.command.environment.PATH, "/usr/bin:/bin");
  assert.equal(config.command.environment.EM_BINARYEN_ROOT, "/toolchain/binaryen-tools");
  const toolInputs = new Map(config.toolchain.emscripten.materialInputs.map(({ label, path }) => [label, path]));
  assert.equal(toolInputs.get("wasm-opt"), "/toolchain/binaryen-tools/bin/wasm-opt");
  assert.equal(toolInputs.get("wasm-emscripten-finalize"), "/toolchain/binaryen-tools/bin/wasm-emscripten-finalize");
  assert.equal(toolInputs.get("binaryen-receipt"), "/toolchain/binaryen-tools/toolchain.json");
  assert.equal(config.toolchain.wasmtime.target.cpu, "baseline");
  assert.match(
    config.toolchain.wasmtime.target.triple,
    /unknown-linux|apple-darwin/u,
  );
  assert.equal(
    config.limits.artifacts.generatedJavaScriptBytes,
    16 * 1024 * 1024,
  );
  assert.equal(config.limits.artifacts.generatedCBytes, 256 * 1024 * 1024);
  assert.equal(config.limits.artifacts.aotBytes, 1024 * 1024 * 1024);
  assert.equal(config.limits.artifacts.wasmBytes, 320 * 1024 * 1024);
  assert.equal(config.limits.execution.executionFuel, 10_000_000_000_000);
  assert.equal(config.limits.execution.maxGuestMemoryBytes, 128 * 1024 * 1024);
  assert.equal(config.limits.execution.timeoutMilliseconds, 1_000);
  assert.equal(
    createStaticHermesGateArtifactConfig({
      gateRoot: "/toolchain",
      policy: {
        ...policy,
        platformLimits: { ...policy.platformLimits, executionTimeMs: 5_000 },
        executionLimits: {
          ...policy.executionLimits,
          timeoutMilliseconds: 5_000,
        },
      },
      precompilerPackageDirectory: "/package",
      wasmtimeRevision,
    }).limits.execution.timeoutMilliseconds,
    5_000,
  );
  assert.match(
    await fs.readFile(config.runtime.mainSourcePath, "utf8"),
    /--gc-max-heap=64MiB/u,
  );
  assert.deepEqual(config.runtime.includeDirectories, [
    "/toolchain/build-wasm/lib/config",
    "/toolchain/hermes/include",
    "/toolchain/hermes/API",
    "/toolchain/hermes/API/jsi",
    "/toolchain/hermes/public",
  ]);
  assert.equal(config.runtime.compileFlags.at(0), "-O2");
  assert.deepEqual(config.runtime.archives, [
    "/toolchain/build-wasm/lib/libhermesvm_a.a",
    "/toolchain/build-wasm/jsi/libjsi.a",
    "/toolchain/build-wasm/external/icu-small/libhermesStaticIcu.a",
    "/toolchain/build-wasm/lib/libconvex_wasm_allocator.a",
  ]);
  assert.deepEqual(config.runtime.mainCompileFlags, [
    "-DCONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS=1",
  ]);
  assert.equal(config.runtime.linkFlags.at(0), "-O2");
  assert.equal(config.runtime.linkFlags.includes("-sMALLOC=none"), true);
  assert.equal(
    config.runtime.linkFlags.includes(
      "-Wl,--export=convex_wasm_udf_prepare_selected_entry",
    ),
    true,
  );
  assert.equal(
    config.runtime.linkFlags.includes(
      "-Wl,--export=convex_wasm_udf_memory_maintenance",
    ),
    true,
  );
  assert.equal(
    config.runtime.linkFlags.at(-1),
    "-Wl,--export=convex_wasm_udf_destroy_runtime",
  );
});

test("allocator gate receipt rejects changed SDK inputs and replaced archives", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "allocator-gate-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const sdk = join(root, "emsdk");
  const llvm = join(sdk, "upstream");
  const emscripten = join(llvm, "emscripten");
  const inputs = [
    join(sdk, ".emscripten"),
    join(llvm, "bin/clang"), join(llvm, "bin/llvm-ar"),
    join(llvm, "lib/clang/fixture/include/stddef.h"),
    ...[
      "emcc.py", "emscripten-version.txt", "src/settings.js",
      "src/settings_internal.js", "system/lib/dlmalloc.c",
      "system/lib/libc/sbrk.c", "tools/system_libs.py", "tools/shared.py",
      "cache/sysroot/include/emscripten/heap.h",
    ].map(name => join(emscripten, name)),
  ];
  for (const path of inputs) {
    await fs.mkdir(dirname(path), { recursive: true });
    await fs.writeFile(path, "original\n");
  }
  const archive = join(root, "build-wasm/lib/libconvex_wasm_allocator.a");
  const bytes = Buffer.from("fixture archive\n");
  await fs.mkdir(dirname(archive), { recursive: true });
  await fs.writeFile(archive, bytes);
  const inputSha256 = await allocatorInputSha256(root);
  await fs.writeFile(`${archive}.json`, JSON.stringify({
    inputSha256,
    archiveSha256: createHash("sha256").update(bytes).digest("hex"),
    archiveBytes: bytes.length,
  }));
  await verifyAllocatorGate(root);
  for (const path of inputs) {
    await fs.appendFile(path, "changed\n");
    await assert.rejects(verifyAllocatorGate(root), /missing or stale/u);
    await fs.writeFile(path, "original\n");
  }
  await fs.mkdir(join(emscripten, "tools/__pycache__"));
  await fs.writeFile(join(emscripten, "tools/__pycache__/shared.pyc"), "generated");
  await verifyAllocatorGate(root);
  await fs.writeFile(archive, "replacement\n");
  await assert.rejects(verifyAllocatorGate(root), /missing or stale/u);
  await fs.writeFile(archive, bytes);
  await verifyAllocatorGate(root);
  await fs.unlink(`${archive}.json`);
  await assert.rejects(verifyAllocatorGate(root), /missing or stale/u);
});

test("allocator builder reads current SDK source despite timestamp-valid bytecode", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "allocator-bytecode-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const sdk = join(root, "emscripten");
  const source = join(sdk, "tools/system_libs.py");
  await fs.mkdir(dirname(source), { recursive: true });
  await fs.writeFile(join(sdk, "tools/__init__.py"), "");
  const timestamp = new Date("2025-01-01T00:00:00Z");
  await fs.writeFile(source, "raise RuntimeError('stale SDK source')\n");
  await fs.utimes(source, timestamp, timestamp);
  await execFile("python3", [
    "-E", "-c",
    "import py_compile, sys; py_compile.compile(sys.argv[1], doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)",
    source,
  ], { timeout: 30_000 });
  // Python's default cache validation checks only timestamp seconds and size.
  // Stop at the first SDK import so this regression needs no native compilation.
  await fs.writeFile(source, "raise RuntimeError('fresh SDK source')\n");
  await fs.utimes(source, timestamp, timestamp);
  await assert.rejects(execFile("python3", [
    "-E", fileURLToPath(new URL("./build-wasm-allocator.py", import.meta.url)),
    "--emscripten", sdk, "--output", join(root, "allocator.a"),
  ], { timeout: 30_000 }), (error) => {
    assert.match(error.stderr, /RuntimeError: fresh SDK source/u);
    return true;
  });
});

test("Static Hermes gate config emits production guest-initialization classes without details", () => {
  const config = createStaticHermesGateArtifactConfig({
    gateRoot: "/toolchain",
    policy: {
      ...policy,
      guestInitializationDiagnostics: "production-class-only",
    },
    precompilerPackageDirectory: "/package",
    wasmtimeRevision,
  });
  assert.deepEqual(config.runtime.mainCompileFlags, []);
});
