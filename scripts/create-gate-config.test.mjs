import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import test from "node:test";

import {
  createStaticHermesGateArtifactConfig,
  normalizeGatePolicy,
  parseArguments,
} from "./create-gate-config.mjs";

const wasmtimeRevision = "a".repeat(40);
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
  ]);
  assert.equal(config.toolchain.wasmtime.packageDirectory, "/package");
  assert.equal(config.toolchain.wasmtime.revision, wasmtimeRevision);
  assert.equal(config.command.environment.HOME, "/home/build");
  assert.equal(config.command.environment.PATH, "/usr/bin:/bin");
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
  assert.equal(config.limits.artifacts.aotBytes, 640 * 1024 * 1024);
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
    /--gc-max-heap=32MiB/u,
  );
  assert.deepEqual(config.runtime.includeDirectories, [
    "/toolchain/build-wasm/lib/config",
    "/toolchain/hermes/include",
    "/toolchain/hermes/API",
    "/toolchain/hermes/API/jsi",
    "/toolchain/hermes/public",
  ]);
  assert.equal(config.runtime.compileFlags.at(0), "-O2");
  assert.deepEqual(config.runtime.mainCompileFlags, [
    "-DCONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS=1",
  ]);
  assert.equal(config.runtime.linkFlags.at(0), "-O1");
  assert.equal(
    config.runtime.linkFlags.includes(
      "-Wl,--export=convex_wasm_udf_prepare_selected_entry",
    ),
    true,
  );
  assert.equal(
    config.runtime.linkFlags.at(-1),
    "-Wl,--export=convex_wasm_udf_destroy_runtime",
  );
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
