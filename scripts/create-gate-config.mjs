#!/usr/bin/env node
/* global AbortSignal, Buffer, process */

import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  canonicalJson,
  convexWasmSerializedModuleMaxBytes,
} from "./lib/convex-wasm-artifact-pipeline.mjs";
import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";
import { gateRevisions } from "./lib/convex-wasm-gate-pins.mjs";

const execFile = promisify(execFileCallback);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const guestInitializationDiagnosticsModes = new Set([
  "production-class-only",
  "verbose-local",
]);
const platformLimitNames = Object.freeze([
  "argumentBytes",
  "documentsRead",
  "documentsWritten",
  "executionTimeMs",
  "readBytes",
  "resultBytes",
  "scheduledArgumentBytes",
  "scheduledFunctions",
  "writeBytes",
]);
const executionLimitNames = Object.freeze([
  "executionFuel",
  "maxGuestMemoryBytes",
  "maxHostOwnedBytes",
  "maxOperationCount",
  "maxResultBytes",
  "maxValueHandles",
  "timeoutMilliseconds",
]);

function usage() {
  return [
    "usage: create-gate-config.mjs",
    "       --gate-root STATIC_HERMES_WASMTIME_GATE",
    "       --precompiler-package VERIFIED_PRECOMPILER_PACKAGE",
    "       --policy PROJECT_POLICY.json",
    "       --artifact-config-output ARTIFACT_CONFIG.json",
    "       --platform-limits-output PLATFORM_LIMITS.json",
  ].join("\n");
}

function targetTriple() {
  if (process.platform === "linux" && process.arch === "x64") {
    return "x86_64-unknown-linux-gnu";
  }
  if (process.platform === "linux" && process.arch === "arm64") {
    return "aarch64-unknown-linux-gnu";
  }
  if (process.platform === "darwin" && process.arch === "x64") {
    return "x86_64-apple-darwin";
  }
  if (process.platform === "darwin" && process.arch === "arm64") {
    return "aarch64-apple-darwin";
  }
  throw new Error(
    `Static Hermes gate config does not support ${process.platform}/${process.arch}`,
  );
}

export function parseArguments(argumentsList) {
  const values = new Map();
  const options = new Set([
    "--artifact-config-output",
    "--gate-root",
    "--platform-limits-output",
    "--policy",
    "--precompiler-package",
  ]);
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !options.has(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error(usage());
    }
    values.set(option, value);
  }
  if (
    [
      "--artifact-config-output",
      "--gate-root",
      "--platform-limits-output",
      "--policy",
      "--precompiler-package",
    ].some((option) => !values.has(option))
  ) {
    throw new Error(usage());
  }
  const artifactConfigOutputPath = resolve(
    values.get("--artifact-config-output"),
  );
  const platformLimitsOutputPath = resolve(
    values.get("--platform-limits-output"),
  );
  if (artifactConfigOutputPath === platformLimitsOutputPath) {
    throw new Error("artifact config and platform limits outputs must differ");
  }
  return {
    artifactConfigOutputPath,
    gateRoot: resolve(values.get("--gate-root")),
    platformLimitsOutputPath,
    policyPath: resolve(values.get("--policy")),
    precompilerPackageDirectory: resolve(values.get("--precompiler-package")),
  };
}

function requireExactObject(value, keys, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(
      `${description} must contain exactly ${expected.join(", ")}`,
    );
  }
  return value;
}

export function normalizeGatePolicy(value) {
  const policy = requireExactObject(
    value,
    [
      "command",
      "executionLimits",
      "guestInitializationDiagnostics",
      "platformLimits",
    ],
    "gate policy",
  );
  const platformLimits = requireExactObject(
    policy.platformLimits,
    platformLimitNames,
    "platform limits",
  );
  const executionLimits = requireExactObject(
    policy.executionLimits,
    executionLimitNames,
    "execution limits",
  );
  for (const [name, limit] of Object.entries({
    ...platformLimits,
    ...executionLimits,
  })) {
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new Error(`${name} must be a positive safe integer`);
    }
  }
  if (
    executionLimits.timeoutMilliseconds > platformLimits.executionTimeMs ||
    executionLimits.maxResultBytes > platformLimits.resultBytes
  ) {
    throw new Error("execution limits exceed platform limits");
  }
  const command = requireExactObject(
    policy.command,
    ["environment", "maxOutputBytes", "phaseTimeoutMs", "timeExecutable"],
    "command policy",
  );
  const environment = requireExactObject(
    command.environment,
    ["HOME", "PATH"],
    "command environment",
  );
  if (
    typeof environment.HOME !== "string" ||
    !isAbsolute(environment.HOME) ||
    resolve(environment.HOME) !== environment.HOME ||
    typeof environment.PATH !== "string" ||
    environment.PATH.length === 0
  ) {
    throw new Error(
      "command environment requires a normalized absolute HOME and non-empty PATH",
    );
  }
  for (const name of ["maxOutputBytes", "phaseTimeoutMs"]) {
    if (!Number.isSafeInteger(command[name]) || command[name] <= 0) {
      throw new Error(`command ${name} must be a positive safe integer`);
    }
  }
  if (
    typeof command.timeExecutable !== "string" ||
    !isAbsolute(command.timeExecutable) ||
    resolve(command.timeExecutable) !== command.timeExecutable
  ) {
    throw new Error(
      "command timeExecutable must be a normalized absolute path",
    );
  }
  if (
    !guestInitializationDiagnosticsModes.has(
      policy.guestInitializationDiagnostics,
    )
  ) {
    throw new Error(
      "guestInitializationDiagnostics must be production-class-only or verbose-local",
    );
  }
  return Object.freeze({
    command: Object.freeze({
      environment: Object.freeze({ ...environment }),
      maxOutputBytes: command.maxOutputBytes,
      phaseTimeoutMs: command.phaseTimeoutMs,
      timeExecutable: command.timeExecutable,
    }),
    executionLimits: Object.freeze({ ...executionLimits }),
    guestInitializationDiagnostics: policy.guestInitializationDiagnostics,
    platformLimits: Object.freeze({ ...platformLimits }),
  });
}

async function requireRegularFile(
  path,
  description,
  { executable = false } = {},
) {
  const status = await fs.stat(path);
  if (!status.isFile()) {
    throw new Error(`${description} must be a regular file: ${path}`);
  }
  if (executable && (status.mode & 0o111) === 0) {
    throw new Error(`${description} must be executable: ${path}`);
  }
}

async function gitRevision(path, description) {
  const result = await execFile("git", ["-C", path, "rev-parse", "HEAD"], {
    encoding: "utf8",
    signal: AbortSignal.timeout(30_000),
  });
  const revision = result.stdout.trim();
  if (!/^[0-9a-f]{40}$/u.test(revision)) {
    throw new Error(`${description} does not have a full Git revision`);
  }
  return revision;
}

async function requireAbsent(path, description) {
  try {
    await fs.lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }
    throw error;
  }
  throw new Error(`${description} already exists: ${path}`);
}

async function writePrivateJson(path, value) {
  await fs.mkdir(dirname(path), { mode: 0o700, recursive: true });
  const handle = await fs.open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(`${canonicalJson(value)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.chmod(path, 0o600);
}

async function verifyPrivateJson(path, expectedValue, description) {
  const status = await fs.lstat(path, { bigint: true });
  const expectedOwner = BigInt(process.getuid());
  if (
    !status.isFile() ||
    status.uid !== expectedOwner ||
    (status.mode & 0o777n) !== 0o600n
  ) {
    throw new Error(
      `${description} must be a current-user-owned 0600 regular file: ${path}`,
    );
  }
  const handle = await fs.open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const opened = await handle.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== status.dev ||
      opened.ino !== status.ino ||
      opened.uid !== expectedOwner ||
      (opened.mode & 0o777n) !== 0o600n
    ) {
      throw new Error(`${description} changed before it was opened: ${path}`);
    }
    const bytes = await handle.readFile();
    if (!bytes.equals(Buffer.from(`${canonicalJson(expectedValue)}\n`))) {
      throw new Error(
        `${description} does not match the current verified gate: ${path}`,
      );
    }
  } finally {
    await handle.close();
  }
}

export function createStaticHermesGateArtifactConfig({
  gateRoot,
  policy,
  precompilerPackageDirectory,
  wasmtimeRevision,
}) {
  const normalizedPolicy = normalizeGatePolicy(policy);
  if (!/^[0-9a-f]{40}$/u.test(wasmtimeRevision)) {
    throw new Error("Wasmtime revision must be a full lowercase Git revision");
  }
  const emsdkRoot = resolve(gateRoot, "emsdk");
  return {
    command: {
      environment: {
        EM_CONFIG: resolve(emsdkRoot, ".emscripten"),
        EMSDK: emsdkRoot,
        HOME: normalizedPolicy.command.environment.HOME,
        PATH: normalizedPolicy.command.environment.PATH,
      },
      maxOutputBytes: normalizedPolicy.command.maxOutputBytes,
      phaseTimeoutMs: normalizedPolicy.command.phaseTimeoutMs,
      timeExecutable: normalizedPolicy.command.timeExecutable,
    },
    limits: {
      artifacts: {
        aotBytes: convexWasmSerializedModuleMaxBytes,
        generatedCBytes: 256 * 1024 * 1024,
        generatedJavaScriptBytes: 16 * 1024 * 1024,
        objectBytes: 256 * 1024 * 1024,
        wasmBytes: 320 * 1024 * 1024,
      },
      execution: normalizedPolicy.executionLimits,
    },
    runtime: {
      archives: [
        resolve(gateRoot, "build-wasm", "lib", "libhermesvm_a.a"),
        resolve(gateRoot, "build-wasm", "jsi", "libjsi.a"),
      ],
      compileFlags: [
        "-O2",
        "-DNDEBUG",
        "-fno-strict-aliasing",
        "-fno-strict-overflow",
        "-fwasm-exceptions",
        "-sWASM_LEGACY_EXCEPTIONS=0",
      ],
      includeDirectories: [
        resolve(gateRoot, "build-wasm", "lib", "config"),
        resolve(gateRoot, "hermes", "include"),
        resolve(gateRoot, "hermes", "API"),
        resolve(gateRoot, "hermes", "API", "jsi"),
        resolve(gateRoot, "hermes", "public"),
      ],
      linkFlags: [
        "-O1",
        "--profiling-funcs",
        "--no-entry",
        "-fwasm-exceptions",
        "-sWASM_LEGACY_EXCEPTIONS=0",
        "-sSUPPORT_LONGJMP=wasm",
        "-sSTANDALONE_WASM=1",
        "-sALLOW_MEMORY_GROWTH=1",
        "-sSTACK_SIZE=512KB",
        "-sINITIAL_HEAP=2MB",
        "-Wl,--export=convex_wasm_udf_prepare_selected_entry",
        "-Wl,--export=convex_wasm_udf_run",
        "-Wl,--export=convex_wasm_udf_destroy_runtime",
      ],
      mainCompileFlags:
        normalizedPolicy.guestInitializationDiagnostics ===
        "production-class-only"
          ? []
          : ["-DCONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS=1"],
      mainSourcePath: resolve(
        repositoryRoot,
        "scripts/lib/convex-wasm-native-capability-runtime-main.cpp",
      ),
      materialInputs: [],
    },
    toolchain: {
      emscripten: {
        executable: resolve(
          gateRoot,
          "emsdk",
          "upstream",
          "emscripten",
          "emcc",
        ),
        llvmRevision: "abd3b3a1445b5a8eeffae5c3912883faa9287fb7",
        materialInputs: [
          {
            label: "emscripten-config",
            path: resolve(gateRoot, "emsdk", ".emscripten"),
          },
          {
            label: "clang",
            path: resolve(gateRoot, "emsdk", "upstream", "bin", "clang"),
          },
          {
            label: "wasm-emscripten-finalize",
            path: resolve(
              gateRoot,
              "emsdk",
              "upstream",
              "bin",
              "wasm-emscripten-finalize",
            ),
          },
          {
            label: "wasm-ld",
            path: resolve(gateRoot, "emsdk", "upstream", "bin", "wasm-ld"),
          },
          {
            label: "wasm-opt",
            path: resolve(gateRoot, "emsdk", "upstream", "bin", "wasm-opt"),
          },
        ],
        revision: gateRevisions.emsdk,
      },
      staticHermes: {
        executable: resolve(gateRoot, "build-host", "bin", "shermes"),
        flags: [
          "-typed",
          "-O",
          "-Xenable-tdz",
          "-Xes6-block-scoping",
          "-emit-c",
          "-Xemit-c-bundle",
          "-Xemit-c-shard-size=2097152",
        ],
        materialInputs: [],
        revision: gateRevisions.hermes,
      },
      wasmtime: {
        engineConfig: {
          consumeFuel: true,
          epochInterruption: true,
          profilingStrategy: "perf-map",
          wasmExceptions: true,
        },
        materialInputs: [],
        packageDirectory: precompilerPackageDirectory,
        revision: wasmtimeRevision,
        target: { cpu: "baseline", triple: targetTriple() },
      },
    },
  };
}

async function verifyGate({ gateRoot, policy, precompilerPackageDirectory }) {
  const normalizedPolicy = normalizeGatePolicy(policy);
  const [hermesRevision, emsdkRevision, precompilerPackage] =
    await Promise.all([
      gitRevision(resolve(gateRoot, "hermes"), "Static Hermes checkout"),
      gitRevision(resolve(gateRoot, "emsdk"), "emsdk checkout"),
      loadAndVerifyPrecompilerPackage(precompilerPackageDirectory),
    ]);
  for (const [component, actual] of Object.entries({
    emsdk: emsdkRevision,
    hermes: hermesRevision,
  })) {
    if (actual !== gateRevisions[component]) {
      throw new Error(
        `${component} revision ${actual} does not match the maintained Static Hermes gate revision ${gateRevisions[component]}`,
      );
    }
  }
  const packagedWasmtimeRevision =
    precompilerPackage.manifest.identities.wasmtime.revision;
  if (
    packagedWasmtimeRevision !== gateRevisions.wasmtime ||
    precompilerPackage.manifest.platform.targetTriple !== targetTriple() ||
    !/^[0-9a-f]{40}$/u.test(packagedWasmtimeRevision)
  ) {
    throw new Error(
      "verified precompiler package does not match the current gate Wasmtime target",
    );
  }
  const config = createStaticHermesGateArtifactConfig({
    gateRoot,
    policy: normalizedPolicy,
    precompilerPackageDirectory,
    wasmtimeRevision: packagedWasmtimeRevision,
  });
  await Promise.all([
    requireRegularFile(
      config.toolchain.staticHermes.executable,
      "Static Hermes compiler",
      {
        executable: true,
      },
    ),
    requireRegularFile(
      config.toolchain.emscripten.executable,
      "Emscripten compiler",
      {
        executable: true,
      },
    ),
    ...config.toolchain.emscripten.materialInputs.map(({ label, path }) =>
      requireRegularFile(path, `Emscripten material ${label}`, {
        executable: label !== "emscripten-config",
      }),
    ),
    ...config.runtime.archives.map((path) =>
      requireRegularFile(path, "Static Hermes runtime archive"),
    ),
  ]);
  return {
    config,
    platformLimits: normalizedPolicy.platformLimits,
    precompilerPackage,
  };
}

export async function createStaticHermesGateConfigArtifacts(args) {
  await Promise.all([
    requireAbsent(args.artifactConfigOutputPath, "artifact config output"),
    requireAbsent(args.platformLimitsOutputPath, "platform limits output"),
  ]);
  const { config, platformLimits, precompilerPackage } = await verifyGate(args);
  await Promise.all([
    writePrivateJson(args.artifactConfigOutputPath, config),
    writePrivateJson(args.platformLimitsOutputPath, platformLimits),
  ]);
  return {
    artifactConfigOutputPath: args.artifactConfigOutputPath,
    platformLimitsOutputPath: args.platformLimitsOutputPath,
    precompilerPackageId: precompilerPackage.manifest.packageId,
    targetTriple: config.toolchain.wasmtime.target.triple,
  };
}

export async function verifyStaticHermesGateConfigArtifacts(args) {
  const { config, platformLimits, precompilerPackage } = await verifyGate(args);
  await Promise.all([
    verifyPrivateJson(
      args.artifactConfigOutputPath,
      config,
      "artifact config output",
    ),
    verifyPrivateJson(
      args.platformLimitsOutputPath,
      platformLimits,
      "platform limits output",
    ),
  ]);
  return {
    artifactConfigOutputPath: args.artifactConfigOutputPath,
    platformLimitsOutputPath: args.platformLimitsOutputPath,
    precompilerPackageId: precompilerPackage.manifest.packageId,
    targetTriple: config.toolchain.wasmtime.target.triple,
  };
}

export async function main(argumentsList) {
  const args = parseArguments(argumentsList);
  const policy = normalizeGatePolicy(
    JSON.parse(await fs.readFile(args.policyPath, "utf8")),
  );
  const result = await createStaticHermesGateConfigArtifacts({
    ...args,
    policy,
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main(process.argv.slice(2));
}
