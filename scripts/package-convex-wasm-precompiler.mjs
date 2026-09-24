#!/usr/bin/env node
/* global AbortSignal, Buffer, process */

import { randomBytes } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  canonicalCompilerPackageJson,
  hashAndInspectCompilerBinary,
  platformForCompilerTarget,
  rustHostFromVerboseVersion,
  sha256Bytes,
} from "./lib/convex-wasm-compiler-package.mjs";
import {
  createPrecompilerPackageManifest,
  loadAndVerifyPrecompilerPackage,
  precompilerPackageBinaryRelativePath,
  precompilerPackageKind,
  precompilerPackageManifestName,
  precompilerPackageSchemaVersion,
} from "./lib/convex-wasm-precompiler-package.mjs";
import {
  describeNativeCommandTermination,
  positiveIntegerEnvironment,
  runBoundedNativeCommand,
} from "./lib/bounded-native-command.mjs";
import {
  assertBinaryOmitsLocalBuildPaths,
  cleanNativeBuildEnvironment,
  collectRustCrateSourceIdentity,
  loadBuildInputs,
  loadRustIdentity,
  resolveCargoBuildJobs,
  nativePackageRustflagArguments,
  resolveNativePackageBuildDirectory,
  resolveNativePackageBuildRoot,
} from "./package-convex-wasm-compiler.mjs";
import { smokePackagedPrecompiler } from "./smoke-packaged-convex-wasm-precompiler.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDirectory, "..");
const crateDirectory = join(scriptDirectory, "convex-wasm-precompiler");
const wasmtimeFeatures = Object.freeze([
  "all-arch",
  "async",
  "cranelift",
  "gc-null",
  "incremental-cache",
  "parallel-compilation",
  "runtime",
  "std",
]);

function usage() {
  return [
    "usage: package-convex-wasm-precompiler.mjs --output-root PATH [--target TRIPLE]",
    "",
    "Builds and packages the native companion for the current Linux or macOS host.",
    "The target defaults to rustc's host and cross-packaging is rejected.",
  ].join("\n");
}

export function parsePrecompilerPackageArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (!["--output-root", "--target"].includes(option) || value === undefined) {
      throw new Error(usage());
    }
    if (value.length === 0 || values.has(option)) {
      throw new Error(`${option} must be set exactly once\n${usage()}`);
    }
    values.set(option, value);
  }
  if (!values.has("--output-root")) {
    throw new Error(`missing --output-root\n${usage()}`);
  }
  return {
    outputRoot: resolve(values.get("--output-root")),
    targetTriple: values.get("--target"),
  };
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function wasmtimeIdentityFromLockedPackages(lockedPackages) {
  const wasmtimeSources = new Set(lockedPackages.map(({ source }) => source));
  if (wasmtimeSources.size !== 1) {
    throw new Error("Cargo.lock must resolve every Wasmtime package from one exact revision");
  }
  const [wasmtimeSource] = wasmtimeSources;
  const wasmtimeSourceMatch = wasmtimeSource.match(
    /^git\+(https:\/\/github\.com\/bytecodealliance\/wasmtime)\?rev=([0-9a-f]{40})#([0-9a-f]{40})$/u
  );
  if (wasmtimeSourceMatch === null || wasmtimeSourceMatch[2] !== wasmtimeSourceMatch[3]) {
    throw new Error(
      "Cargo.lock must bind Wasmtime's requested revision to the same resolved commit"
    );
  }
  return {
    features: [...wasmtimeFeatures],
    git: wasmtimeSourceMatch[1],
    lockedPackages,
    revision: wasmtimeSourceMatch[2],
  };
}

export async function collectPrecompilerSourceIdentity(repositoryRoot = repoRoot) {
  return collectRustCrateSourceIdentity({
    crateRelativePath: "scripts/convex-wasm-precompiler",
    description: "precompiler source",
    repositoryRoot,
  });
}

function quotedTomlValue(text, key) {
  const matches = [...text.matchAll(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]+)"\\s*$`, "gmu"))];
  if (matches.length !== 1) {
    throw new Error(`rust-toolchain.toml must declare exactly one ${key}`);
  }
  return matches[0][1];
}

async function sourceMetadata(source) {
  const cargoLockPath = join(crateDirectory, "Cargo.lock");
  const toolchainPath = join(crateDirectory, "rust-toolchain.toml");
  const [cargoLockText, toolchainText] = await Promise.all([
    fs.readFile(cargoLockPath, "utf8"),
    fs.readFile(toolchainPath, "utf8"),
  ]);
  const cargoLock = source.materials.find(
    (material) => material.path === "scripts/convex-wasm-precompiler/Cargo.lock"
  );
  const toolchainFile = source.materials.find(
    (material) => material.path === "scripts/convex-wasm-precompiler/rust-toolchain.toml"
  );
  if (cargoLock === undefined || toolchainFile === undefined) {
    throw new Error("precompiler source identity is missing Cargo.lock or rust-toolchain.toml");
  }
  if (
    cargoLock.sha256 !== sha256Bytes(cargoLockText) ||
    cargoLock.size !== Buffer.byteLength(cargoLockText) ||
    toolchainFile.sha256 !== sha256Bytes(toolchainText) ||
    toolchainFile.size !== Buffer.byteLength(toolchainText)
  ) {
    throw new Error("precompiler identity input changed after the source snapshot");
  }
  const lockedPackages = [];
  for (const section of cargoLockText.split(/^\[\[package\]\]\s*$/mu).slice(1)) {
    const value = (key) => section.match(new RegExp(`^${key} = "([^"]+)"$`, "mu"))?.[1];
    const name = value("name");
    if (name === undefined || !name.startsWith("wasmtime")) {
      continue;
    }
    const sourceValue = value("source");
    const version = value("version");
    if (sourceValue === undefined || version === undefined) {
      throw new Error(`Cargo.lock has an incomplete identity for ${name}`);
    }
    lockedPackages.push({ name, source: sourceValue, version });
  }
  lockedPackages.sort((left, right) =>
    compareStrings(
      `${left.name}\0${left.version}\0${left.source}`,
      `${right.name}\0${right.version}\0${right.source}`
    )
  );
  const componentMatch = toolchainText.match(/^\s*components\s*=\s*\[([^\]]*)\]\s*$/mu);
  const components =
    componentMatch === null
      ? []
      : [...componentMatch[1].matchAll(/"([^"]+)"/gu)]
          .map((match) => match[1])
          .sort(compareStrings);
  return {
    cargoLock,
    toolchain: {
      channel: quotedTomlValue(toolchainText, "channel"),
      components,
      file: toolchainFile,
      profile: quotedTomlValue(toolchainText, "profile"),
    },
    wasmtime: wasmtimeIdentityFromLockedPackages(lockedPackages),
  };
}

async function ensurePrivateDirectory(path) {
  await fs.mkdir(path, { mode: 0o700, recursive: true });
  const status = await fs.lstat(path);
  if (!status.isDirectory() || status.isSymbolicLink()) {
    throw new Error(`${path} must be a directory, not a symbolic link`);
  }
  if (typeof process.getuid === "function" && status.uid !== process.getuid()) {
    throw new Error(`${path} must be owned by the current user`);
  }
  await fs.chmod(path, 0o700);
}

async function syncDirectory(path) {
  const handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0));
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export function resolvePrecompilerCargoTargetDirectory(environment = process.env) {
  return resolve(environment.CARGO_TARGET_DIR ?? join(crateDirectory, "target"));
}

async function buildPrecompiler(targetTriple, buildInputs, source, cargoBuildJobs) {
  const cargoTestArguments = [
    "test",
    "--locked",
    "--release",
    "--target",
    targetTriple,
    "--bin",
    "convex-wasm-precompiler",
  ];
  const cargoArguments = [
    "build",
    "--locked",
    "--release",
    "--target",
    targetTriple,
    "--bin",
    "convex-wasm-precompiler",
    "--message-format=json-render-diagnostics",
  ];
  const runnerCargoArguments = [
    "build",
    "--locked",
    "--release",
    "--target",
    targetTriple,
    "--bin",
    "convex-wasm-wasmtime-runner",
    "--message-format=json-render-diagnostics",
  ];
  const environment = cleanNativeBuildEnvironment(process.env);
  const cargoTargetDirectory = resolvePrecompilerCargoTargetDirectory(environment);
  const cargoBuildDirectory = resolveNativePackageBuildDirectory({
    buildInputs: buildInputs.manifest,
    packageKind: precompilerPackageKind,
    sourceTreeSha256: source.treeSha256,
    targetTriple,
    environment,
  });
  environment[buildInputs.execution.cargoTargetLinkerVariable] =
    buildInputs.execution.compilerDriverPath;
  environment.CARGO_BUILD_BUILD_DIR = cargoBuildDirectory;
  environment.CC = buildInputs.execution.compilerDriverPath;
  environment.CARGO_BUILD_JOBS = String(cargoBuildJobs);
  environment.CARGO_HOME = buildInputs.execution.cargoHomePath;
  environment.CARGO_INCREMENTAL = "0";
  environment.CARGO_TARGET_DIR = cargoTargetDirectory;
  environment.CARGO_TERM_COLOR = "never";
  environment.LD = buildInputs.execution.linkerPath;
  environment.RUSTC = buildInputs.execution.rustcPath;
  environment.RUSTC_WRAPPER = buildInputs.execution.rustcWrapperPath;
  environment.RUSTC_WORKSPACE_WRAPPER = buildInputs.execution.rustcWrapperPath;
  environment.CARGO_ENCODED_RUSTFLAGS = nativePackageRustflagArguments(
    repoRoot,
    cargoTargetDirectory,
    cargoBuildDirectory,
    buildInputs.execution.cargoHomePath
  ).join("\x1f");
  delete environment.RUSTFLAGS;
  if (buildInputs.execution.sdkRoot === undefined) {
    delete environment.SDKROOT;
  } else {
    environment.SDKROOT = buildInputs.execution.sdkRoot;
  }
  environment.SOURCE_DATE_EPOCH = "0";
  environment.TMPDIR = resolve(process.env.TMPDIR ?? "/var/tmp");
  const timeoutMs = positiveIntegerEnvironment(
    process.env,
    "CONVEX_WASM_NATIVE_PACKAGE_TIMEOUT_MS",
    30 * 60 * 1000
  );
  let binaryPath;
  for (const [operation, argumentsList] of [
    ["Convex Wasm precompiler Cargo test", cargoTestArguments],
    ["Convex Wasm precompiler Cargo build", cargoArguments],
    ["Convex Wasm matrix runner Cargo build", runnerCargoArguments],
  ]) {
    const result = await runBoundedNativeCommand({
      arguments: argumentsList,
      command: buildInputs.execution.cargoPath,
      cwd: crateDirectory,
      environment,
      maxOutputBytes: 4 * 1024 * 1024,
      operation,
      timeoutMs,
    });
    if (result.termination !== undefined) {
      throw new Error(`${operation} ${describeNativeCommandTermination(result.termination)}`);
    }
    if (result.code !== 0) {
      const output = result.output.toString("utf8").trim();
      throw new Error(
        `${operation} failed with ${
          result.signal === null ? `exit ${result.code}` : `signal ${result.signal}`
        }${output.length === 0 ? "" : `\n${output}`}`
      );
    }
    if (argumentsList === cargoArguments) {
      const executablePaths = new Set();
      for (const line of result.stdout.toString("utf8").split("\n")) {
        if (line.length === 0) {
          continue;
        }
        const message = JSON.parse(line);
        if (
          message.reason === "compiler-artifact" &&
          message.target?.name === "convex-wasm-precompiler" &&
          message.profile?.test === false &&
          typeof message.executable === "string"
        ) {
          executablePaths.add(await fs.realpath(message.executable));
        }
      }
      if (executablePaths.size !== 1) {
        throw new Error(
          `Cargo build must report exactly one release precompiler binary, found ${executablePaths.size}`
        );
      }
      [binaryPath] = executablePaths;
    }
  }
  if (binaryPath === undefined) {
    throw new Error("Cargo build completed without reporting the precompiler binary");
  }
  return {
    binaryPath,
    cargoArguments,
    cargoTestArguments,
  };
}

async function publishPackage(outputRoot, manifest, binaryPath) {
  const targetRoot = join(outputRoot, manifest.platform.targetTriple);
  const finalPath = join(targetRoot, manifest.packageId);
  await ensurePrivateDirectory(outputRoot);
  await ensurePrivateDirectory(targetRoot);
  try {
    const existing = await loadAndVerifyPrecompilerPackage(finalPath);
    if (
      canonicalCompilerPackageJson(existing.manifest) !== canonicalCompilerPackageJson(manifest)
    ) {
      throw new Error(`existing precompiler package disagrees with ${manifest.packageId}`);
    }
    return { cache: "hit", path: finalPath };
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
      throw error;
    }
  }
  const stagingRoot = join(
    targetRoot,
    `.publish-${manifest.packageId}-${process.pid}-${randomBytes(8).toString("hex")}`
  );
  const stagingPath = join(stagingRoot, manifest.packageId);
  await fs.mkdir(join(stagingPath, "bin"), { mode: 0o700, recursive: true });
  await fs.chmod(stagingRoot, 0o700);
  await fs.chmod(stagingPath, 0o700);
  await fs.chmod(join(stagingPath, "bin"), 0o700);
  try {
    const publishedBinary = join(stagingPath, precompilerPackageBinaryRelativePath);
    await fs.copyFile(binaryPath, publishedBinary, fsConstants.COPYFILE_EXCL);
    await fs.chmod(publishedBinary, 0o700);
    const binaryHandle = await fs.open(publishedBinary, fsConstants.O_RDONLY);
    try {
      await binaryHandle.sync();
    } finally {
      await binaryHandle.close();
    }
    const manifestPath = join(stagingPath, precompilerPackageManifestName);
    const manifestHandle = await fs.open(
      manifestPath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
      0o600
    );
    try {
      await manifestHandle.writeFile(`${canonicalCompilerPackageJson(manifest)}\n`);
      await manifestHandle.sync();
    } finally {
      await manifestHandle.close();
    }
    await fs.chmod(manifestPath, 0o600);
    await loadAndVerifyPrecompilerPackage(stagingPath);
    await smokePackagedPrecompiler(stagingPath);
    await Promise.all([syncDirectory(join(stagingPath, "bin")), syncDirectory(stagingPath)]);
    try {
      await fs.rename(stagingPath, finalPath);
      await syncDirectory(targetRoot);
      return { cache: "miss", path: finalPath };
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY")
        )
      ) {
        throw error;
      }
      const existing = await loadAndVerifyPrecompilerPackage(finalPath);
      if (existing.manifest.packageId !== manifest.packageId) {
        throw new Error(`published package ${finalPath} has a different package ID`);
      }
      return { cache: "hit", path: finalPath };
    }
  } finally {
    await fs.rm(stagingRoot, { force: true, recursive: true });
  }
}

export async function packagePrecompiler({
  cargoBuildJobs: requestedCargoBuildJobs,
  outputRoot,
  targetTriple: requestedTarget,
}) {
  if (!["darwin", "linux"].includes(process.platform) || !["arm64", "x64"].includes(process.arch)) {
    throw new Error(`precompiler packaging does not support ${process.platform}/${process.arch}`);
  }
  const cargoBuildJobs = resolveCargoBuildJobs(process.env, requestedCargoBuildJobs);
  const [rustContext, beforeSource] = await Promise.all([
    loadRustIdentity(crateDirectory),
    collectPrecompilerSourceIdentity(),
  ]);
  const rustHost = rustHostFromVerboseVersion(rustContext.versionIdentity.rustcVerboseVersion);
  const targetTriple = requestedTarget ?? rustHost;
  if (targetTriple !== rustHost) {
    throw new Error(
      `target ${targetTriple} does not match native Rust host ${rustHost}; package on the target host`
    );
  }
  const platform = platformForCompilerTarget(targetTriple);
  if (platform.os !== process.platform || platform.arch !== process.arch) {
    throw new Error(`target ${targetTriple} does not match ${process.platform}/${process.arch}`);
  }

  const buildInputs = await loadBuildInputs(
    rustContext,
    targetTriple,
    cargoBuildJobs,
    crateDirectory
  );
  const release = await buildPrecompiler(
    targetTriple,
    buildInputs,
    beforeSource,
    cargoBuildJobs
  );
  await assertBinaryOmitsLocalBuildPaths(
    release.binaryPath,
    [
      repoRoot,
      buildInputs.execution.cargoHomePath,
      resolvePrecompilerCargoTargetDirectory(),
      resolveNativePackageBuildRoot(),
      rustContext.sysroot,
      buildInputs.execution.compilerDriverPath,
      buildInputs.execution.linkerPath,
      buildInputs.execution.rustcWrapperPath,
      buildInputs.execution.sdkRoot,
      resolve(process.env.TMPDIR ?? "/var/tmp"),
    ].filter((path) => path !== undefined)
  );
  const afterRustContext = await loadRustIdentity(crateDirectory);
  const [afterBuildInputs, afterSource, { binary, platform: binaryPlatform }] = await Promise.all([
    loadBuildInputs(afterRustContext, targetTriple, cargoBuildJobs, crateDirectory),
    collectPrecompilerSourceIdentity(),
    hashAndInspectCompilerBinary(release.binaryPath),
  ]);
  if (canonicalCompilerPackageJson(beforeSource) !== canonicalCompilerPackageJson(afterSource)) {
    throw new Error("precompiler source changed while Cargo was building");
  }
  if (
    canonicalCompilerPackageJson(rustContext.versionIdentity) !==
      canonicalCompilerPackageJson(afterRustContext.versionIdentity) ||
    canonicalCompilerPackageJson(buildInputs.manifest) !==
      canonicalCompilerPackageJson(afterBuildInputs.manifest)
  ) {
    throw new Error("precompiler build inputs changed while Cargo was building");
  }
  for (const field of ["arch", "binaryFormat", "os"]) {
    if (binaryPlatform[field] !== platform[field]) {
      throw new Error(`precompiler binary ${field} does not match target ${targetTriple}`);
    }
  }
  const identities = await sourceMetadata(afterSource);
  const finalSource = await collectPrecompilerSourceIdentity();
  if (canonicalCompilerPackageJson(afterSource) !== canonicalCompilerPackageJson(finalSource)) {
    throw new Error("precompiler source changed while identities were being read");
  }
  const manifest = createPrecompilerPackageManifest({
    binary: {
      path: precompilerPackageBinaryRelativePath,
      ...binary,
    },
    engineContract: {
      consumeFuel: true,
      epochInterruption: true,
      engineIdentityKind: "convex-wasm-wasmtime-engine-identity",
      profilingStrategy: "perf-map",
      targetCpu: "baseline",
      wasmExceptions: true,
    },
    identities: {
      cargoLock: identities.cargoLock,
      rust: rustContext.versionIdentity,
      source: finalSource,
      toolchain: identities.toolchain,
      wasmtime: identities.wasmtime,
    },
    kind: precompilerPackageKind,
    platform,
    provenance: {
      buildInputs: buildInputs.manifest,
      cargoArguments: release.cargoArguments,
      cargoTestArguments: release.cargoTestArguments,
      profile: "release",
    },
    schemaVersion: precompilerPackageSchemaVersion,
  });
  const publication = await publishPackage(outputRoot, manifest, release.binaryPath);
  return { manifest, ...publication };
}

export async function main(argumentsList) {
  const result = await packagePrecompiler(parsePrecompilerPackageArguments(argumentsList));
  process.stdout.write(`${canonicalCompilerPackageJson(result)}\n`);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
