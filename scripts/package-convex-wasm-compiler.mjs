#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { homedir } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  canonicalCompilerPackageJson,
  compilerPackageBinaryRelativePath,
  compilerPackageKind,
  compilerPackageManifestName,
  compilerPackageSchemaVersion,
  createCompilerPackageManifest,
  hashAndInspectCompilerBinary,
  hashStableFile,
  loadAndVerifyCompilerPackage,
  platformForCompilerTarget,
  rustHostFromVerboseVersion,
  sha256Bytes,
} from "./lib/convex-wasm-compiler-package.mjs";
import {
  describeNativeCommandTermination,
  positiveIntegerEnvironment,
  runBoundedNativeCommand,
} from "./lib/bounded-native-command.mjs";
import { smokePackagedCompiler } from "./smoke-packaged-convex-wasm-compiler.mjs";

const execFileAsync = promisify(execFile);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDirectory, "..");
const compilerCrateDirectory = join(scriptDirectory, "convex-wasm-compiler");
const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const COMMAND_IDENTITY_LIMIT_BYTES = 64 * 1024;
const DEFAULT_CARGO_BUILD_JOBS = 4;

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function usage() {
  return [
    "usage: package-convex-wasm-compiler.mjs --output-root PATH --build [--target TRIPLE]",
    "",
    "The target defaults to rustc's native host and must match it. Cross-packaging is rejected.",
  ].join("\n");
}

export function parsePackageArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; ) {
    const option = argumentsList[index];
    if (option === "--build") {
      if (values.has(option)) {
        throw new Error(`duplicate option ${option}\n${usage()}`);
      }
      values.set(option, true);
      index += 1;
      continue;
    }
    if (!["--output-root", "--target"].includes(option)) {
      throw new Error(usage());
    }
    const value = argumentsList[index + 1];
    if (value === undefined || value.length === 0) {
      throw new Error(`${option} requires a value\n${usage()}`);
    }
    if (values.has(option)) {
      throw new Error(`duplicate option ${option}\n${usage()}`);
    }
    values.set(option, value);
    index += 2;
  }
  if (!values.has("--output-root")) {
    throw new Error(`missing --output-root\n${usage()}`);
  }
  if (!values.has("--build")) {
    throw new Error(`missing --build\n${usage()}`);
  }
  return {
    build: true,
    outputRoot: resolve(values.get("--output-root")),
    targetTriple: values.get("--target"),
  };
}

function normalizeCommandIdentity(value) {
  const normalized = value.trim();
  if (normalized.length === 0 || Buffer.byteLength(normalized) > COMMAND_IDENTITY_LIMIT_BYTES) {
    throw new Error("tool version output is empty or exceeds 64 KiB");
  }
  return `${normalized}\n`;
}

function cleanToolEnvironment() {
  return cleanNativeBuildEnvironment(process.env);
}

export function cleanNativeBuildEnvironment(baseEnvironment = process.env) {
  const environment = { ...baseEnvironment };
  const exactVariables = new Set([
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "COMPILER_PATH",
    "CPATH",
    "CPLUS_INCLUDE_PATH",
    "C_INCLUDE_PATH",
    "CRATE_CC_NO_DEFAULTS",
    "CROSS_COMPILE",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "GCC_EXEC_PREFIX",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LIBRARY_PATH",
    "MACOSX_DEPLOYMENT_TARGET",
    "OBJC_INCLUDE_PATH",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_LINKER",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_TOOLCHAIN",
    "SDKROOT",
  ]);
  for (const name of Object.keys(environment)) {
    if (
      exactVariables.has(name) ||
      /^(?:(?:HOST|TARGET)_)?(?:AR|ARFLAGS|CC|CFLAGS|CPP|CPPFLAGS|CXX|CXXFLAGS|CXXSTDLIB|LD|LDFLAGS|NVCC|NVFLAGS|RANLIB|RANLIBFLAGS)(?:_|$)/u.test(name) ||
      name.startsWith("CARGO_PROFILE_RELEASE_") ||
      /^CARGO_TARGET_.*_(?:LINKER|RUNNER|RUSTFLAGS)$/u.test(name) ||
      /^DYLD_/u.test(name) ||
      /^PKG_CONFIG(?:_|$)/u.test(name)
    ) {
      delete environment[name];
    }
  }
  return environment;
}

export function resolveCargoBuildJobs(environment = process.env, requestedJobs) {
  const jobs =
    requestedJobs ??
    positiveIntegerEnvironment(environment, "CARGO_BUILD_JOBS", DEFAULT_CARGO_BUILD_JOBS);
  if (!Number.isSafeInteger(jobs) || jobs <= 0) {
    throw new Error("Cargo build jobs must be a positive safe integer");
  }
  return jobs;
}

export function resolveCompilerCargoTargetDirectory(environment = process.env) {
  return resolve(environment.CARGO_TARGET_DIR ?? join(compilerCrateDirectory, "target"));
}

export function resolveCompilerCargoBuildRoot(environment = process.env) {
  const configured = environment.CARGO_BUILD_BUILD_DIR;
  if (configured === undefined) {
    return undefined;
  }
  if (!isAbsolute(configured)) {
    throw new Error("CARGO_BUILD_BUILD_DIR must be absolute");
  }
  const templateIndex = configured.indexOf("{");
  const root = resolve(
    templateIndex === -1 ? configured : configured.slice(0, templateIndex).replace(/[\\/]+$/u, "")
  );
  if (root === parse(root).root) {
    throw new Error("CARGO_BUILD_BUILD_DIR must resolve below a filesystem root");
  }
  return root;
}

export function resolveNativePackageBuildRoot(environment = process.env) {
  const configured = environment.CONVEX_WASM_NATIVE_BUILD_ROOT;
  if (configured !== undefined) {
    if (!isAbsolute(configured)) {
      throw new Error("CONVEX_WASM_NATIVE_BUILD_ROOT must be absolute");
    }
    const root = resolve(configured);
    if (root === parse(root).root) {
      throw new Error("CONVEX_WASM_NATIVE_BUILD_ROOT must resolve below a filesystem root");
    }
    return root;
  }
  return join(
    resolve(environment.XDG_CACHE_HOME ?? join(homedir(), ".cache")),
    "convex-wasm-native-builds"
  );
}

export function resolveNativePackageBuildDirectory({
  buildInputs,
  packageKind,
  sourceTreeSha256,
  targetTriple,
  environment = process.env,
}) {
  const identity = sha256Bytes(
    canonicalCompilerPackageJson({
      buildInputs,
      kind: "convex-wasm-native-build-directory",
      packageKind,
      sourceTreeSha256,
      targetTriple,
    })
  );
  return join(resolveNativePackageBuildRoot(environment), identity);
}

export function nativePackageRustflagArguments(
  repositoryRoot,
  cargoTargetDirectory,
  cargoBuildDirectory,
  cargoHomeDirectory
) {
  return [
    `--remap-path-prefix=${repositoryRoot}=.`,
    `--remap-path-prefix=${cargoTargetDirectory}=./.cargo-target`,
    `--remap-path-prefix=${cargoBuildDirectory}=./.cargo-build`,
    `--remap-path-prefix=${cargoHomeDirectory}=./.cargo-home`,
  ];
}

export function compilerBuildEnvironmentIdentity(cargoBuildJobs, cargoTargetLinkerVariable) {
  if (!Number.isSafeInteger(cargoBuildJobs) || cargoBuildJobs <= 0) {
    throw new Error("effective Cargo build jobs must be a positive safe integer");
  }
  return {
    cargoBuildJobs: String(cargoBuildJobs),
    cargoIncremental: "0",
    cargoTargetLinkerVariable,
    rustflags:
      "--remap-path-prefix=$REPOSITORY=. --remap-path-prefix=$CARGO_TARGET_DIR=./.cargo-target --remap-path-prefix=$CARGO_BUILD_BUILD_DIR=./.cargo-build --remap-path-prefix=$CARGO_HOME=./.cargo-home",
    rustcWrapper: "native/rustc-wrapper",
    sourceDateEpoch: "0",
  };
}

export async function assertBinaryOmitsLocalBuildPaths(binaryPath, buildPaths) {
  const binary = await fs.readFile(binaryPath);
  for (const buildPath of new Set(buildPaths.map((path) => resolve(path)))) {
    if (buildPath === parse(buildPath).root) {
      throw new Error("local build path scan cannot use a filesystem root");
    }
    if (binary.indexOf(Buffer.from(buildPath)) !== -1) {
      throw new Error("native binary contains an unremapped local build path");
    }
  }
}

export async function loadRustIdentity(workingDirectory = compilerCrateDirectory) {
  const environment = cleanToolEnvironment();
  const options = {
    cwd: workingDirectory,
    encoding: "utf8",
    env: environment,
    maxBuffer: 64 * 1024,
    timeout: 30_000,
  };
  const { stdout: sysrootOutput } = await execFileAsync("rustc", ["--print", "sysroot"], options);
  const sysroot = sysrootOutput.trim();
  if (!isAbsolute(sysroot)) {
    throw new Error("rustc sysroot must be an absolute path");
  }
  const [rustcPath, cargoPath] = await Promise.all([
    fs.realpath(join(sysroot, "bin", "rustc")),
    fs.realpath(join(sysroot, "bin", "cargo")),
  ]);
  await Promise.all([
    fs.access(cargoPath, fsConstants.X_OK),
    fs.access(rustcPath, fsConstants.X_OK),
  ]);
  const [{ stdout: rustcOutput }, { stdout: cargoOutput }] = await Promise.all([
    execFileAsync(rustcPath, ["-vV"], options),
    execFileAsync(cargoPath, ["-Vv"], options),
  ]);
  return {
    cargoPath,
    rustcPath,
    sysroot,
    versionIdentity: {
      cargoVerboseVersion: normalizeCommandIdentity(cargoOutput),
      rustcVerboseVersion: normalizeCommandIdentity(rustcOutput),
    },
  };
}

async function listRegularFiles(directory, description = "compiler source") {
  const directoryEntry = await fs.lstat(directory);
  if (!directoryEntry.isDirectory() || directoryEntry.isSymbolicLink()) {
    throw new Error(`recursive file root must be a non-symbolic-link directory: ${directory}`);
  }
  const result = [];
  async function visit(current) {
    const entries = await fs.readdir(current, { withFileTypes: true });
    entries.sort((left, right) => compareStrings(left.name, right.name));
    for (const entry of entries) {
      const path = join(current, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`${description} must not contain a symbolic link: ${path}`);
      }
      if (entry.isDirectory()) {
        await visit(path);
      } else if (entry.isFile()) {
        result.push(path);
      } else {
        throw new Error(`${description} contains an unsupported filesystem entry: ${path}`);
      }
    }
  }
  await visit(directory);
  return result;
}

async function optionalPath(path) {
  try {
    return await fs.lstat(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

function rustIncludes(rustSourcePath, source) {
  const invocationCount = [...source.matchAll(/\binclude(?:_(?:str|bytes))?\s*!\s*\(/g)].length;
  const matches = [
    ...source.matchAll(/\b(include(?:_(?:str|bytes))?)\s*!\s*\(\s*("(?:[^"\\]|\\.)*")\s*\)/g),
  ];
  if (matches.length !== invocationCount) {
    throw new Error(
      `${rustSourcePath} contains a non-literal include!, include_str!, or include_bytes! input`
    );
  }
  return matches.map((match) => ({
    kind: match[1],
    path: resolve(dirname(rustSourcePath), JSON.parse(match[2])),
  }));
}

async function rustCrateSourcePaths(repositoryRoot, crateRelativePath, description) {
  const crateDirectory = join(repositoryRoot, ...crateRelativePath.split("/"));
  const [rustSourcePaths, optionalPathGroups] = await Promise.all([
    listRegularFiles(join(crateDirectory, "src"), description),
    Promise.all(
      [join(crateDirectory, ".cargo"), join(crateDirectory, "build.rs")].map(async (optional) => {
        const entry = await optionalPath(optional);
        if (entry === undefined) {
          return [];
        }
        if (entry.isSymbolicLink()) {
          throw new Error(`${description} must not contain a symbolic link: ${optional}`);
        }
        if (entry.isDirectory()) {
          return listRegularFiles(optional, description);
        }
        if (entry.isFile()) {
          return [optional];
        }
        throw new Error(`${description} contains an unsupported filesystem entry: ${optional}`);
      })
    ),
  ]);
  const paths = new Set([
    join(crateDirectory, "Cargo.lock"),
    join(crateDirectory, "Cargo.toml"),
    join(crateDirectory, "rust-toolchain.toml"),
    ...rustSourcePaths,
    ...optionalPathGroups.flat(),
  ]);
  const rustPathsToScan = new Set([...paths].filter((path) => path.endsWith(".rs")));
  const scannedRustPaths = new Set();
  for (;;) {
    const rustPaths = [...rustPathsToScan]
      .filter((path) => !scannedRustPaths.has(path))
      .sort((left, right) => compareStrings(left, right));
    if (rustPaths.length === 0) {
      break;
    }
    for (const path of rustPaths) {
      const relativePath = relative(repositoryRoot, path);
      if (relativePath.startsWith(`..${sep}`) || relativePath === "..") {
        throw new Error(`${description} is outside the repository: ${path}`);
      }
      scannedRustPaths.add(path);
    }
    const includeGroups = await Promise.all(
      rustPaths.map(async (rustSourcePath) =>
        rustIncludes(rustSourcePath, await fs.readFile(rustSourcePath, "utf8"))
      )
    );
    for (const included of includeGroups.flat()) {
      paths.add(included.path);
      if (included.kind === "include") {
        rustPathsToScan.add(included.path);
      }
    }
  }
  return [...paths].sort((left, right) =>
    compareStrings(relative(repositoryRoot, left), relative(repositoryRoot, right))
  );
}

async function collectRustCrateSourceIdentitySnapshot({
  crateRelativePath,
  description,
  repositoryRoot,
}) {
  const paths = await rustCrateSourcePaths(repositoryRoot, crateRelativePath, description);
  const materials = await Promise.all(
    paths.map(async (path) => {
      const relativePath = relative(repositoryRoot, path).split(sep).join("/");
      if (relativePath.startsWith("../") || relativePath === "..") {
        throw new Error(`${description} is outside the repository: ${path}`);
      }
      return {
        path: relativePath,
        ...(await hashStableFile(path, Number.MAX_SAFE_INTEGER, {
          expectedCanonicalPath: path,
        })),
      };
    })
  );
  const pathsAfterHashing = await rustCrateSourcePaths(
    repositoryRoot,
    crateRelativePath,
    description
  );
  if (
    paths.length !== pathsAfterHashing.length ||
    paths.some((path, index) => path !== pathsAfterHashing[index])
  ) {
    throw new Error(`${description} membership changed while its identity was being collected`);
  }
  return {
    materials,
    treeSha256: sha256Bytes(canonicalCompilerPackageJson(materials)),
  };
}

export async function collectRustCrateSourceIdentity({
  crateRelativePath,
  description,
  repositoryRoot = repoRoot,
}) {
  const requestedRepositoryRoot = resolve(repositoryRoot);
  const normalizedRepositoryRoot = await fs.realpath(requestedRepositoryRoot);
  // Include discovery reads Rust sources before their bytes are hashed. Two complete matching
  // snapshots prevent an include or source-file addition in that gap from producing a hybrid
  // identity that describes neither the earlier nor the path's current compiler source.
  const options = {
    crateRelativePath,
    description,
    repositoryRoot: normalizedRepositoryRoot,
  };
  const first = await collectRustCrateSourceIdentitySnapshot(options);
  const second = await collectRustCrateSourceIdentitySnapshot(options);
  if (canonicalCompilerPackageJson(first) !== canonicalCompilerPackageJson(second)) {
    throw new Error(`${description} changed while its identity was being collected`);
  }
  if ((await fs.realpath(requestedRepositoryRoot)) !== normalizedRepositoryRoot) {
    throw new Error("repository root changed while source identity was being collected");
  }
  return second;
}

export async function collectCompilerSourceIdentity(repositoryRoot = repoRoot) {
  return collectRustCrateSourceIdentity({
    crateRelativePath: "scripts/convex-wasm-compiler",
    description: "compiler source",
    repositoryRoot,
  });
}

function quotedTomlValue(text, key) {
  const matches = [...text.matchAll(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]+)"\\s*$`, "gm"))];
  if (matches.length !== 1) {
    throw new Error(`rust-toolchain.toml must declare exactly one ${key}`);
  }
  return matches[0][1];
}

function toolchainIdentity(source, toolchainText) {
  const toolchainPath = "scripts/convex-wasm-compiler/rust-toolchain.toml";
  const file = source.materials.find((material) => material.path === toolchainPath);
  if (file === undefined) {
    throw new Error("toolchain source material is missing");
  }
  const componentMatch = toolchainText.match(/^\s*components\s*=\s*\[([^\]]*)\]\s*$/m);
  const components =
    componentMatch === null
      ? []
      : [...componentMatch[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]).sort();
  return {
    channel: quotedTomlValue(toolchainText, "channel"),
    components,
    file,
    profile: quotedTomlValue(toolchainText, "profile"),
  };
}

function oxcPackagesFromCargoLock(cargoLockText) {
  const packages = [];
  for (const section of cargoLockText.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const value = (key) => {
      const match = section.match(new RegExp(`^${key} = "([^"]+)"$`, "m"));
      return match?.[1];
    };
    const name = value("name");
    if (name === undefined || !name.startsWith("oxc_")) {
      continue;
    }
    const version = value("version");
    const source = value("source");
    const checksum = value("checksum");
    if (version === undefined || source === undefined) {
      throw new Error(`Cargo.lock has an incomplete identity for ${name}`);
    }
    if (source.startsWith("registry+")) {
      if (checksum === undefined) {
        throw new Error(`Cargo.lock has no registry checksum for ${name}`);
      }
      packages.push({ checksum, name, source, version });
      continue;
    }
    const sourceMatch = source.match(
      /^git\+https:\/\/github\.com\/oxc-project\/oxc\.git\?rev=([0-9a-f]{40})#([0-9a-f]{40})$/
    );
    if (checksum !== undefined || sourceMatch === null || sourceMatch[1] !== sourceMatch[2]) {
      throw new Error(`Cargo.lock has an unsupported Git identity for ${name}`);
    }
    packages.push({ name, revision: sourceMatch[2], source, version });
  }
  packages.sort((left, right) =>
    compareStrings(
      `${left.name}\0${left.version}\0${left.source}`,
      `${right.name}\0${right.version}\0${right.source}`
    )
  );
  if (packages.length === 0) {
    throw new Error("Cargo.lock contains no Oxc packages");
  }
  return packages;
}

async function readIdentityInputs(source) {
  const cargoLockPath = join(compilerCrateDirectory, "Cargo.lock");
  const toolchainPath = join(compilerCrateDirectory, "rust-toolchain.toml");
  const [cargoLockText, toolchainText] = await Promise.all([
    fs.readFile(cargoLockPath, "utf8"),
    fs.readFile(toolchainPath, "utf8"),
  ]);
  const cargoLock = source.materials.find(
    (material) => material.path === "scripts/convex-wasm-compiler/Cargo.lock"
  );
  if (cargoLock === undefined) {
    throw new Error("Cargo.lock source material is missing");
  }
  const toolchainFile = source.materials.find(
    (material) => material.path === "scripts/convex-wasm-compiler/rust-toolchain.toml"
  );
  if (toolchainFile === undefined) {
    throw new Error("toolchain source material is missing");
  }
  if (
    cargoLock.size !== Buffer.byteLength(cargoLockText) ||
    cargoLock.sha256 !== sha256Bytes(cargoLockText) ||
    toolchainFile.size !== Buffer.byteLength(toolchainText) ||
    toolchainFile.sha256 !== sha256Bytes(toolchainText)
  ) {
    throw new Error("compiler identity input changed after the source snapshot");
  }
  return {
    cargoLock,
    oxc: { packages: oxcPackagesFromCargoLock(cargoLockText) },
    toolchain: toolchainIdentity(source, toolchainText),
  };
}

async function materialIdentity(path, logicalPath) {
  return { path: logicalPath, ...(await hashStableFile(path, 512 * 1024 * 1024)) };
}

async function commandIdentity(
  command,
  argumentsList,
  environment = cleanToolEnvironment(),
  workingDirectory = compilerCrateDirectory
) {
  const { stderr, stdout } = await execFileAsync(command, argumentsList, {
    cwd: workingDirectory,
    encoding: "utf8",
    env: environment,
    maxBuffer: COMMAND_IDENTITY_LIMIT_BYTES,
    timeout: 30_000,
  });
  return normalizeCommandIdentity(`${stdout}${stderr}`);
}

async function resolveExecutable(command, environment = process.env) {
  if (isAbsolute(command) || command.includes(sep)) {
    const path = await fs.realpath(resolve(compilerCrateDirectory, command));
    await fs.access(path, fsConstants.X_OK);
    return path;
  }
  for (const pathEntry of (environment.PATH ?? "").split(delimiter)) {
    if (pathEntry.length === 0) {
      continue;
    }
    const candidate = join(pathEntry, command);
    try {
      await fs.access(candidate, fsConstants.X_OK);
      return await fs.realpath(candidate);
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error.code === "ENOENT" || error.code === "EACCES")
        )
      ) {
        throw error;
      }
    }
  }
  throw new Error(`could not resolve executable ${command}`);
}

async function cargoConfigurationMaterials(workingDirectory, cargoHome) {
  const candidates = [];
  for (const name of ["config", "config.toml"]) {
    candidates.push({
      logicalPath: `cargo-config/cargo-home/${name}`,
      path: join(cargoHome, name),
    });
  }
  for (let directory = workingDirectory, index = 0; ; index += 1) {
    for (const name of ["config", "config.toml"]) {
      candidates.push({
        logicalPath: `cargo-config/ancestor-${index}/${name}`,
        path: join(directory, ".cargo", name),
      });
    }
    const parent = dirname(directory);
    if (parent === directory) {
      break;
    }
    directory = parent;
  }

  const resolvedCandidates = (
    await Promise.all(
      candidates.map(async (candidate) => {
        const entry = await optionalPath(candidate.path);
        if (entry === undefined) {
          return undefined;
        }
        if (!entry.isFile() || entry.isSymbolicLink()) {
          throw new Error(
            `Cargo configuration must be a regular non-symlink file: ${candidate.path}`
          );
        }
        return { ...candidate, realPath: await fs.realpath(candidate.path) };
      })
    )
  ).filter((candidate) => candidate !== undefined);
  const candidatesByRealPath = new Map();
  for (const candidate of resolvedCandidates) {
    if (!candidatesByRealPath.has(candidate.realPath)) {
      candidatesByRealPath.set(candidate.realPath, candidate);
    }
  }
  const materials = await Promise.all(
    [...candidatesByRealPath.values()].map((candidate) =>
      materialIdentity(candidate.realPath, candidate.logicalPath)
    )
  );
  return materials.sort((left, right) => compareStrings(left.path, right.path));
}

async function rustDistributionIdentity(rustContext, targetTriple, rustcWrapperPath) {
  const rustlibDirectory = join(rustContext.sysroot, "lib", "rustlib");
  const manifestNames = [
    "components",
    `manifest-cargo-${rustHostFromVerboseVersion(rustContext.versionIdentity.cargoVerboseVersion)}`,
    `manifest-rust-std-${targetTriple}`,
    `manifest-rustc-${rustHostFromVerboseVersion(rustContext.versionIdentity.rustcVerboseVersion)}`,
    "multirust-channel-manifest.toml",
    "rust-installer-version",
  ].sort(compareStrings);
  const [manifests, cargo, rustc, rustcWrapper] = await Promise.all([
    Promise.all(
      manifestNames.map((name) =>
        materialIdentity(join(rustlibDirectory, name), `rust-toolchain/lib/rustlib/${name}`)
      )
    ),
    materialIdentity(rustContext.cargoPath, "rust-toolchain/bin/cargo"),
    materialIdentity(rustContext.rustcPath, "rust-toolchain/bin/rustc"),
    materialIdentity(rustcWrapperPath, "native/rustc-wrapper"),
  ]);
  return {
    cargo,
    manifests,
    rustc,
    rustcWrapper,
  };
}

async function linuxNativeToolchainIdentity(workingDirectory = compilerCrateDirectory) {
  const environment = cleanToolEnvironment();
  const compilerDriverPath = await resolveExecutable("cc", environment);
  const linkerName = (
    await commandIdentity(
      compilerDriverPath,
      ["-print-prog-name=ld"],
      environment,
      workingDirectory
    )
  ).trim();
  const linkerPath = await resolveExecutable(linkerName, environment);
  const runtimeNames = [
    "Scrt1.o",
    "crt1.o",
    "crtbeginS.o",
    "crtendS.o",
    "crti.o",
    "crtn.o",
    process.arch === "x64" ? "ld-linux-x86-64.so.2" : "ld-linux-aarch64.so.1",
    "libc.so",
    "libc.so.6",
    "libc_nonshared.a",
    "libgcc.a",
    "libgcc_eh.a",
    "libgcc_s.so",
    "libgcc_s.so.1",
  ];
  const [
    runtimeMaterials,
    compilerDriver,
    compilerDriverVersion,
    linker,
    linkerVersion,
    runtimeIdentity,
  ] = await Promise.all([
    Promise.all(
      runtimeNames.map(async (name) => {
        const reportedPath = (
          await commandIdentity(
            compilerDriverPath,
            [`-print-file-name=${name}`],
            environment,
            workingDirectory
          )
        ).trim();
        if (reportedPath === name) {
          throw new Error(`native compiler driver could not resolve ${name}`);
        }
        return materialIdentity(await fs.realpath(reportedPath), `native/runtime/${name}`);
      })
    ),
    materialIdentity(compilerDriverPath, "native/compiler-driver"),
    commandIdentity(compilerDriverPath, ["--version"], environment, workingDirectory),
    materialIdentity(linkerPath, "native/linker"),
    commandIdentity(linkerPath, ["--version"], environment, workingDirectory),
    resolveExecutable("getconf", environment).then((getconfPath) =>
      commandIdentity(getconfPath, ["GNU_LIBC_VERSION"], environment, workingDirectory)
    ),
  ]);
  runtimeMaterials.sort((left, right) => compareStrings(left.path, right.path));
  return {
    execution: { compilerDriverPath, linkerPath },
    manifest: {
      compilerDriver,
      compilerDriverVersion,
      kind: "linux-gnu",
      linker,
      linkerVersion,
      runtime: {
        identity: runtimeIdentity,
        kind: "glibc",
        materials: runtimeMaterials,
      },
    },
  };
}

async function macosNativeToolchainIdentity(workingDirectory = compilerCrateDirectory) {
  const environment = cleanToolEnvironment();
  const [xcrunPath, xcodebuildPath] = await Promise.all([
    resolveExecutable("xcrun", environment),
    resolveExecutable("xcodebuild", environment),
  ]);
  const [compilerDriverReportedPath, linkerReportedPath, sdkRootOutput] = await Promise.all([
    commandIdentity(xcrunPath, ["--find", "clang"], environment, workingDirectory),
    commandIdentity(xcrunPath, ["--find", "ld"], environment, workingDirectory),
    commandIdentity(
      xcrunPath,
      ["--sdk", "macosx", "--show-sdk-path"],
      environment,
      workingDirectory
    ),
  ]);
  const sdkRoot = sdkRootOutput.trim();
  if (!isAbsolute(sdkRoot)) {
    throw new Error("macOS SDK path must be absolute");
  }
  const [compilerDriverPath, linkerPath] = await Promise.all([
    fs.realpath(compilerDriverReportedPath.trim()),
    fs.realpath(linkerReportedPath.trim()),
  ]);
  const sdkSettingCandidates = [
    join(sdkRoot, "SDKSettings.json"),
    join(sdkRoot, "SDKSettings.plist"),
  ];
  const [
    sdkSettingMaterials,
    libSystem,
    sdkVersion,
    sdkBuildVersion,
    xcodeVersion,
    compilerDriver,
    compilerDriverVersion,
    linker,
    linkerVersion,
  ] = await Promise.all([
    Promise.all(
      sdkSettingCandidates.map(async (candidate) => {
        if (!(await optionalPath(candidate))?.isFile()) {
          return undefined;
        }
        return materialIdentity(
          candidate,
          `native/runtime/${candidate.endsWith(".json") ? "SDKSettings.json" : "SDKSettings.plist"}`
        );
      })
    ),
    fs
      .realpath(join(sdkRoot, "usr", "lib", "libSystem.tbd"))
      .then((path) => materialIdentity(path, "native/runtime/libSystem.tbd")),
    commandIdentity(
      xcrunPath,
      ["--sdk", "macosx", "--show-sdk-version"],
      environment,
      workingDirectory
    ),
    commandIdentity(
      xcrunPath,
      ["--sdk", "macosx", "--show-sdk-build-version"],
      environment,
      workingDirectory
    ),
    commandIdentity(xcodebuildPath, ["-version"], environment, workingDirectory),
    materialIdentity(compilerDriverPath, "native/compiler-driver"),
    commandIdentity(compilerDriverPath, ["--version"], environment, workingDirectory),
    materialIdentity(linkerPath, "native/linker"),
    commandIdentity(linkerPath, ["-v"], environment, workingDirectory),
  ]);
  const runtimeMaterials = sdkSettingMaterials.filter((material) => material !== undefined);
  if (runtimeMaterials.length === 0) {
    throw new Error("macOS SDK has no SDKSettings.json or SDKSettings.plist");
  }
  runtimeMaterials.push(libSystem);
  runtimeMaterials.sort((left, right) => compareStrings(left.path, right.path));
  return {
    execution: { compilerDriverPath, linkerPath, sdkRoot },
    manifest: {
      compilerDriver,
      compilerDriverVersion: compilerDriverVersion
        .split("\n")
        .filter((line) => !line.startsWith("InstalledDir: "))
        .join("\n"),
      kind: "apple-xcode",
      linker,
      linkerVersion,
      runtime: {
        identity: `${xcodeVersion}macOS SDK ${sdkVersion.trim()} (${sdkBuildVersion.trim()})\n`,
        kind: "macos-sdk",
        materials: runtimeMaterials,
      },
    },
  };
}

export async function loadBuildInputs(
  rustContext,
  targetTriple,
  cargoBuildJobs,
  workingDirectory = compilerCrateDirectory
) {
  const cargoHomePath = await fs.realpath(
    resolve(process.env.CARGO_HOME ?? join(homedir(), ".cargo"))
  );
  const cargoTargetLinkerVariable = `CARGO_TARGET_${targetTriple
    .toUpperCase()
    .replaceAll("-", "_")}_LINKER`;
  const rustcWrapperPath = await resolveExecutable("env", cleanToolEnvironment());
  const [cargoConfiguration, rustDistribution, nativeToolchain] = await Promise.all([
    cargoConfigurationMaterials(workingDirectory, cargoHomePath),
    rustDistributionIdentity(rustContext, targetTriple, rustcWrapperPath),
    process.platform === "linux"
      ? linuxNativeToolchainIdentity(workingDirectory)
      : macosNativeToolchainIdentity(workingDirectory),
  ]);
  return {
    execution: {
      ...nativeToolchain.execution,
      cargoHomePath,
      cargoPath: rustContext.cargoPath,
      cargoTargetLinkerVariable,
      rustcPath: rustContext.rustcPath,
      rustcWrapperPath,
    },
    manifest: {
      cargoConfiguration,
      environment: compilerBuildEnvironmentIdentity(cargoBuildJobs, cargoTargetLinkerVariable),
      nativeToolchain: nativeToolchain.manifest,
      rustDistribution,
    },
  };
}

function compilerCargoBuildRuntime({
  baseEnvironment = process.env,
  buildInputs,
  cargoBuildDirectory,
  cargoBuildJobs,
  cargoTargetDirectory,
}) {
  const environment = cleanNativeBuildEnvironment(baseEnvironment);
  environment[buildInputs.execution.cargoTargetLinkerVariable] =
    buildInputs.execution.compilerDriverPath;
  environment.CARGO_BUILD_BUILD_DIR = cargoBuildDirectory;
  environment.CC = buildInputs.execution.compilerDriverPath;
  environment.CARGO_BUILD_JOBS = String(cargoBuildJobs);
  environment.CARGO_HOME = buildInputs.execution.cargoHomePath;
  environment.CARGO_INCREMENTAL = "0";
  environment.CARGO_TERM_COLOR = "never";
  environment.CARGO_TARGET_DIR = cargoTargetDirectory;
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
  environment.TMPDIR = resolve(baseEnvironment.TMPDIR ?? "/var/tmp");
  if (buildInputs.execution.sdkRoot !== undefined) {
    environment.SDKROOT = buildInputs.execution.sdkRoot;
  } else {
    delete environment.SDKROOT;
  }
  environment.SOURCE_DATE_EPOCH = "0";
  return {
    environment,
  };
}

export async function runCompilerCargoBuild({
  baseEnvironment = process.env,
  buildInputs,
  cargoBuildDirectory,
  cargoBuildJobs,
  cargoTargetDirectory,
  runCommand = runBoundedNativeCommand,
  targetTriple,
}) {
  const runtime = compilerCargoBuildRuntime({
    baseEnvironment,
    buildInputs,
    cargoBuildDirectory,
    cargoBuildJobs,
    cargoTargetDirectory,
  });
  const cargoArguments = [
    "build",
    "--locked",
    "--release",
    "--target",
    targetTriple,
    "--bin",
    "convex-wasm-compiler",
  ];
  const result = await runCommand({
    arguments: cargoArguments,
    command: buildInputs.execution.cargoPath,
    cwd: compilerCrateDirectory,
    environment: runtime.environment,
    maxOutputBytes: MAX_COMMAND_OUTPUT_BYTES,
    operation: "Convex Wasm compiler Cargo build",
    timeoutMs: positiveIntegerEnvironment(
      baseEnvironment,
      "CONVEX_WASM_NATIVE_PACKAGE_TIMEOUT_MS",
      30 * 60 * 1000
    ),
  });
  return { ...result, cargoArguments };
}

export async function buildReleaseCompiler({
  buildInputs,
  cargoBuildJobs,
  environment = process.env,
  runCommand = runBoundedNativeCommand,
  source,
  targetTriple,
}) {
  const cargoTargetDirectory = resolveCompilerCargoTargetDirectory(environment);
  const cargoBuildDirectory = resolveNativePackageBuildDirectory({
    buildInputs: buildInputs.manifest,
    packageKind: compilerPackageKind,
    sourceTreeSha256: source.treeSha256,
    targetTriple,
    environment,
  });
  const result = await runCompilerCargoBuild({
    baseEnvironment: environment,
    buildInputs,
    cargoBuildDirectory,
    cargoBuildJobs,
    cargoTargetDirectory,
    runCommand,
    targetTriple,
  });
  if (result.termination !== undefined) {
    throw new Error(`cargo build stopped: ${describeNativeCommandTermination(result.termination)}`);
  }
  if (result.code !== 0) {
    const diagnostic = result.output.toString("utf8").trim();
    throw new Error(
      `cargo build failed with ${result.signal === null ? `exit ${result.code}` : `signal ${result.signal}`}${diagnostic.length === 0 ? "" : `\n${diagnostic}`}`
    );
  }
  const conventionalBinaryPath = join(
    cargoTargetDirectory,
    targetTriple,
    "release",
    "convex-wasm-compiler"
  );
  const targetReleaseSegment = `${sep}${targetTriple}${sep}release${sep}deps${sep}`;
  const buildDirectoryEntry = await optionalPath(cargoBuildDirectory);
  if (
    buildDirectoryEntry !== undefined &&
    (!buildDirectoryEntry.isDirectory() || buildDirectoryEntry.isSymbolicLink())
  ) {
    throw new Error("Cargo build directory must be a directory, not a symbolic link");
  }
  const buildDirectoryBinaries =
    buildDirectoryEntry === undefined
      ? []
      : (await listRegularFiles(cargoBuildDirectory)).filter(
          (path) =>
            path.includes(targetReleaseSegment) &&
            /^convex_wasm_compiler-[0-9a-f]+$/u.test(basename(path))
        );
  if (buildDirectoryBinaries.length > 1) {
    throw new Error(
      `Cargo build directory must contain exactly one release compiler binary, found ${buildDirectoryBinaries.length}`
    );
  }
  if (buildDirectoryBinaries.length === 1) {
    // A configured Cargo build directory is keyed by the complete source and build-input
    // identity. Prefer its output over a conventional target artifact that can remain from an
    // earlier build layout and otherwise be packaged as if Cargo had just produced it.
    return {
      binaryPath: buildDirectoryBinaries[0],
      cargoArguments: result.cargoArguments,
    };
  }
  if ((await optionalPath(conventionalBinaryPath))?.isFile()) {
    return {
      binaryPath: conventionalBinaryPath,
      cargoArguments: result.cargoArguments,
    };
  }
  throw new Error("Cargo build produced no release compiler binary");
}

async function ensurePrivateDirectory(path) {
  await fs.mkdir(path, { mode: 0o700, recursive: true });
  const entry = await fs.lstat(path);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new Error(`${path} must be a directory, not a symbolic link`);
  }
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) {
    throw new Error(`${path} must be owned by the current user`);
  }
  await fs.chmod(path, 0o700);
}

async function syncDirectory(path) {
  const directoryHandle = await fs.open(
    path,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0)
  );
  try {
    await directoryHandle.sync();
  } finally {
    await directoryHandle.close();
  }
}

async function writePackage({ binaryPath, manifest, outputRoot }) {
  const targetDirectory = join(outputRoot, manifest.platform.targetTriple);
  await ensurePrivateDirectory(outputRoot);
  await ensurePrivateDirectory(targetDirectory);
  const stagingRoot = await fs.mkdtemp(
    join(targetDirectory, `.package-stage-${process.pid}-${randomBytes(6).toString("hex")}-`)
  );
  await fs.chmod(stagingRoot, 0o700);
  const stagingDirectory = join(stagingRoot, manifest.packageId);
  await fs.mkdir(stagingDirectory, { mode: 0o700 });
  await fs.chmod(stagingDirectory, 0o700);
  try {
    const binaryDirectory = join(stagingDirectory, "bin");
    await fs.mkdir(binaryDirectory, { mode: 0o700 });
    await fs.chmod(binaryDirectory, 0o700);
    const stagedBinary = join(stagingDirectory, compilerPackageBinaryRelativePath);
    await fs.copyFile(binaryPath, stagedBinary, fsConstants.COPYFILE_EXCL);
    await fs.chmod(stagedBinary, 0o700);
    const binaryHandle = await fs.open(stagedBinary, fsConstants.O_RDONLY);
    try {
      await binaryHandle.sync();
    } finally {
      await binaryHandle.close();
    }
    const manifestPath = join(stagingDirectory, compilerPackageManifestName);
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
    await loadAndVerifyCompilerPackage(stagingDirectory);
    await smokePackagedCompiler(stagingDirectory);
    await syncDirectory(binaryDirectory);
    await syncDirectory(stagingDirectory);

    const finalDirectory = join(targetDirectory, manifest.packageId);
    try {
      await fs.rename(stagingDirectory, finalDirectory);
      await syncDirectory(targetDirectory);
      return finalDirectory;
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
      const existing = await loadAndVerifyCompilerPackage(finalDirectory);
      if (existing.manifest.packageId !== manifest.packageId) {
        throw new Error(`published package ${finalDirectory} has a different package ID`);
      }
      return finalDirectory;
    }
  } finally {
    await fs.rm(stagingRoot, { force: true, recursive: true });
  }
}

export async function packageCompiler(argumentsValue) {
  if (!["darwin", "linux"].includes(process.platform)) {
    throw new Error(`compiler packaging does not support ${process.platform}`);
  }
  if (!["arm64", "x64"].includes(process.arch)) {
    throw new Error(`compiler packaging does not support ${process.arch}`);
  }

  if (argumentsValue.build !== true) {
    throw new Error("compiler packaging requires a release build");
  }
  const cargoBuildJobs = resolveCargoBuildJobs(process.env, argumentsValue.cargoBuildJobs);
  const rustContext = await loadRustIdentity();
  const rustHost = rustHostFromVerboseVersion(rustContext.versionIdentity.rustcVerboseVersion);
  const targetTriple = argumentsValue.targetTriple ?? rustHost;
  if (targetTriple !== rustHost) {
    throw new Error(
      `target ${targetTriple} does not match native Rust host ${rustHost}; run this command on the target platform`
    );
  }
  const platform = platformForCompilerTarget(targetTriple);
  if (platform.os !== process.platform || platform.arch !== process.arch) {
    throw new Error(
      `target ${targetTriple} does not match Node runtime ${process.platform}/${process.arch}`
    );
  }
  const [beforeSource, buildInputs] = await Promise.all([
    collectCompilerSourceIdentity(),
    loadBuildInputs(rustContext, targetTriple, cargoBuildJobs),
  ]);
  const release = await buildReleaseCompiler({
    buildInputs,
    cargoBuildJobs,
    source: beforeSource,
    targetTriple,
  });
  await assertBinaryOmitsLocalBuildPaths(
    release.binaryPath,
    [
      repoRoot,
      buildInputs.execution.cargoHomePath,
      resolveCompilerCargoTargetDirectory(),
      resolveNativePackageBuildRoot(),
      rustContext.sysroot,
      buildInputs.execution.compilerDriverPath,
      buildInputs.execution.linkerPath,
      buildInputs.execution.rustcWrapperPath,
      buildInputs.execution.sdkRoot,
      resolve(process.env.TMPDIR ?? "/var/tmp"),
    ].filter((path) => path !== undefined)
  );
  const [afterBuildSource, { rust: afterRustContext, inputs: afterBuildInputs }] =
    await Promise.all([
      collectCompilerSourceIdentity(),
      loadRustIdentity().then(async (rust) => ({
        inputs: await loadBuildInputs(rust, targetTriple, cargoBuildJobs),
        rust,
      })),
    ]);
  if (
    canonicalCompilerPackageJson(beforeSource) !==
    canonicalCompilerPackageJson(afterBuildSource)
  ) {
    throw new Error("compiler source changed while Cargo was building");
  }
  if (
    canonicalCompilerPackageJson(rustContext.versionIdentity) !==
      canonicalCompilerPackageJson(afterRustContext.versionIdentity) ||
    canonicalCompilerPackageJson(buildInputs.manifest) !==
      canonicalCompilerPackageJson(afterBuildInputs.manifest)
  ) {
    throw new Error("compiler build inputs changed while Cargo was building");
  }

  const [afterSource, { binary, platform: binaryPlatform }] = await Promise.all([
    collectCompilerSourceIdentity(),
    hashAndInspectCompilerBinary(release.binaryPath),
  ]);
  if (canonicalCompilerPackageJson(beforeSource) !== canonicalCompilerPackageJson(afterSource)) {
    throw new Error("compiler source changed while the package was being prepared");
  }
  for (const field of ["arch", "binaryFormat", "os"]) {
    if (binaryPlatform[field] !== platform[field]) {
      throw new Error(`compiler binary ${field} does not match target ${targetTriple}`);
    }
  }
  const [inputs, finalSource] = await Promise.all([
    readIdentityInputs(afterSource),
    collectCompilerSourceIdentity(),
  ]);
  if (canonicalCompilerPackageJson(afterSource) !== canonicalCompilerPackageJson(finalSource)) {
    throw new Error("compiler source changed while identities were being read");
  }
  const rust = rustContext.versionIdentity;
  if (inputs.toolchain.channel !== rust.rustcVerboseVersion.match(/^release: (.+)$/m)?.[1]) {
    throw new Error("active rustc release does not match rust-toolchain.toml");
  }
  const manifest = createCompilerPackageManifest({
    binary: {
      path: compilerPackageBinaryRelativePath,
      ...binary,
    },
    identities: {
      cargoLock: inputs.cargoLock,
      oxc: inputs.oxc,
      rust,
      source: finalSource,
      toolchain: inputs.toolchain,
    },
    kind: compilerPackageKind,
    platform,
    provenance: {
      buildInputs: buildInputs.manifest,
      cargoArguments: release.cargoArguments,
      mode: "built",
      profile: "release",
    },
    schemaVersion: compilerPackageSchemaVersion,
  });
  return await writePackage({
    binaryPath: release.binaryPath,
    manifest,
    outputRoot: argumentsValue.outputRoot,
  });
}

export async function main(argumentsList) {
  const packageDirectory = await packageCompiler(parsePackageArguments(argumentsList));
  process.stdout.write(`${packageDirectory}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
