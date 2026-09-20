import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { basename, join, resolve } from "node:path";

export const compilerPackageKind = "convex-wasm-compiler-package";
export const compilerPackageSchemaVersion = 1;
export const compilerPackageManifestName = "manifest.json";
export const compilerPackageBinaryRelativePath = "bin/convex-wasm-compiler";

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_BINARY_BYTES = 512 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GIT_REVISION_PATTERN = /^[0-9a-f]{40}$/;
const OXC_GIT_SOURCE_PATTERN =
  /^git\+https:\/\/github\.com\/oxc-project\/oxc\.git\?rev=([0-9a-f]{40})#([0-9a-f]{40})$/;
const TARGET_PLATFORMS = new Map([
  ["aarch64-apple-darwin", { arch: "arm64", binaryFormat: "macho64", os: "darwin" }],
  ["aarch64-unknown-linux-gnu", { arch: "arm64", binaryFormat: "elf64", os: "linux" }],
  ["x86_64-apple-darwin", { arch: "x64", binaryFormat: "macho64", os: "darwin" }],
  ["x86_64-unknown-linux-gnu", { arch: "x64", binaryFormat: "elf64", os: "linux" }],
]);

function fail(message) {
  throw new Error(`Convex Wasm compiler package: ${message}`);
}

function assertObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
}

function assertExactKeys(value, expectedKeys, description) {
  assertObject(value, description);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${description} has unsupported fields`);
  }
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireSize(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a non-negative safe integer`);
  }
  return value;
}

function sortedJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortedJsonValue);
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortedJsonValue(value[key])])
    );
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  fail("manifest contains a value that JSON cannot encode");
}

export function canonicalCompilerPackageJson(value) {
  return JSON.stringify(sortedJsonValue(value));
}

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function platformForCompilerTarget(targetTriple) {
  const platform = TARGET_PLATFORMS.get(targetTriple);
  if (platform === undefined) {
    fail(`unsupported target triple ${JSON.stringify(targetTriple)}`);
  }
  return { ...platform, targetTriple };
}

export function rustHostFromVerboseVersion(verboseVersion) {
  requireString(verboseVersion, "Rust verbose version");
  const hostLines = verboseVersion.split("\n").filter((line) => line.startsWith("host: "));
  if (hostLines.length !== 1) {
    fail("Rust verbose version must contain exactly one host");
  }
  return hostLines[0].slice("host: ".length);
}

function releaseFromVerboseVersion(verboseVersion, description) {
  requireString(verboseVersion, description);
  const releaseLines = verboseVersion.split("\n").filter((line) => line.startsWith("release: "));
  if (releaseLines.length !== 1) {
    fail(`${description} must contain exactly one release`);
  }
  return releaseLines[0].slice("release: ".length);
}

function validateMaterial(material, description) {
  assertExactKeys(material, ["path", "sha256", "size"], description);
  const path = requireString(material.path, `${description} path`);
  if (
    path.startsWith("/") ||
    path.includes("\\") ||
    path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    fail(`${description} path must be a normalized relative POSIX path`);
  }
  requireSha256(material.sha256, `${description} sha256`);
  requireSize(material.size, `${description} size`);
}

function validateSortedMaterials(materials, description, { allowEmpty = false } = {}) {
  if (!Array.isArray(materials) || (!allowEmpty && materials.length === 0)) {
    fail(`${description} must be ${allowEmpty ? "an" : "a non-empty"} array`);
  }
  let previousPath = "";
  for (const [index, material] of materials.entries()) {
    validateMaterial(material, `${description} ${index}`);
    if (material.path <= previousPath) {
      fail(`${description} must be sorted by unique path`);
    }
    previousPath = material.path;
  }
}

export function validateNativeRustBuildInputs(buildInputs, platform) {
  assertExactKeys(
    buildInputs,
    ["cargoConfiguration", "environment", "nativeToolchain", "rustDistribution"],
    "build inputs"
  );
  validateSortedMaterials(buildInputs.cargoConfiguration, "Cargo configuration", {
    allowEmpty: true,
  });

  assertExactKeys(
    buildInputs.environment,
    [
      "cargoBuildJobs",
      "cargoIncremental",
      "cargoTargetLinkerVariable",
      "rustflags",
      "rustcWrapper",
      "sourceDateEpoch",
    ],
    "build environment"
  );
  if (
    !/^[1-9][0-9]*$/u.test(buildInputs.environment.cargoBuildJobs) ||
    !Number.isSafeInteger(Number(buildInputs.environment.cargoBuildJobs)) ||
    buildInputs.environment.cargoIncremental !== "0" ||
    buildInputs.environment.sourceDateEpoch !== "0" ||
    buildInputs.environment.rustflags !==
      "--remap-path-prefix=$REPOSITORY=. --remap-path-prefix=$CARGO_TARGET_DIR=./.cargo-target --remap-path-prefix=$CARGO_BUILD_BUILD_DIR=./.cargo-build --remap-path-prefix=$CARGO_HOME=./.cargo-home" ||
    buildInputs.environment.rustcWrapper !== "native/rustc-wrapper"
  ) {
    fail("build environment does not match the deterministic package contract");
  }
  const expectedLinkerVariable = `CARGO_TARGET_${platform.targetTriple
    .toUpperCase()
    .replaceAll("-", "_")}_LINKER`;
  if (buildInputs.environment.cargoTargetLinkerVariable !== expectedLinkerVariable) {
    fail("build linker environment variable does not match the package target");
  }

  assertExactKeys(
    buildInputs.rustDistribution,
    ["cargo", "manifests", "rustc", "rustcWrapper"],
    "Rust distribution"
  );
  validateMaterial(buildInputs.rustDistribution.cargo, "Cargo executable");
  validateMaterial(buildInputs.rustDistribution.rustc, "rustc executable");
  validateMaterial(buildInputs.rustDistribution.rustcWrapper, "rustc pass-through wrapper");
  if (
    buildInputs.rustDistribution.cargo.path !== "rust-toolchain/bin/cargo" ||
    buildInputs.rustDistribution.rustc.path !== "rust-toolchain/bin/rustc" ||
    buildInputs.rustDistribution.rustcWrapper.path !== "native/rustc-wrapper"
  ) {
    fail("Rust executable material paths do not match the package contract");
  }
  validateSortedMaterials(buildInputs.rustDistribution.manifests, "Rust distribution manifest");

  assertExactKeys(
    buildInputs.nativeToolchain,
    ["compilerDriver", "compilerDriverVersion", "kind", "linker", "linkerVersion", "runtime"],
    "native toolchain"
  );
  const expectedNativeKind = platform.os === "linux" ? "linux-gnu" : "apple-xcode";
  if (buildInputs.nativeToolchain.kind !== expectedNativeKind) {
    fail("native toolchain kind does not match the package platform");
  }
  validateMaterial(buildInputs.nativeToolchain.compilerDriver, "native compiler driver");
  validateMaterial(buildInputs.nativeToolchain.linker, "native linker");
  requireString(
    buildInputs.nativeToolchain.compilerDriverVersion,
    "native compiler driver version"
  );
  requireString(buildInputs.nativeToolchain.linkerVersion, "native linker version");
  assertExactKeys(
    buildInputs.nativeToolchain.runtime,
    ["identity", "kind", "materials"],
    "native runtime"
  );
  const expectedRuntimeKind = platform.os === "linux" ? "glibc" : "macos-sdk";
  if (buildInputs.nativeToolchain.runtime.kind !== expectedRuntimeKind) {
    fail("native runtime kind does not match the package platform");
  }
  requireString(buildInputs.nativeToolchain.runtime.identity, "native runtime identity");
  validateSortedMaterials(buildInputs.nativeToolchain.runtime.materials, "native runtime material");
}

function validatePackagePayload(payload) {
  assertExactKeys(
    payload,
    ["binary", "identities", "kind", "platform", "provenance", "schemaVersion"],
    "manifest payload"
  );
  if (payload.kind !== compilerPackageKind) {
    fail(`unsupported manifest kind ${JSON.stringify(payload.kind)}`);
  }
  if (payload.schemaVersion !== compilerPackageSchemaVersion) {
    fail(`unsupported manifest schema ${JSON.stringify(payload.schemaVersion)}`);
  }

  assertExactKeys(
    payload.platform,
    ["arch", "binaryFormat", "os", "targetTriple"],
    "manifest platform"
  );
  const expectedPlatform = platformForCompilerTarget(
    requireString(payload.platform.targetTriple, "manifest target triple")
  );
  for (const field of ["arch", "binaryFormat", "os"]) {
    if (payload.platform[field] !== expectedPlatform[field]) {
      fail(`manifest platform ${field} disagrees with its target triple`);
    }
  }

  assertExactKeys(payload.binary, ["path", "sha256", "size"], "manifest binary");
  if (payload.binary.path !== compilerPackageBinaryRelativePath) {
    fail(`manifest binary path must be ${compilerPackageBinaryRelativePath}`);
  }
  requireSha256(payload.binary.sha256, "manifest binary sha256");
  const binarySize = requireSize(payload.binary.size, "manifest binary size");
  if (binarySize === 0 || binarySize > MAX_BINARY_BYTES) {
    fail(`manifest binary size must be between 1 and ${MAX_BINARY_BYTES}`);
  }

  assertExactKeys(
    payload.provenance,
    ["buildInputs", "cargoArguments", "mode", "profile"],
    "manifest provenance"
  );
  if (payload.provenance.mode !== "built") {
    fail("manifest provenance mode must be built");
  }
  if (payload.provenance.profile !== "release") {
    fail("manifest provenance profile must be release");
  }
  if (
    !Array.isArray(payload.provenance.cargoArguments) ||
    payload.provenance.cargoArguments.some(
      (argument) => typeof argument !== "string" || argument.length === 0
    )
  ) {
    fail("manifest cargo arguments must be an array of non-empty strings");
  }
  const expectedCargoArguments = [
    "build",
    "--locked",
    "--release",
    "--target",
    payload.platform.targetTriple,
    "--bin",
    "convex-wasm-compiler",
  ];
  if (
    canonicalCompilerPackageJson(payload.provenance.cargoArguments) !==
    canonicalCompilerPackageJson(expectedCargoArguments)
  ) {
    fail("built package Cargo arguments do not match the package contract");
  }
  validateNativeRustBuildInputs(payload.provenance.buildInputs, payload.platform);

  assertExactKeys(
    payload.identities,
    ["cargoLock", "oxc", "rust", "source", "toolchain"],
    "manifest identities"
  );
  assertExactKeys(payload.identities.source, ["materials", "treeSha256"], "source identity");
  if (
    !Array.isArray(payload.identities.source.materials) ||
    payload.identities.source.materials.length === 0
  ) {
    fail("source materials must be a non-empty array");
  }
  validateSortedMaterials(payload.identities.source.materials, "source material");
  const expectedTreeSha256 = sha256Bytes(
    canonicalCompilerPackageJson(payload.identities.source.materials)
  );
  if (payload.identities.source.treeSha256 !== expectedTreeSha256) {
    fail("source tree digest does not match its materials");
  }

  assertExactKeys(payload.identities.cargoLock, ["path", "sha256", "size"], "Cargo.lock identity");
  validateMaterial(payload.identities.cargoLock, "Cargo.lock identity");
  const cargoLockMaterial = payload.identities.source.materials.find(
    (material) => material.path === payload.identities.cargoLock.path
  );
  if (
    cargoLockMaterial === undefined ||
    canonicalCompilerPackageJson(cargoLockMaterial) !==
      canonicalCompilerPackageJson(payload.identities.cargoLock)
  ) {
    fail("Cargo.lock identity must match its source material");
  }

  assertExactKeys(
    payload.identities.toolchain,
    ["channel", "components", "file", "profile"],
    "toolchain identity"
  );
  requireString(payload.identities.toolchain.channel, "toolchain channel");
  requireString(payload.identities.toolchain.profile, "toolchain profile");
  if (
    !Array.isArray(payload.identities.toolchain.components) ||
    payload.identities.toolchain.components.some(
      (component) => typeof component !== "string" || component.length === 0
    )
  ) {
    fail("toolchain components must be an array of non-empty strings");
  }
  for (let index = 1; index < payload.identities.toolchain.components.length; index += 1) {
    if (
      payload.identities.toolchain.components[index - 1] >=
      payload.identities.toolchain.components[index]
    ) {
      fail("toolchain components must be sorted and unique");
    }
  }
  validateMaterial(payload.identities.toolchain.file, "toolchain file identity");
  const toolchainMaterial = payload.identities.source.materials.find(
    (material) => material.path === payload.identities.toolchain.file.path
  );
  if (
    toolchainMaterial === undefined ||
    canonicalCompilerPackageJson(toolchainMaterial) !==
      canonicalCompilerPackageJson(payload.identities.toolchain.file)
  ) {
    fail("toolchain identity must match its source material");
  }

  assertExactKeys(
    payload.identities.rust,
    ["cargoVerboseVersion", "rustcVerboseVersion"],
    "Rust identity"
  );
  if (
    rustHostFromVerboseVersion(payload.identities.rust.cargoVerboseVersion) !==
    payload.platform.targetTriple
  ) {
    fail("Cargo host target does not match the package target");
  }
  if (
    rustHostFromVerboseVersion(payload.identities.rust.rustcVerboseVersion) !==
    payload.platform.targetTriple
  ) {
    fail("Rust host target does not match the package target");
  }
  if (
    releaseFromVerboseVersion(
      payload.identities.rust.rustcVerboseVersion,
      "Rust verbose version"
    ) !== payload.identities.toolchain.channel ||
    releaseFromVerboseVersion(
      payload.identities.rust.cargoVerboseVersion,
      "Cargo verbose version"
    ) !== payload.identities.toolchain.channel
  ) {
    fail("Rust or Cargo release does not match the pinned toolchain channel");
  }

  assertExactKeys(payload.identities.oxc, ["packages"], "Oxc identity");
  if (
    !Array.isArray(payload.identities.oxc.packages) ||
    payload.identities.oxc.packages.length === 0
  ) {
    fail("Oxc identity must contain at least one package");
  }
  let previousOxcKey = "";
  for (const [index, oxcPackage] of payload.identities.oxc.packages.entries()) {
    assertObject(oxcPackage, `Oxc package ${index}`);
    if (!requireString(oxcPackage.name, `Oxc package ${index} name`).startsWith("oxc_")) {
      fail(`Oxc package ${index} name must start with oxc_`);
    }
    requireString(oxcPackage.version, `Oxc package ${index} version`);
    const source = requireString(oxcPackage.source, `Oxc package ${index} source`);
    if (source.startsWith("registry+")) {
      assertExactKeys(
        oxcPackage,
        ["checksum", "name", "source", "version"],
        `Oxc package ${index}`
      );
      requireSha256(oxcPackage.checksum, `Oxc package ${index} checksum`);
    } else {
      assertExactKeys(
        oxcPackage,
        ["name", "revision", "source", "version"],
        `Oxc package ${index}`
      );
      const sourceMatch = source.match(OXC_GIT_SOURCE_PATTERN);
      if (
        sourceMatch === null ||
        !GIT_REVISION_PATTERN.test(oxcPackage.revision) ||
        sourceMatch[1] !== oxcPackage.revision ||
        sourceMatch[2] !== oxcPackage.revision
      ) {
        fail(`Oxc package ${index} must bind one exact Oxc Git revision`);
      }
    }
    const key = `${oxcPackage.name}\0${oxcPackage.version}\0${oxcPackage.source}`;
    if (key <= previousOxcKey) {
      fail("Oxc packages must be sorted and unique");
    }
    previousOxcKey = key;
  }
}

export function createCompilerPackageManifest(payload) {
  validatePackagePayload(payload);
  return {
    ...payload,
    packageId: sha256Bytes(canonicalCompilerPackageJson(payload)),
  };
}

export function validateCompilerPackageManifest(manifest) {
  assertExactKeys(
    manifest,
    ["binary", "identities", "kind", "packageId", "platform", "provenance", "schemaVersion"],
    "manifest"
  );
  const { packageId, ...payload } = manifest;
  requireSha256(packageId, "manifest package ID");
  validatePackagePayload(payload);
  if (packageId !== sha256Bytes(canonicalCompilerPackageJson(payload))) {
    fail("manifest package ID does not match its payload");
  }
  return manifest;
}

async function requireFilesystemEntry(path, type, mode) {
  const entry = await fs.lstat(path);
  if (entry.isSymbolicLink()) {
    fail(`${path} must not be a symbolic link`);
  }
  if ((type === "directory" && !entry.isDirectory()) || (type === "file" && !entry.isFile())) {
    fail(`${path} must be a ${type}`);
  }
  if ((entry.mode & 0o7777) !== mode) {
    fail(`${path} must have mode ${mode.toString(8).padStart(4, "0")}`);
  }
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) {
    fail(`${path} must be owned by the current user`);
  }
  return entry;
}

async function requireExactDirectoryEntries(path, expectedNames) {
  const actualNames = (await fs.readdir(path)).sort();
  const sortedExpectedNames = [...expectedNames].sort();
  if (
    actualNames.length !== sortedExpectedNames.length ||
    actualNames.some((name, index) => name !== sortedExpectedNames[index])
  ) {
    fail(`${path} must contain exactly ${sortedExpectedNames.join(", ")}`);
  }
}

function requireNoFollowFlag() {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("this platform does not provide O_NOFOLLOW");
  }
  return fsConstants.O_NOFOLLOW;
}

function sameFileSnapshot(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

export async function hashStableFile(
  path,
  maximumBytes = Number.MAX_SAFE_INTEGER,
  { expectedCanonicalPath } = {}
) {
  const handle = await fs.open(path, fsConstants.O_RDONLY | requireNoFollowFlag());
  try {
    const [before, pathBefore, canonicalBefore] = await Promise.all([
      handle.stat(),
      fs.lstat(path),
      expectedCanonicalPath === undefined ? undefined : fs.realpath(path),
    ]);
    if (!before.isFile()) {
      fail(`${path} must be a regular file`);
    }
    if (
      !sameFileSnapshot(before, pathBefore) ||
      (expectedCanonicalPath !== undefined && canonicalBefore !== expectedCanonicalPath)
    ) {
      fail(`${path} changed while it was being hashed`);
    }
    if (!Number.isSafeInteger(before.size) || before.size > maximumBytes) {
      fail(`${path} exceeds the ${maximumBytes}-byte limit`);
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, before.size - offset),
        offset
      );
      if (bytesRead === 0) {
        fail(`${path} changed while it was being hashed`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    // An opened descriptor remains attached to an unlinked inode. Compare the path as well so an
    // atomic source replacement cannot authenticate bytes that the repository no longer names.
    const [after, pathAfter, canonicalAfter] = await Promise.all([
      handle.stat(),
      fs.lstat(path),
      expectedCanonicalPath === undefined ? undefined : fs.realpath(path),
    ]);
    if (
      !sameFileSnapshot(before, after) ||
      !sameFileSnapshot(after, pathAfter) ||
      (expectedCanonicalPath !== undefined && canonicalAfter !== expectedCanonicalPath)
    ) {
      fail(`${path} changed while it was being hashed`);
    }
    return { sha256: hash.digest("hex"), size: before.size };
  } finally {
    await handle.close();
  }
}

async function readStablePrivateFile(path, maximumBytes, mode) {
  const handle = await fs.open(path, fsConstants.O_RDONLY | requireNoFollowFlag());
  try {
    const [before, pathBefore] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (!before.isFile()) {
      fail(`${path} must be a regular file`);
    }
    if (!sameFileSnapshot(before, pathBefore)) {
      fail(`${path} changed while it was being read`);
    }
    if ((before.mode & 0o7777) !== mode) {
      fail(`${path} must have mode ${mode.toString(8).padStart(4, "0")}`);
    }
    if (typeof process.getuid === "function" && before.uid !== process.getuid()) {
      fail(`${path} must be owned by the current user`);
    }
    if (!Number.isSafeInteger(before.size) || before.size === 0 || before.size > maximumBytes) {
      fail(`${path} size must be between 1 and ${maximumBytes}`);
    }
    const contents = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await handle.read(contents, offset, before.size - offset, offset);
      if (bytesRead === 0) {
        fail(`${path} changed while it was being read`);
      }
      offset += bytesRead;
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (!sameFileSnapshot(before, after) || !sameFileSnapshot(after, pathAfter)) {
      fail(`${path} changed while it was being read`);
    }
    return contents;
  } finally {
    await handle.close();
  }
}

function inspectCompilerBinaryHeader(header, path) {
  if (header.byteLength < 20) {
    fail(`${path} is too short to be a supported native binary`);
  }
  if (header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
    if (header[4] !== 2 || header[5] !== 1) {
      fail(`${path} must be a little-endian ELF64 binary`);
    }
    const machine = header.readUInt16LE(18);
    if (machine === 62) {
      return { arch: "x64", binaryFormat: "elf64", os: "linux" };
    }
    if (machine === 183) {
      return { arch: "arm64", binaryFormat: "elf64", os: "linux" };
    }
    fail(`${path} has unsupported ELF machine ${machine}`);
  }
  if (header[0] === 0xcf && header[1] === 0xfa && header[2] === 0xed && header[3] === 0xfe) {
    const cpuType = header.readUInt32LE(4);
    if (cpuType === 0x01000007) {
      return { arch: "x64", binaryFormat: "macho64", os: "darwin" };
    }
    if (cpuType === 0x0100000c) {
      return { arch: "arm64", binaryFormat: "macho64", os: "darwin" };
    }
    fail(`${path} has unsupported Mach-O CPU type ${cpuType}`);
  }
  fail(`${path} is not a supported ELF64 or thin Mach-O 64-bit binary`);
}

export async function inspectCompilerBinary(path) {
  const handle = await fs.open(path, fsConstants.O_RDONLY | requireNoFollowFlag());
  try {
    const [before, pathBefore] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (!before.isFile()) {
      fail(`${path} must be a regular file`);
    }
    if (!sameFileSnapshot(before, pathBefore)) {
      fail(`${path} changed while its binary format was being inspected`);
    }
    const header = Buffer.alloc(Math.min(64, before.size));
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    const [after, pathAfter] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (
      bytesRead !== header.length ||
      !sameFileSnapshot(before, after) ||
      !sameFileSnapshot(after, pathAfter)
    ) {
      fail(`${path} changed while its binary format was being inspected`);
    }
    return inspectCompilerBinaryHeader(header, path);
  } finally {
    await handle.close();
  }
}

export async function hashAndInspectCompilerBinary(path, { retainContents = false } = {}) {
  if (typeof retainContents !== "boolean") {
    fail("binary content retention must be a boolean");
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | requireNoFollowFlag());
  try {
    const [before, pathBefore] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (!before.isFile() || before.size === 0 || before.size > MAX_BINARY_BYTES) {
      fail(`${path} size must be between 1 and ${MAX_BINARY_BYTES}`);
    }
    if (!sameFileSnapshot(before, pathBefore)) {
      fail(`${path} changed while it was being authenticated`);
    }
    const hash = createHash("sha256");
    const contents = retainContents ? Buffer.alloc(before.size) : undefined;
    const buffer = contents ?? Buffer.allocUnsafe(64 * 1024);
    const header = Buffer.alloc(Math.min(64, before.size));
    let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await handle.read(
        buffer,
        retainContents ? offset : 0,
        Math.min(buffer.length, before.size - offset),
        offset
      );
      if (bytesRead === 0) {
        fail(`${path} changed while it was being authenticated`);
      }
      const chunk = retainContents
        ? buffer.subarray(offset, offset + bytesRead)
        : buffer.subarray(0, bytesRead);
      if (offset < header.length) {
        chunk.copy(header, offset, 0, Math.min(bytesRead, header.length - offset));
      }
      hash.update(chunk);
      offset += bytesRead;
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (!sameFileSnapshot(before, after) || !sameFileSnapshot(after, pathAfter)) {
      fail(`${path} changed while it was being authenticated`);
    }
    return {
      binary: { sha256: hash.digest("hex"), size: before.size },
      ...(contents === undefined ? {} : { contents }),
      platform: inspectCompilerBinaryHeader(header, path),
      snapshot: before,
    };
  } finally {
    await handle.close();
  }
}

export async function loadAndVerifyCompilerPackage(
  packageDirectory,
  { runtimeArch = process.arch, runtimePlatform = process.platform } = {}
) {
  const normalizedPackageDirectory = resolve(packageDirectory);
  const packageDirectoryEntry = await requireFilesystemEntry(
    normalizedPackageDirectory,
    "directory",
    0o700
  );
  await requireExactDirectoryEntries(normalizedPackageDirectory, [
    "bin",
    compilerPackageManifestName,
  ]);
  const manifestPath = join(normalizedPackageDirectory, compilerPackageManifestName);
  const manifestBytes = await readStablePrivateFile(manifestPath, MAX_MANIFEST_BYTES, 0o600);
  const manifestText = manifestBytes.toString("utf8");
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      throw error;
    }
    fail("manifest is not valid JSON");
  }
  validateCompilerPackageManifest(manifest);
  if (manifestText !== `${canonicalCompilerPackageJson(manifest)}\n`) {
    fail("manifest must use canonical JSON with one trailing newline");
  }
  if (basename(normalizedPackageDirectory) !== manifest.packageId) {
    fail("package directory name must equal the manifest package ID");
  }
  if (manifest.platform.os !== runtimePlatform || manifest.platform.arch !== runtimeArch) {
    fail(
      `package platform ${manifest.platform.os}/${manifest.platform.arch} does not match runtime ${runtimePlatform}/${runtimeArch}`
    );
  }

  const binaryDirectory = join(normalizedPackageDirectory, "bin");
  const binaryDirectoryEntry = await requireFilesystemEntry(binaryDirectory, "directory", 0o700);
  await requireExactDirectoryEntries(binaryDirectory, ["convex-wasm-compiler"]);
  const binaryPath = join(normalizedPackageDirectory, compilerPackageBinaryRelativePath);
  const binaryEntry = await requireFilesystemEntry(binaryPath, "file", 0o700);
  if (binaryEntry.size !== manifest.binary.size) {
    fail("compiler binary size does not match the manifest");
  }
  const {
    binary: binaryDigest,
    platform: binaryPlatform,
    snapshot: binarySnapshot,
  } = await hashAndInspectCompilerBinary(binaryPath);
  if (
    binaryDigest.size !== manifest.binary.size ||
    binaryDigest.sha256 !== manifest.binary.sha256
  ) {
    fail("compiler binary digest does not match the manifest");
  }
  for (const field of ["arch", "binaryFormat", "os"]) {
    if (binaryPlatform[field] !== manifest.platform[field]) {
      fail(`compiler binary ${field} does not match the manifest`);
    }
  }
  // Manifest and binary checks are individually path-stable, but the package directory can be
  // replaced between them. Recheck both paths and the exact directory membership so one load
  // cannot return a manifest/binary pair from different package-directory generations.
  const [
    currentManifestBytes,
    currentBinaryEntry,
    currentPackageDirectoryEntry,
    currentBinaryDirectoryEntry,
  ] = await Promise.all([
    readStablePrivateFile(manifestPath, MAX_MANIFEST_BYTES, 0o600),
    requireFilesystemEntry(binaryPath, "file", 0o700),
    requireFilesystemEntry(normalizedPackageDirectory, "directory", 0o700),
    requireFilesystemEntry(binaryDirectory, "directory", 0o700),
    requireExactDirectoryEntries(normalizedPackageDirectory, ["bin", compilerPackageManifestName]),
    requireExactDirectoryEntries(binaryDirectory, ["convex-wasm-compiler"]),
  ]);
  if (
    !currentManifestBytes.equals(manifestBytes) ||
    !sameFileSnapshot(binarySnapshot, currentBinaryEntry) ||
    !sameFileSnapshot(packageDirectoryEntry, currentPackageDirectoryEntry) ||
    !sameFileSnapshot(binaryDirectoryEntry, currentBinaryDirectoryEntry)
  ) {
    fail("package material changed while it was being authenticated");
  }
  return {
    binaryPath,
    manifest,
    manifestPath,
    packageDirectory: normalizedPackageDirectory,
    packageName: basename(normalizedPackageDirectory),
  };
}
