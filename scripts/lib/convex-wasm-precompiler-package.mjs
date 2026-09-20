import { constants as fsConstants, promises as fs } from "node:fs";
import { basename, join, resolve } from "node:path";

import {
  canonicalCompilerPackageJson,
  hashAndInspectCompilerBinary,
  platformForCompilerTarget,
  rustHostFromVerboseVersion,
  sha256Bytes,
  validateNativeRustBuildInputs,
} from "./convex-wasm-compiler-package.mjs";

export const precompilerPackageBinaryRelativePath = "bin/convex-wasm-precompiler";
export const precompilerPackageKind = "convex-wasm-precompiler-package";
export const precompilerPackageManifestName = "manifest.json";
export const precompilerPackageSchemaVersion = 1;

const MAX_BINARY_BYTES = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 256 * 1024;
const GIT_REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex Wasm precompiler package: ${message}`);
}

function assertObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
}

function assertExactKeys(value, keys, description) {
  assertObject(value, description);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
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
  requireSha256(material.sha256, `${description} SHA-256`);
  requireSize(material.size, `${description} size`);
}

function validateMaterials(materials, description) {
  if (!Array.isArray(materials) || materials.length === 0) {
    fail(`${description} must be a non-empty array`);
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

function releaseFromVerboseVersion(value, description) {
  const releases = requireString(value, description)
    .split("\n")
    .filter((line) => line.startsWith("release: "));
  if (releases.length !== 1) {
    fail(`${description} must contain exactly one release`);
  }
  return releases[0].slice("release: ".length);
}

function validateToolchain(toolchain, sourceMaterials) {
  assertExactKeys(toolchain, ["channel", "components", "file", "profile"], "toolchain identity");
  requireString(toolchain.channel, "toolchain channel");
  requireString(toolchain.profile, "toolchain profile");
  if (
    !Array.isArray(toolchain.components) ||
    toolchain.components.some(
      (component) => typeof component !== "string" || component.length === 0
    )
  ) {
    fail("toolchain components must be an array of non-empty strings");
  }
  for (let index = 1; index < toolchain.components.length; index += 1) {
    if (toolchain.components[index - 1] >= toolchain.components[index]) {
      fail("toolchain components must be sorted and unique");
    }
  }
  validateMaterial(toolchain.file, "toolchain file");
  const sourceMaterial = sourceMaterials.find((material) => material.path === toolchain.file.path);
  if (
    sourceMaterial === undefined ||
    canonicalCompilerPackageJson(sourceMaterial) !== canonicalCompilerPackageJson(toolchain.file)
  ) {
    fail("toolchain file must match its source material");
  }
}

function validateWasmtimeIdentity(wasmtime) {
  assertExactKeys(wasmtime, ["features", "git", "lockedPackages", "revision"], "Wasmtime identity");
  if (
    wasmtime.git !== "https://github.com/bytecodealliance/wasmtime" ||
    !GIT_REVISION_PATTERN.test(wasmtime.revision)
  ) {
    fail("Wasmtime repository or revision does not match the package contract");
  }
  const expectedFeatures = [
    "all-arch",
    "async",
    "cranelift",
    "gc-null",
    "incremental-cache",
    "parallel-compilation",
    "runtime",
    "std",
  ].sort();
  if (canonicalCompilerPackageJson(wasmtime.features) !== canonicalCompilerPackageJson(expectedFeatures)) {
    fail("Wasmtime features do not match the package contract");
  }
  if (!Array.isArray(wasmtime.lockedPackages) || wasmtime.lockedPackages.length === 0) {
    fail("Wasmtime locked packages must be a non-empty array");
  }
  let previousKey = "";
  let hasWasmtime = false;
  for (const [index, packageIdentity] of wasmtime.lockedPackages.entries()) {
    assertExactKeys(
      packageIdentity,
      ["name", "source", "version"],
      `Wasmtime locked package ${index}`
    );
    const name = requireString(packageIdentity.name, `Wasmtime locked package ${index} name`);
    const source = requireString(packageIdentity.source, `Wasmtime locked package ${index} source`);
    const version = requireString(
      packageIdentity.version,
      `Wasmtime locked package ${index} version`
    );
    if (!name.startsWith("wasmtime") || !source.endsWith(`#${wasmtime.revision}`)) {
      fail(`Wasmtime locked package ${index} does not match the pinned revision`);
    }
    const key = `${name}\0${version}\0${source}`;
    if (key <= previousKey) {
      fail("Wasmtime locked packages must be sorted and unique");
    }
    previousKey = key;
    hasWasmtime ||= name === "wasmtime";
  }
  if (!hasWasmtime) {
    fail("Wasmtime locked packages do not contain the wasmtime crate");
  }
}

function validatePayload(payload) {
  assertExactKeys(
    payload,
    ["binary", "engineContract", "identities", "kind", "platform", "provenance", "schemaVersion"],
    "manifest payload"
  );
  if (
    payload.kind !== precompilerPackageKind ||
    payload.schemaVersion !== precompilerPackageSchemaVersion
  ) {
    fail("unsupported manifest kind or schema");
  }

  assertExactKeys(payload.platform, ["arch", "binaryFormat", "os", "targetTriple"], "platform");
  const expectedPlatform = platformForCompilerTarget(
    requireString(payload.platform.targetTriple, "target triple")
  );
  for (const field of ["arch", "binaryFormat", "os"]) {
    if (payload.platform[field] !== expectedPlatform[field]) {
      fail(`platform ${field} disagrees with its target triple`);
    }
  }

  assertExactKeys(payload.binary, ["path", "sha256", "size"], "binary");
  if (payload.binary.path !== precompilerPackageBinaryRelativePath) {
    fail(`binary path must be ${precompilerPackageBinaryRelativePath}`);
  }
  requireSha256(payload.binary.sha256, "binary SHA-256");
  const binarySize = requireSize(payload.binary.size, "binary size");
  if (binarySize === 0 || binarySize > MAX_BINARY_BYTES) {
    fail(`binary size must be between 1 and ${MAX_BINARY_BYTES}`);
  }

  assertExactKeys(
    payload.engineContract,
    [
      "consumeFuel",
      "engineIdentityKind",
      "epochInterruption",
      "profilingStrategy",
      "targetCpu",
      "wasmExceptions",
    ],
    "engine contract"
  );
  if (
    payload.engineContract.consumeFuel !== true ||
    payload.engineContract.engineIdentityKind !== "convex-wasm-wasmtime-engine-identity" ||
    payload.engineContract.epochInterruption !== true ||
    payload.engineContract.profilingStrategy !== "perf-map" ||
    payload.engineContract.targetCpu !== "baseline" ||
    payload.engineContract.wasmExceptions !== true
  ) {
    fail("engine contract does not match the backend contract");
  }

  assertExactKeys(
    payload.provenance,
    ["buildInputs", "cargoArguments", "cargoTestArguments", "profile"],
    "provenance"
  );
  if (payload.provenance.profile !== "release") {
    fail("profile must be release");
  }
  const expectedBuildArguments = [
    "build",
    "--locked",
    "--release",
    "--target",
    payload.platform.targetTriple,
    "--bin",
    "convex-wasm-precompiler",
    "--message-format=json-render-diagnostics",
  ];
  const expectedTestArguments = [
    "test",
    "--locked",
    "--release",
    "--target",
    payload.platform.targetTriple,
    "--bin",
    "convex-wasm-precompiler",
  ];
  if (
    canonicalCompilerPackageJson(payload.provenance.cargoArguments) !==
      canonicalCompilerPackageJson(expectedBuildArguments) ||
    canonicalCompilerPackageJson(payload.provenance.cargoTestArguments) !==
      canonicalCompilerPackageJson(expectedTestArguments)
  ) {
    fail("Cargo arguments do not match the package contract");
  }
  validateNativeRustBuildInputs(payload.provenance.buildInputs, payload.platform);

  assertExactKeys(
    payload.identities,
    ["cargoLock", "rust", "source", "toolchain", "wasmtime"],
    "identities"
  );
  assertExactKeys(payload.identities.source, ["materials", "treeSha256"], "source identity");
  validateMaterials(payload.identities.source.materials, "source materials");
  if (
    payload.identities.source.treeSha256 !==
    sha256Bytes(canonicalCompilerPackageJson(payload.identities.source.materials))
  ) {
    fail("source tree digest does not match its materials");
  }
  validateMaterial(payload.identities.cargoLock, "Cargo.lock");
  const cargoLockMaterial = payload.identities.source.materials.find(
    (material) => material.path === payload.identities.cargoLock.path
  );
  if (
    cargoLockMaterial === undefined ||
    canonicalCompilerPackageJson(cargoLockMaterial) !==
      canonicalCompilerPackageJson(payload.identities.cargoLock)
  ) {
    fail("Cargo.lock must match its source material");
  }
  validateToolchain(payload.identities.toolchain, payload.identities.source.materials);
  assertExactKeys(
    payload.identities.rust,
    ["cargoVerboseVersion", "rustcVerboseVersion"],
    "Rust identity"
  );
  if (
    rustHostFromVerboseVersion(payload.identities.rust.cargoVerboseVersion) !==
      payload.platform.targetTriple ||
    rustHostFromVerboseVersion(payload.identities.rust.rustcVerboseVersion) !==
      payload.platform.targetTriple
  ) {
    fail("Rust host does not match the package target");
  }
  if (
    releaseFromVerboseVersion(
      payload.identities.rust.cargoVerboseVersion,
      "Cargo verbose version"
    ) !== payload.identities.toolchain.channel ||
    releaseFromVerboseVersion(
      payload.identities.rust.rustcVerboseVersion,
      "rustc verbose version"
    ) !== payload.identities.toolchain.channel
  ) {
    fail("Rust release does not match the pinned toolchain");
  }
  validateWasmtimeIdentity(payload.identities.wasmtime);
}

export function createPrecompilerPackageManifest(payload) {
  validatePayload(payload);
  return {
    ...payload,
    packageId: sha256Bytes(canonicalCompilerPackageJson(payload)),
  };
}

export function validatePrecompilerPackageManifest(manifest) {
  assertExactKeys(
    manifest,
    [
      "binary",
      "engineContract",
      "identities",
      "kind",
      "packageId",
      "platform",
      "provenance",
      "schemaVersion",
    ],
    "manifest"
  );
  const { packageId, ...payload } = manifest;
  requireSha256(packageId, "package ID");
  validatePayload(payload);
  if (packageId !== sha256Bytes(canonicalCompilerPackageJson(payload))) {
    fail("package ID does not match the manifest payload");
  }
  return manifest;
}

export function precompilerPackageMaterialIdentity(manifest) {
  validatePrecompilerPackageManifest(manifest);
  return {
    binary: {
      sha256: manifest.binary.sha256,
      size: manifest.binary.size,
    },
    kind: "convex-wasm-verified-precompiler-package",
    manifestKind: manifest.kind,
    manifestSchemaVersion: manifest.schemaVersion,
    manifestSha256: sha256Bytes(`${canonicalCompilerPackageJson(manifest)}\n`),
    packageId: manifest.packageId,
    sourceTreeSha256: manifest.identities.source.treeSha256,
    targetTriple: manifest.platform.targetTriple,
    wasmtimeRevision: manifest.identities.wasmtime.revision,
  };
}

async function requireEntry(path, type, mode) {
  const entry = await fs.lstat(path);
  if (entry.isSymbolicLink()) {
    fail(`${path} must not be a symbolic link`);
  }
  if ((type === "file" && !entry.isFile()) || (type === "directory" && !entry.isDirectory())) {
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

async function requireDirectoryEntries(path, names) {
  const actual = (await fs.readdir(path)).sort();
  const expected = [...names].sort();
  if (canonicalCompilerPackageJson(actual) !== canonicalCompilerPackageJson(expected)) {
    fail(`${path} must contain exactly ${expected.join(", ")}`);
  }
}

async function readManifest(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("this platform does not provide O_NOFOLLOW");
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      (before.mode & 0o7777) !== 0o600 ||
      (typeof process.getuid === "function" && before.uid !== process.getuid()) ||
      before.size === 0 ||
      before.size > MAX_MANIFEST_BYTES
    ) {
      fail("manifest must be a private, owned, bounded regular file");
    }
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await handle.read(bytes, offset, before.size - offset, offset);
      if (bytesRead === 0) {
        fail("manifest changed while it was being read");
      }
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs
    ) {
      fail("manifest changed while it was being read");
    }
    return bytes.toString("utf8");
  } finally {
    await handle.close();
  }
}

export async function loadAndVerifyPrecompilerPackage(
  packageDirectory,
  {
    retainBinaryContents = false,
    runtimeArch = process.arch,
    runtimePlatform = process.platform,
  } = {}
) {
  if (typeof retainBinaryContents !== "boolean") {
    fail("binary content retention must be a boolean");
  }
  const normalizedPackageDirectory = resolve(packageDirectory);
  await requireEntry(normalizedPackageDirectory, "directory", 0o700);
  await requireDirectoryEntries(normalizedPackageDirectory, [
    "bin",
    precompilerPackageManifestName,
  ]);
  const manifestPath = join(normalizedPackageDirectory, precompilerPackageManifestName);
  const manifestText = await readManifest(manifestPath);
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    fail("manifest is not valid JSON");
  }
  validatePrecompilerPackageManifest(manifest);
  if (manifestText !== `${canonicalCompilerPackageJson(manifest)}\n`) {
    fail("manifest must use canonical JSON with one trailing newline");
  }
  if (basename(normalizedPackageDirectory) !== manifest.packageId) {
    fail("package directory name must equal the package ID");
  }
  if (manifest.platform.os !== runtimePlatform || manifest.platform.arch !== runtimeArch) {
    fail(
      `package platform ${manifest.platform.os}/${manifest.platform.arch} does not match runtime ${runtimePlatform}/${runtimeArch}`
    );
  }
  const binaryDirectory = join(normalizedPackageDirectory, "bin");
  await requireEntry(binaryDirectory, "directory", 0o700);
  await requireDirectoryEntries(binaryDirectory, ["convex-wasm-precompiler"]);
  const binaryPath = join(normalizedPackageDirectory, precompilerPackageBinaryRelativePath);
  const binaryEntry = await requireEntry(binaryPath, "file", 0o700);
  if (binaryEntry.size !== manifest.binary.size) {
    fail("binary size does not match the manifest");
  }
  // Hash and inspect through one descriptor so concurrent replacement cannot present different
  // byte generations to the identity and format checks. Material sessions retain that same
  // authenticated buffer instead of reading the package path again.
  let binaryContents;
  try {
    const inspectedBinary = await hashAndInspectCompilerBinary(binaryPath, {
      retainContents: retainBinaryContents,
    });
    const { binary, platform: binaryPlatform } = inspectedBinary;
    binaryContents = inspectedBinary.contents;
    if (binary.sha256 !== manifest.binary.sha256 || binary.size !== manifest.binary.size) {
      fail("binary digest does not match the manifest");
    }
    for (const field of ["arch", "binaryFormat", "os"]) {
      if (binaryPlatform[field] !== manifest.platform[field]) {
        fail(`binary ${field} does not match the manifest`);
      }
    }
    return {
      binary,
      ...(binaryContents === undefined ? {} : { binaryContents }),
      binaryPath,
      manifest,
      manifestPath,
      manifestSize: Buffer.byteLength(manifestText),
      packageDirectory: normalizedPackageDirectory,
    };
  } catch (error) {
    binaryContents?.fill(0);
    throw error;
  }
}
