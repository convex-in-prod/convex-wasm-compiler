import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  canonicalCompilerPackageJson,
  compilerPackageBinaryRelativePath,
  compilerPackageKind,
  compilerPackageSchemaVersion,
  createCompilerPackageManifest,
  hashStableFile,
  inspectCompilerBinary,
  platformForCompilerTarget,
  sha256Bytes,
} from "../../lib/convex-wasm-compiler-package.mjs";

const targetByRuntime = {
  "darwin/arm64": "aarch64-apple-darwin",
  "darwin/x64": "x86_64-apple-darwin",
  "linux/arm64": "aarch64-unknown-linux-gnu",
  "linux/x64": "x86_64-unknown-linux-gnu",
};

export async function writeFixtureCompilerPackage({
  binarySuffix,
  binarySourcePath = process.execPath,
  identitySeed = "default",
  root,
}) {
  const stagingDirectory = join(root, `staging-${identitySeed}`);
  const binaryDirectory = join(stagingDirectory, "bin");
  await fs.mkdir(binaryDirectory, { mode: 0o700, recursive: true });
  await fs.chmod(stagingDirectory, 0o700);
  await fs.chmod(binaryDirectory, 0o700);
  const stagingBinaryPath = join(stagingDirectory, compilerPackageBinaryRelativePath);
  await fs.copyFile(binarySourcePath, stagingBinaryPath);
  if (binarySuffix !== undefined) {
    await fs.appendFile(stagingBinaryPath, binarySuffix);
  }
  await fs.chmod(stagingBinaryPath, 0o700);
  const binary = await hashStableFile(stagingBinaryPath);
  const binaryPlatform = await inspectCompilerBinary(stagingBinaryPath);
  const targetTriple = targetByRuntime[`${process.platform}/${process.arch}`];
  assert.ok(targetTriple, "test runtime must be a supported compiler package target");
  assert.deepEqual(
    binaryPlatform,
    (({ targetTriple: _targetTriple, ...platform }) => platform)(
      platformForCompilerTarget(targetTriple)
    )
  );
  const materialSha256 = (label) => sha256Bytes(`${identitySeed}\0${label}`);
  const material = (path, label, size = 1) => ({
    path,
    sha256: materialSha256(label),
    size,
  });
  const materials = [
    {
      path: "scripts/convex-wasm-compiler/Cargo.lock",
      sha256: materialSha256("Cargo.lock"),
      size: 1,
    },
    {
      path: "scripts/convex-wasm-compiler/Cargo.toml",
      sha256: materialSha256("Cargo.toml"),
      size: 2,
    },
    {
      path: "scripts/convex-wasm-compiler/rust-toolchain.toml",
      sha256: materialSha256("rust-toolchain.toml"),
      size: 3,
    },
  ];
  const platform = platformForCompilerTarget(targetTriple);
  const manifest = createCompilerPackageManifest({
    binary: { path: compilerPackageBinaryRelativePath, ...binary },
    identities: {
      cargoLock: materials[0],
      oxc: {
        packages: [
          {
            checksum: materialSha256("oxc_allocator"),
            name: "oxc_allocator",
            source: "registry+https://github.com/rust-lang/crates.io-index",
            version: "0.142.0",
          },
          {
            checksum: materialSha256("oxc_parser"),
            name: "oxc_parser",
            source: "registry+https://github.com/rust-lang/crates.io-index",
            version: "0.142.0",
          },
        ],
      },
      rust: {
        cargoVerboseVersion: `cargo 1.97.1\nrelease: 1.97.1\nhost: ${targetTriple}\n`,
        rustcVerboseVersion: `rustc 1.97.1\nhost: ${targetTriple}\nrelease: 1.97.1\n`,
      },
      source: {
        materials,
        treeSha256: sha256Bytes(canonicalCompilerPackageJson(materials)),
      },
      toolchain: {
        channel: "1.97.1",
        components: [],
        file: materials[2],
        profile: "minimal",
      },
    },
    kind: compilerPackageKind,
    platform,
    provenance: {
      buildInputs: {
        cargoConfiguration: [],
        environment: {
          cargoBuildJobs: "1",
          cargoIncremental: "0",
          cargoTargetLinkerVariable: `CARGO_TARGET_${targetTriple
            .toUpperCase()
            .replaceAll("-", "_")}_LINKER`,
          rustcWrapper: "native/rustc-wrapper",
          rustflags:
            "--remap-path-prefix=$REPOSITORY=. --remap-path-prefix=$CARGO_TARGET_DIR=./.cargo-target --remap-path-prefix=$CARGO_BUILD_BUILD_DIR=./.cargo-build --remap-path-prefix=$CARGO_HOME=./.cargo-home",
          sourceDateEpoch: "0",
        },
        nativeToolchain: {
          compilerDriver: material("native/compiler-driver", "compiler-driver"),
          compilerDriverVersion: "fixture compiler driver",
          kind: platform.os === "linux" ? "linux-gnu" : "apple-xcode",
          linker: material("native/linker", "linker"),
          linkerVersion: "fixture linker",
          runtime: {
            identity: "fixture runtime",
            kind: platform.os === "linux" ? "glibc" : "macos-sdk",
            materials: [material("native/runtime/material", "runtime")],
          },
        },
        rustDistribution: {
          cargo: material("rust-toolchain/bin/cargo", "cargo"),
          manifests: [material("rust-toolchain/lib/rustlib/components", "rust-components")],
          rustc: material("rust-toolchain/bin/rustc", "rustc"),
          rustcWrapper: material("native/rustc-wrapper", "rustc-wrapper"),
        },
      },
      cargoArguments: [
        "build",
        "--locked",
        "--release",
        "--target",
        targetTriple,
        "--bin",
        "convex-wasm-compiler",
      ],
      mode: "built",
      profile: "release",
    },
    schemaVersion: compilerPackageSchemaVersion,
  });
  const stagingManifestPath = join(stagingDirectory, "manifest.json");
  await fs.writeFile(stagingManifestPath, `${canonicalCompilerPackageJson(manifest)}\n`, {
    mode: 0o600,
  });
  await fs.chmod(stagingManifestPath, 0o600);
  const packageDirectory = join(root, manifest.packageId);
  await fs.rename(stagingDirectory, packageDirectory);
  return {
    binaryPath: join(packageDirectory, compilerPackageBinaryRelativePath),
    manifest,
    manifestPath: join(packageDirectory, "manifest.json"),
    packageDirectory,
  };
}
