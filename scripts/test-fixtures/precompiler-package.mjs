import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  canonicalCompilerPackageJson,
  hashStableFile,
  platformForCompilerTarget,
  sha256Bytes,
} from "../lib/convex-wasm-compiler-package.mjs";
import {
  createPrecompilerPackageManifest,
  precompilerPackageKind,
  precompilerPackageSchemaVersion,
} from "../lib/convex-wasm-precompiler-package.mjs";

const WASMTIME_REVISION = "45af25f4984d14c65663ed43541d2e641752f66d";

function targetTripleForHost() {
  if (process.platform === "darwin") {
    return `${process.arch === "arm64" ? "aarch64" : "x86_64"}-apple-darwin`;
  }
  return `${process.arch === "arm64" ? "aarch64" : "x86_64"}-unknown-linux-gnu`;
}

function fixtureDigest(identitySeed, label) {
  return sha256Bytes(`${identitySeed}\0${label}`);
}

function fixtureMaterial(identitySeed, path) {
  return {
    path,
    sha256: fixtureDigest(identitySeed, path),
    size: Buffer.byteLength(`${identitySeed}\0${path}`),
  };
}

export async function writeFixturePrecompilerPackage({
  binaryPath = process.execPath,
  identitySeed,
  root,
}) {
  const targetTriple = targetTripleForHost();
  const platform = platformForCompilerTarget(targetTriple);
  const sourceMaterials = [
    fixtureMaterial(identitySeed, "scripts/convex-wasm-precompiler/Cargo.lock"),
    fixtureMaterial(identitySeed, "scripts/convex-wasm-precompiler/rust-toolchain.toml"),
    fixtureMaterial(identitySeed, "scripts/convex-wasm-precompiler/src/main.rs"),
  ];
  const source = {
    materials: sourceMaterials,
    treeSha256: sha256Bytes(canonicalCompilerPackageJson(sourceMaterials)),
  };
  const cargoLock = sourceMaterials[0];
  const toolchainFile = sourceMaterials[1];
  const rustcVersion = [
    "rustc 1.97.1 (fixture)",
    `host: ${targetTriple}`,
    "release: 1.97.1",
    "",
  ].join("\n");
  const cargoVersion = [
    "cargo 1.97.1 (fixture)",
    "release: 1.97.1",
    `host: ${targetTriple}`,
    "",
  ].join("\n");
  const binary = await hashStableFile(binaryPath);
  const manifest = createPrecompilerPackageManifest({
    binary: { path: "bin/convex-wasm-precompiler", ...binary },
    engineContract: {
      consumeFuel: true,
      engineIdentityKind: "convex-wasm-wasmtime-engine-identity",
      epochInterruption: true,
      profilingStrategy: "perf-map",
      targetCpu: "baseline",
      wasmExceptions: true,
    },
    identities: {
      cargoLock,
      rust: {
        cargoVerboseVersion: cargoVersion,
        rustcVerboseVersion: rustcVersion,
      },
      source,
      toolchain: {
        channel: "1.97.1",
        components: [],
        file: toolchainFile,
        profile: "minimal",
      },
      wasmtime: {
        features: [
          "all-arch",
          "async",
          "cranelift",
          "gc-null",
          "incremental-cache",
          "parallel-compilation",
          "runtime",
          "std",
        ],
        git: "https://github.com/bytecodealliance/wasmtime",
        lockedPackages: [
          {
            name: "wasmtime",
            source: `git+https://github.com/bytecodealliance/wasmtime?rev=${WASMTIME_REVISION}#${WASMTIME_REVISION}`,
            version: "41.0.1",
          },
        ],
        revision: WASMTIME_REVISION,
      },
    },
    kind: precompilerPackageKind,
    platform,
    provenance: {
      buildInputs: {
        cargoConfiguration: [],
        environment: {
          cargoBuildJobs: "4",
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
          compilerDriver: fixtureMaterial(identitySeed, "native/compiler-driver"),
          compilerDriverVersion: "fixture compiler\n",
          kind: platform.os === "linux" ? "linux-gnu" : "apple-xcode",
          linker: fixtureMaterial(identitySeed, "native/linker"),
          linkerVersion: "fixture linker\n",
          runtime: {
            identity: "fixture runtime\n",
            kind: platform.os === "linux" ? "glibc" : "macos-sdk",
            materials: [fixtureMaterial(identitySeed, "native/runtime/material")],
          },
        },
        rustDistribution: {
          cargo: fixtureMaterial(identitySeed, "rust-toolchain/bin/cargo"),
          manifests: [fixtureMaterial(identitySeed, "rust-toolchain/lib/rustlib/components")],
          rustc: fixtureMaterial(identitySeed, "rust-toolchain/bin/rustc"),
          rustcWrapper: fixtureMaterial(identitySeed, "native/rustc-wrapper"),
        },
      },
      cargoArguments: [
        "build",
        "--locked",
        "--release",
        "--target",
        targetTriple,
        "--bin",
        "convex-wasm-precompiler",
        "--message-format=json-render-diagnostics",
      ],
      cargoTestArguments: [
        "test",
        "--locked",
        "--release",
        "--target",
        targetTriple,
        "--bin",
        "convex-wasm-precompiler",
      ],
      profile: "release",
    },
    schemaVersion: precompilerPackageSchemaVersion,
  });
  const packageDirectory = join(root, manifest.packageId);
  const binaryDirectory = join(packageDirectory, "bin");
  await fs.mkdir(binaryDirectory, { mode: 0o700, recursive: true });
  await Promise.all([fs.chmod(packageDirectory, 0o700), fs.chmod(binaryDirectory, 0o700)]);
  const packagedBinaryPath = join(binaryDirectory, "convex-wasm-precompiler");
  await fs.copyFile(binaryPath, packagedBinaryPath);
  await fs.chmod(packagedBinaryPath, 0o700);
  const manifestPath = join(packageDirectory, "manifest.json");
  await fs.writeFile(manifestPath, `${canonicalCompilerPackageJson(manifest)}\n`, {
    mode: 0o600,
  });
  return {
    binaryPath: packagedBinaryPath,
    manifest,
    manifestPath,
    packageDirectory,
  };
}
