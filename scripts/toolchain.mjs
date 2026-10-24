#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyToolchainPackage, toolchainEnvironment } from "./lib/convex-wasm-toolchain-package.mjs";
import { loadAndVerifyCompilerPackage } from "./lib/convex-wasm-compiler-package.mjs";
import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";

export async function main(args) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const [command, ...options] = args;
  if (command === "--help" || command === "help") {
    process.stdout.write("usage: convex-wasm verify | build --config PROJECT.json | smoke --cache-root PATH\n");
    return;
  }
  if (!["verify", "build", "smoke"].includes(command)) throw new Error("Expected verify, build or smoke; use --help");
  const manifest = await verifyToolchainPackage(root);
  const [compiler, precompiler] = await Promise.all([
    loadAndVerifyCompilerPackage(join(root, manifest.nativePackages.compiler)),
    loadAndVerifyPrecompilerPackage(join(root, manifest.nativePackages.precompiler)),
  ]);
  if (command === "verify") {
    if (options.length !== 0) throw new Error("verify accepts no arguments");
    process.stdout.write(`${JSON.stringify({ packageId: manifest.packageId, version: manifest.version,
      platform: manifest.platform, hermes: manifest.source.hermes,
      compilerPackageId: compiler.manifest.packageId, precompilerPackageId: precompiler.manifest.packageId })}\n`);
    return;
  }
  if (command === "smoke") {
    if (options.length !== 2 || options[0] !== "--cache-root") throw new Error("smoke requires --cache-root PATH");
    const cacheRoot = resolve(options[1]);
    const environment = await toolchainEnvironment(root, manifest, cacheRoot);
    const { verifyConvexWasmSourceToAot } = await import("./verify-convex-wasm-source-to-aot.mjs");
    const result = await verifyConvexWasmSourceToAot({ aotWorkers: 1, cacheRoot, environment,
      emcc: join(root, "gate/emsdk/upstream/emscripten/emcc"), emsdkRoot: join(root, "gate/emsdk"),
      hermesSource: join(root, "gate/hermes"), mode: "bundle", precompilerPackage: precompiler.packageDirectory,
      shermes: join(root, "gate/build-host/bin/shermes"), wasmBuild: join(root, "gate/build-wasm") });
    // A successful compilation must not have written Python bytecode or SDK cache
    // files into the sealed installation.
    await verifyToolchainPackage(root);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (options.length !== 2 || options[0] !== "--config") throw new Error("build requires --config PROJECT.json");
  const configPath = resolve(options[1]);
  const value = JSON.parse(await fs.readFile(configPath, "utf8"));
  if (Object.hasOwn(value, "toolchain")) throw new Error("The bundled launcher selects its own toolchain");
  const { parseProjectConfig } = await import("./lib/convex-wasm-project-build-inputs.mjs");
  const { buildConvexWasmFromProjectConfig } = await import("./build-convex-wasm.mjs");
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    const result = await buildConvexWasmFromProjectConfig(parseProjectConfig({ ...value, toolchain: root }, configPath), {
      signal: cancellation.signal,
    });
    process.stdout.write(`${JSON.stringify({ artifactReport: result.reportPath })}\n`);
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}

if (import.meta.main) await main(process.argv.slice(2));
