#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { setupGate } from "./setup-gate.mjs";
import { loadAndVerifyCompilerPackage } from "./lib/convex-wasm-compiler-package.mjs";
import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";
import { sealToolchainPackage } from "./lib/convex-wasm-toolchain-package.mjs";
import { verifyHermesSource } from "./lib/convex-wasm-hermes-source.mjs";
import { describeNativeCommandTermination, runBoundedNativeCommand } from "./lib/bounded-native-command.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function downloadPinnedArchive(url, sha256, destination, signal) {
  const handle = await fs.open(destination, "wx", 0o600);
  await handle.close();
  await promisify(execFile)("curl", ["--fail", "--location", "--silent", "--show-error",
    "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "30", "--retry", "3",
    "--max-time", "600", "--max-filesize", "1073741824",
    "--output", destination, url], {
    signal: signal === undefined ? AbortSignal.timeout(10 * 60_000)
      : AbortSignal.any([signal, AbortSignal.timeout(10 * 60_000)]),
  });
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(destination)) hash.update(bytes);
  if (hash.digest("hex") !== sha256) throw new Error("GNU time archive differs from its pinned SHA-256");
}

export async function buildToolchainRelease({ gateRoot, compilerPackage, precompilerPackage, output, cxx, jobs = 2, signal }) {
  const run = async (command, args, options = {}) => {
    const result = await runBoundedNativeCommand({ command, arguments: args,
      cwd: options.cwd ?? repositoryRoot, environment: options.env ?? process.env,
      maxOutputBytes: 32 * 1024 * 1024, timeoutMs: 60 * 60_000, operation: basename(command), signal });
    if (result.termination !== undefined) throw new Error(`${basename(command)} ${describeNativeCommandTermination(result.termination)}`);
    if (result.code !== 0) throw new Error(`${basename(command)} failed (${result.code ?? result.signal}): ${result.stderr.toString("utf8")}`);
    return result.stdout.toString("utf8");
  };
  const [compiler, precompiler] = await Promise.all([
    loadAndVerifyCompilerPackage(compilerPackage), loadAndVerifyPrecompilerPackage(precompilerPackage),
  ]);
  if (compiler.manifest.platform.targetTriple !== precompiler.manifest.platform.targetTriple) {
    throw new Error("Toolchain native packages target different hosts");
  }
  // Source/build checks run before sealing the release, never in consumer builds.
  await setupGate({ gateRoot, jobs, checkOnly: true });
  const hermesProvenance = await verifyHermesSource(join(gateRoot, "hermes"));
  await fs.mkdir(output, { mode: 0o700 });
  const stage = await fs.mkdtemp(join(output, ".build-"));
  const root = join(stage, "convex-wasm-compiler");
  await fs.mkdir(root, { mode: 0o700 });
  const copy = async (source, destination) => {
    await fs.mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await fs.cp(source, destination, { recursive: true, dereference: true,
      filter: path => !["__pycache__", ".git"].includes(basename(path)) });
  };
  try {
    for (const path of [
      "build-host/bin/shermes", "build-host/bin/hermesc",
      "build-wasm/lib/libhermesvm_a.a", "build-wasm/jsi/libjsi.a",
      "build-wasm/external/icu-small/libhermesStaticIcu.a",
      "build-wasm/lib/libconvex_wasm_allocator.a", "build-wasm/lib/config",
      "hermes/include", "hermes/API", "hermes/public", "hermes/LICENSE",
      "emsdk/upstream", "binaryen-tools", "bin/convex-wasm-wasmtime-runner",
    ]) await copy(join(gateRoot, path), join(root, "gate", path));
    await copy(join(gateRoot, "binaryen/LICENSE"), join(root, "licenses/binaryen.txt"));
    const hermesExternal = join(gateRoot, "hermes/external");
    for (const entry of await fs.readdir(hermesExternal, { recursive: true, withFileTypes: true })) {
      if (entry.isFile() && /^(?:LICENSE|COPYING|UNLICENSE)(?:[._-].*)?$/iu.test(entry.name)) {
        const source = join(entry.parentPath, entry.name);
        await copy(source, join(root, "licenses/hermes", relative(hermesExternal, source)));
      }
    }
    // $CFGDIR is expanded by Emscripten. No build-machine paths survive in the SDK config.
    await fs.writeFile(join(root, "gate/emsdk/.emscripten"), [
      "LLVM_ROOT = '$CFGDIR/upstream/bin'",
      "BINARYEN_ROOT = '$CFGDIR/../binaryen-tools'",
      "EMSCRIPTEN_ROOT = '$CFGDIR/upstream/emscripten'",
      "NODE_JS = 'node'",
      "",
    ].join("\n"));
    // Avoid Python bytecode writes inside the authenticated installation, including
    // when emcc clears ambient Python environment variables with its -E option.
    const pythonWrapper = join(root, "runtime/bin/convex-python");
    await fs.mkdir(dirname(pythonWrapper), { recursive: true });
    await fs.writeFile(pythonWrapper, '#!/bin/sh\nexec python3 -B -E "$@"\n', { mode: 0o755 });
    const emscriptenConfig = join(root, "gate/emsdk/upstream/emscripten/tools/config.py");
    const originalConfig = await fs.readFile(emscriptenConfig, "utf8");
    const interpreterReset = "os.environ['EMSDK_PYTHON'] = sys.executable";
    if (originalConfig.split(interpreterReset).length !== 2) {
      throw new Error("Pinned Emscripten Python selection changed; review the bundled wrapper adaptation");
    }
    // Emscripten normally replaces EMSDK_PYTHON with sys.executable. That loses
    // the wrapper's -B for recursive emcc calls and writes bytecode into the
    // installation. Preserve the explicit interpreter, resolving relative paths
    // for subprocesses just as upstream intends. These adapted bytes are sealed.
    const packagedConfig = originalConfig.replace(interpreterReset,
      "os.environ['EMSDK_PYTHON'] = os.path.abspath(os.environ['EMSDK_PYTHON'])");
    await fs.writeFile(emscriptenConfig, packagedConfig);

    const timeArchive = join(stage, "time.tar.gz");
    const timeSha256 = "fbacf0c81e62429df3e33bda4cee38756604f18e01d977338e23306a3e3b521e";
    await downloadPinnedArchive("https://ftp.gnu.org/gnu/time/time-1.9.tar.gz", timeSha256, timeArchive, signal);
    await run("tar", ["-xzf", timeArchive, "-C", stage]);
    const timeSource = join(stage, "time-1.9");
    await run("./configure", ["--disable-nls", "CFLAGS=-O2 -std=gnu17"], { cwd: timeSource });
    await run("make", ["-j", String(jobs)], { cwd: timeSource });
    await copy(join(timeSource, "time"), join(root, "runtime/bin/time"));
    await copy(join(timeSource, "COPYING"), join(root, "licenses/gnu-time.txt"));
    await copy(timeArchive, join(root, "licenses/time-1.9-source.tar.gz"));
    await fs.writeFile(join(root, "runtime/provenance.json"), `${JSON.stringify({
      hermes: hermesProvenance,
      time: { version: "1.9", sha256: timeSha256 },
      emscriptenPythonWrapper: { sourceSha256: createHash("sha256").update(originalConfig).digest("hex"),
        packagedSha256: createHash("sha256").update(packagedConfig).digest("hex") } })}\n`);

    const metadata = JSON.parse(await fs.readFile(join(repositoryRoot, "package.json"), "utf8"));
    const packed = JSON.parse(await run("npm", ["pack", "--json", "--pack-destination", stage]));
    const library = join(root, "lib/compiler");
    await fs.mkdir(library, { recursive: true, mode: 0o700 });
    await run("tar", ["-xzf", join(stage, packed[0].filename), "-C", library, "--strip-components=1"]);
    const dependencies = join(stage, "dependencies");
    await fs.mkdir(dependencies);
    for (const name of ["package.json", "package-lock.json"]) await copy(join(repositoryRoot, name), join(dependencies, name));
    await run("npm", ["ci", "--include=dev", "--no-audit", "--no-fund"], { cwd: dependencies });
    await copy(join(dependencies, "node_modules"), join(library, "node_modules"));
    const nativePackages = {};
    for (const [name, loaded] of [["compiler", compiler], ["precompiler", precompiler]]) {
      nativePackages[name] = `native/${name}/${loaded.manifest.packageId}`;
      await copy(loaded.packageDirectory, join(root, nativePackages[name]));
    }
    await fs.mkdir(join(root, "evidence"));
    const common = ["--emcc", join(gateRoot, "emsdk/upstream/emscripten/emcc"),
      "--hermes-source", join(gateRoot, "hermes"), "--runner", join(gateRoot, "bin/convex-wasm-wasmtime-runner"),
      "--shermes", join(gateRoot, "build-host/bin/shermes"), "--wasm-build", join(gateRoot, "build-wasm")];
    const env = { ...process.env, EM_CONFIG: await fs.realpath(join(gateRoot, "emsdk/.emscripten")),
      EMSDK: await fs.realpath(join(gateRoot, "emsdk")), EM_BINARYEN_ROOT: join(gateRoot, "binaryen-tools") };
    await run(process.execPath, ["scripts/run-convex-wasm-committed-value-codec-matrix.mjs", ...common,
      "--cxx", cxx, "--host-build", join(gateRoot, "build-host"), "--output", join(root, "evidence/codec.json")], { env });
    await run(process.execPath, ["scripts/run-convex-wasm-request-envelope-matrix.mjs", ...common,
      "--output", join(root, "evidence/request.json")], { env });
    await fs.writeFile(join(root, "convex-wasm"), ["#!/bin/sh", "set -eu",
      'root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)',
      'node -e \'if (Number(process.versions.node.split(".")[0]) < 24) { console.error("Node.js 24 or later is required"); process.exit(1); }\'',
      'python3 -B -E -c \'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10 or later is required")\'',
      'exec node "$root/lib/compiler/scripts/toolchain.mjs" "$@"', ""].join("\n"), { mode: 0o755 });
    await fs.copyFile(join(repositoryRoot, "docs/toolchain-releases.md"), join(root, "README.md"));
    const manifest = await sealToolchainPackage(root, { version: metadata.version, nativePackages });
    const archiveName = `convex-wasm-toolchain-${metadata.version}-${process.platform}-${process.arch}.tar.gz`;
    const archive = join(output, archiveName);
    await run("tar", ["-czf", archive, "-C", stage, "convex-wasm-compiler"]);
    const hash = createHash("sha256");
    for await (const bytes of createReadStream(archive)) hash.update(bytes);
    await fs.writeFile(`${archive}.sha256`, `${hash.digest("hex")}  ${archiveName}\n`, { flag: "wx" });
    return { archive, packageId: manifest.packageId };
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  const args = new Map();
  for (let i = 2; i < process.argv.length; i += 2) {
    const [key, value] = process.argv.slice(i, i + 2);
    if (!["--gate-root", "--compiler-package", "--precompiler-package", "--output", "--cxx", "--jobs"].includes(key) ||
        value === undefined || value === "" || args.has(key)) throw new Error("Invalid toolchain release arguments");
    args.set(key, value);
  }
  for (const key of ["--gate-root", "--compiler-package", "--precompiler-package", "--output", "--cxx"]) {
    if (!args.has(key)) throw new Error(`Toolchain release requires ${key}`);
  }
  const jobs = Number(args.get("--jobs") ?? "2");
  if (!Number.isSafeInteger(jobs) || jobs < 1) throw new Error("--jobs must be a positive integer");
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    const result = await buildToolchainRelease({ gateRoot: resolve(args.get("--gate-root")),
      compilerPackage: resolve(args.get("--compiler-package")), precompilerPackage: resolve(args.get("--precompiler-package")),
      output: resolve(args.get("--output")), cxx: resolve(args.get("--cxx")), jobs, signal: cancellation.signal });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}
