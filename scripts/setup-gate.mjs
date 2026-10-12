#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { emscriptenVersion, gateRevisions } from "./lib/convex-wasm-gate-pins.mjs";
import { staticHermesHostArchives } from "./lib/convex-wasm-static-hermes-host-archives.mjs";
import binaryenSource from "./vendor/binaryen/source.json" with { type: "json" };

const sources = Object.freeze({
  binaryen: {
    revision: binaryenSource.revision,
    url: "https://github.com/WebAssembly/binaryen.git",
  },
  emsdk: {
    revision: gateRevisions.emsdk,
    url: "https://github.com/emscripten-core/emsdk.git",
  },
  hermes: {
    revision: gateRevisions.hermes,
    url: "https://github.com/convex-in-prod/hermes.git",
  },
});

const gitTimeoutMs = 30 * 60 * 1000;
const buildTimeoutMs = 2 * 60 * 60 * 1000;
const runnerName = "convex-wasm-wasmtime-runner";
// Promise, microtask, and generator helpers are on the hot path for the
// official SDK runtime. Compile Hermes' internal unit into the Wasm runtime so
// those helpers do not fall back to the bytecode interpreter.
const staticHermesRuntimeCmakeFlags = [
  "-DHERMESVM_INTERNAL_JAVASCRIPT_NATIVE=ON",
  "-DHERMES_ENABLE_INTL=ON",
  "-DHERMES_USE_STATIC_INTL_PROVIDER=ON",
  "-DHERMES_ICU_FAIL_STOP_ALLOCATION=ON",
];
const staticHermesWasmExceptionFlags = "-fwasm-exceptions -sWASM_LEGACY_EXCEPTIONS=0";
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const runnerCrate = join(scriptDirectory, "convex-wasm-precompiler");
const binaryenVendor = join(scriptDirectory, "vendor", "binaryen");
const binaryenCmakeFlags = [
  "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTS=OFF", "-DBUILD_SHARED_LIBS=OFF",
  "-DBUILD_LLVM_DWARF=ON", "-DBYN_ENABLE_ASSERTIONS=ON",
];
// Only wasm-opt is replaced. Other Emscripten tools retain their SDK binaries.
export const binaryenHelperNames = Object.freeze([
  "wasm-as", "wasm-ctor-eval", "wasm-dis", "wasm-emscripten-finalize",
  "wasm-metadce", "wasm-split", "wasm2js",
]);

function parseArguments(argumentsList) {
  const values = new Map();
  let checkOnly = false;
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    if (option === "--check-only" && !checkOnly) {
      checkOnly = true;
      continue;
    }
    const value = argumentsList[index + 1];
    if (
      !["--gate-root", "--jobs"].includes(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error("usage: convex-wasm-setup-gate --gate-root PATH [--jobs N] [--check-only]");
    }
    values.set(option, value);
    index += 1;
  }
  if (!values.has("--gate-root")) {
    throw new Error("setup gate requires --gate-root PATH");
  }
  const jobs = values.has("--jobs") ? Number(values.get("--jobs")) : 1;
  if (!Number.isSafeInteger(jobs) || jobs < 1) {
    throw new Error("--jobs must be a positive integer");
  }
  return { gateRoot: resolve(values.get("--gate-root")), jobs, checkOnly };
}

async function run(command, argumentsList, { cwd, env, timeoutMs, capture = false }) {
  const child = spawn(command, argumentsList, {
    cwd,
    env,
    detached: true,
    stdio: ["inherit", capture ? "pipe" : "inherit", "inherit"],
  });
  const stop = () => {
    if (child.pid === undefined) return;
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  };
  let stdout = "";
  if (capture) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > 1024 * 1024) {
        stop();
      }
    });
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    stop();
  }, timeoutMs);
  let interrupted = false;
  const interrupt = () => {
    interrupted = true;
    stop();
  };
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    const code = await new Promise((settle, reject) => {
      child.once("error", reject);
      child.once("close", settle);
    });
    if (timedOut) throw new Error(`${command} exceeded its phase timeout`);
    if (interrupted) throw new Error(`${command} was interrupted`);
    if (stdout.length > 1024 * 1024) throw new Error(`${command} produced too much captured output`);
    if (code !== 0) throw new Error(`${command} exited with status ${code}`);
    return stdout.trim();
  } finally {
    clearTimeout(timer);
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}

async function checkout(root, name) {
  const { revision, url } = sources[name];
  const destination = join(root, name);
  let exists = true;
  try {
    await fs.lstat(destination);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    exists = false;
  }
  if (!exists) {
    const temporary = await fs.mkdtemp(join(root, `.download-${name}-`));
    try {
      await run("git", ["clone", "--filter=blob:none", "--no-checkout", url, temporary], {
        cwd: root,
        timeoutMs: gitTimeoutMs,
      });
      await run("git", ["-C", temporary, "checkout", "--detach", revision], {
        cwd: root,
        timeoutMs: gitTimeoutMs,
      });
      await fs.rename(temporary, destination);
    } finally {
      await fs.rm(temporary, { recursive: true, force: true });
    }
  }
  const actual = await run("git", ["-C", destination, "rev-parse", "HEAD"], {
    cwd: root,
    timeoutMs: 30_000,
    capture: true,
  });
  if (actual !== revision) {
    throw new Error(`${name} checkout must be at pinned revision ${revision}`);
  }
}

async function requireFile(path, label, executable = false) {
  const state = await fs.stat(path);
  if (!state.isFile() || state.size === 0 || (executable && (state.mode & 0o111) === 0)) {
    throw new Error(`${label} is missing or invalid: ${path}`);
  }
}

async function cmakeCacheHas(path, key, expected) {
  const cache = await fs.readFile(path, "utf8");
  return new RegExp(`^${key}:[^=]+=.*${expected}$`, "mu").test(cache);
}

async function cmakeCacheValue(path, key) {
  const cache = await fs.readFile(path, "utf8");
  return cache.match(new RegExp(`^${key}:[^=]+=(.*)$`, "mu"))?.[1] ?? null;
}

async function fileIdentity(path) {
  const hash = createHash("sha256");
  let size = 0;
  for await (const bytes of createReadStream(path)) {
    hash.update(bytes);
    size += bytes.length;
  }
  return { sha256: hash.digest("hex"), size };
}

export async function runnerInputSha256(crateDirectory = runnerCrate) {
  const hash = createHash("sha256");
  // The runner shares WASI code and uses a local Cranelift dependency. Cargo.lock
  // does not hash path dependencies, so their source must also invalidate the gate.
  const vendorRoot = join(crateDirectory, "src", "vendor");
  const vendorSources = [];
  for (const entry of await fs.readdir(vendorRoot, { recursive: true, withFileTypes: true })) {
    if (entry.isDirectory()) continue;
    if (!entry.isFile()) throw new Error("Wasmtime runner vendor source must be a regular file");
    const path = join(entry.parentPath, entry.name);
    vendorSources.push(path.slice(vendorRoot.length + 1));
  }
  vendorSources.sort();
  for (const [name, path] of [
    ["Cargo.lock", join(crateDirectory, "Cargo.lock")],
    ["Cargo.toml", join(crateDirectory, "Cargo.toml")],
    ["rust-toolchain.toml", join(crateDirectory, "rust-toolchain.toml")],
    ["runner.rs", join(crateDirectory, "src", "bin", `${runnerName}.rs`)],
    ["lib.rs", join(crateDirectory, "src", "lib.rs")],
    ["wasmtime_wasi.rs", join(crateDirectory, "src", "wasmtime_wasi.rs")],
    ...vendorSources.map((name) => [`vendor/${name}`, join(vendorRoot, name)]),
  ]) {
    const bytes = await fs.readFile(path);
    if (name === "Cargo.lock") {
      const expected = `git+https://github.com/bytecodealliance/wasmtime?rev=${gateRevisions.wasmtime}#${gateRevisions.wasmtime}`;
      const lock = bytes.toString("utf8");
      const wasmtimePackages = lock.split("[[package]]").filter((section) =>
        /^name = "wasmtime"$/mu.test(section)
      );
      const packageSource = wasmtimePackages[0]?.match(/^source = "([^"]+)"$/mu)?.[1];
      const sources = [...lock.matchAll(
        /^source = "(git\+https:\/\/github\.com\/bytecodealliance\/wasmtime\?rev=[^"]+)"$/gmu
      )].map((match) => match[1]);
      // Cargo --locked binds the manifest to this lockfile; every Wasmtime package must use the gate pin.
      if (
        wasmtimePackages.length !== 1 ||
        packageSource !== expected ||
        sources.some((source) => source !== expected)
      ) {
        throw new Error("Wasmtime runner lockfile differs from the pinned gate revision");
      }
    }
    hash.update(`${name.length}:${name}${bytes.length}:`);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

async function runnerStatus(gateRoot) {
  const bin = join(gateRoot, "bin", runnerName);
  let manifestBytes;
  try {
    manifestBytes = await fs.readFile(`${bin}.json`, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return "missing";
    throw error;
  }
  const manifest = JSON.parse(manifestBytes);
  if (
    JSON.stringify(Object.keys(manifest).sort()) !==
      JSON.stringify(["binarySha256", "binarySize", "inputSha256", "kind"].sort()) ||
    manifest.kind !== "convex-wasm-wasmtime-runner-v1"
  ) {
    throw new Error("Wasmtime runner manifest is invalid");
  }
  if (manifest.inputSha256 !== (await runnerInputSha256())) return "stale";
  try {
    await requireFile(bin, "Wasmtime runner", true);
  } catch (error) {
    if (error?.code === "ENOENT") return "missing";
    throw error;
  }
  const identity = await fileIdentity(bin);
  if (identity.sha256 !== manifest.binarySha256 || identity.size !== manifest.binarySize) {
    // The binary and manifest are published separately; an interrupted update can leave a pair to rebuild.
    return "stale";
  }
  return "verified";
}

async function buildRunner(gateRoot, jobs) {
  const inputSha256 = await runnerInputSha256();
  const target = join(gateRoot, "runner-build");
  await run("cargo", [
    "build", "--locked", "--release", "--bin", runnerName,
    "--target-dir", target, "--jobs", String(jobs),
  ], { cwd: runnerCrate, timeoutMs: buildTimeoutMs });
  const built = join(target, "release", runnerName);
  await requireFile(built, "built Wasmtime runner", true);
  const binDirectory = join(gateRoot, "bin");
  await fs.mkdir(binDirectory, { recursive: true });
  const stage = await fs.mkdtemp(join(gateRoot, ".runner-publication-"));
  try {
    const stagedBinary = join(stage, runnerName);
    const stagedManifest = `${stagedBinary}.json`;
    await fs.copyFile(built, stagedBinary);
    await fs.chmod(stagedBinary, 0o755);
    const identity = await fileIdentity(stagedBinary);
    await fs.writeFile(stagedManifest, `${JSON.stringify({
      binarySha256: identity.sha256,
      binarySize: identity.size,
      inputSha256,
      kind: "convex-wasm-wasmtime-runner-v1",
    })}\n`);
    await fs.rename(stagedBinary, join(binDirectory, runnerName));
    await fs.rename(stagedManifest, join(binDirectory, `${runnerName}.json`));
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}

async function buildTargetsPending(buildRoot, targets) {
  const output = await run("ninja", ["-C", buildRoot, "-n", ...targets], {
    cwd: buildRoot,
    timeoutMs: 30_000,
    capture: true,
  });
  return !output.endsWith("ninja: no work to do.");
}

export async function binaryenInputSha256(vendor = binaryenVendor) {
  const sourceBytes = await fs.readFile(join(vendor, "source.json"));
  const source = JSON.parse(sourceBytes);
  if (!/^[0-9a-f]{40}$/u.test(source.revision) || !/^[0-9a-f]{40}$/u.test(source.patchedTree) ||
      !Array.isArray(source.patches) || source.patches.length === 0) {
    throw new Error("Binaryen source recipe is invalid");
  }
  const hash = createHash("sha256").update(sourceBytes).update(JSON.stringify(binaryenCmakeFlags));
  const seen = new Set();
  for (const patch of source.patches) {
    if (!/^[a-z0-9-]+\.patch$/u.test(patch.file) || seen.has(patch.file) ||
        !/^[0-9a-f]{64}$/u.test(patch.sha256)) {
      throw new Error("Binaryen patch recipe is invalid");
    }
    seen.add(patch.file);
    const bytes = await fs.readFile(join(vendor, patch.file));
    if (createHash("sha256").update(bytes).digest("hex") !== patch.sha256) {
      throw new Error(`Binaryen patch differs from its pinned digest: ${patch.file}`);
    }
    hash.update(bytes);
  }
  return hash.digest("hex");
}

export async function verifyBinaryenSource(sourceRoot, expected = binaryenSource) {
  const options = { cwd: sourceRoot, timeoutMs: 30_000, capture: true };
  const revision = await run("git", ["rev-parse", "HEAD"], options);
  const tree = await run("git", ["write-tree"], options);
  if (revision !== expected.revision || tree !== expected.patchedTree) {
    throw new Error("Binaryen checkout differs from the pinned patched source");
  }
  // The staged patch tree is intentional; additional staged, unstaged, ignored,
  // or untracked files must not silently enter a native tool build.
  await run("git", ["diff-files", "--quiet", "--ignore-submodules=none"], options);
  if (await run("git", ["ls-files", "--others"], options)) {
    throw new Error("Binaryen checkout has untracked source files");
  }
}

export async function binaryenStatus(gateRoot, inputSha256) {
  const root = join(gateRoot, "binaryen-tools");
  let receipt;
  try {
    receipt = JSON.parse(await fs.readFile(join(root, "toolchain.json"), "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return "missing";
    throw error;
  }
  const names = ["wasm-opt", ...binaryenHelperNames].sort();
  if (receipt.kind !== "convex-wasm-binaryen-toolchain-v1" ||
      !receipt.binaries || JSON.stringify(Object.keys(receipt.binaries).sort()) !== JSON.stringify(names)) {
    throw new Error("Binaryen toolchain receipt is invalid");
  }
  if (receipt.inputSha256 !== inputSha256 || receipt.platform !== process.platform ||
      receipt.arch !== process.arch) return "stale";
  for (const name of names) {
    try {
      const path = join(root, "bin", name);
      await requireFile(path, `Binaryen ${name}`, true);
      const actual = await fileIdentity(path);
      const recorded = receipt.binaries[name];
      if (actual.sha256 !== recorded.sha256 || actual.size !== recorded.size) return "stale";
      const original = name === "wasm-opt"
        ? join(gateRoot, "build-binaryen", "bin", name)
        : join(gateRoot, "emsdk", "upstream", "bin", name);
      const current = await fileIdentity(original);
      if (current.sha256 !== actual.sha256 || current.size !== actual.size) return "stale";
    } catch (error) {
      if (error?.code === "ENOENT") return "missing";
      throw error;
    }
  }
  return "verified";
}

export async function verifyBinaryenGate(gateRoot) {
  const inputSha256 = await binaryenInputSha256();
  await verifyBinaryenSource(join(gateRoot, "binaryen"));
  const status = await binaryenStatus(gateRoot, inputSha256);
  if (status !== "verified" || await buildTargetsPending(join(gateRoot, "build-binaryen"), ["wasm-opt"])) {
    throw new Error("Binaryen tools are missing or stale; rerun convex-wasm-setup-gate without --check-only");
  }
  const cache = join(gateRoot, "build-binaryen", "CMakeCache.txt");
  const configuredSource = await cmakeCacheValue(cache, "CMAKE_HOME_DIRECTORY");
  if (configuredSource === null ||
      await fs.realpath(configuredSource) !== await fs.realpath(join(gateRoot, "binaryen"))) {
    throw new Error("Binaryen build does not use the authenticated source checkout");
  }
  for (const flag of binaryenCmakeFlags) {
    const [key, value] = flag.slice(2).split("=");
    if (await cmakeCacheValue(cache, key) !== value) {
      throw new Error(`Binaryen build does not use the pinned ${key} setting`);
    }
  }
}

export async function buildBinaryen(gateRoot, jobs) {
  const inputSha256 = await binaryenInputSha256();
  const sourceRoot = join(gateRoot, "binaryen");
  const options = { cwd: sourceRoot, timeoutMs: 30_000, capture: true };
  const tree = await run("git", ["write-tree"], options);
  const originalTree = await run("git", ["rev-parse", "HEAD^{tree}"], options);
  if (tree === originalTree) {
    await run("git", ["apply", "--index", ...binaryenSource.patches.map(({ file }) => join(binaryenVendor, file))], options);
  }
  await verifyBinaryenSource(sourceRoot);
  const build = join(gateRoot, "build-binaryen");
  if (await binaryenStatus(gateRoot, inputSha256) !== "verified") {
    // Ninja tracks dependency timestamps, not the published tool's digest.
    // Relink a stale output from retained objects instead of signing it again.
    await fs.rm(join(build, "bin", "wasm-opt"), { force: true });
  }
  await run("cmake", ["-S", sourceRoot, "-B", build, "-G", "Ninja", ...binaryenCmakeFlags], {
    cwd: gateRoot, timeoutMs: 10 * 60 * 1000,
  });
  await run("cmake", ["--build", build, "--target", "wasm-opt", "--parallel", String(jobs)], {
    cwd: gateRoot, timeoutMs: buildTimeoutMs,
  });
  if (await binaryenStatus(gateRoot, inputSha256) === "verified") return;
  const destination = join(gateRoot, "binaryen-tools");
  await fs.mkdir(join(destination, "bin"), { recursive: true });
  const stage = await fs.mkdtemp(join(gateRoot, ".binaryen-publication-"));
  try {
    const binaries = {};
    for (const name of ["wasm-opt", ...binaryenHelperNames]) {
      const staged = join(stage, name);
      if (name === "wasm-opt") {
        await fs.copyFile(join(build, "bin", name), staged);
        await fs.chmod(staged, 0o755);
      } else {
        await fs.symlink(await fs.realpath(join(gateRoot, "emsdk", "upstream", "bin", name)), staged);
      }
      await requireFile(staged, `Binaryen ${name}`, true);
      binaries[name] = await fileIdentity(staged);
    }
    await fs.writeFile(join(stage, "toolchain.json"), `${JSON.stringify({
      kind: "convex-wasm-binaryen-toolchain-v1", inputSha256,
      platform: process.platform, arch: process.arch, binaries,
    })}\n`);
    for (const name of Object.keys(binaries)) {
      await fs.rename(join(stage, name), join(destination, "bin", name));
    }
    // Publishing the receipt last makes an interrupted replacement detectable.
    await fs.rename(join(stage, "toolchain.json"), join(destination, "toolchain.json"));
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}

async function checkGate(root) {
  for (const name of Object.keys(sources)) {
    const actual = await run("git", ["-C", join(root, name), "rev-parse", "HEAD"], {
      cwd: root,
      timeoutMs: 30_000,
      capture: true,
    });
    if (actual !== sources[name].revision) {
      throw new Error(`${name} checkout must be at pinned revision ${sources[name].revision}`);
    }
  }
  await verifyBinaryenGate(root);
  await Promise.all([
    requireFile(join(root, "emsdk", ".emscripten"), "Emscripten configuration"),
    requireFile(join(root, "emsdk", "upstream", "emscripten", "emcc"), "Emscripten compiler", true),
    requireFile(join(root, "build-host", "bin", "shermes"), "Static Hermes compiler", true),
    requireFile(join(root, "build-wasm", "lib", "libhermesvm_a.a"), "Wasm Hermes archive"),
    requireFile(join(root, "build-wasm", "jsi", "libjsi.a"), "Wasm JSI archive"),
    requireFile(join(root, "build-wasm", "external", "icu-small", "libhermesStaticIcu.a"), "Wasm ICU code and data archive"),
    requireFile(join(root, "build-wasm", "lib", "config", "libhermesvm-config.h"), "Wasm Hermes configuration"),
  ]);
  await Promise.all((await staticHermesHostArchives(join(root, "build-host"))).map((path) =>
    requireFile(path, "Static Hermes host archive")
  ));
  for (const key of ["HERMES_ENABLE_INTL", "HERMES_USE_STATIC_INTL_PROVIDER", "HERMES_ICU_FAIL_STOP_ALLOCATION"]) {
    if (!(await cmakeCacheHas(join(root, "build-wasm", "CMakeCache.txt"), key, "ON"))) {
      throw new Error(`Wasm Hermes archive requires ${key}=ON`);
    }
  }
  if (
    !(await cmakeCacheHas(
      join(root, "build-wasm", "CMakeCache.txt"),
      "HERMESVM_INTERNAL_JAVASCRIPT_NATIVE",
      "ON",
    ))
  ) {
    throw new Error("Wasm Hermes archive was built without native InternalJavaScript support");
  }
  const hostCompilerImport = join(root, "build-host", "ImportHostCompilers.cmake");
  if (
    (await cmakeCacheValue(join(root, "build-wasm", "CMakeCache.txt"), "IMPORT_HOST_COMPILERS")) !==
    hostCompilerImport
  ) {
    throw new Error("Wasm Hermes archive was built without imported host compilers");
  }
  for (const key of ["CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS"]) {
    if ((await cmakeCacheValue(join(root, "build-wasm", "CMakeCache.txt"), key)) !== staticHermesWasmExceptionFlags) {
      throw new Error("Wasm Hermes archive was built with legacy exception lowering");
    }
  }
  if (
    !(await cmakeCacheHas(
      join(root, "build-wasm", "CMakeCache.txt"),
      "HERMES_UNICODE_LITE",
      "ON",
    ))
  ) {
    throw new Error("Wasm Hermes archive was built with host Unicode imports");
  }
  const emsdk = await fs.realpath(join(root, "emsdk"));
  const version = await run(join(emsdk, "upstream", "emscripten", "emcc"), ["--version"], {
    cwd: root,
    env: {
      ...process.env,
      EM_CONFIG: join(emsdk, ".emscripten"),
      EMSDK: emsdk,
    },
    timeoutMs: 30_000,
    capture: true,
  });
  if (!version.includes(emscriptenVersion)) {
    throw new Error(`Emscripten compiler must be version ${emscriptenVersion}`);
  }
  const runner = await runnerStatus(root);
  if (runner !== "verified") {
    throw new Error(`Wasmtime runner is ${runner}; rerun convex-wasm-setup-gate without --check-only`);
  }
  for (const [name, buildRoot, targets] of [
    [
      "host",
      join(root, "build-host"),
      ["shermes", "hermesc", "hermesvm_a", "hermesVMRuntime", "hermesapi", "hermesPublic", "boost_context", "jsi"],
    ],
    ["wasm", join(root, "build-wasm"), ["hermesvm_a", "jsi", "hermesStaticIcu"]],
  ]) {
    if (await buildTargetsPending(buildRoot, targets)) {
      throw new Error(
        `Static Hermes ${name} build is stale; rerun convex-wasm-setup-gate without --check-only`
      );
    }
  }
}

export async function setupGate({ gateRoot, jobs, checkOnly }) {
  if (checkOnly) {
    await checkGate(gateRoot);
    return gateRoot;
  }
  await fs.mkdir(gateRoot, { recursive: true });
  for (const name of Object.keys(sources)) await checkout(gateRoot, name);

  // Emscripten includes its configured LLVM path in the sysroot cache identity.
  // A gate symlink must not make setup and application compilation clear it in turn.
  const emsdk = await fs.realpath(join(gateRoot, "emsdk"));
  const emcc = join(emsdk, "upstream", "emscripten", "emcc");
  let installEmscripten = false;
  try {
    await Promise.all([
      requireFile(emcc, "Emscripten compiler", true),
      requireFile(join(emsdk, ".emscripten"), "Emscripten configuration"),
    ]);
    const version = await run(emcc, ["--version"], {
      cwd: emsdk,
      env: { ...process.env, EM_CONFIG: join(emsdk, ".emscripten"), EMSDK: emsdk },
      timeoutMs: 30_000,
      capture: true,
    });
    installEmscripten = !version.includes(emscriptenVersion);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    installEmscripten = true;
  }
  if (installEmscripten) {
    await run(join(emsdk, "emsdk"), ["install", emscriptenVersion], {
      cwd: emsdk,
      timeoutMs: buildTimeoutMs,
    });
    await run(join(emsdk, "emsdk"), ["activate", emscriptenVersion], {
      cwd: emsdk,
      timeoutMs: 10 * 60 * 1000,
    });
  }

  await buildBinaryen(gateRoot, jobs);

  const hermes = join(gateRoot, "hermes");
  const host = join(gateRoot, "build-host");
  const wasm = join(gateRoot, "build-wasm");
  const hostCompiler = join(host, "bin", "shermes");
  const hostBytecodeCompiler = join(host, "bin", "hermesc");
  const hostCompilerImport = join(host, "ImportHostCompilers.cmake");
  try {
    await Promise.all([
      requireFile(hostCompiler, "Static Hermes compiler", true),
      requireFile(hostBytecodeCompiler, "Hermes bytecode compiler", true),
      requireFile(hostCompilerImport, "Hermes host compiler import", false),
    ]);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await run("cmake", ["-S", hermes, "-B", host, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release", "-DHERMES_ENABLE_INTL=OFF", "-DHERMES_ENABLE_TEST_SUITE=OFF", "-DHERMES_ENABLE_NAPI=OFF"], {
      cwd: gateRoot,
      timeoutMs: 10 * 60 * 1000,
    });
  }
  await run("cmake", [
    "--build", host, "--target", "shermes", "hermesc", "hermesvm_a",
    "hermesVMRuntime", "hermesapi", "hermesPublic", "boost_context", "jsi",
    "--parallel", String(jobs),
  ], { cwd: gateRoot, timeoutMs: buildTimeoutMs });

  const wasmBuildOutputs = [
    join(wasm, "lib", "libhermesvm_a.a"),
    join(wasm, "jsi", "libjsi.a"),
    join(wasm, "external", "icu-small", "libhermesStaticIcu.a"),
    join(wasm, "lib", "config", "libhermesvm-config.h"),
  ];
  const wasmBuildOutputStates = await Promise.all(
    wasmBuildOutputs.map((path) =>
      fs.stat(path).catch((error) => {
        if (error?.code === "ENOENT") return null;
        throw error;
      })
    )
  );
  const wasmBuildEnv = {
    ...process.env,
    EM_BINARYEN_ROOT: join(gateRoot, "binaryen-tools"),
    EM_CONFIG: join(emsdk, ".emscripten"),
    EMSDK: emsdk,
    PATH: [
      join(emsdk, "upstream", "emscripten"),
      join(emsdk, "upstream", "bin"),
      process.env.PATH,
    ].join(":"),
  };
  const wasmNativeIntlReady = (await Promise.all(
    ["HERMES_ENABLE_INTL", "HERMES_USE_STATIC_INTL_PROVIDER", "HERMES_ICU_FAIL_STOP_ALLOCATION"].map(key =>
      cmakeCacheHas(join(wasm, "CMakeCache.txt"), key, "ON").catch(error => {
        if (error?.code === "ENOENT") return false;
        throw error;
      }))
  )).every(Boolean);
  const wasmNeedsConfiguration = !wasmNativeIntlReady || wasmBuildOutputStates.some((state) => state === null) ||
    !(await cmakeCacheHas(
      join(wasm, "CMakeCache.txt"),
      "HERMESVM_INTERNAL_JAVASCRIPT_NATIVE",
      "ON",
    ).catch((error) => {
      if (error?.code === "ENOENT") return false;
      throw error;
    })) ||
    !(await cmakeCacheHas(
      join(wasm, "CMakeCache.txt"),
      "HERMES_UNICODE_LITE",
      "ON",
    ).catch((error) => {
      if (error?.code === "ENOENT") return false;
      throw error;
    })) ||
    (await cmakeCacheValue(join(wasm, "CMakeCache.txt"), "IMPORT_HOST_COMPILERS").catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    })) !== hostCompilerImport ||
    (await cmakeCacheValue(join(wasm, "CMakeCache.txt"), "CMAKE_C_FLAGS").catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    })) !== staticHermesWasmExceptionFlags ||
    (await cmakeCacheValue(join(wasm, "CMakeCache.txt"), "CMAKE_CXX_FLAGS").catch((error) => {
      if (error?.code === "ENOENT") return null;
      throw error;
    })) !== staticHermesWasmExceptionFlags;
  if (wasmNeedsConfiguration) {
    await run(join(emsdk, "upstream", "emscripten", "emcmake"), [
      "cmake", "-S", hermes, "-B", wasm, "-G", "Ninja",
      "-DCMAKE_BUILD_TYPE=Release",
      "-DHERMES_ENABLE_NAPI=OFF", "-DHERMES_ENABLE_TOOLS=OFF",
      "-DHERMES_UNICODE_LITE=ON",
      "-DHERMES_ENABLE_TEST_SUITE=OFF",
      `-DCMAKE_C_FLAGS=${staticHermesWasmExceptionFlags}`,
      `-DCMAKE_CXX_FLAGS=${staticHermesWasmExceptionFlags}`,
      `-DIMPORT_HOST_COMPILERS=${hostCompilerImport}`,
      ...staticHermesRuntimeCmakeFlags,
    ], { cwd: gateRoot, env: wasmBuildEnv, timeoutMs: 10 * 60 * 1000 });
  }
  // Emscripten can generate sysroot headers during the first build, making objects
  // compiled earlier in that build stale. Finish the resulting incremental work.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await run("cmake", ["--build", wasm, "--target", "hermesvm_a", "jsi", "hermesStaticIcu", "--parallel", String(jobs)], {
      cwd: gateRoot,
      env: wasmBuildEnv,
      timeoutMs: buildTimeoutMs,
    });
    if (!(await buildTargetsPending(wasm, ["hermesvm_a", "jsi", "hermesStaticIcu"]))) break;
  }
  if ((await runnerStatus(gateRoot)) !== "verified") {
    await buildRunner(gateRoot, jobs);
  }
  await checkGate(gateRoot);
  return gateRoot;
}

if (import.meta.main) {
  const result = await setupGate(parseArguments(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify({ gateRoot: result })}\n`);
}
