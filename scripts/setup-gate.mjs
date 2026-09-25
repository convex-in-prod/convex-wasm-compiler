#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { emscriptenVersion, gateRevisions } from "./lib/convex-wasm-gate-pins.mjs";

const sources = Object.freeze({
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
];
const staticHermesWasmExceptionFlags = "-fwasm-exceptions -sWASM_LEGACY_EXCEPTIONS=0";
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const runnerCrate = join(scriptDirectory, "convex-wasm-precompiler");

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

async function runnerInputSha256() {
  const hash = createHash("sha256");
  for (const [name, path] of [
    ["Cargo.lock", join(runnerCrate, "Cargo.lock")],
    ["Cargo.toml", join(runnerCrate, "Cargo.toml")],
    ["rust-toolchain.toml", join(runnerCrate, "rust-toolchain.toml")],
    ["runner.rs", join(runnerCrate, "src", "bin", `${runnerName}.rs`)],
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
  await Promise.all([
    requireFile(join(root, "emsdk", ".emscripten"), "Emscripten configuration"),
    requireFile(join(root, "emsdk", "upstream", "emscripten", "emcc"), "Emscripten compiler", true),
    requireFile(join(root, "build-host", "bin", "shermes"), "Static Hermes compiler", true),
    requireFile(join(root, "build-wasm", "lib", "libhermesvm_a.a"), "Wasm Hermes archive"),
    requireFile(join(root, "build-wasm", "jsi", "libjsi.a"), "Wasm JSI archive"),
    requireFile(join(root, "build-wasm", "lib", "config", "libhermesvm-config.h"), "Wasm Hermes configuration"),
  ]);
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
  const version = await run(join(root, "emsdk", "upstream", "emscripten", "emcc"), ["--version"], {
    cwd: root,
    env: {
      ...process.env,
      EM_CONFIG: join(root, "emsdk", ".emscripten"),
      EMSDK: join(root, "emsdk"),
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
}

export async function setupGate({ gateRoot, jobs, checkOnly }) {
  if (checkOnly) {
    await checkGate(gateRoot);
    return gateRoot;
  }
  await fs.mkdir(gateRoot, { recursive: true });
  for (const name of Object.keys(sources)) await checkout(gateRoot, name);

  const emsdk = join(gateRoot, "emsdk");
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
    await run("cmake", ["--build", host, "--target", "shermes", "--parallel", String(jobs)], {
      cwd: gateRoot,
      timeoutMs: buildTimeoutMs,
    });
  }

  const wasmBuildOutputs = [
    join(wasm, "lib", "libhermesvm_a.a"),
    join(wasm, "jsi", "libjsi.a"),
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
  const wasmNeedsConfiguration = wasmBuildOutputStates.some((state) => state === null) ||
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
    const env = {
      ...process.env,
      EM_CONFIG: join(emsdk, ".emscripten"),
      EMSDK: emsdk,
      PATH: [join(emsdk, "upstream", "emscripten"), join(emsdk, "upstream", "bin"), process.env.PATH].join(":"),
    };
    await run(join(emsdk, "upstream", "emscripten", "emcmake"), [
      "cmake", "-S", hermes, "-B", wasm, "-G", "Ninja",
      "-DCMAKE_BUILD_TYPE=Release", "-DHERMES_ENABLE_INTL=OFF",
      "-DHERMES_ENABLE_NAPI=OFF", "-DHERMES_ENABLE_TOOLS=OFF",
      "-DHERMES_UNICODE_LITE=ON",
      "-DHERMES_ENABLE_TEST_SUITE=OFF",
      `-DCMAKE_C_FLAGS=${staticHermesWasmExceptionFlags}`,
      `-DCMAKE_CXX_FLAGS=${staticHermesWasmExceptionFlags}`,
      `-DIMPORT_HOST_COMPILERS=${hostCompilerImport}`,
      ...staticHermesRuntimeCmakeFlags,
    ], { cwd: gateRoot, env, timeoutMs: 10 * 60 * 1000 });
    await run("cmake", ["--build", wasm, "--target", "hermesvm_a", "jsi", "--parallel", String(jobs)], {
      cwd: gateRoot,
      env,
      timeoutMs: buildTimeoutMs,
    });
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
