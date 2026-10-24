import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { canonicalCompilerPackageJson } from "./convex-wasm-compiler-package.mjs";
import { hermesSource, gateRevisions } from "./convex-wasm-gate-pins.mjs";
import { ensureCreatedPrivateDirectoryPath } from "./private-directory.mjs";
import { requirePrivateCacheDirectory, requirePrivateCacheFile } from "./convex-wasm-private-cache.mjs";

const kind = "convex-wasm-toolchain-package-v1";
const digestPattern = /^[0-9a-f]{64}$/u;

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) {
    throw new Error(`${label} has invalid fields`);
  }
}

function packagePath(path) {
  if (typeof path !== "string" || path.includes("\\") || isAbsolute(path) ||
      path.split("/").some(part => part === "" || part === "." || part === "..")) {
    throw new Error("Toolchain file must have a normalized relative path");
  }
  return path;
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

async function filesIn(root, directory = root) {
  const files = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await filesIn(root, path));
    else if (entry.isFile()) files.push(relative(root, path).split(sep).join("/"));
    else throw new Error(`Toolchain package contains a link or special file: ${entry.name}`);
  }
  return files.sort();
}

export async function sealToolchainPackage(root, { version, nativePackages }) {
  const files = [];
  for (const path of await filesIn(root)) {
    const state = await fs.stat(join(root, path));
    files.push({ path, ...await fileIdentity(join(root, path)), executable: (state.mode & 0o111) !== 0 });
  }
  const payload = {
    kind, version, platform: `${process.platform}-${process.arch}`,
    source: { hermes: hermesSource, emsdk: gateRevisions.emsdk }, nativePackages, files,
  };
  const packageId = createHash("sha256").update(canonicalCompilerPackageJson(payload)).digest("hex");
  const manifest = { ...payload, packageId };
  await fs.writeFile(join(root, "toolchain.json"), `${canonicalCompilerPackageJson(manifest)}\n`, {
    flag: "wx", mode: 0o600,
  });
  return manifest;
}

export async function verifyToolchainPackage(root) {
  const manifestPath = join(root, "toolchain.json");
  const state = await fs.lstat(manifestPath);
  if (!state.isFile() || state.size > 32 * 1024 * 1024) {
    throw new Error("Toolchain manifest must be a bounded regular file");
  }
  const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
  exactKeys(manifest, ["kind", "version", "platform", "source", "nativePackages", "files", "packageId"], "Toolchain manifest");
  const { packageId, ...payload } = manifest;
  if (manifest.kind !== kind || typeof manifest.version !== "string" || manifest.version.length === 0 ||
      manifest.platform !== `${process.platform}-${process.arch}` ||
      !digestPattern.test(packageId) ||
      createHash("sha256").update(canonicalCompilerPackageJson(payload)).digest("hex") !== packageId) {
    throw new Error("Toolchain manifest identity or host platform does not match");
  }
  exactKeys(manifest.source, ["hermes", "emsdk"], "Toolchain source");
  if (canonicalCompilerPackageJson(manifest.source.hermes) !== canonicalCompilerPackageJson(hermesSource) ||
      manifest.source.emsdk !== gateRevisions.emsdk) {
    throw new Error("Toolchain package does not match this compiler's pinned source");
  }
  exactKeys(manifest.nativePackages, ["compiler", "precompiler"], "Toolchain native packages");
  for (const path of Object.values(manifest.nativePackages)) packagePath(path);
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    throw new Error("Toolchain manifest must contain its file inventory");
  }
  let previous = "";
  for (const entry of manifest.files) {
    exactKeys(entry, ["path", "sha256", "size", "executable"], "Toolchain file");
    packagePath(entry.path);
    if (entry.path <= previous || !digestPattern.test(entry.sha256) ||
        !Number.isSafeInteger(entry.size) || entry.size < 0 || typeof entry.executable !== "boolean") {
      throw new Error("Toolchain file inventory is invalid");
    }
    previous = entry.path;
  }
  const actualPaths = (await filesIn(root)).filter(path => path !== "toolchain.json");
  if (canonicalCompilerPackageJson(actualPaths) !== canonicalCompilerPackageJson(manifest.files.map(file => file.path))) {
    const expected = new Set(manifest.files.map(file => file.path));
    const actual = new Set(actualPaths);
    const added = actualPaths.filter(path => !expected.has(path)).slice(0, 5);
    const missing = manifest.files.filter(file => !actual.has(file.path)).slice(0, 5).map(file => file.path);
    throw new Error(`Toolchain package file inventory changed: added=${added.join(",")}; missing=${missing.join(",")}`);
  }
  // Authenticate shipped tools and headers, not a build machine's Git/CMake
  // directories. The existing compilation pipeline still binds every used input.
  for (const entry of manifest.files) {
    const path = join(root, entry.path);
    const [actual, state] = await Promise.all([fileIdentity(path), fs.stat(path)]);
    if (actual.sha256 !== entry.sha256 || actual.size !== entry.size ||
        ((state.mode & 0o111) !== 0) !== entry.executable) {
      throw new Error(`Toolchain package file differs: ${entry.path}`);
    }
  }
  return manifest;
}

export async function packagedGate(gateRoot) {
  const root = dirname(resolve(gateRoot));
  try {
    await fs.lstat(join(root, "toolchain.json"));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
  if (resolve(gateRoot) !== join(root, "gate")) {
    throw new Error("Packaged toolchain gate path is invalid");
  }
  return { root, manifest: await verifyToolchainPackage(root) };
}

export async function toolchainEnvironment(root, manifest, cacheRoot) {
  const toolchains = join(cacheRoot, "toolchains");
  const parent = join(toolchains, manifest.packageId);
  const cache = join(parent, "emscripten");
  // Emscripten clears everything inside EM_CACHE when its sanity check changes.
  // Publish the seed receipt beside that directory so a later invocation can reuse it.
  const receipt = join(parent, ".toolchain-seed");
  await ensureCreatedPrivateDirectoryPath(toolchains);
  await requirePrivateCacheDirectory(cacheRoot, toolchains);
  try {
    await fs.lstat(parent);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    const stage = await fs.mkdtemp(join(toolchains, ".emscripten-"));
    try {
      await fs.cp(join(root, "gate/emsdk/upstream/emscripten/cache"), join(stage, "emscripten"), { recursive: true });
      await fs.chmod(join(stage, "emscripten"), 0o700);
      await fs.writeFile(join(stage, ".toolchain-seed"), manifest.packageId, { mode: 0o600 });
      try {
        await fs.rename(stage, parent);
      } catch (error) {
        if (error?.code !== "EEXIST" && error?.code !== "ENOTEMPTY") throw error;
      }
    } finally {
      await fs.rm(stage, { recursive: true, force: true });
    }
  }
  await requirePrivateCacheDirectory(cacheRoot, cache);
  await requirePrivateCacheFile(cacheRoot, receipt);
  if (await fs.readFile(receipt, "utf8") !== manifest.packageId) {
    throw new Error("Emscripten cache belongs to a different toolchain package");
  }
  // Emscripten generates system libraries on demand. Keep that writable state
  // outside the authenticated installation so relocation and reuse stay valid.
  const python = join(root, "runtime/bin/convex-python");
  return {
    EM_CACHE: cache,
    EM_CONFIG: join(root, "gate/emsdk/.emscripten"),
    EMSDK: join(root, "gate/emsdk"),
    EMSDK_PYTHON: python,
    EM_BINARYEN_ROOT: join(root, "gate/binaryen-tools"),
  };
}
