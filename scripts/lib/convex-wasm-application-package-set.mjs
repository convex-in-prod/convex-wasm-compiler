import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { isAbsolute, join, resolve } from "node:path";

function parseManifest(bytes, description) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${description} package manifest is invalid UTF-8 JSON`);
  }
}

function readPackage(path, expectedName) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      throw new Error(`${expectedName} package disappeared while reading its identity`);
    }
    throw error;
  }
  const manifest = parseManifest(bytes, expectedName);
  if (
    manifest === null ||
    typeof manifest !== "object" ||
    Array.isArray(manifest) ||
    manifest.name !== expectedName ||
    typeof manifest.version !== "string" ||
    manifest.version.length === 0 ||
    /[\r\n\0]/u.test(manifest.version)
  ) {
    throw new Error(`${expectedName} package manifest has an invalid identity`);
  }
  return Object.freeze({
    sha256: createHash("sha256").update(bytes).digest("hex"),
    version: manifest.version,
  });
}

function resolvePackage(requireFromRoot, specifier, name) {
  try {
    return requireFromRoot.resolve(specifier);
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "MODULE_NOT_FOUND" || error.code === "ERR_PACKAGE_PATH_NOT_EXPORTED")
    ) {
      throw new Error(`${name} package is unavailable from the application root`);
    }
    throw error;
  }
}

function resolveBundlerPackages(applicationRoot) {
  if (
    typeof applicationRoot !== "string" ||
    !isAbsolute(applicationRoot) ||
    resolve(applicationRoot) !== applicationRoot
  ) {
    throw new Error("application root must be a normalized absolute path");
  }
  const applicationManifestPath = join(applicationRoot, "package.json");
  let applicationBytes;
  try {
    applicationBytes = readFileSync(applicationManifestPath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      throw new Error("application root has no package manifest");
    }
    throw error;
  }
  const applicationManifest = parseManifest(applicationBytes, "application");
  if (
    applicationManifest === null ||
    typeof applicationManifest !== "object" ||
    Array.isArray(applicationManifest)
  ) {
    throw new Error("application package manifest must be an object");
  }
  const requireFromApplication = createRequire(join(applicationRoot, "package.json"));
  const convexPath = resolvePackage(requireFromApplication, "convex/package.json", "convex");
  const convex = readPackage(convexPath, "convex");
  const requireFromConvex = createRequire(convexPath);
  const packageSet = Object.freeze({
    applicationManifestSha256: createHash("sha256").update(applicationBytes).digest("hex"),
    convex,
    esbuild: readPackage(
      resolvePackage(requireFromConvex, "esbuild/package.json", "esbuild"),
      "esbuild"
    ),
  });
  return { packageSet, requireFromApplication };
}

export function resolveConvexWasmApplicationBundlerPackageSet(applicationRoot) {
  return resolveBundlerPackages(applicationRoot).packageSet;
}

export function resolveConvexWasmApplicationPackageSet(applicationRoot) {
  const { packageSet, requireFromApplication } = resolveBundlerPackages(applicationRoot);
  return Object.freeze({
    ...packageSet,
    typescript: readPackage(
      resolvePackage(requireFromApplication, "typescript/package.json", "typescript"),
      "typescript"
    ),
  });
}
