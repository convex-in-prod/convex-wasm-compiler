import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export function projectTsrsCacheRoot(projectRoot, environment = process.env) {
  const configured = environment.TSRS_CACHE_DIR;
  let cacheRoot = configured;
  if (cacheRoot === undefined) {
    const cacheHome = environment.XDG_CACHE_HOME ??
      (process.platform === "darwin" ? join(homedir(), "Library", "Caches") : join(homedir(), ".cache"));
    if (cacheHome === "") throw new Error("Compiler cache paths must not be empty.");
    cacheRoot = join(cacheHome, "tsrs");
  }
  if (cacheRoot === "") {
    throw new Error("Compiler cache paths must not be empty.");
  }
  const packageJson = JSON.parse(readFileSync(join(projectRoot, "package.json"), "utf8"));
  if (packageJson === null || typeof packageJson !== "object" || Array.isArray(packageJson)) {
    throw new Error("The project package manifest must be an object.");
  }
  if (packageJson.name !== undefined && typeof packageJson.name !== "string") {
    throw new Error("The project package name must be a string when provided.");
  }
  // Private application manifests can omit a name; cache identities still bind their inputs.
  const namespace = environment.TSRS_CACHE_NAMESPACE ?? (packageJson.name ?? "project")
    .replace(/^@/u, "").replace(/[^A-Za-z0-9._-]+/gu, "-").toLowerCase();
  // npm package names can contain 214 characters, including a scope.
  if (!/^[a-z0-9][a-z0-9._-]{0,213}$/u.test(namespace)) {
    throw new Error("TSRS_CACHE_NAMESPACE must be a simple non-empty name.");
  }
  return resolve(cacheRoot, namespace);
}
