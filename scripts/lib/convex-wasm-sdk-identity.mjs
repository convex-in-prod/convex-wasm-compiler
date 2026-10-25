import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const requireFromToolchain = createRequire(import.meta.url);
const packageJsonPath = requireFromToolchain.resolve("convex/package.json");
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));

if (
  packageJson.name !== "convex" ||
  typeof packageJson.version !== "string" ||
  packageJson.version.length === 0 ||
  /[\r\n\0]/u.test(packageJson.version)
) {
  throw new Error(`Installed Convex package has an invalid identity: ${packageJsonPath}`);
}

export const convexWasmSdkPackageVersion = packageJson.version;
export const convexWasmSdkClientHeader = `npm-cli-${convexWasmSdkPackageVersion}`;
