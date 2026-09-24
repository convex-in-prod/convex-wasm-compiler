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

const requireFromConvex = createRequire(packageJsonPath);
const esbuildPackageJsonPath = requireFromConvex.resolve("esbuild/package.json");
const esbuildPackageJson = JSON.parse(readFileSync(esbuildPackageJsonPath, "utf8"));
if (
  esbuildPackageJson.name !== "esbuild" ||
  typeof esbuildPackageJson.version !== "string" ||
  esbuildPackageJson.version.length === 0
) {
  throw new Error(`Installed esbuild package has an invalid identity: ${esbuildPackageJsonPath}`);
}

const typescriptPackageJsonPath = requireFromToolchain.resolve("typescript/package.json");
const typescriptPackageJson = JSON.parse(readFileSync(typescriptPackageJsonPath, "utf8"));
if (
  typescriptPackageJson.name !== "typescript" ||
  typeof typescriptPackageJson.version !== "string" ||
  typescriptPackageJson.version.length === 0
) {
  throw new Error(
    `Installed TypeScript package has an invalid identity: ${typescriptPackageJsonPath}`
  );
}

export const convexWasmEsbuildPackageVersion = esbuildPackageJson.version;
export const convexWasmTypescriptPackageVersion = typescriptPackageJson.version;
