#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalCompilerPackageJson } from "./lib/convex-wasm-compiler-package.mjs";
import { defaultConvexWasmCacheRoot } from "./lib/convex-wasm-cache-layout.mjs";
import { acquireNativeReleaseForHost } from "./lib/convex-wasm-native-release-selection.mjs";

const MAX_SELECTION_BYTES = 64 * 1024;
export const bundledNativeReleaseSelectionPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "native-package-selection.json"
);

export function defaultNativePackageCacheRoot() {
  return join(defaultConvexWasmCacheRoot(), "native-packages");
}

export async function acquireNativeReleaseFromSelectionFile({ selectionPath, cacheRoot, signal }) {
  const path = resolve(selectionPath);
  let bytes;
  try {
    bytes = await fs.readFile(path);
  } catch (error) {
    if (error?.code === "ENOENT" && path === bundledNativeReleaseSelectionPath) {
      throw new Error("this compiler package has no bundled native selection; install a tagged release or supply --selection");
    }
    throw error;
  }
  if (bytes.length > MAX_SELECTION_BYTES) {
    throw new Error("native release selection exceeds 64 KiB");
  }
  const selection = JSON.parse(bytes.toString("utf8"));
  return await acquireNativeReleaseForHost({ selection, cacheRoot: resolve(cacheRoot), signal });
}

export async function main(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !["--selection", "--cache-root"].includes(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error("usage: convex-wasm-acquire-native [--selection PATH] [--cache-root PATH]");
    }
    values.set(option, value);
  }
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    const packages = await acquireNativeReleaseFromSelectionFile({
      selectionPath: values.get("--selection") ?? bundledNativeReleaseSelectionPath,
      cacheRoot: values.get("--cache-root") ?? defaultNativePackageCacheRoot(),
      signal: cancellation.signal,
    });
    process.stdout.write(
      `${canonicalCompilerPackageJson({
        compiler: {
          binaryPath: packages.compiler.binaryPath,
          manifestPath: packages.compiler.manifestPath,
          packageId: packages.compiler.manifest.packageId,
        },
        precompiler: {
          binaryPath: packages.precompiler.binaryPath,
          manifestPath: packages.precompiler.manifestPath,
          packageId: packages.precompiler.manifest.packageId,
        },
      })}\n`
    );
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}

if (import.meta.main) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
