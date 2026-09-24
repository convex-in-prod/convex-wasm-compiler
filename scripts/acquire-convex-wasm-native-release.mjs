#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalCompilerPackageJson } from "./lib/convex-wasm-compiler-package.mjs";
import { acquireNativeReleaseForHost } from "./lib/convex-wasm-native-release-selection.mjs";

const MAX_SELECTION_BYTES = 64 * 1024;

export async function acquireNativeReleaseFromSelectionFile({ selectionPath, cacheRoot, signal }) {
  const bytes = await fs.readFile(resolve(selectionPath));
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
      throw new Error("usage: acquire-convex-wasm-native-release.mjs --selection PATH --cache-root PATH");
    }
    values.set(option, value);
  }
  if (values.size !== 2) {
    throw new Error("native release acquisition requires selection and cache root");
  }
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    const packages = await acquireNativeReleaseFromSelectionFile({
      selectionPath: values.get("--selection"),
      cacheRoot: values.get("--cache-root"),
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

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
