#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";
import {
  exitLikeNativeChild,
  runVerifiedNativePackage,
} from "./lib/verified-native-package-launcher.mjs";

function usage() {
  return [
    "usage: run-packaged-convex-wasm-precompiler.mjs [--package PATH] [--] [PRECOMPILER_ARGS...]",
    "       CONVEX_WASM_PRECOMPILER_PACKAGE=PATH run-packaged-convex-wasm-precompiler.mjs [PRECOMPILER_ARGS...]",
  ].join("\n");
}

export function parsePrecompilerLauncherArguments(argumentsList, environment = process.env) {
  const remaining = [...argumentsList];
  let packageDirectory = environment.CONVEX_WASM_PRECOMPILER_PACKAGE;
  if (remaining[0] === "--package") {
    if (remaining[1] === undefined || remaining[1].length === 0) {
      throw new Error(`--package requires a path\n${usage()}`);
    }
    packageDirectory = remaining[1];
    remaining.splice(0, 2);
  }
  if (remaining[0] === "--") {
    remaining.shift();
  }
  if (packageDirectory === undefined || packageDirectory.length === 0) {
    throw new Error(`precompiler package is required\n${usage()}`);
  }
  return { packageDirectory, precompilerArguments: remaining };
}

export async function runPackagedPrecompiler(argumentsValue) {
  return runVerifiedNativePackage({
    argumentsList: argumentsValue.precompilerArguments,
    loadPackage: loadAndVerifyPrecompilerPackage,
    packageDirectory: argumentsValue.packageDirectory,
  });
}

export async function main(argumentsList) {
  exitLikeNativeChild(
    await runPackagedPrecompiler(parsePrecompilerLauncherArguments(argumentsList))
  );
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
