#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import { loadAndVerifyCompilerPackage } from "./lib/convex-wasm-compiler-package.mjs";
import {
  exitLikeNativeChild,
  runVerifiedNativePackage,
} from "./lib/verified-native-package-launcher.mjs";

function usage() {
  return [
    "usage: run-packaged-convex-wasm-compiler.mjs [--package PATH] [--] [COMPILER_ARGS...]",
    "       CONVEX_WASM_COMPILER_PACKAGE=PATH run-packaged-convex-wasm-compiler.mjs [COMPILER_ARGS...]",
  ].join("\n");
}

export function parseLauncherArguments(argumentsList, environment = process.env) {
  const remaining = [...argumentsList];
  let packageDirectory = environment.CONVEX_WASM_COMPILER_PACKAGE;
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
    throw new Error(`compiler package is required\n${usage()}`);
  }
  return { compilerArguments: remaining, packageDirectory };
}

export async function runPackagedCompiler(argumentsValue) {
  return runVerifiedNativePackage({
    argumentsList: argumentsValue.compilerArguments,
    loadPackage: loadAndVerifyCompilerPackage,
    packageDirectory: argumentsValue.packageDirectory,
  });
}

export async function main(argumentsList) {
  exitLikeNativeChild(await runPackagedCompiler(parseLauncherArguments(argumentsList)));
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
