#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

import { createNativeReleaseEvidence } from "./create-native-release-evidence.mjs";
import {
  canonicalCompilerPackageJson,
  sha256Bytes,
} from "./lib/convex-wasm-compiler-package.mjs";
import { packageCompiler } from "./package-convex-wasm-compiler.mjs";
import { packagePrecompiler } from "./package-convex-wasm-precompiler.mjs";

function usage() {
  return "usage: build-native-release.mjs --output PATH --target TRIPLE [--jobs N]";
}

function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !["--jobs", "--output", "--target"].includes(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error(usage());
    }
    values.set(option, value);
  }
  if (!values.has("--output") || !values.has("--target")) throw new Error(usage());
  const jobsText = values.get("--jobs");
  if (
    jobsText !== undefined &&
    (!/^[1-9][0-9]*$/u.test(jobsText) || !Number.isSafeInteger(Number(jobsText)))
  ) {
    throw new Error("--jobs must be a positive integer");
  }
  return {
    jobs: jobsText === undefined ? undefined : Number(jobsText),
    output: resolve(values.get("--output")),
    targetTriple: values.get("--target"),
  };
}

function relativePackagePath(root, path) {
  const result = relative(root, path).split(sep).join("/");
  if (result === "" || result === ".." || result.startsWith("../")) {
    throw new Error("native package path escapes the release directory");
  }
  return result;
}

export async function buildNativeRelease({ jobs, output, targetTriple }) {
  await fs.mkdir(output, { mode: 0o700 });
  await fs.chmod(output, 0o700);
  const packagesRoot = join(output, "packages");
  const compilerPackage = await packageCompiler({
    build: true,
    cargoBuildJobs: jobs,
    outputRoot: join(packagesRoot, "compiler"),
    targetTriple,
  });
  const precompiler = await packagePrecompiler({
    cargoBuildJobs: jobs,
    outputRoot: join(packagesRoot, "precompiler"),
    targetTriple,
  });
  const evidencePath = join(output, "evidence.json");
  const evidence = await createNativeReleaseEvidence({
    compilerPackage,
    jobs,
    output: evidencePath,
    precompilerPackage: precompiler.path,
  });
  const index = {
    compiler: {
      packageId: evidence.compiler.packageId,
      path: relativePackagePath(output, compilerPackage),
    },
    evidenceSha256: sha256Bytes(`${canonicalCompilerPackageJson(evidence)}\n`),
    kind: "convex-wasm-native-release",
    precompiler: {
      packageId: evidence.precompiler.packageId,
      path: relativePackagePath(output, precompiler.path),
    },
    schemaVersion: 1,
    targetTriple,
  };
  await fs.writeFile(join(output, "index.json"), `${canonicalCompilerPackageJson(index)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return index;
}

export async function main(argumentsList) {
  const index = await buildNativeRelease(parseArguments(argumentsList));
  process.stdout.write(`${canonicalCompilerPackageJson(index)}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
