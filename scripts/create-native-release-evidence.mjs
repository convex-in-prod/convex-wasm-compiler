#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  canonicalCompilerPackageJson,
  loadAndVerifyCompilerPackage,
  sha256Bytes,
} from "./lib/convex-wasm-compiler-package.mjs";
import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";
import { smokePackagedCompiler } from "./smoke-packaged-convex-wasm-compiler.mjs";
import { smokePackagedPrecompiler } from "./smoke-packaged-convex-wasm-precompiler.mjs";

function usage() {
  return [
    "usage: create-native-release-evidence.mjs --compiler-package PATH",
    "       --precompiler-package PATH --output PATH [--jobs N]",
  ].join(" ");
}

function parseArguments(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !["--compiler-package", "--jobs", "--output", "--precompiler-package"].includes(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error(usage());
    }
    values.set(option, value);
  }
  for (const required of ["--compiler-package", "--output", "--precompiler-package"]) {
    if (!values.has(required)) throw new Error(usage());
  }
  const jobsText = values.get("--jobs");
  if (
    jobsText !== undefined &&
    (!/^[1-9][0-9]*$/u.test(jobsText) || !Number.isSafeInteger(Number(jobsText)))
  ) {
    throw new Error("--jobs must be a positive integer");
  }
  return {
    compilerPackage: resolve(values.get("--compiler-package")),
    jobs: jobsText === undefined ? undefined : Number(jobsText),
    output: resolve(values.get("--output")),
    precompilerPackage: resolve(values.get("--precompiler-package")),
  };
}

function packageEvidence(loaded, smoke) {
  const manifestText = `${canonicalCompilerPackageJson(loaded.manifest)}\n`;
  return {
    binary: loaded.manifest.binary,
    manifestSha256: sha256Bytes(manifestText),
    packageId: loaded.manifest.packageId,
    smoke,
    sourceTreeSha256: loaded.manifest.identities.source.treeSha256,
  };
}

export async function createNativeReleaseEvidence({
  compilerPackage,
  jobs,
  output,
  precompilerPackage,
}) {
  const [compiler, precompiler] = await Promise.all([
    loadAndVerifyCompilerPackage(compilerPackage),
    loadAndVerifyPrecompilerPackage(precompilerPackage),
  ]);
  if (compiler.manifest.platform.targetTriple !== precompiler.manifest.platform.targetTriple) {
    throw new Error("compiler and precompiler package targets differ");
  }
  const [compilerSmoke, precompilerSmoke] = await Promise.all([
    smokePackagedCompiler(compilerPackage),
    smokePackagedPrecompiler(
      precompilerPackage,
      jobs === undefined ? undefined : { jobs }
    ),
  ]);
  const evidence = {
    compiler: packageEvidence(compiler, compilerSmoke),
    kind: "convex-wasm-native-release-evidence",
    precompiler: packageEvidence(precompiler, precompilerSmoke),
    schemaVersion: 1,
    targetTriple: compiler.manifest.platform.targetTriple,
  };
  const encoded = `${canonicalCompilerPackageJson(evidence)}\n`;
  await fs.writeFile(output, encoded, { flag: "wx", mode: 0o600 });
  return evidence;
}

export async function main(argumentsList) {
  const options = parseArguments(argumentsList);
  const evidence = await createNativeReleaseEvidence(options);
  process.stdout.write(
    `${canonicalCompilerPackageJson({
      compilerPackageId: evidence.compiler.packageId,
      evidenceSha256: sha256Bytes(`${canonicalCompilerPackageJson(evidence)}\n`),
      precompilerPackageId: evidence.precompiler.packageId,
      targetTriple: evidence.targetTriple,
    })}\n`
  );
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
