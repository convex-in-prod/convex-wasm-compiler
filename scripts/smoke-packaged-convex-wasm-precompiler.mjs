#!/usr/bin/env node

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { loadAndVerifyPrecompilerPackage } from "./lib/convex-wasm-precompiler-package.mjs";
import {
  describeNativeCommandTermination,
  runBoundedNativeCommand,
} from "./lib/bounded-native-command.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const MAX_OUTPUT_BYTES = 1024 * 1024;
const TIMEOUT_MS = 120_000;
const BACKEND_TARGET_TRIPLE = "x86_64-unknown-linux-gnu";

function usage() {
  return "usage: smoke-packaged-convex-wasm-precompiler.mjs --package PATH [--jobs 1..AVAILABLE_CPUS]";
}

function parseArguments(argumentsList) {
  let packageDirectory;
  let jobs;
  for (let index = 0; index < argumentsList.length; index += 1) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (value === undefined || (option !== "--jobs" && option !== "--package")) {
      throw new Error(usage());
    }
    if (option === "--package") {
      if (packageDirectory !== undefined || value.length === 0) throw new Error(usage());
      packageDirectory = value;
    } else {
      if (jobs !== undefined || !/^[1-9][0-9]*$/u.test(value)) throw new Error(usage());
      jobs = Number(value);
    }
    index += 1;
  }
  if (packageDirectory === undefined) throw new Error(usage());
  return {
    jobs: jobs ?? availableParallelism(),
    packageDirectory,
  };
}

async function runBounded(command, argumentsList) {
  const result = await runBoundedNativeCommand({
    arguments: argumentsList,
    command,
    maxOutputBytes: MAX_OUTPUT_BYTES,
    operation: "packaged precompiler smoke",
    timeoutMs: TIMEOUT_MS,
  });
  if (result.termination !== undefined) {
    throw new Error(
      `packaged precompiler ${describeNativeCommandTermination(result.termination)}`
    );
  }
  if (result.code !== 0) {
    const output = result.output.toString("utf8").trim();
    throw new Error(
      `packaged precompiler failed with ${
        result.signal === null ? `exit ${result.code}` : `signal ${result.signal}`
      }${output.length === 0 ? "" : `\n${output}`}`
    );
  }
}

export async function smokePackagedPrecompiler(
  packageDirectory,
  { jobs = availableParallelism() } = {}
) {
  if (!Number.isSafeInteger(jobs) || jobs <= 0 || jobs > availableParallelism()) {
    throw new Error("precompiler smoke jobs must be within the available CPU count");
  }
  const { manifest } = await loadAndVerifyPrecompilerPackage(packageDirectory);
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-precompiler-smoke-"));
  await fs.chmod(root, 0o700);
  try {
    const inputPath = join(root, "representative.wasm");
    const outputPath = join(root, "representative.cwasm");
    const identityPath = join(root, "engine-identity.json");
    await fs.writeFile(
      inputPath,
      Buffer.from([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x00,
        0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
      ]),
      { mode: 0o600 }
    );
    await runBounded(process.execPath, [
      join(scriptDirectory, "run-packaged-convex-wasm-precompiler.mjs"),
      "--package",
      packageDirectory,
      "--",
      inputPath,
      outputPath,
      "--engine-identity",
      identityPath,
      "--consume-fuel",
      "true",
      "--epoch-interruption",
      "true",
      "--wasm-exceptions",
      "true",
      "--profiling-strategy",
      "perf-map",
      "--target-triple",
      BACKEND_TARGET_TRIPLE,
      "--target-cpu",
      "baseline",
      "--parallel-compilation-workers",
      String(jobs),
    ]);
    const [outputEntry, identityText] = await Promise.all([
      fs.stat(outputPath),
      fs.readFile(identityPath, "utf8"),
    ]);
    if (outputEntry.size === 0 || outputEntry.size > MAX_OUTPUT_BYTES) {
      throw new Error(`smoke AOT output must be between 1 and ${MAX_OUTPUT_BYTES} bytes`);
    }
    const identity = JSON.parse(identityText);
    if (
      identityText !== `${JSON.stringify(identity)}\n` ||
      identity.kind !== manifest.engineContract.engineIdentityKind ||
      identity.target?.triple !== BACKEND_TARGET_TRIPLE ||
      identity.target?.cpu !== manifest.engineContract.targetCpu ||
      identity.engineConfig?.consumeFuel !== manifest.engineContract.consumeFuel ||
      identity.engineConfig?.epochInterruption !== manifest.engineContract.epochInterruption ||
      identity.engineConfig?.profilingStrategy !== manifest.engineContract.profilingStrategy ||
      identity.engineConfig?.wasmExceptions !== manifest.engineContract.wasmExceptions ||
      !/^[0-9a-f]{64}$/u.test(identity.engineCompatibilitySha256)
    ) {
      throw new Error("packaged precompiler returned an unexpected engine identity");
    }
    return {
      aotBytes: outputEntry.size,
      aotSha256: createHash("sha256")
        .update(await fs.readFile(outputPath))
        .digest("hex"),
      engineIdentity: identity,
    };
  } finally {
    await fs.rm(root, { force: true, recursive: true });
  }
}

export async function main(argumentsList) {
  const { jobs, packageDirectory } = parseArguments(argumentsList);
  const result = await smokePackagedPrecompiler(packageDirectory, { jobs });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
