import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";
import { buildConvexWasmOfficialOutputChunkApplicationUnit, projectConvexWasmOfficialOutputChunkLocalProfiles, projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor } from "./convex-wasm-official-output-chunk-application-unit.mjs";
import { buildConvexWasmOfficialOutputChunkUnits, createConvexWasmOfficialOutputChunkTransformSession } from "./convex-wasm-official-output-chunk-unit.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { convexWasmCapabilityRequestAbiVersion, renderNativeDbGetCapabilityTargetUnits } from "./convex-wasm-lowering.mjs";
import { createConvexWasmNativePhaseScheduler } from "./convex-wasm-native-launch-scheduling.mjs";
import { authenticateConvexWasmOfficialOutputSelectionFixtures } from "../test-fixtures/official-output-selection.mjs";

import { describeNativeCommandTermination, runBoundedNativeCommand } from "./bounded-native-command.mjs";
import {
  compileConvexWasmArtifact,
  compileConvexWasmOfficialOutputModuleGraphInputsInMaterialSession,
  createConvexWasmCapabilityArtifactMaterialSession,
  finalizeConvexWasmArtifactMaterialSession,
  buildConvexWasmOfficialOutputModuleGraphArtifacts,
  loadAndVerifyConvexWasmModuleGraphPackage,
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
  convexWasmCapabilitySourcePipelineSha256,
  createConvexWasmCapabilityRequestEnvelopeInput,
  createConvexWasmGuestNativeJsonCodecInput,
  convexWasmBuildResourceGuardKind,
} from "./convex-wasm-artifact-pipeline.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import { convexWasmTargetRuntimeSurfacePolicyIdentity } from "./convex-wasm-runtime-surface.mjs";
import { convexWasmStaticHermesCBundleMemberCompilationPolicy } from "./convex-wasm-static-hermes-c-bundle.mjs";
import { writeFixturePrecompilerPackage } from "../test-fixtures/precompiler-package.mjs";
import { buildSyntheticDeploymentApplication } from "../test-fixtures/deployment-application.mjs";
import { buildConvexWasmOfficialOutputModuleGraphInputs } from "./convex-wasm-official-output-artifact-adapter.mjs";
import { buildConvexWasmProjectPackage } from "./convex-wasm-project-package.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const require = createRequire(import.meta.url);
const producerIdentityPromise = buildConvexWasmProducerIdentity(repositoryRoot);
const FIRST_GRAPH_FINGERPRINT = "1".repeat(64);

function fixtureGuestSourceProvenance(source, sourceIdentity) {
  const sourceBytes = Buffer.from(source);
  const sourceSha256 = createHash("sha256").update(sourceBytes).digest("hex");
  const endLine = source.split("\n").length;
  const dependencyUnitId = `${sourceIdentity.modulePath}#${sourceIdentity.exportName}`;
  const unitId = `${dependencyUnitId}:handler`;
  return {
    compilerBundle: {
      endLine,
      sha256: sourceSha256,
      size: sourceBytes.length,
      startLine: 1,
    },
    generatedSource: { sha256: sourceSha256, size: sourceBytes.length },
    kind: "convex-wasm-guest-source-provenance-v1",
    schemaVersion: 1,
    units: [
      {
        generatedRange: { endLine, startLine: 1 },
        original: {
          column: 1,
          dependencyChain: [dependencyUnitId],
          end: sourceBytes.length,
          id: unitId,
          kind: "handler",
          line: 1,
          module: sourceIdentity.modulePath,
          name: sourceIdentity.exportName,
          sourceHash: sourceIdentity.exportSha256,
          start: 0,
        },
      },
    ],
  };
}

function bindFixtureGuestSourceProvenance(options) {
  return {
    ...options,
    guestSourceProvenance: fixtureGuestSourceProvenance(
      options.generatedJavaScript,
      options.source
    ),
  };
}

async function writeExecutable(path, source) {
  await fs.writeFile(path, source, { mode: 0o700 });
}

async function createFixture(
  t,
  {
    cacheRoot: sharedCacheRoot,
    moduleGraphWasm = false,
    rootName = "convex-wasm-artifact-pipeline-",
    staticHermesCBundle = false,
  } = {}
) {
  const root = await fs.mkdtemp(join(tmpdir(), rootName));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const cacheRoot = sharedCacheRoot ?? join(root, "cache");
  const includeDirectory = join(root, "include");
  const toolDirectory = join(root, "tool chain");
  const precompilerPackageRoot = join(root, "precompiler packages");
  await Promise.all([
    fs.mkdir(includeDirectory),
    fs.mkdir(toolDirectory),
    fs.mkdir(cacheRoot, { mode: 0o700, recursive: true }),
    fs.mkdir(precompilerPackageRoot, { mode: 0o700 }),
  ]);
  const graphPrecompilerBinary = join(root, "fixture-graph-precompiler");
  if (moduleGraphWasm) {
    const graphPrecompilerSource = join(root, "fixture-graph-precompiler.c");
    await fs.writeFile(
      graphPrecompilerSource,
      `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *option(int argc, char **argv, const char *name) {
  for (int i = 3; i + 1 < argc; ++i) if (strcmp(argv[i], name) == 0) return argv[i + 1];
  fprintf(stderr, "missing option %s\\n", name);
  exit(2);
}
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  option(argc, argv, "--parallel-compilation-workers");
  FILE *input = fopen(argv[1], "rb");
  FILE *output = fopen(argv[2], "wb");
  if (input == NULL || output == NULL) return 3;
  fputs("graph-aot:", output);
  char buffer[4096];
  size_t size;
  while ((size = fread(buffer, 1, sizeof(buffer), input)) > 0) fwrite(buffer, 1, size, output);
  fclose(input);
  fclose(output);
  FILE *identity = fopen(option(argc, argv, "--engine-identity"), "wb");
  if (identity == NULL) return 4;
  fprintf(identity,
    "{\\"engineCompatibilitySha256\\":\\"7777777777777777777777777777777777777777777777777777777777777777\\","
    "\\"engineConfig\\":{\\"consumeFuel\\":true,\\"epochInterruption\\":true,"
    "\\"profilingStrategy\\":\\"%s\\",\\"wasmExceptions\\":true},"
    "\\"kind\\":\\"convex-wasm-wasmtime-engine-identity\\","
    "\\"target\\":{\\"cpu\\":\\"%s\\",\\"triple\\":\\"%s\\"}}\\n",
    option(argc, argv, "--profiling-strategy"),
    option(argc, argv, "--target-cpu"),
    option(argc, argv, "--target-triple"));
  fclose(identity);
  return 0;
}
`
    );
    execFileSync("cc", [graphPrecompilerSource, "-O0", "-o", graphPrecompilerBinary]);
  }
  const precompilerPackage = await writeFixturePrecompilerPackage({
    binaryPath: moduleGraphWasm ? graphPrecompilerBinary : "/usr/bin/dash",
    identitySeed: "artifact-pipeline-fixture-1",
    root: precompilerPackageRoot,
  });
  const toolLog = join(root, "tool.log");
  const fakePrecompilerJavaScript = `const { appendFileSync, lstatSync, readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const args = process.argv.slice(2);
const temporaryDirectoryStatus = lstatSync(process.env.TMPDIR);
appendFileSync(join(process.env.HOME, "tool.log"), JSON.stringify({ tool: "convex-wasm-precompiler", args, cwd: process.cwd(), environment: { HOME: process.env.HOME, PATH: process.env.PATH, TMPDIR: process.env.TMPDIR, ARTIFACT_PIPELINE_TEST_UNRELATED: process.env.ARTIFACT_PIPELINE_TEST_UNRELATED }, temporaryDirectory: { isDirectory: temporaryDirectoryStatus.isDirectory(), isSymbolicLink: temporaryDirectoryStatus.isSymbolicLink(), mode: temporaryDirectoryStatus.mode & 0o7777 } }) + "\\n");
const [output] = args;
const option = (name) => {
  const index = args.indexOf(name);
  if (index < 0 || index + 1 >= args.length) {
    throw new Error("missing " + name);
  }
  return args[index + 1];
};
writeFileSync(output, Buffer.concat([Buffer.from("aot:"), readFileSync(process.argv[1])]));
writeFileSync(
  option("--engine-identity"),
  JSON.stringify({
    engineCompatibilitySha256: "7".repeat(64),
    engineConfig: {
      consumeFuel: option("--consume-fuel") === "true",
      epochInterruption: option("--epoch-interruption") === "true",
      profilingStrategy: option("--profiling-strategy"),
      wasmExceptions: option("--wasm-exceptions") === "true",
    },
    kind: "convex-wasm-wasmtime-engine-identity",
    target: {
      cpu:
        process.env.SOURCE_DATE_EPOCH === "1"
          ? "mismatched"
          : option("--target-cpu"),
      triple: option("--target-triple"),
    },
  }) + "\\n"
);
`;
  const shellQuote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
  const fakePrecompilerModule = `#!/bin/sh
exec ${shellQuote(process.execPath)} -e ${shellQuote(fakePrecompilerJavaScript)} "$0" "$@"
`;
  const fakeToolSource = `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const tool = basename(process.argv[1]);
const args = process.argv.slice(2);
const temporaryDirectoryStatus = lstatSync(process.env.TMPDIR);
const workingNames = readdirSync(".").sort();
const stagedInputNames = existsSync("inputs") ? readdirSync("inputs").sort() : [];
const stagedInputIdentities = stagedInputNames.map((name) => {
  const status = lstatSync(join("inputs", name));
  return { device: status.dev, inode: status.ino, name, sha256: status.isFile() ? createHash("sha256").update(readFileSync(join("inputs", name))).digest("hex") : null };
});
const outputIndex = args.lastIndexOf("-o");
const inputBytes = [];
for (const argument of args) {
  if (existsSync(argument)) {
    inputBytes.push(readFileSync(argument));
  }
}
const includePchIndex = args.indexOf("-include-pch");
let pchMutationRejected;
let pchInputSha256;
if (tool === "emcc" && includePchIndex >= 0) {
  pchInputSha256 = createHash("sha256").update(readFileSync(args[includePchIndex + 1])).digest("hex");
  try {
    writeFileSync(args[includePchIndex + 1], "modified by compiler child");
    pchMutationRejected = false;
  } catch {
    pchMutationRejected = true;
  }
}
appendFileSync(join(process.env.HOME, "tool.log"), JSON.stringify({ tool, args, cwd: process.cwd(), environment: { HOME: process.env.HOME, PATH: process.env.PATH, TMPDIR: process.env.TMPDIR, ARTIFACT_PIPELINE_TEST_UNRELATED: process.env.ARTIFACT_PIPELINE_TEST_UNRELATED }, ...(pchMutationRejected === undefined ? {} : { pchInputSha256, pchMutationRejected }), stagedInputIdentities, stagedInputNames, temporaryDirectory: { isDirectory: temporaryDirectoryStatus.isDirectory(), isSymbolicLink: temporaryDirectoryStatus.isSymbolicLink(), mode: temporaryDirectoryStatus.mode & 0o7777 }, workingNames }) + "\\n");
if (
  tool === "emcc" &&
  outputIndex >= 0 &&
  args[outputIndex + 1] === "artifact.pch" &&
  existsSync(join(process.env.HOME, "runtime-prelude-pch-fail"))
) {
  const profile = args.includes("-O0") ? "O0" : "Oz";
  const otherProfileStart = join(process.env.HOME, "runtime-prelude-pch-start-Oz");
  writeFileSync(join(process.env.HOME, "runtime-prelude-pch-start-" + profile), "started\\n");
  if (profile === "O0") {
    const deadline = Date.now() + 9000;
    while (!existsSync(otherProfileStart)) {
      if (Date.now() >= deadline) throw new Error("runtime-prelude PCH sibling did not start");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  } else {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
  }
  writeFileSync(join(process.env.HOME, "runtime-prelude-pch-drained-" + profile), "drained\\n");
  process.stderr.write("fixture runtime-prelude PCH " + profile + " failure\\n");
  process.exit(1);
}
if (
  tool === "emcc" &&
  inputBytes.some((bytes) => bytes.includes("SHERMES_RUNTIME_HEADER_MUTATION_PROBE"))
) {
  writeFileSync("inputs/include-0/compiler-created.h", "modified by compiler child");
}
if (inputBytes.some((bytes) => bytes.includes("FIXTURE_NATIVE_TOOL_FAILURE"))) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  process.stderr.write("fixture native tool failure\\n");
  process.exit(1);
}
if (
  outputIndex < 0 &&
  tool === "emcc" &&
  args.includes("-c") &&
  inputBytes.some((bytes) => bytes.includes("SHERMES_BATCH_CONCURRENCY_PROBE"))
) {
  writeFileSync(
    join(process.env.HOME, "static-hermes-batch-start-" + basename(process.cwd())),
    "started\\n"
  );
  const releasePath = join(process.env.HOME, "static-hermes-batch-release");
  const deadline = Date.now() + 9000;
  while (!existsSync(releasePath)) {
    if (Date.now() >= deadline) throw new Error("Static Hermes batch probe release timed out");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  }
}
if (outputIndex < 0 && tool === "emcc" && args.includes("-c")) {
  const sourceArguments = args.filter((argument) => /\\.(?:c|cc|cpp|cxx)$/u.test(argument));
  const sourceArgumentSet = new Set(sourceArguments);
  for (const sourceArgument of sourceArguments) {
    const memberArguments = args.filter((argument) => !sourceArgumentSet.has(argument));
    memberArguments.splice(memberArguments.indexOf("-c") + 1, 0, sourceArgument);
    const sourceBytes = readFileSync(sourceArgument);
    const memberHash = createHash("sha256")
      .update(tool)
      .update(JSON.stringify(memberArguments))
      .update(sourceBytes)
      .digest("hex");
    writeFileSync(
      sourceArgument.replace(/\\.(?:c|cc|cpp|cxx)$/u, ".o"),
      tool + ":" + memberHash +
        (sourceBytes.includes("SHERMES_PHYSICAL_CLOSURE_CHANGE")
          ? ":SHERMES_PHYSICAL_CLOSURE_CHANGE"
          : "")
    );
  }
  process.exit(0);
}
if (outputIndex < 0 || outputIndex + 1 >= args.length) {
  throw new Error("missing -o");
}
if (tool === "shermes") {
  const sourcePath = args[args.length - 1];
  const source = readFileSync(sourcePath, "utf8");
  const sourceSha256 = createHash("sha256").update(source).digest("hex");
  if (source.includes("SHERMES_SYNTAX_REJECT")) {
    process.stderr.write(
      sourcePath + ":1:1: error: invalid statement encountered.\\n" +
        "Emitted 1 errors. exiting.\\n"
    );
    process.exit(1);
  }
  if (source.includes("SHERMES_FLOW_REJECT")) {
    const line = source.split("\\n").findIndex((sourceLine) =>
      sourceLine.includes("SHERMES_FLOW_REJECT")
    ) + 1;
    process.stderr.write(
      sourcePath + ":" + String(line) +
        ":7: error: ft: incompatible binary operation: + cannot be applied to number and string\\n" +
        "Emitted 1 errors. exiting.\\n"
    );
    process.exit(1);
  }
  if (source.includes("SHERMES_PRELUDE_REJECT")) {
    process.stderr.write(
      sourcePath + ":1:1: error: ft: incompatible binary operation: + cannot be applied to number and string\\n" +
        "Emitted 1 errors. exiting.\\n"
    );
    process.exit(1);
  }
  if (args.includes("-Xemit-c-bundle")) {
    const canonicalValue = (value) => {
      if (Array.isArray(value)) return value.map(canonicalValue);
      if (value !== null && typeof value === "object") {
        return Object.fromEntries(
          Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])])
        );
      }
      return value;
    };
    const hasCOptimizationLevelZeroMember = source.includes(
      "SHERMES_C_OPTIMIZATION_LEVEL_ZERO_MEMBER"
    );
    const hasInvalidCOptimizationLevelMember = source.includes(
      "SHERMES_INVALID_C_OPTIMIZATION_LEVEL_MEMBER"
    );
    const hasMissingOversizeReason = source.includes(
      "SHERMES_OVERSIZE_C_BUNDLE_MEMBER_MISSING_REASON"
    );
    const hasInvalidOversizeReason = source.includes(
      "SHERMES_OVERSIZE_C_BUNDLE_MEMBER_INVALID_REASON"
    );
    const hasNoOutlineableRunOversizeMember = source.includes(
      "SHERMES_OVERSIZE_NO_OUTLINEABLE_RUN_C_BUNDLE_MEMBER"
    );
    const hasSingleInstructionOversizeMember = source.includes(
      "SHERMES_OVERSIZE_C_BUNDLE_MEMBER"
    );
    const hasNonOversizeReason = source.includes(
      "SHERMES_NON_OVERSIZE_C_BUNDLE_MEMBER_REASON"
    );
    const hasOversizeBundleMember =
      hasMissingOversizeReason ||
      hasInvalidOversizeReason ||
      hasNoOutlineableRunOversizeMember ||
      hasSingleInstructionOversizeMember;
    const oversizeReason = hasMissingOversizeReason
      ? undefined
      : hasInvalidOversizeReason
        ? "unsupported-reason"
        : hasNoOutlineableRunOversizeMember
          ? "no-outlineable-run"
          : hasOversizeBundleMember || hasNonOversizeReason
            ? "single-instruction"
            : undefined;
    const hasInvalidFunctionFragmentSequence = source.includes(
      "SHERMES_INVALID_C_BUNDLE_FRAGMENT_SEQUENCE"
    );
    const hasBatchConcurrencyProbe = source.includes("SHERMES_BATCH_CONCURRENCY_PROBE");
    const hasFullSizedBundleMembers = source.includes("SHERMES_FULL_SIZED_C_BUNDLE_MEMBERS");
    const hasLargeCBundleMember = source.includes("SHERMES_LARGE_C_BUNDLE_MEMBER");
    const emitsOutlinedFunctionMembers =
      source.includes("SHERMES_OUTLINED_C_BUNDLE") ||
      hasInvalidFunctionFragmentSequence ||
      hasBatchConcurrencyProbe;
    const outlinedFunctionMembers = emitsOutlinedFunctionMembers
      ? Array.from({ length: 18 }, (_, index) => ({
          ...(hasCOptimizationLevelZeroMember && index === 0
            ? { cOptimizationLevel: 0 }
            : {}),
          contents:
            "/* outlined function zero part " +
            String(index) +
            (hasBatchConcurrencyProbe ? " SHERMES_BATCH_CONCURRENCY_PROBE" : "") +
            " */",
          firstFunctionId: 0,
          functionFragmentCount: 18,
          functionFragmentIndex:
            hasInvalidFunctionFragmentSequence && index === 1 ? 2 : index,
          functionCount: 1,
          lastFunctionId: 0,
          oversize: false,
          path: "functions-" + String(index).padStart(4, "0") + ".c",
          role: "function",
          targetBytes: 2097152,
        }))
      : [
          {
            contents:
              "/* function zero */" +
              (hasFullSizedBundleMembers ? "x".repeat(1100000) : ""),
            firstFunctionId: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2097152,
          },
          {
            contents:
              "/* function one */" +
              (hasLargeCBundleMember
                ? "x".repeat(${String(
                  convexWasmStaticHermesCBundleMemberCompilationPolicy.largeBundleFunction
                    .minimumTranslationUnitBytes
                )})
                : hasOversizeBundleMember
                ? "x".repeat(2097152)
                : hasFullSizedBundleMembers
                  ? "x".repeat(1100000)
                  : ""),
            ...(hasInvalidCOptimizationLevelMember
              ? { cOptimizationLevel: 1 }
              : hasCOptimizationLevelZeroMember || hasNoOutlineableRunOversizeMember
                ? { cOptimizationLevel: 0 }
                : {}),
            firstFunctionId: source.includes("SHERMES_INVALID_C_BUNDLE_FUNCTION_OVERLAP") ? 0 : 1,
            functionCount: source.includes("SHERMES_INVALID_C_BUNDLE_FUNCTION_OVERLAP") ? 2 : 1,
            lastFunctionId: 1,
            oversize: hasOversizeBundleMember || hasLargeCBundleMember,
            ...(hasLargeCBundleMember
              ? { oversizeReason: "single-instruction" }
              : oversizeReason === undefined
                ? {}
                : { oversizeReason }),
            path: "functions-0001.c",
            role: "function",
            targetBytes: 2097152,
          },
          ...(hasFullSizedBundleMembers
            ? [
                {
                  contents: "/* function two */" + "x".repeat(1100000),
                  firstFunctionId: 2,
                  functionCount: 1,
                  lastFunctionId: 2,
                  oversize: false,
                  path: "functions-0002.c",
                  role: "function",
                  targetBytes: 2097152,
                },
              ]
            : []),
        ];
    const bundleFiles = new Map([
      ["unit.h", "/* generated header */"],
      [
        "metadata.c",
        source.includes("SHERMES_RUNTIME_HEADER_MUTATION_PROBE")
          ? "/* SHERMES_RUNTIME_HEADER_MUTATION_PROBE */"
          : source.includes("SHERMES_PHYSICAL_CLOSURE_CHANGE")
            ? "/* SHERMES_PHYSICAL_CLOSURE_CHANGE " + sourceSha256 + " */"
            : "/* metadata */",
      ],
      ...outlinedFunctionMembers.map(({ contents, path }) => [path, contents]),
    ]);
    const members = [
      { path: "unit.h", role: "header" },
      { path: "metadata.c", role: "metadata" },
      ...outlinedFunctionMembers.map(({ contents: _, ...member }) => member),
    ].map((member) => {
      const contents = bundleFiles.get(member.path);
      return {
        ...member,
        sha256: createHash("sha256").update(contents).digest("hex"),
        size: Buffer.byteLength(contents),
      };
    });
    if (source.includes("SHERMES_MALFORMED_BUNDLE")) {
      members[3].sha256 = "f".repeat(64);
    }
    for (const [path, contents] of bundleFiles) writeFileSync(path, contents);
    writeFileSync(
      args[outputIndex + 1],
      JSON.stringify(canonicalValue({ header: members[0], kind: "static-hermes-c-bundle-v1", schemaVersion: 1, translationUnits: members.slice(1) })) + "\\n"
    );
    process.exit(0);
  }
}
if (${String(moduleGraphWasm)} && tool === "emcc" && args[outputIndex + 1] === "module.wasm" &&
    (args.includes("-sMAIN_MODULE=2") || args.includes("-sSIDE_MODULE=2"))) {
  const u32 = (value) => {
    const bytes = [];
    do {
      let byte = value & 0x7f;
      value >>>= 7;
      if (value !== 0) byte |= 0x80;
      bytes.push(byte);
    } while (value !== 0);
    return Buffer.from(bytes);
  };
  const string = (value) => {
    const bytes = Buffer.from(value);
    return Buffer.concat([u32(bytes.length), bytes]);
  };
  const vector = (values) => Buffer.concat([u32(values.length), ...values]);
  const section = (id, contents) => Buffer.concat([Buffer.from([id]), u32(contents.length), contents]);
  const main = args.includes("-sMAIN_MODULE=2");
  const memoryInfo = Buffer.concat([u32(main ? 0 : 16), u32(0), u32(main ? 0 : 1), u32(0)]);
  const dylink = section(0, Buffer.concat([
    string("dylink.0"), Buffer.from([1]), u32(memoryInfo.length), memoryInfo,
  ]));
  const type = section(1, vector([
    Buffer.concat([Buffer.from([0x60]), vector([]), vector([Buffer.from([0x7f])])]),
    Buffer.concat([Buffer.from([0x60]), vector([]), vector([])]),
  ]));
  const requested = args
    .filter((argument) => argument.startsWith("-Wl,--export="))
    .map((argument) => argument.slice("-Wl,--export=".length));
  const functionNames = [...new Set(requested.filter((name) =>
    !["memory", "__indirect_function_table", "__heap_base", "__c_longjmp"].includes(name)
  ))];
  const functions = section(3, vector(functionNames.map(() => u32(0))));
  const tables = main ? section(4, vector([Buffer.from([0x70, 0, 10])])) : Buffer.alloc(0);
  const memories = main ? section(5, vector([Buffer.from([0, 1])])) : Buffer.alloc(0);
  const globals = main
    ? section(6, vector([Buffer.concat([Buffer.from([0x7f, 0, 0x41]), u32(1024), Buffer.from([0x0b])])]))
    : Buffer.alloc(0);
  const exported = (name, kind, index) => Buffer.concat([string(name), Buffer.from([kind]), u32(index)]);
  const exportValues = functionNames.map((name, index) => exported(name, 0, index));
  if (main) {
    exportValues.push(
      exported("__indirect_function_table", 1, 0),
      exported("memory", 2, 0),
      exported("__heap_base", 3, 0),
      exported("__c_longjmp", 4, 0)
    );
  }
  const exports = section(7, vector(exportValues));
  const code = section(10, vector(functionNames.map(() => {
    const body = Buffer.from([0, 0x41, 1, 0x0b]);
    return Buffer.concat([u32(body.length), body]);
  })));
  const tags = main ? section(13, vector([Buffer.concat([Buffer.from([0]), u32(1)])])) : Buffer.alloc(0);
  const linkedInput = inputBytes.some((bytes) =>
    bytes.includes("SHERMES_PHYSICAL_CLOSURE_CHANGE")
  )
    ? section(0, Buffer.concat([
        string("fixture.linked-input"),
        createHash("sha256").update(JSON.stringify(args)).update(Buffer.concat(inputBytes)).digest(),
      ]))
    : Buffer.alloc(0);
  writeFileSync(args[outputIndex + 1], Buffer.concat([
    Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]), dylink, type, functions,
    tables, memories, globals, exports, code, tags, linkedInput,
  ]));
  process.exit(0);
}
const hash = createHash("sha256")
  .update(tool)
  .update(JSON.stringify(args))
  .update(Buffer.concat(inputBytes))
  .digest("hex");
writeFileSync(
  args[outputIndex + 1],
  args[outputIndex + 1] === "module.wasm"
    ? ${JSON.stringify(fakePrecompilerModule)} + "\\n// linked-input:" + hash + "\\n"
    : tool + ":" + hash
);
`;
  const shermes = join(toolDirectory, "shermes");
  const emcc = join(toolDirectory, "emcc");
  const wasmLd = join(toolDirectory, "wasm-ld");
  await Promise.all([
    writeExecutable(shermes, fakeToolSource),
    writeExecutable(emcc, fakeToolSource),
    writeExecutable(wasmLd, fakeToolSource),
  ]);
  const runtimeMainPath = join(root, "runtime_main.c");
  const runtimeArchive = join(root, "libhermesvm.a");
  await Promise.all([
    fs.writeFile(
      runtimeMainPath,
      "extern void *CONVEX_WASM_EXPORTED_UNIT(void); int convex_run(void) { return CONVEX_WASM_EXPORTED_UNIT() == 0; }\n"
    ),
    fs.writeFile(runtimeArchive, "runtime archive"),
  ]);
  const options = bindFixtureGuestSourceProvenance({
    cacheLayout: deriveConvexWasmCacheLayout({
      buildId: `fixture-${createHash("sha256").update(root).digest("hex").slice(0, 24)}`,
      cacheRoot,
      repositoryRoot: root,
      scope: "isolated-test",
    }),
    cacheRoot,
    command: {
      environment: {
        HOME: root,
        PATH: process.env.PATH,
      },
      maxOutputBytes: 64 * 1024,
      phaseTimeoutMs: 10_000,
      timeExecutable: "/usr/bin/time",
    },
    compiler: {
      admittedLanguageVersion: 29,
      compilerRevision: "compiler-fixture-1",
      loweringPipelineSha256: "3".repeat(64),
      sourcePipelineSha256: "4".repeat(64),
      staticHermesGlobalPolicy: convexWasmTargetRuntimeSurfacePolicyIdentity,
    },
    generatedJavaScript: "const answer = 40 + 2;\n",
    importedOperations: [],
    limits: {
      artifacts: {
        aotBytes: 1024 * 1024,
        generatedCBytes: 1024 * 1024,
        generatedJavaScriptBytes: 1024 * 1024,
        objectBytes: 1024 * 1024,
        wasmBytes: 1024 * 1024,
      },
      execution: {
        executionFuel: 2_000_000_000,
        maxGuestMemoryBytes: 32 * 1024 * 1024,
        maxHostOwnedBytes: 16 * 1024 * 1024,
        maxOperationCount: 10_000,
        maxResultBytes: 8 * 1024 * 1024,
        maxValueHandles: 1024,
        timeoutMilliseconds: 1000,
      },
    },
    opaqueValueAbiVersion: 3,
    platformLimits: {
      argumentBytes: 16 * 1024 * 1024,
      documentsRead: 32_000,
      documentsWritten: 16_000,
      executionTimeMs: 60_000,
      readBytes: 64 * 1024 * 1024,
      resultBytes: 16 * 1024 * 1024,
      scheduledArgumentBytes: 16 * 1024 * 1024,
      scheduledFunctions: 1_000,
      writeBytes: 64 * 1024 * 1024,
    },
    producerIdentity: await producerIdentityPromise,
    routingDecision: {
      decision: "wasm",
    },
    runtime: {
      archives: [runtimeArchive],
      compileFlags: ["-O2", "-DNDEBUG", "-fwasm-exceptions", "-sWASM_LEGACY_EXCEPTIONS=0"],
      includeDirectories: [includeDirectory],
      linkFlags: [
        "-O2",
        "--no-entry",
        "-fwasm-exceptions",
        "-sWASM_LEGACY_EXCEPTIONS=0",
        "-sSUPPORT_LONGJMP=wasm",
        "-sSTANDALONE_WASM=1",
        "-sALLOW_MEMORY_GROWTH=1",
        "-sSTACK_SIZE=512KB",
        "-Wl,--export=convex_run",
      ],
      mainCompileFlags: ["-DCONVEX_WASM_PERSIST_RUNTIME=1"],
      mainSourcePath: runtimeMainPath,
      materialInputs: [],
    },
    source: {
      exportName: "query",
      exportSha256: "4".repeat(64),
      modulePath: "convex/example.ts",
      resolvedGraphSha256: FIRST_GRAPH_FINGERPRINT,
      runtimeModulePath: "example.js",
      udfKind: "query",
    },
    toolchain: {
      emscripten: {
        executable: emcc,
        llvmRevision: "llvm-fixture-1",
        materialInputs: [{ label: "wasm-ld", path: wasmLd }],
        revision: "emscripten-fixture-1",
      },
      staticHermes: {
        executable: shermes,
        flags: [
          "-typed",
          "-O",
          "-Xenable-tdz",
          "-Xes6-block-scoping",
          "-emit-c",
          ...(staticHermesCBundle ? ["-Xemit-c-bundle", "-Xemit-c-shard-size=2097152"] : []),
        ],
        materialInputs: [],
        revision: "static-hermes-fixture-1",
      },
      wasmtime: {
        engineConfig: {
          consumeFuel: true,
          epochInterruption: true,
          profilingStrategy: "perf-map",
          wasmExceptions: true,
        },
        materialInputs: [],
        packageDirectory: precompilerPackage.packageDirectory,
        revision: precompilerPackage.manifest.identities.wasmtime.revision,
        target: {
          cpu: "baseline",
          triple:
            process.platform === "darwin"
              ? `${process.arch === "arm64" ? "aarch64" : "x86_64"}-apple-darwin`
              : `${process.arch === "arm64" ? "aarch64" : "x86_64"}-unknown-linux-gnu`,
        },
      },
    },
    valueMode: "opaque",
  });
  return { options, root, toolLog };
}

function contextReuseAnalysisIdentityFixture(entries) {
  const entryGraphs = entries
    .map((entry) =>
      typeof entry === "string"
        ? { dependencyGraphSha256: "a".repeat(64), entryPath: entry }
        : {
            dependencyGraphSha256: entry.localProfile.dependencyGraphSha256,
            entryPath: entry.entryPath,
          }
    )
    .sort((left, right) => left.entryPath.localeCompare(right.entryPath));
  const payload = {
    entries: entryGraphs.map(({ entryPath }) => entryPath),
    entryGraphSha256s: entryGraphs.map(({ dependencyGraphSha256 }) => dependencyGraphSha256),
    kind: "convex-context-reuse-cohort-analysis",
    policyFingerprint: fingerprintJson({ kind: "pipeline-context-reuse-fixture-policy-v1" }),
    sharedAnalysisSha256: fingerprintJson({ kind: "pipeline-context-reuse-fixture-shared-v1" }),
    thirdPartyMaterialFingerprints: {},
  };
  return authenticateConvexContextReuseCohortAnalysisIdentity({
    ...payload,
    resultSha256: fingerprintJson(payload),
  });
}

function canonicalVectorCorpusFixture(seed = "a") {
  return {
    kind: "convex-wasm-canonical-convex-value-vector-corpus-v1",
    producer: {
      kind: "convex-sdk-backend-canonical-value-producer-v1",
      sourceSha256: seed.repeat(64),
    },
    schemaVersion: 1,
    sha256: seed.repeat(64),
  };
}

function guestNativeValueCodecFixture(seed) {
  return { canonicalVectorCorpus: canonicalVectorCorpusFixture(seed) };
}

function requestEnvelopeVectorCorpusFixture(seed = "a") {
  return {
    kind: "convex-wasm-canonical-capability-request-envelope-vector-corpus-v4",
    producer: {
      kind: "convex-sdk-backend-capability-request-envelope-producer-v4",
      sourceSha256: seed.repeat(64),
    },
    schemaVersion: 1,
    sha256: seed.repeat(64),
  };
}

function requestEnvelopeFixture(seed) {
  return createConvexWasmCapabilityRequestEnvelopeInput({
    capabilityRequestAbiVersion: convexWasmCapabilityRequestAbiVersion,
    canonicalVectorCorpus: requestEnvelopeVectorCorpusFixture(seed),
  });
}

function capabilityEntryFixture() {
  const entryPath = "convex/sampleRoute.ts";
  const localProfile = {
    dependencyGraphSha256: "a".repeat(64),
    javascript: { sha256: "d".repeat(64), size: 1024 },
    metafileSha256: "e".repeat(64),
    sha256: "f".repeat(64),
    sourceMap: { sha256: "1".repeat(64), size: 2048 },
  };
  return {
    capabilityRequestAbiVersion: convexWasmCapabilityRequestAbiVersion,
    contextReuseAnalysis: contextReuseAnalysisIdentityFixture([{ entryPath, localProfile }]),
    invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
    localProfile,
    entryPath,
    modulePath: "sampleRoute",
    routes: [
      { exportName: "getStatus", udfKind: "query", visibility: "public" },
      {
        exportName: "observeScheduledExecution",
        udfKind: "mutation",
        visibility: "internal",
      },
    ],
    runtimeSurfacePolicySha256:
      convexWasmTargetRuntimeSurfacePolicyIdentity.runtimeSurfacePolicySha256,
  };
}

async function physicalChunkApplicationFixture(
  entries,
  {
    cOptimizationLevelZeroEntryPath,
    compactUnitCache,
    dependencyInputs,
    dependencyImporterEntryPath,
    dependencySource,
    rejectedEntryPath,
  } = {}
) {
  const esbuildFixture = {
    async transform(source) {
      return { code: source };
    },
    version: "pipeline-fixture-esbuild-1",
  };
  const sourceEnvelopeSha256 = "b".repeat(64);
  if (
    dependencyInputs !== undefined &&
    (dependencyImporterEntryPath !== undefined || dependencySource !== undefined)
  ) {
    throw new Error("pipeline physical chunk fixture dependency forms cannot be combined");
  }
  if (
    (dependencySource === undefined) !== (dependencyImporterEntryPath === undefined) ||
    (dependencyImporterEntryPath !== undefined &&
      !entries.some(({ entryPath }) => entryPath === dependencyImporterEntryPath))
  ) {
    throw new Error("pipeline physical chunk fixture dependency configuration is incomplete");
  }
  const dependencies =
    dependencyInputs ??
    (dependencySource === undefined
      ? []
      : [
          {
            importerEntryPath: dependencyImporterEntryPath,
            path: "_deps/pipeline-shared.js",
            source: dependencySource,
            variableName: "pipelineShared",
          },
        ]);
  if (
    !Array.isArray(dependencies) ||
    dependencies.some(
      ({ importerEntryPath, path, source, sourceMap }) =>
        typeof importerEntryPath !== "string" ||
        !entries.some(({ entryPath }) => entryPath === importerEntryPath) ||
        typeof path !== "string" ||
        typeof source !== "string" ||
        (sourceMap !== undefined && typeof sourceMap !== "string")
    ) ||
    new Set(dependencies.map(({ path }) => path)).size !== dependencies.length
  ) {
    throw new Error("pipeline physical chunk fixture dependency inputs are invalid");
  }
  const normalizedDependencies = dependencies.map((dependency, index) => {
    const sourceMap =
      dependency.sourceMap ??
      canonicalJson({ sources: [`../../${dependency.path}.ts`], version: 3 });
    const parsedSourceMap = JSON.parse(sourceMap);
    return {
      ...dependency,
      module: {
        identity: {
          environment: "isolate",
          moduleSha256: createHash("sha256")
            .update(dependency.source)
            .update(sourceMap)
            .digest("hex"),
          path: dependency.path,
          sourceMap: {
            sha256: createHash("sha256").update(sourceMap).digest("hex"),
            size: Buffer.byteLength(sourceMap),
            sourcesContentCount: Array.isArray(parsedSourceMap.sourcesContent)
              ? parsedSourceMap.sourcesContent.filter((source) => source !== null).length
              : 0,
            sourcesCount: parsedSourceMap.sources.length,
          },
          sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
            sourceRoot: parsedSourceMap.sourceRoot,
            sources: parsedSourceMap.sources,
          }),
          sourceSha256: createHash("sha256").update(dependency.source).digest("hex"),
          sourceSize: Buffer.byteLength(dependency.source),
        },
        source: dependency.source,
        sourceMap,
      },
      variableName: dependency.variableName ?? `pipelineShared${String(index)}`,
    };
  });
  const selections = entries.flatMap((entry) => {
    const entryModulePath = `${entry.modulePath}.js`;
    const entryDependencies = normalizedDependencies.filter(
      ({ importerEntryPath }) => entry.entryPath === importerEntryPath
    );
    const source =
      entry.entryPath === rejectedEntryPath
        ? "const SHERMES_FLOW_REJECT = 40 + 2;\nmodule.exports = {};\n"
        : `${entryDependencies
            .map(({ path, variableName }) => `const ${variableName} = require("./${path}");\n`)
            .join("")}${
            entry.entryPath === cOptimizationLevelZeroEntryPath
              ? "const SHERMES_C_OPTIMIZATION_LEVEL_ZERO_MEMBER = true;\n"
              : ""
          }module.exports = { ${entry.routes
            .map(({ exportName }) => `${exportName}: function () {}`)
            .join(", ")} };\n`;
    const sourceMap = canonicalJson({ sources: [`../../${entry.entryPath}`], version: 3 });
    const parsedSourceMap = JSON.parse(sourceMap);
    const moduleIdentity = {
      environment: "isolate",
      moduleSha256: createHash("sha256").update(source).update(sourceMap).digest("hex"),
      path: entryModulePath,
      sourceMap: {
        sha256: createHash("sha256").update(sourceMap).digest("hex"),
        size: Buffer.byteLength(sourceMap),
        sourcesContentCount: 0,
        sourcesCount: parsedSourceMap.sources.length,
      },
      sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
        sourceRoot: parsedSourceMap.sourceRoot,
        sources: parsedSourceMap.sources,
      }),
      sourceSha256: createHash("sha256").update(source).digest("hex"),
      sourceSize: Buffer.byteLength(source),
    };
    const imports = entryDependencies.map(({ path }) => ({
      external: false,
      importerPath: entryModulePath,
      kind: "import-statement",
      path,
    }));
    const modules = [
      { identity: moduleIdentity, source, sourceMap },
      ...entryDependencies.map(({ module }) => module),
    ];
    const closureIdentity = {
      entryModulePath,
      imports,
      kind: "pipeline-fixture-official-output-closure-v1",
      modules: modules.map(({ identity }) => identity),
    };
    return entry.routes.map((route) => ({
      closure: {
        identity: { ...closureIdentity, sha256: fingerprintJson(closureIdentity) },
        modules,
      },
      manifestMembership: {
        dependencyGraphSha256: entry.localProfile.dependencyGraphSha256,
        inventoryKind: "pipeline-fixture-inventory-v1",
        sourceEnvelopeSha256,
      },
      route: {
        entryPath: entry.entryPath,
        exportName: route.exportName,
        modulePath: entry.modulePath,
        runtimeModulePath: entryModulePath,
        udfKind: route.udfKind,
        visibility: route.visibility,
      },
      toolchain: { convex: "pipeline-fixture-convex-1", esbuild: esbuildFixture.version },
    }));
  });
  const authenticatedFixture = authenticateConvexWasmOfficialOutputSelectionFixtures(selections);
  const authenticatedSelections = authenticatedFixture.selections;
  const transformSession =
    compactUnitCache === undefined
      ? undefined
      : createConvexWasmOfficialOutputChunkTransformSession({
          esbuild: esbuildFixture,
          persistentCache: compactUnitCache,
        });
  const chunkUnits = await buildConvexWasmOfficialOutputChunkUnits({
    ...(compactUnitCache === undefined ? {} : { compactUnitAuthority: true }),
    esbuild: esbuildFixture,
    selections: authenticatedSelections,
    transformSession,
  });
  const applicationUnit = buildConvexWasmOfficialOutputChunkApplicationUnit({ chunkUnits });
  const profilesByPath = new Map(
    projectConvexWasmOfficialOutputChunkLocalProfiles(applicationUnit).map((profile) => [
      profile.identity.selectedEntry.entryPath,
      profile,
    ])
  );
  const boundEntriesWithoutContextReuse = entries.map((entry) => {
    const profile = profilesByPath.get(entry.entryPath);
    return {
      ...entry,
      localProfile: {
        dependencyGraphSha256: profile.identity.dependencyGraphSha256,
        javascript: profile.identity.output.javascript,
        metafileSha256: profile.identity.metafileSha256,
        sha256: profile.sha256,
        sourceMap: profile.identity.output.sourceMap,
      },
    };
  });
  const contextReuseAnalysis = contextReuseAnalysisIdentityFixture(boundEntriesWithoutContextReuse);
  const boundEntries = boundEntriesWithoutContextReuse.map((entry) => ({
    ...entry,
    contextReuseAnalysis,
  }));
  return {
    applicationUnit,
    descriptor: projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor(applicationUnit),
    entries: boundEntries,
    selections: authenticatedSelections,
    transformSession,
  };
}

function scheduledCohortEntriesForCompilerOutput(compilerOutput) {
  return compilerOutput.cohortContract.entries.map((entry) => {
    const namespace = {
      dependencyGraphSha256: entry.localProfile.dependencyGraphSha256,
      entryPath: entry.entryPath,
      modulePath: entry.modulePath,
      routes: compilerOutput.cohortContract.routes
        .filter((route) => route.entryId === entry.entryId)
        .map(({ exportName, udfKind, visibility }) => ({ exportName, udfKind, visibility })),
      runtimeModulePath: entry.source.runtimeModulePath,
    };
    return {
      entryId: fingerprintJson({
        ...namespace,
        domain: "convex-wasm-official-output-cohort-entry-v1",
      }),
      entryPath: entry.entryPath,
    };
  });
}

async function moduleGraphMaterialSessionInputFixture(fixture, entryPath, udfKind = "query") {
  const modulePath = basename(entryPath, ".ts");
  const entry = {
    ...capabilityEntryFixture(),
    entryPath,
    invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
    modulePath,
    routes: [{ exportName: "sharedHandler", udfKind, visibility: "public" }],
  };
  const physical = await physicalChunkApplicationFixture([entry]);
  const { applicationJavascript, bridgeJavascript, formatterJavascript } =
    renderNativeDbGetCapabilityTargetUnits({
      argumentFields: [],
      sdkPackageVersion: require("convex/package.json").version,
      compileProfileJavascript: `var __convexWasmCompileProfile = {
  sharedHandler: async () => ({ ok: true }),
};`,
    });
  const capabilityEntry = physical.entries[0];
  return bindFixtureGuestSourceProvenance({
    ...fixture.options,
    capabilityBridgeJavaScript: bridgeJavascript,
    capabilityChunkApplication: physical.descriptor,
    capabilityEntry,
    capabilityFormatterJavaScript: formatterJavascript,
    compiler: {
      ...fixture.options.compiler,
      sourcePipelineSha256: convexWasmCapabilitySourcePipelineSha256([
        capabilityEntry.localProfile,
      ]),
    },
    effectExecutionMode: "guest-promise-event-loop",
    generatedJavaScript: applicationJavascript,
    requestEnvelope: requestEnvelopeFixture(),
    source: {
      exportName: "sharedHandler",
      exportSha256: capabilityEntry.localProfile.javascript.sha256,
      modulePath: capabilityEntry.entryPath,
      resolvedGraphSha256: capabilityEntry.localProfile.dependencyGraphSha256,
      runtimeModulePath: `${capabilityEntry.modulePath}.js`,
      udfKind,
    },
    valueCodec: guestNativeValueCodecFixture(),
    valueMode: "guest-native-json",
  });
}


test("public artifact pipeline constructs and reuses a complete package", async (t) => {
  const fixture = await createFixture(t);
  const launchPolicy = { aggregateMemoryMaxBytes: 2 * 1024 * 1024 * 1024, aotWorkers: 1, jobs: 1 };
  fixture.options.resourceGuard = {
    kind: convexWasmBuildResourceGuardKind,
    launchPolicy,
    released: false,
    runCommand: runBoundedNativeCommand,
    describeTermination: describeNativeCommandTermination,
  };
  const first = await compileConvexWasmArtifact(fixture.options);
  const initialCommandCount = (await fs.readFile(fixture.toolLog, "utf8")).trim().split("\n").length;
  const second = await compileConvexWasmArtifact(fixture.options);
  assert.equal(first.buildReport.package.cache, "miss");
  assert.equal(second.buildReport.package.cache, "hit");
  assert.deepEqual(first.buildReport.phases.map(({ cache }) => cache), Array(6).fill("miss"));
  assert.deepEqual(second.buildReport.phases.map(({ cache }) => cache), Array(6).fill("hit"));
  assert.deepEqual(second.executionManifest, first.executionManifest);
  assert.equal(second.package.cacheKey, first.package.cacheKey);
  assert.equal((await fs.readFile(fixture.toolLog, "utf8")).trim().split("\n").length, initialCommandCount);
});

test("public artifact pipeline constructs a module-graph package with Core Wasm and AOT", async (t) => {
  const fixture = await createFixture(t, { moduleGraphWasm: true });
  const launchPolicy = { aggregateMemoryMaxBytes: 2 * 1024 * 1024 * 1024, aotWorkers: 1, jobs: 1 };
  fixture.options.resourceGuard = {
    kind: convexWasmBuildResourceGuardKind,
    launchPolicy,
    released: false,
    runCommand: runBoundedNativeCommand,
    describeTermination: describeNativeCommandTermination,
  };
  const options = await moduleGraphMaterialSessionInputFixture(fixture, "convex/sampleRoute.ts");
  const nativePhaseScheduler = createConvexWasmNativePhaseScheduler(launchPolicy);
  const session = await createConvexWasmCapabilityArtifactMaterialSession(options, {
    launchPolicy,
    nativePhaseScheduler,
  });
  const compilerOutput = await compileConvexWasmOfficialOutputModuleGraphInputsInMaterialSession(session, [options]);
  await finalizeConvexWasmArtifactMaterialSession(session);
  const entries = scheduledCohortEntriesForCompilerOutput(compilerOutput);
  const cohort = { cohortId: fingerprintJson({ entries }), entries };
  const artifact = await buildConvexWasmOfficialOutputModuleGraphArtifacts({
    artifactConfig: {
      cacheLayout: fixture.options.cacheLayout,
      cacheRoot: fixture.options.cacheRoot,
      producerIdentity: fixture.options.producerIdentity,
      resourceGuard: fixture.options.resourceGuard,
    },
    cohortSchedule: {
      cohorts: [cohort],
      identity: { sha256: fingerprintJson({ cohorts: [cohort], kind: "synthetic-schedule-v1" }) },
    },
    compilerOutputs: [compilerOutput],
    nativePhaseScheduler,
    async verifyDeploymentMaterials() {},
  });
  assert.equal(artifact.buildReport.package.cache, "miss");
  assert.ok(artifact.package.path);
  await artifact.verifyMaterials();
  const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout: fixture.options.cacheLayout,
    cacheRoot: fixture.options.cacheRoot,
    graphManifestSha256: artifact.graphManifest.graphManifestSha256,
    packagePath: artifact.package.path,
  });
  assert.equal(
    verified.graphManifest.graphManifestSha256,
    artifact.graphManifest.graphManifestSha256
  );
});

test("builds a module-graph package from a separate application's source graph", async (t) => {
  const fixture = await createFixture(t, { moduleGraphWasm: true });
  const application = await buildSyntheticDeploymentApplication(t);
  const launchPolicy = { aggregateMemoryMaxBytes: 2 * 1024 * 1024 * 1024, aotWorkers: 1, jobs: 1 };
  fixture.options.resourceGuard = {
    kind: convexWasmBuildResourceGuardKind,
    launchPolicy,
    released: false,
    runCommand: runBoundedNativeCommand,
    describeTermination: describeNativeCommandTermination,
  };
  const artifactConfig = {
    ...fixture.options,
    requestEnvelope: requestEnvelopeFixture(),
    valueCodec: guestNativeValueCodecFixture(),
  };
  const entryPath = "functions/read.ts";
  const contextReuseCohortPayload = {
    entries: [entryPath],
    entryGraphSha256s: [application.graphSession.dependencyGraphByEntry.get(entryPath).sha256],
    kind: "convex-context-reuse-cohort-analysis",
    policyFingerprint: application.graphSession.contextReuseAnalysisIdentity.policyFingerprint,
    sharedAnalysisSha256: application.graphSession.contextReuseAnalysisSharedIdentity.sha256,
    thirdPartyMaterialFingerprints:
      application.graphSession.contextReuseAnalysisThirdPartyMaterialFingerprints,
  };
  const contextReuseCohortIdentity = authenticateConvexContextReuseCohortAnalysisIdentity({
    ...contextReuseCohortPayload,
    resultSha256: fingerprintJson(contextReuseCohortPayload),
  });
  const prepared = await buildConvexWasmOfficialOutputModuleGraphInputs({
    applicationUnit: application.chunkApplicationUnit,
    artifactConfig,
    contextReuseAnalysisIdentity: contextReuseCohortIdentity,
    platformLimits: fixture.options.platformLimits,
    sdkPackageVersion: application.packageSet.convex.version,
  });
  const compilerOutput = prepared.compilerOutput;
  assert.equal(
    compilerOutput.cohortContract.entries[0].localProfile.dependencyGraphSha256,
    application.graphSession.dependencyGraphByEntry.get(entryPath).sha256
  );
  const entries = scheduledCohortEntriesForCompilerOutput(compilerOutput);
  const cohort = { cohortId: fingerprintJson({ entries }), entries };
  const nativePhaseScheduler = createConvexWasmNativePhaseScheduler(launchPolicy);
  const artifact = await buildConvexWasmOfficialOutputModuleGraphArtifacts({
    artifactConfig: {
      cacheLayout: fixture.options.cacheLayout,
      cacheRoot: fixture.options.cacheRoot,
      producerIdentity: fixture.options.producerIdentity,
      resourceGuard: fixture.options.resourceGuard,
    },
    cohortSchedule: {
      cohorts: [cohort],
      identity: { sha256: fingerprintJson({ cohorts: [cohort], kind: "synthetic-schedule-v1" }) },
    },
    compilerOutputs: [compilerOutput],
    nativePhaseScheduler,
    async verifyDeploymentMaterials() {
      await Promise.all([
        application.graphSession.verifyInputMaterials(),
        application.graphSession.verifyBundleInputMaterials(),
        application.graphSession.verifyGitSourceSnapshot(),
      ]);
    },
  });
  assert.equal(artifact.buildReport.package.cache, "miss");
  await artifact.verifyMaterials();
  const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout: fixture.options.cacheLayout,
    cacheRoot: fixture.options.cacheRoot,
    graphManifestSha256: artifact.graphManifest.graphManifestSha256,
    packagePath: artifact.package.path,
  });
  assert.equal(verified.graphManifest.graphManifestSha256, artifact.graphManifest.graphManifestSha256);
});

test("builds an authenticated project package from a separate application's staged source", async (t) => {
  const fixture = await createFixture(t, { moduleGraphWasm: true });
  const application = await buildSyntheticDeploymentApplication(t, { bindAnalysis: false });
  const launchPolicy = { aggregateMemoryMaxBytes: 2 * 1024 * 1024 * 1024, aotWorkers: 1, jobs: 1 };
  const resourceGuard = {
    kind: convexWasmBuildResourceGuardKind,
    launchPolicy,
    released: false,
    runCommand: runBoundedNativeCommand,
    describeTermination: describeNativeCommandTermination,
  };
  const built = await buildConvexWasmProjectPackage({
    config: { projectRoot: application.applicationRoot, selectedExports: ["read:read"] },
    inputs: {
      artifactConfig: fixture.options,
      buildDirectory: fixture.root,
      cacheLayout: fixture.options.cacheLayout,
      cacheRoot: fixture.options.cacheRoot,
      contextReuseAnalysis: application.analysis,
      graphSession: application.pendingGraph,
      inventory: application.inventory,
      platformLimits: fixture.options.platformLimits,
      producerIdentity: fixture.options.producerIdentity,
      requestEnvelope: requestEnvelopeFixture(),
      valueCodec: guestNativeValueCodecFixture(),
    },
    resourceGuard,
  });
  assert.equal(built.artifact.graphManifest.routing.cohortId, built.schedule.cohorts[0].cohortId);
  const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
    cacheLayout: fixture.options.cacheLayout,
    cacheRoot: fixture.options.cacheRoot,
    graphManifestSha256: built.artifact.graphManifest.graphManifestSha256,
    packagePath: built.artifact.package.path,
  });
  assert.equal(verified.graphManifest.graphManifestSha256, built.artifact.graphManifest.graphManifestSha256);
});
