import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeConvexWasmNativeMemberObjectWork,
  createConvexWasmNativeMemberObjectInput,
} from "./convex-wasm-native-duplicate-work.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmStaticHermesCBundleMemberCompilationPolicy,
  staticHermesCBundleMemberCompilationBaselinePolicy,
} from "./convex-wasm-static-hermes-c-bundle.mjs";

const sha256 = (digit) => digit.repeat(64);

function work(authenticatedInputValue, cache, timing, batch) {
  const member = { ...authenticatedInputValue.identity.generatedC.member };
  delete member.sha256;
  delete member.size;
  return {
    authenticatedInput: authenticatedInputValue,
    ...(batch === undefined ? {} : { batch }),
    cache,
    member,
    optimization: authenticatedInputValue.identity.compilation.optimization,
    stage: "module-graph-application-pic-object",
    timing,
  };
}

function memberIdentity(path = "functions-00000.c", memberSha256Digit = "6") {
  return {
    compilation: {
      arguments: ["-O2", "-c", path, "-o", "artifact.o"],
      executable: "/toolchain/emcc",
      memberCompilationPolicy: convexWasmStaticHermesCBundleMemberCompilationPolicy,
      optimization: "-O2",
    },
    emscripten: {
      llvmRevision: sha256("1"),
      materials: sha256("2"),
      revision: sha256("3"),
    },
    generatedC: {
      header: { path: "unit.h", role: "header", sha256: sha256("4"), size: 16 },
      member: {
        firstFunctionId: 0,
        functionCount: 1,
        lastFunctionId: 0,
        oversize: false,
        path,
        role: "function",
        sha256: sha256(memberSha256Digit),
        size: 32,
        targetBytes: 2_097_152,
      },
    },
    kind: "convex-wasm-static-hermes-c-bundle-member-object-v1",
    nativeArtifactIdentitySchemaVersion: 2,
    runtimeHeaders: sha256("5"),
    semanticEnvironment: { LANG: "C", LC_ALL: "C", SOURCE_DATE_EPOCH: "0", TZ: "UTC" },
  };
}

function inputForIdentity(identity) {
  return createConvexWasmNativeMemberObjectInput({
    cacheKey: fingerprintJson({
      identity,
      kind: "convex-wasm-artifact-pipeline-v9",
      stage: "static-hermes-c-bundle-member-object",
    }),
    identity,
    pipelineKind: "convex-wasm-artifact-pipeline-v9",
    stage: "static-hermes-c-bundle-member-object",
  });
}

test("reports only measured duplicate native member work with an authenticated input", () => {
  const input = inputForIdentity(memberIdentity());
  const report = analyzeConvexWasmNativeMemberObjectWork([
    work(input, "miss", {
      systemCpuMilliseconds: 10,
      userCpuMilliseconds: 90,
      wallMilliseconds: 100,
    }),
    work(input, "miss", {
      systemCpuMilliseconds: 20,
      userCpuMilliseconds: 120,
      wallMilliseconds: 150,
    }),
    work(input, "hit", null),
  ]);

  assert.equal(report.kind, "convex-wasm-native-member-duplicate-work-report-v2");
  assert.deepEqual(report.summary, {
    authenticatedInputCount: 1,
    cacheHitCount: 1,
    cacheMissCount: 2,
    nativeCompilationCount: 2,
    requestCount: 3,
  });
  assert.deepEqual(report.exactReusableNativeWorkCeiling, {
    nativeCompilationCount: 1,
    systemCpuMilliseconds: 20,
    userCpuMilliseconds: 120,
    wallMilliseconds: 150,
  });
});

test("counts each two-member process timing once", () => {
  const firstInput = inputForIdentity(memberIdentity());
  const secondInput = inputForIdentity(memberIdentity("functions-00001.c", "7"));
  const batch = {
    id: "0123456789abcdef0123456789abcdef",
    kind: "convex-wasm-native-member-batch-timing-v1",
    memberCacheKeys: [firstInput.cacheKey, secondInput.cacheKey].sort(),
    memberCount: 2,
    timing: { systemCpuMilliseconds: 10, userCpuMilliseconds: 90, wallMilliseconds: 100 },
  };
  const secondBatch = {
    ...batch,
    id: "fedcba9876543210fedcba9876543210",
    timing: { systemCpuMilliseconds: 20, userCpuMilliseconds: 120, wallMilliseconds: 150 },
  };
  const report = analyzeConvexWasmNativeMemberObjectWork([
    work(
      firstInput,
      "miss",
      { systemCpuMilliseconds: 10, userCpuMilliseconds: 90, wallMilliseconds: 100 },
      batch
    ),
    work(
      secondInput,
      "miss",
      { systemCpuMilliseconds: 10, userCpuMilliseconds: 90, wallMilliseconds: 100 },
      batch
    ),
    work(
      firstInput,
      "miss",
      { systemCpuMilliseconds: 20, userCpuMilliseconds: 120, wallMilliseconds: 150 },
      secondBatch
    ),
    work(secondInput, "hit", null, secondBatch),
  ]);

  assert.equal(report.summary.nativeCompilationCount, 2);
  assert.deepEqual(report.observedNativeWork, {
    systemCpuMilliseconds: 30,
    userCpuMilliseconds: 210,
    wallMilliseconds: 250,
  });
  assert.deepEqual(report.exactReusableNativeWorkCeiling, {
    nativeCompilationCount: 1,
    systemCpuMilliseconds: 20,
    userCpuMilliseconds: 120,
    wallMilliseconds: 150,
  });
  assert.deepEqual(report.duplicateGroups, [
    {
      authenticatedInputCacheKeys: batch.memberCacheKeys,
      nativeCompilationCount: 2,
      removable: report.exactReusableNativeWorkCeiling,
      requestCount: 4,
    },
  ]);
});

test("accepts at most four members in one native batch", () => {
  const inputs = [
    inputForIdentity(memberIdentity("functions-00000.c", "6")),
    inputForIdentity(memberIdentity("functions-00001.c", "7")),
    inputForIdentity(memberIdentity("functions-00002.c", "8")),
    inputForIdentity(memberIdentity("functions-00003.c", "9")),
    inputForIdentity(memberIdentity("functions-00004.c", "a")),
  ];
  const timing = { systemCpuMilliseconds: 10, userCpuMilliseconds: 90, wallMilliseconds: 100 };
  const batch = (memberInputs) => ({
    id: "0123456789abcdef0123456789abcdef",
    kind: "convex-wasm-native-member-batch-timing-v1",
    memberCacheKeys: memberInputs.map(({ cacheKey }) => cacheKey).sort(),
    memberCount: memberInputs.length,
    timing,
  });
  const fourMemberBatch = batch(inputs.slice(0, 4));
  const report = analyzeConvexWasmNativeMemberObjectWork(
    inputs.slice(0, 4).map((input) => work(input, "miss", timing, fourMemberBatch))
  );
  assert.equal(report.summary.nativeCompilationCount, 1);
  const fiveMemberBatch = batch(inputs);
  assert.throws(
    () =>
      analyzeConvexWasmNativeMemberObjectWork(
        inputs.map((input) => work(input, "miss", timing, fiveMemberBatch))
      ),
    /memberCount must be at most four/u
  );
});

test("rejects a member record whose cache key does not authenticate its content inputs", () => {
  assert.throws(
    () =>
      createConvexWasmNativeMemberObjectInput({
        cacheKey: sha256("f"),
        identity: memberIdentity(),
        pipelineKind: "convex-wasm-artifact-pipeline-v9",
        stage: "static-hermes-c-bundle-member-object",
      }),
    /does not authenticate/u
  );
});

test("accepts only exact current member policies and effective optimization arguments", () => {
  const baselineIdentity = memberIdentity();
  baselineIdentity.compilation = {
    ...baselineIdentity.compilation,
    arguments: ["-O2", "-c", "functions-00000.c", "-o", "artifact.o"],
    memberCompilationPolicy: staticHermesCBundleMemberCompilationBaselinePolicy,
    optimization: "-O2",
  };
  assert.doesNotThrow(() => inputForIdentity(baselineIdentity));

  const largeFunctionMemberIdentity = memberIdentity();
  largeFunctionMemberIdentity.generatedC.member.size =
    convexWasmStaticHermesCBundleMemberCompilationPolicy.largeFunctionMember.minimumMemberBytes;
  largeFunctionMemberIdentity.generatedC.member.oversize = true;
  largeFunctionMemberIdentity.generatedC.member.oversizeReason = "single-instruction";
  largeFunctionMemberIdentity.compilation.arguments[0] = "-Oz";
  largeFunctionMemberIdentity.compilation.optimization = "-Oz";
  assert.doesNotThrow(() => inputForIdentity(largeFunctionMemberIdentity));
  largeFunctionMemberIdentity.compilation.arguments[0] = "-O0";
  largeFunctionMemberIdentity.compilation.optimization = "-O0";
  assert.throws(
    () => inputForIdentity(largeFunctionMemberIdentity),
    /optimization is unsupported for its generated-C member/u
  );

  const explicitO0Identity = memberIdentity();
  explicitO0Identity.generatedC.member.cOptimizationLevel = 0;
  explicitO0Identity.compilation.arguments[0] = "-O0";
  explicitO0Identity.compilation.optimization = "-O0";
  assert.doesNotThrow(() => inputForIdentity(explicitO0Identity));

  const helperIdentity = memberIdentity();
  helperIdentity.generatedC.member.functionFragmentCount = 2;
  helperIdentity.generatedC.member.functionFragmentIndex = 1;
  assert.doesNotThrow(() => inputForIdentity(helperIdentity));

  const runtimePreludePchIdentity = memberIdentity();
  runtimePreludePchIdentity.compilation.arguments.splice(
    2,
    0,
    "-include-pch",
    "static-hermes-runtime-prelude.pch"
  );
  runtimePreludePchIdentity.runtimePreludePch = {
    cacheKey: sha256("a"),
    stage: "static-hermes-runtime-prelude-pch",
  };
  assert.doesNotThrow(() => inputForIdentity(runtimePreludePchIdentity));

  const unboundRuntimePreludePchIdentity = memberIdentity();
  unboundRuntimePreludePchIdentity.runtimePreludePch = runtimePreludePchIdentity.runtimePreludePch;
  assert.throws(
    () => inputForIdentity(unboundRuntimePreludePchIdentity),
    /runtimePreludePch does not match its compilation arguments/u
  );

  const changedPolicyIdentity = memberIdentity();
  changedPolicyIdentity.compilation.memberCompilationPolicy = {
    ...convexWasmStaticHermesCBundleMemberCompilationPolicy,
    largeFunctionMember: {
      ...convexWasmStaticHermesCBundleMemberCompilationPolicy.largeFunctionMember,
      minimumMemberBytes:
        convexWasmStaticHermesCBundleMemberCompilationPolicy.largeFunctionMember
          .minimumMemberBytes + 1,
    },
  };
  assert.throws(
    () => inputForIdentity(changedPolicyIdentity),
    /memberCompilationPolicy is unsupported/u
  );

  const mismatchedOptimizationIdentity = memberIdentity();
  mismatchedOptimizationIdentity.compilation.arguments[0] = "-O0";
  assert.throws(
    () => inputForIdentity(mismatchedOptimizationIdentity),
    /arguments and optimization disagree/u
  );

  const unsupportedOptimizationIdentity = memberIdentity();
  unsupportedOptimizationIdentity.compilation.arguments[0] = "-O1";
  unsupportedOptimizationIdentity.compilation.optimization = "-O1";
  assert.throws(
    () => inputForIdentity(unsupportedOptimizationIdentity),
    /optimization is unsupported for its generated-C member/u
  );

  const metadataAtO0Identity = memberIdentity("metadata.c");
  metadataAtO0Identity.generatedC.member = {
    path: "metadata.c",
    role: "metadata",
    sha256: sha256("6"),
    size: 32,
  };
  metadataAtO0Identity.compilation.arguments[0] = "-O0";
  metadataAtO0Identity.compilation.optimization = "-O0";
  assert.throws(
    () => inputForIdentity(metadataAtO0Identity),
    /optimization is unsupported for its generated-C member/u
  );

  const helperAtO0Identity = memberIdentity();
  helperAtO0Identity.generatedC.member.functionFragmentCount = 2;
  helperAtO0Identity.generatedC.member.functionFragmentIndex = 1;
  helperAtO0Identity.compilation.arguments[0] = "-O0";
  helperAtO0Identity.compilation.optimization = "-O0";
  assert.throws(
    () => inputForIdentity(helperAtO0Identity),
    /optimization is unsupported for its generated-C member/u
  );

  const explicitO0AtO2Identity = memberIdentity();
  explicitO0AtO2Identity.generatedC.member.cOptimizationLevel = 0;
  assert.throws(
    () => inputForIdentity(explicitO0AtO2Identity),
    /optimization is unsupported for its generated-C member/u
  );
});

test("rejects incomplete or inconsistent native batch evidence", () => {
  const firstInput = inputForIdentity(memberIdentity());
  const secondInput = inputForIdentity(memberIdentity("functions-00001.c", "7"));
  const batch = {
    id: "0123456789abcdef0123456789abcdef",
    kind: "convex-wasm-native-member-batch-timing-v1",
    memberCacheKeys: [firstInput.cacheKey, secondInput.cacheKey].sort(),
    memberCount: 2,
    timing: { systemCpuMilliseconds: 10, userCpuMilliseconds: 90, wallMilliseconds: 100 },
  };
  const timing = { systemCpuMilliseconds: 10, userCpuMilliseconds: 90, wallMilliseconds: 100 };

  assert.throws(
    () =>
      analyzeConvexWasmNativeMemberObjectWork([
        work(firstInput, "miss", timing, batch),
        work(firstInput, "miss", timing, batch),
      ]),
    /does not exactly cover its declared members/u
  );
  assert.throws(
    () =>
      analyzeConvexWasmNativeMemberObjectWork([
        { ...work(firstInput, "miss", timing), optimization: "-O0" },
      ]),
    /optimization disagrees with its authenticated compilation/u
  );
  assert.throws(
    () =>
      analyzeConvexWasmNativeMemberObjectWork([
        { ...work(firstInput, "miss", timing), member: { path: "other.c", role: "function" } },
      ]),
    /member disagrees with its authenticated generated-C input/u
  );
});
