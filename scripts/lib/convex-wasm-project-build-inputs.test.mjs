import assert from "node:assert/strict";
import test from "node:test";

import {
  bundledNativeReleaseSelectionPath,
  defaultNativePackageCacheRoot,
} from "../acquire-convex-wasm-native-release.mjs";
import { parseProjectConfig } from "./convex-wasm-project-build-inputs.mjs";

const configPath = "/project/config/wasm.json";

function projectConfig() {
  return {
    gatePolicy: "./gate-policy.json",
    gateRoot: "../gate",
    jobs: 1,
    aotWorkers: 1,
    memoryMaxMiB: 2048,
    matrixReports: { codec: "./codec.json", request: "./request.json" },
    nativePackageCacheRoot: "../native-cache",
    nativeReleaseSelection: "./native-release.json",
    projectRoot: "..",
    schemaVersion: 1,
    selectedExports: ["items/read:get", "items/write:put"],
    sourcePathspecs: ["convex.json", "functions", "shared"],
    sourceRoots: ["shared/"],
    workRoot: "../work",
  };
}

test("project build inputs resolve a selected release and staged source authority", () => {
  const config = projectConfig();
  config.sourceAuthority = {
    backendImageId: `sha256:${"a".repeat(64)}`,
    helper: "../backend/source-authority",
    producerCertificate: "./producer.json",
  };
  const parsed = parseProjectConfig(config, configPath);
  assert.equal(parsed.projectRoot, "/project");
  assert.equal(parsed.gatePolicyPath, "/project/config/gate-policy.json");
  assert.equal(parsed.nativeReleaseSelectionPath, "/project/config/native-release.json");
  assert.equal(parsed.nativePackageCacheRoot, "/project/native-cache");
  assert.deepEqual(parsed.selectedExports, ["items/read:get", "items/write:put"]);
  assert.deepEqual(parsed.sourcePathspecs, ["convex.json", "functions", "shared"]);
  assert.deepEqual(parsed.sourceAuthority, {
    backendImageId: `sha256:${"a".repeat(64)}`,
    helperPath: "/project/backend/source-authority",
    producerCertificatePath: "/project/config/producer.json",
    analysisEnvironmentPath: undefined,
    externalDepsPackagePath: undefined,
    targetExternalDepsPackagePath: undefined,
  });
  config.sourceAuthority.analysisEnvironment = "./analysis-environment.json";
  assert.equal(
    parseProjectConfig(config, configPath).sourceAuthority.analysisEnvironmentPath,
    "/project/config/analysis-environment.json"
  );
  config.sourceAuthority.allowNodeDependencyEgress = true;
  assert.equal(
    parseProjectConfig(config, configPath).sourceAuthority.allowNodeDependencyEgress,
    true
  );
  config.sourceAuthority.allowNodeDependencyEgress = "true";
  assert.throws(
    () => parseProjectConfig(config, configPath),
    /sourceAuthority.allowNodeDependencyEgress must be a boolean/u
  );
});

test("project build inputs require one native package source and staged paths", () => {
  const direct = projectConfig();
  delete direct.nativeReleaseSelection;
  delete direct.nativePackageCacheRoot;
  direct.compilerPackage = "./compiler";
  direct.precompilerPackage = "./precompiler";
  assert.equal(parseProjectConfig(direct, configPath).compilerPackage, "/project/config/compiler");
  assert.throws(
    () => parseProjectConfig({ ...direct, nativeReleaseSelection: "./native-release.json" }, configPath),
    /configure a native release selection or both native package directories/u
  );
  assert.throws(
    () => parseProjectConfig({ ...direct, sourcePathspecs: [] }, configPath),
    /sourcePathspecs must contain staged Git paths/u
  );
});

test("released project build uses its bundled native selection by default", () => {
  const config = projectConfig();
  delete config.nativeReleaseSelection;
  delete config.nativePackageCacheRoot;
  const parsed = parseProjectConfig(config, configPath);
  assert.equal(parsed.nativeReleaseSelectionPath, bundledNativeReleaseSelectionPath);
  assert.equal(parsed.nativePackageCacheRoot, defaultNativePackageCacheRoot());
});

test("project matrix tools use the gate-owned Wasmtime runner", () => {
  const config = projectConfig();
  delete config.matrixReports;
  config.matrixTools = { cxx: "../toolchain/c++" };
  const parsed = parseProjectConfig(config, configPath);
  assert.deepEqual(parsed.matrixTools, {
    cxx: "/project/toolchain/c++",
    runner: "/project/gate/bin/convex-wasm-wasmtime-runner",
  });
});
