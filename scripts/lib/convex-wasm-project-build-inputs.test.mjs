import assert from "node:assert/strict";
import test from "node:test";

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
  const parsed = parseProjectConfig(projectConfig(), configPath);
  assert.equal(parsed.projectRoot, "/project");
  assert.equal(parsed.gatePolicyPath, "/project/config/gate-policy.json");
  assert.equal(parsed.nativeReleaseSelectionPath, "/project/config/native-release.json");
  assert.equal(parsed.nativePackageCacheRoot, "/project/native-cache");
  assert.deepEqual(parsed.selectedExports, ["items/read:get", "items/write:put"]);
  assert.deepEqual(parsed.sourcePathspecs, ["convex.json", "functions", "shared"]);
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
