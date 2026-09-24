#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { resolve } from "node:path";

import { canonicalJson, convexWasmBuildResourceGuardKind } from "./lib/convex-wasm-artifact-pipeline.mjs";
import { describeNativeCommandTermination, runBoundedNativeCommand } from "./lib/bounded-native-command.mjs";
import {
  parseProjectConfig,
  prepareConvexWasmProjectBuildInputs,
} from "./lib/convex-wasm-project-build-inputs.mjs";
import { buildConvexWasmProjectPackage } from "./lib/convex-wasm-project-package.mjs";
import { createConvexWasmProjectStartPush } from "./lib/convex-wasm-project-start-push.mjs";
import { normalizeConvexWasmNativeLaunchPolicy } from "./lib/convex-wasm-native-launch-scheduling.mjs";

export async function buildConvexWasmFromProjectConfig(config, { signal } = {}) {
  const inputs = await prepareConvexWasmProjectBuildInputs(config, { signal });
  const aggregateMemoryMaxBytes = config.memoryMaxMiB * 1024 * 1024;
  if (!Number.isSafeInteger(aggregateMemoryMaxBytes)) {
    throw new Error("memoryMaxMiB exceeds the supported byte limit");
  }
  const resourceGuard = {
    kind: convexWasmBuildResourceGuardKind,
    launchPolicy: normalizeConvexWasmNativeLaunchPolicy({
      aggregateMemoryMaxBytes,
      aotWorkers: config.aotWorkers,
      jobs: config.jobs,
    }),
    released: false,
    runCommand: runBoundedNativeCommand,
    describeTermination: describeNativeCommandTermination,
  };
  try {
    const built = await buildConvexWasmProjectPackage({ config, inputs, resourceGuard });
    const startPush = await createConvexWasmProjectStartPush({
      buildDirectory: inputs.buildDirectory,
      projectRoot: config.projectRoot,
      signal,
    });
    const artifacts = built.artifact.artifacts ?? [built.artifact];
    const runtimeModules = [
      ...new Set(built.sourceEnvelope.selectedRoutes.map(({ runtimeModulePath }) => runtimeModulePath)),
    ]
      .sort()
      .map((path) => {
        const module = built.graphSession.bundleModulesByPath.get(path);
        if (module === undefined) {
          throw new Error(`selected runtime module ${path} is missing from the authenticated graph`);
        }
        return { ...module };
      });
    const report = {
      cohortContracts: built.cohortContracts,
      cohortSchedule: built.schedule,
      contextReusePolicy: built.graphSession.contextReusePolicy,
      graphs: artifacts.map(({ graphManifest, package: packageRecord }) => ({
        graphManifestSha256: graphManifest.graphManifestSha256,
        packagePath: packageRecord.path,
      })),
      kind: "convex-wasm-project-artifact-report-v1",
      runtimeModules,
      scheduleSha256: built.schedule.identity.sha256,
      sourceEnvelope: built.sourceEnvelopePublication.file,
      startPush,
    };
    const reportPath = resolve(inputs.buildDirectory, "artifact-report.json");
    await fs.writeFile(reportPath, `${canonicalJson(report)}\n`, { flag: "wx", mode: 0o600 });
    return { report, reportPath };
  } finally {
    resourceGuard.released = true;
  }
}

export async function main(argumentsList) {
  if (argumentsList.length !== 2 || argumentsList[0] !== "--config") {
    throw new Error("usage: convex-wasm-build --config PROJECT.json");
  }
  const configPath = resolve(argumentsList[1]);
  const config = parseProjectConfig(JSON.parse(await fs.readFile(configPath, "utf8")), configPath);
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    const result = await buildConvexWasmFromProjectConfig(config, { signal: cancellation.signal });
    process.stdout.write(`${canonicalJson({ artifactReport: result.reportPath })}\n`);
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
  }
}

if (import.meta.main) {
  await main(process.argv.slice(2));
}
