#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  bindDeployedRuntimeIdentity,
  normalizeDeployedRuntimeAuthority,
  verifyFrozenGraphBindingRequestEvidence,
  verifyFrozenGraphBindingSourceEnvelope,
} from "./lib/convex-deployed-runtime-identity.mjs";
import {
  defaultConvexWasmCacheRoot,
  deriveConvexWasmCacheLayout,
} from "./lib/convex-wasm-cache-layout.mjs";
import {
  bindConvexWasmModuleGraphsToDeploymentManifest,
  validateConvexWasmModuleGraphDeploymentManifest,
} from "./lib/convex-wasm-module-graph-deployment-binding.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "./lib/convex-wasm-module-graph-package.mjs";
import {
  readConvexWasmPrivateEvidence,
  readConvexWasmPrivateEvidenceJson,
} from "./lib/convex-wasm-private-evidence.mjs";
import { parseProjectConfig } from "./lib/convex-wasm-project-build-inputs.mjs";
import { createConvexWasmModuleGraphDeploymentInputManifest } from "./lib/convex-wasm-project-deployment-manifest.mjs";

function parseArguments(argumentsList) {
  const required = new Set([
    "--config",
    "--artifact-report",
    "--output",
  ]);
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !required.has(option) ||
      typeof value !== "string" ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error(
        "usage: convex-wasm-bind --config PROJECT.json --artifact-report REPORT.json --output DEPLOYMENT_V8.json"
      );
    }
    values.set(option, resolve(value));
  }
  if (values.size !== required.size) {
    throw new Error("bind-convex-wasm requires config, artifact report, and output paths");
  }
  return Object.fromEntries(values);
}

export async function bindConvexWasmProjectBuild({
  configPath,
  artifactReportPath,
  outputPath,
}) {
  const config = parseProjectConfig(
    JSON.parse(await fs.readFile(configPath, "utf8")),
    configPath
  );
  if (config.deployedRuntimeAuthorityPath === undefined && config.sourceAuthority === undefined) {
    throw new Error("project binding requires deployedRuntimeAuthority or sourceAuthority in the project config");
  }
  const report = (
    await readConvexWasmPrivateEvidenceJson(artifactReportPath, "project artifact report")
  ).value;
  if (
    report.kind !== "convex-wasm-project-artifact-report-v1" ||
    !Array.isArray(report.graphs) ||
    report.graphs.length === 0 ||
    !Array.isArray(report.cohortContracts) ||
    report.cohortContracts.length !== report.graphs.length ||
    !Array.isArray(report.runtimeModules) ||
    report.runtimeModules.length === 0 ||
    report.contextReusePolicy === undefined ||
    report.startPush?.path === undefined ||
    report.cohortSchedule?.identity?.sha256 !== report.scheduleSha256
  ) {
    throw new Error("project artifact report lacks complete authenticated graph binding inputs");
  }
  const sourceEnvelopeEvidence = await readConvexWasmPrivateEvidenceJson(
    report.sourceEnvelope?.path,
    "project source envelope"
  );
  if (
    sourceEnvelopeEvidence.sha256 !== report.sourceEnvelope.sha256 ||
    sourceEnvelopeEvidence.size !== report.sourceEnvelope.size
  ) {
    throw new Error("project source envelope differs from the artifact report");
  }
  const cacheRoot = config.artifactCacheRoot ?? defaultConvexWasmCacheRoot();
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "deployment-binding",
    cacheRoot,
    repositoryRoot: config.projectRoot,
  });
  const graphManifests = await Promise.all(
    report.graphs.map(async ({ graphManifestSha256, packagePath }) => {
      const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
        cacheLayout,
        cacheRoot,
        graphManifestSha256,
        packagePath,
      });
      return verified.graphManifest;
    })
  );
  const authority = normalizeDeployedRuntimeAuthority(
    (
      await readConvexWasmPrivateEvidenceJson(
        config.deployedRuntimeAuthorityPath ?? join(dirname(artifactReportPath), "source-authority.json"),
        "deployed-runtime authority"
      )
    ).value
  );
  verifyFrozenGraphBindingSourceEnvelope({
    normalizedAuthority: authority,
    sourceEnvelope: sourceEnvelopeEvidence.value,
    sourceEnvelopeFileSha256: sourceEnvelopeEvidence.sha256,
    sourceEnvelopeFileSize: sourceEnvelopeEvidence.size,
  });
  if (authority.frozenGraphBinding === null) {
    throw new Error("project binding requires frozen source-package authority");
  }
  const startPushEvidence = await readConvexWasmPrivateEvidence(
    report.startPush.path,
    "project source request",
    256 * 1024 * 1024
  );
  if (
    startPushEvidence.sha256 !== report.startPush.sha256 ||
    startPushEvidence.size !== report.startPush.size
  ) {
    throw new Error("project source request differs from the artifact report");
  }
  verifyFrozenGraphBindingRequestEvidence({
    normalizedAuthority: authority,
    requestBytes: startPushEvidence.bytes,
    requestEvidence: authority.frozenGraphBinding.inputAuthority.request,
  });
  const runtimeModules = new Map(report.runtimeModules.map((module) => [module.path, module]));
  if (runtimeModules.size !== report.runtimeModules.length) {
    throw new Error("project artifact report repeats selected runtime modules");
  }
  const deployedRuntimeBindings = new Map();
  for (const { runtimeModulePath } of sourceEnvelopeEvidence.value.selectedRoutes) {
    if (deployedRuntimeBindings.has(runtimeModulePath)) continue;
    const bundleModule = runtimeModules.get(runtimeModulePath);
    const binding = bindDeployedRuntimeIdentity({
      authority,
      bundleModule,
      runtimeModulePath,
    });
    if (binding.identity === null) {
      throw new Error(`selected route ${runtimeModulePath} lacks matching deployed-runtime identity: ${canonicalJson(binding.diagnostic)}`);
    }
    deployedRuntimeBindings.set(runtimeModulePath, binding);
  }
  const deploymentManifest = createConvexWasmModuleGraphDeploymentInputManifest({
    baseManifest: sourceEnvelopeEvidence.value,
    cohortContracts: report.cohortContracts,
    contextReusePolicy: report.contextReusePolicy,
    deployedRuntimeBindings,
    frozenGraphBindingIdentity: authority.frozenGraphBindingIdentity,
    selectedSourceEnvelopeIdentity: {
      kind: sourceEnvelopeEvidence.value.kind,
      sha256: sourceEnvelopeEvidence.value.sourceEnvelopeSha256,
    },
  });
  const options = {
    cohortContracts: report.cohortContracts,
    cohortSchedule: report.cohortSchedule,
    deploymentManifest,
    graphManifests,
    sourceEnvelope: sourceEnvelopeEvidence.value,
    sourceEnvelopeFileSha256: sourceEnvelopeEvidence.sha256,
    sourceEnvelopeFileSize: sourceEnvelopeEvidence.size,
  };
  const bound = bindConvexWasmModuleGraphsToDeploymentManifest(options);
  validateConvexWasmModuleGraphDeploymentManifest({ ...options, deploymentManifest: bound });
  const parent = dirname(outputPath);
  const status = await fs.lstat(parent);
  if (
    !status.isDirectory() ||
    (await fs.realpath(parent)) !== parent ||
    (status.mode & 0o777) !== 0o700
  ) {
    throw new Error("deployment output parent must be a canonical mode-0700 directory");
  }
  await fs.writeFile(outputPath, `${canonicalJson(bound)}\n`, { flag: "wx", mode: 0o600 });
  return { deploymentManifest: outputPath, deploymentSha256: bound.deploymentSha256 };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const values = parseArguments(process.argv.slice(2));
  const result = await bindConvexWasmProjectBuild({
    configPath: values["--config"],
    artifactReportPath: values["--artifact-report"],
    outputPath: values["--output"],
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}
