#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { canonicalJson } from "./lib/convex-wasm-artifact-contract.mjs";
import { defaultConvexWasmCacheRoot, deriveConvexWasmCacheLayout } from "./lib/convex-wasm-cache-layout.mjs";
import {
  normalizeDeployedRuntimeAuthority,
  verifyFrozenGraphBindingRequestEvidence,
  verifyFrozenGraphBindingSourceEnvelope,
} from "./lib/convex-deployed-runtime-identity.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "./lib/convex-wasm-module-graph-package.mjs";
import {
  readConvexWasmPrivateEvidence,
  readConvexWasmPrivateEvidenceJson,
} from "./lib/convex-wasm-private-evidence.mjs";
import { parseProjectConfig } from "./lib/convex-wasm-project-build-inputs.mjs";
import {
  createRuntimeRegistryModuleGraphArtifacts,
  createRuntimeRegistryModuleGraphGeneration,
  createRuntimeRegistryModuleGraphRecord,
} from "./lib/runtime-registry-generation.mjs";
import { publishFreshRuntimeRegistry } from "./lib/runtime-registry-publication.mjs";

function parseArguments(argv) {
  const required = new Set([
    "--config",
    "--artifact-report",
    "--deployment",
    "--registry-root",
    "--publication",
    "--preflight-output",
  ]);
  const allowed = new Set([...required, "--source-package"]);
  if (argv.length % 2 !== 0) {
    throw new Error("usage: convex-wasm-publish-registry --config PROJECT.json --artifact-report REPORT.json --deployment DEPLOYMENT.json --registry-root NEW_DIRECTORY --publication primary|shadow-only --preflight-output PREFLIGHT.json [--source-package ARCHIVE.zip]");
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    if (!allowed.has(argv[index]) || values.has(argv[index]) || !argv[index + 1]) {
      throw new Error("invalid registry publication option");
    }
    values.set(argv[index], argv[index + 1]);
  }
  if ([...required].some((option) => !values.has(option))) {
    throw new Error("registry publication requires config, artifact report, deployment, target, policy, and preflight output");
  }
  if (!["primary", "shadow-only"].includes(values.get("--publication"))) {
    throw new Error("registry publication must be primary or shadow-only");
  }
  return Object.fromEntries(
    [...values].map(([option, value]) => [
      option,
      option === "--publication" ? value : resolve(value),
    ])
  );
}

export async function publishConvexWasmProjectRegistry({
  artifactReportPath,
  configPath,
  deploymentPath,
  publication,
  preflightOutputPath,
  registryRoot,
  sourcePackagePath,
}) {
  const config = parseProjectConfig(JSON.parse(await fs.readFile(configPath, "utf8")), configPath);
  const preflightParent = dirname(preflightOutputPath);
  const preflightParentState = await fs.lstat(preflightParent);
  if (
    !preflightParentState.isDirectory() ||
    preflightParentState.uid !== process.getuid() ||
    (preflightParentState.mode & 0o777) !== 0o700 ||
    (await fs.realpath(preflightParent)) !== preflightParent
  ) {
    throw new Error("registry preflight output parent must be a canonical current-user-owned mode-0700 directory");
  }
  try {
    await fs.lstat(preflightOutputPath);
    throw new Error("registry preflight output already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const report = (
    await readConvexWasmPrivateEvidenceJson(artifactReportPath, "project artifact report")
  ).value;
  if (
    report.kind !== "convex-wasm-project-artifact-report-v1" ||
    !Array.isArray(report.graphs) || report.graphs.length === 0 ||
    !Array.isArray(report.cohortContracts) || report.cohortContracts.length !== report.graphs.length ||
    report.sourceEnvelope?.path === undefined || report.startPush?.path === undefined
  ) {
    throw new Error("registry publication requires a complete project artifact report");
  }
  const sourceEnvelopeEvidence = await readConvexWasmPrivateEvidenceJson(
    report.sourceEnvelope.path,
    "project source envelope"
  );
  const startPushEvidence = await readConvexWasmPrivateEvidence(
    report.startPush.path,
    "project source request",
    256 * 1024 * 1024
  );
  for (const [actual, expected, description] of [
    [sourceEnvelopeEvidence, report.sourceEnvelope, "source envelope"],
    [startPushEvidence, report.startPush, "source request"],
  ]) {
    if (actual.sha256 !== expected.sha256 || actual.size !== expected.size) {
      throw new Error(`project ${description} differs from the artifact report`);
    }
  }
  const authority = normalizeDeployedRuntimeAuthority(
    (
      await readConvexWasmPrivateEvidenceJson(
        config.deployedRuntimeAuthorityPath ?? join(dirname(artifactReportPath), "source-authority.json"),
        "deployed-runtime authority"
      )
    ).value
  );
  if (authority.frozenGraphBinding === null) {
    throw new Error("registry publication requires frozen source-package authority");
  }
  verifyFrozenGraphBindingSourceEnvelope({
    normalizedAuthority: authority,
    sourceEnvelope: sourceEnvelopeEvidence.value,
    sourceEnvelopeFileSha256: sourceEnvelopeEvidence.sha256,
    sourceEnvelopeFileSize: sourceEnvelopeEvidence.size,
  });
  verifyFrozenGraphBindingRequestEvidence({
    normalizedAuthority: authority,
    requestBytes: startPushEvidence.bytes,
    requestEvidence: authority.frozenGraphBinding.inputAuthority.request,
  });
  const sourcePackage = await readConvexWasmPrivateEvidence(
    sourcePackagePath ?? join(dirname(artifactReportPath), "source-package.zip"),
    "frozen source package",
    256 * 1024 * 1024
  );
  if (
    authority.sourcePackageFileSha256.size !== 1 ||
    !authority.sourcePackageFileSha256.has(sourcePackage.sha256)
  ) {
    throw new Error("source-package bytes differ from the frozen authority");
  }
  const cacheRoot = config.artifactCacheRoot ?? defaultConvexWasmCacheRoot();
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "registry-publication",
    cacheRoot,
    repositoryRoot: config.projectRoot,
  });
  const moduleGraphs = [];
  for (const graph of report.graphs) {
    const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
      cacheLayout,
      cacheRoot,
      graphManifestSha256: graph.graphManifestSha256,
      packagePath: graph.packagePath,
    });
    moduleGraphs.push({
      cacheLayout,
      ...createRuntimeRegistryModuleGraphRecord(verified, cacheLayout),
    });
  }
  const deployment = await readConvexWasmPrivateEvidence(
    deploymentPath,
    "bound deployment manifest",
    16 * 1024 * 1024
  );
  const artifacts = createRuntimeRegistryModuleGraphArtifacts(deployment.bytes, {
    cohortContracts: report.cohortContracts,
    cohortSchedule: report.cohortSchedule,
    graphManifests: moduleGraphs.map(({ graphManifest }) => graphManifest),
    sourceEnvelope: sourceEnvelopeEvidence.value,
    sourceEnvelopeFileSha256: sourceEnvelopeEvidence.sha256,
    sourceEnvelopeFileSize: sourceEnvelopeEvidence.size,
  });
  for (const runtimeModulePath of new Set(
    artifacts.activationRouteScope.map((route) => route.runtimeModulePath)
  )) {
    const module = authority.modulesByPath.get(runtimeModulePath);
    if (
      module?.sourcePackageRuntimeContentSha256 !==
        artifacts.sourcePackageRuntimeContentSha256 ||
      module.sourcePackageSha256 !== sourcePackage.sha256
    ) {
      throw new Error("selected runtime module differs from the frozen source package");
    }
  }
  const generation = createRuntimeRegistryModuleGraphGeneration(artifacts, moduleGraphs, publication);
  const { preflight, ...published } = await publishFreshRuntimeRegistry({
    artifacts,
    deploymentBytes: deployment.bytes,
    generation,
    moduleGraphs,
    registryRoot,
  });
  await fs.writeFile(preflightOutputPath, `${canonicalJson(preflight)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return { ...published, preflight: preflightOutputPath };
}

if (import.meta.main) {
  const values = parseArguments(process.argv.slice(2));
  const result = await publishConvexWasmProjectRegistry({
    artifactReportPath: values["--artifact-report"],
    configPath: values["--config"],
    deploymentPath: values["--deployment"],
    publication: values["--publication"],
    preflightOutputPath: values["--preflight-output"],
    registryRoot: values["--registry-root"],
    sourcePackagePath: values["--source-package"],
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}
