#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { canonicalJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  MAX_ANALYSIS_ENVIRONMENT_BYTES,
  parseSyntheticAnalysisEnvironment,
} from "./lib/convex-wasm-analysis-environment.mjs";
import { defaultConvexWasmCacheRoot } from "./lib/convex-wasm-cache-layout.mjs";
import {
  readConvexWasmPrivateEvidence,
  readConvexWasmPrivateEvidenceJson,
} from "./lib/convex-wasm-private-evidence.mjs";
import { parseProjectConfig } from "./lib/convex-wasm-project-build-inputs.mjs";
import { ensureRuntimeContentHelper } from "./backend-report.mjs";
import {
  createPreactivationRuntimeAuthority,
  convexRuntimeContentAlgorithm,
  executeRuntimeContentHelperInBackendImage,
  inspectRuntimeContentHelper,
} from "./lib/convex-wasm-preactivation-runtime-authority.mjs";
import {
  createRuntimeContentProducerCacheIdentity,
  publishRuntimeContentProducerCertificate,
  validateProducerCertificate,
} from "./lib/source-authority-cache.mjs";
import { certifyRuntimeContentProducer } from "./lib/source-producer-conformance.mjs";

async function writeProducerCertificate(path, certificate) {
  const directory = dirname(path);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const [status, realPath] = await Promise.all([fs.lstat(directory), fs.realpath(directory)]);
  if (
    !status.isDirectory() ||
    status.uid !== process.getuid() ||
    (status.mode & 0o777) !== 0o700 ||
    realPath !== directory
  ) {
    throw new Error("producer certificate directory must be a canonical current-user-owned mode-0700 directory");
  }
  const { cache: ignoredCache, cacheKey: ignoredCacheKey, ...payload } = certificate;
  validateProducerCertificate(payload, certificate.identity, certificate.externalDepsPackage);
  const bytes = Buffer.from(`${canonicalJson(payload)}\n`);
  const temporaryPath = join(directory, `.producer-certificate-${randomBytes(8).toString("hex")}`);
  try {
    const handle = await fs.open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporaryPath, path);
    const directoryHandle = await fs.open(directory, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } finally {
    await fs.rm(temporaryPath, { force: true });
  }
  const written = await readConvexWasmPrivateEvidenceJson(
    path,
    "source-package producer certificate"
  );
  validateProducerCertificate(
    written.value,
    certificate.identity,
    certificate.externalDepsPackage
  );
}

export async function createConvexWasmProjectAuthority({ configPath, artifactReportPath, backendReportPath }) {
  const config = parseProjectConfig(JSON.parse(await fs.readFile(configPath, "utf8")), configPath);
  if (config.sourceAuthority === undefined) {
    throw new Error("project source authority requires sourceAuthority in the project config");
  }
  const report = (
    await readConvexWasmPrivateEvidenceJson(artifactReportPath, "project artifact report")
  ).value;
  if (
    report.kind !== "convex-wasm-project-artifact-report-v1" ||
    report.sourceEnvelope?.path === undefined ||
    report.startPush?.path === undefined
  ) {
    throw new Error("project artifact report lacks source-authority inputs");
  }
  const buildDirectory = dirname(artifactReportPath);
  const [sourceEnvelope, startPush, helper, targetExternalDepsPackage] =
    await Promise.all([
      readConvexWasmPrivateEvidenceJson(report.sourceEnvelope.path, "project source envelope"),
      readConvexWasmPrivateEvidence(report.startPush.path, "project source request", 256 * 1024 * 1024),
      inspectRuntimeContentHelper(config.sourceAuthority.helperPath),
      config.sourceAuthority.targetExternalDepsPackagePath === undefined
        ? Promise.resolve(undefined)
        : readConvexWasmPrivateEvidenceJson(
            config.sourceAuthority.targetExternalDepsPackagePath,
            "target external dependency package"
          ),
    ]);
  for (const [actual, expected, description] of [
    [sourceEnvelope, report.sourceEnvelope, "project source envelope"],
    [startPush, report.startPush, "project source request"],
  ]) {
    if (actual.sha256 !== expected.sha256 || actual.size !== expected.size) {
      throw new Error(`${description} differs from the artifact report`);
    }
  }
  const request = JSON.parse(startPush.bytes.toString("utf8"));
  if (!Array.isArray(request.nodeDependencies)) {
    throw new Error("project source request lacks Node dependency declarations");
  }
  if (request.nodeDependencies.length === 0 && config.sourceAuthority.externalDepsPackagePath !== undefined) {
    throw new Error("an external dependency output was configured without Node dependencies");
  }
  const externalDepsPackagePath = request.nodeDependencies.length === 0
    ? undefined
    : (config.sourceAuthority.externalDepsPackagePath ?? join(buildDirectory, "external-deps-package.zip"));
  const externalDepsPackage = externalDepsPackagePath === undefined
    ? null
    : await readConvexWasmPrivateEvidence(
        externalDepsPackagePath,
        "source-package external dependencies",
        256 * 1024 * 1024
      );
  const producerIdentity = createRuntimeContentProducerCacheIdentity({
    backendImageId: config.sourceAuthority.backendImageId,
    dependencies: request.nodeDependencies.map(({ name, version }) => ({ package: name, version })),
    helper: { sha256: helper.sha256, size: helper.size },
    runtimeContentAlgorithm: convexRuntimeContentAlgorithm,
  });
  const status = await fs.lstat(buildDirectory);
  if (
    !status.isDirectory() ||
    (await fs.realpath(buildDirectory)) !== buildDirectory ||
    (status.mode & 0o777) !== 0o700 ||
    status.uid !== process.getuid()
  ) {
    throw new Error("project build directory must be a canonical current-user-owned mode-0700 directory");
  }
  let createAuthority = createPreactivationRuntimeAuthority;
  if (process.platform === "darwin") {
    const scratch = await fs.mkdtemp(join(buildDirectory, ".image-helper-"));
    try {
      const imageHelper = await ensureRuntimeContentHelper({
        backendImageId: config.sourceAuthority.backendImageId,
        buildDirectory,
        helperPath: join(scratch, "source-package-helper"),
      });
      if (imageHelper.sha256 !== helper.sha256 || imageHelper.size !== helper.size) {
        throw new Error("configured source-package helper differs from the backend image");
      }
    } finally {
      await fs.rm(scratch, { force: true, recursive: true });
    }
    createAuthority = (input) => createPreactivationRuntimeAuthority(input, {
      executeHelperImplementation: (arguments_) => executeRuntimeContentHelperInBackendImage({
        ...arguments_,
        backendImageId: config.sourceAuthority.backendImageId,
      }),
    });
  }
  if (backendReportPath !== undefined) {
    const backend = (
      await readConvexWasmPrivateEvidenceJson(backendReportPath, "backend source-package report")
    ).value;
    const analysisEnvironment = config.sourceAuthority.analysisEnvironmentPath === undefined
      ? undefined
      : parseSyntheticAnalysisEnvironment((await readConvexWasmPrivateEvidence(
          config.sourceAuthority.analysisEnvironmentPath,
          "analysis environment",
          MAX_ANALYSIS_ENVIRONMENT_BYTES
        )).bytes);
    if (
      backend.backendImageId !== config.sourceAuthority.backendImageId ||
      backend.sourceScope !== "current-complete-frozen-graph-v1" ||
      (analysisEnvironment === undefined
        ? backend.environmentScope !== "fresh-empty" ||
          backend.analysisEnvironmentFileSha256 !== undefined ||
          backend.analysisEnvironmentNames !== undefined ||
          backend.analysisEnvironmentValueSha256 !== undefined
        : backend.environmentScope !== "synthetic-analysis-only" ||
          backend.analysisEnvironmentFileSha256 !== analysisEnvironment.evidence.fileSha256 ||
          canonicalJson(backend.analysisEnvironmentNames) !== canonicalJson(analysisEnvironment.evidence.names) ||
          canonicalJson(backend.analysisEnvironmentValueSha256) !== canonicalJson(analysisEnvironment.evidence.values)) ||
      backend.requestSha256 !== startPush.sha256 ||
      backend.requestSize !== startPush.size ||
      backend.sourceEnvelopeFileSha256 !== sourceEnvelope.sha256 ||
      (backend.externalDepsPackage === undefined) !== (externalDepsPackage === null) ||
      backend.externalDepsPackage?.sha256 !== externalDepsPackage?.sha256 ||
      backend.externalDepsPackage?.size !== externalDepsPackage?.size ||
      typeof backend.output !== "string" ||
      typeof backend.sourcePackage?.path !== "string"
    ) {
      throw new Error("backend source-package report differs from the project build or configured producer");
    }
    if (backend.externalDepsPackage !== undefined) {
      if (typeof backend.externalDepsPackage.path !== "string") {
        throw new Error("backend source-package report lacks its dependency archive");
      }
      const backendExternalDepsPackage = await readConvexWasmPrivateEvidence(
        backend.externalDepsPackage.path,
        "backend external dependency package",
        256 * 1024 * 1024
      );
      if (
        backendExternalDepsPackage.sha256 !== externalDepsPackage.sha256 ||
        backendExternalDepsPackage.size !== externalDepsPackage.size
      ) {
        throw new Error("backend dependency archive differs from the configured archive");
      }
    }
    const scratch = await fs.mkdtemp(join(buildDirectory, ".certify-"));
    try {
      const certificate = await certifyRuntimeContentProducer(
        {
          authorityPath: backend.output,
          cacheRoot: config.artifactCacheRoot ?? defaultConvexWasmCacheRoot(),
          conformanceAuthorityPath: join(scratch, "source-authority.json"),
          conformanceSourcePackagePath: join(scratch, "source-package.zip"),
          helper,
          producerIdentity,
          report: backend,
          sourceEnvelope: sourceEnvelope.value,
          sourceEnvelopeBytes: sourceEnvelope.bytes,
          sourcePackagePath: backend.sourcePackage?.path,
          startPushBytes: startPush.bytes,
          startPushPath: startPush.path,
        },
        {
          assertHelperCurrent: async () => {
            const current = await inspectRuntimeContentHelper(helper.path);
            if (current.sha256 !== helper.sha256 || current.size !== helper.size) {
              throw new Error("source-package helper changed during backend conformance");
            }
          },
          createPreactivationAuthority: createAuthority,
          publishCertificate: publishRuntimeContentProducerCertificate,
          readMaterial: async (path, maximumBytes, description) =>
            (await readConvexWasmPrivateEvidence(path, description, maximumBytes)).bytes,
        }
      );
      await writeProducerCertificate(config.sourceAuthority.producerCertificatePath, certificate);
    } finally {
      await fs.rm(scratch, { force: true, recursive: true });
    }
  }
  const producerCertificate = await readConvexWasmPrivateEvidenceJson(
    config.sourceAuthority.producerCertificatePath,
    "source-package producer certificate"
  );
  const certificate = validateProducerCertificate(
    producerCertificate.value,
    producerIdentity,
    externalDepsPackage === null
      ? null
      : { sha256: externalDepsPackage.sha256, size: externalDepsPackage.size }
  );
  const authorityOutputPath = join(buildDirectory, "source-authority.json");
  const sourcePackageOutputPath = join(buildDirectory, "source-package.zip");
  const result = await createAuthority({
    authorityOutputPath,
    externalDepsPackagePath,
    helper,
    producerCertificate: certificate,
    sourceEnvelope: sourceEnvelope.value,
    sourceEnvelopeBytes: sourceEnvelope.bytes,
    sourcePackageOutputPath,
    startPushBytes: startPush.bytes,
    startPushPath: startPush.path,
    targetExternalDepsPackage: targetExternalDepsPackage?.value,
  });
  // A producer certificate may have been established with a different request. When it used this
  // exact request, its backend-produced result must also match the current helper output.
  if (
    certificate.request.sha256 === startPush.sha256 &&
    certificate.request.size === startPush.size &&
    (result.authoritySha256 !== certificate.backendAuthoritySha256 ||
      result.sourcePackageSha256 !== certificate.sourcePackage.sha256 ||
      result.sourcePackageSize !== certificate.sourcePackage.size ||
      result.sourcePackageRuntimeContentSha256 !== certificate.runtimeContentSha256)
  ) {
    throw new Error("derived source authority differs from the certified backend producer");
  }
  return {
    authority: authorityOutputPath,
    authoritySha256: result.authoritySha256,
    sourcePackage: sourcePackageOutputPath,
    producerCertificateSha256: certificate.certificateSha256,
    sourcePackageRuntimeContentSha256: result.sourcePackageRuntimeContentSha256,
  };
}

if (import.meta.main) {
  const argumentsList = process.argv.slice(2);
  if (
    ![4, 6].includes(argumentsList.length) ||
    argumentsList[0] !== "--config" ||
    argumentsList[2] !== "--artifact-report" ||
    (argumentsList.length === 6 && argumentsList[4] !== "--backend-report")
  ) {
    throw new Error(
      "usage: convex-wasm-authority --config PROJECT.json --artifact-report REPORT.json [--backend-report BACKEND.json]"
    );
  }
  const result = await createConvexWasmProjectAuthority({
    configPath: resolve(argumentsList[1]),
    artifactReportPath: resolve(argumentsList[3]),
    ...(argumentsList.length === 6 ? { backendReportPath: resolve(argumentsList[5]) } : {}),
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}
