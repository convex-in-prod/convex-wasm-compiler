import { promises as fs } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  acquireNativeReleaseFromSelectionFile,
  bundledNativeReleaseSelectionPath,
  defaultNativePackageCacheRoot,
} from "../acquire-convex-wasm-native-release.mjs";
import {
  createStaticHermesGateConfigArtifacts,
  normalizeGatePolicy,
} from "../create-gate-config.mjs";
import {
  createConvexWasmValueCodecInputFromMatrixReport,
  readConvexWasmValueCodecMatrixReport,
} from "./convex-wasm-committed-value-codec-report.mjs";
import { analyzeContextReuse } from "./convex-context-reuse.mjs";
import {
  defaultConvexWasmCacheRoot,
  deriveConvexWasmCacheLayout,
} from "./convex-wasm-cache-layout.mjs";
import { captureConvexWasmGitSourceSnapshot } from "./convex-wasm-git-source-snapshot.mjs";
import { buildConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import {
  createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile,
  createConvexWasmRequestEnvelopeInputFromMatrixReport,
  readConvexWasmRequestEnvelopeMatrixReport,
} from "./convex-wasm-request-envelope-report.mjs";
import { publishConvexWasmRequestEnvelopeEvidenceAuthority } from "../create-convex-wasm-request-envelope-evidence-authority.mjs";
import {
  parseArguments as parseCodecMatrixArguments,
  runConvexWasmCommittedValueCodecMatrix,
} from "../run-convex-wasm-committed-value-codec-matrix.mjs";
import {
  parseArguments as parseRequestMatrixArguments,
  runConvexWasmRequestEnvelopeMatrix,
} from "../run-convex-wasm-request-envelope-matrix.mjs";

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value;
}

function requireKeys(value, allowed, required, description) {
  const object = requireObject(value, description);
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) throw new Error(`${description} has unsupported field ${key}`);
  }
  for (const key of required) {
    if (!(key in object)) throw new Error(`${description} requires ${key}`);
  }
  return object;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${description} must be a non-empty string`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${description} must be a positive integer`);
  }
  return value;
}

export function parseProjectConfig(value, configPath) {
  const config = requireKeys(
    value,
    [
      "schemaVersion",
      "projectRoot",
      "workRoot",
      "gateRoot",
      "gatePolicy",
      "artifactCacheRoot",
      "deployedRuntimeAuthority",
      "nativeReleaseSelection",
      "nativePackageCacheRoot",
      "compilerPackage",
      "precompilerPackage",
      "selectedExports",
      "sourceRoots",
      "sourcePathspecs",
      "inventoryConfig",
      "sourceAuthority",
      "matrixReports",
      "matrixTools",
      "jobs",
      "aotWorkers",
      "memoryMaxMiB",
    ],
    [
      "schemaVersion",
      "projectRoot",
      "workRoot",
      "gateRoot",
      "gatePolicy",
      "selectedExports",
      "sourcePathspecs",
      "jobs",
      "aotWorkers",
      "memoryMaxMiB",
    ],
    "Convex Wasm project config"
  );
  if (config.schemaVersion !== 1) throw new Error("unsupported Convex Wasm project config version");
  if (!Array.isArray(config.selectedExports) || config.selectedExports.length === 0) {
    throw new Error("selectedExports must contain at least one MODULE:EXPORT route");
  }
  const selectedExports = config.selectedExports.map((route) => {
    requireString(route, "selected export");
    if (!/^[^:]+:[^:]+$/u.test(route)) {
      throw new Error("selected export must have the form MODULE:EXPORT");
    }
    return route;
  });
  if ((config.matrixReports === undefined) === (config.matrixTools === undefined)) {
    throw new Error("configure exactly one of matrixReports or matrixTools");
  }
  if (
    (config.compilerPackage === undefined) !== (config.precompilerPackage === undefined) ||
    (config.nativeReleaseSelection !== undefined && config.compilerPackage !== undefined)
  ) {
    throw new Error("configure a native release selection or both native package directories");
  }
  if (
    config.sourceRoots !== undefined &&
    (!Array.isArray(config.sourceRoots) ||
      config.sourceRoots.some((root) => typeof root !== "string" || root.length === 0))
  ) {
    throw new Error("sourceRoots must be an array of non-empty paths");
  }
  if (
    !Array.isArray(config.sourcePathspecs) ||
    config.sourcePathspecs.length === 0 ||
    config.sourcePathspecs.some((pathspec) => typeof pathspec !== "string" || pathspec.length === 0)
  ) {
    throw new Error("sourcePathspecs must contain staged Git paths");
  }
  const configDirectory = dirname(resolve(configPath));
  const path = (value, description) => resolve(configDirectory, requireString(value, description));
  const matrixReports =
    config.matrixReports === undefined
      ? undefined
      : requireKeys(
          config.matrixReports,
          ["codec", "request"],
          ["codec", "request"],
          "matrixReports"
        );
  const matrixTools =
    config.matrixTools === undefined
      ? undefined
      : requireKeys(config.matrixTools, ["runner", "cxx"], ["cxx"], "matrixTools");
  const sourceAuthority =
    config.sourceAuthority === undefined
      ? undefined
      : requireKeys(
          config.sourceAuthority,
          ["backendImageId", "helper", "producerCertificate", "externalDepsPackage", "targetExternalDepsPackage"],
          ["backendImageId", "helper", "producerCertificate"],
          "sourceAuthority"
        );
  const jobs = requirePositiveInteger(config.jobs, "jobs");
  const aotWorkers = requirePositiveInteger(config.aotWorkers, "aotWorkers");
  if (aotWorkers > jobs) {
    throw new Error("aotWorkers must not exceed jobs");
  }
  const memoryMaxMiB = requirePositiveInteger(config.memoryMaxMiB, "memoryMaxMiB");
  if (!Number.isSafeInteger(memoryMaxMiB * 1024 * 1024)) {
    throw new Error("memoryMaxMiB exceeds the supported byte limit");
  }
  const gateRoot = path(config.gateRoot, "gateRoot");
  return {
    projectRoot: path(config.projectRoot, "projectRoot"),
    workRoot: path(config.workRoot, "workRoot"),
    gateRoot,
    gatePolicyPath: path(config.gatePolicy, "gatePolicy"),
    artifactCacheRoot:
      config.artifactCacheRoot === undefined
        ? undefined
        : path(config.artifactCacheRoot, "artifactCacheRoot"),
    deployedRuntimeAuthorityPath:
      config.deployedRuntimeAuthority === undefined
        ? undefined
        : path(config.deployedRuntimeAuthority, "deployedRuntimeAuthority"),
    sourceAuthority:
      sourceAuthority === undefined
        ? undefined
        : {
            backendImageId: requireString(
              sourceAuthority.backendImageId,
              "sourceAuthority.backendImageId"
            ),
            helperPath: path(sourceAuthority.helper, "sourceAuthority.helper"),
            producerCertificatePath: path(
              sourceAuthority.producerCertificate,
              "sourceAuthority.producerCertificate"
            ),
            externalDepsPackagePath:
              sourceAuthority.externalDepsPackage === undefined
                ? undefined
                : path(sourceAuthority.externalDepsPackage, "sourceAuthority.externalDepsPackage"),
            targetExternalDepsPackagePath:
              sourceAuthority.targetExternalDepsPackage === undefined
                ? undefined
                : path(
                    sourceAuthority.targetExternalDepsPackage,
                    "sourceAuthority.targetExternalDepsPackage"
                  ),
          },
    nativeReleaseSelectionPath:
      config.compilerPackage !== undefined
        ? undefined
        : config.nativeReleaseSelection === undefined
          ? bundledNativeReleaseSelectionPath
          : path(config.nativeReleaseSelection, "nativeReleaseSelection"),
    nativePackageCacheRoot:
      config.nativePackageCacheRoot === undefined
        ? defaultNativePackageCacheRoot()
        : path(config.nativePackageCacheRoot, "nativePackageCacheRoot"),
    compilerPackage:
      config.compilerPackage === undefined
        ? undefined
        : path(config.compilerPackage, "compilerPackage"),
    precompilerPackage:
      config.precompilerPackage === undefined
        ? undefined
        : path(config.precompilerPackage, "precompilerPackage"),
    selectedExports,
    sourceRoots: config.sourceRoots ?? [],
    sourcePathspecs: config.sourcePathspecs,
    inventoryConfigPath:
      config.inventoryConfig === undefined
        ? undefined
        : path(config.inventoryConfig, "inventoryConfig"),
    matrixReports:
      matrixReports === undefined
        ? undefined
        : {
            codec: path(matrixReports.codec, "matrixReports.codec"),
            request: path(matrixReports.request, "matrixReports.request"),
          },
    matrixTools:
      matrixTools === undefined
        ? undefined
        : {
            runner:
              matrixTools.runner === undefined
                ? join(gateRoot, "bin", "convex-wasm-wasmtime-runner")
                : path(matrixTools.runner, "matrixTools.runner"),
            cxx: path(matrixTools.cxx, "matrixTools.cxx"),
          },
    jobs,
    aotWorkers,
    memoryMaxMiB,
  };
}

async function createPrivateBuildDirectory(workRoot) {
  await fs.mkdir(workRoot, { recursive: true, mode: 0o700 });
  const [status, realPath] = await Promise.all([fs.lstat(workRoot), fs.realpath(workRoot)]);
  if (
    !status.isDirectory() ||
    status.uid !== process.getuid() ||
    (status.mode & 0o777) !== 0o700 ||
    realPath !== workRoot
  ) {
    throw new Error("workRoot must be a canonical current-user-owned 0700 directory");
  }
  return await fs.mkdtemp(join(workRoot, "build-"));
}

async function createMatrixReports(config, buildDirectory, artifactConfig) {
  if (config.matrixReports !== undefined) return config.matrixReports;
  const commonArguments = [
    "--emcc",
    artifactConfig.toolchain.emscripten.executable,
    "--hermes-source",
    join(config.gateRoot, "hermes"),
    "--runner",
    config.matrixTools.runner,
    "--shermes",
    artifactConfig.toolchain.staticHermes.executable,
    "--wasm-build",
    join(config.gateRoot, "build-wasm"),
  ];
  const codec = join(buildDirectory, "codec-matrix.json");
  const request = join(buildDirectory, "request-matrix.json");
  const codecReport = await runConvexWasmCommittedValueCodecMatrix(
    parseCodecMatrixArguments([
      ...commonArguments,
      "--cxx",
      config.matrixTools.cxx,
      "--host-build",
      join(config.gateRoot, "build-host"),
      "--output",
      codec,
    ])
  );
  await fs.writeFile(codec, `${JSON.stringify(codecReport, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  const requestReport = await runConvexWasmRequestEnvelopeMatrix(
    parseRequestMatrixArguments([...commonArguments, "--output", request])
  );
  await fs.writeFile(request, `${JSON.stringify(requestReport, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return { codec, request };
}

export async function prepareConvexWasmProjectBuildInputs(config, { signal } = {}) {
  const buildDirectory = await createPrivateBuildDirectory(config.workRoot);
  const cacheRoot = config.artifactCacheRoot ?? defaultConvexWasmCacheRoot();
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: basename(buildDirectory),
    cacheRoot,
    repositoryRoot: config.projectRoot,
  });
  const packages =
    config.compilerPackage !== undefined && config.precompilerPackage !== undefined
      ? undefined
      : await acquireNativeReleaseFromSelectionFile({
          cacheRoot: config.nativePackageCacheRoot,
          selectionPath: config.nativeReleaseSelectionPath,
          signal,
        });
  const compilerPackage = config.compilerPackage ?? packages.compiler.packageDirectory;
  const precompilerPackage = config.precompilerPackage ?? packages.precompiler.packageDirectory;
  const artifactConfigPath = join(buildDirectory, "artifact-config.json");
  const platformLimitsPath = join(buildDirectory, "platform-limits.json");
  const contextReuseAnalysisPath = join(buildDirectory, "context-reuse-analysis.json");
  const gatePolicy = normalizeGatePolicy(
    JSON.parse(await fs.readFile(config.gatePolicyPath, "utf8"))
  );
  const gitSourceSnapshot = await captureConvexWasmGitSourceSnapshot({
    pathspecs: config.sourcePathspecs,
    repoRoot: config.projectRoot,
  });
  let analyzedGraphSession;
  let inventory;
  const [gateConfig, contextReuseAnalysis, producerIdentity] = await Promise.all([
    createStaticHermesGateConfigArtifacts({
      artifactConfigOutputPath: artifactConfigPath,
      gateRoot: config.gateRoot,
      platformLimitsOutputPath: platformLimitsPath,
      policy: gatePolicy,
      precompilerPackageDirectory: precompilerPackage,
    }),
    analyzeContextReuse({
      compilerPackage,
      diagnosticEncoding: "admission",
      effectExecutionMode: "guest-promise-event-loop",
      gitSourceSnapshot: { repoRoot: config.projectRoot, snapshot: gitSourceSnapshot },
      inventoryOptions:
        config.inventoryConfigPath === undefined
          ? {}
          : { configPath: config.inventoryConfigPath },
      repoRoot: config.projectRoot,
      retainGraphSession: ({ graphSession, inventory: generatedInventory }) => {
        analyzedGraphSession = graphSession;
        inventory = generatedInventory;
      },
      sourceRoots: config.sourceRoots,
    }),
    buildConvexWasmProducerIdentity(resolve(dirname(fileURLToPath(import.meta.url)), "../..")),
  ]);
  if (analyzedGraphSession === undefined || inventory === undefined) {
    throw new Error("context-reuse analysis did not retain its authenticated source graph");
  }
  await fs.writeFile(contextReuseAnalysisPath, `${JSON.stringify(contextReuseAnalysis, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  const artifactConfig = JSON.parse(await fs.readFile(gateConfig.artifactConfigOutputPath, "utf8"));
  const matrixReports = await createMatrixReports(config, buildDirectory, artifactConfig);
  const authorityPath = join(buildDirectory, "request-envelope-authority.json");
  const authority = await createConvexWasmRequestEnvelopeEvidenceAuthorityFromMatrixReportFile(
    matrixReports.request
  );
  await publishConvexWasmRequestEnvelopeEvidenceAuthority({ authority, outputPath: authorityPath });
  const [codecReport, requestReport] = await Promise.all([
    readConvexWasmValueCodecMatrixReport(matrixReports.codec),
    readConvexWasmRequestEnvelopeMatrixReport(matrixReports.request, authority),
  ]);
  return Object.freeze({
    artifactConfig,
    artifactConfigPath,
    authority,
    authorityPath,
    buildDirectory,
    cacheLayout,
    cacheRoot,
    compilerPackage,
    contextReuseAnalysis,
    contextReuseAnalysisPath,
    gitSourceSnapshot,
    graphSession: analyzedGraphSession,
    inventory,
    matrixReports,
    platformLimits: gatePolicy.platformLimits,
    platformLimitsPath,
    precompilerPackage,
    producerIdentity,
    requestEnvelope: createConvexWasmRequestEnvelopeInputFromMatrixReport(requestReport, authority),
    valueCodec: createConvexWasmValueCodecInputFromMatrixReport(codecReport),
  });
}
