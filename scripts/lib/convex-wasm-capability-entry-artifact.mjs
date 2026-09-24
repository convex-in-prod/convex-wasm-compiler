import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJson,
  compileConvexWasmCapabilityArtifactsInMaterialSession,
  compileConvexWasmCapabilityEntryArtifact,
  compileConvexWasmCapabilityPackageArtifact,
  compileConvexWasmCapabilityPackagePartialInitializationFixtureArtifact as compilePartialInitializationFixtureArtifact,
  compileConvexWasmOfficialOutputModuleGraphInputsInMaterialSession,
  convexWasmCapabilityArtifactMaterialSessionSeedKind,
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilitySourcePipelineSha256,
  createConvexWasmCapabilityArtifactMaterialSession,
  createConvexWasmCapabilityArtifactMaterialSessionFromSharedSeed,
  drainConvexWasmOfficialOutputModuleGraphSupportObjectPreactivation,
  finalizeConvexWasmArtifactMaterialSession,
  fingerprintJson,
  startConvexWasmCapabilitySharedGeneratedCPrewarmInMaterialSession,
  startConvexWasmOfficialOutputModuleGraphSupportObjectPreactivationInMaterialSession,
  startConvexWasmOfficialOutputPhysicalUnitPreactivationInMaterialSession,
} from "./convex-wasm-artifact-pipeline.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";
import { convexWasmCompilerAdmittedLanguageVersion } from "./convex-wasm-compiler-contract.mjs";
import {
  authenticateConvexWasmCompileProfile,
  authenticateConvexWasmCompileProfileSession,
  buildConvexWasmCompileProfile,
  convexWasmCompileProfileTargetAdapterMode,
  projectConvexWasmLocalCompileProfile,
} from "./convex-wasm-compile-profile.mjs";
import {
  convexWasmIntrinsicHardeningPolicySha256,
  convexWasmIntrinsicHardeningSourceSha256,
  convexWasmCapabilityRequestAbiVersion,
  convexWasmLoweringFormat,
  convexWasmOpaqueAbiVersion,
  convexWasmTargetRuntimeSurfacePolicySha256,
  renderNativeDbGetCapabilityTargetUnits,
  renderOpaqueAbiHeader,
} from "./convex-wasm-lowering.mjs";
import { convexWasmTargetRuntimeSurfacePolicyIdentity } from "./convex-wasm-runtime-surface.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import { fingerprintMaterialPaths } from "./convex-wasm-artifact-material.mjs";
import { loadOrCreateConvexWasmRuntimeHeaderSnapshotCache } from "./convex-wasm-runtime-header-snapshot-cache.mjs";

const CAPABILITY_RUNTIME_MAIN_PATH = fileURLToPath(
  new URL("./convex-wasm-native-capability-runtime-main.cpp", import.meta.url)
);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function settleCapabilityArtifactWork(promises) {
  const settlements = await Promise.allSettled(promises);
  const failure = settlements.find(({ status }) => status === "rejected");
  if (failure !== undefined) throw failure.reason;
  return settlements.map(({ value }) => value);
}

async function validateCapabilityRuntimeHeader(cacheRoot, directory, expectedSource) {
  await requirePrivateCacheDirectory(cacheRoot, directory);
  const names = await fs.readdir(directory);
  if (names.length !== 1 || names[0] !== "convex_wasm_opaque_abi_v3.h") {
    throw new Error("Convex Wasm capability runtime header directory has unexpected files");
  }
  const path = join(directory, names[0]);
  await requirePrivateCacheFile(cacheRoot, path);
  const [source, stat] = await settleCapabilityArtifactWork([
    fs.readFile(path, "utf8"),
    fs.lstat(path),
  ]);
  if (!stat.isFile() || source !== expectedSource) {
    throw new Error("Convex Wasm capability runtime header material is invalid");
  }
}

export async function stageConvexWasmCapabilityRuntimeHeader({ cacheLayout, cacheRoot }) {
  const directory = await stagePrivateCapabilityRuntimeHeader({ cacheLayout, cacheRoot });
  const runtimeHeaderMaterials = await fingerprintMaterialPaths(
    [{ label: "runtime-include-directory-0", path: directory }],
    "generated capability runtime header"
  );
  // The candidate certificate outlives build scratch. Return the existing immutable include
  // snapshot so automatic-material evidence names retained bytes after work-lease cleanup.
  const snapshot = await loadOrCreateConvexWasmRuntimeHeaderSnapshotCache({
    cacheLayout,
    includeDirectories: [directory],
    runtimeHeaderMaterials,
  });
  return join(snapshot.inputRoot, "include-0");
}

async function stagePrivateCapabilityRuntimeHeader({ cacheLayout, cacheRoot }) {
  const source = renderOpaqueAbiHeader();
  const root = join(cacheLayout.work.scratch, "capability-runtime-headers");
  const directory = join(root, sha256(source));
  await fs.mkdir(root, { mode: 0o700, recursive: true });
  try {
    await validateCapabilityRuntimeHeader(cacheRoot, directory, source);
    return directory;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }

  const publication = await fs.mkdtemp(join(root, ".publish-"));
  try {
    await fs.writeFile(join(publication, "convex_wasm_opaque_abi_v3.h"), source, {
      flag: "wx",
      mode: 0o600,
    });
    try {
      await fs.rename(publication, directory);
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "ENOTEMPTY") {
        throw error;
      }
    }
  } finally {
    await fs.rm(publication, { force: true, recursive: true });
  }
  await validateCapabilityRuntimeHeader(cacheRoot, directory, source);
  return directory;
}

export function createConvexWasmCapabilityGuestSourceProvenance(source, entryPath, sourceHash) {
  const bytes = Buffer.from(source);
  const lines = source.split("\n");
  const unitName = "entryGraph";
  const unitId = `${entryPath}#${unitName}`;
  return {
    compilerBundle: {
      endLine: lines.length,
      sha256: sha256(bytes),
      size: bytes.length,
      startLine: 1,
    },
    generatedSource: { sha256: sha256(bytes), size: bytes.length },
    kind: "convex-wasm-guest-source-provenance-v1",
    schemaVersion: 1,
    units: [
      {
        generatedRange: { endLine: lines.length, startLine: 1 },
        original: {
          column: 1,
          dependencyChain: [unitId],
          end: bytes.length,
          id: unitId,
          kind: "variable",
          line: 1,
          module: entryPath,
          name: unitName,
          sourceHash,
          start: 0,
        },
      },
    ],
  };
}

export function createConvexWasmCapabilityApplicationArtifactOptions({
  applicationJavascript,
  artifactConfig,
  bridgeJavascript,
  capabilityRuntimeHeaderDirectory,
  formatterJavascript,
  invocationAbi,
  localProfile,
  modulePath,
  platformLimits,
  routes,
  sourcePipelineSha256,
  contextReuseAnalysisIdentity,
  entryPath,
}) {
  if (!Array.isArray(routes) || routes.length === 0) {
    throw new Error("Convex Wasm capability application requires at least one route");
  }
  const contextReuseAnalysis =
    contextReuseAnalysisIdentity?.kind === "convex-context-reuse-cohort-analysis"
      ? authenticateConvexContextReuseCohortAnalysisIdentity(contextReuseAnalysisIdentity)
      : authenticateConvexContextReuseResultIdentity(contextReuseAnalysisIdentity);
  if (!contextReuseAnalysis.entries.includes(entryPath)) {
    throw new Error("Convex Wasm capability application is outside its context-reuse analysis");
  }
  const primaryRoute = routes[0];
  const sharedOptions = createConvexWasmCapabilityArtifactMaterialSessionSeed({
    artifactConfig,
    bridgeJavascript,
    capabilityRuntimeHeaderDirectory,
    formatterJavascript,
  });
  const sharedArtifactOptions = { ...sharedOptions };
  delete sharedArtifactOptions.kind;
  return {
    ...artifactConfig,
    ...sharedArtifactOptions,
    capabilityEntry: {
      capabilityRequestAbiVersion: convexWasmCapabilityRequestAbiVersion,
      entryPath,
      invocationAbi,
      localProfile,
      modulePath,
      routes,
      runtimeSurfacePolicySha256: convexWasmTargetRuntimeSurfacePolicySha256,
      contextReuseAnalysis,
    },
    compiler: {
      ...sharedArtifactOptions.compiler,
      sourcePipelineSha256,
    },
    generatedJavaScript: applicationJavascript,
    guestSourceProvenance: createConvexWasmCapabilityGuestSourceProvenance(
      applicationJavascript,
      entryPath,
      localProfile.javascript.sha256
    ),
    importedOperations: [],
    platformLimits,
    routingDecision: { decision: "wasm" },
    source: {
      exportName: primaryRoute.exportName,
      exportSha256: localProfile.javascript.sha256,
      modulePath: entryPath,
      resolvedGraphSha256: localProfile.dependencyGraphSha256,
      runtimeModulePath: `${modulePath}.js`,
      udfKind: primaryRoute.udfKind,
    },
  };
}

export function createConvexWasmCapabilityArtifactMaterialSessionSeed({
  artifactConfig,
  bridgeJavascript,
  capabilityRuntimeHeaderDirectory,
  formatterJavascript,
}) {
  const loweringPipelineSha256 = fingerprintJson({
    convexWasmLoweringFormat,
    intrinsicHardeningPolicySha256: convexWasmIntrinsicHardeningPolicySha256,
    intrinsicHardeningSourceSha256: convexWasmIntrinsicHardeningSourceSha256,
    runtimeSurfacePolicySha256: convexWasmTargetRuntimeSurfacePolicySha256,
  });
  return Object.freeze({
    cacheLayout: artifactConfig.cacheLayout,
    cacheRoot: artifactConfig.cacheRoot,
    capabilityBridgeJavaScript: bridgeJavascript,
    capabilityFormatterJavaScript: formatterJavascript,
    command: artifactConfig.command,
    compiler: {
      admittedLanguageVersion: convexWasmCompilerAdmittedLanguageVersion,
      compilerRevision: "runtime-capability-entry-v1",
      loweringPipelineSha256,
      staticHermesGlobalPolicy: convexWasmTargetRuntimeSurfacePolicyIdentity,
    },
    effectExecutionMode: "guest-promise-event-loop",
    kind: convexWasmCapabilityArtifactMaterialSessionSeedKind,
    limits: artifactConfig.limits,
    opaqueValueAbiVersion: convexWasmOpaqueAbiVersion,
    producerIdentity: artifactConfig.producerIdentity,
    requestEnvelope: artifactConfig.requestEnvelope,
    resourceGuard: artifactConfig.resourceGuard,
    runtime: {
      ...artifactConfig.runtime,
      includeDirectories: [
        capabilityRuntimeHeaderDirectory,
        ...artifactConfig.runtime.includeDirectories,
      ],
      mainSourcePath: CAPABILITY_RUNTIME_MAIN_PATH,
    },
    toolchain: artifactConfig.toolchain,
    valueCodec: artifactConfig.valueCodec,
    valueMode: "guest-native-json",
  });
}

export function finalizeConvexWasmCapabilityEntryArtifactResult(result) {
  if (result?.kind === "v8Fallback") {
    return result;
  }
  if (
    typeof result !== "object" ||
    result === null ||
    typeof result.package !== "object" ||
    result.package === null ||
    typeof result.entryManifest !== "object" ||
    result.entryManifest === null
  ) {
    throw new Error("Convex Wasm capability entry pipeline returned an unsupported result");
  }
  if (result.package.cacheKey !== fingerprintJson(result.entryManifest)) {
    throw new Error("Convex Wasm capability entry package identity changed after construction");
  }
  return result;
}

async function buildConvexWasmCapabilityArtifact({
  artifactConfig,
  artifactCompiler,
  contextReuseAnalysisIdentity,
  compileProfileSession,
  deploymentGraphSession,
  entrySelections,
  inventory,
  partialInitializationFixture = false,
  platformLimits,
  repoRoot,
  sdkPackageVersion,
  toolchainRoot = repoRoot,
}) {
  const authenticatedCompileProfileSession =
    compileProfileSession === undefined
      ? undefined
      : authenticateConvexWasmCompileProfileSession(compileProfileSession);
  const profiles = await settleCapabilityArtifactWork(
    entrySelections.map(async ({ entryPath, selectedExportNames }) =>
      authenticateConvexWasmCompileProfile(
        await (authenticatedCompileProfileSession === undefined
          ? buildConvexWasmCompileProfile({
              deploymentGraphSession,
              entryPath,
              exportNames: selectedExportNames,
              inventory,
              mode: convexWasmCompileProfileTargetAdapterMode,
              repoRoot,
              toolchainRoot,
            })
          : authenticatedCompileProfileSession.buildProfile({
              entryPath,
              exportNames: selectedExportNames,
            }))
      )
    )
  );
  if (authenticatedCompileProfileSession === undefined) {
    await settleCapabilityArtifactWork(profiles.map((profile) => profile.verifyMaterials()));
  }
  const localProfiles = profiles.map(projectConvexWasmLocalCompileProfile);
  const targetUnits = profiles.map((profile) =>
    renderNativeDbGetCapabilityTargetUnits({
      argumentFields: [],
      compileProfileJavascript: profile.javascript,
      sdkPackageVersion,
    })
  );
  const bridgeJavascript = targetUnits[0].bridgeJavascript;
  if (targetUnits.some((units) => units.bridgeJavascript !== bridgeJavascript)) {
    throw new Error("Convex Wasm capability package entries produced different shared bridges");
  }
  const formatterJavascript = targetUnits[0].formatterJavascript;
  if (targetUnits.some((units) => units.formatterJavascript !== formatterJavascript)) {
    throw new Error(
      "Convex Wasm capability package entries produced different shared runtime-support units"
    );
  }
  const capabilityRuntimeHeaderDirectory =
    await stageConvexWasmCapabilityRuntimeHeader(artifactConfig);
  const sourcePipelineSha256 = convexWasmCapabilitySourcePipelineSha256(localProfiles);
  const rawOptions = profiles.map((profile, index) => {
    const applicationJavascript = targetUnits[index].applicationJavascript;
    const localProfile = localProfiles[index];
    const routes = profile.identity.routes;
    const localProfileSummary = {
      dependencyGraphSha256: localProfile.identity.dependencyGraphSha256,
      javascript: localProfile.identity.output.javascript,
      metafileSha256: localProfile.identity.metafileSha256,
      sha256: localProfile.sha256,
      sourceMap: localProfile.identity.output.sourceMap,
    };
    return createConvexWasmCapabilityApplicationArtifactOptions({
      applicationJavascript,
      artifactConfig,
      bridgeJavascript,
      capabilityRuntimeHeaderDirectory,
      entryPath: profile.identity.selectedEntry.entryPath,
      formatterJavascript,
      invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
      localProfile: localProfileSummary,
      modulePath: profile.identity.selectedEntry.modulePath,
      platformLimits,
      routes,
      sourcePipelineSha256,
      contextReuseAnalysisIdentity,
    });
  });
  if (partialInitializationFixture && rawOptions.length !== 2) {
    throw new Error(
      "Convex Wasm formatter partial-initialization fixture requires exactly two entries"
    );
  }
  const result = await artifactCompiler(rawOptions);
  await settleCapabilityArtifactWork(profiles.map((profile) => profile.verifyMaterials()));
  return {
    artifact: finalizeConvexWasmCapabilityEntryArtifactResult(result),
    ...(profiles.length === 1
      ? { localProfile: localProfiles[0], profile: profiles[0] }
      : { localProfiles, profiles }),
  };
}

export async function buildConvexWasmCapabilityEntryArtifact(options) {
  if (options.entries !== undefined) {
    return await buildConvexWasmCapabilityPackageArtifact(options);
  }
  return await buildConvexWasmCapabilityArtifact({
    ...options,
    artifactCompiler: async ([rawOptions]) =>
      await compileConvexWasmCapabilityEntryArtifact(rawOptions),
    entrySelections: [
      { entryPath: options.entryPath, selectedExportNames: options.selectedExportNames },
    ],
  });
}

async function buildConvexWasmCapabilityPackageArtifactWithCompiler(
  { entries, ...options },
  artifactCompiler,
  partialInitializationFixture = false
) {
  if (!Array.isArray(entries) || entries.length < 2 || entries.length > 8) {
    throw new Error("Convex Wasm capability package requires between two and eight entries");
  }
  const entrySelections = entries
    .map(({ entryPath, selectedExportNames }) => ({ entryPath, selectedExportNames }))
    .sort((left, right) => compareStrings(left.entryPath, right.entryPath));
  if (
    entrySelections.some(
      ({ entryPath }, index) => index > 0 && entrySelections[index - 1].entryPath === entryPath
    )
  ) {
    throw new Error("Convex Wasm capability package entries must be unique");
  }
  return await buildConvexWasmCapabilityArtifact({
    ...options,
    artifactCompiler,
    entrySelections,
    partialInitializationFixture,
  });
}

export async function buildConvexWasmCapabilityPackageArtifact(options) {
  return await buildConvexWasmCapabilityPackageArtifactWithCompiler(
    options,
    compileConvexWasmCapabilityPackageArtifact
  );
}

export async function buildConvexWasmCapabilityPackagePartialInitializationFixtureArtifact({
  entries,
  ...options
}) {
  if (!Array.isArray(entries) || entries.length !== 2) {
    throw new Error(
      "Convex Wasm formatter partial-initialization fixture requires exactly two entries"
    );
  }
  if (entries[0].entryPath === entries[1].entryPath) {
    throw new Error("Convex Wasm formatter partial-initialization fixture entries must be unique");
  }
  return await buildConvexWasmCapabilityPackageArtifactWithCompiler(
    { ...options, entries },
    compilePartialInitializationFixtureArtifact,
    true
  );
}

export function createConvexWasmCapabilityArtifactCompilationSession(scheduling) {
  if (
    typeof scheduling !== "object" ||
    scheduling === null ||
    Array.isArray(scheduling) ||
    Object.getPrototypeOf(scheduling) !== Object.prototype
  ) {
    throw new Error(
      "Convex Wasm capability artifact compilation session scheduling must be a plain object"
    );
  }
  const schedulingKeys = Object.keys(scheduling).sort();
  const expectedSchedulingKeys = [
    "launchPolicy",
    "nativePhaseScheduler",
    ...(Object.hasOwn(scheduling, "baseSupportPreactivation") ? ["baseSupportPreactivation"] : []),
    ...(Object.hasOwn(scheduling, "precompilerPackageAdmission")
      ? ["precompilerPackageAdmission"]
      : []),
  ].sort();
  if (
    schedulingKeys.length !== expectedSchedulingKeys.length ||
    schedulingKeys.some((key, index) => key !== expectedSchedulingKeys[index])
  ) {
    throw new Error(
      "Convex Wasm capability artifact compilation session scheduling must contain launchPolicy and nativePhaseScheduler"
    );
  }
  const normalizedScheduling = {
    ...(scheduling.baseSupportPreactivation === undefined
      ? {}
      : { baseSupportPreactivation: scheduling.baseSupportPreactivation }),
    launchPolicy: scheduling.launchPolicy,
    nativePhaseScheduler: scheduling.nativePhaseScheduler,
    ...(scheduling.precompilerPackageAdmission === undefined
      ? {}
      : { precompilerPackageAdmission: scheduling.precompilerPackageAdmission }),
  };
  let activeBuilds = 0;
  let authoritativeMaterialSessionRequested = false;
  let finalized = false;
  let materialSessionReadinessStarted = false;
  let materialSessionPromise;
  let speculativeMaterialSessionRequested = false;
  const speculativeMaterialSessionPromises = new WeakSet();
  const physicalUnitPreactivationPromises = new Set();
  const supportObjectPreactivationPromises = new Set();
  const sharedGeneratedCPrewarmPromises = new Set();
  const requireMaterialSession = async (rawOptions, speculative = false, sharedOnly = false) => {
    let sessionPromise = materialSessionPromise;
    const producer = sessionPromise === undefined;
    if (sessionPromise === undefined) {
      sessionPromise = sharedOnly
        ? createConvexWasmCapabilityArtifactMaterialSessionFromSharedSeed(
            rawOptions,
            normalizedScheduling
          )
        : createConvexWasmCapabilityArtifactMaterialSession(rawOptions, normalizedScheduling);
      materialSessionPromise = sessionPromise;
      if (speculative) {
        speculativeMaterialSessionPromises.add(sessionPromise);
        void sessionPromise.catch(() => {
          if (materialSessionPromise === sessionPromise) materialSessionPromise = undefined;
        });
      }
    }
    try {
      return await sessionPromise;
    } catch (error) {
      if (!producer && !speculative && speculativeMaterialSessionPromises.has(sessionPromise)) {
        // A failed speculative initializer has no authority over an overlapping compiler. Clear
        // that exact flight and let every authoritative waiter join one ordinary retry.
        if (materialSessionPromise === sessionPromise) materialSessionPromise = undefined;
        return await requireMaterialSession(rawOptions);
      }
      throw error;
    }
  };
  const compileArtifact = async (rawOptions) => {
    authoritativeMaterialSessionRequested = true;
    return await compileConvexWasmCapabilityArtifactsInMaterialSession(
      await requireMaterialSession(rawOptions[0]),
      rawOptions
    );
  };
  const compileModuleGraphInputs = async (rawOptions, compilationOptions) => {
    authoritativeMaterialSessionRequested = true;
    return await compileConvexWasmOfficialOutputModuleGraphInputsInMaterialSession(
      await requireMaterialSession(rawOptions[0]),
      rawOptions,
      compilationOptions
    );
  };
  const runBuild = async (build) => {
    if (finalized) {
      throw new Error("Convex Wasm capability artifact compilation session was finalized");
    }
    activeBuilds += 1;
    try {
      return await build();
    } finally {
      activeBuilds -= 1;
    }
  };
  return Object.freeze({
    async build(options) {
      return await runBuild(async () => {
        return options.entries === undefined
          ? await buildConvexWasmCapabilityArtifact({
              ...options,
              artifactCompiler: compileArtifact,
              entrySelections: [
                {
                  entryPath: options.entryPath,
                  selectedExportNames: options.selectedExportNames,
                },
              ],
            })
          : await buildConvexWasmCapabilityPackageArtifactWithCompiler(options, compileArtifact);
      });
    },
    async compile(rawOptions) {
      return await runBuild(
        async () => await compileArtifact(Array.isArray(rawOptions) ? rawOptions : [rawOptions])
      );
    },
    async compileModuleGraphInputs(rawOptions, compilationOptions) {
      return await runBuild(
        async () =>
          await compileModuleGraphInputs(
            Array.isArray(rawOptions) ? rawOptions : [rawOptions],
            compilationOptions
          )
      );
    },
    startMaterialSessionReadiness(sharedSeed) {
      if (finalized) {
        throw new Error("Convex Wasm capability artifact compilation session was finalized");
      }
      if (materialSessionReadinessStarted || materialSessionPromise !== undefined) {
        throw new Error("Convex Wasm capability material-session readiness was already started");
      }
      materialSessionReadinessStarted = true;
      speculativeMaterialSessionRequested = true;
      const readiness = requireMaterialSession(sharedSeed, true, true);
      const prewarm = readiness.then(
        async (materialSession) =>
          await startConvexWasmCapabilitySharedGeneratedCPrewarmInMaterialSession(materialSession)
      );
      sharedGeneratedCPrewarmPromises.add(prewarm);
      const clear = () => sharedGeneratedCPrewarmPromises.delete(prewarm);
      void prewarm.then(clear, clear);
      // Speculative readiness and generated-C work have no failure authority. An authoritative
      // compiler joins successful shared stages and retries an initializer or stage that rejected.
      void prewarm.catch(() => undefined);
    },
    preactivateModuleGraphPhysicalUnit(rawOptions, physicalUnit, authority) {
      if (finalized) {
        throw new Error("Convex Wasm capability artifact compilation session was finalized");
      }
      speculativeMaterialSessionRequested = true;
      const preactivation = (async () =>
        await startConvexWasmOfficialOutputPhysicalUnitPreactivationInMaterialSession(
          await requireMaterialSession(rawOptions, true),
          rawOptions,
          physicalUnit,
          authority
        ))();
      physicalUnitPreactivationPromises.add(preactivation);
      const clear = () => physicalUnitPreactivationPromises.delete(preactivation);
      void preactivation.then(clear, clear);
      // Speculative work has no failure authority. The authoritative compiler call retries the
      // ordinary stage after observing this settlement, and finalization drains any survivor.
      void preactivation.catch(() => undefined);
    },
    preactivateModuleGraphSupportObject(options) {
      if (finalized) {
        throw new Error("Convex Wasm capability artifact compilation session was finalized");
      }
      if (materialSessionPromise === undefined) {
        return Promise.resolve(Object.freeze({}));
      }
      const preactivation = materialSessionPromise.then((session) =>
        startConvexWasmOfficialOutputModuleGraphSupportObjectPreactivationInMaterialSession({
          ...options,
          session,
        })
      );
      const drain = preactivation.then(async (token) => {
        await drainConvexWasmOfficialOutputModuleGraphSupportObjectPreactivation(token);
        return token;
      });
      supportObjectPreactivationPromises.add(drain);
      const clear = () => supportObjectPreactivationPromises.delete(drain);
      void drain.then(clear, clear);
      void drain.catch(() => undefined);
      return preactivation;
    },
    async finalize() {
      if (finalized) {
        throw new Error("Convex Wasm capability artifact compilation session was finalized");
      }
      if (activeBuilds !== 0) {
        throw new Error(
          "Convex Wasm capability artifact compilation session still has an active build"
        );
      }
      if (materialSessionPromise === undefined && !speculativeMaterialSessionRequested) {
        throw new Error(
          "Convex Wasm capability artifact compilation session did not build artifacts"
        );
      }
      const finalMaterialSessionPromise = materialSessionPromise;
      // Close admission before the first await. Otherwise a caller can start a new speculative
      // preactivation after the drain snapshot and race material-session finalization.
      finalized = true;
      await Promise.allSettled([
        ...sharedGeneratedCPrewarmPromises,
        ...physicalUnitPreactivationPromises,
        ...supportObjectPreactivationPromises,
      ]);
      if (finalMaterialSessionPromise === undefined) return undefined;
      let materialSession;
      try {
        materialSession = await finalMaterialSessionPromise;
      } catch (error) {
        // A speculative initializer can be the only material-session work when the authoritative
        // transform fails first. Its drained failure must not replace that transform result.
        if (
          !authoritativeMaterialSessionRequested &&
          speculativeMaterialSessionPromises.has(finalMaterialSessionPromise)
        ) {
          return undefined;
        }
        throw error;
      }
      const report = await finalizeConvexWasmArtifactMaterialSession(materialSession);
      // Support-object preactivation has no failure authority. Its graph consumer retries a
      // failed token after finalization; if no graph follows, finalization merely drains it.
      return report;
    },
  });
}

export function capabilityEntryArtifactSummary(result) {
  if (result.artifact.kind === "v8Fallback") {
    return canonicalJson(result.artifact);
  }
  return canonicalJson({
    entry: result.artifact.entryManifest.entry,
    package: result.artifact.package,
    routes: result.artifact.entryManifest.routes,
  });
}
