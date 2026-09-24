import {
  compileConvexWasmCapabilityPackageArtifact,
  compileConvexWasmCapabilityEntryArtifact,
  compileConvexWasmOfficialOutputModuleGraphInputs,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
  convexWasmCapabilitySourcePipelineSha256,
  fingerprintJson,
} from "./convex-wasm-artifact-pipeline.mjs";
import {
  createConvexWasmCapabilityApplicationArtifactOptions,
  createConvexWasmCapabilityArtifactMaterialSessionSeed,
  finalizeConvexWasmCapabilityEntryArtifactResult,
  stageConvexWasmCapabilityRuntimeHeader,
} from "./convex-wasm-capability-entry-artifact.mjs";
import { renderNativeDbGetCapabilityTargetUnits } from "./convex-wasm-lowering.mjs";
import {
  authenticateConvexWasmOfficialOutputCohortApplicationUnit,
  authenticateConvexWasmOfficialOutputApplicationUnit,
  convexWasmOfficialOutputCohortApplicationUnitKind,
  convexWasmOfficialOutputCohortGeneratedJavaScriptMaxBytes,
  projectConvexWasmOfficialOutputCohortLocalApplicationUnitIdentity,
  projectConvexWasmOfficialOutputCohortLocalProfiles,
  projectConvexWasmOfficialOutputLocalProfile,
  summarizeConvexWasmOfficialOutputLocalProfile,
} from "./convex-wasm-official-output-application-unit.mjs";
import {
  authenticateConvexWasmOfficialOutputChunkApplicationUnit,
  convexWasmOfficialOutputChunkApplicationUnitKind,
  projectConvexWasmOfficialOutputChunkLocalProfiles,
  projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor,
} from "./convex-wasm-official-output-chunk-application-unit.mjs";
import { retainProjectedConvexWasmOfficialOutputChunkLocalProfileSummaries } from "./convex-wasm-official-output-chunk-projection-provenance.mjs";

const authenticatedBuildReportCompileProfiles = new WeakSet();

export function retainAuthenticatedBuildReportCompileProfile(profile) {
  authenticatedBuildReportCompileProfiles.add(profile);
  return profile;
}

export function isAuthenticatedConvexWasmBuildReportCompileProfile(profile) {
  return authenticatedBuildReportCompileProfiles.has(profile);
}

function officialProfile(applicationUnit, localProfile) {
  return retainAuthenticatedBuildReportCompileProfile(
    Object.freeze({
      identity: localProfile.identity,
      kind: "convex-wasm-official-output-application-profile-v1",
      sha256: localProfile.sha256,
      async verifyMaterials() {
        authenticateConvexWasmOfficialOutputApplicationUnit(applicationUnit);
        summarizeConvexWasmOfficialOutputLocalProfile(localProfile);
      },
    })
  );
}

function createOfficialOutputLocalProfileVerifier({
  localProfiles,
  membershipChangedMessage,
  projectLocalProfiles,
  retainSuccessfulVerification = false,
  subject,
  unit,
}) {
  const expectedByEntryPath = new Map(
    localProfiles.map((localProfile) => [
      localProfile.identity.selectedEntry.entryPath,
      localProfile,
    ])
  );
  if (expectedByEntryPath.size !== localProfiles.length) {
    throw new Error(`${subject} local profiles have duplicate entry paths`);
  }
  let activeVerification;
  let verifiedProfilesByEntryPath;

  async function verifyProjection() {
    const currentProfiles = projectLocalProfiles(unit);
    const currentByEntryPath = new Map(
      currentProfiles.map((profile) => [profile.identity.selectedEntry.entryPath, profile])
    );
    if (
      currentByEntryPath.size !== currentProfiles.length ||
      currentByEntryPath.size !== expectedByEntryPath.size
    ) {
      throw new Error(membershipChangedMessage);
    }
    return currentByEntryPath;
  }

  async function currentProfilesByEntryPath() {
    if (retainSuccessfulVerification && verifiedProfilesByEntryPath !== undefined) {
      return verifiedProfilesByEntryPath;
    }
    if (activeVerification !== undefined) return await activeVerification;
    const verification = Promise.resolve().then(verifyProjection);
    activeVerification = verification;
    try {
      const verified = await verification;
      if (retainSuccessfulVerification) verifiedProfilesByEntryPath = verified;
      return verified;
    } finally {
      if (activeVerification === verification) activeVerification = undefined;
    }
  }

  async function verifyProfile(localProfile) {
    const entryPath = localProfile.identity.selectedEntry.entryPath;
    if (expectedByEntryPath.get(entryPath) !== localProfile) {
      throw new Error(`${subject} profile is not bound to this verifier`);
    }
    const current = (await currentProfilesByEntryPath()).get(entryPath);
    if (current?.sha256 !== localProfile.sha256) {
      throw new Error(`${subject} local profile changed after construction`);
    }
  }

  async function verifyProfiles() {
    const currentByEntryPath = await currentProfilesByEntryPath();
    for (const localProfile of localProfiles) {
      const entryPath = localProfile.identity.selectedEntry.entryPath;
      if (currentByEntryPath.get(entryPath)?.sha256 !== localProfile.sha256) {
        throw new Error(`${subject} local profile changed after construction`);
      }
    }
  }

  return { verifyProfile, verifyProfiles };
}

export function createConvexWasmOfficialOutputArtifactApplication({
  applicationUnit,
  artifactConfig,
  capabilityRuntimeHeaderDirectory,
  contextReuseAnalysisIdentity,
  platformLimits,
  sdkPackageVersion,
}) {
  const unit = authenticateConvexWasmOfficialOutputApplicationUnit(applicationUnit);
  const localProfile = projectConvexWasmOfficialOutputLocalProfile(unit);
  const localProfileSummary = summarizeConvexWasmOfficialOutputLocalProfile(localProfile);
  const targetUnits = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    sdkPackageVersion,
    // Bridge generation is source-independent. The official application unit
    // carries and authenticates its own bounded global-facade handoff.
    compileProfileJavascript:
      "var __convexWasmCompileProfile = {__convexWasmSdkCommitTsPlaceholder: {}};",
  });
  const routes = unit.identity.routes.map(({ exportName, udfKind, visibility }) => ({
    exportName,
    udfKind,
    visibility,
  }));
  const sourcePipelineSha256 = convexWasmCapabilitySourcePipelineSha256([localProfile]);
  const options = createConvexWasmCapabilityApplicationArtifactOptions({
    applicationJavascript: unit.javascript,
    artifactConfig,
    bridgeJavascript: targetUnits.bridgeJavascript,
    capabilityRuntimeHeaderDirectory,
    entryPath: unit.identity.routes[0].entryPath,
    formatterJavascript: targetUnits.formatterJavascript,
    invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
    localProfile: localProfileSummary,
    modulePath: unit.identity.routes[0].modulePath,
    platformLimits,
    routes,
    sourcePipelineSha256,
    contextReuseAnalysisIdentity,
  });
  return {
    applicationUnit: unit,
    localProfile,
    options,
    profile: officialProfile(unit, localProfile),
  };
}

export async function buildConvexWasmOfficialOutputCapabilityEntryArtifact({
  applicationUnit,
  artifactCompiler = compileConvexWasmCapabilityEntryArtifact,
  artifactConfig,
  contextReuseAnalysisIdentity,
  platformLimits,
  sdkPackageVersion,
}) {
  if (applicationUnit?.kind === convexWasmOfficialOutputChunkApplicationUnitKind) {
    const capabilityRuntimeHeaderDirectory =
      await stageConvexWasmCapabilityRuntimeHeader(artifactConfig);
    const prepared = createConvexWasmOfficialOutputChunkArtifactApplications({
      applicationUnit,
      artifactConfig,
      capabilityRuntimeHeaderDirectory,
      contextReuseAnalysisIdentity,
      platformLimits,
      sdkPackageVersion,
    });
    const cohort = prepared.options.length > 1;
    const chunkArtifactCompiler =
      cohort && artifactCompiler === compileConvexWasmCapabilityEntryArtifact
        ? compileConvexWasmCapabilityPackageArtifact
        : artifactCompiler;
    const artifact = finalizeConvexWasmCapabilityEntryArtifactResult(
      await chunkArtifactCompiler(cohort ? prepared.options : prepared.options[0])
    );
    await Promise.all(prepared.profiles.map((profile) => profile.verifyMaterials()));
    return { ...prepared, artifact };
  }
  if (applicationUnit?.kind === convexWasmOfficialOutputCohortApplicationUnitKind) {
    const capabilityRuntimeHeaderDirectory =
      await stageConvexWasmCapabilityRuntimeHeader(artifactConfig);
    const prepared = createConvexWasmOfficialOutputCohortArtifactApplications({
      applicationUnit,
      artifactConfig,
      capabilityRuntimeHeaderDirectory,
      contextReuseAnalysisIdentity,
      platformLimits,
      sdkPackageVersion,
    });
    const cohortArtifactCompiler =
      artifactCompiler === compileConvexWasmCapabilityEntryArtifact
        ? compileConvexWasmCapabilityPackageArtifact
        : artifactCompiler;
    const artifact = finalizeConvexWasmCapabilityEntryArtifactResult(
      await cohortArtifactCompiler(prepared.options)
    );
    await prepared.verifyMaterials();
    return { ...prepared, artifact };
  }
  const capabilityRuntimeHeaderDirectory =
    await stageConvexWasmCapabilityRuntimeHeader(artifactConfig);
  const prepared = createConvexWasmOfficialOutputArtifactApplication({
    applicationUnit,
    artifactConfig,
    capabilityRuntimeHeaderDirectory,
    contextReuseAnalysisIdentity,
    platformLimits,
    sdkPackageVersion,
  });
  const artifact = finalizeConvexWasmCapabilityEntryArtifactResult(
    await artifactCompiler(prepared.options)
  );
  await prepared.profile.verifyMaterials();
  return { ...prepared, artifact };
}

export async function buildConvexWasmOfficialOutputModuleGraphInputs({
  applicationUnit,
  artifactConfig,
  compiler = compileConvexWasmOfficialOutputModuleGraphInputs,
  contextReuseAnalysisIdentity,
  physicalUnitPreactivationAuthority,
  platformLimits,
  sdkPackageVersion,
}) {
  if (applicationUnit?.kind !== convexWasmOfficialOutputChunkApplicationUnitKind) {
    throw new Error(
      "official-output module-graph input production requires a physical chunk application unit"
    );
  }
  const capabilityRuntimeHeaderDirectory =
    await stageConvexWasmCapabilityRuntimeHeader(artifactConfig);
  const prepared = createConvexWasmOfficialOutputChunkArtifactApplications({
    applicationUnit,
    artifactConfig,
    capabilityRuntimeHeaderDirectory,
    contextReuseAnalysisIdentity,
    platformLimits,
    sdkPackageVersion,
  });
  const compilerOutput = await compiler(prepared.options, {
    packageReceiptTopologyOnly: true,
    ...(physicalUnitPreactivationAuthority === undefined
      ? {}
      : { physicalUnitPreactivationAuthority }),
  });
  await Promise.all(prepared.profiles.map((profile) => profile.verifyMaterials()));
  return { ...prepared, compilerOutput };
}

function createConvexWasmOfficialOutputCohortArtifactConfig(artifactConfig) {
  if (
    artifactConfig?.limits?.artifacts === undefined ||
    typeof artifactConfig.limits.artifacts !== "object" ||
    artifactConfig.limits.artifacts === null
  ) {
    throw new Error("official-output artifact config omits artifact limits");
  }
  return {
    ...artifactConfig,
    limits: {
      ...artifactConfig.limits,
      artifacts: {
        ...artifactConfig.limits.artifacts,
        generatedJavaScriptBytes: convexWasmOfficialOutputCohortGeneratedJavaScriptMaxBytes,
      },
    },
  };
}

export function createConvexWasmOfficialOutputCapabilityMaterialSessionSeed({
  artifactConfig,
  capabilityRuntimeHeaderDirectory,
  sdkPackageVersion,
}) {
  const targetUnits = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    sdkPackageVersion,
    compileProfileJavascript:
      "var __convexWasmCompileProfile = {__convexWasmSdkCommitTsPlaceholder: {}};",
  });
  return createConvexWasmCapabilityArtifactMaterialSessionSeed({
    artifactConfig: createConvexWasmOfficialOutputCohortArtifactConfig(artifactConfig),
    bridgeJavascript: targetUnits.bridgeJavascript,
    capabilityRuntimeHeaderDirectory,
    formatterJavascript: targetUnits.formatterJavascript,
  });
}

export function createConvexWasmOfficialOutputModuleGraphPhysicalUnitPreactivationSeed({
  artifactConfig,
  capabilityRuntimeHeaderDirectory,
  contextReuseAnalysisIdentity,
  physicalUnit,
  platformLimits,
  sdkPackageVersion,
  selection,
}) {
  const route = selection?.route;
  const membership = selection?.manifestMembership;
  if (
    typeof route?.entryPath !== "string" ||
    typeof route.exportName !== "string" ||
    typeof route.modulePath !== "string" ||
    typeof membership?.dependencyGraphSha256 !== "string" ||
    typeof selection?.closure?.identity?.sha256 !== "string" ||
    typeof physicalUnit?.javascriptSource !== "string" ||
    typeof physicalUnit?.javascript?.sha256 !== "string" ||
    !Number.isSafeInteger(physicalUnit?.javascript?.size) ||
    physicalUnit.javascript.size < 1
  ) {
    throw new Error("official-output physical-unit preactivation seed is invalid");
  }
  const targetUnits = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    sdkPackageVersion,
    compileProfileJavascript:
      "var __convexWasmCompileProfile = {__convexWasmSdkCommitTsPlaceholder: {}};",
  });
  const cohortArtifactConfig = createConvexWasmOfficialOutputCohortArtifactConfig(artifactConfig);
  // The exact physical unit can start native preactivation before the complete application
  // descriptor exists. These bounded entry fields supply only that unit's native identity; shared
  // material-session readiness uses the source-independent seed above.
  const localProfile = {
    dependencyGraphSha256: membership.dependencyGraphSha256,
    javascript: physicalUnit.javascript,
    metafileSha256: selection.closure.identity.sha256,
    sha256: fingerprintJson({
      domain: "convex-wasm-official-output-physical-unit-preactivation-profile-v1",
      entryPath: route.entryPath,
      physicalUnit: {
        identitySha256: physicalUnit.identitySha256,
        reusableCodeIdentitySha256: physicalUnit.reusableCodeIdentitySha256,
      },
    }),
    sourceMap: physicalUnit.javascript,
  };
  const rawOptions = createConvexWasmCapabilityApplicationArtifactOptions({
    applicationJavascript: physicalUnit.javascriptSource,
    artifactConfig: cohortArtifactConfig,
    bridgeJavascript: targetUnits.bridgeJavascript,
    capabilityRuntimeHeaderDirectory,
    contextReuseAnalysisIdentity,
    entryPath: route.entryPath,
    formatterJavascript: targetUnits.formatterJavascript,
    invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
    localProfile,
    modulePath: route.modulePath,
    platformLimits,
    routes: [
      {
        exportName: route.exportName,
        udfKind: route.udfKind,
        visibility: route.visibility,
      },
    ],
    sourcePipelineSha256: convexWasmCapabilitySourcePipelineSha256([localProfile]),
  });
  return Object.freeze({ physicalUnit, rawOptions });
}

export function createConvexWasmOfficialOutputChunkArtifactApplications({
  applicationUnit,
  artifactConfig,
  capabilityRuntimeHeaderDirectory,
  contextReuseAnalysisIdentity,
  platformLimits,
  sdkPackageVersion,
}) {
  const unit = authenticateConvexWasmOfficialOutputChunkApplicationUnit(applicationUnit);
  const nativeApplication = projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor(unit);
  const localProfiles = projectConvexWasmOfficialOutputChunkLocalProfiles(unit);
  retainProjectedConvexWasmOfficialOutputChunkLocalProfileSummaries(
    nativeApplication,
    localProfiles
  );
  const chunkProfileVerifier = createOfficialOutputLocalProfileVerifier({
    localProfiles,
    membershipChangedMessage: "official-output chunk local profile changed after construction",
    projectLocalProfiles: projectConvexWasmOfficialOutputChunkLocalProfiles,
    retainSuccessfulVerification: true,
    subject: "official-output chunk",
    unit,
  });
  const targetUnits = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    sdkPackageVersion,
    compileProfileJavascript:
      "var __convexWasmCompileProfile = {__convexWasmSdkCommitTsPlaceholder: {}};",
  });
  const cohortArtifactConfig = createConvexWasmOfficialOutputCohortArtifactConfig(artifactConfig);
  const sourcePipelineSha256 = convexWasmCapabilitySourcePipelineSha256(localProfiles);
  const options = unit.identity.entries.map((entry, index) => {
    const localProfile = localProfiles[index];
    const localProfileSummary = Object.freeze({
      dependencyGraphSha256: localProfile.identity.dependencyGraphSha256,
      javascript: localProfile.identity.output.javascript,
      metafileSha256: localProfile.identity.metafileSha256,
      sha256: localProfile.sha256,
      sourceMap: localProfile.identity.output.sourceMap,
    });
    const prepared = createConvexWasmCapabilityApplicationArtifactOptions({
      applicationJavascript: unit.units[entry.entryPublicationUnitSlot].javascript,
      artifactConfig: cohortArtifactConfig,
      bridgeJavascript: targetUnits.bridgeJavascript,
      capabilityRuntimeHeaderDirectory,
      entryPath: entry.entryPath,
      formatterJavascript: targetUnits.formatterJavascript,
      invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
      localProfile: localProfileSummary,
      modulePath: entry.modulePath,
      platformLimits,
      routes: entry.routes,
      sourcePipelineSha256,
      contextReuseAnalysisIdentity,
    });
    return { ...prepared, capabilityChunkApplication: nativeApplication };
  });
  const profiles = localProfiles.map((localProfile) =>
    retainAuthenticatedBuildReportCompileProfile(
      Object.freeze({
        identity: localProfile.identity,
        kind: "convex-wasm-official-output-chunk-application-profile-v1",
        sha256: localProfile.sha256,
        async verifyMaterials() {
          await chunkProfileVerifier.verifyProfile(localProfile);
        },
      })
    )
  );
  return { applicationUnit: unit, localProfiles, nativeApplication, options, profiles };
}

export function createConvexWasmOfficialOutputCohortArtifactApplications({
  applicationUnit,
  artifactConfig,
  capabilityRuntimeHeaderDirectory,
  contextReuseAnalysisIdentity,
  platformLimits,
  sdkPackageVersion,
}) {
  const unit = authenticateConvexWasmOfficialOutputCohortApplicationUnit(applicationUnit);
  const localApplicationUnit =
    projectConvexWasmOfficialOutputCohortLocalApplicationUnitIdentity(unit);
  const localProfiles = projectConvexWasmOfficialOutputCohortLocalProfiles(unit);
  const cohortProfileVerifier = createOfficialOutputLocalProfileVerifier({
    localProfiles,
    membershipChangedMessage:
      "official-output cohort local profile membership changed after construction",
    projectLocalProfiles: projectConvexWasmOfficialOutputCohortLocalProfiles,
    subject: "official-output cohort",
    unit,
  });
  const targetUnits = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    sdkPackageVersion,
    compileProfileJavascript:
      "var __convexWasmCompileProfile = {__convexWasmSdkCommitTsPlaceholder: {}};",
  });
  const cohortArtifactConfig = createConvexWasmOfficialOutputCohortArtifactConfig(artifactConfig);
  const sourcePipelineSha256 = convexWasmCapabilitySourcePipelineSha256(localProfiles);
  const applicationUnitIdentity = {
    compilerMode: localApplicationUnit.compilerMode,
    entries: localApplicationUnit.entries.map(({ entryPath, handoffSlot }) => ({
      entryPath,
      handoffSlot,
    })),
    identitySha256: localApplicationUnit.sha256,
    kind: "convex-wasm-multi-entry-application-unit-v1",
    unitCount: localApplicationUnit.unitCount,
  };
  const options = unit.identity.entries.map((entry, index) => {
    const localProfile = localProfiles[index];
    const localProfileSummary = Object.freeze({
      dependencyGraphSha256: localProfile.identity.dependencyGraphSha256,
      javascript: localProfile.identity.output.javascript,
      metafileSha256: localProfile.identity.metafileSha256,
      sha256: localProfile.sha256,
      sourceMap: localProfile.identity.output.sourceMap,
    });
    const prepared = createConvexWasmCapabilityApplicationArtifactOptions({
      applicationJavascript: unit.javascript,
      artifactConfig: cohortArtifactConfig,
      bridgeJavascript: targetUnits.bridgeJavascript,
      capabilityRuntimeHeaderDirectory,
      entryPath: entry.entryPath,
      formatterJavascript: targetUnits.formatterJavascript,
      invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
      localProfile: localProfileSummary,
      modulePath: entry.modulePath,
      platformLimits,
      routes: entry.routes,
      sourcePipelineSha256,
      contextReuseAnalysisIdentity,
    });
    return { ...prepared, capabilityApplicationUnit: applicationUnitIdentity };
  });
  const profiles = localProfiles.map((localProfile) =>
    retainAuthenticatedBuildReportCompileProfile(
      Object.freeze({
        identity: localProfile.identity,
        kind: "convex-wasm-official-output-cohort-application-profile-v1",
        sha256: localProfile.sha256,
        async verifyMaterials() {
          await cohortProfileVerifier.verifyProfile(localProfile);
        },
      })
    )
  );
  return {
    applicationUnit: unit,
    localProfiles,
    options,
    profiles,
    verifyMaterials: cohortProfileVerifier.verifyProfiles,
  };
}
