import { createRequire } from "node:module";
import { join } from "node:path";

import { resolveConvexWasmApplicationBundlerPackageSet } from "./convex-wasm-application-package-set.mjs";
import { createConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse.mjs";
import {
  bindPackagedPrecompilerToArtifactConfig,
  buildConvexWasmOfficialOutputModuleGraphArtifacts,
} from "./convex-wasm-artifact-pipeline.mjs";
import { acquireConvexWasmCacheLock } from "./convex-wasm-cache-lock.mjs";
import { createConvexWasmBuildWorkLease } from "./convex-wasm-cache-retention.mjs";
import { bindConvexWasmContextReuseAnalysisGraphSession } from "./convex-wasm-deployment-graph.mjs";
import { buildConvexWasmOfficialOutputModuleGraphInputs } from "./convex-wasm-official-output-artifact-adapter.mjs";
import { buildConvexWasmOfficialOutputChunkApplicationUnit } from "./convex-wasm-official-output-chunk-application-unit.mjs";
import { buildConvexWasmOfficialOutputChunkUnits } from "./convex-wasm-official-output-chunk-unit.mjs";
import { createConvexWasmModuleGraphCohortContract } from "./convex-wasm-module-graph-cohort-contract.mjs";
import {
  authenticateConvexWasmOfficialOutputCohortSchedule,
  createConvexWasmOfficialOutputCohortSchedule,
  scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule,
} from "./convex-wasm-official-output-cohort-schedule.mjs";
import { createConvexWasmOfficialOutputSelectionSession } from "./convex-wasm-official-output-prototype.mjs";
import {
  createConvexWasmSourceEnvelope,
  publishConvexWasmSourceEnvelopePublication,
} from "./convex-wasm-source-envelope.mjs";

export async function buildConvexWasmProjectPackage({ config, inputs, resourceGuard }) {
  const graphSession = bindConvexWasmContextReuseAnalysisGraphSession({
    contextReuseAnalysis: inputs.contextReuseAnalysis,
    graphSession: inputs.graphSession,
  });
  const sourceEnvelope = createConvexWasmSourceEnvelope({
    graphSession,
    inventory: inputs.inventory,
    selectedExports: config.selectedExports.map((route) => {
      const separator = route.indexOf(":");
      return { modulePath: route.slice(0, separator), exportName: route.slice(separator + 1) };
    }),
  });
  const sourceEnvelopePublication = await publishConvexWasmSourceEnvelopePublication({
    envelope: sourceEnvelope,
    outputPath: join(inputs.buildDirectory, "source-envelope.json"),
  });
  const schedule = authenticateConvexWasmOfficialOutputCohortSchedule({
    schedule: createConvexWasmOfficialOutputCohortSchedule({
      sourceEnvelope,
      sourceEnvelopeFileSha256: sourceEnvelopePublication.file.sha256,
      sourceEnvelopeFileSize: sourceEnvelopePublication.file.size,
    }),
    sourceEnvelope,
    sourceEnvelopeFileSha256: sourceEnvelopePublication.file.sha256,
    sourceEnvelopeFileSize: sourceEnvelopePublication.file.size,
  });
  const selectionSession = createConvexWasmOfficialOutputSelectionSession({
    graphSession,
    inventory: inputs.inventory,
    sourceEnvelope,
  });
  const packageSet = resolveConvexWasmApplicationBundlerPackageSet(config.projectRoot);
  const requireFromApplication = createRequire(join(config.projectRoot, "package.json"));
  const requireFromConvex = createRequire(requireFromApplication.resolve("convex/package.json"));
  const esbuild = requireFromConvex("esbuild");
  if (esbuild.version !== packageSet.esbuild.version) {
    throw new Error("application esbuild changed after its package identity was read");
  }
  const artifactConfig = await bindPackagedPrecompilerToArtifactConfig(
    {
      ...inputs.artifactConfig,
      cacheLayout: inputs.cacheLayout,
      cacheRoot: inputs.cacheRoot,
      producerIdentity: inputs.producerIdentity,
      requestEnvelope: inputs.requestEnvelope,
      resourceGuard,
      valueCodec: inputs.valueCodec,
    },
    {}
  );
  const releaseLock = await acquireConvexWasmCacheLock();
  try {
    const lease = await createConvexWasmBuildWorkLease({ cacheLayout: inputs.cacheLayout });
    try {
      const compilerOutputs = await scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule({
        concurrency: resourceGuard.launchPolicy.jobs,
        schedule,
        build: async ({ cohort }) => {
          const selections = cohort.entries.flatMap((entry) =>
            entry.routes.map((route) =>
              selectionSession.select({
                entryPath: entry.entryPath,
                exportName: route.exportName,
              })
            )
          );
          const chunkUnits = await buildConvexWasmOfficialOutputChunkUnits({ esbuild, selections });
          const applicationUnit = buildConvexWasmOfficialOutputChunkApplicationUnit({ chunkUnits });
          const contextReuseAnalysisIdentity = createConvexContextReuseCohortAnalysisIdentity({
            analysisIdentity: graphSession.contextReuseAnalysisIdentity,
            entryGraphs: cohort.entries.map(({ dependencyGraphSha256, entryPath }) => ({
              dependencyGraphSha256,
              entryPath,
            })),
            sharedAnalysisIdentity: graphSession.contextReuseAnalysisSharedIdentity,
            thirdPartyMaterialFingerprints:
              graphSession.contextReuseAnalysisThirdPartyMaterialFingerprints,
          });
          const prepared = await buildConvexWasmOfficialOutputModuleGraphInputs({
            applicationUnit,
            artifactConfig,
            contextReuseAnalysisIdentity,
            platformLimits: inputs.platformLimits,
            sdkPackageVersion: packageSet.convex.version,
          });
          return prepared.compilerOutput;
        },
      });
      if (compilerOutputs.length !== schedule.cohorts.length) {
        throw new Error("cohort compiler outputs do not match the authenticated schedule");
      }
      const cohortContracts = compilerOutputs.map((compilerOutput, index) =>
        createConvexWasmModuleGraphCohortContract({
          cohortId: schedule.cohorts[index].cohortId,
          compilerContract: compilerOutput.cohortContract,
          scheduleSha256: schedule.identity.sha256,
          sourceEnvelopeSha256: sourceEnvelope.sourceEnvelopeSha256,
        })
      );
      const artifact = await buildConvexWasmOfficialOutputModuleGraphArtifacts({
        artifactConfig: {
          cacheLayout: inputs.cacheLayout,
          cacheRoot: inputs.cacheRoot,
          producerIdentity: inputs.producerIdentity,
          resourceGuard,
        },
        cohortSchedule: schedule,
        compilerOutputs,
        async verifyDeploymentMaterials() {
          await Promise.all([
            graphSession.verifyInputMaterials(),
            graphSession.verifyBundleInputMaterials(),
            graphSession.verifyGitSourceSnapshot(),
          ]);
        },
      });
      await artifact.verifyMaterials();
      await lease.complete();
      return {
        artifact,
        cohortContracts,
        graphSession,
        schedule,
        sourceEnvelope,
        sourceEnvelopePublication,
      };
    } catch (error) {
      await lease.fail();
      throw error;
    }
  } finally {
    releaseLock();
  }
}
