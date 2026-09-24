import { promises as fs } from "node:fs";

import {
  fail,
  fingerprintJson,
  requireExactPlainObject,
  requirePositiveInteger,
} from "./convex-wasm-artifact-contract.mjs";
import { mapBounded } from "./convex-wasm-artifact-material.mjs";
import {
  ensureArtifactControlStageFromMaterial,
  ensureArtifactStage,
} from "./convex-wasm-artifact-stage.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import {
  MODULE_GRAPH_LEAF_ROLE,
  normalizeModuleGraphContract,
  normalizeModuleGraphCoreWasmInputs,
  normalizeModuleGraphHostAbi,
  normalizeModuleGraphModule,
  moduleGraphRoles,
  validateModuleGraphProviders,
} from "./convex-wasm-module-graph-contract.mjs";
import {
  assertConvexWasmModuleGraphLeafReplacement,
  convexWasmModuleGraphCoreWasmMaxBytes,
  convexWasmModuleGraphManifestKind,
  convexWasmModuleGraphProvenanceKind,
  convexWasmSerializedModuleMaxBytes,
  createConvexWasmModuleGraphPackagePayloadValidationScope,
  createModuleGraphLeafInvalidation,
  createModuleGraphManifestFromBuiltModules,
  loadAndVerifyConvexWasmModuleGraphPackageCollection,
  loadAndVerifyConvexWasmModuleGraphPackageInValidationScope,
  moduleGraphAotMaterialStage,
  moduleGraphAotStage,
  moduleGraphCoreMaterialStage,
  moduleGraphCoreStage,
  moduleGraphTopologyFromBuildInputs,
  nativeStageIdentity,
  normalizeEngineIdentity,
  normalizeModuleGraphBuildResult,
  normalizeModuleGraphEngine,
  normalizeModuleGraphInitialization,
  normalizeModuleGraphManifest,
  normalizeModuleGraphProvenance,
  normalizeModuleGraphRouting,
  normalizeModuleGraphToolchain,
  publishModuleGraphPackage,
} from "./convex-wasm-module-graph-package.mjs";
import { requirePrivateCacheDirectory } from "./convex-wasm-private-cache.mjs";
import { normalizeConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";

const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";

function moduleGraphAotMaterialIdentity({ coreWasm, engine, toolchain }) {
  return nativeStageIdentity({
    coreWasm: {
      sha256: coreWasm.sha256,
      size: coreWasm.size,
    },
    engine,
    kind: "convex-wasm-module-graph-wasmtime-aot-material-identity-v1",
    pipelineKind: PIPELINE_KIND,
    toolchain: toolchain.aot,
  });
}

async function buildConvexWasmModuleGraphAotMaterial({
  buildAot,
  coreWasm,
  engine,
  materialIdentity,
  role,
  workPath,
}) {
  const built = normalizeModuleGraphBuildResult(
    await buildAot({
      coreWasm,
      identity: materialIdentity,
      module: { role },
      workPath,
    }),
    role,
    "AOT",
    workPath
  );
  const engineIdentity = normalizeEngineIdentity(
    built.engineIdentity,
    engine.config,
    engine.target
  );
  if (engineIdentity.engineCompatibilitySha256 !== engine.compatibilitySha256) {
    fail(`${role} module AOT engine compatibility identity changed during build`);
  }
  return {
    metadata: engineIdentity,
    outputPath: built.outputPath,
    timing: built.timing,
  };
}

export async function buildConvexWasmModuleGraphModuleArtifacts({
  buildAot,
  buildCoreWasm,
  cacheLayout,
  cacheRoot,
  coreWasmInput,
  engine,
  immutableCacheValidationMemo,
  leafInvalidation,
  leafInvalidationSha256,
  limits,
  module,
  routing,
  toolchain,
}) {
  const coreIdentity = nativeStageIdentity({
    contract: module.contract,
    kind: "convex-wasm-module-graph-core-wasm-identity-v1",
    layout: module.layout,
    link: module.link,
    objectCompilation: module.objectCompilation,
    ownership: module.ownership,
    pipelineKind: PIPELINE_KIND,
    providers: module.providers,
    role: module.role,
    ...(module.sharedShardSha256 === undefined
      ? {}
      : { sharedShardSha256: module.sharedShardSha256 }),
    ...(module.role === MODULE_GRAPH_LEAF_ROLE
      ? { leafInvalidation, leafInvalidationSha256, routing }
      : {}),
    sourceProvenance: module.sourceProvenance,
    toolchain: {
      core: toolchain.core,
      staticHermesCBundleMemberCompilation: toolchain.staticHermesCBundleMemberCompilation,
    },
  });
  const coreMaterialIdentity =
    coreWasmInput === undefined
      ? undefined
      : nativeStageIdentity({
          contract: module.contract,
          coreWasmInput,
          kind: "convex-wasm-module-graph-core-wasm-material-identity-v1",
          link: module.link,
          objectCompilation: module.objectCompilation,
          ownership: module.ownership,
          pipelineKind: PIPELINE_KIND,
          providers: module.providers,
          ...(module.sharedShardSha256 === undefined
            ? {}
            : { sharedShardSha256: module.sharedShardSha256 }),
          toolchain: {
            core: toolchain.core,
            staticHermesCBundleMemberCompilation: toolchain.staticHermesCBundleMemberCompilation,
          },
        });
  const buildCoreWasmArtifact = async (workPath, identity, controlIdentity) => {
    const built = normalizeModuleGraphBuildResult(
      await buildCoreWasm({
        ...(controlIdentity === undefined ? {} : { controlIdentity }),
        identity,
        module,
        workPath,
      }),
      module.role,
      "Core Wasm",
      workPath
    );
    const authenticatedContract = normalizeModuleGraphContract(
      built.contract,
      module.role,
      engine.compatibilitySha256
    );
    if (authenticatedContract.contractSha256 !== module.contract.contractSha256) {
      fail(`${module.role} module Core Wasm changed its authenticated Wasmtime contract`);
    }
    return {
      metadata: { contract: authenticatedContract },
      outputPath: built.outputPath,
      timing: built.timing,
    };
  };
  const coreWasm =
    coreWasmInput === undefined
      ? await ensureArtifactStage({
          build: async (workPath) => await buildCoreWasmArtifact(workPath, coreIdentity),
          cacheLayout,
          cacheRoot,
          extension: "wasm",
          identity: coreIdentity,
          immutableCacheValidationMemo,
          maxArtifactBytes: limits.wasmBytes,
          previousIdentity: undefined,
          stage: moduleGraphCoreStage(module.role),
        })
      : await ensureArtifactControlStageFromMaterial({
          build: async (workPath) =>
            await buildCoreWasmArtifact(workPath, coreMaterialIdentity, coreIdentity),
          cacheLayout,
          cacheRoot,
          extension: "wasm",
          identity: coreIdentity,
          immutableCacheValidationMemo,
          materialIdentity: coreMaterialIdentity,
          materialStage: moduleGraphCoreMaterialStage(),
          maxArtifactBytes: limits.wasmBytes,
          previousIdentity: undefined,
          stage: moduleGraphCoreStage(module.role),
        });
  requireExactPlainObject(
    coreWasm.entry.metadata,
    ["contract"],
    `${module.role} cached Core Wasm metadata`
  );
  if (coreWasm.entry.metadata.contract.contractSha256 !== module.contract.contractSha256) {
    fail(`${module.role} cached Core Wasm contract does not match its graph identity`);
  }
  const aotIdentity = nativeStageIdentity({
    coreWasm: {
      cacheKey: coreWasm.report.cacheKey,
      sha256: coreWasm.entry.artifactSha256,
      size: coreWasm.entry.artifactSize,
    },
    engine,
    kind: "convex-wasm-module-graph-wasmtime-aot-identity-v1",
    pipelineKind: PIPELINE_KIND,
    role: module.role,
    toolchain: toolchain.aot,
  });
  const aotMaterialIdentity = moduleGraphAotMaterialIdentity({
    coreWasm: {
      sha256: coreWasm.entry.artifactSha256,
      size: coreWasm.entry.artifactSize,
    },
    engine,
    toolchain,
  });
  const aot = await ensureArtifactControlStageFromMaterial({
    build: async (workPath) =>
      await buildConvexWasmModuleGraphAotMaterial({
        buildAot,
        coreWasm: {
          cacheKey: coreWasm.report.cacheKey,
          path: coreWasm.entry.artifactPath,
          sha256: coreWasm.entry.artifactSha256,
          size: coreWasm.entry.artifactSize,
        },
        engine,
        materialIdentity: aotMaterialIdentity,
        role: module.role,
        workPath,
      }),
    cacheLayout,
    cacheRoot,
    extension: "cwasm",
    identity: aotIdentity,
    immutableCacheValidationMemo,
    materialIdentity: aotMaterialIdentity,
    materialStage: moduleGraphAotMaterialStage(),
    maxArtifactBytes: limits.aotBytes,
    previousIdentity: undefined,
    stage: moduleGraphAotStage(module.role),
  });
  normalizeEngineIdentity(aot.entry.metadata, engine.config, engine.target);
  return { aot, aotIdentity, coreIdentity, coreWasm, ...module };
}

export async function buildConvexWasmModuleGraphPackage(options) {
  return await buildConvexWasmModuleGraphPackageInPayloadValidationScope(
    options,
    createConvexWasmModuleGraphPackagePayloadValidationScope()
  );
}

async function buildConvexWasmModuleGraphPackageInPayloadValidationScope(
  {
    artifactLimits,
    buildAot,
    buildCoreWasm,
    beforePackagePublication,
    cacheLayout: rawCacheLayout,
    cacheRoot,
    coreWasmInputs: rawCoreWasmInputs,
    engine: rawEngine,
    hostAbi: rawHostAbi,
    initialization: rawInitialization,
    concurrency: rawConcurrency,
    maximumPackageValidationAttempts: rawMaximumPackageValidationAttempts,
    modules: rawModules,
    physicalShardPlan: rawPhysicalShardPlan,
    previousGraphManifest: rawPreviousGraphManifest,
    producerIdentity: rawProducerIdentity,
    contextReuseAnalysisIdentity: rawContextReuseAnalysisIdentity,
    routing: rawRouting,
    toolchain: rawToolchain,
  },
  payloadValidationScope
) {
  if (typeof buildCoreWasm !== "function" || typeof buildAot !== "function") {
    fail("module graph artifact builders must be functions");
  }
  if (beforePackagePublication !== undefined && typeof beforePackagePublication !== "function") {
    fail("module graph package publication barrier must be a function");
  }
  const concurrency = requirePositiveInteger(rawConcurrency, "module graph build concurrency");
  const cacheLayout = normalizeConvexWasmCacheLayout(rawCacheLayout);
  if (cacheRoot !== cacheLayout.cacheRoot) {
    fail("module graph cache root disagrees with its normalized immutable cache layout");
  }
  const immutableCacheValidationMemo = new Map();
  requireExactPlainObject(
    artifactLimits,
    ["aotBytes", "wasmBytes"],
    "module graph artifact limits"
  );
  const limits = {
    aotBytes: Math.min(
      requirePositiveInteger(artifactLimits.aotBytes, "module graph AOT byte limit"),
      convexWasmSerializedModuleMaxBytes
    ),
    wasmBytes: Math.min(
      requirePositiveInteger(artifactLimits.wasmBytes, "module graph Core Wasm byte limit"),
      convexWasmModuleGraphCoreWasmMaxBytes
    ),
  };
  const engine = normalizeModuleGraphEngine(rawEngine);
  const hostAbi = normalizeModuleGraphHostAbi(rawHostAbi);
  const routing = normalizeModuleGraphRouting(rawRouting);
  const contextReuseAnalysis = authenticateConvexContextReuseCohortAnalysisIdentity(
    rawContextReuseAnalysisIdentity
  );
  const topology = moduleGraphTopologyFromBuildInputs(
    rawModules,
    rawPhysicalShardPlan,
    routing.cohortId
  );
  const modules = rawModules.map((module, index) =>
    normalizeModuleGraphModule(
      module,
      topology.roles[index],
      topology.roles,
      engine.compatibilitySha256
    )
  );
  // Some generic callers build Core Wasm directly and cannot prove an exact predecessor digest.
  // They intentionally omit this input and retain the control-keyed path; only authenticated
  // predecessor bytes may opt into cross-control material reuse.
  const coreWasmInputs =
    rawCoreWasmInputs === undefined
      ? undefined
      : normalizeModuleGraphCoreWasmInputs(rawCoreWasmInputs, topology.roles);
  const previousGraphManifest =
    rawPreviousGraphManifest === undefined
      ? undefined
      : normalizeModuleGraphManifest(rawPreviousGraphManifest);
  validateModuleGraphProviders(modules, hostAbi);
  if (modules.some((module) =>
    module.ownership.tags.length !== modules[0].ownership.tags.length ||
    module.ownership.tags.some((tag, index) => tag !== modules[0].ownership.tags[index])
  )) {
    fail("module graph modules must authenticate the same shared Wasm EH tag set");
  }
  const initialization = normalizeModuleGraphInitialization(rawInitialization, modules);
  const toolchain = normalizeModuleGraphToolchain(rawToolchain);
  const producerIdentity = normalizeConvexWasmProducerIdentity(rawProducerIdentity);
  const producerImplementation = {
    kind: producerIdentity.kind,
    sha256: producerIdentity.sha256,
  };
  const leafInvalidation = createModuleGraphLeafInvalidation(modules, routing);
  const leafInvalidationSha256 = fingerprintJson(leafInvalidation);
  const directories = await Promise.allSettled(
    [cacheLayout.immutable.artifacts, cacheLayout.immutable.packages, cacheLayout.work.scratch].map(
      async (directory) => {
        await fs.mkdir(directory, { recursive: true, mode: 0o700 });
        await requirePrivateCacheDirectory(cacheRoot, directory);
      }
    )
  );
  const directoryFailure = directories.find(({ status }) => status === "rejected");
  if (directoryFailure !== undefined) throw directoryFailure.reason;

  const builtModules = await mapBounded(modules, concurrency, async (module) => {
    const options = {
      buildAot,
      buildCoreWasm,
      cacheLayout,
      cacheRoot,
      coreWasmInput: coreWasmInputs?.[module.role],
      engine,
      immutableCacheValidationMemo,
      leafInvalidation,
      leafInvalidationSha256,
      limits,
      module,
      routing,
      toolchain,
    };
    return await buildConvexWasmModuleGraphModuleArtifacts(options);
  });

  if (beforePackagePublication !== undefined) await beforePackagePublication();

  const manifestPayload = {
    contextReuseAnalysis,
    engine,
    hostAbi,
    initialization,
    kind: convexWasmModuleGraphManifestKind,
    moduleReferences: builtModules.map((module) => {
      const artifacts = {
        aot: {
          cacheKey: module.aot.report.cacheKey,
          sha256: module.aot.entry.artifactSha256,
          size: module.aot.entry.artifactSize,
          stage: moduleGraphAotStage(module.role),
        },
        coreWasm: {
          cacheKey: module.coreWasm.report.cacheKey,
          sha256: module.coreWasm.entry.artifactSha256,
          size: module.coreWasm.entry.artifactSize,
          stage: moduleGraphCoreStage(module.role),
        },
      };
      return module.role === MODULE_GRAPH_LEAF_ROLE
        ? {
            artifacts,
            contract: module.contract,
            layout: module.layout,
            link: module.link,
            objectCompilation: module.objectCompilation,
            ownership: module.ownership,
            providers: module.providers,
            role: module.role,
            sourceProvenance: module.sourceProvenance,
          }
        : {
            artifacts,
            authority: {
              kind: "convex-wasm-module-graph-core-identity-authority-v1",
            },
            role: module.role,
          };
    }),
    producerImplementation,
    replacement: {
      leafInvalidation,
      leafInvalidationSha256,
      previousGraphManifestSha256: previousGraphManifest?.graphManifestSha256 ?? null,
      replace: previousGraphManifest === undefined ? "all" : MODULE_GRAPH_LEAF_ROLE,
      stable:
        previousGraphManifest === undefined ? [] : moduleGraphRoles(builtModules.slice(0, -1)),
    },
    routing,
    schemaVersion: 5,
    ...(topology.sharedShards === undefined ? {} : { sharedShards: topology.sharedShards }),
    toolchain,
  };
  const manifest = createModuleGraphManifestFromBuiltModules(
    {
      ...manifestPayload,
      graphManifestSha256: fingerprintJson(manifestPayload),
    },
    builtModules
  );
  if (previousGraphManifest !== undefined) {
    assertConvexWasmModuleGraphLeafReplacement({
      previousGraphManifest,
      replacementGraphManifest: manifest,
    });
  }
  const provenance = normalizeModuleGraphProvenance(
    {
      contextReuseAnalysis: manifest.contextReuseAnalysis,
      kind: convexWasmModuleGraphProvenanceKind,
      producerIdentity,
      schemaVersion: 5,
    },
    manifest
  );
  const publicationPackageValidationMemo = new Map();
  const maximumPackageValidationAttempts =
    rawMaximumPackageValidationAttempts === undefined
      ? 4
      : Math.max(
          4,
          requirePositiveInteger(
            rawMaximumPackageValidationAttempts,
            "module graph package build validation attempt limit"
          )
        );
  const packageResult = await publishModuleGraphPackage({
    cacheLayout,
    cacheRoot,
    immutableCacheValidationMemo: new Map(),
    manifest,
    maximumValidationAttempts: maximumPackageValidationAttempts,
    modules: builtModules,
    packageValidationMemo: publicationPackageValidationMemo,
    payloadValidationScope,
    provenance,
  });
  const packageAuthority =
    packageResult.verifiedPackage ??
    (await loadAndVerifyConvexWasmModuleGraphPackageInValidationScope(
      {
        cacheLayout,
        cacheRoot,
        expectedGraphManifest: manifest,
        expectedProvenance: provenance,
        graphManifestSha256: manifest.graphManifestSha256,
        packagePath: packageResult.path,
      },
      new Map(),
      new Map(),
      maximumPackageValidationAttempts,
      payloadValidationScope
    ));
  const graphManifest = packageAuthority.graphManifest;
  const packageRecord = Object.freeze(packageAuthority.package);
  const retainedPackageAuthority = Object.freeze(packageAuthority);
  const expectedProvenance = packageAuthority.provenance;
  if (expectedProvenance === undefined) {
    fail("module graph package authority lacks its expected provenance");
  }
  const verifyMaterials = async (validationScope) =>
    await loadAndVerifyConvexWasmModuleGraphPackageCollection({
      cacheLayout,
      cacheRoot,
      packages: [
        {
          authenticatedPackageMaterial: retainedPackageAuthority.packageMaterial,
          expectedGraphManifest: graphManifest,
          expectedProvenance,
          graphManifestSha256: graphManifest.graphManifestSha256,
          packagePath: packageRecord.path,
        },
      ],
      validationScope,
    });
  const artifact = {
    buildReport: {
      kind: "convex-wasm-module-graph-build-report-v1",
      modules: builtModules.map((module) => ({
        aot: module.aot.report,
        coreWasm: module.coreWasm.report,
        role: module.role,
      })),
      package: {
        cache: packageResult.cache,
        cacheKey: packageResult.cacheKey,
        reason:
          packageResult.cache === "hit"
            ? "complete-authenticated-module-graph-package-present"
            : "complete-authenticated-module-graph-package-absent",
      },
    },
    graphManifest,
    package: packageRecord,
    verifyMaterials,
  };
  return artifact;
}
