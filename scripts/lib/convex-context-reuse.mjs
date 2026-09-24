import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  constants as fsConstants,
  closeSync,
  existsSync,
  fchmodSync,
  fstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { convexApiFunctionsRoot } from "./convex-api-flattener-reuse.mjs";
import { defaultConvexWasmCacheRoot } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  canonicalCompilerPackageJson,
  loadAndVerifyCompilerPackage,
} from "./convex-wasm-compiler-package.mjs";
import {
  captureConvexContextReusePackageReviewMaterials,
  captureConvexContextReusePolicyInputMaterials,
  createConvexContextReuseAnalysisInput,
  createConvexContextReuseAnalysisInputGraphSha256,
} from "./convex-context-reuse-analysis-input.mjs";
import {
  authenticateConvexContextReuseApplicationAdmission,
  authenticateConvexContextReuseApplicationAdmissionPolicy,
  captureContextReuseExternalDependencyIdentities,
  compareStrings,
  contextReuseOutputDiagnosticEncoding,
  contextReuseResultIdentity,
  convexContextReuseTestHooks,
  dependencyMaterial,
  freezeGraphBasis,
  installedPackageBoundary,
  loadConvexContextReuseApplicationAdmissionPolicy,
  normalizedThirdPartyMaterialFingerprints,
  requireContextReuseOutput,
  requireContextReuseResultSelection,
  retainConvexContextReuseApplicationAdmission,
  sortedContextReuseEntries,
  statusIdentity,
  toPosix,
  validContextReusePath,
  validSha256,
} from "./convex-context-reuse-application-admission.mjs";
import { authenticateConvexContextReuseCohortAnalysisIdentity } from "./convex-context-reuse-cohort-identity.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";

export {
  authenticateConvexContextReuseApplicationAdmission,
  authenticateConvexContextReuseApplicationAdmissionPolicy,
  captureContextReuseExternalDependencyIdentities,
  convexContextReuseTestHooks,
  loadConvexContextReuseApplicationAdmissionPolicy,
  retainConvexContextReuseApplicationAdmission,
};
export {
  authenticateConvexContextReuseCohortAnalysisIdentity,
  authenticateConvexContextReuseResultIdentity,
};

const INPUT_KIND = "convex-context-reuse-graph";
const OUTPUT_KIND = "convex-context-reuse-analysis";
const APPLICATION_ADMISSION_KIND = "convex-context-reuse-application-admission";
const APPLICATION_ADMISSION_POLICY_FILE = "convex-context-reuse-application-admission.json";
const THIRD_PARTY_POLICY_FILE = "convex-context-reuse-third-party-policy.json";
const COHORT_IDENTITY_KIND = "convex-context-reuse-cohort-analysis";
const SHARED_IDENTITY_KIND = "convex-context-reuse-shared-analysis";
const RESULT_CACHE_KIND = "convex-context-reuse-result-cache";
const ENTRY_CACHE_KIND = "convex-context-reuse-entry-cache";
const EXPANDED_DIAGNOSTIC_ENCODING = "expanded";
const GROUPED_DIAGNOSTIC_ENCODING = "grouped";
const ADMISSION_DIAGNOSTIC_ENCODING = "admission";
const DEFAULT_COMPILER_TIMEOUT_MS = 120_000;
const MAX_COMPILER_TIMEOUT_MS = 600_000;
const MAX_RESULT_CACHE_BYTES = 256 * 1024 * 1024;
const MAX_INPUT_IDENTITY_CHANGE_DIAGNOSTICS = 8;
const scriptsDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const toolRoot = dirname(scriptsDirectory);

// This identity is the narrow handoff from the complete analyzer into Wasm admission. Keep
// the full result out of deployment/artifact records, but bind its semantic fields and policy
// fingerprint so metrics and a config-only selection cannot masquerade as analysis authority.
export const convexContextReuseAnalysisKind = OUTPUT_KIND;
export const convexContextReuseApplicationAdmissionKind = APPLICATION_ADMISSION_KIND;
export const convexContextReuseApplicationAdmissionPolicyFile = APPLICATION_ADMISSION_POLICY_FILE;
export const convexContextReuseCohortAnalysisKind = COHORT_IDENTITY_KIND;
const producerIdentity = await buildConvexWasmProducerIdentity(toolRoot);
const policyInputPaths = [
  join(scriptsDirectory, "convex-wasm-artifact-producer-source-manifest.json"),
  ...producerIdentity.sources.map(({ path }) => join(toolRoot, path)),
];

function thirdPartyPolicyPathForGraph(graph) {
  if (graph.thirdPartyPolicyPath === undefined || graph.thirdPartyPolicyPath === null) {
    return undefined;
  }
  const expectedPolicyPath = join(resolve(graph.repoRoot), THIRD_PARTY_POLICY_FILE);
  if (graph.thirdPartyPolicyPath !== expectedPolicyPath) {
    throw new Error(
      "Convex context-reuse third-party policy path must name the repository policy file."
    );
  }
  return expectedPolicyPath;
}

function isInside(directory, filePath) {
  const path = relative(directory, filePath);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`));
}

function readEntryPolicyConfig(repoRoot, functionsDirectory) {
  const configPath = join(repoRoot, "convex.json");
  if (!existsSync(configPath)) {
    return { defaultEnabled: false, exclusions: {} };
  }
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new Error("convex.json must contain an object.");
  }
  const configuredFunctions = Object.hasOwn(config, "functions") ? config.functions : "convex/";
  if (typeof configuredFunctions !== "string") {
    throw new Error("convex.json functions must be a string.");
  }
  if (resolve(repoRoot, configuredFunctions) !== functionsDirectory) {
    throw new Error(
      `Context-reuse functions directory disagrees with convex.json: ${toPosix(configuredFunctions)}.`
    );
  }
  const policy = config.bundler?.experimentalContextReuse;
  if (policy === undefined) {
    return { defaultEnabled: false, exclusions: {} };
  }
  if (
    typeof policy !== "object" ||
    policy === null ||
    Array.isArray(policy) ||
    policy.default !== true ||
    typeof (policy.exclusions ?? {}) !== "object" ||
    policy.exclusions === null ||
    Array.isArray(policy.exclusions)
  ) {
    throw new Error(
      "convex.json bundler.experimentalContextReuse must contain default true and an exclusions object."
    );
  }
  const exclusions = {};
  for (const [entryPath, reason] of Object.entries(policy.exclusions ?? {})) {
    if (
      typeof reason !== "string" ||
      reason.length < 32 ||
      reason.trim() !== reason ||
      /[\r\n]/u.test(reason)
    ) {
      throw new Error(
        `convex.json context-reuse exclusion ${entryPath} must contain a literal reason of at least 32 characters.`
      );
    }
    const absoluteEntry = resolve(functionsDirectory, entryPath);
    if (
      !isInside(functionsDirectory, absoluteEntry) ||
      entryPath !== toPosix(relative(functionsDirectory, absoluteEntry))
    ) {
      throw new Error(
        `convex.json context-reuse exclusion ${entryPath} must be a normalized POSIX path relative to the functions directory.`
      );
    }
    exclusions[toPosix(relative(repoRoot, absoluteEntry))] = reason;
  }
  return { defaultEnabled: true, exclusions };
}

async function buildContextReuseGraphAndSession(repoRoot, generatedInventory, options = {}) {
  const normalizedRoot = resolve(repoRoot);
  const functionsRoot = convexApiFunctionsRoot(
    JSON.parse(readFileSync(join(normalizedRoot, "convex.json"), "utf8"))
  );
  const functionsDirectory = join(normalizedRoot, functionsRoot);
  const additionalRoots = options.sourceRoots ?? [];
  if (
    !Array.isArray(additionalRoots) ||
    additionalRoots.some(
      (root) =>
        typeof root !== "string" ||
        root.length === 0 ||
        root.startsWith("/") ||
        root.includes("\\") ||
        root.split("/").some((part) => part.length === 0 || part === "." || part === "..")
    ) ||
    new Set([functionsRoot, ...additionalRoots]).size !== additionalRoots.length + 1 ||
    additionalRoots.some(
      (root) =>
        root.startsWith(`${functionsRoot}/`) ||
        functionsRoot.startsWith(`${root}/`) ||
        additionalRoots.some((other) => other !== root && other.startsWith(`${root}/`))
    )
  ) {
    throw new Error("Context-reuse source roots must be unique normalized application directories.");
  }
  const roots = [functionsRoot, ...additionalRoots].sort();
  const policy = readEntryPolicyConfig(normalizedRoot, functionsDirectory);
  const applicationAdmissionPolicyPath = join(normalizedRoot, APPLICATION_ADMISSION_POLICY_FILE);
  const applicationAdmissionPolicy =
    loadConvexContextReuseApplicationAdmissionPolicy(normalizedRoot);
  const thirdPartyPolicyPath = join(normalizedRoot, THIRD_PARTY_POLICY_FILE);
  const hasThirdPartyPolicy = existsSync(thirdPartyPolicyPath);
  if (generatedInventory === undefined) {
    const { loadConvexGeneratedApiInventory } =
      await import("./convex-generated-api-inventory.mjs");
    generatedInventory = await loadConvexGeneratedApiInventory({
      repoRoot: normalizedRoot,
      gitSourceSnapshot: options.gitSourceSnapshot,
    });
  }
  // The compiler protocol intentionally carries only the route identity needed
  // for source-registration comparison. The inventory also retains its
  // source-module path for downstream routing, but that field is not part of
  // the authenticated context-reuse input contract.
  const databaseFunctions = generatedInventory.inventory.functions.map(
    ({ entryPath, exportName, udfKind }) => ({ entryPath, exportName, udfKind })
  );
  const entryCandidatePaths = [...new Set(databaseFunctions.map((func) => func.entryPath))].sort();
  const graphInventory = {
    authority: {
      sourceRoot: functionsRoot,
      snapshot: generatedInventory.inventory.snapshot,
    },
    ...(Array.isArray(generatedInventory.inventory.actions)
      ? { actions: generatedInventory.inventory.actions }
      : {}),
    // Keep the complete route records on the deployment graph boundary. The analyzer protocol
    // narrows them to databaseFunctions above, while a daemon-owned graph session must retain the
    // exact generated route topology for the following source-envelope request.
    functions: generatedInventory.inventory.functions,
  };
  const {
    buildConvexWasmDeploymentGraphSession,
    captureConvexWasmContextReuseAnalysisInputGraphBasis,
    captureConvexWasmContextReuseSourceTexts,
  } = await import("./convex-wasm-deployment-graph.mjs");
  const graphBuilder = options.graphBuilder ?? buildConvexWasmDeploymentGraphSession;
  if (typeof graphBuilder !== "function") {
    throw new Error("Convex context-reuse graph builder must be a function.");
  }
  const session = await graphBuilder({
    ...(options.effectExecutionMode === undefined
      ? {}
      : { effectExecutionMode: options.effectExecutionMode }),
    ...(options.gitSourceSnapshot === undefined
      ? {}
      : { gitSourceSnapshot: options.gitSourceSnapshot }),
    ...(options.includeSourceGraphSnapshot === undefined
      ? {}
      : { includeSourceGraphSnapshot: options.includeSourceGraphSnapshot }),
    inventory: graphInventory,
    materialVerificationConcurrency: options.materialVerificationConcurrency ?? 1,
    repoRoot: normalizedRoot,
  });
  const deploymentGraphBasis = captureConvexWasmContextReuseAnalysisInputGraphBasis(session);
  const databaseEntryPaths = new Set(databaseFunctions.map(({ entryPath }) => entryPath));
  const expectedContextReuseSelectionPayload = {
    entries: deploymentGraphBasis.bundleEntryPaths
      .filter((entryPath) => databaseEntryPaths.has(entryPath))
      .map((entryPath) => ({
        enabled: policy.defaultEnabled && !Object.hasOwn(policy.exclusions, entryPath),
        entryPath,
      })),
    kind: "convex-wasm-context-reuse-selection",
  };
  const expectedContextReuseSelection = {
    ...expectedContextReuseSelectionPayload,
    sha256: fingerprintJson(expectedContextReuseSelectionPayload),
  };
  if (
    JSON.stringify(deploymentGraphBasis.contextReusePolicy) !==
    JSON.stringify(expectedContextReuseSelection)
  ) {
    throw new Error(
      "Context-reuse analysis policy disagrees with the authenticated deployment graph policy."
    );
  }
  const { externalDependencies, externalDependencyManifestPaths, externalDependencyResolutions } =
    captureContextReuseExternalDependencyIdentities(normalizedRoot, session.graphTemplate.metafile);
  const graph = {
    kind: INPUT_KIND,
    repoRoot: normalizedRoot,
    functionsRoot,
    roots,
    entryCandidates: entryCandidatePaths,
    databaseFunctions,
    ...policy,
    virtualInputs: Object.entries(deploymentGraphBasis.inputMaterials)
      .filter(([, material]) => material.virtual === true)
      .map(([path]) => path)
      .sort(),
    defaultDatabaseEntries: entryCandidatePaths,
    generatedInventorySnapshot: structuredClone(generatedInventory.inventory.snapshot),
    metafile: session.graphTemplate.metafile,
    registrationAdapter: deploymentGraphBasis.registrationAdapter,
    resultCacheInputPaths: [
      ...session.toolchainInputPaths,
      ...externalDependencyManifestPaths,
      ...(applicationAdmissionPolicy === undefined ? [] : [applicationAdmissionPolicyPath]),
    ].sort(),
    thirdPartyPolicyPath: hasThirdPartyPolicy ? thirdPartyPolicyPath : null,
    externalDependencies,
    externalDependencyResolutions,
    phaseTimingsUs: session.graphTemplate.phaseTimingsUs,
    ...(options.gitSourceSnapshot === undefined
      ? {}
      : {
          sourceTexts: await captureConvexWasmContextReuseSourceTexts(session, {
            functionsRoot,
            sourceRoots: roots.map((root) => `${root}/`),
          }),
        }),
  };
  // The private basis is immutable, but native execution also consumes these top-level graph
  // fields. Freeze their containers so callers cannot change the protocol input after its basis
  // was authenticated (the acceptance harness may still attach its own non-authority metadata).
  for (const field of [
    "roots",
    "entryCandidates",
    "databaseFunctions",
    "defaultDatabaseEntries",
    "exclusions",
    "virtualInputs",
    "generatedInventorySnapshot",
    "metafile",
    "registrationAdapter",
    "resultCacheInputPaths",
    "thirdPartyPolicyPath",
    "externalDependencies",
    "externalDependencyResolutions",
    "phaseTimingsUs",
    "sourceTexts",
  ]) {
    freezeGraphBasis(graph[field]);
  }
  // This private projection is deliberately non-enumerable: the complete graph identity belongs
  // to the JavaScript deployment wrapper, not the native context-reuse input protocol. Keeping it
  // out of JSON also prevents wrapper-only authority fields from being mistaken for compiler
  // inputs.
  Object.defineProperty(graph, "analysisInputGraphBasis", {
    configurable: false,
    enumerable: false,
    value: freezeGraphBasis({
      ...deploymentGraphBasis,
      databaseFunctions,
      // Package names and versions for external runtime imports are not encoded in the esbuild
      // metafile. Keep them in the wrapper-owned basis so a package-manifest/version change cannot
      // leave the same analysis-input digest attached to a different diagnostic identity.
      externalDependencies,
      generatedInventoryInputSha256: generatedInventory.inventory.snapshot.inputSha256,
      policy,
    }),
    writable: false,
  });
  // Verify after deriving dependency identities so a graph/source change during construction
  // fails against the exact material esbuild loaded. The analysis wrapper captures cache inputs
  // immediately after this function returns and verifies them again after native analysis.
  await session.verifyInputMaterials();
  return { graph, graphSession: session };
}

export async function buildContextReuseGraph(repoRoot, generatedInventory, options) {
  return (await buildContextReuseGraphAndSession(repoRoot, generatedInventory, options)).graph;
}

export function contextReuseCacheDir() {
  return join(defaultConvexWasmCacheRoot(), "context-reuse");
}

function resultCachePath(repoRoot) {
  const repositoryIdentity = createHash("sha256").update(resolve(repoRoot)).digest("hex");
  return join(defaultConvexWasmCacheRoot(), "context-reuse", `${repositoryIdentity}.json`);
}

function ensurePrivateResultCacheDirectory() {
  const cacheRoot = join(defaultConvexWasmCacheRoot(), "context-reuse");
  mkdirSync(cacheRoot, { recursive: true, mode: 0o700 });
  if (fsConstants.O_NOFOLLOW === undefined || fsConstants.O_DIRECTORY === undefined) {
    throw new Error("this platform cannot authenticate private cache directories");
  }
  const descriptor = openSync(
    cacheRoot,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
  );
  try {
    const status = fstatSync(descriptor);
    if (
      !status.isDirectory() ||
      (typeof process.getuid === "function" && status.uid !== process.getuid())
    ) {
      throw new Error(`${cacheRoot} must be a directory owned by the current user`);
    }
    fchmodSync(descriptor, 0o700);
  } finally {
    closeSync(descriptor);
  }
}

function statIdentity(path) {
  return statusIdentity(path, statSync(path, { bigint: true }));
}

function inputIdentityChangeDiagnostic(beforeIdentities, afterIdentities) {
  const beforeByPath = new Map(beforeIdentities.map((identity) => [identity.path, identity]));
  const afterByPath = new Map(afterIdentities.map((identity) => [identity.path, identity]));
  const shownChanges = [];
  let changeCount = 0;
  const recordChange = (change) => {
    changeCount += 1;
    if (shownChanges.length < MAX_INPUT_IDENTITY_CHANGE_DIAGNOSTICS) {
      shownChanges.push(change);
    }
  };
  const identityFields = [
    "kind",
    "device",
    "inode",
    "size",
    "modifiedNanoseconds",
    "changedNanoseconds",
  ];
  for (const path of [...new Set([...beforeByPath.keys(), ...afterByPath.keys()])].sort()) {
    const before = beforeByPath.get(path);
    const after = afterByPath.get(path);
    if (before === undefined) {
      recordChange({ change: "added", identity: after, path });
      continue;
    }
    if (after === undefined) {
      recordChange({ change: "removed", identity: before, path });
      continue;
    }
    const fields = Object.fromEntries(
      identityFields
        .filter((field) => before[field] !== after[field])
        .map((field) => [field, { after: after[field], before: before[field] }])
    );
    if (Object.keys(fields).length > 0) {
      recordChange({ change: "changed", fields, path });
    }
  }
  return `showing ${shownChanges.length} of ${changeCount} path changes ${JSON.stringify(
    shownChanges
  )}`;
}

function identityMatches(identity) {
  try {
    return JSON.stringify(statIdentity(identity.path)) === JSON.stringify(identity);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function hashOpenedFile(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    throw new Error("this platform cannot authenticate an opened compiler binary");
  }
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size <= 0n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${path} must be a non-empty regular compiler binary.`);
    }
    const size = Number(before.size);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < size) {
      const bytesRead = readSync(
        descriptor,
        buffer,
        0,
        Math.min(buffer.length, size - offset),
        offset
      );
      if (bytesRead === 0) {
        throw new Error(`${path} changed while it was being hashed.`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (
      JSON.stringify(statusIdentity(path, before)) !== JSON.stringify(statusIdentity(path, after))
    ) {
      throw new Error(`${path} changed while it was being hashed.`);
    }
    return { sha256: hash.digest("hex"), size };
  } finally {
    closeSync(descriptor);
  }
}

function directCompilerSelection(compilerBinary) {
  if (typeof compilerBinary !== "string" || compilerBinary.length === 0) {
    throw new Error("Convex context-reuse direct compiler binary path must be non-empty.");
  }
  const binaryPath = resolve(compilerBinary);
  const binaryIdentity = hashOpenedFile(binaryPath);
  return {
    binaryIdentity,
    binaryPath,
    cacheIdentity: {
      binary: binaryIdentity,
      kind: "direct-binary",
    },
    cacheInputPaths: [binaryPath],
  };
}

function compilerPackageCacheIdentity(manifest) {
  return {
    binary: {
      sha256: manifest.binary.sha256,
      size: manifest.binary.size,
    },
    kind: "compiler-package",
    manifest: {
      kind: manifest.kind,
      packageId: manifest.packageId,
      schemaVersion: manifest.schemaVersion,
      sha256: createHash("sha256")
        .update(`${canonicalCompilerPackageJson(manifest)}\n`)
        .digest("hex"),
    },
  };
}

function normalizedCompilerSelection(selection) {
  const normalized = typeof selection === "string" ? directCompilerSelection(selection) : selection;
  if (
    typeof normalized !== "object" ||
    normalized === null ||
    Array.isArray(normalized) ||
    typeof normalized.binaryPath !== "string" ||
    !validBinaryIdentity(normalized.binaryIdentity) ||
    !validCompilerCacheIdentity(normalized.cacheIdentity) ||
    !Array.isArray(normalized.cacheInputPaths) ||
    normalized.cacheInputPaths.some((path) => typeof path !== "string")
  ) {
    throw new Error("Convex context-reuse compiler selection is invalid.");
  }
  if (
    JSON.stringify(normalized.binaryIdentity) !== JSON.stringify(normalized.cacheIdentity.binary)
  ) {
    throw new Error("Convex context-reuse compiler selection binary identity is inconsistent.");
  }
  return normalized;
}

function normalizedDiagnosticEncoding(value = EXPANDED_DIAGNOSTIC_ENCODING) {
  if (
    value !== EXPANDED_DIAGNOSTIC_ENCODING &&
    value !== GROUPED_DIAGNOSTIC_ENCODING &&
    value !== ADMISSION_DIAGNOSTIC_ENCODING
  ) {
    throw new Error(
      `Convex context-reuse diagnostic encoding must be ${EXPANDED_DIAGNOSTIC_ENCODING}, ${GROUPED_DIAGNOSTIC_ENCODING}, or ${ADMISSION_DIAGNOSTIC_ENCODING}.`
    );
  }
  return value;
}

function validBinaryIdentity(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === "sha256,size" &&
    validSha256(value.sha256) &&
    Number.isSafeInteger(value.size) &&
    value.size > 0
  );
}

function validStatIdentity(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") ===
      "changedNanoseconds,device,inode,kind,modifiedNanoseconds,path,size" &&
    typeof value.path === "string" &&
    resolve(value.path) === value.path &&
    ["directory", "file", "other"].includes(value.kind) &&
    [
      value.device,
      value.inode,
      value.size,
      value.modifiedNanoseconds,
      value.changedNanoseconds,
    ].every((component) => typeof component === "string" && /^-?[0-9]+$/u.test(component))
  );
}

/**
 * Authenticate one complete, safe result for a concrete graph selection.
 *
 * The analyzer result is intentionally retained by callers only at the boundary where it is
 * consumed.  Downstream manifests and runtime identities carry this compact digest identity;
 * they must never reconstruct authority from `contextReuseEnabledByEntry` alone.
 */
export function authenticateConvexContextReuseResult(
  result,
  { expectedEntries, expectedAnalysisInputGraphSha256 } = {}
) {
  const output = requireContextReuseOutput(result, "Convex context-reuse result", {
    requireAnalysisInputSha256: true,
  });
  if (output.safe !== true) {
    throw new Error("Convex context-reuse result is not safe for Wasm admission.");
  }
  const entries = sortedContextReuseEntries(output.entries, "Convex context-reuse result entries");
  requireContextReuseResultSelection(output, entries, {
    expectedAnalysisInputGraphSha256,
    expectedEntries,
  });
  // Cache outcomes, timings, and process counters describe one execution, not the admitted
  // application. Excluding metrics keeps repeated authentication of the same semantic result
  // stable across cache hits and misses. Accepted package material must remain in this projection:
  // safe diagnostics are otherwise silent when one reviewed exact closure replaces another.
  return contextReuseResultIdentity(output, entries);
}

export function convexContextReuseGeneratedInventoryInputSha256(result, { expectedIdentity } = {}) {
  const output = requireContextReuseOutput(result, "Convex context-reuse result", {
    requireAnalysisInputSha256: true,
  });
  if (output.safe !== true) {
    throw new Error("Convex context-reuse result is not safe for Wasm admission.");
  }
  const identity = authenticateConvexContextReuseResult(result);
  if (
    expectedIdentity !== undefined &&
    JSON.stringify(identity) !==
      JSON.stringify(authenticateConvexContextReuseResultIdentity(expectedIdentity))
  ) {
    throw new Error(
      "Convex context-reuse generated inventory input disagrees with its result identity."
    );
  }
  return output.generatedInventoryInputSha256;
}

export function createConvexContextReuseSharedAnalysisIdentity(result, { expectedIdentity } = {}) {
  const output = requireContextReuseOutput(result, "Convex context-reuse result", {
    requireAnalysisInputSha256: true,
  });
  if (output.safe !== true) {
    throw new Error("Convex context-reuse result is not safe for Wasm admission.");
  }
  const identity = authenticateConvexContextReuseResult(result);
  if (
    expectedIdentity !== undefined &&
    JSON.stringify(identity) !==
      JSON.stringify(authenticateConvexContextReuseResultIdentity(expectedIdentity))
  ) {
    throw new Error("Convex context-reuse shared analysis disagrees with its result identity.");
  }
  const payload = {
    kind: SHARED_IDENTITY_KIND,
    moduleSummarySchema: output.moduleSummarySchema,
    policyFingerprint: output.policyFingerprint,
  };
  return freezeGraphBasis({ ...payload, sha256: fingerprintJson(payload) });
}

export function convexContextReuseThirdPartyMaterialFingerprints(
  result,
  { expectedIdentity } = {}
) {
  const output = requireContextReuseOutput(result, "Convex context-reuse result", {
    requireAnalysisInputSha256: true,
  });
  if (output.safe !== true) {
    throw new Error("Convex context-reuse result is not safe for Wasm admission.");
  }
  const identity = authenticateConvexContextReuseResult(result);
  if (
    expectedIdentity !== undefined &&
    JSON.stringify(identity) !==
      JSON.stringify(authenticateConvexContextReuseResultIdentity(expectedIdentity))
  ) {
    throw new Error(
      "Convex context-reuse third-party material disagrees with its result identity."
    );
  }
  return freezeGraphBasis(
    normalizedThirdPartyMaterialFingerprints(
      output.thirdPartyMaterialFingerprints,
      "Convex context-reuse third-party material fingerprints"
    )
  );
}

export function authenticateConvexContextReuseSharedAnalysisIdentity(value) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "kind,moduleSummarySchema,policyFingerprint,sha256" ||
    value.kind !== SHARED_IDENTITY_KIND ||
    typeof value.moduleSummarySchema !== "string" ||
    value.moduleSummarySchema.length === 0 ||
    !validSha256(value.policyFingerprint) ||
    !validSha256(value.sha256)
  ) {
    throw new Error("Convex context-reuse shared analysis identity is invalid.");
  }
  const payload = {
    kind: value.kind,
    moduleSummarySchema: value.moduleSummarySchema,
    policyFingerprint: value.policyFingerprint,
  };
  if (fingerprintJson(payload) !== value.sha256) {
    throw new Error("Convex context-reuse shared analysis identity digest is invalid.");
  }
  return freezeGraphBasis({ ...payload, sha256: value.sha256 });
}

function normalizedCohortEntryGraphs(entryGraphs, description) {
  if (!Array.isArray(entryGraphs) || entryGraphs.length === 0) {
    throw new Error(`${description} must not be empty.`);
  }
  const normalized = entryGraphs.map((entry, index) => {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      Object.keys(entry).sort().join(",") !== "dependencyGraphSha256,entryPath" ||
      !validContextReusePath(entry.entryPath) ||
      !validSha256(entry.dependencyGraphSha256)
    ) {
      throw new Error(`${description} entry ${index} is invalid.`);
    }
    return {
      dependencyGraphSha256: entry.dependencyGraphSha256,
      entryPath: entry.entryPath,
    };
  });
  const sorted = [...normalized].sort((left, right) =>
    compareStrings(left.entryPath, right.entryPath)
  );
  if (
    JSON.stringify(sorted) !== JSON.stringify(normalized) ||
    new Set(normalized.map(({ entryPath }) => entryPath)).size !== normalized.length
  ) {
    throw new Error(`${description} must be sorted and unique.`);
  }
  return normalized;
}

export function createConvexContextReuseCohortAnalysisIdentity({
  analysisIdentity,
  entryGraphs,
  sharedAnalysisIdentity,
  thirdPartyMaterialFingerprints,
}) {
  const analysis = authenticateConvexContextReuseResultIdentity(analysisIdentity);
  const shared = authenticateConvexContextReuseSharedAnalysisIdentity(sharedAnalysisIdentity);
  if (analysis.policyFingerprint !== shared.policyFingerprint) {
    throw new Error("Convex context-reuse cohort analysis policy identity is inconsistent.");
  }
  const normalizedEntryGraphs = normalizedCohortEntryGraphs(
    entryGraphs,
    "Convex context-reuse cohort analysis entry graphs"
  );
  const analyzedEntries = new Set(analysis.entries);
  if (normalizedEntryGraphs.some(({ entryPath }) => !analyzedEntries.has(entryPath))) {
    throw new Error("Convex context-reuse cohort analysis contains an unanalyzed entry.");
  }
  const payload = {
    entries: normalizedEntryGraphs.map(({ entryPath }) => entryPath),
    entryGraphSha256s: normalizedEntryGraphs.map(
      ({ dependencyGraphSha256 }) => dependencyGraphSha256
    ),
    kind: COHORT_IDENTITY_KIND,
    policyFingerprint: analysis.policyFingerprint,
    sharedAnalysisSha256: shared.sha256,
    thirdPartyMaterialFingerprints: normalizedThirdPartyMaterialFingerprints(
      thirdPartyMaterialFingerprints,
      "Convex context-reuse cohort third-party material fingerprints"
    ),
  };
  return freezeGraphBasis({ ...payload, resultSha256: fingerprintJson(payload) });
}

function validCompilerCacheIdentity(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  if (value.kind === "direct-binary") {
    return (
      Object.keys(value).sort().join(",") === "binary,kind" && validBinaryIdentity(value.binary)
    );
  }
  return (
    value.kind === "compiler-package" &&
    Object.keys(value).sort().join(",") === "binary,kind,manifest" &&
    typeof value.manifest === "object" &&
    value.manifest !== null &&
    !Array.isArray(value.manifest) &&
    Object.keys(value.manifest).sort().join(",") === "kind,packageId,schemaVersion,sha256" &&
    typeof value.manifest.kind === "string" &&
    Number.isSafeInteger(value.manifest.schemaVersion) &&
    validSha256(value.manifest.packageId) &&
    validSha256(value.manifest.sha256) &&
    validBinaryIdentity(value.binary)
  );
}

function compilerCacheIdentityMatches(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

export async function resolveContextReuseCompilerSelection(
  { compilerBinary, compilerPackage } = {},
  environment = process.env
) {
  const packagePath = compilerPackage ?? environment.CONVEX_WASM_COMPILER_PACKAGE;
  const directBinaryPath = compilerBinary ?? environment.CONVEX_WASM_COMPILER_BINARY;
  if (packagePath !== undefined && directBinaryPath !== undefined) {
    throw new Error(
      "Convex context-reuse compiler package and direct compiler binary options are mutually exclusive."
    );
  }
  if (packagePath === undefined) {
    if (directBinaryPath === undefined) {
      throw new Error(
        "Convex context-reuse compiler selection requires an authenticated package or an explicit direct compiler binary."
      );
    }
    return directCompilerSelection(directBinaryPath);
  }
  if (typeof packagePath !== "string" || packagePath.length === 0) {
    throw new Error("Convex context-reuse compiler package path must be non-empty.");
  }
  const loaded = await loadAndVerifyCompilerPackage(packagePath);
  return {
    binaryIdentity: {
      sha256: loaded.manifest.binary.sha256,
      size: loaded.manifest.binary.size,
    },
    binaryPath: loaded.binaryPath,
    cacheIdentity: compilerPackageCacheIdentity(loaded.manifest),
    cacheInputPaths: [],
    sourceIdentity: loaded.manifest.identities.source,
  };
}

function readPrivateContextReuseCache(path) {
  ensurePrivateResultCacheDirectory();
  let descriptor;
  try {
    if (fsConstants.O_NOFOLLOW === undefined) {
      throw new Error("this platform does not provide O_NOFOLLOW");
    }
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw new Error(`Convex context-reuse result cache is corrupt: ${path}`, {
      cause: error,
    });
  }
  let parsed;
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (
      !before.isFile() ||
      before.size <= 0n ||
      before.size > BigInt(MAX_RESULT_CACHE_BYTES) ||
      (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))
    ) {
      throw new Error("cache entry must be a regular file owned by the current user");
    }
    // Published entries are already private; avoid unnecessary permission writes on reads.
    if ((before.mode & 0o777n) !== 0o600n) fchmodSync(descriptor, 0o600);
    parsed = JSON.parse(readFileSync(descriptor, "utf8"));
    const after = fstatSync(descriptor, { bigint: true });
    // Atomic replacement unlinks this reader's old inode and changes its ctime, but the
    // opened bytes remain valid. Only content metadata detects an in-place write here.
    if (before.size !== after.size || before.mtimeNs !== after.mtimeNs) {
      throw new Error("cache entry changed while it was being read");
    }
  } catch (error) {
    throw new Error(`Convex context-reuse result cache is corrupt: ${path}`, {
      cause: error,
    });
  } finally {
    closeSync(descriptor);
  }
  return parsed;
}

export function readContextReuseResultCacheEntry(
  repoRoot,
  compilerSelection,
  generatedInventoryInputSha256,
  diagnosticEncoding = EXPANDED_DIAGNOSTIC_ENCODING
) {
  const normalizedEncoding = normalizedDiagnosticEncoding(diagnosticEncoding);
  if (process.env.CONVEX_DISABLE_CONTEXT_REUSE_RESULT_CACHE === "1") {
    return null;
  }
  const path = resultCachePath(repoRoot);
  const parsed = readPrivateContextReuseCache(path);
  if (parsed === undefined) return null;
  const normalizedSelection = normalizedCompilerSelection(compilerSelection);
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join(",") !==
      "analysisInputSha256,compilerSelection,diagnosticEncoding,generatedInventoryInputSha256,inputs,kind,output,repoRoot" ||
    parsed.kind !== RESULT_CACHE_KIND ||
    typeof parsed.repoRoot !== "string" ||
    !validCompilerCacheIdentity(parsed.compilerSelection) ||
    (parsed.diagnosticEncoding !== EXPANDED_DIAGNOSTIC_ENCODING &&
      parsed.diagnosticEncoding !== GROUPED_DIAGNOSTIC_ENCODING &&
      parsed.diagnosticEncoding !== ADMISSION_DIAGNOSTIC_ENCODING) ||
    typeof parsed.generatedInventoryInputSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(parsed.generatedInventoryInputSha256) ||
    typeof parsed.analysisInputSha256 !== "string" ||
    !validSha256(parsed.analysisInputSha256) ||
    !Array.isArray(parsed.inputs) ||
    parsed.inputs.some((identity) => !validStatIdentity(identity))
  ) {
    throw new Error(`Convex context-reuse result cache is corrupt: ${path}`);
  }
  if (
    parsed.repoRoot !== resolve(repoRoot) ||
    !compilerCacheIdentityMatches(parsed.compilerSelection, normalizedSelection.cacheIdentity) ||
    parsed.diagnosticEncoding !== normalizedEncoding ||
    parsed.generatedInventoryInputSha256 !== generatedInventoryInputSha256
  ) {
    return null;
  }
  try {
    requireContextReuseOutput(parsed.output, "Convex context-reuse cached output", {
      requireAnalysisInputSha256: true,
    });
  } catch (error) {
    throw new Error(`Convex context-reuse result cache is corrupt: ${path}`, {
      cause: error,
    });
  }
  if (
    contextReuseOutputDiagnosticEncoding(parsed.output) !== parsed.diagnosticEncoding ||
    parsed.output.generatedInventoryInputSha256 !== parsed.generatedInventoryInputSha256 ||
    parsed.output.analysisInputSha256 !== parsed.analysisInputSha256
  ) {
    return null;
  }
  return parsed.inputs.every(identityMatches)
    ? { analysisInputSha256: parsed.analysisInputSha256, output: parsed.output }
    : null;
}

export function readContextReuseResultCache(
  repoRoot,
  compilerSelection,
  generatedInventoryInputSha256,
  analysisInputSha256,
  diagnosticEncoding = EXPANDED_DIAGNOSTIC_ENCODING
) {
  if (!validSha256(analysisInputSha256)) return null;
  const entry = readContextReuseResultCacheEntry(
    repoRoot,
    compilerSelection,
    generatedInventoryInputSha256,
    diagnosticEncoding
  );
  return entry?.analysisInputSha256 === analysisInputSha256 ? entry.output : null;
}

function* walkDirectories(directory) {
  if (!existsSync(directory)) {
    return;
  }
  yield directory;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      yield* walkDirectories(join(directory, entry.name));
    }
  }
}

function addResolutionDirectoryInputs(inputs, repoRoot, inputPath) {
  let directory = dirname(inputPath);
  while (isInside(repoRoot, directory)) {
    if (existsSync(directory)) {
      inputs.add(directory);
    }
    if (directory === repoRoot) {
      break;
    }
    directory = dirname(directory);
  }
}

function resultCacheInputs(graph, compilerSelection, additionalPolicyInputPaths) {
  const normalizedSelection = normalizedCompilerSelection(compilerSelection);
  if (
    !Array.isArray(graph.virtualInputs) ||
    graph.virtualInputs.some((inputPath) => typeof inputPath !== "string")
  ) {
    throw new Error("Convex context-reuse graph virtual inputs are invalid.");
  }
  if (
    graph.resultCacheInputPaths !== undefined &&
    (!Array.isArray(graph.resultCacheInputPaths) ||
      graph.resultCacheInputPaths.some(
        (path) => typeof path !== "string" || resolve(path) !== path
      ))
  ) {
    throw new Error("Convex context-reuse graph cache input paths are invalid.");
  }
  const virtualInputs = new Set(graph.virtualInputs);
  const thirdPartyPolicyPath = thirdPartyPolicyPathForGraph(graph);
  const inputs = new Set([
    ...policyInputPaths,
    ...additionalPolicyInputPaths,
    ...normalizedSelection.cacheInputPaths,
    ...(graph.resultCacheInputPaths ?? []),
    ...(thirdPartyPolicyPath === undefined ? [] : [thirdPartyPolicyPath]),
    join(graph.repoRoot, graph.registrationAdapter.source.path),
  ]);
  for (const relativePath of [
    "convex.json",
    `${graph.functionsRoot}/_generated/api.d.ts`,
    "package.json",
    "package-lock.json",
  ]) {
    const path = join(graph.repoRoot, relativePath);
    if (existsSync(path)) {
      inputs.add(path);
    }
  }
  for (const inputPath of Object.keys(graph.metafile.inputs)) {
    if (virtualInputs.has(inputPath)) {
      continue;
    }
    const path = resolve(graph.repoRoot, inputPath);
    // Captured runtime bytes and resolution belong to the graph digest. Later worktree
    // changes, including deletion, must not invalidate analysis of those same bytes.
    if (
      (graph.sourceTexts === undefined || !Object.hasOwn(graph.sourceTexts, inputPath)) &&
      isInside(graph.repoRoot, path) &&
      existsSync(path)
    ) {
      inputs.add(path);
      if (graph.sourceTexts === undefined) {
        addResolutionDirectoryInputs(inputs, graph.repoRoot, path);
      }
    }
    const packageBoundary = installedPackageBoundary(inputPath);
    if (packageBoundary !== undefined) {
      const packageDirectory = resolve(graph.repoRoot, packageBoundary);
      if (isInside(graph.repoRoot, packageDirectory) && existsSync(packageDirectory)) {
        inputs.add(packageDirectory);
        const packageJsonPath = join(packageDirectory, "package.json");
        if (existsSync(packageJsonPath)) {
          inputs.add(packageJsonPath);
        }
      }
    }
  }
  if (!graph.defaultEnabled && graph.sourceTexts === undefined) {
    for (const root of graph.roots) {
      for (const directory of walkDirectories(join(graph.repoRoot, root))) {
        inputs.add(directory);
      }
    }
  }
  return [...inputs].sort().map(statIdentity);
}

export function captureContextReuseResultCacheInputs(
  graph,
  compilerSelection,
  { additionalPolicyInputPaths = [] } = {}
) {
  return resultCacheInputs(graph, compilerSelection, additionalPolicyInputPaths);
}

export function writeContextReuseResultCache(
  repoRoot,
  compilerSelection,
  graph,
  output,
  {
    additionalPolicyInputPaths = [],
    analysisInputSha256,
    diagnosticEncoding = contextReuseOutputDiagnosticEncoding(output),
    preAnalysisInputIdentities,
  } = {}
) {
  const normalizedRepoRoot = resolve(repoRoot);
  if (graph.repoRoot !== normalizedRepoRoot) {
    throw new Error(
      "Convex context-reuse result-cache repository root must match the graph repository root."
    );
  }
  const cacheDisabled = process.env.CONVEX_DISABLE_CONTEXT_REUSE_RESULT_CACHE === "1";
  if (cacheDisabled && preAnalysisInputIdentities === undefined) {
    return;
  }
  requireContextReuseOutput(output, "Convex context-reuse output", {
    requireAnalysisInputSha256: true,
  });
  const normalizedEncoding = normalizedDiagnosticEncoding(diagnosticEncoding);
  if (contextReuseOutputDiagnosticEncoding(output) !== normalizedEncoding) {
    throw new Error("Convex context-reuse result diagnostic encoding is invalid.");
  }
  const normalizedAnalysisInputSha256 = analysisInputSha256 ?? output.analysisInputSha256;
  if (
    !validSha256(normalizedAnalysisInputSha256) ||
    output.analysisInputSha256 !== normalizedAnalysisInputSha256 ||
    output.generatedInventoryInputSha256 !== graph.generatedInventorySnapshot.inputSha256
  ) {
    throw new Error("Convex context-reuse result analysis-input identity is invalid.");
  }
  if (
    graph.analysisInputGraphBasis !== undefined &&
    output.analysisInputGraphSha256 !== createConvexContextReuseAnalysisInputGraphSha256(graph)
  ) {
    throw new Error("Convex context-reuse result graph-input identity is invalid.");
  }
  const normalizedSelection = normalizedCompilerSelection(compilerSelection);
  const currentInputIdentities = resultCacheInputs(
    graph,
    normalizedSelection,
    additionalPolicyInputPaths
  );
  if (
    preAnalysisInputIdentities !== undefined &&
    JSON.stringify(preAnalysisInputIdentities) !== JSON.stringify(currentInputIdentities)
  ) {
    throw new Error(
      `Convex context-reuse inputs changed during native analysis; ${inputIdentityChangeDiagnostic(
        preAnalysisInputIdentities,
        currentInputIdentities
      )}.`
    );
  }
  if (cacheDisabled) {
    return;
  }
  const path = resultCachePath(repoRoot);
  const entry = {
    analysisInputSha256: normalizedAnalysisInputSha256,
    kind: RESULT_CACHE_KIND,
    repoRoot: normalizedRepoRoot,
    compilerSelection: normalizedSelection.cacheIdentity,
    diagnosticEncoding: normalizedEncoding,
    generatedInventoryInputSha256: graph.generatedInventorySnapshot.inputSha256,
    inputs: currentInputIdentities,
    output,
  };
  writePrivateContextReuseCache(path, entry);
}

function writePrivateContextReuseCache(path, entry) {
  ensurePrivateResultCacheDirectory();
  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const encodedEntry = JSON.stringify(entry);
  if (Buffer.byteLength(encodedEntry) > MAX_RESULT_CACHE_BYTES) {
    throw new Error(`Convex context-reuse result cache exceeds ${MAX_RESULT_CACHE_BYTES} bytes.`);
  }
  try {
    const descriptor = openSync(temporaryPath, "wx", 0o600);
    try {
      writeFileSync(descriptor, encodedEntry);
    } finally {
      closeSync(descriptor);
    }
    // Analysis caches are reconstructible. Atomic replacement prevents partial reads; unlike
    // deployment publication, these writes need not survive a host power loss.
    renameSync(temporaryPath, path);
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

function requireCompilerTimeout(timeoutMs) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_COMPILER_TIMEOUT_MS) {
    throw new Error(
      `Convex context-reuse compiler timeout must be an integer from 1 through ${MAX_COMPILER_TIMEOUT_MS} milliseconds.`
    );
  }
  return timeoutMs;
}

export function runContextReuseCompiler({
  graph,
  cacheDir = contextReuseCacheDir(),
  compilerBinary,
  compilerTimeoutMs = DEFAULT_COMPILER_TIMEOUT_MS,
  diagnosticEncoding = EXPANDED_DIAGNOSTIC_ENCODING,
  entryResults,
}) {
  requireCompilerTimeout(compilerTimeoutMs);
  const normalizedEncoding = normalizedDiagnosticEncoding(diagnosticEncoding);
  if (typeof compilerBinary !== "string" || compilerBinary.length === 0) {
    throw new Error("Convex context-reuse compiler binary path must be explicit.");
  }
  if (!existsSync(compilerBinary)) {
    throw new Error(`Convex Wasm compiler binary is missing at ${compilerBinary}.`);
  }
  const thirdPartyPolicyPath = thirdPartyPolicyPathForGraph(graph);
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "convex-context-reuse-"));
  const graphPath = join(temporaryDirectory, "graph.json");
  const outputPath = join(temporaryDirectory, "output.json");
  const entryResultsPath = join(temporaryDirectory, "entry-results.json");
  try {
    writeFileSync(graphPath, JSON.stringify(graph));
    if (entryResults !== undefined) {
      if (typeof entryResults.encoded !== "string") {
        throw new Error(
          "Context-reuse entry results must contain native-encoded computation material."
        );
      }
      writeFileSync(entryResultsPath, entryResults.encoded);
    }
    const result = spawnSync(
      compilerBinary,
      [
        "context-reuse",
        ...(normalizedEncoding !== EXPANDED_DIAGNOSTIC_ENCODING
          ? ["--diagnostic-encoding", normalizedEncoding]
          : []),
        "--graph",
        graphPath,
        "--cache-dir",
        cacheDir,
        "--output",
        outputPath,
        ...(entryResults === undefined ? [] : ["--entry-results", entryResultsPath]),
        ...(thirdPartyPolicyPath === undefined
          ? []
          : ["--third-party-policy", thirdPartyPolicyPath]),
      ],
      {
        cwd: graph.repoRoot,
        encoding: "utf8",
        killSignal: "SIGKILL",
        maxBuffer: 16 * 1024 * 1024,
        timeout: compilerTimeoutMs,
      }
    );
    if (result.error !== undefined) {
      if (
        result.error instanceof Error &&
        "code" in result.error &&
        result.error.code === "ETIMEDOUT"
      ) {
        throw new Error(
          `Convex context-reuse compiler exceeded ${compilerTimeoutMs} milliseconds and was terminated.`
        );
      }
      throw new Error("Failed to start the Convex context-reuse compiler.", {
        cause: result.error,
      });
    }
    if (result.status !== 0) {
      throw new Error(
        `Convex context-reuse compiler failed with status ${result.status}: ${result.stderr.trim()}`
      );
    }
    const output = JSON.parse(readFileSync(outputPath, "utf8"));
    const admitted = requireContextReuseOutput(output, "Convex context-reuse compiler output");
    if (contextReuseOutputDiagnosticEncoding(admitted) !== normalizedEncoding) {
      throw new Error("Convex context-reuse compiler returned the wrong diagnostic encoding.");
    }
    if (entryResults !== undefined) {
      entryResults.encoded = readFileSync(entryResultsPath, "utf8");
    }
    return admitted;
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function verifyExternalDependencyIdentities(graph) {
  for (const [specifier, expected] of Object.entries(graph.externalDependencies)) {
    if (
      JSON.stringify(
        dependencyMaterial(
          graph.repoRoot,
          specifier,
          graph.externalDependencyResolutions[specifier]
        ).identity
      ) !== JSON.stringify(expected)
    ) {
      throw new Error(
        `Context-reuse external dependency identity changed after graph construction for ${specifier}.`
      );
    }
  }
}

function contextReuseAnalysisCompilerMaterial(selection) {
  const normalizedSelection = normalizedCompilerSelection(selection);
  if (normalizedSelection.cacheIdentity.kind === "direct-binary") {
    const currentBinaryIdentity = hashOpenedFile(normalizedSelection.binaryPath);
    if (
      JSON.stringify(currentBinaryIdentity) !== JSON.stringify(normalizedSelection.binaryIdentity)
    ) {
      throw new Error("Convex context-reuse direct compiler binary changed after verification.");
    }
    return {
      binary: normalizedSelection.binaryIdentity,
      kind: "direct-binary",
    };
  }
  if (normalizedSelection.sourceIdentity === undefined) {
    throw new Error("Convex context-reuse compiler package source identity is missing.");
  }
  return {
    binary: normalizedSelection.binaryIdentity,
    kind: "compiler-package",
    package: normalizedSelection.cacheIdentity.manifest,
    source: normalizedSelection.sourceIdentity,
  };
}

export function createConvexContextReuseAnalysisInputForResult({
  graph,
  result,
  compilerSelection,
  additionalPolicyInputPaths = [],
}) {
  const packageReviewMaterials = captureConvexContextReusePackageReviewMaterials({
    repoRoot: graph.repoRoot,
    thirdPartyMaterialFingerprints: result.thirdPartyMaterialFingerprints,
  });
  if (result.safe === true) {
    if (
      packageReviewMaterials.packages.length > 0 &&
      (packageReviewMaterials.lock?.kind !== "file" ||
        packageReviewMaterials.packages.some(
          (material) =>
            material.packageJson.kind !== "file" ||
            material.lockEntry === null ||
            typeof material.lockEntry !== "object" ||
            Array.isArray(material.lockEntry)
        ))
    ) {
      throw new Error(
        "Convex context-reuse safe result requires complete package-lock and package.json material."
      );
    }
  }
  const thirdPartyPolicyPath = thirdPartyPolicyPathForGraph(graph);
  const policyInputMaterialsSha256 = captureConvexContextReusePolicyInputMaterials({
    repoRoot: graph.repoRoot,
    policyInputPaths: [
      ...policyInputPaths,
      ...additionalPolicyInputPaths,
      ...(thirdPartyPolicyPath === undefined ? [] : [thirdPartyPolicyPath]),
    ],
  });
  return createConvexContextReuseAnalysisInput({
    compilerMaterial: contextReuseAnalysisCompilerMaterial(compilerSelection),
    graph,
    packageReviewMaterials,
    policyInputMaterialsSha256,
  });
}

export function bindConvexContextReuseAnalysisInputIdentity(
  result,
  analysisInput,
  generatedInventoryInputSha256
) {
  if (!validSha256(analysisInput.analysisInputGraphSha256)) {
    throw new Error("Convex context-reuse graph-input SHA-256 is invalid.");
  }
  if (!validSha256(analysisInput.analysisInputSha256)) {
    throw new Error("Convex context-reuse analysis-input SHA-256 is invalid.");
  }
  if (!validSha256(generatedInventoryInputSha256)) {
    throw new Error("Convex context-reuse generated inventory input SHA-256 is invalid.");
  }
  if (analysisInput.generatedInventoryInputSha256 !== generatedInventoryInputSha256) {
    throw new Error(
      "Convex context-reuse analysis input disagrees with the generated inventory input."
    );
  }
  return {
    ...result,
    analysisInputGraphSha256: analysisInput.analysisInputGraphSha256,
    analysisInputSha256: analysisInput.analysisInputSha256,
    generatedInventoryInputSha256,
  };
}

export function convexContextReuseAnalysisInputIdentityMatches(result, analysisInput) {
  return (
    result.analysisInputGraphSha256 === analysisInput.analysisInputGraphSha256 &&
    result.analysisInputSha256 === analysisInput.analysisInputSha256 &&
    result.generatedInventoryInputSha256 === analysisInput.generatedInventoryInputSha256
  );
}

async function retainContextReuseAnalyzedGraphSession(
  retainGraphSession,
  { analysis, generatedInventory, graphSession }
) {
  if (retainGraphSession === undefined) return;
  if (typeof retainGraphSession !== "function") {
    throw new Error("Convex context-reuse graph-session retainer must be a function.");
  }
  await retainGraphSession({
    analysis,
    graphSession,
    inventory: generatedInventory.inventory,
  });
}

export async function analyzeContextReuse(options) {
  const started = performance.now();
  const diagnosticEncoding = normalizedDiagnosticEncoding(options.diagnosticEncoding);
  const compilerSelection = await resolveContextReuseCompilerSelection(options);
  // Toolchain installation is excluded during an analysis. Carry this admitted selection
  // through cache lookup, execution, and publication. Reopening the package and walking compiler
  // sources again cannot improve result identity.
  const compilerTimeoutMs = requireCompilerTimeout(
    options.compilerTimeoutMs ?? DEFAULT_COMPILER_TIMEOUT_MS
  );
  const { loadConvexGeneratedApiInventory } = await import("./convex-generated-api-inventory.mjs");
  const generatedInventory = await loadConvexGeneratedApiInventory({
    ...options.inventoryOptions,
    repoRoot: options.repoRoot,
    gitSourceSnapshot: options.gitSourceSnapshot,
  });
  const inventoryPrecheckWallTimeUs = Math.round((performance.now() - started) * 1_000);
  const { graph, graphSession } = await buildContextReuseGraphAndSession(
    options.repoRoot,
    generatedInventory,
    {
      effectExecutionMode: options.effectExecutionMode,
      gitSourceSnapshot: options.gitSourceSnapshot,
      graphBuilder: options.graphBuilder,
      includeSourceGraphSnapshot: options.includeSourceGraphSnapshot,
      materialVerificationConcurrency: options.materialVerificationConcurrency,
      sourceRoots: options.sourceRoots,
    }
  );
  const preAnalysisInputIdentities = captureContextReuseResultCacheInputs(graph, compilerSelection);
  const entryResultsCompilerIdentity = fingerprintJson(compilerSelection.cacheIdentity);
  const entryCacheEnabled =
    options.entryResultCache !== undefined &&
    process.env.CONVEX_DISABLE_CONTEXT_REUSE_RESULT_CACHE !== "1";
  const entryResults = entryCacheEnabled
    ? {
        encoded:
          options.entryResultCache.compilerIdentity === entryResultsCompilerIdentity
            ? options.entryResultCache.encoded
            : "null",
      }
    : undefined;
  // Entry computation survives daemon replacement independently of exact whole-result hits.
  // Native analysis validates each retained dependency closure against the new graph.
  const entryCachePath = `${resultCachePath(options.repoRoot)}.entries`;
  if (entryCacheEnabled && entryResults.encoded === "null") {
    const retained = readPrivateContextReuseCache(entryCachePath);
    if (retained !== undefined) {
      if (
        typeof retained !== "object" ||
        retained === null ||
        Array.isArray(retained) ||
        Object.keys(retained).sort().join(",") !== "compilerIdentity,encoded,kind,repoRoot" ||
        retained.kind !== ENTRY_CACHE_KIND ||
        !validSha256(retained.compilerIdentity) ||
        typeof retained.repoRoot !== "string" ||
        typeof retained.encoded !== "string"
      ) {
        throw new Error(`Convex context-reuse entry cache is corrupt: ${entryCachePath}`);
      }
      if (
        retained.repoRoot === resolve(options.repoRoot) &&
        retained.compilerIdentity === entryResultsCompilerIdentity
      ) {
        entryResults.encoded = retained.encoded;
      }
    }
  }
  // The exact graph basis is needed before a retained result can be admitted. Build it before
  // reading the whole-result cache, then compare its wrapper-owned digest with the cached result;
  // a generated-inventory digest alone cannot bind a result to the complete metafile/material.
  const cachedEntry = readContextReuseResultCacheEntry(
    options.repoRoot,
    compilerSelection,
    generatedInventory.inventory.snapshot.inputSha256,
    diagnosticEncoding
  );
  if (cachedEntry !== null) {
    const cachedAnalysisInput = createConvexContextReuseAnalysisInputForResult({
      compilerSelection,
      graph,
      result: cachedEntry.output,
    });
    if (
      cachedEntry.analysisInputSha256 === cachedAnalysisInput.analysisInputSha256 &&
      convexContextReuseAnalysisInputIdentityMatches(cachedEntry.output, cachedAnalysisInput)
    ) {
      // A cache hit skips native analysis, so repeat the external-edge identity check that a
      // miss performs immediately before launch. Package-review material alone does not cover
      // every external edge recorded by the esbuild graph.
      verifyExternalDependencyIdentities(graph);
      // A cache hit still spans asynchronous package/material reads.
      // Recheck residual physical inputs before returning. Captured runtime sources are bound
      // by the graph digest and do not depend on their later worktree state.
      const postHitInputIdentities = captureContextReuseResultCacheInputs(graph, compilerSelection);
      if (JSON.stringify(preAnalysisInputIdentities) !== JSON.stringify(postHitInputIdentities)) {
        throw new Error(
          `Convex context-reuse inputs changed during cached-result admission; ${inputIdentityChangeDiagnostic(
            preAnalysisInputIdentities,
            postHitInputIdentities
          )}.`
        );
      }
      const wrapperFinished = performance.now();
      const result = {
        ...cachedEntry.output,
        metrics: {
          ...cachedEntry.output.metrics,
          inventoryPrecheckWallTimeUs,
          resultCacheHit: true,
          wrapperWallTimeUs: Math.round((wrapperFinished - started) * 1_000),
        },
      };
      await retainContextReuseAnalyzedGraphSession(options.retainGraphSession, {
        analysis: result,
        generatedInventory,
        graphSession,
      });
      if (entryResults !== undefined) {
        options.entryResultCache.compilerIdentity = entryResultsCompilerIdentity;
        options.entryResultCache.encoded = entryResults.encoded;
      }
      const analysisFinished = performance.now();
      options.onAnalysisPhaseTimings?.(
        Object.freeze({
          contextReuseAnalysisInputBinding: 0,
          contextReuseAnalysisGraphHandoff: Math.round(
            (analysisFinished - wrapperFinished) * 1_000
          ),
          contextReuseAnalysisCachePublication: 0,
          contextReuseAnalysisComplete: Math.round((analysisFinished - started) * 1_000),
        })
      );
      return result;
    }
  }
  verifyExternalDependencyIdentities(graph);
  // The service retains only native computation material, not a second admitted result. Keep
  // publication transactional and discard it when the compiler changes, including main.rs edits
  // that need not change the context-policy fingerprint or module-summary schema.
  const output = runContextReuseCompiler({
    graph,
    cacheDir: options.cacheDir,
    compilerBinary: compilerSelection.binaryPath,
    compilerTimeoutMs,
    diagnosticEncoding,
    ...(entryResults === undefined ? {} : { entryResults }),
  });
  const wrapperFinished = performance.now();
  const resultWithoutAnalysisInput = {
    ...output,
    metrics: {
      ...output.metrics,
      inventoryPrecheckWallTimeUs,
      resultCacheHit: false,
      wrapperWallTimeUs: Math.round((wrapperFinished - started) * 1_000),
    },
  };
  const analysisInput = createConvexContextReuseAnalysisInputForResult({
    compilerSelection,
    graph,
    result: resultWithoutAnalysisInput,
  });
  const result = bindConvexContextReuseAnalysisInputIdentity(
    resultWithoutAnalysisInput,
    analysisInput,
    generatedInventory.inventory.snapshot.inputSha256
  );
  const bindingFinished = performance.now();
  // A failed handoff must not leave a whole-result hit without its entry computation records.
  // The existing publication check also covers the asynchronous handoff before either write.
  await retainContextReuseAnalyzedGraphSession(options.retainGraphSession, {
    analysis: result,
    generatedInventory,
    graphSession,
  });
  const handoffFinished = performance.now();
  writeContextReuseResultCache(options.repoRoot, compilerSelection, graph, result, {
    analysisInputSha256: analysisInput.analysisInputSha256,
    diagnosticEncoding,
    preAnalysisInputIdentities,
  });
  if (entryResults !== undefined) {
    writePrivateContextReuseCache(entryCachePath, {
      kind: ENTRY_CACHE_KIND,
      repoRoot: resolve(options.repoRoot),
      compilerIdentity: entryResultsCompilerIdentity,
      encoded: entryResults.encoded,
    });
    options.entryResultCache.compilerIdentity = entryResultsCompilerIdentity;
    options.entryResultCache.encoded = entryResults.encoded;
  }
  const analysisFinished = performance.now();
  // The graph handoff can deeply freeze result, including metrics, before publication finishes.
  // Report complete timing separately; keep the historical wrapper boundary and result identity.
  options.onAnalysisPhaseTimings?.(
    Object.freeze({
      contextReuseAnalysisInputBinding: Math.round((bindingFinished - wrapperFinished) * 1_000),
      contextReuseAnalysisGraphHandoff: Math.round((handoffFinished - bindingFinished) * 1_000),
      contextReuseAnalysisCachePublication: Math.round(
        (analysisFinished - handoffFinished) * 1_000
      ),
      contextReuseAnalysisComplete: Math.round((analysisFinished - started) * 1_000),
    })
  );
  return result;
}

export function formatContextReuseResult(result, { verbose = false } = {}) {
  if (contextReuseOutputDiagnosticEncoding(result) === ADMISSION_DIAGNOSTIC_ENCODING) {
    throw new Error(
      "Context-reuse admission output omits dependency chains; request expanded or grouped output for diagnostic rendering."
    );
  }
  if (typeof verbose !== "boolean") {
    throw new Error("Context-reuse verbose output selection must be boolean.");
  }
  const severityOrder = new Map([
    ["hard", 0],
    ["unsupported", 1],
    ["information", 2],
  ]);
  const groupsById = new Map();
  let diagnosticOccurrenceCount = 0;
  const recordOccurrence = (diagnostic, entry, dependencyChain, definitionIdentity) => {
    diagnosticOccurrenceCount += 1;
    if (!severityOrder.has(diagnostic.severity)) {
      throw new Error(
        `Context-reuse diagnostic ${diagnostic.id} has unsupported severity ${JSON.stringify(diagnostic.severity)}.`
      );
    }
    const identity =
      definitionIdentity ??
      JSON.stringify({
        category: diagnostic.category,
        file: diagnostic.file,
        message: diagnostic.message,
        rule: diagnostic.rule,
        severity: diagnostic.severity,
        span: diagnostic.span,
      });
    const group = groupsById.get(diagnostic.id);
    if (group === undefined) {
      groupsById.set(diagnostic.id, {
        entries: new Set([entry]),
        identity,
        representative: { ...diagnostic, dependencyChain, entry },
      });
      return;
    }
    if (group.identity !== identity) {
      throw new Error(
        `Context-reuse diagnostic ID ${diagnostic.id} identifies inconsistent findings.`
      );
    }
    if (group.entries.has(entry)) {
      throw new Error(`Context-reuse diagnostic ID ${diagnostic.id} repeats entry ${entry}.`);
    }
    group.entries.add(entry);
    const representative = group.representative;
    if (
      dependencyChain.length < representative.dependencyChain.length ||
      (dependencyChain.length === representative.dependencyChain.length &&
        entry < representative.entry)
    ) {
      group.representative = { ...diagnostic, dependencyChain, entry };
    }
  };
  if (contextReuseOutputDiagnosticEncoding(result) === GROUPED_DIAGNOSTIC_ENCODING) {
    const definitionsById = new Map(
      result.diagnosticDefinitions.map((definition) => [definition.id, definition])
    );
    const identitiesById = new Map(
      result.diagnosticDefinitions.map((definition) => [
        definition.id,
        JSON.stringify({
          category: definition.category,
          file: definition.file,
          message: definition.message,
          rule: definition.rule,
          severity: definition.severity,
          span: definition.span,
        }),
      ])
    );
    for (const group of result.diagnosticGroups) {
      for (const id of group.findingIds) {
        const definition = definitionsById.get(id);
        if (definition === undefined) {
          throw new Error(`Context-reuse diagnostic group references unknown finding ${id}.`);
        }
        recordOccurrence(definition, group.entry, group.dependencyChain, identitiesById.get(id));
      }
    }
  } else {
    for (const diagnostic of result.diagnostics) {
      recordOccurrence(diagnostic, diagnostic.entry, diagnostic.dependencyChain);
    }
  }
  const groups = [...groupsById.values()].sort((left, right) => {
    const leftDiagnostic = left.representative;
    const rightDiagnostic = right.representative;
    const leftKey = [
      severityOrder.get(leftDiagnostic.severity),
      leftDiagnostic.rule,
      leftDiagnostic.file,
      leftDiagnostic.span.start,
      leftDiagnostic.id,
    ];
    const rightKey = [
      severityOrder.get(rightDiagnostic.severity),
      rightDiagnostic.rule,
      rightDiagnostic.file,
      rightDiagnostic.span.start,
      rightDiagnostic.id,
    ];
    for (let index = 0; index < leftKey.length; index += 1) {
      if (leftKey[index] < rightKey[index]) {
        return -1;
      }
      if (leftKey[index] > rightKey[index]) {
        return 1;
      }
    }
    return 0;
  });
  const lines = [];
  const groupedSeverityCounts = new Map([...severityOrder.keys()].map((severity) => [severity, 0]));
  const informationCountsByRule = new Map();
  for (const group of groups) {
    const diagnostic = group.representative;
    groupedSeverityCounts.set(
      diagnostic.severity,
      groupedSeverityCounts.get(diagnostic.severity) + 1
    );
    const affectedEntryCount = group.entries.size;
    if (diagnostic.severity === "information") {
      const counts = informationCountsByRule.get(diagnostic.rule) ?? {
        groups: 0,
        instances: 0,
      };
      counts.groups += 1;
      counts.instances += affectedEntryCount;
      informationCountsByRule.set(diagnostic.rule, counts);
      if (!verbose) {
        continue;
      }
    }
    lines.push(
      `${diagnostic.severity.toUpperCase()} [${diagnostic.rule}] ${diagnostic.file}:${diagnostic.span.line}:${diagnostic.span.column} (${diagnostic.id}; ${affectedEntryCount} affected ${affectedEntryCount === 1 ? "entry" : "entries"}; representative entry: ${diagnostic.entry})`
    );
    lines.push(`  ${diagnostic.message}`);
    if (diagnostic.dependencyChain.length > 0) {
      lines.push("  Representative dependency chain:");
    }
    for (const edge of diagnostic.dependencyChain) {
      lines.push(
        `    ${edge.from}:${edge.span.line}:${edge.span.column} --${edge.specifier}--> ${edge.to}`
      );
    }
  }
  if (!verbose && informationCountsByRule.size > 0) {
    const informationGroups = groupedSeverityCounts.get("information");
    const informationInstances = [...informationCountsByRule.values()].reduce(
      (total, counts) => total + counts.instances,
      0
    );
    lines.push(
      `Information summary: ${informationGroups} group(s) from ${informationInstances} entry-specific instance(s).`
    );
    for (const [rule, counts] of [...informationCountsByRule].sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0
    )) {
      lines.push(`  ${rule}: ${counts.groups} group(s), ${counts.instances} instance(s)`);
    }
    lines.push(
      "Information details omitted. Use --verbose for grouped information details or --json for the unchanged complete structured output."
    );
  }
  lines.push(
    `Context-reuse: ${result.entries.length} selected entries, ${groups.length} diagnostic group(s) from ${diagnosticOccurrenceCount} entry-specific instance(s), ${result.suppressedFindings} source suppression(s), safe=${String(result.safe)}.`
  );
  lines.push(
    `Grouped findings: hard=${groupedSeverityCounts.get("hard")}, unsupported=${groupedSeverityCounts.get("unsupported")}, information=${groupedSeverityCounts.get("information")}.`
  );
  const cacheTiming =
    result.metrics.resultCacheHit === undefined
      ? ""
      : `resultCacheHit=${String(result.metrics.resultCacheHit)}, wrapperWall=${result.metrics.wrapperWallTimeUs}us, inventoryPrecheck=${result.metrics.inventoryPrecheckWallTimeUs}us; `;
  const analysisLabel =
    result.metrics.resultCacheHit === true ? "retained analysis evidence" : "analysis";
  lines.push(
    `Metrics: ${cacheTiming}${analysisLabel}: modules=${result.metrics.modulesAnalyzed}, parsed=${result.metrics.parsedModules}, cacheHits=${result.metrics.cacheHits}, cacheMisses=${result.metrics.cacheMisses}, compilerWall=${result.metrics.wallTimeUs}us, compilerPeakRss=${result.metrics.peakRssBytes ?? "unavailable"} bytes.`
  );
  return lines.join("\n");
}
