import { createConvexContextReuseAnalysisInputGraphSha256 } from "./convex-context-reuse-analysis-input.mjs";
import { authenticateConvexContextReuseApplicationAdmission, captureContextReuseExternalDependencyIdentities, loadConvexContextReuseApplicationAdmissionPolicy } from "./convex-context-reuse-application-admission.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmGuestPromiseEffectExecutionMode } from "./convex-wasm-compiler-contract.mjs";
import { hydrateConvexWasmDependencyAdapterMaterial, loadConvexWasmDependencyAdapterMaterial, projectConvexWasmActiveDependencyAdapterIdentity, selectConvexWasmDependencyAdapters } from "./convex-wasm-dependency-adapters.mjs";
import { convexWasmDeploymentGraphAssumptions } from "./convex-wasm-source-graph.mjs";
import { resolveConvexWasmApplicationBundlerPackageSet } from "./convex-wasm-application-package-set.mjs";
import { readConvexWasmGitBlobMaterials } from "./convex-wasm-git-blob-material.mjs";
import { detachConvexWasmGitSourceSnapshot, validateConvexWasmGitSourceSnapshot, verifyConvexWasmGitSourceSnapshot } from "./convex-wasm-git-source-snapshot.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { loadConvexWasmRegistrationAdapterMaterial } from "./convex-wasm-registration-adapters.mjs";
import { isOrdinaryJsonData } from "./convex-wasm-source-envelope.mjs";
import { convexWasmSourceGraphSnapshotCachePath, loadConvexWasmSourceGraphSnapshotForLookup, publishConvexWasmSourceGraphSnapshot } from "./convex-wasm-source-graph-snapshot-cache.mjs";
import { createConvexWasmSourceGraphSnapshot, createConvexWasmSourceGraphSnapshotLookupIdentity } from "./convex-wasm-source-graph-snapshot.mjs";
import { convexWasmDefaultEffectExecutionMode, normalizeConvexWasmEffectExecutionMode } from "./convex-wasm-source-graph.mjs";
import { parse as parseBabelAst } from "@babel/parser";
import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { basename, dirname, extname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { isProxy } from "node:util/types";

const GRAPH_KIND = "convex-wasm-esbuild-graph";

const GRAPH_SESSION_KIND = "convex-wasm-esbuild-graph-session-v2";

const DEPLOYMENT_OUTPUT_CLOSURE_KIND = "convex-wasm-deployment-output-closure-v1";

const deploymentGraphSessionSourceMaterials = new WeakMap();

function gitSourceSnapshotChangedPaths(previous, current) {
  if (previous === undefined) return undefined;
  if (
    previous.objectFormat !== current.objectFormat ||
    previous.pathspecs.length !== current.pathspecs.length ||
    previous.pathspecs.some((path, index) => path !== current.pathspecs[index])
  ) {
    return undefined;
  }
  const entryIdentity = (entry) =>
    `${entry.mode}\0${entry.oid}\0${entry.path}\0${String(entry.stage)}`;
  const previousByPathAndStage = new Map(
    previous.entries.map((entry) => [`${entry.path}\0${String(entry.stage)}`, entryIdentity(entry)])
  );
  const currentByPathAndStage = new Map(
    current.entries.map((entry) => [`${entry.path}\0${String(entry.stage)}`, entryIdentity(entry)])
  );
  const changedPaths = new Set();
  for (const [key, identity] of previousByPathAndStage) {
    if (currentByPathAndStage.get(key) !== identity) {
      changedPaths.add(key.slice(0, key.lastIndexOf("\0")));
    }
  }
  for (const [key, identity] of currentByPathAndStage) {
    if (previousByPathAndStage.get(key) !== identity) {
      changedPaths.add(key.slice(0, key.lastIndexOf("\0")));
    }
  }
  return changedPaths;
}

function sourceMaterialGitIdentity(entry, generatedSourcePrefix) {
  if (
    typeof entry?.path !== "string" ||
    !DEPLOYMENT_RESULT_REGULAR_GIT_MODES.has(entry.mode) ||
    entry.path.startsWith(generatedSourcePrefix) ||
    entry.path.split("/").includes("node_modules") ||
    typeof entry.oid !== "string"
  ) {
    return undefined;
  }
  return {
    blobOid: entry.oid,
    mode: entry.mode,
    path: entry.path,
  };
}

function sourceMaterialGitIdentityKey(identity) {
  return identity === undefined ? undefined : canonicalJson(identity);
}

function sourceMaterialGitEntries(snapshot, generatedSourcePrefix) {
  const entriesByPath = new Map();
  for (const entry of snapshot?.entries ?? []) {
    const path = toPosix(entry.path);
    // Any non-zero stage makes the path unmerged. A stage-0 entry cannot restore ordinary-file
    // authority beside that ambiguity, even though Git does not normally emit both forms.
    if (entry.stage !== 0 || entriesByPath.has(path)) {
      entriesByPath.set(path, undefined);
      continue;
    }
    const identity = sourceMaterialGitIdentity(entry, generatedSourcePrefix);
    entriesByPath.set(path, identity === undefined ? undefined : { identity });
  }
  return entriesByPath;
}

function createSourceMaterialBuildState() {
  return {
    counters: { read: 0, rebuilt: 0, reused: 0 },
    countedSourceMaterialPaths: new Set(),
    committedMaterialsByAbsolutePath: new Map(),
    currentGitEntriesByPath: new Map(),
    currentGitIdentitiesByPath: new Map(),
    loadedPaths: new Set(),
    pendingSourceMaterialsByGitIdentity: new Map(),
    previousGitIdentitiesByPath: new Map(),
    repoRoot: undefined,
    sourceMaterialsByGitIdentity: new Map(),
  };
}

function setSourceMaterialGitSnapshot(state, { generatedSourcePrefix, gitSourceSnapshot, repoRoot }) {
  state.currentGitIdentitiesByPath = new Map();
  if (gitSourceSnapshot === undefined && repoRoot === undefined) {
    state.repoRoot = undefined;
    state.currentGitEntriesByPath = new Map();
    return;
  }
  if (gitSourceSnapshot === undefined || typeof repoRoot !== "string") {
    fail("source material build requires Git snapshot and repository root");
  }
  state.repoRoot = resolve(repoRoot);
  state.currentGitEntriesByPath = sourceMaterialGitEntries(
    gitSourceSnapshot,
    generatedSourcePrefix
  );
  for (const [path, entry] of state.currentGitEntriesByPath) {
    if (entry !== undefined) {
      state.currentGitIdentitiesByPath.set(path, sourceMaterialGitIdentityKey(entry.identity));
    }
  }
}

const DEPLOYMENT_RESULT_REGULAR_GIT_MODES = new Set(["100644", "100755"]);

function deploymentGraphContextScopeEntryPaths(entryPaths) {
  if (!Array.isArray(entryPaths)) {
    fail("deployment graph context scope entry paths must be an array");
  }
  const normalized = entryPaths.map((path, index) =>
    deploymentResultRelativePath(path, `deployment graph context scope entry path ${index}`)
  );
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1] >= normalized[index]) {
      fail("deployment graph context scope entry paths must be sorted and unique");
    }
  }
  return normalized;
}

export function convexWasmDeploymentGraphContextScopeSha256({
  entryPaths,
  gitSourceSnapshot,
  lookupIdentity,
} = {}) {
  validateConvexWasmGitSourceSnapshot(
    gitSourceSnapshot,
    "deployment graph context scope Git authority"
  );
  const graphContextLookupIdentity = structuredClone(
    createConvexWasmSourceGraphSnapshotLookupIdentity(lookupIdentity)
  );
  return deploymentGraphContextScopeSha256({
    entryPaths,
    gitSourceSnapshot,
    lookupIdentity: graphContextLookupIdentity,
  });
}

function deploymentGraphContextScopeSha256({ entryPaths, gitSourceSnapshot, lookupIdentity }) {
  const graphContextLookupIdentity = structuredClone(lookupIdentity);
  // The complete result remains required at the persisted-snapshot boundary, but it does not
  // affect esbuild. Adjacent result trees must therefore share this in-memory context scope.
  delete graphContextLookupIdentity.contextReuseAnalysis;
  return fingerprintJson({
    authority: {
      objectFormat: gitSourceSnapshot.objectFormat,
      pathspecs: [...gitSourceSnapshot.pathspecs],
    },
    entryPaths: deploymentGraphContextScopeEntryPaths(entryPaths),
    kind: "convex-wasm-deployment-graph-context-scope-v1",
    lookupIdentity: graphContextLookupIdentity,
  });
}

const CONVEX_BUNDLER_MATERIALS = Object.freeze([
  "cli/lib/components.js",
  "cli/lib/config.js",
  "debugBundle.js",
  "external.js",
  "fs.js",
  "index.js",
  "serverOnly.js",
  "wasm.js",
]);

function fail(message) {
  throw new Error(`Convex Wasm deployment: ${message}`);
}

async function settleParallelVerification(operationFactories) {
  const results = await Promise.allSettled(
    operationFactories.map((operationFactory) => Promise.resolve().then(operationFactory))
  );
  const failure = results.find((result) => result.status === "rejected");
  if (failure !== undefined) throw failure.reason;
  return results.map((result) => result.value);
}

async function runWithCleanupFailurePrecedence(operation, cleanup, description) {
  let operationFailed = false;
  let operationFailure;
  let value;
  try {
    value = await operation();
  } catch (error) {
    operationFailed = true;
    operationFailure = error;
  }
  let cleanupFailed = false;
  let cleanupFailure;
  try {
    await cleanup();
  } catch (error) {
    cleanupFailed = true;
    cleanupFailure = error;
  }
  if (operationFailed && cleanupFailed) {
    throw new AggregateError([operationFailure, cleanupFailure], description, {
      cause: operationFailure,
    });
  }
  if (operationFailed) throw operationFailure;
  if (cleanupFailed) throw cleanupFailure;
  return value;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function toPosix(path) {
  return path.split(sep).join("/");
}

function requireObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function normalizeGitSourceSnapshotAuthority(value) {
  const fields = ordinaryOwnDataPropertySnapshot(value);
  if (
    fields === undefined ||
    fields.size !== 2 ||
    !fields.has("repoRoot") ||
    !fields.has("snapshot")
  ) {
    fail("Git source snapshot authority must contain only repoRoot and dense snapshot data");
  }
  // Capture both wrapper data descriptors once before validation. Re-reading a caller accessor
  // here could validate one snapshot and retain a different snapshot across later awaits.
  const snapshot = detachConvexWasmGitSourceSnapshot(fields.get("snapshot"), "Git source snapshot");
  return Object.freeze({
    repoRoot: resolve(requireString(fields.get("repoRoot"), "Git source snapshot repository root")),
    // Keep caller-owned snapshot objects out of retained cache state. The staged authority is
    // metadata for admission, but mutating it after capture must not rewrite invalidation history.
    snapshot,
  });
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function sameFileState(left, right) {
  const hasNanosecondTimestamps =
    left.mtimeNs !== undefined &&
    left.ctimeNs !== undefined &&
    right.mtimeNs !== undefined &&
    right.ctimeNs !== undefined;
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    (hasNanosecondTimestamps
      ? left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
      : left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs)
  );
}

async function readStableFile(path, maxBytes = Number.MAX_SAFE_INTEGER) {
  const beforePath = await fs.stat(path, { bigint: true });
  if (!beforePath.isFile() || beforePath.size > BigInt(maxBytes)) {
    fail(
      beforePath.isFile() ? `${path} exceeded ${maxBytes} bytes` : `${path} is not a regular file`
    );
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY);
  return await runWithCleanupFailurePrecedence(
    async () => {
      const before = await handle.stat({ bigint: true });
      if (!sameFileState(beforePath, before) || !before.isFile()) {
        fail(`${path} changed before it could be read`);
      }
      const contents = await handle.readFile();
      const [after, afterPath] = await settleParallelVerification([
        () => handle.stat({ bigint: true }),
        () => fs.stat(path, { bigint: true }),
      ]);
      if (
        BigInt(contents.length) !== before.size ||
        !sameFileState(before, after) ||
        !sameFileState(after, afterPath)
      ) {
        fail(`${path} changed while it was being read`);
      }
      return {
        contents,
        sha256: createHash("sha256").update(contents).digest("hex"),
        size: contents.length,
        state: afterPath,
      };
    },
    () => handle.close(),
    `stable file read and handle cleanup failed: ${path}`
  );
}

async function hashFile(path) {
  const { sha256, size } = await readStableFile(path);
  return { sha256, size };
}

async function packageVersion(path) {
  const material = await readStableFile(path, 1024 * 1024);
  const source = decodeUtf8(material.contents, `${path} package manifest`);
  const packageJson = JSON.parse(source);
  return requireString(packageJson.version, `${path} version`);
}

async function loadGraphToolchain(repoRoot) {
  const packageSet = resolveConvexWasmApplicationBundlerPackageSet(repoRoot);
  const requireFromRepo = createRequire(resolve(repoRoot, "package.json"));
  const convexPackageJson = requireFromRepo.resolve("convex/package.json");
  const requireFromConvex = createRequire(convexPackageJson);
  const esbuildPackageJson = requireFromConvex.resolve("esbuild/package.json");
  const [convexVersion, esbuildVersion] = await settleParallelVerification([
    () => packageVersion(convexPackageJson),
    () => packageVersion(esbuildPackageJson),
  ]);
  if (convexVersion !== packageSet.convex.version || esbuildVersion !== packageSet.esbuild.version) {
    fail("graph toolchain disagrees with the application package set");
  }
  const esbuild = requireFromConvex("esbuild");
  if (esbuild.version !== esbuildVersion) {
    fail("resolved esbuild runtime and package versions disagree");
  }
  const bundlerDirectory = resolve(dirname(convexPackageJson), "dist", "esm", "bundler");
  const cliDirectory = resolve(dirname(convexPackageJson), "dist", "esm", "cli", "lib");
  const [{ serverOnlyPlugin }, { wasmPlugin }] = await settleParallelVerification([
    () => import(pathToFileURL(join(bundlerDirectory, "serverOnly.js")).href),
    () => import(pathToFileURL(join(bundlerDirectory, "wasm.js")).href),
  ]);
  return {
    bundlerDirectory,
    cliDirectory,
    esbuild,
    inputMaterialPaths: Object.freeze([
      convexPackageJson,
      esbuildPackageJson,
      ...convexBundlerMaterialPaths({ bundlerDirectory, cliDirectory }),
    ]),
    serverOnlyPlugin,
    toolchain: {
      convex: convexVersion,
      esbuild: esbuildVersion,
    },
    wasmPlugin,
  };
}

function convexBundlerMaterialPaths({ bundlerDirectory, cliDirectory }) {
  return CONVEX_BUNDLER_MATERIALS.map((name) =>
    name.startsWith("cli/")
      ? join(dirname(cliDirectory), name.slice("cli/".length))
      : join(bundlerDirectory, name)
  );
}

async function authenticateConvexBundlerMaterials({ bundlerDirectory, cliDirectory }) {
  const materialPaths = convexBundlerMaterialPaths({ bundlerDirectory, cliDirectory });
  return Object.fromEntries(
    await settleParallelVerification(
      CONVEX_BUNDLER_MATERIALS.map((name, index) => async () => {
        const materialPath = materialPaths[index];
        const sha256 = (await hashFile(materialPath)).sha256;
        return [name, { sha256 }];
      })
    )
  );
}

function isMaterialInputPath(
  inputPath,
  repoRoot,
  toolchainRoot,
  materialsByAbsolutePath,
  loadedPhysicalPaths
) {
  // Namespace-qualified metafile keys are only lexical identifiers. A physical Linux source can
  // have the same spelling. Retained maps also contain prior-build entries, so prefer physical
  // material only when the current build's file loader authenticated that source.
  const absoluteInputPath = resolve(repoRoot, inputPath);
  if (
    !isAbsolute(inputPath) &&
    inputPath !== ".." &&
    !inputPath.startsWith("../") &&
    materialsByAbsolutePath.has(absoluteInputPath) &&
    (loadedPhysicalPaths === undefined || loadedPhysicalPaths.has(absoluteInputPath))
  ) {
    return true;
  }
  if (
    !isAbsolute(inputPath) &&
    (inputPath.startsWith("(disabled):") ||
      inputPath.startsWith("async-hooks-shim:") ||
      inputPath.startsWith("server-only-stub:") ||
      inputPath.startsWith("wasm-binary:") ||
      inputPath.startsWith("wasm-stub:") ||
      inputPath === "<runtime>")
  ) {
    return false;
  }
  if (!isAbsolute(inputPath) && inputPath !== ".." && !inputPath.startsWith("../")) {
    return true;
  }
  const toolchainPath = toPosix(relative(toolchainRoot, resolve(repoRoot, inputPath)));
  return toolchainPath !== ".." && !toolchainPath.startsWith("../") && !isAbsolute(toolchainPath);
}

function sourceLoader(path) {
  const extension = extname(path);
  const loader = {
    ".cjs": "js",
    ".css": "css",
    ".cts": "ts",
    ".js": "js",
    ".json": "json",
    ".jsx": "jsx",
    ".mjs": "js",
    ".mts": "ts",
    ".ts": "ts",
    ".tsx": "tsx",
  }[extension];
  if (loader === undefined) {
    fail(`esbuild loaded unsupported source extension ${extension || "(none)"} at ${path}`);
  }
  return loader;
}

function cloneSourceMaterial(material) {
  if (typeof material !== "object" || material === null || !Object.hasOwn(material, "contents")) {
    fail("source material is missing contents");
  }
  return {
    ...material,
    contents: Buffer.from(material.contents),
    ...(material.state === undefined ? {} : { state: { ...material.state } }),
  };
}

const sourceMaterialReadFlights = new WeakMap();

const stagedSourceMaterialReadBatches = new WeakMap();

const stagedSourceMaterialReadFlights = new WeakMap();

function readStagedSourceMaterial(state, blobOid) {
  const retained =
    state.pendingSourceMaterialsByGitIdentity.get(blobOid) ??
    state.sourceMaterialsByGitIdentity.get(blobOid);
  if (retained !== undefined && retained.gitBlobOid === blobOid) {
    return Promise.resolve(retained);
  }
  let flights = stagedSourceMaterialReadFlights.get(state);
  if (flights === undefined) {
    flights = new Map();
    stagedSourceMaterialReadFlights.set(state, flights);
  }
  const flight = flights.get(blobOid);
  if (flight !== undefined) return flight;
  let batch = stagedSourceMaterialReadBatches.get(state);
  if (batch === undefined) {
    batch = new Map();
    stagedSourceMaterialReadBatches.set(state, batch);
    // Coalesce concurrent esbuild onLoad requests without a process per source file. Promotion
    // remains transactional: only the pending map receives newly read blob material.
    setImmediate(() => {
      stagedSourceMaterialReadBatches.delete(state);
      readConvexWasmGitBlobMaterials(state.repoRoot, [...batch.keys()]).then(
        (materials) => {
          for (const [oid, request] of batch) {
            const material = materials.get(oid);
            state.pendingSourceMaterialsByGitIdentity.set(oid, material);
            state.counters.read += 1;
            state.counters.rebuilt += 1;
            flights.delete(oid);
            request.resolve(material);
          }
        },
        (error) => {
          for (const [oid, request] of batch) {
            flights.delete(oid);
            request.reject(error);
          }
        }
      );
    });
  }
  let request = batch.get(blobOid);
  if (request === undefined) {
    request = {};
    request.promise = new Promise((resolve, reject) => {
      request.resolve = resolve;
      request.reject = reject;
    });
    batch.set(blobOid, request);
    flights.set(blobOid, request.promise);
  }
  return request.promise;
}

function sourceMaterialPlugin(
  materialsByAbsolutePath,
  verificationMemo,
  readMaterial = readStableFile,
  sourceMaterialBuildState
) {
  if (typeof readMaterial !== "function") {
    fail("source material reader must be a function");
  }
  if (verificationMemo !== undefined && !(verificationMemo instanceof Map)) {
    fail("source material verification memo must be a Map");
  }
  if (
    sourceMaterialBuildState !== undefined &&
    !(sourceMaterialBuildState.loadedPaths instanceof Set)
  ) {
    fail("source material build state must contain a loaded-path Set");
  }
  if (
    sourceMaterialBuildState !== undefined &&
    (!(sourceMaterialBuildState.currentGitEntriesByPath instanceof Map) ||
      !(sourceMaterialBuildState.currentGitIdentitiesByPath instanceof Map) ||
      !(sourceMaterialBuildState.pendingSourceMaterialsByGitIdentity instanceof Map) ||
      !(sourceMaterialBuildState.sourceMaterialsByGitIdentity instanceof Map) ||
      !(sourceMaterialBuildState.countedSourceMaterialPaths instanceof Set) ||
      typeof sourceMaterialBuildState.counters !== "object" ||
      sourceMaterialBuildState.counters === null)
  ) {
    fail("source material build state has invalid staged derivation fields");
  }
  let readFlightsByOperation = sourceMaterialReadFlights.get(materialsByAbsolutePath);
  if (readFlightsByOperation === undefined) {
    readFlightsByOperation = new WeakMap();
    sourceMaterialReadFlights.set(materialsByAbsolutePath, readFlightsByOperation);
  }
  let readFlights = readFlightsByOperation.get(readMaterial);
  if (readFlights === undefined) {
    readFlights = new Map();
    readFlightsByOperation.set(readMaterial, readFlights);
  }
  return {
    name: "convex-source-material-snapshot",
    setup(build) {
      build.onLoad({ filter: /.*/, namespace: "file" }, async ({ path }) => {
        const absolutePath = resolve(path);
        const relativePath = toPosix(
          relative(sourceMaterialBuildState?.repoRoot ?? process.cwd(), absolutePath)
        );
        const stagedEntry = sourceMaterialBuildState?.currentGitEntriesByPath.get(relativePath);
        const stagedIdentity = stagedEntry?.identity;
        const stagedIdentityKey = sourceMaterialGitIdentityKey(stagedIdentity);
        if (stagedIdentityKey !== undefined) {
          sourceMaterialBuildState.currentGitIdentitiesByPath.set(relativePath, stagedIdentityKey);
          const blobOid = stagedIdentity.blobOid;
          const retained =
            sourceMaterialBuildState.pendingSourceMaterialsByGitIdentity.get(blobOid) ??
            sourceMaterialBuildState.sourceMaterialsByGitIdentity.get(blobOid);
          const material = await readStagedSourceMaterial(sourceMaterialBuildState, blobOid);
          if (
            retained?.gitBlobOid === blobOid &&
            !sourceMaterialBuildState.loadedPaths.has(absolutePath)
          ) {
            sourceMaterialBuildState.counters.reused += 1;
          }
          sourceMaterialBuildState.countedSourceMaterialPaths.add(relativePath);
          sourceMaterialBuildState.loadedPaths.add(absolutePath);
          const retainedMaterial = cloneSourceMaterial({
            ...material,
            gitIdentity: stagedIdentityKey,
          });
          materialsByAbsolutePath.set(absolutePath, retainedMaterial);
          // These bytes came from the captured object, not a physical-file observation. Never
          // publish a stat memo that could misrepresent later worktree bytes as this blob.
          verificationMemo?.delete(absolutePath);
          return {
            contents: Buffer.from(retainedMaterial.contents),
            loader: sourceLoader(absolutePath),
            resolveDir: dirname(absolutePath),
          };
        }
        const cached = materialsByAbsolutePath.get(absolutePath);
        if (
          cached !== undefined &&
          Buffer.isBuffer(cached.contents) &&
          cached.state !== undefined &&
          cached.gitIdentity === undefined
        ) {
          // Isolate, Node, and auth-config bundles can load the same source in one graph session.
          // Reuse its bytes and digest only after a fresh state check; final graph verification
          // still performs its own stable check before any artifact or deployment authority.
          const currentState = await fs.lstat(absolutePath, { bigint: true });
          if (currentState.isFile() && sameFileState(cached.state, currentState)) {
            const afterState = await fs.lstat(absolutePath, { bigint: true });
            if (afterState.isFile() && sameFileState(currentState, afterState)) {
              verificationMemo?.set(absolutePath, {
                sha256: cached.sha256,
                size: cached.size,
                state: afterState,
              });
              sourceMaterialBuildState?.loadedPaths.add(absolutePath);
              return {
                contents: Buffer.from(cached.contents),
                loader: sourceLoader(absolutePath),
                resolveDir: dirname(absolutePath),
              };
            }
          }
        }
        let material;
        let performedPhysicalRead = false;
        const readFlight = readFlights.get(absolutePath);
        if (readFlight === undefined) {
          const nextRead = Promise.resolve().then(() => readMaterial(absolutePath));
          readFlights.set(absolutePath, nextRead);
          performedPhysicalRead = true;
          try {
            material = await nextRead;
          } finally {
            if (readFlights.get(absolutePath) === nextRead) {
              readFlights.delete(absolutePath);
            }
          }
        } else {
          material = await readFlight;
        }
        if (sourceMaterialBuildState !== undefined && performedPhysicalRead) {
          sourceMaterialBuildState.counters.read += 1;
          sourceMaterialBuildState.counters.rebuilt += 1;
          sourceMaterialBuildState.countedSourceMaterialPaths.add(relativePath);
        }
        const previous = materialsByAbsolutePath.get(absolutePath);
        if (
          previous !== undefined &&
          (sourceMaterialBuildState === undefined ||
            sourceMaterialBuildState.loadedPaths.has(absolutePath)) &&
          (previous.sha256 !== material.sha256 || previous.size !== material.size)
        ) {
          fail(`source ${absolutePath} changed while esbuild was constructing the graph`);
        }
        const retainedMaterial = cloneSourceMaterial(material);
        materialsByAbsolutePath.set(absolutePath, retainedMaterial);
        sourceMaterialBuildState?.loadedPaths.add(absolutePath);
        // The final source boundary must still stat every input. Reuse the digest only while the
        // exact path identity and timestamps from this stable esbuild read remain unchanged.
        verificationMemo?.set(absolutePath, {
          sha256: retainedMaterial.sha256,
          size: retainedMaterial.size,
          state: retainedMaterial.state,
        });
        return {
          contents: Buffer.from(retainedMaterial.contents),
          loader: sourceLoader(absolutePath),
          resolveDir: dirname(absolutePath),
        };
      });
    },
  };
}

function externalModuleIdentity(importPath) {
  const parts = importPath.split("/");
  return importPath.startsWith("@")
    ? { directory: join(parts[0], parts[1]), name: `${parts[0]}/${parts[1]}` }
    : { directory: parts[0], name: parts[0] };
}

function shouldMarkNodePackageExternal(packageName, packageVersion, allowList) {
  if (
    packageName === "convex" ||
    packageVersion.startsWith("file:") ||
    packageVersion.startsWith("git+file://") ||
    packageVersion.startsWith("http://") ||
    packageVersion.startsWith("https://") ||
    packageVersion.startsWith("git://") ||
    packageVersion.startsWith("git+ssh://") ||
    packageVersion.startsWith("git+http://") ||
    packageVersion.startsWith("git+https://")
  ) {
    return false;
  }
  return allowList.includes(packageName) || allowList.includes("*");
}

async function existingDirectory(path) {
  try {
    return (await fs.stat(path)).isDirectory();
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function pinnedExternalNodePackages(repoRoot, allowList) {
  if (allowList.length === 0) {
    return new Map();
  }
  const packagePath = join(repoRoot, "package.json");
  const packageMaterial = await readStableFile(packagePath, 16 * 1024 * 1024);
  const packageJson = requireObject(
    JSON.parse(decodeUtf8(packageMaterial.contents, "package.json")),
    "package.json"
  );
  const candidateExternalPackages = new Map();
  for (const key of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    const dependencies = requireObject(packageJson[key] ?? {}, `package.json ${key}`);
    for (const [packageName, packageVersion] of Object.entries(dependencies)) {
      if (candidateExternalPackages.has(packageName)) {
        continue;
      }
      if (typeof packageVersion !== "string") {
        fail(`package.json ${key}.${packageName} must be a string`);
      }
      if (!shouldMarkNodePackageExternal(packageName, packageVersion, allowList)) {
        continue;
      }
      const packageDirectory = join(
        repoRoot,
        "node_modules",
        externalModuleIdentity(packageName).directory
      );
      candidateExternalPackages.set(packageName, { path: packageDirectory });
    }
  }
  return new Map(
    (
      await settleParallelVerification(
        [...candidateExternalPackages].map(
          ([packageName, material]) =>
            async () =>
              (await existingDirectory(material.path)) ? [packageName, material] : undefined
        )
      )
    ).filter((entry) => entry !== undefined)
  );
}

async function resolveInstalledNodePackage(moduleDirectory, resolveDirectory) {
  let current = resolve(resolveDirectory);
  while (true) {
    const candidate = join(current, "node_modules", moduleDirectory);
    if (await existingDirectory(candidate)) {
      return candidate;
    }
    const parent = dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function pinnedNodeExternalPlugin(externalPackages) {
  const externalModuleNames = new Set();
  return {
    externalModuleNames,
    plugin: {
      name: "convex-node-externals",
      setup(build) {
        build.onResolve({ filter: /.*/, namespace: "file" }, async (args) => {
          if (args.path.startsWith(".")) {
            return null;
          }
          const module = externalModuleIdentity(args.path);
          const externalPackage = externalPackages.get(module.name);
          if (externalPackage === undefined) {
            return null;
          }
          const resolved = await resolveInstalledNodePackage(module.directory, args.resolveDir);
          if (resolved === externalPackage.path) {
            externalModuleNames.add(module.name);
            return { external: true, path: args.path };
          }
          return null;
        });
      },
    },
  };
}

function pinnedAsyncHooksShimPlugin(platform) {
  return {
    name: "convex-async-hooks-shim",
    setup(build) {
      if (platform !== "browser") {
        return;
      }
      build.onResolve({ filter: /^(node:)?async_hooks$/ }, (args) => ({
        namespace: "async-hooks-shim",
        path: args.path,
      }));
      build.onLoad({ filter: /.*/, namespace: "async-hooks-shim" }, () => ({
        contents: `
            export const AsyncLocalStorage = globalThis.AsyncLocalStorage;
            export const AsyncResource = globalThis.AsyncResource;
            export default { AsyncLocalStorage, AsyncResource };
          `,
        loader: "js",
      }));
    },
  };
}

const CONVEX_ENTRY_EXTENSIONS = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".jsx"];

const DEFAULT_DATABASE_CONTEXT_REUSE_EXPORT = "export const experimental_reuseContext = true;\n";

const DEFAULT_DATABASE_AND_HTTP_ACTION_CONTEXT_REUSE_EXPORT =
  "export const experimental_reuseContext = { queries: true, mutations: true, actions: false, httpActions: true };\n";

function parsePinnedProjectConfig(source) {
  const raw = requireObject(JSON.parse(source), "convex.json");
  const functions = raw.functions === undefined ? "convex/" : raw.functions;
  requireString(functions, "convex.json functions");
  const rawNode = raw.node === undefined ? {} : raw.node;
  requireObject(rawNode, "convex.json node");
  const externalPackages = rawNode.externalPackages === undefined ? [] : rawNode.externalPackages;
  if (
    !Array.isArray(externalPackages) ||
    externalPackages.some((packageName) => typeof packageName !== "string")
  ) {
    fail("convex.json node.externalPackages must be an array of strings");
  }
  if (rawNode.nodeVersion !== undefined && typeof rawNode.nodeVersion !== "string") {
    fail("convex.json node.nodeVersion must be a string when present");
  }
  const rawBundler = raw.bundler;
  if (rawBundler !== undefined) {
    requireObject(rawBundler, "convex.json bundler");
  }
  const includeSourcesContent =
    rawBundler?.includeSourcesContent === undefined ? false : rawBundler.includeSourcesContent;
  if (typeof includeSourcesContent !== "boolean") {
    fail("convex.json bundler.includeSourcesContent must be a boolean");
  }
  const rawContextReuse = rawBundler?.experimentalContextReuse;
  let experimentalContextReuse;
  if (rawContextReuse !== undefined) {
    requireObject(rawContextReuse, "convex.json bundler.experimentalContextReuse");
    if (
      Object.keys(rawContextReuse).some(
        (key) => !["default", "exclusions", "httpActions"].includes(key)
      )
    ) {
      fail("convex.json bundler.experimentalContextReuse has unexpected fields");
    }
    if (rawContextReuse.default !== true) {
      fail("convex.json bundler.experimentalContextReuse.default must be true");
    }
    const httpActions =
      rawContextReuse.httpActions === undefined ? false : rawContextReuse.httpActions;
    if (typeof httpActions !== "boolean") {
      fail("convex.json bundler.experimentalContextReuse.httpActions must be a boolean");
    }
    const exclusions = requireObject(
      rawContextReuse.exclusions === undefined ? {} : rawContextReuse.exclusions,
      "convex.json bundler.experimentalContextReuse.exclusions"
    );
    for (const [entry, reason] of Object.entries(exclusions)) {
      if (
        entry === "" ||
        entry.includes("\\") ||
        posix.isAbsolute(entry) ||
        posix.normalize(entry) !== entry ||
        entry === ".." ||
        entry.startsWith("../") ||
        toPosix(entry) !== entry
      ) {
        fail(`invalid context-reuse exclusion ${JSON.stringify(entry)}`);
      }
      if (
        typeof reason !== "string" ||
        reason.length < 32 ||
        reason.trim() !== reason ||
        /[\r\n]/u.test(reason)
      ) {
        fail(`context-reuse exclusion ${entry} must have a review reason`);
      }
    }
    experimentalContextReuse = { exclusions, httpActions };
  }
  const rawWasmCompilation = rawBundler?.wasmCompilation;
  let wasmCompilation;
  if (rawWasmCompilation !== undefined) {
    requireObject(rawWasmCompilation, "convex.json bundler.wasmCompilation");
    if (Object.keys(rawWasmCompilation).some((key) => !["default", "modules"].includes(key))) {
      fail("convex.json bundler.wasmCompilation has unexpected fields");
    }
    if (rawWasmCompilation.default !== false) {
      fail("convex.json bundler.wasmCompilation.default must be false");
    }
    if (!Array.isArray(rawWasmCompilation.modules)) {
      fail("convex.json bundler.wasmCompilation.modules must be an array");
    }
    const modules = rawWasmCompilation.modules.map((modulePath, index) => {
      if (
        typeof modulePath !== "string" ||
        modulePath === "" ||
        modulePath.includes("\\") ||
        posix.isAbsolute(modulePath) ||
        posix.normalize(modulePath) !== modulePath ||
        modulePath === ".." ||
        modulePath.startsWith("../") ||
        modulePath.endsWith(".js") ||
        toPosix(modulePath) !== modulePath
      ) {
        fail(
          `invalid Wasm compilation module path at index ${index}: ${JSON.stringify(modulePath)}`
        );
      }
      return modulePath;
    });
    const uniqueModules = [...new Set(modules)].sort(compareStrings);
    if (uniqueModules.length !== modules.length) {
      fail("convex.json bundler.wasmCompilation.modules must not contain duplicates");
    }
    wasmCompilation = { default: false, modules: uniqueModules };
  }
  return {
    bundler: {
      includeSourcesContent,
      ...(experimentalContextReuse === undefined ? {} : { experimentalContextReuse }),
      ...(wasmCompilation === undefined ? {} : { wasmCompilation }),
    },
    functions,
    node: {
      externalPackages,
      ...(rawNode.nodeVersion === undefined ? {} : { nodeVersion: rawNode.nodeVersion }),
    },
  };
}

function contextReusePolicyIdentity({
  databaseEntryPaths,
  entryPoints,
  functionsDirectory,
  normalizedRoot,
  projectConfig,
}) {
  // This selection is the database-UDF analyzer contract. HTTP-action eligibility is reviewed
  // separately and is authenticated by the exact emitted module bytes in bundleModuleIdentity.
  const configured = projectConfig.bundler.experimentalContextReuse;
  const exclusions = configured?.exclusions ?? {};
  const databaseEntries = new Set(databaseEntryPaths);
  const entries = entryPoints
    .map((absolutePath) => {
      const configEntryPath = toPosix(relative(functionsDirectory, absolutePath));
      return {
        enabled: configured !== undefined && !Object.hasOwn(exclusions, configEntryPath),
        entryPath: toPosix(relative(normalizedRoot, absolutePath)),
      };
    })
    .filter(({ entryPath }) => databaseEntries.has(entryPath))
    .sort((left, right) => compareStrings(left.entryPath, right.entryPath));
  const payload = {
    entries,
    kind: "convex-wasm-context-reuse-selection",
  };
  return { ...payload, sha256: fingerprintJson(payload) };
}

function contextReuseAnalysisPolicy({ functionsDirectory, normalizedRoot, projectConfig }) {
  const configured = projectConfig.bundler.experimentalContextReuse;
  return {
    defaultEnabled: configured !== undefined,
    exclusions: Object.fromEntries(
      Object.entries(configured?.exclusions ?? {})
        .map(([entryPath, reason]) => [
          toPosix(relative(normalizedRoot, resolve(functionsDirectory, entryPath))),
          reason,
        ])
        .sort(([left], [right]) => compareStrings(left, right))
    ),
  };
}

function compareDirectoryEntries(left, right) {
  return compareStrings(left.name, right.name);
}

async function walkConvexEntries(directory, depth = 0) {
  const entries = (await fs.readdir(directory, { withFileTypes: true })).sort(
    compareDirectoryEntries
  );
  const nestedEntries = await settleParallelVerification(
    entries.map((entry) => async () => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        try {
          await fs.access(join(path, "convex.config.ts"));
          return [];
        } catch (error) {
          if (error?.code !== "ENOENT") {
            throw error;
          }
        }
        return await walkConvexEntries(path, depth + 1);
      }
      return entry.isFile() ? [{ depth, path }] : [];
    })
  );
  return nestedEntries.flat();
}

function hasUseNodeDirective(source) {
  if (!source.includes("use node")) {
    return false;
  }
  try {
    const ast = parseBabelAst(source, {
      plugins: ["jsx", "typescript"],
      sourceType: "module",
    });
    return ast.program.directives.some((directive) => directive.value.value === "use node");
  } catch {
    return source.split("\n").some((line) => /^\s*("|')use node\1;?\s*$/u.test(line));
  }
}

async function convexEntryPointsByEnvironment(functionsDirectory) {
  const classified = await settleParallelVerification(
    (await walkConvexEntries(functionsDirectory)).map(({ path }) => async () => {
      const relativePath = relative(functionsDirectory, path);
      const parsed = {
        base: basename(path),
        extension: extname(path).toLowerCase(),
      };
      if (relativePath.startsWith(`_deps${sep}`)) {
        fail(`the authoritative Convex bundle input contains reserved path ${relativePath}`);
      }
      if (
        !CONVEX_ENTRY_EXTENSIONS.some((extension) => relativePath.endsWith(extension)) ||
        relativePath.startsWith(`_generated${sep}`) ||
        parsed.base.startsWith(".") ||
        parsed.base.startsWith("#") ||
        parsed.base === "schema.ts" ||
        parsed.base === "schema.js" ||
        (parsed.base.match(/\./gu) ?? []).length > 1 ||
        relativePath.includes(" ")
      ) {
        return undefined;
      }
      const source = await fs.readFile(path, "utf8");
      if (
        (parsed.extension === ".ts" || parsed.extension === ".tsx") &&
        !/^\s{0,100}(import|export)/mu.test(source)
      ) {
        return undefined;
      }
      const useNode = hasUseNodeDirective(source);
      const normalizedRelativePath = toPosix(relativePath);
      if (
        useNode &&
        ["http", "crons", "schema", "auth.config"].includes(
          normalizedRelativePath.replace(/\.[^/.]+$/u, "")
        )
      ) {
        fail(`"use node" is not allowed for ${normalizedRelativePath}`);
      }
      if (!useNode && relativePath.startsWith(`actions${sep}`)) {
        fail(`${normalizedRelativePath} is in actions/ but has no "use node" directive`);
      }
      return { environment: useNode ? "node" : "isolate", path };
    })
  );
  const output = { isolate: [], node: [] };
  for (const entry of classified) {
    if (entry !== undefined) output[entry.environment].push(entry.path);
  }
  return output;
}

function outputExportsContextReuse(source) {
  const ast = parseBabelAst(source, { sourceType: "module" });
  return ast.program.body.some((statement) => {
    if (statement.type !== "ExportNamedDeclaration") {
      return false;
    }
    if (
      statement.declaration?.type === "VariableDeclaration" &&
      statement.declaration.declarations.some(
        (declaration) =>
          declaration.id.type === "Identifier" &&
          declaration.id.name === "experimental_reuseContext"
      )
    ) {
      return true;
    }
    if (
      (statement.declaration?.type === "FunctionDeclaration" ||
        statement.declaration?.type === "ClassDeclaration") &&
      statement.declaration.id?.name === "experimental_reuseContext"
    ) {
      return true;
    }
    return statement.specifiers.some(
      (specifier) =>
        specifier.type === "ExportSpecifier" &&
        (specifier.exported.type === "Identifier"
          ? specifier.exported.name
          : specifier.exported.value) === "experimental_reuseContext"
    );
  });
}

function applyPinnedDefaultContextReusePolicy(source, policy) {
  if (outputExportsContextReuse(source)) {
    fail(
      `cannot apply the default context-reuse policy to ${policy.entry}: the entry already exports experimental_reuseContext`
    );
  }
  if (!policy.enabled) {
    return source;
  }
  const contextReuseExport = policy.httpActions
    ? DEFAULT_DATABASE_AND_HTTP_ACTION_CONTEXT_REUSE_EXPORT
    : DEFAULT_DATABASE_CONTEXT_REUSE_EXPORT;
  const sourceMapComment = source.match(/\/\/# sourceMappingURL=[^\n]*\n?$/u);
  if (sourceMapComment === null || sourceMapComment.index === undefined) {
    return `${source.endsWith("\n") ? source : `${source}\n`}${contextReuseExport}`;
  }
  return `${source.slice(0, sourceMapComment.index)}${contextReuseExport}${source.slice(sourceMapComment.index)}`;
}

function hashPinnedConvexBundle(bundle) {
  return createHash("sha256")
    .update(bundle.source)
    .update(bundle.sourceMap ?? "")
    .digest("hex");
}

function sourceMapIdentity(sourceMap) {
  if (sourceMap === undefined) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(sourceMap);
  } catch {
    fail("installed Convex bundler emitted an invalid source map");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    parsed.version !== 3 ||
    !Array.isArray(parsed.sources)
  ) {
    fail("installed Convex bundler emitted invalid source-membership provenance");
  }
  return {
    identity: {
      sha256: createHash("sha256").update(sourceMap).digest("hex"),
      size: Buffer.byteLength(sourceMap),
      sourcesContentCount: Array.isArray(parsed.sourcesContent)
        ? parsed.sourcesContent.filter((source) => source !== null).length
        : 0,
      sourcesCount: parsed.sources.length,
    },
    sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
      sourceRoot: parsed.sourceRoot,
      sources: parsed.sources,
    }),
  };
}

function bundleModuleIdentity(bundle, description, expectedEnvironment) {
  requireObject(bundle, description);
  if (bundle.environment !== expectedEnvironment) {
    fail(`${description} environment must be ${expectedEnvironment}`);
  }
  const path = requireString(bundle.path, `${description} path`);
  const source = requireString(bundle.source, `${description} source`);
  if (bundle.sourceMap !== undefined && typeof bundle.sourceMap !== "string") {
    fail(`${description} source map must be a string when present`);
  }
  if (expectedEnvironment === "isolate" && bundle.sourceMap === undefined) {
    fail(`${description} isolate module has no source-map provenance`);
  }
  const sourceMap = sourceMapIdentity(bundle.sourceMap);
  return {
    environment: bundle.environment,
    moduleSha256: hashPinnedConvexBundle(bundle),
    path,
    sourceMap: sourceMap?.identity ?? null,
    sourceMembershipSha256:
      bundle.environment === "isolate" ? (sourceMap?.sourceMembershipSha256 ?? null) : null,
    sourceSha256: createHash("sha256").update(source).digest("hex"),
    sourceSize: Buffer.byteLength(source),
  };
}

function outputModulePath(repoRoot, outputPath) {
  const pathFromOutdir = isAbsolute(outputPath)
    ? relative(resolve(repoRoot, "out"), outputPath)
    : relative("out", outputPath);
  return toPosix(pathFromOutdir);
}

function resolveOutputImport({
  importerOutputPath,
  importedPath,
  outputPathsByAbsolutePath,
  outputs,
  repoRoot,
}) {
  if (Object.hasOwn(outputs, importedPath)) {
    return importedPath;
  }
  const importerAbsolutePath = isAbsolute(importerOutputPath)
    ? resolve(importerOutputPath)
    : resolve(repoRoot, importerOutputPath);
  const candidates = new Set([
    isAbsolute(importedPath) ? resolve(importedPath) : resolve(repoRoot, importedPath),
    resolve(dirname(importerAbsolutePath), importedPath),
  ]);
  const matches = new Set();
  for (const candidate of candidates) {
    for (const outputPath of outputPathsByAbsolutePath.get(candidate) ?? []) {
      matches.add(outputPath);
    }
  }
  if (matches.size > 1) {
    fail(
      `esbuild output import ${importedPath} from ${importerOutputPath} matches multiple outputs`
    );
  }
  return matches.values().next().value;
}

const deploymentOutputClosureProjectionAuthorities = new WeakMap();

const deploymentOutputClosureProjectionSelections = new WeakMap();

const deploymentOutputClosureProjectionOutputMaps = new WeakMap();

const deploymentOutputClosureProjectionGraphSessions = new WeakMap();

const deploymentGraphSessionMaterialVerificationMemos = new WeakMap();

const pendingContextReuseAnalysisGraphSessionAuthorities = new WeakMap();

function isExactPlainMap(value) {
  return (
    !isProxy(value) &&
    value instanceof Map &&
    Object.getPrototypeOf(value) === Map.prototype &&
    Reflect.ownKeys(value).length === 0
  );
}

function intrinsicMapGet(map, key) {
  return Map.prototype.get.call(map, key);
}

function plainMapSnapshot(map) {
  return new Map(Map.prototype.entries.call(map));
}

function hasExactMapEntries(map, snapshot) {
  if (!isExactPlainMap(map) || snapshot.size !== map.size) return false;
  for (const [key, value] of snapshot) {
    if (intrinsicMapGet(map, key) !== value) return false;
  }
  return true;
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !isProxy(value) &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function hasExactEnumerableDataProperty(object, key, value) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return (
    descriptor !== undefined &&
    "value" in descriptor &&
    descriptor.enumerable &&
    descriptor.value === value
  );
}

function ordinaryOwnDataPropertySnapshot(value) {
  if (!isPlainObject(value)) return undefined;
  const snapshot = new Map();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      return undefined;
    }
    snapshot.set(key, descriptor.value);
  }
  return snapshot;
}

function hasExactOwnDataPropertySnapshot(value, snapshot) {
  if (!isPlainObject(value) || !(snapshot instanceof Map)) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== snapshot.size) return false;
  return keys.every(
    (key) =>
      typeof key === "string" &&
      snapshot.has(key) &&
      hasExactEnumerableDataProperty(value, key, snapshot.get(key))
  );
}

function createConvexWasmDeploymentOutputClosureProjection({
  bundleModulesByPath,
  metafile,
  repoRoot,
}) {
  if (!isExactPlainMap(bundleModulesByPath)) {
    fail("deployment output closure requires bundle module identities");
  }
  requireObject(metafile, "deployment output metafile");
  if (!isOrdinaryJsonData(metafile)) {
    fail("deployment output metafile must contain ordinary JSON data");
  }
  if (!Object.hasOwn(metafile, "outputs")) {
    fail("deployment metafile has no own outputs object");
  }
  const outputs = requireObject(metafile.outputs, "deployment metafile outputs");
  const metafileSha256 = fingerprintJson(metafile);
  freezeAuthenticatedJsonTree(metafile);
  const projection = Object.freeze({});
  const outputPathsByAbsolutePath = new Map();
  for (const outputPath of Object.keys(outputs)) {
    const absoluteOutputPath = isAbsolute(outputPath)
      ? resolve(outputPath)
      : resolve(repoRoot, outputPath);
    const collidingOutputPaths = outputPathsByAbsolutePath.get(absoluteOutputPath);
    if (collidingOutputPaths === undefined) {
      outputPathsByAbsolutePath.set(absoluteOutputPath, [outputPath]);
    } else {
      collidingOutputPaths.push(outputPath);
    }
  }
  const outputPathByModulePath = new Map();
  const modulePathByOutputPath = new Map();
  for (const outputPath of Object.keys(outputs).sort(compareStrings)) {
    const modulePath = outputModulePath(repoRoot, outputPath);
    if (!bundleModulesByPath.has(modulePath)) {
      continue;
    }
    if (outputPathByModulePath.has(modulePath)) {
      fail(`esbuild metafile contains duplicate output module path ${modulePath}`);
    }
    outputPathByModulePath.set(modulePath, outputPath);
    modulePathByOutputPath.set(outputPath, modulePath);
  }
  const closureModulesByPath = new Map();
  const closureModuleSourcesByPath = new Map();
  for (const [modulePath, module] of bundleModulesByPath) {
    requireString(modulePath, "deployment output module path");
    if (!outputPathByModulePath.has(modulePath)) {
      fail(`esbuild metafile is missing deployment output module ${modulePath}`);
    }
    if (!isOrdinaryJsonData(module)) {
      fail(`deployment output module identity ${modulePath} must contain ordinary JSON data`);
    }
    if (module.path !== modulePath) {
      fail(`deployment output module identity path disagrees with map key ${modulePath}`);
    }
    const closureModule = freezeAuthenticatedJsonTree({
      environment: module.environment,
      moduleSha256: module.moduleSha256,
      path: module.path,
      sourceMap: module.sourceMap === null ? null : { ...module.sourceMap },
      sourceMembershipSha256: module.sourceMembershipSha256,
      sourceSha256: module.sourceSha256,
      sourceSize: module.sourceSize,
    });
    closureModulesByPath.set(modulePath, closureModule);
    closureModuleSourcesByPath.set(modulePath, canonicalJson(closureModule));
  }
  const closureImportsByModulePath = new Map();
  const closureImportSourcesByModulePath = new Map();
  for (const [modulePath, outputPath] of outputPathByModulePath) {
    const output = requireObject(outputs[outputPath], `esbuild output ${outputPath}`);
    if (!isOrdinaryJsonData(output)) {
      fail(`esbuild output ${outputPath} must contain ordinary JSON data`);
    }
    const outputImports = Object.hasOwn(output, "imports") ? output.imports : [];
    if (!Array.isArray(outputImports)) {
      fail(`esbuild output ${outputPath} imports must be an array`);
    }
    const imports = outputImports.map((imported, index) => {
      requireObject(imported, `esbuild output ${outputPath} import ${index}`);
      if (
        !isOrdinaryJsonData(imported) ||
        !Object.hasOwn(imported, "kind") ||
        !Object.hasOwn(imported, "path")
      ) {
        fail(`esbuild output ${outputPath} import ${index} shape is invalid`);
      }
      const kind = requireString(
        imported.kind,
        `esbuild output ${outputPath} import ${index} kind`
      );
      const importedPath = requireString(
        imported.path,
        `esbuild output ${outputPath} import ${index} path`
      );
      const external = Object.hasOwn(imported, "external") ? imported.external : undefined;
      if (external === true) {
        return { external: true, kind, path: importedPath };
      }
      if (external !== undefined && external !== false) {
        fail(`esbuild output ${outputPath} import ${index} external flag must be boolean`);
      }
      const importedOutputPath = resolveOutputImport({
        importerOutputPath: outputPath,
        importedPath,
        outputPathsByAbsolutePath,
        outputs,
        repoRoot,
      });
      const importedModulePath = modulePathByOutputPath.get(importedOutputPath);
      if (importedModulePath === undefined) {
        fail(`esbuild output module ${modulePath} imports missing output ${importedPath}`);
      }
      return { external: false, kind, path: importedModulePath };
    });
    imports.sort((left, right) => {
      const pathOrder = compareStrings(left.path, right.path);
      if (pathOrder !== 0) {
        return pathOrder;
      }
      const kindOrder = compareStrings(left.kind, right.kind);
      return kindOrder === 0 ? Number(left.external) - Number(right.external) : kindOrder;
    });
    const closureImports = freezeAuthenticatedJsonTree(
      imports.map((imported) => ({ ...imported, importerPath: modulePath }))
    );
    closureImportsByModulePath.set(modulePath, closureImports);
    closureImportSourcesByModulePath.set(modulePath, closureImports.map(canonicalJson));
  }
  const closuresByEntry = new Map();
  const closureForEntry = (entryPath, entryModulePath) => {
    const cached = closuresByEntry.get(entryPath);
    if (cached !== undefined) {
      if (cached.entryModulePath !== entryModulePath) {
        fail(`deployment output entry ${entryPath} changed its runtime module path`);
      }
      return cached;
    }
    const entryOutputPath = outputPathByModulePath.get(entryModulePath);
    if (entryOutputPath === undefined) {
      fail(`deployment output topology is missing entry module ${entryModulePath}`);
    }
    const entryOutput = requireObject(
      outputs[entryOutputPath],
      `esbuild output ${entryOutputPath}`
    );
    if (!Object.hasOwn(entryOutput, "entryPoint")) {
      fail(`esbuild output ${entryOutputPath} has no entry point`);
    }
    const declaredEntryPoint = requireString(
      entryOutput.entryPoint,
      `esbuild output ${entryOutputPath} entry point`
    );
    const normalizedEntryPoint = isAbsolute(declaredEntryPoint)
      ? toPosix(relative(repoRoot, declaredEntryPoint))
      : toPosix(declaredEntryPoint);
    if (normalizedEntryPoint !== entryPath) {
      fail(`deployment output entry ${entryPath} does not own runtime module ${entryModulePath}`);
    }
    const modulePaths = [];
    const visited = new Set();
    const visit = (modulePath) => {
      if (visited.has(modulePath)) {
        return;
      }
      visited.add(modulePath);
      modulePaths.push(modulePath);
      const imports = closureImportsByModulePath.get(modulePath);
      if (imports === undefined) {
        fail(`deployment output topology is missing module ${modulePath}`);
      }
      for (const imported of imports) {
        if (!imported.external) {
          visit(imported.path);
        }
      }
    };
    visit(entryModulePath);
    const imports = Object.freeze(
      modulePaths.flatMap((modulePath) => closureImportsByModulePath.get(modulePath))
    );
    const identity = Object.freeze({
      entryModulePath,
      imports,
      kind: DEPLOYMENT_OUTPUT_CLOSURE_KIND,
      metafileSha256,
      modules: Object.freeze(modulePaths.map((modulePath) => closureModulesByPath.get(modulePath))),
    });
    // These detached records were admitted once by this projection. Compose the same sorted-key
    // canonical identity bytes without revalidating shared module/import trees for every entry.
    const identitySource =
      `{"entryModulePath":${canonicalJson(entryModulePath)},"imports":[` +
      modulePaths
        .flatMap((modulePath) => closureImportSourcesByModulePath.get(modulePath))
        .join(",") +
      `],"kind":${canonicalJson(DEPLOYMENT_OUTPUT_CLOSURE_KIND)},` +
      `"metafileSha256":${canonicalJson(metafileSha256)},"modules":[` +
      modulePaths.map((modulePath) => closureModuleSourcesByPath.get(modulePath)).join(",") +
      "]}";
    const sha256 = createHash("sha256").update(identitySource).digest("hex");
    const closure = Object.freeze({
      ...identity,
      sha256,
    });
    deploymentOutputClosureProjectionAuthorities.set(
      closure,
      Object.freeze({
        bundleModulesByPath,
        entryModulePath,
        entryPath,
        metafile,
        metafileSha256,
        projection,
        sha256,
      })
    );
    closuresByEntry.set(entryPath, closure);
    return closure;
  };
  return {
    select({ entryPaths, runtimeModulePathByEntry }) {
      if (!isExactPlainMap(runtimeModulePathByEntry)) {
        fail("deployment output closure requires runtime module paths");
      }
      const closures = new Map();
      for (const entryPath of [...entryPaths].sort(compareStrings)) {
        const entryModulePath = runtimeModulePathByEntry.get(entryPath);
        if (entryModulePath === undefined) {
          fail(`missing runtime module path for deployment output entry ${entryPath}`);
        }
        closures.set(entryPath, closureForEntry(entryPath, entryModulePath));
      }
      deploymentOutputClosureProjectionSelections.set(
        closures,
        Object.freeze({
          bundleModulesByPath,
          metafile,
          metafileSha256,
          projection,
          runtimeModulePathByEntry,
        })
      );
      return { closures, metafileSha256 };
    },
  };
}

function authenticateDeploymentOutputClosureProjectionGraphSession(graphSession) {
  const selection = deploymentOutputClosureProjectionSelections.get(
    graphSession.deploymentOutputClosureByEntry
  );
  const graphTemplate = graphSession.graphTemplate;
  const graphSessionOwnProperties = ordinaryOwnDataPropertySnapshot(graphSession);
  const graphTemplateOwnProperties = ordinaryOwnDataPropertySnapshot(graphTemplate);
  if (
    selection === undefined ||
    graphSessionOwnProperties === undefined ||
    graphTemplateOwnProperties === undefined ||
    graphSession.bundleModulesByPath !== selection.bundleModulesByPath ||
    graphSession.runtimeModulePathByEntry !== selection.runtimeModulePathByEntry ||
    graphTemplate?.metafile !== selection.metafile ||
    graphSession.deploymentOutputMetafileSha256 !== selection.metafileSha256 ||
    !isExactPlainMap(graphSession.bundleModulesByPath) ||
    !isExactPlainMap(graphSession.deploymentOutputClosureByEntry) ||
    !isExactPlainMap(graphSession.deploymentOutputModulesByPath) ||
    !isExactPlainMap(graphSession.runtimeModulePathByEntry) ||
    !hasExactEnumerableDataProperty(graphTemplate, "metafile", selection.metafile) ||
    graphSession.deploymentOutputClosureByEntry.size !== graphSession.runtimeModulePathByEntry.size
  ) {
    return graphSession;
  }
  const selectedOutputMap = graphSession.deploymentOutputModulesByPath;
  const retainedOutputMap = deploymentOutputClosureProjectionOutputMaps.get(selection.projection);
  if (retainedOutputMap !== undefined && retainedOutputMap !== selectedOutputMap) {
    return graphSession;
  }
  for (const [entryPath, closure] of graphSession.deploymentOutputClosureByEntry) {
    const authority = deploymentOutputClosureProjectionAuthorities.get(closure);
    if (
      authority === undefined ||
      authority.projection !== selection.projection ||
      authority.entryPath !== entryPath ||
      authority.entryModulePath !== graphSession.runtimeModulePathByEntry.get(entryPath)
    ) {
      return graphSession;
    }
  }
  deploymentOutputClosureProjectionOutputMaps.set(selection.projection, selectedOutputMap);
  deploymentOutputClosureProjectionGraphSessions.set(
    graphSession,
    Object.freeze({
      bundleModulesByPath: selection.bundleModulesByPath,
      // These maps stay mutable for existing consumers. Reference-only snapshots invalidate the
      // exact fast path after an in-place edit without repeating canonical JSON or byte hashing.
      bundleModulesByPathEntries: plainMapSnapshot(selection.bundleModulesByPath),
      deploymentOutputClosureByEntry: graphSession.deploymentOutputClosureByEntry,
      deploymentOutputClosureByEntryEntries: plainMapSnapshot(
        graphSession.deploymentOutputClosureByEntry
      ),
      deploymentOutputModulesByPath: graphSession.deploymentOutputModulesByPath,
      deploymentOutputModulesByPathEntries: plainMapSnapshot(
        graphSession.deploymentOutputModulesByPath
      ),
      graphTemplate,
      graphSessionOwnProperties,
      graphTemplateOwnProperties,
      metafile: selection.metafile,
      metafileSha256: selection.metafileSha256,
      projection: selection.projection,
      runtimeModulePathByEntry: selection.runtimeModulePathByEntry,
      runtimeModulePathByEntryEntries: plainMapSnapshot(selection.runtimeModulePathByEntry),
    })
  );
  return graphSession;
}

function exactDeploymentOutputClosureProjectionGraphSession(graphSession) {
  const authority = deploymentOutputClosureProjectionGraphSessions.get(graphSession);
  return authority !== undefined &&
    hasExactOwnDataPropertySnapshot(graphSession, authority.graphSessionOwnProperties) &&
    hasExactOwnDataPropertySnapshot(
      authority.graphTemplate,
      authority.graphTemplateOwnProperties
    ) &&
    hasExactMapEntries(authority.bundleModulesByPath, authority.bundleModulesByPathEntries) &&
    hasExactMapEntries(
      authority.deploymentOutputClosureByEntry,
      authority.deploymentOutputClosureByEntryEntries
    ) &&
    hasExactMapEntries(
      authority.deploymentOutputModulesByPath,
      authority.deploymentOutputModulesByPathEntries
    ) &&
    hasExactMapEntries(
      authority.runtimeModulePathByEntry,
      authority.runtimeModulePathByEntryEntries
    ) &&
    deploymentOutputClosureProjectionOutputMaps.get(authority.projection) ===
      authority.deploymentOutputModulesByPath &&
    authority.deploymentOutputClosureByEntry.size === authority.runtimeModulePathByEntry.size
    ? authority
    : undefined;
}

function bindDeploymentGraphSessionMaterialVerificationMemo(graphSession, verificationMemo) {
  if (
    exactDeploymentOutputClosureProjectionGraphSession(graphSession) === undefined ||
    !isExactPlainMap(verificationMemo)
  ) {
    fail("graph material verification memo requires an exact authenticated graph session");
  }
  deploymentGraphSessionMaterialVerificationMemos.set(graphSession, verificationMemo);
  return graphSession;
}

function createContextReuseAnalysisInputGraphBasis({
  activeDependencyAdapters,
  assumptions,
  bundleEntryPaths,
  bundlerMaterials,
  contextReusePolicy,
  dependencyAdapter,
  inputMaterials,
  metafileSha256,
  registrationAdapter,
  toolchain,
  analysisGraphBasis,
}) {
  // Keep the complete config material in deployment graph authority, but project it out of the
  // database-UDF analyzer identity. Database-relevant config is represented by the entry topology
  // and reason-bearing policy below; retaining raw bytes here would make an HTTP-only policy
  // change rotate every database-UDF analysis result.
  freezeAuthenticatedJsonTree(inputMaterials);
  const analysisInputMaterials = Object.fromEntries(
    Object.entries(inputMaterials).filter(([path]) => path !== "convex.json")
  );
  return freezeAuthenticatedJsonTree({
    activeDependencyAdapters,
    assumptions,
    bundleEntryPaths,
    bundlerMaterials,
    contextReusePolicy,
    dependencyAdapter,
    inputMaterials: analysisInputMaterials,
    metafileSha256,
    registrationAdapter,
    toolchain,
    ...(analysisGraphBasis === undefined ? {} : analysisGraphBasis),
  });
}

function contextReuseAnalysisGraphBasisMaterial({
  functionsDirectory,
  inventory,
  normalizedRoot,
  projectConfig,
}) {
  const snapshot = inventory?.snapshot ?? inventory?.authority?.snapshot;
  const inputSha256 = snapshot?.inputSha256;
  if (typeof inputSha256 !== "string" || !/^[a-f0-9]{64}$/u.test(inputSha256)) {
    fail("context-reuse analysis graph binding requires generated inventory input identity");
  }
  const databaseFunctions = inventory.functions.map((func, index) => {
    if (
      typeof func?.entryPath !== "string" ||
      typeof func.exportName !== "string" ||
      typeof func.udfKind !== "string"
    ) {
      fail(`context-reuse analysis inventory function ${index} is incomplete`);
    }
    return { entryPath: func.entryPath, exportName: func.exportName, udfKind: func.udfKind };
  });
  return {
    databaseFunctions,
    generatedInventoryInputSha256: inputSha256,
    policy: contextReuseAnalysisPolicy({ functionsDirectory, normalizedRoot, projectConfig }),
  };
}

function bindContextReuseAnalysisToGraph({
  analysis,
  applicationAdmissionPolicy,
  expectedEntries,
  graphBasis,
  expectedIdentity,
}) {
  if (analysis === undefined) return;
  const graphSha256 = createConvexContextReuseAnalysisInputGraphSha256(graphBasis);
  const identity = authenticateConvexContextReuseApplicationAdmission(analysis, {
    applicationAdmissionPolicy,
    expectedAnalysisInputGraphSha256: graphSha256,
    expectedEntries,
  }).identity;
  if (canonicalJson(identity) !== canonicalJson(expectedIdentity)) {
    fail("context-reuse analysis result changed while the deployment graph was constructed");
  }
}

function verifyContextReuseApplicationAdmission({
  analysis,
  applicationAdmissionPolicy,
  expectedEntries,
  expectedIdentity,
}) {
  if (analysis === undefined) {
    if (expectedIdentity !== undefined) {
      fail("context-reuse application admission lost its complete analysis result");
    }
    return;
  }
  // Reauthenticate mutable caller-owned result data against the policy retained at graph
  // admission. Reloading the origin file here would let a later non-Git edit change this session.
  authenticateConvexContextReuseApplicationAdmission(analysis, {
    applicationAdmissionPolicy,
    expectedEntries,
    expectedIdentity,
  });
}

function freezeAuthenticatedJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeAuthenticatedJsonTree(nested);
    if (!Object.isFrozen(value)) Object.freeze(value);
  }
  return value;
}

async function bundledModulesFromResult({
  entryPoints,
  environment = "isolate",
  functionsDirectory,
  outputFiles,
  metafile,
  projectConfig,
  repoRoot,
}) {
  const sourceMaps = new Map();
  const sources = [];
  for (const outputFile of outputFiles) {
    const relativePath = relative(resolve(repoRoot, "out"), outputFile.path);
    if (extname(relativePath) === ".map") {
      sourceMaps.set(toPosix(relativePath), outputFile.text);
    } else {
      sources.push({
        outputPath: resolve(outputFile.path),
        path: toPosix(relativePath),
        source: outputFile.text,
      });
    }
  }
  const contextReuse = projectConfig.bundler?.experimentalContextReuse;
  const contextReuseOutputPolicy = new Map();
  if (contextReuse !== undefined) {
    const unmatchedExclusions = new Set(Object.keys(contextReuse.exclusions));
    const reuseByEntryPoint = new Map(
      entryPoints.map((entryPoint) => {
        const normalizedEntry = toPosix(relative(functionsDirectory, entryPoint));
        return [resolve(entryPoint), !unmatchedExclusions.delete(normalizedEntry)];
      })
    );
    if (unmatchedExclusions.size > 0) {
      fail(
        `context-reuse exclusions do not match isolate bundle entries: ${[...unmatchedExclusions]
          .sort(compareStrings)
          .join(", ")}`
      );
    }
    for (const [outputPath, output] of Object.entries(metafile.outputs ?? {})) {
      if (output.entryPoint === undefined) {
        continue;
      }
      const entryPoint = resolve(repoRoot, output.entryPoint);
      const enabled = reuseByEntryPoint.get(entryPoint);
      if (enabled !== undefined) {
        contextReuseOutputPolicy.set(resolve(repoRoot, outputPath), {
          enabled,
          entry: toPosix(relative(functionsDirectory, entryPoint)),
          httpActions: contextReuse.httpActions,
        });
      }
    }
  }
  const modulesByPath = new Map();
  const exactModulesByPath = new Map();
  for (const output of sources.sort((left, right) => compareStrings(left.path, right.path))) {
    const policy = contextReuseOutputPolicy.get(output.outputPath);
    const source =
      policy === undefined
        ? output.source
        : applyPinnedDefaultContextReusePolicy(output.source, policy);
    const sourceMap = sourceMaps.get(`${output.path}.map`);
    const bundle = {
      environment,
      path: output.path,
      source,
      ...(sourceMap === undefined ? {} : { sourceMap }),
    };
    if (modulesByPath.has(output.path)) {
      fail(`installed Convex bundler emitted duplicate module ${output.path}`);
    }
    const identity = bundleModuleIdentity(
      bundle,
      `installed Convex bundle module ${output.path}`,
      environment
    );
    modulesByPath.set(output.path, identity);
    exactModulesByPath.set(output.path, {
      path: output.path,
      source,
      ...(sourceMap === undefined ? {} : { sourceMap }),
    });
  }
  if (sourceMaps.size !== sources.filter(({ path }) => sourceMaps.has(`${path}.map`)).length) {
    fail("installed Convex bundler emitted an unattached source map");
  }
  return { exactModulesByPath, modulesByPath };
}

async function bundleOfficialNodeModules({
  entryPoints,
  esbuild,
  externalPackagesAllowList,
  functionsDirectory,
  graphMaterialVerificationMemo,
  materialsByAbsolutePath,
  nodeShimsPlugin,
  normalizedRoot,
  previousInputMaterials,
  serverOnlyPlugin,
  sourceMaterialBuildState,
  wasmPlugin,
}) {
  if (entryPoints.length === 0) {
    return { inputMaterials: {}, modulesByPath: new Map() };
  }
  const availableExternalPackages = await pinnedExternalNodePackages(
    normalizedRoot,
    externalPackagesAllowList
  );
  const external = pinnedNodeExternalPlugin(availableExternalPackages);
  const result = await esbuild.build({
    absWorkingDir: normalizedRoot,
    bundle: true,
    chunkNames: join("_deps", "node", "[hash]"),
    conditions: ["convex", "module"],
    define: {
      "process.env.NODE_ENV": '"production"',
    },
    entryPoints,
    format: "esm",
    jsx: "automatic",
    keepNames: true,
    logLevel: "silent",
    metafile: true,
    minifyIdentifiers: true,
    minifySyntax: true,
    minifyWhitespace: false,
    outbase: functionsDirectory,
    outdir: "out",
    platform: "node",
    plugins: [
      sourceMaterialPlugin(
        materialsByAbsolutePath,
        graphMaterialVerificationMemo,
        readStableFile,
        sourceMaterialBuildState
      ),
      nodeShimsPlugin,
      serverOnlyPlugin,
      external.plugin,
      wasmPlugin,
    ],
    sourcemap: true,
    sourcesContent: false,
    splitting: true,
    target: "esnext",
    treeShaking: true,
    write: false,
  });
  if (result.errors.length > 0) {
    fail(
      `installed Convex Node bundler returned ${result.errors.length} errors without rejecting the build`
    );
  }
  const bundled = await bundledModulesFromResult({
    entryPoints,
    environment: "node",
    functionsDirectory,
    metafile: result.metafile,
    outputFiles: result.outputFiles,
    projectConfig: { bundler: {} },
    repoRoot: normalizedRoot,
  });
  return {
    inputMaterials: await graphInputMaterials(
      normalizedRoot,
      normalizedRoot,
      result.metafile,
      materialsByAbsolutePath,
      { previousMaterials: previousInputMaterials, sourceMaterialBuildState }
    ),
    modulesByPath: bundled.modulesByPath,
  };
}

async function resolveAuthConfigEntryPath(functionsDirectory) {
  const javascriptPath = join(functionsDirectory, "auth.config.js");
  const typescriptPath = join(functionsDirectory, "auth.config.ts");
  const [javascriptExists, typescriptExists] = await settleParallelVerification(
    [javascriptPath, typescriptPath].map((path) => async () => {
      try {
        await fs.access(path);
        return true;
      } catch (error) {
        if (error?.code === "ENOENT") {
          return false;
        }
        throw error;
      }
    })
  );
  if (javascriptExists && typescriptExists) {
    fail("both auth.config.js and auth.config.ts exist; exactly one is allowed");
  }
  return typescriptExists ? typescriptPath : javascriptExists ? javascriptPath : null;
}

async function bundleOfficialDeploymentConfiguration({
  browserExternalPlugin,
  esbuild,
  functionsDirectory,
  graphMaterialVerificationMemo,
  materialsByAbsolutePath,
  nodeShimsPlugin,
  normalizedRoot,
  previousInputMaterials,
  serverOnlyPlugin,
  sourceMaterialBuildState,
  wasmPlugin,
}) {
  const entryPath = await resolveAuthConfigEntryPath(functionsDirectory);
  if (entryPath === null) {
    return {
      entryPath,
      inputMaterials: {},
      modulesByPath: new Map(),
    };
  }
  // Convex excludes auth.config from UDF entry points and appends this separate,
  // single-output browser bundle to the deployment request.
  const result = await esbuild.build({
    absWorkingDir: normalizedRoot,
    bundle: true,
    chunkNames: join("_deps", "[hash]"),
    conditions: ["convex", "module"],
    define: {
      "process.env.NODE_ENV": '"production"',
    },
    entryPoints: [entryPath],
    format: "esm",
    jsx: "automatic",
    keepNames: true,
    logLevel: "silent",
    metafile: true,
    minifyIdentifiers: true,
    minifySyntax: true,
    minifyWhitespace: false,
    outbase: functionsDirectory,
    outdir: "out",
    platform: "browser",
    plugins: [
      sourceMaterialPlugin(
        materialsByAbsolutePath,
        graphMaterialVerificationMemo,
        readStableFile,
        sourceMaterialBuildState
      ),
      nodeShimsPlugin,
      serverOnlyPlugin,
      browserExternalPlugin,
      wasmPlugin,
    ],
    sourcemap: true,
    sourcesContent: false,
    splitting: false,
    target: "esnext",
    treeShaking: true,
    write: false,
  });
  if (result.errors.length > 0) {
    fail(
      `installed Convex auth-config bundler returned ${result.errors.length} errors without rejecting the build`
    );
  }
  const bundled = await bundledModulesFromResult({
    entryPoints: [entryPath],
    functionsDirectory,
    metafile: result.metafile,
    outputFiles: result.outputFiles,
    projectConfig: { bundler: {} },
    repoRoot: normalizedRoot,
  });
  const modulesByPath = bundled.modulesByPath;
  if (
    modulesByPath.size !== 1 ||
    !modulesByPath.has("auth.config.js") ||
    modulesByPath.get("auth.config.js").environment !== "isolate"
  ) {
    fail("the installed Convex auth-config bundler must emit only auth.config.js");
  }
  return {
    entryPath,
    inputMaterials: await graphInputMaterials(
      normalizedRoot,
      normalizedRoot,
      result.metafile,
      materialsByAbsolutePath,
      { previousMaterials: previousInputMaterials, sourceMaterialBuildState }
    ),
    modulesByPath,
  };
}

async function graphInputMaterials(
  repoRoot,
  toolchainRoot,
  metafile,
  materialsByAbsolutePath,
  { previousMaterials, sourceMaterialBuildState } = {}
) {
  const materials = {};
  for (const inputPath of Object.keys(metafile.inputs).sort(compareStrings)) {
    const input = metafile.inputs[inputPath];
    const imports = (input.imports ?? [])
      .map(({ external = false, kind, original, path }) => ({
        external,
        kind,
        ...(original === undefined ? {} : { original }),
        path,
      }))
      .sort((left, right) => {
        const pathOrder = compareStrings(left.path, right.path);
        if (pathOrder !== 0) {
          return pathOrder;
        }
        const kindOrder = compareStrings(left.kind, right.kind);
        return kindOrder === 0
          ? compareStrings(left.original ?? "", right.original ?? "")
          : kindOrder;
      });
    if (
      !isMaterialInputPath(
        inputPath,
        repoRoot,
        toolchainRoot,
        materialsByAbsolutePath,
        sourceMaterialBuildState?.loadedPaths
      )
    ) {
      materials[inputPath] = { imports, virtual: true };
      continue;
    }
    const rawMaterial = materialsByAbsolutePath.get(resolve(repoRoot, inputPath));
    if (rawMaterial === undefined || rawMaterial.size !== input.bytes) {
      fail(`source ${inputPath} changed while esbuild was constructing the graph`);
    }
    const material = {
      imports,
      sha256: rawMaterial.sha256,
      size: rawMaterial.size,
      virtual: false,
    };
    const stagedEntryKey = sourceMaterialBuildState?.currentGitIdentitiesByPath.get(inputPath);
    const previousEntryKey = sourceMaterialBuildState?.previousGitIdentitiesByPath.get(inputPath);
    const previous = previousMaterials?.[inputPath];
    if (
      previous !== undefined &&
      stagedEntryKey !== undefined &&
      stagedEntryKey === previousEntryKey &&
      sourceGraphInputMaterialEqual(previous, material)
    ) {
      materials[inputPath] = previous;
      if (
        sourceMaterialBuildState !== undefined &&
        !sourceMaterialBuildState.countedSourceMaterialPaths.has(inputPath)
      ) {
        sourceMaterialBuildState.counters.reused += 1;
        sourceMaterialBuildState.countedSourceMaterialPaths.add(inputPath);
      }
    } else {
      materials[inputPath] = material;
    }
  }
  return materials;
}

async function verifyGraphInputMaterials(
  repoRoot,
  materials,
  concurrency,
  readMaterial = hashFile,
  verificationMemo,
  capturedSourceMaterials
) {
  requireObject(materials, "graph input materials");
  if (verificationMemo !== undefined && !(verificationMemo instanceof Map)) {
    fail("graph input material verification memo must be a Map");
  }
  await mapBounded(Object.entries(materials), concurrency, async ([inputPath, expected]) => {
    requireObject(expected, `graph input material ${inputPath}`);
    if (expected.virtual === true) {
      return;
    }
    if (
      expected.virtual !== false ||
      typeof expected.sha256 !== "string" ||
      !Number.isSafeInteger(expected.size) ||
      expected.size < 0
    ) {
      fail(`graph input material ${inputPath} is incomplete`);
    }
    const absolutePath = resolve(repoRoot, inputPath);
    const captured = capturedSourceMaterials?.get(absolutePath);
    if (captured?.gitBlobOid !== undefined) {
      // The source loader consumed this captured blob. Later worktree bytes belong to a
      // different build and cannot verify or invalidate the bytes this graph owns.
      if (captured.sha256 !== expected.sha256 || captured.size !== expected.size) {
        fail(`captured graph input ${inputPath} disagrees with its consumed material`);
      }
      return;
    }
    // A deployment may verify the same authenticated graph before and after artifact work. Keep
    // the first digest, but require the exact file identity to remain stable before reusing it.
    const before =
      verificationMemo === undefined ? undefined : await fs.lstat(absolutePath, { bigint: true });
    const cached = verificationMemo?.get(absolutePath);
    if (
      cached !== undefined &&
      before !== undefined &&
      before.isFile() &&
      sameFileState(cached.state, before)
    ) {
      const after = await fs.lstat(absolutePath, { bigint: true });
      if (after.isFile() && sameFileState(before, after)) {
        if (cached.sha256 !== expected.sha256 || cached.size !== expected.size) {
          fail(`graph input ${inputPath} changed after esbuild constructed the graph`);
        }
        return;
      }
    }
    const current = await readMaterial(absolutePath);
    if (current.sha256 !== expected.sha256 || current.size !== expected.size) {
      fail(`graph input ${inputPath} changed after esbuild constructed the graph`);
    }
    if (verificationMemo !== undefined) {
      const after = await fs.lstat(absolutePath, { bigint: true });
      if (before !== undefined && !sameFileState(before, after)) {
        fail(`graph input ${inputPath} changed during material verification`);
      }
      // Symlink target state is not represented by lstat. Do not let a symlink memoize its target
      // digest; later verifications must continue through the complete stable physical read.
      if (after.isFile()) {
        verificationMemo.set(absolutePath, {
          sha256: current.sha256,
          size: current.size,
          state: after,
        });
      } else {
        verificationMemo.delete(absolutePath);
      }
    }
  });
}

function dependencyClosure(entryPath, metafile) {
  if (metafile.inputs[entryPath] === undefined) {
    fail(`esbuild metafile is missing entry ${entryPath}`);
  }
  const visited = new Set();
  const pending = [entryPath];
  while (pending.length > 0) {
    const current = pending.pop();
    if (visited.has(current)) {
      continue;
    }
    visited.add(current);
    const input = metafile.inputs[current];
    if (input === undefined) {
      fail(`esbuild dependency ${current} disappeared from the metafile`);
    }
    for (const imported of input.imports ?? []) {
      if (!imported.external && metafile.inputs[imported.path] !== undefined) {
        pending.push(imported.path);
      }
    }
  }
  return [...visited].sort(compareStrings);
}

function sourceGraphInputMaterialEqual(left, right) {
  if (left === undefined || right === undefined || left.virtual !== right.virtual) return false;
  if (left.virtual !== true && (left.sha256 !== right.sha256 || left.size !== right.size)) {
    return false;
  }
  return canonicalJson(left.imports) === canonicalJson(right.imports);
}

function changedSourceGraphInputPaths(previousMaterials, currentMaterials, changedGitPaths) {
  if (previousMaterials === undefined || changedGitPaths === undefined) return undefined;
  const changed = new Set(changedGitPaths);
  for (const path of new Set([
    ...Object.keys(previousMaterials),
    ...Object.keys(currentMaterials),
  ])) {
    if (!sourceGraphInputMaterialEqual(previousMaterials[path], currentMaterials[path])) {
      changed.add(path);
    }
  }
  return changed;
}

function deduplicateMetafileImports(metafile) {
  for (const input of Object.values(metafile.inputs)) {
    const seen = new Set();
    input.imports = (input.imports ?? []).filter((imported) => {
      const identity = canonicalJson(imported);
      if (seen.has(identity)) {
        return false;
      }
      seen.add(identity);
      return true;
    });
  }
}

function runtimeModulePathsByEntry(repoRoot, entryPaths, metafile) {
  const entrySet = new Set(entryPaths);
  const paths = new Map();
  for (const [outputPath, output] of Object.entries(metafile.outputs ?? {})) {
    if (output.entryPoint === undefined) {
      continue;
    }
    const entryPath = isAbsolute(output.entryPoint)
      ? toPosix(relative(repoRoot, output.entryPoint))
      : toPosix(output.entryPoint);
    if (!entrySet.has(entryPath)) {
      // Esbuild also marks dynamically imported modules as entry points in its
      // metafile. They are deployed dependency chunks, not UDF route modules.
      continue;
    }
    const runtimeModulePath = outputModulePath(repoRoot, outputPath);
    if (
      runtimeModulePath === ".." ||
      runtimeModulePath.startsWith("../") ||
      runtimeModulePath.startsWith("/") ||
      !runtimeModulePath.endsWith(".js")
    ) {
      fail(`esbuild emitted an invalid runtime module path ${runtimeModulePath}`);
    }
    if (paths.has(entryPath)) {
      fail(`esbuild emitted multiple runtime modules for ${entryPath}`);
    }
    paths.set(entryPath, runtimeModulePath);
  }
  for (const entryPath of entryPaths) {
    if (!paths.has(entryPath)) {
      fail(`esbuild did not emit a runtime module for ${entryPath}`);
    }
  }
  return paths;
}

function cachedGraphMap(value, description) {
  requireObject(value, description);
  return new Map(
    Object.entries(value)
      .sort(([left], [right]) => compareStrings(left, right))
      .map(([path, item]) => [path, freezeAuthenticatedJsonTree(item)])
  );
}

function includeSourceGraphSnapshotForSelection(options) {
  if (options === undefined) return true;
  requireObject(options, "graph entry selection options");
  if (
    Object.keys(options).length !== 1 ||
    !Object.hasOwn(options, "includeSourceGraphSnapshot") ||
    typeof options.includeSourceGraphSnapshot !== "boolean"
  ) {
    fail("graph entry selection options must contain one includeSourceGraphSnapshot boolean");
  }
  return options.includeSourceGraphSnapshot;
}

async function materializeCachedDeploymentGraphSession({
  contextReuseAnalysis,
  contextReuseApplicationAdmissionPolicy,
  contextReuseAnalysisSharedIdentity,
  contextReuseAnalysisThirdPartyMaterialFingerprints,
  contextReuseAnalysisGraphMaterial,
  admittedSnapshot,
  bundlerDirectory,
  cliDirectory,
  entryPaths,
  functionsDirectory,
  generatedSourcePrefix,
  gitSourceSnapshot,
  graphMaterialVerificationMemo,
  includeSourceGraphSnapshot,
  inventory,
  lookupUs,
  materialVerificationConcurrency,
  normalizedRoot,
  sourceGraphSnapshotCacheDirectory,
  toolchainInputPaths,
  wasmCompilationPolicy,
}) {
  const cached = requireObject(admittedSnapshot.session, "cached source graph session");
  const metafile = freezeAuthenticatedJsonTree(
    requireObject(cached.metafile, "cached source graph metafile")
  );
  const materials = freezeAuthenticatedJsonTree(admittedSnapshot.inputs);
  const bundleModulesByPath = cachedGraphMap(
    cached.bundleModulesByPath,
    "cached isolate bundle modules"
  );
  const deploymentOutputModulesByPath = cachedGraphMap(
    cached.deploymentOutputModulesByPath,
    "cached exact deployment output modules"
  );
  if (
    bundleModulesByPath.size !== deploymentOutputModulesByPath.size ||
    [...bundleModulesByPath].some(([path, expectedIdentity]) => {
      const exactModule = deploymentOutputModulesByPath.get(path);
      return (
        exactModule === undefined ||
        canonicalJson(
          bundleModuleIdentity(
            { environment: "isolate", ...exactModule },
            `cached deployment output module ${path}`,
            "isolate"
          )
        ) !== canonicalJson(expectedIdentity)
      );
    })
  ) {
    fail("cached deployment output modules disagree with their authenticated identities");
  }
  const deploymentConfigurationModulesByPath = cachedGraphMap(
    cached.deploymentConfigurationModulesByPath,
    "cached deployment configuration modules"
  );
  const nodeModulesByPath = cachedGraphMap(cached.nodeModulesByPath, "cached Node modules");
  const authoritativeInputMaterials = freezeAuthenticatedJsonTree(
    requireObject(cached.authoritativeInputMaterials, "cached authoritative graph input materials")
  );
  const nodeInputMaterials = freezeAuthenticatedJsonTree(
    requireObject(cached.nodeInputMaterials, "cached Node input materials")
  );
  const deploymentConfigurationInputMaterials = freezeAuthenticatedJsonTree(
    requireObject(
      cached.deploymentConfigurationInputMaterials,
      "cached deployment configuration input materials"
    )
  );
  const activeDependencyAdapters = freezeAuthenticatedJsonTree(
    requireObject(cached.activeDependencyAdapters, "cached active dependency adapters")
  );
  if (!Array.isArray(activeDependencyAdapters.adapters)) {
    fail("cached active dependency adapters have no adapter list");
  }
  const dependencyAdapter = freezeAuthenticatedJsonTree(
    admittedSnapshot.identity.dependencyAdapter
  );
  const registrationAdapter = freezeAuthenticatedJsonTree(
    admittedSnapshot.identity.registrationAdapter
  );
  const contextReusePolicy = freezeAuthenticatedJsonTree(
    admittedSnapshot.identity.contextReusePolicy
  );
  // The deployment graph covers every isolate bundle entry, so a newly added action-only entry
  // still invalidates the graph. Context-reuse analysis, however, is a database-UDF contract:
  // actions are intentionally absent from the generated `functions` inventory and from this
  // selection identity. Narrow result authentication to actual query/mutation entry paths.
  const databaseEntryPaths = new Set(inventory.functions.map(({ entryPath }) => entryPath));
  const contextReuseEnabledEntries = contextReusePolicy.entries
    .filter(({ enabled, entryPath }) => enabled && databaseEntryPaths.has(entryPath))
    .map(({ entryPath }) => entryPath)
    .sort(compareStrings);
  const contextReuseAnalysisIdentity =
    admittedSnapshot.identity.contextReuseAnalysis === undefined
      ? undefined
      : authenticateConvexContextReuseResultIdentity(
          admittedSnapshot.identity.contextReuseAnalysis
        );
  const toolchain = freezeAuthenticatedJsonTree(admittedSnapshot.identity.toolchain);
  const lookupIdentity = freezeAuthenticatedJsonTree(admittedSnapshot.lookupIdentity);
  const normalizedEffectExecutionMode = normalizeConvexWasmEffectExecutionMode(
    lookupIdentity.effectExecutionMode
  );
  const cachedEntryPaths = admittedSnapshot.dependencyGraphs.map(({ entryPath }) => entryPath);
  const cachedEntryPathSet = new Set(cachedEntryPaths);
  if (entryPaths.some((entryPath) => !cachedEntryPathSet.has(entryPath))) {
    fail("cached source graph snapshot does not cover the requested graph scope");
  }
  const dependencyGraphsByEntry = new Map(
    admittedSnapshot.dependencyGraphs.map((graph) => [
      graph.entryPath,
      freezeAuthenticatedJsonTree({ inputPaths: [...graph.inputPaths], sha256: graph.sha256 }),
    ])
  );
  const isolateEntryPaths = lookupIdentity.bundleEntryPaths;
  const isolateEntrySet = new Set(
    isolateEntryPaths.map((entryPath) => resolve(normalizedRoot, entryPath))
  );
  const runtimeModulePathsForIsolateEntries = runtimeModulePathsByEntry(
    normalizedRoot,
    isolateEntryPaths,
    metafile
  );
  const deploymentOutputClosureProjection = createConvexWasmDeploymentOutputClosureProjection({
    bundleModulesByPath,
    metafile,
    repoRoot: normalizedRoot,
  });
  const externalDependencies =
    contextReuseAnalysisGraphMaterial === undefined
      ? undefined
      : captureContextReuseExternalDependencyIdentities(normalizedRoot, metafile)
          .externalDependencies;
  const graphIdentityInputs = Object.fromEntries(
    Object.entries(materials).filter(([path]) => path !== dependencyAdapter.source.path)
  );
  const capturedSourceMaterials = new Map();
  const stagedEntries = sourceMaterialGitEntries(gitSourceSnapshot, generatedSourcePrefix);
  const stagedBundleInputs = new Map();
  for (const path of new Set([
    ...Object.keys(metafile.inputs),
    ...Object.keys(nodeInputMaterials),
    ...Object.keys(deploymentConfigurationInputMaterials),
  ])) {
    const staged = stagedEntries.get(path)?.identity;
    if (staged !== undefined && authoritativeInputMaterials[path]?.virtual === false) {
      stagedBundleInputs.set(path, staged.blobOid);
    }
  }
  // Persisted sessions retain emitted bytes and digests, not source buffers. Recover their
  // consumed staged sources once; configuration and non-Git inputs still use physical checks.
  if (stagedBundleInputs.size !== 0) {
    const blobs = await readConvexWasmGitBlobMaterials(normalizedRoot, [
      ...new Set(stagedBundleInputs.values()),
    ]);
    for (const [path, oid] of stagedBundleInputs) {
      const material = blobs.get(oid);
      const expected = authoritativeInputMaterials[path];
      if (
        material === undefined ||
        material.sha256 !== expected.sha256 ||
        material.size !== expected.size
      ) {
        fail(`captured graph input ${path} disagrees with its consumed material`);
      }
      capturedSourceMaterials.set(resolve(normalizedRoot, path), material);
    }
  }
  const verifyBundleInputMaterials = async () => {
    await settleParallelVerification([
      () =>
        verifyGraphInputMaterials(
          normalizedRoot,
          nodeInputMaterials,
          materialVerificationConcurrency,
          hashFile,
          graphMaterialVerificationMemo,
          capturedSourceMaterials
        ),
      () =>
        verifyGraphInputMaterials(
          normalizedRoot,
          deploymentConfigurationInputMaterials,
          materialVerificationConcurrency,
          hashFile,
          graphMaterialVerificationMemo,
          capturedSourceMaterials
        ),
    ]);
  };
  const verifyBundleEntryPaths = async () => {
    const [current, currentAuthConfigEntryPath] = await settleParallelVerification([
      () => convexEntryPointsByEnvironment(functionsDirectory),
      () => resolveAuthConfigEntryPath(functionsDirectory),
    ]);
    const currentIsolate = current.isolate
      .map((entryPoint) => resolve(entryPoint))
      .sort(compareStrings);
    if (
      canonicalJson(currentIsolate) !==
      canonicalJson(isolateEntryPaths.map((entryPath) => resolve(normalizedRoot, entryPath)))
    ) {
      fail("Convex isolate bundle entry paths changed after cached graph admission");
    }
    const currentNode = current.node.map((entryPoint) => resolve(entryPoint)).sort(compareStrings);
    if (
      canonicalJson(currentNode) !==
      canonicalJson(
        lookupIdentity.nodeEntryPaths.map((entryPath) => resolve(normalizedRoot, entryPath))
      )
    ) {
      fail("Convex Node bundle entry paths changed after cached graph admission");
    }
    const expectedAuthConfigEntryPath =
      lookupIdentity.deploymentConfigurationEntryPath === null
        ? null
        : resolve(normalizedRoot, lookupIdentity.deploymentConfigurationEntryPath);
    if (currentAuthConfigEntryPath !== expectedAuthConfigEntryPath) {
      fail("Convex auth-config entry path changed after cached graph admission");
    }
    await verifyBundleInputMaterials();
  };
  const verifyInputMaterials = async () => {
    const currentToolchain = await loadGraphToolchain(normalizedRoot);
    if (
      currentToolchain.bundlerDirectory !== bundlerDirectory ||
      currentToolchain.cliDirectory !== cliDirectory ||
      canonicalJson(currentToolchain.toolchain) !== canonicalJson(toolchain)
    ) {
      fail("Convex graph toolchain changed after cached graph admission");
    }
    const [currentBundlerMaterials, currentDependencyAdapter] = await settleParallelVerification([
      () => authenticateConvexBundlerMaterials(currentToolchain),
      () =>
        hydrateConvexWasmDependencyAdapterMaterial(
          normalizedRoot,
          dependencyAdapter,
          activeDependencyAdapters.adapters
        ),
      () =>
        verifyGraphInputMaterials(
          normalizedRoot,
          materials,
          materialVerificationConcurrency,
          hashFile,
          graphMaterialVerificationMemo,
          capturedSourceMaterials
        ),
      () =>
        verifyContextReuseApplicationAdmission({
          analysis: contextReuseAnalysis,
          applicationAdmissionPolicy: contextReuseApplicationAdmissionPolicy,
          expectedEntries: contextReuseEnabledEntries,
          expectedIdentity: contextReuseAnalysisIdentity,
        }),
    ]);
    if (canonicalJson(currentBundlerMaterials) !== canonicalJson(lookupIdentity.bundlerMaterials)) {
      fail("Convex graph bundler materials changed after cached graph admission");
    }
    if (canonicalJson(currentDependencyAdapter) !== canonicalJson(dependencyAdapter)) {
      fail("Convex dependency adapter materials changed after cached graph admission");
    }
  };
  const selectEntryCandidates = (candidates, options) => {
    const includeSourceGraphSnapshot = includeSourceGraphSnapshotForSelection(options);
    const selectedEntryPaths = [...new Set(candidates)].sort(compareStrings);
    if (selectedEntryPaths.length === 0) {
      fail("selected cached graph session contains no entry points");
    }
    for (const entryPath of selectedEntryPaths) {
      if (
        !isolateEntrySet.has(resolve(normalizedRoot, entryPath)) ||
        !dependencyGraphsByEntry.has(entryPath)
      ) {
        fail(`cached graph session has no authenticated entry ${entryPath}`);
      }
    }
    const runtimeModulePathByEntry = new Map(
      selectedEntryPaths.map((entryPath) => [
        entryPath,
        runtimeModulePathsForIsolateEntries.get(entryPath),
      ])
    );
    const deploymentOutput = deploymentOutputClosureProjection.select({
      entryPaths: selectedEntryPaths,
      runtimeModulePathByEntry,
    });
    const dependencyGraphByEntry = new Map(
      selectedEntryPaths.map((entryPath) => [entryPath, dependencyGraphsByEntry.get(entryPath)])
    );
    const graphIdentity = {
      activeDependencyAdapters,
      assumptions: admittedSnapshot.identity.assumptions,
      bundleEntryPaths: isolateEntryPaths,
      bundlerMaterials: lookupIdentity.bundlerMaterials,
      contextReusePolicy,
      ...(wasmCompilationPolicy === undefined ? {} : { wasmCompilationPolicy }),
      ...(contextReuseAnalysisIdentity === undefined
        ? {}
        : { contextReuseAnalysis: contextReuseAnalysisIdentity }),
      ...(normalizedEffectExecutionMode === convexWasmDefaultEffectExecutionMode
        ? {}
        : { effectExecutionMode: normalizedEffectExecutionMode }),
      entryPaths: selectedEntryPaths,
      inputs: graphIdentityInputs,
      kind: GRAPH_SESSION_KIND,
      deploymentOutputClosures: Object.fromEntries(
        [...deploymentOutput.closures].map(([entryPath, closure]) => [entryPath, closure.sha256])
      ),
      deploymentOutputMetafileSha256: deploymentOutput.metafileSha256,
      runtimeModulePaths: Object.fromEntries(runtimeModulePathByEntry),
      registrationAdapter,
      toolchain,
    };
    const sameSnapshotScope =
      selectedEntryPaths.length === cachedEntryPaths.length &&
      selectedEntryPaths.every((entryPath, index) => entryPath === cachedEntryPaths[index]);
    const sourceGraphSnapshot = includeSourceGraphSnapshot
      ? sameSnapshotScope
        ? admittedSnapshot
        : createConvexWasmSourceGraphSnapshot({
            gitSourceSnapshot,
            graphSession: {
              ...(contextReuseAnalysisIdentity === undefined
                ? {}
                : { contextReuseAnalysisIdentity }),
              contextReusePolicy,
              dependencyGraphByEntry,
              graphTemplate: {
                assumptions: graphIdentity.assumptions,
                dependencyAdapter,
                registrationAdapter,
              },
              inputMaterials: materials,
              sourceGraphSnapshotLookupIdentity: lookupIdentity,
              sourceGraphSnapshotSession: admittedSnapshot.session,
              toolchain,
            },
          })
      : undefined;
    const contextReuseAnalysisInputGraphBasis = createContextReuseAnalysisInputGraphBasis({
      activeDependencyAdapters,
      assumptions: graphIdentity.assumptions,
      bundleEntryPaths: isolateEntryPaths,
      bundlerMaterials: lookupIdentity.bundlerMaterials,
      contextReusePolicy,
      dependencyAdapter,
      inputMaterials: materials,
      metafileSha256: deploymentOutput.metafileSha256,
      registrationAdapter,
      toolchain,
      ...(contextReuseAnalysisGraphMaterial === undefined
        ? {}
        : {
            analysisGraphBasis: {
              ...contextReuseAnalysisGraphMaterial,
              externalDependencies,
            },
          }),
    });
    bindContextReuseAnalysisToGraph({
      analysis: contextReuseAnalysis,
      applicationAdmissionPolicy: contextReuseApplicationAdmissionPolicy,
      expectedEntries: contextReuseEnabledEntries,
      expectedIdentity: contextReuseAnalysisIdentity,
      graphBasis: contextReuseAnalysisInputGraphBasis,
    });
    const graphSession = {
      authoritativeInputMaterials,
      bundleModulesByPath,
      contextReuseAnalysisInputGraphBasis,
      deploymentConfigurationModulesByPath,
      dependencyGraphByEntry,
      graphSha256: fingerprintJson(graphIdentity),
      graphTemplate: {
        assumptions: graphIdentity.assumptions,
        functionsRoot: functionsRelativePath,
        ...(normalizedEffectExecutionMode === convexWasmDefaultEffectExecutionMode
          ? {}
          : { effectExecutionMode: normalizedEffectExecutionMode }),
        kind: GRAPH_KIND,
        metafile,
        phaseTimingsUs: {
          esbuildGraph: 0,
          sourceGraphSnapshotCacheLookup: lookupUs,
        },
        dependencyAdapter,
        registrationAdapter,
        repoRoot: normalizedRoot,
        toolchain,
      },
      inputCount: Object.keys(metafile.inputs).length,
      inputMaterials: materials,
      contextReuseEnabledByEntry: new Map(
        contextReusePolicy.entries.map(({ enabled, entryPath }) => [entryPath, enabled])
      ),
      contextReusePolicy,
      ...(wasmCompilationPolicy === undefined ? {} : { wasmCompilationPolicy }),
      ...(contextReuseApplicationAdmissionPolicy === undefined
        ? {}
        : { contextReuseApplicationAdmissionPolicy }),
      ...(contextReuseAnalysisIdentity === undefined ? {} : { contextReuseAnalysisIdentity }),
      ...(contextReuseAnalysisSharedIdentity === undefined
        ? {}
        : { contextReuseAnalysisSharedIdentity }),
      ...(contextReuseAnalysisThirdPartyMaterialFingerprints === undefined
        ? {}
        : { contextReuseAnalysisThirdPartyMaterialFingerprints }),
      effectExecutionMode: normalizedEffectExecutionMode,
      gitSourceSnapshot,
      nodeModulesByPath,
      deploymentOutputClosureByEntry: deploymentOutput.closures,
      deploymentOutputMetafileSha256: deploymentOutput.metafileSha256,
      deploymentOutputModulesByPath,
      phaseTimingsUs: { esbuildGraph: 0, sourceGraphSnapshotCacheLookup: lookupUs },
      runtimeModulePathByEntry,
      selectEntryCandidates,
      ...(sourceGraphSnapshot === undefined ? {} : { sourceGraphSnapshot }),
      sourceGraphSnapshotCache: {
        lookup: "authenticated-session-hit",
        lookupUs,
        snapshotSha256: admittedSnapshot.sha256,
      },
      sourceGraphSnapshotCacheDirectory,
      sourceGraphSnapshotLookupIdentity: lookupIdentity,
      sourceGraphSnapshotSession: admittedSnapshot.session,
      toolchain,
      toolchainInputPaths,
      verifyBundleInputMaterials,
      verifyBundleEntryPaths,
      verifyGitSourceSnapshot: async () =>
        verifyConvexWasmGitSourceSnapshot(gitSourceSnapshot, { repoRoot: normalizedRoot }),
      verifyInputMaterials,
    };
    const authenticatedGraphSession = bindDeploymentGraphSessionMaterialVerificationMemo(
      authenticateDeploymentOutputClosureProjectionGraphSession(graphSession),
      graphMaterialVerificationMemo
    );
    deploymentGraphSessionSourceMaterials.set(authenticatedGraphSession, capturedSourceMaterials);
    return authenticatedGraphSession;
  };
  return selectEntryCandidates(
    entryPaths,
    includeSourceGraphSnapshot ? undefined : { includeSourceGraphSnapshot: false }
  );
}

async function buildConvexWasmDeploymentGraphSessionImplementation({
  contextReuseAnalysis,
  effectExecutionMode = convexWasmDefaultEffectExecutionMode,
  entryCandidates,
  graphContextCache,
  gitSourceSnapshot,
  includeSourceGraphSnapshot = true,
  inventory,
  materialVerificationConcurrency,
  repoRoot,
  sourceGraphSnapshotCacheDirectory,
}) {
  const normalizedEffectExecutionMode = normalizeConvexWasmEffectExecutionMode(effectExecutionMode);
  requirePositiveInteger(materialVerificationConcurrency, "material verification concurrency");
  if (typeof includeSourceGraphSnapshot !== "boolean") {
    fail("source graph snapshot inclusion flag must be boolean");
  }
  const normalizedRoot = resolve(repoRoot);
  const contextReuseApplicationAdmissionPolicy =
    loadConvexContextReuseApplicationAdmissionPolicy(normalizedRoot);
  const normalizedGitSourceSnapshot =
    gitSourceSnapshot === undefined
      ? undefined
      : normalizeGitSourceSnapshotAuthority(gitSourceSnapshot);
  if (graphContextCache !== undefined && normalizedGitSourceSnapshot === undefined) {
    fail("deployment graph context reuse requires a Git source snapshot");
  }
  if (normalizedGitSourceSnapshot !== undefined) {
    if (normalizedGitSourceSnapshot.repoRoot !== normalizedRoot) {
      fail(
        "Git source snapshot repository root must be the same physical root as the deployment graph"
      );
    }
    // The caller captured this authority before graph construction. Verify it again here so a
    // staged-index/worktree mutation cannot turn snapshot metadata into an admission shortcut.
    await verifyConvexWasmGitSourceSnapshot(normalizedGitSourceSnapshot.snapshot, {
      repoRoot: normalizedGitSourceSnapshot.repoRoot,
    });
  }
  let graphMaterialVerificationMemo = new Map();
  const entryPaths = [
    ...new Set(entryCandidates ?? inventory.functions.map((func) => func.entryPath)),
  ].sort(compareStrings);
  if (entryPaths.length === 0) {
    fail("production inventory contains no query or mutation entry points");
  }
  const configPath = join(normalizedRoot, "convex.json");
  const [graphToolchain, configMaterial, dependencyAdapterDescriptor, registrationAdapter] =
    await settleParallelVerification([
      () => loadGraphToolchain(normalizedRoot),
      () => readStableFile(configPath, 1024 * 1024),
      () => loadConvexWasmDependencyAdapterMaterial(normalizedRoot),
      () => loadConvexWasmRegistrationAdapterMaterial(normalizedRoot),
    ]);
  const {
    bundlerDirectory,
    cliDirectory,
    esbuild,
    inputMaterialPaths: toolchainInputPaths,
    serverOnlyPlugin,
    toolchain,
    wasmPlugin,
  } = graphToolchain;
  graphMaterialVerificationMemo.set(configPath, {
    sha256: configMaterial.sha256,
    size: configMaterial.size,
    state: configMaterial.state,
  });
  const projectConfig = parsePinnedProjectConfig(
    decodeUtf8(configMaterial.contents, "convex.json")
  );
  const wasmCompilationPolicy = projectConfig.bundler.wasmCompilation;
  const functionsDirectory = resolve(normalizedRoot, projectConfig.functions);
  const functionsRelativePath = toPosix(relative(normalizedRoot, functionsDirectory));
  if (
    functionsRelativePath === ".." ||
    functionsRelativePath.startsWith("../") ||
    posix.isAbsolute(functionsRelativePath)
  ) {
    fail("Convex functions directory must stay within the application root");
  }
  const generatedSourcePrefix =
    functionsRelativePath === ""
      ? "_generated/"
      : `${functionsRelativePath}/_generated/`;
  const expectedFunctionsDirectory = resolve(
    normalizedRoot,
    inventory.authority?.sourceRoot ?? "convex"
  );
  if (functionsDirectory !== expectedFunctionsDirectory) {
    fail(
      `Convex project config resolves functions to ${functionsDirectory}, but the compiler inventory uses ${expectedFunctionsDirectory}`
    );
  }
  const [bundlerMaterials, entryPointsByRuntime, expectedDeploymentConfigurationEntryPath] =
    await settleParallelVerification([
      () => authenticateConvexBundlerMaterials({ bundlerDirectory, cliDirectory }),
      () => convexEntryPointsByEnvironment(functionsDirectory),
      () =>
        normalizedGitSourceSnapshot === undefined
          ? undefined
          : resolveAuthConfigEntryPath(functionsDirectory),
    ]);
  const isolateEntryPoints = entryPointsByRuntime.isolate
    .map((entryPoint) => resolve(entryPoint))
    .sort(compareStrings);
  const isolateEntryPaths = isolateEntryPoints.map((entryPoint) =>
    toPosix(relative(normalizedRoot, entryPoint))
  );
  const nodeEntryPoints = entryPointsByRuntime.node
    .map((entryPoint) => resolve(entryPoint))
    .sort(compareStrings);
  const nodeEntryPaths = nodeEntryPoints.map((entryPoint) =>
    toPosix(relative(normalizedRoot, entryPoint))
  );
  const contextReusePolicy = contextReusePolicyIdentity({
    databaseEntryPaths: inventory.functions.map(({ entryPath }) => entryPath),
    entryPoints: isolateEntryPoints,
    functionsDirectory,
    normalizedRoot,
    projectConfig,
  });
  const contextReuseEnabledEntries = contextReusePolicy.entries
    .filter(({ enabled }) => enabled)
    .map(({ entryPath }) => entryPath)
    .sort(compareStrings);
  const contextReuseApplicationAdmission =
    contextReuseAnalysis === undefined
      ? undefined
      : authenticateConvexContextReuseApplicationAdmission(contextReuseAnalysis, {
          applicationAdmissionPolicy: contextReuseApplicationAdmissionPolicy,
          expectedEntries: contextReuseEnabledEntries,
        });
  const contextReuseAnalysisIdentity = contextReuseApplicationAdmission?.identity;
  const contextReuseAnalysisSharedIdentity =
    contextReuseApplicationAdmission?.sharedAnalysisIdentity;
  const contextReuseAnalysisThirdPartyMaterialFingerprints =
    contextReuseApplicationAdmission?.thirdPartyMaterialFingerprints;
  const inventorySnapshot = inventory?.snapshot ?? inventory?.authority?.snapshot;
  if (contextReuseAnalysis !== undefined && inventorySnapshot === undefined) {
    fail("context-reuse analysis graph binding requires generated inventory input identity");
  }
  const contextReuseAnalysisGraphMaterial =
    inventorySnapshot === undefined
      ? undefined
      : contextReuseAnalysisGraphBasisMaterial({
          functionsDirectory,
          inventory,
          normalizedRoot,
          projectConfig,
        });
  const pendingContextReuseAnalysisBinding =
    contextReuseAnalysis === undefined &&
    normalizedEffectExecutionMode === convexWasmGuestPromiseEffectExecutionMode &&
    normalizedGitSourceSnapshot !== undefined &&
    contextReuseEnabledEntries.length > 0;
  const isolateEntrySet = new Set(isolateEntryPoints);
  for (const entryPath of entryPaths) {
    if (!isolateEntrySet.has(resolve(normalizedRoot, entryPath))) {
      fail(`compiler entry ${entryPath} is not an authoritative Convex isolate bundle entry`);
    }
  }
  const sourceGraphSnapshotLookupIdentityInput =
    normalizedGitSourceSnapshot === undefined
      ? undefined
      : {
          assumptions: convexWasmDeploymentGraphAssumptions,
          bundleEntryPaths: isolateEntryPaths,
          bundlerMaterials,
          config: { sha256: configMaterial.sha256, size: configMaterial.size },
          ...(contextReuseAnalysisIdentity === undefined
            ? {}
            : { contextReuseAnalysis: contextReuseAnalysisIdentity }),
          contextReusePolicy,
          dependencyAdapterDescriptor,
          deploymentConfigurationEntryPath:
            expectedDeploymentConfigurationEntryPath === null
              ? null
              : toPosix(relative(normalizedRoot, expectedDeploymentConfigurationEntryPath)),
          effectExecutionMode: normalizedEffectExecutionMode,
          kind: "convex-wasm-source-graph-snapshot-lookup-identity-v2",
          nodeEntryPaths,
          registrationAdapter,
          toolchain,
        };
  // A daemon may build the exact staged-Git graph while the analyzer is still running. That
  // private session is not persisted or exposed as a complete lookup identity until the binder
  // below attaches the authenticated result to this same object-level authority.
  const sourceGraphSnapshotLookupIdentity =
    sourceGraphSnapshotLookupIdentityInput === undefined || pendingContextReuseAnalysisBinding
      ? undefined
      : createConvexWasmSourceGraphSnapshotLookupIdentity(sourceGraphSnapshotLookupIdentityInput);
  // Keep the probes ordered. A valid exact hit must not depend on reading an unrelated complete-
  // inventory index, and it must not pay for that redundant cache I/O.
  const sourceGraphSnapshotCacheLookupStarted = performance.now();
  let admittedSourceGraphSnapshot =
    sourceGraphSnapshotLookupIdentity === undefined ||
    sourceGraphSnapshotCacheDirectory === undefined
      ? undefined
      : await loadConvexWasmSourceGraphSnapshotForLookup({
          cacheDirectory: sourceGraphSnapshotCacheDirectory,
          entryPaths,
          gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
          lookupIdentity: sourceGraphSnapshotLookupIdentity,
        });
  const completeInventoryEntryPaths = [
    ...new Set(inventory.functions.map(({ entryPath }) => entryPath)),
  ].sort(compareStrings);
  if (
    admittedSourceGraphSnapshot === undefined &&
    sourceGraphSnapshotLookupIdentity !== undefined &&
    sourceGraphSnapshotCacheDirectory !== undefined &&
    completeInventoryEntryPaths.length > entryPaths.length &&
    entryPaths.every((entryPath) => completeInventoryEntryPaths.includes(entryPath))
  ) {
    // Source-envelope staging persists the complete inventory graph. Compilation commonly asks
    // for its context-reuse-selected subset in a separate process; admit that exact immutable
    // superset and project it instead of rebuilding and publishing the same 47 MiB session again.
    admittedSourceGraphSnapshot = await loadConvexWasmSourceGraphSnapshotForLookup({
      cacheDirectory: sourceGraphSnapshotCacheDirectory,
      entryPaths: completeInventoryEntryPaths,
      gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
      lookupIdentity: sourceGraphSnapshotLookupIdentity,
    });
  }
  if (
    admittedSourceGraphSnapshot !== undefined &&
    (canonicalJson(admittedSourceGraphSnapshot.authority) !==
      canonicalJson(normalizedGitSourceSnapshot.snapshot) ||
      canonicalJson(admittedSourceGraphSnapshot.lookupIdentity) !==
        canonicalJson(sourceGraphSnapshotLookupIdentity))
  ) {
    fail("admitted source graph snapshot disagrees with its exact lookup authority");
  }
  const sourceGraphSnapshotCacheLookupUs = Math.round(
    (performance.now() - sourceGraphSnapshotCacheLookupStarted) * 1_000
  );
  if (admittedSourceGraphSnapshot !== undefined) {
    const cachedSession = await materializeCachedDeploymentGraphSession({
      admittedSnapshot: admittedSourceGraphSnapshot,
      bundlerDirectory,
      cliDirectory,
      contextReuseAnalysis,
      contextReuseApplicationAdmissionPolicy,
      contextReuseAnalysisGraphMaterial,
      contextReuseAnalysisSharedIdentity,
      contextReuseAnalysisThirdPartyMaterialFingerprints,
      entryPaths,
      functionsDirectory,
      generatedSourcePrefix,
      gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
      graphMaterialVerificationMemo,
      includeSourceGraphSnapshot,
      inventory,
      lookupUs: sourceGraphSnapshotCacheLookupUs,
      materialVerificationConcurrency,
      normalizedRoot,
      sourceGraphSnapshotCacheDirectory,
      toolchainInputPaths,
      wasmCompilationPolicy,
    });
    const sourceGraphSnapshotCachePath = convexWasmSourceGraphSnapshotCachePath(
      sourceGraphSnapshotCacheDirectory,
      admittedSourceGraphSnapshot.sha256
    );
    // Keep the authenticated producer session exact. A spread copy must not inherit the private
    // closure authority merely because all of its public references happen to be equal.
    cachedSession.sourceGraphSnapshotCachePath = sourceGraphSnapshotCachePath;
    return authenticateDeploymentOutputClosureProjectionGraphSession(cachedSession);
  }
  const retainedGraphContext =
    graphContextCache === undefined
      ? undefined
      : await graphContextCache.prepare({
          esbuild,
          key: fingerprintJson({
            kind: "convex-wasm-deployment-graph-context-v1",
            repoRoot: normalizedRoot,
            scopeSha256:
              sourceGraphSnapshotLookupIdentity === undefined
                ? deploymentGraphContextScopeSha256({
                    entryPaths,
                    gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
                    lookupIdentity: sourceGraphSnapshotLookupIdentityInput,
                  })
                : convexWasmDeploymentGraphContextScopeSha256({
                    entryPaths,
                    gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
                    lookupIdentity: sourceGraphSnapshotLookupIdentity,
                  }),
            toolchainRoot: normalizedRoot,
          }),
        });
  const previousDerivationState = retainedGraphContext?.previousDerivationState;
  const sourceMaterialBuildState =
    retainedGraphContext?.sourceMaterialBuildState ??
    (normalizedGitSourceSnapshot === undefined ? undefined : createSourceMaterialBuildState());
  if (retainedGraphContext !== undefined) {
    retainedGraphContext.beginBuild({
      gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
      repoRoot: normalizedRoot,
    });
    graphMaterialVerificationMemo = retainedGraphContext.graphMaterialVerificationMemo;
    graphMaterialVerificationMemo.set(configPath, {
      sha256: configMaterial.sha256,
      size: configMaterial.size,
      state: configMaterial.state,
    });
  } else if (sourceMaterialBuildState !== undefined) {
    setSourceMaterialGitSnapshot(sourceMaterialBuildState, {
      generatedSourcePrefix,
      gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
      repoRoot: normalizedRoot,
    });
  }
  const browserNodeShimsPlugin = pinnedAsyncHooksShimPlugin("browser");
  const nodeNodeShimsPlugin = pinnedAsyncHooksShimPlugin("node");
  const browserExternalPlugin = {
    name: "convex-node-externals",
    setup(build) {
      build.onResolve({ filter: /.*/, namespace: "file" }, () => null);
    },
  };
  const materialsByAbsolutePath = retainedGraphContext?.materialsByAbsolutePath ?? new Map();
  const started = performance.now();
  let result;
  let bundleModulesByPath;
  let deploymentOutputModulesByPath;
  let deploymentConfigurationEntryPath;
  let deploymentConfigurationInputMaterials;
  let deploymentConfigurationModulesByPath;
  let nodeInputMaterials;
  let nodeModulesByPath;
  {
    const isolateBuildOptions = {
      absWorkingDir: normalizedRoot,
      bundle: true,
      chunkNames: join("_deps", "[hash]"),
      conditions: ["convex", "module"],
      define: {
        "process.env.NODE_ENV": '"production"',
      },
      entryPoints: isolateEntryPoints,
      format: "esm",
      jsx: "automatic",
      keepNames: true,
      logLevel: "silent",
      metafile: true,
      minifyIdentifiers: true,
      minifySyntax: true,
      minifyWhitespace: false,
      outbase: functionsDirectory,
      outdir: "out",
      platform: "browser",
      plugins: [
        sourceMaterialPlugin(
          materialsByAbsolutePath,
          graphMaterialVerificationMemo,
          readStableFile,
          sourceMaterialBuildState
        ),
        browserNodeShimsPlugin,
        serverOnlyPlugin,
        browserExternalPlugin,
        wasmPlugin,
      ],
      sourcemap: true,
      sourcesContent: false,
      splitting: true,
      target: "esnext",
      treeShaking: true,
      write: false,
    };
    const isolateBuild = (async () => {
      const isolateResult =
        retainedGraphContext === undefined
          ? await esbuild.build(isolateBuildOptions)
          : await retainedGraphContext.rebuildIsolate(isolateBuildOptions);
      if (isolateResult.errors.length > 0) {
        fail(
          `installed Convex bundler returned ${isolateResult.errors.length} errors without rejecting the build`
        );
      }
      const isolateBundle = await bundledModulesFromResult({
        entryPoints: isolateEntryPoints,
        functionsDirectory,
        metafile: isolateResult.metafile,
        outputFiles: isolateResult.outputFiles,
        projectConfig,
        repoRoot: normalizedRoot,
      });
      return { isolateBundle, isolateResult };
    })();
    const buildResults = await Promise.allSettled([
      isolateBuild,
      bundleOfficialNodeModules({
        entryPoints: nodeEntryPoints,
        esbuild,
        externalPackagesAllowList: projectConfig.node.externalPackages,
        functionsDirectory,
        graphMaterialVerificationMemo,
        materialsByAbsolutePath,
        nodeShimsPlugin: nodeNodeShimsPlugin,
        normalizedRoot,
        previousInputMaterials: previousDerivationState?.nodeInputMaterials,
        serverOnlyPlugin,
        sourceMaterialBuildState,
        wasmPlugin,
      }),
      bundleOfficialDeploymentConfiguration({
        browserExternalPlugin,
        esbuild,
        functionsDirectory,
        graphMaterialVerificationMemo,
        materialsByAbsolutePath,
        nodeShimsPlugin: browserNodeShimsPlugin,
        normalizedRoot,
        previousInputMaterials: previousDerivationState?.deploymentConfigurationInputMaterials,
        serverOnlyPlugin,
        sourceMaterialBuildState,
        wasmPlugin,
      }),
    ]);
    // Wait for every shared source-material operation to settle. A rejected build must not leave
    // another request mutating the retained maps after return.
    const failedBuild = buildResults.find((build) => build.status === "rejected");
    if (failedBuild !== undefined) throw failedBuild.reason;
    const isolate = buildResults[0].value;
    const node = buildResults[1].value;
    const deploymentConfiguration = buildResults[2].value;
    result = isolate.isolateResult;
    bundleModulesByPath = isolate.isolateBundle.modulesByPath;
    deploymentOutputModulesByPath = isolate.isolateBundle.exactModulesByPath;
    nodeInputMaterials = node.inputMaterials;
    nodeModulesByPath = node.modulesByPath;
    deploymentConfigurationEntryPath = deploymentConfiguration.entryPath;
    deploymentConfigurationInputMaterials = deploymentConfiguration.inputMaterials;
    deploymentConfigurationModulesByPath = deploymentConfiguration.modulesByPath;
  }
  if (
    expectedDeploymentConfigurationEntryPath !== undefined &&
    deploymentConfigurationEntryPath !== expectedDeploymentConfigurationEntryPath
  ) {
    fail("Convex auth-config entry path changed while the graph was being bundled");
  }
  // Esbuild records one identical metafile import for each source import
  // declaration. The compiler resolves by module specifier, so remove only
  // byte-identical duplicates while preserving distinct resolutions.
  deduplicateMetafileImports(result.metafile);
  const selectedDependencyAdapters = await selectConvexWasmDependencyAdapters(
    normalizedRoot,
    result.metafile,
    dependencyAdapterDescriptor
  );
  // Adapter hydration reads installed package material while graphInputMaterials projects the
  // already captured esbuild source map. Neither mutates the other's inputs after selection.
  const [dependencyAdapter, materials] = await settleParallelVerification([
    () =>
      hydrateConvexWasmDependencyAdapterMaterial(
        normalizedRoot,
        dependencyAdapterDescriptor,
        selectedDependencyAdapters
      ),
    () =>
      graphInputMaterials(
        normalizedRoot,
        normalizedRoot,
        result.metafile,
        materialsByAbsolutePath,
        {
          previousMaterials: previousDerivationState?.inputMaterials,
          sourceMaterialBuildState,
        }
      ),
  ]);
  const esbuildGraphUs = Math.round((performance.now() - started) * 1_000);
  materials["convex.json"] = {
    imports: [],
    sha256: configMaterial.sha256,
    size: configMaterial.size,
    virtual: false,
  };
  materials[registrationAdapter.source.path] = {
    imports: [],
    sha256: registrationAdapter.source.sha256,
    size: registrationAdapter.source.bytes,
    virtual: false,
  };
  materials[dependencyAdapter.source.path] = {
    imports: [],
    sha256: dependencyAdapter.source.sha256,
    size: dependencyAdapter.source.bytes,
    virtual: false,
  };
  const activeDependencyAdapters = projectConvexWasmActiveDependencyAdapterIdentity(
    dependencyAdapter,
    selectedDependencyAdapters
  );
  const externalDependencies =
    contextReuseAnalysisGraphMaterial === undefined
      ? undefined
      : captureContextReuseExternalDependencyIdentities(normalizedRoot, result.metafile)
          .externalDependencies;
  const graphIdentityInputs = Object.fromEntries(
    Object.entries(materials).filter(([path]) => path !== dependencyAdapter.source.path)
  );
  const runtimeModulePathsForIsolateEntries = runtimeModulePathsByEntry(
    normalizedRoot,
    isolateEntryPaths,
    result.metafile
  );
  // This basis is scoped to one bundled metafile. It caches only immutable per-entry records;
  // each projection still creates its exact selected maps and graph identity.
  const deploymentOutputClosureProjection = createConvexWasmDeploymentOutputClosureProjection({
    bundleModulesByPath,
    metafile: result.metafile,
    repoRoot: normalizedRoot,
  });
  const dependencyGraphsByEntry = new Map();
  const dependencyInputSourcesByPath = new Map();
  let dependencyGraphIdentityPrefix;
  let dependencyGraphIdentitySuffix;
  const changedGitPaths = gitSourceSnapshotChangedPaths(
    previousDerivationState?.gitSourceSnapshot,
    normalizedGitSourceSnapshot?.snapshot
  );
  const changedInputPaths = changedSourceGraphInputPaths(
    previousDerivationState?.inputMaterials,
    materials,
    changedGitPaths
  );
  let reusedDependencyGraphCount = 0;
  let rebuiltDependencyGraphCount = 0;
  let reusedDependencyClosureCount = 0;
  let rebuiltDependencyClosureCount = 0;
  const authoritativeInputMaterials = {};
  for (const materialSet of [
    materials,
    nodeInputMaterials,
    deploymentConfigurationInputMaterials,
  ]) {
    for (const [path, material] of Object.entries(materialSet)) {
      const proof =
        material.virtual === true
          ? { virtual: true }
          : { sha256: material.sha256, size: material.size, virtual: false };
      const previous = authoritativeInputMaterials[path];
      if (previous !== undefined && canonicalJson(previous) !== canonicalJson(proof)) {
        fail(`authoritative Convex graph input ${path} has conflicting material identities`);
      }
      authoritativeInputMaterials[path] = proof;
    }
  }
  freezeAuthenticatedJsonTree(authoritativeInputMaterials);
  const sourceGraphSnapshotSession = {
    activeDependencyAdapters,
    authoritativeInputMaterials,
    bundleModulesByPath: Object.fromEntries(bundleModulesByPath),
    deploymentConfigurationInputMaterials,
    deploymentConfigurationModulesByPath: Object.fromEntries(deploymentConfigurationModulesByPath),
    deploymentOutputModulesByPath: Object.fromEntries(deploymentOutputModulesByPath),
    metafile: result.metafile,
    nodeInputMaterials,
    nodeModulesByPath: Object.fromEntries(nodeModulesByPath),
  };
  const verifyBundleInputMaterials = async () => {
    await settleParallelVerification([
      () =>
        verifyGraphInputMaterials(
          normalizedRoot,
          nodeInputMaterials,
          materialVerificationConcurrency,
          hashFile,
          graphMaterialVerificationMemo,
          capturedSourceMaterials
        ),
      () =>
        verifyGraphInputMaterials(
          normalizedRoot,
          deploymentConfigurationInputMaterials,
          materialVerificationConcurrency,
          hashFile,
          graphMaterialVerificationMemo,
          capturedSourceMaterials
        ),
    ]);
  };
  const verifyBundleEntryPaths = async () => {
    const [current, currentAuthConfigEntryPath] = await settleParallelVerification([
      () => convexEntryPointsByEnvironment(functionsDirectory),
      () => resolveAuthConfigEntryPath(functionsDirectory),
    ]);
    const currentIsolate = current.isolate
      .map((entryPoint) => resolve(entryPoint))
      .sort(compareStrings);
    if (canonicalJson(currentIsolate) !== canonicalJson(isolateEntryPoints)) {
      fail("Convex isolate bundle entry paths changed after the authoritative bundle session");
    }
    const currentNode = current.node.map((entryPoint) => resolve(entryPoint)).sort(compareStrings);
    if (canonicalJson(currentNode) !== canonicalJson(nodeEntryPoints)) {
      fail("Convex Node bundle entry paths changed after the authoritative bundle session");
    }
    if (currentAuthConfigEntryPath !== deploymentConfigurationEntryPath) {
      fail("Convex auth-config entry path changed after the authoritative bundle session");
    }
    await verifyBundleInputMaterials();
  };
  const verifyInputMaterials = async () => {
    const currentToolchain = await loadGraphToolchain(normalizedRoot);
    if (
      currentToolchain.bundlerDirectory !== bundlerDirectory ||
      currentToolchain.cliDirectory !== cliDirectory ||
      canonicalJson(currentToolchain.toolchain) !== canonicalJson(toolchain)
    ) {
      fail("Convex graph toolchain changed after the authoritative bundle session");
    }
    const [currentBundlerMaterials] = await settleParallelVerification([
      () => authenticateConvexBundlerMaterials(currentToolchain),
      () =>
        verifyGraphInputMaterials(
          normalizedRoot,
          materials,
          materialVerificationConcurrency,
          hashFile,
          graphMaterialVerificationMemo,
          capturedSourceMaterials
        ),
      () =>
        verifyContextReuseApplicationAdmission({
          analysis: contextReuseAnalysis,
          applicationAdmissionPolicy: contextReuseApplicationAdmissionPolicy,
          expectedEntries: contextReuseEnabledEntries,
          expectedIdentity: contextReuseAnalysisIdentity,
        }),
    ]);
    if (canonicalJson(currentBundlerMaterials) !== canonicalJson(bundlerMaterials)) {
      fail("Convex graph bundler materials changed after the authoritative bundle session");
    }
  };
  // Retained rebuilds replace entries in the shared map. Keep this build's consumed material
  // for every later projection, including generated inputs that cannot be reopened from Git.
  const capturedSourceMaterials = new Map(materialsByAbsolutePath);
  const selectEntryCandidates = (candidates, options) => {
    const includeSourceGraphSnapshot = includeSourceGraphSnapshotForSelection(options);
    const selectedEntryPaths = [...new Set(candidates)].sort(compareStrings);
    if (selectedEntryPaths.length === 0) {
      fail("selected graph session contains no entry points");
    }
    for (const entryPath of selectedEntryPaths) {
      if (!isolateEntrySet.has(resolve(normalizedRoot, entryPath))) {
        fail(`compiler entry ${entryPath} is not an authoritative Convex isolate bundle entry`);
      }
    }
    const runtimeModulePathByEntry = new Map(
      selectedEntryPaths.map((entryPath) => {
        const runtimeModulePath = runtimeModulePathsForIsolateEntries.get(entryPath);
        if (runtimeModulePath === undefined) {
          fail(`esbuild did not emit a runtime module for ${entryPath}`);
        }
        return [entryPath, runtimeModulePath];
      })
    );
    const deploymentOutput = deploymentOutputClosureProjection.select({
      entryPaths: selectedEntryPaths,
      runtimeModulePathByEntry,
    });
    const graphIdentity = {
      activeDependencyAdapters,
      assumptions: convexWasmDeploymentGraphAssumptions,
      bundleEntryPaths: isolateEntryPaths,
      bundlerMaterials,
      contextReusePolicy,
      ...(wasmCompilationPolicy === undefined ? {} : { wasmCompilationPolicy }),
      ...(contextReuseAnalysisIdentity === undefined
        ? {}
        : { contextReuseAnalysis: contextReuseAnalysisIdentity }),
      ...(normalizedEffectExecutionMode === convexWasmDefaultEffectExecutionMode
        ? {}
        : { effectExecutionMode: normalizedEffectExecutionMode }),
      entryPaths: selectedEntryPaths,
      inputs: graphIdentityInputs,
      kind: GRAPH_SESSION_KIND,
      deploymentOutputClosures: Object.fromEntries(
        [...deploymentOutput.closures].map(([entryPath, closure]) => [entryPath, closure.sha256])
      ),
      deploymentOutputMetafileSha256: deploymentOutput.metafileSha256,
      runtimeModulePaths: Object.fromEntries(runtimeModulePathByEntry),
      registrationAdapter,
      toolchain,
    };
    const dependencyGraphByEntry = new Map(
      selectedEntryPaths.map((entryPath) => {
        let dependencyGraph = dependencyGraphsByEntry.get(entryPath);
        if (dependencyGraph === undefined) {
          const retainedDependencyGraph =
            previousDerivationState?.dependencyGraphsByEntry.get(entryPath);
          if (
            changedInputPaths !== undefined &&
            retainedDependencyGraph !== undefined &&
            retainedDependencyGraph.inputPaths.every((path) => !changedInputPaths.has(path))
          ) {
            dependencyGraph = retainedDependencyGraph;
            reusedDependencyClosureCount += 1;
            reusedDependencyGraphCount += 1;
          } else {
            const inputPaths = dependencyClosure(entryPath, result.metafile);
            if (dependencyGraphIdentityPrefix === undefined) {
              dependencyGraphIdentityPrefix =
                `{"assumptions":${canonicalJson(graphIdentity.assumptions)},` +
                (normalizedEffectExecutionMode === convexWasmDefaultEffectExecutionMode
                  ? ""
                  : `"effectExecutionMode":${canonicalJson(normalizedEffectExecutionMode)},`);
              dependencyGraphIdentitySuffix =
                `},"kind":"convex-wasm-entry-dependency-graph-v1",` +
                `"toolchain":${canonicalJson(toolchain)}}`;
            }
            // Paths are sorted by dependencyClosure. Reuse graph-owned material encodings so
            // overlapping entries do not reconstruct and revalidate the same input trees.
            const inputSources = inputPaths.map((path) => {
              let source = dependencyInputSourcesByPath.get(path);
              if (source === undefined) {
                source = `${canonicalJson(path)}:${canonicalJson(materials[path])}`;
                dependencyInputSourcesByPath.set(path, source);
              }
              return source;
            });
            const identitySource =
              dependencyGraphIdentityPrefix +
              `"entryPath":${canonicalJson(entryPath)},"inputs":{` +
              inputSources.join(",") +
              dependencyGraphIdentitySuffix;
            dependencyGraph = freezeAuthenticatedJsonTree({
              inputPaths,
              sha256: createHash("sha256").update(identitySource).digest("hex"),
            });
            rebuiltDependencyClosureCount += 1;
            rebuiltDependencyGraphCount += 1;
          }
          dependencyGraphsByEntry.set(entryPath, dependencyGraph);
        }
        return [entryPath, dependencyGraph];
      })
    );
    const sourceGraphSnapshot =
      normalizedGitSourceSnapshot === undefined ||
      sourceGraphSnapshotLookupIdentity === undefined ||
      !includeSourceGraphSnapshot
        ? undefined
        : createConvexWasmSourceGraphSnapshot({
            gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
            graphSession: {
              ...(contextReuseAnalysisIdentity === undefined
                ? {}
                : { contextReuseAnalysisIdentity }),
              contextReusePolicy,
              dependencyGraphByEntry,
              graphTemplate: {
                assumptions: graphIdentity.assumptions,
                dependencyAdapter,
                registrationAdapter,
              },
              inputMaterials: materials,
              sourceGraphSnapshotLookupIdentity,
              sourceGraphSnapshotSession,
              toolchain,
            },
          });
    const contextReuseAnalysisInputGraphBasis = createContextReuseAnalysisInputGraphBasis({
      activeDependencyAdapters,
      assumptions: graphIdentity.assumptions,
      bundleEntryPaths: isolateEntryPaths,
      bundlerMaterials,
      contextReusePolicy,
      dependencyAdapter,
      inputMaterials: materials,
      metafileSha256: deploymentOutput.metafileSha256,
      registrationAdapter,
      toolchain,
      ...(contextReuseAnalysisGraphMaterial === undefined
        ? {}
        : {
            analysisGraphBasis: {
              ...contextReuseAnalysisGraphMaterial,
              externalDependencies,
            },
          }),
    });
    bindContextReuseAnalysisToGraph({
      analysis: contextReuseAnalysis,
      applicationAdmissionPolicy: contextReuseApplicationAdmissionPolicy,
      expectedEntries: contextReuseEnabledEntries,
      expectedIdentity: contextReuseAnalysisIdentity,
      graphBasis: contextReuseAnalysisInputGraphBasis,
    });
    const graphSession = {
      authoritativeInputMaterials,
      bundleModulesByPath,
      contextReuseAnalysisInputGraphBasis,
      deploymentConfigurationModulesByPath,
      dependencyGraphByEntry,
      graphSha256: fingerprintJson(graphIdentity),
      graphTemplate: {
        assumptions: graphIdentity.assumptions,
        functionsRoot: functionsRelativePath,
        ...(normalizedEffectExecutionMode === convexWasmDefaultEffectExecutionMode
          ? {}
          : { effectExecutionMode: normalizedEffectExecutionMode }),
        kind: GRAPH_KIND,
        metafile: result.metafile,
        phaseTimingsUs: {
          esbuildGraph: esbuildGraphUs,
          ...(normalizedGitSourceSnapshot === undefined ||
          sourceGraphSnapshotCacheDirectory === undefined
            ? {}
            : { sourceGraphSnapshotCacheLookup: sourceGraphSnapshotCacheLookupUs }),
        },
        dependencyAdapter,
        registrationAdapter,
        repoRoot: normalizedRoot,
        toolchain,
      },
      inputCount: Object.keys(result.metafile.inputs).length,
      inputMaterials: materials,
      contextReuseEnabledByEntry: new Map(
        contextReusePolicy.entries.map(({ enabled, entryPath }) => [entryPath, enabled])
      ),
      contextReusePolicy,
      ...(wasmCompilationPolicy === undefined ? {} : { wasmCompilationPolicy }),
      ...(contextReuseApplicationAdmissionPolicy === undefined
        ? {}
        : { contextReuseApplicationAdmissionPolicy }),
      ...(contextReuseAnalysisIdentity === undefined ? {} : { contextReuseAnalysisIdentity }),
      ...(contextReuseAnalysisSharedIdentity === undefined
        ? {}
        : { contextReuseAnalysisSharedIdentity }),
      ...(contextReuseAnalysisThirdPartyMaterialFingerprints === undefined
        ? {}
        : { contextReuseAnalysisThirdPartyMaterialFingerprints }),
      effectExecutionMode: normalizedEffectExecutionMode,
      ...(normalizedGitSourceSnapshot === undefined
        ? {}
        : {
            gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
            ...(sourceGraphSnapshot === undefined ? {} : { sourceGraphSnapshot }),
            verifyGitSourceSnapshot: async () =>
              verifyConvexWasmGitSourceSnapshot(normalizedGitSourceSnapshot.snapshot, {
                repoRoot: normalizedGitSourceSnapshot.repoRoot,
              }),
          }),
      nodeModulesByPath,
      deploymentOutputClosureByEntry: deploymentOutput.closures,
      deploymentOutputMetafileSha256: deploymentOutput.metafileSha256,
      deploymentOutputModulesByPath,
      phaseTimingsUs: {
        esbuildGraph: esbuildGraphUs,
        ...(normalizedGitSourceSnapshot === undefined ||
        sourceGraphSnapshotCacheDirectory === undefined
          ? {}
          : { sourceGraphSnapshotCacheLookup: sourceGraphSnapshotCacheLookupUs }),
      },
      runtimeModulePathByEntry,
      selectEntryCandidates,
      ...(sourceGraphSnapshotLookupIdentity === undefined ||
      sourceGraphSnapshotCacheDirectory === undefined
        ? {}
        : {
            sourceGraphSnapshotCache: {
              lookup:
                admittedSourceGraphSnapshot === undefined ? "miss" : "authenticated-metadata-hit",
              lookupUs: sourceGraphSnapshotCacheLookupUs,
              ...(admittedSourceGraphSnapshot === undefined
                ? {}
                : { snapshotSha256: admittedSourceGraphSnapshot.sha256 }),
            },
          }),
      ...(sourceGraphSnapshotLookupIdentity === undefined
        ? {}
        : { sourceGraphSnapshotLookupIdentity }),
      ...(retainedGraphContext === undefined
        ? {}
        : {
            sourceGraphContext: {
              changedGitPaths: changedGitPaths?.size ?? 0,
              changedInputPaths: changedInputPaths?.size ?? 0,
              dependencyGraphs: {
                rebuilt: rebuiltDependencyGraphCount,
                reused: reusedDependencyGraphCount,
              },
              dependencyClosures: {
                rebuilt: rebuiltDependencyClosureCount,
                reused: reusedDependencyClosureCount,
              },
              sourceMaterials: {
                read: retainedGraphContext.sourceMaterialBuildState.counters.read,
                rebuilt: retainedGraphContext.sourceMaterialBuildState.counters.rebuilt,
                reused: retainedGraphContext.sourceMaterialBuildState.counters.reused,
              },
              sourceEnvelope: retainedGraphContext.sourceEnvelopeDerivation.counters,
              reuse: retainedGraphContext.reused ? "retained-rebuild" : "seed",
            },
          }),
      ...(normalizedGitSourceSnapshot === undefined ? {} : { sourceGraphSnapshotSession }),
      ...(retainedGraphContext === undefined
        ? {}
        : { sourceEnvelopeDerivation: retainedGraphContext.sourceEnvelopeDerivation }),
      toolchain,
      toolchainInputPaths,
      verifyBundleInputMaterials,
      verifyBundleEntryPaths,
      verifyInputMaterials,
    };
    const authenticatedGraphSession = bindDeploymentGraphSessionMaterialVerificationMemo(
      authenticateDeploymentOutputClosureProjectionGraphSession(graphSession),
      graphMaterialVerificationMemo
    );
    deploymentGraphSessionSourceMaterials.set(authenticatedGraphSession, capturedSourceMaterials);
    if (pendingContextReuseAnalysisBinding) {
      pendingContextReuseAnalysisGraphSessionAuthorities.set(
        authenticatedGraphSession,
        Object.freeze({
          contextReuseApplicationAdmissionPolicy,
          contextReuseEnabledEntries: Object.freeze([...contextReuseEnabledEntries]),
          sourceGraphSnapshotLookupIdentityInput: freezeAuthenticatedJsonTree(
            structuredClone(sourceGraphSnapshotLookupIdentityInput)
          ),
        })
      );
    }
    return authenticatedGraphSession;
  };
  const session = selectEntryCandidates(
    entryPaths,
    includeSourceGraphSnapshot ? undefined : { includeSourceGraphSnapshot: false }
  );
  if (
    session.sourceGraphSnapshot !== undefined &&
    sourceGraphSnapshotCacheDirectory !== undefined
  ) {
    await settleParallelVerification([
      () => session.verifyInputMaterials(),
      () => session.verifyBundleInputMaterials(),
    ]);
    // The snapshot binds the consumed graph material. A later index/worktree edit belongs to
    // another build and does not invalidate publication of these captured bytes.
    const sourceGraphSnapshotCachePath = await publishConvexWasmSourceGraphSnapshot({
      cacheDirectory: sourceGraphSnapshotCacheDirectory,
      snapshot: session.sourceGraphSnapshot,
    });
    // Preserve the exact producer session rather than authenticating a shallow copy. External
    // graph-session copies intentionally take the complete validation path.
    session.sourceGraphSnapshotCachePath = sourceGraphSnapshotCachePath;
    authenticateDeploymentOutputClosureProjectionGraphSession(session);
  }
  retainedGraphContext?.commitDerivationState({
    dependencyGraphsByEntry: new Map(dependencyGraphsByEntry),
    deploymentConfigurationInputMaterials,
    gitSourceSnapshot: normalizedGitSourceSnapshot.snapshot,
    inputMaterials: materials,
    nodeInputMaterials,
    sourceMaterialGitIdentitiesByPath: Object.fromEntries(
      retainedGraphContext?.sourceMaterialBuildState.currentGitIdentitiesByPath ?? []
    ),
  });
  return session;
}

const deploymentGraphBuildQueues = new WeakMap();

export async function buildConvexWasmDeploymentGraphSession(options) {
  const graphContextCache = options?.graphContextCache;
  if (
    graphContextCache === undefined ||
    (typeof graphContextCache !== "object" && typeof graphContextCache !== "function") ||
    graphContextCache === null
  ) {
    return await buildConvexWasmDeploymentGraphSessionImplementation(options);
  }
  const previousBuild = deploymentGraphBuildQueues.get(graphContextCache) ?? Promise.resolve();
  let releaseBuild;
  const currentBuild = new Promise((resolveBuild) => {
    releaseBuild = resolveBuild;
  });
  deploymentGraphBuildQueues.set(graphContextCache, currentBuild);
  await previousBuild;
  try {
    // A retained context carries mutable esbuild/material state. Serialize only callers that share
    // that context; independent and non-retained graph builds remain concurrent.
    return await buildConvexWasmDeploymentGraphSessionImplementation(options);
  } finally {
    releaseBuild();
    if (deploymentGraphBuildQueues.get(graphContextCache) === currentBuild) {
      deploymentGraphBuildQueues.delete(graphContextCache);
    }
  }
}

async function mapBounded(values, concurrency, operation) {
  requirePositiveInteger(concurrency, "concurrency");
  const results = new Array(values.length);
  // Occupied input slots preserve deterministic precedence even when a rejection reason is nullish.
  const failures = new Array(values.length);
  let nextIndex = 0;
  let failed = false;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    for (;;) {
      if (failed) {
        return;
      }
      const index = nextIndex;
      nextIndex += 1;
      if (index >= values.length) {
        return;
      }
      try {
        results[index] = await operation(values[index], index);
      } catch (error) {
        failures[index] = { reason: error };
        failed = true;
        return;
      }
    }
  });
  await Promise.all(workers);
  if (failed) {
    throw failures.find((failure) => failure !== undefined).reason;
  }
  return results;
}

function decodeUtf8(contents, description) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(contents);
  } catch (error) {
    throw new Error(`Convex Wasm deployment: ${description} is not valid UTF-8`, {
      cause: error,
    });
  }
}

function deploymentResultRelativePath(value, description) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\\") ||
    value.includes("\0") ||
    isAbsolute(value) ||
    value === "." ||
    value === ".." ||
    value.startsWith("../") ||
    toPosix(resolve("/", value)).slice(1) !== value
  ) {
    fail(`${description} must be a normalized repository-relative path`);
  }
  return value;
}

function isDeeplyFrozenBuildInput(value, seen = new Set()) {
  if (value === null || typeof value !== "object") return true;
  if (seen.has(value)) return false;
  if (
    isProxy(value) ||
    !Object.isFrozen(value) ||
    (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype)
  ) {
    return false;
  }
  seen.add(value);
  const frozen = Reflect.ownKeys(value).every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return (
      typeof key === "string" &&
      descriptor !== undefined &&
      "value" in descriptor &&
      isDeeplyFrozenBuildInput(descriptor.value, seen)
    );
  });
  seen.delete(value);
  return frozen;
}

export function captureConvexWasmContextReuseAnalysisInputGraphBasis(graphSession) {
  if (exactDeploymentOutputClosureProjectionGraphSession(graphSession) === undefined) {
    fail("context-reuse analysis requires an exact authenticated deployment graph session");
  }
  const basis = graphSession.contextReuseAnalysisInputGraphBasis;
  if (!isDeeplyFrozenBuildInput(basis)) {
    fail("context-reuse analysis graph basis must be detached and immutable");
  }
  return basis;
}

export async function captureConvexWasmContextReuseSourceTexts(
  graphSession,
  { functionsRoot, sourceRoots }
) {
  const basis = captureConvexWasmContextReuseAnalysisInputGraphBasis(graphSession);
  if (
    !Array.isArray(sourceRoots) ||
    sourceRoots.length === 0 ||
    sourceRoots.some(
      (root) =>
        typeof root !== "string" ||
        !root.endsWith("/") ||
        root.split("/").includes("node_modules") ||
        deploymentResultRelativePath(root.slice(0, -1), "analyzer source root") !==
          root.slice(0, -1)
    ) ||
    new Set(sourceRoots).size !== sourceRoots.length ||
    canonicalJson([...sourceRoots].sort(compareStrings)) !== canonicalJson(sourceRoots)
  ) {
    fail("analyzer source roots must be sorted unique repository-relative directories");
  }
  if (!sourceRoots.includes(`${functionsRoot}/`)) {
    fail("the configured functions root must be included in analyzer source roots");
  }
  for (const { entryPath } of basis.databaseFunctions ?? []) {
    if (!entryPath.startsWith(`${functionsRoot}/`)) {
      fail("analyzer functions root disagrees with the graph inventory");
    }
  }
  const generatedSourcePrefix = `${functionsRoot}/_generated/`;
  const repoRoot = graphSession.graphTemplate.repoRoot;
  const retained = deploymentGraphSessionSourceMaterials.get(graphSession);
  const stagedEntries = sourceMaterialGitEntries(
    graphSession.gitSourceSnapshot,
    generatedSourcePrefix
  );
  const materials = new Map();
  const pendingBlobs = new Map();
  for (const [path, expected] of Object.entries(basis.inputMaterials)) {
    if (
      expected.virtual ||
      !sourceRoots.some((root) => path.startsWith(root)) ||
      !/\.(?:[cm]?[jt]s|[jt]sx)$/u.test(path) ||
      /\.d\.(?:[cm]?ts)$/u.test(path)
    )
      continue;
    const material = retained?.get(resolve(repoRoot, path));
    if (
      material !== undefined &&
      material.sha256 === expected.sha256 &&
      material.size === expected.size
    ) {
      materials.set(path, material);
      continue;
    }
    const staged = stagedEntries.get(path)?.identity;
    if (
      staged !== undefined &&
      DEPLOYMENT_RESULT_REGULAR_GIT_MODES.has(staged.mode) &&
      !path.startsWith(generatedSourcePrefix)
    ) {
      pendingBlobs.set(path, staged.blobOid);
    } else {
      materials.set(path, await readStableFile(resolve(repoRoot, path)));
    }
  }
  if (pendingBlobs.size !== 0) {
    const blobs = await readConvexWasmGitBlobMaterials(repoRoot, [
      ...new Set(pendingBlobs.values()),
    ]);
    for (const [path, oid] of pendingBlobs) materials.set(path, blobs.get(oid));
  }
  const texts = {};
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  for (const [path, material] of materials) {
    const expected = basis.inputMaterials[path];
    if (
      material === undefined ||
      material.sha256 !== expected.sha256 ||
      material.size !== expected.size
    ) {
      fail(`captured analyzer source does not match graph material: ${path}`);
    }
    // Native analysis consumes these exact graph bytes, not another read of the worktree.
    // Preserve a UTF-8 BOM because it participates in the existing module cache identity.
    texts[path] = decoder.decode(material.contents);
  }
  return Object.freeze(texts);
}

export function bindConvexWasmContextReuseAnalysisGraphSession({
  contextReuseAnalysis,
  graphSession,
  includeSourceGraphSnapshot = true,
} = {}) {
  if (typeof includeSourceGraphSnapshot !== "boolean") {
    fail("context-reuse graph binding snapshot inclusion flag must be a boolean");
  }
  if (graphSession?.contextReuseAnalysisIdentity !== undefined) {
    fail("context-reuse graph binding requires an unbound graph session");
  }
  const exactGraphAuthority = exactDeploymentOutputClosureProjectionGraphSession(graphSession);
  const bindingAuthority = pendingContextReuseAnalysisGraphSessionAuthorities.get(graphSession);
  if (exactGraphAuthority === undefined || bindingAuthority === undefined) {
    fail("context-reuse graph binding requires an exact pending deployment graph session");
  }
  if (
    graphSession.effectExecutionMode !== convexWasmGuestPromiseEffectExecutionMode ||
    graphSession.gitSourceSnapshot === undefined ||
    typeof graphSession.verifyGitSourceSnapshot !== "function"
  ) {
    fail("context-reuse graph binding requires guest-promise staged-Git authority");
  }
  const graphBasis = graphSession.contextReuseAnalysisInputGraphBasis;
  if (
    !isDeeplyFrozenBuildInput(graphBasis) ||
    canonicalJson(graphBasis.contextReusePolicy) !== canonicalJson(graphSession.contextReusePolicy)
  ) {
    fail("context-reuse graph binding basis disagrees with the pending graph session");
  }
  const databaseEntryPaths = new Set(
    graphBasis.databaseFunctions?.map(({ entryPath }) => entryPath) ?? []
  );
  const expectedEntries = graphSession.contextReusePolicy.entries
    .filter(({ enabled, entryPath }) => enabled && databaseEntryPaths.has(entryPath))
    .map(({ entryPath }) => entryPath)
    .sort(compareStrings);
  if (
    canonicalJson(expectedEntries) !== canonicalJson(bindingAuthority.contextReuseEnabledEntries)
  ) {
    fail("context-reuse graph binding entry authority disagrees with its graph basis");
  }
  const applicationAdmission = authenticateConvexContextReuseApplicationAdmission(
    contextReuseAnalysis,
    {
      applicationAdmissionPolicy: bindingAuthority.contextReuseApplicationAdmissionPolicy,
      expectedAnalysisInputGraphSha256:
        createConvexContextReuseAnalysisInputGraphSha256(graphBasis),
      expectedEntries,
    }
  );
  const graphMaterialVerificationMemo =
    deploymentGraphSessionMaterialVerificationMemos.get(graphSession);
  if (graphMaterialVerificationMemo === undefined) {
    fail("pending deployment graph session lost its material verification memo");
  }
  pendingContextReuseAnalysisGraphSessionAuthorities.delete(graphSession);

  const sourceGraphSnapshotLookupIdentity = createConvexWasmSourceGraphSnapshotLookupIdentity({
    ...bindingAuthority.sourceGraphSnapshotLookupIdentityInput,
    contextReuseAnalysis: applicationAdmission.identity,
  });
  const graphIdentity = {
    activeDependencyAdapters: graphBasis.activeDependencyAdapters,
    assumptions: graphBasis.assumptions,
    bundleEntryPaths: graphBasis.bundleEntryPaths,
    bundlerMaterials: graphBasis.bundlerMaterials,
    contextReuseAnalysis: applicationAdmission.identity,
    contextReusePolicy: graphSession.contextReusePolicy,
    ...(graphSession.wasmCompilationPolicy === undefined
      ? {}
      : { wasmCompilationPolicy: graphSession.wasmCompilationPolicy }),
    effectExecutionMode: graphSession.effectExecutionMode,
    entryPaths: [...graphSession.dependencyGraphByEntry.keys()],
    inputs: Object.fromEntries(
      Object.entries(graphSession.inputMaterials).filter(
        ([path]) => path !== graphSession.graphTemplate.dependencyAdapter.source.path
      )
    ),
    kind: GRAPH_SESSION_KIND,
    deploymentOutputClosures: Object.fromEntries(
      [...graphSession.deploymentOutputClosureByEntry].map(([entryPath, closure]) => [
        entryPath,
        closure.sha256,
      ])
    ),
    deploymentOutputMetafileSha256: graphSession.deploymentOutputMetafileSha256,
    runtimeModulePaths: Object.fromEntries(graphSession.runtimeModulePathByEntry),
    registrationAdapter: graphBasis.registrationAdapter,
    toolchain: graphSession.toolchain,
  };
  const verifyPendingInputMaterials = graphSession.verifyInputMaterials.bind(graphSession);
  const selectPendingEntryCandidates = graphSession.selectEntryCandidates.bind(graphSession);
  const verifyInputMaterials = async () => {
    await verifyPendingInputMaterials();
    verifyContextReuseApplicationAdmission({
      analysis: contextReuseAnalysis,
      applicationAdmissionPolicy: bindingAuthority.contextReuseApplicationAdmissionPolicy,
      expectedEntries,
      expectedIdentity: applicationAdmission.identity,
    });
  };
  const bindSelection = (candidates, options) => {
    const selectedIncludeSourceGraphSnapshot = includeSourceGraphSnapshotForSelection(options);
    return bindConvexWasmContextReuseAnalysisGraphSession({
      contextReuseAnalysis,
      graphSession: selectPendingEntryCandidates(candidates, {
        includeSourceGraphSnapshot: false,
      }),
      includeSourceGraphSnapshot: selectedIncludeSourceGraphSnapshot,
    });
  };
  const {
    sourceGraphSnapshot: ignoredSourceGraphSnapshot,
    sourceGraphSnapshotCache: ignoredSourceGraphSnapshotCache,
    sourceGraphSnapshotCachePath: ignoredSourceGraphSnapshotCachePath,
    sourceGraphSnapshotLookupIdentity: ignoredSourceGraphSnapshotLookupIdentity,
    ...unboundGraphSession
  } = graphSession;
  const boundGraphSessionWithoutSnapshot = {
    ...unboundGraphSession,
    contextReuseAnalysisIdentity: applicationAdmission.identity,
    contextReuseAnalysisSharedIdentity: applicationAdmission.sharedAnalysisIdentity,
    contextReuseAnalysisThirdPartyMaterialFingerprints:
      applicationAdmission.thirdPartyMaterialFingerprints,
    graphSha256: fingerprintJson(graphIdentity),
    selectEntryCandidates: bindSelection,
    sourceGraphSnapshotLookupIdentity,
    verifyInputMaterials,
  };
  const sourceGraphSnapshot = includeSourceGraphSnapshot
    ? createConvexWasmSourceGraphSnapshot({
        gitSourceSnapshot: graphSession.gitSourceSnapshot,
        graphSession: boundGraphSessionWithoutSnapshot,
      })
    : undefined;
  const boundGraphSession = bindDeploymentGraphSessionMaterialVerificationMemo(
    authenticateDeploymentOutputClosureProjectionGraphSession({
      ...boundGraphSessionWithoutSnapshot,
      ...(sourceGraphSnapshot === undefined ? {} : { sourceGraphSnapshot }),
    }),
    graphMaterialVerificationMemo
  );
  const capturedSourceMaterials = deploymentGraphSessionSourceMaterials.get(graphSession);
  if (capturedSourceMaterials !== undefined) {
    deploymentGraphSessionSourceMaterials.set(boundGraphSession, capturedSourceMaterials);
  }
  return boundGraphSession;
}
