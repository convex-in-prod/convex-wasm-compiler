import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { relative, resolve, sep } from "node:path";

import { validateConvexWasmGitSourceSnapshot } from "./convex-wasm-git-source-snapshot.mjs";

const sha256Pattern = /^[a-f0-9]{64}$/u;
const supportedGitModes = new Set(["100644", "100755"]);

export function convexApiFunctionsRoot(projectConfig) {
  if (typeof projectConfig !== "object" || projectConfig === null || Array.isArray(projectConfig)) {
    throw new Error("convex.json must contain an object");
  }
  const configured = projectConfig.functions ?? "convex/";
  if (
    typeof configured !== "string" ||
    configured.length === 0 ||
    configured.startsWith("/") ||
    configured.includes("\\")
  ) {
    throw new Error("convex.json functions must be a repository-relative directory");
  }
  const root = configured.endsWith("/") ? configured.slice(0, -1) : configured;
  if (
    root.length === 0 ||
    root.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw new Error("convex.json functions must be a normalized repository-relative directory");
  }
  return root;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function toPosixPath(path) {
  return path.split(sep).join("/");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireExactKeys(value, expectedKeys, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${description} is not an object.`);
  }
  const keys = Object.keys(value).sort(compareStrings);
  if (JSON.stringify(keys) !== JSON.stringify([...expectedKeys].sort(compareStrings))) {
    throw new Error(`${description} has invalid fields.`);
  }
}

function sourceFileForProjection(ts, sourcePath, source) {
  const sourceFile = ts.createSourceFile(
    sourcePath,
    source,
    ts.ScriptTarget.Latest,
    true,
    sourcePath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  );
  return sourceFile.parseDiagnostics.length === 0 ? sourceFile : undefined;
}

function hasExplicitReturnTypeAndBody(ts, node) {
  return ts.isFunctionLike(node) && node.type !== undefined && node.body !== undefined;
}

function containsModuleResolutionSyntax(ts, node) {
  let found = false;
  function visit(current) {
    if (found) {
      return;
    }
    if (
      ts.isImportTypeNode(current) ||
      ts.isJsxElement(current) ||
      ts.isJsxSelfClosingElement(current) ||
      ts.isJsxFragment(current) ||
      (ts.isCallExpression(current) &&
        (current.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(current.expression) && current.expression.text === "require") ||
          (ts.isPropertyAccessExpression(current.expression) &&
            ts.isIdentifier(current.expression.expression) &&
            ((current.expression.expression.text === "require" &&
              current.expression.name.text === "resolve") ||
              (current.expression.expression.text === "module" &&
                current.expression.name.text === "require")))))
    ) {
      found = true;
      return;
    }
    current.forEachChild(visit);
  }
  visit(node);
  return found;
}

export function convexApiSourceSurfaceProjection({ source, sourceFileCache, sourcePath, ts }) {
  const sourceFile = sourceFileForProjection(ts, sourcePath, source);
  if (sourceFile === undefined) {
    return undefined;
  }
  if (sourceFileCache !== undefined) {
    if (!(sourceFileCache instanceof Map)) {
      throw new Error("Convex API source projection cache is invalid.");
    }
    sourceFileCache.set(sourcePath, sourceFile);
  }

  const bodyRanges = [];
  function visit(node) {
    // TypeScript still resolves modules referenced inside an explicitly typed body, including the
    // implicit JSX runtime. Those modules can contribute global declarations that change another
    // exported function's inferred API, so keep such bodies exact.
    if (hasExplicitReturnTypeAndBody(ts, node) && !containsModuleResolutionSyntax(ts, node.body)) {
      bodyRanges.push({ end: node.body.end, start: node.body.pos });
      return;
    }
    node.forEachChild(visit);
  }
  visit(sourceFile);

  let projected = "";
  let offset = 0;
  for (const range of bodyRanges) {
    projected += source.slice(offset, range.start);
    projected += "\0convex-api-explicit-return-body-v1\0";
    offset = range.end;
  }
  return projected + source.slice(offset);
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function serializedFileState(status) {
  return {
    ctimeNs: String(status.ctimeNs),
    dev: String(status.dev),
    gid: String(status.gid),
    ino: String(status.ino),
    mode: String(status.mode),
    mtimeNs: String(status.mtimeNs),
    nlink: String(status.nlink),
    size: String(status.size),
    uid: String(status.uid),
  };
}

function captureStableFile(path, description, readContents) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    throw new Error(`${description} requires O_NOFOLLOW.`);
  }
  const beforePath = lstatSync(path, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()) {
    throw new Error(`${description} is not a regular file: ${path}`);
  }
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameFileState(beforePath, opened)) {
      throw new Error(`${description} changed while it was opened: ${path}`);
    }
    const contents = readContents ? readFileSync(descriptor) : undefined;
    const after = fstatSync(descriptor, { bigint: true });
    const afterPath = lstatSync(path, { bigint: true });
    if (
      !sameFileState(opened, after) ||
      !afterPath.isFile() ||
      afterPath.isSymbolicLink() ||
      !sameFileState(opened, afterPath) ||
      (contents !== undefined && BigInt(contents.length) !== after.size)
    ) {
      throw new Error(`${description} changed while it was read: ${path}`);
    }
    return { contents, state: serializedFileState(after) };
  } finally {
    closeSync(descriptor);
  }
}

export function convexApiReadStableFile(path, description) {
  const { contents } = captureStableFile(path, description, true);
  if (contents === undefined) {
    throw new Error(`${description} stable read did not return contents.`);
  }
  return contents;
}

function packageResolutionMaterial(source) {
  JSON.parse(source.toString("utf8"));
  const physicalSha256 = sha256(source);
  return {
    path: "package.json",
    physicalSha256,
    physicalSize: source.length,
    // Root package fields beyond exports/imports can participate in TypeScript and Node package
    // resolution. Keep the early semantic surface conservative instead of maintaining a partial
    // field allowlist that can silently miss a new resolver input.
    resolutionSha256: physicalSha256,
  };
}

function repositoryInputSha256(inputs, packageResolution) {
  const hash = createHash("sha256");
  hash.update("convex-api-repository-input-v3\0");
  for (const input of inputs) {
    hash.update(input.path);
    hash.update("\0");
    hash.update(input.physicalSha256);
    hash.update("\0");
    hash.update(String(input.physicalSize));
    hash.update("\0");
  }
  hash.update("package-resolution-material\0");
  hash.update(packageResolution.physicalSha256);
  hash.update("\0");
  hash.update(String(packageResolution.physicalSize));
  hash.update("\0");
  hash.update(packageResolution.resolutionSha256);
  hash.update("\0");
  return hash.digest("hex");
}

function bumpCounter(counters, key) {
  if (counters !== undefined) {
    if (typeof counters !== "object" || counters === null || Array.isArray(counters)) {
      throw new Error("Convex API repository input material counters must be an object.");
    }
    counters[key] = (counters[key] ?? 0) + 1;
  }
}

function materialPath(root, inputPath, requireInsideRoot) {
  const resolvedPath = resolve(inputPath);
  const path = toPosixPath(relative(root, resolvedPath));
  if (
    path.length === 0 ||
    path.includes("\\") ||
    path === "." ||
    (requireInsideRoot &&
      path.split("/").some((part) => part.length === 0 || part === "." || part === ".."))
  ) {
    throw new Error(`Invalid Convex API repository input path: ${path}`);
  }
  if (requireInsideRoot && (path === ".." || path.startsWith("../"))) {
    throw new Error(`Invalid Convex API repository input path: ${path}`);
  }
  return { path, resolvedPath };
}

function snapshotEntriesByPath(snapshot) {
  if (snapshot === undefined) return undefined;
  validateConvexWasmGitSourceSnapshot(snapshot, "Convex API staged surface Git snapshot");
  if (snapshot.unstagedPaths.length > 0 || snapshot.untrackedPaths.length > 0) {
    throw new Error("Convex API staged surface Git snapshot has dirty worktree inputs.");
  }
  const entries = new Map();
  for (const entry of snapshot.entries) {
    if (entry.stage !== 0 || entries.has(entry.path)) {
      throw new Error("Convex API staged surface Git snapshot has unsupported index stages.");
    }
    entries.set(entry.path, { ...entry });
  }
  return entries;
}

function requiredGitEntry(entries, path) {
  const entry = entries.get(path);
  if (entry === undefined) {
    throw new Error(`Convex API staged surface Git snapshot does not cover ${path}.`);
  }
  if (!supportedGitModes.has(entry.mode)) {
    throw new Error(`Convex API staged surface Git snapshot has unsupported mode: ${path}`);
  }
  return entry;
}

function retainedManifestMaterial(previousManifest) {
  if (previousManifest === undefined) return undefined;
  if (typeof previousManifest !== "object" || previousManifest === null) {
    throw new Error("Convex API staged surface manifest material is invalid.");
  }
  // The caller normally validates the manifest against its scope before this function runs.
  // Revalidate its self-contained material here so a direct helper caller cannot use partial data.
  validateConvexApiStagedSurfaceManifest(previousManifest, previousManifest.scopeIdentity);
  return previousManifest;
}

export function convexApiRepositoryInputMaterial({
  counters,
  gitSourceSnapshot,
  inputPaths,
  previousManifest,
  retainContents = false,
  repositoryRoot,
}) {
  const root = resolve(repositoryRoot);
  const entries = snapshotEntriesByPath(gitSourceSnapshot);
  const retained = retainedManifestMaterial(previousManifest);
  const previousInputs =
    retained === undefined
      ? undefined
      : new Map(retained.inputs.map((input) => [input.path, input]));
  const normalizedInputPaths = [];
  const seen = new Set();
  for (const inputPath of inputPaths) {
    const { path, resolvedPath } = materialPath(root, inputPath, entries !== undefined);
    if (path.length === 0 || seen.has(path)) {
      throw new Error(`Invalid or duplicate Convex API repository input path: ${path}`);
    }
    seen.add(path);
    normalizedInputPaths.push({ path, resolvedPath });
  }
  const layoutMatches =
    previousInputs !== undefined &&
    previousInputs.size === normalizedInputPaths.length &&
    normalizedInputPaths.every(({ path }) => previousInputs.has(path));
  const allowRetainedReuse = entries !== undefined && layoutMatches;
  const inputsByPath = new Map();
  const sourceContentsByPath = retainContents ? new Map() : undefined;
  for (const { path, resolvedPath } of normalizedInputPaths) {
    const currentEntry = entries === undefined ? undefined : requiredGitEntry(entries, path);
    const previousInput = previousInputs?.get(path);
    const retainedGitEntry = previousInput?.gitEntry;
    if (
      previousInput !== undefined &&
      currentEntry !== undefined &&
      allowRetainedReuse &&
      sameGitEntry(currentEntry, retainedGitEntry)
    ) {
      // A staged blob identity is an early reuse key, not physical worktree authority. Reuse
      // bytes only while a fresh no-follow descriptor window still matches the retained read.
      const currentState = captureStableFile(
        resolvedPath,
        "Convex API repository input",
        false
      ).state;
      if (sameValue(currentState, previousInput.physicalState)) {
        inputsByPath.set(path, {
          path,
          physicalSha256: previousInput.physicalSha256,
          physicalSize: previousInput.physicalSize,
          physicalState: currentState,
        });
        bumpCounter(counters, "reused");
        continue;
      }
    }
    const { contents, state } = captureStableFile(
      resolvedPath,
      "Convex API repository input",
      true
    );
    if (contents === undefined) {
      throw new Error("Convex API repository input stable read did not return contents.");
    }
    if (sourceContentsByPath !== undefined && /\.(?:ts|tsx|mts|cts)$/u.test(path)) {
      sourceContentsByPath.set(path, contents);
    }
    inputsByPath.set(path, {
      path,
      physicalSha256: sha256(contents),
      physicalSize: contents.length,
      physicalState: state,
    });
    bumpCounter(counters, "read");
    bumpCounter(counters, "rebuilt");
  }

  const packagePath = "package.json";
  const packageEntry = entries === undefined ? undefined : requiredGitEntry(entries, packagePath);
  const previousPackage = retained?.packageResolution;
  let packageResolution;
  if (
    previousPackage !== undefined &&
    packageEntry !== undefined &&
    allowRetainedReuse &&
    sameGitEntry(packageEntry, previousPackage.gitEntry)
  ) {
    const currentState = captureStableFile(
      resolve(root, packagePath),
      "Convex API package resolution input",
      false
    ).state;
    if (sameValue(currentState, previousPackage.physicalState)) {
      bumpCounter(counters, "reused");
      packageResolution = {
        path: packagePath,
        physicalSha256: previousPackage.physicalSha256,
        physicalSize: previousPackage.physicalSize,
        physicalState: currentState,
        resolutionSha256: previousPackage.resolutionSha256,
      };
    }
  }
  if (packageResolution === undefined) {
    const { contents: source, state } = captureStableFile(
      resolve(root, packagePath),
      "Convex API package resolution input",
      true
    );
    if (source === undefined) {
      throw new Error("Convex API package resolution stable read did not return contents.");
    }
    bumpCounter(counters, "read");
    bumpCounter(counters, "rebuilt");
    packageResolution = { ...packageResolutionMaterial(source), physicalState: state };
  }
  const inputs = [...inputsByPath.values()].sort((left, right) =>
    compareStrings(left.path, right.path)
  );
  return {
    inputSha256: repositoryInputSha256(inputs, packageResolution),
    inputs,
    packageResolution: {
      path: packagePath,
      physicalSha256: packageResolution.physicalSha256,
      physicalSize: packageResolution.physicalSize,
      physicalState: packageResolution.physicalState,
      resolutionSha256: packageResolution.resolutionSha256,
    },
    ...(sourceContentsByPath === undefined ? {} : { sourceContentsByPath }),
  };
}

function surfaceSha256(inputs, packageResolutionSha256) {
  const hash = createHash("sha256");
  hash.update("convex-api-repository-surface-v3\0");
  for (const input of inputs) {
    hash.update(input.path);
    hash.update("\0");
    hash.update(input.projected ? "projected\0" : "exact\0");
    hash.update(input.surfaceSha256);
    hash.update("\0");
  }
  hash.update("package-resolution-config\0");
  hash.update(packageResolutionSha256);
  hash.update("\0");
  return hash.digest("hex");
}

function repositorySurfaceMaterial({
  counters,
  inputMaterial,
  repositoryRoot,
  sourceFileCache,
  sourcePaths,
  ts,
}) {
  if (ts === undefined) {
    throw new Error("TypeScript is required to compute the Convex API repository surface.");
  }
  const root = resolve(repositoryRoot);
  const projectedPaths = new Set(
    sourcePaths.map((path) => toPosixPath(relative(root, resolve(path))))
  );
  const inputs = [];
  const sourceContentsByPath = inputMaterial.sourceContentsByPath;
  if (sourceContentsByPath !== undefined && !(sourceContentsByPath instanceof Map)) {
    throw new Error("Convex API repository input material contents are invalid.");
  }
  for (const input of inputMaterial.inputs) {
    const projected = projectedPaths.has(input.path);
    let surfaceDigest = input.physicalSha256;
    if (projected) {
      const sourcePath = resolve(root, input.path);
      const cachedSource = sourceContentsByPath?.get(input.path);
      const source =
        cachedSource ??
        convexApiReadStableFile(sourcePath, "Convex API projected repository input");
      if (cachedSource !== undefined && !Buffer.isBuffer(cachedSource)) {
        throw new Error("Convex API repository input material contains invalid source contents.");
      }
      bumpCounter(counters, cachedSource === undefined ? "read" : "cached");
      if (source.length !== input.physicalSize || sha256(source) !== input.physicalSha256) {
        throw new Error(
          `Convex API projected repository input changed before projection: ${sourcePath}`
        );
      }
      const projection = convexApiSourceSurfaceProjection({
        source: source.toString("utf8"),
        sourcePath,
        sourceFileCache,
        ts,
      });
      if (projection === undefined) {
        return undefined;
      }
      surfaceDigest = sha256(projection);
    }
    inputs.push({
      path: input.path,
      physicalSha256: input.physicalSha256,
      physicalSize: input.physicalSize,
      physicalState: input.physicalState,
      projected,
      surfaceSha256: surfaceDigest,
    });
  }
  inputs.sort((left, right) => compareStrings(left.path, right.path));
  return {
    inputs,
    repositorySurfaceSha256: surfaceSha256(
      inputs,
      inputMaterial.packageResolution.resolutionSha256
    ),
  };
}

export function convexApiRepositorySurfaceSha256({
  counters,
  inputMaterial,
  inputPaths,
  repositoryRoot,
  sourceFileCache,
  sourcePaths,
  ts,
}) {
  const material = repositorySurfaceMaterial({
    counters,
    inputMaterial:
      inputMaterial ?? convexApiRepositoryInputMaterial({ inputPaths, repositoryRoot }),
    repositoryRoot,
    sourceFileCache,
    sourcePaths,
    ts,
  });
  return material?.repositorySurfaceSha256;
}

export function convexApiStagedSurfaceScopeIdentity({
  arch = process.arch,
  configPath,
  installedLayoutSha256,
  nodeVersion = process.version,
  platform = process.platform,
}) {
  if (
    (configPath !== null && typeof configPath !== "string") ||
    typeof arch !== "string" ||
    arch.length === 0 ||
    typeof nodeVersion !== "string" ||
    nodeVersion.length === 0 ||
    typeof platform !== "string" ||
    platform.length === 0 ||
    !sha256Pattern.test(installedLayoutSha256)
  ) {
    throw new Error("Invalid Convex API staged surface scope identity.");
  }
  if (configPath !== null) {
    requireRelativePath(configPath, "Convex API staged surface scope identity");
  }
  return {
    arch,
    configPath,
    installedLayoutSha256,
    kind: "convex-api-staged-surface-scope-v3",
    nodeVersion,
    platform,
  };
}

export function convexApiStagedSurfaceScopeKey(identity) {
  return sha256(JSON.stringify(identity));
}

function sameValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameGitEntry(left, right) {
  return (
    left?.path === right?.path &&
    left?.mode === right?.mode &&
    left?.oid === right?.oid &&
    left?.stage === right?.stage
  );
}

function requireRelativePath(path, description) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.startsWith("/") ||
    path.includes("\\") ||
    path === ".." ||
    path.startsWith("../") ||
    path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw new Error(`${description} has an invalid path.`);
  }
}

function validateManifestGitEntry(value, expectedPath, description) {
  requireExactKeys(value, ["mode", "oid", "path", "stage"], description);
  requireRelativePath(value.path, description);
  if (
    value.path !== expectedPath ||
    typeof value.mode !== "string" ||
    !supportedGitModes.has(value.mode) ||
    typeof value.oid !== "string" ||
    !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(value.oid) ||
    value.stage !== 0
  ) {
    throw new Error(`${description} is invalid.`);
  }
}

function validateManifestInput(value, description) {
  requireExactKeys(
    value,
    [
      "gitEntry",
      "path",
      "physicalSha256",
      "physicalSize",
      "physicalState",
      "projected",
      "surfaceSha256",
    ],
    description
  );
  requireRelativePath(value.path, description);
  validateManifestGitEntry(value.gitEntry, value.path, `${description} Git entry`);
  if (
    !sha256Pattern.test(value.physicalSha256) ||
    !Number.isSafeInteger(value.physicalSize) ||
    value.physicalSize < 0 ||
    validateManifestFileState(value.physicalState, value.physicalSize, description) !== true ||
    typeof value.projected !== "boolean" ||
    !sha256Pattern.test(value.surfaceSha256)
  ) {
    throw new Error(`${description} is invalid.`);
  }
}

function validateManifestFileState(value, expectedSize, description) {
  requireExactKeys(
    value,
    ["ctimeNs", "dev", "gid", "ino", "mode", "mtimeNs", "nlink", "size", "uid"],
    `${description} physical state`
  );
  if (
    Object.values(value).some((field) => typeof field !== "string" || !/^-?[0-9]+$/u.test(field)) ||
    value.size !== String(expectedSize)
  ) {
    throw new Error(`${description} physical state is invalid.`);
  }
  return true;
}

export function validateConvexApiStagedSurfaceManifest(value, expectedScopeIdentity) {
  requireExactKeys(
    value,
    ["inputs", "kind", "packageResolution", "repositorySurfaceSha256", "scopeIdentity", "treeOid"],
    "Convex API staged surface manifest"
  );
  if (
    value.kind !== "convex-api-staged-surface-manifest-v3" ||
    !sameValue(value.scopeIdentity, expectedScopeIdentity) ||
    !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(value.treeOid) ||
    !sha256Pattern.test(value.repositorySurfaceSha256) ||
    !Array.isArray(value.inputs) ||
    value.inputs.length > 100_000
  ) {
    throw new Error("Convex API staged surface manifest is corrupt.");
  }
  let previousPath;
  for (const [index, input] of value.inputs.entries()) {
    validateManifestInput(input, `Convex API staged surface manifest input ${index}`);
    if (previousPath !== undefined && compareStrings(previousPath, input.path) >= 0) {
      throw new Error("Convex API staged surface manifest inputs are not sorted and unique.");
    }
    previousPath = input.path;
  }
  requireExactKeys(
    value.packageResolution,
    ["gitEntry", "path", "physicalSha256", "physicalSize", "physicalState", "resolutionSha256"],
    "Convex API staged surface manifest package resolution"
  );
  requireRelativePath(
    value.packageResolution.path,
    "Convex API staged surface manifest package resolution"
  );
  validateManifestGitEntry(
    value.packageResolution.gitEntry,
    value.packageResolution.path,
    "Convex API staged surface manifest package resolution Git entry"
  );
  if (
    value.packageResolution.path !== "package.json" ||
    !sha256Pattern.test(value.packageResolution.physicalSha256) ||
    !Number.isSafeInteger(value.packageResolution.physicalSize) ||
    value.packageResolution.physicalSize < 0 ||
    validateManifestFileState(
      value.packageResolution.physicalState,
      value.packageResolution.physicalSize,
      "Convex API staged surface manifest package resolution"
    ) !== true ||
    !sha256Pattern.test(value.packageResolution.resolutionSha256)
  ) {
    throw new Error("Convex API staged surface manifest package resolution is invalid.");
  }
  if (
    surfaceSha256(value.inputs, value.packageResolution.resolutionSha256) !==
    value.repositorySurfaceSha256
  ) {
    throw new Error("Convex API staged surface manifest aggregate is corrupt.");
  }
  return value;
}

function projectedPathSet(repositoryRoot, sourcePaths) {
  const root = resolve(repositoryRoot);
  return new Set(sourcePaths.map((path) => toPosixPath(relative(root, resolve(path)))));
}

export function createConvexApiStagedSurfaceManifest({
  gitSourceSnapshot,
  inputMaterial,
  repositoryRoot,
  sourceFileCache,
  scopeIdentity,
  sourcePaths,
  ts,
}) {
  const surface = repositorySurfaceMaterial({
    inputMaterial,
    repositoryRoot,
    sourceFileCache,
    sourcePaths,
    ts,
  });
  if (surface === undefined) {
    return undefined;
  }
  const entries = snapshotEntriesByPath(gitSourceSnapshot);
  const manifest = {
    inputs: surface.inputs
      .map((input) => ({
        gitEntry: requiredGitEntry(entries, input.path),
        ...input,
      }))
      .sort((left, right) => compareStrings(left.path, right.path)),
    kind: "convex-api-staged-surface-manifest-v3",
    packageResolution: {
      gitEntry: requiredGitEntry(entries, inputMaterial.packageResolution.path),
      ...inputMaterial.packageResolution,
    },
    repositorySurfaceSha256: surface.repositorySurfaceSha256,
    scopeIdentity,
    treeOid: gitSourceSnapshot.treeOid,
  };
  return validateConvexApiStagedSurfaceManifest(manifest, scopeIdentity);
}

export function reuseConvexApiStagedSurfaceManifest({
  gitSourceSnapshot,
  inputMaterial,
  previousManifest,
  repositoryRoot,
  sourceFileCache,
  scopeIdentity,
  sourcePaths,
  ts,
}) {
  validateConvexApiStagedSurfaceManifest(previousManifest, scopeIdentity);
  const currentEntries = snapshotEntriesByPath(gitSourceSnapshot);
  const projectedPaths = projectedPathSet(repositoryRoot, sourcePaths);
  const currentInputs = [...inputMaterial.inputs].sort((left, right) =>
    compareStrings(left.path, right.path)
  );
  if (
    currentInputs.length !== previousManifest.inputs.length ||
    currentInputs.some(
      (input, index) =>
        input.path !== previousManifest.inputs[index].path ||
        projectedPaths.has(input.path) !== previousManifest.inputs[index].projected
    )
  ) {
    return { decision: "full", reason: "input-layout-changed" };
  }

  const currentPackageEntry = requiredGitEntry(
    currentEntries,
    inputMaterial.packageResolution.path
  );
  if (
    !sameGitEntry(currentPackageEntry, previousManifest.packageResolution.gitEntry) ||
    inputMaterial.packageResolution.physicalSha256 !==
      previousManifest.packageResolution.physicalSha256 ||
    inputMaterial.packageResolution.physicalSize !==
      previousManifest.packageResolution.physicalSize ||
    inputMaterial.packageResolution.resolutionSha256 !==
      previousManifest.packageResolution.resolutionSha256
  ) {
    return { decision: "full", reason: "package-resolution-input-changed" };
  }

  const nextInputs = [];
  for (const [index, currentInput] of currentInputs.entries()) {
    const previousInput = previousManifest.inputs[index];
    const currentGitEntry = requiredGitEntry(currentEntries, currentInput.path);
    const gitEntryChanged = !sameGitEntry(currentGitEntry, previousInput.gitEntry);
    const physicalInputChanged =
      currentInput.physicalSha256 !== previousInput.physicalSha256 ||
      currentInput.physicalSize !== previousInput.physicalSize;
    if (!gitEntryChanged && physicalInputChanged) {
      return { decision: "full", reason: "physical-input-changed-without-git-change" };
    }
    if (gitEntryChanged && !previousInput.projected) {
      return { decision: "full", reason: "non-projected-input-changed" };
    }
    if (gitEntryChanged) {
      const sourcePath = resolve(repositoryRoot, currentInput.path);
      const cachedSource = inputMaterial.sourceContentsByPath?.get(currentInput.path);
      const source =
        cachedSource ??
        convexApiReadStableFile(sourcePath, "Convex API projected repository input");
      if (cachedSource !== undefined && !Buffer.isBuffer(cachedSource)) {
        throw new Error("Convex API repository input material contains invalid source contents.");
      }
      if (
        source.length !== currentInput.physicalSize ||
        sha256(source) !== currentInput.physicalSha256
      ) {
        throw new Error(
          `Convex API projected repository input changed before projection: ${sourcePath}`
        );
      }
      const projection = convexApiSourceSurfaceProjection({
        source: source.toString("utf8"),
        sourcePath,
        sourceFileCache,
        ts,
      });
      if (projection === undefined || sha256(projection) !== previousInput.surfaceSha256) {
        return { decision: "full", reason: "source-projection-changed" };
      }
    }
    nextInputs.push({
      gitEntry: currentGitEntry,
      path: currentInput.path,
      physicalSha256: currentInput.physicalSha256,
      physicalSize: currentInput.physicalSize,
      physicalState: currentInput.physicalState,
      projected: previousInput.projected,
      surfaceSha256: previousInput.surfaceSha256,
    });
  }

  const manifest = {
    inputs: nextInputs,
    kind: previousManifest.kind,
    packageResolution: {
      gitEntry: currentPackageEntry,
      ...inputMaterial.packageResolution,
    },
    repositorySurfaceSha256: previousManifest.repositorySurfaceSha256,
    scopeIdentity,
    treeOid: gitSourceSnapshot.treeOid,
  };
  return {
    decision: "reuse",
    manifest: validateConvexApiStagedSurfaceManifest(manifest, scopeIdentity),
  };
}

export function convexApiFastReuseIdentity({
  arch = process.arch,
  configPath,
  installedLayoutSha256,
  nodeVersion = process.version,
  platform = process.platform,
  repositorySurfaceSha256,
}) {
  if (
    (configPath !== null && typeof configPath !== "string") ||
    typeof arch !== "string" ||
    arch.length === 0 ||
    typeof nodeVersion !== "string" ||
    nodeVersion.length === 0 ||
    typeof platform !== "string" ||
    platform.length === 0 ||
    !sha256Pattern.test(installedLayoutSha256) ||
    !sha256Pattern.test(repositorySurfaceSha256)
  ) {
    throw new Error("Invalid Convex API fast reuse identity hash.");
  }
  if (configPath !== null) {
    requireRelativePath(configPath, "Convex API fast reuse identity");
  }
  return {
    arch,
    configPath,
    installedLayoutSha256,
    kind: "convex-api-fast-reuse-surface-v3",
    nodeVersion,
    platform,
    repositorySurfaceSha256,
  };
}

export function convexApiFastReuseKey(identity) {
  return createHash("sha256").update(JSON.stringify(identity)).digest("hex");
}

export function validateConvexApiFastReuseIndex(value, expectedIdentity) {
  requireExactKeys(
    value,
    ["identity", "inputSha256", "kind", "outputSha256", "programMaterialPaths"],
    "Convex API fast reuse index"
  );
  if (
    value.kind !== "convex-api-fast-reuse-index-v3" ||
    JSON.stringify(value.identity) !== JSON.stringify(expectedIdentity) ||
    !sha256Pattern.test(value.inputSha256) ||
    !sha256Pattern.test(value.outputSha256) ||
    !Array.isArray(value.programMaterialPaths) ||
    value.programMaterialPaths.some(
      (path) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.startsWith("/") ||
        path.includes("\\") ||
        path.split("/").some((part) => part === "" || part === "." || part === "..")
    ) ||
    JSON.stringify(value.programMaterialPaths) !==
      JSON.stringify([...new Set(value.programMaterialPaths)].sort(compareStrings))
  ) {
    throw new Error("Convex API fast reuse index is corrupt.");
  }
  return value;
}

function propertyName(ts, node) {
  if (node.name !== undefined && ts.isStringLiteral(node.name)) {
    return node.name.text;
  }
  throw new Error("Flattened Convex API output contains an unsupported property name.");
}

function collectOutputFunctions(ts, typeNode, visibility, path, functions) {
  if (!ts.isTypeLiteralNode(typeNode)) {
    throw new Error("Flattened Convex API output contains an unsupported API tree node.");
  }
  for (const member of typeNode.members) {
    if (!ts.isPropertySignature(member) || member.type === undefined) {
      throw new Error("Flattened Convex API output contains an unsupported API tree member.");
    }
    const nextPath = [...path, propertyName(ts, member)];
    if (ts.isTypeLiteralNode(member.type)) {
      collectOutputFunctions(ts, member.type, visibility, nextPath, functions);
      continue;
    }
    if (
      !ts.isTypeReferenceNode(member.type) ||
      !ts.isIdentifier(member.type.typeName) ||
      member.type.typeName.text !== "FunctionReference" ||
      member.type.typeArguments === undefined ||
      member.type.typeArguments.length !== 4 ||
      !ts.isLiteralTypeNode(member.type.typeArguments[0]) ||
      !ts.isStringLiteral(member.type.typeArguments[0].literal) ||
      !ts.isLiteralTypeNode(member.type.typeArguments[1]) ||
      !ts.isStringLiteral(member.type.typeArguments[1].literal) ||
      !["query", "mutation", "action"].includes(member.type.typeArguments[0].literal.text) ||
      member.type.typeArguments[1].literal.text !== visibility ||
      nextPath.length < 2
    ) {
      throw new Error("Flattened Convex API output contains an invalid function reference.");
    }
    functions.push({
      exportName: nextPath.at(-1),
      kind: member.type.typeArguments[0].literal.text,
      modulePath: nextPath.slice(0, -1).join("/"),
      visibility,
    });
  }
}

export function convexApiFunctionsFromOutput({ output, sourcePath = "api.d.ts", ts }) {
  const sourceFile = sourceFileForProjection(ts, sourcePath, output);
  if (sourceFile === undefined) {
    throw new Error("Flattened Convex API output is not valid TypeScript.");
  }
  const functions = [];
  const declarations = new Map();
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) {
      continue;
    }
    for (const declaration of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(declaration.name) &&
        (declaration.name.text === "api" || declaration.name.text === "internal")
      ) {
        if (declaration.type === undefined || declarations.has(declaration.name.text)) {
          throw new Error("Flattened Convex API output has invalid API declarations.");
        }
        declarations.set(declaration.name.text, declaration.type);
      }
    }
  }
  if (declarations.size !== 2) {
    throw new Error("Flattened Convex API output is missing API declarations.");
  }
  collectOutputFunctions(ts, declarations.get("api"), "public", [], functions);
  collectOutputFunctions(ts, declarations.get("internal"), "internal", [], functions);
  return functions.sort((left, right) => {
    const moduleOrder = compareStrings(left.modulePath, right.modulePath);
    return moduleOrder === 0 ? compareStrings(left.exportName, right.exportName) : moduleOrder;
  });
}

export function convexApiRouteOutput(functions) {
  const routePaths = new Set(
    functions.map(({ exportName, modulePath, visibility }) =>
      JSON.stringify([visibility, ...modulePath.split("/"), exportName])
    )
  );
  for (const { exportName, modulePath, visibility } of functions) {
    const parts = [visibility, ...modulePath.split("/"), exportName];
    for (let length = 2; length < parts.length; length += 1) {
      if (routePaths.has(JSON.stringify(parts.slice(0, length)))) {
        throw new Error(
          `A Convex API function collides with a namespace at ${modulePath}:${exportName}.`
        );
      }
    }
  }
  return `${JSON.stringify({
    kind: "convex-api-routes-v1",
    functions: functions.map(({ exportName, kind, modulePath, visibility }) => ({
      exportName,
      kind,
      modulePath,
      visibility,
    })),
  })}\n`;
}

export function validateConvexApiCachedInventory({
  expectedEntryPathByModulePath,
  expectedInput,
  expectedOutputSha256,
  inventory,
  output,
  routeInventoryOnly = false,
  ts,
}) {
  if (!(expectedEntryPathByModulePath instanceof Map)) {
    throw new Error("Shared flattened API inventory expected entry paths are invalid.");
  }
  requireExactKeys(
    inventory,
    [
      "functions",
      "inputSha256",
      "kind",
      "materialIdentity",
      "outputSha256",
      "programMaterialPaths",
    ],
    "Shared flattened API inventory cache"
  );
  requireExactKeys(
    inventory.materialIdentity,
    [
      "configPath",
      "generator",
      "inputSha256",
      "installedMaterialIdentity",
      "kind",
      "repositoryInputSha256",
    ],
    "Shared flattened API inventory material identity"
  );
  requireExactKeys(
    inventory.materialIdentity.installedMaterialIdentity,
    ["arch", "bytes", "fileCount", "kind", "nodeModulesSha256", "nodeVersion", "platform"],
    "Shared flattened API inventory installed material identity"
  );
  const installedMaterialIdentity = inventory.materialIdentity.installedMaterialIdentity;
  if (
    inventory.kind !==
      (routeInventoryOnly
        ? "convex-api-route-snapshot-inventory-v1"
        : "convex-generated-api-snapshot-inventory-v3") ||
    inventory.inputSha256 !== expectedInput.inputSha256 ||
    inventory.outputSha256 !== expectedOutputSha256 ||
    JSON.stringify(inventory.materialIdentity) !== JSON.stringify(expectedInput.identity) ||
    !Array.isArray(inventory.functions) ||
    !Array.isArray(inventory.programMaterialPaths) ||
    inventory.programMaterialPaths.some(
      (path) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.startsWith("/") ||
        path.includes("\\") ||
        path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
    ) ||
    JSON.stringify(inventory.programMaterialPaths) !==
      JSON.stringify([...new Set(inventory.programMaterialPaths)].sort(compareStrings)) ||
    inventory.materialIdentity.generator !== "scripts/flatten-convex-api.mjs" ||
    inventory.materialIdentity.kind !== "convex-api-flattener-input-v1" ||
    !sha256Pattern.test(inventory.materialIdentity.inputSha256) ||
    !sha256Pattern.test(inventory.materialIdentity.repositoryInputSha256) ||
    (inventory.materialIdentity.configPath !== null &&
      typeof inventory.materialIdentity.configPath !== "string") ||
    typeof installedMaterialIdentity.arch !== "string" ||
    !Number.isSafeInteger(installedMaterialIdentity.bytes) ||
    installedMaterialIdentity.bytes < 0 ||
    !Number.isSafeInteger(installedMaterialIdentity.fileCount) ||
    installedMaterialIdentity.fileCount < 0 ||
    installedMaterialIdentity.kind !== "convex-api-installed-material-v1" ||
    !sha256Pattern.test(installedMaterialIdentity.nodeModulesSha256) ||
    typeof installedMaterialIdentity.nodeVersion !== "string" ||
    typeof installedMaterialIdentity.platform !== "string"
  ) {
    throw new Error("Shared flattened API inventory cache is corrupt.");
  }
  for (const func of inventory.functions) {
    requireExactKeys(
      func,
      ["entryPath", "exportName", "kind", "modulePath", "visibility"],
      "Shared flattened API inventory function"
    );
    if (
      typeof func.entryPath !== "string" ||
      func.entryPath !== expectedEntryPathByModulePath.get(func.modulePath) ||
      typeof func.exportName !== "string" ||
      func.exportName.length === 0 ||
      typeof func.modulePath !== "string" ||
      func.modulePath.length === 0 ||
      !["query", "mutation", "action"].includes(func.kind) ||
      !["public", "internal"].includes(func.visibility)
    ) {
      throw new Error("Shared flattened API inventory cache is corrupt.");
    }
  }
  if (routeInventoryOnly) {
    // The route product authenticates registrations only. It must never enter the cache for
    // complete argument/return declarations, even when both products have identical routes.
    if (
      sha256(output) !== expectedOutputSha256 ||
      output !== convexApiRouteOutput(inventory.functions)
    ) {
      throw new Error("Convex API route inventory cache disagrees with the route output.");
    }
    const targets = inventory.functions.map(
      ({ modulePath, exportName }) => `${modulePath}\0${exportName}`
    );
    if (JSON.stringify(targets) !== JSON.stringify([...new Set(targets)].sort(compareStrings))) {
      throw new Error("Convex API route inventory contains duplicate or unsorted routes.");
    }
    return inventory;
  }
  if (
    JSON.stringify(
      inventory.functions.map(({ exportName, kind, modulePath, visibility }) => ({
        exportName,
        kind,
        modulePath,
        visibility,
      }))
    ) !== JSON.stringify(convexApiFunctionsFromOutput({ output, ts }))
  ) {
    throw new Error("Shared flattened API inventory cache disagrees with the generated output.");
  }
  return inventory;
}
