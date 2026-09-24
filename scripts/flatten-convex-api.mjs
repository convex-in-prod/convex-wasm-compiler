import console from "node:console";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  ftruncateSync,
  fsyncSync,
  mkdirSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

import { defaultConvexWasmCacheRoot } from "./lib/convex-wasm-cache-layout.mjs";
import { readConvexWasmGitBlobMaterials } from "./lib/convex-wasm-git-blob-material.mjs";
import {
  convexApiCompilerMaterialPaths,
  convexApiFlattenerInputIdentity,
  convexApiInstalledLayoutSha256,
  convexApiInstalledMaterialIdentity,
  convexApiPathsIdentifySameFile,
  convexApiProgramMaterialPaths,
} from "./lib/convex-api-flattener-material.mjs";
import {
  createConvexApiStagedSurfaceManifest,
  convexApiRouteOutput,
  convexApiReadStableFile,
  convexApiRepositoryInputMaterial,
  convexApiFastReuseIdentity,
  convexApiFastReuseKey,
  convexApiFunctionsRoot,
  convexApiRepositorySurfaceSha256,
  convexApiStagedSurfaceScopeIdentity,
  convexApiStagedSurfaceScopeKey,
  reuseConvexApiStagedSurfaceManifest,
  validateConvexApiCachedInventory,
  validateConvexApiFastReuseIndex,
  validateConvexApiStagedSurfaceManifest,
} from "./lib/convex-api-flattener-reuse.mjs";
import {
  readConvexWasmGitSourceSnapshotFile,
  verifyConvexWasmGitSourceSnapshot,
} from "./lib/convex-wasm-git-source-snapshot.mjs";
import { buildConvexWasmProducerIdentity } from "./lib/convex-wasm-producer-identity.mjs";

export async function main(argumentsList = process.argv.slice(2)) {
const scriptDir = dirname(fileURLToPath(import.meta.url));
const sourceChangedExitCode = 75;
const [mode, ...modeArguments] = argumentsList;
const routeInventoryOnly = mode === "--route-inventory-snapshot";
const inventorySnapshotMode = routeInventoryOnly || mode === "--inventory-snapshot";
const inventorySnapshotRoot = inventorySnapshotMode ? modeArguments.shift() : undefined;
const inventoryArtifactName = routeInventoryOnly ? "api-routes.json" : "api.d.ts";
const inventoryCacheSuffix = routeInventoryOnly ? "routes.json" : "d.ts";
const inventoryVersion = routeInventoryOnly ? "routes-v1" : "v3";
const options = new Map();
for (let index = 0; index < modeArguments.length; index += 2) {
  const option = modeArguments[index];
  const value = modeArguments[index + 1];
  if (
    !["--config", "--git-source-snapshot", "--project-root"].includes(option) ||
    value === undefined ||
    options.has(option)
  ) {
    throw new Error(
      "Usage: node scripts/flatten-convex-api.mjs (--write|--check) [--config <path>] [--git-source-snapshot <path>] [--project-root <path>]\n" +
        "       node scripts/flatten-convex-api.mjs (--inventory-snapshot|--route-inventory-snapshot) <directory> [--config <path>] [--git-source-snapshot <path>] [--project-root <path>]"
    );
  }
  options.set(option, value);
}
const configArgument = options.get("--config");
const gitSourceSnapshotArgument = options.get("--git-source-snapshot");
const projectRootArgument = options.get("--project-root");

if (
  (mode !== "--write" && mode !== "--check" && !inventorySnapshotMode) ||
  (inventorySnapshotMode &&
    (inventorySnapshotRoot === undefined || inventorySnapshotRoot.length === 0))
) {
  throw new Error(
    "Usage: node scripts/flatten-convex-api.mjs (--write|--check) [--config <path>] [--git-source-snapshot <path>] [--project-root <path>]\n" +
      "       node scripts/flatten-convex-api.mjs (--inventory-snapshot|--route-inventory-snapshot) <directory> [--config <path>] [--git-source-snapshot <path>] [--project-root <path>]"
  );
}

if (projectRootArgument === undefined) {
  throw new Error("--project-root must name the adopting application");
}
const rootDir = resolve(projectRootArgument);
const projectRequire = createRequire(resolve(rootDir, "package.json"));
const gitSourceSnapshotPath =
  gitSourceSnapshotArgument === undefined ? undefined : resolve(rootDir, gitSourceSnapshotArgument);
const gitSourceSnapshot =
  gitSourceSnapshotPath === undefined
    ? undefined
    : await readConvexWasmGitSourceSnapshotFile(gitSourceSnapshotPath);
const projectConfig = JSON.parse(
  convexApiReadStableFile(resolve(rootDir, "convex.json"), "Convex project configuration")
);
const functionsRoot = convexApiFunctionsRoot(projectConfig);
const functionsPrefix = `${functionsRoot}/`;
const apiRelativePath = `${functionsPrefix}_generated/api.d.ts`;
const convexDir = resolve(rootDir, functionsRoot);
const apiPath = resolve(convexDir, "_generated/api.d.ts");
const configPath = resolve(convexDir, "tsconfig.json");
const profileGeneration = process.env.CONVEX_WASM_PROFILE_API === "1";
const generatedServerPath = resolve(convexDir, "_generated/server.d.ts");
const componentConfigPath = resolve(convexDir, "convex.config.ts");
const convexRegistrationPath = resolve(
  rootDir,
  "node_modules/convex/dist/esm-types/server/registration.d.ts"
);
const normalizePathForHostComparison = (path) =>
  process.platform === "darwin" || process.platform === "win32" ? path.toLowerCase() : path;
const pathsEqualForHost = (left, right) =>
  normalizePathForHostComparison(left) === normalizePathForHostComparison(right);
let typeScriptPromise;
let ts;
async function loadTypeScript() {
  typeScriptPromise ??= import(projectRequire.resolve("typescript")).then((module) => module.default);
  ts ??= await typeScriptPromise;
  return ts;
}

const userConfigPath = configArgument === undefined ? undefined : resolve(rootDir, configArgument);
const relativeUserConfigPath =
  userConfigPath === undefined ? null : toPosixPath(relative(rootDir, userConfigPath));
let userConfigSource;
if (userConfigPath !== undefined) {
  let source;
  try {
    source = convexApiReadStableFile(userConfigPath, "Convex API flattener configuration");
  } catch (error) {
    if (isConcurrentInputError(error)) {
      exitForConcurrentSourceChange();
    }
    throw error;
  }
  const configTypeScript = await loadTypeScript();
  const sourceFile = configTypeScript.createSourceFile(
    userConfigPath,
    source.toString("utf8"),
    configTypeScript.ScriptTarget.Latest,
    true,
    configTypeScript.ScriptKind.JS
  );
  if (sourceFile.parseDiagnostics.length > 0) {
    throw new Error("The Convex API flattener configuration is not valid JavaScript.");
  }
  function rejectConfigDependency(node) {
    if (
      configTypeScript.isImportDeclaration(node) ||
      configTypeScript.isImportEqualsDeclaration(node) ||
      (configTypeScript.isExportDeclaration(node) && node.moduleSpecifier !== undefined) ||
      (configTypeScript.isCallExpression(node) &&
        node.expression.kind === configTypeScript.SyntaxKind.ImportKeyword)
    ) {
      throw new Error(
        "The Convex API flattener configuration must not import another module; its complete material must remain in one file."
      );
    }
    node.forEachChild(rejectConfigDependency);
  }
  rejectConfigDependency(sourceFile);
  const statements = sourceFile.statements.filter(
    (statement) => !configTypeScript.isEmptyStatement(statement)
  );
  if (
    statements.length !== 1 ||
    !configTypeScript.isExportAssignment(statements[0]) ||
    statements[0].isExportEquals
  ) {
    throw new Error("The Convex API flattener configuration must be one literal default export.");
  }
  function validateConfigLiteral(node) {
    if (
      configTypeScript.isStringLiteral(node) ||
      configTypeScript.isNumericLiteral(node) ||
      node.kind === configTypeScript.SyntaxKind.TrueKeyword ||
      node.kind === configTypeScript.SyntaxKind.FalseKeyword ||
      node.kind === configTypeScript.SyntaxKind.NullKeyword
    ) {
      return;
    }
    if (configTypeScript.isArrayLiteralExpression(node)) {
      for (const element of node.elements) {
        if (configTypeScript.isSpreadElement(element)) {
          throw new Error(
            "The Convex API flattener configuration must contain only literal values."
          );
        }
        validateConfigLiteral(element);
      }
      return;
    }
    if (configTypeScript.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        if (
          !configTypeScript.isPropertyAssignment(property) ||
          (!configTypeScript.isIdentifier(property.name) &&
            !configTypeScript.isStringLiteral(property.name))
        ) {
          throw new Error(
            "The Convex API flattener configuration must contain only literal properties."
          );
        }
        validateConfigLiteral(property.initializer);
      }
      return;
    }
    throw new Error("The Convex API flattener configuration must contain only literal values.");
  }
  validateConfigLiteral(statements[0].expression);
  userConfigSource = source;
}
const userConfig =
  userConfigPath === undefined ? {} : (await import(pathToFileURL(userConfigPath).href)).default;
if (userConfigPath !== undefined) {
  try {
    if (
      !convexApiReadStableFile(userConfigPath, "Convex API flattener configuration").equals(
        userConfigSource
      )
    ) {
      throw new Error("The Convex API flattener configuration changed while it was imported.");
    }
  } catch (error) {
    if (isConcurrentInputError(error)) {
      exitForConcurrentSourceChange();
    }
    throw error;
  }
}
if (typeof userConfig !== "object" || userConfig === null || Array.isArray(userConfig)) {
  throw new Error("The Convex API flattener configuration must export an object as default.");
}
const knownConfigKeys = new Set([
  "additionalBuilders",
  "generatedRegistry",
  "inputFiles",
  "patchFiles",
  "sourceRoots",
]);
for (const key of Object.keys(userConfig)) {
  if (!knownConfigKeys.has(key)) {
    throw new Error(`Unknown Convex API flattener configuration field: ${key}`);
  }
}
function projectRelativePaths(value, description) {
  if (
    !Array.isArray(value) ||
    value.some(
      (path) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.startsWith("/") ||
        path.includes("\\") ||
        path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
    ) ||
    new Set(value).size !== value.length
  ) {
    throw new Error(`${description} must be unique normalized application-relative paths`);
  }
  return value;
}
const patchFiles = projectRelativePaths(userConfig.patchFiles ?? [], "patchFiles");
const inputFiles = projectRelativePaths(userConfig.inputFiles ?? [], "inputFiles");
const sourceRoots = projectRelativePaths(userConfig.sourceRoots ?? [], "sourceRoots");
if (
  sourceRoots.some(
    (root) =>
      root === functionsRoot ||
      root.startsWith(`${functionsRoot}/`) ||
      functionsRoot.startsWith(`${root}/`) ||
      sourceRoots.some((other) => other !== root && other.startsWith(`${root}/`))
  )
) {
  throw new Error("sourceRoots must not overlap each other or the functions directory");
}
const sourceRootPrefixes = [functionsRoot, ...sourceRoots].map((root) => `${root}/`);
const additionalSourceDirs = sourceRoots.map((root) => resolve(rootDir, root));

const directBuilders = new Map();
function addBuilder(name, kind, visibility, sourcePath) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    !["query", "mutation", "action"].includes(kind) ||
    !["public", "internal"].includes(visibility) ||
    typeof sourcePath !== "string" ||
    sourcePath.length === 0
  ) {
    throw new Error(`Invalid Convex API builder configuration for ${String(name)}.`);
  }
  if (directBuilders.has(name)) {
    throw new Error(`Duplicate Convex API builder configuration: ${name}`);
  }
  directBuilders.set(name, {
    kind,
    sourcePath: resolve(rootDir, sourcePath),
    visibility,
  });
}

for (const [name, kind, visibility] of [
  ["query", "query", "public"],
  ["mutation", "mutation", "public"],
  ["action", "action", "public"],
  ["internalQuery", "query", "internal"],
  ["internalMutation", "mutation", "internal"],
  ["internalAction", "action", "internal"],
]) {
  addBuilder(name, kind, visibility, generatedServerPath);
}

const additionalBuilders = userConfig.additionalBuilders ?? [];
if (!Array.isArray(additionalBuilders)) {
  throw new Error("additionalBuilders must be an array.");
}
for (const builder of additionalBuilders) {
  if (typeof builder !== "object" || builder === null || Array.isArray(builder)) {
    throw new Error("Each additional builder configuration must be an object.");
  }
  const knownBuilderKeys = new Set(["name", "kind", "visibility", "source"]);
  for (const key of Object.keys(builder)) {
    if (!knownBuilderKeys.has(key)) {
      throw new Error(`Unknown additional builder configuration field: ${key}`);
    }
  }
  addBuilder(builder.name, builder.kind, builder.visibility, builder.source);
}

let generatedRegistryAdapter;
if (userConfig.generatedRegistry !== undefined) {
  const generatedRegistry = userConfig.generatedRegistry;
  if (
    typeof generatedRegistry !== "object" ||
    generatedRegistry === null ||
    Array.isArray(generatedRegistry)
  ) {
    throw new Error("generatedRegistry must be an object.");
  }
  const knownRegistryKeys = new Set([
    "generatedModule",
    "runtimeIdentifier",
    "expectedRegisteredExports",
  ]);
  for (const key of Object.keys(generatedRegistry)) {
    if (!knownRegistryKeys.has(key)) {
      throw new Error(`Unknown generated registry adapter configuration field: ${key}`);
    }
  }
  if (
    typeof generatedRegistry.generatedModule !== "string" ||
    generatedRegistry.generatedModule.length === 0 ||
    generatedRegistry.generatedModule.startsWith("/") ||
    generatedRegistry.generatedModule.includes("\\") ||
    generatedRegistry.generatedModule
      .split("/")
      .some((part) => part.length === 0 || part === "." || part === "..") ||
    typeof generatedRegistry.runtimeIdentifier !== "string" ||
    !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(generatedRegistry.runtimeIdentifier) ||
    !Array.isArray(generatedRegistry.expectedRegisteredExports) ||
    generatedRegistry.expectedRegisteredExports.length === 0 ||
    new Set(generatedRegistry.expectedRegisteredExports).size !==
      generatedRegistry.expectedRegisteredExports.length ||
    generatedRegistry.expectedRegisteredExports.some(
      (exportName) =>
        typeof exportName !== "string" || !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(exportName)
    ) === true
  ) {
    throw new Error("Invalid generated registry adapter configuration.");
  }
  generatedRegistryAdapter = {
    expectedRegisteredExports: new Set(generatedRegistry.expectedRegisteredExports),
    generatedModulePath: resolve(rootDir, generatedRegistry.generatedModule),
    runtimeIdentifier: generatedRegistry.runtimeIdentifier,
  };
}
const outputHashPattern = / \* Output hash: ([a-f0-9]{64})\n/u;
const outputHashPlaceholder = "0".repeat(64);

function toPosixPath(path) {
  return path.split(sep).join("/");
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sourceLocation(node) {
  const sourceFile = node.getSourceFile();
  const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return `${toPosixPath(relative(rootDir, sourceFile.fileName))}:${position.line + 1}:${position.character + 1}`;
}

function isTestSource(path) {
  return /\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(path);
}

function isTypeScriptImplementationSource(path) {
  return (
    (path.endsWith(".ts") ||
      path.endsWith(".tsx") ||
      path.endsWith(".mts") ||
      path.endsWith(".cts")) &&
    !/\.d\.(?:ts|mts|cts)$/u.test(path) &&
    !isTestSource(path)
  );
}

function typeScriptInputFilesUnder(dir) {
  const rootStatus = lstatSync(dir);
  if (!rootStatus.isDirectory() || rootStatus.isSymbolicLink()) {
    throw new Error(`Convex API source discovery requires a real directory: ${dir}`);
  }
  const paths = [];
  const generatedDirectory = resolve(convexDir, "_generated");
  function walk(current) {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) =>
      compareStrings(left.name, right.name)
    )) {
      const path = resolve(current, entry.name);
      if (entry.isDirectory()) {
        if (!pathsEqualForHost(path, generatedDirectory)) {
          walk(path);
        }
      } else if (entry.isSymbolicLink()) {
        throw new Error(`Convex API source discovery does not support symbolic links: ${path}`);
      } else if (
        entry.isFile() &&
        (path.endsWith(".ts") ||
          path.endsWith(".tsx") ||
          path.endsWith(".mts") ||
          path.endsWith(".cts") ||
          path.endsWith(".json"))
      ) {
        paths.push(path);
      } else if (
        entry.isFile() &&
        /\.[cm]?[jt]sx?$/u.test(path) &&
        !/\.d\.[cm]?ts$/u.test(path) &&
        !isTestSource(path)
      ) {
        throw new Error(`Convex API source discovery does not support this extension: ${path}`);
      } else if (!entry.isFile()) {
        throw new Error(`Convex API source discovery found an unsupported entry: ${path}`);
      }
    }
  }
  walk(dir);
  return paths.sort(compareStrings);
}

function importPathForSource(sourcePath, fromDir) {
  const extension = extname(sourcePath);
  const withoutExtension = relative(fromDir, sourcePath).slice(0, -extension.length);
  const path = toPosixPath(withoutExtension);
  const runtimeExtension = extension === ".mts" ? ".mjs" : extension === ".cts" ? ".cjs" : ".js";
  return `${path.startsWith(".") ? path : `./${path}`}${runtimeExtension}`;
}

function convexModulePath(sourcePath) {
  return toPosixPath(relative(convexDir, sourcePath)).slice(0, -extname(sourcePath).length);
}

const convexTypeScriptInputPaths = typeScriptInputFilesUnder(convexDir);
const additionalTypeScriptInputPaths = additionalSourceDirs.flatMap(typeScriptInputFilesUnder);
const convexSourcePaths = convexTypeScriptInputPaths.filter(isTypeScriptImplementationSource);
const additionalSourcePaths = additionalTypeScriptInputPaths.filter(isTypeScriptImplementationSource);
const convexSourceByModulePath = new Map();
for (const sourcePath of convexSourcePaths) {
  const modulePath = convexModulePath(sourcePath);
  const previousSourcePath = convexSourceByModulePath.get(modulePath);
  if (previousSourcePath !== undefined) {
    throw new Error(
      `Convex API source discovery found multiple implementation entries for module ${modulePath}: ${previousSourcePath}, ${sourcePath}`
    );
  }
  convexSourceByModulePath.set(modulePath, sourcePath);
}
const inventoryEntryPathByModulePath = new Map(
  [...convexSourceByModulePath].map(([modulePath, sourcePath]) => [
    modulePath,
    toPosixPath(relative(rootDir, sourcePath)),
  ])
);
// Component discovery is runtime-sensitive, so keep its complete source exact.
const repositorySourcePaths = [...convexSourcePaths, ...additionalSourcePaths].filter(
  (path) => path !== componentConfigPath
);
function repositoryInputPaths(currentConvexInputPaths, currentAdditionalInputPaths) {
  return [
    ...new Set([
      ...(userConfigPath === undefined ? [] : [userConfigPath]),
      ...inputFiles.map((path) => resolve(rootDir, path)),
      resolve(rootDir, "convex.json"),
      configPath,
      resolve(convexDir, "_generated/dataModel.d.ts"),
      resolve(convexDir, "_generated/server.d.ts"),
      ...[...directBuilders.values()].map((builder) => builder.sourcePath),
      ...(generatedRegistryAdapter === undefined ? [] : [generatedRegistryAdapter.generatedModulePath]),
      ...patchFiles.map((path) => resolve(rootDir, path)),
      ...currentConvexInputPaths,
      ...currentAdditionalInputPaths,
    ]),
  ];
}

function inputPathLayout(paths) {
  return paths.map((path) => resolve(path)).sort(compareStrings);
}

const inputPaths = repositoryInputPaths(convexTypeScriptInputPaths, additionalTypeScriptInputPaths);
const initialInputPathLayout = inputPathLayout(inputPaths);

if (gitSourceSnapshot !== undefined) {
  const stagedSourcePaths = gitSourceSnapshot.entries
    .map((entry) => entry.path)
    .filter(
      (path) =>
        sourceRootPrefixes.some((prefix) => path.startsWith(prefix)) &&
        !path.startsWith(`${functionsPrefix}_generated/`) &&
        (path.endsWith(".ts") ||
          path.endsWith(".tsx") ||
          path.endsWith(".mts") ||
          path.endsWith(".cts") ||
          path.endsWith(".json"))
    )
    .sort(compareStrings);
  const discoveredSourcePaths = [...convexTypeScriptInputPaths, ...additionalTypeScriptInputPaths]
    .map((path) => toPosixPath(relative(rootDir, path)))
    .sort(compareStrings);
  if (JSON.stringify(stagedSourcePaths) !== JSON.stringify(discoveredSourcePaths)) {
    throw new Error(
      "Convex API physical source discovery disagrees with the staged Git source inventory."
    );
  }
}
const sharedCacheDir = join(defaultConvexWasmCacheRoot(), "convex-api");
const sharedInventoryCacheDir = join(sharedCacheDir, `inventory-${inventoryVersion}`);
const privateJsonCacheMaxBytes = 8 * 1024 * 1024;
const compressedCacheMaxBytes = 64 * 1024 * 1024;
const expandedCacheMaxBytes = 64 * 1024 * 1024;
const installedLayoutSha256 = convexApiInstalledLayoutSha256({
  nodeModulesRoot: resolve(rootDir, "node_modules"),
});
const stagedSurfaceScopeIdentity = convexApiStagedSurfaceScopeIdentity({
  configPath: relativeUserConfigPath,
  installedLayoutSha256,
});
const stagedSurfaceManifestPath =
  gitSourceSnapshot === undefined
    ? undefined
    : join(
        sharedCacheDir,
        "staged-surface-manifest",
        `${convexApiStagedSurfaceScopeKey(stagedSurfaceScopeIdentity)}.json`
      );
const stagedSurfaceManifestMaxBytes = 8 * 1024 * 1024;

function ensurePrivateCacheDirectory(path) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const status = lstatSync(path, { bigint: true });
  if (
    !status.isDirectory() ||
    status.isSymbolicLink() ||
    (status.mode & 0o777n) !== 0o700n ||
    (typeof process.getuid === "function" && status.uid !== BigInt(process.getuid()))
  ) {
    throw new Error(`Convex API cache directory is not private: ${path}`);
  }
}

function sameCacheFileState(left, right) {
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

function readPrivateCacheFile(path, description, maximumBytes) {
  ensurePrivateCacheDirectory(sharedCacheDir);
  const parent = dirname(path);
  if (parent !== sharedCacheDir) {
    ensurePrivateCacheDirectory(parent);
  }
  const before = lstatSync(path, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size <= 0n ||
    before.size > BigInt(maximumBytes) ||
    (before.mode & 0o777n) !== 0o600n ||
    (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))
  ) {
    throw new Error(`${description} is not a private bounded file: ${path}`);
  }
  const source = convexApiReadStableFile(path, description);
  const after = lstatSync(path, { bigint: true });
  if (!sameCacheFileState(before, after) || BigInt(source.length) !== after.size) {
    throw new Error(`${description} changed across its authenticated read: ${path}`);
  }
  return source;
}

function writePrivateJsonCacheFile(path, value) {
  const parent = dirname(path);
  ensurePrivateCacheDirectory(sharedCacheDir);
  ensurePrivateCacheDirectory(parent);
  const temporaryPath = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const source = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(source) > privateJsonCacheMaxBytes) {
    throw new Error(`Convex API private JSON cache exceeds its byte boundary: ${path}`);
  }
  try {
    const descriptor = openSync(temporaryPath, "wx", 0o600);
    try {
      writeFileSync(descriptor, source);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporaryPath, path);
    const parentDescriptor = openSync(parent, "r");
    try {
      fsyncSync(parentDescriptor);
    } finally {
      closeSync(parentDescriptor);
    }
  } finally {
    rmSync(temporaryPath, { force: true });
  }
}

function readStagedSurfaceManifest() {
  if (stagedSurfaceManifestPath === undefined) {
    return undefined;
  }
  let parsed;
  try {
    const source = readPrivateCacheFile(
      stagedSurfaceManifestPath,
      "Convex API staged surface manifest",
      stagedSurfaceManifestMaxBytes
    );
    parsed = JSON.parse(source.toString("utf8"));
  } catch (error) {
    // The retained manifest is an optimization. If another process removes it after the
    // existence check, treat the race as a cache miss and rebuild the manifest.
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return undefined;
    }
    throw new Error(`Convex API staged surface manifest is corrupt: ${stagedSurfaceManifestPath}`, {
      cause: error,
    });
  }
  try {
    return validateConvexApiStagedSurfaceManifest(parsed, stagedSurfaceScopeIdentity);
  } catch (error) {
    throw new Error(`Convex API staged surface manifest is corrupt: ${stagedSurfaceManifestPath}`, {
      cause: error,
    });
  }
}

// Keep declaration capture independent of the retained source manifest, whose physical-file
// records cannot describe a staged blob when the worktree declaration differs.
let routeApiSource;
let routeApiSha256;
if (routeInventoryOnly) {
  let contents;
  if (gitSourceSnapshot === undefined) {
    contents = convexApiReadStableFile(apiPath, "Convex API route declaration");
    routeApiSha256 = createHash("sha256").update(contents).digest("hex");
  } else {
    const entry = gitSourceSnapshot.entries.find(
      ({ path }) => path === apiRelativePath
    );
    if (entry === undefined || !["100644", "100755"].includes(entry.mode)) {
      throw new Error("Convex API route declaration is missing from the captured Git tree.");
    }
    const materials = await readConvexWasmGitBlobMaterials(rootDir, [entry.oid]);
    const material = materials.get(entry.oid);
    if (material === undefined) {
      throw new Error("Convex API route declaration blob was not captured.");
    }
    contents = material.contents;
    routeApiSha256 = material.sha256;
  }
  routeApiSource = contents.toString("utf8");
}

const producerIdentity = await buildConvexWasmProducerIdentity(resolve(scriptDir, ".."));
function combinedRepositoryInputHash(repositoryHash, producerSha256 = producerIdentity.sha256) {
  if (repositoryHash === undefined) return undefined;
  return createHash("sha256")
    .update(JSON.stringify([repositoryHash, producerSha256, routeInventoryOnly ? routeApiSha256 : null]))
    .digest("hex");
}

const previousStagedSurfaceManifest = readStagedSurfaceManifest();
let pendingStagedSurfaceManifest;
// Surface projection and candidate discovery both need the same classic TypeScript AST. Keep
// this handoff process-local; persisted identities continue to authenticate source bytes.
const sourceFileCache = new Map();
let repositoryInputMaterial;
try {
  repositoryInputMaterial = convexApiRepositoryInputMaterial({
    gitSourceSnapshot,
    inputPaths,
    previousManifest: previousStagedSurfaceManifest,
    retainContents: true,
    repositoryRoot: rootDir,
  });
} catch (error) {
  if (isConcurrentInputError(error)) {
    exitForConcurrentSourceChange();
  }
  throw error;
}
if (userConfigSource !== undefined) {
  const configInput = repositoryInputMaterial.inputs.find(
    (input) => input.path === relativeUserConfigPath
  );
  if (
    configInput === undefined ||
    configInput.physicalSize !== userConfigSource.length ||
    configInput.physicalSha256 !== createHash("sha256").update(userConfigSource).digest("hex")
  ) {
    exitForConcurrentSourceChange();
  }
}
const repositoryInputSha256 = combinedRepositoryInputHash(repositoryInputMaterial.inputSha256);
const repositoryInputByAbsolutePath = new Map(
  repositoryInputMaterial.inputs.map((input) => [
    normalizePathForHostComparison(resolve(rootDir, input.path)),
    input,
  ])
);
repositoryInputByAbsolutePath.set(
  normalizePathForHostComparison(resolve(rootDir, repositoryInputMaterial.packageResolution.path)),
  repositoryInputMaterial.packageResolution
);
const repositorySourceTextByAbsolutePath = new Map();

function authenticatedRepositorySource(path) {
  const absolutePath = resolve(rootDir, path);
  const normalizedPath = normalizePathForHostComparison(absolutePath);
  const cached = repositorySourceTextByAbsolutePath.get(normalizedPath);
  if (cached !== undefined) {
    return cached;
  }
  const input = repositoryInputByAbsolutePath.get(normalizedPath);
  if (input === undefined) {
    return undefined;
  }
  const retainedSource = repositoryInputMaterial.sourceContentsByPath?.get(input.path);
  let source;
  try {
    source =
      retainedSource ?? convexApiReadStableFile(absolutePath, "Convex API source analysis input");
  } catch (error) {
    if (isConcurrentInputError(error)) {
      exitForConcurrentSourceChange();
    }
    throw error;
  }
  if (
    !Buffer.isBuffer(source) ||
    source.length !== input.physicalSize ||
    createHash("sha256").update(source).digest("hex") !== input.physicalSha256
  ) {
    exitForConcurrentSourceChange();
  }
  const text = source.toString("utf8");
  repositorySourceTextByAbsolutePath.set(normalizedPath, text);
  return text;
}

const materialIndexIdentity = {
  arch: process.arch,
  installedLayoutSha256,
  kind: "convex-api-material-index-v1",
  nodeVersion: process.version,
  platform: process.platform,
  repositoryInputSha256,
};
const materialIndexKey = createHash("sha256")
  .update(JSON.stringify(materialIndexIdentity))
  .digest("hex");
const materialIndexPath = join(sharedCacheDir, "material-index", `${materialIndexKey}.json`);
const compilerMaterialPaths = convexApiCompilerMaterialPaths({
  nodeModulesRoot: resolve(rootDir, "node_modules"),
});

function publishPendingStagedSurfaceManifest() {
  if (stagedSurfaceManifestPath !== undefined && pendingStagedSurfaceManifest !== undefined) {
    writePrivateJsonCacheFile(stagedSurfaceManifestPath, pendingStagedSurfaceManifest);
  }
}

function computeRepositorySurfaceHash() {
  try {
    if (gitSourceSnapshot === undefined) {
      return convexApiRepositorySurfaceSha256({
        inputMaterial: repositoryInputMaterial,
        repositoryRoot: rootDir,
        sourceFileCache,
        sourcePaths: repositorySourcePaths,
        ts,
      });
    }
    if (previousStagedSurfaceManifest !== undefined) {
      const reused = reuseConvexApiStagedSurfaceManifest({
        gitSourceSnapshot,
        inputMaterial: repositoryInputMaterial,
        previousManifest: previousStagedSurfaceManifest,
        repositoryRoot: rootDir,
        sourceFileCache,
        scopeIdentity: stagedSurfaceScopeIdentity,
        sourcePaths: repositorySourcePaths,
        ts,
      });
      if (reused.decision === "reuse") {
        pendingStagedSurfaceManifest = reused.manifest;
        return reused.manifest.repositorySurfaceSha256;
      }
    }
    const manifest = createConvexApiStagedSurfaceManifest({
      gitSourceSnapshot,
      inputMaterial: repositoryInputMaterial,
      repositoryRoot: rootDir,
      sourceFileCache,
      scopeIdentity: stagedSurfaceScopeIdentity,
      sourcePaths: repositorySourcePaths,
      ts,
    });
    pendingStagedSurfaceManifest = manifest;
    return manifest?.repositorySurfaceSha256;
  } catch (error) {
    if (isConcurrentInputError(error)) {
      exitForConcurrentSourceChange();
    }
    throw error;
  }
}

async function verifyInputsAtPublication({
  expectedInputSha256,
  expectedInstalledMaterialIdentity,
  materialPaths,
}) {
  let finalRepositoryInputMaterial;
  let finalInstalledMaterialIdentity;
  let finalInstalledLayoutSha256;
  try {
    // Other repository and installed inputs still use fresh publication checks. The route API
    // declaration alone is sealed at capture and contributes its retained digest below.
    const finalConvexInputPaths = typeScriptInputFilesUnder(convexDir);
    const finalAdditionalInputPaths = additionalSourceDirs.flatMap(typeScriptInputFilesUnder);
    const finalInputPaths = repositoryInputPaths(finalConvexInputPaths, finalAdditionalInputPaths);
    if (
      JSON.stringify(inputPathLayout(finalInputPaths)) !== JSON.stringify(initialInputPathLayout)
    ) {
      exitForConcurrentSourceChange();
    }
    finalRepositoryInputMaterial = convexApiRepositoryInputMaterial({
      inputPaths: finalInputPaths,
      repositoryRoot: rootDir,
    });
    const finalCompilerMaterialPaths = convexApiCompilerMaterialPaths({
      nodeModulesRoot: resolve(rootDir, "node_modules"),
    });
    if (JSON.stringify(finalCompilerMaterialPaths) !== JSON.stringify(compilerMaterialPaths)) {
      exitForConcurrentSourceChange();
    }
    finalInstalledMaterialIdentity = convexApiInstalledMaterialIdentity({
      materialPaths,
      nodeModulesRoot: resolve(rootDir, "node_modules"),
    });
    finalInstalledLayoutSha256 = convexApiInstalledLayoutSha256({
      nodeModulesRoot: resolve(rootDir, "node_modules"),
    });
  } catch (error) {
    if (isConcurrentInputError(error)) {
      exitForConcurrentSourceChange();
    }
    throw error;
  }
  const finalProducerIdentity = await buildConvexWasmProducerIdentity(resolve(scriptDir, ".."));
  const finalRepositoryInputSha256 = combinedRepositoryInputHash(
    finalRepositoryInputMaterial.inputSha256,
    finalProducerIdentity.sha256
  );
  if (
    finalRepositoryInputSha256 !== repositoryInputSha256 ||
    JSON.stringify(finalInstalledMaterialIdentity) !==
      JSON.stringify(expectedInstalledMaterialIdentity) ||
    finalInstalledLayoutSha256 !== installedLayoutSha256
  ) {
    exitForConcurrentSourceChange();
  }
  const finalInput = convexApiFlattenerInputIdentity({
    configPath: relativeUserConfigPath,
    installedMaterialIdentity: finalInstalledMaterialIdentity,
    repositoryInputSha256: finalRepositoryInputSha256,
  });
  if (expectedInputSha256 !== undefined && finalInput.inputSha256 !== expectedInputSha256) {
    exitForConcurrentSourceChange();
  }
  if (gitSourceSnapshot !== undefined && !routeInventoryOnly) {
    // Route declarations are owned by the captured tree; later index/worktree edits belong
    // to the next inventory and cannot replace the bytes included in this result's identity.
    await verifyConvexWasmGitSourceSnapshot(gitSourceSnapshot, { repoRoot: rootDir });
  }
  return finalInput;
}

function readMaterialIndex() {
  let parsed;
  try {
    parsed = JSON.parse(
      readPrivateCacheFile(
        materialIndexPath,
        "Convex API material index",
        privateJsonCacheMaxBytes
      ).toString("utf8")
    );
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return undefined;
    }
    throw error;
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    JSON.stringify(Object.keys(parsed).sort(compareStrings)) !==
      JSON.stringify(["identity", "kind", "programMaterialPaths"].sort(compareStrings)) ||
    parsed.kind !== "convex-api-material-index-v1" ||
    JSON.stringify(parsed.identity) !== JSON.stringify(materialIndexIdentity) ||
    !Array.isArray(parsed.programMaterialPaths) ||
    parsed.programMaterialPaths.some(
      (path) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.startsWith("/") ||
        path.includes("\\") ||
        path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
    ) ||
    JSON.stringify(parsed.programMaterialPaths) !==
      JSON.stringify([...new Set(parsed.programMaterialPaths)].sort(compareStrings))
  ) {
    throw new Error(`Convex API material index is corrupt: ${materialIndexPath}`);
  }
  return parsed.programMaterialPaths;
}

function writeMaterialIndex(programMaterialPaths) {
  writePrivateJsonCacheFile(materialIndexPath, {
    identity: materialIndexIdentity,
    kind: "convex-api-material-index-v1",
    programMaterialPaths,
  });
}

function computeFlattenerInput(
  programMaterialPaths,
  currentRepositoryInputSha256 = repositoryInputSha256
) {
  const installedMaterialIdentity = convexApiInstalledMaterialIdentity({
    materialPaths: [...compilerMaterialPaths, ...programMaterialPaths],
    nodeModulesRoot: resolve(rootDir, "node_modules"),
  });
  return convexApiFlattenerInputIdentity({
    configPath: relativeUserConfigPath,
    installedMaterialIdentity,
    repositoryInputSha256: currentRepositoryInputSha256,
  });
}
let programMaterialPaths = readMaterialIndex();
let flattenerInput;
if (programMaterialPaths !== undefined) {
  try {
    flattenerInput = computeFlattenerInput(programMaterialPaths);
  } catch (error) {
    // A dependency reinstall can remove a path retained by the previous program-material index.
    // That is an ordinary stale-index miss; native discovery below will rebuild the index.
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      programMaterialPaths = undefined;
    } else {
      throw error;
    }
  }
}
let inputHash = flattenerInput?.inputSha256;
let sharedCachePath =
  inputHash === undefined
    ? undefined
    : join(sharedInventoryCacheDir, `${inputHash}.${inventoryCacheSuffix}.gz`);
let sharedInventoryCachePath =
  inputHash === undefined
    ? undefined
    : join(sharedInventoryCacheDir, `${inputHash}.inventory.json.gz`);

function setFlattenerInput(nextProgramMaterialPaths) {
  programMaterialPaths = nextProgramMaterialPaths;
  flattenerInput = computeFlattenerInput(programMaterialPaths);
  inputHash = flattenerInput.inputSha256;
  sharedCachePath = join(sharedInventoryCacheDir, `${inputHash}.${inventoryCacheSuffix}.gz`);
  sharedInventoryCachePath = join(sharedInventoryCacheDir, `${inputHash}.inventory.json.gz`);
}

function inventorySnapshotMetadata(output, inventoryFunctions) {
  const outputHash = inventoryOutputHash(output);
  if (outputHash === undefined || !outputHashIsValid(output)) {
    throw new Error("Cannot publish a Convex API inventory with an invalid generated output.");
  }
  return {
    functions: inventoryFunctions.map(
      ({ entryPath, exportName, kind, modulePath, visibility }) => ({
        entryPath,
        exportName,
        kind,
        modulePath,
        visibility,
      })
    ),
    inputSha256: inputHash,
    kind: routeInventoryOnly
      ? "convex-api-route-snapshot-inventory-v1"
      : "convex-generated-api-snapshot-inventory-v3",
    materialIdentity: flattenerInput.identity,
    outputSha256: outputHash,
    programMaterialPaths: [...programMaterialPaths],
  };
}

function ensurePrivateInventoryDirectory(path) {
  try {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) {
      throw error;
    }
  }
  const status = lstatSync(path);
  if (
    !status.isDirectory() ||
    status.isSymbolicLink() ||
    (status.mode & 0o777) !== 0o700 ||
    (typeof process.getuid === "function" && status.uid !== process.getuid())
  ) {
    throw new Error(`Convex API inventory directory is not private: ${path}`);
  }
}

function validatePrivateInventorySnapshot(path) {
  ensurePrivateInventoryDirectory(path);
  const expectedNames = ["COMPLETE", inventoryArtifactName, "inventory.json"];
  if (JSON.stringify(readdirSync(path).sort(compareStrings)) !== JSON.stringify(expectedNames)) {
    throw new Error(`Convex API inventory snapshot has invalid files: ${path}`);
  }
  for (const name of expectedNames) {
    const filePath = join(path, name);
    const status = lstatSync(filePath);
    if (
      !status.isFile() ||
      status.isSymbolicLink() ||
      (status.mode & 0o777) !== 0o600 ||
      (typeof process.getuid === "function" && status.uid !== process.getuid())
    ) {
      throw new Error(`Convex API inventory snapshot file is not private: ${filePath}`);
    }
  }
}

async function publishInventorySnapshot(output, metadata) {
  const inventoryRoot = resolve(rootDir, inventorySnapshotRoot);
  const versionRoot = join(inventoryRoot, inventoryVersion);
  const parent = join(versionRoot, "snapshots");
  for (const path of [inventoryRoot, versionRoot, parent]) {
    ensurePrivateInventoryDirectory(path);
  }
  const finalPath = join(parent, inputHash);
  validateConvexApiCachedInventory({
    expectedEntryPathByModulePath: inventoryEntryPathByModulePath,
    expectedInput: flattenerInput,
    expectedOutputSha256: metadata.outputSha256,
    inventory: metadata,
    output,
    routeInventoryOnly,
    ts,
  });
  const temporaryPath = `${finalPath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  let cache = "miss";
  mkdirSync(temporaryPath, { mode: 0o700 });
  try {
    writeFileSync(join(temporaryPath, inventoryArtifactName), output, { mode: 0o600 });
    writeFileSync(join(temporaryPath, "inventory.json"), `${JSON.stringify(metadata)}\n`, {
      mode: 0o600,
    });
    writeFileSync(join(temporaryPath, "COMPLETE"), `${inputHash}\n`, { mode: 0o600 });
    for (const name of [inventoryArtifactName, "inventory.json", "COMPLETE"]) {
      const descriptor = openSync(join(temporaryPath, name), "r");
      try {
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
    }
    const temporaryDescriptor = openSync(temporaryPath, "r");
    try {
      fsyncSync(temporaryDescriptor);
    } finally {
      closeSync(temporaryDescriptor);
    }
    // Snapshot rename is the inventory authority commit point. Verify the product's inputs after
    // scratch durability and immediately before rename; earlier cache writes cannot authorize it.
    await verifyInputsAtPublication({
      expectedInputSha256: inputHash,
      expectedInstalledMaterialIdentity: flattenerInput.identity.installedMaterialIdentity,
      materialPaths: [...compilerMaterialPaths, ...programMaterialPaths],
    });
    try {
      renameSync(temporaryPath, finalPath);
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error.code === "EEXIST" || error.code === "ENOTEMPTY")
        )
      ) {
        throw error;
      }
      validatePrivateInventorySnapshot(finalPath);
      const concurrentMetadata = JSON.parse(
        readFileSync(join(finalPath, "inventory.json"), "utf8")
      );
      const concurrentOutput = readFileSync(join(finalPath, inventoryArtifactName), "utf8");
      if (
        readFileSync(join(finalPath, "COMPLETE"), "utf8") !== `${inputHash}\n` ||
        concurrentOutput !== output
      ) {
        throw new Error(`Concurrent flattened API inventory snapshot is corrupt: ${finalPath}`);
      }
      try {
        validateConvexApiCachedInventory({
          expectedEntryPathByModulePath: inventoryEntryPathByModulePath,
          expectedInput: flattenerInput,
          expectedOutputSha256: metadata.outputSha256,
          inventory: concurrentMetadata,
          output: concurrentOutput,
          routeInventoryOnly,
          ts,
        });
      } catch (validationError) {
        throw new Error(`Concurrent flattened API inventory snapshot is corrupt: ${finalPath}`, {
          cause: validationError,
        });
      }
      cache = "hit";
    }
    const parentDescriptor = openSync(parent, "r");
    try {
      fsyncSync(parentDescriptor);
    } finally {
      closeSync(parentDescriptor);
    }
  } finally {
    rmSync(temporaryPath, { recursive: true, force: true });
  }
  return { cache, path: finalPath };
}

function reportInventorySnapshot(publication, metadata, generatorCache) {
  const inventorySha256 = createHash("sha256")
    .update(`${JSON.stringify(metadata)}\n`)
    .digest("hex");
  process.stdout.write(
    `${JSON.stringify({
      cache: publication.cache,
      generatorCache,
      inputSha256: metadata.inputSha256,
      inventorySha256,
      kind: routeInventoryOnly
        ? "convex-api-route-snapshot-result-v1"
        : "convex-generated-api-snapshot-result-v3",
      outputSha256: metadata.outputSha256,
      snapshotPath: publication.path,
    })}\n`
  );
}

// Keep the source hash outside the generated declaration so implementation-only
// edits can reuse the declaration without invalidating every TypeScript project.
function inventoryOutputHash(output) {
  return routeInventoryOnly
    ? createHash("sha256").update(output).digest("hex")
    : output.match(outputHashPattern)?.[1];
}

function outputHashIsValid(output) {
  if (routeInventoryOnly) {
    // The route cache validator checks the exact canonical artifact against native-discovered
    // metadata. Unlike declarations, this artifact has no embedded self-hash.
    return output === convexApiRouteOutput(JSON.parse(output).functions);
  }
  const cachedOutputHash = output.match(outputHashPattern)?.[1];
  if (cachedOutputHash === undefined) {
    return false;
  }
  const normalized = output.replace(
    outputHashPattern,
    ` * Output hash: ${outputHashPlaceholder}\n`
  );
  return createHash("sha256").update(normalized).digest("hex") === cachedOutputHash;
}

function exitForConcurrentSourceChange() {
  console.error("Convex API inputs changed during generation; rerun after source changes settle.");
  process.exit(sourceChangedExitCode);
}

function isConcurrentInputError(error) {
  return (
    error instanceof Error &&
    (("code" in error && (error.code === "ENOENT" || error.code === "ENOTDIR")) ||
      /changed while it was/u.test(error.message) ||
      /changed before projection/u.test(error.message) ||
      /is not a regular file/u.test(error.message) ||
      /source discovery does not support symbolic links/u.test(error.message) ||
      /source discovery requires a real directory/u.test(error.message))
  );
}

function readSourceFileForAnalysis(path) {
  const authenticatedSource = authenticatedRepositorySource(path);
  if (authenticatedSource !== undefined) {
    return authenticatedSource;
  }
  try {
    // Candidate discovery can run after a retained staged-manifest hit, when no projection read
    // supplied bytes for this path. Keep that fallback under the same descriptor/path-state
    // boundary as initial input capture so a replacement cannot feed a partial source file into
    // the TypeScript AST. Final publication still performs its complete fresh scan.
    return convexApiReadStableFile(path, "Convex API source analysis input").toString("utf8");
  } catch (error) {
    if (isConcurrentInputError(error)) {
      exitForConcurrentSourceChange();
    }
    throw error;
  }
}

function readGeneratedApiIfPresent() {
  try {
    return convexApiReadStableFile(apiPath, "Flattened Convex API output").toString("utf8");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

function writeGeneratedApi(output) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    throw new Error("Flattened Convex API output requires O_NOFOLLOW.");
  }
  // Keep the final component bound to the opened descriptor. A replaced API symlink must not
  // redirect --write into an arbitrary path between the final authority check and publication.
  const descriptor = openSync(
    apiPath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    0o644
  );
  try {
    const opened = fstatSync(descriptor);
    if (
      !opened.isFile() ||
      opened.nlink !== 1 ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())
    ) {
      throw new Error(`Flattened Convex API output is not an owner-bound regular file: ${apiPath}`);
    }
    ftruncateSync(descriptor, 0);
    writeFileSync(descriptor, output);
  } finally {
    closeSync(descriptor);
  }
}

async function useSharedCacheIfPresent() {
  if (inputHash === undefined) {
    return false;
  }
  try {
    const cachedOutput = gunzipSync(
      readPrivateCacheFile(sharedCachePath, "Shared flattened API cache", compressedCacheMaxBytes),
      { maxOutputLength: expandedCacheMaxBytes }
    ).toString();
    let metadata;
    try {
      metadata = JSON.parse(
        gunzipSync(
          readPrivateCacheFile(
            sharedInventoryCachePath,
            "Shared flattened API inventory cache",
            compressedCacheMaxBytes
          ),
          { maxOutputLength: expandedCacheMaxBytes }
        ).toString()
      );
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        (error.code === "ENOENT" || error.code === "ENOTDIR")
      ) {
        throw error;
      }
      throw new Error(
        `Shared flattened API inventory cache is corrupt: ${sharedInventoryCachePath}`,
        {
          cause: error,
        }
      );
    }
    if (!outputHashIsValid(cachedOutput)) {
      throw new Error(`Shared flattened API cache is corrupt: ${sharedCachePath}`);
    }
    const outputSha256 = inventoryOutputHash(cachedOutput);
    try {
      validateConvexApiCachedInventory({
        expectedEntryPathByModulePath: inventoryEntryPathByModulePath,
        expectedInput: flattenerInput,
        expectedOutputSha256: outputSha256,
        inventory: metadata,
        output: cachedOutput,
        routeInventoryOnly,
        ts: await loadTypeScript(),
      });
    } catch (error) {
      throw new Error(
        `Shared flattened API inventory cache is corrupt: ${sharedInventoryCachePath}`,
        {
          cause: error,
        }
      );
    }
    if (gitSourceSnapshot !== undefined && pendingStagedSurfaceManifest === undefined) {
      // Exact hits precede the surface lookup. Still advance the retained staged records after a
      // successful command so a reverted or mode-only staged change is not reread on every run.
      await loadTypeScript();
      computeRepositorySurfaceHash();
    }
    if (inventorySnapshotMode) {
      const publication = await publishInventorySnapshot(cachedOutput, metadata);
      publishPendingStagedSurfaceManifest();
      reportInventorySnapshot(publication, metadata, "hit");
      console.error("Published cached flattened Convex API inventory.");
      return true;
    }
    await verifyInputsAtPublication({
      expectedInputSha256: inputHash,
      expectedInstalledMaterialIdentity: flattenerInput.identity.installedMaterialIdentity,
      materialPaths: [...compilerMaterialPaths, ...programMaterialPaths],
    });
    const currentApi = readGeneratedApiIfPresent();
    if (mode === "--check" && currentApi !== cachedOutput) {
      throw new Error(
        `${apiRelativePath} is stale. Regenerate and stage the Convex API declaration.`
      );
    }
    if (mode === "--write" && currentApi !== cachedOutput) {
      writeGeneratedApi(cachedOutput);
      console.error("Restored the flattened Convex API from the shared cache.");
    } else {
      console.error("Flattened Convex API is current.");
    }
    publishPendingStagedSurfaceManifest();
    return true;
  } catch (error) {
    if (
      !(
        error instanceof Error &&
        "code" in error &&
        (error.code === "ENOENT" || error.code === "ENOTDIR")
      )
    ) {
      throw error;
    }
    return false;
  }
}

if (await useSharedCacheIfPresent()) {
  process.exit(0);
}
await loadTypeScript();

const repositorySurfaceSha256 = combinedRepositoryInputHash(computeRepositorySurfaceHash());
const fastReuseIdentity =
  repositorySurfaceSha256 === undefined
    ? undefined
    : convexApiFastReuseIdentity({
        configPath: relativeUserConfigPath,
        installedLayoutSha256: materialIndexIdentity.installedLayoutSha256,
        repositorySurfaceSha256,
      });
const fastReuseIndexPath =
  fastReuseIdentity === undefined
    ? undefined
    : join(
        sharedCacheDir,
        routeInventoryOnly ? "route-fast-reuse-index-v1" : "fast-reuse-index",
        `${convexApiFastReuseKey(fastReuseIdentity)}.json`
      );

function readFastReuseIndex() {
  if (fastReuseIndexPath === undefined) {
    return undefined;
  }
  let parsed;
  try {
    parsed = JSON.parse(
      readPrivateCacheFile(
        fastReuseIndexPath,
        "Convex API fast reuse index",
        privateJsonCacheMaxBytes
      ).toString("utf8")
    );
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return undefined;
    }
    throw new Error(`Convex API fast reuse index is corrupt: ${fastReuseIndexPath}`, {
      cause: error,
    });
  }
  try {
    return validateConvexApiFastReuseIndex(parsed, fastReuseIdentity);
  } catch (error) {
    throw new Error(`Convex API fast reuse index is corrupt: ${fastReuseIndexPath}`, {
      cause: error,
    });
  }
}

function readFastReuseCacheFile(path, description) {
  try {
    return gunzipSync(readPrivateCacheFile(path, description, compressedCacheMaxBytes), {
      maxOutputLength: expandedCacheMaxBytes,
    }).toString();
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return undefined;
    }
    throw new Error(`${description} is corrupt or missing: ${path}`, { cause: error });
  }
}

async function useFastReuseIfPresent() {
  const index = readFastReuseIndex();
  if (index === undefined) {
    return false;
  }

  const cachedOutputPath = join(
    sharedInventoryCacheDir,
    `${index.inputSha256}.${inventoryCacheSuffix}.gz`
  );
  const cachedInventoryPath = join(
    sharedInventoryCacheDir,
    `${index.inputSha256}.inventory.json.gz`
  );
  const cachedOutput = readFastReuseCacheFile(
    cachedOutputPath,
    "Shared flattened API fast reuse output"
  );
  if (cachedOutput === undefined) {
    return false;
  }
  if (
    !outputHashIsValid(cachedOutput) ||
    inventoryOutputHash(cachedOutput) !== index.outputSha256
  ) {
    throw new Error(`Shared flattened API fast reuse output is corrupt: ${cachedOutputPath}`);
  }
  let cachedInventory;
  try {
    const cachedInventorySource = readFastReuseCacheFile(
      cachedInventoryPath,
      "Shared flattened API fast reuse inventory"
    );
    if (cachedInventorySource === undefined) {
      return false;
    }
    cachedInventory = JSON.parse(cachedInventorySource);
  } catch (error) {
    throw new Error(
      `Shared flattened API fast reuse inventory is corrupt: ${cachedInventoryPath}`,
      {
        cause: error,
      }
    );
  }
  const cachedMaterialIdentity = cachedInventory?.materialIdentity;
  if (
    typeof cachedMaterialIdentity !== "object" ||
    cachedMaterialIdentity === null ||
    Array.isArray(cachedMaterialIdentity) ||
    typeof cachedMaterialIdentity.repositoryInputSha256 !== "string" ||
    cachedMaterialIdentity.configPath !== relativeUserConfigPath
  ) {
    throw new Error(`Shared flattened API fast reuse inventory is corrupt: ${cachedInventoryPath}`);
  }
  const cachedExactInput = convexApiFlattenerInputIdentity({
    configPath: cachedMaterialIdentity.configPath,
    installedMaterialIdentity: cachedMaterialIdentity.installedMaterialIdentity,
    repositoryInputSha256: cachedMaterialIdentity.repositoryInputSha256,
  });
  if (cachedExactInput.inputSha256 !== index.inputSha256) {
    throw new Error(
      `Convex API fast reuse index points to the wrong exact input: ${fastReuseIndexPath}`
    );
  }
  try {
    validateConvexApiCachedInventory({
      expectedEntryPathByModulePath: inventoryEntryPathByModulePath,
      expectedInput: cachedExactInput,
      expectedOutputSha256: index.outputSha256,
      inventory: cachedInventory,
      output: cachedOutput,
      routeInventoryOnly,
      ts,
    });
  } catch (error) {
    throw new Error(
      `Shared flattened API fast reuse inventory is corrupt: ${cachedInventoryPath}`,
      {
        cause: error,
      }
    );
  }

  let currentInstalledMaterialIdentity;
  try {
    currentInstalledMaterialIdentity = convexApiInstalledMaterialIdentity({
      materialPaths: [...compilerMaterialPaths, ...index.programMaterialPaths],
      nodeModulesRoot: resolve(rootDir, "node_modules"),
    });
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return false;
    }
    throw error;
  }
  if (
    JSON.stringify(currentInstalledMaterialIdentity) !==
    JSON.stringify(cachedMaterialIdentity.installedMaterialIdentity)
  ) {
    return false;
  }
  programMaterialPaths = index.programMaterialPaths;
  if (inventorySnapshotMode) {
    // The surface match proves that the function inventory and flattened declaration are
    // unchanged. Rebind those semantic outputs to the current exact repository/program material
    // identity; downstream graph authority still authenticates every physical source input.
    setFlattenerInput(index.programMaterialPaths);
    if (
      JSON.stringify(flattenerInput.identity.installedMaterialIdentity) !==
      JSON.stringify(currentInstalledMaterialIdentity)
    ) {
      throw new Error(
        "Convex API fast reuse changed installed material while rebinding inventory."
      );
    }
  } else {
    await verifyInputsAtPublication({
      expectedInstalledMaterialIdentity: currentInstalledMaterialIdentity,
      materialPaths: [...compilerMaterialPaths, ...index.programMaterialPaths],
    });
  }
  if (inventorySnapshotMode) {
    const metadata = inventorySnapshotMetadata(cachedOutput, cachedInventory.functions);
    publishSharedInventoryCache(cachedOutput, metadata);
    writeMaterialIndex(programMaterialPaths);
    writeFastReuseIndex(metadata.outputSha256);
    const publication = await publishInventorySnapshot(cachedOutput, metadata);
    publishPendingStagedSurfaceManifest();
    reportInventorySnapshot(publication, metadata, "hit");
    console.error("Published implementation-safe flattened Convex API inventory.");
    return true;
  }
  // The fast-reuse index is sufficient to recover the native program material after a stale or
  // missing material index. Persist that recovered path set for the next exact-cache admission;
  // this does not grant reuse authority until the final physical scan above has completed.
  writeMaterialIndex(programMaterialPaths);
  const currentApi = readGeneratedApiIfPresent();
  if (mode === "--check" && currentApi !== cachedOutput) {
    throw new Error(
      `${apiRelativePath} is stale. Regenerate and stage the Convex API declaration.`
    );
  }
  if (mode === "--write" && currentApi !== cachedOutput) {
    writeGeneratedApi(cachedOutput);
    console.error("Restored the flattened Convex API from the implementation-safe cache.");
  } else {
    console.error("Flattened Convex API is current after an implementation-only edit.");
  }
  publishPendingStagedSurfaceManifest();
  return true;
}

function writeFastReuseIndex(outputSha256) {
  if (fastReuseIndexPath === undefined) {
    return;
  }
  writePrivateJsonCacheFile(fastReuseIndexPath, {
    identity: fastReuseIdentity,
    inputSha256: inputHash,
    kind: "convex-api-fast-reuse-index-v3",
    outputSha256,
    programMaterialPaths,
  });
}

function publishSharedInventoryCache(output, metadata) {
  ensurePrivateCacheDirectory(sharedInventoryCacheDir);
  validateConvexApiCachedInventory({
    expectedEntryPathByModulePath: inventoryEntryPathByModulePath,
    expectedInput: flattenerInput,
    expectedOutputSha256: metadata.outputSha256,
    inventory: metadata,
    output,
    routeInventoryOnly,
    ts,
  });
  const temporarySuffix = `${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const temporaryCachePath = `${sharedCachePath}.${temporarySuffix}`;
  const temporaryInventoryCachePath = `${sharedInventoryCachePath}.${temporarySuffix}`;
  const inventorySource = `${JSON.stringify(metadata)}\n`;
  if (
    Buffer.byteLength(output) > expandedCacheMaxBytes ||
    Buffer.byteLength(inventorySource) > expandedCacheMaxBytes
  ) {
    throw new Error("Shared flattened API cache exceeds its expanded byte boundary.");
  }
  const compressedOutput = gzipSync(output);
  const compressedInventory = gzipSync(inventorySource);
  if (
    compressedOutput.length > compressedCacheMaxBytes ||
    compressedInventory.length > compressedCacheMaxBytes
  ) {
    throw new Error("Shared flattened API cache exceeds its compressed byte boundary.");
  }
  try {
    writeFileSync(temporaryCachePath, compressedOutput, { flag: "wx", mode: 0o600 });
    writeFileSync(temporaryInventoryCachePath, compressedInventory, {
      flag: "wx",
      mode: 0o600,
    });
    for (const path of [temporaryCachePath, temporaryInventoryCachePath]) {
      const descriptor = openSync(path, "r");
      try {
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
    }
    renameSync(temporaryCachePath, sharedCachePath);
    renameSync(temporaryInventoryCachePath, sharedInventoryCachePath);
    const directoryDescriptor = openSync(sharedInventoryCacheDir, "r");
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
  } finally {
    rmSync(temporaryCachePath, { force: true });
    rmSync(temporaryInventoryCachePath, { force: true });
  }
}

if (await useFastReuseIfPresent()) {
  process.exit(0);
}
if (await useSharedCacheIfPresent()) {
  process.exit(0);
}
if (await useFastReuseIfPresent()) {
  process.exit(0);
}
const {
  API: NativeTypeScriptAPI,
  ModifierFlags: NativeModifierFlags,
  NodeBuilderFlags: NativeNodeBuilderFlags,
  SignatureKind: NativeSignatureKind,
  SymbolFlags: NativeSymbolFlags,
  TypeFlags: NativeTypeFlags,
} = await import(projectRequire.resolve("typescript-native/unstable/sync"));
if (convexTypeScriptInputPaths.includes(componentConfigPath)) {
  const retainedComponentConfigSource = authenticatedRepositorySource(componentConfigPath);
  if (retainedComponentConfigSource === undefined) {
    throw new Error("Convex API component configuration is missing from repository input material.");
  }
  const componentConfigSource = ts.createSourceFile(
    componentConfigPath,
    retainedComponentConfigSource,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS
  );
  sourceFileCache.set(componentConfigPath, componentConfigSource);
  let usesComponents = false;
  function findComponentUse(node) {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === "app" &&
      node.expression.name.text === "use"
    ) {
      usesComponents = true;
      return;
    }
    node.forEachChild(findComponentUse);
  }
  findComponentUse(componentConfigSource);
  if (usesComponents) {
    throw new Error(
      "Flattened Convex API generation does not yet support app.use(...) components. Add explicit component type generation before enabling a component."
    );
  }
}
let analysisApi;
if (routeInventoryOnly) {
  // Route identity observes the captured declaration's types. Regenerating the API here
  // would infer handler argument/return contracts that the route product does not consume.
  analysisApi = routeApiSource;
  if (analysisApi === undefined) {
    throw new Error("Convex API route declaration is missing from repository input material.");
  }
} else {
  const virtualImports = [];
  const fullApiEntries = [];
  for (const [index, sourcePath] of convexSourcePaths.entries()) {
    const identifier = `_convex${index}`;
    const specifier = importPathForSource(sourcePath, dirname(apiPath));
    virtualImports.push(`import type * as ${identifier} from ${JSON.stringify(specifier)};`);
    fullApiEntries.push(`  ${JSON.stringify(convexModulePath(sourcePath))}: typeof ${identifier};`);
  }

  // Declaration generation infers fresh handler returns even when the staged API is stale.
  analysisApi = `
${virtualImports.join("\n")}
import type { ApiFromModules, FilterApi, FunctionReference } from "convex/server";
declare const fullApi: ApiFromModules<{
${fullApiEntries.join("\n")}
}>;
export declare const api: FilterApi<typeof fullApi, FunctionReference<any, "public">>;
export declare const internal: FilterApi<typeof fullApi, FunctionReference<any, "internal">>;
export declare const components: {};
`;
}

function hasExportModifier(node) {
  return ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
}

function addBindingCandidates(candidates, sourcePath, sourceFile, declaration, name) {
  if (ts.isIdentifier(name)) {
    candidates.push({
      declaration,
      exportName: name.text,
      position: name.getStart(sourceFile),
      sourceFile,
      sourcePath,
    });
    return;
  }
  for (const element of name.elements) {
    if (!ts.isOmittedExpression(element)) {
      addBindingCandidates(candidates, sourcePath, sourceFile, element, element.name);
    }
  }
}

const readonlyPropertyNamesBySourcePath = new Map();

function collectReadonlyPropertyNames(sourceFile) {
  const names = new Set();
  function visit(node) {
    if (
      ts.canHaveModifiers(node) &&
      ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ReadonlyKeyword) ===
        true &&
      "name" in node
    ) {
      const { name } = node;
      if (
        name !== undefined &&
        (ts.isIdentifier(name) || ts.isPrivateIdentifier(name) || ts.isLiteralExpression(name))
      ) {
        names.add(name.text);
      }
    }
    node.forEachChild(visit);
  }
  visit(sourceFile);
  return names;
}

function sourceMayDeclareReadonlyProperty(sourcePath, propertyName) {
  let names = readonlyPropertyNamesBySourcePath.get(sourcePath);
  if (names === undefined) {
    const retainedSourceFile = sourceFileCache.get(sourcePath);
    const sourceFile =
      retainedSourceFile ??
      (() => {
        const retainedSource = authenticatedRepositorySource(sourcePath);
        return ts.createSourceFile(
          sourcePath,
          retainedSource ?? readSourceFileForAnalysis(sourcePath),
          ts.ScriptTarget.Latest,
          true,
          sourcePath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
        );
      })();
    sourceFileCache.set(sourcePath, sourceFile);
    names = collectReadonlyPropertyNames(sourceFile);
    readonlyPropertyNamesBySourcePath.set(sourcePath, names);
  }
  return names.has(propertyName);
}

const exportedCandidatesBySource = new Map();
for (const sourcePath of convexSourcePaths) {
  const sourceFile =
    sourceFileCache.get(sourcePath) ??
    ts.createSourceFile(
      sourcePath,
      readSourceFileForAnalysis(sourcePath),
      ts.ScriptTarget.Latest,
      true,
      sourcePath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    );
  sourceFileCache.set(sourcePath, sourceFile);
  if (!routeInventoryOnly) {
    readonlyPropertyNamesBySourcePath.set(sourcePath, collectReadonlyPropertyNames(sourceFile));
  }
  const candidates = [];
  for (const statement of sourceFile.statements) {
    if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        addBindingCandidates(candidates, sourcePath, sourceFile, declaration, declaration.name);
      }
      continue;
    }
    if (ts.isExportDeclaration(statement)) {
      if (statement.exportClause === undefined) {
        throw new Error(
          `Wildcard exports are not supported in Convex modules because they could hide a registered function at ${sourceLocation(statement)}.`
        );
      }
      if (ts.isNamedExports(statement.exportClause)) {
        for (const element of statement.exportClause.elements) {
          if (!element.isTypeOnly) {
            candidates.push({
              declaration: element,
              exportName: element.name.text,
              position: element.name.getStart(sourceFile),
              sourceFile,
              sourcePath,
            });
          }
        }
      } else {
        candidates.push({
          declaration: statement.exportClause,
          exportName: statement.exportClause.name.text,
          position: statement.exportClause.name.getStart(sourceFile),
          sourceFile,
          sourcePath,
        });
      }
      continue;
    }
    if (ts.isExportAssignment(statement)) {
      candidates.push({
        declaration: statement,
        exportName: "default",
        position: statement.expression.getStart(sourceFile),
        sourceFile,
        sourcePath,
      });
    }
  }
  // Duplicate exported names are invalid ECMAScript even when both declarations refer to the
  // same local binding. Reject them here because native semantic diagnostics are not this
  // inventory pass's authority and the generated API tree cannot represent both declarations.
  const uniqueCandidatesByExport = new Map();
  for (const candidate of candidates) {
    const previous = uniqueCandidatesByExport.get(candidate.exportName);
    if (previous === undefined) {
      uniqueCandidatesByExport.set(candidate.exportName, candidate);
    } else {
      throw new Error(
        `Convex API source discovery found duplicate export ${candidate.exportName} at ${sourceLocation(candidate.declaration)}.`
      );
    }
  }
  exportedCandidatesBySource.set(sourcePath, [...uniqueCandidatesByExport.values()]);
}

ensurePrivateCacheDirectory(sharedCacheDir);
const declaredRepositoryInputPaths = new Set(
  inputPaths.map((path) => normalizePathForHostComparison(resolve(path)))
);
const nativeApi = new NativeTypeScriptAPI({
  collectTiming: profileGeneration,
  cwd: rootDir,
  fs: {
    readFile(fileName) {
      // A full semantic miss must infer from the same authenticated repository bytes captured
      // above; a transient worktree edit cannot be allowed to reach native TypeScript and then be
      // hidden by restoring the file before final publication verification.
      return pathsEqualForHost(resolve(rootDir, fileName), apiPath)
        ? analysisApi
        : authenticatedRepositorySource(fileName);
    },
  },
});
const snapshot = nativeApi.updateSnapshot({ openProject: configPath });
const project = snapshot.getProject(configPath);
if (project === undefined) {
  nativeApi.close();
  throw new Error(`Native TypeScript did not load ${toPosixPath(relative(rootDir, configPath))}.`);
}
const normalizedNodeModulesRoot = normalizePathForHostComparison(resolve(rootDir, "node_modules"));
const programSourceFileNames = project.program
  .getSourceFileNames()
  .map((path) => resolve(rootDir, path));
const unexpectedRepositoryProgramPaths = programSourceFileNames
  .filter((path) => {
    const normalizedPath = normalizePathForHostComparison(path);
    return (
      !pathsEqualForHost(path, apiPath) &&
      !normalizedPath.startsWith(`${normalizedNodeModulesRoot}${sep}`) &&
      !declaredRepositoryInputPaths.has(normalizedPath)
    );
  })
  .sort(compareStrings);
if (unexpectedRepositoryProgramPaths.length > 0) {
  nativeApi.close();
  throw new Error(
    `Native TypeScript loaded repository inputs outside the Convex API material set: ${unexpectedRepositoryProgramPaths
      .map((path) => toPosixPath(relative(rootDir, path)))
      .join(", ")}`
  );
}
const resolvedProgramMaterialPaths = convexApiProgramMaterialPaths({
  nodeModulesRoot: resolve(rootDir, "node_modules"),
  sourceFileNames: programSourceFileNames,
});
const previousInputHash = inputHash;
setFlattenerInput(resolvedProgramMaterialPaths);
if (inputHash !== previousInputHash && (await useSharedCacheIfPresent())) {
  writeMaterialIndex(resolvedProgramMaterialPaths);
  nativeApi.close();
  process.exit(0);
}
const checker = project.checker;
const typePrintContext = project.program.getSourceFile(generatedServerPath);
if (typePrintContext === undefined) {
  nativeApi.close();
  throw new Error(
    `Native TypeScript did not load ${toPosixPath(relative(rootDir, generatedServerPath))}.`
  );
}

function trueProperty(type, propertyName) {
  const property = checker.getPropertyOfType(type, propertyName);
  if (property === undefined) {
    return false;
  }
  const propertyType = checker.getTypeOfSymbol(property);
  return (
    propertyType !== undefined &&
    (propertyType.flags & NativeTypeFlags.BooleanLiteral) !== 0 &&
    propertyType.value === true
  );
}

function registeredTypeParts(type, declaration) {
  if (type === undefined) {
    return null;
  }
  if (!trueProperty(type, "isConvexFunction")) {
    return null;
  }

  const kinds = [
    ["isQuery", "query"],
    ["isMutation", "mutation"],
    ["isAction", "action"],
  ].filter(([property]) => trueProperty(type, property));
  const visibilities = [
    ["isPublic", "public"],
    ["isInternal", "internal"],
  ].filter(([property]) => trueProperty(type, property));
  if (kinds.length !== 1 || visibilities.length !== 1) {
    throw new Error(
      `Cannot determine Convex function kind or visibility at ${sourceLocation(declaration)}.`
    );
  }

  const aliasSymbol = type.getAliasSymbol();
  const aliasName = aliasSymbol?.name;
  const expectedAlias = `Registered${kinds[0][1][0].toUpperCase()}${kinds[0][1].slice(1)}`;
  const aliasTypeArguments = type.getAliasTypeArguments();
  if (
    aliasName !== expectedAlias ||
    aliasTypeArguments.length !== 3 ||
    aliasSymbol.declarations.some((aliasDeclaration) =>
      convexApiPathsIdentifySameFile(String(aliasDeclaration.path), convexRegistrationPath)
    ) !== true
  ) {
    throw new Error(
      `Unsupported registered Convex function type ${aliasName ?? "<anonymous>"} at ${sourceLocation(declaration)}.`
    );
  }

  return {
    kind: kinds[0][1],
    visibility: visibilities[0][1],
    args: aliasTypeArguments[1],
    returns: aliasTypeArguments[2],
  };
}

function unwrapExpression(expression) {
  let current = expression;
  while (
    ts.isAsExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isParenthesizedExpression(current) ||
    ts.isNonNullExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function validateRegistrationShape(candidate, parts) {
  const { declaration, exportName, sourcePath } = candidate;
  if (ts.isVariableDeclaration(declaration) && declaration.initializer !== undefined) {
    const initializer = unwrapExpression(declaration.initializer);
    if (ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression)) {
      const builder = directBuilders.get(initializer.expression.text);
      if (builder === undefined) {
        throw new Error(
          `Unsupported Convex function builder ${initializer.expression.text} for ${exportName} at ${sourceLocation(declaration)}.`
        );
      }
      if (builder.kind !== parts.kind || builder.visibility !== parts.visibility) {
        throw new Error(
          `Builder ${initializer.expression.text} disagrees with the inferred Convex function type at ${sourceLocation(declaration)}.`
        );
      }
      const calledSymbol = checker.getSymbolAtPosition(
        sourcePath,
        initializer.expression.getStart(candidate.sourceFile)
      );
      const resolvedCalledSymbol =
        calledSymbol !== undefined && (calledSymbol.flags & NativeSymbolFlags.Alias) !== 0
          ? checker.getAliasedSymbol(calledSymbol)
          : calledSymbol;
      if (
        resolvedCalledSymbol?.declarations.some((builderDeclaration) =>
          pathsEqualForHost(resolve(builderDeclaration.path), builder.sourcePath)
        ) !== true
      ) {
        throw new Error(
          `Builder ${initializer.expression.text} for ${exportName} at ${sourceLocation(declaration)} does not resolve to the supported repository builder.`
        );
      }
      return;
    }
  }

  if (
    generatedRegistryAdapter !== undefined &&
    pathsEqualForHost(
      resolve(declaration.getSourceFile().fileName),
      generatedRegistryAdapter.generatedModulePath
    ) &&
    ts.isBindingElement(declaration) &&
    ts.isObjectBindingPattern(declaration.parent) &&
    ts.isVariableDeclaration(declaration.parent.parent) &&
    declaration.parent.parent.initializer !== undefined &&
    ts.isIdentifier(declaration.parent.parent.initializer) &&
    declaration.parent.parent.initializer.text === generatedRegistryAdapter.runtimeIdentifier &&
    generatedRegistryAdapter.expectedRegisteredExports.has(exportName)
  ) {
    // The configured generated registry adapter permits its generated registry destructure.
    // All other registered exports must use one of the explicit builders above.
    return;
  }

  throw new Error(
    `Registered Convex export ${exportName} at ${sourceLocation(declaration)} is not a supported direct builder call.`
  );
}

const nodeBuilderFlags =
  NativeNodeBuilderFlags.NoTruncation |
  NativeNodeBuilderFlags.WriteArrayAsGenericType |
  NativeNodeBuilderFlags.GenerateNamesForShadowedTypeParams |
  NativeNodeBuilderFlags.UseStructuralFallback |
  NativeNodeBuilderFlags.WriteTypeArgumentsOfSignature |
  NativeNodeBuilderFlags.UseFullyQualifiedType |
  NativeNodeBuilderFlags.MultilineObjectLiterals |
  NativeNodeBuilderFlags.InTypeAlias |
  NativeNodeBuilderFlags.AllowNodeModulesRelativePaths;
const readonlyCheckFlag = 8;
const serializedTypeCache = new Map();

function primitiveTypeText(type) {
  if (type.flags & NativeTypeFlags.Any) return "any";
  if (type.flags & NativeTypeFlags.Unknown) return "unknown";
  if (type.flags & NativeTypeFlags.Never) return "never";
  if (type.flags & NativeTypeFlags.Void) return "void";
  if (type.flags & NativeTypeFlags.Undefined) return "undefined";
  if (type.flags & NativeTypeFlags.Null) return "null";
  if (type.flags & NativeTypeFlags.String) return "string";
  if (type.flags & NativeTypeFlags.Number) return "number";
  if (type.flags & NativeTypeFlags.Boolean) return "boolean";
  if (type.flags & NativeTypeFlags.BigInt) return "bigint";
  if (type.flags & NativeTypeFlags.ESSymbol) return "symbol";
  if (type.flags & NativeTypeFlags.StringLiteral) return JSON.stringify(type.value);
  if (type.flags & NativeTypeFlags.NumberLiteral) return String(type.value);
  if (type.flags & NativeTypeFlags.BooleanLiteral) return String(type.value);
  if (type.flags & NativeTypeFlags.BigIntLiteral) return `${type.value}n`;
  return null;
}

function emittedTypeText(type) {
  return checker.typeToString(type, typePrintContext, nodeBuilderFlags);
}

function referencesLocalSource(text) {
  return (
    /\b_(?:convex|shared)\d+\b/u.test(text) ||
    /import\(["']\.{1,2}\//u.test(text) ||
    /import\(["'](?:\/|[A-Za-z]:[\\/])/u.test(text)
  );
}

function propertyIsReadonly(property) {
  if ((property.checkFlags & readonlyCheckFlag) !== 0) {
    return true;
  }
  return (
    property.declarations?.some(
      (declaration) =>
        sourceMayDeclareReadonlyProperty(declaration.path, property.name) &&
        ((declaration.resolve()?.modifierFlags ?? NativeModifierFlags.None) &
          NativeModifierFlags.Readonly) !==
          0
    ) === true
  );
}

function serializeTuple(type, declaration, exportName, partName, active) {
  const target = type.getTarget();
  const elements = checker.getTypeArguments(type);
  const elementFlags = target.elementFlags ?? [];
  const values = elements.map((element, index) => {
    const flag = elementFlags[index] ?? ts.ElementFlags.Required;
    const elementText = serializeType(element, declaration, exportName, partName, active);
    if ((flag & (ts.ElementFlags.Rest | ts.ElementFlags.Variadic)) !== 0) {
      return `...Array<${elementText}>`;
    }
    if ((flag & ts.ElementFlags.Optional) !== 0) {
      return `(${elementText})?`;
    }
    return elementText;
  });
  return `${target.readonly === true ? "readonly " : ""}[${values.join(", ")}]`;
}

function serializeObject(type, declaration, exportName, partName, active) {
  const callSignatures = checker.getSignaturesOfType(type, NativeSignatureKind.Call);
  const constructSignatures = checker.getSignaturesOfType(type, NativeSignatureKind.Construct);
  if (callSignatures.length > 0 || constructSignatures.length > 0) {
    throw new Error(
      `The ${partName} type for ${exportName} at ${sourceLocation(declaration)} contains a local callable or constructable type (${emittedTypeText(type)}). Move that API contract to a standalone exported data type.`
    );
  }

  const members = [];
  const properties = checker.getPropertiesOfType(type);
  const propertyTypes = checker.getTypeOfSymbol(properties);
  for (const [index, property] of properties.entries()) {
    const propertyType = propertyTypes[index];
    if (propertyType === undefined) {
      throw new Error(
        `Native TypeScript did not resolve property ${property.name} in the ${partName} type for ${exportName} at ${sourceLocation(declaration)}.`
      );
    }
    if (property.name.startsWith("__@")) {
      throw new Error(
        `The ${partName} type for ${exportName} at ${sourceLocation(declaration)} contains symbol property ${property.name}.`
      );
    }
    const propertyText = serializeType(propertyType, declaration, exportName, partName, active);
    const readonly = propertyIsReadonly(property) ? "readonly " : "";
    const optional = (property.flags & NativeSymbolFlags.Optional) !== 0 ? "?" : "";
    members.push(`${readonly}${JSON.stringify(property.name)}${optional}: ${propertyText};`);
  }

  for (const indexInfo of checker.getIndexInfosOfType(type)) {
    const key = primitiveTypeText(indexInfo.keyType);
    if (key !== "string" && key !== "number" && key !== "symbol") {
      throw new Error(
        `The ${partName} type for ${exportName} at ${sourceLocation(declaration)} has an unsupported index key type.`
      );
    }
    const value = serializeType(indexInfo.valueType, declaration, exportName, partName, active);
    members.push(`${indexInfo.isReadonly ? "readonly " : ""}[key: ${key}]: ${value};`);
  }

  if (members.length === 0) {
    return "{}";
  }
  return `{ ${members.join(" ")} }`;
}

function serializeType(type, declaration, exportName, partName, active = new Set()) {
  const cached = serializedTypeCache.get(type);
  if (cached !== undefined) {
    return cached;
  }

  const primitive = primitiveTypeText(type);
  if (primitive !== null) {
    serializedTypeCache.set(type, primitive);
    return primitive;
  }

  const emitted = emittedTypeText(type);
  if (!referencesLocalSource(emitted)) {
    serializedTypeCache.set(type, emitted);
    return emitted;
  }

  if (active.has(type)) {
    throw new Error(
      `The ${partName} type for ${exportName} at ${sourceLocation(declaration)} contains a recursive local type. Move it to a standalone API contract module or make the returned shape non-recursive.`
    );
  }
  active.add(type);

  // TypeScript normally preserves exported aliases as imports. Expand local
  // data shapes so consumers do not load the backend modules that own them.
  let text;
  if (type.isUnionType()) {
    text = type
      .getTypes()
      .map((member) => serializeType(member, declaration, exportName, partName, active))
      .join(" | ");
  } else if (type.isIntersectionType()) {
    text = type
      .getTypes()
      .map((member) => serializeType(member, declaration, exportName, partName, active))
      .join(" & ");
  } else if (type.isObjectType()) {
    if (checker.isTupleType(type)) {
      text = serializeTuple(type, declaration, exportName, partName, active);
    } else if (type.isTypeReference()) {
      const targetName = type.getTarget().getSymbol()?.name;
      const typeArguments = checker.getTypeArguments(type);
      if (
        (targetName === "Array" || targetName === "ReadonlyArray" || targetName === "Promise") &&
        typeArguments.length === 1
      ) {
        const argument = serializeType(typeArguments[0], declaration, exportName, partName, active);
        text = `${targetName}<${argument}>`;
      } else {
        text = serializeObject(type, declaration, exportName, partName, active);
      }
    } else {
      text = serializeObject(type, declaration, exportName, partName, active);
    }
  } else {
    throw new Error(
      `Cannot flatten ${partName} type for ${exportName} at ${sourceLocation(declaration)}. TypeScript emitted ${emitted}. Move this contract to a standalone exported data type.`
    );
  }

  active.delete(type);
  serializedTypeCache.set(type, text);
  return text;
}

const functions = [];
for (const sourcePath of convexSourcePaths) {
  const candidates = exportedCandidatesBySource.get(sourcePath);
  if (candidates === undefined || candidates.length === 0) {
    continue;
  }
  const types = checker.getTypeAtPosition(
    sourcePath,
    candidates.map((candidate) => candidate.position)
  );
  for (const [index, candidate] of candidates.entries()) {
    const { declaration, exportName } = candidate;
    const type = types[index];
    const directInitializer =
      ts.isVariableDeclaration(declaration) && declaration.initializer !== undefined
        ? unwrapExpression(declaration.initializer)
        : undefined;
    const expectedDirectRegistration =
      directInitializer !== undefined &&
      ts.isCallExpression(directInitializer) &&
      ts.isIdentifier(directInitializer.expression) &&
      directBuilders.has(directInitializer.expression.text);
    const expectedGeneratedRegistryRegistration =
      generatedRegistryAdapter !== undefined &&
      pathsEqualForHost(sourcePath, generatedRegistryAdapter.generatedModulePath) &&
      generatedRegistryAdapter.expectedRegisteredExports.has(exportName) &&
      ts.isBindingElement(declaration) &&
      ts.isObjectBindingPattern(declaration.parent) &&
      ts.isVariableDeclaration(declaration.parent.parent) &&
      declaration.parent.parent.initializer !== undefined &&
      ts.isIdentifier(declaration.parent.parent.initializer) &&
      declaration.parent.parent.initializer.text === generatedRegistryAdapter.runtimeIdentifier;
    const parts = registeredTypeParts(type, declaration);
    if (parts === null) {
      if (expectedDirectRegistration || expectedGeneratedRegistryRegistration) {
        throw new Error(
          `Native TypeScript did not infer a registered Convex function for ${exportName} at ${sourceLocation(declaration)}.`
        );
      }
      continue;
    }
    validateRegistrationShape(candidate, parts);

    const registeredFunction = {
      entryPath: toPosixPath(relative(rootDir, sourcePath)),
      modulePath: convexModulePath(sourcePath),
      exportName,
      kind: parts.kind,
      visibility: parts.visibility,
    };
    // Wasm route authority needs native registration/provenance discovery, but does not consume
    // argument or return declarations. Keep those checker/serialization queries exclusive to
    // the complete declaration product.
    functions.push(
      routeInventoryOnly
        ? registeredFunction
        : {
            ...registeredFunction,
            args: serializeType(parts.args, declaration, exportName, "argument"),
            returns: serializeType(parts.returns, declaration, exportName, "return"),
          }
    );
  }
}
if (profileGeneration) {
  console.error(JSON.stringify(nativeApi.getTimingInfo(), null, 2));
}
nativeApi.close();

functions.sort((left, right) => {
  const moduleOrder = compareStrings(left.modulePath, right.modulePath);
  return moduleOrder === 0 ? compareStrings(left.exportName, right.exportName) : moduleOrder;
});

function treeForVisibility(visibility) {
  const root = new Map();
  for (const func of functions.filter((candidate) => candidate.visibility === visibility)) {
    let current = root;
    for (const part of [...func.modulePath.split("/"), func.exportName]) {
      let child = current.get(part);
      if (child === undefined) {
        child = new Map();
        current.set(part, child);
      }
      if (!(child instanceof Map)) {
        throw new Error(`Ambiguous Convex API path for ${func.modulePath}:${func.exportName}.`);
      }
      current = child;
    }
    current.set(Symbol.for("function"), func);
  }
  return root;
}

function printTree(tree, indent) {
  const func = tree.get(Symbol.for("function"));
  if (func !== undefined) {
    if (tree.size !== 1) {
      throw new Error(
        `A Convex API function collides with a namespace at ${func.modulePath}:${func.exportName}.`
      );
    }
    return `FunctionReference<${JSON.stringify(func.kind)}, ${JSON.stringify(func.visibility)}, ${func.args}, ConvertReturnType<Awaited<${func.returns}>>>`;
  }

  const lines = ["{"];
  const entries = [...tree.entries()].sort(([left], [right]) => compareStrings(left, right));
  for (const [name, child] of entries) {
    lines.push(
      `${" ".repeat(indent + 2)}${JSON.stringify(name)}: ${printTree(child, indent + 2)};`
    );
  }
  lines.push(`${" ".repeat(indent)}}`);
  return lines.join("\n");
}

function flattenedDeclarationOutput() {
  const publicTree = printTree(treeForVisibility("public"), 0);
  const internalTree = printTree(treeForVisibility("internal"), 0);
  const combinedTypes = `${publicTree}\n${internalTree}`;
  if (referencesLocalSource(combinedTypes)) {
    throw new Error("Flattened Convex API generation retained a local backend type reference.");
  }

  const output = `/* eslint-disable */
/**
 * Generated flattened Convex API types.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run \`npm run convex:api:flatten\`.
 * Output hash: ${outputHashPlaceholder}
 * @module
 */

import type { FunctionReference } from "convex/server";

type ConvertReturnType<T> = T extends void ? null : T;

/** Public Convex function references. */
export declare const api: ${publicTree};

/** Internal Convex function references. */
export declare const internal: ${internalTree};

export declare const components: {};
`;
  const outputHash = createHash("sha256").update(output).digest("hex");
  return output.replace(
    ` * Output hash: ${outputHashPlaceholder}\n`,
    ` * Output hash: ${outputHash}\n`
  );
}
const finalizedOutput = routeInventoryOnly
  ? convexApiRouteOutput(functions)
  : flattenedDeclarationOutput();
if (!inventorySnapshotMode) {
  await verifyInputsAtPublication({
    expectedInputSha256: inputHash,
    expectedInstalledMaterialIdentity: flattenerInput.identity.installedMaterialIdentity,
    materialPaths: [...compilerMaterialPaths, ...programMaterialPaths],
  });
}
writeMaterialIndex(programMaterialPaths);
const inventoryMetadata = inventorySnapshotMetadata(finalizedOutput, functions);
publishSharedInventoryCache(finalizedOutput, inventoryMetadata);
writeFastReuseIndex(inventoryMetadata.outputSha256);

if (inventorySnapshotMode) {
  const publication = await publishInventorySnapshot(finalizedOutput, inventoryMetadata);
  reportInventorySnapshot(publication, inventoryMetadata, "miss");
  console.error(
    routeInventoryOnly
      ? `Published Convex API route inventory: ${functions.length} functions, no argument/return serialization.`
      : `Published flattened Convex API inventory: ${functions.length} functions, 0 retained local type imports.`
  );
} else if (mode === "--check") {
  if (readGeneratedApiIfPresent() !== finalizedOutput) {
    throw new Error(
      `${apiRelativePath} is stale. Regenerate and stage the Convex API declaration.`
    );
  }
  console.error(
    `Verified flattened Convex API: ${functions.length} functions, 0 retained local type imports.`
  );
} else {
  writeGeneratedApi(finalizedOutput);
  console.error(
    `Flattened Convex API: ${functions.length} functions, 0 retained local type imports.`
  );
}
publishPendingStagedSurfaceManifest();
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
