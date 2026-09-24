import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  canonicalCompilerPackageJson,
  compilerPackageKind,
  compilerPackageSchemaVersion,
} from "./convex-wasm-compiler-package.mjs";

const SHA256 = /^[a-f0-9]{64}$/u;
const ANALYSIS_INPUT_KIND = "convex-context-reuse-analysis-input";
const ANALYSIS_INPUT_GRAPH_KIND = "convex-context-reuse-analysis-graph-input";
const POLICY_MATERIAL_KIND = "convex-context-reuse-policy-material";
const TOOL_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function fail(message) {
  throw new Error(`Convex context-reuse analysis input: ${message}`);
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

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  requireObject(value, description);
  const actual = Object.keys(value).sort(compareStrings);
  const sortedExpected = [...expected].sort(compareStrings);
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    fail(`${description} has unsupported fields`);
  }
  return value;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isInside(directory, filePath) {
  const path = relative(directory, filePath);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`));
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
    return Object.freeze(value);
  }
  if (typeof value === "object" && value !== null) {
    for (const item of Object.values(value)) deepFreeze(item);
    return Object.freeze(value);
  }
  return value;
}

function normalizedPath(path, description) {
  requireString(path, description);
  if (!isAbsolute(path) || resolve(path) !== path) {
    fail(`${description} must be an absolute normalized path`);
  }
  return path;
}

function isAbsolute(path) {
  return path.startsWith("/") || /^[A-Za-z]:[\\/]/u.test(path);
}

function pathMaterial(repoRoot, path, description) {
  const normalizedRoot = resolve(repoRoot);
  const absolutePath = normalizedPath(path, description);
  if (!isInside(normalizedRoot, absolutePath)) {
    fail(`${description} escapes the repository root`);
  }
  return absolutePath;
}

function checkedRealPath(repoRoot, physicalRoot, absolutePath, description) {
  const normalizedRoot = resolve(repoRoot);
  let current = absolutePath;
  while (isInside(normalizedRoot, current)) {
    try {
      const real = realpathSync(current);
      if (!isInside(physicalRoot, real)) {
        fail(`${description} escapes the repository root through a symlink`);
      }
      return;
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
        throw error;
      }
      const parent = dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  fail(`${description} is outside the repository root`);
}

function stableFileBytes(repoRoot, path, description, { allowMissing = false } = {}) {
  const normalizedRoot = resolve(repoRoot);
  const physicalRoot = realpathSync(normalizedRoot);
  const absolutePath = pathMaterial(repoRoot, path, description);
  checkedRealPath(repoRoot, physicalRoot, absolutePath, description);
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("stable package-review reads require O_NOFOLLOW");
  }
  let descriptor;
  try {
    descriptor = openSync(absolutePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    if (allowMissing && error instanceof Error && "code" in error && error.code === "ENOENT") {
      return { material: { kind: "missing" }, bytes: undefined };
    }
    throw error;
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    checkedRealPath(repoRoot, physicalRoot, absolutePath, description);
    const beforePath = lstatSync(absolutePath, { bigint: true });
    if (!before.isFile() || !beforePath.isFile() || !sameFileState(before, beforePath)) {
      fail(`${description} changed before it could be read`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    checkedRealPath(repoRoot, physicalRoot, absolutePath, description);
    const afterPath = lstatSync(absolutePath, { bigint: true });
    if (
      BigInt(bytes.length) !== before.size ||
      !afterPath.isFile() ||
      !sameFileState(before, after) ||
      !sameFileState(after, afterPath)
    ) {
      fail(`${description} changed while it was being read`);
    }
    return {
      material: {
        kind: "file",
        sha256: createHash("sha256").update(bytes).digest("hex"),
        size: bytes.length,
      },
      bytes,
    };
  } finally {
    closeSync(descriptor);
  }
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function fileMaterial(repoRoot, path, description, options = {}) {
  return stableFileBytes(repoRoot, path, description, options).material;
}

function installedPackageBoundary(modulePath) {
  const components = modulePath.split("/");
  if (components[0] !== "node_modules") return undefined;
  let packageEnd;
  for (let index = 0; index < components.length; index += 1) {
    if (components[index] !== "node_modules") continue;
    const first = components[index + 1];
    if (first === undefined || first.length === 0 || first === "." || first === "..") {
      fail(`third-party target has an invalid package boundary ${modulePath}`);
    }
    packageEnd = first.startsWith("@") ? index + 3 : index + 2;
    if (
      packageEnd > components.length ||
      components
        .slice(index + 1, packageEnd)
        .some((component) => component.length === 0 || component === "." || component === "..")
    ) {
      fail(`third-party target has an invalid package boundary ${modulePath}`);
    }
    index = packageEnd - 1;
  }
  return packageEnd === undefined ? undefined : components.slice(0, packageEnd).join("/");
}

function packageTargetRecords(repoRoot, fingerprints) {
  const targets = Object.entries(fingerprints).sort(([left], [right]) =>
    compareStrings(left, right)
  );
  return targets.map(([target, fingerprint]) => {
    requireString(target, "third-party material target");
    if (
      target.startsWith("/") ||
      target.includes("\\") ||
      target.includes("\0") ||
      target
        .split("/")
        .some((component) => component.length === 0 || component === "." || component === "..")
    ) {
      fail(`third-party material target ${target} is not a normalized relative path`);
    }
    if (!target.startsWith("node_modules/")) {
      fail(`third-party material target ${target} must be under node_modules/`);
    }
    const packageBoundary = installedPackageBoundary(target);
    if (packageBoundary === undefined) {
      fail(`third-party material target ${target} has no package boundary`);
    }
    requireSha256(fingerprint, `third-party material ${target} fingerprint`);
    const packageJsonPath = `${packageBoundary}/package.json`;
    const packageJson = fileMaterial(
      repoRoot,
      resolve(repoRoot, packageJsonPath),
      `${packageJsonPath} package manifest`,
      { allowMissing: true }
    );
    return { packageBoundary, packageJson, target, fingerprint };
  });
}

/**
 * Capture exact package-review material referenced by a completed analyzer result.
 *
 * The result's target map is the authority for which installed package closures contributed to
 * analysis. In particular, an empty map must not cause package-lock or node_modules reads: a
 * fully tree-shaken package has no package-review material and grants no package authority.
 */
export function captureConvexContextReusePackageReviewMaterials({
  repoRoot,
  thirdPartyMaterialFingerprints,
}) {
  const fingerprints = requireObject(
    thirdPartyMaterialFingerprints,
    "third-party material fingerprints"
  );
  if (Object.keys(fingerprints).length === 0) {
    return deepFreeze({ packages: [] });
  }
  const normalizedRoot = resolve(repoRoot);
  const lockPath = resolve(normalizedRoot, "package-lock.json");
  const lockRead = stableFileBytes(normalizedRoot, lockPath, "package-lock.json", {
    allowMissing: true,
  });
  const lockMaterial = lockRead.material;
  let lockPackages = {};
  if (lockMaterial.kind === "file") {
    let lock;
    try {
      // Parse the exact bytes whose digest is bound into the projection. A second read would
      // allow a package-lock replacement between hashing and parsing.
      lock = JSON.parse(lockRead.bytes.toString("utf8"));
    } catch (error) {
      fail(
        `package-lock.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    if (
      typeof lock !== "object" ||
      lock === null ||
      Array.isArray(lock) ||
      typeof lock.packages !== "object" ||
      lock.packages === null ||
      Array.isArray(lock.packages)
    ) {
      fail("package-lock.json has no packages object");
    }
    lockPackages = lock.packages;
  }
  const packages = packageTargetRecords(normalizedRoot, fingerprints).map(
    ({ packageBoundary, packageJson, target, fingerprint }) => ({
      fingerprint,
      lockEntry:
        lockMaterial.kind === "file" && Object.hasOwn(lockPackages, packageBoundary)
          ? lockPackages[packageBoundary]
          : null,
      packageBoundary,
      packageJson,
      target,
    })
  );
  return deepFreeze({ lock: lockMaterial, packages });
}

export function captureConvexContextReusePolicyInputMaterials({ repoRoot, policyInputPaths }) {
  if (!Array.isArray(policyInputPaths)) fail("policy input paths must be an array");
  const normalizedRoot = resolve(repoRoot);
  const materials = [...new Set(policyInputPaths)]
    .map((path, index) => {
      const absolutePath = normalizedPath(path, `policy input ${index}`);
      // A downstream repository can be nested under the tooling checkout. Its policy still
      // belongs to that repository and cannot use the broader tooling root to follow a symlink.
      let materialRoot = normalizedRoot;
      if (!isInside(normalizedRoot, absolutePath) && isInside(TOOL_ROOT, absolutePath)) {
        materialRoot = TOOL_ROOT;
      }
      const material = fileMaterial(materialRoot, absolutePath, `policy input ${absolutePath}`);
      return {
        path: toPosix(relative(materialRoot, absolutePath)),
        sha256: material.sha256,
        size: material.size,
      };
    })
    .sort((left, right) => compareStrings(left.path, right.path));
  return fingerprintJson({ kind: POLICY_MATERIAL_KIND, materials });
}

function toPosix(path) {
  return path.replaceAll("\\", "/");
}

function normalizedDatabaseFunctions(value) {
  if (!Array.isArray(value)) fail("database functions must be an array");
  const functions = value.map((func, index) => {
    const object = requireObject(func, `database function ${index}`);
    const keys = Object.keys(object).sort(compareStrings);
    if (keys.join(",") !== "entryPath,exportName,udfKind") {
      fail(`database function ${index} has unsupported fields`);
    }
    return {
      entryPath: requireString(object.entryPath, `database function ${index} entry path`),
      exportName: requireString(object.exportName, `database function ${index} export name`),
      udfKind: requireString(object.udfKind, `database function ${index} UDF kind`),
    };
  });
  functions.sort((left, right) => {
    const entryOrder = compareStrings(left.entryPath, right.entryPath);
    return entryOrder === 0 ? compareStrings(left.exportName, right.exportName) : entryOrder;
  });
  for (let index = 1; index < functions.length; index += 1) {
    if (
      functions[index - 1].entryPath === functions[index].entryPath &&
      functions[index - 1].exportName === functions[index].exportName
    ) {
      fail(
        `database functions contain duplicate ${functions[index].entryPath}:${functions[index].exportName}`
      );
    }
  }
  return functions;
}

function normalizedEntryPaths(value, description) {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string" || entry.length === 0)
  ) {
    fail(`${description} must contain entry paths`);
  }
  const paths = [...value].sort(compareStrings);
  if (new Set(paths).size !== paths.length) fail(`${description} must be unique`);
  return paths;
}

function normalizedExternalDependencies(value) {
  const dependencies = requireObject(value, "external dependency identities");
  return Object.fromEntries(
    Object.entries(dependencies)
      .sort(([left], [right]) => compareStrings(left, right))
      .map(([specifier, identity]) => {
        requireString(specifier, "external dependency specifier");
        requireExactKeys(
          identity,
          ["packageName", "version"],
          `external dependency ${specifier} identity`
        );
        const packageName = requireString(
          identity.packageName,
          `external dependency ${specifier} package name`
        );
        if (identity.version !== null && typeof identity.version !== "string") {
          fail(`external dependency ${specifier} version must be a string or null`);
        }
        return [specifier, { packageName, version: identity.version }];
      })
  );
}

function normalizedPolicy(value) {
  const policy = requireExactKeys(value, ["defaultEnabled", "exclusions"], "context-reuse policy");
  if (typeof policy.defaultEnabled !== "boolean") {
    fail("context-reuse policy defaultEnabled must be boolean");
  }
  const exclusions = requireObject(policy.exclusions, "context-reuse policy exclusions");
  const normalizedExclusions = Object.fromEntries(
    Object.entries(exclusions)
      .map(([entryPath, reason]) => {
        requireString(entryPath, "context-reuse exclusion entry path");
        requireString(reason, `context-reuse exclusion ${entryPath} reason`);
        return [entryPath, reason];
      })
      .sort(([left], [right]) => compareStrings(left, right))
  );
  return {
    defaultEnabled: policy.defaultEnabled,
    exclusions: normalizedExclusions,
  };
}

function normalizedContextReuseGraphPolicy(value) {
  const policy = requireExactKeys(
    value,
    ["entries", "kind", "sha256"],
    "context-reuse graph policy"
  );
  if (policy.kind !== "convex-wasm-context-reuse-selection" || !Array.isArray(policy.entries)) {
    fail("context-reuse graph policy kind or entries are invalid");
  }
  let previousEntryPath = "";
  const entries = policy.entries.map((value, index) => {
    const entry = requireExactKeys(
      value,
      ["enabled", "entryPath"],
      `context-reuse graph policy entry ${index}`
    );
    const entryPath = requireString(
      entry.entryPath,
      `context-reuse graph policy entry ${index} path`
    );
    if (entryPath <= previousEntryPath || typeof entry.enabled !== "boolean") {
      fail("context-reuse graph policy entries must be sorted, unique, and boolean-valued");
    }
    previousEntryPath = entryPath;
    return { enabled: entry.enabled, entryPath };
  });
  const sha256 = requireSha256(policy.sha256, "context-reuse graph policy SHA-256");
  if (sha256 !== fingerprintJson({ entries, kind: policy.kind })) {
    fail("context-reuse graph policy SHA-256 does not match its entries");
  }
  return { entries, kind: policy.kind, sha256 };
}

function normalizedBinaryMaterial(value, description) {
  const material = requireExactKeys(value, ["sha256", "size"], description);
  if (!Number.isSafeInteger(material.size) || material.size <= 0) {
    fail(`${description} size must be a positive safe integer`);
  }
  return {
    sha256: requireSha256(material.sha256, `${description} SHA-256`),
    size: material.size,
  };
}

function normalizedCompilerSource(value) {
  const source = requireExactKeys(value, ["materials", "treeSha256"], "compiler package source");
  if (!Array.isArray(source.materials) || source.materials.length === 0) {
    fail("compiler package source materials must be a non-empty array");
  }
  let previousPath = "";
  const materials = source.materials.map((value, index) => {
    const material = requireExactKeys(
      value,
      ["path", "sha256", "size"],
      `compiler package source material ${index}`
    );
    const path = requireString(material.path, `compiler package source material ${index} path`);
    if (
      path.startsWith("/") ||
      path.includes("\\") ||
      path
        .split("/")
        .some((component) => component.length === 0 || component === "." || component === "..") ||
      path <= previousPath
    ) {
      fail("compiler package source materials must use sorted unique relative POSIX paths");
    }
    if (!Number.isSafeInteger(material.size) || material.size < 0) {
      fail(`compiler package source material ${index} size must be a non-negative safe integer`);
    }
    previousPath = path;
    return {
      path,
      sha256: requireSha256(material.sha256, `compiler package source material ${index} SHA-256`),
      size: material.size,
    };
  });
  const treeSha256 = requireSha256(source.treeSha256, "compiler package source tree SHA-256");
  const expectedTreeSha256 = createHash("sha256")
    .update(canonicalCompilerPackageJson(materials))
    .digest("hex");
  if (treeSha256 !== expectedTreeSha256) {
    fail("compiler package source tree SHA-256 does not match its materials");
  }
  return { materials, treeSha256 };
}

function normalizedCompilerPackage(value) {
  const packageIdentity = requireExactKeys(
    value,
    ["kind", "packageId", "schemaVersion", "sha256"],
    "compiler package identity"
  );
  if (
    packageIdentity.kind !== compilerPackageKind ||
    packageIdentity.schemaVersion !== compilerPackageSchemaVersion
  ) {
    fail("compiler package identity kind and schema version are invalid");
  }
  return {
    kind: packageIdentity.kind,
    packageId: requireSha256(packageIdentity.packageId, "compiler package ID"),
    schemaVersion: packageIdentity.schemaVersion,
    sha256: requireSha256(packageIdentity.sha256, "compiler package manifest SHA-256"),
  };
}

function normalizedCompilerMaterial(value) {
  const material = requireObject(value, "analysis compiler material");
  if (material.kind === "direct-binary") {
    requireExactKeys(material, ["binary", "kind"], "direct compiler material");
    return {
      binary: normalizedBinaryMaterial(material.binary, "direct compiler binary"),
      kind: material.kind,
    };
  }
  if (material.kind === "compiler-package") {
    requireExactKeys(
      material,
      ["binary", "kind", "package", "source"],
      "packaged compiler material"
    );
    return {
      binary: normalizedBinaryMaterial(material.binary, "packaged compiler binary"),
      kind: material.kind,
      package: normalizedCompilerPackage(material.package),
      source: normalizedCompilerSource(material.source),
    };
  }
  fail("analysis compiler material has an unsupported kind");
}

function normalizedPackageReviewFileMaterial(value, description) {
  requireObject(value, description);
  if (value.kind === "missing") {
    requireExactKeys(value, ["kind"], description);
    return { kind: value.kind };
  }
  requireExactKeys(value, ["kind", "sha256", "size"], description);
  if (value.kind !== "file") {
    fail(`${description} kind is unsupported`);
  }
  if (!Number.isSafeInteger(value.size) || value.size < 0) {
    fail(`${description} size must be a non-negative safe integer`);
  }
  return {
    kind: value.kind,
    sha256: requireSha256(value.sha256, `${description} SHA-256`),
    size: value.size,
  };
}

function normalizePackageReviewMaterials(value) {
  const packageReview = requireObject(value, "package-review materials");
  requireExactKeys(
    packageReview,
    Object.hasOwn(packageReview, "lock") ? ["lock", "packages"] : ["packages"],
    "package-review materials"
  );
  if (!Array.isArray(packageReview.packages)) {
    fail("package-review materials packages must be an array");
  }
  if (packageReview.packages.length > 0 && !Object.hasOwn(packageReview, "lock")) {
    fail("package-review materials with contributing packages must include lock material");
  }
  const packages = packageReview.packages.map((value, index) => {
    const description = `package-review material ${index}`;
    requireExactKeys(
      value,
      ["fingerprint", "lockEntry", "packageBoundary", "packageJson", "target"],
      description
    );
    const target = requireString(value.target, `${description} target`);
    if (
      !target.startsWith("node_modules/") ||
      target.includes("\\") ||
      target.includes("\0") ||
      target
        .split("/")
        .some((component) => component.length === 0 || component === "." || component === "..")
    ) {
      fail(`${description} target is not a normalized node_modules path`);
    }
    const packageBoundary = requireString(value.packageBoundary, `${description} package boundary`);
    if (
      !packageBoundary.startsWith("node_modules/") ||
      installedPackageBoundary(packageBoundary) !== packageBoundary
    ) {
      fail(`${description} package boundary is invalid`);
    }
    if (installedPackageBoundary(target) !== packageBoundary) {
      fail(`${description} target does not belong to its package boundary`);
    }
    requireSha256(value.fingerprint, `${description} fingerprint`);
    if (value.lockEntry !== null) {
      if (typeof value.lockEntry !== "object" || Array.isArray(value.lockEntry)) {
        fail(`${description} lock entry must be an object or null`);
      }
    }
    return {
      fingerprint: value.fingerprint,
      lockEntry: value.lockEntry,
      packageBoundary,
      packageJson: normalizedPackageReviewFileMaterial(
        value.packageJson,
        `${description} package.json`
      ),
      target,
    };
  });
  packages.sort((left, right) => compareStrings(left.target, right.target));
  for (let index = 1; index < packages.length; index += 1) {
    if (packages[index - 1].target === packages[index].target) {
      fail(`package-review materials contain duplicate target ${packages[index].target}`);
    }
  }
  return {
    ...(Object.hasOwn(packageReview, "lock")
      ? { lock: normalizedPackageReviewFileMaterial(packageReview.lock, "package-lock.json") }
      : {}),
    packages,
  };
}

function normalizedGraphBasis(graph) {
  const source = graph?.analysisInputGraphBasis ?? graph;
  requireExactKeys(
    source,
    [
      "activeDependencyAdapters",
      "assumptions",
      "bundleEntryPaths",
      "bundlerMaterials",
      "contextReusePolicy",
      "databaseFunctions",
      "dependencyAdapter",
      "externalDependencies",
      "generatedInventoryInputSha256",
      "inputMaterials",
      "metafileSha256",
      "policy",
      "registrationAdapter",
      "toolchain",
    ],
    "analysis graph basis"
  );
  const inputMaterials = requireObject(source.inputMaterials, "analysis graph input materials");
  return {
    activeDependencyAdapters: requireObject(
      source.activeDependencyAdapters,
      "active dependency adapters"
    ),
    assumptions: requireObject(source.assumptions, "graph assumptions"),
    bundleEntryPaths: normalizedEntryPaths(source.bundleEntryPaths, "bundle entry paths"),
    bundlerMaterials: requireObject(source.bundlerMaterials, "bundler materials"),
    contextReusePolicy: normalizedContextReuseGraphPolicy(source.contextReusePolicy),
    databaseFunctions: normalizedDatabaseFunctions(source.databaseFunctions),
    dependencyAdapter: requireObject(source.dependencyAdapter, "dependency adapter"),
    externalDependencies: normalizedExternalDependencies(source.externalDependencies),
    generatedInventoryInputSha256: requireSha256(
      source.generatedInventoryInputSha256,
      "generated inventory input SHA-256"
    ),
    inputMaterials: Object.fromEntries(
      Object.entries(inputMaterials).sort(([left], [right]) => compareStrings(left, right))
    ),
    metafileSha256: requireSha256(source.metafileSha256, "graph metafile SHA-256"),
    policy: normalizedPolicy(source.policy),
    registrationAdapter: requireObject(source.registrationAdapter, "registration adapter"),
    toolchain: requireObject(source.toolchain, "graph toolchain"),
  };
}

function normalizedGraphPayload(graph) {
  const basis = normalizedGraphBasis(graph);
  return {
    activeDependencyAdapters: basis.activeDependencyAdapters,
    assumptions: basis.assumptions,
    bundleEntryPaths: basis.bundleEntryPaths,
    bundlerMaterials: basis.bundlerMaterials,
    contextReusePolicy: basis.contextReusePolicy,
    databaseFunctions: basis.databaseFunctions,
    dependencyAdapter: basis.dependencyAdapter,
    externalDependencies: basis.externalDependencies,
    generatedInventoryInputSha256: basis.generatedInventoryInputSha256,
    inputMaterials: basis.inputMaterials,
    metafileSha256: basis.metafileSha256,
    policy: basis.policy,
    registrationAdapter: basis.registrationAdapter,
    toolchain: basis.toolchain,
  };
}

/**
 * Build the wrapper-owned exact input identity. The returned digest is deliberately separate
 * from the compact four-field result identity and from the native compiler's input schema.
 */
export function createConvexContextReuseAnalysisInput({
  graph,
  compilerMaterial,
  packageReviewMaterials,
  policyInputMaterialsSha256,
}) {
  const normalizedPackageReviewMaterials = normalizePackageReviewMaterials(packageReviewMaterials);
  const normalizedAnalysisCompilerMaterial = normalizedCompilerMaterial(compilerMaterial);
  requireSha256(policyInputMaterialsSha256, "policy input materials SHA-256");
  const graphPayload = normalizedGraphPayload(graph);
  const analysisInputGraphSha256 = fingerprintJson({
    kind: ANALYSIS_INPUT_GRAPH_KIND,
    ...graphPayload,
  });
  const payload = {
    ...graphPayload,
    analysisInputGraphSha256,
    compilerMaterial: normalizedAnalysisCompilerMaterial,
    packageReviewMaterials: normalizedPackageReviewMaterials,
    policyInputMaterialsSha256,
  };
  return deepFreeze({
    ...payload,
    analysisInputSha256: fingerprintJson({ kind: ANALYSIS_INPUT_KIND, ...payload }),
  });
}

/**
 * Return the graph-only identity shared with deployment admission. Compiler, package-review, and
 * policy-file material intentionally stay outside this digest because deployment does not own
 * those producer inputs; the complete analysis-input digest still binds all of them.
 */
export function createConvexContextReuseAnalysisInputGraphSha256(graph) {
  return fingerprintJson({
    kind: ANALYSIS_INPUT_GRAPH_KIND,
    ...normalizedGraphPayload(graph),
  });
}
