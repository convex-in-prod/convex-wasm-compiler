import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { types as utilTypes } from "node:util";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";

const OUTPUT_KIND = "convex-context-reuse-analysis";
const APPLICATION_ADMISSION_KIND = "convex-context-reuse-application-admission";
const APPLICATION_ADMISSION_POLICY_KIND = "convex-context-reuse-application-admission-policy";
const APPLICATION_ADMISSION_POLICY_FILE = "convex-context-reuse-application-admission.json";
const SHARED_IDENTITY_KIND = "convex-context-reuse-shared-analysis";
const EXPANDED_DIAGNOSTIC_ENCODING = "expanded";
const GROUPED_DIAGNOSTIC_ENCODING = "grouped";
const ADMISSION_DIAGNOSTIC_ENCODING = "admission";
const MAX_RUST_SOURCE_OFFSET = 0xffff_ffff;
const MAX_RUST_SOURCE_COORDINATE = MAX_RUST_SOURCE_OFFSET + 1;
const OUTPUT_METRIC_NAMES = [
  "wallTimeUs",
  "esbuildGraphUs",
  "graphReadUs",
  "sourceReadUs",
  "cacheLookupUs",
  "parseUs",
  "semanticUs",
  "reachabilityUs",
  "modulesAnalyzed",
  "parsedModules",
  "cacheHits",
  "cacheMisses",
];
const OUTPUT_METRIC_KEYS = new Set([
  ...OUTPUT_METRIC_NAMES,
  "peakRssBytes",
  "inventoryPrecheckWallTimeUs",
  "resultCacheHit",
  "wrapperWallTimeUs",
  "entryCacheHits",
  "entryCacheMisses",
]);
const NO_APPLICATION_ADMISSION_POLICY = Symbol("no application-admission policy");
const retainedApplicationAdmissions = new WeakMap();
let applicationAdmissionFullAuthenticationCount = 0;
let outputFullValidationCount = 0;

function freezeRetainedApplicationAdmissionResult(value, active = new Set()) {
  if (value === null || typeof value !== "object") return value;
  if (utilTypes.isProxy(value)) {
    throw new Error("Retained Convex context-reuse application admission must be JSON data.");
  }
  if (
    (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype) ||
    (Array.isArray(value) && Object.getPrototypeOf(value) !== Array.prototype)
  ) {
    throw new Error("Retained Convex context-reuse application admission must be JSON data.");
  }
  if (active.has(value)) {
    throw new Error("Retained Convex context-reuse application admission must be acyclic.");
  }
  active.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (Array.isArray(value) && key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      throw new Error("Retained Convex context-reuse application admission must be JSON data.");
    }
    freezeRetainedApplicationAdmissionResult(descriptor.value, active);
  }
  active.delete(value);
  return Object.freeze(value);
}
export function toPosix(path) {
  return path.replaceAll("\\", "/");
}
export function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
function validRustString(value) {
  // Rust String cannot contain isolated UTF-16 surrogates. Reject them before scalar ordering or
  // UTF-8 hashing can authenticate a value that the native producer could not have emitted.
  return typeof value === "string" && value.isWellFormed();
}
export function compareRustStrings(left, right) {
  // Rust String/BTreeMap order compares UTF-8 bytes. Authenticate that producer order even when
  // module paths or import specifiers contain characters outside JavaScript's BMP ordering.
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftCodePoint = left.codePointAt(leftIndex);
    const rightCodePoint = right.codePointAt(rightIndex);
    if (leftCodePoint !== rightCodePoint) return leftCodePoint < rightCodePoint ? -1 : 1;
    leftIndex += leftCodePoint > 0xffff ? 2 : 1;
    rightIndex += rightCodePoint > 0xffff ? 2 : 1;
  }
  return leftIndex < left.length ? 1 : rightIndex < right.length ? -1 : 0;
}
export function freezeGraphBasis(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeGraphBasis(nested);
    Object.freeze(value);
  }
  return value;
}
function exactObjectKeys(value, expectedKeys) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.every((key) => {
      if (typeof key !== "string") return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && descriptor.enumerable && "value" in descriptor;
    }) && keys.sort().join(",") === [...expectedKeys].sort().join(",")
  );
}
export function authenticateConvexContextReuseApplicationAdmissionPolicy(
  value,
  description = "Convex context-reuse application-admission policy"
) {
  if (
    !exactObjectKeys(value, [
      "admittedFinding",
      "hardFindings",
      "kind",
      "otherUnsupportedFindings",
      "rationale",
    ]) ||
    value.kind !== APPLICATION_ADMISSION_POLICY_KIND ||
    value.hardFindings !== "block" ||
    value.otherUnsupportedFindings !== "block" ||
    typeof value.rationale !== "string" ||
    value.rationale.length < 64 ||
    value.rationale.trim() !== value.rationale ||
    /[\r\n]/u.test(value.rationale)
  ) {
    throw new Error(
      `${description} must be the closed policy with blocking defaults and a literal rationale of at least 64 characters.`
    );
  }
  const finding = value.admittedFinding;
  if (
    !exactObjectKeys(finding, ["category", "fileRoots", "rule", "severity"]) ||
    finding.category !== "unsupported-construct" ||
    finding.rule !== "unresolved-mutator-application" ||
    finding.severity !== "unsupported" ||
    !Array.isArray(finding.fileRoots) ||
    finding.fileRoots.length === 0 ||
    finding.fileRoots.some(
      (root) =>
        typeof root !== "string" ||
        !root.endsWith("/") ||
        !validContextReusePath(root.slice(0, -1)) ||
        root.split("/").includes("node_modules")
    ) ||
    new Set(finding.fileRoots).size !== finding.fileRoots.length ||
    JSON.stringify([...finding.fileRoots].sort()) !== JSON.stringify(finding.fileRoots)
  ) {
    throw new Error(
      `${description} must admit only unsupported unresolved-mutator-application findings in sorted first-party file roots.`
    );
  }
  return freezeGraphBasis(structuredClone(value));
}

export function statusIdentity(path, status) {
  return {
    path,
    kind: status.isDirectory() ? "directory" : status.isFile() ? "file" : "other",
    device: status.dev.toString(),
    inode: status.ino.toString(),
    size: status.size.toString(),
    modifiedNanoseconds: status.mtimeNs.toString(),
    changedNanoseconds: status.ctimeNs.toString(),
  };
}

export function loadConvexContextReuseApplicationAdmissionPolicy(repoRoot) {
  const policyPath = join(resolve(repoRoot), APPLICATION_ADMISSION_POLICY_FILE);
  if (!existsSync(policyPath)) return undefined;
  if (fsConstants.O_NOFOLLOW === undefined) {
    throw new Error("this platform cannot authenticate the context-reuse application policy");
  }
  let source;
  const descriptor = openSync(policyPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size <= 0n || before.size > 1024n * 1024n) {
      throw new Error(`${policyPath} must be a non-empty regular file no larger than 1 MiB.`);
    }
    source = readFileSync(descriptor, "utf8");
    const after = fstatSync(descriptor, { bigint: true });
    if (
      JSON.stringify(statusIdentity(policyPath, before)) !==
      JSON.stringify(statusIdentity(policyPath, after))
    ) {
      throw new Error(`${policyPath} changed while it was being read.`);
    }
  } finally {
    closeSync(descriptor);
  }
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new Error(`Convex context-reuse application-admission policy is invalid: ${policyPath}`, {
      cause: error,
    });
  }
  return authenticateConvexContextReuseApplicationAdmissionPolicy(
    parsed,
    `Convex context-reuse application-admission policy at ${policyPath}`
  );
}
function packageName(specifier) {
  // Esbuild records imports between files within an installed package with a
  // relative `original` specifier (for example `./core.js`). Such an import
  // still belongs to the package identified by its resolved `node_modules/`
  // boundary; relative specifiers do not carry a package name of their own.
  if (specifier.startsWith(".") || specifier.startsWith("/")) {
    return undefined;
  }
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}
function packageNameFromBoundary(packageBoundary) {
  const components = packageBoundary.split("/");
  const packageIndex = components.lastIndexOf("node_modules") + 1;
  const first = components[packageIndex];
  if (first === undefined || first.length === 0) {
    throw new Error(`Installed package boundary is malformed: ${packageBoundary}`);
  }
  if (first.startsWith("@")) {
    const second = components[packageIndex + 1];
    if (second === undefined || second.length === 0) {
      throw new Error(`Installed package boundary is malformed: ${packageBoundary}`);
    }
    return `${first}/${second}`;
  }
  return first;
}
export function dependencyMaterial(repoRoot, specifier, resolvedInputPath) {
  const requestedName = packageName(specifier);
  if (specifier.startsWith("node:")) {
    return {
      identity: { packageName: requestedName, version: process.version },
      packageJsonPath: undefined,
    };
  }
  const packageBoundary =
    resolvedInputPath === undefined ? undefined : installedPackageBoundary(resolvedInputPath);
  if (packageBoundary !== undefined) {
    const boundaryName = packageNameFromBoundary(packageBoundary);
    const packageJsonPath = join(repoRoot, packageBoundary, "package.json");
    if (existsSync(packageJsonPath)) {
      const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
      if (typeof packageJson.name !== "string" || packageJson.name.length === 0) {
        throw new Error(`Installed package manifest has no valid name at ${packageJsonPath}.`);
      }
      if (requestedName !== undefined && packageJson.name !== requestedName) {
        throw new Error(
          `Resolved dependency ${specifier} has package name ${JSON.stringify(packageJson.name)} at ${packageJsonPath}.`
        );
      }
      return {
        identity: {
          packageName: packageJson.name,
          version: typeof packageJson.version === "string" ? packageJson.version : null,
        },
        packageJsonPath,
      };
    }
    return {
      identity: { packageName: requestedName ?? boundaryName, version: null },
      packageJsonPath: undefined,
    };
  }
  const requireFromRoot = createRequire(join(repoRoot, "package.json"));
  let resolved;
  try {
    resolved = requireFromRoot.resolve(specifier);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "MODULE_NOT_FOUND")) {
      throw error;
    }
  }
  if (resolved !== undefined) {
    let directory = dirname(resolved);
    while (true) {
      const packageJsonPath = join(directory, "package.json");
      if (existsSync(packageJsonPath)) {
        const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
        if (requestedName !== undefined && packageJson.name === requestedName) {
          return {
            identity: {
              packageName: requestedName,
              version: typeof packageJson.version === "string" ? packageJson.version : null,
            },
            packageJsonPath,
          };
        }
      }
      const parent = dirname(directory);
      if (parent === directory) {
        break;
      }
      directory = parent;
    }
  }
  return { identity: { packageName: requestedName, version: null }, packageJsonPath: undefined };
}
export function captureContextReuseExternalDependencyIdentities(repoRoot, metafile) {
  const externalDependencies = {};
  const externalDependencyResolutions = {};
  const externalDependencyManifestPaths = new Set();
  for (const input of Object.values(metafile?.inputs ?? {})) {
    for (const dependency of input.imports ?? []) {
      const dependencySpecifier = dependency.external
        ? !dependency.path.startsWith(".") && !dependency.path.startsWith("/")
          ? dependency.path
          : undefined
        : dependency.path.startsWith("node_modules/")
          ? dependency.original !== undefined &&
            !dependency.original.startsWith(".") &&
            !dependency.original.startsWith("/")
            ? dependency.original
            : undefined
          : undefined;
      if (dependencySpecifier === undefined) continue;
      const material = dependencyMaterial(resolve(repoRoot), dependencySpecifier, dependency.path);
      const identity = material.identity;
      const previous = externalDependencies[dependencySpecifier];
      if (previous !== undefined && JSON.stringify(previous) !== JSON.stringify(identity)) {
        throw new Error(
          `Runtime dependency ${dependencySpecifier} resolves to inconsistent installed package identities.`
        );
      }
      externalDependencies[dependencySpecifier] = identity;
      externalDependencyResolutions[dependencySpecifier] ??= dependency.path;
      if (material.packageJsonPath !== undefined) {
        externalDependencyManifestPaths.add(material.packageJsonPath);
      }
    }
  }
  return {
    externalDependencies,
    externalDependencyManifestPaths,
    externalDependencyResolutions,
  };
}
export function validSha256(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
}
function validUnsignedSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
}
export function contextReuseOutputDiagnosticEncoding(output) {
  return Object.hasOwn(output, "diagnosticEncoding")
    ? output.diagnosticEncoding
    : EXPANDED_DIAGNOSTIC_ENCODING;
}
function validSourceSpan(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === "column,end,endColumn,endLine,line,start" &&
    validUnsignedSafeInteger(value.start) &&
    value.start <= MAX_RUST_SOURCE_OFFSET &&
    validUnsignedSafeInteger(value.end) &&
    value.end >= value.start &&
    value.end <= MAX_RUST_SOURCE_OFFSET &&
    validUnsignedSafeInteger(value.line) &&
    value.line >= 1 &&
    value.line <= MAX_RUST_SOURCE_COORDINATE &&
    validUnsignedSafeInteger(value.column) &&
    value.column >= 1 &&
    value.column <= MAX_RUST_SOURCE_COORDINATE &&
    validUnsignedSafeInteger(value.endLine) &&
    value.endLine >= value.line &&
    value.endLine <= MAX_RUST_SOURCE_COORDINATE &&
    validUnsignedSafeInteger(value.endColumn) &&
    value.endColumn >= 1 &&
    value.endColumn <= MAX_RUST_SOURCE_COORDINATE &&
    (value.endLine !== value.line || value.endColumn >= value.column)
  );
}
export function validContextReusePath(value) {
  return (
    validRustString(value) &&
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.includes("\0") &&
    value.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..")
  );
}
function validDiagnosticDefinition(value, occurrence = false) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      (occurrence
        ? "category,dependencyChain,entry,file,id,message,rule,severity,span"
        : "category,file,id,message,rule,severity,span") ||
    !["hard", "unsupported", "information"].includes(value.severity) ||
    !validRustString(value.rule) ||
    value.rule.length === 0 ||
    !validRustString(value.category) ||
    value.category.length === 0 ||
    !validRustString(value.message) ||
    value.message.length === 0 ||
    !validContextReusePath(value.file) ||
    !validSourceSpan(value.span)
  ) {
    return false;
  }
  const expectedIdMaterial = [
    "context-reuse-diagnostic",
    value.rule,
    value.file,
    String(value.span.start),
    String(value.span.end),
    value.message,
    "",
  ].join("\0");
  return (
    value.id === `ctx-${createHash("sha256").update(expectedIdMaterial).digest("hex").slice(0, 20)}`
  );
}
function dependencyChainTerminal(dependencyChain, entry) {
  if (!Array.isArray(dependencyChain)) return undefined;
  let expectedFrom = entry;
  for (const edge of dependencyChain) {
    if (
      typeof edge !== "object" ||
      edge === null ||
      Array.isArray(edge) ||
      Object.keys(edge).sort().join(",") !== "from,span,specifier,to" ||
      edge.from !== expectedFrom ||
      !validContextReusePath(edge.from) ||
      !validContextReusePath(edge.to) ||
      !validRustString(edge.specifier) ||
      edge.specifier.length === 0 ||
      !validSourceSpan(edge.span)
    ) {
      return undefined;
    }
    expectedFrom = edge.to;
  }
  return expectedFrom;
}
function compareSourceSpans(left, right) {
  for (const field of ["start", "end", "line", "column", "endLine", "endColumn"]) {
    if (left[field] < right[field]) return -1;
    if (left[field] > right[field]) return 1;
  }
  return 0;
}
function compareDependencyChains(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    for (const field of ["from", "to", "specifier"]) {
      const order = compareRustStrings(left[index][field], right[index][field]);
      if (order !== 0) return order;
    }
    const spanOrder = compareSourceSpans(left[index].span, right[index].span);
    if (spanOrder !== 0) return spanOrder;
  }
  return left.length - right.length;
}
function compareDiagnosticGroups(left, leftTerminal, right, rightTerminal) {
  const entryOrder = compareRustStrings(left.entry, right.entry);
  if (entryOrder !== 0) return entryOrder;
  const terminalOrder = compareRustStrings(leftTerminal, rightTerminal);
  return terminalOrder === 0
    ? compareDependencyChains(left.dependencyChain, right.dependencyChain)
    : terminalOrder;
}
function compareExpandedDiagnostics(left, right) {
  for (const field of ["entry", "file"]) {
    const order = compareRustStrings(left[field], right[field]);
    if (order !== 0) return order;
  }
  if (left.span.start !== right.span.start) return left.span.start - right.span.start;
  for (const field of ["rule", "id"]) {
    const order = compareRustStrings(left[field], right[field]);
    if (order !== 0) return order;
  }
  return 0;
}
export function requireContextReuseOutput(
  output,
  description,
  { requireAnalysisInputSha256 = false } = {}
) {
  // Retention already validated the complete wrapper identity and deeply froze this exact
  // result. Cache publication and later consumers need no second whole-diagnostic shape pass;
  // their policy, graph-selection, and identity checks remain separate below their call sites.
  if (retainedApplicationAdmissions.has(output)) return output;
  outputFullValidationCount += 1;
  const errorMessage = `${description} is invalid.`;
  const hasAnalysisInputSha256 = Object.hasOwn(output ?? {}, "analysisInputSha256");
  const hasAnalysisInputGraphSha256 = Object.hasOwn(output ?? {}, "analysisInputGraphSha256");
  const hasGeneratedInventoryInputSha256 = Object.hasOwn(
    output ?? {},
    "generatedInventoryInputSha256"
  );
  const hasCompleteWrapperIdentity =
    hasAnalysisInputSha256 && hasAnalysisInputGraphSha256 && hasGeneratedInventoryInputSha256;
  const admissionOnly = output?.diagnosticEncoding === ADMISSION_DIAGNOSTIC_ENCODING;
  const grouped = admissionOnly || output?.diagnosticEncoding === GROUPED_DIAGNOSTIC_ENCODING;
  const representationKeys = grouped
    ? ["diagnosticDefinitions", "diagnosticEncoding", "diagnosticGroups"]
    : ["diagnostics"];
  if (
    typeof output !== "object" ||
    output === null ||
    Array.isArray(output) ||
    Object.keys(output).sort().join(",") !==
      [
        "categoryCounts",
        "diagnosticCounts",
        ...representationKeys,
        "entries",
        "kind",
        "metrics",
        "moduleSummarySchema",
        "policyFingerprint",
        "safe",
        "suppressedFindings",
        "thirdPartyMaterialFingerprints",
        ...(hasAnalysisInputGraphSha256 ? ["analysisInputGraphSha256"] : []),
        ...(hasAnalysisInputSha256 ? ["analysisInputSha256"] : []),
        ...(hasGeneratedInventoryInputSha256 ? ["generatedInventoryInputSha256"] : []),
      ]
        .sort()
        .join(",") ||
    ((hasAnalysisInputSha256 || hasAnalysisInputGraphSha256 || hasGeneratedInventoryInputSha256) &&
      !hasCompleteWrapperIdentity) ||
    (requireAnalysisInputSha256 && !hasCompleteWrapperIdentity) ||
    (hasAnalysisInputSha256 && !validSha256(output.analysisInputSha256)) ||
    (hasAnalysisInputGraphSha256 && !validSha256(output.analysisInputGraphSha256)) ||
    (hasGeneratedInventoryInputSha256 && !validSha256(output.generatedInventoryInputSha256)) ||
    output.kind !== OUTPUT_KIND ||
    typeof output.safe !== "boolean" ||
    !Array.isArray(output.entries) ||
    output.entries.some((entry) => !validContextReusePath(entry)) ||
    JSON.stringify(output.entries) !==
      JSON.stringify([...new Set(output.entries)].sort(compareRustStrings)) ||
    (grouped
      ? !Array.isArray(output.diagnosticDefinitions) || !Array.isArray(output.diagnosticGroups)
      : !Array.isArray(output.diagnostics)) ||
    !validUnsignedSafeInteger(output.suppressedFindings) ||
    typeof output.diagnosticCounts !== "object" ||
    output.diagnosticCounts === null ||
    Array.isArray(output.diagnosticCounts) ||
    typeof output.categoryCounts !== "object" ||
    output.categoryCounts === null ||
    Array.isArray(output.categoryCounts) ||
    typeof output.metrics !== "object" ||
    output.metrics === null ||
    Array.isArray(output.metrics) ||
    Object.keys(output.metrics).some((name) => !OUTPUT_METRIC_KEYS.has(name)) ||
    !validRustString(output.moduleSummarySchema) ||
    output.moduleSummarySchema.length === 0 ||
    !validSha256(output.policyFingerprint) ||
    typeof output.thirdPartyMaterialFingerprints !== "object" ||
    output.thirdPartyMaterialFingerprints === null ||
    Array.isArray(output.thirdPartyMaterialFingerprints) ||
    Object.entries(output.thirdPartyMaterialFingerprints).some(
      ([target, fingerprint]) =>
        !target.startsWith("node_modules/") ||
        !validContextReusePath(target) ||
        !validSha256(fingerprint)
    )
  ) {
    throw new Error(errorMessage);
  }
  if (
    OUTPUT_METRIC_NAMES.some((name) => !validUnsignedSafeInteger(output.metrics[name])) ||
    !(
      output.metrics.peakRssBytes === null || validUnsignedSafeInteger(output.metrics.peakRssBytes)
    ) ||
    output.metrics.parsedModules !== output.metrics.cacheMisses
  ) {
    throw new Error(errorMessage);
  }
  for (const name of [
    "inventoryPrecheckWallTimeUs",
    "wrapperWallTimeUs",
    "entryCacheHits",
    "entryCacheMisses",
  ]) {
    if (Object.hasOwn(output.metrics, name) && !validUnsignedSafeInteger(output.metrics[name])) {
      throw new Error(errorMessage);
    }
  }
  if (
    Object.hasOwn(output.metrics, "resultCacheHit") &&
    typeof output.metrics.resultCacheHit !== "boolean"
  ) {
    throw new Error(errorMessage);
  }

  const diagnosticCounts = new Map();
  const categoryCounts = new Map();
  const entriesById = new Map();
  const selectedEntries = new Set(output.entries);
  if (grouped) {
    let previousDefinitionId;
    const definitionsById = new Map();
    for (const definition of output.diagnosticDefinitions) {
      if (
        !validDiagnosticDefinition(definition) ||
        (previousDefinitionId !== undefined && previousDefinitionId >= definition.id)
      ) {
        throw new Error(errorMessage);
      }
      previousDefinitionId = definition.id;
      definitionsById.set(definition.id, definition);
    }
    let previousGroup;
    let previousGroupTerminal;
    const referencedDefinitionIds = new Set();
    for (const group of output.diagnosticGroups) {
      if (
        typeof group !== "object" ||
        group === null ||
        Array.isArray(group) ||
        Object.keys(group).sort().join(",") !==
          (admissionOnly ? "entry,findingIds" : "dependencyChain,entry,findingIds") ||
        !validContextReusePath(group.entry) ||
        !Array.isArray(group.findingIds) ||
        group.findingIds.length === 0 ||
        group.findingIds.some((id) => typeof id !== "string") ||
        JSON.stringify(group.findingIds) !== JSON.stringify([...new Set(group.findingIds)].sort())
      ) {
        throw new Error(errorMessage);
      }
      // Admission keeps the producer's entry/finding binding, not a reconstructed trace.
      // Non-selected global findings still belong to their own file in either encoding.
      const terminal = admissionOnly
        ? undefined
        : dependencyChainTerminal(group.dependencyChain, group.entry);
      if (!admissionOnly && terminal === undefined) throw new Error(errorMessage);
      if (
        previousGroup !== undefined &&
        (admissionOnly
          ? compareRustStrings(previousGroup.entry, group.entry)
          : compareDiagnosticGroups(previousGroup, previousGroupTerminal, group, terminal)) >= 0
      ) {
        throw new Error(errorMessage);
      }
      previousGroup = group;
      previousGroupTerminal = terminal;
      for (const id of group.findingIds) {
        const definition = definitionsById.get(id);
        const selectedEntryDiagnostic = selectedEntries.has(group.entry);
        if (
          definition === undefined ||
          (!admissionOnly && selectedEntryDiagnostic && terminal !== definition.file) ||
          (!selectedEntryDiagnostic &&
            ((!admissionOnly && group.dependencyChain.length !== 0) ||
              group.entry !== definition.file))
        ) {
          throw new Error(errorMessage);
        }
        // Compact groups already require unique entries and unique IDs within each entry.
        // Only full chain groups can repeat an entry/finding pair across separate groups.
        if (!admissionOnly) {
          const seenEntries = entriesById.get(id) ?? new Set();
          if (seenEntries.has(group.entry)) throw new Error(errorMessage);
          seenEntries.add(group.entry);
          entriesById.set(id, seenEntries);
        }
        referencedDefinitionIds.add(id);
        diagnosticCounts.set(
          definition.severity,
          (diagnosticCounts.get(definition.severity) ?? 0) + 1
        );
        categoryCounts.set(definition.category, (categoryCounts.get(definition.category) ?? 0) + 1);
      }
    }
    if (referencedDefinitionIds.size !== definitionsById.size) {
      throw new Error(errorMessage);
    }
  } else {
    const identitiesById = new Map();
    let previousDiagnostic;
    for (const diagnostic of output.diagnostics) {
      if (
        typeof diagnostic !== "object" ||
        diagnostic === null ||
        Array.isArray(diagnostic) ||
        Object.keys(diagnostic).sort().join(",") !==
          "category,dependencyChain,entry,file,id,message,rule,severity,span" ||
        !validDiagnosticDefinition(diagnostic, true) ||
        !validContextReusePath(diagnostic.entry)
      ) {
        throw new Error(errorMessage);
      }
      if (
        previousDiagnostic !== undefined &&
        compareExpandedDiagnostics(previousDiagnostic, diagnostic) > 0
      ) {
        throw new Error(errorMessage);
      }
      previousDiagnostic = diagnostic;
      const terminal = dependencyChainTerminal(diagnostic.dependencyChain, diagnostic.entry);
      const selectedEntryDiagnostic = selectedEntries.has(diagnostic.entry);
      if (
        terminal === undefined ||
        (selectedEntryDiagnostic && terminal !== diagnostic.file) ||
        (!selectedEntryDiagnostic &&
          (diagnostic.dependencyChain.length !== 0 || diagnostic.entry !== diagnostic.file))
      ) {
        throw new Error(errorMessage);
      }
      const identity = JSON.stringify({
        category: diagnostic.category,
        file: diagnostic.file,
        message: diagnostic.message,
        rule: diagnostic.rule,
        severity: diagnostic.severity,
        span: diagnostic.span,
      });
      const previousIdentity = identitiesById.get(diagnostic.id);
      if (previousIdentity !== undefined && previousIdentity !== identity) {
        throw new Error(errorMessage);
      }
      identitiesById.set(diagnostic.id, identity);
      const seenEntries = entriesById.get(diagnostic.id) ?? new Set();
      if (seenEntries.has(diagnostic.entry)) throw new Error(errorMessage);
      seenEntries.add(diagnostic.entry);
      entriesById.set(diagnostic.id, seenEntries);
      diagnosticCounts.set(
        diagnostic.severity,
        (diagnosticCounts.get(diagnostic.severity) ?? 0) + 1
      );
      categoryCounts.set(diagnostic.category, (categoryCounts.get(diagnostic.category) ?? 0) + 1);
    }
  }
  const actualDiagnosticCounts = Object.entries(output.diagnosticCounts).sort();
  const actualCategoryCounts = Object.entries(output.categoryCounts).sort();
  if (
    actualDiagnosticCounts.some(
      ([name, count]) => name.length === 0 || !Number.isSafeInteger(count) || count <= 0
    ) ||
    actualCategoryCounts.some(
      ([name, count]) => name.length === 0 || !Number.isSafeInteger(count) || count <= 0
    ) ||
    JSON.stringify(actualDiagnosticCounts) !==
      JSON.stringify([...diagnosticCounts.entries()].sort()) ||
    JSON.stringify(actualCategoryCounts) !== JSON.stringify([...categoryCounts.entries()].sort()) ||
    output.safe !==
      ((diagnosticCounts.get("hard") ?? 0) === 0 &&
        (diagnosticCounts.get("unsupported") ?? 0) === 0)
  ) {
    throw new Error(errorMessage);
  }
  return output;
}
export function sortedContextReuseEntries(entries, description) {
  if (!Array.isArray(entries) || entries.some((entry) => !validContextReusePath(entry))) {
    throw new Error(`${description} must contain normalized entry paths.`);
  }
  const sorted = [...entries].sort(compareRustStrings);
  if (
    JSON.stringify(sorted) !== JSON.stringify(entries) ||
    new Set(entries).size !== entries.length
  ) {
    throw new Error(`${description} must be sorted and unique.`);
  }
  return sorted;
}
function semanticContextReuseResult(output, entries) {
  const common = {
    analysisInputGraphSha256: output.analysisInputGraphSha256,
    analysisInputSha256: output.analysisInputSha256,
    categoryCounts: output.categoryCounts,
    diagnosticCounts: output.diagnosticCounts,
    entries,
    generatedInventoryInputSha256: output.generatedInventoryInputSha256,
    kind: output.kind,
    moduleSummarySchema: output.moduleSummarySchema,
    policyFingerprint: output.policyFingerprint,
    safe: output.safe,
    suppressedFindings: output.suppressedFindings,
    thirdPartyMaterialFingerprints: output.thirdPartyMaterialFingerprints,
  };
  return contextReuseOutputDiagnosticEncoding(output) !== EXPANDED_DIAGNOSTIC_ENCODING
    ? {
        ...common,
        diagnosticDefinitions: output.diagnosticDefinitions,
        diagnosticEncoding: output.diagnosticEncoding,
        diagnosticGroups: output.diagnosticGroups,
      }
    : { ...common, diagnostics: output.diagnostics };
}
export function contextReuseResultIdentity(output, entries) {
  return Object.freeze({
    entries: Object.freeze(entries),
    kind: OUTPUT_KIND,
    policyFingerprint: output.policyFingerprint,
    resultSha256: fingerprintJson(semanticContextReuseResult(output, entries)),
  });
}
export function requireContextReuseResultSelection(
  output,
  entries,
  { expectedEntries, expectedAnalysisInputGraphSha256 }
) {
  if (expectedEntries !== undefined) {
    const expected = [...expectedEntries].sort(compareRustStrings);
    if (
      JSON.stringify(sortedContextReuseEntries(expected, "expected context-reuse entries")) !==
      JSON.stringify(entries)
    ) {
      throw new Error("Convex context-reuse result entries do not match the selected graph.");
    }
  }
  if (
    expectedAnalysisInputGraphSha256 !== undefined &&
    output.analysisInputGraphSha256 !== expectedAnalysisInputGraphSha256
  ) {
    throw new Error("Convex context-reuse result graph-input identity does not match the graph.");
  }
}
function createContextReuseApplicationAdmission(
  output,
  entries,
  analysisIdentity,
  applicationAdmissionPolicy
) {
  const findingsByEntry = new Map(entries.map((entry) => [entry, new Set()]));
  let firstBlockingFinding;
  let blockingFindingCount = 0;
  const admitOccurrence = (diagnostic, entry) => {
    if (diagnostic.severity === "information") return;
    const admittedFinding =
      diagnostic.severity === applicationAdmissionPolicy.admittedFinding.severity &&
      diagnostic.category === applicationAdmissionPolicy.admittedFinding.category &&
      diagnostic.rule === applicationAdmissionPolicy.admittedFinding.rule &&
      applicationAdmissionPolicy.admittedFinding.fileRoots.some((root) =>
        diagnostic.file.startsWith(root)
      ) &&
      findingsByEntry.has(entry);
    if (!admittedFinding) {
      firstBlockingFinding ??= diagnostic;
      blockingFindingCount += 1;
      return;
    }
    findingsByEntry.get(entry).add(diagnostic.id);
  };
  if (contextReuseOutputDiagnosticEncoding(output) !== EXPANDED_DIAGNOSTIC_ENCODING) {
    const definitionsById = new Map(
      output.diagnosticDefinitions.map((definition) => [definition.id, definition])
    );
    for (const group of output.diagnosticGroups) {
      for (const id of group.findingIds) {
        admitOccurrence(definitionsById.get(id), group.entry);
      }
    }
  } else {
    for (const diagnostic of output.diagnostics) {
      admitOccurrence(diagnostic, diagnostic.entry);
    }
  }
  if (firstBlockingFinding !== undefined) {
    throw new Error(
      `Convex context-reuse application admission is blocked by ${blockingFindingCount} finding(s); first blocker is ${firstBlockingFinding.severity} ${firstBlockingFinding.rule} at ${firstBlockingFinding.file}.`
    );
  }

  const entryAdmissions = entries.map((entry) => {
    const findingIds = [...findingsByEntry.get(entry)].sort();
    return Object.freeze({
      disposition:
        findingIds.length === 0 ? "analysis-safe" : "conservative-local-mutator-application",
      entry,
      findingIds: Object.freeze(findingIds),
    });
  });
  const policySha256 = fingerprintJson(applicationAdmissionPolicy);
  const payload = {
    analysisResultSha256: analysisIdentity.resultSha256,
    entryAdmissions,
    kind: APPLICATION_ADMISSION_KIND,
    policySha256,
  };
  return Object.freeze({
    ...payload,
    entryAdmissions: Object.freeze(entryAdmissions),
    sha256: fingerprintJson(payload),
  });
}
export function normalizeApplicationAdmissionPolicy(applicationAdmissionPolicy) {
  return applicationAdmissionPolicy === undefined
    ? undefined
    : authenticateConvexContextReuseApplicationAdmissionPolicy(applicationAdmissionPolicy);
}
export function applicationAdmissionPolicyKey(applicationAdmissionPolicy) {
  return applicationAdmissionPolicy === undefined
    ? NO_APPLICATION_ADMISSION_POLICY
    : fingerprintJson(applicationAdmissionPolicy);
}
function requireContextReuseApplicationAdmissionIdentity(identity, expectedIdentity) {
  if (
    expectedIdentity !== undefined &&
    JSON.stringify(identity) !==
      JSON.stringify(authenticateConvexContextReuseResultIdentity(expectedIdentity))
  ) {
    throw new Error("Convex context-reuse application admission identity changed.");
  }
}
export function authenticateConvexContextReuseApplicationAdmission(
  result,
  {
    applicationAdmissionPolicy,
    expectedEntries,
    expectedAnalysisInputGraphSha256,
    expectedIdentity,
  } = {}
) {
  const retainedByPolicy =
    result !== null && typeof result === "object"
      ? retainedApplicationAdmissions.get(result)
      : undefined;
  let normalizedApplicationAdmissionPolicy;
  let applicationAdmissionPolicyWasNormalized = false;
  if (retainedByPolicy !== undefined) {
    // Only the retaining boundary populates this WeakMap after it freezes and fully authenticates
    // the exact result. Authenticate current policy content before selecting that private record.
    normalizedApplicationAdmissionPolicy = normalizeApplicationAdmissionPolicy(
      applicationAdmissionPolicy
    );
    applicationAdmissionPolicyWasNormalized = true;
    const retained = retainedByPolicy.get(
      applicationAdmissionPolicyKey(normalizedApplicationAdmissionPolicy)
    );
    if (retained !== undefined) {
      requireContextReuseResultSelection(result, retained.entries, {
        expectedAnalysisInputGraphSha256,
        expectedEntries,
      });
      requireContextReuseApplicationAdmissionIdentity(
        retained.admission.identity,
        expectedIdentity
      );
      return retained.admission;
    }
  }

  applicationAdmissionFullAuthenticationCount += 1;
  const output = requireContextReuseOutput(result, "Convex context-reuse result", {
    requireAnalysisInputSha256: true,
  });
  const entries = sortedContextReuseEntries(output.entries, "Convex context-reuse result entries");
  requireContextReuseResultSelection(output, entries, {
    expectedAnalysisInputGraphSha256,
    expectedEntries,
  });
  const analysisIdentity = contextReuseResultIdentity(output, entries);
  if (!applicationAdmissionPolicyWasNormalized) {
    normalizedApplicationAdmissionPolicy = normalizeApplicationAdmissionPolicy(
      applicationAdmissionPolicy
    );
  }
  if (output.safe !== true && normalizedApplicationAdmissionPolicy === undefined) {
    throw new Error(
      "Convex context-reuse result is not safe and no explicit application-admission policy was supplied."
    );
  }
  const applicationAdmission =
    output.safe === true
      ? undefined
      : createContextReuseApplicationAdmission(
          output,
          entries,
          analysisIdentity,
          normalizedApplicationAdmissionPolicy
        );
  const identity =
    output.safe === true
      ? analysisIdentity
      : Object.freeze({
          entries: Object.freeze(entries),
          kind: OUTPUT_KIND,
          policyFingerprint: output.policyFingerprint,
          resultSha256: applicationAdmission.sha256,
        });
  requireContextReuseApplicationAdmissionIdentity(identity, expectedIdentity);
  const sharedPayload = {
    kind: SHARED_IDENTITY_KIND,
    moduleSummarySchema: output.moduleSummarySchema,
    policyFingerprint: output.policyFingerprint,
  };
  return freezeGraphBasis({
    ...(applicationAdmission === undefined ? {} : { applicationAdmission }),
    generatedInventoryInputSha256: output.generatedInventoryInputSha256,
    identity,
    kind: APPLICATION_ADMISSION_KIND,
    sharedAnalysisIdentity: {
      ...sharedPayload,
      sha256: fingerprintJson(sharedPayload),
    },
    thirdPartyMaterialFingerprints: normalizedThirdPartyMaterialFingerprints(
      output.thirdPartyMaterialFingerprints,
      "Convex context-reuse third-party material fingerprints"
    ),
  });
}

export function retainConvexContextReuseApplicationAdmission(result, options = {}) {
  freezeRetainedApplicationAdmissionResult(result);
  const admission = authenticateConvexContextReuseApplicationAdmission(result, options);
  const normalizedApplicationAdmissionPolicy = normalizeApplicationAdmissionPolicy(
    options.applicationAdmissionPolicy
  );
  let retainedByPolicy = retainedApplicationAdmissions.get(result);
  if (retainedByPolicy === undefined) {
    retainedByPolicy = new Map();
    retainedApplicationAdmissions.set(result, retainedByPolicy);
  }
  retainedByPolicy.set(
    applicationAdmissionPolicyKey(normalizedApplicationAdmissionPolicy),
    Object.freeze({
      admission,
      entries: admission.identity.entries,
    })
  );
  return admission;
}

export const convexContextReuseTestHooks = Object.freeze({
  applicationAdmissionFullAuthenticationCount: () => applicationAdmissionFullAuthenticationCount,
  outputFullValidationCount: () => outputFullValidationCount,
});
export function normalizedThirdPartyMaterialFingerprints(value, description) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.entries(value).some(
      ([target, fingerprint]) =>
        !target.startsWith("node_modules/") ||
        !validContextReusePath(target) ||
        !validSha256(fingerprint)
    )
  ) {
    throw new Error(`${description} is invalid.`);
  }
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => compareStrings(left, right))
  );
}
export function installedPackageBoundary(inputPath) {
  const components = toPosix(inputPath).split("/");
  if (components[0] !== "node_modules") {
    return undefined;
  }
  let packageEnd;
  for (let index = 0; index < components.length; index += 1) {
    if (components[index] !== "node_modules") {
      continue;
    }
    const first = components[index + 1];
    if (first === undefined || first.length === 0 || first === "." || first === "..") {
      return undefined;
    }
    packageEnd = first.startsWith("@") ? index + 3 : index + 2;
    if (
      packageEnd > components.length ||
      components
        .slice(index + 1, packageEnd)
        .some((component) => component.length === 0 || component === "." || component === "..")
    ) {
      return undefined;
    }
    index = packageEnd - 1;
  }
  return packageEnd === undefined ? undefined : components.slice(0, packageEnd).join("/");
}
