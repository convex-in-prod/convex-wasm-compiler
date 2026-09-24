import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { authenticateConvexContextReuseResultIdentity } from "./convex-context-reuse-result-identity.mjs";
import { validateConvexWasmGitSourceSnapshot } from "./convex-wasm-git-source-snapshot.mjs";

export const convexWasmSourceGraphSnapshotKind = "convex-wasm-source-graph-snapshot-v2";
export const convexWasmSourceGraphSnapshotLookupIdentityKind =
  "convex-wasm-source-graph-snapshot-lookup-identity-v2";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const authenticatedSourceGraphSnapshots = new WeakSet();

function fail(message) {
  throw new Error(`Convex Wasm source graph snapshot: ${message}`);
}

function freezeJsonTree(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        fail("authenticated source graph snapshot cannot retain sparse arrays");
      }
    }
  }
  for (const nested of Object.values(value)) freezeJsonTree(nested);
  return Object.freeze(value);
}

function retainAuthenticatedSnapshot(snapshot) {
  freezeJsonTree(snapshot);
  // Only fully normalized, SHA-authenticated trees enter this set. Deep immutability makes later
  // scope and publication checks safe to reuse without reparsing every per-file record.
  authenticatedSourceGraphSnapshots.add(snapshot);
  return snapshot;
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  const actual = Object.keys(requireObject(value, description)).sort(compareStrings);
  const expectedKeys = [...expected].sort(compareStrings);
  if (canonicalJson(actual) !== canonicalJson(expectedKeys)) {
    fail(`${description} must contain exactly ${expectedKeys.join(", ")}`);
  }
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireNonnegativeSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a nonnegative safe integer`);
  }
  return value;
}

function normalizeRelativePath(value, description) {
  const path = requireString(value, description);
  if (
    path.startsWith("/") ||
    path.includes("\\") ||
    path.includes("\0") ||
    path === "." ||
    path === ".." ||
    path.startsWith("../") ||
    path.includes("/../") ||
    path.endsWith("/..")
  ) {
    fail(`${description} must be a normalized repository-relative POSIX path`);
  }
  return path;
}

function normalizeSortedPaths(values, description) {
  if (!Array.isArray(values)) fail(`${description} must be an array`);
  const paths = values.map((value, index) =>
    normalizeRelativePath(value, `${description}[${index}]`)
  );
  for (let index = 1; index < paths.length; index += 1) {
    if (compareStrings(paths[index - 1], paths[index]) >= 0) {
      fail(`${description} must be sorted and unique`);
    }
  }
  return paths;
}

function normalizeImports(value, description) {
  if (!Array.isArray(value)) fail(`${description} must be an array`);
  // Import records are already authenticated by the deployment graph builder. Keep their exact
  // JSON shape in the persisted snapshot so a future incremental resolver can reuse it without
  // reparsing the metafile. Canonicalization rejects functions, accessors, and non-JSON values.
  const imports = structuredClone(value);
  try {
    canonicalJson(imports);
  } catch (error) {
    fail(
      `${description} is not canonical JSON: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  return imports;
}

function normalizeInput(path, value) {
  const description = `source graph input ${path}`;
  if (typeof value.virtual !== "boolean") fail(`${description} virtual flag is invalid`);
  requireExactKeys(
    value,
    value.virtual ? ["imports", "virtual"] : ["imports", "sha256", "size", "virtual"],
    description
  );
  const imports = normalizeImports(value.imports, `${description} imports`);
  if (value.virtual) {
    if (value.sha256 !== undefined || value.size !== undefined) {
      fail(`${description} virtual input cannot carry physical identity`);
    }
    return { imports, virtual: true };
  }
  return {
    imports,
    sha256: requireSha256(value.sha256, `${description} SHA-256`),
    size: requireNonnegativeSafeInteger(value.size, `${description} size`),
    virtual: false,
  };
}

function normalizeInputs(value) {
  requireObject(value, "source graph snapshot inputs");
  const paths = Object.keys(value).sort(compareStrings);
  return Object.fromEntries(
    paths.map((path) => [
      normalizeRelativePath(path, "source graph input path"),
      normalizeInput(path, value[path]),
    ])
  );
}

function normalizeDependencyGraphs(value) {
  if (!Array.isArray(value)) fail("source graph snapshot dependency graphs must be an array");
  const graphs = value.map((graph, index) => {
    const description = `source graph snapshot dependency graph ${index}`;
    requireExactKeys(graph, ["entryPath", "inputPaths", "sha256"], description);
    const entryPath = normalizeRelativePath(graph.entryPath, `${description} entry path`);
    const inputPaths = normalizeSortedPaths(graph.inputPaths, `${description} input paths`);
    return {
      entryPath,
      inputPaths,
      sha256: requireSha256(graph.sha256, `${description} SHA-256`),
    };
  });
  graphs.sort((left, right) => compareStrings(left.entryPath, right.entryPath));
  for (let index = 1; index < graphs.length; index += 1) {
    if (graphs[index - 1].entryPath === graphs[index].entryPath) {
      fail(
        `source graph snapshot dependency graphs contain duplicate entry ${graphs[index].entryPath}`
      );
    }
  }
  return graphs;
}

function normalizeIdentity(value) {
  const hasContextReuseAnalysis = Object.hasOwn(value, "contextReuseAnalysis");
  requireExactKeys(
    value,
    [
      "assumptions",
      "contextReusePolicy",
      ...(hasContextReuseAnalysis ? ["contextReuseAnalysis"] : []),
      "dependencyAdapter",
      "registrationAdapter",
      "toolchain",
    ],
    "source graph snapshot identity"
  );
  const identity = structuredClone(value);
  const enabledEntries = Array.isArray(identity.contextReusePolicy?.entries)
    ? identity.contextReusePolicy.entries
        .filter((entry) => entry?.enabled === true)
        .map((entry) => entry.entryPath)
        .sort(compareStrings)
    : [];
  if (enabledEntries.length > 0 && !hasContextReuseAnalysis) {
    fail("source graph snapshot identity has no complete context-reuse result");
  }
  if (hasContextReuseAnalysis) {
    identity.contextReuseAnalysis = authenticateConvexContextReuseResultIdentity(
      identity.contextReuseAnalysis,
      { expectedEntries: enabledEntries }
    );
  }
  canonicalJson(identity);
  return identity;
}

function normalizeLookupIdentity(value) {
  const hasContextReuseAnalysis = Object.hasOwn(value, "contextReuseAnalysis");
  requireExactKeys(
    value,
    [
      "assumptions",
      "bundleEntryPaths",
      "bundlerMaterials",
      "config",
      ...(hasContextReuseAnalysis ? ["contextReuseAnalysis"] : []),
      "contextReusePolicy",
      "dependencyAdapterDescriptor",
      "deploymentConfigurationEntryPath",
      "effectExecutionMode",
      "kind",
      "nodeEntryPaths",
      "registrationAdapter",
      "toolchain",
    ],
    "source graph snapshot lookup identity"
  );
  if (value.kind !== convexWasmSourceGraphSnapshotLookupIdentityKind) {
    fail("source graph snapshot lookup identity kind is unsupported");
  }
  const config = requireObject(value.config, "source graph snapshot lookup config");
  requireExactKeys(config, ["sha256", "size"], "source graph snapshot lookup config");
  const deploymentConfigurationEntryPath = value.deploymentConfigurationEntryPath;
  if (deploymentConfigurationEntryPath !== null) {
    normalizeRelativePath(
      deploymentConfigurationEntryPath,
      "source graph snapshot lookup deployment configuration entry path"
    );
  }
  const normalized = {
    assumptions: structuredClone(value.assumptions),
    bundleEntryPaths: normalizeSortedPaths(
      value.bundleEntryPaths,
      "source graph snapshot lookup bundle entry paths"
    ),
    bundlerMaterials: structuredClone(value.bundlerMaterials),
    config: {
      sha256: requireSha256(config.sha256, "source graph snapshot lookup config SHA-256"),
      size: requireNonnegativeSafeInteger(config.size, "source graph snapshot lookup config size"),
    },
    contextReusePolicy: structuredClone(value.contextReusePolicy),
    ...(hasContextReuseAnalysis
      ? {
          contextReuseAnalysis: authenticateConvexContextReuseResultIdentity(
            value.contextReuseAnalysis,
            {
              expectedEntries: Array.isArray(value.contextReusePolicy?.entries)
                ? value.contextReusePolicy.entries
                    .filter((entry) => entry?.enabled === true)
                    .map((entry) => entry.entryPath)
                : [],
            }
          ),
        }
      : {}),
    dependencyAdapterDescriptor: structuredClone(value.dependencyAdapterDescriptor),
    deploymentConfigurationEntryPath,
    effectExecutionMode: requireString(
      value.effectExecutionMode,
      "source graph snapshot lookup effect execution mode"
    ),
    kind: value.kind,
    nodeEntryPaths: normalizeSortedPaths(
      value.nodeEntryPaths,
      "source graph snapshot lookup Node entry paths"
    ),
    registrationAdapter: structuredClone(value.registrationAdapter),
    toolchain: structuredClone(value.toolchain),
  };
  if (
    Array.isArray(value.contextReusePolicy?.entries) &&
    value.contextReusePolicy.entries.some((entry) => entry?.enabled === true) &&
    !hasContextReuseAnalysis
  ) {
    fail("source graph snapshot lookup identity has no complete context-reuse result");
  }
  canonicalJson(normalized);
  return normalized;
}

function normalizeSession(value) {
  requireExactKeys(
    value,
    [
      "activeDependencyAdapters",
      "authoritativeInputMaterials",
      "bundleModulesByPath",
      "deploymentConfigurationInputMaterials",
      "deploymentConfigurationModulesByPath",
      "deploymentOutputModulesByPath",
      "metafile",
      "nodeInputMaterials",
      "nodeModulesByPath",
    ],
    "source graph snapshot session"
  );
  const session = structuredClone(value);
  canonicalJson(session);
  return session;
}

export function createConvexWasmSourceGraphSnapshotLookupIdentity(value) {
  return Object.freeze(normalizeLookupIdentity(value));
}

function normalizeAuthority(value) {
  let materialized;
  try {
    materialized = structuredClone(value);
  } catch (error) {
    fail(
      `source graph snapshot Git authority cannot be materialized: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
  validateConvexWasmGitSourceSnapshot(materialized, "source graph snapshot Git authority");
  return {
    entries: structuredClone(materialized.entries),
    kind: materialized.kind,
    objectFormat: materialized.objectFormat,
    pathspecs: [...materialized.pathspecs],
    treeOid: materialized.treeOid,
    untrackedPaths: [...materialized.untrackedPaths],
    unstagedPaths: [...materialized.unstagedPaths],
  };
}

function snapshotPayload(value) {
  requireExactKeys(
    value,
    [
      "authority",
      "dependencyGraphs",
      "identity",
      "inputs",
      "kind",
      "lookupIdentity",
      "schemaVersion",
      "session",
    ],
    "source graph snapshot"
  );
  if (value.kind !== convexWasmSourceGraphSnapshotKind || value.schemaVersion !== 2) {
    fail("source graph snapshot kind or schema version is unsupported");
  }
  const dependencyGraphs = normalizeDependencyGraphs(value.dependencyGraphs);
  const identity = normalizeIdentity(value.identity);
  const inputs = normalizeInputs(value.inputs);
  const lookupIdentity = normalizeLookupIdentity(value.lookupIdentity);
  // Cache selection authenticates lookupIdentity, while graph materialization consumes identity.
  // Bind their shared fields here so one persisted record cannot route under one configuration
  // and produce graph authority under another.
  for (const field of ["assumptions", "contextReusePolicy", "registrationAdapter", "toolchain"]) {
    if (canonicalJson(identity[field]) !== canonicalJson(lookupIdentity[field])) {
      fail(`source graph snapshot identity ${field} disagrees with its lookup identity`);
    }
  }
  if (
    Object.hasOwn(identity, "contextReuseAnalysis") !==
      Object.hasOwn(lookupIdentity, "contextReuseAnalysis") ||
    (Object.hasOwn(identity, "contextReuseAnalysis") &&
      canonicalJson(identity.contextReuseAnalysis) !==
        canonicalJson(lookupIdentity.contextReuseAnalysis))
  ) {
    fail(
      "source graph snapshot identity context-reuse analysis disagrees with its lookup identity"
    );
  }
  for (const graph of dependencyGraphs) {
    for (const path of graph.inputPaths) {
      if (!Object.hasOwn(inputs, path)) {
        fail(
          `source graph snapshot dependency graph ${graph.entryPath} references missing input ${path}`
        );
      }
    }
  }
  return {
    authority: normalizeAuthority(value.authority),
    dependencyGraphs,
    identity,
    inputs,
    kind: value.kind,
    lookupIdentity,
    schemaVersion: value.schemaVersion,
    session: normalizeSession(value.session),
  };
}

export function createConvexWasmSourceGraphSnapshot({ gitSourceSnapshot, graphSession } = {}) {
  requireObject(graphSession, "deployment graph session");
  if (!(graphSession.dependencyGraphByEntry instanceof Map)) {
    fail("deployment graph session has no dependency graph map");
  }
  const graphTemplate = requireObject(graphSession.graphTemplate, "deployment graph template");
  const payload = {
    authority: gitSourceSnapshot,
    dependencyGraphs: [...graphSession.dependencyGraphByEntry].map(([entryPath, graph]) => ({
      entryPath,
      inputPaths: graph.inputPaths,
      sha256: graph.sha256,
    })),
    identity: {
      assumptions: graphTemplate.assumptions,
      ...(graphSession.contextReuseAnalysisIdentity === undefined
        ? {}
        : { contextReuseAnalysis: graphSession.contextReuseAnalysisIdentity }),
      contextReusePolicy: graphSession.contextReusePolicy,
      dependencyAdapter: graphTemplate.dependencyAdapter,
      registrationAdapter: graphTemplate.registrationAdapter,
      toolchain: graphSession.toolchain,
    },
    inputs: graphSession.inputMaterials,
    kind: convexWasmSourceGraphSnapshotKind,
    lookupIdentity: graphSession.sourceGraphSnapshotLookupIdentity,
    schemaVersion: 2,
    session: graphSession.sourceGraphSnapshotSession,
  };
  const normalized = snapshotPayload(payload);
  return retainAuthenticatedSnapshot({ ...normalized, sha256: fingerprintJson(normalized) });
}

export function authenticateConvexWasmSourceGraphSnapshot(value) {
  if (authenticatedSourceGraphSnapshots.has(value)) return value;
  requireObject(value, "source graph snapshot");
  requireExactKeys(
    value,
    [
      "authority",
      "dependencyGraphs",
      "identity",
      "inputs",
      "kind",
      "lookupIdentity",
      "schemaVersion",
      "session",
      "sha256",
    ],
    "source graph snapshot"
  );
  const { sha256, ...payload } = value;
  const normalized = snapshotPayload(payload);
  if (requireSha256(sha256, "source graph snapshot SHA-256") !== fingerprintJson(normalized)) {
    fail("source graph snapshot SHA-256 does not match its payload");
  }
  return retainAuthenticatedSnapshot({ ...normalized, sha256 });
}

function authorityEntryMap(snapshot) {
  return new Map(
    snapshot.authority.entries.map((entry) => [
      `${entry.path}\0${String(entry.stage)}`,
      `${entry.mode}\0${entry.oid}`,
    ])
  );
}

function changedAuthorityPaths(from, to) {
  const before = authorityEntryMap(from);
  const after = authorityEntryMap(to);
  const paths = new Set();
  for (const [key, identity] of before) {
    if (after.get(key) !== identity) paths.add(key.slice(0, key.indexOf("\0")));
  }
  for (const [key, identity] of after) {
    if (before.get(key) !== identity) paths.add(key.slice(0, key.indexOf("\0")));
  }
  return [...paths].sort(compareStrings);
}

export function diffConvexWasmSourceGraphSnapshots({ fromSnapshot, toSnapshot } = {}) {
  const from = authenticateConvexWasmSourceGraphSnapshot(fromSnapshot);
  const to = authenticateConvexWasmSourceGraphSnapshot(toSnapshot);
  const changedPaths = new Set(changedAuthorityPaths(from, to));
  const allInputPaths = new Set([...Object.keys(from.inputs), ...Object.keys(to.inputs)]);
  for (const path of allInputPaths) {
    const before = from.inputs[path];
    const after = to.inputs[path];
    if (
      before === undefined ||
      after === undefined ||
      canonicalJson(before) !== canonicalJson(after)
    ) {
      changedPaths.add(path);
    }
  }
  const sortedChangedPaths = [...changedPaths].sort(compareStrings);
  const globalInvalidation =
    fingerprintJson(from.identity) !== fingerprintJson(to.identity) ||
    fingerprintJson(from.lookupIdentity) !== fingerprintJson(to.lookupIdentity) ||
    from.authority.objectFormat !== to.authority.objectFormat ||
    from.authority.pathspecs.join("\0") !== to.authority.pathspecs.join("\0");
  const changedSet = new Set(sortedChangedPaths);
  const invalidatedEntries = to.dependencyGraphs
    .filter((graph) => globalInvalidation || graph.inputPaths.some((path) => changedSet.has(path)))
    .map(({ entryPath }) => entryPath)
    .sort(compareStrings);
  const invalidatedInputPaths = to.dependencyGraphs
    .filter(({ entryPath }) => globalInvalidation || invalidatedEntries.includes(entryPath))
    .flatMap(({ inputPaths }) => inputPaths)
    .concat(globalInvalidation ? Object.keys(to.inputs) : sortedChangedPaths)
    .filter((path, index, values) => values.indexOf(path) === index)
    .sort(compareStrings);
  return {
    changedPaths: sortedChangedPaths,
    globalInvalidation,
    invalidatedEntries,
    invalidatedInputPaths,
  };
}

export const convexWasmSourceGraphSnapshotTestHooks = Object.freeze({
  normalizeInputs,
  snapshotPayload,
});
