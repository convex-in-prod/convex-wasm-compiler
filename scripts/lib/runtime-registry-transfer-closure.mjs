import path from "node:path";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const STAGE_PATTERN = /^module-graph-[a-z][a-z0-9-]{0,127}-(?:core-wasm|wasmtime-aot)$/u;
const SOURCE_CATALOG_KIND_V1 = "convex-wasm-runtime-registry-source-catalog-v1";
const SOURCE_CATALOG_KIND_V2 = "convex-wasm-runtime-registry-source-catalog-v2";
const MAX_REGISTRY_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_SOURCE_CATALOG_ENTRIES = 4096;

function fail(message) {
  throw new Error(message);
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireExactFields(value, fields, description) {
  const object = requireObject(value, description);
  if (canonicalJson(Object.keys(object).sort()) !== canonicalJson([...fields].sort())) {
    fail(`${description} fields are invalid`);
  }
  return object;
}

export function validateRuntimeRegistrySourceCatalog(value) {
  const catalog = requireExactFields(
    value,
    ["catalogSha256", "entries", "kind"],
    "runtime registry source catalog"
  );
  if (catalog.kind !== SOURCE_CATALOG_KIND_V1 && catalog.kind !== SOURCE_CATALOG_KIND_V2) {
    fail("runtime registry source catalog kind is unsupported");
  }
  if (
    !Array.isArray(catalog.entries) ||
    catalog.entries.length === 0 ||
    catalog.entries.length > MAX_SOURCE_CATALOG_ENTRIES
  ) {
    fail(`runtime registry source catalog must contain 1 through ${MAX_SOURCE_CATALOG_ENTRIES} entries`);
  }
  const entries = catalog.entries.map((entryValue, index) => {
    const description = `runtime registry source catalog entry ${index}`;
    const entry = requireExactFields(
      entryValue,
      ["deploymentSha256", "generation", "generationSha256", "sourcePackageRuntimeContentSha256"],
      description
    );
    const generation = requireExactFields(
      entry.generation,
      ["sha256", "size"],
      `${description} generation`
    );
    if (
      !Number.isSafeInteger(generation.size) ||
      generation.size <= 0 ||
      generation.size > MAX_REGISTRY_MANIFEST_BYTES
    ) {
      fail(`${description} generation size is invalid`);
    }
    return {
      deploymentSha256: requireSha256(entry.deploymentSha256, `${description} deploymentSha256`),
      generation: {
        sha256: requireSha256(generation.sha256, `${description} generation sha256`),
        size: generation.size,
      },
      generationSha256: requireSha256(entry.generationSha256, `${description} generationSha256`),
      sourcePackageRuntimeContentSha256: requireSha256(
        entry.sourcePackageRuntimeContentSha256,
        `${description} sourcePackageRuntimeContentSha256`
      ),
    };
  });
  if (
    entries.some((entry, index) => {
      if (index === 0) return false;
      const previous = entries[index - 1];
      return catalog.kind === SOURCE_CATALOG_KIND_V1
        ? previous.sourcePackageRuntimeContentSha256 >= entry.sourcePackageRuntimeContentSha256
        : sourceCatalogEntryKey(previous) >= sourceCatalogEntryKey(entry);
    })
  ) {
    fail("runtime registry source catalog entries must have unique, sorted exact pair keys");
  }
  const withoutIdentity = { entries, kind: catalog.kind };
  const catalogSha256 = requireSha256(catalog.catalogSha256, "source catalog identity");
  if (catalogSha256 !== fingerprintJson(withoutIdentity)) {
    fail("runtime registry source catalog identity differs from its contents");
  }
  return { catalogSha256, ...withoutIdentity };
}

export function createRuntimeRegistrySourceCatalog(entries) {
  const sortedEntries = [...entries].sort((left, right) =>
    sourceCatalogEntryKey(left).localeCompare(sourceCatalogEntryKey(right))
  );
  const withoutIdentity = { entries: sortedEntries, kind: SOURCE_CATALOG_KIND_V2 };
  const manifest = validateRuntimeRegistrySourceCatalog({
    catalogSha256: fingerprintJson(withoutIdentity),
    ...withoutIdentity,
  });
  return Object.freeze({ bytes: Buffer.from(`${canonicalJson(manifest)}\n`), manifest });
}

function relativeRegistryPath(registryRoot, absolutePath, expected, description) {
  if (typeof absolutePath !== "string" || !path.isAbsolute(absolutePath)) {
    fail(`${description} must be an absolute path`);
  }
  const relativePath = path.relative(registryRoot, absolutePath).split(path.sep).join("/");
  if (
    relativePath.length === 0 ||
    relativePath === ".." ||
    relativePath.startsWith("../") ||
    path.isAbsolute(relativePath) ||
    relativePath !== expected
  ) {
    fail(`${description} is outside its authenticated registry layout`);
  }
  return relativePath;
}

function addDirectory(paths, relativePath) {
  const components = relativePath.split("/");
  for (let length = 1; length <= components.length; length += 1) {
    paths.add(components.slice(0, length).join("/"));
  }
}

function addFile(paths, relativePath) {
  addDirectory(paths, path.posix.dirname(relativePath));
  paths.add(relativePath);
}

function generationKey({ deploymentSha256, generationSha256 }) {
  return `${deploymentSha256}:${generationSha256}`;
}

function sourceCatalogEntryKey(entry) {
  return JSON.stringify([
    entry.sourcePackageRuntimeContentSha256,
    entry.deploymentSha256,
    entry.generation.sha256,
    entry.generationSha256,
  ]);
}

function compareTransferPaths(left, right) {
  const depth = left.split("/").length - right.split("/").length;
  return depth === 0 ? left.localeCompare(right) : depth;
}

export function deriveRuntimeRegistryTransferPlan(preflight, { retainedSourceCatalog } = {}) {
  requireObject(preflight, "runtime registry preflight");
  const runtimeRegistry = requireObject(
    preflight.runtimeRegistry,
    "runtime registry preflight identity"
  );
  const registryRoot = runtimeRegistry.path;
  if (typeof registryRoot !== "string" || !path.isAbsolute(registryRoot)) {
    fail("runtime registry preflight path must be absolute");
  }
  const sourceCatalog = requireObject(
    runtimeRegistry.sourceCatalog,
    "runtime registry source catalog"
  );
  if (!Array.isArray(sourceCatalog.entries) || sourceCatalog.entries.length === 0) {
    fail("runtime registry source catalog must contain at least one entry");
  }
  if (!Array.isArray(runtimeRegistry.generationReferences)) {
    fail("runtime registry preflight generation references must be an array");
  }

  const referencesByKey = new Map();
  for (const referenceValue of runtimeRegistry.generationReferences) {
    const reference = requireObject(referenceValue, "runtime registry generation reference");
    requireSha256(reference.deploymentSha256, "runtime registry deployment identity");
    requireSha256(reference.generationSha256, "runtime registry generation identity");
    const key = generationKey(reference);
    if (referencesByKey.has(key)) {
      fail("runtime registry preflight repeats a generation reference");
    }
    referencesByKey.set(key, reference);
  }

  const catalogEntriesByKey = new Map();
  for (const entryValue of sourceCatalog.entries) {
    const entry = requireObject(entryValue, "runtime registry source catalog entry");
    requireSha256(entry.deploymentSha256, "source catalog deployment identity");
    requireSha256(entry.generationSha256, "source catalog generation identity");
    requireSha256(
      entry.sourcePackageRuntimeContentSha256,
      "source catalog source-package identity"
    );
    const key = generationKey(entry);
    if (catalogEntriesByKey.has(key)) {
      fail("runtime registry source catalog repeats a generation reference");
    }
    catalogEntriesByKey.set(key, entry);
  }

  const retainedEntries =
    retainedSourceCatalog === undefined
      ? []
      : validateRuntimeRegistrySourceCatalog(retainedSourceCatalog).entries;
  for (const retainedEntry of retainedEntries) {
    const localEntry = catalogEntriesByKey.get(generationKey(retainedEntry));
    if (localEntry !== undefined && JSON.stringify(localEntry) !== JSON.stringify(retainedEntry)) {
      fail("destination source catalog conflicts with the local catalog for one generation");
    }
  }

  const reachable = new Map();
  for (const reference of referencesByKey.values()) {
    const entry = catalogEntriesByKey.get(generationKey(reference));
    if (
      entry === undefined ||
      reference.sourcePackageRuntimeContentSha256 !== entry.sourcePackageRuntimeContentSha256 ||
      reference.generation?.sha256 !== entry.generation?.sha256 ||
      reference.generation?.size !== entry.generation?.size
    ) {
      fail("source catalog entry differs from its authenticated generation reference");
    }
    reachable.set(generationKey(reference), reference);
  }

  const artifactPayloads = new Map();
  const hardlinksByTarget = new Map();
  const paths = new Set();
  addDirectory(paths, "generations");
  addDirectory(paths, "packages");
  addDirectory(paths, "module-graph-cache/immutable/v6/artifacts");
  addDirectory(paths, "module-graph-cache/immutable/v6/packages");

  for (const reference of reachable.values()) {
    const deploymentSha256 = requireSha256(
      reference.deploymentSha256,
      "reachable deployment identity"
    );
    const generationSha256 = requireSha256(
      reference.generationSha256,
      "reachable generation identity"
    );
    const generationRoot = `generations/${deploymentSha256}/${generationSha256}`;
    for (const name of ["COMPLETE", "deployment.json", "generation.json"]) {
      addFile(paths, `${generationRoot}/${name}`);
    }

    if (!Array.isArray(reference.moduleGraphs) || reference.moduleGraphs.length === 0) {
      fail("selective registry transfer requires module-graph generation references");
    }
    for (const graphValue of reference.moduleGraphs) {
      const graph = requireObject(graphValue, "runtime registry module graph");
      const graphManifestSha256 = requireSha256(
        graph.graphManifestSha256,
        "module graph manifest identity"
      );
      const packageRoot = `module-graph-cache/immutable/v6/packages/${graphManifestSha256}`;
      relativeRegistryPath(
        registryRoot,
        graph.packagePath,
        packageRoot,
        "module graph package path"
      );
      relativeRegistryPath(
        registryRoot,
        graph.graphManifestPath,
        `${packageRoot}/graph-manifest.json`,
        "module graph manifest path"
      );
      for (const name of [
        "COMPLETE",
        "build-provenance.json",
        "graph-manifest.json",
        "package-entry.json",
      ]) {
        addFile(paths, `${packageRoot}/${name}`);
      }

      const graphArtifacts = requireObject(graph.artifacts, "module graph artifacts");
      if (!Array.isArray(graphArtifacts.shared)) {
        fail("module graph shared artifacts must be an array");
      }
      for (const moduleValue of [
        graphArtifacts.base,
        ...graphArtifacts.shared,
        graphArtifacts.leaf,
      ]) {
        const moduleArtifacts = requireObject(moduleValue, "module graph role artifacts");
        for (const [kind, payloadName] of [
          ["coreWasm", "artifact.wasm"],
          ["aot", "artifact.cwasm"],
        ]) {
          const artifact = requireObject(moduleArtifacts[kind], `module graph ${kind} artifact`);
          if (typeof artifact.stage !== "string" || !STAGE_PATTERN.test(artifact.stage)) {
            fail(`module graph ${kind} artifact has an unsupported stage`);
          }
          const cacheKey = requireSha256(artifact.cacheKey, `module graph ${kind} cache key`);
          const artifactSha256 = requireSha256(
            artifact.sha256,
            `module graph ${kind} artifact identity`
          );
          if (!Number.isSafeInteger(artifact.size) || artifact.size <= 0) {
            fail(`module graph ${kind} artifact size must be a positive safe integer`);
          }
          const expectedStageSuffix = kind === "coreWasm" ? "-core-wasm" : "-wasmtime-aot";
          if (!artifact.stage.endsWith(expectedStageSuffix)) {
            fail(`module graph ${kind} artifact stage does not match its kind`);
          }
          const artifactRoot = `module-graph-cache/immutable/v6/artifacts/${artifact.stage}/${cacheKey}`;
          const artifactPath = `${artifactRoot}/${payloadName}`;
          relativeRegistryPath(
            registryRoot,
            artifact.path,
            artifactPath,
            `module graph ${kind} artifact path`
          );
          for (const name of ["COMPLETE", "entry.json"]) {
            addFile(paths, `${artifactRoot}/${name}`);
          }
          // The local build already produced compatible AOT. Transfer it with
          // the same content deduplication as Core Wasm instead of repeating
          // compilation on the production host before activation.
          const identity = `${kind}:${artifactSha256}`;
          const canonical = artifactPayloads.get(identity);
          if (canonical === undefined) {
            artifactPayloads.set(identity, { path: artifactPath, size: artifact.size });
            addFile(paths, artifactPath);
          } else if (canonical.size !== artifact.size) {
            fail(`module graph ${kind} artifact identity repeats with a different size`);
          } else if (canonical.path !== artifactPath) {
            const previousSource = hardlinksByTarget.get(artifactPath);
            if (previousSource !== undefined && previousSource !== canonical.path) {
              fail("runtime registry hard-link target has conflicting source identities");
            }
            addDirectory(paths, artifactRoot);
            hardlinksByTarget.set(artifactPath, canonical.path);
          }
        }
      }
    }
  }

  const outputCatalogEntries = new Map(
    retainedEntries.map((entry) => [sourceCatalogEntryKey(entry), entry])
  );
  for (const key of reachable.keys()) {
    const entry = catalogEntriesByKey.get(key);
    outputCatalogEntries.set(sourceCatalogEntryKey(entry), entry);
  }
  const { bytes: sourceCatalogBytes } = createRuntimeRegistrySourceCatalog([
    ...outputCatalogEntries.values(),
  ]);

  return Object.freeze({
    hardlinks: Object.freeze(
      [...hardlinksByTarget]
        .map(([target, source]) => Object.freeze({ source, target }))
        .sort((left, right) => left.target.localeCompare(right.target))
    ),
    paths: Object.freeze([...paths].sort(compareTransferPaths)),
    sourceCatalogBytes,
  });
}

export function deriveRuntimeRegistryTransferPaths(preflight) {
  return deriveRuntimeRegistryTransferPlan(preflight).paths;
}
