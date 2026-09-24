import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { resolve } from "node:path";
import { TextDecoder } from "node:util";

import {
  collectConvexWasmRelativeSourceClosure,
  requireConvexWasmRepositoryRelativePath,
  requireConvexWasmSortedUniquePaths,
} from "./convex-wasm-relative-source-closure.mjs";

const MANIFEST_RELATIVE_PATH = "scripts/convex-wasm-artifact-producer-source-manifest.json";
const MANIFEST_KIND = "convex-wasm-artifact-producer-source-manifest";
const IDENTITY_KIND = "convex-wasm-artifact-producer-identity-v1";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex Wasm producer identity: ${message}`);
}

function requireExactKeys(value, expected, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const keys = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(`${description} must contain exactly ${expectedKeys.join(", ")}`);
  }
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

export function normalizeConvexWasmProducerIdentity(value) {
  const expectedKeys = ["kind", "manifest", "nodeVersion", "sha256", "sources"];
  if (Object.hasOwn(value, "operationalSources")) {
    expectedKeys.push("operationalSources");
  }
  requireExactKeys(value, expectedKeys, "producer identity");
  if (value.kind !== IDENTITY_KIND) {
    fail("producer identity kind is unsupported");
  }
  if (typeof value.nodeVersion !== "string" || value.nodeVersion.length === 0) {
    fail("producer identity Node version must be a non-empty string");
  }
  requireExactKeys(value.manifest, ["path", "sha256", "size"], "producer identity manifest");
  const manifest = Object.freeze({
    path: requireConvexWasmRepositoryRelativePath(
      value.manifest.path,
      "producer identity manifest path"
    ),
    sha256: requireSha256(value.manifest.sha256, "producer identity manifest SHA-256"),
    size: requireNonnegativeSafeInteger(value.manifest.size, "producer identity manifest size"),
  });
  if (!Array.isArray(value.sources) || value.sources.length === 0) {
    fail("producer identity sources must be a non-empty array");
  }
  const sourcePaths = value.sources.map((source, index) => {
    const description = `producer identity sources[${index}]`;
    requireExactKeys(source, ["path", "sha256", "size"], description);
    return requireConvexWasmRepositoryRelativePath(source.path, `${description} path`);
  });
  requireConvexWasmSortedUniquePaths(sourcePaths, "producer identity source paths");
  const sources = Object.freeze(
    value.sources.map((source, index) =>
      Object.freeze({
        path: sourcePaths[index],
        sha256: requireSha256(source.sha256, `producer identity sources[${index}] SHA-256`),
        size: requireNonnegativeSafeInteger(
          source.size,
          `producer identity sources[${index}] size`
        ),
      })
    )
  );
  if (value.operationalSources !== undefined && !Array.isArray(value.operationalSources)) {
    fail("producer identity operationalSources must be an array");
  }
  const operationalSources =
    value.operationalSources === undefined
      ? undefined
      : Object.freeze(
          value.operationalSources.map((source, index) => {
            const description = `producer identity operationalSources[${index}]`;
            requireExactKeys(source, ["path", "sha256", "size"], description);
            return Object.freeze({
              path: requireConvexWasmRepositoryRelativePath(source.path, `${description} path`),
              sha256: requireSha256(source.sha256, `${description} SHA-256`),
              size: requireNonnegativeSafeInteger(source.size, `${description} size`),
            });
          })
        );
  if (operationalSources !== undefined && operationalSources.length > 0) {
    requireConvexWasmSortedUniquePaths(
      operationalSources.map(({ path }) => path),
      "producer identity operational source paths"
    );
  }
  return Object.freeze({
    kind: IDENTITY_KIND,
    manifest,
    nodeVersion: value.nodeVersion,
    sha256: requireSha256(value.sha256, "producer identity SHA-256"),
    sources,
    ...(operationalSources === undefined ? {} : { operationalSources }),
  });
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function readStableSourceFile(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("source validation requires O_NOFOLLOW");
  }
  const beforePath = await fs.lstat(path);
  if (beforePath.isSymbolicLink() || !beforePath.isFile()) {
    fail(`source must be a non-symlink regular file: ${path}`);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.dev !== beforePath.dev || before.ino !== beforePath.ino) {
      fail(`source changed while it was opened: ${path}`);
    }
    const contents = await handle.readFile();
    const [after, afterPath] = await Promise.all([handle.stat(), fs.lstat(path)]);
    if (
      contents.length !== before.size ||
      !sameFileState(before, after) ||
      afterPath.isSymbolicLink() ||
      !afterPath.isFile() ||
      !sameFileState(after, afterPath)
    ) {
      fail(`source changed while it was read: ${path}`);
    }
    return contents;
  } finally {
    await handle.close();
  }
}

function decodeManifest(bytes) {
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error("Convex Wasm producer identity: manifest is not valid UTF-8", {
      cause: error,
    });
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm producer identity: manifest is not valid JSON", { cause: error });
  }
}

function validateManifest(manifest) {
  const manifestKeys = Object.keys(manifest).sort();
  const expectedKeys = ["kind", "roots", "schemaVersion"];
  if (Object.hasOwn(manifest, "operationalFiles")) {
    expectedKeys.push("operationalFiles");
  }
  const sortedExpectedKeys = expectedKeys.sort();
  if (
    manifestKeys.length !== sortedExpectedKeys.length ||
    manifestKeys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    fail(`manifest must contain exactly ${sortedExpectedKeys.join(", ")}`);
  }
  if (manifest.kind !== MANIFEST_KIND || manifest.schemaVersion !== 2) {
    fail("manifest kind or schema version is unsupported");
  }
  requireConvexWasmSortedUniquePaths(manifest.roots, "manifest roots");
  const operationalFiles = manifest.operationalFiles ?? [];
  if (!Array.isArray(operationalFiles)) {
    fail("manifest operationalFiles must be an array when present");
  }
  if (operationalFiles.length > 0) {
    requireConvexWasmSortedUniquePaths(operationalFiles, "manifest operationalFiles");
  }
  return new Set(operationalFiles);
}

function updateFramed(hash, value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  hash.update(`${bytes.length}:`);
  hash.update(bytes);
  hash.update("\0");
}

export async function buildConvexWasmProducerIdentity(repositoryRoot) {
  if (typeof repositoryRoot !== "string" || repositoryRoot.length === 0) {
    fail("repository root must be a non-empty string");
  }
  const normalizedRoot = resolve(repositoryRoot);
  const manifestBytes = await readStableSourceFile(resolve(normalizedRoot, MANIFEST_RELATIVE_PATH));
  const manifest = decodeManifest(manifestBytes);
  const operationalFiles = validateManifest(manifest);
  const closure = await collectConvexWasmRelativeSourceClosure({
    readSource: (relativePath) => readStableSourceFile(resolve(normalizedRoot, relativePath)),
    roots: manifest.roots,
  });
  for (const operationalFile of operationalFiles) {
    if (!closure.contentsByPath.has(operationalFile)) {
      fail(`manifest operational file is not reachable from a root: ${operationalFile}`);
    }
  }
  const sourcePairs = closure.paths.map((path) => [path, closure.contentsByPath.get(path)]);

  const hash = createHash("sha256");
  updateFramed(hash, IDENTITY_KIND);
  updateFramed(hash, process.version);
  updateFramed(hash, MANIFEST_RELATIVE_PATH);
  updateFramed(hash, manifestBytes);
  const sources = sourcePairs.flatMap(([path, contents]) => {
    if (operationalFiles.has(path)) {
      return [];
    }
    updateFramed(hash, path);
    updateFramed(hash, contents);
    return [
      Object.freeze({
        path,
        sha256: createHash("sha256").update(contents).digest("hex"),
        size: contents.length,
      }),
    ];
  });
  const operationalSources = sourcePairs.flatMap(([path, contents]) =>
    operationalFiles.has(path)
      ? [
          Object.freeze({
            path,
            sha256: createHash("sha256").update(contents).digest("hex"),
            size: contents.length,
          }),
        ]
      : []
  );

  return normalizeConvexWasmProducerIdentity({
    kind: IDENTITY_KIND,
    nodeVersion: process.version,
    manifest: Object.freeze({
      path: MANIFEST_RELATIVE_PATH,
      sha256: createHash("sha256").update(manifestBytes).digest("hex"),
      size: manifestBytes.length,
    }),
    operationalSources: Object.freeze(operationalSources),
    sources: Object.freeze(sources),
    sha256: hash.digest("hex"),
  });
}
