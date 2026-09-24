import { createHash, randomUUID } from "node:crypto";
import { constants, promises as fs } from "node:fs";
import { join } from "node:path";

import { validateAuthenticatedConvexOrigin } from "./convex-authenticated-origin.mjs";
import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex target external dependencies: ${message}`);
}

export function validateTargetExternalDepsSelection(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort()) !== canonicalJson(["id", "sha256"]) ||
    typeof value.id !== "string" ||
    value.id.length === 0 ||
    typeof value.sha256 !== "string" ||
    !SHA256.test(value.sha256)
  )
    fail("invalid exact package selection");
  return Object.freeze({ id: value.id, sha256: value.sha256 });
}

export function validateTargetExternalDepsDescriptor(value, nodeDependencies) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort()) !==
      canonicalJson(["dependencies", "id", "kind", "sha256", "size", "storageKey"]) ||
    value.kind !== "convex-external-deps-package-v1" ||
    typeof value.storageKey !== "string" ||
    value.storageKey.length === 0 ||
    !Number.isSafeInteger(value.size) ||
    value.size <= 0 ||
    value.size > MAX_ARCHIVE_BYTES ||
    !Array.isArray(nodeDependencies) ||
    nodeDependencies.length === 0
  )
    fail("invalid admitted package descriptor");
  validateTargetExternalDepsSelection({ id: value.id, sha256: value.sha256 });
  const dependencies = nodeDependencies
    .map(({ name, version }) => {
      if (
        typeof name !== "string" ||
        name.length === 0 ||
        typeof version !== "string" ||
        version.length === 0
      ) {
        fail("invalid dependency declaration");
      }
      return { package: name, version };
    })
    .sort((left, right) =>
      left.package < right.package ? -1 : left.package > right.package ? 1 : 0
    );
  if (
    new Set(dependencies.map(({ package: name }) => name)).size !== dependencies.length ||
    canonicalJson(dependencies) !== canonicalJson(value.dependencies)
  ) {
    fail("admitted dependency declarations differ from request");
  }
  return Object.freeze({ ...value, dependencies: Object.freeze(dependencies.map(Object.freeze)) });
}

async function readBoundedResponse(response, maximumBytes) {
  if (!response.ok || response.body === null) fail("target request failed");
  const chunks = [];
  let size = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maximumBytes) fail("target response exceeds its byte limit");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  return Buffer.concat(chunks, size);
}

export async function prepareTargetExternalDeps(
  {
    adminKey,
    archive,
    artifactCacheRoot,
    externalDepsPackageOutputPath,
    nodeDependencies,
    signal,
    url,
  },
  { fetchImplementation = fetch } = {}
) {
  const origin = validateAuthenticatedConvexOrigin(url, "Target dependency URL");
  if (
    typeof adminKey !== "string" ||
    adminKey.length === 0 ||
    adminKey.includes("\r") ||
    adminKey.includes("\n") ||
    adminKey.includes("\u0000")
  ) {
    fail("invalid deployment credential");
  }
  if (!Array.isArray(nodeDependencies) || nodeDependencies.length === 0)
    fail("nonempty declarations required");
  // Frozen replay imports admitted bytes, not a fresh resolution of the names.
  // The returned document ID belongs to this destination only.
  if (
    archive !== undefined &&
    (!Buffer.isBuffer(archive.bytes) ||
      archive.bytes.length === 0 ||
      archive.bytes.length > MAX_ARCHIVE_BYTES ||
      typeof archive.sha256 !== "string" ||
      !SHA256.test(archive.sha256) ||
      createHash("sha256").update(archive.bytes).digest("hex") !== archive.sha256)
  )
    fail("supplied archive differs from the frozen selection");
  const post = async (endpoint, body, maximumBytes, timeoutMs) => {
    const timeout = AbortSignal.timeout(timeoutMs);
    const requestSignal = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
    const response = await fetchImplementation(new URL(`/api/deploy2/${endpoint}`, origin), {
      method: "POST",
      redirect: "error",
      headers: { Authorization: `Convex ${adminKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ adminKey, ...body }),
      signal: requestSignal,
    });
    const bytes = await readBoundedResponse(response, maximumBytes);
    requestSignal.throwIfAborted();
    return bytes;
  };
  const descriptor = validateTargetExternalDepsDescriptor(
    JSON.parse(
      (
        await post(
          "prepare_external_deps",
          {
            nodeDependencies,
            ...(archive === undefined
              ? {}
              : {
                  archive: { sha256: archive.sha256, bytes: archive.bytes.toString("base64url") },
                }),
          },
          1024 * 1024,
          15 * 60 * 1000
        )
      ).toString("utf8")
    ),
    nodeDependencies
  );
  if (
    archive !== undefined &&
    (descriptor.sha256 !== archive.sha256 || descriptor.size !== archive.bytes.length)
  )
    fail("target imported a different archive");
  const cacheDirectory = join(artifactCacheRoot, "target-external-deps-v1");
  await fs.mkdir(cacheDirectory, { recursive: true, mode: 0o700 });
  const directory = await fs.lstat(cacheDirectory);
  if (
    !directory.isDirectory() ||
    directory.isSymbolicLink() ||
    (directory.mode & 0o777) !== 0o700 ||
    (typeof process.getuid === "function" && directory.uid !== process.getuid())
  )
    fail("archive cache is not private");
  const cachePath = join(cacheDirectory, `${descriptor.sha256}.zip`);
  let bytes;
  try {
    const handle = await fs.open(cachePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const status = await handle.stat();
      if (
        !status.isFile() ||
        status.size !== descriptor.size ||
        (status.mode & 0o777) !== 0o600 ||
        (typeof process.getuid === "function" && status.uid !== process.getuid())
      )
        fail("cached archive identity is invalid");
      bytes = await handle.readFile();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const cache = bytes === undefined ? "miss" : "hit";
  if (bytes === undefined) {
    bytes =
      archive === undefined
        ? await post(
            "download_external_deps",
            { id: descriptor.id, sha256: descriptor.sha256 },
            descriptor.size,
            5 * 60 * 1000
          )
        : archive.bytes;
  }
  if (
    bytes.length !== descriptor.size ||
    createHash("sha256").update(bytes).digest("hex") !== descriptor.sha256
  ) {
    fail("archive SHA-256 or size differs from admission");
  }
  signal?.throwIfAborted();
  if (cache === "miss") {
    const temporaryPath = join(cacheDirectory, `pending-${randomUUID()}`);
    const handle = await fs.open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      try {
        await fs.link(temporaryPath, cachePath);
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
    } finally {
      await handle.close();
      await fs.rm(temporaryPath);
    }
  }
  await fs.writeFile(externalDepsPackageOutputPath, bytes, { flag: "wx", mode: 0o600 });
  return Object.freeze({ cache, descriptor });
}
