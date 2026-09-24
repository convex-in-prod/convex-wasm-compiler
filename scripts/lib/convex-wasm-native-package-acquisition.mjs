import { createWriteStream, promises as fs } from "node:fs";
import { join, resolve } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import {
  loadAndVerifyCompilerPackage,
  platformForCompilerTarget,
  validateCompilerPackageManifest,
} from "./convex-wasm-compiler-package.mjs";
import {
  loadAndVerifyPrecompilerPackage,
  validatePrecompilerPackageManifest,
} from "./convex-wasm-precompiler-package.mjs";

const PACKAGE_KINDS = {
  compiler: {
    binaryName: "convex-wasm-compiler",
    load: loadAndVerifyCompilerPackage,
    validateManifest: validateCompilerPackageManifest,
  },
  precompiler: {
    binaryName: "convex-wasm-precompiler",
    load: loadAndVerifyPrecompilerPackage,
    validateManifest: validatePrecompilerPackageManifest,
  },
};
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_BINARY_BYTES = 512 * 1024 * 1024;

export function validateNativePackageReference(reference) {
  if (typeof reference !== "object" || reference === null || Array.isArray(reference)) {
    throw new Error("Native package reference must be an object.");
  }
  const keys = Object.keys(reference).sort().join(",");
  if (keys !== "packageId,targetTriple" && keys !== "download,packageId,targetTriple") {
    throw new Error("Native package reference has unsupported fields.");
  }
  if (typeof reference.packageId !== "string" || !/^[0-9a-f]{64}$/u.test(reference.packageId)) {
    throw new Error("Native package ID must be a lowercase SHA-256 digest.");
  }
  const platform = platformForCompilerTarget(reference.targetTriple);
  if (Object.hasOwn(reference, "download")) {
    const download = reference.download;
    if (
      typeof download !== "object" ||
      download === null ||
      Array.isArray(download) ||
      Object.keys(download).sort().join(",") !== "binaryUrl,manifestUrl"
    ) {
      throw new Error("Native package download requires manifestUrl and binaryUrl.");
    }
    for (const value of Object.values(download)) {
      const url = new URL(value);
      if (
        typeof value !== "string" ||
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.hash
      ) {
        throw new Error(
          "Native package downloads require HTTPS URLs without embedded credentials or fragments."
        );
      }
    }
  }
  return platform;
}

async function downloadFile(url, destination, maximumBytes, mode, signal) {
  const response = await fetch(url, { signal });
  if (!response.ok || response.body === null) {
    await response.body?.cancel();
    throw new Error(`Native package download failed with HTTP ${response.status}.`);
  }
  let size = 0;
  await pipeline(
    Readable.fromWeb(response.body),
    new Transform({
      transform(chunk, _encoding, callback) {
        size += chunk.length;
        callback(
          size > maximumBytes
            ? new Error(`Native package download exceeds its ${maximumBytes}-byte limit.`)
            : null,
          chunk
        );
      },
    }),
    createWriteStream(destination, { flags: "wx", mode }),
    { signal }
  );
  // Package permissions are fixed even when the developer uses a restrictive umask.
  await fs.chmod(destination, mode);
}

/**
 * Acquire a selected native package, not a complete Wasm deployment toolchain.
 * Release URLs are consulted only on a cache miss; the package ID directory is
 * the immutable cache key shared by all checkouts on this host.
 */
export async function acquireNativePackage({ kind, reference, packageRoot, signal }) {
  const platform = validateNativePackageReference(reference);
  const implementation = Object.hasOwn(PACKAGE_KINDS, kind) ? PACKAGE_KINDS[kind] : undefined;
  if (implementation === undefined) {
    throw new Error("Native package kind must be compiler or precompiler.");
  }
  if (platform.os !== process.platform || platform.arch !== process.arch) {
    throw new Error("Selected native package does not match the developer host.");
  }
  const operationSignal =
    signal === undefined
      ? AbortSignal.timeout(120_000)
      : AbortSignal.any([signal, AbortSignal.timeout(120_000)]);
  operationSignal.throwIfAborted();
  const targetRoot = resolve(packageRoot, reference.targetTriple);
  const packageDirectory = join(targetRoot, reference.packageId);
  const verifySelection = (loaded) => {
    // Package readers perform asynchronous filesystem work without a signal. Do not
    // turn an interrupt during cache verification into a successful acquisition.
    operationSignal.throwIfAborted();
    if (
      loaded.manifest.packageId !== reference.packageId ||
      loaded.manifest.platform.targetTriple !== reference.targetTriple
    ) {
      throw new Error("Acquired native package does not match its selected identity.");
    }
    return loaded;
  };
  let exists = true;
  try {
    await fs.lstat(packageDirectory);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    exists = false;
  }
  if (exists) return verifySelection(await implementation.load(packageDirectory));
  if (reference.download === undefined) {
    throw new Error("Selected native package is missing and has no published package material.");
  }

  await fs.mkdir(targetRoot, { recursive: true, mode: 0o700 });
  const temporaryRoot = await fs.mkdtemp(join(targetRoot, ".download-"));
  // Keep the package ID basename required by existing package readers. The outer
  // directory is private scratch; only a completely verified package becomes visible.
  const stagedDirectory = join(temporaryRoot, reference.packageId);
  try {
    await fs.mkdir(stagedDirectory, { mode: 0o700 });
    await fs.chmod(stagedDirectory, 0o700);
    const manifestPath = join(stagedDirectory, "manifest.json");
    await downloadFile(
      reference.download.manifestUrl,
      manifestPath,
      MAX_MANIFEST_BYTES,
      0o600,
      operationSignal
    );
    const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
    implementation.validateManifest(manifest);
    verifySelection({ manifest });
    if (manifest.binary.size > MAX_BINARY_BYTES) {
      throw new Error("Selected native package binary exceeds the download size limit.");
    }
    const binaryDirectory = join(stagedDirectory, "bin");
    await fs.mkdir(binaryDirectory, { mode: 0o700 });
    await fs.chmod(binaryDirectory, 0o700);
    const binaryPath = join(binaryDirectory, implementation.binaryName);
    await downloadFile(
      reference.download.binaryUrl,
      binaryPath,
      manifest.binary.size,
      0o700,
      operationSignal
    );
    const loaded = verifySelection(await implementation.load(stagedDirectory));
    try {
      await fs.rename(stagedDirectory, packageDirectory);
    } catch (error) {
      if (error.code !== "EEXIST" && error.code !== "ENOTEMPTY") throw error;
      // Another checkout can win installation of the same immutable package. Its
      // result is consumed only after the normal package reader accepts it.
      return verifySelection(await implementation.load(packageDirectory));
    }
    return {
      ...loaded,
      packageDirectory,
      binaryPath: join(packageDirectory, "bin", implementation.binaryName),
      manifestPath: join(packageDirectory, "manifest.json"),
    };
  } finally {
    await fs.rm(temporaryRoot, { recursive: true, force: true });
    // Cancellation can arrive during rename or cleanup after verification. A fully
    // published package stays reusable, but the interrupted caller does not continue.
    operationSignal.throwIfAborted();
  }
}
