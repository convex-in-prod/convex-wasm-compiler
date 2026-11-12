import { promises as fs } from "node:fs";
import { availableParallelism } from "node:os";
import { join } from "node:path";

import {
  acquireNativeReleaseFromSelectionFile,
  bundledNativeReleaseSelectionPath,
  defaultNativePackageCacheRoot,
} from "../acquire-convex-wasm-native-release.mjs";
import { canonicalJson, requireExactPlainObject, requirePositiveInteger, requireSha256 } from "./convex-wasm-artifact-contract.mjs";
import { mapBounded } from "./convex-wasm-artifact-material.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-stage.mjs";
import { verifyToolchainPackage } from "./convex-wasm-toolchain-package.mjs";
import { loadAndVerifyPrecompilerPackage } from "./convex-wasm-precompiler-package.mjs";
import { createConvexWasmNativeCommandRunner } from "./convex-wasm-native-command-runner.mjs";

export const snapshotMetadataKind = "convex-wasm-module-snapshot-v1";
const MAX_METADATA_BYTES = 16 * 1024 * 1024;

export function validateSnapshotMetadata(value, core) {
  requireExactPlainObject(value, ["kind", "coreSha256", "coreSize", "state"], "module snapshot metadata");
  requireSha256(value.coreSha256, "snapshot Core digest");
  requirePositiveInteger(value.coreSize, "snapshot Core size");
  if (value.kind !== snapshotMetadataKind || value.coreSha256 !== core.sha256 || value.coreSize !== core.size) {
    throw new Error("Module snapshot metadata version or Core identity differs from its artifact");
  }
  if (value.state?.kind === "supported") {
    requireExactPlainObject(value.state, ["kind", "globals", "stackLimits"], "snapshot state");
    if (!Array.isArray(value.state.globals) || value.state.globals.some((name) => typeof name !== "string" || name.length === 0) ||
        new Set(value.state.globals).size !== value.state.globals.length || typeof value.state.stackLimits !== "boolean") {
      throw new Error("Module snapshot restoration fields are invalid");
    }
  } else if (value.state?.kind === "unsupported") {
    requireExactPlainObject(value.state, ["kind", "reason"], "snapshot state");
    if (typeof value.state.reason !== "string" || value.state.reason.length === 0) {
      throw new Error("Module snapshot rejection has no reason");
    }
  } else {
    throw new Error("Module snapshot state is unsupported");
  }
  return value;
}

// Derived metadata has its own cache identity. It never changes an existing Core,
// AOT, or graph-package entry. Generations carry the small result inline, so cache
// pruning may discard this derivation without invalidating a published generation.
export async function prepareRuntimeRegistrySnapshotMetadata(moduleGraphs, {
  toolchainRoot,
  // Callers resolve environment overrides; a selected release must not inherit an unrelated one.
  precompilerPackageDirectory,
  nativeReleaseSelectionPath = bundledNativeReleaseSelectionPath,
  nativePackageCacheRoot = defaultNativePackageCacheRoot(),
  concurrency = availableParallelism(),
  signal = AbortSignal.timeout(120_000),
} = {}) {
  requirePositiveInteger(concurrency, "snapshot inspection concurrency");
  const runCommand = createConvexWasmNativeCommandRunner({
    environment: process.env, signal, timeoutMs: 120_000, maxOutputBytes: 64 * 1024,
  });
  let precompiler;
  const entries = new Map();
  const work = [];
  for (const graph of moduleGraphs) {
    for (const record of graph.record.artifacts) {
      if (record.kind !== "coreWasm") continue;
      const key = `${graph.cacheLayout.cacheRoot}/${record.sha256}/${record.size}`;
      if (entries.has(key)) continue;
      entries.set(key, undefined);
      work.push({ key, graph, record });
    }
  }
  await mapBounded(work, concurrency, async ({ key, graph, record }) => {
    const { cacheLayout } = graph;
    const cached = await ensureArtifactStage({
      cacheLayout,
      cacheRoot: cacheLayout.cacheRoot,
      stage: "module-snapshot-metadata",
      extension: "json",
      identity: { kind: snapshotMetadataKind, coreSha256: record.sha256, coreSize: record.size },
      maxArtifactBytes: MAX_METADATA_BYTES,
      readCachedArtifactContents: true,
      readPublishedArtifactContents: true,
      build: async (workPath) => {
        precompiler ??= (async () => {
          if (toolchainRoot !== undefined) {
            const bundle = await verifyToolchainPackage(toolchainRoot);
            return await loadAndVerifyPrecompilerPackage(join(toolchainRoot, bundle.nativePackages.precompiler));
          }
          if (precompilerPackageDirectory !== undefined) return await loadAndVerifyPrecompilerPackage(precompilerPackageDirectory);
          const packages = await acquireNativeReleaseFromSelectionFile({ selectionPath: nativeReleaseSelectionPath, cacheRoot: nativePackageCacheRoot, signal });
          return packages.precompiler;
        })();
        const { binaryPath } = await precompiler;
        const outputPath = join(workPath, "snapshot.json");
        const corePath = join(cacheLayout.immutable.artifacts, record.stage, record.cacheKey, "artifact.wasm");
        // Cancellation must drain the child before stage cleanup and cache-lock release.
        await runCommand({
          command: { executable: binaryPath, args: ["--snapshot-metadata", corePath, outputPath] },
          stage: "module-snapshot-metadata",
          workPath,
        });
        const status = await fs.stat(outputPath);
        if (status.size > MAX_METADATA_BYTES) throw new Error("Module snapshot metadata exceeds its size limit");
        const metadata = validateSnapshotMetadata(JSON.parse(await fs.readFile(outputPath, "utf8")), record);
        await fs.writeFile(outputPath, `${canonicalJson(metadata)}\n`);
        return { metadata: null, outputPath, timing: null };
      },
    });
    entries.set(key, validateSnapshotMetadata(JSON.parse(cached.entry.artifactContents.toString("utf8")), record));
  });
  return moduleGraphs.map((graph) => ({
    ...graph,
    record: { ...graph.record, artifacts: graph.record.artifacts.map((record) => record.kind === "coreWasm"
      ? { ...record, snapshotMetadata: entries.get(`${graph.cacheLayout.cacheRoot}/${record.sha256}/${record.size}`) }
      : record) },
  }));
}
