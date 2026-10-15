import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { deriveConvexWasmCacheLayout } from "./lib/convex-wasm-cache-layout.mjs";
import { loadAndVerifyConvexWasmModuleGraphPackage } from "./lib/convex-wasm-module-graph-package.mjs";

export async function prepareConvexWasmGraphInitialization({ configurationPath, outputPath }) {
  const bytes = await readFile(configurationPath);
  const configuration = JSON.parse(bytes);
  const { cacheRoot: inputCacheRoot, graphs: requestedGraphs, ...measurement } = configuration;
  const cacheRoot = resolve(dirname(configurationPath), inputCacheRoot);
  assert(Array.isArray(requestedGraphs) && requestedGraphs.length > 0, "graphs must be nonempty");
  const cacheLayout = deriveConvexWasmCacheLayout({
    cacheRoot,
    buildId: "graph-initialization-measurement",
    repositoryRoot: process.cwd(),
    scope: "isolated-test",
  });
  const graphs = [];
  for (const requested of requestedGraphs) {
    assert.match(requested.graphManifestSha256, /^[0-9a-f]{64}$/u);
    const verified = await loadAndVerifyConvexWasmModuleGraphPackage({
      cacheLayout,
      cacheRoot,
      graphManifestSha256: requested.graphManifestSha256,
      packagePath: join(cacheLayout.immutable.packages, requested.graphManifestSha256),
    });
    const manifest = verified.graphManifest;
    const knownSelectors = new Set(manifest.routing.routes.map((route) => route.entrySelectorId));
    assert(Array.isArray(requested.entries) && requested.entries.length > 0);
    const selected = new Set();
    for (const entry of requested.entries) {
      assert(typeof entry.name === "string" && entry.name.length > 0);
      assert(knownSelectors.has(entry.selectorHex), "entry selector is absent from verified graph");
      assert(!selected.has(entry.selectorHex), "entry selector occurs twice");
      selected.add(entry.selectorHex);
    }
    graphs.push({
      name: requested.name,
      entries: requested.entries,
      ...(requested.initializationTrace === undefined ? {} : {
        initializationTrace: requested.initializationTrace,
      }),
      initialization: manifest.initialization,
      modules: manifest.modules.map(({ role, layout, providers, artifacts }) => ({
        role,
        layout,
        providers,
        aot: {
          path: join(cacheLayout.immutable.artifacts, artifacts.aot.stage, artifacts.aot.cacheKey, "artifact.cwasm"),
          sha256: artifacts.aot.sha256,
          size: artifacts.aot.size,
        },
      })),
    });
  }
  await writeFile(outputPath, `${JSON.stringify({ ...measurement, graphs })}\n`, { flag: "wx", mode: 0o600 });
  return {
    graphs: graphs.length,
    entries: graphs.reduce((sum, graph) => sum + graph.entries.length, 0),
    configurationSha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [configurationPath, outputPath, ...extra] = process.argv.slice(2);
  assert(configurationPath && outputPath && extra.length === 0,
    "usage: prepare-convex-wasm-graph-initialization.mjs CONFIG.json OUTPUT.json");
  const result = await prepareConvexWasmGraphInitialization({ configurationPath, outputPath });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
