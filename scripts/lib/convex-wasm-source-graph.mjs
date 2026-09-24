import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { readFile, realpath } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";

import {
  convexWasmBlockingEffectExecutionMode,
  convexWasmGuestPromiseEffectExecutionMode,
} from "./convex-wasm-compiler-contract.mjs";
import { resolveConvexWasmApplicationBundlerPackageSet } from "./convex-wasm-application-package-set.mjs";
import {
  hydrateConvexWasmDependencyAdapterMaterial,
  loadConvexWasmDependencyAdapterMaterial,
  selectConvexWasmDependencyAdapters,
} from "./convex-wasm-dependency-adapters.mjs";
import { loadConvexWasmRegistrationAdapterMaterial } from "./convex-wasm-registration-adapters.mjs";
import { convexApiFunctionsRoot } from "./convex-api-flattener-reuse.mjs";

const GRAPH_KIND = "convex-wasm-esbuild-graph";
// Operational build code is not itself hashed into graph identities. Bump this revision when
// graph construction changes in a way that the literal assumptions below do not represent.
export const convexWasmDeploymentGraphConstructionSemanticRevision =
  "convex-wasm-deployment-graph-construction";
export const convexWasmDeploymentGraphAssumptions = Object.freeze({
  conditions: Object.freeze(["convex", "module"]),
  format: "esm",
  graphConstructionSemanticRevision: convexWasmDeploymentGraphConstructionSemanticRevision,
  platform: "browser",
  plugins: Object.freeze([
    "convex-source-material-snapshot",
    "convex-async-hooks-shim",
    "convex-server-only",
    "convex-node-externals(empty-browser-map)",
    "convex-wasm",
  ]),
  productionArtifact: false,
  resolutionAuthority: "esbuild-metafile",
  splitting: true,
  target: "esnext",
});
export const convexWasmDefaultEffectExecutionMode = convexWasmBlockingEffectExecutionMode;
const EFFECT_EXECUTION_MODES = new Set([
  convexWasmDefaultEffectExecutionMode,
  convexWasmGuestPromiseEffectExecutionMode,
]);

export function normalizeConvexWasmEffectExecutionMode(
  value = convexWasmDefaultEffectExecutionMode
) {
  if (!EFFECT_EXECUTION_MODES.has(value)) {
    throw new Error(`Unsupported Convex Wasm effect execution mode: ${JSON.stringify(value)}.`);
  }
  return value;
}

function toPosix(path) {
  return path.replaceAll("\\", "/");
}

function loadToolchain(repoRoot) {
  const packageSet = resolveConvexWasmApplicationBundlerPackageSet(repoRoot);
  const requireFromRepo = createRequire(resolve(repoRoot, "package.json"));
  const convexPackageJson = requireFromRepo.resolve("convex/package.json");
  const requireFromConvex = createRequire(convexPackageJson);
  const toolchain = {
    convex: packageSet.convex.version,
    esbuild: packageSet.esbuild.version,
  };
  return { esbuild: requireFromConvex("esbuild"), toolchain };
}

export async function buildConvexWasmSourceGraph({
  repoRoot,
  entryPath,
  exportName,
  effectExecutionMode = convexWasmDefaultEffectExecutionMode,
}) {
  const normalizedEffectExecutionMode = normalizeConvexWasmEffectExecutionMode(effectExecutionMode);
  const normalizedRoot = await realpath(resolve(repoRoot));
  const projectConfigPath = join(normalizedRoot, "convex.json");
  const functionsRoot = convexApiFunctionsRoot(
    existsSync(projectConfigPath) ? JSON.parse(await readFile(projectConfigPath, "utf8")) : {}
  );
  const normalizedEntry = await realpath(resolve(normalizedRoot, entryPath));
  const normalizedEntryRelative = toPosix(relative(normalizedRoot, normalizedEntry));
  if (
    normalizedEntryRelative === ".." ||
    normalizedEntryRelative.startsWith("../") ||
    normalizedEntryRelative.startsWith("/")
  ) {
    throw new Error(`Compiler entry escapes the repository root: ${entryPath}`);
  }
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(exportName)) {
    throw new Error(`Compiler export is not a JavaScript identifier: ${exportName}`);
  }
  const { esbuild, toolchain } = loadToolchain(normalizedRoot);
  const [dependencyAdapterDescriptor, registrationAdapter] = await Promise.all([
    loadConvexWasmDependencyAdapterMaterial(normalizedRoot),
    loadConvexWasmRegistrationAdapterMaterial(normalizedRoot),
  ]);
  if (esbuild.version !== toolchain.esbuild) {
    throw new Error("Resolved esbuild package version disagrees with its runtime version.");
  }
  const started = performance.now();
  const result = await esbuild.build({
    absWorkingDir: normalizedRoot,
    stdin: {
      contents: `export { ${exportName} as default } from ` + `${JSON.stringify(normalizedEntry)};`,
      loader: "js",
      resolveDir: normalizedRoot,
      sourcefile: "<convex-wasm-export-entry>",
    },
    bundle: true,
    platform: "browser",
    format: "esm",
    target: "esnext",
    jsx: "automatic",
    conditions: ["convex", "module"],
    define: {
      "process.env.NODE_ENV": '"production"',
    },
    treeShaking: true,
    write: false,
    metafile: true,
    logLevel: "silent",
  });
  const activeDependencyAdapters = await selectConvexWasmDependencyAdapters(
    normalizedRoot,
    result.metafile,
    dependencyAdapterDescriptor
  );
  const dependencyAdapter = await hydrateConvexWasmDependencyAdapterMaterial(
    normalizedRoot,
    dependencyAdapterDescriptor,
    activeDependencyAdapters
  );
  return {
    kind: GRAPH_KIND,
    ...(normalizedEffectExecutionMode === convexWasmDefaultEffectExecutionMode
      ? {}
      : { effectExecutionMode: normalizedEffectExecutionMode }),
    repoRoot: normalizedRoot,
    functionsRoot,
    entryPath: normalizedEntryRelative,
    exportName,
    toolchain,
    assumptions: {
      platform: "browser",
      format: "esm",
      target: "esnext",
      conditions: ["convex", "module"],
      productionArtifact: false,
      resolutionAuthority: "esbuild-metafile",
    },
    metafile: result.metafile,
    phaseTimingsUs: {
      esbuildGraph: Math.round((performance.now() - started) * 1_000),
    },
    dependencyAdapter,
    registrationAdapter,
  };
}
