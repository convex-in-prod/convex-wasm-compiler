import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";

import {
  convexWasmBlockingEffectExecutionMode,
  convexWasmGuestPromiseEffectExecutionMode,
} from "./convex-wasm-compiler-contract.mjs";
import {
  hydrateConvexWasmDependencyAdapterMaterial,
  loadConvexWasmDependencyAdapterMaterial,
  selectConvexWasmDependencyAdapters,
} from "./convex-wasm-dependency-adapters.mjs";
import { loadConvexWasmRegistrationAdapterMaterial } from "./convex-wasm-registration-adapters.mjs";

const GRAPH_KIND = "convex-wasm-esbuild-graph";
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

function packageVersion(packageJsonPath) {
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  if (typeof packageJson.version !== "string") {
    throw new Error(`${packageJsonPath} has no string version.`);
  }
  return packageJson.version;
}

function loadToolchain(repoRoot) {
  const requireFromRepo = createRequire(resolve(repoRoot, "package.json"));
  const convexPackageJson = requireFromRepo.resolve("convex/package.json");
  const requireFromConvex = createRequire(convexPackageJson);
  const esbuildPackageJson = requireFromConvex.resolve("esbuild/package.json");
  const toolchain = {
    convex: packageVersion(convexPackageJson),
    esbuild: packageVersion(esbuildPackageJson),
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
