#!/usr/bin/env node

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { validateConvexWasmCompilerOutputContract } from "./lib/convex-wasm-compiler-contract.mjs";
import {
  describeNativeCommandTermination,
  runBoundedNativeCommand,
} from "./lib/bounded-native-command.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const MAX_CHILD_OUTPUT_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const CHILD_TIMEOUT_MS = 120_000;

function usage() {
  return "usage: smoke-packaged-convex-wasm-compiler.mjs --package PATH";
}

function parseArguments(argumentsList) {
  if (
    argumentsList.length !== 2 ||
    argumentsList[0] !== "--package" ||
    argumentsList[1].length === 0
  ) {
    throw new Error(usage());
  }
  return { packageDirectory: argumentsList[1] };
}

async function runBounded(command, argumentsList) {
  const result = await runBoundedNativeCommand({
    arguments: argumentsList,
    command,
    maxOutputBytes: MAX_CHILD_OUTPUT_BYTES,
    operation: "packaged compiler smoke",
    timeoutMs: CHILD_TIMEOUT_MS,
  });
  if (result.termination !== undefined) {
    throw new Error(
      `packaged compiler ${describeNativeCommandTermination(result.termination)}`
    );
  }
  if (result.code !== 0) {
    const output = result.output.toString("utf8").trim();
    throw new Error(
      `packaged compiler failed with ${result.signal === null ? `exit ${result.code}` : `signal ${result.signal}`}${output.length === 0 ? "" : `\n${output}`}`
    );
  }
}

export function validatePackagedCompilerSmokeResponse(
  response,
  { entryPath = "convex/packageSmoke.ts", exportName = "packageSmoke" } = {}
) {
  const output = response?.results?.[0]?.output;
  if (
    response?.kind !== "convex-wasm-compiler-batch-response" ||
    response.mode !== "compile" ||
    response.compileTargets?.length !== 1 ||
    response.compileTargets[0]?.entryPath !== entryPath ||
    response.compileTargets[0]?.exportName !== exportName ||
    response.results?.length !== 1
  ) {
    throw new Error("packaged compiler returned an unexpected smoke response envelope");
  }
  validateConvexWasmCompilerOutputContract(output, {
    expectedGraphToolchain: { convex: "package-smoke", esbuild: "package-smoke" },
    mode: "compile",
  });
  const authorization = output.directAsyncBatches[0];
  const operation = output.operations.find(
    (candidate) => candidate.id === authorization?.operationId
  );
  if (
    output.routing.decision !== "wasm" ||
    output.eligible !== true ||
    output.directAsyncBatches.length !== 1 ||
    authorization.kind !== "singleEffectMap" ||
    operation?.kind !== "databaseGet" ||
    operation.table !== "documents" ||
    output.arrayArgumentFields.length !== 1 ||
    output.arrayArgumentFields[0] !== "ids" ||
    typeof output.generatedJavascriptArtifact?.sha256 !== "string" ||
    output.generatedJavascriptArtifact.source !== null ||
    output.generatedJavascriptArtifact.cachePath !==
      `generated-sources/${output.generatedJavascriptArtifact.sha256.slice(0, 2)}/${output.generatedJavascriptArtifact.sha256}.js`
  ) {
    throw new Error("packaged compiler returned an unexpected ABI smoke result");
  }
  return output;
}

export async function createPackagedCompilerSmokeRequest({ entryPath, exportName, repoRoot }) {
  const generatedServerPath = "convex/_generated/server.js";
  const materialSourceRoot = dirname(scriptDirectory);
  const loadAdapterMaterial = async ({ descriptorKind, materialKind, name }) => {
    const path = `scripts/test-fixtures/native-package/${name}-adapters.json`;
    const bytes = await fs.readFile(join(materialSourceRoot, path));
    const descriptor = JSON.parse(bytes.toString("utf8"));
    if (descriptor.kind !== descriptorKind) {
      throw new Error(`${name} adapter smoke fixture has an unexpected kind`);
    }
    const destination = join(repoRoot, path);
    await fs.mkdir(dirname(destination), { mode: 0o700, recursive: true });
    await fs.writeFile(destination, bytes, { mode: 0o600 });
    return {
      kind: materialKind,
      descriptor,
      source: {
        bytes: bytes.length,
        path,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
      ...(name === "dependency" ? { current: { files: [], locks: [] } } : {}),
    };
  };
  const [dependencyAdapter, registrationAdapter] = await Promise.all([
    loadAdapterMaterial({
      descriptorKind: "convex-wasm-dependency-adapter-descriptor",
      materialKind: "convex-wasm-dependency-adapter-material",
      name: "dependency",
    }),
    loadAdapterMaterial({
      descriptorKind: "convex-wasm-registration-adapter-descriptor",
      materialKind: "convex-wasm-registration-adapter-material",
      name: "registration",
    }),
  ]);
  return {
    kind: "convex-wasm-compiler-batch-request",
    commonGraph: {
      kind: "convex-wasm-esbuild-graph",
      functionsRoot: "convex",
      metafile: {
        inputs: {
          [entryPath]: {
            imports: [
              {
                external: false,
                kind: "import-statement",
                original: "./_generated/server",
                path: generatedServerPath,
              },
            ],
          },
          [generatedServerPath]: { imports: [] },
        },
      },
      phaseTimingsUs: { esbuildGraph: 0 },
      dependencyAdapter,
      registrationAdapter,
      repoRoot,
      toolchain: { convex: "package-smoke", esbuild: "package-smoke" },
      assumptions: {
        conditions: ["convex", "module"],
        format: "esm",
        graphConstructionSemanticRevision: "convex-wasm-deployment-graph-construction",
        innerEsbuildSourceSha256: "0".repeat(64),
        platform: "browser",
        plugins: [
          "convex-source-material-snapshot",
          "convex-async-hooks-shim",
          "convex-server-only",
          "convex-node-externals(empty-browser-map)",
          "convex-wasm",
        ],
        productionArtifact: false,
        resolutionAuthority: "esbuild-metafile",
        splitting: true,
        target: "esnext",
      },
    },
    compileTargets: [{ entryPath, exportName }],
    compileSelection: { kind: "explicitTargets" },
    entryCandidates: [],
    authoritativeExports: [],
    exports: [{ entryPath, exportName }],
    mode: "compile",
  };
}

export async function smokePackagedCompiler(packageDirectory) {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-package-smoke-"));
  await fs.chmod(root, 0o700);
  try {
    const entryPath = "convex/packageSmoke.ts";
    const sourceDirectory = join(root, "convex");
    const requestPath = join(root, "request.json");
    const responsePath = join(root, "response.json");
    const cacheDirectory = join(root, "cache");
    await fs.mkdir(join(sourceDirectory, "_generated"), { mode: 0o700, recursive: true });
    await Promise.all([
      fs.writeFile(
        join(root, entryPath),
        `import { query } from "./_generated/server";
export const packageSmoke = query({
  args: { ids: v.array(v.id("documents")) },
  handler: async (ctx, args) =>
    await Promise.all(args.ids.map((id) => ctx.db.get("documents", id))),
});
`,
        { mode: 0o600 }
      ),
      fs.writeFile(join(root, "convex/_generated/server.js"), "export const query = undefined;\n", {
        mode: 0o600,
      }),
    ]);
    await fs.writeFile(
      requestPath,
      JSON.stringify(
        await createPackagedCompilerSmokeRequest({
          entryPath,
          exportName: "packageSmoke",
          repoRoot: root,
        })
      ),
      { mode: 0o600 }
    );
    await fs.mkdir(cacheDirectory, { mode: 0o700 });
    await runBounded(process.execPath, [
      join(scriptDirectory, "run-packaged-convex-wasm-compiler.mjs"),
      "--package",
      packageDirectory,
      "--",
      "--batch-request",
      requestPath,
      "--batch-output",
      responsePath,
      "--cache-dir",
      cacheDirectory,
    ]);
    const responseEntry = await fs.stat(responsePath);
    if (responseEntry.size === 0 || responseEntry.size > MAX_RESPONSE_BYTES) {
      throw new Error(`smoke response must be between 1 and ${MAX_RESPONSE_BYTES} bytes`);
    }
    const response = JSON.parse(await fs.readFile(responsePath, "utf8"));
    const output = validatePackagedCompilerSmokeResponse(response, {
      entryPath,
      exportName: "packageSmoke",
    });
    return {
      compilerPipelineSha256: output.compiler.pipelineSha256,
      generatedJavascriptSha256: output.generatedJavascriptArtifact.sha256,
      sourceGraphFingerprint: output.sourceGraphFingerprint,
    };
  } finally {
    await fs.rm(root, { force: true, recursive: true });
  }
}

export async function main(argumentsList) {
  const { packageDirectory } = parseArguments(argumentsList);
  await smokePackagedCompiler(packageDirectory);
  process.stdout.write("Packaged Convex Wasm compiler smoke test passed.\n");
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
