import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { main as flattenConvexApi } from "../flatten-convex-api.mjs";
import { resolveConvexWasmApplicationPackageSet } from "./convex-wasm-application-package-set.mjs";
import {
  authenticateConvexWasmCompileProfile,
  buildConvexWasmCompileProfile,
  convexWasmCompileProfileBuildOptions,
  convexWasmCompileProfileInstalledBootstrapMode,
  convexWasmCompileProfileTargetAdapterMode,
  convexWasmTargetZodJitlessTransformPolicy,
  transformConvexWasmTargetZodJitlessSource,
} from "./convex-wasm-compile-profile.mjs";

const compilerRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("authenticates the exact Zod source before applying the target transform", async () => {
  const packageManifestPath = join(compilerRoot, "node_modules", "zod", "package.json");
  const [lockfile, packageManifest, source] = await Promise.all([
    fs.readFile(join(compilerRoot, "package-lock.json")),
    fs.readFile(packageManifestPath),
    fs.readFile(join(compilerRoot, "node_modules", "zod", "v4", "core", "util.js")),
  ]);
  const transformed = transformConvexWasmTargetZodJitlessSource({
    lockfile,
    packageManifest,
    source,
  });
  assert.equal(
    transformed.contents.length,
    convexWasmTargetZodJitlessTransformPolicy.transformedSource.size
  );
  assert.doesNotMatch(transformed.contents.toString("utf8"), /\bnavigator\b/u);
  assert.throws(
    () =>
      transformConvexWasmTargetZodJitlessSource({
        lockfile,
        packageManifest,
        source: Buffer.concat([source, Buffer.from("\n")]),
      }),
    /util source changed outside the authenticated segment/u
  );
});

test("builds a target profile using the explicit application package root", async (context) => {
  const applicationRoot = await fs.mkdtemp(join(await fs.realpath(tmpdir()), "convex-wasm-profile-"));
  context.after(() => fs.rm(applicationRoot, { force: true, recursive: true }));
  await fs.mkdir(join(applicationRoot, "functions"));
  const compilerManifest = JSON.parse(await fs.readFile(join(compilerRoot, "package.json"), "utf8"));
  const applicationManifest = {
    name: "synthetic-convex-project",
    version: "1.0.0",
    private: true,
    type: "module",
    dependencies: compilerManifest.dependencies,
    devDependencies: compilerManifest.devDependencies,
  };
  const applicationLock = JSON.parse(await fs.readFile(join(compilerRoot, "package-lock.json"), "utf8"));
  applicationLock.name = applicationManifest.name;
  applicationLock.version = applicationManifest.version;
  applicationLock.packages[""].name = applicationManifest.name;
  applicationLock.packages[""].version = applicationManifest.version;
  await Promise.all([
    fs.writeFile(join(applicationRoot, "package.json"), JSON.stringify(applicationManifest)),
    fs.writeFile(join(applicationRoot, "package-lock.json"), JSON.stringify(applicationLock)),
    fs.writeFile(join(applicationRoot, "convex.json"), '{"functions":"functions/"}\n'),
    fs.writeFile(
      join(applicationRoot, "functions", "tsconfig.json"),
      '{"compilerOptions":{"module":"ESNext","moduleResolution":"Bundler","target":"ESNext"}}\n'
    ),
    fs.writeFile(
      join(applicationRoot, "functions", "read.ts"),
      'import { queryGeneric as query } from "convex/server";\n' +
        'import { type Answer } from "./answer";\n' +
        'import { answer } from "./answer";\n' +
        'export const read = query({ args: {}, handler: (): Answer => answer });\n'
    ),
    fs.writeFile(
      join(applicationRoot, "functions", "answer.ts"),
      'export type Answer = number;\nexport const answer = 42;\n'
    ),
    fs.cp(join(compilerRoot, "node_modules"), join(applicationRoot, "node_modules"), {
      dereference: true,
      recursive: true,
    }),
  ]);
  const options = {
    entryPath: "functions/read.ts",
    exportNames: ["read"],
    inventory: {
      functions: [
        {
          entryPath: "functions/read.ts",
          exportName: "read",
          modulePath: "read",
          udfKind: "query",
          visibility: "public",
        },
      ],
      snapshot: {
        apiSha256: "a".repeat(64),
        inputSha256: "b".repeat(64),
        materialSha256: "c".repeat(64),
        outputSha256: "d".repeat(64),
      },
    },
    mode: convexWasmCompileProfileTargetAdapterMode,
    repoRoot: applicationRoot,
    sourceConfigurationPaths: ["convex.json", "functions/tsconfig.json"],
    toolchainRoot: applicationRoot,
  };
  const profile = await buildConvexWasmCompileProfile(options);
  authenticateConvexWasmCompileProfile(profile);
  const answerImports = profile.identity.inputs["functions/read.ts"].imports.filter(
    ({ path, original }) => (original ?? path) === "./answer"
  );
  assert.equal(answerImports.length, 2);
  assert.equal(answerImports.filter(({ erased }) => erased === "esbuild-typescript").length, 1);
  assert.equal(answerImports.filter(({ external }) => external === false).length, 1);
  const packageSet = resolveConvexWasmApplicationPackageSet(applicationRoot);
  assert.deepEqual(profile.identity.toolchain.versions, {
    convex: packageSet.convex.version,
    esbuild: packageSet.esbuild.version,
    tsrs: packageSet.tsrs.version,
  });
  assert.ok(profile.javascript.length > 0);
  await profile.verifyMaterials();
  const linkedRoot = await fs.mkdtemp(join(await fs.realpath(tmpdir()), "convex-wasm-profile-link-"));
  context.after(() => fs.rm(linkedRoot, { force: true, recursive: true }));
  await Promise.all([
    fs.writeFile(join(linkedRoot, "package.json"), JSON.stringify(applicationManifest)),
    fs.writeFile(join(linkedRoot, "convex.json"), '{"functions":"functions/"}\n'),
    fs.writeFile(join(linkedRoot, "flattener.config.mjs"), "export default { unknown: true };\n"),
    fs.symlink(join(applicationRoot, "node_modules"), join(linkedRoot, "node_modules"), "dir"),
  ]);
  // A linked installation shares Node's API modules with the profile caller.
  // Its distinct link authority must not look like a changed compiler runtime.
  await assert.rejects(flattenConvexApi([
    "--check", "--project-root", linkedRoot, "--config", "flattener.config.mjs",
  ]), /Unknown Convex API flattener configuration field: unknown/u);
  const bootstrap = await buildConvexWasmCompileProfile({
    ...options,
    mode: convexWasmCompileProfileInstalledBootstrapMode,
  });
  authenticateConvexWasmCompileProfile(bootstrap);
  assert.notEqual(bootstrap.sha256, profile.sha256);
  const inputMaterials = Object.fromEntries(
    Object.entries(bootstrap.identity.inputs)
      .filter(([, input]) => !input.virtual)
      .map(([path, input]) => [
        path,
        {
          sha256: input.sha256,
          size: input.size,
          virtual: false,
          imports: input.imports
            .filter((edge) => edge.synthetic !== "esbuild-runtime")
            .map(({ external, kind, original, path: target }) => ({
              external,
              kind,
              ...(original === undefined ? {} : { original }),
              path: target,
            })),
        },
      ])
  );
  const deploymentGraphSession = {
    dependencyGraphByEntry: new Map([
      [options.entryPath, { inputPaths: Object.keys(inputMaterials), sha256: "1".repeat(64) }],
    ]),
    deploymentOutputMetafileSha256: "2".repeat(64),
    graphSha256: "3".repeat(64),
    graphTemplate: {
      assumptions: {
        conditions: convexWasmCompileProfileBuildOptions.conditions,
        platform: convexWasmCompileProfileBuildOptions.platform,
        target: convexWasmCompileProfileBuildOptions.target,
      },
    },
    inputMaterials,
    toolchain: bootstrap.identity.toolchain.versions,
  };
  const boundBootstrap = await buildConvexWasmCompileProfile({
    ...options,
    mode: convexWasmCompileProfileInstalledBootstrapMode,
    deploymentGraphSession,
  });
  assert.deepEqual(boundBootstrap.javascript, bootstrap.javascript);
  await boundBootstrap.verifyMaterials();
  const deployedImports = inputMaterials[options.entryPath].imports;
  assert.equal(deployedImports.filter((edge) => (edge.original ?? edge.path) === "./answer").length, 2);
  const liveAnswer = deployedImports.find((edge) => edge.original === "./answer");
  assert.ok(liveAnswer);
  deployedImports.push({ ...liveAnswer, path: "functions/missing.ts" });
  await assert.rejects(
    boundBootstrap.verifyMaterials(),
    /compile-profile erased import functions\/read\.ts -> \.\/answer disagrees/u
  );
  deployedImports.pop();
  await boundBootstrap.verifyMaterials();
  const copiedRoot = join(await fs.realpath(tmpdir()), `convex-wasm-profile-copy-${process.pid}-${Date.now()}`);
  context.after(() => fs.rm(copiedRoot, { force: true, recursive: true }));
  await fs.cp(applicationRoot, copiedRoot, { recursive: true });
  const copiedProfile = await buildConvexWasmCompileProfile({
    ...options,
    repoRoot: copiedRoot,
    toolchainRoot: copiedRoot,
  });
  assert.equal(copiedProfile.sha256, profile.sha256);
  // Replacing and restoring a native package leaves its files unchanged, but a
  // worker started during that interval could have executed the replacement.
  const nativeScopePath = join(copiedRoot, "node_modules", "@tsrs");
  await fs.rename(nativeScopePath, `${nativeScopePath}-replaced`);
  await fs.rename(`${nativeScopePath}-replaced`, nativeScopePath);
  await assert.rejects(copiedProfile.verifyMaterials(), /changed after capture/u);
  await assert.rejects(
    buildConvexWasmCompileProfile({
      ...options,
      sourceConfigurationPaths: ["../outside.json"],
    }),
    /source configuration path is not a normalized repository-relative path/u
  );
  const previousBinaryOverride = process.env.TSRS_BINARY;
  try {
    await assert.rejects(buildConvexWasmCompileProfile({
      ...options,
      onOperationalEvent({ stage, type }) {
        if (stage === "initial-build" && type === "finish") {
          process.env.TSRS_BINARY = process.execPath;
        }
      },
    }), /TSRS_BINARY must be unset/u);
  } finally {
    if (previousBinaryOverride === undefined) delete process.env.TSRS_BINARY;
    else process.env.TSRS_BINARY = previousBinaryOverride;
  }
  const tsrsAstPath = join(applicationRoot, "node_modules", "tsrs", "dist", "ast", "is.js");
  const tsrsAstSource = await fs.readFile(tsrsAstPath);
  await assert.rejects(buildConvexWasmCompileProfile({
    ...options,
    async onOperationalEvent({ stage, type }) {
      if (stage === "initial-build" && type === "finish") {
        await fs.appendFile(tsrsAstPath, "\n// intervening implementation\n");
        await fs.writeFile(tsrsAstPath, tsrsAstSource);
      }
    },
  }), /changed after capture/u);
  await assert.rejects(
    buildConvexWasmCompileProfile(options),
    /Installed tsrs material changed after it was loaded/u
  );
  // Both callers import the same application API modules in this process. The
  // flattener must inherit the profile builder's invalidated package lifetime.
  await fs.writeFile(join(applicationRoot, "flattener.config.mjs"), "export default { unknown: true };\n");
  await assert.rejects(flattenConvexApi([
    "--check", "--project-root", applicationRoot, "--config", "flattener.config.mjs",
  ]), /Installed tsrs material changed after it was loaded/u);
  await fs.appendFile(tsrsAstPath, "\n// changed implementation with the same package version\n");
  await assert.rejects(
    buildConvexWasmCompileProfile(options),
    /Installed tsrs material changed after it was loaded/u
  );
  await fs.writeFile(tsrsAstPath, tsrsAstSource);
  const tsrsManifestPath = join(applicationRoot, "node_modules", "tsrs", "package.json");
  const tsrsManifest = JSON.parse(await fs.readFile(tsrsManifestPath, "utf8"));
  tsrsManifest.version = "0.0.0";
  await fs.writeFile(tsrsManifestPath, JSON.stringify(tsrsManifest));
  await assert.rejects(
    buildConvexWasmCompileProfile(options),
    /Installed tsrs material changed after it was loaded/u
  );
});
