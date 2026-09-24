import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { resolveConvexWasmApplicationPackageSet } from "./convex-wasm-application-package-set.mjs";
import {
  authenticateConvexWasmCompileProfile,
  buildConvexWasmCompileProfile,
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
      'import { queryGeneric as query } from "convex/server";\nexport const read = query({ args: {}, handler: () => 42 });\n'
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
  const packageSet = resolveConvexWasmApplicationPackageSet(applicationRoot);
  assert.deepEqual(profile.identity.toolchain.versions, {
    convex: packageSet.convex.version,
    esbuild: packageSet.esbuild.version,
    typescript: packageSet.typescript.version,
  });
  assert.ok(profile.javascript.length > 0);
  await profile.verifyMaterials();
  const bootstrap = await buildConvexWasmCompileProfile({
    ...options,
    mode: convexWasmCompileProfileInstalledBootstrapMode,
  });
  authenticateConvexWasmCompileProfile(bootstrap);
  assert.notEqual(bootstrap.sha256, profile.sha256);
  const copiedRoot = join(await fs.realpath(tmpdir()), `convex-wasm-profile-copy-${process.pid}-${Date.now()}`);
  context.after(() => fs.rm(copiedRoot, { force: true, recursive: true }));
  await fs.cp(applicationRoot, copiedRoot, { recursive: true });
  const copiedProfile = await buildConvexWasmCompileProfile({
    ...options,
    repoRoot: copiedRoot,
    toolchainRoot: copiedRoot,
  });
  assert.equal(copiedProfile.sha256, profile.sha256);
  await assert.rejects(
    buildConvexWasmCompileProfile({
      ...options,
      sourceConfigurationPaths: ["../outside.json"],
    }),
    /source configuration path is not a normalized repository-relative path/u
  );
  const typescriptManifestPath = join(applicationRoot, "node_modules", "typescript", "package.json");
  const typescriptManifest = JSON.parse(await fs.readFile(typescriptManifestPath, "utf8"));
  typescriptManifest.version = "0.0.0";
  await fs.writeFile(typescriptManifestPath, JSON.stringify(typescriptManifest));
  await assert.rejects(
    buildConvexWasmCompileProfile(options),
    /resolved TypeScript runtime and package versions disagree/u
  );
});
