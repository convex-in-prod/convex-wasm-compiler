import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmGeneratedCLinkInput } from "./convex-wasm-generated-c-build.mjs";
import {
  C_BUNDLE_KIND,
  C_BUNDLE_MANIFEST_PATH,
  staticHermesCBundleMemberCompilationBaselinePolicy,
  staticHermesCBundleShardTargetBytes,
} from "./convex-wasm-static-hermes-c-bundle.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const materials = {
  staticHermes: {
    entries: [{ label: "static-hermes-executable", sha256: "a".repeat(64), size: 17 }],
    sha256: "b".repeat(64),
  },
};

async function fixture(t, bundleOutput) {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-generated-c-build-"));
  t.after(() => fs.rm(cacheRoot, { recursive: true, force: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "generated-c",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const calls = [];
  const bundleFiles = new Map([
    ["unit.h", "#define SYNTHETIC 1\n"],
    ["metadata.c", "const int synthetic_metadata = SYNTHETIC;\n"],
    ["function-0.c", "int synthetic_function(void) { return SYNTHETIC; }\n"],
  ]);
  const member = (path, role, fields = {}) => ({
    ...fields,
    path,
    role,
    sha256: sha256(bundleFiles.get(path)),
    size: Buffer.byteLength(bundleFiles.get(path)),
  });
  const manifest = {
    header: member("unit.h", "header"),
    kind: C_BUNDLE_KIND,
    schemaVersion: 1,
    translationUnits: [
      member("metadata.c", "metadata"),
      member("function-0.c", "function", {
        cOptimizationLevel: 0,
        firstFunctionId: 0,
        functionCount: 1,
        lastFunctionId: 0,
        oversize: false,
        targetBytes: staticHermesCBundleShardTargetBytes,
      }),
    ],
  };
  const manifestSource = `${canonicalJson(manifest)}\n`;
  const bundle = {
    ...manifest,
    manifest: {
      path: C_BUNDLE_MANIFEST_PATH,
      sha256: sha256(manifestSource),
      size: Buffer.byteLength(manifestSource),
    },
  };
  const runCommand = async ({ command, stage, workPath }) => {
    calls.push({ args: command.args, stage });
    if (stage === "static-hermes") {
      const request = JSON.parse(await fs.readFile(join(workPath, "request.json"), "utf8"));
      const result = bundleOutput ? { kind: "success", output: bundle } : { kind: "success" };
      if (bundleOutput) {
        await Promise.all([
          fs.writeFile(join(workPath, C_BUNDLE_MANIFEST_PATH), manifestSource, { mode: 0o600 }),
          ...[...bundleFiles].map(([name, source]) =>
            fs.writeFile(join(workPath, name), source, { mode: 0o600 })
          ),
        ]);
      } else {
        await fs.writeFile(join(workPath, "unit.c"), "int synthetic(void) { return 1; }\n", { mode: 0o600 });
      }
      await fs.writeFile(join(workPath, "response.json"), `${canonicalJson({
        kind: "convex-wasm-static-hermes-precompile-response-v1",
        requestSha256: fingerprintJson(request),
        result,
        schemaVersion: 1,
      })}\n`, { mode: 0o600 });
    } else {
      const outputIndex = command.args.indexOf("-o");
      const outputName = command.args[outputIndex + 1];
      const sourceName = command.args[outputIndex - 1];
      const source = await fs.readFile(join(workPath, sourceName));
      await fs.writeFile(join(workPath, outputName), Buffer.concat([Buffer.from("object:"), source]), { mode: 0o600 });
    }
    return { wallMilliseconds: 1 };
  };
  return {
    calls,
    options: {
      cacheLayout,
      cacheRoot,
      commands: {
        staticHermes: {
          executable: "/synthetic/launcher",
          args: [
            "--compiler", "/synthetic/compiler", "--request", "request.json",
            "--response", "response.json", "--", "-emit-c",
            ...(bundleOutput
              ? ["-Xemit-c-bundle", `-Xemit-c-shard-size=${String(staticHermesCBundleShardTargetBytes)}`]
              : []),
            "-o", bundleOutput ? C_BUNDLE_MANIFEST_PATH : "unit.c", "input.js",
          ],
        },
        compileExport: {
          executable: "/synthetic/emcc",
          args: ["-O2", "-c", "unit.c", "-o", "unit.o"],
        },
        compileExportMember: { executable: "/synthetic/emcc", args: ["-O2", "-c"] },
      },
      generatedJavaScript: "function synthetic() { return 1; }\n",
      identities: {
        archive: { kind: "synthetic-archive-v1" },
        object: { kind: "synthetic-object-v1", toolchain: "synthetic" },
      },
      limits: { archiveBytes: 4096, generatedCBytes: 4096, objectBytes: 4096 },
      linkInputName: bundleOutput ? "selected.a" : "selected.o",
      materials,
      memberCompilationPolicy: staticHermesCBundleMemberCompilationBaselinePolicy,
      memberJobs: 2,
      runCommand,
      verifyEmscriptenMaterials: async () => {},
      verifyStaticHermesMaterials: async () => {},
    },
  };
}

test("generated C becomes a cached linker object across fresh source work directories", async (t) => {
  const { calls, options } = await fixture(t, false);
  const first = await buildConvexWasmGeneratedCLinkInput(options);
  const second = await buildConvexWasmGeneratedCLinkInput(options);
  assert.equal(first.kind, "success");
  assert.equal(first.object.report.cache, "miss");
  assert.equal(second.object.report.cache, "hit");
  assert.deepEqual(calls.map(({ stage }) => stage), ["static-hermes", "export-object", "static-hermes"]);
  assert.equal(first.linkInput.name, "selected.o");
  assert.equal(first.linkInput.sha256, second.linkInput.sha256);
  assert.equal((await fs.readFile(first.linkInput.path, "utf8")).startsWith("object:"), true);
});

test("generated C bundle compiles every member with its policy and caches an ordered archive", async (t) => {
  const { calls, options } = await fixture(t, true);
  const first = await buildConvexWasmGeneratedCLinkInput(options);
  const second = await buildConvexWasmGeneratedCLinkInput(options);
  assert.equal(first.kind, "success");
  assert.equal(first.objects.length, 2);
  assert.equal(first.archive.report.cache, "miss");
  assert.equal(second.archive.report.cache, "hit");
  assert.deepEqual(second.objects.map(({ report }) => report.cache), ["hit", "hit"]);
  assert.equal(calls.filter(({ stage }) => stage === "static-hermes").length, 2);
  assert.equal(calls.some(({ stage, args }) =>
    stage === "c-optimization-level-zero-c-bundle-member-object" && args.includes("-O0")
  ), true);
  assert.equal(first.linkInput.name, "selected.a");
  assert.equal((await fs.readFile(first.linkInput.path)).subarray(0, 8).toString("ascii"), "!<arch>\n");
});

test("generated-C composition returns source rejection without starting object compilation", async (t) => {
  const { options } = await fixture(t, false);
  const rejection = {
    diagnostics: [{ category: "flow-type-spread-argument-not-array", column: 2, line: 3 }],
    kind: "sourceRejected",
    rawDiagnosticSha256: "c".repeat(64),
  };
  const calls = [];
  const result = await buildConvexWasmGeneratedCLinkInput({
    ...options,
    runCommand: async ({ stage, workPath }) => {
      calls.push(stage);
      const request = JSON.parse(await fs.readFile(join(workPath, "request.json"), "utf8"));
      await fs.writeFile(join(workPath, "response.json"), `${canonicalJson({
        kind: "convex-wasm-static-hermes-precompile-response-v1",
        requestSha256: fingerprintJson(request),
        result: rejection,
        schemaVersion: 1,
      })}\n`, { mode: 0o600 });
    },
  });
  assert.equal(result.kind, "sourceRejected");
  assert.deepEqual(result.rejection, rejection);
  assert.deepEqual(calls, ["static-hermes"]);
});
