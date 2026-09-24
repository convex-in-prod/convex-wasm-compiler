import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { createConvexWasmNativeCommandRunner } from "./convex-wasm-native-command-runner.mjs";
import { C_BUNDLE_KIND, C_BUNDLE_MANIFEST_PATH } from "./convex-wasm-static-hermes-c-bundle.mjs";
import { runStaticHermesSourceStage } from "./convex-wasm-static-hermes-stage.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const materials = {
  staticHermes: {
    entries: [{ label: "static-hermes-executable", sha256: "a".repeat(64), size: 17 }],
    sha256: "b".repeat(64),
  },
};

function command(flags, output) {
  return {
    args: [
      "--compiler", "/synthetic/compiler", "--request", "request.json",
      "--response", "response.json", "--", ...flags, "-o", output, "input.js",
    ],
    executable: "/synthetic/launcher",
  };
}

async function writeResponse(workPath, request, result) {
  await fs.writeFile(
    join(workPath, "response.json"),
    `${canonicalJson({
      kind: "convex-wasm-static-hermes-precompile-response-v1",
      requestSha256: fingerprintJson(request),
      result,
      schemaVersion: 1,
    })}\n`,
    { mode: 0o600 }
  );
}

test("Static Hermes source stage binds its request and authenticates C output", async (t) => {
  const workPath = await fs.mkdtemp(join(tmpdir(), "convex-wasm-hermes-stage-"));
  t.after(() => fs.rm(workPath, { force: true, recursive: true }));
  const source = "function example(): number { return 1; }\n";
  const output = "int example(void) { return 1; }\n";
  const nativeRunner = createConvexWasmNativeCommandRunner({
    environment: process.env,
    maxOutputBytes: 1024,
    timeoutMs: 5000,
  });
  let verifications = 0;
  const result = await runStaticHermesSourceStage({
    command: command(["-emit-c"], "unit.c"),
    generatedJavaScript: source,
    materials,
    maxGeneratedCBytes: 1024,
    runCommand: async ({ stage, workPath: commandWorkPath }) => {
      const request = JSON.parse(await fs.readFile(join(commandWorkPath, "request.json"), "utf8"));
      assert.equal(request.generatedSource.sha256, sha256(source));
      assert.equal(await fs.readFile(join(commandWorkPath, "input.js"), "utf8"), source);
      await fs.writeFile(join(commandWorkPath, "unit.c"), output, { mode: 0o600 });
      await writeResponse(commandWorkPath, request, { kind: "success" });
      return nativeRunner({
        command: { executable: process.execPath, args: ["-e", ""] },
        stage,
        workPath: commandWorkPath,
      });
    },
    verifyMaterials: async () => { verifications += 1; },
    workPath,
  });
  assert.equal(verifications, 2);
  assert.equal(result.kind, "success");
  assert.equal(result.artifact.sha256, sha256(output));
  assert.equal(result.artifact.size, Buffer.byteLength(output));
  assert.equal(result.timing.wallMilliseconds > 0, true);
});

test("Static Hermes source rejection remains a typed stage outcome", async (t) => {
  const workPath = await fs.mkdtemp(join(tmpdir(), "convex-wasm-hermes-rejection-"));
  t.after(() => fs.rm(workPath, { force: true, recursive: true }));
  const rejection = {
    diagnostics: [{ category: "flow-type-spread-argument-not-array", column: 2, line: 3 }],
    kind: "sourceRejected",
    rawDiagnosticSha256: "c".repeat(64),
  };
  const result = await runStaticHermesSourceStage({
    command: command(["-emit-c"], "unit.c"),
    generatedJavaScript: "function example() {}\n",
    materials,
    maxGeneratedCBytes: 1024,
    runCommand: async ({ workPath: commandWorkPath }) => {
      const request = JSON.parse(await fs.readFile(join(commandWorkPath, "request.json"), "utf8"));
      await writeResponse(commandWorkPath, request, rejection);
    },
    verifyMaterials: async () => {},
    workPath,
  });
  assert.equal(result.kind, "sourceRejected");
  assert.deepEqual(result.rejection, rejection);
});

test("Static Hermes source stage authenticates every C-bundle member", async (t) => {
  const workPath = await fs.mkdtemp(join(tmpdir(), "convex-wasm-hermes-bundle-"));
  t.after(() => fs.rm(workPath, { force: true, recursive: true }));
  const sources = new Map([
    ["unit.h", "#define EXAMPLE 1\n"],
    ["metadata.c", "const int metadata = 1;\n"],
    ["function-0.c", "int example(void) { return 1; }\n"],
  ]);
  const member = (path, role, fields = {}) => ({
    ...fields,
    path,
    role,
    sha256: sha256(sources.get(path)),
    size: Buffer.byteLength(sources.get(path)),
  });
  const manifest = {
    header: member("unit.h", "header"),
    kind: C_BUNDLE_KIND,
    schemaVersion: 1,
    translationUnits: [
      member("metadata.c", "metadata"),
      member("function-0.c", "function", {
        firstFunctionId: 0,
        functionCount: 1,
        lastFunctionId: 0,
        oversize: false,
        targetBytes: 2_097_152,
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
  const options = {
    command: command(
      ["-emit-c", "-Xemit-c-bundle", "-Xemit-c-shard-size=2097152"],
      C_BUNDLE_MANIFEST_PATH
    ),
    generatedJavaScript: "function example() {}\n",
    materials,
    maxGeneratedCBytes: 1024,
    runCommand: async ({ workPath: commandWorkPath }) => {
      const request = JSON.parse(await fs.readFile(join(commandWorkPath, "request.json"), "utf8"));
      await Promise.all([
        fs.writeFile(join(commandWorkPath, C_BUNDLE_MANIFEST_PATH), manifestSource, { mode: 0o600 }),
        ...[...sources].map(([path, source]) =>
          fs.writeFile(join(commandWorkPath, path), source, { mode: 0o600 })
        ),
      ]);
      await writeResponse(commandWorkPath, request, { kind: "success", output: bundle });
    },
    verifyMaterials: async () => {},
    workPath,
  };
  const result = await runStaticHermesSourceStage(options);
  assert.equal(result.kind, "success");
  assert.equal(result.artifact.artifactSha256, bundle.manifest.sha256);
  assert.deepEqual(result.artifact.bundle, bundle);

  await fs.rm(workPath, { recursive: true, force: true });
  await fs.mkdir(workPath, { mode: 0o700 });
  await assert.rejects(
    runStaticHermesSourceStage({
      ...options,
      runCommand: async ({ workPath: commandWorkPath }) => {
        await options.runCommand({ workPath: commandWorkPath });
        await fs.writeFile(join(commandWorkPath, "function-0.c"), "tampered\n");
      },
    }),
    /does not match its identity/u
  );
});
