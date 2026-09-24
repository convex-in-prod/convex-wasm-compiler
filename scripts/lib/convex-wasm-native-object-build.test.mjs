import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { createConvexWasmNativeCommandRunner } from "./convex-wasm-native-command-runner.mjs";
import { buildConvexWasmNativeObject } from "./convex-wasm-native-object-build.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("native object stage compiles a staged source and reuses authenticated output", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-object-build-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "native-object",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const sourcePath = join(cacheRoot, "source.c");
  const source = Buffer.from("int synthetic_add(int a, int b) { return a + b; }\n");
  await fs.writeFile(sourcePath, source, { mode: 0o600 });
  const runCommand = createConvexWasmNativeCommandRunner({
    environment: process.env,
    maxOutputBytes: 1024,
    timeoutMs: 5000,
  });
  let materialChecks = 0;
  const options = {
    cacheLayout,
    cacheRoot,
    command: {
      executable: process.execPath,
      args: [
        "-e",
        "require('node:fs').copyFileSync('unit.c', 'unit.o')",
        "--",
        "unit.c",
        "-o",
        "unit.o",
      ],
    },
    identity: { kind: "synthetic-object-v1", toolchain: "synthetic" },
    inputs: [{ name: "unit.c", path: sourcePath, sha256: sha256(source), size: source.length }],
    maxObjectBytes: 1024,
    outputName: "unit.o",
    runCommand,
    sourceName: "unit.c",
    stage: "export-object",
    verifyMaterials: async () => { materialChecks += 1; },
  };
  const first = await buildConvexWasmNativeObject(options);
  assert.equal(first.report.cache, "miss");
  assert.equal(first.entry.artifactSha256, sha256(source));
  assert.deepEqual(await fs.readFile(first.entry.artifactPath), source);
  const second = await buildConvexWasmNativeObject(options);
  assert.equal(second.report.cache, "hit");
  assert.equal(second.entry.artifactPath, first.entry.artifactPath);
  assert.equal(materialChecks >= 5, true);

  await fs.writeFile(sourcePath, "changed source\n");
  await assert.rejects(
    buildConvexWasmNativeObject(options),
    /does not match its identity/u
  );
});

test("native object stage rejects a command that does not use its staged source", async () => {
  await assert.rejects(
    buildConvexWasmNativeObject({
      command: { args: ["other.c", "-o", "unit.o"] },
      identity: {},
      inputs: [{ name: "unit.c", path: "/tmp/unit.c", sha256: "a".repeat(64), size: 1 }],
      maxObjectBytes: 1024,
      outputName: "unit.o",
      runCommand: async () => {},
      sourceName: "unit.c",
      stage: "export-object",
      verifyMaterials: async () => {},
    }),
    /must compile its staged source/u
  );
});
