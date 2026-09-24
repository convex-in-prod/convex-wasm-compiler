import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { buildConvexWasmCoreWasmAndAot } from "./convex-wasm-native-artifact-build.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const engineConfig = {
  consumeFuel: true,
  epochInterruption: true,
  profilingStrategy: "perf-map",
  wasmExceptions: true,
};
const target = { cpu: "baseline", triple: "x86_64-unknown-linux-gnu" };
const engineIdentity = {
  engineCompatibilitySha256: "a".repeat(64),
  engineConfig,
  kind: "convex-wasm-wasmtime-engine-identity",
  target,
};

test("Core Wasm and AOT stages bind copied inputs and reuse authenticated entries", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-build-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "native-build",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const objectPath = join(cacheRoot, "object.o");
  const object = Buffer.from("synthetic object");
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const aot = Buffer.from("synthetic AOT");
  await fs.writeFile(objectPath, object, { mode: 0o600 });
  const calls = [];
  const verified = [];
  const options = {
    cacheLayout,
    cacheRoot,
    commands: {
      link: { executable: "/synthetic/linker", args: ["inputs/object.o", "-o", "module.wasm"] },
      precompile: { executable: "/synthetic/precompiler", args: ["module.wasm", "module.cwasm"] },
    },
    engineConfig,
    identities: { coreWasm: { build: "synthetic" }, wasmtimeAot: { build: "synthetic" } },
    limits: { aotBytes: 1024, coreWasmBytes: 1024 },
    linkInputs: [{ name: "inputs/object.o", path: objectPath, sha256: sha256(object), size: object.length }],
    runCommand: async ({ stage, workPath }) => {
      calls.push(stage);
      if (stage === "core-wasm") {
        assert.deepEqual(await fs.readFile(join(workPath, "inputs/object.o")), object);
        await fs.writeFile(join(workPath, "module.wasm"), wasm, { mode: 0o600 });
      } else {
        assert.deepEqual(await fs.readFile(join(workPath, "module.wasm")), wasm);
        await Promise.all([
          fs.writeFile(join(workPath, "module.cwasm"), aot, { mode: 0o600 }),
          fs.writeFile(join(workPath, "engine-identity.json"), `${canonicalJson(engineIdentity)}\n`, { mode: 0o600 }),
        ]);
      }
      return { stage };
    },
    target,
    verifyMaterials: async (stage) => { verified.push(stage); },
  };
  const first = await buildConvexWasmCoreWasmAndAot(options);
  assert.deepEqual(calls, ["core-wasm", "wasmtime-aot"]);
  assert.deepEqual(verified, ["link", "link", "link", "aot", "aot", "aot"]);
  assert.equal(first.coreWasm.report.cache, "miss");
  assert.equal(first.wasmtimeAot.report.cache, "miss");
  assert.equal(first.coreWasm.entry.artifactSha256, sha256(wasm));
  assert.equal(first.wasmtimeAot.entry.artifactSha256, sha256(aot));
  assert.deepEqual(first.engineIdentity, engineIdentity);

  const second = await buildConvexWasmCoreWasmAndAot(options);
  assert.equal(second.coreWasm.report.cache, "hit");
  assert.equal(second.wasmtimeAot.report.cache, "hit");
  assert.deepEqual(calls, ["core-wasm", "wasmtime-aot"]);

  await fs.writeFile(objectPath, Buffer.from("changed object!!"));
  await assert.rejects(
    buildConvexWasmCoreWasmAndAot(options),
    /does not match its identity/u
  );
  assert.deepEqual(calls, ["core-wasm", "wasmtime-aot"]);
});

test("Core Wasm linking rejects a copied object that differs from its identity", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-input-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "native-input",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const objectPath = join(cacheRoot, "object.o");
  await fs.writeFile(objectPath, "changed", { mode: 0o600 });
  await assert.rejects(
    buildConvexWasmCoreWasmAndAot({
      cacheLayout,
      cacheRoot,
      commands: { link: { args: [] }, precompile: { args: [] } },
      engineConfig,
      identities: { coreWasm: {}, wasmtimeAot: {} },
      limits: { aotBytes: 1024, coreWasmBytes: 1024 },
      linkInputs: [{ name: "object.o", path: objectPath, sha256: sha256("original"), size: 8 }],
      runCommand: async () => { throw new Error("must not run a linker with changed inputs"); },
      target,
      verifyMaterials: async () => {},
    }),
    /does not match its identity/u
  );
});

test("AOT stage rejects an engine identity for another target", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-engine-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "native-engine",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const objectPath = join(cacheRoot, "object.o");
  await fs.writeFile(objectPath, "object", { mode: 0o600 });
  await assert.rejects(
    buildConvexWasmCoreWasmAndAot({
      cacheLayout,
      cacheRoot,
      commands: { link: { args: [] }, precompile: { args: [] } },
      engineConfig,
      identities: { coreWasm: {}, wasmtimeAot: {} },
      limits: { aotBytes: 1024, coreWasmBytes: 1024 },
      linkInputs: [{ name: "object.o", path: objectPath, sha256: sha256("object"), size: 6 }],
      runCommand: async ({ stage, workPath }) => {
        if (stage === "core-wasm") {
          await fs.writeFile(join(workPath, "module.wasm"), "wasm", { mode: 0o600 });
        } else {
          await Promise.all([
            fs.writeFile(join(workPath, "module.cwasm"), "aot", { mode: 0o600 }),
            fs.writeFile(join(workPath, "engine-identity.json"), `${canonicalJson({
              ...engineIdentity,
              target: { cpu: "baseline", triple: "aarch64-apple-darwin" },
            })}\n`, { mode: 0o600 }),
          ]);
        }
      },
      target,
      verifyMaterials: async () => {},
    }),
    /does not match the requested engine configuration and target/u
  );
});

test("same-key callers authenticate their own input paths before sharing a build", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-shared-input-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "native-shared-input",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const goodPath = join(cacheRoot, "good.o");
  const badPath = join(cacheRoot, "bad.o");
  await Promise.all([
    fs.writeFile(goodPath, "good", { mode: 0o600 }),
    fs.writeFile(badPath, "evil", { mode: 0o600 }),
  ]);
  let releaseLink;
  const linkGate = new Promise((resolve) => { releaseLink = resolve; });
  let linkStarted;
  const started = new Promise((resolve) => { linkStarted = resolve; });
  const options = {
    cacheLayout,
    cacheRoot,
    commands: { link: { args: ["good.o"] }, precompile: { args: ["module.wasm"] } },
    engineConfig,
    identities: { coreWasm: {}, wasmtimeAot: {} },
    limits: { aotBytes: 1024, coreWasmBytes: 1024 },
    linkInputs: [{ name: "object.o", path: goodPath, sha256: sha256("good"), size: 4 }],
    runCommand: async ({ stage, workPath }) => {
      if (stage === "core-wasm") {
        linkStarted();
        await linkGate;
        await fs.writeFile(join(workPath, "module.wasm"), "wasm", { mode: 0o600 });
      } else {
        await Promise.all([
          fs.writeFile(join(workPath, "module.cwasm"), "aot", { mode: 0o600 }),
          fs.writeFile(join(workPath, "engine-identity.json"), `${canonicalJson(engineIdentity)}\n`, { mode: 0o600 }),
        ]);
      }
    },
    target,
    verifyMaterials: async () => {},
  };
  const producer = buildConvexWasmCoreWasmAndAot(options);
  await started;
  try {
    await assert.rejects(
      buildConvexWasmCoreWasmAndAot({
        ...options,
        linkInputs: [{ ...options.linkInputs[0], path: badPath }],
      }),
      /does not match its identity/u
    );
  } finally {
    releaseLink();
  }
  const result = await producer;
  assert.equal(result.coreWasm.report.cache, "miss");
});
