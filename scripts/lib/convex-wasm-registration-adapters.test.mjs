import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConvexWasmRegistrationAdapterMaterial } from "./convex-wasm-registration-adapters.mjs";

test("inventory builder declarations remain distinct from callback-lowering authority", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "registration-inventory-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  const descriptorPath = join(root, "scripts/convex-wasm-registration-adapters.json");
  const descriptor = {
    kind: "convex-wasm-registration-adapter-descriptor",
    adapters: [],
    sourceOperations: [],
  };
  await writeFile(descriptorPath, JSON.stringify(descriptor));
  const legacy = await loadConvexWasmRegistrationAdapterMaterial(root);
  assert.deepEqual(legacy.descriptor, descriptor);
  await writeFile(descriptorPath, JSON.stringify({ ...descriptor, inventoryBuilders: [] }));
  const empty = await loadConvexWasmRegistrationAdapterMaterial(root);
  assert.deepEqual(empty.descriptor.inventoryBuilders, []);
  assert.notEqual(empty.source.sha256, legacy.source.sha256);
  const builder = { modulePath: "convex/wrappers.ts", exportName: "scopedQuery", registrationKind: "query" };
  await writeFile(descriptorPath, JSON.stringify({ ...descriptor, inventoryBuilders: [builder] }));
  const current = await loadConvexWasmRegistrationAdapterMaterial(root);
  assert.deepEqual(current.descriptor.inventoryBuilders, [builder]);
  assert.deepEqual(current.descriptor.adapters, []);
  assert.notEqual(current.source.sha256, legacy.source.sha256);
  const unicodeBuilders = ["convex/\uE000.ts", "convex/\u{1F600}.ts"].map((modulePath) => ({
    ...builder,
    modulePath,
  }));
  await writeFile(descriptorPath, JSON.stringify({ ...descriptor, inventoryBuilders: unicodeBuilders }));
  assert.deepEqual(
    (await loadConvexWasmRegistrationAdapterMaterial(root)).descriptor.inventoryBuilders,
    unicodeBuilders
  );
  for (const inventoryBuilders of [
    null,
    [builder, builder],
    [{ ...builder, exportName: "z" }, builder],
    [{ ...builder, registrationKind: "httpAction" }],
    [{ ...builder, modulePath: "../wrappers.ts" }],
    [{ ...builder, modulePath: "convex/invalid\0.ts" }],
    [{ ...builder, extraAuthority: true }],
  ]) {
    await writeFile(descriptorPath, JSON.stringify({ ...descriptor, inventoryBuilders }));
    await assert.rejects(loadConvexWasmRegistrationAdapterMaterial(root));
  }
  const identity = { modulePath: builder.modulePath, exportName: builder.exportName, sourceSha256: "a".repeat(64) };
  await writeFile(descriptorPath, JSON.stringify({
    ...descriptor,
    adapters: [{
      id: "scopedQuery",
      wrapper: identity,
      registrationKind: "query",
      authentication: {
        helper: { ...identity, exportName: "authenticate" },
        resultKind: "value",
        resultParameters: [{ callbackParameterIndex: 2, property: null }],
      },
    }],
    inventoryBuilders: [builder],
  }));
  await assert.rejects(loadConvexWasmRegistrationAdapterMaterial(root), /duplicates a lowering adapter/u);
  await writeFile(descriptorPath, "null");
  await assert.rejects(loadConvexWasmRegistrationAdapterMaterial(root), /descriptor must be an object/u);
});
