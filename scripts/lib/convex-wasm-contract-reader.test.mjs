import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  WasmContractReader,
  inspectConvexWasmCoreWasmImports,
} from "./convex-wasm-contract-reader.mjs";

const wasmHeader = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);

function section(id, payload) {
  assert.ok(payload.length < 128);
  return Buffer.from([id, payload.length, ...payload]);
}

test("reads and fingerprints an imported Core Wasm function type", () => {
  const typeSection = section(1, Buffer.from([1, 0x60, 0, 1, 0x7f]));
  const importSection = section(
    2,
    Buffer.from([1, 3, ...Buffer.from("env"), 4, ...Buffer.from("read"), 0, 0])
  );
  const imports = inspectConvexWasmCoreWasmImports(
    Buffer.concat([wasmHeader, typeSection, importSection]),
    "synthetic module"
  );
  const canonical = "func()->(i32)";
  assert.deepEqual(imports, [
    {
      index: 0,
      module: "env",
      name: "read",
      type: {
        canonical,
        kind: "func",
        sha256: createHash("sha256").update(canonical).digest("hex"),
      },
    },
  ]);
});

test("rejects malformed and unsupported Core Wasm type encodings", () => {
  assert.throws(
    () => inspectConvexWasmCoreWasmImports(wasmHeader.subarray(0, 7), "synthetic module"),
    /Core Wasm is truncated/u
  );
  assert.throws(
    () => new WasmContractReader(Buffer.from([0xff, 0xff, 0xff, 0xff, 0x1f]), "type").u32(),
    /out-of-range u32 LEB/u
  );
  assert.throws(
    () => new WasmContractReader(Buffer.from([0xff, 0xff, 0xff, 0xff, 0x0f]), "type").s32(),
    /out-of-range s32 LEB/u
  );
  const unsupportedTypeSection = section(1, Buffer.from([1, 0x60, 1, 0x63, 0]));
  assert.throws(
    () =>
      inspectConvexWasmCoreWasmImports(
        Buffer.concat([wasmHeader, unsupportedTypeSection]),
        "synthetic module"
      ),
    /unsupported value type 0x63/u
  );
});
