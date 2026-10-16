import assert from "node:assert/strict";
import test from "node:test";

import { certifyConvexWasmImmutableStaticData } from "./convex-wasm-immutable-static-data.mjs";

function leb(value) {
  const bytes = [];
  do {
    const byte = value & 127;
    value >>>= 7;
    bytes.push(value === 0 ? byte : byte | 128);
  } while (value !== 0);
  return bytes;
}

function section(id, bytes) {
  return [id, ...leb(bytes.length), ...bytes];
}

function string(value) {
  const bytes = Buffer.from(value);
  return [...leb(bytes.length), ...bytes];
}

function fixture(emptySegment = false) {
  return Buffer.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    ...section(5, [1, 0, 1]),
    ...section(6, [1, 0x7f, 0, 0x41, 7, 0x0b]),
    ...section(7, [2, ...string("memory"), 2, 0, ...string("answer"), 3, 0]),
    ...section(11, [emptySegment ? 4 : 3,
      0, 0x41, 0x80, 0x20, 0x0b, 2, 13, 14,
      ...(emptySegment ? [2, 0, 0x41, 0x81, 0x20, 0x0b, 0] : []),
      0, 0x41, 0x80, 0xc0, 0x00, 0x0b, 1, 15,
      0, 0x41, 0x80, 0x80, 0x01, 0x0b, 1, 16]),
  ]);
}

const header = "    Addr      Off     Size Out     In      Symbol\n";
function mapLine(start, offset, size, name, column = "Out") {
  return [start, offset, size].map((value) => value.padStart(8)).join(" ") +
    " ".repeat(header.indexOf(column) - 26) + name + "\n";
}
const map = `${header}
${mapLine("1000", "100", "3000", ".rodata")}
${mapLine("1000", "100", "2000", "object.o:(.rodata.lookup)", "In")}
${mapLine("4000", "200", "1000", ".data")}
${mapLine("4000", "200", "1000", "object.o:(.rodata.relocated)", "In")}
${mapLine("5000", "300", "1000", ".data.rel.ro")}
`;

test("certifies linker output sections and preserves actual module execution", () => {
  const original = fixture();
  const certified = certifyConvexWasmImmutableStaticData(original, map);
  const module = new WebAssembly.Module(certified);
  const instance = new WebAssembly.Instance(module);
  assert.equal(instance.exports.answer.value, 7);
  assert.deepEqual(WebAssembly.Module.exports(module).map(({ name }) => name), [
    "memory", "answer", "convex_wasm_immutable_static_v1_4096_16384_3",
  ]);
  const memory = new Uint8Array(instance.exports.memory.buffer);
  assert.deepEqual([...memory.subarray(4096, 4099)], [13, 14, 0]);
  assert.equal(memory[8192], 15);
  assert.equal(memory[16384], 16);
  memory[16384] = 90;
  assert.equal(memory[16384], 90);
  assert.throws(() => certifyConvexWasmImmutableStaticData(certified, map), /already contains/u);
});

test("does not certify const input sections embedded in writable or relocated output", () => {
  const original = fixture();
  const writableMap = header + mapLine("1000", "100", "3000", ".data") +
    mapLine("1000", "100", "3000", "object.o:(.rodata.lookup)", "In") +
    mapLine("1000", "100", "3000", ".rodata", "Symbol");
  assert.equal(certifyConvexWasmImmutableStaticData(original, writableMap), original);
});

test("rejects missing, overlapping and out-of-memory linker evidence", () => {
  assert.throws(() => certifyConvexWasmImmutableStaticData(fixture(), ""), /layout map/u);
  assert.throws(() => certifyConvexWasmImmutableStaticData(fixture(), map + mapLine("2000", "100", "2000", ".rodata.more")), /overlap/u);
  assert.throws(() => certifyConvexWasmImmutableStaticData(fixture(), header + mapLine("1000", "100", "10000", ".rodata")), /exceeds/u);
  assert.throws(() => certifyConvexWasmImmutableStaticData(fixture(), header + mapLine("badhex", "100", "1000", ".rodata")), /Malformed/u);
});

test("empty active segments inside emitted bytes do not overlap or inflate payload", () => {
  const module = new WebAssembly.Module(certifyConvexWasmImmutableStaticData(fixture(true), map));
  assert.ok(WebAssembly.Module.exports(module).some(({ name }) =>
    name === "convex_wasm_immutable_static_v1_4096_16384_3"));
});

test("signed i32 data offsets preserve a wasm32 interval ending at 4 GiB", () => {
  const bytes = Buffer.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    ...section(5, [1, 0, ...leb(65536)]),
    ...section(6, [1, 0x7f, 0, 0x41, 0, 0x0b]),
    ...section(7, [1, ...string("memory"), 2, 0]),
    ...section(11, [1, 0, 0x41, 0x7f, 0x0b, 1, 13]),
  ]);
  const certified = certifyConvexWasmImmutableStaticData(
    bytes,
    header + mapLine("fffff000", "100", "1000", ".rodata")
  );
  assert.ok(WebAssembly.Module.exports(new WebAssembly.Module(certified)).some(({ name }) =>
    name === "convex_wasm_immutable_static_v1_4294963200_4294967296_1"));
});
