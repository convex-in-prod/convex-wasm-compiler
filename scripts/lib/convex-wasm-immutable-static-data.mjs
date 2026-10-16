import {
  WasmContractReader,
  wasmContractFunctionTypes,
  wasmContractGlobalInitializer,
  wasmContractGlobalType,
  wasmContractImports,
  wasmContractMemoryType,
} from "./convex-wasm-contract-reader.mjs";

// The linker classifies native const objects independently of their library or
// symbol names. Relocated read-only data (.data.rel.ro), mutable globals and
// side-module data are not eligible: they may be written during initialization.
export const convexWasmImmutableStaticDataPolicy = Object.freeze({
  kind: "convex-wasm-immutable-static-v1",
  classification: "lld-non-pic-rodata-output-sections",
  revision: 2,
});

const PREFIX = "convex_wasm_immutable_static_v1_";
const HEADER = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);

function u32(value) {
  const bytes = [];
  do {
    const byte = value & 127;
    value >>>= 7;
    bytes.push(value === 0 ? byte : byte | 128);
  } while (value !== 0);
  return Buffer.from(bytes);
}

// Runs once after base linking/normalization and before Core-Wasm hashing and
// AOT compilation. Existing globals and code indices are unchanged. Ordinary
// Wasm runtimes can ignore the immutable i32 exports.
export function certifyConvexWasmImmutableStaticData(bytes, linkMap) {
  if (!Buffer.isBuffer(bytes) || !bytes.subarray(0, 8).equals(HEADER)) {
    throw new Error("Immutable static data requires a Core-Wasm module");
  }
  const reader = new WasmContractReader(bytes.subarray(8), "immutable static data");
  const sections = [];
  const types = [];
  const globals = [];
  const exports = [];
  const memories = [];
  const data = [];
  const seen = new Set();
  let importedGlobals = 0;
  let importedMemories = 0;
  let globalSection;
  let exportSection;
  while (reader.remaining() > 0) {
    const id = reader.byte();
    const payload = reader.bytesValue(reader.u32());
    if (id !== 0 && seen.has(id)) throw new Error("Repeated Core-Wasm section");
    seen.add(id);
    const section = { id, payload };
    sections.push(section);
    const input = new WasmContractReader(payload, `immutable static section ${id}`);
    if (id === 1) types.push(...wasmContractFunctionTypes(input, "immutable static data"));
    else if (id === 2) {
      for (const imported of wasmContractImports(input, "immutable static data", types)) {
        if (imported.kind === "global") importedGlobals += 1;
        if (imported.kind === "memory") importedMemories += 1;
      }
    } else if (id === 5) memories.push(...input.vector(() => wasmContractMemoryType(input)));
    else if (id === 6) {
      globalSection = section;
      globals.push(...input.vector(() => ({
        type: wasmContractGlobalType(input),
        value: wasmContractGlobalInitializer(input, "immutable static data"),
      })));
    } else if (id === 7) {
      exportSection = section;
      exports.push(...input.vector(() => ({ name: input.string(), kind: input.byte(), index: input.u32() })));
    } else if (id === 11) {
      data.push(...input.vector(() => {
        const flags = input.u32();
        if (flags !== 0 && (flags !== 2 || input.u32() !== 0)) {
          throw new Error("Static data certification requires active memory-zero segments");
        }
        const offset = wasmContractGlobalInitializer(input, "immutable static data");
        if (offset === null) throw new Error("Static data segment has a nonconstant offset");
        const length = input.u32();
        input.bytesValue(length);
        return { start: offset >>> 0, end: (offset >>> 0) + length };
      }));
    } else input.bytesValue(input.remaining());
    input.done();
  }
  if (exports.some(({ name }) => name.startsWith(PREFIX))) {
    throw new Error("Linked module already contains immutable static declarations");
  }
  const mapHeader = typeof linkMap === "string"
    ? /^[ \t]*Addr[ \t]+Off[ \t]+Size[ \t]+Out[ \t]+In[ \t]+Symbol[ \t]*$/mu.exec(linkMap)
    : null;
  if (mapHeader === null) {
    throw new Error("Immutable static data requires the producing linker's layout map");
  }
  const certified = [];
  const outputColumn = mapHeader[0].indexOf("Out");
  for (const line of linkMap.split("\n")) {
    // lld aligns output, input and symbol names in distinct columns. Counting
    // tokens alone also accepts a symbol named ".rodata" in writable output.
    const outputName = line.slice(outputColumn).trimEnd();
    if (!/^\.rodata(?:\.[^\s]+)?$/u.test(outputName)) continue;
    const match = /^[ \t]*([0-9a-f]+)[ \t]+([0-9a-f]+)[ \t]+([0-9a-f]+)[ \t]+$/u.exec(
      line.slice(0, outputColumn)
    );
    if (match === null) {
      throw new Error("Malformed read-only linker output section");
    }
    const start = Number.parseInt(match[1], 16);
    const length = Number.parseInt(match[3], 16);
    const end = start + length;
    if (importedMemories !== 0 || memories.length !== 1 || memories[0].shared ||
        !Number.isSafeInteger(end) || end > 0x1_0000_0000 ||
        end > memories[0].minimum * 65_536) {
      throw new Error("Read-only output section exceeds the defined initial memory");
    }
    if (length === 0) continue;
    if (certified.some((range) => start < range.end && end > range.start)) {
      throw new Error("Immutable static output sections overlap");
    }
    certified.push({ start, end });
  }
  if (certified.length > 64) throw new Error("Too many immutable static output sections");
  certified.sort((a, b) => a.start - b.start);
  if (certified.length === 0) return bytes;
  if (data.some((segment) => segment.end > memories[0].minimum * 65_536)) {
    throw new Error("Static data segments exceed initial memory");
  }
  const emittedData = data.filter((segment) => segment.start !== segment.end)
    .sort((a, b) => a.start - b.start);
  for (const [index, segment] of emittedData.entries()) {
    if (index > 0 && emittedData[index - 1].end > segment.start) {
      throw new Error("Static data segments overlap");
    }
  }
  if (globalSection === undefined || exportSection === undefined) {
    throw new Error("Static data declarations lost their defining sections");
  }
  const newGlobals = [];
  const newExports = [];
  for (const range of certified) {
    // Count only bytes present in Core Wasm, not zero-filled address-space gaps.
    // A loader can remove this payload from its metadata-size allowance without
    // removing actual parsed segment descriptors, code or type information.
    const payload = emittedData.reduce((total, segment) =>
      total + Math.max(0, Math.min(range.end, segment.end) - Math.max(range.start, segment.start)), 0);
    const name = Buffer.from(`${PREFIX}${range.start}_${range.end}_${payload}`);
    newExports.push(u32(name.length), name, Buffer.from([3]), u32(importedGlobals + globals.length + newGlobals.length));
    newGlobals.push(Buffer.from([0x7f, 0, 0x41, 0, 0x0b]));
  }
  for (const [section, count, additions] of [
    [globalSection, globals.length, newGlobals],
    [exportSection, exports.length, newExports],
  ]) {
    const input = new WasmContractReader(section.payload, "static declaration section");
    input.u32();
    section.payload = Buffer.concat([u32(count + certified.length), input.bytesValue(input.remaining()), ...additions]);
  }
  return Buffer.concat([HEADER, ...sections.flatMap(({ id, payload }) => [Buffer.from([id]), u32(payload.length), payload])]);
}
