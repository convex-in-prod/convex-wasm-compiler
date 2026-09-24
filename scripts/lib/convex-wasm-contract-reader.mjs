import { createHash } from "node:crypto";

import { fail, requireString } from "./convex-wasm-artifact-contract.mjs";

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function decodeUtf8(contents, description) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(contents);
  } catch (error) {
    throw new Error(`Convex Wasm artifact pipeline: ${description} is not valid UTF-8`, {
      cause: error,
    });
  }
}

class WasmContractReader {
  constructor(bytes, description) {
    this.bytes = bytes;
    this.description = description;
    this.offset = 0;
  }

  remaining() {
    return this.bytes.length - this.offset;
  }

  byte() {
    if (this.offset >= this.bytes.length) fail(`${this.description} ended unexpectedly`);
    const value = this.bytes[this.offset];
    this.offset += 1;
    return value;
  }

  bytesValue(size) {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.remaining()) {
      fail(`${this.description} contains an invalid byte range`);
    }
    const value = this.bytes.subarray(this.offset, this.offset + size);
    this.offset += size;
    return value;
  }

  u32() {
    let value = 0;
    let shift = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.byte();
      value += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) {
        if (!Number.isSafeInteger(value) || value > 0xffff_ffff) {
          fail(`${this.description} contains an out-of-range u32 LEB`);
        }
        return value;
      }
      shift += 7;
    }
    fail(`${this.description} contains an overlong u32 LEB`);
  }

  s32() {
    let value = 0;
    let shift = 0;
    let byte;
    for (let index = 0; index < 5; index += 1) {
      byte = this.byte();
      const payload = byte & 0x7f;
      // In the fifth byte, bits above the i32 sign bit must be a sign extension. Without this
      // check an out-of-range value can truncate through JavaScript's bitwise operators into a
      // plausible positive layout export such as __heap_base.
      if (index === 4 && (payload & 0x70) !== ((payload & 0x08) === 0 ? 0 : 0x70)) {
        fail(`${this.description} contains an out-of-range s32 LEB`);
      }
      value |= payload << shift;
      shift += 7;
      if ((byte & 0x80) === 0) {
        if (shift < 32 && (byte & 0x40) !== 0) value |= ~0 << shift;
        return value | 0;
      }
    }
    fail(`${this.description} contains an overlong s32 LEB`);
  }

  string() {
    const bytes = this.bytesValue(this.u32());
    return decodeUtf8(bytes, `${this.description} string`);
  }

  vector(read) {
    const count = this.u32();
    // Every vector element admitted by the contract readers consumes at least one byte. Check
    // the bounded section before constructing the result array so malformed external Wasm cannot
    // turn an attacker-controlled count into an unbounded allocation.
    if (count > this.remaining()) {
      fail(`${this.description} vector exceeds its remaining bytes`);
    }
    return Array.from({ length: count }, () => read());
  }

  done() {
    if (this.remaining() !== 0) fail(`${this.description} has trailing bytes`);
  }
}

const wasmContractValueTypes = new Map([
  [0x7f, "i32"],
  [0x7e, "i64"],
  [0x7d, "f32"],
  [0x7c, "f64"],
  [0x7b, "v128"],
  [0x70, "funcref"],
  [0x6f, "externref"],
  [0x69, "exnref"],
]);

function wasmContractValueType(reader) {
  const byte = reader.byte();
  const valueType = wasmContractValueTypes.get(byte);
  if (valueType !== undefined) return valueType;
  // The long reference encodings (0x63 and 0x64) carry heap types and may refer to
  // GC/recursive type definitions. This contract parser only admits function type
  // definitions, so it must reject them rather than compare a partial type.
  fail(`${reader.description} contains unsupported value type 0x${byte.toString(16)}`);
}

function wasmContractLimits(reader) {
  const flags = reader.u32();
  if ((flags & ~0x07) !== 0 || (flags & 0x04) !== 0) {
    fail(`${reader.description} contains unsupported memory/table limits flags`);
  }
  const minimum = reader.u32();
  const maximum = (flags & 0x01) === 0 ? null : reader.u32();
  if (maximum !== null && maximum < minimum) {
    fail(`${reader.description} contains inverted memory/table limits`);
  }
  return { maximum, minimum, shared: (flags & 0x02) !== 0 };
}

function wasmContractTableType(reader) {
  return { element: wasmContractValueType(reader), limits: wasmContractLimits(reader) };
}

function wasmContractMemoryType(reader) {
  return wasmContractLimits(reader);
}

function wasmContractGlobalType(reader) {
  const value = wasmContractValueType(reader);
  const mutable = reader.byte();
  if (mutable !== 0 && mutable !== 1) fail(`${reader.description} has invalid global mutability`);
  return { mutable: mutable === 1, value };
}

function wasmContractSkipSignedLeb(reader, maximumBytes) {
  for (let index = 0; index < maximumBytes; index += 1) {
    if ((reader.byte() & 0x80) === 0) return;
  }
  fail(`${reader.description} contains an overlong signed LEB`);
}

function wasmContractGlobalInitializer(reader, role) {
  const opcode = reader.byte();
  let i32Const = null;
  if (opcode === 0x41) i32Const = reader.s32();
  else if (opcode === 0x42) wasmContractSkipSignedLeb(reader, 10);
  else if (opcode === 0x43) reader.bytesValue(4);
  else if (opcode === 0x44) reader.bytesValue(8);
  else if (opcode === 0x23 || opcode === 0xd2) reader.u32();
  else if (opcode === 0xd0) wasmContractSkipSignedLeb(reader, 5);
  else fail(`${role} Core Wasm uses an unsupported global initializer`);
  if (reader.byte() !== 0x0b) fail(`${role} Core Wasm has an invalid global initializer`);
  return i32Const;
}

function wasmContractCanonicalType(kind, value) {
  if (kind === "func") return `func(${value.parameters.join(",")})->(${value.results.join(",")})`;
  if (kind === "tag") return `tag(${wasmContractCanonicalType("func", value)})`;
  if (kind === "global") return `global(${value.value},${value.mutable ? "var" : "const"})`;
  if (kind === "memory") {
    return `memory32(min=${String(value.minimum)},max=${
      value.maximum === null ? "none" : String(value.maximum)
    },shared=${String(value.shared)},page=16)`;
  }
  return `table32(${value.element},min=${String(value.limits.minimum)},max=${
    value.limits.maximum === null ? "none" : String(value.limits.maximum)
  })`;
}

function wasmContractExternalType(kind, value) {
  const canonical = wasmContractCanonicalType(kind, value);
  return { canonical, kind, sha256: hashBytes(Buffer.from(canonical)) };
}

function wasmContractFunctionTypes(reader, role) {
  return reader.vector(() => {
    if (reader.byte() !== 0x60) fail(`${role} Core Wasm uses unsupported non-function types`);
    return {
      parameters: reader.vector(() => wasmContractValueType(reader)),
      results: reader.vector(() => wasmContractValueType(reader)),
    };
  });
}

function wasmContractFunctionTypeReference(reader, types, role) {
  const type = types[reader.u32()];
  if (type === undefined) fail(`${role} Core Wasm references a missing function type`);
  return type;
}

function wasmContractImports(reader, role, types) {
  return reader.vector(() => {
    const module = reader.string();
    const name = reader.string();
    const externalKind = reader.byte();
    let kind;
    let type;
    if (externalKind === 0) {
      kind = "func";
      type = types[reader.u32()];
    } else if (externalKind === 1) {
      kind = "table";
      type = wasmContractTableType(reader);
    } else if (externalKind === 2) {
      kind = "memory";
      type = wasmContractMemoryType(reader);
    } else if (externalKind === 3) {
      kind = "global";
      type = wasmContractGlobalType(reader);
    } else if (externalKind === 4) {
      kind = "tag";
      if (reader.byte() !== 0) fail(`${role} Core Wasm uses an unsupported tag attribute`);
      type = types[reader.u32()];
    } else {
      fail(`${role} Core Wasm has an unsupported import kind`);
    }
    if (type === undefined) fail(`${role} Core Wasm import references a missing type`);
    return { kind, module, name, type };
  });
}

function inspectConvexWasmCoreWasmImports(bytes, description) {
  const role = requireString(description, "Core Wasm import inspection description");
  if (!Buffer.isBuffer(bytes) || bytes.length < 8) fail(`${role} Core Wasm is truncated`);
  if (!bytes.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) {
    fail(`${role} Core Wasm has an invalid header`);
  }
  const reader = new WasmContractReader(bytes.subarray(8), `${role} Core Wasm`);
  const types = [];
  const imports = [];
  while (reader.remaining() > 0) {
    const id = reader.byte();
    const section = new WasmContractReader(
      reader.bytesValue(reader.u32()),
      `${role} Core Wasm section ${id}`
    );
    if (id === 1) {
      types.push(...wasmContractFunctionTypes(section, role));
    } else if (id === 2) {
      imports.push(...wasmContractImports(section, role, types));
    } else {
      section.bytesValue(section.remaining());
    }
    section.done();
  }
  return imports.map(({ kind, module, name, type }, index) => ({
    index,
    module,
    name,
    type: wasmContractExternalType(kind, type),
  }));
}

export {
  WasmContractReader,
  inspectConvexWasmCoreWasmImports,
  wasmContractExternalType,
  wasmContractFunctionTypeReference,
  wasmContractFunctionTypes,
  wasmContractGlobalInitializer,
  wasmContractGlobalType,
  wasmContractImports,
  wasmContractMemoryType,
  wasmContractTableType,
};
