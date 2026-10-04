import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import * as esbuild from "esbuild";
import { parse } from "@babel/parser";

import {
  convexWasmOfficialOutputChunkModuleTransform,
  convexWasmModuleLinkage,
} from "./convex-wasm-official-output-chunk-unit.mjs";

async function loadModules(sources, entry, reads = new Map()) {
  const { kind: _kind, ...options } = convexWasmOfficialOutputChunkModuleTransform;
  const code = new Map();
  const graph = new Map(
    Object.entries(sources).map(([path, source]) => [
      path.slice(2),
      { identity: { path: path.slice(2) }, source },
    ])
  );
  for (const [name, original] of Object.entries(sources)) {
    const module = graph.get(name.slice(2));
    const plan = convexWasmModuleLinkage.immutableImportPlan(module, graph);
    const dependencies = parse(original, { sourceType: "module" })
      .program.body.filter((node) => node.type === "ImportDeclaration")
      .map((node) => ({
        start: node.source.start,
        executableSpecifier: node.source.value,
      }));
    const source = convexWasmModuleLinkage.snapshotImmutableImports(
      original,
      dependencies,
      plan,
      name
    );

    const transformed = await esbuild.transform(source, options);
    const lowered = convexWasmModuleLinkage.lowerModuleExportForwarding(
      transformed.code,
      source,
      name
    );
    assert.notEqual(lowered, transformed.code, `Expected native export linkage in ${name}`);
    code.set(name, lowered);
  }
  const modules = new Map();
  const load = (name) => {
    if (modules.has(name)) return modules.get(name).exports;
    const module = { exports: {} };
    modules.set(name, module);
    vm.runInNewContext(
      code.get(name),
      {
        module,
        require: (target) =>
          new Proxy(load(target), {
            get(exports, name, receiver) {
              const key = `${target}:${String(name)}`;
              reads.set(key, (reads.get(key) ?? 0) + 1);
              return Reflect.get(exports, name, receiver);
            },
          }),
      },
      { filename: name }
    );
    return module.exports;
  };
  return load(entry);
}

test("module linkage keeps live exports, own keys and accessor descriptors", async () => {
  const exports = await loadModules(
    {
      "./entry.js": `
      let value = 1;
      export { value, value as __proto__ };
      export function update() { value += 1; }
      export default function result() { return value; }
    `,
    },
    "./entry.js"
  );
  assert.equal(exports.value, 1);
  exports.update();
  assert.equal(exports.value, 2);
  assert.equal(exports.__proto__, 2);
  assert.equal(exports.default(), 2);
  assert.deepEqual(Object.getOwnPropertyNames(exports), [
    "__esModule",
    "__proto__",
    "default",
    "update",
    "value",
  ]);
  const descriptor = Object.getOwnPropertyDescriptor(exports, "value");
  assert.equal(typeof descriptor.get, "function");
  assert.equal(descriptor.set, undefined);
  assert.equal(descriptor.enumerable, true);
  assert.equal(descriptor.configurable, false);
  assert.equal(Object.getOwnPropertyDescriptor(exports, "__esModule").enumerable, false);
});

test("module linkage preserves cyclic initialization and early lexical access errors", async () => {
  const exports = await loadModules(
    {
      "./a.js": `
      import { get, early } from "./b.js";
      export let value = 3;
      export function read() { return value; }
      export function result() { return [get(), early]; }
    `,
      "./b.js": `
      import { value, read } from "./a.js";
      export let early;
      try { read(); } catch (error) { early = error.name; }
      export function get() { return value; }
    `,
    },
    "./a.js"
  );
  assert.deepEqual(Array.from(exports.result()), [3, "ReferenceError"]);
});

test("immutable imports are captured once while mutable imports stay live", async () => {
  const reads = new Map();
  const entry = await loadModules(
    {
      "./dep.js": `export const stable = () => 7; export let changing = () => 1;
      export function update() { changing = () => 2; }`,
      "./entry.js": `import { stable, changing, update } from "./dep.js";
      export function result() { return [stable(), changing()]; }
      export { update };`,
    },
    "./entry.js",
    reads
  );
  assert.deepEqual(Array.from(entry.result()), [7, 1]);
  entry.update();
  assert.deepEqual(Array.from(entry.result()), [7, 2]);
  assert.equal(reads.get("./dep.js:stable"), 1);
  assert.equal(reads.get("./dep.js:changing"), 2);
});

test("cyclic reexports are not replaced by early snapshots", async () => {
  const entry = await loadModules(
    {
      "./stable.js": `export const stable = 7;`,
      "./a.js": `import { stable } from "./stable.js";
      import { early } from "./b.js";
      export { stable }; export function result() { return early; }`,
      "./b.js": `import { stable } from "./a.js"; export const early = stable;`,
    },
    "./a.js"
  );
  assert.equal(entry.result(), 7);
});

test("immutable import proofs change when an export becomes writable", () => {
  const importer = {
    identity: { path: "entry.js" },
    source: 'import { x } from "./dep.js"; export function result() { return x; }',
  };
  const immutable = {
    identity: { path: "dep.js" },
    source: "export let x = 1;",
  };
  const mutable = {
    identity: { path: "dep.js" },
    source: "export let x = 1; export function update() { x++; }",
  };
  const plan = (target) =>
    convexWasmModuleLinkage.immutableImportPlan(
      importer,
      new Map([
        ["entry.js", importer],
        ["dep.js", target],
      ])
    );
  assert.deepEqual(
    plan(immutable).map(({ names }) => names),
    [["x"]]
  );
  assert.deepEqual(plan(mutable), []);
});
