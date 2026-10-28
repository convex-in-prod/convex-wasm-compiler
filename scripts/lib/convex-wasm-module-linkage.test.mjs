import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import vm from "node:vm";
import * as esbuild from "esbuild";
import { parse } from "@babel/parser";
import { deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s } from "./convex-wasm-official-output-chunk-contract.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { buildConvexWasmProducerIdentity } from "./convex-wasm-producer-identity.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { authenticateConvexWasmOfficialOutputSelectionFixtures } from "../test-fixtures/official-output-selection.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";

import {
  convexWasmOfficialOutputChunkModuleTransform,
  convexWasmModuleLinkage,
  buildConvexWasmOfficialOutputChunkUnits,
  createConvexWasmOfficialOutputChunkTransformSession,
  convexWasmOfficialOutputChunkUnitTestHooks,
  initializeConvexWasmOfficialOutputChunkUnits,
  materializeConvexWasmOfficialOutputCompactChunkUnitJavascript,
} from "./convex-wasm-official-output-chunk-unit.mjs";

async function loadModules(sources, entry, reads = new Map(), functionPlans = new Map()) {
  const { kind: _kind, ...options } = convexWasmOfficialOutputChunkModuleTransform;
  const code = new Map();
  const graph = new Map(
    Object.entries(sources).map(([path, source]) => [
      path.slice(2),
      { identity: { path: path.slice(2) }, source },
    ])
  );
  await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization([...graph.values()]);
  for (const [name, original] of Object.entries(sources)) {
    const module = graph.get(name.slice(2));
    const plan = convexWasmModuleLinkage.immutableImportPlan(module, graph);
    const functions = convexWasmModuleLinkage.planConvexWasmFunctionImports(module, graph, plan);
    functionPlans.set(name, functions);
    const dependencies = parse(original, { sourceType: "module" })
      .program.body.filter((node) => node.type === "ImportDeclaration")
      .map((node) => ({
        start: node.source.start,
        end: node.source.end,
        executableSpecifier: node.source.value,
      }));
    const source = convexWasmModuleLinkage.snapshotImmutableImports(
      convexWasmModuleLinkage.renderConvexWasmSpecializedModuleSource(
        original,
        dependencies,
        functions
      ),
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
      // Production wraps every module in a strict chunk function.
      `"use strict";\n${code.get(name)}`,
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

test("direct imported calls expose bodies while callbacks and constructors keep identity", async () => {
  const plans = new Map();
  const entry = await loadModules(
    {
      "./dep.js": `export function read(value) { return value.amount + value.limit; }
      export { read as alias };`,
      "./entry.js": `import { read, alias } from "./dep.js";
      export function result() { return read({ amount: 3, limit: 5 }); }
      export function same() { return read === alias; }
      export function callback(accept) { return accept(read); }
      export function construct(value) { return new read(value); }
      export { read };`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.equal(entry.result(), 8);
  assert.equal(entry.same(), true);
  assert.equal(
    entry.callback((fn) => fn),
    entry.read
  );
  assert.equal(
    Object.getPrototypeOf(entry.construct({ amount: 1, limit: 2 })),
    entry.read.prototype
  );
  assert.equal(plans.get("./entry.js").calls.length, 1);
  assert.equal(plans.get("./entry.js").bodies.length, 1);
});

test("closed bodies preserve local writes, parameter defaults and escaping nested closures", async () => {
  const plans = new Map();
  const entry = await loadModules(
    {
      "./dep.js": `export const make = ({ value = 2 } = {}, add = (x) => x + 1) => {
      let local = value; ({ value: local } = { value: add(local) });
      for (local of [local + 1]) { value = local; }
      return function next({ value: increment = 1 } = {}) { local += increment; return local; };
    };`,
      "./entry.js": `import { make } from "./dep.js";
      export function result() { return make(); }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  const first = entry.result();
  const second = entry.result();
  assert.equal(first(), 5);
  assert.equal(first({ value: 3 }), 8);
  assert.equal(second(), 5);
  assert.equal(plans.get("./entry.js").calls.length, 1);
});

test("unsafe captures, writes, invocation context and source-site identity retain ordinary calls", async () => {
  const cases = [
    `let value = 1; export function f() { return value; }`,
    `let value = 1; export function f() { value = 2; }`,
    `let value = 1; export function f() { ({ value } = { value: 2 }); }`,
    `let value = 1; export function f() { [value] = [2]; }`,
    `let value = 1; export function f() { for (value of [2]) {} }`,
    `export function f() { absent = 2; }`,
    `export function f() { return f; }`,
    `export const f = function self() { return () => self; };`,
    `export default function self() { return self; }`,
    `export function f() { return this; }`,
    `export function f() { return arguments; }`,
    `export const f = () => arguments;`,
    `export function f() { return new.target; }`,
    `export function f() { return eval("1"); }`,
    "export function f(tag) { return tag`constant`; }",
    `export let f = () => 1; export function change() { f = () => 2; }`,
  ];
  for (const source of cases) {
    const target = { identity: { path: "dep.js" }, source };
    const importer = {
      identity: { path: "entry.js" },
      source: `${source.includes("export default") ? "import f" : "import { f }"} from "./dep.js"; export function result() { return f(); }`,
    };
    const graph = new Map([
      ["dep.js", target],
      ["entry.js", importer],
    ]);
    const plan = convexWasmModuleLinkage.planConvexWasmFunctionImports(
      importer,
      graph,
      convexWasmModuleLinkage.immutableImportPlan(importer, graph)
    );
    assert.deepEqual(plan.calls, [], source);
  }
});

test("imported call replacement respects shadowing, arguments and thrown values", async () => {
  const plans = new Map();
  const entry = await loadModules(
    {
      "./dep.js": `export default ({ value }, accept) => { return accept(value); };`,
      "./entry.js": `import read from "./dep.js";
      export function result(log, fail) {
        return read((log.push("argument"), { value: 7 }), (value) => {
          log.push(value); if (fail) throw fail; return value;
        });
      }
      export function shadow(read) { return read(); }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  const log = [];
  assert.equal(entry.result(log), 7);
  assert.deepEqual(log, ["argument", 7]);
  const sentinel = {};
  assert.throws(
    () => entry.result(log, sentinel),
    (error) => error === sentinel
  );
  assert.equal(
    entry.shadow(() => 99),
    99
  );
  assert.equal(plans.get("./entry.js").calls.length, 1);
});

test("copying closed bodies retains dependency initialization and cyclic calls", async () => {
  await assert.rejects(
    loadModules(
      {
        "./dep.js": `throw "initialization"; export function read() { return 7; }`,
        "./entry.js": `import { read } from "./dep.js"; export const result = read();`,
      },
      "./entry.js"
    ),
    (error) => error === "initialization"
  );
  const plans = new Map();
  const entry = await loadModules(
    {
      "./a.js": `import { early } from "./b.js"; export const read = () => 7;
      export function result() { return early; }`,
      "./b.js": `import { read } from "./a.js"; export let early;
      try { read(); } catch (error) { early = error.name; }`,
    },
    "./a.js",
    new Map(),
    plans
  );
  assert.equal(entry.result(), "ReferenceError");
  assert.equal(plans.get("./b.js").calls.length, 0);
});

test("body duplication stays bounded and reuses identical closed implementations", async () => {
  const names = Array.from({ length: 40 }, (_, i) => `f${i}`);
  const plans = new Map();
  const entry = await loadModules(
    {
      "./dep.js":
        names
          .map((name, i) => `export function ${name}(value) { return value + ${i}; }`)
          .join("\n") + `\nexport const identical = value => { return value + 0; };`,
      "./entry.js": `import { ${names.join(", ")}, identical } from "./dep.js";
      export function result() { return [${names.map((name) => `${name}(1)`).join(", ")}, identical(2)]; }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.deepEqual(Array.from(entry.result()), [...names.map((_, i) => i + 1), 2]);
  const plan = plans.get("./entry.js");
  assert.equal(plan.bodies.length, 32);
  assert.equal(plan.calls.length, 33);
  assert.equal(plan.rejectedBindings, 8);
});

test("private local bodies preserve annotation identity, live captures and escaping closures", async () => {
  const plans = new Map();
  const entry = await loadModules(
    {
      "./names.js": `const define = Object.defineProperty;
        export const registered = [];
        export function name(fn, label) {
          registered.push(fn); define(fn, "name", { value: label, configurable: true });
          fn.offset = 3;
        }`,
      "./entry.js": `import { name, registered } from "./names.js";
        let increment = 1;
        function read(record) {
          return () => [record.left + record.right + record.left + record.right + increment,
            read, read.offset, this, new.target];
        }
        name(read, "namedReader");
        export { read, registered };
        export function change() { increment += 10; read.offset += 2; }
        export function result(effect) { return read({ left: effect(2), right: effect(4) }); }
        export function shadow(read) { return read({ left: 7, right: 8 }); }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  const trace = [];
  const closure = entry.result((value) => (trace.push(value), value));
  assert.deepEqual(trace, [2, 4]);
  assert.deepEqual(Array.from(closure()), [13, entry.read, 3, undefined, undefined]);
  assert.equal(entry.registered[0], entry.read);
  assert.equal(entry.read.name, "namedReader");
  assert.equal(entry.read.length, 1);
  entry.change();
  assert.deepEqual(Array.from(closure()), [23, entry.read, 5, undefined, undefined]);
  const receiver = {};
  assert.deepEqual(Array.from(entry.read.call(receiver, { left: 1, right: 2 })()), [
    17,
    entry.read,
    5,
    receiver,
    undefined,
  ]);
  assert.equal(
    entry.shadow((record) => record.left * record.right),
    56
  );
  const sentinel = {};
  assert.throws(
    () =>
      entry.result(() => {
        throw sentinel;
      }),
    (error) => error === sentinel
  );
  assert.equal(plans.get("./entry.js").localBodies.length, 1);
});

test("guarded callable targets preserve annotation identity, replacement and exports", async () => {
  const plans = new Map();
  const entry = await loadModules({
    "./entry.js": `
      const names = [], retained = [];
      let offset = 3;
      function annotate(fn, label) {
        names.push(fn.name); retained.push(fn);
        Object.defineProperty(fn, "name", { value: label, configurable: true });
        return fn;
      }
      function replace(fn) { return value => fn(value) + 10; }
      let early;
      try { helper(1); } catch (error) { early = error.name; }
      export const helper = annotate(value => value + offset, "named");
      const replacement = replace(value => value * 2);
      export function result(effect) {
        const a = helper(effect(4)); offset = 5;
        return [a, helper(4), replacement(4), helper === retained[0], helper.name,
          names[0], helper.length, early];
      }`,
  }, "./entry.js", new Map(), plans);
  const effects = [];
  assert.deepEqual(Array.from(entry.result((value) => (effects.push(value), value))),
    [7, 9, 18, true, "named", "", 1, "ReferenceError"]);
  assert.deepEqual(effects, [4]);
  assert.deepEqual(Object.keys(entry).sort(), ["helper", "result"]);
  assert.equal(plans.get("./entry.js").callableTargets.length, 2);
  const sentinel = {};
  assert.throws(() => entry.result(() => { throw sentinel; }), (error) => error === sentinel);
});

test("guarded property helpers preserve own-field definition and proxy effects", async () => {
  const plans = new Map();
  const entry = await loadModules({
    "./entry.js": `
      function annotate(fn) { return fn; }
      const define = Object.defineProperty;
      var normal = annotate((object, key, value) => key in object
        ? define(object, key, { value, enumerable: true, configurable: true, writable: true })
        : object[key] = value);
      var field = annotate((object, key, value) => normal(object,
        typeof key !== "symbol" ? key + "" : key, value));
      export function result(object, key, value) { field(object, key, value); return object; }`,
  }, "./entry.js", new Map(), plans);
  const object = Object.create({ set field(_) { assert.fail("inherited setter ran"); } });
  assert.equal(entry.result(object, "field", 3), object);
  assert.equal(object.field, 3);
  Object.defineProperty(object, "field", { value: 7, configurable: true, writable: false });
  entry.result(object, "field", 8);
  assert.deepEqual(Object.getOwnPropertyDescriptor(object, "field"), {
    value: 8, enumerable: true, configurable: true, writable: true,
  });
  const key = Symbol("field");
  entry.result(object, key, 5);
  assert.equal(object[key], 5);
  const effects = [];
  const proxy = new Proxy({}, {
    has() { effects.push("has"); return false; },
    set(object, key, value) { effects.push("set"); object[key] = value; return true; },
  });
  entry.result(proxy, "field", 9);
  assert.deepEqual(effects, ["has", "set"]);
  assert.equal(proxy.field, 9);
  assert.throws(() => entry.result(Object.freeze({}), "field", 1), { name: "TypeError" });
  assert.equal(plans.get("./entry.js").callableTargets.length, 2);
});

test("guarded calls compose nested arguments, imported bodies and private record bodies", async () => {
  const plans = new Map();
  const entry = await loadModules({
    "./dep.js": "export function twice(x) { return x * 2; }",
    "./entry.js": `import { twice } from "./dep.js";
      function identity(fn) { return fn; }
      const first = identity(value => value + 1);
      const second = identity(value => first(value) + 3);
      function read(record) {
        return second(first(twice(record.left))) + record.right + record.left + record.right;
      }
      identity(read);
      export function result(effect) { return read({left: effect(2), right: effect(4)}); }`,
  }, "./entry.js", new Map(), plans);
  const effects = [];
  assert.equal(entry.result((x) => (effects.push(x), x)), 19);
  assert.deepEqual(effects, [2, 4]);
  assert.equal(plans.get("./entry.js").callableTargets.length, 2);
  assert.equal(plans.get("./entry.js").localBodies.length, 1);
  assert.equal(plans.get("./entry.js").bodies.length, 1);
});

test("guarded calls retain source-site arguments and reject mutable bindings", async () => {
  const plans = new Map();
  const entry = await loadModules({
    "./entry.js": `
      function identity(fn) { return fn; }
      const fn = identity(value => value);
      let mutable = identity(value => value); mutable = value => value + 10;
      function tag(strings) { return strings; }
      export function result() { return [fn(tag\`constant\`), fn(4), (fn /*callee*/)(6), mutable(5)]; }
      export function indirect() { return fn.call(undefined, 6); }
      export function construct() { return new fn(1); }`,
  }, "./entry.js", new Map(), plans);
  const first = entry.result(), second = entry.result();
  assert.equal(first[0], second[0]);
  assert.deepEqual(Array.from(first).slice(1), [4, 6, 15]);
  assert.equal(entry.indirect(), 6);
  assert.throws(() => entry.construct(), { name: "TypeError" });
  const targets = plans.get("./entry.js").callableTargets;
  assert.equal(targets.length, 1);
  assert.equal(targets[0].calls.length, 2);
});

test("guarded callable selection is bounded and keeps names stable across additions", () => {
  const summarize = (source) => {
    const module = { identity: { path: "entry.js" }, source };
    return convexWasmModuleLinkage.planConvexWasmFunctionImports(module, new Map(), []);
  };
  const base = "function identity(fn) { return fn; } const target = identity(x => x + 1); target(1);";
  const original = summarize(base).callableTargets[0];
  const next = summarize("const earlier = identity(x => x); earlier(1);" + base);
  assert.equal(next.callableTargets.find((x) => x.local === "target").name, original.name);
  const oversized = summarize(base + "target(2);".repeat(256));
  assert.equal(oversized.callableTargets.length, 0);
  const opaque = summarize(base + "eval('');");
  assert.equal(opaque.callableTargets.length, 0);
  const nested = base + "target(".repeat(100) + "0" + ")".repeat(100) + ";";
  const nestedPlan = summarize(nested);
  const rendered = convexWasmModuleLinkage.renderConvexWasmSpecializedModuleSource(
    nested, [], nestedPlan
  );
  assert.ok(rendered.length < nested.length * 4);
  assert.equal(vm.runInNewContext(rendered), vm.runInNewContext(nested));
});

test("guarded callable summaries persist and invalidate changed annotation bodies", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-callable-summary-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "callable-summary", cacheRoot, repositoryRoot: cacheRoot, scope: "isolated-test",
  });
  const cache = { cacheRoot, cacheLayout };
  const make = (offset) => ({
    identity: { path: "entry.js" },
    source: `function identity(fn) { return fn; }
      const target = identity(value => value + ${offset});
      export function result() { return target(3); }`,
  });
  const initial = make(1);
  assert.equal((await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization(
    [initial], cache
  )).cacheMisses, 1);
  const fresh = make(1);
  assert.equal((await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization(
    [fresh], cache
  )).cacheHits, 1);
  const plan = convexWasmModuleLinkage.planConvexWasmFunctionImports(fresh, new Map(), []);
  assert.equal(plan.callableTargets.length, 1);
  assert.equal(plan.callableTargets[0].calls.length, 1);
  assert.equal((await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization(
    [make(2)], cache
  )).cacheMisses, 1);
});

test("local specialization preserves optional-field prototype effects and field evaluation order", async () => {
  const plans = new Map();
  const entry = await loadModules(
    {
      "./entry.js": `
        export function read(record) {
          const before = record.left + record.right;
          const optional = record.optional;
          return [before, optional, record.left + record.right];
        }
        export function result(effect) {
          let saved;
          Object.defineProperty(Object.prototype, "optional", {
            configurable: true,
            get() { saved = this; this.left = 20; return 9; },
          });
          try {
            const absent = read({ left: effect(2), right: effect(4) });
            const own = read({ left: effect(3), right: effect(5), optional: undefined });
            return [absent, own, saved.left];
          } finally { delete Object.prototype.optional; }
        }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  const trace = [];
  const result = entry.result((value) => (trace.push(value), value));
  assert.deepEqual(trace, [2, 4, 3, 5]);
  assert.deepEqual(Array.from(result[0]), [6, 9, 24]);
  assert.deepEqual(Array.from(result[1]), [8, undefined, 8]);
  assert.equal(result[2], 20);
  assert.equal(plans.get("./entry.js").localBodies.length, 1);
});

test("local cloning rejects source-site identity and unresolved mutable bindings", async () => {
  const cases = [
    "return tag`site` + record.a + record.b + record.c + record.d;",
    'return eval("record.a") + record.a + record.b + record.c + record.d;',
    "return arguments.length + record.a + record.b + record.c + record.d;",
    'return import("./dep.js").then(() => record.a + record.b + record.c + record.d);',
  ];
  for (const body of cases) {
    const module = {
      identity: { path: "entry.js" },
      source: `export function read(record) { ${body} }
        export function result() { return read({ a: 1, b: 2, c: 3, d: 4 }); }`,
    };
    const plan = convexWasmModuleLinkage.planConvexWasmFunctionImports(module, new Map(), []);
    assert.deepEqual(plan.localBodies, [], body);
  }
  const plans = new Map();
  const entry = await loadModules(
    {
      "./entry.js": `export function read(record) { return record.a + record.b + record.c + record.d; }
        export function change() { read = () => 99; }
        export function result() { return read({ a: 1, b: 2, c: 3, d: 4 }); }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.equal(entry.result(), 10);
  entry.change();
  assert.equal(entry.result(), 99);
  assert.deepEqual(plans.get("./entry.js").localBodies, []);
});

test("bounded local bodies preserve recursion and nested imported substitutions", async () => {
  const plans = new Map();
  const names = Array.from({ length: 6 }, (_, i) => `read${i}`);
  const entry = await loadModules(
    {
      "./dep.js": "export function twice(value) { return value * 2; }",
      "./entry.js": `import { twice } from "./dep.js";
        const __convexLocalBody0 = 7;
        ${names
          .map(
            (name) => `export function ${name}(record, depth) {
          if (depth > 0) return ${name}({ a: record.a, b: record.b, c: record.c, d: record.d }, depth - 1);
          return twice(record.a + record.b + record.c + record.d) + __convexLocalBody0;
        }`
          )
          .join("\n")}
        export function result() { return [${names
          .map((name) => `${name}({ a: 1, b: 2, c: 3, d: 4 }, 2)`)
          .join(", ")}]; }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.deepEqual(Array.from(entry.result()), [27, 27, 27, 27, 27, 27]);
  assert.equal(plans.get("./entry.js").localBodies.length, 4);
  assert.ok(
    plans.get("./entry.js").localBodies.every((body) => body.name !== "__convexLocalBody0")
  );
});

test("private local summaries survive warm reuse and invalidate edited bodies", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-local-summary-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "local-summary",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const prepare = async (operator) => {
    const module = {
      identity: { path: "entry.js" },
      source: `export function read(record) { return record.a ${operator} record.b + record.c + record.d; }
        export function result() { return read({ a: 1, b: 2, c: 3, d: 4 }); }`,
    };
    const report = await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization([module], {
      cacheRoot,
      cacheLayout,
    });
    const plan = convexWasmModuleLinkage.planConvexWasmFunctionImports(module, new Map(), []);
    const source = convexWasmModuleLinkage.renderConvexWasmSpecializedModuleSource(
      module.source,
      [],
      plan
    );
    return { report, plan, source };
  };
  const cold = await prepare("+");
  assert.equal(cold.plan.localBodies.length, 1);
  const warm = await prepare("+");
  assert.equal(warm.report.cacheHits, 1);
  assert.deepEqual(warm.plan, cold.plan);
  assert.equal(warm.source, cold.source);
  const edited = await prepare("-");
  assert.equal(edited.report.cacheMisses, 1);
  assert.notEqual(edited.source, cold.source);
});

test("local selection does not score records beyond native promotion limits", async () => {
  const fields = Array.from({ length: 17 }, (_, i) => `field${i}`);
  const plans = new Map();
  const entry = await loadModules(
    {
      "./entry.js": `
      export function wide(record) { return ${fields
        .slice(0, 9)
        .map((key) => `record.${key}`)
        .join(" + ")}; }
      export function narrow(record) { return record.field0 + record.field1 + record.field2 + record.field3; }
      export function result() { return [
        wide({ ${fields
          .slice(0, 9)
          .map((key, i) => `${key}: ${i}`)
          .join(", ")} }),
        narrow({ ${fields.map((key, i) => `${key}: ${i}`).join(", ")} }),
        narrow({ field0: 1, field1: 2, field2: 3, field3: 4 })
      ]; }
    `,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.deepEqual(Array.from(entry.result()), [36, 6, 10]);
  const plan = plans.get("./entry.js");
  assert.deepEqual(
    plan.localBodies.map((body) => body.local),
    ["narrow"]
  );
  assert.equal(plan.localBodies[0].calls.length, 1);
});

test("local selection rejects destructuring and loop-target record writes", async () => {
  const plans = new Map();
  const entry = await loadModules(
    {
      "./entry.js": `
        export function destructured(record) {
          ({value: record.a} = {value: 10});
          return record.a + record.b + record.c + record.d;
        }
        export function loopTarget(record) {
          for (record.a of [10, 20]) {}
          return record.a + record.b + record.c + record.d;
        }
        export function result() {
          return [destructured({a:1,b:2,c:3,d:4}), loopTarget({a:1,b:2,c:3,d:4})];
        }
      `,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.deepEqual(Array.from(entry.result()), [19, 29]);
  assert.deepEqual(plans.get("./entry.js").localBodies, []);
});

test("local specialization retains helper names and order when edited reads change ranking", async () => {
  const prepare = async (extraRead) => {
    const plans = new Map();
    const entry = await loadModules(
      {
        "./entry.js": `
          const __convexLocalBody_first = 3;
          const __convexLocalBody_second = 5;
          export function first(record) { return record.a + record.b + record.c + record.d + __convexLocalBody_first; }
          export function second(record) { return record.a + record.b + record.c + record.d + __convexLocalBody_second ${extraRead}; }
          export function result() {
            return [first({ a: 1, b: 2, c: 3, d: 4 }), second({ a: 1, b: 2, c: 3, d: 4 })];
          }`,
      },
      "./entry.js",
      new Map(),
      plans
    );
    return { plan: plans.get("./entry.js"), result: Array.from(entry.result()) };
  };
  const initial = await prepare("");
  const edited = await prepare("+ record.a + record.b");
  assert.deepEqual(initial.result, [13, 15]);
  assert.deepEqual(edited.result, [13, 18]);
  const initialNames = initial.plan.localBodies.map(({ local, name }) => ({ local, name }));
  assert.deepEqual(initialNames.map(({ local }) => local), ["first", "second"]);
  assert.deepEqual(
    edited.plan.localBodies.map(({ local, name }) => ({ local, name })),
    initialNames
  );
  assert.equal(initial.plan.localBodies[0].benefit, initial.plan.localBodies[1].benefit);
  assert.ok(edited.plan.localBodies[1].benefit > edited.plan.localBodies[0].benefit);
  assert.equal(initialNames[0].name, "__convexLocalBody_first_0");
  assert.equal(initialNames[1].name, "__convexLocalBody_second_0");
});

test("large bundled modules retain bounded specialization across distinct helpers", async () => {
  const names = Array.from({ length: 12 }, (_, i) => `read${i}`);
  const plans = new Map();
  const entry = await loadModules(
    {
      "./entry.js": `
      export const retainedMaterial = ${JSON.stringify("x".repeat(512 * 1024))};
      ${names
        .map(
          (name, i) => `export function ${name}(record) {
        return record.a + record.b + record.c + record.d + ${i};
      }`
        )
        .join("\n")}
      export function result() { return [${names
        .map((name) => `${name}({ a: 1, b: 2, c: 3, d: 4 })`)
        .join(", ")}]; }
    `,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.deepEqual(
    Array.from(entry.result()),
    names.map((_, i) => 10 + i)
  );
  const bodies = plans.get("./entry.js").localBodies;
  assert.ok(bodies.length > 4 && bodies.length <= 64);
  assert.ok(bodies.reduce((bytes, body) => bytes + body.bytes, 0) <= 128 * 1024);
});

test("source-local summaries reuse warm work and invalidate only incorporated body changes", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-function-summary-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "summary",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const source = 'import { read } from "./dep.js"; export function result(v) { return read(v); }';
  const graphFor = (extra, operation = "+") =>
    new Map([
      ["entry.js", { identity: { path: "entry.js" }, source }],
      [
        "dep.js",
        {
          identity: { path: "dep.js" },
          source: `export function read(v) { return v.amount ${operation} v.limit; } export const extra = ${extra};`,
        },
      ],
    ]);
  const prepare = async (graph) => ({
    report: await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization(
      [...graph.values()],
      { cacheRoot, cacheLayout }
    ),
    plan: convexWasmModuleLinkage.planConvexWasmFunctionImports(
      graph.get("entry.js"),
      graph,
      convexWasmModuleLinkage.immutableImportPlan(graph.get("entry.js"), graph)
    ),
  });
  const graph = graphFor(1);
  const cold = await prepare(graph);
  assert.deepEqual(cold.report, {
    memoryHits: 0,
    cacheHits: 0,
    cacheMisses: 2,
  });
  const memory = await prepare(graph);
  assert.deepEqual(memory.report, {
    memoryHits: 2,
    cacheHits: 0,
    cacheMisses: 0,
  });
  const warm = await prepare(graphFor(1));
  assert.deepEqual(warm.report, {
    memoryHits: 0,
    cacheHits: 2,
    cacheMisses: 0,
  });
  assert.deepEqual(warm.plan, cold.plan);
  const unrelated = await prepare(graphFor(2));
  assert.deepEqual(unrelated.report, {
    memoryHits: 0,
    cacheHits: 1,
    cacheMisses: 1,
  });
  assert.deepEqual(unrelated.plan, cold.plan);
  const changed = await prepare(graphFor(2, "-"));
  assert.deepEqual(changed.report, {
    memoryHits: 0,
    cacheHits: 1,
    cacheMisses: 1,
  });
  assert.notDeepEqual(changed.plan.bodies, cold.plan.bodies);
});

test("installed chunk transforms require their exact semantic implementation source root", async (t) => {
  const cacheRoot = await fs.mkdtemp(
    join(tmpdir(), "convex-wasm-installed-transforms-"),
  );
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const repositoryRoot = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../..",
  );
  const standalone = await buildConvexWasmProducerIdentity(repositoryRoot);
  const implementationSourceRoot = "node_modules/convex-wasm-compiler";
  const installed = {
    ...standalone,
    sources: standalone.sources.map((source) => ({
      ...source,
      path: `${implementationSourceRoot}/${source.path}`,
    })),
    operationalSources: [],
  };
  const create = (producerIdentity, options = {}) =>
    createConvexWasmOfficialOutputChunkTransformSession({
      esbuild,
      persistentCache: {
        cacheRoot,
        cacheLayout: deriveConvexWasmCacheLayout({
          buildId: "installed",
          cacheRoot,
          repositoryRoot,
          scope: "isolated-test",
        }),
        producerIdentity,
        ...options,
      },
    });
  assert.doesNotThrow(() => create(standalone));
  assert.doesNotThrow(() => create(installed, { implementationSourceRoot }));
  assert.throws(() => create(installed), /exactly one source record/);
  assert.throws(
    () => create(standalone, { implementationSourceRoot }),
    /exactly one source record/,
  );
  for (const root of [
    "",
    "/absolute",
    "../compiler",
    "node_modules/../compiler",
  ]) {
    assert.throws(
      () => create(installed, { implementationSourceRoot: root }),
      /source root/,
    );
  }
  const path = `${implementationSourceRoot}/scripts/lib/convex-wasm-official-output-chunk-unit.mjs`;
  const owner = installed.sources.find((source) => source.path === path);
  const sources = installed.sources.filter((source) => source.path !== path);
  assert.throws(
    () => create({ ...installed, sources }, { implementationSourceRoot }),
    /exactly one source record/,
  );
  assert.throws(
    () =>
      create(
        { ...installed, sources, operationalSources: [owner] },
        { implementationSourceRoot },
      ),
    /must be a semantic producer source/,
  );
  assert.throws(
    () =>
      create(
        { ...installed, operationalSources: [owner] },
        { implementationSourceRoot },
      ),
    /exactly one source record/,
  );
});

async function chunkSelections(sources) {
  const modules = Object.entries(sources).map(([path, source]) => {
    const sources = [`fixture:///${path.replace(/-[a-z0-9]+(?=\.js$)/u, "")}`];
    const sourceMap = JSON.stringify({ sources, version: 3 });
    const byteHash = (value) => createHash("sha256").update(value).digest("hex");
    return {
      source,
      sourceMap,
      identity: {
        path,
        environment: "isolate",
        sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({
          sources,
        }),
        sourceSha256: byteHash(source),
        sourceSize: Buffer.byteLength(source),
        sourceMap: {
          sha256: byteHash(sourceMap),
          size: Buffer.byteLength(sourceMap),
          sourcesCount: 1,
          sourcesContentCount: 0,
        },
        moduleSha256: byteHash(source + sourceMap),
      },
    };
  });
  const closure = {
    entryModulePath: "entry.js",
    kind: "fixture-closure-v1",
    imports: Object.entries(sources).flatMap(([importerPath, source]) => {
      const imports = [];
      const visit = (node) => {
        if (node === null || typeof node !== "object") return;
        const specifier =
          node.type === "ImportDeclaration" ||
          node.type === "ExportNamedDeclaration" ||
          node.type === "ExportAllDeclaration"
            ? node.source
            : node.type === "CallExpression" && node.callee.type === "Import"
              ? node.arguments[0]
              : undefined;
        if (specifier)
          imports.push({
            external: false,
            importerPath,
            kind: node.type === "CallExpression" ? "dynamic-import" : "import-statement",
            path: specifier.value.slice(2),
          });
        for (const value of Object.values(node)) {
          if (Array.isArray(value)) value.forEach(visit);
          else if (value && typeof value === "object") visit(value);
        }
      };
      visit(parse(source, { sourceType: "module" }));
      return imports;
    }),
    modules: modules.map(({ identity }) => identity),
  };
  const visited = new Set();
  const ordered = [];
  const importsByPath = new Map(
    modules.map(({ identity }) => [
      identity.path,
      [
        ...new Map(
          closure.imports
            .filter(({ importerPath }) => importerPath === identity.path)
            .map((item) => [fingerprintJson(item), item])
        ).values(),
      ].sort((a, b) => a.path.localeCompare(b.path) || a.kind.localeCompare(b.kind)),
    ])
  );
  const visit = (modulePath) => {
    if (visited.has(modulePath)) return;
    visited.add(modulePath);
    ordered.push(modules.find(({ identity }) => identity.path === modulePath));
    for (const imported of importsByPath.get(modulePath)) visit(imported.path);
  };
  visit("entry.js");
  closure.modules = ordered.map(({ identity }) => identity);
  closure.imports = ordered.flatMap(({ identity }) => importsByPath.get(identity.path));
  return authenticateConvexWasmOfficialOutputSelectionFixtures([
    {
      closure: {
        identity: { ...closure, sha256: fingerprintJson(closure) },
        modules,
      },
      manifestMembership: {
        dependencyGraphSha256: "b".repeat(64),
        inventoryKind: "fixture-inventory-v1",
        sourceEnvelopeSha256: "a".repeat(64),
      },
      route: {
        entryPath: "convex/entry.ts",
        exportName: "result",
        modulePath: "entry",
        runtimeModulePath: "entry.js",
        udfKind: "query",
        visibility: "public",
      },
      toolchain: { esbuild: esbuild.version },
    },
  ]).selections;
}

function runChunkUnits(chunkUnits) {
  const facade = Object.create(null);
  Object.defineProperty(facade, "globalThis", { value: facade });
  const context = vm.createContext({
    __convexWasmApplicationGlobalThis: facade,
  });
  return initializeConvexWasmOfficialOutputChunkUnits({
    chunkUnits,
    destroyStore(error) {
      throw error;
    },
    executeChunk({ begin, javascript, publish, reportThrown, require }) {
      Object.assign(context, {
        __convexWasmOfficialChunkBegin: begin,
        __convexWasmOfficialChunkPublish: publish,
        __convexWasmOfficialChunkReportThrown: reportThrown,
        __convexWasmOfficialChunkRequire: require,
      });
      vm.runInContext(javascript, context, { timeout: 1000 });
    },
  });
}

test("chunk preparation binds imported bodies and reuses unaffected compact artifacts", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-linkage-pipeline-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const producerIdentity = await buildConvexWasmProducerIdentity(repositoryRoot);
  let transforms = 0;
  const counting = {
    version: esbuild.version,
    async transform(...args) {
      ++transforms;
      return esbuild.transform(...args);
    },
  };
  const build = async (buildId, extra, operation = "+", mutable = false) => {
    const sources = {
      "entry.js": 'import { read } from "./dep.js"; export function result(v) { return read(v); }',
      "dep.js": `export ${mutable ? "let" : "const"} read = v => v.amount ${operation} v.limit;
        export const extra = ${extra}; ${mutable ? "export function update() { read = () => 99; }" : ""}`,
    };
    const selections = await chunkSelections(sources);
    const session = createConvexWasmOfficialOutputChunkTransformSession({
      esbuild: counting,
      persistentCache: {
        cacheRoot,
        producerIdentity,
        cacheLayout: deriveConvexWasmCacheLayout({
          buildId,
          cacheRoot,
          repositoryRoot,
          scope: "isolated-test",
        }),
      },
    });
    const compact = await buildConvexWasmOfficialOutputChunkUnits({
      esbuild: counting,
      selections,
      transformSession: session,
      compactUnitAuthority: true,
    });
    const report = convexWasmOfficialOutputChunkUnitTestHooks.compactAuthorityReport(session);
    const materialized = {
      ...compact,
      units: await Promise.all(
        compact.units.map(async (unit) => ({
          ...unit,
          javascript: await materializeConvexWasmOfficialOutputCompactChunkUnitJavascript(unit),
        }))
      ),
    };
    const entries = runChunkUnits(materialized);
    assert.equal(entries[0].namespace.result({ amount: 8, limit: 3 }), operation === "+" ? 11 : 5);
    return {
      report,
      entry: compact.units.find(({ identity }) => identity.module.path === "entry.js"),
      summary: convexWasmOfficialOutputChunkUnitTestHooks.functionSpecializationReport(session),
    };
  };
  const first = await build("cold", 1);
  assert.equal(transforms, 2);
  assert.equal(first.report.persistentPreparationCacheMisses, 2);
  assert.equal(first.summary.cacheMisses, 2);
  const warm = await build("warm", 1);
  assert.equal(transforms, 2);
  assert.equal(warm.report.persistentIdentityCacheHits, 2);
  assert.equal(warm.summary.cacheHits, 2);
  const unrelated = await build("unrelated", 2);
  assert.equal(transforms, 3);
  assert.equal(unrelated.report.persistentIdentityCacheHits, 1);
  assert.deepEqual(unrelated.entry.identity.javascript, first.entry.identity.javascript);
  const bodyChanged = await build("body-changed", 2, "-");
  assert.equal(transforms, 5);
  assert.equal(bodyChanged.report.persistentPreparationCacheMisses, 2);
  assert.notDeepEqual(bodyChanged.entry.identity.javascript, first.entry.identity.javascript);
  const mutable = await build("mutable", 2, "-", true);
  assert.equal(transforms, 7);
  assert.notDeepEqual(mutable.entry.identity.javascript, bodyChanged.entry.identity.javascript);
});

test("immutable helper chains preserve early calls, defaults, shadowing and export identity", async () => {
  const plans = new Map();
  const reads = new Map();
  const entry = await loadModules(
    {
      "./dep.js": `function positive(value) { return value > 0 ? value : 0; }
      function read(value) { return positive(value.left) + positive(value.right); }
      export function total(value = { left: 2, right: 3 }, scale = read(value)) {
        return scale * 2;
      }
      export { read };`,
      "./entry.js": `import { total, read } from "./dep.js";
      const positive = () => 1000;
      export const early = total();
      export function result(value) { return total(value); }
      export function identity() { return read; }
      export { read };
      export function collision() { return positive(); }`,
    },
    "./entry.js",
    reads,
    plans
  );
  assert.equal(entry.early, 10);
  assert.equal(entry.result({ left: -7, right: 11 }), 22);
  assert.equal(entry.collision(), 1000);
  assert.equal(entry.identity(), entry.read);
  const plan = plans.get("./entry.js");
  assert.equal(plan.calls.length, 2);
  assert.equal(plan.bodies[0].helpers.length, 2);
  // Helper factories must retain immutable import snapshots.
  assert.equal(reads.get("./dep.js:total"), 1);
});

test("helper closure proofs reject state, identity, recursion and global shadowing", async () => {
  const cases = [
    `let amount = 1; function read() { return amount; } export function f() { return read(); }`,
    `function read() { return 1; } export function f() { return read; }`,
    `function read() { return 1; } export function f() { return read.name; }`,
    `function read() { return 1; } export function f() { return new read(); }`,
    `function read() { return 1; } export function f() { return read(); } read = () => 2;`,
    `function read() { return f(); } export function f() { return read(); }`,
    `function read() { return arguments; } export function f() { return read(); }`,
    `function read() { return this; } export function f() { return read(); }`,
    `function read() { return module; } export function f() { return read(); }`,
    `export function f(value) { return Number(value); }`,
  ];
  for (const source of cases) {
    const target = { identity: { path: "dep.js" }, source };
    const importer = {
      identity: { path: "entry.js" },
      source: `import { f } from "./dep.js"; const Number = () => 99;
       export function result(value) { return f(value); }`,
    };
    const graph = new Map([
      ["dep.js", target],
      ["entry.js", importer],
    ]);
    const plan = convexWasmModuleLinkage.planConvexWasmFunctionImports(
      importer,
      graph,
      convexWasmModuleLinkage.immutableImportPlan(importer, graph)
    );
    assert.deepEqual(plan.calls, [], source);
  }
});

test("global reads in closed helpers retain exceptions and avoid importer bindings", async () => {
  const source = `function read(value) {
    if (!Number.isFinite(value.left)) throw new Error("invalid value");
    return value.left + value.right;
  }
  export function total(value) { return read(value); }`;
  const plans = new Map();
  const entry = await loadModules(
    {
      "./dep.js": source,
      "./entry.js": `import { total } from "./dep.js";
      export function result(value) { return total(value); }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.equal(entry.result({ left: 3, right: 5 }), 8);
  assert.throws(() => entry.result({ left: NaN, right: 5 }), { message: "invalid value" });
  assert.equal(plans.get("./entry.js").bodies[0].helpers.length, 1);
  const shadowed = new Map();
  const other = await loadModules(
    {
      "./dep.js": source,
      "./entry.js": `import { total } from "./dep.js";
      const Error = () => 0; export function result(value) { return total(value); }`,
    },
    "./entry.js",
    new Map(),
    shadowed
  );
  assert.throws(() => other.result({ left: NaN, right: 5 }), { message: "invalid value" });
  assert.deepEqual(shadowed.get("./entry.js").calls, []);
});

test("helper bodies participate in persistent proofs and imported-consumer invalidation", async (t) => {
  const cacheRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-helper-summary-"));
  t.after(() => fs.rm(cacheRoot, { force: true, recursive: true }));
  const cacheLayout = deriveConvexWasmCacheLayout({
    buildId: "helpers",
    cacheRoot,
    repositoryRoot: cacheRoot,
    scope: "isolated-test",
  });
  const prepare = async (operator, extra) => {
    const importer = {
      identity: { path: "entry.js" },
      source: `import { total } from "./dep.js"; export function result(v) { return total(v); }`,
    };
    const target = {
      identity: { path: "dep.js" },
      source: `function read(v) { return v.left ${operator} v.right; }
       export function total(v) { return read(v); } export const unused = ${extra};`,
    };
    const graph = new Map([
      ["entry.js", importer],
      ["dep.js", target],
    ]);
    const report = await convexWasmModuleLinkage.prepareConvexWasmFunctionSpecialization(
      [...graph.values()],
      { cacheRoot, cacheLayout }
    );
    const plan = convexWasmModuleLinkage.planConvexWasmFunctionImports(
      importer,
      graph,
      convexWasmModuleLinkage.immutableImportPlan(importer, graph)
    );
    return { report, plan };
  };
  const cold = await prepare("+", 1);
  const warm = await prepare("+", 1);
  assert.equal(warm.report.cacheHits, 2);
  assert.deepEqual(warm.plan, cold.plan);
  const unrelated = await prepare("+", 2);
  assert.equal(unrelated.report.cacheHits, 1);
  assert.deepEqual(unrelated.plan, cold.plan);
  const edited = await prepare("-", 2);
  assert.equal(edited.report.cacheHits, 1);
  assert.notDeepEqual(edited.plan.bodies, cold.plan.bodies);
});

test("bounded imports prioritize fresh object fields and charge helper bodies", async () => {
  const names = Array.from({ length: 40 }, (_, i) => `f${i}`);
  const plans = new Map();
  const entry = await loadModules(
    {
      "./dep.js":
        names
          .map((name, i) => `export function ${name}(value) { return value + ${i}; }`)
          .join("\n") +
        `\nfunction read(value) { return value.left + value.right; }
          export function total(value) { return read(value); }`,
      "./entry.js": `import { ${names.join(", ")}, total } from "./dep.js";
        export function result() { return [${names.map((name) => `${name}(1)`).join(", ")},
          total({ left: 3, right: 5 })]; }`,
    },
    "./entry.js",
    new Map(),
    plans
  );
  assert.deepEqual(Array.from(entry.result()), [...names.map((_, i) => i + 1), 8]);
  const plan = plans.get("./entry.js");
  assert.equal(plan.bodies[0].helpers.length, 1);
  assert.equal(plan.bodies.length, 31);
  assert.equal(
    plan.bodies.reduce((count, body) => count + 1 + body.helpers.length, 0),
    32
  );
  assert.equal(plan.rejectedBindings, 10);
});


test("stable import bindings retain source order, cyclic exports and deferred dynamic imports", async () => {
  const builds = [];
  for (const suffix of ["old", "new"]) {
    const a = `a-${suffix}.js`,
      b = `b-${suffix}.js`;
    const declarations = [`import { value } from "./${a}";`, `import { early } from "./${b}";`];
    const sources = {
      "entry.js": `${(suffix === "old" ? declarations : declarations.toReversed()).join("\n")}
        export { value }; export function result() { return early; }
        export function deferred() { return import("./dynamic.js"); }`,
      [a]: `export let value = 7; export function update() { value++; }`,
      [b]: `import { value } from "./entry.js";
        export let early; try { early = value; } catch (error) { early = error.name; }`,
      "dynamic.js": `throw new Error("deferred");`,
    };
    const chunks = await buildConvexWasmOfficialOutputChunkUnits({
      esbuild,
      selections: await chunkSelections(sources),
    });
    builds.push(chunks);
    const entries = runChunkUnits(chunks);
    assert.equal(entries[0].namespace.result(), suffix === "old" ? 7 : "TypeError");
    await assert.rejects(entries[0].namespace.deferred(), /deferred/u);
  }
  const entry = (chunks) =>
    chunks.units.find(({ identity }) => identity.module.path === "entry.js");
  assert.equal(entry(builds[0]).javascript, entry(builds[1]).javascript);
  assert.notDeepEqual(
    entry(builds[0]).identity.dependencies,
    entry(builds[1]).identity.dependencies
  );
  const reusable = builds.map((chunks) => {
    const identities = deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
      chunkSlotCount: chunks.units.length,
      units: chunks.units.map(({ identity }) => ({ ...identity, entryPublication: false })),
    });
    return identities[chunks.units.indexOf(entry(chunks))];
  });
  assert.equal(reusable[0], reusable[1]);
});

test("stable import bindings retain imported function specialization identity", async () => {
  const builds = [];
  for (const suffix of ["old", "new"]) {
    const imports = [
      `import { first } from "./a-${suffix}.js";`,
      `import { second } from "./b-${suffix}.js";`,
    ];
    const chunks = await buildConvexWasmOfficialOutputChunkUnits({
      esbuild,
      selections: await chunkSelections({
        "entry.js": `${(suffix === "old" ? imports : imports.toReversed()).join("\n")}
          export function result(value) { return first(value) + second(value); }`,
        [`a-${suffix}.js`]: "export const first = value => value.amount + 1;",
        [`b-${suffix}.js`]: "export const second = value => value.amount + 2;",
      }),
    });
    assert.equal(runChunkUnits(chunks)[0].namespace.result({ amount: 3 }), 9);
    builds.push(chunks.units.find(({ identity }) => identity.module.path === "entry.js"));
  }
  assert.equal(builds[0].javascript, builds[1].javascript);
});

test("ordered initialization retains default imports, star reexports and repeated imports", async () => {
  for (const repeated of [false, true]) {
    const chunks = await buildConvexWasmOfficialOutputChunkUnits({
      esbuild,
      selections: await chunkSelections({
        "entry.js": `import first from "./a.js"; export * from "./b.js"; export * from "./c.js";
          ${repeated ? 'import { value as again } from "./b.js"; export { again };' : ""}
          globalThis.trace.push("entry");
          export function result() { return [first, globalThis.trace.join(",")]; }`,
        "a.js": `globalThis.trace = ["a"]; export default 7;`,
        "b.js": `globalThis.trace.push("b"); export let value = 9;`,
        "c.js": `globalThis.trace.push("c"); export let other = 2;`,
      }),
    });
    const [{ namespace }] = runChunkUnits(chunks);
    assert.deepEqual(Array.from(namespace.result()), [7, "a,b,c,entry"]);
    assert.equal(namespace.value, 9);
    assert.equal(namespace.other, 2);
    if (repeated) assert.equal(namespace.again, 9);
  }
});
