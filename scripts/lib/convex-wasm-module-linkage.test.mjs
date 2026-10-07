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
    const modules = Object.entries(sources).map(([path, source]) => {
      const sources = [`fixture:///${path}`];
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
      imports: [
        {
          external: false,
          importerPath: "entry.js",
          kind: "import-statement",
          path: "dep.js",
        },
      ],
      modules: modules.map(({ identity }) => identity),
    };
    const selections = authenticateConvexWasmOfficialOutputSelectionFixtures([
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
    const facade = Object.create(null);
    Object.defineProperty(facade, "globalThis", { value: facade });
    const context = vm.createContext({
      __convexWasmApplicationGlobalThis: facade,
    });
    const entries = initializeConvexWasmOfficialOutputChunkUnits({
      chunkUnits: materialized,
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
