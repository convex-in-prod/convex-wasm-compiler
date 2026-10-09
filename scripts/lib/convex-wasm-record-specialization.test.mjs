import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { parse } from "@babel/parser";
import traverseModule from "@babel/traverse";

import {
  analyzeConvexWasmRecordInterface,
  renderConvexWasmRecordInterface,
} from "./convex-wasm-record-specialization.mjs";

const traverse = traverseModule.default;

function analyze(source, name = "entry", parameterIndex = 0) {
  const ast = parse(source, { sourceType: "module" });
  let program;
  const names = new Set();
  traverse(ast, {
    Program(path) { program = path; },
    Identifier(path) { names.add(path.node.name); },
  });
  const summary = analyzeConvexWasmRecordInterface(
    program.scope.getBinding(name), parameterIndex, source
  );
  return { summary, names };
}

test("record interfaces carry field demand through helpers and live closures", () => {
  const source = `
    let epoch = 1;
    const __convexRecord_entry_1_field0 = 100;
    function leaf(record, increment) {
      record.child.count += increment;
      return () => record.child.count + record.amount + epoch + __convexRecord_entry_1_field0;
    }
    function middle(record, increment) { return leaf(record, increment); }
    function entry(increment, record, suffix) { return [middle(record, increment), suffix]; }
    Object.defineProperty(entry, "name", {value: "published"});
    entry.note = "retained";
  `;
  const { summary, names } = analyze(source, "entry", 1);
  assert.deepEqual(summary.fields, ["amount", "child"]);
  assert.equal(summary.functions.length, 3);
  const rendered = renderConvexWasmRecordInterface(source, summary, names);
  const api = vm.runInNewContext(`(function() { "use strict"; ${source}
    ${rendered.source}
    return {original: entry, specialized: ${rendered.entry}, advance: () => ++epoch};
  })()`);
  const firstChild = { count: 2 };
  const secondChild = { count: 2 };
  const original = api.original(3, { child: firstChild, amount: 7 }, "end");
  const specialized = api.specialized(3, 7, secondChild, "end");
  assert.equal(original[0](), specialized[0]());
  assert.equal(original[1], specialized[1]);
  api.advance();
  firstChild.count = secondChild.count = 19;
  assert.equal(original[0](), 128);
  assert.equal(specialized[0](), 128);
  assert.equal(api.original.name, "published");
  assert.equal(api.original.length, 3);
  assert.equal(api.original.note, "retained");
});

test("nested forwarding arguments preserve evaluation order, exceptions and unused arguments", () => {
  const source = `
    let trace = "";
    function effect(value) { trace += value; if (value === "throw") throw value; return value; }
    function leaf(record, value) { return record.value + value; }
    function entry(record, fail) {
      return leaf(record, effect("a") + leaf(record, effect(fail ? "throw" : "b")) + record.value, effect("extra"));
    }
  `;
  const { summary, names } = analyze(source);
  const rendered = renderConvexWasmRecordInterface(source, summary, names);
  const api = vm.runInNewContext(`(function() { "use strict"; ${source}
    ${rendered.source}
    return {original: entry, specialized: ${rendered.entry}, take: () => {const value=trace;trace="";return value;}};
  })()`);
  assert.equal(api.original({ value: "v" }, false), api.specialized("v", false));
  assert.equal(api.take(), "abextraabextra");
  assert.throws(() => api.original({ value: "v" }, true), (error) => error === "throw");
  assert.equal(api.take(), "athrow");
  assert.throws(() => api.specialized("v", true), (error) => error === "throw");
  assert.equal(api.take(), "athrow");
});

test("record writes, identity observations and dynamic callees stay generic", () => {
  const rejected = [
    "return record;",
    "record.value = 2; return record.value;",
    "[record.value] = [2]; return record.value;",
    "({a: record.value} = {a: 2}); return record.value;",
    "[record.value = 2] = []; return record.value;",
    "for (record.value of [1,2]) {} return record.value;",
    "for (record.value in {a:1}) {} return record.value;",
    "record.value++; return record.value;",
    "delete record.value; return record.value;",
    "return record.method();",
    "return record.method?.();",
    "return record[key];",
    "return Object.keys(record);",
    "return unknown(record);",
    "return child(record, record);",
    "return child(...[record]);",
    "record = {value: 2}; return record.value;",
    "return () => { record = {value: 2}; return record.value; };",
    "return arguments[0].value + record.value;",
    "return eval('record.value');",
    "return tag`literal` + record.value;",
  ];
  for (const body of rejected) {
    const source = `function child(a,b) {return a.value + b.value;} function entry(record) {${body}}`;
    assert.equal(analyze(source).summary, undefined, body);
  }
});

test("recursive, reassigned, imported and asynchronous forwarding is rejected", () => {
  for (const source of [
    "function entry(r) {return entry(r) + r.value;}",
    "function child(r) {return entry(r);} function entry(r) {return child(r) + r.value;}",
    "function child(r) {return r.value;} child = x => x; function entry(r) {return child(r);}",
    "import {child} from './other.js'; function entry(r) {return child(r);}",
    "async function child(r) {return r.value;} function entry(r) {return child(r);}",
    "function* child(r) {yield r.value;} function entry(r) {return child(r);}",
    "function child(...rest) {return rest[0].value;} function entry(r) {return child(r);}",
  ]) assert.equal(analyze(source).summary, undefined, source);
});

test("record interfaces bound graph size, field growth and copied bytes", () => {
  const fields = Array.from({ length: 9 }, (_, i) => `r.field${i}`).join("+");
  assert.equal(analyze(`function entry(r) {return ${fields};}`).summary, undefined);
  const chain = Array.from({ length: 9 }, (_, i) =>
    `function ${i === 0 ? "entry" : `step${i}`}(r) {return ${i === 8 ? "r.value" : `step${i+1}(r)`};}`
  ).join("\n");
  assert.equal(analyze(chain).summary, undefined);
  assert.equal(analyze(`function entry(r) {/*${"x".repeat(65536)}*/ return r.value;}`).summary, undefined);
});

test("rendering rejects a mismatched source and uses stable field order", () => {
  const source = "function entry(r) {return r.z + r.a;}";
  const { summary, names } = analyze(source);
  assert.deepEqual(summary.fields, ["a", "z"]);
  assert.throws(() => renderConvexWasmRecordInterface(source.replace("r.z", "r.y"), summary, names), /source body/u);
  const first = renderConvexWasmRecordInterface(source, summary, names);
  const second = renderConvexWasmRecordInterface(source, summary, names);
  assert.deepEqual(first, second);
});
