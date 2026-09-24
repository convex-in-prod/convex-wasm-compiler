import assert from "node:assert/strict";
import test from "node:test";

import ts from "typescript";

import { createConvexWasmRegistrationSourceAnalyzer } from "./convex-wasm-registration-source-analysis.mjs";

const analyze = createConvexWasmRegistrationSourceAnalyzer(ts);

function analyzeSource(source) {
  return analyze({
    absolutePath: "/example/convex/entry.ts",
    input: {
      imports: [
        {
          kind: "import-statement",
          original: "convex/server",
          path: "node_modules/convex/dist/esm/server/index.js",
        },
      ],
    },
    inputPath: "convex/entry.ts",
    material: { contents: Buffer.from(source) },
  });
}

test("records imports, immutable aliases, exports, and declarative registrations", () => {
  const source = `
import { queryGeneric as query } from "convex/server";
const register = query;
export const read = register({ args: {}, handler: () => 42 });
export { read as renamed };
`;
  const result = analyzeSource(source);
  assert.deepEqual(result.imports, [
    ["query", { importedName: "queryGeneric", target: "node_modules/convex/dist/esm/server/index.js" }],
  ]);
  assert.deepEqual(result.aliases, [["register", "query"]]);
  assert.deepEqual(result.exports, [
    ["read", { localName: "read" }],
    ["renamed", { localName: "read" }],
  ]);
  assert.deepEqual(result.candidates, [
    { callee: "register", initializerStart: source.indexOf("register({") },
  ]);
  assert.equal(Object.isFrozen(result.candidates[0]), true);
});

test("rejects registration calls whose definition can invoke inherited or accessor code", () => {
  for (const definition of [
    "{ __proto__: unexpected, handler: () => 42 }",
    "{ get handler() { return () => 42; } }",
    "{ args: {} }",
  ]) {
    const result = analyzeSource(`export const read = query(${definition});`);
    assert.deepEqual(result.candidates, []);
  }
});

test("requires an injected TypeScript runtime", () => {
  assert.throws(
    () => createConvexWasmRegistrationSourceAnalyzer(undefined),
    /requires a TypeScript runtime/u
  );
});
