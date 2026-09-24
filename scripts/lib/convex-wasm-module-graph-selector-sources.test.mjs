import assert from "node:assert/strict";
import test from "node:test";

import {
  renderConvexWasmModuleGraphCommonFactoryAdapter,
  renderConvexWasmModuleGraphHostForwarders,
  renderConvexWasmModuleGraphStructuralTraps,
} from "./convex-wasm-module-graph-selector-sources.mjs";

test("common factory adapter binds each reviewed source symbol to its stable slot", () => {
  const common = [
    { factorySymbol: "stable_first", occurrence: { unit: { entrySymbol: "source_first" } } },
    { factorySymbol: "stable_second", occurrence: { unit: { entrySymbol: "source_second" } } },
  ];
  const source = renderConvexWasmModuleGraphCommonFactoryAdapter(common);
  assert.match(source, /SHUnit \*stable_first\(void\) \{ return source_first\(\); \}/u);
  assert.match(source, /SHUnit \*stable_second\(void\) \{ return source_second\(\); \}/u);
  assert.throws(
    () => renderConvexWasmModuleGraphCommonFactoryAdapter([...common, common[0]]),
    /duplicate factory symbol/u
  );
});

test("host forwarders retain byte-transfer and async-operation imports", () => {
  const source = renderConvexWasmModuleGraphHostForwarders();
  for (const name of [
    "convex_async_operation_cancel_all",
    "convex_capability_query_stream_open_take",
    "convex_guest_value_request_copy",
    "convex_guest_value_payload_copy",
    "convex_guest_value_result",
  ]) {
    assert.equal(source.includes(`CONVEX_WASM_GRAPH_HOST_IMPORT("${name}")`), true, name);
  }
  const traps = renderConvexWasmModuleGraphStructuralTraps();
  assert.match(traps, /int32_t __syscall_chdir\(int32_t a\).*CONVEX_WASM_GRAPH_TRAP/u);
  assert.match(traps, /int32_t _dlopen_js\(int32_t a\).*CONVEX_WASM_GRAPH_TRAP/u);
});
