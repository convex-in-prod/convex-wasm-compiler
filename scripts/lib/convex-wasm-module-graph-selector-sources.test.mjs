import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  renderConvexWasmModuleGraphCommonFactoryAdapter,
  renderConvexWasmModuleGraphHostForwarders,
  renderConvexWasmModuleGraphStructuralTraps,
} from "./convex-wasm-module-graph-selector-sources.mjs";

test("common factory adapter binds each reviewed source symbol to its stable slot", () => {
  const common = [
    {
      factorySymbol: "stable_first",
      occurrence: { unit: { entrySymbol: "source_first" } },
    },
    {
      factorySymbol: "stable_second",
      occurrence: { unit: { entrySymbol: "source_second" } },
    },
  ];
  const source = renderConvexWasmModuleGraphCommonFactoryAdapter(common);
  assert.match(
    source,
    /SHUnit \*stable_first\(void\) \{ return source_first\(\); \}/u,
  );
  assert.match(
    source,
    /SHUnit \*stable_second\(void\) \{ return source_second\(\); \}/u,
  );
  assert.throws(
    () =>
      renderConvexWasmModuleGraphCommonFactoryAdapter([...common, common[0]]),
    /duplicate factory symbol/u,
  );
});

test("host forwarders retain byte-transfer and async-operation imports", () => {
  const source = renderConvexWasmModuleGraphHostForwarders();
  for (const name of [
    "convex_async_operation_cancel_all",
    "convex_capability_query_stream_open_take",
    "convex_guest_value_request_copy",
    "convex_guest_value_payload_copy",
    "convex_guest_value_result_binary",
  ]) {
    assert.equal(
      source.includes(`CONVEX_WASM_GRAPH_HOST_IMPORT("${name}")`),
      true,
      name,
    );
  }
  assert.doesNotMatch(source, /\bconvex_guest_value_result\b/u);
  const traps = renderConvexWasmModuleGraphStructuralTraps();
  assert.match(
    traps,
    /int32_t __syscall_chdir\(int32_t a\).*CONVEX_WASM_GRAPH_TRAP/u,
  );
  assert.match(
    traps,
    /int32_t _dlopen_js\(int32_t a\).*CONVEX_WASM_GRAPH_TRAP/u,
  );
});

test(
  "export-all forwarders link with exactly one binary result import",
  {
    skip:
      !process.env.CONVEX_WASM_TEST_CLANG && !process.env.CONVEX_WASM_TEST_LD,
  },
  () => {
    const clang = process.env.CONVEX_WASM_TEST_CLANG;
    const linker = process.env.CONVEX_WASM_TEST_LD;
    assert(clang && linker, "Both Wasm compiler and linker are required");
    const directory = mkdtempSync(join(tmpdir(), "convex-forwarders-"));
    try {
      writeFileSync(
        join(directory, "forwarders.c"),
        renderConvexWasmModuleGraphHostForwarders(),
      );
      const options = {
        cwd: directory,
        timeout: 30_000,
        maxBuffer: 1024 * 1024,
      };
      execFileSync(
        clang,
        [
          "--target=wasm32",
          "-ffreestanding",
          "-O2",
          "-c",
          "forwarders.c",
          "-o",
          "forwarders.o",
        ],
        options,
      );
      execFileSync(
        linker,
        ["--no-entry", "--export-all", "forwarders.o", "-o", "forwarders.wasm"],
        options,
      );
      const module = new WebAssembly.Module(
        readFileSync(join(directory, "forwarders.wasm")),
      );
      const resultImports = WebAssembly.Module.imports(module).filter(
        ({ module, name }) =>
          module === "convex" && name.startsWith("convex_guest_value_result"),
      );
      assert.deepEqual(
        resultImports.map(({ name }) => name),
        ["convex_guest_value_result_binary"],
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  },
);
