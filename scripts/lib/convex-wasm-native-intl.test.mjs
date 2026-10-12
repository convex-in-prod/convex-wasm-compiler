import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { nativeRuntimeProbeConfiguration, runNativeRuntimeProbe } from "./convex-wasm-native-runtime-probe.mjs";

test("native Intl survives production descriptor validation and Wasm runtime reuse", async (context) => {
  const configuration = nativeRuntimeProbeConfiguration();
  if (configuration === undefined) {
    context.skip("set the native runtime probe toolchain under the native-build resource guard");
    return;
  }
  const javascript = await readFile(new URL("../test-fixtures/native-values/intl.js", import.meta.url), "utf8");
  const result = await runNativeRuntimeProbe({ javascript, configuration });
  assert.deepEqual(result.results, Array(9).fill(true));
});
