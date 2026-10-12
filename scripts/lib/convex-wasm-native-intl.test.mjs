import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { nativeRuntimeProbeConfiguration, runNativeRuntimeProbe, runNativeResourceProbe } from "./convex-wasm-native-runtime-probe.mjs";

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

test("native allocations outside ICU obey the host linear-memory limit", async (context) => {
  const configuration = nativeRuntimeProbeConfiguration();
  if (configuration === undefined) {
    context.skip("set the native runtime probe toolchain under the native-build resource guard");
    return;
  }
  const result = await runNativeResourceProbe({ configuration });
  for (const [name, probe] of Object.entries(result.results)) {
    assert.equal(probe.kind, "convex-wasm-resource-probe-v1");
    assert.equal(probe.phase, "execution", name);
    assert.ok(probe.memoryBytes > 0 && probe.memoryBytes <= 64 * 1024 * 1024, name);
    assert.deepEqual(probe.stderr, [], name);
    if (name === "control") {
      assert.deepEqual(probe.outcome, { kind: "returned", status: 0 });
      assert.equal(Buffer.from(probe.stdout).toString(), "NATIVE_INTL_READY\nNATIVE_ALLOCATIONS_COMPLETE\n");
    } else {
      assert.equal(probe.outcome.kind, "failed", name);
      assert.match(probe.outcome.error, /memory/u, name);
      assert.doesNotMatch(probe.outcome.error, /fuel|allocator returned null/u, name);
      assert.equal(Buffer.from(probe.stdout).toString(), "NATIVE_INTL_READY\n", name);
    }
  }
  context.diagnostic(JSON.stringify(result));
});
