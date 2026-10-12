import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { nodeUrlService } from "../test-fixtures/native-url/node-service.mjs";

import {
  convexWasmRuntimeSupportIdentity,
  renderConvexWasmRuntimeSupportUnit,
} from "./convex-wasm-runtime-support.mjs";

test("runtime support is reproducible with its required native URL service", () => {
  execFileSync(
    process.execPath,
    [fileURLToPath(new URL("../generate-convex-wasm-runtime-support.mjs", import.meta.url))],
    { stdio: "pipe", timeout: 30_000 }
  );

  const source = renderConvexWasmRuntimeSupportUnit();
  assert.equal(
    createHash("sha256").update(source).digest("hex"),
    convexWasmRuntimeSupportIdentity.browserBundleSha256
  );

  let installed;
  runInNewContext(source, {
    TextDecoder,
    TextEncoder,
    __convexWasmNativeUrl: nodeUrlService(),
    __convexWasmApplicationInstallRuntimeSupport(value) {
      installed = value;
    },
  });
  assert.equal(new installed.URL("/next", "https://example.test/base").href, "https://example.test/next");
  assert.equal(new installed.DOMException("closed", "AbortError").name, "AbortError");
  assert.equal(Object.hasOwn(installed, "Intl"), false);

});

test("runtime support rejects a missing native URL service", () => {
  assert.throws(() => runInNewContext(renderConvexWasmRuntimeSupportUnit(), {
    TextDecoder, TextEncoder,
    __convexWasmApplicationInstallRuntimeSupport() {
      assert.fail("Support must not install without its native service");
    },
  }), /Native URL bootstrap is unavailable/u);
});
