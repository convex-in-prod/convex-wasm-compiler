import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

import {
  convexWasmRuntimeSupportIdentity,
  renderConvexWasmRuntimeSupportUnit,
} from "./convex-wasm-runtime-support.mjs";

test("runtime support is reproducible and works without host web globals", () => {
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
    __convexWasmApplicationInstallRuntimeSupport(value) {
      installed = value;
    },
  });
  assert.equal(new installed.URL("/next", "https://example.test/base").href, "https://example.test/next");
  assert.equal(new installed.DOMException("closed", "AbortError").name, "AbortError");
  assert.equal(
    new installed.Intl.DateTimeFormat("en-US", { timeZone: "UTC", year: "numeric" }).format(0),
    "1970"
  );
});
