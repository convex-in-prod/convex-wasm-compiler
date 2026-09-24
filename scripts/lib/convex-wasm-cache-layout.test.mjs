import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  defaultConvexWasmCacheRoot,
  deriveConvexWasmCacheLayout,
  normalizeConvexWasmCacheLayout,
} from "./convex-wasm-cache-layout.mjs";

test("shares immutable cache objects across application checkouts", () => {
  const parent = resolve(tmpdir(), "convex-wasm-cache-layout-test");
  const cacheRoot = join(parent, "shared-cache");
  const first = deriveConvexWasmCacheLayout({
    buildId: "first-build",
    cacheRoot,
    repositoryRoot: join(parent, "first-project"),
    scope: "isolated-test",
  });
  const second = deriveConvexWasmCacheLayout({
    buildId: "second-build",
    cacheRoot,
    repositoryRoot: join(parent, "second-project"),
    scope: "isolated-test",
  });
  assert.equal(first.cacheRoot, cacheRoot);
  assert.equal(first.scope, "isolated-test");
  assert.deepEqual(first.immutable, second.immutable);
  assert.equal(first.immutable.artifacts, join(cacheRoot, "immutable", "v6", "artifacts"));
  assert.notEqual(first.state.checkoutDiagnosticKey, second.state.checkoutDiagnosticKey);
  assert.notEqual(first.work.buildRoot, second.work.buildRoot);
  assert.equal(Object.isFrozen(first.immutable), true);
  assert.deepEqual(normalizeConvexWasmCacheLayout(structuredClone(first)), first);
});

test("chooses a checkout-independent generic cache root", () => {
  const cacheHome = resolve(tmpdir(), "generic-cache-home");
  assert.equal(
    defaultConvexWasmCacheRoot({ XDG_CACHE_HOME: cacheHome }),
    join(cacheHome, "convex-wasm-compiler")
  );
  assert.throws(
    () => defaultConvexWasmCacheRoot({ XDG_CACHE_HOME: "relative-cache" }),
    /XDG_CACHE_HOME must be a normalized absolute path/u
  );
  const first = deriveConvexWasmCacheLayout({
    buildId: "first",
    repositoryRoot: resolve(tmpdir(), "project-a"),
  });
  const second = deriveConvexWasmCacheLayout({
    buildId: "second",
    repositoryRoot: resolve(tmpdir(), "project-b"),
  });
  assert.equal(first.cacheRoot, defaultConvexWasmCacheRoot());
  assert.deepEqual(first.immutable, second.immutable);
  assert.equal(first.scope, "per-user-local");
});

test("rejects unsafe or inconsistent cache layout inputs", () => {
  const parent = resolve(tmpdir(), "convex-wasm-cache-layout-test");
  const options = {
    buildId: "good-build",
    cacheRoot: join(parent, "cache"),
    repositoryRoot: join(parent, "project"),
  };
  assert.throws(
    () => deriveConvexWasmCacheLayout({ ...options, buildId: "../escape" }),
    /build ID/u
  );
  assert.throws(
    () => deriveConvexWasmCacheLayout({ ...options, cacheRoot: "relative-cache" }),
    /cache root must be a normalized absolute path/u
  );
  assert.throws(
    () => deriveConvexWasmCacheLayout({ ...options, scope: "unknown" }),
    /layout scope/u
  );
  const layout = structuredClone(deriveConvexWasmCacheLayout(options));
  layout.immutable.artifacts = join(parent, "wrong");
  assert.throws(() => normalizeConvexWasmCacheLayout(layout), /layout paths do not match/u);
});
