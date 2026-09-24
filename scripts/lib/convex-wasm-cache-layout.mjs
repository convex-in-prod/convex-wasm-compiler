import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const BUILD_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CACHE_SCOPES = new Set(["per-user-local", "evidence", "isolated-test"]);

function fail(message) {
  throw new Error(`Convex Wasm cache layout: ${message}`);
}

function requireExactKeys(value, expected, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const keys = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(`${description} must contain exactly ${expectedKeys.join(", ")}`);
  }
}

function requireNormalizedAbsolutePath(path, description) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) {
    fail(`${description} must be a normalized absolute path`);
  }
}

export function defaultConvexWasmCacheRoot(environment = process.env) {
  const configuredCacheHome = environment.XDG_CACHE_HOME;
  if (configuredCacheHome !== undefined) {
    requireNormalizedAbsolutePath(configuredCacheHome, "XDG_CACHE_HOME");
  }
  const cacheHome =
    configuredCacheHome === undefined
      ? process.platform === "darwin"
        ? join(homedir(), "Library", "Caches")
        : join(homedir(), ".cache")
      : configuredCacheHome;
  return join(cacheHome, "convex-wasm-compiler");
}

export function deriveConvexWasmCacheLayout({
  repositoryRoot,
  buildId,
  cacheRoot = defaultConvexWasmCacheRoot(),
  scope = "per-user-local",
}) {
  requireNormalizedAbsolutePath(repositoryRoot, "repository root");
  requireNormalizedAbsolutePath(cacheRoot, "cache root");
  if (typeof buildId !== "string" || !BUILD_ID_PATTERN.test(buildId)) {
    fail("build ID must contain 1-128 letters, digits, dots, underscores, or hyphens");
  }
  if (!CACHE_SCOPES.has(scope)) {
    fail("layout scope must be per-user-local, evidence, or isolated-test");
  }
  const checkoutDiagnosticKey = createHash("sha256")
    .update("convex-wasm-checkout-diagnostics-v1\0")
    .update(repositoryRoot)
    .digest("hex");
  const immutableRoot = join(cacheRoot, "immutable", "v6");
  const stateRoot = join(cacheRoot, "state", "v1");
  const checkoutStateRoot = join(stateRoot, checkoutDiagnosticKey);
  const workRoot = join(cacheRoot, "work", "v1");
  const buildWorkRoot = join(workRoot, buildId);
  return normalizeConvexWasmCacheLayout({
    cacheRoot,
    scope,
    immutable: {
      root: immutableRoot,
      artifacts: join(immutableRoot, "artifacts"),
      packages: join(immutableRoot, "packages"),
    },
    state: {
      root: stateRoot,
      checkoutDiagnosticKey,
      checkoutRoot: checkoutStateRoot,
      routeState: join(checkoutStateRoot, "route-state"),
      lastBuild: join(checkoutStateRoot, "last-build"),
    },
    work: {
      root: workRoot,
      buildRoot: buildWorkRoot,
      scratch: join(buildWorkRoot, "scratch"),
      timings: join(buildWorkRoot, "timings"),
      reports: join(buildWorkRoot, "reports"),
    },
  });
}

export function normalizeConvexWasmCacheLayout(value) {
  requireExactKeys(value, ["cacheRoot", "immutable", "scope", "state", "work"], "layout");
  requireNormalizedAbsolutePath(value.cacheRoot, "cache root");
  if (!CACHE_SCOPES.has(value.scope)) {
    fail("layout scope must be per-user-local, evidence, or isolated-test");
  }
  requireExactKeys(value.immutable, ["artifacts", "packages", "root"], "immutable layout");
  requireExactKeys(
    value.state,
    ["checkoutDiagnosticKey", "checkoutRoot", "lastBuild", "root", "routeState"],
    "state layout"
  );
  requireExactKeys(
    value.work,
    ["buildRoot", "reports", "root", "scratch", "timings"],
    "work layout"
  );
  if (!SHA256_PATTERN.test(value.state.checkoutDiagnosticKey)) {
    fail("checkout diagnostic key must be a lowercase SHA-256 digest");
  }
  const immutableRoot = join(value.cacheRoot, "immutable", "v6");
  const stateRoot = join(value.cacheRoot, "state", "v1");
  const checkoutRoot = join(stateRoot, value.state.checkoutDiagnosticKey);
  const workRoot = join(value.cacheRoot, "work", "v1");
  const buildId = relative(workRoot, value.work.buildRoot);
  if (
    !BUILD_ID_PATTERN.test(buildId) ||
    buildId.includes(sep) ||
    value.immutable.root !== immutableRoot ||
    value.immutable.artifacts !== join(immutableRoot, "artifacts") ||
    value.immutable.packages !== join(immutableRoot, "packages") ||
    value.state.root !== stateRoot ||
    value.state.checkoutRoot !== checkoutRoot ||
    value.state.routeState !== join(checkoutRoot, "route-state") ||
    value.state.lastBuild !== join(checkoutRoot, "last-build") ||
    value.work.root !== workRoot ||
    value.work.buildRoot !== join(workRoot, buildId) ||
    value.work.scratch !== join(workRoot, buildId, "scratch") ||
    value.work.timings !== join(workRoot, buildId, "timings") ||
    value.work.reports !== join(workRoot, buildId, "reports")
  ) {
    fail("layout paths do not match the Convex Wasm cache layout");
  }
  return Object.freeze({
    cacheRoot: value.cacheRoot,
    scope: value.scope,
    immutable: Object.freeze({ ...value.immutable }),
    state: Object.freeze({ ...value.state }),
    work: Object.freeze({ ...value.work }),
  });
}
