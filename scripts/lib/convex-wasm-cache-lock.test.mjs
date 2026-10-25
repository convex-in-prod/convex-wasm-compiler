import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { bindConvexWasmProjectBuild } from "../bind-convex-wasm.mjs";
import { publishConvexWasmProjectRegistry } from "../publish-registry.mjs";
import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";
import { acquireConvexWasmCacheLock, requireConvexWasmCacheLockAuthority } from "./convex-wasm-cache-lock.mjs";
import { deriveConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";

const TEST_TEMPORARY_DIRECTORY = process.platform === "linux" ? "/var/tmp" : tmpdir();

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function lockEnvironment(t) {
  // Private evidence rejects symlink ancestors, including macOS's /var temporary paths.
  const directory = await fs.realpath(
    await fs.mkdtemp(join(TEST_TEMPORARY_DIRECTORY, "convex-wasm-cache-lock-test-"))
  );
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  return { CONVEX_WASM_CACHE_LOCK_DB: join(directory, "convex-wasm-cache-lock.sqlite") };
}

function useLockEnvironment(t, environment) {
  for (const key of ["CONVEX_WASM_CACHE_LOCK_DB", "CONVEX_WASM_CACHE_LOCK_AUTHORITY"]) {
    const previous = process.env[key];
    t.after(() => {
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    });
    if (environment[key] === undefined) delete process.env[key];
    else process.env[key] = environment[key];
  }
}

test("binding and registry publication wait for cache ownership and release it on failure", async (t) => {
  for (const operation of [bindConvexWasmProjectBuild, publishConvexWasmProjectRegistry]) {
    await t.test(operation.name, async (t) => {
      const environment = await lockEnvironment(t);
      useLockEnvironment(t, environment);
      const releaseOwner = await acquireConvexWasmCacheLock({ environment });
      let finished = false;
      const outcome = assert.rejects(
        operation({ configPath: join(dirname(environment.CONVEX_WASM_CACHE_LOCK_DB), "missing.json") })
          .finally(() => { finished = true; }),
        { code: "ENOENT" }
      );
      try {
        await delay(350);
        assert.equal(finished, false);
      } finally {
        releaseOwner();
        await outcome;
      }
      const releaseNext = await acquireConvexWasmCacheLock({ environment });
      releaseNext();
    });
  }
});

test("cache consumers preserve same-process and inherited-child ownership", async (t) => {
  const environment = await lockEnvironment(t);
  useLockEnvironment(t, environment);
  const root = dirname(environment.CONVEX_WASM_CACHE_LOCK_DB);
  const releaseOwner = await acquireConvexWasmCacheLock();
  try {
    for (const [operation, script, options] of [
      [bindConvexWasmProjectBuild, "scripts/bind-convex-wasm.mjs", ["--output", join(root, "bound.json")]],
      [publishConvexWasmProjectRegistry, "scripts/publish-registry.mjs", [
        "--deployment", join(root, "bound.json"),
        "--registry-root", join(root, "registry"),
        "--publication", "shadow-only",
        "--preflight-output", join(root, "preflight.json"),
      ]],
    ]) {
      await assert.rejects(operation({ configPath: join(root, "missing.json") }), /already owns the cache lock/u);
      const child = spawnSync(process.execPath, [
        script, "--config", join(root, "missing.json"),
        "--artifact-report", join(root, "report.json"), ...options,
      ], { cwd: process.cwd(), encoding: "utf8", env: process.env, timeout: 10_000 });
      assert.equal(child.error, undefined);
      assert.equal(child.status, 1, child.stderr);
      assert.match(child.stderr, /ENOENT/u);
      requireConvexWasmCacheLockAuthority();
      const contender = new DatabaseSync(environment.CONVEX_WASM_CACHE_LOCK_DB);
      try {
        assert.throws(() => contender.exec("BEGIN IMMEDIATE"), { errcode: 5 });
      } finally {
        contender.close();
      }
    }
  } finally {
    releaseOwner();
  }
});

test("failed binding keeps cache ownership until its other package reads finish", async (t) => {
  const environment = await lockEnvironment(t);
  useLockEnvironment(t, environment);
  const root = dirname(environment.CONVEX_WASM_CACHE_LOCK_DB);
  const cacheRoot = join(root, "cache");
  const layout = deriveConvexWasmCacheLayout({ buildId: "binding-test", cacheRoot, repositoryRoot: root });
  const missingKey = "1".repeat(64);
  const slowKey = "2".repeat(64);
  const missingPackage = join(layout.immutable.packages, missingKey);
  const slowPackage = join(layout.immutable.packages, slowKey);
  await fs.mkdir(slowPackage, { recursive: true, mode: 0o700 });
  const configPath = join(root, "config.json");
  const artifactReportPath = join(root, "report.json");
  const sourcePath = join(root, "source-envelope.json");
  const source = Buffer.from("{}\n");
  await fs.writeFile(configPath, JSON.stringify({
    schemaVersion: 1, projectRoot: root, workRoot: join(root, "work"),
    toolchain: join(root, "toolchain"), gatePolicy: join(root, "policy.json"),
    artifactCacheRoot: cacheRoot, deployedRuntimeAuthority: join(root, "authority.json"),
    selectedExports: ["items:read"], sourcePathspecs: ["functions"],
    jobs: 1, aotWorkers: 1, memoryMaxMiB: 2048,
  }));
  await fs.writeFile(sourcePath, source, { mode: 0o600 });
  await fs.writeFile(artifactReportPath, `${canonicalJson({
    kind: "convex-wasm-project-artifact-report-v1",
    graphs: [
      { graphManifestSha256: missingKey, packagePath: missingPackage },
      { graphManifestSha256: slowKey, packagePath: slowPackage },
    ],
    cohortContracts: [{}, {}], runtimeModules: [{}], contextReusePolicy: {},
    startPush: { path: join(root, "request.json") },
    cohortSchedule: { identity: { sha256: missingKey } }, scheduleSha256: missingKey,
    sourceEnvelope: { path: sourcePath, sha256: createHash("sha256").update(source).digest("hex"), size: source.length },
  })}\n`, { mode: 0o600 });

  const paused = Promise.withResolvers();
  const resume = Promise.withResolvers();
  const failed = Promise.withResolvers();
  const lstat = fs.lstat;
  t.mock.method(fs, "lstat", async (path, ...args) => {
    if (path === slowPackage) {
      paused.resolve();
      await resume.promise;
    }
    if (path === missingPackage) {
      await paused.promise;
      try {
        return await lstat(path, ...args);
      } finally {
        failed.resolve();
      }
    }
    return await lstat(path, ...args);
  });
  const binding = bindConvexWasmProjectBuild({ configPath, artifactReportPath, outputPath: join(root, "bound.json") });
  const rejected = assert.rejects(binding, { code: "ENOENT" });
  let contender;
  try {
    await Promise.race([failed.promise, binding]);
    // Let the failed read propagate while the sibling remains paused in the filesystem.
    await new Promise((resolve) => setImmediate(resolve));
    contender = new DatabaseSync(environment.CONVEX_WASM_CACHE_LOCK_DB);
    assert.throws(() => contender.exec("BEGIN IMMEDIATE"), { errcode: 5 });
  } finally {
    resume.resolve();
    try {
      await rejected;
    } finally {
      contender?.close();
    }
  }
  const releaseNext = await acquireConvexWasmCacheLock({ environment });
  releaseNext();
});

test("legacy environment markers do not bypass an active lock", async (t) => {
  const ownerEnvironment = await lockEnvironment(t);
  const releaseOwner = await acquireConvexWasmCacheLock({ environment: ownerEnvironment });
  t.after(releaseOwner);

  let acquired = false;
  const contender = acquireConvexWasmCacheLock({
    environment: {
      CONVEX_WASM_DISABLE_CACHE_LOCK: "1",
      CONVEX_WASM_CACHE_LOCK_DB: ownerEnvironment.CONVEX_WASM_CACHE_LOCK_DB,
      CONVEX_WASM_CACHE_LOCK_HELD: "1",
    },
  }).then((release) => {
    acquired = true;
    release();
  });

  await delay(350);
  assert.equal(acquired, false);
  releaseOwner();
  await contender;
  assert.equal(acquired, true);
});

test("only a child process can reuse a live owner's lock authority", async (t) => {
  const ownerEnvironment = await lockEnvironment(t);
  const releaseOwner = await acquireConvexWasmCacheLock({ environment: ownerEnvironment });
  const inheritedEnvironment = { ...ownerEnvironment };

  assert.doesNotThrow(() => requireConvexWasmCacheLockAuthority(inheritedEnvironment));
  await assert.rejects(
    acquireConvexWasmCacheLock({ environment: inheritedEnvironment }),
    /already owns the cache lock/u
  );
  const child = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      'import { acquireConvexWasmCacheLock, requireConvexWasmCacheLockAuthority } from "./scripts/lib/convex-wasm-cache-lock.mjs"; const release = await acquireConvexWasmCacheLock(); requireConvexWasmCacheLockAuthority(); release();',
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, ...inheritedEnvironment },
    }
  );
  assert.equal(child.status, 0, child.stderr);

  let competingAcquired = false;
  const contender = acquireConvexWasmCacheLock({
    environment: { CONVEX_WASM_CACHE_LOCK_DB: ownerEnvironment.CONVEX_WASM_CACHE_LOCK_DB },
  }).then((release) => {
    competingAcquired = true;
    release();
  });
  await delay(350);
  assert.equal(competingAcquired, false);

  releaseOwner();
  await contender;
  assert.equal(competingAcquired, true);
  assert.throws(
    () => requireConvexWasmCacheLockAuthority(inheritedEnvironment),
    /holds the cache lock/u
  );
});

test("a boolean marker is not executable authority", async (t) => {
  const environment = await lockEnvironment(t);
  environment.CONVEX_WASM_CACHE_LOCK_HELD = "1";
  assert.throws(() => requireConvexWasmCacheLockAuthority(environment), /holds the cache lock/u);
});

test("a recycled owner PID is not executable authority", async (t) => {
  const environment = await lockEnvironment(t);
  environment.CONVEX_WASM_CACHE_LOCK_AUTHORITY = "r".repeat(43);
  const authorityDatabase = new DatabaseSync(
    `${environment.CONVEX_WASM_CACHE_LOCK_DB}.authority`
  );
  authorityDatabase.exec(`
    CREATE TABLE convex_wasm_cache_lock_authorities (
      authority TEXT PRIMARY KEY,
      owner_pid INTEGER NOT NULL,
      owner_start_identity TEXT NOT NULL
    )
  `);
  authorityDatabase
    .prepare(
      "INSERT INTO convex_wasm_cache_lock_authorities (authority, owner_pid, owner_start_identity) VALUES (?, ?, ?)"
    )
    .run(environment.CONVEX_WASM_CACHE_LOCK_AUTHORITY, process.pid, "different-process");
  authorityDatabase.close();

  assert.throws(() => requireConvexWasmCacheLockAuthority(environment), /holds the cache lock/u);
});

test("a later acquisition removes authority records left by a dead owner", async (t) => {
  const environment = await lockEnvironment(t);
  const exitedOwner = spawnSync(process.execPath, ["--eval", ""]);
  assert.equal(exitedOwner.status, 0, exitedOwner.stderr?.toString());
  assert.throws(() => process.kill(exitedOwner.pid, 0), { code: "ESRCH" });

  const authorityDatabase = new DatabaseSync(
    `${environment.CONVEX_WASM_CACHE_LOCK_DB}.authority`
  );
  authorityDatabase.exec(`
    CREATE TABLE convex_wasm_cache_lock_authorities (
      authority TEXT PRIMARY KEY,
      owner_pid INTEGER NOT NULL,
      owner_start_identity TEXT NOT NULL
    )
  `);
  authorityDatabase
    .prepare(
      "INSERT INTO convex_wasm_cache_lock_authorities (authority, owner_pid, owner_start_identity) VALUES (?, ?, ?)"
    )
    .run("s".repeat(43), exitedOwner.pid, "exited-process");
  authorityDatabase.close();

  const release = await acquireConvexWasmCacheLock({ environment });
  release();

  const settledAuthorityDatabase = new DatabaseSync(
    `${environment.CONVEX_WASM_CACHE_LOCK_DB}.authority`,
    { readOnly: true }
  );
  assert.deepEqual(
    settledAuthorityDatabase.prepare("SELECT * FROM convex_wasm_cache_lock_authorities").all(),
    []
  );
  settledAuthorityDatabase.close();
});

test("revokes legacy PID-only owner records while migrating the persistent database", async (t) => {
  const environment = await lockEnvironment(t);
  const authorityDatabase = new DatabaseSync(
    `${environment.CONVEX_WASM_CACHE_LOCK_DB}.authority`
  );
  authorityDatabase.exec(`
    CREATE TABLE convex_wasm_cache_lock_authorities (
      authority TEXT PRIMARY KEY,
      owner_pid INTEGER NOT NULL
    )
  `);
  authorityDatabase
    .prepare("INSERT INTO convex_wasm_cache_lock_authorities (authority, owner_pid) VALUES (?, ?)")
    .run("m".repeat(43), process.pid);
  authorityDatabase.close();

  const release = await acquireConvexWasmCacheLock({ environment });
  release();

  const settledAuthorityDatabase = new DatabaseSync(
    `${environment.CONVEX_WASM_CACHE_LOCK_DB}.authority`,
    { readOnly: true }
  );
  assert.ok(
    settledAuthorityDatabase
      .prepare("PRAGMA table_info(convex_wasm_cache_lock_authorities)")
      .all()
      .some(({ name }) => name === "owner_start_identity")
  );
  assert.deepEqual(
    settledAuthorityDatabase.prepare("SELECT * FROM convex_wasm_cache_lock_authorities").all(),
    []
  );
  settledAuthorityDatabase.close();
});

test("does not unlock when nested authority revocation fails", async (t) => {
  const environment = await lockEnvironment(t);
  const markerPath = join(environment.CONVEX_WASM_CACHE_LOCK_DB, "..", "contender-acquired");
  const releaseOwner = await acquireConvexWasmCacheLock({ environment });
  t.after(() => releaseOwner());

  const contender = spawn(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      'import { writeFileSync } from "node:fs"; import { acquireConvexWasmCacheLock } from "./scripts/lib/convex-wasm-cache-lock.mjs"; const release = await acquireConvexWasmCacheLock(); writeFileSync(process.env.TEST_MARKER, "acquired"); release();',
    ],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        TEST_MARKER: markerPath,
        CONVEX_WASM_CACHE_LOCK_DB: environment.CONVEX_WASM_CACHE_LOCK_DB,
      },
      stdio: ["ignore", "ignore", "pipe"],
    }
  );
  t.after(() => {
    if (contender.exitCode === null && contender.signalCode === null) {
      contender.kill("SIGKILL");
    }
  });
  await new Promise((resolveWait, rejectWait) => {
    contender.once("error", rejectWait);
    contender.stderr.once("data", (chunk) => {
      try {
        assert.match(chunk.toString("utf8"), /Waiting for another checkout/u);
        resolveWait();
      } catch (error) {
        rejectWait(error);
      }
    });
  });

  const authorityBlocker = new DatabaseSync(`${environment.CONVEX_WASM_CACHE_LOCK_DB}.authority`);
  authorityBlocker.exec("BEGIN IMMEDIATE");
  assert.throws(releaseOwner, /database is locked/u);
  await delay(100);
  await assert.rejects(fs.lstat(markerPath), { code: "ENOENT" });

  authorityBlocker.exec("ROLLBACK");
  authorityBlocker.close();
  releaseOwner();
  const [code, signal] = await once(contender, "exit");
  assert.equal(code, 0);
  assert.equal(signal, null);
  assert.equal(await fs.readFile(markerPath, "utf8"), "acquired");
});
