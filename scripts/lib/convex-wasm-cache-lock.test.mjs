import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { acquireConvexWasmCacheLock, requireConvexWasmCacheLockAuthority } from "./convex-wasm-cache-lock.mjs";

const TEST_TEMPORARY_DIRECTORY = process.platform === "linux" ? "/var/tmp" : tmpdir();

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function lockEnvironment(t) {
  const directory = await fs.mkdtemp(join(TEST_TEMPORARY_DIRECTORY, "convex-wasm-cache-lock-test-"));
  t.after(() => fs.rm(directory, { force: true, recursive: true }));
  return { CONVEX_WASM_CACHE_LOCK_DB: join(directory, "convex-wasm-cache-lock.sqlite") };
}

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
