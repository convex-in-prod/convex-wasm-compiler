import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const AUTHORITY_ENVIRONMENT_NAME = "CONVEX_WASM_CACHE_LOCK_AUTHORITY";
const AUTHORITY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
// Keep direct checks and launchers that override TMPDIR on one cross-worktree lock, outside the
// memory-backed system temporary directory used by large test fixtures.
const DEFAULT_LOCK_DATABASE_DIRECTORY = "/var/tmp";
const LINUX_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";
const SUPPORTED_PLATFORMS = new Set(["darwin", "linux"]);

function delay(delayMs) {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

function lockDatabasePath(environment) {
  return (
    environment.CONVEX_WASM_CACHE_LOCK_DB ??
    join(DEFAULT_LOCK_DATABASE_DIRECTORY, `convex-wasm-cache-lock-${process.getuid()}.sqlite`)
  );
}

function authorityDatabasePath(path) {
  return `${path}.authority`;
}

function prepareDatabase(path) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const status = lstatSync(path, { throwIfNoEntry: false });
  if (status !== undefined && (!status.isFile() || status.isSymbolicLink())) {
    throw new Error(`Convex Wasm cache lock database must be a regular file: ${path}`);
  }
  return status;
}

function openDatabase(path, { mustExist = false, queryOnly = false } = {}) {
  const initialStatus = prepareDatabase(path);
  if (mustExist && initialStatus === undefined) {
    return undefined;
  }
  if (initialStatus === undefined) {
    try {
      closeSync(
        openSync(
          path,
          fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_RDWR | fsConstants.O_NOFOLLOW,
          0o600
        )
      );
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) {
        throw error;
      }
    }
  }
  const database = new DatabaseSync(path);
  const status = lstatSync(path);
  if (!status.isFile() || status.isSymbolicLink()) {
    database.close();
    throw new Error(`Convex Wasm cache lock database must be a regular file: ${path}`);
  }
  if (typeof process.getuid === "function" && status.uid !== process.getuid()) {
    database.close();
    throw new Error(`Convex Wasm cache lock database must be owned by the current user: ${path}`);
  }
  chmodSync(path, 0o600);
  database.exec("PRAGMA busy_timeout = 1000");
  if (queryOnly) {
    database.exec("PRAGMA query_only = ON");
  }
  return database;
}

function openLockDatabase(path) {
  return openDatabase(path);
}

function openAuthorityDatabase(path, options = {}) {
  const database = openDatabase(authorityDatabasePath(path), options);
  if (database === undefined || options.queryOnly) {
    return database;
  }
  const authorityTable = database
    .prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'convex_wasm_cache_lock_authorities'"
    )
    .get();
  if (authorityTable === undefined) {
    database.exec(`
      CREATE TABLE convex_wasm_cache_lock_authorities (
        authority TEXT PRIMARY KEY,
        owner_pid INTEGER NOT NULL,
        owner_start_identity TEXT NOT NULL
      )
    `);
  } else {
    const columns = database.prepare("PRAGMA table_info(convex_wasm_cache_lock_authorities)").all();
    if (!columns.some(({ name }) => name === "owner_start_identity")) {
      // PID-only records cannot distinguish a live owner from a recycled PID. Revoke them while
      // migrating the persistent /var/tmp database rather than treating them as authority.
      database.exec(
        "ALTER TABLE convex_wasm_cache_lock_authorities ADD COLUMN owner_start_identity TEXT"
      );
      database.exec("DELETE FROM convex_wasm_cache_lock_authorities");
    }
  }
  if (options.pruneStale !== false) {
    const staleAuthorities = database
      .prepare(
        "SELECT rowid, authority, owner_pid, owner_start_identity FROM convex_wasm_cache_lock_authorities"
      )
      .all()
      .filter(({ authority, owner_pid, owner_start_identity }) => {
        if (
          typeof authority !== "string" ||
          !AUTHORITY_PATTERN.test(authority) ||
          !Number.isSafeInteger(owner_pid) ||
          owner_pid <= 0 ||
          typeof owner_start_identity !== "string" ||
          owner_start_identity.length === 0
        ) {
          return true;
        }
        const owner = processStartIdentity(owner_pid);
        return (
          owner.kind === "missing" ||
          (owner.kind === "identified" && owner.identity !== owner_start_identity)
        );
      });
    const deleteAuthority = database.prepare(
      "DELETE FROM convex_wasm_cache_lock_authorities WHERE rowid = ?"
    );
    for (const { rowid } of staleAuthorities) {
      deleteAuthority.run(rowid);
    }
  }
  return database;
}

function authorityFromEnvironment(environment) {
  const authority = environment[AUTHORITY_ENVIRONMENT_NAME];
  if (authority === undefined) {
    return undefined;
  }
  if (typeof authority !== "string" || !AUTHORITY_PATTERN.test(authority)) {
    throw new Error("Convex Wasm cache lock authority is invalid.");
  }
  return authority;
}

function authorityOwner(database, authority) {
  const row = database
    .prepare(
      "SELECT owner_pid, owner_start_identity FROM convex_wasm_cache_lock_authorities WHERE authority = ? LIMIT 1"
    )
    .get(authority);
  if (
    row === undefined ||
    !Number.isSafeInteger(row.owner_pid) ||
    row.owner_pid <= 0 ||
    typeof row.owner_start_identity !== "string" ||
    row.owner_start_identity.length === 0
  ) {
    return undefined;
  }
  return { pid: row.owner_pid, startIdentity: row.owner_start_identity };
}

function processStartIdentity(pid) {
  if (process.platform === "linux") {
    try {
      const stat = readFileSync(`/proc/${String(pid)}/stat`, "utf8");
      const fields = stat
        .slice(stat.lastIndexOf(") ") + 2)
        .trim()
        .split(/\s+/u);
      const startTime = fields[19];
      if (stat.lastIndexOf(") ") === -1 || !/^[0-9]+$/u.test(startTime)) {
        throw new Error(`Linux process ${String(pid)} has invalid start-time information.`);
      }
      const bootId = readFileSync(LINUX_BOOT_ID_PATH, "utf8").trim();
      if (!/^[0-9a-f-]+$/u.test(bootId)) {
        throw new Error("Linux boot identity is invalid.");
      }
      return { identity: `linux:${bootId}:${startTime}`, kind: "identified" };
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") {
        return { kind: "missing" };
      }
      if (error instanceof Error && "code" in error && error.code === "EACCES") {
        return { kind: "inaccessible" };
      }
      throw error;
    }
  }
  const result = spawnSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
    encoding: "utf8",
    env: { LC_ALL: "C", PATH: "/usr/bin:/bin" },
    maxBuffer: 4096,
    timeout: 2_000,
  });
  if (result.error !== undefined) {
    throw result.error;
  }
  const startTime = result.stdout.trim();
  if (result.status === 1 && startTime.length === 0) {
    return { kind: "missing" };
  }
  if (result.status !== 0 || result.signal !== null || startTime.length === 0) {
    return { kind: "inaccessible" };
  }
  return { identity: `darwin:${startTime}`, kind: "identified" };
}

function liveInheritedAuthorityOwnerPid(environment) {
  const authority = authorityFromEnvironment(environment);
  if (authority === undefined) {
    return undefined;
  }
  const database = openAuthorityDatabase(lockDatabasePath(environment), {
    mustExist: true,
    queryOnly: true,
  });
  if (database === undefined) {
    return undefined;
  }
  try {
    const owner = authorityOwner(database, authority);
    if (owner === undefined) {
      return undefined;
    }
    const observedOwner = processStartIdentity(owner.pid);
    return observedOwner.kind === "identified" && observedOwner.identity === owner.startIdentity
      ? owner.pid
      : undefined;
  } finally {
    database.close();
  }
}

function removeAuthority(path, authority) {
  const database = openAuthorityDatabase(path, { pruneStale: false });
  try {
    database.prepare("DELETE FROM convex_wasm_cache_lock_authorities WHERE authority = ?").run(authority);
  } finally {
    database.close();
  }
}

// This is intentionally an opaque capability rather than a boolean environment marker. A nested
// process can reuse the lock only while the owner record still names the same live process.
export function requireConvexWasmCacheLockAuthority(environment = process.env) {
  if (liveInheritedAuthorityOwnerPid(environment) === undefined) {
    throw new Error("Run this executable through a process that holds the cache lock.");
  }
}

export function inheritedConvexWasmCacheLockAuthorityEnvironment(environment = process.env) {
  const authority = authorityFromEnvironment(environment);
  if (authority === undefined) {
    return {};
  }
  return {
    [AUTHORITY_ENVIRONMENT_NAME]: authority,
    ...(environment.CONVEX_WASM_CACHE_LOCK_DB === undefined
      ? {}
      : { CONVEX_WASM_CACHE_LOCK_DB: environment.CONVEX_WASM_CACHE_LOCK_DB }),
  };
}

export async function acquireConvexWasmCacheLock({ environment = process.env } = {}) {
  if (!SUPPORTED_PLATFORMS.has(process.platform)) {
    throw new Error(`Convex Wasm cache locking does not support ${process.platform}.`);
  }
  const inheritedOwnerPid = liveInheritedAuthorityOwnerPid(environment);
  if (inheritedOwnerPid === process.pid) {
    throw new Error(
      "This process already owns the cache lock; reuse its acquired resource guard."
    );
  }
  if (inheritedOwnerPid !== undefined) {
    return () => {};
  }

  const path = lockDatabasePath(environment);
  const authority = randomBytes(32).toString("base64url");
  const owner = processStartIdentity(process.pid);
  if (owner.kind !== "identified") {
    throw new Error("Convex Wasm cache lock owner identity is unavailable.");
  }
  const authorityDatabase = openAuthorityDatabase(path);
  try {
    authorityDatabase
      .prepare(
        "INSERT INTO convex_wasm_cache_lock_authorities (authority, owner_pid, owner_start_identity) VALUES (?, ?, ?)"
      )
      .run(authority, process.pid, owner.identity);
  } catch (error) {
    authorityDatabase.close();
    throw error;
  }
  authorityDatabase.close();
  let database;
  try {
    database = openLockDatabase(path);
  } catch (error) {
    removeAuthority(path, authority);
    throw error;
  }

  let reportedWait = false;
  try {
    for (;;) {
      try {
        database.exec("BEGIN IMMEDIATE");
        break;
      } catch (error) {
        if (!(error instanceof Error && "errcode" in error && error.errcode === 5)) {
          throw error;
        }
        if (!reportedWait) {
          console.error("Waiting for another checkout's cache maintenance to finish.");
          reportedWait = true;
        }
        await delay(250);
      }
    }
  } catch (error) {
    database.close();
    removeAuthority(path, authority);
    throw error;
  }

  const inheritedAuthority = environment[AUTHORITY_ENVIRONMENT_NAME];
  environment[AUTHORITY_ENVIRONMENT_NAME] = authority;
  let released = false;
  const release = () => {
    if (released) {
      return;
    }
    // Revoke nested authority before unlocking the shared transaction. If revocation fails, keep
    // the main lock held so an inherited child cannot overlap a newly admitted heavy operation.
    removeAuthority(path, authority);
    if (inheritedAuthority === undefined) {
      delete environment[AUTHORITY_ENVIRONMENT_NAME];
    } else {
      environment[AUTHORITY_ENVIRONMENT_NAME] = inheritedAuthority;
    }
    const cleanupErrors = [];
    try {
      database.exec("ROLLBACK");
    } catch (error) {
      cleanupErrors.push(error);
    }
    try {
      database.close();
    } catch (error) {
      cleanupErrors.push(error);
    }
    released = true;
    if (cleanupErrors.length === 1) {
      throw cleanupErrors[0];
    }
    if (cleanupErrors.length > 1) {
      throw new AggregateError(cleanupErrors, "Failed to release the cache lock.");
    }
  };
  process.once("exit", release);

  return () => {
    release();
    process.off("exit", release);
  };
}
