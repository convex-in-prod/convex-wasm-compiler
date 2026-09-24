import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const REQUEST_ADMIN_KEY = "local-request-only-placeholder";
const REQUEST_ORIGIN = "http://127.0.0.1:1";
const REQUEST_MAX_BYTES = 256 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15 * 60 * 1000;

export async function createConvexWasmProjectStartPush({ buildDirectory, projectRoot, signal }) {
  const requireFromProject = createRequire(join(projectRoot, "package.json"));
  const convexPackagePath = requireFromProject.resolve("convex/package.json");
  const cliPath = join(dirname(convexPackagePath), "bin", "main.js");
  const prefix = join(buildDirectory, "current-start-push");
  try {
    await execFile(
      process.execPath,
      [
        cliPath,
        "deploy",
        "--url",
        REQUEST_ORIGIN,
        "--admin-key",
        REQUEST_ADMIN_KEY,
        "--write-push-request",
        prefix,
        "--typecheck",
        "disable",
        "--codegen",
        "disable",
        "--yes",
        "--push-all-modules",
      ],
      { cwd: projectRoot, maxBuffer: 1024 * 1024, signal, timeout: REQUEST_TIMEOUT_MS }
    );
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new Error("installed Convex CLI failed to write the complete source request");
  }
  const path = `${prefix}.json`;
  const status = await fs.lstat(path);
  if (!status.isFile() || status.isSymbolicLink() || status.size <= 0 || status.size > REQUEST_MAX_BYTES) {
    throw new Error("installed Convex CLI wrote an invalid source request file");
  }
  await fs.chmod(path, 0o600);
  const bytes = await fs.readFile(path);
  let request;
  try {
    request = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("installed Convex CLI wrote an invalid source request");
  }
  if (
    request?.adminKey !== REQUEST_ADMIN_KEY ||
    request.dryRun !== false ||
    !Array.isArray(request.appDefinition?.changedModules) ||
    request.appDefinition.changedModules.length === 0 ||
    !Array.isArray(request.nodeDependencies)
  ) {
    throw new Error("installed Convex CLI did not write a complete source request");
  }
  return {
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    size: bytes.length,
  };
}
