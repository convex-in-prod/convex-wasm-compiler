import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import { hermesSource } from "./convex-wasm-gate-pins.mjs";

const exec = promisify(execFile);

async function git(cwd, args, signal) {
  const result = await exec("git", ["-C", cwd, ...args], {
    signal: signal === undefined
      ? AbortSignal.timeout(30 * 60 * 1_000)
      : AbortSignal.any([signal, AbortSignal.timeout(30 * 60 * 1_000)]),
    maxBuffer: 16 * 1024 * 1024,
  });
  return result.stdout.trim();
}

export async function verifyHermesSource(source, { pin = hermesSource, signal } = {}) {
  const [tree, changed, untracked, topLevel, sourcePath] = await Promise.all([
    git(source, ["rev-parse", "HEAD^{tree}"], signal),
    git(source, ["diff", "--name-only", "HEAD", "--"], signal),
    // Upstream Python utilities write bytecode beside their tracked inputs.
    // Those files are not Hermes C/C++ build inputs; added source still fails.
    git(source, ["ls-files", "--others", "--exclude=**/__pycache__/*.pyc"], signal),
    git(source, ["rev-parse", "--show-toplevel"], signal),
    fs.realpath(source),
  ]);
  if (tree !== pin.tree || changed !== "" || untracked !== "" || topLevel !== sourcePath) {
    throw new Error("Hermes source must be clean and match the pinned patch-history result tree");
  }
  return { tree, revision: await git(source, ["rev-parse", "HEAD"], signal) };
}

export async function installHermesSource(destination, { pin = hermesSource, signal } = {}) {
  try {
    await fs.lstat(destination);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    const stage = await fs.mkdtemp(join(dirname(destination), ".hermes-source-"));
    try {
      const history = join(stage, "history");
      const source = join(stage, "source");
      for (const directory of [history, source]) {
        await fs.mkdir(directory);
        await git(directory, ["init", "--quiet"], signal);
      }
      await git(history, ["fetch", "--depth=1", pin.repository, pin.historyRevision], signal);
      await git(history, ["checkout", "--detach", "FETCH_HEAD"], signal);
      const [upstream, resultTree, series] = await Promise.all(
        ["UPSTREAM", "RESULT_TREE", "SERIES"].map(name => fs.readFile(join(history, name), "utf8"))
      );
      if (upstream.trim() !== pin.upstreamRevision || resultTree.trim() !== pin.tree) {
        throw new Error("Hermes patch-history snapshot differs from the pinned source recipe");
      }
      await git(source, ["fetch", "--depth=1", pin.repository, pin.upstreamRevision], signal);
      await git(source, ["checkout", "--detach", "FETCH_HEAD"], signal);
      const patches = [];
      for (const line of series.trim().split("\n")) {
        if (line.trim() === "" || line.startsWith("#")) continue;
        const match = /^([A-Za-z0-9_.-]+\.patch)\s+([0-9a-f]{40})$/u.exec(line);
        if (match === null || patches.includes(match[1])) {
          throw new Error("Hermes patch-history series has an invalid or duplicate patch");
        }
        patches.push(match[1]);
        await git(source, ["apply", "--index", join(history, "patches", match[1])], signal);
      }
      if (patches.length === 0) throw new Error("Hermes patch-history series is empty");
      if (await git(source, ["write-tree"], signal) !== pin.tree) {
        throw new Error("Reconstructed Hermes source differs from the pinned result tree");
      }
      // This local commit only gives the reconstructed source a clean Git HEAD.
      // Consumers authenticate its tree, never this generated commit's identity.
      const hooks = join(stage, "empty-hooks");
      await fs.mkdir(hooks);
      await git(source, ["-c", "user.name=Hermes source installer", "-c",
        "user.email=source-installer@localhost", "-c", `core.hooksPath=${hooks}`,
        "commit", "--quiet", "--no-gpg-sign", "-m", "Reconstruct pinned Hermes source"], signal);
      await verifyHermesSource(source, { pin, signal });
      await fs.rename(source, destination);
    } finally {
      await fs.rm(stage, { recursive: true, force: true });
    }
  }
  return await verifyHermesSource(destination, { pin, signal });
}
