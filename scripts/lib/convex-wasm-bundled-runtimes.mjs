import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { createReadStream, promises as fs } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";

const nodeVersion = "24.22.1";
const pythonRelease = "20261021";
const pythonVersion = "3.13.17";
const platforms = Object.freeze({
  "linux-x64": {
    node: "eb6728e77c576a35162c122c45ccadf224d89ff00abc8dae46cc2897c6002d7c",
    pythonTarget: "x86_64-unknown-linux-gnu",
    python: "f829adc9d888e76c8801b4799ed444188d35239fcae3a9808a99ec5cb0d8d92c",
  },
  "darwin-arm64": {
    node: "89c682593d76cd44233fa53b1563264e7de9cbb189cad169135c5b4fadfbc0a7",
    pythonTarget: "aarch64-apple-darwin",
    python: "8dc60610a82f1e73be7faf964383e02520f95f6e39592a5c37c3809f5a7b798e",
  },
  "darwin-x64": {
    node: "d132557e7ee2b85af08b0c8c34338e65c6430f2238d01f727728ef42dc83b035",
    pythonTarget: "x86_64-apple-darwin",
    python: "ce9c748c8f7525c0052247edb2435fdb1cac89c77e687e0e199eaf2b827668c2",
  },
});

export async function downloadPinnedArchive(url, sha256, destination, signal) {
  const handle = await fs.open(destination, "wx", 0o600);
  await handle.close();
  await promisify(execFile)("curl", ["--fail", "--location", "--silent", "--show-error",
    "--proto", "=https", "--proto-redir", "=https", "--max-time", "600", "--max-filesize", "1073741824",
    "--output", destination, url], {
    signal: signal === undefined ? AbortSignal.timeout(10 * 60_000)
      : AbortSignal.any([signal, AbortSignal.timeout(10 * 60_000)]),
  });
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(destination)) hash.update(bytes);
  if (hash.digest("hex") !== sha256) throw new Error("Runtime archive differs from its pinned SHA-256");
}

export async function installBundledRuntimes(root, stage, run, signal) {
  const platform = `${process.platform}-${process.arch}`;
  const pins = platforms[platform];
  if (pins === undefined) throw new Error(`No bundled runtime release for ${platform}`);
  const nodeName = `node-v${nodeVersion}-${platform}`;
  const pythonName = `cpython-${pythonVersion}+${pythonRelease}-${pins.pythonTarget}-install_only_stripped.tar.gz`;
  const archives = [
    { name: "node", url: `https://nodejs.org/dist/v${nodeVersion}/${nodeName}.tar.gz`, sha256: pins.node },
    { name: "python", url: `https://github.com/astral-sh/python-build-standalone/releases/download/${pythonRelease}/${encodeURIComponent(pythonName)}`, sha256: pins.python },
  ];
  const installations = await Promise.allSettled(archives.map(async ({ name, url, sha256 }) => {
    const archive = join(stage, `${name}.tar.gz`);
    await downloadPinnedArchive(url, sha256, archive, signal);
    const unpacked = join(stage, name);
    await fs.mkdir(unpacked);
    // Extraction only sees bytes authenticated against the source-controlled pin.
    await run("tar", ["-xzf", archive, "-C", unpacked, "--strip-components=1"]);
    await fs.cp(unpacked, join(root, "runtime", name), { recursive: true, dereference: true });
  }));
  // The caller removes the staging directory on failure. Finish both writers
  // before returning so a failed download cannot race that cleanup.
  for (const result of installations) if (result.status === "rejected") throw result.reason;
  return { node: { version: nodeVersion, sha256: pins.node },
    python: { version: pythonVersion, release: pythonRelease, sha256: pins.python } };
}
