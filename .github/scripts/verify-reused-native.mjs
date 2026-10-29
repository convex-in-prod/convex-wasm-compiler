#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const [selectionPath, selectionSha256, baselinePath, repository, outputPath, ...extra] = process.argv.slice(2);
assert.ok(selectionPath && baselinePath && outputPath && extra.length === 0,
  "usage: verify-reused-native.mjs SELECTION SHA256 BASELINE_ROOT OWNER/REPO OUTPUT");
assert.match(selectionSha256, /^[0-9a-f]{64}$/u);
assert.match(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u);
// Workflow scripts can be newer than the tested commit. Load its collectors and
// package readers from the source checkout, never from the workflow's directory.
const sourceRoot = process.cwd();
const [
  { collectCompilerSourceIdentity },
  { collectPrecompilerSourceIdentity },
  { loadAndVerifyCompilerPackage, validateCompilerPackageManifest },
  { loadAndVerifyPrecompilerPackage, validatePrecompilerPackageManifest },
  { validateNativeReleaseSelection },
] = await Promise.all([
  "package-convex-wasm-compiler.mjs",
  "package-convex-wasm-precompiler.mjs",
  "lib/convex-wasm-compiler-package.mjs",
  "lib/convex-wasm-precompiler-package.mjs",
  "lib/convex-wasm-native-release-selection.mjs",
].map((path) => import(pathToFileURL(join(sourceRoot, "scripts", path)))));
const baselineRoot = resolve(baselinePath);
const bytes = await fs.readFile(selectionPath);
assert.equal(createHash("sha256").update(bytes).digest("hex"), selectionSha256,
  "selection does not match the published release asset digest");
const selection = validateNativeReleaseSelection(JSON.parse(bytes));

// Reuse preserves the previous release's native source contract. Native manifests
// retain their original build identity; they are never rewritten for a new JS version.
const collectors = [collectCompilerSourceIdentity, collectPrecompilerSourceIdentity];
for (const collect of collectors) {
  const [before, after] = await Promise.all([collect(baselineRoot), collect(sourceRoot)]);
  assert.deepEqual(after.materials.filter(({ path }) => path !== "package-lock.json"),
    before.materials.filter(({ path }) => path !== "package-lock.json"),
    "native source inputs changed; use a native release");
}
const locks = await Promise.all([baselineRoot, sourceRoot].map(async (root) => {
  const lock = JSON.parse(await fs.readFile(join(root, "package-lock.json"), "utf8"));
  const pkg = JSON.parse(await fs.readFile(join(root, "package.json"), "utf8"));
  assert.equal(typeof pkg.version, "string");
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[""].version, pkg.version);
  // A package version bump is required for publication. Dependency and other lock
  // changes still require the native path because the compiler embeds this file.
  delete lock.version;
  delete lock.packages[""].version;
  return lock;
}));
assert.deepEqual(locks[1], locks[0], "dependency lock changed; use a native release");

const scratch = await fs.mkdtemp(join(tmpdir(), "verify-reused-native-"));
const run = promisify(execFile);
async function downloadReleaseAsset(value, path, limit, mode) {
  const url = new URL(value);
  const prefix = `https://github.com/${repository}/releases/download/`;
  assert.ok(url.href.startsWith(prefix) && !url.search && !url.hash,
    "reused native packages must be release assets in this repository");
  await run("curl", ["--fail", "--silent", "--show-error", "--location",
    "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15",
    "--max-time", "120", "--max-filesize", String(limit), "--output", path, url.href],
  { timeout: 125_000, maxBuffer: 64 * 1024 });
  await fs.chmod(path, mode);
}
try {
  for (const [runtime, references] of Object.entries(selection.packages)) {
    for (const [kind, reference] of Object.entries(references)) {
      assert.ok(reference.download, "reused packages require published downloads");
      const directory = join(scratch, runtime, kind, reference.packageId);
      await fs.mkdir(join(directory, "bin"), { recursive: true, mode: 0o700 });
      const binaryName = `convex-wasm-${kind}`;
      const manifestPath = join(directory, "manifest.json");
      await downloadReleaseAsset(reference.download.manifestUrl, manifestPath, 256 * 1024, 0o600);
      const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
      const validate = kind === "compiler" ? validateCompilerPackageManifest : validatePrecompilerPackageManifest;
      validate(manifest);
      assert.equal(manifest.packageId, reference.packageId);
      assert.equal(manifest.platform.targetTriple, reference.targetTriple);
      // Authenticate the small manifest before downloading its binary; its bound
      // applies to the transfer as well as the subsequent package verification.
      await downloadReleaseAsset(reference.download.binaryUrl,
        join(directory, "bin", binaryName), manifest.binary.size, 0o700);
      const load = kind === "compiler" ? loadAndVerifyCompilerPackage : loadAndVerifyPrecompilerPackage;
      // Cross-host verification hashes and inspects binary headers; it never runs
      // a foreign executable or substitutes for the original native smoke tests.
      await load(directory, { runtimePlatform: manifest.platform.os, runtimeArch: manifest.platform.arch });
      process.stdout.write(`Verified ${runtime} ${kind} ${reference.packageId}\n`);
    }
  }
  await fs.writeFile(outputPath, bytes, { flag: "wx", mode: 0o600 });
} finally {
  await fs.rm(scratch, { recursive: true, force: true });
}
