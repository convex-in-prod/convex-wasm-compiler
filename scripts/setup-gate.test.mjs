import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { gateRevisions } from "./lib/convex-wasm-gate-pins.mjs";
import {
  binaryenHelperNames, binaryenInputSha256, binaryenStatus,
  runnerInputSha256, verifyBinaryenSource,
} from "./setup-gate.mjs";

const execute = promisify(execFile);

test("runner freshness covers shared WASI and vendored compiler sources", async (t) => {
  const crate = await fs.mkdtemp(join(tmpdir(), "wasm-runner-inputs-"));
  t.after(() => fs.rm(crate, { recursive: true, force: true }));
  const files = {
    "Cargo.lock": `[[package]]\nname = "wasmtime"\nsource = "git+https://github.com/bytecodealliance/wasmtime?rev=${gateRevisions.wasmtime}#${gateRevisions.wasmtime}"\n`,
    "Cargo.toml": "[package]\nname = 'runner'\n",
    "rust-toolchain.toml": "[toolchain]\nchannel = 'nightly'\n",
    "src/bin/convex-wasm-wasmtime-runner.rs": "fn main() {}\n",
    "src/lib.rs": "pub fn shared() {}\n",
    "src/wasmtime_wasi.rs": "pub fn imports() {}\n",
    "src/vendor/frontend/Cargo.toml": "[package]\nname = 'frontend'\n",
    "src/vendor/frontend/src/lib.rs": "pub fn compile() {}\n",
  };
  for (const [path, source] of Object.entries(files)) {
    const file = join(crate, path);
    await fs.mkdir(dirname(file), { recursive: true });
    await fs.writeFile(file, source);
  }
  const baseline = await runnerInputSha256(crate);
  for (const path of [
    "src/lib.rs",
    "src/wasmtime_wasi.rs",
    "src/vendor/frontend/Cargo.toml",
    "src/vendor/frontend/src/lib.rs",
  ]) {
    await fs.appendFile(join(crate, path), "// changed\n");
    assert.notEqual(await runnerInputSha256(crate), baseline, path);
    await fs.writeFile(join(crate, path), files[path]);
    assert.equal(await runnerInputSha256(crate), baseline);
  }
  const added = join(crate, "src/vendor/frontend/src/added.rs");
  await fs.writeFile(added, "pub fn added() {}\n");
  assert.notEqual(await runnerInputSha256(crate), baseline);
  await fs.unlink(added);
  await fs.mkdir(join(crate, "target"));
  await fs.writeFile(join(crate, "target/intermediate"), "unrelated build output");
  assert.equal(await runnerInputSha256(crate), baseline);
  await fs.symlink(join(crate, "src/wasmtime_wasi.rs"), added);
  await assert.rejects(runnerInputSha256(crate), /vendor source must be a regular file/u);
});

test("Binaryen recipe authenticates patches and invalidates changed build inputs", async (t) => {
  const vendor = await fs.mkdtemp(join(tmpdir(), "binaryen-recipe-"));
  t.after(() => fs.rm(vendor, { recursive: true, force: true }));
  const patch = "pinned patch\n";
  const recipe = {
    revision: "a".repeat(40), patchedTree: "b".repeat(40),
    patches: [{ file: "example.patch", sha256: createHash("sha256").update(patch).digest("hex") }],
  };
  const recipePath = join(vendor, "source.json");
  await fs.writeFile(recipePath, JSON.stringify(recipe));
  await fs.writeFile(join(vendor, "example.patch"), patch);
  const baseline = await binaryenInputSha256(vendor);
  await fs.writeFile(join(vendor, "example.patch"), "changed patch\n");
  await assert.rejects(binaryenInputSha256(vendor), /patch differs from its pinned digest/u);
  await fs.writeFile(join(vendor, "example.patch"), patch);
  await fs.writeFile(recipePath, JSON.stringify({ ...recipe, patchedTree: "c".repeat(40) }));
  assert.notEqual(await binaryenInputSha256(vendor), baseline);
  await fs.writeFile(recipePath, JSON.stringify({ ...recipe, patches: [...recipe.patches, ...recipe.patches] }));
  await assert.rejects(binaryenInputSha256(vendor), /patch recipe is invalid/u);
  await fs.writeFile(recipePath, JSON.stringify({ ...recipe, patches: [{ ...recipe.patches[0], file: "../example.patch" }] }));
  await assert.rejects(binaryenInputSha256(vendor), /patch recipe is invalid/u);
});

test("Binaryen source verification rejects unstaged, staged and ignored changes", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "binaryen-source-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const git = async (...args) => (await execute("git", ["-C", root, ...args], { timeout: 30_000 })).stdout.trim();
  await git("init", "--quiet");
  await fs.writeFile(join(root, ".gitignore"), "ignored.cpp\n");
  await fs.writeFile(join(root, "source.cpp"), "original\n");
  await git("add", ".");
  await git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture");
  const revision = await git("rev-parse", "HEAD");
  await fs.writeFile(join(root, "source.cpp"), "patched\n");
  await git("add", "source.cpp");
  const expected = { revision, patchedTree: await git("write-tree") };
  await verifyBinaryenSource(root, expected);
  await fs.writeFile(join(root, "source.cpp"), "unrecorded change\n");
  await assert.rejects(verifyBinaryenSource(root, expected), /git exited with status/u);
  await git("add", "source.cpp");
  await assert.rejects(verifyBinaryenSource(root, expected), /differs from the pinned patched source/u);
  await fs.writeFile(join(root, "source.cpp"), "patched\n");
  await git("add", "source.cpp");
  for (const name of ["extra.cpp", "ignored.cpp"]) {
    await fs.writeFile(join(root, name), "unexpected source\n");
    await assert.rejects(verifyBinaryenSource(root, expected), /untracked source files/u);
    await fs.unlink(join(root, name));
  }
  await verifyBinaryenSource(root, expected);
  await assert.rejects(verifyBinaryenSource(root, { ...expected, revision: "0".repeat(40) }), /differs from the pinned patched source/u);
});

test("Binaryen receipts bind optimizer, SDK helpers, recipe and host platform", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "binaryen-tools-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const inputSha256 = "a".repeat(64);
  assert.equal(await binaryenStatus(root, inputSha256), "missing");
  const binaries = {};
  for (const name of ["wasm-opt", ...binaryenHelperNames]) {
    const bytes = Buffer.from(`${name} fixture binary\n`);
    const original = join(root, name === "wasm-opt" ? "build-binaryen" : "emsdk/upstream", "bin", name);
    const installed = join(root, "binaryen-tools/bin", name);
    await fs.mkdir(dirname(original), { recursive: true });
    await fs.mkdir(dirname(installed), { recursive: true });
    await fs.writeFile(original, bytes, { mode: 0o755 });
    await fs.copyFile(original, installed);
    binaries[name] = { sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length };
  }
  const receiptPath = join(root, "binaryen-tools/toolchain.json");
  const receipt = { kind: "convex-wasm-binaryen-toolchain-v1", inputSha256, platform: process.platform, arch: process.arch, binaries };
  await fs.writeFile(receiptPath, JSON.stringify(receipt));
  assert.equal(await binaryenStatus(root, inputSha256), "verified");
  assert.equal(await binaryenStatus(root, "b".repeat(64)), "stale");
  await fs.writeFile(receiptPath, JSON.stringify({ ...receipt, arch: "other" }));
  assert.equal(await binaryenStatus(root, inputSha256), "stale");
  await fs.writeFile(receiptPath, JSON.stringify(receipt));
  for (const path of [
    "binaryen-tools/bin/wasm-opt", "build-binaryen/bin/wasm-opt",
    "emsdk/upstream/bin/wasm-emscripten-finalize", "binaryen-tools/bin/wasm-dis",
  ]) {
    const bytes = await fs.readFile(join(root, path));
    await fs.appendFile(join(root, path), "changed");
    assert.equal(await binaryenStatus(root, inputSha256), "stale", path);
    await fs.writeFile(join(root, path), bytes);
  }
  assert.equal(await binaryenStatus(root, inputSha256), "verified");
  await fs.unlink(join(root, "binaryen-tools/bin/wasm-opt"));
  assert.equal(await binaryenStatus(root, inputSha256), "missing");
  await fs.writeFile(receiptPath, JSON.stringify({ ...receipt, binaries: {} }));
  await assert.rejects(binaryenStatus(root, inputSha256), /receipt is invalid/u);
});
