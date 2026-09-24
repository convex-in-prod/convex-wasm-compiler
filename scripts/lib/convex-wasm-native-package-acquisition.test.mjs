import assert from "node:assert/strict";
import { existsSync, promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  acquireNativePackage,
  validateNativePackageReference,
} from "./convex-wasm-native-package-acquisition.mjs";
import { writeFixtureCompilerPackage } from "../test-fixtures/native-package/compiler-package-fixture.mjs";
import { writeFixturePrecompilerPackage } from "../test-fixtures/native-package/precompiler-package-fixture.mjs";

async function fixture(t, kind = "compiler") {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-native-download-test-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const binarySourcePath = await fs.realpath(
    process.platform === "linux" && existsSync("/usr/bin/true") ? "/usr/bin/true" : process.execPath
  );
  const original =
    kind === "compiler"
      ? await writeFixtureCompilerPackage({ root, binarySourcePath })
      : await writeFixturePrecompilerPackage({
          root,
          binaryPath: binarySourcePath,
          identitySeed: "download",
        });
  const reference = {
    packageId: original.manifest.packageId,
    targetTriple: original.manifest.platform.targetTriple,
    download: {
      manifestUrl: "https://packages.example.test/immutable/manifest.json",
      binaryUrl: "https://packages.example.test/immutable/binary",
    },
  };
  const manifestBytes = await fs.readFile(join(original.packageDirectory, "manifest.json"));
  const binaryBytes = await fs.readFile(
    join(original.packageDirectory, original.manifest.binary.path)
  );
  const packageRoot = join(root, "cache");
  const targetRoot = join(packageRoot, reference.targetTriple);
  const argumentsValue = { kind, reference, packageRoot };
  const requests = [];
  const fetchMock = t.mock.method(globalThis, "fetch", async (url, { signal }) => {
    signal.throwIfAborted();
    requests.push(url);
    if (url === reference.download.manifestUrl) return new Response(manifestBytes);
    assert.equal(url, reference.download.binaryUrl);
    return new Response(binaryBytes);
  });
  return {
    argumentsValue,
    binaryBytes,
    fetchMock,
    manifestBytes,
    original,
    reference,
    requests,
    targetRoot,
  };
}

test("native package references require exact identity and HTTPS material", () => {
  const reference = {
    packageId: "a".repeat(64),
    targetTriple:
      process.platform === "darwin"
        ? `${process.arch === "arm64" ? "aarch64" : "x86_64"}-apple-darwin`
        : `${process.arch === "arm64" ? "aarch64" : "x86_64"}-unknown-linux-gnu`,
    download: {
      manifestUrl: "https://packages.example.test/manifest.json",
      binaryUrl: "https://packages.example.test/binary",
    },
  };
  assert.doesNotThrow(() => validateNativePackageReference(reference));
  assert.throws(
    () => validateNativePackageReference({ ...reference, packageId: "not-a-digest" }),
    /SHA-256/u
  );
  assert.throws(
    () =>
      validateNativePackageReference({
        ...reference,
        download: { ...reference.download, binaryUrl: "http://packages.example.test/binary" },
      }),
    /HTTPS/u
  );
  assert.throws(
    () =>
      validateNativePackageReference({
        ...reference,
        download: { ...reference.download, binaryUrl: "https://user@packages.example.test/binary" },
      }),
    /HTTPS/u
  );
});

for (const kind of ["compiler", "precompiler"]) {
  test(`${kind}: concurrent acquisition publishes one verified package and reuses it offline`, async (t) => {
    const f = await fixture(t, kind);
    const [first, sibling] = await Promise.all([
      acquireNativePackage(f.argumentsValue),
      acquireNativePackage(f.argumentsValue),
    ]);
    assert.equal(first.packageDirectory, sibling.packageDirectory);
    assert.deepEqual(first.manifest, f.original.manifest);
    assert.deepEqual(await fs.readdir(f.targetRoot), [f.reference.packageId]);
    assert.deepEqual(await fs.readFile(first.binaryPath), f.binaryBytes);
    f.fetchMock.mock.mockImplementation(() => {
      throw new Error("offline");
    });
    const cached = await acquireNativePackage(f.argumentsValue);
    assert.deepEqual(cached.manifest, first.manifest);
    assert.equal(cached.binaryPath, first.binaryPath);
    // A corrupt existing installation is reported, not hidden by automatic replacement.
    await fs.writeFile(cached.binaryPath, Buffer.alloc(f.binaryBytes.length));
    await assert.rejects(acquireNativePackage(f.argumentsValue), /binary|ELF/u);
  });
}

test("wrong or incomplete downloaded material never publishes a package and can be retried", async (t) => {
  const f = await fixture(t);
  for (const bytes of [
    Buffer.alloc(f.binaryBytes.length),
    f.binaryBytes.subarray(0, f.binaryBytes.length - 1),
    Buffer.concat([f.binaryBytes, Buffer.from("extra")]),
  ]) {
    f.fetchMock.mock.mockImplementation(
      async (url) =>
        new Response(url === f.reference.download.manifestUrl ? f.manifestBytes : bytes)
    );
    await assert.rejects(acquireNativePackage(f.argumentsValue), /binary|ELF|byte limit/u);
    assert.deepEqual(await fs.readdir(f.targetRoot), []);
  }
  f.fetchMock.mock.mockImplementation(
    async (url) =>
      new Response(url === f.reference.download.manifestUrl ? f.manifestBytes : f.binaryBytes)
  );
  await acquireNativePackage(f.argumentsValue);
  assert.deepEqual(await fs.readdir(f.targetRoot), [f.reference.packageId]);
});

test("a different valid manifest is rejected before its executable is downloaded", async (t) => {
  const f = await fixture(t);
  await assert.rejects(
    acquireNativePackage({
      ...f.argumentsValue,
      reference: { ...f.reference, packageId: "0".repeat(64) },
    }),
    /selected identity/u
  );
  assert.deepEqual(f.requests, [f.reference.download.manifestUrl]);
  assert.deepEqual(await fs.readdir(f.targetRoot), []);
});

test("interrupted streamed acquisition cancels the download and removes partial staging", async (t) => {
  const f = await fixture(t);
  const controller = new AbortController();
  let cancelled = false;
  f.fetchMock.mock.mockImplementation(async (url) => {
    if (url === f.reference.download.manifestUrl) return new Response(f.manifestBytes);
    return new Response(
      new ReadableStream({
        start(stream) {
          stream.enqueue(f.binaryBytes.subarray(0, 8));
          setImmediate(() => controller.abort());
        },
        cancel() {
          cancelled = true;
        },
      })
    );
  });
  await assert.rejects(acquireNativePackage({ ...f.argumentsValue, signal: controller.signal }), {
    name: "AbortError",
  });
  assert.equal(cancelled, true);
  assert.deepEqual(await fs.readdir(f.targetRoot), []);
});

test("HTTP and oversized-manifest failures leave the shared cache retryable", async (t) => {
  const f = await fixture(t);
  for (const response of [
    new Response("unavailable", { status: 503 }),
    new Response(Buffer.alloc(256 * 1024 + 1)),
  ]) {
    f.fetchMock.mock.mockImplementation(async () => response);
    await assert.rejects(acquireNativePackage(f.argumentsValue), /HTTP 503|byte limit/u);
    assert.deepEqual(await fs.readdir(f.targetRoot), []);
  }
});

test("cancellation during a cache hit rejects without changing the installed package", async (t) => {
  const f = await fixture(t);
  const installed = await acquireNativePackage(f.argumentsValue);
  const controller = new AbortController();
  const lstat = fs.lstat;
  t.mock.method(fs, "lstat", async (...args) => {
    const entry = await lstat(...args);
    controller.abort();
    return entry;
  });
  await assert.rejects(acquireNativePackage({ ...f.argumentsValue, signal: controller.signal }), {
    name: "AbortError",
  });
  assert.deepEqual(await fs.readFile(installed.binaryPath), f.binaryBytes);
  assert.equal(f.requests.length, 2);
});

test("cancellation during publication cleanup rejects but preserves the complete package", async (t) => {
  const f = await fixture(t);
  const controller = new AbortController();
  const rm = fs.rm;
  const cleanup = t.mock.method(fs, "rm", async (...args) => {
    await rm(...args);
    controller.abort();
  });
  await assert.rejects(acquireNativePackage({ ...f.argumentsValue, signal: controller.signal }), {
    name: "AbortError",
  });
  cleanup.mock.restore();
  assert.deepEqual(await fs.readdir(f.targetRoot), [f.reference.packageId]);
  const cached = await acquireNativePackage(f.argumentsValue);
  assert.deepEqual(await fs.readFile(cached.binaryPath), f.binaryBytes);
  assert.equal(f.requests.length, 2);
});
