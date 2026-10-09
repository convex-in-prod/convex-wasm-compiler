import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { renderUrlCorpus } from "../test-fixtures/native-url/corpus.mjs";
import { staticHermesHostArchives } from "./convex-wasm-static-hermes-host-archives.mjs";
import { convexWasmNativeUrlSupportObjectInputs } from "./convex-wasm-native-url-support.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const vendor = join(root, "scripts/vendor/ada-4.0.0");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("native URL sources and corpora match their portable identities", () => {
  const source = JSON.parse(readFileSync(join(vendor, "source.json"), "utf8"));
  for (const [name, identity] of Object.entries(source.files)) {
    const bytes = readFileSync(join(vendor, name));
    assert.equal(bytes.length, identity.size, name);
    assert.equal(hash(bytes), identity.sha256, name);
  }
  assert.equal(hash(readFileSync(join(vendor, source.patch))), source.patchSha256);
});

test("native URL executes Web IDL, WPT and memory contracts in Hermes", async (context) => {
  const source = process.env.CONVEX_HERMES_TEST_SOURCE_ROOT;
  const build = process.env.CONVEX_HERMES_TEST_BUILD_ROOT;
  if (source === undefined || build === undefined) {
    context.skip("set CONVEX_HERMES_TEST_SOURCE_ROOT and CONVEX_HERMES_TEST_BUILD_ROOT");
    return;
  }
  const temporary = mkdtempSync(join(tmpdir(), "convex-native-url-"));
  const run = (command, args) => {
    const result = spawnSync(command, args, {
      encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    });
    assert.equal(result.status, 0, `${result.error ?? ""}\n${result.stdout}\n${result.stderr}`);
    return result.stdout;
  };
  try {
    run(process.execPath, [join(root, "scripts/generate-convex-wasm-runtime-support.mjs")]);
    const corpus = join(temporary, "corpus.js");
    writeFileSync(corpus, renderUrlCorpus());
    const cxx = process.env.CXX ?? "c++";
    const runtimeIncludes = [
      join(build, "lib/config"), join(source, "include"),
      join(source, "API"), join(source, "API/jsi"), join(source, "public"),
    ].map((path) => `-I${path}`);
    const objects = [];
    for (const input of convexWasmNativeUrlSupportObjectInputs(["-O2", "-DNDEBUG"])) {
      const sourcePath = join(temporary, input.fileName);
      const objectPath = `${sourcePath}.o`;
      writeFileSync(sourcePath, input.source);
      run(cxx, [...input.flags, "-Wno-attributes",
        ...(input.includeRuntimeHeaders ? runtimeIncludes : []),
        "-c", sourcePath, "-o", objectPath]);
      objects.push(objectPath);
    }
    const executable = join(temporary, "native-url");
    run(cxx, ["-std=c++20", "-O2", "-DNDEBUG", "-DADA_INCLUDE_URL_PATTERN=0",
    "-Wno-attributes", "-DSTATIC_HERMES", `-I${vendor}`, `-I${join(root, "scripts/lib")}`,
    ...runtimeIncludes, join(root, "scripts/test-fixtures/native-url/main.cpp"), ...objects,
    "-o", executable, "-Wl,--start-group", ...(await staticHermesHostArchives(build)),
    "-Wl,--end-group", "-licui18n", "-licuuc", "-licudata", "-ldl", "-lpthread"]);
    assert.match(run(executable, [
      join(root, "scripts/vendor/convex-wasm-runtime-support/browser-bundle.js.txt"),
      corpus, join(root, "scripts/test-fixtures/native-url/semantics.js"),
    ]), /native URL wrappers, corpus and retained memory passed/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
