import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildConvexWasmCompileProfile,
  convexWasmCompileProfileTargetAdapterMode,
} from "./convex-wasm-compile-profile.mjs";
import { renderNativeDbGetCapabilityTarget } from "./convex-wasm-lowering.mjs";
import {
  renderConvexWasmRequestEnvelopeMatrix,
  renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector,
} from "./convex-wasm-request-envelope-matrix.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const pinnedShermesSha256 = "9d530001a6d8c39d4efc301061994ccf108bcff05f54bf3845df0bfce4d75533";
const configuredShermesPath = process.env.CONVEX_WASM_SHERMES;

async function authenticatePinnedShermes() {
  const shermesPath = resolve(configuredShermesPath);
  const shermes = await fs.readFile(shermesPath);
  assert.equal(
    createHash("sha256").update(shermes).digest("hex"),
    pinnedShermesSha256,
    "CONVEX_WASM_SHERMES does not match the pinned Static Hermes compiler"
  );
  return shermesPath;
}

test(
  "pinned Static Hermes emits C for current and legacy request-envelope matrices",
  {
    skip:
      configuredShermesPath === undefined
        ? "set CONVEX_WASM_SHERMES to run the focused request-envelope emit-C gate"
        : false,
  },
  async (t) => {
    const shermesPath = await authenticatePinnedShermes();

    const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-request-envelope-shermes-"));
    t.after(() => fs.rm(directory, { force: true, recursive: true }));
    const variants = [
      ["current", renderConvexWasmRequestEnvelopeMatrix()],
      ["legacy-whole-request", renderConvexWasmRequestEnvelopeMatrixLegacyWholeRequestRejector()],
    ];
    for (const [name, rendered] of variants) {
      const sourcePath = join(directory, `${name}.js`);
      const outputPath = join(directory, `${name}.c`);
      await fs.writeFile(sourcePath, rendered.source);
      const result = spawnSync(
        shermesPath,
        [
          "-typed",
          "-O",
          "-Xenable-tdz",
          "-emit-c",
          `-exported-unit=convex_wasm_request_envelope_matrix_${name.replaceAll("-", "_")}`,
          sourcePath,
          "-o",
          outputPath,
        ],
        { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }
      );
      if (result.error !== undefined) {
        throw new Error(`failed to start ${basename(shermesPath)}`, { cause: result.error });
      }
      assert.equal(
        result.status,
        0,
        `${name} request-envelope emit-C failed:\n${result.stderr.trim()}`
      );
      const generated = await fs.stat(outputPath);
      assert.ok(generated.isFile() && generated.size > 0);
    }
  }
);

test(
  "pinned Static Hermes emits C for the complete three-route capability target",
  {
    skip:
      configuredShermesPath === undefined
        ? "set CONVEX_WASM_SHERMES to run the full capability-target emit-C gate"
        : false,
  },
  async (t) => {
    const shermesPath = await authenticatePinnedShermes();
    const fixtureRoot = await fs.mkdtemp(join(repoRoot, ".convex-wasm-shermes-target-"));
    const outputRoot = await fs.mkdtemp(join(tmpdir(), "convex-wasm-shermes-target-output-"));
    t.after(() =>
      Promise.all([
        fs.rm(fixtureRoot, { force: true, recursive: true }),
        fs.rm(outputRoot, { force: true, recursive: true }),
      ])
    );
    const convexDirectory = join(fixtureRoot, "convex");
    await fs.mkdir(convexDirectory);
    await Promise.all([
      fs.writeFile(join(fixtureRoot, "package.json"), '{"private":true,"type":"module"}\n'),
      fs.writeFile(
        join(fixtureRoot, "package-lock.json"),
        '{"lockfileVersion":3,"name":"shermes-target-fixture","packages":{}}\n'
      ),
      fs.writeFile(join(fixtureRoot, "convex.json"), '{"functions":"convex/"}\n'),
      fs.writeFile(
        join(convexDirectory, "tsconfig.json"),
        '{"compilerOptions":{"module":"ESNext","moduleResolution":"Bundler","target":"ESNext"}}\n'
      ),
      fs.writeFile(
        join(convexDirectory, "entry.ts"),
        'import { mutationGeneric as mutation, queryGeneric as query } from "convex/server";\n' +
          "export const first = query({ args: {}, handler: () => 1 });\n" +
          "export const second = query({ args: {}, handler: () => 2 });\n" +
          "export const third = mutation({ args: {}, handler: () => 3 });\n"
      ),
    ]);
    const functions = [
      { exportName: "first", udfKind: "query" },
      { exportName: "second", udfKind: "query" },
      { exportName: "third", udfKind: "mutation" },
    ].map(({ exportName, udfKind }) => ({
      entryPath: "convex/entry.ts",
      exportName,
      modulePath: "entry",
      udfKind,
      visibility: "public",
    }));
    const profile = await buildConvexWasmCompileProfile({
      entryPath: "convex/entry.ts",
      inventory: {
        functions,
        snapshot: {
          apiSha256: "a".repeat(64),
          inputSha256: "b".repeat(64),
          materialSha256: "c".repeat(64),
          outputSha256: "d".repeat(64),
        },
      },
      mode: convexWasmCompileProfileTargetAdapterMode,
      repoRoot: fixtureRoot,
      toolchainRoot: repoRoot,
    });
    assert.deepEqual(
      profile.identity.routes.map(({ exportName }) => exportName),
      ["first", "second", "third"]
    );
    const source = renderNativeDbGetCapabilityTarget({
      argumentFields: [],
      compileProfileJavascript: profile.javascript,
    });
    assert.match(
      source,
      /function __convexDatabaseUdfTimerDeveloperError\(message: string\): number/u
    );
    assert.doesNotMatch(source, /:\s*never\b/u);

    const sourcePath = join(outputRoot, "input.js");
    const outputPath = join(outputRoot, "capability-target.c");
    await fs.writeFile(sourcePath, source);
    const result = spawnSync(
      shermesPath,
      [
        "-typed",
        "-O",
        "-Xenable-tdz",
        "-emit-c",
        "-exported-unit=convex_wasm_capability_three_route",
        sourcePath,
        "-o",
        outputPath,
      ],
      { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 60_000 }
    );
    if (result.error !== undefined) {
      throw new Error(`failed to start ${basename(shermesPath)}`, { cause: result.error });
    }
    assert.equal(
      result.status,
      0,
      `three-route capability target emit-C failed:\n${result.stderr}`
    );
    const generated = await fs.stat(outputPath);
    assert.ok(generated.isFile() && generated.size > 0);
  }
);
