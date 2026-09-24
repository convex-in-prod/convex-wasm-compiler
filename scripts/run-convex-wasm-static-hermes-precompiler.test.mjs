import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const launcher = resolve("scripts/run-convex-wasm-static-hermes-precompiler.mjs");

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function runLauncher(
  t,
  compilerBody,
  {
    compilerArguments = ["-typed", "-emit-c", "-o", "unit.c", "input.js"],
    mutatePaths,
    mutateRequest,
  } = {}
) {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-shermes-launcher-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const compiler = join(root, "shermes");
  const input = Buffer.from("const answer = 40 + 2;\n");
  await Promise.all([
    fs.writeFile(
      compiler,
      `#!/usr/bin/env node\nimport { writeFileSync } from "node:fs";\n${compilerBody}\n`,
      { mode: 0o700 }
    ),
    fs.writeFile(join(root, "input.js"), input),
  ]);
  await mutatePaths?.({ compiler, inputPath: join(root, "input.js"), root });
  const compilerBytes = await fs.readFile(compiler);
  let request = {
    argumentsSha256: sha256(canonicalJson(compilerArguments)),
    compiler: { sha256: sha256(compilerBytes), size: compilerBytes.length },
    generatedSource: { sha256: sha256(input), size: input.length },
    kind: "convex-wasm-static-hermes-precompile-request-v1",
    materialSha256: "1".repeat(64),
    nonce: "2".repeat(64),
    schemaVersion: 1,
  };
  request = mutateRequest?.(request) ?? request;
  await fs.writeFile(join(root, "request.json"), `${canonicalJson(request)}\n`, { mode: 0o600 });
  const child = spawn(
    launcher,
    [
      "--compiler",
      compiler,
      "--max-output-bytes",
      "65536",
      "--request",
      "request.json",
      "--response",
      "response.json",
      "--",
      ...compilerArguments,
    ],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] }
  );
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const result = await new Promise((resolveResult, rejectResult) => {
    child.once("error", rejectResult);
    child.once("close", (code, signal) => resolveResult({ code, signal }));
  });
  let response;
  try {
    response = await fs.readFile(join(root, "response.json"), "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  return {
    ...result,
    response,
    stderr: Buffer.concat(stderr).toString("utf8"),
    stdout: Buffer.concat(stdout).toString("utf8"),
  };
}

function bundleCompilerFixture({
  extraFile,
  functionMembers = [
    {
      contents: "function C",
      firstFunctionId: 0,
      functionCount: 1,
      lastFunctionId: 0,
      oversize: false,
      path: "functions-0000.c",
      role: "function",
      targetBytes: 2_097_152,
    },
  ],
  manifestSource,
  mutateManifest,
  omitPath,
} = {}) {
  const files = new Map([
    ["unit.h", "generated header"],
    ["metadata.c", "metadata C"],
    ...functionMembers.map(({ contents, path }) => [path, contents]),
  ]);
  const members = [
    { path: "unit.h", role: "header" },
    { path: "metadata.c", role: "metadata" },
    ...functionMembers.map(({ contents: _, ...member }) => member),
  ].map((member) => ({
    ...member,
    sha256: sha256(files.get(member.path)),
    size: Buffer.byteLength(files.get(member.path)),
  }));
  let manifest = {
    header: members[0],
    kind: "static-hermes-c-bundle-v1",
    schemaVersion: 1,
    translationUnits: members.slice(1),
  };
  manifest = mutateManifest?.(structuredClone(manifest)) ?? manifest;
  const writes = [...files]
    .filter(([path]) => path !== omitPath)
    .map(
      ([path, contents]) => `writeFileSync(${JSON.stringify(path)}, ${JSON.stringify(contents)});`
    );
  writes.push(
    `writeFileSync("unit.c.json", ${JSON.stringify(manifestSource ?? `${canonicalJson(manifest)}\n`)});`
  );
  if (extraFile !== undefined) {
    writes.push(`writeFileSync(${JSON.stringify(extraFile)}, "extra");`);
  }
  return { body: writes.join("\n"), manifest };
}

function oversizeFunctionMember(overrides = {}) {
  return {
    contents: "x".repeat(2_097_153),
    firstFunctionId: 0,
    functionCount: 1,
    lastFunctionId: 0,
    oversize: true,
    path: "functions-0000.c",
    role: "function",
    targetBytes: 2_097_152,
    ...overrides,
  };
}

test("writes an authenticated success response only after unit.c exists", async (t) => {
  const result = await runLauncher(t, 'writeFileSync("unit.c", "generated C");');
  assert.equal(result.code, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.response).result.kind, "success");
});

test("authenticates a canonical Static Hermes C bundle success response", async (t) => {
  const fixture = bundleCompilerFixture();
  const result = await runLauncher(t, fixture.body, {
    compilerArguments: [
      "-typed",
      "-emit-c",
      "-Xemit-c-bundle",
      "-Xemit-c-shard-size=2097152",
      "-o",
      "unit.c.json",
      "input.js",
    ],
  });
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.response).result.output;
  assert.equal(output.kind, "static-hermes-c-bundle-v1");
  assert.equal(output.schemaVersion, 1);
  assert.deepEqual(output.header, fixture.manifest.header);
  assert.deepEqual(output.translationUnits, fixture.manifest.translationUnits);
  assert.equal(output.manifest.path, "unit.c.json");
  assert.match(output.manifest.sha256, /^[0-9a-f]{64}$/u);
});

test("authenticates cOptimizationLevel=0 only for singleton function translation units", async (t) => {
  const fixture = bundleCompilerFixture({
    functionMembers: [
      {
        cOptimizationLevel: 0,
        contents: "function C",
        firstFunctionId: 0,
        functionCount: 1,
        lastFunctionId: 0,
        oversize: false,
        path: "functions-0000.c",
        role: "function",
        targetBytes: 2_097_152,
      },
    ],
  });
  const result = await runLauncher(t, fixture.body, {
    compilerArguments: [
      "-typed",
      "-emit-c",
      "-Xemit-c-bundle",
      "-Xemit-c-shard-size=2097152",
      "-o",
      "unit.c.json",
      "input.js",
    ],
  });
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.response).result.output.translationUnits[1].cOptimizationLevel, 0);
});

test("authenticates and preserves legal oversize reasons", async (t) => {
  for (const { cOptimizationLevel, oversizeReason } of [
    { cOptimizationLevel: undefined, oversizeReason: "single-instruction" },
    { cOptimizationLevel: 0, oversizeReason: "no-outlineable-run" },
  ]) {
    const fixture = bundleCompilerFixture({
      functionMembers: [
        oversizeFunctionMember({
          ...(cOptimizationLevel === undefined ? {} : { cOptimizationLevel }),
          oversizeReason,
        }),
      ],
    });
    const result = await runLauncher(t, fixture.body, {
      compilerArguments: [
        "-typed",
        "-emit-c",
        "-Xemit-c-bundle",
        "-Xemit-c-shard-size=2097152",
        "-o",
        "unit.c.json",
        "input.js",
      ],
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.deepEqual(
      JSON.parse(result.response).result.output.translationUnits[1],
      fixture.manifest.translationUnits[1]
    );
  }
});

test("canonicalizes the deterministic Static Hermes O0 bundle manifest", async (t) => {
  const functionMembers = [
    {
      cOptimizationLevel: 0,
      contents: "function C",
      firstFunctionId: 0,
      functionCount: 1,
      lastFunctionId: 0,
      oversize: false,
      path: "functions-0000.c",
      role: "function",
      targetBytes: 2_097_152,
    },
  ];
  const canonicalFixture = bundleCompilerFixture({ functionMembers });
  const [metadata, functionMember] = canonicalFixture.manifest.translationUnits;
  const staticHermesManifest = {
    header: canonicalFixture.manifest.header,
    kind: canonicalFixture.manifest.kind,
    schemaVersion: canonicalFixture.manifest.schemaVersion,
    translationUnits: [
      metadata,
      {
        firstFunctionId: functionMember.firstFunctionId,
        functionCount: functionMember.functionCount,
        cOptimizationLevel: functionMember.cOptimizationLevel,
        lastFunctionId: functionMember.lastFunctionId,
        oversize: functionMember.oversize,
        path: functionMember.path,
        role: functionMember.role,
        sha256: functionMember.sha256,
        size: functionMember.size,
        targetBytes: functionMember.targetBytes,
      },
    ],
  };
  const manifestSource = `${JSON.stringify(staticHermesManifest)}\n`;
  const fixture = bundleCompilerFixture({ functionMembers, manifestSource });
  assert.notEqual(manifestSource, `${canonicalJson(fixture.manifest)}\n`);

  const result = await runLauncher(t, fixture.body, {
    compilerArguments: [
      "-typed",
      "-emit-c",
      "-Xemit-c-bundle",
      "-Xemit-c-shard-size=2097152",
      "-o",
      "unit.c.json",
      "input.js",
    ],
  });

  assert.equal(result.code, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.response).result.output;
  assert.equal(output.manifest.sha256, sha256(`${canonicalJson(fixture.manifest)}\n`));
  assert.equal(output.translationUnits[1].cOptimizationLevel, 0);
});

test("authenticates an outlined C bundle with O0 only on the wrapper", async (t) => {
  const fixture = bundleCompilerFixture({
    functionMembers: Array.from({ length: 3 }, (_, index) => ({
      ...(index === 0 ? { cOptimizationLevel: 0 } : {}),
      contents: `outlined function part ${String(index)}`,
      firstFunctionId: 0,
      functionFragmentCount: 3,
      functionFragmentIndex: index,
      functionCount: 1,
      lastFunctionId: 0,
      oversize: false,
      path: `functions-${String(index).padStart(4, "0")}.c`,
      role: "function",
      targetBytes: 2_097_152,
    })),
  });
  const result = await runLauncher(t, fixture.body, {
    compilerArguments: [
      "-typed",
      "-emit-c",
      "-Xemit-c-bundle",
      "-Xemit-c-shard-size=2097152",
      "-o",
      "unit.c.json",
      "input.js",
    ],
  });
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  const output = JSON.parse(result.response).result.output;
  assert.deepEqual(output.translationUnits, fixture.manifest.translationUnits);
  assert.equal(output.translationUnits[1].cOptimizationLevel, 0);
  assert.equal(output.translationUnits[2].cOptimizationLevel, undefined);
});

test("authenticates no-outlineable-run for an oversized outlined wrapper", async (t) => {
  const fixture = bundleCompilerFixture({
    functionMembers: [
      oversizeFunctionMember({
        cOptimizationLevel: 0,
        functionFragmentCount: 2,
        functionFragmentIndex: 0,
        oversizeReason: "no-outlineable-run",
      }),
      {
        contents: "outlined helper",
        firstFunctionId: 0,
        functionFragmentCount: 2,
        functionFragmentIndex: 1,
        functionCount: 1,
        lastFunctionId: 0,
        oversize: false,
        path: "functions-0001.c",
        role: "function",
        targetBytes: 2_097_152,
      },
    ],
  });
  const result = await runLauncher(t, fixture.body, {
    compilerArguments: [
      "-typed",
      "-emit-c",
      "-Xemit-c-bundle",
      "-Xemit-c-shard-size=2097152",
      "-o",
      "unit.c.json",
      "input.js",
    ],
  });

  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(
    JSON.parse(result.response).result.output.translationUnits[1].oversizeReason,
    "no-outlineable-run"
  );
});

test("rejects malformed, incomplete, or unauthenticated C bundles", async (t) => {
  const cases = [
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].path = "../functions.c";
          return manifest;
        },
      }),
      message: /safe relative \.c basename/u,
      name: "traversing path",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].path = manifest.translationUnits[0].path;
          return manifest;
        },
      }),
      message: /duplicate path/u,
      name: "duplicate path",
    },
    {
      fixture: bundleCompilerFixture({ omitPath: "functions-0000.c" }),
      message: /not the expected regular file/u,
      name: "missing member",
    },
    {
      fixture: bundleCompilerFixture({ extraFile: "unexpected.c" }),
      message: /missing or extra C bundle files/u,
      name: "extra member",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].sha256 = "f".repeat(64);
          return manifest;
        },
      }),
      message: /SHA-256 does not match/u,
      name: "wrong digest",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].size += 1;
          return manifest;
        },
      }),
      message: /not the expected regular file/u,
      name: "wrong size",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          [manifest.translationUnits[0], manifest.translationUnits[1]] = [
            manifest.translationUnits[1],
            manifest.translationUnits[0],
          ];
          return manifest;
        },
      }),
      message: /not in metadata, then function order/u,
      name: "wrong role order",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [oversizeFunctionMember()],
      }),
      message: /oversize member must declare an oversizeReason/u,
      name: "oversize member without a reason",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [oversizeFunctionMember({ oversizeReason: "unsupported-reason" })],
      }),
      message: /oversizeReason is unsupported/u,
      name: "oversize member with an unsupported reason",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].oversizeReason = "single-instruction";
          return manifest;
        },
      }),
      message: /non-oversize member must not declare an oversizeReason/u,
      name: "non-oversize member with a reason",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].size = 2_097_153;
          return manifest;
        },
      }),
      message: /oversize marker does not match its size and function count/u,
      name: "oversize member without an oversize marker",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[1].cOptimizationLevel = 1;
          return manifest;
        },
      }),
      message: /cOptimizationLevel must be 0/u,
      name: "unsupported C optimization level",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.header.cOptimizationLevel = 0;
          return manifest;
        },
      }),
      message: /C bundle header has unexpected fields/u,
      name: "C optimization level on header",
    },
    {
      fixture: bundleCompilerFixture({
        mutateManifest: (manifest) => {
          manifest.translationUnits[0].cOptimizationLevel = 0;
          return manifest;
        },
      }),
      message: /translationUnits\[0\] has unexpected fields/u,
      name: "C optimization level on metadata",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            cOptimizationLevel: 0,
            contents: "functions zero through one",
            firstFunctionId: 0,
            functionCount: 2,
            lastFunctionId: 1,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /cOptimizationLevel=0 member must contain exactly one function/u,
      name: "grouped C optimization level zero member",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            cOptimizationLevel: 0,
            contents: "outlined function fragment",
            firstFunctionId: 0,
            functionFragmentCount: 1,
            functionFragmentIndex: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function fragment identity is invalid/u,
      name: "one-member function fragment sequence",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: Array.from({ length: 2 }, (_, index) => ({
          ...(index === 1 ? { cOptimizationLevel: 0 } : {}),
          contents: `outlined function part ${String(index)}`,
          firstFunctionId: 0,
          functionFragmentCount: 2,
          functionFragmentIndex: index,
          functionCount: 1,
          lastFunctionId: 0,
          oversize: false,
          path: `functions-${String(index).padStart(4, "0")}.c`,
          role: "function",
          targetBytes: 2_097_152,
        })),
      }),
      message: /cOptimizationLevel=0 function fragment must be the wrapper at index 0/u,
      name: "C optimization level zero helper fragment",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: Array.from({ length: 2 }, (_, index) => ({
          contents: `outlined function part ${String(index)}`,
          firstFunctionId: 0,
          functionFragmentCount: 2,
          functionFragmentIndex: index,
          functionCount: 1,
          lastFunctionId: 0,
          oversize: false,
          path: `functions-${String(index).padStart(4, "0")}.c`,
          role: "function",
          targetBytes: 2_097_152,
        })),
        mutateManifest: (manifest) => {
          manifest.translationUnits[2].oversize = true;
          manifest.translationUnits[2].oversizeReason = "no-outlineable-run";
          manifest.translationUnits[2].size = 2_097_153;
          return manifest;
        },
      }),
      message: /function fragment oversizeReason must be single-instruction/u,
      name: "no-outlineable-run helper fragment",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            contents: "function one",
            firstFunctionId: 1,
            functionCount: 1,
            lastFunctionId: 1,
            oversize: false,
            path: "functions-0001.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function member ranges must start at zero/u,
      name: "missing initial function range",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            contents: "functions zero through one",
            firstFunctionId: 0,
            functionCount: 2,
            lastFunctionId: 1,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
          {
            contents: "overlapping function one",
            firstFunctionId: 1,
            functionCount: 1,
            lastFunctionId: 1,
            oversize: false,
            path: "functions-0001.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function member ranges are not contiguous and ordered/u,
      name: "non-singleton overlap",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            contents: "legacy first function member",
            firstFunctionId: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
          {
            contents: "legacy repeated function member",
            firstFunctionId: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0001.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function fragment sequence is invalid/u,
      name: "legacy repeated singleton range",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            contents: "first outlined fragment",
            firstFunctionId: 0,
            functionFragmentCount: 3,
            functionFragmentIndex: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
          {
            contents: "out-of-order outlined fragment",
            firstFunctionId: 0,
            functionFragmentCount: 3,
            functionFragmentIndex: 2,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0001.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function fragment sequence is invalid/u,
      name: "out-of-order function fragment",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            contents: "incomplete outlined function",
            firstFunctionId: 0,
            functionFragmentCount: 2,
            functionFragmentIndex: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
          {
            contents: "next function",
            firstFunctionId: 1,
            functionCount: 1,
            lastFunctionId: 1,
            oversize: false,
            path: "functions-0001.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function fragment sequence is incomplete/u,
      name: "incomplete function fragment sequence",
    },
    {
      fixture: bundleCompilerFixture({
        functionMembers: [
          {
            contents: "fragment identity without count",
            firstFunctionId: 0,
            functionFragmentIndex: 0,
            functionCount: 1,
            lastFunctionId: 0,
            oversize: false,
            path: "functions-0000.c",
            role: "function",
            targetBytes: 2_097_152,
          },
        ],
      }),
      message: /function fragment identity must include index and count/u,
      name: "partial function fragment identity",
    },
  ];
  for (const fixtureCase of cases) {
    await t.test(fixtureCase.name, async (subtest) => {
      const result = await runLauncher(subtest, fixtureCase.fixture.body, {
        compilerArguments: [
          "-typed",
          "-emit-c",
          "-Xemit-c-bundle",
          "-Xemit-c-shard-size=2097152",
          "-o",
          "unit.c.json",
          "input.js",
        ],
      });
      assert.equal(result.code, 1);
      assert.equal(result.response, undefined);
      assert.match(result.stderr, fixtureCase.message);
    });
  }
});

test("normalizes the classified Static Hermes binary type rejection", async (t) => {
  const result = await runLauncher(
    t,
    `process.stderr.write(
  "input.js:1:19: error: ft: incompatible binary operation: + cannot be applied to number and string\\n" +
  "const answer = 40 + 2;\\n                  ^\\n" +
  "Emitted 1 errors. exiting.\\n"
);
process.exitCode = 1;`
  );
  assert.equal(result.code, 0);
  const response = JSON.parse(result.response);
  assert.deepEqual(response.result.diagnostics, [
    {
      category: "flow-type-incompatible-binary-operation",
      column: 19,
      line: 1,
    },
  ]);
  assert.equal(response.result.kind, "sourceRejected");
  assert.match(response.result.rawDiagnosticSha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(result.response, /const answer|cannot be applied/u);
});

test("normalizes the classified Static Hermes exact-object spread rejection", async (t) => {
  const result = await runLauncher(
    t,
    `process.stderr.write(
  "input.js:3:5: error: ft: spread argument must be an exact object type\\n" +
  "Emitted 1 errors. exiting.\\n"
);
process.exitCode = 1;`
  );
  assert.equal(result.code, 0);
  const response = JSON.parse(result.response);
  assert.deepEqual(response.result.diagnostics, [
    {
      category: "flow-type-spread-argument-not-exact-object",
      column: 5,
      line: 3,
    },
  ]);
  assert.equal(response.result.kind, "sourceRejected");
  assert.match(response.result.rawDiagnosticSha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(result.response, /spread argument|exact object/u);
});

test("normalizes the classified Static Hermes array-spread rejection", async (t) => {
  const result = await runLauncher(
    t,
    `process.stderr.write(
  "input.js:6:9: error: ft: spread argument must be an array\\n" +
  "Emitted 1 errors. exiting.\\n"
);
process.exitCode = 1;`
  );
  assert.equal(result.code, 0);
  const response = JSON.parse(result.response);
  assert.deepEqual(response.result.diagnostics, [
    {
      category: "flow-type-spread-argument-not-array",
      column: 9,
      line: 6,
    },
  ]);
  assert.equal(response.result.kind, "sourceRejected");
  assert.match(response.result.rawDiagnosticSha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(result.response, /spread argument|must be an array/u);
});

test("normalizes the classified Static Hermes constructor arity rejection", async (t) => {
  const result = await runLauncher(
    t,
    `process.stderr.write(
  "input.js:9:12: error: ft: class Set constructor expects at most 0 arguments, but 1 supplied\\n" +
  "Emitted 1 errors. exiting.\\n"
);
process.exitCode = 1;`
  );
  assert.equal(result.code, 0);
  const response = JSON.parse(result.response);
  assert.deepEqual(response.result.diagnostics, [
    {
      category: "flow-type-constructor-arity-mismatch",
      column: 12,
      line: 9,
    },
  ]);
  assert.equal(response.result.kind, "sourceRejected");
  assert.match(response.result.rawDiagnosticSha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(result.response, /class Set|constructor expects/u);
});

test("normalizes the classified Static Hermes generic-method inference rejection", async (t) => {
  const result = await runLauncher(
    t,
    `process.stderr.write(
  "input.js:11:7: error: ft: could not infer type arguments for generic method\\n" +
  "Emitted 1 errors. exiting.\\n"
);
process.exitCode = 1;`
  );
  assert.equal(result.code, 0);
  const response = JSON.parse(result.response);
  assert.deepEqual(response.result.diagnostics, [
    {
      category: "flow-type-generic-method-inference",
      column: 7,
      line: 11,
    },
  ]);
  assert.equal(response.result.kind, "sourceRejected");
  assert.match(response.result.rawDiagnosticSha256, /^[0-9a-f]{64}$/u);
  assert.doesNotMatch(result.response, /infer type arguments|generic method/u);
});

test("keeps syntax and parser diagnostics fatal", async (t) => {
  const result = await runLauncher(
    t,
    `process.stderr.write(
  "input.js:1:7: error: invalid statement encountered.\\n" +
  "const = ;\\n      ^\\n" +
  "Emitted 1 errors. exiting.\\n"
);
process.exitCode = 1;`
  );
  assert.equal(result.code, 1);
  assert.equal(result.response, undefined);
  assert.match(result.stderr, /invalid statement encountered/u);
});

test("rejects a spoofed compiler identity before execution", async (t) => {
  const result = await runLauncher(t, 'writeFileSync("unit.c", "generated C");', {
    mutateRequest: (request) => ({
      ...request,
      compiler: { ...request.compiler, sha256: "f".repeat(64) },
    }),
  });
  assert.equal(result.code, 1);
  assert.equal(result.response, undefined);
  assert.match(result.stderr, /compiler does not match the authenticated request/u);
});

test("rejects symbolic links for authenticated compiler and source inputs", async (t) => {
  for (const input of ["compiler", "source"]) {
    await t.test(input, async (subtest) => {
      const result = await runLauncher(subtest, 'writeFileSync("unit.c", "generated C");', {
        async mutatePaths({ compiler, inputPath, root }) {
          const path = input === "compiler" ? compiler : inputPath;
          const target = join(root, `${input}-target`);
          await fs.rename(path, target);
          await fs.symlink(target, path);
        },
      });
      assert.equal(result.code, 1);
      assert.equal(result.response, undefined);
      assert.match(
        result.stderr,
        input === "compiler"
          ? /compiler is not the expected regular file/u
          : /generated source is not the expected regular file/u
      );
    });
  }
});

test("rejects a malformed authenticated request envelope", async (t) => {
  const result = await runLauncher(t, 'writeFileSync("unit.c", "generated C");', {
    mutateRequest: (request) => ({ ...request, unexpected: true }),
  });
  assert.equal(result.code, 1);
  assert.equal(result.response, undefined);
  assert.match(result.stderr, /request has unexpected fields/u);
});

test("rejects a generated source replacement after the preflight hash", async (t) => {
  const result = await runLauncher(
    t,
    'writeFileSync("input.js", "const answer = 41 + 2;\\n"); writeFileSync("unit.c", "generated C");'
  );
  assert.equal(result.code, 1);
  assert.equal(result.response, undefined);
  assert.match(result.stderr, /generated source changed during execution/u);
});
