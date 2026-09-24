import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  createStaticHermesPrecompileRequest,
  readStaticHermesPrecompileResponse,
} from "./convex-wasm-static-hermes-precompile-protocol.mjs";

const REQUEST_KIND = "convex-wasm-static-hermes-precompile-request-v1";
const RESPONSE_KIND = "convex-wasm-static-hermes-precompile-response-v1";

test("precompile requests bind compiler material and the exact compiler arguments", () => {
  const command = { args: ["--compiler", "/synthetic/compiler", "--", "-O2", "input.js"] };
  const generatedSource = { sha256: "c".repeat(64), size: 37 };
  const materials = {
    staticHermes: {
      entries: [{ label: "static-hermes-executable", sha256: "b".repeat(64), size: 42 }],
      sha256: "a".repeat(64),
    },
  };
  const request = createStaticHermesPrecompileRequest(command, generatedSource, materials);
  assert.equal(request.kind, REQUEST_KIND);
  assert.equal(request.argumentsSha256, fingerprintJson(["-O2", "input.js"]));
  assert.deepEqual(request.compiler, { sha256: "b".repeat(64), size: 42 });
  assert.deepEqual(request.generatedSource, generatedSource);
  assert.match(request.nonce, /^[0-9a-f]{64}$/u);
  assert.notEqual(
    createStaticHermesPrecompileRequest(command, generatedSource, materials).nonce,
    request.nonce
  );
  assert.throws(
    () => createStaticHermesPrecompileRequest({ args: ["-O2"] }, generatedSource, materials),
    /exactly one argument separator/u
  );
  assert.throws(
    () => createStaticHermesPrecompileRequest(
      command,
      generatedSource,
      { staticHermes: { entries: [], sha256: "a".repeat(64) } }
    ),
    /does not contain its compiler executable/u
  );
});

test("precompile responses require a canonical request-bound result", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-precompile-response-"));
  t.after(() => fs.rm(root, { force: true, recursive: true }));
  const path = join(root, "response.json");
  const request = {
    argumentsSha256: "a".repeat(64),
    compiler: { sha256: "b".repeat(64), size: 42 },
    generatedSource: { sha256: "c".repeat(64), size: 37 },
    kind: REQUEST_KIND,
    materialSha256: "d".repeat(64),
    nonce: "e".repeat(64),
    schemaVersion: 1,
  };
  const response = {
    kind: RESPONSE_KIND,
    requestSha256: fingerprintJson(request),
    result: { kind: "success" },
    schemaVersion: 1,
  };
  await fs.writeFile(path, `${canonicalJson(response)}\n`, { mode: 0o600 });
  assert.deepEqual(await readStaticHermesPrecompileResponse(path, request), { kind: "success" });

  const rejection = {
    diagnostics: [{ category: "flow-type-spread-argument-not-array", column: 2, line: 3 }],
    kind: "sourceRejected",
    rawDiagnosticSha256: "f".repeat(64),
  };
  await fs.writeFile(path, `${canonicalJson({ ...response, result: rejection })}\n`);
  assert.deepEqual(await readStaticHermesPrecompileResponse(path, request), rejection);

  await fs.writeFile(path, `${canonicalJson({ ...response, requestSha256: "0".repeat(64) })}\n`);
  await assert.rejects(
    readStaticHermesPrecompileResponse(path, request),
    /does not match its authenticated request/u
  );
  await fs.writeFile(path, `${JSON.stringify(response, null, 2)}\n`);
  await assert.rejects(readStaticHermesPrecompileResponse(path, request), /not canonical JSON/u);
  await fs.writeFile(path, `${canonicalJson({
    ...response,
    result: { ...rejection, diagnostics: [{ ...rejection.diagnostics[0], category: "unknown" }] },
  })}\n`);
  await assert.rejects(readStaticHermesPrecompileResponse(path, request), /category is unsupported/u);
});
