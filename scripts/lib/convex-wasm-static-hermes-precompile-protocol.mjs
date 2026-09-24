import { randomBytes } from "node:crypto";

import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  fail,
  fingerprintJson,
  normalizeJson,
  requirePositiveU32,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import { decodeUtf8, readPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import { normalizeStaticHermesCBundleOutput } from "./convex-wasm-static-hermes-c-bundle.mjs";

const REQUEST_KIND = "convex-wasm-static-hermes-precompile-request-v1";
const RESPONSE_KIND = "convex-wasm-static-hermes-precompile-response-v1";
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const SOURCE_REJECTION_CATEGORIES = new Set([
  "flow-type-incompatible-binary-operation",
  "flow-type-constructor-arity-mismatch",
  "flow-type-generic-method-inference",
  "flow-type-spread-argument-not-array",
  "flow-type-spread-argument-not-exact-object",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

export function createStaticHermesPrecompileRequest(command, generatedSource, materials) {
  const separator = command.args.indexOf("--");
  if (separator < 0 || command.args.indexOf("--", separator + 1) >= 0) {
    fail("Static Hermes launcher command must contain exactly one argument separator");
  }
  const compiler = materials.staticHermes.entries.find(
    ({ label }) => label === "static-hermes-executable"
  );
  if (
    compiler === undefined ||
    !Number.isSafeInteger(compiler.size) ||
    compiler.size <= 0 ||
    !SHA256_PATTERN.test(compiler.sha256)
  ) {
    fail("Static Hermes material identity does not contain its compiler executable");
  }
  return normalizeJson(
    {
      argumentsSha256: fingerprintJson(command.args.slice(separator + 1)),
      compiler: { sha256: compiler.sha256, size: compiler.size },
      generatedSource,
      kind: REQUEST_KIND,
      materialSha256: materials.staticHermes.sha256,
      nonce: randomBytes(32).toString("hex"),
      schemaVersion: 1,
    },
    "Static Hermes precompile request"
  );
}

function normalizeStaticHermesSourceRejection(value, description) {
  assertPlainObject(value, description);
  assertExactKeys(value, new Set(["diagnostics", "kind", "rawDiagnosticSha256"]), description);
  if (value.kind !== "sourceRejected") fail(`${description}.kind must be sourceRejected`);
  if (!Array.isArray(value.diagnostics) || value.diagnostics.length === 0) {
    fail(`${description}.diagnostics must be a nonempty array`);
  }
  if (value.diagnostics.length > 256) {
    fail(`${description}.diagnostics must contain at most 256 entries`);
  }
  return {
    diagnostics: value.diagnostics.map((diagnostic, index) => {
      const item = `${description}.diagnostics[${index}]`;
      assertPlainObject(diagnostic, item);
      assertExactKeys(diagnostic, new Set(["category", "column", "line"]), item);
      if (!SOURCE_REJECTION_CATEGORIES.has(diagnostic.category)) {
        fail(`${item}.category is unsupported`);
      }
      return {
        category: diagnostic.category,
        column: requirePositiveU32(diagnostic.column, `${item}.column`),
        line: requirePositiveU32(diagnostic.line, `${item}.line`),
      };
    }),
    kind: "sourceRejected",
    rawDiagnosticSha256: requireSha256(
      value.rawDiagnosticSha256,
      `${description}.rawDiagnosticSha256`
    ),
  };
}

export async function readStaticHermesPrecompileResponse(path, request) {
  const source = decodeUtf8(
    await readPrivateRegularFile(path, MAX_RESPONSE_BYTES, "Static Hermes precompile response"),
    "Static Hermes precompile response"
  );
  let response;
  try {
    response = JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm Static Hermes response is not valid JSON", { cause: error });
  }
  assertPlainObject(response, "Static Hermes precompile response");
  assertExactKeys(
    response,
    new Set(["kind", "requestSha256", "result", "schemaVersion"]),
    "Static Hermes precompile response"
  );
  if (response.kind !== RESPONSE_KIND || response.schemaVersion !== 1) {
    fail("Static Hermes precompile response kind or schema version is unsupported");
  }
  if (response.requestSha256 !== fingerprintJson(request)) {
    fail("Static Hermes precompile response does not match its authenticated request");
  }
  if (`${canonicalJson(response)}\n` !== source) {
    fail("Static Hermes precompile response is not canonical JSON");
  }
  assertPlainObject(response.result, "Static Hermes precompile result");
  requireString(response.result.kind, "Static Hermes precompile result kind");
  if (response.result.kind === "success") {
    const hasOutput = Object.hasOwn(response.result, "output");
    assertExactKeys(
      response.result,
      new Set(hasOutput ? ["kind", "output"] : ["kind"]),
      "Static Hermes success result"
    );
    return {
      kind: "success",
      ...(hasOutput
        ? { output: normalizeStaticHermesCBundleOutput(response.result.output, "Static Hermes C bundle output") }
        : {}),
    };
  }
  return normalizeStaticHermesSourceRejection(response.result, "Static Hermes source rejection");
}
