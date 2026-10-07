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
import {
  MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES,
  normalizeStaticHermesCBundleOutput,
} from "./convex-wasm-static-hermes-c-bundle.mjs";

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

export function staticHermesRetainedLayoutInvocation(argumentsList) {
  const emission = argumentsList.filter((argument) => argument.startsWith("-Xemit-c-layout"));
  const inputs = argumentsList.filter((argument) => argument.startsWith("-Xc-layout-input"));
  if (emission.length === 0 && inputs.length === 0) return undefined;
  if (emission.length !== 1 || emission[0] !== "-Xemit-c-layout" ||
      !argumentsList.includes("-Xemit-c-bundle") || inputs.length > 1 ||
      (inputs.length === 1 && inputs[0] !== "-Xc-layout-input=retained-layout.json")) {
    fail("retained layout requires bundle emission and one fixed input path");
  }
  const units = argumentsList.filter((argument) => argument.startsWith("-exported-unit="));
  if (units.length > 1) fail("retained layout requires one exported unit name");
  const unitName = units.length === 0 ? "this_unit" : units[0].slice("-exported-unit=".length);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(unitName)) fail("retained layout unit name is invalid");
  return {
    outputPath: `sh_${unitName}_layout.json`,
    ...(inputs.length === 0 ? {} : { inputPath: "retained-layout.json" }),
  };
}

export function createStaticHermesPrecompileRequest(command, generatedSource, materials, retainedLayout) {
  const separator = command.args.indexOf("--");
  if (separator < 0 || command.args.indexOf("--", separator + 1) >= 0) {
    fail("Static Hermes launcher command must contain exactly one argument separator");
  }
  const layout = staticHermesRetainedLayoutInvocation(command.args.slice(separator + 1));
  if ((layout?.inputPath !== undefined) !== (retainedLayout !== undefined)) {
    fail("retained layout input must match its authenticated request");
  }
  if (retainedLayout !== undefined) {
    assertPlainObject(retainedLayout, "retained layout input");
    assertExactKeys(retainedLayout, new Set(["path", "sha256", "size"]), "retained layout input");
    if (retainedLayout.path !== layout.inputPath ||
        requirePositiveU32(retainedLayout.size, "retained layout size") > MAX_STATIC_HERMES_RETAINED_LAYOUT_BYTES) {
      fail("retained layout input path or byte limit is invalid");
    }
    requireSha256(retainedLayout.sha256, "retained layout SHA-256");
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
      ...(retainedLayout === undefined ? {} : { retainedLayout }),
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
    const output = hasOutput
      ? normalizeStaticHermesCBundleOutput(response.result.output, "Static Hermes C bundle output")
      : undefined;
    return {
      kind: "success",
      ...(output === undefined ? {} : { output }),
    };
  }
  return normalizeStaticHermesSourceRejection(response.result, "Static Hermes source rejection");
}
