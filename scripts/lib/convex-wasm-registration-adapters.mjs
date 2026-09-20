import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

const DESCRIPTOR_KIND = "convex-wasm-registration-adapter-descriptor";
const MATERIAL_KIND = "convex-wasm-registration-adapter-material";
const DESCRIPTOR_PATH = "scripts/convex-wasm-registration-adapters.json";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const HOST_SECRET_SELECTOR_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u;

function fail(message) {
  throw new Error(`Convex Wasm registration adapters: ${message}`);
}

function exactKeys(value, keys, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${description} has unsupported fields`);
  }
}

function string(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function identifier(value, description) {
  string(value, description);
  if (!IDENTIFIER_PATTERN.test(value)) fail(`${description} must be a JavaScript identifier`);
  return value;
}

function sha256(value, description) {
  string(value, description);
  if (!SHA256_PATTERN.test(value)) fail(`${description} must be a lowercase SHA-256 digest`);
  return value;
}

function modulePath(value, description) {
  string(value, description);
  if (
    value.startsWith("/") ||
    value.includes("\\") ||
    value.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${description} must be a normalized repository-relative path`);
  }
  return value;
}

function validateExportIdentity(value, description) {
  exactKeys(value, ["exportName", "modulePath", "sourceSha256"], description);
  return {
    exportName: identifier(value.exportName, `${description}.exportName`),
    modulePath: modulePath(value.modulePath, `${description}.modulePath`),
    sourceSha256: sha256(value.sourceSha256, `${description}.sourceSha256`),
  };
}

function validateAdapter(value, index) {
  const description = `adapter ${index}`;
  exactKeys(value, ["authentication", "id", "registrationKind", "wrapper"], description);
  exactKeys(
    value.authentication,
    ["helper", "resultKind", "resultParameters"],
    `${description}.authentication`
  );
  if (!Array.isArray(value.authentication.resultParameters)) {
    fail(`${description}.authentication.resultParameters must be an array`);
  }
  const resultKind = string(
    value.authentication.resultKind,
    `${description}.authentication.resultKind`
  );
  if (resultKind !== "object" && resultKind !== "value") {
    fail(`${description}.authentication.resultKind must be object or value`);
  }
  if (resultKind === "value" && value.authentication.resultParameters.length !== 1) {
    fail(`${description}.authentication value result must bind one whole callback parameter`);
  }
  const seenIndexes = new Set();
  const resultParameters = value.authentication.resultParameters.map(
    (parameter, parameterIndex) => {
      exactKeys(
        parameter,
        ["callbackParameterIndex", "property"],
        `${description}.authentication.resultParameters[${parameterIndex}]`
      );
      if (
        !Number.isSafeInteger(parameter.callbackParameterIndex) ||
        parameter.callbackParameterIndex < 2
      ) {
        fail(`${description}.authentication result callbackParameterIndex must be at least 2`);
      }
      if (seenIndexes.has(parameter.callbackParameterIndex)) {
        fail(`${description}.authentication has duplicate callbackParameterIndex`);
      }
      seenIndexes.add(parameter.callbackParameterIndex);
      const property = parameter.property;
      if (resultKind === "object")
        identifier(property, `${description}.authentication result property`);
      else if (property !== null)
        fail(`${description}.authentication value result property must be null`);
      return { callbackParameterIndex: parameter.callbackParameterIndex, property };
    }
  );
  const sortedIndexes = [...seenIndexes].sort((left, right) => left - right);
  if (
    sortedIndexes.some((callbackParameterIndex, offset) => callbackParameterIndex !== offset + 2)
  ) {
    fail(`${description}.authentication callbackParameterIndex values must be contiguous from 2`);
  }
  const registrationKind = string(value.registrationKind, `${description}.registrationKind`);
  if (registrationKind !== "query" && registrationKind !== "mutation") {
    fail(`${description}.registrationKind must be query or mutation`);
  }
  return {
    authentication: {
      helper: validateExportIdentity(
        value.authentication.helper,
        `${description}.authentication.helper`
      ),
      resultKind,
      resultParameters,
    },
    id: identifier(value.id, `${description}.id`),
    registrationKind,
    wrapper: validateExportIdentity(value.wrapper, `${description}.wrapper`),
  };
}

function validateSourceOperation(value, index) {
  const description = `source operation ${index}`;
  exactKeys(value, ["helper", "id", "semantic"], description);
  exactKeys(
    value.semantic,
    ["kind", "mismatchError", "missingConfigurationError", "selector"],
    `${description}.semantic`
  );
  if (value.semantic.kind !== "hostSecretVerify") {
    fail(`${description}.semantic.kind must be hostSecretVerify`);
  }
  const selector = string(value.semantic.selector, `${description}.semantic.selector`);
  if (!HOST_SECRET_SELECTOR_PATTERN.test(selector)) {
    fail(`${description}.semantic.selector must be an opaque host-secret selector`);
  }
  return {
    helper: validateExportIdentity(value.helper, `${description}.helper`),
    id: identifier(value.id, `${description}.id`),
    semantic: {
      kind: "hostSecretVerify",
      mismatchError: string(value.semantic.mismatchError, `${description}.semantic.mismatchError`),
      missingConfigurationError: string(
        value.semantic.missingConfigurationError,
        `${description}.semantic.missingConfigurationError`
      ),
      selector,
    },
  };
}

export async function loadConvexWasmRegistrationAdapterMaterial(repoRoot) {
  const normalizedRoot = await realpath(resolve(repoRoot));
  const absolutePath = await realpath(join(normalizedRoot, DESCRIPTOR_PATH));
  const relativePath = relative(normalizedRoot, absolutePath).split(sep).join("/");
  if (isAbsolute(relativePath) || relativePath !== DESCRIPTOR_PATH) {
    fail("registration adapter descriptor path is inconsistent");
  }
  const contents = await readFile(absolutePath);
  const parsed = JSON.parse(contents.toString("utf8"));
  exactKeys(parsed, ["adapters", "kind", "sourceOperations"], "descriptor");
  if (parsed.kind !== DESCRIPTOR_KIND) fail(`unsupported descriptor kind ${parsed.kind}`);
  if (!Array.isArray(parsed.adapters)) {
    fail("descriptor.adapters must be an array");
  }
  const adapters = parsed.adapters.map(validateAdapter);
  const adapterIds = new Set();
  for (const adapter of adapters) {
    if (adapterIds.has(adapter.id)) fail("descriptor adapter IDs must be unique");
    adapterIds.add(adapter.id);
  }
  if (!Array.isArray(parsed.sourceOperations)) {
    fail("descriptor.sourceOperations must be an array");
  }
  const sourceOperations = parsed.sourceOperations.map(validateSourceOperation);
  const sourceOperationHelpers = new Set();
  for (const operation of sourceOperations) {
    const helperKey = `${operation.helper.modulePath}\0${operation.helper.exportName}`;
    if (sourceOperationHelpers.has(helperKey)) {
      fail("descriptor source operation helper identities must be unique");
    }
    sourceOperationHelpers.add(helperKey);
  }
  for (let index = 1; index < adapters.length; index += 1) {
    const previous = adapters[index - 1];
    const current = adapters[index];
    const previousKey = `${previous.wrapper.modulePath}\0${previous.wrapper.exportName}`;
    const currentKey = `${current.wrapper.modulePath}\0${current.wrapper.exportName}`;
    if (previousKey >= currentKey)
      fail("descriptor adapters must be sorted by unique wrapper identity");
  }
  for (let index = 1; index < sourceOperations.length; index += 1) {
    if (sourceOperations[index - 1].id >= sourceOperations[index].id) {
      fail("descriptor source operations must be sorted by unique ID");
    }
  }
  return {
    descriptor: { adapters, kind: DESCRIPTOR_KIND, sourceOperations },
    kind: MATERIAL_KIND,
    source: {
      bytes: contents.length,
      path: relativePath,
      sha256: createHash("sha256").update(contents).digest("hex"),
    },
  };
}

export const convexWasmRegistrationAdapterDescriptorPath = DESCRIPTOR_PATH;
