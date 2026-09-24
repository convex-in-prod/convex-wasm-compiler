import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  requirePrivateCacheDirectory,
  requirePrivateCacheFile,
} from "./convex-wasm-private-cache.mjs";
import { resolveConvexWasmApplicationPackageSet } from "./convex-wasm-application-package-set.mjs";
import { createConvexWasmRegistrationSourceAnalyzer } from "./convex-wasm-registration-source-analysis.mjs";
import {
  ConvexWasmTargetRuntimeSurfaceGap,
  convexWasmApplicationGlobalThisBinding,
} from "./convex-wasm-runtime-surface.mjs";
import { convexWasmStaticHermesEsbuildSupportedSyntax } from "./convex-wasm-static-hermes-syntax.mjs";

const PROFILE_KIND = "convex-wasm-esbuild-compile-profile-v2";
const PROFILE_IDENTITY_KIND = "convex-wasm-esbuild-compile-profile-identity-v2";
const LOCAL_PROFILE_KIND = "convex-wasm-local-compile-profile-v1";
const PROFILE_CACHE_KEY_KIND = "convex-wasm-local-compile-profile-cache-key-v1";
const PROFILE_CACHE_METADATA_KIND = "convex-wasm-local-compile-profile-cache-metadata-v1";
const PROFILE_CACHE_FILES = Object.freeze({
  complete: "COMPLETE",
  diagnostics: "diagnostics.json",
  javascript: "profile.js",
  metadata: "metadata.json",
  metafile: "metafile.json",
  sourceMap: "profile.js.map",
});
export const convexWasmCompileProfileInstalledBootstrapMode = "installed-convex-bootstrap";
export const convexWasmCompileProfileTargetAdapterMode = "target-hybrid-sdk-adapter";
const PROFILE_MODES = new Set([
  convexWasmCompileProfileInstalledBootstrapMode,
  convexWasmCompileProfileTargetAdapterMode,
]);
const VIRTUAL_ENTRY_PATH = "<convex-wasm-compile-profile-entry>";
const OUTPUT_PATH = "out/convex-wasm-compile-profile.js";
const TARGET_ADAPTER_NAMESPACE = "convex-wasm-target-adapter";
export const convexWasmCompileProfileRouteMetadataExportName = "__convexWasmRouteMetadata";
const ROUTE_METADATA_EXPORT_NAME = convexWasmCompileProfileRouteMetadataExportName;
export const convexWasmCompileProfileCommitTsPlaceholderExportName =
  "__convexWasmSdkCommitTsPlaceholder";
const SDK_COMMIT_TS_PLACEHOLDER_EXPORT_NAME = convexWasmCompileProfileCommitTsPlaceholderExportName;
const TARGET_ZOD_VERSION = "4.4.3";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const TARGET_ZOD_PACKAGE_MANIFEST_SHA256 =
  "c630bd10b52dcf71c112a2bf78dbf2734b9db58d62de663b8d86c2ec2c8cda2e";
const TARGET_ZOD_UTIL_SOURCE_SHA256 =
  "968e3433e810cf7ba5efb609a1cb6d9a6cfb51215fd1f699938228f7ac25deb3";
const TARGET_ZOD_UTIL_TRANSFORMED_SHA256 =
  "55876c30743828077b7fff78a015f6fdd1d8fa1fdbfba3d83cf6dcacec9f102b";
const TARGET_ZOD_ALLOWS_EVAL_SOURCE = `export const allowsEval = /* @__PURE__*/ cached(() => {
    // Skip the probe under \`jitless\`: strict CSPs report the caught \`new Function\`
    // as a \`securitypolicyviolation\` even though the throw is swallowed.
    if (globalConfig.jitless) {
        return false;
    }
    // @ts-ignore
    if (typeof navigator !== "undefined" && navigator?.userAgent?.includes("Cloudflare")) {
        return false;
    }
    try {
        const F = Function;
        new F("");
        return true;
    }
    catch (_) {
        return false;
    }
});
`;
// Keep the replacement at 19 lines so mappings after this unit still address the installed source.
const TARGET_ZOD_ALLOWS_EVAL_JITLESS_SOURCE = [
  "export const allowsEval = /* @__PURE__*/ cached(() => {",
  "",
  "",
  "",
  "        return false;",
  ...Array(13).fill(""),
  "});",
  "",
].join("\n");
const TARGET_ZOD_LOCK_ENTRY = Object.freeze({
  funding: Object.freeze({ url: "https://github.com/sponsors/colinhacks" }),
  integrity:
    "sha512-ytENFjIJFl2UwYglde2jchW2Hwm4GJFLDiSXWdTrJQBIN9Fcyp7n4DhxJEiWNAJMV1/BqWfW/kkg71UDcHJyTQ==",
  license: "MIT",
  resolved: "https://registry.npmjs.org/zod/-/zod-4.4.3.tgz",
  version: TARGET_ZOD_VERSION,
});
export const convexWasmTargetZodJitlessTransformPolicy = Object.freeze({
  commonJs: Object.freeze({
    path: "v4/core/util.cjs",
    reachable: "reject",
  }),
  kind: "convex-wasm-target-zod-jitless-source-transform-v1",
  lock: Object.freeze({
    packageEntry: TARGET_ZOD_LOCK_ENTRY,
    rootRequirement: "^4.4.3",
  }),
  package: Object.freeze({
    manifestSha256: TARGET_ZOD_PACKAGE_MANIFEST_SHA256,
    name: "zod",
    version: TARGET_ZOD_VERSION,
  }),
  replacement: Object.freeze({
    sha256: "c911907c7ad786c206ad18d7b97fc2dcd1640c9c73608a7fdc1c5151dd032d52",
    size: 98,
  }),
  source: Object.freeze({
    path: "v4/core/util.js",
    segment: Object.freeze({
      sha256: "bc2fdcce2f9cd84c54f62d95823010ffe1f3ffa0a8473e4279080206c2003967",
      size: 544,
    }),
    sha256: TARGET_ZOD_UTIL_SOURCE_SHA256,
    size: 22_018,
  }),
  transformedSource: Object.freeze({
    sha256: TARGET_ZOD_UTIL_TRANSFORMED_SHA256,
    size: 21_572,
  }),
});
const ASYNC_HOOKS_SHIM_SOURCE = `
            export const AsyncLocalStorage = globalThis.AsyncLocalStorage;
            export const AsyncResource = globalThis.AsyncResource;
            export default { AsyncLocalStorage, AsyncResource };
          `;
const TARGET_CREATE_FUNCTION_HANDLE_SUBSTITUTION_UNIT_SOURCE = `async function createFunctionHandle(_functionReference) {
  throw new Error("Convex createFunctionHandle dependency adapter call was not lowered");
}`;
const TARGET_EXPORT_CLASSIFICATION = Object.freeze({
  "convex/server": Object.freeze([
    Object.freeze({
      classification: "custom-registration",
      exportName: "actionGeneric",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "anyApi",
      sourcePath: "node_modules/convex/dist/esm/server/api.js",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "componentsGeneric",
      sourcePath: "node_modules/convex/dist/esm/server/components/index.js",
    }),
    Object.freeze({
      adapterId: "convexCreateFunctionHandleV1",
      authenticatedSourcePath: "node_modules/convex/dist/esm/server/components/index.js",
      classification: "dependency-adapter-substitution",
      exportName: "createFunctionHandle",
      unitSourceSha256: sha256(TARGET_CREATE_FUNCTION_HANDLE_SUBSTITUTION_UNIT_SOURCE),
    }),
    Object.freeze({
      classification: "metadata",
      exportName: "defineSchema",
      sourcePath: "node_modules/convex/dist/esm/server/schema.js",
    }),
    Object.freeze({
      classification: "metadata",
      exportName: "defineTable",
      sourcePath: "node_modules/convex/dist/esm/server/schema.js",
    }),
    Object.freeze({
      classification: "custom-registration",
      exportName: "httpActionGeneric",
    }),
    Object.freeze({
      classification: "custom-registration",
      exportName: "internalActionGeneric",
    }),
    Object.freeze({
      classification: "custom-registration",
      exportName: "internalMutationGeneric",
    }),
    Object.freeze({
      classification: "custom-registration",
      exportName: "internalQueryGeneric",
    }),
    Object.freeze({
      classification: "custom-registration",
      exportName: "mutationGeneric",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "makeFunctionReference",
      sourcePath: "node_modules/convex/dist/esm/server/api.js",
    }),
    Object.freeze({
      classification: "metadata",
      exportName: "paginationOptsValidator",
      sourcePath: "node_modules/convex/dist/esm/server/pagination.js",
    }),
    Object.freeze({
      classification: "custom-registration",
      exportName: "queryGeneric",
    }),
  ]),
  "convex/values": Object.freeze([
    Object.freeze({
      classification: "internal-runtime-link",
      exportName: SDK_COMMIT_TS_PLACEHOLDER_EXPORT_NAME,
      sourceExportName: "commitTsPlaceholder",
      sourcePath: "node_modules/convex/dist/esm/values/value.js",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "CommitTsPlaceholder",
      sourcePath: "node_modules/convex/dist/esm/values/value.js",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "ConvexError",
      sourcePath: "node_modules/convex/dist/esm/values/errors.js",
    }),
    Object.freeze({
      classification: "custom-metadata",
      exportName: "asObjectValidator",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "compareValues",
      sourcePath: "node_modules/convex/dist/esm/values/compare.js",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "convexToJson",
      sourcePath: "node_modules/convex/dist/esm/values/value.js",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "getDocumentSize",
      sourcePath: "node_modules/convex/dist/esm/values/size.js",
    }),
    Object.freeze({
      classification: "runtime-semantics",
      exportName: "jsonToConvex",
      sourcePath: "node_modules/convex/dist/esm/values/value.js",
    }),
    Object.freeze({
      classification: "custom-metadata",
      exportName: "v",
    }),
  ]),
});
const TARGET_DEEP_LEAF_SOURCE_PATHS = new Set(
  Object.values(TARGET_EXPORT_CLASSIFICATION)
    .flat()
    .flatMap(({ sourcePath }) => (sourcePath === undefined ? [] : [sourcePath]))
);
const TARGET_REGISTRATION_EXPORT_NAMES = new Set(
  TARGET_EXPORT_CLASSIFICATION["convex/server"]
    .filter(({ classification }) => classification === "custom-registration")
    .map(({ exportName }) => exportName)
);
const TARGET_REGISTRATION_PRUNING_POLICY = Object.freeze({
  adapterBinding: "resolved-named-export-and-static-local-alias",
  argumentEvaluation: "native-javascript-preserved-by-esbuild-pure-call-liveness",
  applicationModuleInitialization:
    "esbuild-side-effect-only-probe-and-transitive-local-import-closure",
  applicationRoots: "selected-reachable-repository-source-excluding-node_modules",
  candidate: "single-top-level-variable-initialized-by-direct-adapter-binding-call",
  compilerLiveness: "pure-call-annotation",
  definition: "inline-function-or-object-without-accessors-or-prototype-mutation",
  dependencyLiveness: "esbuild-tree-shaking",
  dynamicDefinition: "retain",
  unsupportedModuleInitialization: "retain",
  version: 5,
});

function targetDeepLeafReexports(moduleSpecifier) {
  const exportsBySourcePath = new Map();
  for (const entry of TARGET_EXPORT_CLASSIFICATION[moduleSpecifier]) {
    if (entry.sourcePath === undefined) {
      continue;
    }
    const exports = exportsBySourcePath.get(entry.sourcePath) ?? [];
    exports.push({
      exportName: entry.exportName,
      sourceExportName: entry.sourceExportName ?? entry.exportName,
    });
    exportsBySourcePath.set(entry.sourcePath, exports);
  }
  return [...exportsBySourcePath]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(
      ([sourcePath, exports]) =>
        `export { ${exports
          .sort((left, right) =>
            left.exportName < right.exportName ? -1 : left.exportName > right.exportName ? 1 : 0
          )
          .map(({ exportName, sourceExportName }) =>
            sourceExportName === exportName ? exportName : `${sourceExportName} as ${exportName}`
          )
          .join(", ")} } from ${JSON.stringify(`./${sourcePath}`)};`
    )
    .join("\n");
}

const TARGET_SERVER_ADAPTER_SOURCE = `
import { asObjectValidator, v } from "convex/values";

function directCallAdapter(functionType, handler) {
  return (ctx, args) => {
    globalThis.console.warn(
      "Convex functions should not directly call other Convex functions. Consider calling a helper function instead. e.g. \`export const foo = " +
        functionType +
        "(...); await foo(ctx);\` is not supported. See https://docs.convex.dev/production/best-practices/#use-helper-functions-to-write-shared-code"
    );
    return handler(ctx, args);
  };
}

function strictReplacer(key, value) {
  if (value === undefined) {
    throw new Error(
      'A validator is undefined for field "' + key + '". This is often caused by circular imports. See https://docs.convex.dev/error#undefined-validator for details.'
    );
  }
  return value;
}

function exportArgs(functionDefinition) {
  return () => {
    let args = v.any();
    if (typeof functionDefinition === "object" && functionDefinition.args !== undefined) {
      args = asObjectValidator(functionDefinition.args);
    }
    return JSON.stringify(args.json, strictReplacer);
  };
}

function exportReturns(functionDefinition) {
  return () => {
    let returns;
    if (typeof functionDefinition === "object" && functionDefinition.returns !== undefined) {
      returns = asObjectValidator(functionDefinition.returns);
    }
    return JSON.stringify(returns ? returns.json : null, strictReplacer);
  };
}

function registerFunction(functionDefinition, kind, visibility) {
  const handler =
    typeof functionDefinition === "function" ? functionDefinition : functionDefinition.handler;
  const functionType =
    visibility === "public" ? kind : "internal" + kind.charAt(0).toUpperCase() + kind.slice(1);
  const registered = directCallAdapter(functionType, handler);
  registered[kind === "query" ? "isQuery" : kind === "mutation" ? "isMutation" : "isAction"] = true;
  registered[visibility === "public" ? "isPublic" : "isInternal"] = true;
  registered.exportArgs = exportArgs(functionDefinition);
  registered.exportReturns = exportReturns(functionDefinition);
  registered._handler = handler;
  return registered;
}
export const queryGeneric = (definition) =>
  registerFunction(definition, "query", "public");
export const internalQueryGeneric = (definition) =>
  registerFunction(definition, "query", "internal");
export const mutationGeneric = (definition) =>
  registerFunction(definition, "mutation", "public");
export const internalMutationGeneric = (definition) =>
  registerFunction(definition, "mutation", "internal");
export const actionGeneric = (definition) =>
  registerFunction(definition, "action", "public");
export const internalActionGeneric = (definition) =>
  registerFunction(definition, "action", "internal");
export const httpActionGeneric = (handler) => {
  const registered = directCallAdapter("httpAction", handler);
  registered.isHttp = true;
  registered._handler = handler;
  return registered;
};
export ${TARGET_CREATE_FUNCTION_HANDLE_SUBSTITUTION_UNIT_SOURCE}
${targetDeepLeafReexports("convex/server")}
`;
const TARGET_VALUES_ADAPTER_SOURCE = `
const UNDEFINED_VALIDATOR_ERROR_URL = "https://docs.convex.dev/error#undefined-validator";
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const MIN_INT64 = -9223372036854775808n;
const MAX_INT64 = 9223372036854775807n;
const UINT64_MODULUS = 18446744073709551616n;

function throwUndefinedValidatorError(context, fieldName) {
  const fieldInfo = fieldName !== undefined ? ' for field "' + fieldName + '"' : "";
  throw new Error(
    "A validator is undefined" + fieldInfo + " in " + context + ". " +
      "This is often caused by circular imports. " +
      "See " + UNDEFINED_VALIDATOR_ERROR_URL + " for details."
  );
}

function bytesToBase64(bytes) {
  const first = bytes[0];
  const second = bytes[1];
  const third = bytes[2];
  const fourth = bytes[3];
  const fifth = bytes[4];
  const sixth = bytes[5];
  const seventh = bytes[6];
  const eighth = bytes[7];
  return (
    BASE64_ALPHABET[first >> 2] +
    BASE64_ALPHABET[((first & 3) << 4) | (second >> 4)] +
    BASE64_ALPHABET[((second & 15) << 2) | (third >> 6)] +
    BASE64_ALPHABET[third & 63] +
    BASE64_ALPHABET[fourth >> 2] +
    BASE64_ALPHABET[((fourth & 3) << 4) | (fifth >> 4)] +
    BASE64_ALPHABET[((fifth & 15) << 2) | (sixth >> 6)] +
    BASE64_ALPHABET[sixth & 63] +
    BASE64_ALPHABET[seventh >> 2] +
    BASE64_ALPHABET[((seventh & 3) << 4) | (eighth >> 4)] +
    BASE64_ALPHABET[(eighth & 15) << 2] +
    "="
  );
}

function bigintToJson(value) {
  if (value < MIN_INT64 || MAX_INT64 < value) {
    throw new Error("BigInt " + value + " does not fit into a 64-bit signed integer.");
  }
  let encoded = value < 0n ? value + UINT64_MODULUS : value;
  const bytes = new Uint8Array(8);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number(encoded & 255n);
    encoded >>= 8n;
  }
  return { $integer: bytesToBase64(bytes) };
}

function numberToJson(value) {
  if (!Number.isNaN(value) && Number.isFinite(value) && !Object.is(value, -0)) {
    return value;
  }
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setFloat64(0, value, true);
  return { $float: bytesToBase64(new Uint8Array(buffer)) };
}

function literalToJson(value) {
  if (typeof value === "bigint") {
    return bigintToJson(value);
  }
  if (typeof value === "number") {
    return numberToJson(value);
  }
  return value;
}

function validatorPrototype(json, asOptional, methods) {
  const prototype = {};
  Object.defineProperty(prototype, "json", {
    configurable: true,
    enumerable: false,
    get: json,
  });
  Object.defineProperty(prototype, "asOptional", {
    configurable: true,
    enumerable: false,
    value: asOptional,
    writable: true,
  });
  for (const entry of Object.entries(methods || {})) {
    Object.defineProperty(prototype, entry[0], {
      configurable: true,
      enumerable: false,
      value: entry[1],
      writable: true,
    });
  }
  return prototype;
}

function baseValidator(prototype, isOptional) {
  const validator = Object.create(prototype);
  validator.type = undefined;
  validator.fieldPaths = undefined;
  validator.isOptional = isOptional;
  validator.isConvexValidator = true;
  return validator;
}

const NULL_PROTOTYPE = validatorPrototype(
    function json() {
      return { type: this.kind };
    },
    () => makePrimitive("null", "optional")
  );
const FLOAT64_PROTOTYPE = validatorPrototype(
    () => ({ type: "number" }),
    () => makePrimitive("float64", "optional")
  );
const INT64_PROTOTYPE = validatorPrototype(
    () => ({ type: "bigint" }),
    () => makePrimitive("int64", "optional")
  );
const COMMIT_TS_PROTOTYPE = validatorPrototype(
    function json() {
      return { type: this.kind };
    },
    () => makePrimitive("commitTs", "optional")
  );
const BOOLEAN_PROTOTYPE = validatorPrototype(
    function json() {
      return { type: this.kind };
    },
    () => makePrimitive("boolean", "optional")
  );
const STRING_PROTOTYPE = validatorPrototype(
    function json() {
      return { type: this.kind };
    },
    () => makePrimitive("string", "optional")
  );
const BYTES_PROTOTYPE = validatorPrototype(
    function json() {
      return { type: this.kind };
    },
    () => makePrimitive("bytes", "optional")
  );
const ANY_PROTOTYPE = validatorPrototype(
    function json() {
      return { type: this.kind };
    },
    () => makePrimitive("any", "optional")
  );

const ID_PROTOTYPE = validatorPrototype(
  function json() {
    return { type: "id", tableName: this.tableName };
  },
  function asOptional() {
    return makeId(this.tableName, "optional");
  }
);

const LITERAL_PROTOTYPE = validatorPrototype(
  function json() {
    return { type: this.kind, value: literalToJson(this.value) };
  },
  function asOptional() {
    return makeLiteral(this.value, "optional");
  }
);

const ARRAY_PROTOTYPE = validatorPrototype(
  function json() {
    return { type: this.kind, value: this.element.json };
  },
  function asOptional() {
    return makeArray(this.element, "optional");
  }
);

const OBJECT_PROTOTYPE = validatorPrototype(
  function json() {
    return {
      type: this.kind,
      value: Object.fromEntries(
        Object.entries(this.fields).map((entry) => [
          entry[0],
          {
            fieldType: entry[1].json,
            optional: entry[1].isOptional === "optional" ? true : false,
          },
        ])
      ),
    };
  },
  function asOptional() {
    return makeObject(this.fields, "optional");
  },
  {
    omit(...fieldNames) {
      const newFields = Object.assign({}, this.fields);
      for (const fieldName of fieldNames) {
        delete newFields[fieldName];
      }
      return makeObject(newFields, this.isOptional);
    },
    pick(...fieldNames) {
      const newFields = {};
      for (const fieldName of fieldNames) {
        newFields[fieldName] = this.fields[fieldName];
      }
      return makeObject(newFields, this.isOptional);
    },
    partial() {
      const newFields = {};
      for (const entry of Object.entries(this.fields)) {
        newFields[entry[0]] = entry[1].asOptional();
      }
      return makeObject(newFields, this.isOptional);
    },
    extend(fields) {
      return makeObject(Object.assign({}, this.fields, fields), this.isOptional);
    },
  }
);

const RECORD_PROTOTYPE = validatorPrototype(
  function json() {
    return {
      type: this.kind,
      keys: this.key.json,
      values: { fieldType: this.value.json, optional: false },
    };
  },
  function asOptional() {
    return makeRecord(this.key, this.value, "optional");
  }
);

const UNION_PROTOTYPE = validatorPrototype(
  function json() {
    return { type: this.kind, value: this.members.map((member) => member.json) };
  },
  function asOptional() {
    return makeUnion(this.members, "optional");
  }
);

function makePrimitive(kind, isOptional) {
  let prototype;
  if (kind === "null") {
    prototype = NULL_PROTOTYPE;
  } else if (kind === "float64") {
    prototype = FLOAT64_PROTOTYPE;
  } else if (kind === "int64") {
    prototype = INT64_PROTOTYPE;
  } else if (kind === "commitTs") {
    prototype = COMMIT_TS_PROTOTYPE;
  } else if (kind === "boolean") {
    prototype = BOOLEAN_PROTOTYPE;
  } else if (kind === "string") {
    prototype = STRING_PROTOTYPE;
  } else if (kind === "bytes") {
    prototype = BYTES_PROTOTYPE;
  } else if (kind === "any") {
    prototype = ANY_PROTOTYPE;
  } else {
    throw new Error("Unsupported validator kind " + kind);
  }
  const validator = baseValidator(prototype, isOptional);
  validator.kind = kind;
  return validator;
}

function makeId(tableName, isOptional) {
  const validator = baseValidator(ID_PROTOTYPE, isOptional);
  validator.tableName = undefined;
  validator.kind = "id";
  if (typeof tableName !== "string") {
    throw new Error("v.id(tableName) requires a string");
  }
  validator.tableName = tableName;
  return validator;
}

function makeLiteral(value, isOptional) {
  const validator = baseValidator(LITERAL_PROTOTYPE, isOptional);
  validator.value = undefined;
  validator.kind = "literal";
  if (
    typeof value !== "string" &&
    typeof value !== "boolean" &&
    typeof value !== "number" &&
    typeof value !== "bigint"
  ) {
    throw new Error("v.literal(value) must be a string, number, or boolean");
  }
  validator.value = value;
  return validator;
}

function makeArray(element, isOptional) {
  const validator = baseValidator(ARRAY_PROTOTYPE, isOptional);
  validator.element = undefined;
  validator.kind = "array";
  if (element === undefined) {
    throwUndefinedValidatorError("v.array()");
  }
  validator.element = element;
  return validator;
}

function validateObjectFields(fields) {
  for (const entry of Object.entries(fields)) {
    const fieldName = entry[0];
    const validator = entry[1];
    if (validator === undefined) {
      throwUndefinedValidatorError("v.object()", fieldName);
    }
    if (!validator.isConvexValidator) {
      throw new Error("v.object() entries must be validators");
    }
  }
}

function makeObject(fields, isOptional) {
  const validator = baseValidator(OBJECT_PROTOTYPE, isOptional);
  validator.fields = undefined;
  validator.kind = "object";
  validateObjectFields(fields);
  validator.fields = fields;
  return validator;
}

function makeRecord(key, value, isOptional) {
  const validator = baseValidator(RECORD_PROTOTYPE, isOptional);
  validator.key = undefined;
  validator.value = undefined;
  validator.kind = "record";
  if (key === undefined) {
    throwUndefinedValidatorError("v.record()", "key");
  }
  if (value === undefined) {
    throwUndefinedValidatorError("v.record()", "value");
  }
  if (key.isOptional === "optional") {
    throw new Error("Record validator cannot have optional keys");
  }
  if (value.isOptional === "optional") {
    throw new Error("Record validator cannot have optional values");
  }
  if (!key.isConvexValidator || !value.isConvexValidator) {
    throw new Error("Key and value of v.record() but be validators");
  }
  validator.key = key;
  validator.value = value;
  return validator;
}

function makeUnion(members, isOptional) {
  const validator = baseValidator(UNION_PROTOTYPE, isOptional);
  validator.members = undefined;
  validator.kind = "union";
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    if (member === undefined) {
      throwUndefinedValidatorError("v.union()", "member at index " + String(index));
    }
    if (!member.isConvexValidator) {
      throw new Error("All members of v.union() must be validators");
    }
  }
  validator.members = members;
  return validator;
}

export const v = {
  id(tableName) {
    return makeId(tableName, "required");
  },
  null() {
    return makePrimitive("null", "required");
  },
  number() {
    return makePrimitive("float64", "required");
  },
  float64() {
    return makePrimitive("float64", "required");
  },
  bigint() {
    return makePrimitive("int64", "required");
  },
  int64() {
    return makePrimitive("int64", "required");
  },
  commitTs() {
    return makePrimitive("commitTs", "required");
  },
  boolean() {
    return makePrimitive("boolean", "required");
  },
  string() {
    return makePrimitive("string", "required");
  },
  bytes() {
    return makePrimitive("bytes", "required");
  },
  literal(value) {
    return makeLiteral(value, "required");
  },
  array(element) {
    return makeArray(element, "required");
  },
  object(fields) {
    return makeObject(fields, "required");
  },
  record(keys, values) {
    return makeRecord(keys, values, "required");
  },
  union(...members) {
    return makeUnion(members, "required");
  },
  any() {
    return makePrimitive("any", "required");
  },
  optional(value) {
    return value.asOptional();
  },
  nullable(value) {
    return makeUnion([value, makePrimitive("null", "required")], "required");
  },
};

function isValidator(value) {
  return value?.isConvexValidator === true;
}

export function asObjectValidator(value) {
  return isValidator(value) ? value : v.object(value);
}

${targetDeepLeafReexports("convex/values")}
`;
const TARGET_ADAPTER_SOURCES = Object.freeze({
  "convex/server": TARGET_SERVER_ADAPTER_SOURCE,
  "convex/values": TARGET_VALUES_ADAPTER_SOURCE,
});
const CONVEX_BUNDLER_MATERIALS = Object.freeze([
  "cli/lib/components.js",
  "cli/lib/config.js",
  "debugBundle.js",
  "external.js",
  "fs.js",
  "index.js",
  "serverOnly.js",
  "wasm.js",
]);
export const convexWasmCompileProfileOutputGlobalName = "__convexWasmCompileProfile";

const BUILD_OPTIONS = Object.freeze({
  bundle: true,
  conditions: Object.freeze(["convex", "module"]),
  define: Object.freeze({ "process.env.NODE_ENV": '"production"' }),
  format: "iife",
  globalName: convexWasmCompileProfileOutputGlobalName,
  jsx: "automatic",
  keepNames: true,
  metafile: true,
  minifyIdentifiers: true,
  minifySyntax: false,
  minifyWhitespace: false,
  outfile: OUTPUT_PATH,
  platform: "browser",
  sourcemap: true,
  sourcesContent: false,
  splitting: false,
  supported: convexWasmStaticHermesEsbuildSupportedSyntax,
  target: "esnext",
  treeShaking: true,
  write: false,
});
const TARGET_BUILD_OPTIONS = Object.freeze({
  ...BUILD_OPTIONS,
  define: Object.freeze({
    ...BUILD_OPTIONS.define,
    globalThis: convexWasmApplicationGlobalThisBinding,
  }),
});
const TARGET_APPLICATION_GLOBAL_BINDING_POLICY = Object.freeze({
  binding: convexWasmApplicationGlobalThisBinding,
  scope: "selected-reachable-source-graph",
  valueBindings: "reject",
});

function compileProfileBuildOptions(mode) {
  return mode === convexWasmCompileProfileTargetAdapterMode ? TARGET_BUILD_OPTIONS : BUILD_OPTIONS;
}

function classifyCompileProfileInputPath(path, mode) {
  requireString(path, "compile profile input path");
  if (path === VIRTUAL_ENTRY_PATH) return { kind: "virtual-entry" };
  if (path.startsWith("async-hooks-shim:")) return { kind: "async-hooks-shim" };
  const targetAdapterPrefix = `${TARGET_ADAPTER_NAMESPACE}:`;
  if (path.startsWith(targetAdapterPrefix)) {
    if (mode !== convexWasmCompileProfileTargetAdapterMode) {
      fail(`compile profile input ${path} is forbidden in mode ${mode}`);
    }
    const modulePath = path.slice(targetAdapterPrefix.length);
    const source = TARGET_ADAPTER_SOURCES[modulePath];
    if (source === undefined) {
      fail(`compile profile input ${path} is not a supported target adapter module`);
    }
    return { kind: "target-adapter", source };
  }
  if (path.includes(":")) {
    fail(`compile profile input ${path} has unknown virtual provenance`);
  }
  if (
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#") ||
    posix.isAbsolute(path) ||
    posix.normalize(path) !== path ||
    path === "." ||
    path.endsWith("/") ||
    path.split("/").every((segment) => segment === "..")
  ) {
    fail(`compile profile real input path is not canonical POSIX syntax: ${path}`);
  }
  const targetZodSourcePath = "node_modules/zod/v4/core/util.js";
  const targetZodCommonJsSourcePath = "node_modules/zod/v4/core/util.cjs";
  const targetZodSource = path === targetZodSourcePath || path.endsWith(`/${targetZodSourcePath}`);
  const targetZodCommonJsSource =
    path === targetZodCommonJsSourcePath || path.endsWith(`/${targetZodCommonJsSourcePath}`);
  return {
    kind: "real",
    targetZod: targetZodSource ? "esm" : targetZodCommonJsSource ? "commonjs" : undefined,
  };
}

function fail(message) {
  throw new Error(`Convex Wasm compile profile: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function toPosix(path) {
  return path.split(sep).join("/");
}

function requireObject(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireProfileMode(value) {
  if (!PROFILE_MODES.has(value)) {
    fail(`mode must be one of ${[...PROFILE_MODES].join(", ")}`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  const actualKeys = Object.keys(requireObject(value, description)).sort(compareStrings);
  const expectedKeys = [...expected].sort(compareStrings);
  if (canonicalJson(actualKeys) !== canonicalJson(expectedKeys)) {
    fail(`${description} has unexpected fields`);
  }
  return value;
}

function materialBuffer(value, description) {
  if (typeof value === "string") return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  fail(`${description} must be text or bytes`);
}

function parseJsonMaterial(contents, description) {
  try {
    return requireObject(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents)),
      description
    );
  } catch (error) {
    if (error instanceof TypeError || error instanceof SyntaxError) {
      fail(`${description} must be valid UTF-8 JSON`);
    }
    throw error;
  }
}

function exactSubstringCount(source, substring) {
  let count = 0;
  for (
    let index = source.indexOf(substring);
    index !== -1;
    index = source.indexOf(substring, index + substring.length)
  ) {
    count += 1;
  }
  return count;
}

export function transformConvexWasmTargetZodJitlessSource({ lockfile, packageManifest, source }) {
  const lockfileBytes = materialBuffer(lockfile, "Zod lockfile material");
  const packageManifestBytes = materialBuffer(packageManifest, "Zod package manifest material");
  const sourceBytes = materialBuffer(source, "Zod util source material");
  const packageJson = parseJsonMaterial(packageManifestBytes, "Zod package manifest");
  if (packageJson.name !== "zod" || packageJson.version !== TARGET_ZOD_VERSION) {
    fail(`Zod package manifest must describe zod@${TARGET_ZOD_VERSION}`);
  }
  if (sha256(packageManifestBytes) !== TARGET_ZOD_PACKAGE_MANIFEST_SHA256) {
    fail(`Zod ${TARGET_ZOD_VERSION} package manifest changed`);
  }
  const packageLock = parseJsonMaterial(lockfileBytes, "toolchain package lock");
  if (
    packageLock.lockfileVersion !== 3 ||
    packageLock.packages?.[""]?.dependencies?.zod !==
      convexWasmTargetZodJitlessTransformPolicy.lock.rootRequirement ||
    canonicalJson(packageLock.packages?.["node_modules/zod"]) !==
      canonicalJson(TARGET_ZOD_LOCK_ENTRY)
  ) {
    fail(`toolchain package lock must pin zod@${TARGET_ZOD_VERSION}`);
  }
  const sourceText = new TextDecoder("utf-8", { fatal: true }).decode(sourceBytes);
  const segmentCount = exactSubstringCount(sourceText, TARGET_ZOD_ALLOWS_EVAL_SOURCE);
  if (segmentCount !== 1) {
    fail(
      `Zod ${TARGET_ZOD_VERSION} util source must contain exactly one authenticated allowsEval segment; found ${segmentCount}`
    );
  }
  if (
    sourceBytes.length !== convexWasmTargetZodJitlessTransformPolicy.source.size ||
    sha256(sourceBytes) !== convexWasmTargetZodJitlessTransformPolicy.source.sha256
  ) {
    fail(`Zod ${TARGET_ZOD_VERSION} util source changed outside the authenticated segment`);
  }
  const transformedText = sourceText.replace(
    TARGET_ZOD_ALLOWS_EVAL_SOURCE,
    TARGET_ZOD_ALLOWS_EVAL_JITLESS_SOURCE
  );
  const transformedSource = Buffer.from(transformedText);
  if (
    transformedSource.length !== convexWasmTargetZodJitlessTransformPolicy.transformedSource.size ||
    sha256(transformedSource) !== convexWasmTargetZodJitlessTransformPolicy.transformedSource.sha256
  ) {
    fail(`Zod ${TARGET_ZOD_VERSION} jitless transformed source identity changed`);
  }
  const identity = {
    ...convexWasmTargetZodJitlessTransformPolicy,
    lock: {
      ...convexWasmTargetZodJitlessTransformPolicy.lock,
      material: { sha256: sha256(lockfileBytes), size: lockfileBytes.length },
    },
    package: {
      ...convexWasmTargetZodJitlessTransformPolicy.package,
      manifestSize: packageManifestBytes.length,
    },
  };
  return {
    contents: transformedSource,
    identity: Object.freeze(identity),
  };
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function readStableFile(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("stable material authentication requires O_NOFOLLOW");
  }
  const beforePath = await fs.lstat(path, { bigint: true });
  if (beforePath.isSymbolicLink() || !beforePath.isFile()) {
    fail(`${path} is not a non-symlink regular file`);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || !sameFileState(beforePath, before)) {
      fail(`${path} changed while it was opened`);
    }
    if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(`${path} is too large to authenticate`);
    }
    const contents = await handle.readFile();
    const [after, afterPath] = await Promise.all([
      handle.stat({ bigint: true }),
      fs.lstat(path, { bigint: true }),
    ]);
    if (
      contents.length !== Number(before.size) ||
      !sameFileState(before, after) ||
      afterPath.isSymbolicLink() ||
      !afterPath.isFile() ||
      !sameFileState(after, afterPath)
    ) {
      fail(`${path} changed while it was being read`);
    }
    return {
      contents,
      sha256: sha256(contents),
      size: contents.length,
      state: {
        ctimeNs: after.ctimeNs,
        dev: after.dev,
        ino: after.ino,
        mode: after.mode,
        mtimeNs: after.mtimeNs,
        size: after.size,
      },
    };
  } finally {
    await handle.close();
  }
}

function normalizeProfileCacheConfig(value, deploymentGraphSession) {
  if (value === undefined) return undefined;
  requireExactKeys(
    value,
    ["cacheRoot", "producerSha256", "profileDirectory"],
    "compile-profile cache configuration"
  );
  if (deploymentGraphSession === undefined) {
    fail("compile-profile cache requires an authoritative deployment graph session");
  }
  const cacheRoot = value.cacheRoot;
  const profileDirectory = value.profileDirectory;
  if (typeof cacheRoot !== "string" || !isAbsolute(cacheRoot) || resolve(cacheRoot) !== cacheRoot) {
    fail("compile-profile cache root must be a normalized absolute path");
  }
  if (
    typeof profileDirectory !== "string" ||
    !isAbsolute(profileDirectory) ||
    resolve(profileDirectory) !== profileDirectory
  ) {
    fail("compile-profile cache directory must be a normalized absolute path");
  }
  const relativeDirectory = relative(cacheRoot, profileDirectory);
  if (
    relativeDirectory === "" ||
    relativeDirectory === ".." ||
    relativeDirectory.startsWith(`..${sep}`) ||
    isAbsolute(relativeDirectory)
  ) {
    fail("compile-profile cache directory must be below the cache root");
  }
  return Object.freeze({
    cacheRoot,
    producerSha256: requireSha256(value.producerSha256, "compile-profile cache producer SHA-256"),
    profileDirectory,
  });
}

async function ensureProfileCacheDirectory(profileCache) {
  await fs.mkdir(profileCache.profileDirectory, { mode: 0o700, recursive: true });
  await requirePrivateCacheDirectory(profileCache.cacheRoot, profileCache.profileDirectory);
}

function parseCanonicalCacheJson(material, description) {
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(material.contents);
    value = JSON.parse(text);
  } catch (error) {
    if (error instanceof TypeError || error instanceof SyntaxError) {
      fail(`${description} must be canonical UTF-8 JSON`);
    }
    throw error;
  }
  if (text !== canonicalJson(value)) {
    fail(`${description} is not canonical JSON`);
  }
  return value;
}

function validateProfileCacheArtifact(identity, expectedPath, material, description) {
  requireExactKeys(identity, ["path", "sha256", "size"], description);
  if (identity.path !== expectedPath) {
    fail(`${description} has the wrong path`);
  }
  requireSha256(identity.sha256, `${description} SHA-256`);
  requirePositiveInteger(identity.size, `${description} size`);
  if (identity.sha256 !== material.sha256 || identity.size !== material.size) {
    fail(`${description} bytes disagree with authenticated metadata`);
  }
}

function profileCacheEntryPath(profileCache, cacheKey) {
  requireSha256(cacheKey, "compile-profile cache key");
  return join(profileCache.profileDirectory, cacheKey);
}

async function readProfileCacheEntry(profileCache, cacheKey, keyIdentity) {
  const entryDirectory = profileCacheEntryPath(profileCache, cacheKey);
  try {
    await fs.lstat(entryDirectory);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
  await requirePrivateCacheDirectory(profileCache.cacheRoot, entryDirectory);
  const expectedFiles = Object.values(PROFILE_CACHE_FILES).sort(compareStrings);
  const actualFiles = (await fs.readdir(entryDirectory)).sort(compareStrings);
  if (canonicalJson(actualFiles) !== canonicalJson(expectedFiles)) {
    fail(`compile-profile cache entry ${cacheKey} has an incomplete or unexpected file set`);
  }
  const paths = Object.fromEntries(
    Object.entries(PROFILE_CACHE_FILES).map(([name, filename]) => [
      name,
      join(entryDirectory, filename),
    ])
  );
  await Promise.all(
    Object.values(paths).map((path) => requirePrivateCacheFile(profileCache.cacheRoot, path))
  );
  const materials = Object.fromEntries(
    await Promise.all(
      Object.entries(paths).map(async ([name, path]) => [name, await readStableFile(path)])
    )
  );
  await Promise.all(
    Object.values(paths).map((path) => requirePrivateCacheFile(profileCache.cacheRoot, path))
  );

  const metadata = parseCanonicalCacheJson(
    materials.metadata,
    `compile-profile cache entry ${cacheKey} metadata`
  );
  requireExactKeys(
    metadata,
    [
      "artifacts",
      "cacheKey",
      "keyIdentity",
      "kind",
      "localProfileIdentity",
      "localProfileSha256",
      "schemaVersion",
    ],
    "compile-profile cache metadata"
  );
  if (metadata.kind !== PROFILE_CACHE_METADATA_KIND || metadata.schemaVersion !== 1) {
    fail("compile-profile cache metadata kind or schema version is unsupported");
  }
  if (
    metadata.cacheKey !== cacheKey ||
    cacheKey !== fingerprintJson(metadata.keyIdentity) ||
    canonicalJson(metadata.keyIdentity) !== canonicalJson(keyIdentity)
  ) {
    fail("compile-profile cache key identity changed");
  }
  if (
    metadata.keyIdentity.kind !== PROFILE_CACHE_KEY_KIND ||
    metadata.keyIdentity.producerSha256 !== profileCache.producerSha256
  ) {
    fail("compile-profile cache producer identity changed");
  }
  requireObject(metadata.localProfileIdentity, "compile-profile cache local profile identity");
  if (
    Object.hasOwn(metadata.localProfileIdentity, "inventory") ||
    Object.hasOwn(metadata.localProfileIdentity, "deploymentGraph")
  ) {
    fail("compile-profile cache local identity contains deployment-wide proof material");
  }
  if (
    requireSha256(
      metadata.localProfileIdentity.dependencyGraphSha256,
      "compile-profile cache dependency graph SHA-256"
    ) !== metadata.keyIdentity.dependencyGraph?.sha256
  ) {
    fail("compile-profile cache local dependency graph identity changed");
  }
  if (
    requireSha256(metadata.localProfileSha256, "compile-profile cache local profile SHA-256") !==
    fingerprintJson(metadata.localProfileIdentity)
  ) {
    fail("compile-profile cache local profile identity changed");
  }
  requireExactKeys(
    metadata.artifacts,
    ["diagnostics", "javascript", "metafile", "sourceMap"],
    "compile-profile cache artifact identities"
  );
  validateProfileCacheArtifact(
    metadata.artifacts.diagnostics,
    PROFILE_CACHE_FILES.diagnostics,
    materials.diagnostics,
    "compile-profile cache diagnostics"
  );
  validateProfileCacheArtifact(
    metadata.artifacts.javascript,
    PROFILE_CACHE_FILES.javascript,
    materials.javascript,
    "compile-profile cache JavaScript"
  );
  validateProfileCacheArtifact(
    metadata.artifacts.metafile,
    PROFILE_CACHE_FILES.metafile,
    materials.metafile,
    "compile-profile cache metafile"
  );
  validateProfileCacheArtifact(
    metadata.artifacts.sourceMap,
    PROFILE_CACHE_FILES.sourceMap,
    materials.sourceMap,
    "compile-profile cache source map"
  );
  const metadataComplete = `${sha256(materials.metadata.contents)}\n`;
  if (materials.complete.contents.toString("utf8") !== metadataComplete) {
    fail("compile-profile cache COMPLETE marker disagrees with canonical metadata");
  }
  const diagnostics = parseCanonicalCacheJson(
    materials.diagnostics,
    "compile-profile cache diagnostics"
  );
  requireExactKeys(diagnostics, ["errors", "warnings"], "compile-profile cache diagnostics");
  if (
    !Array.isArray(diagnostics.errors) ||
    diagnostics.errors.length !== 0 ||
    !Array.isArray(diagnostics.warnings) ||
    diagnostics.warnings.length !== 0
  ) {
    fail("compile-profile cache diagnostics must record a clean build");
  }
  const metafile = parseCanonicalCacheJson(materials.metafile, "compile-profile cache metafile");
  return {
    diagnostics,
    javascript: Buffer.from(materials.javascript.contents),
    localProfileIdentity: metadata.localProfileIdentity,
    metadata,
    metafile,
    sourceMap: Buffer.from(materials.sourceMap.contents),
  };
}

async function writePrivateCacheFile(path, contents) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("compile-profile cache publication requires O_NOFOLLOW");
  }
  const handle = await fs.open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
    0o600
  );
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncPrivateCacheDirectory(path) {
  if (fsConstants.O_DIRECTORY === undefined || fsConstants.O_NOFOLLOW === undefined) {
    fail("compile-profile cache publication requires O_DIRECTORY and O_NOFOLLOW");
  }
  const handle = await fs.open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function profileCacheArtifact(path, contents) {
  return { path, sha256: sha256(contents), size: contents.length };
}

function profileCacheRecordsEqual(left, right) {
  return (
    canonicalJson(left.metadata) === canonicalJson(right.metadata) &&
    left.javascript.equals(right.javascript) &&
    canonicalJson(left.metafile) === canonicalJson(right.metafile) &&
    left.sourceMap.equals(right.sourceMap)
  );
}

async function publishProfileCacheEntry(profileCache, cacheKey, keyIdentity, profile) {
  const localProfile = projectConvexWasmLocalCompileProfile(profile);
  const localProfileIdentity = localProfile.identity;
  const diagnosticsContents = Buffer.from(canonicalJson({ errors: [], warnings: [] }));
  const javascript = Buffer.from(profile.javascript);
  const metafileContents = Buffer.from(canonicalJson(profile.metafile));
  const sourceMap = Buffer.from(profile.sourceMap);
  const metadata = {
    artifacts: {
      diagnostics: profileCacheArtifact(PROFILE_CACHE_FILES.diagnostics, diagnosticsContents),
      javascript: profileCacheArtifact(PROFILE_CACHE_FILES.javascript, javascript),
      metafile: profileCacheArtifact(PROFILE_CACHE_FILES.metafile, metafileContents),
      sourceMap: profileCacheArtifact(PROFILE_CACHE_FILES.sourceMap, sourceMap),
    },
    cacheKey,
    keyIdentity,
    kind: PROFILE_CACHE_METADATA_KIND,
    localProfileIdentity,
    localProfileSha256: localProfile.sha256,
    schemaVersion: 1,
  };
  const metadataContents = Buffer.from(canonicalJson(metadata));
  const completeContents = Buffer.from(`${sha256(metadataContents)}\n`);
  const temporaryDirectory = await fs.mkdtemp(
    join(profileCache.profileDirectory, `.publish-${cacheKey}-`)
  );
  await fs.chmod(temporaryDirectory, 0o700);
  let renamed = false;
  try {
    await Promise.all([
      writePrivateCacheFile(
        join(temporaryDirectory, PROFILE_CACHE_FILES.diagnostics),
        diagnosticsContents
      ),
      writePrivateCacheFile(join(temporaryDirectory, PROFILE_CACHE_FILES.javascript), javascript),
      writePrivateCacheFile(
        join(temporaryDirectory, PROFILE_CACHE_FILES.metadata),
        metadataContents
      ),
      writePrivateCacheFile(
        join(temporaryDirectory, PROFILE_CACHE_FILES.metafile),
        metafileContents
      ),
      writePrivateCacheFile(join(temporaryDirectory, PROFILE_CACHE_FILES.sourceMap), sourceMap),
    ]);
    await syncPrivateCacheDirectory(temporaryDirectory);
    await writePrivateCacheFile(
      join(temporaryDirectory, PROFILE_CACHE_FILES.complete),
      completeContents
    );
    await syncPrivateCacheDirectory(temporaryDirectory);
    try {
      await fs.rename(temporaryDirectory, profileCacheEntryPath(profileCache, cacheKey));
      renamed = true;
      await syncPrivateCacheDirectory(profileCache.profileDirectory);
    } catch (error) {
      if (error?.code !== "EEXIST" && error?.code !== "ENOTEMPTY") throw error;
    }
    const winner = await readProfileCacheEntry(profileCache, cacheKey, keyIdentity);
    if (winner === undefined) {
      fail("compile-profile cache winner disappeared after publication");
    }
    const candidate = {
      javascript,
      metadata,
      metafile: profile.metafile,
      sourceMap,
    };
    if (!profileCacheRecordsEqual(candidate, winner)) {
      fail("concurrent compile-profile cache winner produced different authenticated bytes");
    }
    return winner;
  } finally {
    if (!renamed) {
      await fs.rm(temporaryDirectory, { force: true, recursive: true });
    }
  }
}

function sourceLoader(path) {
  const loader = {
    ".cjs": "js",
    ".css": "css",
    ".cts": "ts",
    ".js": "js",
    ".json": "json",
    ".jsx": "jsx",
    ".mjs": "js",
    ".mts": "ts",
    ".ts": "ts",
    ".tsx": "tsx",
  }[extname(path)];
  if (loader === undefined) {
    fail(`esbuild loaded unsupported source extension at ${path}`);
  }
  return loader;
}

function scriptKind(ts, path) {
  return {
    ".cjs": ts.ScriptKind.JS,
    ".cts": ts.ScriptKind.TS,
    ".js": ts.ScriptKind.JS,
    ".jsx": ts.ScriptKind.JSX,
    ".mjs": ts.ScriptKind.JS,
    ".mts": ts.ScriptKind.TS,
    ".ts": ts.ScriptKind.TS,
    ".tsx": ts.ScriptKind.TSX,
  }[extname(path)];
}


async function registrationModuleRecords({
  analyzeRegistrationInput,
  analyzeSource,
  analyzerIdentity,
  materialsByAbsolutePath,
  metafile,
  repoRoot,
  typescript,
}) {
  const records = new Map();
  await Promise.all(
    Object.entries(metafile.inputs).map(async ([inputPath, input]) => {
      if (inputPath.includes(":")) return;
      const absolutePath = resolve(repoRoot, inputPath);
      const material = materialsByAbsolutePath.get(absolutePath);
      const kind = scriptKind(typescript, absolutePath);
      if (material === undefined || kind === undefined) return;
      const imports = (input.imports ?? []).map(({ external = false, kind, original, path }) => ({
        external,
        kind,
        ...(original === undefined ? {} : { original }),
        path,
      }));
      const key = fingerprintJson({
        absolutePath,
        analyzer: analyzerIdentity,
        buildOptionsSha256: fingerprintJson(BUILD_OPTIONS),
        imports,
        inputPath,
        pruningPolicy: TARGET_REGISTRATION_PRUNING_POLICY,
        source: { sha256: material.sha256, size: material.size },
      });
      const analysis = await analyzeRegistrationInput(key, async () =>
        analyzeSource({ absolutePath, input, inputPath, material })
      );
      records.set(inputPath, {
        ...analysis,
        aliases: new Map(analysis.aliases),
        exports: new Map(analysis.exports),
        imports: new Map(analysis.imports),
      });
    })
  );
  return records;
}

async function targetRegistrationTransforms({
  analyzeRegistrationInput,
  analyzeSource,
  analyzerIdentity,
  materialsByAbsolutePath,
  metafile,
  repoRoot,
  typescript,
}) {
  const records = await registrationModuleRecords({
    analyzeRegistrationInput,
    analyzeSource,
    analyzerIdentity,
    materialsByAbsolutePath,
    metafile,
    repoRoot,
    typescript,
  });
  const exportMemo = new Map();
  const bindingMemo = new Map();
  const resolving = new Set();
  const resolveExport = (inputPath, exportName) => {
    const key = `export\0${inputPath}\0${exportName}`;
    if (exportMemo.has(key)) return exportMemo.get(key);
    if (
      inputPath === `${TARGET_ADAPTER_NAMESPACE}:convex/server` &&
      TARGET_REGISTRATION_EXPORT_NAMES.has(exportName)
    ) {
      exportMemo.set(key, exportName);
      return exportName;
    }
    if (resolving.has(key)) return undefined;
    resolving.add(key);
    const record = records.get(inputPath);
    const exported = record?.exports.get(exportName);
    let identity;
    if (exported?.localName !== undefined) {
      identity = resolveBinding(inputPath, exported.localName);
    } else if (exported?.target !== undefined) {
      identity = resolveExport(exported.target, exported.importedName);
    } else if (record !== undefined) {
      const identities = new Set(
        record.starExports.flatMap((target) => {
          const resolved = resolveExport(target, exportName);
          return resolved === undefined ? [] : [resolved];
        })
      );
      if (identities.size === 1) identity = [...identities][0];
    }
    resolving.delete(key);
    exportMemo.set(key, identity);
    return identity;
  };
  const resolveBinding = (inputPath, localName) => {
    const key = `binding\0${inputPath}\0${localName}`;
    if (bindingMemo.has(key)) return bindingMemo.get(key);
    if (resolving.has(key)) return undefined;
    resolving.add(key);
    const record = records.get(inputPath);
    const imported = record?.imports.get(localName);
    let identity;
    if (imported !== undefined && imported.importedName !== "*") {
      identity = resolveExport(imported.target, imported.importedName);
    } else {
      const alias = record?.aliases.get(localName);
      if (alias !== undefined) identity = resolveBinding(inputPath, alias);
    }
    resolving.delete(key);
    bindingMemo.set(key, identity);
    return identity;
  };

  const transforms = new Map();
  for (const record of records.values()) {
    const edits = [];
    for (const candidate of record.candidates) {
      const registrationIdentity = resolveBinding(record.inputPath, candidate.callee);
      if (!TARGET_REGISTRATION_EXPORT_NAMES.has(registrationIdentity)) {
        continue;
      }
      edits.push({
        end: candidate.initializerStart,
        replacement: "/* @__PURE__ */ ",
        start: candidate.initializerStart,
      });
    }
    if (edits.length === 0) continue;
    let transformed = record.source;
    for (const edit of edits.sort((left, right) => right.start - left.start)) {
      transformed =
        transformed.slice(0, edit.start) + edit.replacement + transformed.slice(edit.end);
    }
    transforms.set(record.absolutePath, transformed);
  }
  return transforms;
}

function applicationInputPath(repoRoot, inputPath) {
  if (inputPath.includes(":") || isAbsolute(inputPath)) return false;
  const fromRoot = relative(repoRoot, resolve(repoRoot, inputPath));
  return (
    fromRoot !== "" &&
    fromRoot !== ".." &&
    !fromRoot.startsWith(`..${sep}`) &&
    !fromRoot.split(sep).includes("node_modules")
  );
}

async function sideEffectFreeApplicationModules({
  esbuild,
  materialsByAbsolutePath,
  metafile,
  mode,
  readMaterial,
  rejectedSourcePaths,
  repoRoot,
  serverOnlyPlugin,
  toolchainRoot,
  transformedSources,
  typescript,
  wasmPlugin,
}) {
  const candidates = Object.entries(metafile.inputs)
    .filter(
      ([inputPath]) =>
        applicationInputPath(repoRoot, inputPath) &&
        scriptKind(typescript, resolve(repoRoot, inputPath)) !== undefined
    )
    .sort(([left], [right]) => compareStrings(left, right));
  if (candidates.length === 0) return new Set();

  const entryNamespace = "convex-wasm-side-effect-proof-entry";
  const moduleNamespace = "convex-wasm-side-effect-proof-module";
  const applicationExternalPrefix = "convex-wasm-side-effect-proof-application:";
  const unsupportedExternalPrefix = "convex-wasm-side-effect-proof-unsupported:";
  const candidateById = new Map(
    candidates.map(([inputPath, input], index) => [String(index), { input, inputPath }])
  );
  const inputPathByEntryPoint = new Map(
    [...candidateById].map(([id, { inputPath }]) => [`${entryNamespace}:${id}`, inputPath])
  );
  const proofPlugin = {
    name: "convex-application-module-side-effect-proof",
    setup(build) {
      build.onResolve({ filter: /^convex-wasm-side-effect-proof-entry:/ }, ({ path }) => ({
        namespace: entryNamespace,
        path: path.slice(path.indexOf(":") + 1),
      }));
      build.onLoad({ filter: /.*/, namespace: entryNamespace }, ({ path }) => ({
        contents: `import ${JSON.stringify(`convex-wasm-side-effect-proof-module:${path}`)};`,
        loader: "js",
      }));
      build.onResolve(
        { filter: /^convex-wasm-side-effect-proof-module:/, namespace: entryNamespace },
        ({ path }) => ({
          namespace: moduleNamespace,
          path: path.slice(path.indexOf(":") + 1),
        })
      );
      build.onLoad({ filter: /.*/, namespace: moduleNamespace }, ({ path }) => {
        const candidate = candidateById.get(path);
        if (candidate === undefined) fail(`unknown application side-effect proof module ${path}`);
        const absolutePath = resolve(repoRoot, candidate.inputPath);
        const material = materialsByAbsolutePath.get(absolutePath);
        if (material === undefined) {
          fail(`application side-effect proof lost source material for ${candidate.inputPath}`);
        }
        return {
          contents: transformedSources.get(absolutePath) ?? material.contents,
          loader: sourceLoader(absolutePath),
          resolveDir: dirname(absolutePath),
        };
      });
      build.onResolve({ filter: /.*/, namespace: moduleNamespace }, async (args) => {
        const candidate = candidateById.get(args.importer);
        if (candidate === undefined) {
          fail(`unknown application side-effect proof importer ${args.importer}`);
        }
        const matchingEdges = (candidate.input.imports ?? []).filter(
          ({ kind, original, path }) => kind === args.kind && (original ?? path) === args.path
        );
        if (matchingEdges.length === 0) {
          fail(
            `application side-effect proof cannot bind ${candidate.inputPath} import ${JSON.stringify(args.path)}`
          );
        }
        const [edge] = matchingEdges;
        if (
          matchingEdges.some(
            ({ external = false, path }) =>
              external !== (edge.external ?? false) || path !== edge.path
          )
        ) {
          fail(
            `application side-effect proof found inconsistent resolutions for ${candidate.inputPath} import ${JSON.stringify(args.path)}`
          );
        }
        if (edge.external === true) {
          return {
            external: true,
            path: `${unsupportedExternalPrefix}${candidate.inputPath}:${args.path}`,
          };
        }
        if (applicationInputPath(repoRoot, edge.path)) {
          return { external: true, path: `${applicationExternalPrefix}${edge.path}` };
        }
        const resolved = await build.resolve(args.path, {
          kind: args.kind,
          resolveDir: args.resolveDir,
        });
        if (resolved.errors.length !== 0) return resolved;
        const resolvedInputPath =
          resolved.namespace === "file"
            ? toPosix(relative(repoRoot, resolve(resolved.path)))
            : `${resolved.namespace}:${resolved.path}`;
        if (resolvedInputPath !== edge.path) {
          fail(
            `application side-effect proof resolution ${candidate.inputPath} -> ${resolvedInputPath} disagrees with ${edge.path}`
          );
        }
        return resolved;
      });
    },
  };
  const result = await esbuild.build({
    absWorkingDir: repoRoot,
    bundle: true,
    conditions: BUILD_OPTIONS.conditions,
    define: compileProfileBuildOptions(mode).define,
    entryNames: "[name]",
    entryPoints: Object.fromEntries(
      [...candidateById].map(([id]) => [
        `module-${id}`,
        `convex-wasm-side-effect-proof-entry:${id}`,
      ])
    ),
    format: "esm",
    jsx: BUILD_OPTIONS.jsx,
    logLevel: "silent",
    metafile: true,
    outdir: "out",
    platform: BUILD_OPTIONS.platform,
    plugins: [
      proofPlugin,
      sourceMaterialPlugin(
        materialsByAbsolutePath,
        transformedSources,
        readMaterial,
        rejectedSourcePaths
      ),
      ...(mode === convexWasmCompileProfileTargetAdapterMode
        ? [targetAdapterPlugin(toolchainRoot)]
        : []),
      asyncHooksShimPlugin(mode),
      serverOnlyPlugin,
      noExternalPackagesPlugin(),
      wasmPlugin,
    ],
    supported: BUILD_OPTIONS.supported,
    target: BUILD_OPTIONS.target,
    treeShaking: true,
    write: false,
  });
  if (result.errors.length !== 0 || result.warnings.length !== 0) {
    fail(
      `installed esbuild returned ${result.errors.length} errors and ${result.warnings.length} warnings without rejecting the application side-effect proof`
    );
  }

  const locallySafe = new Set();
  const requiredApplicationDependencies = new Map();
  for (const output of Object.values(result.metafile.outputs)) {
    const inputPath = inputPathByEntryPoint.get(output.entryPoint);
    if (inputPath === undefined) {
      fail(`application side-effect proof emitted unknown entry ${output.entryPoint}`);
    }
    const emitsCode = Object.values(output.inputs ?? {}).some(
      ({ bytesInOutput }) => bytesInOutput !== 0
    );
    const retainedImports = output.imports ?? [];
    const unsupportedImport = retainedImports.some(
      ({ path }) => !path.startsWith(applicationExternalPrefix)
    );
    requiredApplicationDependencies.set(
      inputPath,
      retainedImports.flatMap(({ path }) =>
        path.startsWith(applicationExternalPrefix)
          ? [path.slice(applicationExternalPrefix.length)]
          : []
      )
    );
    if (!emitsCode && !unsupportedImport) locallySafe.add(inputPath);
  }
  if (result.outputFiles.length !== candidates.length) {
    fail("application side-effect proof did not emit exactly one output per candidate module");
  }

  // A module with no local initialization effects is still unsafe to omit when doing so would
  // omit an imported application module that has initialization effects. Starting with every
  // locally safe module and removing such importers computes the conservative cyclic closure.
  const safe = new Set(locallySafe);
  let changed = true;
  while (changed) {
    changed = false;
    for (const inputPath of [...safe]) {
      const unsafeLocalDependency = requiredApplicationDependencies
        .get(inputPath)
        .some((path) => extname(path) !== ".json" && !safe.has(path));
      if (!unsafeLocalDependency) continue;
      safe.delete(inputPath);
      changed = true;
    }
  }
  return safe;
}

function sideEffectFreeApplicationModulesPlugin({ metafile, repoRoot, safeInputPaths }) {
  const safeResolutions = new Map();
  for (const [inputPath, input] of Object.entries(metafile.inputs)) {
    if (inputPath.includes(":")) continue;
    const importer = resolve(repoRoot, inputPath);
    for (const { external = false, kind, original, path } of input.imports ?? []) {
      if (external || !safeInputPaths.has(path) || original === undefined) continue;
      safeResolutions.set(`${importer}\0${kind}\0${original}`, resolve(repoRoot, path));
    }
  }
  return {
    name: "convex-proved-side-effect-free-application-modules",
    setup(build) {
      build.onResolve({ filter: /.*/, namespace: "file" }, (args) => {
        const path = safeResolutions.get(`${resolve(args.importer)}\0${args.kind}\0${args.path}`);
        if (path === undefined) return null;
        return { namespace: "file", path, sideEffects: false };
      });
    },
  };
}

function sourceMaterialPlugin(
  materialsByAbsolutePath,
  transformedSources = new Map(),
  readMaterial = readStableFile,
  rejectedSourcePaths = new Set()
) {
  return {
    name: "convex-source-material-snapshot",
    setup(build) {
      build.onLoad({ filter: /.*/, namespace: "file" }, async ({ path }) => {
        const absolutePath = resolve(path);
        if (rejectedSourcePaths.has(absolutePath)) {
          fail(`reachable target Zod CommonJS util source is unsupported: ${absolutePath}`);
        }
        const material = await readMaterial(absolutePath);
        const previous = materialsByAbsolutePath.get(absolutePath);
        if (
          previous !== undefined &&
          (previous.sha256 !== material.sha256 || previous.size !== material.size)
        ) {
          fail(`source ${absolutePath} changed while esbuild was constructing the bundle`);
        }
        materialsByAbsolutePath.set(absolutePath, material);
        return {
          contents: transformedSources.get(absolutePath) ?? material.contents,
          loader: sourceLoader(absolutePath),
          resolveDir: dirname(absolutePath),
        };
      });
    },
  };
}

function bindingPatternContainsName(ts, pattern, name) {
  if (ts.isIdentifier(pattern)) return pattern.text === name;
  if (!ts.isObjectBindingPattern(pattern) && !ts.isArrayBindingPattern(pattern)) return false;
  return pattern.elements.some(
    (element) =>
      !ts.isOmittedExpression(element) && bindingPatternContainsName(ts, element.name, name)
  );
}

function importBindingIsTypeOnly(ts, node) {
  if (ts.isImportSpecifier(node) && node.isTypeOnly) return true;
  for (let parent = node.parent; parent !== undefined; parent = parent.parent) {
    if (ts.isImportClause(parent)) return parent.isTypeOnly;
    if (ts.isImportDeclaration(parent)) return false;
  }
  return false;
}

function declaredRuntimeBindingName(ts, node) {
  if (ts.isVariableDeclaration(node) || ts.isParameter(node)) return node.name;
  if (
    (ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isClassDeclaration(node) ||
      ts.isClassExpression(node) ||
      ts.isEnumDeclaration(node) ||
      ts.isModuleDeclaration(node) ||
      ts.isImportEqualsDeclaration(node)) &&
    node.name !== undefined
  ) {
    return node.name;
  }
  if (ts.isImportClause(node) && !node.isTypeOnly && node.name !== undefined) {
    return node.name;
  }
  if (
    (ts.isImportSpecifier(node) || ts.isNamespaceImport(node)) &&
    !importBindingIsTypeOnly(ts, node)
  ) {
    return node.name;
  }
  return undefined;
}

function assertTargetApplicationGlobalBindingIsUnbound(ts, { absolutePath, inputPath, material }) {
  const kind = scriptKind(ts, absolutePath);
  if (kind === undefined) return;
  const source = new TextDecoder("utf-8", { fatal: true }).decode(material.contents);
  const sourceFile = ts.createSourceFile(absolutePath, source, ts.ScriptTarget.ESNext, true, kind);
  const visit = (node) => {
    const declaredName = declaredRuntimeBindingName(ts, node);
    if (
      declaredName !== undefined &&
      bindingPatternContainsName(ts, declaredName, TARGET_APPLICATION_GLOBAL_BINDING_POLICY.binding)
    ) {
      fail(
        `target application global binding ${JSON.stringify(
          TARGET_APPLICATION_GLOBAL_BINDING_POLICY.binding
        )} is reserved in reachable input ${inputPath}`
      );
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

function assertTargetApplicationGlobalBindingIsReserved({
  materialsByAbsolutePath,
  metafile,
  repoRoot,
  typescript,
}) {
  const inputs = requireObject(metafile.inputs, "esbuild metafile inputs");
  for (const inputPath of Object.keys(inputs).sort(compareStrings)) {
    const absolutePath = resolve(repoRoot, inputPath);
    const material = materialsByAbsolutePath.get(absolutePath);
    if (material === undefined) continue;
    assertTargetApplicationGlobalBindingIsUnbound(typescript, { absolutePath, inputPath, material });
  }
}

function asyncHooksShimPlugin(mode) {
  return {
    name: "convex-async-hooks-shim",
    setup(build) {
      build.onResolve({ filter: /^(node:)?async_hooks$/ }, (args) => {
        if (mode === convexWasmCompileProfileTargetAdapterMode) {
          throw new ConvexWasmTargetRuntimeSurfaceGap("async-hooks-adapter", args.path);
        }
        return {
          namespace: "async-hooks-shim",
          path: args.path,
        };
      });
      build.onLoad({ filter: /.*/, namespace: "async-hooks-shim" }, () => ({
        contents: ASYNC_HOOKS_SHIM_SOURCE,
        loader: "js",
      }));
    },
  };
}

function targetAdapterPlugin(toolchainRoot) {
  return {
    name: "convex-target-hybrid-sdk-adapter",
    setup(build) {
      build.onResolve({ filter: /^convex\/(?:server|values)$/ }, ({ path }) => ({
        namespace: TARGET_ADAPTER_NAMESPACE,
        path,
        sideEffects: false,
      }));
      build.onResolve(
        { filter: /^\.\/node_modules\//, namespace: TARGET_ADAPTER_NAMESPACE },
        ({ path }) => {
          const sourcePath = path.slice(2);
          if (!TARGET_DEEP_LEAF_SOURCE_PATHS.has(sourcePath)) {
            fail(`target adapter requested unclassified deep leaf ${sourcePath}`);
          }
          return {
            namespace: "file",
            path: resolve(toolchainRoot, sourcePath),
            sideEffects: false,
          };
        }
      );
      build.onLoad({ filter: /.*/, namespace: TARGET_ADAPTER_NAMESPACE }, ({ path }) => {
        const source = TARGET_ADAPTER_SOURCES[path];
        if (source === undefined) {
          fail(`target adapter resolved unsupported module ${path}`);
        }
        return { contents: source, loader: "js", resolveDir: toolchainRoot };
      });
    },
  };
}

function noExternalPackagesPlugin() {
  return {
    name: "convex-node-externals",
    setup(build) {
      build.onResolve({ filter: /.*/, namespace: "file" }, () => null);
    },
  };
}

function packageVersion(source, path) {
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(source));
  if (typeof value.version !== "string" || value.version.length === 0) {
    fail(`${path} has no package version`);
  }
  return value.version;
}

function normalizedMaterialPath(repoRoot, toolchainRoot, path) {
  const repositoryPath = toPosix(relative(repoRoot, path));
  if (repositoryPath !== ".." && !repositoryPath.startsWith("../")) {
    return `repository/${repositoryPath}`;
  }
  const toolchainPath = toPosix(relative(toolchainRoot, path));
  if (toolchainPath !== ".." && !toolchainPath.startsWith("../")) {
    return `toolchain/${toolchainPath}`;
  }
  fail(`authenticated material escapes the repository and toolchain roots: ${path}`);
}

function resolvedPackageManifestPath(path) {
  const parts = resolve(path).split(sep);
  const nodeModulesIndex = parts.lastIndexOf("node_modules");
  if (nodeModulesIndex < 0 || nodeModulesIndex + 1 >= parts.length) {
    return undefined;
  }
  const packageEnd = parts[nodeModulesIndex + 1].startsWith("@")
    ? nodeModulesIndex + 3
    : nodeModulesIndex + 2;
  if (packageEnd > parts.length) {
    fail(`resolved package path is incomplete: ${path}`);
  }
  return join(sep, ...parts.slice(0, packageEnd), "package.json");
}

async function loadToolchain(
  repoRoot,
  toolchainRoot,
  mode,
  sourceConfigurationPaths,
  readMaterial = readStableFile
) {
  if (
    typeof process.env.ESBUILD_BINARY_PATH === "string" &&
    process.env.ESBUILD_BINARY_PATH !== ""
  ) {
    fail("ESBUILD_BINARY_PATH must be unset so the pinned installed binary is authoritative");
  }
  const packageSet = resolveConvexWasmApplicationPackageSet(toolchainRoot);
  const requireFromToolchain = createRequire(resolve(toolchainRoot, "package.json"));
  const convexPackageJsonPath = requireFromToolchain.resolve("convex/package.json");
  const requireFromConvex = createRequire(convexPackageJsonPath);
  const esbuildPackageJsonPath = requireFromConvex.resolve("esbuild/package.json");
  const esbuildMainPath = requireFromConvex.resolve("esbuild");
  const esbuildLauncherPath = requireFromConvex.resolve("esbuild/bin/esbuild");
  const nativePlatform = `${process.platform}-${process.arch}`;
  if (!["linux-x64", "darwin-arm64", "darwin-x64"].includes(nativePlatform)) {
    fail(`unsupported esbuild native platform ${process.platform}/${process.arch}`);
  }
  const nativePackageJsonPath = requireFromConvex.resolve(`@esbuild/${nativePlatform}/package.json`);
  const nativeBinaryPath = requireFromConvex.resolve(`@esbuild/${nativePlatform}/bin/esbuild`);
  const typescriptPackageJsonPath = requireFromToolchain.resolve("typescript/package.json");
  const typescriptRuntimePath = requireFromToolchain.resolve("typescript");
  const convexDirectory = dirname(convexPackageJsonPath);
  const bundlerDirectory = join(convexDirectory, "dist", "esm", "bundler");
  const cliDirectory = join(convexDirectory, "dist", "esm", "cli", "lib");
  const fixedPaths = new Map([
    ["repository/package.json", join(repoRoot, "package.json")],
    ["repository/package-lock.json", join(repoRoot, "package-lock.json")],
    ...sourceConfigurationPaths.map((path) => [`repository/${path}`, join(repoRoot, path)]),
    ["toolchain/package.json", join(toolchainRoot, "package.json")],
    ["toolchain/package-lock.json", join(toolchainRoot, "package-lock.json")],
    ["toolchain/convex/package.json", convexPackageJsonPath],
    ["toolchain/esbuild/package.json", esbuildPackageJsonPath],
    ["toolchain/esbuild/main.js", esbuildMainPath],
    ["toolchain/esbuild/launcher", esbuildLauncherPath],
    ["toolchain/esbuild/native-package.json", nativePackageJsonPath],
    ["toolchain/esbuild/native-binary", nativeBinaryPath],
    ["registration-analysis/typescript/package.json", typescriptPackageJsonPath],
    ["registration-analysis/typescript/runtime.js", typescriptRuntimePath],
    ["compile-profile-adapter", fileURLToPath(import.meta.url)],
    [
      "compile-profile-library/application-package-set",
      fileURLToPath(new URL("./convex-wasm-application-package-set.mjs", import.meta.url)),
    ],
    [
      "compile-profile-library/artifact-contract",
      fileURLToPath(new URL("./convex-wasm-artifact-contract.mjs", import.meta.url)),
    ],
    [
      "compile-profile-library/private-cache",
      fileURLToPath(new URL("./convex-wasm-private-cache.mjs", import.meta.url)),
    ],
    [
      "registration-analysis/source-analyzer",
      fileURLToPath(new URL("./convex-wasm-registration-source-analysis.mjs", import.meta.url)),
    ],
    [
      "compile-profile-library/static-hermes-syntax",
      fileURLToPath(new URL("./convex-wasm-static-hermes-syntax.mjs", import.meta.url)),
    ],
    [
      "target-runtime-surface-policy",
      fileURLToPath(new URL("./convex-wasm-runtime-surface.mjs", import.meta.url)),
    ],
  ]);
  let targetZodPaths;
  if (mode === convexWasmCompileProfileTargetAdapterMode) {
    const packageManifest = requireFromToolchain.resolve("zod/package.json");
    const packageDirectory = dirname(packageManifest);
    targetZodPaths = Object.freeze({
      commonJsSource: join(packageDirectory, "v4", "core", "util.cjs"),
      packageManifest,
      source: join(packageDirectory, "v4", "core", "util.js"),
    });
    fixedPaths.set("target-zod-jitless/package.json", targetZodPaths.packageManifest);
    fixedPaths.set("target-zod-jitless/v4/core/util.js", targetZodPaths.source);
  }
  const materials = {};
  const materialPaths = new Map();
  for (const [name, path] of fixedPaths) {
    const material = await readMaterial(path);
    materials[name] = { sha256: material.sha256, size: material.size };
    materialPaths.set(name, path);
  }
  for (const [name, identity] of [
    ["toolchain/convex/package.json", packageSet.convex],
    ["toolchain/esbuild/package.json", packageSet.esbuild],
    ["registration-analysis/typescript/package.json", packageSet.typescript],
  ]) {
    if (materials[name].sha256 !== identity.sha256) {
      fail(`${name} changed after application package resolution`);
    }
  }
  let targetZodJitless;
  if (mode === convexWasmCompileProfileTargetAdapterMode) {
    requireObject(targetZodPaths, "target Zod paths");
    const [lockfile, packageManifest, source] = await Promise.all([
      readMaterial(join(toolchainRoot, "package-lock.json")),
      readMaterial(targetZodPaths.packageManifest),
      readMaterial(targetZodPaths.source),
    ]);
    const transformed = transformConvexWasmTargetZodJitlessSource({
      lockfile: lockfile.contents,
      packageManifest: packageManifest.contents,
      source: source.contents,
    });
    targetZodJitless = Object.freeze({
      absolutePath: targetZodPaths.source,
      commonJsAbsolutePath: targetZodPaths.commonJsSource,
      contents: transformed.contents,
      identity: transformed.identity,
    });
  }
  for (const name of CONVEX_BUNDLER_MATERIALS) {
    const path = name.startsWith("cli/")
      ? join(dirname(cliDirectory), name.slice("cli/".length))
      : join(bundlerDirectory, name);
    const material = await readMaterial(path);
    const key = `toolchain/convex-bundler/${name}`;
    materials[key] = { sha256: material.sha256, size: material.size };
    materialPaths.set(key, path);
  }
  const convexVersion = packageVersion(
    (await readMaterial(convexPackageJsonPath)).contents,
    convexPackageJsonPath
  );
  const convexPackageJson = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(
      (await readMaterial(convexPackageJsonPath)).contents
    )
  );
  if (convexPackageJson.sideEffects !== false) {
    fail("installed Convex package must declare sideEffects=false for target deep-leaf resolution");
  }
  const esbuildVersion = packageVersion(
    (await readMaterial(esbuildPackageJsonPath)).contents,
    esbuildPackageJsonPath
  );
  const typescriptVersion = packageVersion(
    (await readMaterial(typescriptPackageJsonPath)).contents,
    typescriptPackageJsonPath
  );
  if (
    convexVersion !== packageSet.convex.version ||
    esbuildVersion !== packageSet.esbuild.version ||
    typescriptVersion !== packageSet.typescript.version
  ) {
    fail("toolchain versions changed after application package resolution");
  }
  const esbuild = requireFromConvex("esbuild");
  const typescript = requireFromToolchain("typescript");
  if (esbuild.version !== esbuildVersion) {
    fail("resolved esbuild runtime and package versions disagree");
  }
  if (typescript.version !== typescriptVersion) {
    fail("resolved TypeScript runtime and package versions disagree");
  }
  const [{ serverOnlyPlugin }, { wasmPlugin }] = await Promise.all([
    import(pathToFileURL(join(bundlerDirectory, "serverOnly.js")).href),
    import(pathToFileURL(join(bundlerDirectory, "wasm.js")).href),
  ]);
  return {
    esbuild,
    materialPaths,
    materials,
    serverOnlyPlugin,
    ...(targetZodJitless === undefined ? {} : { targetZodJitless }),
    toolchain: { convex: convexVersion, esbuild: esbuildVersion, typescript: typescriptVersion },
    typescript,
    wasmPlugin,
  };
}

function selectedEntryCohort(inventory, entryPath, selectedExportNames) {
  requireObject(inventory, "generated API inventory");
  if (!Array.isArray(inventory.functions)) {
    fail("generated API inventory has no query/mutation functions");
  }
  const matches = inventory.functions
    .filter((func) => func?.entryPath === entryPath)
    .sort((left, right) => compareStrings(String(left?.exportName), String(right?.exportName)));
  if (matches.length === 0) {
    fail(`inventory contains no query or mutation routes for entry ${entryPath}`);
  }
  const modulePath = matches[0]?.modulePath;
  const routes = [];
  const exportNames = new Set();
  for (const route of matches) {
    if (
      typeof route?.exportName !== "string" ||
      !IDENTIFIER_PATTERN.test(route.exportName) ||
      !["query", "mutation"].includes(route?.udfKind) ||
      !["internal", "public"].includes(route?.visibility) ||
      typeof route?.modulePath !== "string" ||
      route.modulePath.length === 0 ||
      route.modulePath !== modulePath
    ) {
      fail(`selected entry ${entryPath} has incomplete or inconsistent inventory metadata`);
    }
    if (exportNames.has(route.exportName)) {
      fail(`selected entry ${entryPath} contains duplicate export ${route.exportName}`);
    }
    if (
      route.exportName === ROUTE_METADATA_EXPORT_NAME ||
      route.exportName === SDK_COMMIT_TS_PLACEHOLDER_EXPORT_NAME
    ) {
      fail(`selected entry ${entryPath} uses reserved export ${route.exportName}`);
    }
    exportNames.add(route.exportName);
    routes.push({
      exportName: route.exportName,
      udfKind: route.udfKind,
      visibility: route.visibility,
    });
  }
  let selectedRoutes = routes;
  if (selectedExportNames !== undefined) {
    if (!Array.isArray(selectedExportNames) || selectedExportNames.length === 0) {
      fail(`selected entry ${entryPath} export selection must be a non-empty array`);
    }
    const normalizedSelectedExportNames = selectedExportNames
      .map((exportName, index) =>
        requireString(exportName, `selected entry ${entryPath} export selection ${index}`)
      )
      .sort(compareStrings);
    for (let index = 1; index < normalizedSelectedExportNames.length; index += 1) {
      if (normalizedSelectedExportNames[index - 1] === normalizedSelectedExportNames[index]) {
        fail(
          `selected entry ${entryPath} contains duplicate selected export ${normalizedSelectedExportNames[index]}`
        );
      }
    }
    const selectedExportNameSet = new Set(normalizedSelectedExportNames);
    selectedRoutes = routes.filter(({ exportName }) => selectedExportNameSet.has(exportName));
    if (selectedRoutes.length !== normalizedSelectedExportNames.length) {
      const knownExportNames = new Set(routes.map(({ exportName }) => exportName));
      const unknown = normalizedSelectedExportNames.filter(
        (exportName) => !knownExportNames.has(exportName)
      );
      fail(`selected entry ${entryPath} has unknown selected exports: ${unknown.join(", ")}`);
    }
  }
  const snapshot = requireObject(inventory.snapshot, "generated API inventory snapshot");
  return {
    inventory: {
      apiSha256: requireSha256(snapshot.apiSha256, "inventory API SHA-256"),
      inputSha256: requireSha256(snapshot.inputSha256, "inventory input SHA-256"),
      materialSha256: requireSha256(snapshot.materialSha256, "inventory material SHA-256"),
      outputSha256: requireSha256(snapshot.outputSha256, "inventory output SHA-256"),
    },
    routes: selectedRoutes,
    selectedEntry: {
      entryPath,
      modulePath,
    },
  };
}

function validateEntryPath(repoRoot, entryPath, description = "entryPath") {
  requireString(entryPath, description);
  const absolutePath = resolve(repoRoot, entryPath);
  const relativePath = toPosix(relative(repoRoot, absolutePath));
  if (
    relativePath !== entryPath ||
    relativePath === ".." ||
    relativePath.startsWith("../") ||
    isAbsolute(relativePath)
  ) {
    fail(`${description} is not a normalized repository-relative path: ${entryPath}`);
  }
  return absolutePath;
}

function virtualEntrySource(selectedEntry, routes, mode) {
  const imports = routes
    .map(({ exportName }, index) => `${exportName} as __convexWasmRoute${index}`)
    .join(", ");
  let source =
    `// Convex module ${JSON.stringify(selectedEntry.modulePath)}\n` +
    (mode === convexWasmCompileProfileTargetAdapterMode
      ? `import { ${SDK_COMMIT_TS_PLACEHOLDER_EXPORT_NAME} } from "convex/values";\n`
      : "") +
    `import { ${imports} } from ${JSON.stringify(`./${selectedEntry.entryPath}`)};\n`;
  for (const [index, route] of routes.entries()) {
    const { exportName, udfKind, visibility } = route;
    const wrapper = `__convexWasmRoute${index}`;
    const handler = `__convexWasmHandler${index}`;
    const kindProperty = udfKind === "query" ? "isQuery" : "isMutation";
    const otherKindProperty = udfKind === "query" ? "isMutation" : "isQuery";
    const visibilityProperty = visibility === "public" ? "isPublic" : "isInternal";
    const otherVisibilityProperty = visibility === "public" ? "isInternal" : "isPublic";
    const errorMessage = `Selected Convex ${udfKind}/${visibility} route ${selectedEntry.entryPath}:${exportName} metadata is invalid`;
    source +=
      `const ${wrapper}Type = typeof ${wrapper};\n` +
      `if (${wrapper}Type !== "function") {\n` +
      `  throw new Error(${JSON.stringify(errorMessage)});\n` +
      "}\n" +
      `const ${handler}Type = typeof ${wrapper}._handler;\n` +
      `if (${wrapper}.${kindProperty} !== true || ${wrapper}.${otherKindProperty} !== undefined || ` +
      `${wrapper}.${visibilityProperty} !== true || ${wrapper}.${otherVisibilityProperty} !== undefined || ` +
      `typeof ${wrapper}.exportArgs !== "function" || ` +
      `typeof ${wrapper}.exportReturns !== "function" || ` +
      `${handler}Type !== "function") {\n` +
      `  throw new Error(${JSON.stringify(errorMessage)});\n` +
      "}\n" +
      `const ${handler} = ${wrapper}._handler;\n`;
  }
  source += `const ${ROUTE_METADATA_EXPORT_NAME} = [\n`;
  for (const [index, { exportName, udfKind, visibility }] of routes.entries()) {
    source +=
      "  { " +
      `exportName: ${JSON.stringify(exportName)}, ` +
      `udfKind: ${JSON.stringify(udfKind)}, ` +
      `visibility: ${JSON.stringify(visibility)}, ` +
      `args: __convexWasmRoute${index}.exportArgs(), ` +
      `returns: __convexWasmRoute${index}.exportReturns() },\n`;
  }
  source += "];\n";
  source +=
    "export { " +
    [
      ROUTE_METADATA_EXPORT_NAME,
      ...(mode === convexWasmCompileProfileTargetAdapterMode
        ? [SDK_COMMIT_TS_PLACEHOLDER_EXPORT_NAME]
        : []),
      ...routes.map(({ exportName }, index) => `__convexWasmHandler${index} as ${exportName}`),
    ].join(", ") +
    " };\n";
  return source;
}

function externalImportKey({ kind, path }) {
  return canonicalJson({ kind, path });
}

const ERASURE_BUILD_OPTIONS = Object.freeze({
  bundle: false,
  format: "esm",
  jsx: BUILD_OPTIONS.jsx,
  platform: BUILD_OPTIONS.platform,
  target: BUILD_OPTIONS.target,
  write: false,
});

function importIdentity(
  input,
  { allowSyntheticRuntime = false, erasedExternalImports = new Set(), inputPath } = {}
) {
  if (!Array.isArray(input.imports)) {
    return [];
  }
  return input.imports
    .map((imported, index) => {
      requireObject(imported, `metafile import ${index}`);
      const syntheticRuntime =
        allowSyntheticRuntime &&
        imported.external === true &&
        imported.path === "<runtime>" &&
        imported.kind === "import-statement" &&
        imported.original === undefined;
      const erasedTypeScriptImport =
        imported.external === true && erasedExternalImports.has(externalImportKey(imported));
      if (imported.external === true && !syntheticRuntime && !erasedTypeScriptImport) {
        fail(
          `external input import is forbidden: ${inputPath === undefined ? "<unknown>" : inputPath} -> ${String(imported.path)}`
        );
      }
      if (
        !syntheticRuntime &&
        !erasedTypeScriptImport &&
        imported.external !== undefined &&
        imported.external !== false
      ) {
        fail("metafile import external flag must be boolean");
      }
      return {
        external: imported.external === true,
        kind: requireString(imported.kind, `metafile import ${index} kind`),
        ...(imported.original === undefined
          ? {}
          : { original: requireString(imported.original, `metafile import ${index} original`) }),
        path: requireString(imported.path, `metafile import ${index} path`),
        ...(syntheticRuntime ? { synthetic: "esbuild-runtime" } : {}),
        ...(erasedTypeScriptImport ? { erased: "esbuild-typescript" } : {}),
      };
    })
    .sort((left, right) => compareStrings(canonicalJson(left), canonicalJson(right)));
}

async function computeErasedExternalImportKeys(esbuild, absolutePath, inputPath, material, input) {
  const externalImports = (input.imports ?? []).filter(
    (imported) => imported.external === true && imported.path !== "<runtime>"
  );
  if (externalImports.length === 0) {
    return new Set();
  }
  if (![".cts", ".mts", ".ts", ".tsx"].includes(extname(absolutePath))) {
    fail(`external input import is forbidden: ${inputPath} -> ${externalImports[0].path}`);
  }
  const result = await esbuild.build({
    absWorkingDir: dirname(absolutePath),
    ...ERASURE_BUILD_OPTIONS,
    logLevel: "silent",
    metafile: true,
    stdin: {
      contents: material.contents,
      loader: sourceLoader(absolutePath),
      resolveDir: dirname(absolutePath),
      sourcefile: inputPath,
    },
  });
  if (result.errors.length !== 0 || result.warnings.length !== 0) {
    fail(`could not prove erased TypeScript imports for ${inputPath}`);
  }
  const outputs = Object.values(requireObject(result.metafile.outputs, "erasure proof outputs"));
  if (outputs.length !== 1) {
    fail(`TypeScript erasure proof for ${inputPath} emitted an unexpected output set`);
  }
  const runtimeImportKeys = new Set(
    (outputs[0].imports ?? []).map((imported) => externalImportKey(imported))
  );
  const erased = new Set();
  for (const imported of externalImports) {
    const key = externalImportKey(imported);
    if (runtimeImportKeys.has(key)) {
      fail(`external input import is forbidden: ${inputPath} -> ${imported.path}`);
    }
    erased.add(key);
  }
  return Object.freeze([...erased].sort(compareStrings));
}

async function erasedExternalImportKeys({
  absolutePath,
  cacheErasureProof,
  esbuild,
  input,
  inputPath,
  material,
}) {
  const externalImports = (input.imports ?? [])
    .filter((imported) => imported.external === true && imported.path !== "<runtime>")
    .map(({ external = false, kind, original, path }) => ({
      external,
      kind,
      ...(original === undefined ? {} : { original }),
      path,
    }));
  if (externalImports.length === 0) return new Set();
  const key = fingerprintJson({
    absolutePath,
    buildOptions: ERASURE_BUILD_OPTIONS,
    externalImports,
    inputPath,
    loader: sourceLoader(absolutePath),
    source: {
      sha256: sha256(material.contents),
      size: material.contents.length,
    },
  });
  const erased = await cacheErasureProof(key, async () =>
    computeErasedExternalImportKeys(esbuild, absolutePath, inputPath, material, input)
  );
  return new Set(erased);
}

async function inputIdentity({
  cacheErasureProof,
  esbuild,
  metafile,
  materialsByAbsolutePath,
  mode,
  repoRoot,
  transformedSources,
  transformedSourceIdentities = new Map(),
  toolchainRoot,
  virtualEntry,
}) {
  const inputs = requireObject(metafile.inputs, "esbuild metafile inputs");
  const result = {};
  const materialPaths = new Map();
  for (const inputPath of Object.keys(inputs).sort(compareStrings)) {
    const input = requireObject(inputs[inputPath], `metafile input ${inputPath}`);
    const pathClassification = classifyCompileProfileInputPath(inputPath, mode);
    let erasedExternalImports = new Set();
    if (pathClassification.kind === "real") {
      const inputAbsolutePath = resolve(repoRoot, inputPath);
      const inputMaterial = materialsByAbsolutePath.get(inputAbsolutePath);
      if (inputMaterial === undefined) {
        fail(`esbuild input ${inputPath} has no authenticated source snapshot`);
      }
      const transformedSource = transformedSources.get(inputAbsolutePath);
      erasedExternalImports = await erasedExternalImportKeys({
        absolutePath: inputAbsolutePath,
        cacheErasureProof,
        esbuild,
        input,
        inputPath,
        material:
          transformedSource === undefined
            ? inputMaterial
            : { ...inputMaterial, contents: Buffer.from(transformedSource) },
      });
    }
    const imports = importIdentity(input, {
      allowSyntheticRuntime: true,
      erasedExternalImports,
      inputPath,
    });
    for (const imported of imports) {
      if (
        imported.synthetic === undefined &&
        imported.erased === undefined &&
        !Object.hasOwn(inputs, imported.path)
      ) {
        fail(`input ${inputPath} imports unknown input ${imported.path}`);
      }
    }
    if (pathClassification.kind === "virtual-entry") {
      const bytes = Buffer.from(virtualEntry);
      result[inputPath] = {
        imports,
        sha256: sha256(bytes),
        size: bytes.length,
        virtual: true,
      };
      continue;
    }
    if (pathClassification.kind === "async-hooks-shim") {
      const bytes = Buffer.from(ASYNC_HOOKS_SHIM_SOURCE);
      result[inputPath] = {
        imports,
        sha256: sha256(bytes),
        size: bytes.length,
        virtual: true,
      };
      continue;
    }
    if (pathClassification.kind === "target-adapter") {
      const bytes = Buffer.from(pathClassification.source);
      result[inputPath] = {
        imports,
        sha256: sha256(bytes),
        size: bytes.length,
        virtual: true,
      };
      continue;
    }
    const absolutePath = resolve(repoRoot, inputPath);
    const material = materialsByAbsolutePath.get(absolutePath);
    if (material === undefined) fail(`esbuild input ${inputPath} lost its authenticated snapshot`);
    const transformedSourceIdentity = transformedSourceIdentities.get(absolutePath);
    if (
      transformedSourceIdentity !== undefined &&
      transformedSources.get(absolutePath) === undefined
    ) {
      fail(`input ${inputPath} has a transform identity without transformed source bytes`);
    }
    const transformedSource = transformedSources.get(absolutePath);
    if (
      transformedSourceIdentity !== undefined &&
      (sha256(transformedSource) !== transformedSourceIdentity.transformedSource.sha256 ||
        transformedSource.length !== transformedSourceIdentity.transformedSource.size)
    ) {
      fail(`input ${inputPath} transformed source bytes changed after authentication`);
    }
    result[inputPath] = {
      imports,
      sha256: material.sha256,
      size: material.size,
      ...(transformedSourceIdentity === undefined ? {} : { transform: transformedSourceIdentity }),
      virtual: false,
    };
    materialPaths.set(normalizedMaterialPath(repoRoot, toolchainRoot, absolutePath), absolutePath);
  }
  return { inputs: result, materialPaths };
}

function outputIdentity(result) {
  if (!Array.isArray(result.outputFiles) || result.outputFiles.length !== 2) {
    fail("esbuild must emit exactly one JavaScript file and one source map");
  }
  const javascriptFiles = result.outputFiles.filter((file) => file.path.endsWith(".js"));
  const sourceMapFiles = result.outputFiles.filter((file) => file.path.endsWith(".js.map"));
  if (javascriptFiles.length !== 1 || sourceMapFiles.length !== 1) {
    fail("esbuild output is not exactly one JavaScript file plus one attached map");
  }
  const javascriptFile = javascriptFiles[0];
  const sourceMapFile = sourceMapFiles[0];
  if (`${javascriptFile.path}.map` !== sourceMapFile.path) {
    fail("esbuild source map is not attached to the emitted JavaScript file");
  }
  const javascript = Buffer.from(javascriptFile.contents);
  const sourceMap = Buffer.from(sourceMapFile.contents);
  if (
    !javascript
      .toString("utf8")
      .endsWith("//# sourceMappingURL=convex-wasm-compile-profile.js.map\n")
  ) {
    fail("emitted JavaScript does not name its exact attached source map");
  }
  JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(sourceMap));
  const outputs = requireObject(result.metafile.outputs, "esbuild metafile outputs");
  if (Object.keys(outputs).length !== 2) {
    fail("esbuild metafile must describe exactly the JavaScript file and attached source map");
  }
  for (const [path, output] of Object.entries(outputs)) {
    const imports = importIdentity(requireObject(output, `metafile output ${path}`));
    if (imports.length !== 0) {
      fail(`output ${path} contains an import`);
    }
  }
  return {
    javascript,
    output: {
      javascript: { sha256: sha256(javascript), size: javascript.length },
      sourceMap: { sha256: sha256(sourceMap), size: sourceMap.length },
    },
    sourceMap,
  };
}

function authenticateTargetDependencySubstitutions(graphSession) {
  const descriptors = graphSession.graphTemplate?.dependencyAdapter?.descriptor?.adapters;
  if (!Array.isArray(descriptors)) {
    fail("deployment graph has no dependency adapter descriptors");
  }
  const substitutions = Object.entries(TARGET_EXPORT_CLASSIFICATION).flatMap(
    ([moduleSpecifier, entries]) =>
      entries
        .filter(({ classification }) => classification === "dependency-adapter-substitution")
        .map((entry) => ({ ...entry, moduleSpecifier }))
  );
  for (const substitution of substitutions) {
    const matches = descriptors.filter(({ id }) => id === substitution.adapterId);
    if (matches.length !== 1) {
      fail(`dependency adapter substitution ${substitution.adapterId} is not uniquely described`);
    }
    const descriptor = matches[0];
    if (
      descriptor.export?.modulePath !== substitution.authenticatedSourcePath ||
      descriptor.export?.exportName !== substitution.exportName ||
      canonicalJson(descriptor.substitution) !==
        canonicalJson({
          exportName: substitution.exportName,
          moduleSpecifier: substitution.moduleSpecifier,
          unitSourceSha256: substitution.unitSourceSha256,
        })
    ) {
      fail(`dependency adapter substitution ${substitution.adapterId} changed`);
    }
  }
}

function deploymentComparison(graphSession, selectedEntry, inputs, toolchain, mode) {
  if (graphSession === undefined) {
    return undefined;
  }
  requireObject(graphSession, "deployment graph session");
  if (
    graphSession.toolchain?.convex !== toolchain.convex ||
    graphSession.toolchain?.esbuild !== toolchain.esbuild
  ) {
    fail("compile-profile and deployment graph toolchains disagree");
  }
  if (mode === convexWasmCompileProfileTargetAdapterMode) {
    authenticateTargetDependencySubstitutions(graphSession);
  }
  const dependencyGraph = graphSession.dependencyGraphByEntry?.get(selectedEntry.entryPath);
  if (dependencyGraph === undefined || !Array.isArray(dependencyGraph.inputPaths)) {
    fail(`deployment graph is missing selected entry ${selectedEntry.entryPath}`);
  }
  const deploymentInputs = requireObject(
    graphSession.inputMaterials,
    "deployment graph input materials"
  );
  const dependencyInputSet = new Set(dependencyGraph.inputPaths);
  for (const [path, profileInput] of Object.entries(inputs)) {
    if (profileInput.virtual) {
      continue;
    }
    const deploymentInput = deploymentInputs[path];
    if (
      !dependencyInputSet.has(path) ||
      deploymentInput === undefined ||
      deploymentInput.virtual ||
      deploymentInput.sha256 !== profileInput.sha256 ||
      deploymentInput.size !== profileInput.size
    ) {
      fail(`compile-profile input ${path} disagrees with selected deployment graph provenance`);
    }
    const deploymentEdges = new Set(
      (deploymentInput.imports ?? []).map(({ external = false, kind, original, path: target }) =>
        canonicalJson({
          external,
          kind,
          ...(original === undefined ? {} : { original }),
          path: target,
          ...(external === true && target === "<runtime>" ? { synthetic: "esbuild-runtime" } : {}),
        })
      )
    );
    for (const edge of profileInput.imports) {
      if (edge.synthetic === "esbuild-runtime") {
        // This helper edge is derived from the authenticated profile build options. It has no
        // source import that the deployment build must resolve.
        continue;
      }
      if (edge.erased === "esbuild-typescript") {
        // Esbuild records a fully erased type import as its unresolved external specifier. If the
        // deployment build retains a value use, it instead records the resolved internal target.
        const deploymentMatches = (deploymentInput.imports ?? []).filter(
          ({ external = false, kind, original, path: target }) =>
            kind === edge.kind &&
            ((external === true && original === undefined && target === edge.path) ||
              (external === false && original === edge.path))
        );
        const deploymentMatch = deploymentMatches[0];
        if (
          deploymentMatches.length !== 1 ||
          (deploymentMatch.external !== true &&
            (!dependencyInputSet.has(deploymentMatch.path) ||
              deploymentInputs[deploymentMatch.path] === undefined))
        ) {
          fail(
            `compile-profile erased import ${path} -> ${edge.path} disagrees with the deployment graph`
          );
        }
        continue;
      }
      const targetAdapterPrefix = `${TARGET_ADAPTER_NAMESPACE}:`;
      if (
        mode === convexWasmCompileProfileTargetAdapterMode &&
        edge.path.startsWith(targetAdapterPrefix)
      ) {
        const moduleSpecifier = edge.path.slice(targetAdapterPrefix.length);
        const deploymentAdapterEdges = (deploymentInput.imports ?? []).filter(
          ({ external = false, kind, original }) =>
            external === false && kind === edge.kind && original === moduleSpecifier
        );
        if (
          edge.external !== false ||
          edge.original !== moduleSpecifier ||
          deploymentAdapterEdges.length !== 1 ||
          !dependencyInputSet.has(deploymentAdapterEdges[0].path) ||
          deploymentInputs[deploymentAdapterEdges[0].path] === undefined
        ) {
          fail(
            `compile-profile target adapter resolution ${path} -> ${edge.path} disagrees with the deployment graph`
          );
        }
        continue;
      }
      const deploymentComparableEdge = {
        external: edge.external,
        kind: edge.kind,
        ...(edge.original === undefined ? {} : { original: edge.original }),
        path: edge.path,
        ...(edge.synthetic === undefined ? {} : { synthetic: edge.synthetic }),
      };
      if (!deploymentEdges.has(canonicalJson(deploymentComparableEdge))) {
        fail(
          `compile-profile resolution ${path} -> ${edge.path} disagrees with the deployment graph`
        );
      }
    }
  }
  const assumptions = graphSession.graphTemplate?.assumptions;
  if (
    assumptions?.platform !== BUILD_OPTIONS.platform ||
    assumptions?.target !== BUILD_OPTIONS.target ||
    canonicalJson(assumptions?.conditions) !== canonicalJson(BUILD_OPTIONS.conditions)
  ) {
    fail("compile-profile resolver assumptions disagree with the deployment graph");
  }
  return {
    dependencyGraphSha256: requireSha256(
      dependencyGraph.sha256,
      "deployment dependency graph SHA-256"
    ),
    graphSha256: requireSha256(graphSession.graphSha256, "deployment graph SHA-256"),
    metafileSha256: requireSha256(
      graphSession.deploymentOutputMetafileSha256,
      "deployment output metafile SHA-256"
    ),
  };
}

function targetZodJitlessIdentity(toolMaterials) {
  const lockfile = requireObject(
    toolMaterials["toolchain/package-lock.json"],
    "target Zod jitless lockfile material"
  );
  const packageManifest = requireObject(
    toolMaterials["target-zod-jitless/package.json"],
    "target Zod jitless package manifest material"
  );
  const source = requireObject(
    toolMaterials["target-zod-jitless/v4/core/util.js"],
    "target Zod jitless source material"
  );
  if (
    packageManifest.sha256 !== convexWasmTargetZodJitlessTransformPolicy.package.manifestSha256 ||
    source.sha256 !== convexWasmTargetZodJitlessTransformPolicy.source.sha256 ||
    source.size !== convexWasmTargetZodJitlessTransformPolicy.source.size
  ) {
    fail("target Zod jitless tool materials changed");
  }
  return {
    ...convexWasmTargetZodJitlessTransformPolicy,
    lock: {
      ...convexWasmTargetZodJitlessTransformPolicy.lock,
      material: { ...lockfile },
    },
    package: {
      ...convexWasmTargetZodJitlessTransformPolicy.package,
      manifestSize: packageManifest.size,
    },
  };
}

function pluginIdentity(toolMaterials, mode, versions) {
  const plugins = [
    {
      implementation: toolMaterials["compile-profile-adapter"],
      name: "convex-source-material-snapshot",
    },
  ];
  if (mode === convexWasmCompileProfileTargetAdapterMode) {
    plugins.push({
      implementation: toolMaterials["compile-profile-adapter"],
      name: "convex-target-zod-jitless-source-transform",
      transform: targetZodJitlessIdentity(toolMaterials),
    });
    plugins.push({
      deepLeafResolution: {
        packageManifest: toolMaterials["toolchain/convex/package.json"],
        sideEffects: false,
      },
      exportClassification: TARGET_EXPORT_CLASSIFICATION,
      implementation: toolMaterials["compile-profile-adapter"],
      metadataEvaluator: {
        convexVersion: versions.convex,
        exports: ["asObjectValidator", "v"],
        source: {
          sha256: sha256(TARGET_VALUES_ADAPTER_SOURCE),
          size: Buffer.byteLength(TARGET_VALUES_ADAPTER_SOURCE),
        },
      },
      moduleResolution: { sideEffects: false },
      modules: Object.fromEntries(
        Object.entries(TARGET_ADAPTER_SOURCES).map(([name, source]) => [
          name,
          { sha256: sha256(source), size: Buffer.byteLength(source) },
        ])
      ),
      name: "convex-target-hybrid-sdk-adapter",
      namespace: TARGET_ADAPTER_NAMESPACE,
    });
    plugins.push({
      implementation: toolMaterials["compile-profile-adapter"],
      name: "convex-target-global-facade-binding",
      policy: TARGET_APPLICATION_GLOBAL_BINDING_POLICY,
    });
    plugins.push({
      analyzer: {
        implementation: toolMaterials["registration-analysis/source-analyzer"],
        packageManifest: toolMaterials["registration-analysis/typescript/package.json"],
        runtime: toolMaterials["registration-analysis/typescript/runtime.js"],
        version: versions.typescript,
      },
      implementation: toolMaterials["compile-profile-adapter"],
      name: "convex-target-registration-pruning",
      policy: TARGET_REGISTRATION_PRUNING_POLICY,
    });
  }
  plugins.push(
    {
      ...(mode === convexWasmCompileProfileTargetAdapterMode
        ? {
            gap: "async-hooks-adapter",
            gapPolicy: toolMaterials["target-runtime-surface-policy"],
            mode: "reject",
          }
        : {
            source: {
              sha256: sha256(ASYNC_HOOKS_SHIM_SOURCE),
              size: Buffer.byteLength(ASYNC_HOOKS_SHIM_SOURCE),
            },
          }),
      implementation: toolMaterials["compile-profile-adapter"],
      name: "convex-async-hooks-shim",
    },
    {
      implementation: toolMaterials["toolchain/convex-bundler/serverOnly.js"],
      name: "convex-server-only",
    },
    {
      implementation: toolMaterials["compile-profile-adapter"],
      mode: "empty-browser-map",
      name: "convex-node-externals",
    },
    {
      implementation: toolMaterials["toolchain/convex-bundler/wasm.js"],
      name: "convex-wasm",
    }
  );
  return plugins;
}

function persistentProfileKeyIdentity({
  deploymentGraphSession,
  loaded,
  mode,
  producerSha256,
  selection,
  virtualEntry,
}) {
  const dependencyGraph = deploymentGraphSession.dependencyGraphByEntry?.get(
    selection.selectedEntry.entryPath
  );
  if (dependencyGraph === undefined || !Array.isArray(dependencyGraph.inputPaths)) {
    fail(`deployment graph is missing selected entry ${selection.selectedEntry.entryPath}`);
  }
  const inputPaths = [...dependencyGraph.inputPaths].sort(compareStrings);
  if (
    inputPaths.length === 0 ||
    inputPaths.some(
      (path, index) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.includes("\\") ||
        path.includes("\0") ||
        isAbsolute(path) ||
        (index > 0 && inputPaths[index - 1] === path)
    )
  ) {
    fail("deployment entry dependency closure paths are invalid");
  }
  const deploymentInputs = requireObject(
    deploymentGraphSession.inputMaterials,
    "deployment graph input materials"
  );
  const inputs = Object.fromEntries(
    inputPaths.map((path) => {
      const input = deploymentInputs[path];
      if (input === undefined) {
        fail(`deployment entry dependency closure is missing input ${path}`);
      }
      return [path, structuredClone(requireObject(input, `deployment graph input ${path}`))];
    })
  );
  const options = compileProfileBuildOptions(mode);
  return {
    dependencyGraph: {
      inputPaths,
      inputs,
      sha256: requireSha256(dependencyGraph.sha256, "deployment entry dependency graph SHA-256"),
    },
    kind: PROFILE_CACHE_KEY_KIND,
    mode,
    node: {
      architecture: process.arch,
      platform: process.platform,
      version: process.version,
    },
    options,
    optionsSha256: fingerprintJson(options),
    plugins: pluginIdentity(loaded.materials, mode, loaded.toolchain),
    producerSha256,
    routes: selection.routes,
    selectedEntry: selection.selectedEntry,
    toolchain: {
      materials: loaded.materials,
      versions: loaded.toolchain,
    },
    virtualEntry: {
      sha256: sha256(virtualEntry),
      size: Buffer.byteLength(virtualEntry),
    },
  };
}

async function authenticateCachedProfileMaterials(localProfileIdentity, loaded, session) {
  const expectedMaterials = requireObject(
    localProfileIdentity.toolchain?.materials,
    "cached compile-profile tool materials"
  );
  const expectedMaterialNames = new Set(Object.keys(loaded.materials));
  for (const [name, current] of Object.entries(loaded.materials)) {
    if (canonicalJson(expectedMaterials[name]) !== canonicalJson(current)) {
      fail(`cached compile-profile tool material ${name} changed`);
    }
  }
  if (canonicalJson(localProfileIdentity.toolchain?.versions) !== canonicalJson(loaded.toolchain)) {
    fail("cached compile-profile toolchain versions changed");
  }
  for (const [inputPath, input] of Object.entries(
    requireObject(localProfileIdentity.inputs, "cached compile-profile inputs")
  )) {
    if (input.virtual === true) continue;
    const absolutePath = resolve(session.normalizedRoot, inputPath);
    const material = await session.readMaterial(absolutePath);
    if (material.sha256 !== input.sha256 || material.size !== input.size) {
      fail(`cached compile-profile input ${inputPath} changed after deployment graph creation`);
    }
    const materialName = `resolved/${normalizedMaterialPath(
      session.normalizedRoot,
      session.normalizedToolchainRoot,
      absolutePath
    )}`;
    expectedMaterialNames.add(materialName);
    if (
      canonicalJson(expectedMaterials[materialName]) !==
      canonicalJson({ sha256: material.sha256, size: material.size })
    ) {
      fail(`cached compile-profile resolved material ${materialName} changed`);
    }
    const manifestPath = resolvedPackageManifestPath(absolutePath);
    if (manifestPath === undefined) continue;
    const manifestName = `resolution/${normalizedMaterialPath(
      session.normalizedRoot,
      session.normalizedToolchainRoot,
      manifestPath
    )}`;
    if (expectedMaterialNames.has(manifestName)) continue;
    const manifest = await session.readMaterial(manifestPath);
    expectedMaterialNames.add(manifestName);
    if (
      canonicalJson(expectedMaterials[manifestName]) !==
      canonicalJson({ sha256: manifest.sha256, size: manifest.size })
    ) {
      fail(`cached compile-profile resolution material ${manifestName} changed`);
    }
  }
  const cachedMaterialNames = Object.keys(expectedMaterials).sort(compareStrings);
  const currentMaterialNames = [...expectedMaterialNames].sort(compareStrings);
  if (canonicalJson(cachedMaterialNames) !== canonicalJson(currentMaterialNames)) {
    fail("cached compile-profile tool material set changed");
  }
}

async function rebindCachedCompileProfile({
  cached,
  deploymentGraphSession,
  entryPath,
  inventory,
  loaded,
  selectedExportNames,
  session,
}) {
  const selection = selectedEntryCohort(inventory, entryPath, selectedExportNames);
  const fullEntryInventoryIdentity = canonicalJson(selectedEntryCohort(inventory, entryPath));
  const selectedRouteExportNames = selection.routes.map(({ exportName }) => exportName);
  const selectedInventoryIdentity = canonicalJson(selection);
  await authenticateCachedProfileMaterials(cached.localProfileIdentity, loaded, session);
  const {
    dependencyGraphSha256: cachedDependencyGraphSha256,
    ...cachedProfileIdentityWithoutProof
  } = cached.localProfileIdentity;
  const comparison = await session.runStage("deployment-comparison", entryPath, async () =>
    deploymentComparison(
      deploymentGraphSession,
      selection.selectedEntry,
      cachedProfileIdentityWithoutProof.inputs,
      loaded.toolchain,
      cachedProfileIdentityWithoutProof.mode
    )
  );
  if (comparison.dependencyGraphSha256 !== cachedDependencyGraphSha256) {
    fail("cached compile-profile dependency graph proof changed");
  }
  const identity = {
    ...cachedProfileIdentityWithoutProof,
    inventory: selection.inventory,
    deploymentGraph: comparison,
  };
  const verifyEntry = async () => {
    if (
      canonicalJson(selectedEntryCohort(inventory, entryPath)) !== fullEntryInventoryIdentity ||
      canonicalJson(selectedEntryCohort(inventory, entryPath, selectedRouteExportNames)) !==
        selectedInventoryIdentity
    ) {
      fail("selected entry inventory metadata changed after the compile-profile cache hit");
    }
    const currentComparison = deploymentComparison(
      deploymentGraphSession,
      selection.selectedEntry,
      cachedProfileIdentityWithoutProof.inputs,
      loaded.toolchain,
      cachedProfileIdentityWithoutProof.mode
    );
    if (canonicalJson(currentComparison) !== canonicalJson(identity.deploymentGraph)) {
      fail("selected entry deployment graph changed after the compile-profile cache hit");
    }
    session.assertFixedInputs();
  };
  const verifyMaterials = async () => {
    await session.verifyMaterialUnion(true);
    await verifyEntry();
  };
  const profile = {
    identity,
    javascript: cached.javascript,
    kind: PROFILE_KIND,
    metafile: cached.metafile,
    sha256: fingerprintJson(identity),
    sourceMap: cached.sourceMap,
    verifyMaterials,
  };
  authenticateConvexWasmCompileProfile(profile);
  const localProfile = projectConvexWasmLocalCompileProfile(profile);
  if (
    localProfile.sha256 !== cached.metadata.localProfileSha256 ||
    canonicalJson(localProfile.identity) !== canonicalJson(cached.localProfileIdentity)
  ) {
    fail("cached compile-profile local identity changed while binding deployment proof");
  }
  await verifyEntry();
  session.registerProfileVerification(verifyEntry);
  session.recordProfile(profile);
  return profile;
}

function validateOutputMaterial(value, bytes, description) {
  const identity = requireExactKeys(value, ["sha256", "size"], description);
  requireSha256(identity.sha256, `${description} SHA-256`);
  requirePositiveInteger(identity.size, `${description} size`);
  if (identity.size !== bytes.length || identity.sha256 !== sha256(bytes)) {
    fail(`${description} bytes disagree with authenticated identity`);
  }
}

function validateProfileIdentity(identity) {
  const expectedKeys = [
    "inputs",
    "inventory",
    "kind",
    "metafileSha256",
    "mode",
    "options",
    "optionsSha256",
    "output",
    "plugins",
    "routes",
    "selectedEntry",
    "toolchain",
    ...(identity.deploymentGraph === undefined ? [] : ["deploymentGraph"]),
  ];
  requireExactKeys(identity, expectedKeys, "compile profile identity");
  const mode = requireProfileMode(identity.mode);
  requireExactKeys(
    identity.selectedEntry,
    ["entryPath", "modulePath"],
    "compile profile selected entry"
  );
  validateEntryPath(resolve("/compile-profile-schema-root"), identity.selectedEntry.entryPath);
  requireString(identity.selectedEntry.modulePath, "selected entry modulePath");
  if (!Array.isArray(identity.routes) || identity.routes.length === 0) {
    fail("compile profile route cohort must be a non-empty array");
  }
  let previousExportName;
  for (const [index, route] of identity.routes.entries()) {
    requireExactKeys(
      route,
      ["exportName", "udfKind", "visibility"],
      `compile profile route cohort member ${index}`
    );
    requireString(route.exportName, `compile profile route cohort member ${index} exportName`);
    if (
      !IDENTIFIER_PATTERN.test(route.exportName) ||
      route.exportName === ROUTE_METADATA_EXPORT_NAME ||
      !["query", "mutation"].includes(route.udfKind) ||
      !["internal", "public"].includes(route.visibility) ||
      (previousExportName !== undefined &&
        compareStrings(previousExportName, route.exportName) >= 0)
    ) {
      fail("compile profile route cohort metadata is invalid or unsorted");
    }
    previousExportName = route.exportName;
  }
  requireExactKeys(
    identity.inventory,
    ["apiSha256", "inputSha256", "materialSha256", "outputSha256"],
    "compile profile inventory identity"
  );
  for (const [name, digest] of Object.entries(identity.inventory)) {
    requireSha256(digest, `compile profile inventory ${name}`);
  }
  requireExactKeys(identity.output, ["javascript", "sourceMap"], "compile profile output identity");
  for (const [name, material] of Object.entries(identity.output)) {
    requireExactKeys(material, ["sha256", "size"], `compile profile output ${name}`);
    requireSha256(material.sha256, `compile profile output ${name} SHA-256`);
    requirePositiveInteger(material.size, `compile profile output ${name} size`);
  }
  const expectedBuildOptions = compileProfileBuildOptions(mode);
  if (canonicalJson(identity.options) !== canonicalJson(expectedBuildOptions)) {
    fail("compile profile build options are not the fixed compile-profile options");
  }
  requireExactKeys(
    identity.toolchain,
    ["materials", "versions"],
    "compile profile toolchain identity"
  );
  requireExactKeys(
    identity.toolchain.versions,
    ["convex", "esbuild", "typescript"],
    "compile profile toolchain versions"
  );
  for (const [name, version] of Object.entries(identity.toolchain.versions)) {
    requireString(version, `compile profile ${name} version`);
  }
  const materials = requireObject(identity.toolchain.materials, "compile profile tool materials");
  if (Object.keys(materials).length === 0) {
    fail("compile profile has no tool materials");
  }
  for (const [name, material] of Object.entries(materials)) {
    requireExactKeys(material, ["sha256", "size"], `compile profile tool material ${name}`);
    requireSha256(material.sha256, `compile profile tool material ${name} SHA-256`);
    requirePositiveInteger(material.size, `compile profile tool material ${name} size`);
  }
  if (
    canonicalJson(identity.plugins) !==
    canonicalJson(pluginIdentity(materials, mode, identity.toolchain.versions))
  ) {
    fail("compile profile plugin identity changed");
  }
  const targetZodJitlessPlugin = identity.plugins.find(
    ({ name }) => name === "convex-target-zod-jitless-source-transform"
  );
  const inputs = requireObject(identity.inputs, "compile profile input identities");
  if (!Object.hasOwn(inputs, VIRTUAL_ENTRY_PATH)) {
    fail("compile profile input identity is missing the virtual entry");
  }
  let targetZodInputCount = 0;
  for (const [path, input] of Object.entries(inputs)) {
    const pathClassification = classifyCompileProfileInputPath(path, mode);
    const isTargetZodSource = pathClassification.targetZod === "esm";
    const isTargetZodCommonJsSource = pathClassification.targetZod === "commonjs";
    if (isTargetZodSource) targetZodInputCount += 1;
    requireExactKeys(
      input,
      [
        "imports",
        "sha256",
        "size",
        ...(input.transform === undefined ? [] : ["transform"]),
        "virtual",
      ],
      `compile profile input ${path}`
    );
    requireSha256(input.sha256, `compile profile input ${path} SHA-256`);
    requirePositiveInteger(input.size, `compile profile input ${path} size`);
    if (typeof input.virtual !== "boolean" || !Array.isArray(input.imports)) {
      fail(`compile profile input ${path} metadata is invalid`);
    }
    if (isTargetZodCommonJsSource && mode === convexWasmCompileProfileTargetAdapterMode) {
      fail(`compile profile input ${path} reaches the unsupported target Zod CommonJS source`);
    }
    if (
      isTargetZodSource &&
      mode === convexWasmCompileProfileTargetAdapterMode &&
      (targetZodJitlessPlugin === undefined ||
        input.virtual ||
        input.sha256 !== targetZodJitlessPlugin.transform.source.sha256 ||
        input.size !== targetZodJitlessPlugin.transform.source.size ||
        canonicalJson(input.transform) !== canonicalJson(targetZodJitlessPlugin.transform))
    ) {
      fail(`compile profile input ${path} does not bind the target Zod jitless transform`);
    }
    if (
      isTargetZodSource &&
      mode !== convexWasmCompileProfileTargetAdapterMode &&
      input.transform !== undefined
    ) {
      fail(`compile profile input ${path} applies a target-only source transform`);
    }
    if (!isTargetZodSource && input.transform !== undefined) {
      fail(`compile profile input ${path} has an unknown source transform`);
    }
    let expectedVirtualSource;
    if (pathClassification.kind === "virtual-entry") {
      expectedVirtualSource = virtualEntrySource(
        identity.selectedEntry,
        identity.routes,
        identity.mode
      );
    } else if (pathClassification.kind === "async-hooks-shim") {
      expectedVirtualSource = ASYNC_HOOKS_SHIM_SOURCE;
    } else if (pathClassification.kind === "target-adapter") {
      expectedVirtualSource = pathClassification.source;
    } else if (input.virtual) {
      fail(`compile profile input ${path} has unknown virtual provenance`);
    }
    if (
      expectedVirtualSource !== undefined &&
      (input.virtual !== true ||
        input.sha256 !== sha256(expectedVirtualSource) ||
        input.size !== Buffer.byteLength(expectedVirtualSource))
    ) {
      fail(`compile profile virtual input ${path} bytes disagree with the fixed source`);
    }
    for (const [index, imported] of input.imports.entries()) {
      const expectedImportKeys = [
        "external",
        "kind",
        "path",
        ...(imported.erased === undefined ? [] : ["erased"]),
        ...(imported.original === undefined ? [] : ["original"]),
        ...(imported.synthetic === undefined ? [] : ["synthetic"]),
      ];
      requireExactKeys(
        imported,
        expectedImportKeys,
        `compile profile input ${path} import ${index}`
      );
      requireString(imported.kind, `compile profile input ${path} import ${index} kind`);
      requireString(imported.path, `compile profile input ${path} import ${index} path`);
      if (imported.original !== undefined) {
        requireString(imported.original, `compile profile input ${path} import ${index} original`);
      }
      if (
        imported.synthetic === "esbuild-runtime" &&
        imported.external === true &&
        imported.path === "<runtime>" &&
        imported.kind === "import-statement" &&
        imported.original === undefined
      ) {
        continue;
      }
      if (
        imported.erased === "esbuild-typescript" &&
        imported.external === true &&
        imported.synthetic === undefined &&
        imported.original === undefined &&
        imported.kind === "import-statement" &&
        !path.includes(":")
      ) {
        continue;
      }
      if (
        imported.erased !== undefined ||
        imported.synthetic !== undefined ||
        imported.external !== false
      ) {
        fail(`compile profile input ${path} import ${index} is external or unknown`);
      }
      if (!Object.hasOwn(inputs, imported.path)) {
        fail(`compile profile input ${path} imports unknown input ${imported.path}`);
      }
    }
  }
  if (targetZodInputCount > 1) {
    fail("compile profile contains multiple target Zod util source inputs");
  }
  if (identity.deploymentGraph !== undefined) {
    requireExactKeys(
      identity.deploymentGraph,
      ["dependencyGraphSha256", "graphSha256", "metafileSha256"],
      "compile profile deployment graph comparison"
    );
    for (const [name, digest] of Object.entries(identity.deploymentGraph)) {
      requireSha256(digest, `compile profile deployment graph ${name}`);
    }
  }
  requireSha256(identity.metafileSha256, "compile profile metafile SHA-256");
  requireSha256(identity.optionsSha256, "compile profile options SHA-256");
}

function validateProfileMetafile(metafile, identity) {
  requireExactKeys(metafile, ["inputs", "outputs"], "compile profile metafile");
  const inputs = requireObject(metafile.inputs, "compile profile metafile inputs");
  if (
    canonicalJson(Object.keys(inputs).sort(compareStrings)) !==
    canonicalJson(Object.keys(identity.inputs).sort(compareStrings))
  ) {
    fail("compile profile metafile input set changed");
  }
  for (const [path, input] of Object.entries(inputs)) {
    requireObject(input, `compile profile metafile input ${path}`);
    const erasedExternalImports = new Set(
      identity.inputs[path].imports
        .filter(({ erased }) => erased === "esbuild-typescript")
        .map((imported) => externalImportKey(imported))
    );
    const actualImports = importIdentity(input, {
      allowSyntheticRuntime: true,
      erasedExternalImports,
      inputPath: path,
    });
    if (canonicalJson(actualImports) !== canonicalJson(identity.inputs[path].imports)) {
      fail(`compile profile metafile input ${path} resolutions changed`);
    }
  }
  const outputs = requireObject(metafile.outputs, "compile profile metafile outputs");
  const outputPaths = Object.keys(outputs).sort(compareStrings);
  if (
    canonicalJson(outputPaths) !==
    canonicalJson([OUTPUT_PATH, `${OUTPUT_PATH}.map`].sort(compareStrings))
  ) {
    fail("compile profile metafile output set changed");
  }
  for (const [path, output] of Object.entries(outputs)) {
    if (
      importIdentity(requireObject(output, `compile profile metafile output ${path}`)).length !== 0
    ) {
      fail(`compile profile metafile output ${path} contains an import`);
    }
  }
  if (outputs[OUTPUT_PATH].entryPoint !== VIRTUAL_ENTRY_PATH) {
    fail("compile profile JavaScript output is not owned by the virtual entry");
  }
  if (
    outputs[OUTPUT_PATH].bytes !== identity.output.javascript.size ||
    outputs[`${OUTPUT_PATH}.map`].bytes !== identity.output.sourceMap.size
  ) {
    fail("compile profile metafile output sizes disagree with emitted bytes");
  }
}

export function authenticateConvexWasmCompileProfile(profile) {
  requireExactKeys(
    profile,
    ["identity", "javascript", "kind", "metafile", "sha256", "sourceMap", "verifyMaterials"],
    "compile profile"
  );
  if (profile.kind !== PROFILE_KIND || typeof profile.verifyMaterials !== "function") {
    fail("compile profile kind or material verifier is invalid");
  }
  const identity = requireObject(profile.identity, "compile profile identity");
  if (identity.kind !== PROFILE_IDENTITY_KIND) {
    fail("compile profile identity kind is invalid");
  }
  validateProfileIdentity(identity);
  requireSha256(profile.sha256, "compile profile SHA-256");
  if (profile.sha256 !== fingerprintJson(identity)) {
    fail("compile profile identity changed");
  }
  if (identity.optionsSha256 !== fingerprintJson(compileProfileBuildOptions(identity.mode))) {
    fail("compile profile build options changed");
  }
  const expectedVirtualEntry = virtualEntrySource(
    identity.selectedEntry,
    identity.routes,
    identity.mode
  );
  const virtualInput = identity.inputs[VIRTUAL_ENTRY_PATH];
  if (
    virtualInput?.virtual !== true ||
    virtualInput.sha256 !== sha256(expectedVirtualEntry) ||
    virtualInput.size !== Buffer.byteLength(expectedVirtualEntry)
  ) {
    fail("compile profile virtual entry changed");
  }
  if (identity.metafileSha256 !== fingerprintJson(profile.metafile)) {
    fail("compile profile metafile changed");
  }
  validateProfileMetafile(profile.metafile, identity);
  validateOutputMaterial(
    identity.output.javascript,
    Buffer.from(profile.javascript),
    "compile profile JavaScript"
  );
  validateOutputMaterial(
    identity.output.sourceMap,
    Buffer.from(profile.sourceMap),
    "compile profile source map"
  );
  return profile;
}

function freezeJsonValue(value) {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Array.isArray(value) ? value : Object.values(value)) {
    freezeJsonValue(child);
  }
  return Object.freeze(value);
}

export function projectConvexWasmLocalCompileProfile(profile) {
  authenticateConvexWasmCompileProfile(profile);
  const deploymentGraph = requireObject(
    profile.identity.deploymentGraph,
    "local compile-profile deployment graph proof"
  );
  const {
    deploymentGraph: _deploymentGraph,
    inventory: _inventory,
    ...profileIdentityWithoutProof
  } = profile.identity;
  const identity = freezeJsonValue(
    structuredClone({
      ...profileIdentityWithoutProof,
      dependencyGraphSha256: requireSha256(
        deploymentGraph.dependencyGraphSha256,
        "local compile-profile dependency graph SHA-256"
      ),
    })
  );
  return Object.freeze({
    identity,
    kind: LOCAL_PROFILE_KIND,
    sha256: fingerprintJson(identity),
  });
}

async function buildCompileProfileInSession(entryPath, selectedExportNames, session) {
  const {
    analyzeRegistrationInput,
    cacheErasureProof,
    deploymentGraphSession,
    inventory,
    mode: selectedMode,
    normalizedRoot,
    normalizedToolchainRoot,
    readMaterial,
    runStage,
  } = session;
  session.assertOpen();
  session.assertFixedInputs();
  const buildOptions = compileProfileBuildOptions(selectedMode);
  validateEntryPath(normalizedRoot, entryPath);
  const selection = selectedEntryCohort(inventory, entryPath, selectedExportNames);
  const fullEntryInventoryIdentity = canonicalJson(selectedEntryCohort(inventory, entryPath));
  const selectedRouteExportNames = selection.routes.map(({ exportName }) => exportName);
  const virtualEntry = virtualEntrySource(selection.selectedEntry, selection.routes, selectedMode);
  const loaded = await runStage("toolchain", entryPath, async () => session.loadToolchain());
  const materialsByAbsolutePath = new Map();
  const fixedTransformedSources = new Map();
  const transformedSourceIdentities = new Map();
  const rejectedSourcePaths = new Set();
  if (selectedMode === convexWasmCompileProfileTargetAdapterMode) {
    const targetZodJitless = requireObject(loaded.targetZodJitless, "target Zod jitless transform");
    const expectedIdentity = targetZodJitlessIdentity(loaded.materials);
    if (canonicalJson(targetZodJitless.identity) !== canonicalJson(expectedIdentity)) {
      fail("target Zod jitless transform identity changed after authentication");
    }
    fixedTransformedSources.set(targetZodJitless.absolutePath, targetZodJitless.contents);
    transformedSourceIdentities.set(targetZodJitless.absolutePath, expectedIdentity);
    rejectedSourcePaths.add(targetZodJitless.commonJsAbsolutePath);
  }
  const build = (sourcePlugin, applicationModulePlugin) =>
    loaded.esbuild.build({
      absWorkingDir: normalizedRoot,
      ...buildOptions,
      logLevel: "silent",
      plugins: [
        sourcePlugin,
        ...(applicationModulePlugin === undefined ? [] : [applicationModulePlugin]),
        ...(selectedMode === convexWasmCompileProfileTargetAdapterMode
          ? [targetAdapterPlugin(normalizedToolchainRoot)]
          : []),
        asyncHooksShimPlugin(selectedMode),
        loaded.serverOnlyPlugin,
        noExternalPackagesPlugin(),
        loaded.wasmPlugin,
      ],
      stdin: {
        contents: virtualEntry,
        loader: "js",
        resolveDir: normalizedRoot,
        sourcefile: VIRTUAL_ENTRY_PATH,
      },
    });
  const initialResult = await runStage("initial-build", entryPath, async () => {
    const key = fingerprintJson({
      buildOptions,
      entryPath,
      inventory: selection.inventory,
      mode: selectedMode,
      plugins: pluginIdentity(loaded.materials, selectedMode, loaded.toolchain),
      repoRoot: normalizedRoot,
      toolchain: loaded.toolchain,
      toolchainRoot: normalizedToolchainRoot,
      virtualEntry: {
        sha256: sha256(virtualEntry),
        size: Buffer.byteLength(virtualEntry),
      },
    });
    return session.loadInitialBundle(key, materialsByAbsolutePath, async () => {
      session.recordBuild("initial");
      return build(
        sourceMaterialPlugin(
          materialsByAbsolutePath,
          fixedTransformedSources,
          readMaterial,
          rejectedSourcePaths
        )
      );
    });
  });
  if (initialResult.errors.length !== 0 || initialResult.warnings.length !== 0) {
    fail(
      `installed esbuild returned ${initialResult.errors.length} errors and ${initialResult.warnings.length} warnings without rejecting the initial build`
    );
  }
  if (selectedMode === convexWasmCompileProfileTargetAdapterMode) {
    // esbuild resolves a define replacement through a same-named local binding, so reject that
    // binding from every input in the selected graph before target transforms or runtime checks.
    assertTargetApplicationGlobalBindingIsReserved({
      materialsByAbsolutePath,
      metafile: initialResult.metafile,
      repoRoot: normalizedRoot,
      typescript: loaded.typescript,
    });
  }
  const registrationTransforms =
    selectedMode === convexWasmCompileProfileTargetAdapterMode
      ? await runStage("registration-analysis", entryPath, async () =>
          targetRegistrationTransforms({
            analyzeRegistrationInput,
            analyzeSource: createConvexWasmRegistrationSourceAnalyzer(loaded.typescript),
            analyzerIdentity: {
              implementation: loaded.materials["registration-analysis/source-analyzer"],
              packageManifest: loaded.materials["registration-analysis/typescript/package.json"],
              runtime: loaded.materials["registration-analysis/typescript/runtime.js"],
              version: loaded.toolchain.typescript,
            },
            materialsByAbsolutePath,
            metafile: initialResult.metafile,
            repoRoot: normalizedRoot,
            typescript: loaded.typescript,
          })
        )
      : new Map();
  const transformedSources = new Map(fixedTransformedSources);
  for (const [path, source] of registrationTransforms) {
    if (transformedSources.has(path)) {
      fail(`multiple target source transforms selected ${path}`);
    }
    transformedSources.set(path, source);
  }
  const safeApplicationModules =
    selectedMode === convexWasmCompileProfileTargetAdapterMode
      ? await runStage("registration-analysis", entryPath, async () =>
          sideEffectFreeApplicationModules({
            esbuild: loaded.esbuild,
            materialsByAbsolutePath,
            metafile: initialResult.metafile,
            mode: selectedMode,
            readMaterial,
            rejectedSourcePaths,
            repoRoot: normalizedRoot,
            serverOnlyPlugin: loaded.serverOnlyPlugin,
            toolchainRoot: normalizedToolchainRoot,
            transformedSources,
            typescript: loaded.typescript,
            wasmPlugin: loaded.wasmPlugin,
          })
        )
      : new Set();
  const result = await runStage("transformed-build", entryPath, async () => {
    session.recordBuild("transformed");
    return build(
      sourceMaterialPlugin(
        materialsByAbsolutePath,
        transformedSources,
        readMaterial,
        rejectedSourcePaths
      ),
      selectedMode === convexWasmCompileProfileTargetAdapterMode
        ? sideEffectFreeApplicationModulesPlugin({
            metafile: initialResult.metafile,
            repoRoot: normalizedRoot,
            safeInputPaths: safeApplicationModules,
          })
        : undefined
    );
  });
  if (result.errors.length !== 0 || result.warnings.length !== 0) {
    fail(
      `installed esbuild returned ${result.errors.length} errors and ${result.warnings.length} warnings without rejecting the build`
    );
  }
  const inputs = await runStage("input-identity", entryPath, async () =>
    inputIdentity({
      cacheErasureProof,
      esbuild: loaded.esbuild,
      materialsByAbsolutePath,
      metafile: result.metafile,
      mode: selectedMode,
      repoRoot: normalizedRoot,
      transformedSources,
      transformedSourceIdentities,
      toolchainRoot: normalizedToolchainRoot,
      virtualEntry,
    })
  );
  for (const [name, path] of inputs.materialPaths) {
    const material = await readMaterial(path);
    loaded.materials[`resolved/${name}`] = { sha256: material.sha256, size: material.size };
    loaded.materialPaths.set(`resolved/${name}`, path);
  }
  for (const path of [...inputs.materialPaths.values()]) {
    const manifestPath = resolvedPackageManifestPath(path);
    if (manifestPath === undefined) {
      continue;
    }
    const name = `resolution/${normalizedMaterialPath(
      normalizedRoot,
      normalizedToolchainRoot,
      manifestPath
    )}`;
    if (loaded.materialPaths.has(name)) {
      continue;
    }
    const material = await readMaterial(manifestPath);
    loaded.materials[name] = { sha256: material.sha256, size: material.size };
    loaded.materialPaths.set(name, manifestPath);
  }
  const outputs = outputIdentity(result);
  const comparison = await runStage("deployment-comparison", entryPath, async () =>
    deploymentComparison(
      deploymentGraphSession,
      selection.selectedEntry,
      inputs.inputs,
      loaded.toolchain,
      selectedMode
    )
  );
  const identity = {
    inputs: inputs.inputs,
    inventory: selection.inventory,
    kind: PROFILE_IDENTITY_KIND,
    metafileSha256: fingerprintJson(result.metafile),
    mode: selectedMode,
    options: buildOptions,
    optionsSha256: fingerprintJson(buildOptions),
    output: outputs.output,
    plugins: pluginIdentity(loaded.materials, selectedMode, loaded.toolchain),
    ...(comparison === undefined ? {} : { deploymentGraph: comparison }),
    routes: selection.routes,
    selectedEntry: selection.selectedEntry,
    toolchain: {
      materials: Object.fromEntries(
        Object.entries(loaded.materials).sort(([left], [right]) => compareStrings(left, right))
      ),
      versions: loaded.toolchain,
    },
  };
  const selectedInventoryIdentity = canonicalJson(selection);
  const verifyEntry = async () => {
    if (
      canonicalJson(selectedEntryCohort(inventory, entryPath)) !== fullEntryInventoryIdentity ||
      canonicalJson(selectedEntryCohort(inventory, entryPath, selectedRouteExportNames)) !==
        selectedInventoryIdentity
    ) {
      fail("selected entry inventory metadata changed after the compile-profile build");
    }
    if (deploymentGraphSession !== undefined) {
      const currentComparison = deploymentComparison(
        deploymentGraphSession,
        selection.selectedEntry,
        inputs.inputs,
        loaded.toolchain,
        selectedMode
      );
      if (canonicalJson(currentComparison) !== canonicalJson(identity.deploymentGraph)) {
        fail("selected entry deployment graph changed after the compile-profile build");
      }
    }
    session.assertFixedInputs();
  };
  const verifyMaterials = async () => {
    await session.verifyMaterialUnion(true);
    await verifyEntry();
  };
  const profile = {
    identity,
    javascript: outputs.javascript,
    kind: PROFILE_KIND,
    metafile: result.metafile,
    sha256: fingerprintJson(identity),
    sourceMap: outputs.sourceMap,
    verifyMaterials,
  };
  authenticateConvexWasmCompileProfile(profile);
  if (session.requiresImmediateProfileVerification) await verifyEntry();
  session.registerProfileVerification(verifyEntry);
  session.recordProfile(profile);
  return profile;
}

const PROFILE_SESSION_KIND = "convex-wasm-compile-profile-session-v1";
export const convexWasmCompileProfileDefaultBuildConcurrency =
  6;
export const convexWasmCompileProfileSessionCacheRetention = Object.freeze({
  activeBuild: "active-build",
  session: "session",
});
const compileProfileSessions = new WeakSet();
const PROFILE_SESSION_STAGES = new Set([
  "deployment-comparison",
  "initial-build",
  "input-identity",
  "material-verification",
  "registration-analysis",
  "toolchain",
  "transformed-build",
]);

export function authenticateConvexWasmCompileProfileSession(session) {
  if (!compileProfileSessions.has(session) || session.kind !== PROFILE_SESSION_KIND) {
    fail("compile-profile session is invalid");
  }
  return session;
}

function deploymentSessionIdentity(deploymentGraphSession) {
  if (deploymentGraphSession === undefined) return null;
  requireObject(deploymentGraphSession, "deployment graph session");
  const graphs = deploymentGraphSession.dependencyGraphByEntry;
  if (!(graphs instanceof Map)) {
    fail("deployment graph session has no entry graph map");
  }
  return canonicalJson({
    ...(deploymentGraphSession.deploymentOutputMetafileSha256 === undefined
      ? {}
      : {
          deploymentOutputMetafileSha256: deploymentGraphSession.deploymentOutputMetafileSha256,
        }),
    entries: [...graphs]
      .map(([entryPath, graph]) => ({
        entryPath,
        sha256: graph?.sha256,
      }))
      .sort((left, right) => compareStrings(left.entryPath, right.entryPath)),
    ...(deploymentGraphSession.graphSha256 === undefined
      ? {}
      : { graphSha256: deploymentGraphSession.graphSha256 }),
    toolchain: deploymentGraphSession.toolchain,
  });
}

export function createConvexWasmCompileProfileSession({
  deploymentGraphSession,
  inventory,
  mode,
  onOperationalEvent,
  profileCache,
  profileBuildConcurrency = convexWasmCompileProfileDefaultBuildConcurrency,
  repoRoot,
  sessionCacheRetention = convexWasmCompileProfileSessionCacheRetention.session,
  sourceConfigurationPaths,
  toolchainRoot = repoRoot,
}) {
  const selectedMode = requireProfileMode(mode);
  const normalizedRoot = resolve(repoRoot);
  const normalizedToolchainRoot = resolve(toolchainRoot);
  const packageSet = resolveConvexWasmApplicationPackageSet(normalizedToolchainRoot);
  if (!Array.isArray(sourceConfigurationPaths)) {
    fail("source configuration paths must be an array");
  }
  const normalizedSourceConfigurationPaths = Object.freeze(
    sourceConfigurationPaths
      .map((path) => {
        validateEntryPath(normalizedRoot, path, "source configuration path");
        if (path === "package.json" || path === "package-lock.json") {
          fail(`source configuration path ${path} duplicates a required package file`);
        }
        return path;
      })
      .sort(compareStrings)
  );
  if (
    normalizedSourceConfigurationPaths.some(
      (path, index) => index > 0 && normalizedSourceConfigurationPaths[index - 1] === path
    )
  ) {
    fail("source configuration paths must be unique");
  }
  requireObject(inventory, "generated API inventory");
  if (onOperationalEvent !== undefined && typeof onOperationalEvent !== "function") {
    fail("compile-profile operational observer must be a function");
  }
  requirePositiveInteger(profileBuildConcurrency, "profile-build concurrency");
  if (
    !Object.values(convexWasmCompileProfileSessionCacheRetention).includes(sessionCacheRetention)
  ) {
    fail("compile-profile session cache retention is invalid");
  }
  const normalizedProfileCache = normalizeProfileCacheConfig(profileCache, deploymentGraphSession);
  const inventoryIdentity = fingerprintJson(inventory);
  const fixedDeploymentIdentity = deploymentSessionIdentity(deploymentGraphSession);
  const caches = {
    erasureProof: new Map(),
    initialBundle: new Map(),
    material: new Map(),
    registrationAnalysis: new Map(),
    toolchain: new Map(),
  };
  const metrics = {
    builds: {
      erasureProof: 0,
      initial: 0,
      profiles: 0,
      transformed: 0,
    },
    caches: Object.fromEntries(
      Object.keys(caches).map((name) => [name, { coalesced: 0, hits: 0, misses: 0 }])
    ),
  };
  const materialExpectations = new Map();
  const ownedProfiles = new WeakSet();
  const profileBuildQueue = [];
  const profileVerifiers = [];
  const persistentCacheMetrics = {
    enabled: normalizedProfileCache !== undefined,
    hits: 0,
    misses: 0,
    publications: 0,
  };
  let activeBuilds = 0;
  let activeProfileRequests = 0;
  let closed = false;
  let invalidated = false;
  let materialRevision = 0;
  let maximumActiveBuilds = 0;
  let maximumQueuedBuilds = 0;
  let profileBuildFailure;
  let profileCacheReady;
  let rejectedQueuedBuilds = 0;
  let totalQueuedBuilds = 0;
  let verifiedMaterialRevision = -1;
  let verificationRecord;

  function metricsSnapshot() {
    return {
      builds: { ...metrics.builds },
      caches: Object.fromEntries(
        Object.entries(metrics.caches).map(([name, counts]) => [name, { ...counts }])
      ),
      persistentCache: { ...persistentCacheMetrics },
      scheduling: {
        activeProfileBuilds: activeBuilds,
        failed: profileBuildFailure !== undefined,
        maximumActiveProfileBuilds: maximumActiveBuilds,
        maximumQueuedProfileBuilds: maximumQueuedBuilds,
        profileBuildConcurrency,
        queuedProfileBuilds: profileBuildQueue.length,
        rejectedQueuedProfileBuilds: rejectedQueuedBuilds,
        totalQueuedProfileBuilds: totalQueuedBuilds,
      },
    };
  }

  async function emit(event) {
    await onOperationalEvent?.(Object.freeze({ ...event, metrics: metricsSnapshot() }));
  }

  async function runStage(stage, entryPath, callback) {
    if (!PROFILE_SESSION_STAGES.has(stage) || typeof callback !== "function") {
      fail("compile-profile session stage is invalid");
    }
    await emit({ entryPath, stage, type: "start" });
    try {
      return await callback();
    } finally {
      await emit({ entryPath, stage, type: "finish" });
    }
  }

  async function cached(cacheName, key, compute) {
    const cache = caches[cacheName];
    const existing = cache.get(key);
    if (existing !== undefined) {
      metrics.caches[cacheName][existing.pending ? "coalesced" : "hits"] += 1;
      return existing.promise;
    }
    metrics.caches[cacheName].misses += 1;
    const record = { pending: true };
    record.promise = Promise.resolve().then(compute);
    cache.set(key, record);
    try {
      const value = await record.promise;
      record.pending = false;
      return value;
    } catch (error) {
      if (cache.get(key) === record) cache.delete(key);
      throw error;
    }
  }

  function evictSettledActiveBuildCaches() {
    if (
      sessionCacheRetention !== convexWasmCompileProfileSessionCacheRetention.activeBuild ||
      activeProfileRequests !== 0
    ) {
      return;
    }
    for (const [cacheName, cache] of Object.entries(caches)) {
      if (cacheName === "toolchain") continue;
      for (const [key, record] of cache) {
        if (!record.pending) cache.delete(key);
      }
    }
  }

  function assertOpen() {
    if (closed) fail("compile-profile session is finalized");
    if (profileBuildFailure !== undefined) throw profileBuildFailure.error;
    if (invalidated) fail("compile-profile session material changed");
  }

  function rejectQueuedProfileBuilds(error) {
    const queued = profileBuildQueue.splice(0);
    rejectedQueuedBuilds += queued.length;
    for (const record of queued) record.reject(error);
  }

  function drainProfileBuildQueue() {
    while (
      profileBuildFailure === undefined &&
      activeBuilds < profileBuildConcurrency &&
      profileBuildQueue.length !== 0
    ) {
      const record = profileBuildQueue.shift();
      activeBuilds += 1;
      maximumActiveBuilds = Math.max(maximumActiveBuilds, activeBuilds);
      Promise.resolve()
        .then(record.build)
        .then(
          (profile) => {
            activeBuilds -= 1;
            if (profileBuildFailure === undefined) {
              record.resolve(profile);
              drainProfileBuildQueue();
            } else {
              record.reject(profileBuildFailure.error);
            }
          },
          (error) => {
            activeBuilds -= 1;
            if (profileBuildFailure === undefined) {
              profileBuildFailure = { error };
              rejectQueuedProfileBuilds(error);
            }
            record.reject(profileBuildFailure.error);
          }
        );
    }
  }

  function scheduleProfileBuild(build) {
    assertOpen();
    return new Promise((resolveBuild, rejectBuild) => {
      if (activeBuilds >= profileBuildConcurrency || profileBuildQueue.length !== 0) {
        totalQueuedBuilds += 1;
      }
      profileBuildQueue.push({ build, reject: rejectBuild, resolve: resolveBuild });
      drainProfileBuildQueue();
      maximumQueuedBuilds = Math.max(maximumQueuedBuilds, profileBuildQueue.length);
    });
  }

  function assertFixedInputs() {
    if (
      fingerprintJson(inventory) !== inventoryIdentity ||
      deploymentSessionIdentity(deploymentGraphSession) !== fixedDeploymentIdentity
    ) {
      invalidated = true;
      fail("compile-profile session inputs changed");
    }
  }

  function registerMaterial(path, material) {
    const expected = materialExpectations.get(path);
    if (
      expected !== undefined &&
      (expected.sha256 !== material.sha256 || expected.size !== material.size)
    ) {
      invalidated = true;
      fail(`compile-profile session material ${path} changed identity`);
    }
    if (expected === undefined) {
      materialExpectations.set(path, { sha256: material.sha256, size: material.size });
      materialRevision += 1;
    }
  }

  async function readMaterial(path) {
    assertOpen();
    const absolutePath = resolve(path);
    const hadCached = caches.material.has(absolutePath);
    const cachedMaterial = await cached("material", absolutePath, async () => {
      const material = await readStableFile(absolutePath);
      return Object.freeze({
        contents: Buffer.from(material.contents),
        sha256: material.sha256,
        size: material.size,
        state: Object.freeze({ ...material.state }),
      });
    });
    if (hadCached) {
      const current = await fs.stat(absolutePath, { bigint: true });
      if (!current.isFile() || !sameFileState(cachedMaterial.state, current)) {
        invalidated = true;
        fail(`compile-profile session material ${absolutePath} changed after authentication`);
      }
    }
    registerMaterial(absolutePath, cachedMaterial);
    return {
      contents: Buffer.from(cachedMaterial.contents),
      sha256: cachedMaterial.sha256,
      size: cachedMaterial.size,
    };
  }

  async function loadSessionToolchain() {
    assertOpen();
    const key = fingerprintJson({
      arch: process.arch,
      mode: selectedMode,
      platform: process.platform,
      repoRoot: normalizedRoot,
      toolchainRoot: normalizedToolchainRoot,
      packageSet,
      sourceConfigurationPaths: normalizedSourceConfigurationPaths,
    });
    const loaded = await cached("toolchain", key, async () => {
      const value = await loadToolchain(
        normalizedRoot,
        normalizedToolchainRoot,
        selectedMode,
        normalizedSourceConfigurationPaths,
        readMaterial
      );
      const materialPaths = [...value.materialPaths].map((entry) => Object.freeze(entry));
      const materials = Object.fromEntries(
        Object.entries(value.materials).map(([name, material]) => [
          name,
          Object.freeze({ ...material }),
        ])
      );
      return Object.freeze({
        ...value,
        materialPaths: Object.freeze(materialPaths),
        materials: Object.freeze(materials),
        toolchain: Object.freeze({ ...value.toolchain }),
      });
    });
    return {
      ...loaded,
      materialPaths: new Map(loaded.materialPaths),
      materials: Object.fromEntries(
        Object.entries(loaded.materials).map(([name, material]) => [name, { ...material }])
      ),
      toolchain: { ...loaded.toolchain },
    };
  }

  async function loadInitialBundle(key, materialsByAbsolutePath, compute) {
    const snapshot = await cached("initialBundle", key, async () => {
      const result = await compute();
      if (result.errors.length !== 0 || result.warnings.length !== 0) {
        fail(
          `installed esbuild returned ${result.errors.length} errors and ${result.warnings.length} warnings without rejecting the initial build`
        );
      }
      const materials = [...materialsByAbsolutePath]
        .map(([path, material]) =>
          Object.freeze({ path, sha256: material.sha256, size: material.size })
        )
        .sort((left, right) => compareStrings(left.path, right.path));
      return Object.freeze({
        materials: Object.freeze(materials),
        metafile: structuredClone(result.metafile),
      });
    });
    for (const expected of snapshot.materials) {
      const material = await readMaterial(expected.path);
      if (material.sha256 !== expected.sha256 || material.size !== expected.size) {
        invalidated = true;
        fail(`compile-profile initial bundle material ${expected.path} changed identity`);
      }
      materialsByAbsolutePath.set(expected.path, material);
    }
    return { errors: [], metafile: structuredClone(snapshot.metafile), warnings: [] };
  }

  async function verifyMaterialUnion(force = false) {
    const revision = materialRevision;
    if (!force && verifiedMaterialRevision === revision) return;
    if (verificationRecord?.revision === revision) return verificationRecord.promise;
    const record = { revision };
    record.promise = (async () => {
      for (const [path, expected] of [...materialExpectations].sort(([left], [right]) =>
        compareStrings(left, right)
      )) {
        const current = await readStableFile(path);
        if (current.sha256 !== expected.sha256 || current.size !== expected.size) {
          invalidated = true;
          fail(`compile-profile session material ${path} changed after the compile-profile build`);
        }
      }
      verifiedMaterialRevision = revision;
    })();
    verificationRecord = record;
    try {
      await record.promise;
    } catch (error) {
      if (verificationRecord === record) verificationRecord = undefined;
      throw error;
    }
    if (verificationRecord === record) verificationRecord = undefined;
  }

  const context = {
    analyzeRegistrationInput: (key, compute) => cached("registrationAnalysis", key, compute),
    assertFixedInputs,
    assertOpen,
    cacheErasureProof: (key, compute) =>
      cached("erasureProof", key, async () => {
        metrics.builds.erasureProof += 1;
        return compute();
      }),
    deploymentGraphSession,
    inventory,
    loadInitialBundle,
    loadToolchain: loadSessionToolchain,
    mode: selectedMode,
    normalizedRoot,
    normalizedToolchainRoot,
    readMaterial,
    recordBuild(kind) {
      metrics.builds[kind] += 1;
    },
    recordProfile(profile) {
      ownedProfiles.add(profile);
      metrics.builds.profiles += 1;
    },
    registerProfileVerification(verifier) {
      if (sessionCacheRetention === convexWasmCompileProfileSessionCacheRetention.session) {
        profileVerifiers.push(verifier);
      }
    },
    // Active-build callers verify this entry before returning it. Retaining its verifier would
    // retain the full per-entry input identity; final session verification still authenticates
    // the fixed inventory/deployment identities and every material read during every build.
    requiresImmediateProfileVerification:
      sessionCacheRetention === convexWasmCompileProfileSessionCacheRetention.activeBuild,
    runStage,
    verifyMaterialUnion,
  };

  async function cachedOrBuildProfile(entryPath, exportNames) {
    if (normalizedProfileCache === undefined) {
      return scheduleProfileBuild(() =>
        buildCompileProfileInSession(entryPath, exportNames, context)
      );
    }
    assertOpen();
    assertFixedInputs();
    validateEntryPath(normalizedRoot, entryPath);
    const selection = selectedEntryCohort(inventory, entryPath, exportNames);
    const virtualEntry = virtualEntrySource(
      selection.selectedEntry,
      selection.routes,
      selectedMode
    );
    const loaded = await runStage("toolchain", entryPath, async () => loadSessionToolchain());
    const keyIdentity = persistentProfileKeyIdentity({
      deploymentGraphSession,
      loaded,
      mode: selectedMode,
      producerSha256: normalizedProfileCache.producerSha256,
      selection,
      virtualEntry,
    });
    const cacheKey = fingerprintJson(keyIdentity);
    profileCacheReady ??= ensureProfileCacheDirectory(normalizedProfileCache);
    await profileCacheReady;
    const cached = await readProfileCacheEntry(normalizedProfileCache, cacheKey, keyIdentity);
    if (cached !== undefined) {
      persistentCacheMetrics.hits += 1;
      return rebindCachedCompileProfile({
        cached,
        deploymentGraphSession,
        entryPath,
        inventory,
        loaded,
        selectedExportNames: exportNames,
        session: context,
      });
    }
    persistentCacheMetrics.misses += 1;
    return scheduleProfileBuild(async () => {
      const concurrentWinner = await readProfileCacheEntry(
        normalizedProfileCache,
        cacheKey,
        keyIdentity
      );
      if (concurrentWinner !== undefined) {
        persistentCacheMetrics.hits += 1;
        return rebindCachedCompileProfile({
          cached: concurrentWinner,
          deploymentGraphSession,
          entryPath,
          inventory,
          loaded,
          selectedExportNames: exportNames,
          session: context,
        });
      }
      const profile = await buildCompileProfileInSession(entryPath, exportNames, context);
      await publishProfileCacheEntry(normalizedProfileCache, cacheKey, keyIdentity, profile);
      persistentCacheMetrics.publications += 1;
      return profile;
    });
  }

  const session = Object.freeze({
    async buildProfile({ entryPath, exportNames }) {
      activeProfileRequests += 1;
      try {
        return await cachedOrBuildProfile(entryPath, exportNames);
      } finally {
        activeProfileRequests -= 1;
        evictSettledActiveBuildCaches();
      }
    },
    async finish() {
      if (closed) fail("compile-profile session is finalized");
      if (activeProfileRequests !== 0 || activeBuilds !== 0 || profileBuildQueue.length !== 0) {
        fail("compile-profile session cannot finalize while profile builds are active or queued");
      }
      if (profileBuildFailure !== undefined) throw profileBuildFailure.error;
      if (invalidated) fail("compile-profile session material changed");
      assertFixedInputs();
      closed = true;
      await runStage("material-verification", undefined, async () => {
        await verifyMaterialUnion();
        assertFixedInputs();
        for (const verifyProfile of profileVerifiers) await verifyProfile();
      });
      return metricsSnapshot();
    },
    getMetrics: metricsSnapshot,
    kind: PROFILE_SESSION_KIND,
    ownsProfile(profile) {
      return (
        ((typeof profile === "object" && profile !== null) || typeof profile === "function") &&
        ownedProfiles.has(profile)
      );
    },
    verifyMaterials: () => verifyMaterialUnion(true),
  });
  compileProfileSessions.add(session);
  return session;
}

export async function buildConvexWasmCompileProfile(options) {
  const session = createConvexWasmCompileProfileSession(options);
  const profile = await session.buildProfile({
    entryPath: options.entryPath,
    exportNames: options.exportNames,
  });
  await session.finish();
  await profile.verifyMaterials();
  return profile;
}

export const convexWasmCompileProfileBuildOptions = BUILD_OPTIONS;
