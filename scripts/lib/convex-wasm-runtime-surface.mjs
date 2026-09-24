import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import ts from "typescript";

import {
  assertConvexWasmQueryMutationVisibleDeterministicGlobals,
  convexWasmAdmittedStaticHermesGlobals,
  convexWasmApplicationGlobalFacadeEngineGlobals,
  convexWasmRoutingEligibleStaticHermesGlobals,
  convexWasmSharedRuntimeSupportGlobals,
  convexWasmStaticHermesGlobalInventory,
  convexWasmStaticHermesGlobalInventorySha256,
  convexWasmStaticHermesGlobalSemantics,
} from "./convex-wasm-static-hermes-engine-globals.mjs";
import {
  convexWasmRuntimeSupportIdentity,
  convexWasmRuntimeSupportIdentitySha256,
} from "./convex-wasm-runtime-support.mjs";

const POLICY_KIND = "convex-wasm-target-runtime-surface-policy-v11";
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const VIRTUAL_SOURCE_PATH = "/convex-wasm-target-compile-profile.js";
export const convexWasmApplicationGlobalThisBinding = "__convexWasmApplicationGlobalThis";
export const convexWasmApplicationInstallRuntimeSupportBinding =
  "__convexWasmApplicationInstallRuntimeSupport";
export const convexWasmApplicationPublishCompileProfileBinding =
  "__convexWasmApplicationPublishCompileProfile";
export const convexWasmApplicationReportThrownBinding = "__convexWasmApplicationReportThrown";
const applicationInitializationHandoffBindings = new Set([
  convexWasmApplicationGlobalThisBinding,
  convexWasmApplicationInstallRuntimeSupportBinding,
  convexWasmApplicationPublishCompileProfileBinding,
  convexWasmApplicationReportThrownBinding,
]);
const databaseUdfTimerGlobals = Object.freeze([
  "clearInterval",
  "clearTimeout",
  "setInterval",
  "setTimeout",
]);

const gapDefinitions = Object.freeze({
  "async-hooks-adapter": Object.freeze({
    layer: "adapter",
    reason:
      "The target adapter does not expose Node AsyncLocalStorage or AsyncResource to database UDFs.",
  }),
  "ambient-global-unavailable": Object.freeze({
    layer: "engine",
    reason: "The target does not expose this ambient global to application code.",
  }),
  "ambient-global-write": Object.freeze({
    layer: "adapter",
    reason: "Application code cannot replace or mutate an admitted ambient global binding.",
  }),
  "ambient-global-rejected": Object.freeze({
    layer: "engine",
    reason: "The reviewed target policy rejects this engine global.",
  }),
  "raw-global-object-flow": Object.freeze({
    layer: "adapter",
    reason: "Compile-profile output cannot retain a reference to the raw engine global object.",
  }),
  "reserved-initialization-handoff": Object.freeze({
    layer: "adapter",
    reason: "Application source cannot bind or reference a host-owned initialization handoff.",
  }),
  "math-ambient-object-flow": Object.freeze({
    layer: "adapter",
    reason: "The complete Math object cannot flow through application values.",
  }),
  "math-computed-member": Object.freeze({
    layer: "adapter",
    reason: "A dynamic computed Math member cannot be authenticated by the target adapter.",
  }),
  "performance-runtime": Object.freeze({
    layer: "runtime",
    reason: "The invocation performance capability is unavailable during bundle evaluation.",
  }),
  "sdk-retained-context-isolation": Object.freeze({
    layer: "runtime",
    reason:
      "The process-global SDK facade cannot distinguish a context method retained by invocation N when application code calls it during invocation N+1.",
  }),
});

const implementedAmbientGlobals = convexWasmRoutingEligibleStaticHermesGlobals;
const implementedAmbientGlobalSet = new Set([
  ...implementedAmbientGlobals,
  ...databaseUdfTimerGlobals,
  "Convex",
  "crypto",
  "console",
  "performance",
  "process",
]);
const routingEligibleAmbientGlobalSet = new Set(convexWasmRoutingEligibleStaticHermesGlobals);
const deterministicWebRuntimeSupportGlobals = Object.freeze(
  convexWasmSharedRuntimeSupportGlobals.filter(
    (name) =>
      convexWasmStaticHermesGlobalInventory.semantics[name].class === "deterministic-web-like"
  )
);
assertConvexWasmQueryMutationVisibleDeterministicGlobals(
  [
    ...convexWasmApplicationGlobalFacadeEngineGlobals,
    ...convexWasmSharedRuntimeSupportGlobals,
  ].sort()
);
const namedGlobalGaps = new Map([
  ...[...convexWasmStaticHermesGlobalSemantics]
    .filter(([, semantic]) => semantic.read.state !== "admitted")
    .map(([name, semantic]) => [
      name,
      semantic.read.state === "gap" ? semantic.read.gap : "ambient-global-rejected",
    ]),
]);

function normalizeJson(value) {
  if (Array.isArray(value)) return value.map(normalizeJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, normalizeJson(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(normalizeJson(value));
}

function freezeJson(value) {
  if (Array.isArray(value)) {
    for (const entry of value) freezeJson(entry);
  } else if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) freezeJson(entry);
  }
  return Object.freeze(value);
}

export const convexWasmTargetRuntimeSurfacePolicy = freezeJson({
  ambientGlobals: implementedAmbientGlobals.map((name) => ({
    implementation: convexWasmStaticHermesGlobalInventory.semantics[name].provider,
    name,
    routingEligible: routingEligibleAmbientGlobalSet.has(name),
    semanticClass: convexWasmStaticHermesGlobalInventory.semantics[name].class,
    state: "implemented",
  })),
  date: {
    ambientObjectFlow: {
      implementation: "native-date-proxy-facade",
      state: "implemented",
    },
    construction: {
      explicitArguments: {
        implementation: "pinned-static-hermes-reflect-construct",
        state: "implemented",
      },
      spreadArguments: {
        implementation: "runtime-arity-native-date-proxy",
        state: "implemented",
      },
      zeroArguments: {
        implementation: "invocation-timestamp-then-pinned-static-hermes-reflect-construct",
        state: "implemented",
      },
    },
    functionCall: {
      argumentEvaluation: "native-javascript-call-site",
      implementation: "invocation-timestamp-native-date-string",
      state: "implemented",
    },
    now: {
      capabilityGuardHostImport: "convex_capability_current",
      hostImport: "convex_invocation_unix_timestamp_ms",
      implementation: "stable-frozen-invocation-capability-function",
      state: "implemented",
    },
    prototypeAndStaticMembers: {
      implementation: "pinned-static-hermes-engine",
      state: "implemented",
    },
  },
  console: {
    formatting: {
      browserBundleSha256: convexWasmRuntimeSupportIdentity.browserBundleSha256,
      customInspect: true,
      implementation: "shared-untyped-runtime-support-bundle",
      indent: 2,
      installation: "one-time-hidden-bridge-handoff",
      maximumStringCodeUnits: 32_768,
      package: "object-inspect@1.13.4",
      sourceSha256: "9aad508be54fbe29d82145d54352e7a19c01e19b70e1202b0123449fe9afcde6",
      state: "implemented",
    },
    hostImport: "convex_console_message",
    implementation: "frozen-invocation-capability-facade",
    levels: ["debug", "error", "info", "log", "warn"],
    state: "implemented",
  },
  convexSdkFacade: {
    implementation: "frozen-closed-capability-request-facade",
    methods: ["asyncSyscall", "jsSyscall", "syscall"],
    moduleInitializationAuthority: false,
    retainedContextIsolation: {
      gap: "sdk-retained-context-isolation",
      state: "gap",
    },
    state: "implemented",
  },
  gaps: gapDefinitions,
  globalObject: {
    application: {
      adapterGlobals: databaseUdfTimerGlobals,
      capabilityGlobals: ["Convex", "Date", "console", "crypto", "performance", "process"],
      engineGlobals: convexWasmApplicationGlobalFacadeEngineGlobals,
      implementation: "inventory-derived-extensible-null-prototype-immutable-builtins-facade",
      runtimeSupportGlobals: convexWasmSharedRuntimeSupportGlobals,
      selfReference: "globalThis",
      state: "implemented",
    },
    bridge: { implementation: "pinned-static-hermes-engine", state: "implemented" },
    rawApplicationFlow: { gap: "raw-global-object-flow", state: "gap" },
  },
  environment: {
    process: {
      environment: {
        implementation: "invocation-capability-proxy",
        missingValue: "undefined",
        state: "implemented",
      },
      implementation: "frozen-process-env-only",
      state: "implemented",
    },
  },
  globalInventory: {
    kind: convexWasmStaticHermesGlobalInventory.kind,
    sha256: convexWasmStaticHermesGlobalInventorySha256,
  },
  intl: {
    dateTimeFormat: {
      calendar: "gregory",
      defaultTimeZone: "UTC",
      fields: {
        day: ["numeric", "2-digit"],
        hour: ["numeric", "2-digit"],
        minute: ["numeric", "2-digit"],
        month: ["numeric", "2-digit"],
        second: ["numeric", "2-digit"],
        weekday: ["short"],
        year: ["numeric", "2-digit"],
      },
      hourCycle: "h23",
      methods: ["format", "formatToParts", "resolvedOptions"],
      numberingSystem: "latn",
    },
    implementation: "shared-untyped-runtime-support-bundle",
    installation: "one-time-hidden-bridge-handoff",
    locales: ["en", "en-CA", "en-US", "ru-RU"],
    numberFormat: {
      fractionDigits: [0, 2],
      methods: ["format", "resolvedOptions"],
      numberingSystem: "latn",
      style: "decimal",
    },
    runtimeSupportIdentitySha256: convexWasmRuntimeSupportIdentitySha256,
    state: "implemented",
    timeZoneData: {
      aliases: convexWasmRuntimeSupportIdentity.materials.timeZoneData.aliasCount,
      canonicalZones: convexWasmRuntimeSupportIdentity.materials.timeZoneData.canonicalZoneCount,
      dataSha256: convexWasmRuntimeSupportIdentity.materials.timeZoneData.sha256,
      licenseSha256: convexWasmRuntimeSupportIdentity.licenses["iana-tzdata@2026c"].sha256,
      sourceSha256: convexWasmRuntimeSupportIdentity.materials.timeZoneData.sourceSha256,
      version: convexWasmRuntimeSupportIdentity.materials.timeZoneData.version,
    },
    unsupportedSurface: "explicit-rejection",
  },
  kind: POLICY_KIND,
  mathRandom: {
    hostImport: "convex_math_random",
    implementation: "invocation-seeded-chacha12-stream",
    state: "implemented",
  },
  nodeAsyncHooks: { gap: "async-hooks-adapter", state: "gap" },
  permittedCrypto: {
    getRandomValues: {
      acceptedViews: [
        "BigInt64Array",
        "BigUint64Array",
        "Int8Array",
        "Int16Array",
        "Int32Array",
        "Uint8Array",
        "Uint8ClampedArray",
        "Uint16Array",
        "Uint32Array",
      ],
      hostImport: "convex_crypto_get_random_values",
      maximumBytes: 65_536,
      state: "implemented",
    },
    implementation: "frozen-webcrypto-facade",
    randomUUID: {
      hostImport: "convex_crypto_random_uuid",
      implementation: "canonical-convex-uuid-builder",
      state: "implemented",
    },
    state: "implemented",
    subtle: {
      digest: {
        algorithms: ["SHA-256"],
        hostImport: "convex_crypto_subtle_digest_sha256",
        input: "synchronously-snapshotted-buffer-source",
        result: "Promise<ArrayBuffer>",
        state: "implemented",
      },
      implementation: "frozen-subtle-crypto-facade",
      state: "implemented",
    },
  },
  performance: {
    implementation: "frozen-invocation-capability-facade",
    now: {
      capabilityRequest: "performanceNow",
      implementation: "invocation-capability-monotonic-time",
      mutation: "monotonic-elapsed-since-invocation-start",
      precisionMilliseconds: 0.1,
      query: "fixed-zero",
      state: "implemented",
    },
    state: "implemented",
  },
  timers: {
    clear: {
      implementation: "idempotent-noop-without-scheduled-timers",
      members: ["clearInterval", "clearTimeout"],
      state: "implemented",
    },
    functions: {
      constructible: false,
      extensible: false,
      implementation: "frozen-arrow-functions",
      state: "implemented",
    },
    scheduling: {
      developerErrorCode: "NoSleepInQueriesOrMutations",
      implementation: "database-udf-developer-error",
      members: ["setInterval", "setTimeout"],
      state: "implemented",
    },
  },
  webStandards: {
    globals: deterministicWebRuntimeSupportGlobals,
    implementation: "shared-untyped-runtime-support-bundle",
    installation: "one-time-hidden-bridge-handoff",
    packages: convexWasmRuntimeSupportIdentity.packages,
    runtimeSupportIdentitySha256: convexWasmRuntimeSupportIdentitySha256,
    state: "implemented",
  },
  unlistedAmbientGlobals: { gap: "ambient-global-unavailable", state: "gap" },
});

export const convexWasmTargetRuntimeSurfacePolicySha256 = createHash("sha256")
  .update(canonicalJson(convexWasmTargetRuntimeSurfacePolicy))
  .digest("hex");

const runtimeSurfacePolicyIdentity = JSON.parse(
  readFileSync(
    new URL("../convex-wasm-runtime-surface-policy-identity.json", import.meta.url),
    "utf8"
  )
);
if (
  runtimeSurfacePolicyIdentity.kind !== "convex-wasm-runtime-surface-policy-identity" ||
  runtimeSurfacePolicyIdentity.inventorySha256 !== convexWasmStaticHermesGlobalInventorySha256 ||
  runtimeSurfacePolicyIdentity.runtimeSurfacePolicySha256 !==
    convexWasmTargetRuntimeSurfacePolicySha256
) {
  throw new Error(
    `Convex Wasm runtime-surface policy identity is stale; expected ${JSON.stringify({
      inventorySha256: convexWasmStaticHermesGlobalInventorySha256,
      kind: "convex-wasm-runtime-surface-policy-identity",
      runtimeSurfacePolicySha256: convexWasmTargetRuntimeSurfacePolicySha256,
    })}.`
  );
}
export const convexWasmTargetRuntimeSurfacePolicyIdentity = freezeJson(
  runtimeSurfacePolicyIdentity
);

export class ConvexWasmTargetRuntimeSurfaceGap extends Error {
  constructor(code, surface) {
    const definition = gapDefinitions[code];
    if (definition === undefined) {
      throw new Error(`Unknown Convex Wasm target runtime surface gap ${JSON.stringify(code)}`);
    }
    super(
      `target runtime ${definition.layer} gap ${code} for ${JSON.stringify(surface)}: ${definition.reason}`
    );
    this.name = "ConvexWasmTargetRuntimeSurfaceGap";
    this.code = code;
    this.layer = definition.layer;
    this.surface = surface;
  }
}

function compilerHost(sourceFile, source) {
  return {
    fileExists: (path) => path === VIRTUAL_SOURCE_PATH,
    getCanonicalFileName: (path) => path,
    getCurrentDirectory: () => "/",
    getDefaultLibFileName: () => "",
    getNewLine: () => "\n",
    getSourceFile: (path) => (path === VIRTUAL_SOURCE_PATH ? sourceFile : undefined),
    readFile: (path) => (path === VIRTUAL_SOURCE_PATH ? source : undefined),
    useCaseSensitiveFileNames: () => true,
    writeFile() {},
  };
}

function identifierIsPropertyName(identifier) {
  const parent = identifier.parent;
  return (
    (ts.isPropertyAccessExpression(parent) && parent.name === identifier) ||
    ((ts.isPropertyAssignment(parent) ||
      ts.isMethodDeclaration(parent) ||
      ts.isGetAccessorDeclaration(parent) ||
      ts.isSetAccessorDeclaration(parent) ||
      ts.isPropertyDeclaration(parent) ||
      ts.isPropertySignature(parent) ||
      ts.isMethodSignature(parent)) &&
      parent.name === identifier) ||
    ((ts.isBreakStatement(parent) || ts.isContinueStatement(parent)) &&
      parent.label === identifier) ||
    (ts.isLabeledStatement(parent) && parent.label === identifier) ||
    (ts.isBindingElement(parent) &&
      (parent.name === identifier || parent.propertyName === identifier)) ||
    ((ts.isVariableDeclaration(parent) ||
      ts.isParameter(parent) ||
      ts.isFunctionDeclaration(parent) ||
      ts.isFunctionExpression(parent) ||
      ts.isClassDeclaration(parent) ||
      ts.isClassExpression(parent) ||
      ts.isTypeParameterDeclaration(parent) ||
      ts.isImportClause(parent) ||
      ts.isImportSpecifier(parent) ||
      ts.isNamespaceImport(parent)) &&
      parent.name === identifier)
  );
}

function unshadowedAmbientIdentifier(identifier, checker) {
  if (identifierIsPropertyName(identifier)) return false;
  const symbol = checker.resolveName(identifier.text, identifier, ts.SymbolFlags.Value, false);
  if (symbol === undefined) return true;
  return !(symbol.declarations ?? []).some(
    (declaration) =>
      ts.isVariableDeclaration(declaration) ||
      ts.isBindingElement(declaration) ||
      ts.isParameter(declaration) ||
      ts.isFunctionDeclaration(declaration) ||
      ts.isFunctionExpression(declaration) ||
      ts.isClassDeclaration(declaration) ||
      ts.isClassExpression(declaration) ||
      ts.isImportClause(declaration) ||
      ts.isImportSpecifier(declaration) ||
      ts.isNamespaceImport(declaration)
  );
}

function staticMember(expression) {
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (
    ts.isElementAccessExpression(expression) &&
    expression.argumentExpression !== undefined &&
    (ts.isStringLiteral(expression.argumentExpression) ||
      ts.isNoSubstitutionTemplateLiteral(expression.argumentExpression))
  ) {
    return expression.argumentExpression.text;
  }
  return undefined;
}

function expressionWrite(expression) {
  let target = expression;
  let parent = target.parent;
  while (
    ts.isParenthesizedExpression(parent) ||
    ts.isArrayLiteralExpression(parent) ||
    ts.isObjectLiteralExpression(parent) ||
    (ts.isShorthandPropertyAssignment(parent) && parent.name === target) ||
    (ts.isPropertyAssignment(parent) && parent.initializer === target) ||
    (ts.isSpreadAssignment(parent) && parent.expression === target) ||
    (ts.isSpreadElement(parent) && parent.expression === target)
  ) {
    target = parent;
    parent = target.parent;
  }
  return (
    (ts.isBinaryExpression(parent) &&
      parent.left === target &&
      parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment) ||
    ((ts.isForInStatement(parent) || ts.isForOfStatement(parent)) &&
      parent.initializer === target) ||
    (target === expression &&
      ((ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.PlusPlusToken) ||
        (ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.MinusMinusToken) ||
        ts.isPostfixUnaryExpression(parent) ||
        (ts.isDeleteExpression(parent) && parent.expression === expression)))
  );
}

function ambientGlobalWrite(identifier) {
  if (expressionWrite(identifier)) return true;
  let expression = identifier;
  while (
    (ts.isPropertyAccessExpression(expression.parent) ||
      ts.isElementAccessExpression(expression.parent)) &&
    expression.parent.expression === expression
  ) {
    expression = expression.parent;
    if (expressionWrite(expression)) return true;
  }
  return false;
}

function rejectMathUse(identifier) {
  const parent = identifier.parent;
  if (
    (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
    parent.expression === identifier
  ) {
    if (expressionWrite(parent)) {
      throw new ConvexWasmTargetRuntimeSurfaceGap("ambient-global-write", "Math member");
    }
    const member = staticMember(parent);
    if (member === undefined) {
      throw new ConvexWasmTargetRuntimeSurfaceGap("math-computed-member", "Math[expression]");
    }
    return;
  }
  throw new ConvexWasmTargetRuntimeSurfaceGap("math-ambient-object-flow", "Math");
}

function rejectRawGlobalThisUse() {
  throw new ConvexWasmTargetRuntimeSurfaceGap("raw-global-object-flow", "globalThis");
}

export function assertConvexWasmTargetRuntimeSurface(compileProfileJavascript) {
  const javascript =
    typeof compileProfileJavascript === "string"
      ? compileProfileJavascript
      : compileProfileJavascript instanceof Uint8Array
        ? new TextDecoder("utf-8", { fatal: true }).decode(compileProfileJavascript)
        : undefined;
  if (javascript === undefined || javascript.length === 0) {
    throw new Error("compileProfileJavascript must be a non-empty string or UTF-8 byte array.");
  }
  if (!SHA256_PATTERN.test(convexWasmTargetRuntimeSurfacePolicySha256)) {
    throw new Error("Convex Wasm target runtime surface policy identity is invalid.");
  }
  const options = {
    allowJs: true,
    noLib: true,
    target: ts.ScriptTarget.ESNext,
  };
  const sourceFile = ts.createSourceFile(
    VIRTUAL_SOURCE_PATH,
    javascript,
    options.target,
    true,
    ts.ScriptKind.JS
  );
  const program = ts.createProgram(
    [VIRTUAL_SOURCE_PATH],
    options,
    compilerHost(sourceFile, javascript)
  );
  const parseDiagnostics = program.getSyntacticDiagnostics(sourceFile);
  if (parseDiagnostics.length !== 0) {
    throw new Error("compileProfileJavascript must be valid JavaScript before runtime checks.");
  }
  const checker = program.getTypeChecker();
  const visit = (node) => {
    if (ts.isIdentifier(node)) {
      const name = node.text;
      if (
        applicationInitializationHandoffBindings.has(name) &&
        (name !== convexWasmApplicationGlobalThisBinding ||
          !unshadowedAmbientIdentifier(node, checker))
      ) {
        throw new ConvexWasmTargetRuntimeSurfaceGap("reserved-initialization-handoff", name);
      }
      if (!unshadowedAmbientIdentifier(node, checker)) {
        ts.forEachChild(node, visit);
        return;
      }
      if (name === "arguments") {
        // TypeScript does not bind the implicit function arguments object without library input.
      } else if (name === "globalThis") {
        rejectRawGlobalThisUse(node);
      } else if (name === convexWasmApplicationGlobalThisBinding) {
        if (ambientGlobalWrite(node)) {
          throw new ConvexWasmTargetRuntimeSurfaceGap("ambient-global-write", "globalThis");
        }
      } else if (implementedAmbientGlobalSet.has(name) && ambientGlobalWrite(node)) {
        throw new ConvexWasmTargetRuntimeSurfaceGap("ambient-global-write", name);
      } else if (implementedAmbientGlobalSet.has(name)) {
        if (name === "Math") {
          rejectMathUse(node);
        } else if (name === "Date") {
          // Date is implemented by the invocation-capability facade rendered below.
        } else {
          // These names are implemented by the pinned engine and authenticated as policy inputs.
        }
      } else if (name === "Date") {
        // Date is implemented by the invocation-capability facade rendered below.
      } else if (name === "Math") {
        rejectMathUse(node);
      } else {
        const namedGap = namedGlobalGaps.get(name);
        throw new ConvexWasmTargetRuntimeSurfaceGap(namedGap ?? "ambient-global-unavailable", name);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return {
    javascript,
    kind: POLICY_KIND,
    policySha256: convexWasmTargetRuntimeSurfacePolicySha256,
  };
}

export function renderConvexWasmTargetRuntimeGlobalPrelude() {
  const typedBridgeDefinitions = convexWasmAdmittedStaticHermesGlobals
    .filter(
      (name) =>
        !convexWasmStaticHermesGlobalInventory.staticHermesTypedDeclarations.globals.includes(name)
    )
    .map((name) => `const ${name}: any = __convexTargetGlobal.${name};`)
    .join("\n");
  const compileVisibleGlobals = convexWasmAdmittedStaticHermesGlobals
    .map((name) => {
      if (name === "Array") return "  void new Array<any>();";
      if (name === "Map") return "  void new Map<any, any>();";
      if (name === "Set") return "  void new Set<any>();";
      return `  void ${name};`;
    })
    .join("\n");
  return String.raw`const __convexTargetGlobal: any = globalThis;
${typedBridgeDefinitions}
{
const __convexTargetRuntimeSurfacePolicySha256: string = ${JSON.stringify(
    convexWasmTargetRuntimeSurfacePolicySha256
  )};
function __convexTargetRuntimeSurfaceCompileCorpus(): void {
${compileVisibleGlobals}
  void __convexTargetRuntimeSurfacePolicySha256;
}
const __convexTargetHostInvocationUnixTimestampMs = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_invocation_unix_timestamp_ms(): c_double { throw 0; },
);
const __convexTargetHostCapabilityCurrent = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_capability_current(): c_longlong { throw 0; },
);
const __convexTargetHostMathRandom = $SHBuiltin.extern_c(
  {include: "convex_wasm_opaque_abi_v3.h"},
  function convex_math_random(capabilityIdentity: c_longlong): c_double { throw 0; },
);
const __convexTargetNativeDate: any = __convexTargetGlobal.Date;
const __convexTargetDateNow: any = (): number => {
  const capabilityIdentity = __convexTargetHostCapabilityCurrent();
  if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
  return __convexTargetHostInvocationUnixTimestampMs();
};
__convexTargetGlobal.Object.defineProperty(__convexTargetDateNow, "name", {
  configurable: true,
  value: "now",
});
__convexTargetGlobal.Object.freeze(__convexTargetDateNow);
const __convexTargetNativeDateNowDescriptor: any =
  __convexTargetGlobal.Object.getOwnPropertyDescriptor(__convexTargetNativeDate, "now");
if (
  __convexTargetNativeDateNowDescriptor === undefined ||
  !("value" in __convexTargetNativeDateNowDescriptor)
) {
  throw new Error("Static Hermes Date.now descriptor is unavailable");
}
__convexTargetGlobal.Object.defineProperty(__convexTargetNativeDate, "now", {
  configurable: __convexTargetNativeDateNowDescriptor.configurable,
  enumerable: __convexTargetNativeDateNowDescriptor.enumerable,
  value: __convexTargetDateNow,
  writable: __convexTargetNativeDateNowDescriptor.writable,
});
const __convexTargetDateHandler: any = __convexTargetGlobal.Object.freeze({
  apply(target, _thisArgument, _argumentsList) {
    const date = __convexTargetGlobal.Reflect.construct(
      target,
      [__convexTargetDateNow()],
      target,
    );
    return __convexTargetNativeDate.prototype.toString.call(date);
  },
  construct(target, argumentsList, newTarget) {
    if (argumentsList.length === 0) {
      return __convexTargetGlobal.Reflect.construct(
        target,
        [__convexTargetDateNow()],
        newTarget,
      );
    }
    return __convexTargetGlobal.Reflect.construct(target, argumentsList, newTarget);
  },
});
const __convexTargetDate: any = new __convexTargetGlobal.Proxy(
  __convexTargetNativeDate,
  __convexTargetDateHandler,
);
const __convexTargetNativeDateConstructorDescriptor: any =
  __convexTargetGlobal.Object.getOwnPropertyDescriptor(
    __convexTargetNativeDate.prototype,
    "constructor",
  );
if (
  __convexTargetNativeDateConstructorDescriptor === undefined ||
  !("value" in __convexTargetNativeDateConstructorDescriptor)
) {
  throw new Error("Static Hermes Date prototype constructor descriptor is unavailable");
}
__convexTargetGlobal.Object.defineProperty(__convexTargetNativeDate.prototype, "constructor", {
  configurable: __convexTargetNativeDateConstructorDescriptor.configurable,
  enumerable: __convexTargetNativeDateConstructorDescriptor.enumerable,
  value: __convexTargetDate,
  writable: __convexTargetNativeDateConstructorDescriptor.writable,
});
const __convexTargetNativeDateGlobalDescriptor: any =
  __convexTargetGlobal.Object.getOwnPropertyDescriptor(__convexTargetGlobal, "Date");
if (
  __convexTargetNativeDateGlobalDescriptor === undefined ||
  !("value" in __convexTargetNativeDateGlobalDescriptor)
) {
  throw new Error("Static Hermes Date global descriptor is unavailable");
}
__convexTargetGlobal.Object.defineProperty(__convexTargetGlobal, "Date", {
  configurable: __convexTargetNativeDateGlobalDescriptor.configurable,
  enumerable: __convexTargetNativeDateGlobalDescriptor.enumerable,
  value: __convexTargetDate,
  writable: __convexTargetNativeDateGlobalDescriptor.writable,
});
function __convexMathRandom(): number {
  const capabilityIdentity = __convexTargetHostCapabilityCurrent();
  if (capabilityIdentity <= 0) throw new Error("Invocation capability is unavailable");
  return __convexTargetHostMathRandom(capabilityIdentity);
}
Object.freeze(__convexMathRandom);
__convexTargetGlobal.Math.random = __convexMathRandom;
}`;
}

export function renderConvexWasmApplicationGlobalFacade() {
  const propertyDefinitions = [
    ...convexWasmApplicationGlobalFacadeEngineGlobals.map(
      (name) =>
        `  ${JSON.stringify(name)}: {enumerable: true, value: __convexTargetGlobal[${JSON.stringify(name)}]}`
    ),
    '  "Date": {enumerable: true, value: __convexTargetGlobal.Date}',
    '  "console": {enumerable: true, value: __convexTargetGlobal.console}',
    '  "performance": {enumerable: true, value: __convexTargetGlobal.performance}',
    '  "process": {enumerable: true, value: __convexTargetGlobal.process}',
    '  "crypto": {enumerable: true, value: __convexTargetGlobal.crypto}',
    '  "Convex": {enumerable: true, value: __convexTargetGlobal.Convex}',
    ...databaseUdfTimerGlobals.map(
      (name) => `  ${JSON.stringify(name)}: {enumerable: true, value: ${name}}`
    ),
    `  "globalThis": {enumerable: true, value: ${convexWasmApplicationGlobalThisBinding}}`,
  ].join(",\n");
  return String.raw`const ${convexWasmApplicationGlobalThisBinding}: any = __convexTargetGlobal.Object.create(null);
__convexTargetGlobal.Object.defineProperties(${convexWasmApplicationGlobalThisBinding}, {
${propertyDefinitions}
});
`;
}
