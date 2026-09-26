import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { version as convexSdkVersion } from "convex";
import { CommitTsPlaceholder, compareValues, convexToJson, jsonToConvex } from "convex/values";
import ts from "typescript";

import {
  assertNativeCapabilityHelperDefinitions,
  convexWasmCapabilityRequestAbiVersion,
  convexWasmIntrinsicHardeningPolicy,
  convexWasmIntrinsicHardeningPolicySha256,
  convexWasmIntrinsicHardeningSourceSha256,
  convexWasmLoweringFormat,
  convexWasmOpaqueAbiVersion,
  convexWasmTargetRuntimeSurfacePolicy,
  convexWasmTargetRuntimeSurfacePolicySha256,
  lowerConvexWasmExport as lowerConvexWasmExportProduction,
  renderNativeDbGetCapabilityTarget as renderNativeDbGetCapabilityTargetProduction,
  renderNativeDbGetCapabilityTargetUnits as renderNativeDbGetCapabilityTargetUnitsProduction,
  renderNativeRuntimeSupportAdapter,
  renderNativeRuntimeSupportUnit,
  renderOpaqueAbiHeader,
} from "./convex-wasm-lowering.mjs";
import {
  assertConvexWasmTargetRuntimeSurface,
  convexWasmApplicationGlobalThisBinding,
  convexWasmApplicationInstallRuntimeSupportBinding,
} from "./convex-wasm-runtime-surface.mjs";

const sourceFingerprint = "a".repeat(64);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function renderNativeDbGetCapabilityTarget(input) {
  return renderNativeDbGetCapabilityTargetProduction({
    ...input,
    sdkPackageVersion: convexSdkVersion,
  });
}

function renderNativeDbGetCapabilityTargetUnits(input) {
  return renderNativeDbGetCapabilityTargetUnitsProduction({
    ...input,
    sdkPackageVersion: convexSdkVersion,
  });
}

test("renders the caller's SDK version and rejects a missing version", () => {
  const input = {
    argumentFields: [],
    compileProfileJavascript: "var __convexWasmCompileProfile = {};",
  };
  for (const version of [undefined, "", "1.0\nforged"]) {
    assert.throws(
      () =>
        renderNativeDbGetCapabilityTargetUnitsProduction({
          ...input,
          sdkPackageVersion: version,
        }),
      /sdkPackageVersion must be a non-empty package version/u
    );
  }
  const rendered = renderNativeDbGetCapabilityTargetUnitsProduction({
    ...input,
    sdkPackageVersion: "9.9.9-example",
  });
  assert.match(rendered.bridgeJavascript, /if \(version !== "9\.9\.9-example"\)/u);
});

async function drainCapabilityMicrotasks() {
  for (let checkpoint = 0; checkpoint < 4; checkpoint += 1) {
    await Promise.resolve();
  }
}

function lowerConvexWasmExport(input) {
  return lowerConvexWasmExportProduction({
    operationsSha256: sha256(JSON.stringify(input.operations)),
    ...input,
  });
}

function lower(overrides = {}) {
  return lowerConvexWasmExport({
    bundleCode: `
      function sha256Hex(input) {
        return __convexSha256(9, input);
      }
      function admittedHandler(ctx, args) {
        const hash = sha256Hex(args.key);
        return ctx.db
          .query("documents")
          .withIndex("by_hash", (q) => q.eq("hash", hash))
          .unique();
      }
    `,
    bundleSourceName: "generated-export.js",
    handlerIdentifier: "admittedHandler",
    argumentFields: ["key"],
    arrayArgumentFields: [],
    documentFields: ["_id", "enabled"],
    operations: [
      {
        id: 7,
        kind: "databaseIndexQuery",
        table: "documents",
        index: "by_hash",
        constraints: [{ field: "hash", operator: "eq" }],
        limit: null,
        order: "ascending",
        terminal: "unique",
      },
    ],
    intrinsics: {
      sha256Hex: {
        kind: "sha256",
        operationId: 9,
      },
    },
    appliedDependencyAdapters: [],
    directAsyncBatches: [],
    runtimeInputs: [],
    sourceGraphFingerprint: sourceFingerprint,
    valueMode: "opaque",
    ...overrides,
  });
}

function guestNativeCodec(commitTsPlaceholder) {
  const code = lower({ valueMode: "guest-native-json" }).code;
  const start = code.indexOf("const __convexCommitTsUnresolved =");
  const end = code.indexOf("let __convexGuestTransferScratchPointer", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const helpers = code
    .slice(start, end)
    .replaceAll(": any[]", "")
    .replaceAll(": any", "")
    .replaceAll(": string", "")
    .replaceAll(": number", "")
    .replaceAll(": boolean", "")
    .replaceAll(": void", "")
    // The capability harness evaluates generated code in a VM context while
    // this extracted codec runs in the test context. Treat the other realm's
    // Object.prototype as the ordinary plain-object prototype it represents.
    .replace(
      "if (prototype !== Object.prototype && prototype !== null) {",
      "if (prototype !== Object.prototype && prototype !== null && Object.getPrototypeOf(prototype) !== null) {"
    );
  const codec = Function(
    `"use strict"; function __convexArrayPush(values, value) { values.push(value); } ${helpers}; return { get commitTs() { return __convexCommitTsPlaceholder; }, encode: __convexGuestEncodeTagged, linkCommitTs(value) { __convexCommitTsPlaceholder = value; }, restore: __convexGuestRestoreTagged };`
  )();
  if (commitTsPlaceholder !== undefined) codec.linkCommitTs(commitTsPlaceholder);
  return codec;
}

function nativeCapabilityHarness({ now = 1_700_000_000_250 } = {}) {
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript: "var __convexWasmCompileProfile = {};",
  });
  const requestStart = rendered.indexOf(
    "function __convexCapabilityOwnDataKeys(value: any, description: string, sortKeys: boolean = true): any {"
  );
  const requestEnd = rendered.indexOf(
    "\nconst __convexHostCapabilityCurrent = $SHBuiltin.extern_c(",
    requestStart
  );
  const runtimeStart = rendered.lastIndexOf(
    "const __convexDynamicGlobal: any = __convexTargetGlobal;"
  );
  const facadeStart = rendered.indexOf("let __convexSdkActiveUdfKind: ?string = null;");
  const facadeEndMarker = 'Object.defineProperty(__convexTargetGlobal, "Convex", {';
  const facadeDescriptorStart = rendered.indexOf(facadeEndMarker, facadeStart);
  const facadeEnd = rendered.indexOf("\n});", facadeDescriptorStart) + "\n});".length;
  const bootstrap = rendered.indexOf(
    'Object.defineProperty(__convexTargetGlobal, "__convexWasmCapabilityBootstrap"',
    runtimeStart
  );
  const end = rendered.indexOf("\n});", bootstrap) + "\n});".length;
  assert.ok(
    requestStart >= 0 &&
      requestEnd > requestStart &&
      facadeStart > requestEnd &&
      facadeEnd > facadeStart &&
      runtimeStart > facadeEnd &&
      bootstrap > runtimeStart &&
      end > bootstrap
  );

  let nextHandle = 1;
  const values = new Map();
  const requests = [];
  const requestCapabilityIdentities = [];
  const requestPayloads = [];
  const restoredTransfers = [];
  const taggedTransfers = [];
  const taggedResultSources = [];
  const guestEncodes = [];
  const results = [];
  const sdkSyncResults = [];
  const closedQueryStreams = [];
  const openQueryStreams = new Set();
  const queryStreamReads = new Map();
  let nextQueryStream = 1;
  const allocate = (value) => {
    const handle = nextHandle++;
    values.set(handle, value);
    return handle;
  };
  const take = (handle) => {
    assert.ok(values.has(handle), `unknown harness value handle ${String(handle)}`);
    const value = values.get(handle);
    values.delete(handle);
    return value;
  };
  const sdkCommitTsPlaceholder = jsonToConvex({ $commitTs: null });
  const transferScratch = { source: "" };
  const {
    commitTs: commitTsPlaceholder,
    encode: encodeCommittedValue,
    restore: restoreCommittedValue,
  } = guestNativeCodec(sdkCommitTsPlaceholder);
  let currentCapabilityIdentity = 1;
  const sandbox = {
    Date: class extends Date {
      static now() {
        return now;
      }
    },
    __convexGuestFromHost: (handle) => {
      restoredTransfers.push(handle);
      return take(handle);
    },
    __convexGuestTaggedJsonFromHost: (handle) => {
      const source = JSON.stringify(encodeCommittedValue(take(handle), []));
      taggedTransfers.push(source);
      return source;
    },
    __convexGuestEncodeTagged: (value, ancestors) => {
      guestEncodes.push(value);
      return encodeCommittedValue(value, ancestors);
    },
    __convexGuestRestoreTagged: restoreCommittedValue,
    __convexCommitTsPlaceholder: commitTsPlaceholder,
    __convexArrayPush: (values, value) => values.push(value),
    __convexGuestDefineObjectField: (output, key, value) => {
      Object.defineProperty(output, key, {
        configurable: true,
        enumerable: true,
        value,
        writable: true,
      });
    },
    __convexGuestIsArray: Array.isArray,
    __convexGuestValidateObjectField: (key) => {
      if (key.length > 1024) throw new Error("Convex object field name is too long");
      if (key.charAt(0) === "$") {
        throw new Error("Convex object field name uses a reserved prefix");
      }
      for (let index = 0; index < key.length; index += 1) {
        const character = key.charAt(index);
        if (character < " " || character > "~") {
          throw new Error(
            "Convex object field name must contain only non-control ASCII characters"
          );
        }
      }
    },
    __convexAllocateUtf8: (source) => source,
    __convexGuestTransferScratch: () => transferScratch,
    __convexWriteUtf8: (source, pointer) => {
      if (pointer === transferScratch) pointer.source = source;
      else assert.equal(pointer, source);
      return Buffer.byteLength(source);
    },
    __convexFree: (pointer) => {
      assert.equal(typeof pointer, "string");
    },
    __convexHostCapabilityRequestDecode: (pointer, length) => {
      const source = pointer === transferScratch ? pointer.source : pointer;
      assert.equal(length, Buffer.byteLength(source));
      requestPayloads.push(source);
      return allocate(JSON.parse(source));
    },
    __convexHostCapabilityRequestRelease: (handle) => {
      assert.ok(values.delete(handle), `released unknown request handle ${String(handle)}`);
    },
    __convexHostCapabilityCurrent: () => currentCapabilityIdentity,
    __convexHostCapabilityStartTake: (identity, requestHandle) =>
      startOperation(requestHandle, identity),
    __convexHostCapabilitySyncTake: (identity, requestHandle) => {
      requestCapabilityIdentities.push(identity);
      requests.push(take(requestHandle));
      return allocate(sdkSyncResults.length === 0 ? null : sdkSyncResults.shift());
    },
    __convexHostCapabilityQueryStreamOpenTake: (identity, requestHandle) => {
      assert.equal(identity, 1);
      requests.push(take(requestHandle));
      const streamHandle = nextQueryStream++;
      assert.ok(!openQueryStreams.has(streamHandle));
      openQueryStreams.add(streamHandle);
      return streamHandle;
    },
    __convexHostAsyncQueryStreamNext: (streamHandle) => {
      assert.ok(openQueryStreams.has(streamHandle), `unknown query stream ${String(streamHandle)}`);
      const operationHandle = nextOperation++;
      queryStreamReads.set(operationHandle, streamHandle);
      return operationHandle;
    },
    __convexHostAsyncQueryStreamClose: (streamHandle) => {
      assert.ok(
        openQueryStreams.delete(streamHandle),
        `closed unknown query stream ${String(streamHandle)}`
      );
      closedQueryStreams.push(streamHandle);
    },
    __convexInvocationUnixTimestampMs: () => now,
    __convexReadGuestRequest: () => ({}),
    __convexReadGuestRequestTaggedJson: () => "{}",
    __convexReportThrown: (error) => {
      throw error;
    },
    __convexSetGuestFunctionResult: (value) => results.push(value),
    __convexSetGuestFunctionTaggedJsonResult: (source) => {
      taggedResultSources.push(source);
      results.push(jsonToConvex(JSON.parse(source)));
    },
  };
  sandbox.__convexTargetGlobal = sandbox;
  const javascript = ts.transpileModule(
    `${rendered.slice(requestStart, requestEnd)}\n${rendered.slice(
      facadeStart,
      facadeEnd
    )}\n${rendered.slice(runtimeStart, end)}`,
    {
      compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
    }
  ).outputText;
  runInNewContext(javascript, sandbox);
  let bridge;
  sandbox.__convexWasmCapabilityBootstrap((...installed) => {
    bridge = installed;
  });
  assert.equal(bridge.length, 10);
  const [
    createContext,
    ,
    invoke,
    done,
    cleanup,
    settle,
    status,
    activateSdk,
    invokeRegisteredWrapper,
  ] = bridge;
  let nextOperation = 1;
  const startOperation = (requestHandle, capabilityIdentity) => {
    requestCapabilityIdentities.push(capabilityIdentity);
    requests.push(take(requestHandle));
    return nextOperation++;
  };
  const syncOperation = (requestHandle) => {
    requests.push(take(requestHandle));
    return allocate(null);
  };
  const settleOperation = (operationHandle, completionStatus, payloadHandle) => {
    const streamHandle = queryStreamReads.get(operationHandle);
    if (streamHandle !== undefined) {
      const payload = values.get(payloadHandle);
      if (completionStatus === 1 || payload?.done === true) {
        assert.ok(openQueryStreams.delete(streamHandle));
      }
      queryStreamReads.delete(operationHandle);
    }
    return settle(operationHandle, completionStatus, payloadHandle);
  };
  const selectedCommitTsPlaceholder = jsonToConvex({ $commitTs: null });
  const guestArguments = (argumentsObject) => {
    // Installed SDK modules run in Node; the facade under test runs in this VM realm.
    // Real guest SDK arguments are already created in the facade's realm.
    if (Object.getPrototypeOf(argumentsObject) !== Object.prototype) return argumentsObject;
    sandbox.__convexHostSdkArguments = argumentsObject;
    try {
      return runInNewContext("JSON.parse(JSON.stringify(__convexHostSdkArguments))", sandbox);
    } finally {
      delete sandbox.__convexHostSdkArguments;
    }
  };
  const hostSdkFacade = {
    ...sandbox.Convex,
    asyncSyscallObjectArgs: (operation, argumentsObject) =>
      sandbox.Convex.asyncSyscallObjectArgs(operation, guestArguments(argumentsObject)),
    syscallObjectArgs: (operation, argumentsObject) =>
      sandbox.Convex.syscallObjectArgs(operation, guestArguments(argumentsObject)),
  };
  return {
    allocate,
    activateSdk,
    cleanup,
    closedQueryStreams,
    createContext: (udfKind, sync = syncOperation, capabilityIdentity = 1) =>
      createContext(
        (requestHandle) => startOperation(requestHandle, capabilityIdentity),
        sync,
        udfKind,
        selectedCommitTsPlaceholder
      ),
    date: (value) => new sandbox.Date(value),
    done,
    guestValue: (source, values = {}) => {
      Object.assign(sandbox, values);
      try {
        return runInNewContext(source, sandbox);
      } finally {
        for (const name of Object.keys(values)) delete sandbox[name];
      }
    },
    invoke,
    invokeRegisteredWrapper,
    guestEncodes,
    lastStartedOperationHandle: () => nextOperation - 1,
    now: () => runInNewContext("Date.now()", sandbox),
    outstandingHandles: () => values.size,
    openQueryStreams,
    queryStreamReads,
    queueSdkSyncResult: (value) => sdkSyncResults.push(value),
    requestCapabilityIdentities,
    requests,
    requestPayloads,
    restoredTransfers,
    restartOperationHandles: () => {
      nextOperation = 1;
    },
    results,
    settle: settleOperation,
    status,
    rawSdkFacade: sandbox.Convex,
    sdkFacade: hostSdkFacade,
    taggedTransfers,
    taggedResultSources,
    setCapabilityIdentity: (identity) => {
      currentCapabilityIdentity = identity;
    },
    take,
  };
}

function nativeDatabaseUdfTimerHarness() {
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript:
      "var __convexWasmCompileProfile = { selected: () => setTimeout(() => {}, 1) };",
  });
  const start = rendered.indexOf("function __convexDatabaseUdfTimerDeveloperError(");
  const end = rendered.indexOf("const __convexCryptoDigestBytes = 32;", start);
  assert.ok(start >= 0 && end > start);

  const developerErrors = [];
  const sandbox = {
    __convexAllocateUtf8: (message) => message,
    __convexFree: (pointer) => assert.equal(typeof pointer, "string"),
    __convexHostDeveloperError: (pointer, length, hostOperationErrorHandle) => {
      assert.equal(length, Buffer.byteLength(pointer));
      assert.equal(hostOperationErrorHandle, 0);
      developerErrors.push(pointer);
    },
    __convexWriteUtf8: (message, pointer) => {
      assert.equal(pointer, message);
      return Buffer.byteLength(message);
    },
  };
  const source = `${rendered.slice(start, end)}
globalThis.__convexTimerHarness = {clearInterval, clearTimeout, setInterval, setTimeout};`;
  const javascript = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(javascript, sandbox);
  return {
    developerErrors,
    evaluate: (source) => runInNewContext(source, sandbox),
  };
}

function nativeConsoleHarness({
  capabilityIdentity = 7,
  hostStatus = 0,
  initializeRuntimeSupport = true,
} = {}) {
  let currentCapabilityIdentity = capabilityIdentity;
  let currentHostStatus = hostStatus;
  const calls = [];
  const capabilityLookups = [];
  const freedPointers = [];
  const sandbox = {
    Map,
    Set,
    TextDecoder,
    TextEncoder,
    __convexAllocateUtf8: (source) => source,
    __convexFree: (pointer) => freedPointers.push(pointer),
    __convexHostCapabilityCurrent: () => {
      capabilityLookups.push(currentCapabilityIdentity);
      return currentCapabilityIdentity;
    },
    __convexHostConsoleMessage: (identity, level, pointer, length) => {
      assert.equal(length, Buffer.byteLength(pointer));
      calls.push({ identity, level, messages: JSON.parse(pointer) });
      return currentHostStatus;
    },
    __convexWriteUtf8: (source, pointer) => {
      assert.equal(pointer, source);
      return Buffer.byteLength(source);
    },
  };
  sandbox.__convexTargetGlobal = sandbox;
  sandbox.__convexWasmApplicationGlobalThis = Object.create(null);
  runInNewContext("delete globalThis.Intl;", sandbox);
  const javascript = ts.transpileModule(renderNativeRuntimeSupportAdapter(), {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(javascript, sandbox);
  const installRuntimeSupport = sandbox[convexWasmApplicationInstallRuntimeSupportBinding];
  if (initializeRuntimeSupport) runInNewContext(renderNativeRuntimeSupportUnit(), sandbox);
  return {
    calls,
    capabilityLookups,
    evaluate: (source) => runInNewContext(source, sandbox),
    freedPointers,
    installRuntimeSupport,
    runRuntimeSupportUnit: () => runInNewContext(renderNativeRuntimeSupportUnit(), sandbox),
    setCapabilityIdentity: (identity) => {
      currentCapabilityIdentity = identity;
    },
    setHostStatus: (status) => {
      currentHostStatus = status;
    },
  };
}

function nativePerformanceHarness({ capabilityIdentity = 7, result = 12.3, syncResult } = {}) {
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript:
      "var __convexWasmCompileProfile = { selected: () => performance.now() };",
  });
  const start = rendered.indexOf("function __convexPerformanceNow(): number {");
  const end = rendered.indexOf("function __convexEnvironmentVariableGet", start);
  assert.ok(start >= 0 && end > start);

  let nextHandle = 1;
  const values = new Map();
  const requests = [];
  const allocate = (value) => {
    const handle = nextHandle++;
    values.set(handle, value);
    return handle;
  };
  const take = (handle) => {
    assert.ok(values.has(handle), `unknown performance harness value handle ${String(handle)}`);
    const value = values.get(handle);
    values.delete(handle);
    return value;
  };
  const sandbox = {
    __convexGuestFromHost: take,
    __convexCapabilityRequestToHost: allocate,
    __convexCapabilityRequestRelease: (handle) => {
      assert.ok(
        values.delete(handle),
        `released unknown performance request handle ${String(handle)}`
      );
    },
    __convexHostCapabilityCurrent: () => capabilityIdentity,
    __convexHostCapabilitySyncTake: (_identity, requestHandle) => {
      if (syncResult === -2) return -2;
      requests.push(take(requestHandle));
      return allocate(result);
    },
  };
  sandbox.__convexTargetGlobal = sandbox;
  const javascript = ts.transpileModule(rendered.slice(start, end), {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(javascript, sandbox);
  return {
    evaluate: (source) => runInNewContext(source, sandbox),
    now: () => runInNewContext("performance.now()", sandbox),
    outstandingHandles: () => values.size,
    requests,
  };
}

function nativeCryptoHarness({ capabilityIdentity = 7 } = {}) {
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript:
      "var __convexWasmCompileProfile = { selected: (algorithm, data) => crypto.subtle.digest(algorithm, data) };",
  });
  const mathStart = rendered.indexOf("function __convexMathRandom(): number {");
  const mathEndMarker = "__convexTargetGlobal.Math.random = __convexMathRandom;";
  const mathEnd = rendered.indexOf(mathEndMarker, mathStart) + mathEndMarker.length;
  const cryptoStart = rendered.indexOf("const __convexCryptoDigestBytes = 32;");
  const cryptoEnd = rendered.indexOf("function __convexPerformanceNow(): number {", cryptoStart);
  assert.ok(
    mathStart >= 0 && mathEnd >= mathStart + mathEndMarker.length && cryptoEnd > cryptoStart
  );

  let currentCapabilityIdentity = capabilityIdentity;
  let nextPointer = 1;
  const allocations = new Map();
  const capabilityLookups = [];
  const calls = [];
  const randomnessCalls = [];
  const allocate = (size) => {
    assert.ok(Number.isSafeInteger(size) && size > 0);
    const pointer = nextPointer++;
    allocations.set(pointer, new Uint8Array(size));
    return pointer;
  };
  const allocation = (pointer) => {
    const value = allocations.get(pointer);
    assert.notEqual(value, undefined, `unknown crypto harness pointer ${String(pointer)}`);
    return value;
  };
  const sandboxMath = Object.create(Math);
  const sandbox = {
    ArrayBuffer,
    BigInt64Array,
    BigUint64Array,
    DataView,
    Error,
    Float32Array,
    Float64Array,
    Int8Array,
    Int16Array,
    Int32Array,
    Math: sandboxMath,
    Object,
    Promise,
    String,
    TextEncoder,
    TypeError,
    Uint8Array,
    Uint8ClampedArray,
    Uint16Array,
    Uint32Array,
    __convexFree: (pointer) => {
      assert.ok(
        allocations.delete(pointer),
        `freed unknown crypto harness pointer ${String(pointer)}`
      );
    },
    __convexHostCapabilityCurrent: () => {
      capabilityLookups.push(currentCapabilityIdentity);
      return currentCapabilityIdentity;
    },
    __convexHostCryptoGetRandomValues: (identity, outputPointer, outputLength) => {
      const output = allocation(outputPointer);
      for (let index = 0; index < outputLength; index += 1) {
        output[index] = (identity + index * 17) & 0xff;
      }
      randomnessCalls.push({ identity, kind: "getRandomValues", length: outputLength });
    },
    __convexHostCryptoRandomUuid: (identity, outputPointer, outputLength) => {
      const uuid = "123e4567-e89b-42d3-a456-426614174000";
      assert.equal(outputLength, uuid.length);
      allocation(outputPointer).set(new TextEncoder().encode(uuid));
      randomnessCalls.push({ identity, kind: "randomUUID" });
    },
    __convexHostCryptoSubtleDigestSha256: (
      identity,
      inputPointer,
      inputLength,
      outputPointer,
      outputLength
    ) => {
      assert.equal(outputLength, 32);
      const input = allocation(inputPointer).slice(0, inputLength);
      const digest = createHash("sha256").update(input).digest();
      allocation(outputPointer).set(digest);
      calls.push({ identity, input });
    },
    __convexTargetHostCapabilityCurrent: () => {
      capabilityLookups.push(currentCapabilityIdentity);
      return currentCapabilityIdentity;
    },
    __convexTargetHostMathRandom: (identity) => {
      randomnessCalls.push({ identity, kind: "Math.random" });
      return identity / 100;
    },
    __convexMalloc: allocate,
    __convexNullPointer: 0,
    __convexPtrReadUChar: (pointer, offset) => allocation(pointer)[offset],
    __convexPtrWriteChar: (pointer, offset, value) => {
      allocation(pointer)[offset] = value;
    },
  };
  sandbox.__convexTargetGlobal = sandbox;
  const javascript = ts.transpileModule(
    `${rendered.slice(mathStart, mathEnd)}\n${rendered.slice(cryptoStart, cryptoEnd)}`,
    {
      compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
    }
  ).outputText;
  runInNewContext(javascript, sandbox);
  return {
    capabilityLookups,
    calls,
    digest: (algorithm, data) => sandbox.crypto.subtle.digest(algorithm, data),
    evaluate: (source) => runInNewContext(source, sandbox),
    getRandomValues: (view) => sandbox.crypto.getRandomValues(view),
    loadSharedSha256: () => {
      const source = readFileSync(new URL("../../shared/sha256.ts", import.meta.url), "utf8");
      const exports = {};
      sandbox.exports = exports;
      const compiled = ts.transpileModule(source, {
        compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
      }).outputText;
      runInNewContext(compiled, sandbox);
      return exports.sha256Hex;
    },
    mathRandom: () => sandbox.Math.random(),
    outstandingAllocations: () => allocations.size,
    randomUUID: () => sandbox.crypto.randomUUID(),
    randomnessCalls,
    setCapabilityIdentity: (identity) => {
      currentCapabilityIdentity = identity;
    },
  };
}

function bufferHex(value) {
  return Buffer.from(new Uint8Array(value)).toString("hex");
}

function executableIndexQueryBuilder(code, overrides = {}) {
  const start = code.indexOf("function __convexCreateIndexRange(");
  const end = code.indexOf("const __convexContext = {", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const source = ts.transpileModule(code.slice(start, end), {
    compilerOptions: {
      module: ts.ModuleKind.None,
      target: ts.ScriptTarget.ES2020,
    },
  }).outputText;
  return runInNewContext(`${source}; __convexCreateQuery`, {
    __convexArrayPush(values, value) {
      values.push(value);
    },
    __convexAsyncBatchArgumentCount() {
      return 0;
    },
    __convexMarkArray(values) {
      return values;
    },
    ...overrides,
  });
}

test("guest Promise execution emits the generic start and root settlement contract", () => {
  const result = lower({
    bundleCode: `
      async function admittedHandler(ctx, args) {
        const first = await ctx.db.get("documents", args.key);
        return await ctx.db.get("documents", first._id);
      }
    `,
    documentFields: ["_id"],
    effectExecutionMode: "guest-promise-event-loop",
    intrinsics: {},
    operations: [
      {
        id: 1,
        kind: "databaseGet",
        table: "documents",
      },
    ],
  });

  assert.equal(result.loweringInputs.effectExecutionMode, "guest-promise-event-loop");
  assert.equal(result.loweringInputs.format, "convex-wasm-lowered-guest-v37");
  assert.match(result.code, /convex_async_operation_start_take/u);
  assert.match(result.code, /function __convexWasmSettle\(/u);
  assert.match(result.code, /function __convexPendingOperationSlot\(/u);
  assert.match(result.code, /const slot = operationHandle - 1/u);
  assert.match(result.code, /while \(__convexPendingOperationIds\.length <= slot\)/u);
  assert.doesNotMatch(result.code, /Resolves\[operationHandle\]/u);
  assert.match(result.code, /__convexGuestPromise\.resolve\(__convexHandlerResult\)\.then/u);
  assert.match(result.code, /globalThis\.__convexWasmInvocationDone/u);
  assert.match(result.code, /globalThis\.__convexWasmInvocationStatus/u);
  assert.match(result.code, /globalThis\.__convexWasmInvocationCleanup/u);
  assert.doesNotMatch(result.code, /function convex_db_get\(/u);
  assert.doesNotMatch(result.code, /function convex_async_batch_take\(/u);
  assert.doesNotMatch(result.code, /function convex_query_start_/u);
  assert.doesNotMatch(result.code, /const __convexResult = admittedHandler/u);
});

test("guest query streams preserve native async iteration behind the authenticated lifecycle", () => {
  const result = lower({
    bundleCode: `
      async function admittedHandler(ctx, args) {
        const rows = ctx.db
          .query("documents")
          .withIndex("by_updated", (q) => q.gte("updated", args.minimum));
        for await (const row of rows) {
          if (row.enabled) return row._id;
        }
        return null;
      }
    `,
    documentFields: ["_id", "enabled"],
    effectExecutionMode: "guest-promise-event-loop",
    intrinsics: {},
    operations: [
      {
        id: 17,
        kind: "databaseIndexQuery",
        table: "documents",
        index: "by_updated",
        constraints: [{ field: "updated", operator: "gte" }],
        limit: null,
        order: "ascending",
        terminal: "stream",
      },
    ],
  });

  for (const name of [
    "convex_async_query_stream_open_take",
    "convex_async_query_stream_next",
    "convex_async_query_stream_close",
  ]) {
    assert.match(result.code, new RegExp(name, "u"));
  }
  assert.match(result.code, /\[__convexDynamicGlobal\.Symbol\.asyncIterator\]/u);
  assert.match(result.code, /function __convexCreateQueryIterator\(/u);
  assert.match(result.code, /__convexHostAsyncQueryStreamClose\(streamHandle\)/u);
  assert.match(result.code, /for await \(const row of rows\)/u);
  assert.match(result.code, /normalizedTerminal === "stream"/u);
  assert.doesNotMatch(result.code, /function convex_query_start_value\(/u);
});

test("query and range builders preserve authenticated branch snapshots", () => {
  const blocking = lower({ intrinsics: {} });
  const blockingDescriptors = [];
  const blockingArguments = [];
  const createBlockingQuery = executableIndexQueryBuilder(blocking.code, {
    __convexAsyncBatchArgumentCount() {
      return 1;
    },
    __convexFromHost() {
      throw new Error("unexpected host value");
    },
    __convexFromHostArrayTake() {
      throw new Error("unexpected host array");
    },
    __convexIndexQueryOperationId(...descriptor) {
      blockingDescriptors.push(
        descriptor.map((value) => (Array.isArray(value) ? [...value] : value))
      );
      return blockingDescriptors.length;
    },
    __convexQueryNext() {
      return 0;
    },
    __convexStartQuery(operationId, operationArguments) {
      blockingArguments.push({ operationArguments: [...operationArguments], operationId });
      return operationId;
    },
    __convexValueArrayNew() {
      throw new Error("unexpected collect");
    },
    __convexValueArrayPush() {
      throw new Error("unexpected collect");
    },
    __convexValueRelease() {},
  });
  const blockingBase = createBlockingQuery(
    "documents",
    undefined,
    undefined,
    undefined,
    undefined,
    null
  );
  const byOwner = blockingBase.withIndex("by_owner", (range) => range.eq("owner", "owner-1"));
  const byKind = blockingBase.withIndex("by_kind", (range) => range.eq("kind", "worker"));
  const ascending = byOwner.order("asc");
  const descending = byOwner.order("desc");
  descending.unique();
  ascending.unique();
  byKind.unique();

  assert.deepEqual(blockingDescriptors, [
    ["documents", "by_owner", ["owner"], ["eq"], "desc", "unique", null],
    ["documents", "by_owner", ["owner"], ["eq"], "asc", "unique", null],
    ["documents", "by_kind", ["kind"], ["eq"], null, "unique", null],
  ]);
  assert.deepEqual(blockingArguments, [
    { operationArguments: ["owner-1"], operationId: 1 },
    { operationArguments: ["owner-1"], operationId: 2 },
    { operationArguments: ["worker"], operationId: 3 },
  ]);

  const ignoredDescriptors = [];
  const createGuestQuery = executableIndexQueryBuilder(
    lower({
      bundleCode: `
        async function admittedHandler(ctx) {
          for await (const row of ctx.db.query("documents").withIndex("by_kept", (range) => range.eq("kept", 2))) {
            return row._id;
          }
          return null;
        }
      `,
      documentFields: ["_id"],
      effectExecutionMode: "guest-promise-event-loop",
      intrinsics: {},
      operations: [
        {
          constraints: [{ field: "kept", operator: "eq" }],
          id: 41,
          index: "by_kept",
          kind: "databaseIndexQuery",
          limit: null,
          order: "ascending",
          table: "documents",
          terminal: "stream",
        },
      ],
    }).code,
    {
      __convexCreateQueryIterator(operationId, operationArguments) {
        return { operationArguments: [...operationArguments], operationId };
      },
      __convexDynamicGlobal: { Symbol },
      __convexIndexQueryOperationId(...descriptor) {
        ignoredDescriptors.push(
          descriptor.map((value) => (Array.isArray(value) ? [...value] : value))
        );
        return 41;
      },
      __convexStartAsyncOperation() {
        throw new Error("unexpected non-stream terminal");
      },
    }
  );
  const guestBase = createGuestQuery("documents", undefined, undefined, undefined, undefined, null);
  const selected = guestBase.withIndex("by_kept", (range) => {
    range.eq("ignored", 1);
    return range.eq("kept", 2);
  });
  const iterator = selected[Symbol.asyncIterator]();
  assert.deepEqual(ignoredDescriptors, [
    ["documents", "by_kept", ["kept"], ["eq"], null, "stream", null],
  ]);
  assert.deepEqual(iterator, { operationArguments: [2], operationId: 41 });
  assert.throws(
    () =>
      guestBase.withIndex("by_missing_return", (range) => {
        range.eq("ignored", 1);
      }),
    /Unsupported index range expression/u
  );
});

test("guest Promise result encoding recognizes VM-created arrays without another reaction", () => {
  const result = lower({
    bundleCode: `
      async function admittedHandler() {
        return await __convexGuestPromise.all([]);
      }
    `,
    documentFields: [],
    effectExecutionMode: "guest-promise-event-loop",
    intrinsics: {},
    operations: [],
  });

  assert.match(
    result.code,
    /const __convexDynamicArrayIsArray: any = __convexDynamicGlobal\.Array\.isArray;/u
  );
  assert.match(
    result.code,
    /function __convexIsKnownArray\(value\) \{\s*if \(__convexDynamicArrayIsArray\(value\)\) return true;/u
  );
  assert.match(
    result.code,
    /__convexGuestPromise\.all = function\(values: any\): any \{\s*return __convexDynamicPromise\.all\(__convexVmPromiseValues\(values\)\);\s*\};/u
  );
  assert.doesNotMatch(
    result.code,
    /__convexDynamicPromise\.all\(__convexVmPromiseValues\(values\)\)\.then/u
  );
  assert.doesNotMatch(lower().code, /__convexDynamicArrayIsArray/u);
});

function executableGuestPromiseEffectRuntime(code) {
  const start = code.indexOf("const __convexPendingOperationIds:");
  const end = code.indexOf("function __convexDatabaseGet(", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const source = (
    "const __convexHostOperationErrorCandidates = new WeakMap();\n" +
    extractedFunction(code, "__convexReportThrown") +
    "\n" +
    extractedFunction(code, "__convexHostOperationErrorHandle") +
    "\n" +
    code.slice(start, end)
  ).replace("Array<?number>", "Array<number | undefined>");
  return ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
}

function extractedFunction(code, name) {
  const start = code.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} is missing`);
  const bodyStart = code.indexOf("{", start);
  assert.notEqual(bodyStart, -1, `${name} has no body`);
  let depth = 0;
  for (let index = bodyStart; index < code.length; index += 1) {
    if (code[index] === "{") depth += 1;
    else if (code[index] === "}") {
      depth -= 1;
      if (depth === 0) return code.slice(start, index + 1);
    }
  }
  assert.fail(`${name} has an unterminated body`);
}

function executableFunctionHandleRuntime(code, { guest = false } = {}) {
  const source = [
    guest ? executableGuestPromiseEffectRuntime(code) : "",
    "const __convexFunctionReferenceBrand = Symbol();",
    extractedFunction(code, "__convexInternalFunctionReference"),
    extractedFunction(code, "__convexFunctionReference"),
    extractedFunction(code, "__convexFunctionHandleCreateOperationId"),
    extractedFunction(code, "__convexFunctionHandleAddress"),
    extractedFunction(code, "__convexCreateFunctionHandle"),
  ].join("\n");
  return ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
}

test("plan-owned guest effect sites select exact variants and retain Promise lifecycle semantics", async () => {
  const bundleCode = `
    function __convexEffectSite_ab12(table, id) {
      if (table === "documents") return __convexStartAsyncOperation(41, [id]);
      if (table === "accounts") return __convexStartAsyncOperation(42, [id]);
      throw new Error("Convex effect site received an unauthorized static operand");
    }
    function admittedHandler() {
      return __convexGuestPromise.all([
        __convexEffectSite_ab12("documents", "document-id"),
        __convexEffectSite_ab12("accounts", "account-id"),
      ]);
    }
  `;
  const result = lower({
    argumentFields: [],
    bundleCode,
    documentFields: [],
    effectExecutionMode: "guest-promise-event-loop",
    intrinsics: {},
    operations: [
      { id: 41, kind: "databaseGet", table: "documents" },
      { id: 42, kind: "databaseGet", table: "accounts" },
    ],
  });
  assert.match(
    result.code,
    /function __convexEffectSite_ab12\(table, id\)[\s\S]*__convexStartAsyncOperation\(41, \[id\]\)[\s\S]*__convexStartAsyncOperation\(42, \[id\]\)/u
  );

  const valueArrays = new Map();
  const values = new Map();
  const starts = [];
  let nextArrayHandle = 1;
  let nextValueHandle = 1;
  let nextOperationHandle = 1;
  const sandbox = {
    __convexAsyncBatchResultKind(operationId) {
      assert.ok(operationId === 41 || operationId === 42);
      return "hostValue";
    },
    __convexFromHost(handle) {
      assert.equal(values.has(handle), true);
      const value = values.get(handle);
      values.delete(handle);
      return value;
    },
    __convexFromHostArrayTake() {
      throw new Error("Unexpected array completion");
    },
    __convexHostAsyncOperationStartTake(operationId, argumentsHandle) {
      assert.equal(valueArrays.has(argumentsHandle), true);
      const operationHandle = nextOperationHandle;
      nextOperationHandle += 1;
      starts.push({
        arguments: valueArrays.get(argumentsHandle),
        operationHandle,
        operationId,
      });
      valueArrays.delete(argumentsHandle);
      return operationHandle;
    },
    __convexToHost(value) {
      const handle = nextValueHandle;
      nextValueHandle += 1;
      values.set(handle, value);
      return handle;
    },
    __convexValueArrayNew() {
      const handle = nextArrayHandle;
      nextArrayHandle += 1;
      valueArrays.set(handle, []);
      return handle;
    },
    __convexValueArrayPush(arrayHandle, valueHandle) {
      assert.equal(valueArrays.has(arrayHandle), true);
      assert.equal(values.has(valueHandle), true);
      valueArrays.get(arrayHandle).push(values.get(valueHandle));
      values.delete(valueHandle);
    },
    __convexValueRelease(handle) {
      valueArrays.delete(handle);
      values.delete(handle);
    },
    storePayload(value) {
      const handle = nextValueHandle;
      nextValueHandle += 1;
      values.set(handle, value);
      return handle;
    },
  };
  const api = runInNewContext(
    `${executableGuestPromiseEffectRuntime(result.code)}
     ${bundleCode}
     ({
       cleanup: __convexWasmInvocationCleanup,
       settle: __convexWasmSettle,
       start: __convexEffectSite_ab12,
       startPair: admittedHandler,
     });`,
    sandbox
  );

  const orderedResult = api.startPair();
  assert.deepEqual(starts, [
    { arguments: ["document-id"], operationHandle: 1, operationId: 41 },
    { arguments: ["account-id"], operationHandle: 2, operationId: 42 },
  ]);
  let pairSettled = false;
  void orderedResult.then(() => {
    pairSettled = true;
  });
  api.settle(2, 0, sandbox.storePayload("account-result"));
  await Promise.resolve();
  assert.equal(pairSettled, false);
  api.settle(1, 0, sandbox.storePayload("document-result"));
  assert.deepEqual(Array.from(await orderedResult), ["document-result", "account-result"]);

  const startsBeforeUnknownVariant = starts.length;
  assert.throws(
    () => api.start("unknown-table", "unknown-id"),
    /Convex effect site received an unauthorized static operand/u
  );
  assert.equal(starts.length, startsBeforeUnknownVariant);

  const rejected = api.start("accounts", "rejected-id");
  const rejection = assert.rejects(rejected, /host rejected the effect/u);
  const rejectedOperationHandle = starts.at(-1).operationHandle;
  api.settle(rejectedOperationHandle, 1, sandbox.storePayload("host rejected the effect"));
  await rejection;
  assert.throws(
    () => api.settle(rejectedOperationHandle, 0, sandbox.storePayload("late completion")),
    /Convex async completion has no pending Promise/u
  );

  const abandoned = api.start("documents", "abandoned-id");
  const winner = api.start("accounts", "winner-id");
  const raced = Promise.race([abandoned, winner]);
  const winnerHandle = starts.at(-1).operationHandle;
  api.settle(winnerHandle, 0, sandbox.storePayload("winner-result"));
  assert.equal(await raced, "winner-result");
  assert.equal(api.cleanup(), 1);
  assert.equal(api.cleanup(), 0);
  const abandonedHandle = starts.at(-2).operationHandle;
  assert.throws(
    () => api.settle(abandonedHandle, 0, sandbox.storePayload("late abandoned result")),
    /Convex async completion has no pending Promise/u
  );
});

test("guest Promise host-error candidates preserve exact terminal error identity", async () => {
  const result = lower({
    bundleCode: `
      async function admittedHandler(ctx, args) {
        return await ctx.db.get("documents", args.id);
      }
    `,
    documentFields: [],
    effectExecutionMode: "guest-promise-event-loop",
    intrinsics: {},
    operations: [{ id: 1, kind: "databaseGet", table: "documents" }],
  });
  const values = new Map();
  const valueArrays = new Map();
  const starts = [];
  const reported = [];
  let nextHandle = 1;
  let nextOperationHandle = 1;
  const sandbox = {
    __convexAllocateUtf8: (message) => message,
    __convexAsyncBatchResultKind: () => "hostValue",
    __convexFree: () => {},
    __convexFromHost: (handle) => {
      const value = values.get(handle);
      values.delete(handle);
      return value;
    },
    __convexFromHostArrayTake: () => {
      throw new Error("unexpected array completion");
    },
    __convexHostAsyncOperationStartTake: (operationId, argumentsHandle) => {
      assert.equal(operationId, 1);
      valueArrays.delete(argumentsHandle);
      const operationHandle = nextOperationHandle;
      nextOperationHandle += 1;
      starts.push(operationHandle);
      return operationHandle;
    },
    __convexHostDeveloperError: (message, length, hostOperationErrorHandle) => {
      assert.equal(length, message.length);
      reported.push({ hostOperationErrorHandle, message });
    },
    __convexHostHasDeveloperError: () => 0,
    __convexToHost: (value) => {
      const handle = nextHandle;
      nextHandle += 1;
      values.set(handle, value);
      return handle;
    },
    __convexValueArrayNew: () => {
      const handle = nextHandle;
      nextHandle += 1;
      valueArrays.set(handle, []);
      return handle;
    },
    __convexValueArrayPush: (arrayHandle, valueHandle) => {
      valueArrays.get(arrayHandle).push(values.get(valueHandle));
      values.delete(valueHandle);
    },
    __convexValueRelease: () => {},
    __convexWriteUtf8: (message) => message.length,
    storePayload: (value) => {
      const handle = nextHandle;
      nextHandle += 1;
      values.set(handle, value);
      return handle;
    },
  };
  const api = runInNewContext(
    `${executableGuestPromiseEffectRuntime(result.code)}
     ({
       report: __convexReportThrown,
       settle: __convexWasmSettle,
       start: () => __convexStartAsyncOperation(1, ["document-id"]),
       wrapCausally: (promise) =>
         promise.catch((error) => {
           throw new Error("causal wrapper", { cause: error });
         }),
     });`,
    sandbox
  );

  async function settleRejected(promise) {
    const handle = starts.at(-1);
    api.settle(handle, 1, sandbox.storePayload("host rejected the effect"));
    let terminalError;
    await promise.catch((error) => {
      terminalError = error;
    });
    return { handle, terminalError };
  }

  const direct = await settleRejected(api.start());
  api.report(direct.terminalError);
  assert.deepEqual(reported.at(-1), {
    hostOperationErrorHandle: direct.handle,
    message: "Uncaught Error: host rejected the effect",
  });

  const rethrown = await settleRejected(
    api.start().catch((error) => {
      throw error;
    })
  );
  api.report(rethrown.terminalError);
  assert.deepEqual(reported.at(-1), {
    hostOperationErrorHandle: rethrown.handle,
    message: "Uncaught Error: host rejected the effect",
  });

  const causal = await settleRejected(api.wrapCausally(api.start()));
  api.report(causal.terminalError);
  assert.deepEqual(reported.at(-1), {
    hostOperationErrorHandle: causal.handle,
    message: "Uncaught Error: causal wrapper",
  });

  const wrapped = await settleRejected(
    api.start().catch(() => {
      throw new Error("wrapped rejection");
    })
  );
  api.report(wrapped.terminalError);
  assert.deepEqual(reported.at(-1), {
    hostOperationErrorHandle: 0,
    message: "Uncaught Error: wrapped rejection",
  });

  const cyclic = new Error("cyclic wrapper");
  Object.defineProperty(cyclic, "cause", { value: cyclic });
  api.report(cyclic);
  assert.deepEqual(reported.at(-1), {
    hostOperationErrorHandle: 0,
    message: "Uncaught Error: cyclic wrapper",
  });

  const accessor = new Error("accessor wrapper");
  Object.defineProperty(accessor, "cause", {
    get() {
      throw new Error("cause accessor was invoked");
    },
  });
  api.report(accessor);
  assert.deepEqual(reported.at(-1), {
    hostOperationErrorHandle: 0,
    message: "Uncaught Error: accessor wrapper",
  });

  const recovered = api.start().catch(() => "recovered");
  const recoveredHandle = starts.at(-1);
  api.settle(recoveredHandle, 1, sandbox.storePayload("host rejected the effect"));
  assert.equal(await recovered, "recovered");
  assert.equal(reported.length, 6);
});

test("guest Promise execution rejects legacy direct batch metadata", () => {
  const bundleCode =
    'function admittedHandler(ctx, args) { return Promise.all(args.ids.map((id) => ctx.db.get("documents", id))); }';
  const operation = { id: 1, kind: "databaseGet", table: "documents" };
  assert.throws(
    () =>
      lower({
        argumentFields: ["ids"],
        arrayArgumentFields: ["ids"],
        bundleCode,
        directAsyncBatches: [directBatchAuthorization(bundleCode, 1)],
        effectExecutionMode: "guest-promise-event-loop",
        intrinsics: {},
        operations: [operation],
      }),
    /does not accept directAsyncBatches/u
  );
});

function executableIndexQueryMatcher(code) {
  const start = code.indexOf("function __convexIndexQueryOperationId");
  const end = code.indexOf("function __convexDatabaseGetOperationId", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  return code.slice(start, end).replace(/: (?:\?number|\?string|number|string(?:\[\])?)/gu, "");
}

function directBatchAuthorization(source, operationId) {
  const batchSource = 'Promise.all(args.ids.map((id) => ctx.db.get("documents", id)))';
  const iteratorSource = "args.ids";
  const callbackSource = '(id) => ctx.db.get("documents", id)';
  const operationSource = 'ctx.db.get("documents", id)';
  const start = source.indexOf(batchSource);
  const iteratorStart = source.indexOf(iteratorSource, start);
  const callbackStart = source.indexOf(callbackSource, iteratorStart);
  const operationStart = source.indexOf(operationSource, callbackStart);
  const idExpression = "id";
  const idExpressionStart = source.indexOf(idExpression, operationStart + "ctx.db.get(".length);
  assert.notEqual(start, -1);
  return {
    argumentField: "ids",
    callbackEnd: callbackStart + Buffer.byteLength(callbackSource),
    callbackParameter: "id",
    callbackStart,
    column: start + 1,
    end: start + Buffer.byteLength(batchSource),
    file: "convex/direct.ts",
    generatedEnd: start + Buffer.byteLength(batchSource),
    generatedIteratorEnd: iteratorStart + Buffer.byteLength(iteratorSource),
    generatedIteratorSha256: sha256(iteratorSource),
    generatedIteratorStart: iteratorStart,
    generatedSourceSha256: sha256(batchSource),
    generatedStart: start,
    id: "batch_0123456789abcdef",
    kind: "singleEffectMap",
    helperContinuationPrebound: false,
    line: 1,
    operationEnd: operationStart + Buffer.byteLength(operationSource),
    operationId,
    operationKind: "databaseGet",
    operationStart,
    resultKind: "hostValue",
    source: batchSource,
    sourceSha256: sha256(batchSource),
    start,
    dynamicArguments: [
      {
        generatedEnd: idExpressionStart + Buffer.byteLength(idExpression),
        generatedSha256: sha256(idExpression),
        generatedStart: idExpressionStart,
        source: idExpression,
        sourceEnd: idExpressionStart + Buffer.byteLength(idExpression),
        sourceSha256: sha256(idExpression),
        sourceStart: idExpressionStart,
      },
    ],
  };
}

function fixedBatchAuthorization(source, operationIds) {
  const batchSource =
    'Promise.all([ctx.db.get("documents", args.id), ctx.db.patch("documents", args.id, { state: "done" })])';
  const childSources = [
    'ctx.db.get("documents", args.id)',
    'ctx.db.patch("documents", args.id, { state: "done" })',
  ];
  const start = source.indexOf(batchSource);
  assert.notEqual(start, -1);
  const children = childSources.map((childSource, index) => {
    const childStart = source.indexOf(childSource, start);
    const childEnd = childStart + Buffer.byteLength(childSource);
    const argumentSources = index === 0 ? ["args.id"] : ["args.id", '{ state: "done" }'];
    let argumentSearchStart = childStart;
    const dynamicArguments = argumentSources.map((argumentSource) => {
      const argumentStart = source.indexOf(argumentSource, argumentSearchStart);
      const argumentEnd = argumentStart + Buffer.byteLength(argumentSource);
      argumentSearchStart = argumentEnd;
      return {
        generatedEnd: argumentEnd,
        generatedSha256: sha256(argumentSource),
        generatedStart: argumentStart,
        source: argumentSource,
        sourceEnd: argumentEnd,
        sourceSha256: sha256(argumentSource),
        sourceStart: argumentStart,
      };
    });
    return {
      dynamicArguments,
      end: childEnd,
      generatedEnd: childEnd,
      generatedSourceSha256: sha256(childSource),
      generatedStart: childStart,
      helperContinuationPrebound: false,
      operationEnd: childEnd,
      operationId: operationIds[index],
      operationKind: index === 0 ? "databaseGet" : "databasePatch",
      operationStart: childStart,
      resultKind: index === 0 ? "hostValue" : "undefined",
      source: childSource,
      sourceSha256: sha256(childSource),
      start: childStart,
    };
  });
  return {
    children,
    column: start + 1,
    end: start + Buffer.byteLength(batchSource),
    file: "convex/fixed.ts",
    generatedEnd: start + Buffer.byteLength(batchSource),
    generatedSourceSha256: sha256(batchSource),
    generatedStart: start,
    id: "batch_fedcba9876543210",
    kind: "fixedEffectArray",
    line: 1,
    source: batchSource,
    sourceSha256: sha256(batchSource),
    start,
  };
}

test("lowers admitted sequential awaits and the SHA-256 intrinsic", () => {
  const result = lower();

  assert.equal(result.loweringInputs.format, convexWasmLoweringFormat);
  assert.equal(result.loweringInputs.abiVersion, convexWasmOpaqueAbiVersion);
  assert.deepEqual(result.loweringInputs.intrinsicHardening, {
    kind: convexWasmIntrinsicHardeningPolicy.kind,
    policySha256: convexWasmIntrinsicHardeningPolicySha256,
    sourceSha256: convexWasmIntrinsicHardeningSourceSha256,
  });
  // Intrinsic hardening owns an async literal so it can tame AsyncFunction construction.
  assert.doesNotMatch(result.code, /async function admittedHandler\b/u);
  assert.doesNotMatch(result.code, /\bawait\b/);
  assert.doesNotMatch(result.code, /\bexport\b/);
  assert.match(result.code, /return __convexSha256\(9, input\);/);
  assert.match(
    result.code,
    /const __convexResult = admittedHandler\(__convexContext, __convexArgs\);/
  );
  const matcher = executableIndexQueryMatcher(result.code);
  assert.equal(
    runInNewContext(
      `${matcher}; __convexIndexQueryOperationId("documents", "by_hash", ["hash"], ["eq"], null, "unique", null)`
    ),
    7
  );
  assert.throws(
    () =>
      runInNewContext(
        `${matcher}; __convexIndexQueryOperationId("documents", "by_hash", ["hash"], ["eq"], null, "collect", null)`
      ),
    /Convex operation was not admitted/u
  );
  const loweredBundle = result.code
    .split("\n")
    .slice(result.bundleLayout.startLine - 1, result.bundleLayout.endLine)
    .join("\n");
  assert.doesNotMatch(loweredBundle, /\.prototype/u);
  assert.doesNotMatch(loweredBundle, /Array\.isArray/u);
});

test("lowers host-secret verification without exposing configured secret material", () => {
  const result = lower({
    bundleCode: `
      function admittedHandler(_ctx, args) {
        const result = __convexVerifyHostSecret(11, args.key);
        if (result < 0) throw new Error("WORKER_SECRET is not set");
        if (result !== 1) throw new Error("Unauthorized");
        return null;
      }
    `,
    intrinsics: {},
    operations: [
      {
        contractVersion: 1,
        id: 11,
        kind: "hostSecretVerify",
        selector: "WORKER_SECRET",
      },
    ],
  });

  assert.equal(result.loweringInputs.operations[0].selector, "WORKER_SECRET");
  assert.match(result.code, /convex_host_secret_verify/u);
  assert.match(result.code, /typeof providedValue !== "string"/u);
  assert.doesNotMatch(result.code, /configured-secret-sentinel/u);
  assert.match(renderOpaqueAbiHeader(), /convex_host_secret_verify/u);
});

test("binds invocation time to one authenticated per-attempt host import", () => {
  const baseline = lower({
    bundleCode: "function admittedHandler() { return 0; }",
    intrinsics: {},
    operations: [],
  });
  const result = lower({
    bundleCode:
      "function admittedHandler() { return [__convexInvocationUnixTimestampMs(), __convexInvocationUnixTimestampMs()]; }",
    intrinsics: {},
    operations: [],
    runtimeInputs: ["invocationUnixTimestampMs"],
  });

  assert.deepEqual(result.loweringInputs.runtimeInputs, ["invocationUnixTimestampMs"]);
  assert.notEqual(result.loweringFingerprint, baseline.loweringFingerprint);
  assert.equal(
    result.code.match(/function convex_invocation_unix_timestamp_ms\(\): c_double \{ throw 0; \}/gu)
      ?.length,
    1
  );
  assert.match(
    result.code,
    /function __convexInvocationUnixTimestampMs\(\): number \{\s*return __convexHostInvocationUnixTimestampMs\(\);\s*\}/u
  );
  assert.match(
    renderOpaqueAbiHeader(),
    /CONVEX_WASM_IMPORT\("convex_invocation_unix_timestamp_ms"\)\s*double convex_invocation_unix_timestamp_ms\(void\);/u
  );
  assert.doesNotMatch(baseline.code, /function convex_invocation_unix_timestamp_ms\(/u);
});

test("rejects missing, duplicated, and unknown runtime input contracts", () => {
  assert.throws(() => lower({ runtimeInputs: undefined }), /runtimeInputs must be an array/u);
  assert.throws(
    () => lower({ runtimeInputs: ["invocationUnixTimestampMs", "invocationUnixTimestampMs"] }),
    /must not contain duplicates/u
  );
  assert.throws(() => lower({ runtimeInputs: ["randomSeed"] }), /Unsupported runtime input/u);
});

test("matches implicit ascending take queries to authenticated collect operations", () => {
  for (const limit of [1, 2, 100_000]) {
    const result = lower({
      bundleCode: `
        function admittedHandler(ctx, args) {
          return ctx.db
            .query("documents")
            .withIndex("by_owner", (q) => q.eq("owner", args.key))
            .take(${limit});
        }
      `,
      intrinsics: {},
      operations: [
        {
          constraints: [{ field: "owner", operator: "eq" }],
          id: 12,
          index: "by_owner",
          kind: "databaseIndexQuery",
          limit,
          order: "ascending",
          table: "documents",
          terminal: "collect",
        },
      ],
    });
    assert.match(
      result.code,
      new RegExp(
        `normalizedOrder === "ascending" && normalizedTerminal === "collect" && limit === ${limit}`
      )
    );
    assert.match(result.code, /constraintFields: string\[\]/u);
    assert.match(result.code, /constraintOperators: string\[\]/u);
    assert.match(result.code, new RegExp(`\\.take\\(${limit}\\)`));
    assert.match(result.code, /const selected = operation\("take", limit\);/u);

    const operationId = runInNewContext(
      `${executableIndexQueryMatcher(result.code)};
       __convexIndexQueryOperationId(
         "documents",
         "by_owner",
         ["owner"],
         ["eq"],
         null,
         "take",
         ${limit},
       )`
    );
    assert.equal(operationId, 12);
  }

  for (const limit of [0, 100_001, 1.5]) {
    assert.throws(
      () =>
        lower({
          intrinsics: {},
          operations: [
            {
              constraints: [{ field: "owner", operator: "eq" }],
              id: 12,
              index: "by_owner",
              kind: "databaseIndexQuery",
              limit,
              order: "ascending",
              table: "documents",
              terminal: "collect",
            },
          ],
        }),
      /limit must be null or between 1 and 100000/u
    );
  }
});

test("selects exact index query operations from typed primitive descriptor arrays", () => {
  const result = lower({
    intrinsics: {},
    operations: [
      {
        constraints: [{ field: "owner", operator: "eq" }],
        id: 12,
        index: "by_owner",
        kind: "databaseIndexQuery",
        limit: 2,
        order: "ascending",
        table: "documents",
        terminal: "collect",
      },
      {
        constraints: [
          { field: "owner", operator: "eq" },
          { field: "updated", operator: "gt" },
        ],
        id: 13,
        index: "by_owner",
        kind: "databaseIndexQuery",
        limit: 1,
        order: "descending",
        table: "documents",
        terminal: "collect",
      },
    ],
  });
  const matcher = executableIndexQueryMatcher(result.code);

  assert.equal(
    runInNewContext(
      `${matcher}; __convexIndexQueryOperationId("documents", "by_owner", ["owner"], ["eq"], null, "take", 2)`
    ),
    12
  );
  assert.equal(
    runInNewContext(
      `${matcher}; __convexIndexQueryOperationId("documents", "by_owner", ["owner", "updated"], ["eq", "gt"], "desc", "take", 1)`
    ),
    13
  );
  assert.throws(
    () =>
      runInNewContext(
        `${matcher}; __convexIndexQueryOperationId("documents", "by_owner", ["owner", "updated"], ["eq", "gte"], "desc", "take", 1)`
      ),
    /Convex operation was not admitted/u
  );
});

test("schema-6 static arity-one index queries pass one positional opaque array", () => {
  for (const valueMode of ["opaque", "guest-native-json"]) {
    const result = lower({
      bundleCode: `
        function admittedHandler(ctx, args) {
          return ctx.db
            .query("documents")
            .withIndex("by_owner", (q) => q.eq("owner", args.key))
            .unique();
        }
      `,
      intrinsics: {},
      operations: [
        {
          constraints: [{ field: "owner", operator: "eq" }],
          id: 12,
          index: "by_owner",
          kind: "databaseIndexQuery",
          limit: null,
          order: "ascending",
          table: "documents",
          terminal: "unique",
        },
      ],
      valueMode,
    });
    assert.match(
      result.code,
      /__convex(?:Guest)?ToHost\(__convexMarkArray\(values\)\)/u,
      valueMode
    );
    assert.match(
      result.code,
      /__convexHostQueryStartValue\(operationId, transferredValuesHandle\)/u,
      valueMode
    );
    assert.doesNotMatch(result.code, /values\.length === 1|__convexHostQueryStartUtf8/u);
  }
});

test("schema-6 dynamic take appends its limit after query constraints", () => {
  const result = lower({
    intrinsics: {},
    operations: [
      {
        constraints: [{ field: "owner", operator: "eq" }],
        id: 17,
        index: "by_owner",
        kind: "databaseIndexQuery",
        limit: null,
        limitArgumentIndex: 1,
        order: "ascending",
        table: "documents",
        terminal: "collect",
      },
    ],
  });
  const matcher = executableIndexQueryMatcher(result.code);
  assert.equal(
    runInNewContext(
      `${matcher}; __convexIndexQueryOperationId("documents", "by_owner", ["owner"], ["eq"], null, "take", 7)`
    ),
    17
  );
  assert.throws(
    () =>
      runInNewContext(
        `${matcher}; __convexIndexQueryOperationId("documents", "by_owner", ["owner"], ["eq"], null, "collect", null)`
      ),
    /Convex operation was not admitted/u
  );
  assert.match(result.code, /if \(operationId === 17\) return 2;/u);
  assert.match(result.code, /__convexArrayPush\(operationArguments, limit\)/u);
});

test("preserves ordered compound index constraints through one existing query-start import", () => {
  const constraints = [
    { field: "owner", operator: "eq" },
    { field: "kind", operator: "eq" },
    { field: "terminal", operator: "eq" },
    { field: "active", operator: "eq" },
    { field: "updated", operator: "gt" },
  ];
  const result = lower({
    bundleCode: `
      function admittedHandler(ctx, args) {
        return ctx.db
          .query("documents")
          .withIndex("by_owner_kind_terminal_active_updated", (q) => q
            .eq("owner", args.key)
            .eq("kind", "worker")
            .eq("terminal", undefined)
            .eq("active", true)
            .gt("updated", 17))
          .order("desc")
          .take(2);
      }
    `,
    intrinsics: {},
    operations: [
      {
        constraints,
        id: 13,
        index: "by_owner_kind_terminal_active_updated",
        kind: "databaseIndexQuery",
        limit: 2,
        order: "descending",
        table: "documents",
        terminal: "collect",
      },
    ],
  });

  assert.match(result.code, /constraintFields\.length === 5/u);
  assert.match(result.code, /constraintOperators\.length === 5/u);
  assert.match(result.code, /constraintFields\[4\] === "updated"/u);
  assert.match(result.code, /constraintOperators\[4\] === "gt"/u);
  assert.match(result.code, /if \(operationId === 13\) return 5;/u);
  assert.match(result.code, /__convexHostQueryStartValue\(operationId, transferredValuesHandle\)/u);
  assert.match(result.code, /__convexToHost\(__convexMarkArray\(values\)\)/u);
  assert.doesNotMatch(result.code, /values\.length === 1/u);
  assert.equal(
    (result.code.match(/function convex_query_start_value\(/gu) ?? []).length,
    1,
    "compound queries must reuse the existing value-handle query-start import"
  );

  assert.doesNotThrow(() =>
    lower({
      intrinsics: {},
      operations: [
        {
          constraints: [{ field: "updated", operator: "gt" }],
          id: 14,
          index: "by_updated",
          kind: "databaseIndexQuery",
          limit: 2,
          order: "ascending",
          table: "documents",
          terminal: "collect",
        },
      ],
    })
  );

  for (const invalidConstraints of [
    [
      { field: "owner", operator: "eq" },
      { field: "updated", operator: "gt" },
      { field: "kind", operator: "eq" },
    ],
    [
      { field: "owner", operator: "eq" },
      { field: "updated", operator: "gt" },
      { field: "created", operator: "lt" },
    ],
    [
      { field: "owner", operator: "eq" },
      { field: "owner", operator: "eq" },
    ],
  ]) {
    assert.throws(
      () =>
        lower({
          intrinsics: {},
          operations: [
            {
              constraints: invalidConstraints,
              id: 13,
              index: "by_owner_updated",
              kind: "databaseIndexQuery",
              limit: 2,
              order: "ascending",
              table: "documents",
              terminal: "collect",
            },
          ],
        }),
      /must precede the range|at most one final range|must be unique/u
    );
  }
});

test("routes generated array growth through the typed Static Hermes FastArray boundary", () => {
  const code = lower({ valueMode: "guest-native-json" }).code;

  assert.match(
    code,
    /function __convexArrayPush\(values: any\[\], value: any\): void \{\s*\/\/ Static Hermes lowers this typed boundary to its FastArray push primitive\.\s*values\.push\(value\);\s*\}/u
  );
  assert.equal(
    code.match(/\.push\(/gu)?.length,
    2,
    "only typed FastArray boundaries may use push syntax"
  );
  assert.match(code, /const nextFields: any\[\] = \[\];/u);
  assert.match(code, /const nextOperators: any\[\] = \[\];/u);
  assert.match(code, /const nextValues: any\[\] = \[\];/u);
  assert.match(code, /__convexArrayPush\(nextFields, field\);/u);
  assert.match(code, /__convexArrayPush\(nextOperators, operator\);/u);
  assert.match(code, /__convexArrayPush\(nextValues, value\);/u);
});

test("assembles compiler-lowered arrows and function expressions without reparsing", () => {
  const conciseArrow = lower({
    bundleCode: `
      function helper(value) {
        return value;
      }
      const admittedHandler = (_ctx, args) => helper(args.key);
    `,
    intrinsics: {},
    operations: [],
  });
  assert.doesNotMatch(conciseArrow.code, /const admittedHandler = async\b/u);
  assert.doesNotMatch(conciseArrow.code, /\bawait\b/u);
  assert.match(
    conciseArrow.code,
    /const admittedHandler = \(_ctx, args\) => helper\(args\.key\);/u
  );

  const functionExpression = lower({
    bundleCode: `
      const helper = (value) => value;
      const admittedHandler = function (_ctx, args) {
        return helper(args.key);
      };
    `,
    intrinsics: {},
    operations: [],
  });
  assert.doesNotMatch(functionExpression.code, /const admittedHandler = async\b/u);
  assert.doesNotMatch(functionExpression.code, /\bawait\b/u);
  assert.match(functionExpression.code, /const helper = \(value\) => value;/u);
  assert.match(functionExpression.code, /const admittedHandler = function \(_ctx, args\)/u);
});

test("normalizes generated inputs while binding exact compiler operation order", () => {
  const secondOperation = {
    id: 3,
    kind: "databaseIndexQuery",
    table: "documents",
    index: "by_owner",
    constraints: [{ field: "owner", operator: "eq" }],
    limit: null,
    order: "descending",
    terminal: "collect",
  };
  const first = lower({
    argumentFields: ["key", "optional", "key"],
    documentFields: ["enabled", "_id", "enabled"],
    operations: [lower().loweringInputs.operations[0], secondOperation],
  });
  const second = lower({
    argumentFields: ["optional", "key"],
    documentFields: ["_id", "enabled"],
    operations: [secondOperation, lower().loweringInputs.operations[0]],
  });

  assert.deepEqual(first.loweringInputs.argumentFields, ["key", "optional"]);
  assert.deepEqual(first.loweringInputs.documentFields, ["_id", "enabled"]);
  assert.deepEqual(
    first.loweringInputs.operations.map(({ id }) => id),
    [3, 7]
  );
  assert.notEqual(first.loweringFingerprint, second.loweringFingerprint);
  assert.equal(first.codeSha256, second.codeSha256);
});

test("binds normalized applied dependency material into the lowering fingerprint", () => {
  const first = lower({
    appliedDependencyAdapters: [{ adapterId: "fixtureV1", material: { sha256: "a".repeat(64) } }],
  });
  const reordered = lower({
    appliedDependencyAdapters: [{ material: { sha256: "a".repeat(64) }, adapterId: "fixtureV1" }],
  });
  const changed = lower({
    appliedDependencyAdapters: [{ adapterId: "fixtureV1", material: { sha256: "b".repeat(64) } }],
  });

  assert.equal(first.loweringFingerprint, reordered.loweringFingerprint);
  assert.notEqual(first.loweringFingerprint, changed.loweringFingerprint);
});

test("mechanically preserves compiler-owned bundle text", () => {
  const marker = 'const compilerOwnedMarker = "Promise async await";';
  const result = lower({
    bundleCode: `${marker}\nfunction admittedHandler() { return null; }`,
    intrinsics: {},
    operations: [],
  });
  assert.match(result.code, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.equal(result.loweringInputs.directAsyncBatches.length, 0);
});

test("filters with indexed iteration and the standard predicate arguments", () => {
  const code = lower().code;
  const helperStart = code.indexOf("function __convexFilter");
  const helperEnd = code.indexOf("function __convexIsKnownArray", helperStart);
  assert.notEqual(helperStart, -1);
  assert.notEqual(helperEnd, -1);
  const helperSource = code.slice(helperStart, helperEnd);
  const filter = runInNewContext(`${helperSource}; __convexFilter`, {
    __convexArrayPush(values, value) {
      values.push(value);
    },
  });
  const values = ["first", "second", "third", "fourth"];
  const calls = [];

  const result = filter(values, (value, index, receivedValues) => {
    calls.push({ value, index, receivedValues });
    return index % 2 === 0;
  });

  assert.deepEqual([...result], ["first", "third"]);
  assert.deepEqual(
    calls.map(({ value, index }) => ({ value, index })),
    [
      { value: "first", index: 0 },
      { value: "second", index: 1 },
      { value: "third", index: 2 },
      { value: "fourth", index: 3 },
    ]
  );
  assert.ok(calls.every(({ receivedValues }) => receivedValues === values));
});

test("exposes admitted document fields without array-container getters", () => {
  const bundleCode = "function admittedHandler() { return null; }";
  const code = lower({
    bundleCode,
    documentFields: ["_id", "outreachFirstTouchDailyLimit"],
    intrinsics: {},
    operations: [],
  }).code;
  const wrapperStart = code.indexOf("let __convexLiveOpaqueValues");
  const wrapperEnd = code.indexOf(bundleCode, wrapperStart);
  assert.notEqual(wrapperStart, -1);
  assert.notEqual(wrapperEnd, -1);
  const reads = [];
  const document = runInNewContext(
    `${code.slice(wrapperStart, wrapperEnd)}; __convexWrapObject(41)`,
    {
      __convexReadField(handle, field) {
        reads.push({ field, handle });
        return field === "_id" ? "account-41" : 17;
      },
      __convexArrayPush(values, value) {
        values.push(value);
      },
      __convexValueRelease() {},
    }
  );

  assert.equal(document._id, "account-41");
  assert.equal(document.outreachFirstTouchDailyLimit, 17);
  assert.deepEqual(reads, [
    { field: "_id", handle: 41 },
    { field: "outreachFirstTouchDailyLimit", handle: 41 },
  ]);
  assert.equal(Object.getOwnPropertyDescriptor(document, "filter"), undefined);
  assert.equal(Object.getOwnPropertyDescriptor(document, "length"), undefined);
});

test("assembles compiler-authorized generic batch metadata through opaque ABI v3", () => {
  const generatedSource = 'Promise.all(args.ids.map((id) => ctx.db.get("documents", id)))';
  const bundleCode =
    "function admittedHandler(ctx, args) { return __convexAsyncBatch(args.ids, 11, (id) => [id]); }";
  const authorization = directBatchAuthorization(generatedSource, 11);
  const result = lower({
    argumentFields: ["ids"],
    arrayArgumentFields: ["ids"],
    bundleCode,
    directAsyncBatches: [authorization],
    documentFields: ["_id"],
    intrinsics: {},
    operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
  });

  assert.equal(convexWasmOpaqueAbiVersion, 3);
  assert.equal(convexWasmLoweringFormat, "convex-wasm-lowered-guest-v37");
  const runtimeStart = result.code.indexOf("const __convexMalloc");
  assert.notEqual(runtimeStart, -1);
  assert.doesNotMatch(result.code.slice(runtimeStart), /\bPromise\b|\basync\b|\bawait\b/u);
  assert.match(result.code, /return __convexAsyncBatch\(args\.ids, 11, \(id\) => \[id\]\);/u);
  assert.match(result.code, /"ids": __convexReadRequestArrayField\("ids"\)/u);
  assert.match(
    result.code,
    /const transferredInvocationsHandle = invocationsHandle;\s*invocationsHandle = 0;\s*const resultArrayHandle = __convexAsyncBatchTake\(transferredInvocationsHandle\);/u
  );
  assert.match(
    result.code,
    /return __convexFromBatchResultArrayTake\(resultArrayHandle, values\.length, resultKind\);/u
  );
  assert.match(
    result.code,
    /resultKind === "hostArray"[\s\S]*__convexFromHostArrayTake\(elementHandle, -1\)/u
  );
  assert.match(
    result.code,
    /resultKind === "undefined"[\s\S]*__convexBatchUndefinedTake\(elementHandle\)/u
  );
  assert.match(
    result.code,
    /function __convexBatchUndefinedTake\(handle: number\): void \{[\s\S]*return;/u
  );
  assert.match(
    result.code,
    /__convexHostValueType\(handle\) !== 6[\s\S]*__convexReadField\(handle, "\$convexWasmBatchUndefined"\) !== true/u
  );
  assert.match(
    result.code,
    /function __convexFromHostArrayTake[\s\S]*finally \{\s*__convexValueRelease\(arrayHandle\);\s*\}/u
  );
  assert.match(result.code, /return __convexMarkArray\(result\);/u);
  assert.match(result.code, /if \(__convexIsKnownArray\(value\)\) \{/u);
  assert.throws(
    () =>
      lower({
        argumentFields: ["ids"],
        arrayArgumentFields: ["ids"],
        bundleCode,
        directAsyncBatches: [
          {
            ...authorization,
            resultKind: "undefined",
          },
        ],
        intrinsics: {},
        operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
      }),
    /result or argument contract disagrees with its operation descriptor/u
  );
  assert.throws(
    () =>
      lower({
        argumentFields: ["ids"],
        arrayArgumentFields: ["ids"],
        bundleCode,
        directAsyncBatches: [
          {
            ...authorization,
            source: "Promise.all([])",
          },
        ],
        intrinsics: {},
        operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
      }),
    /original source does not match its compiler authorization/u
  );
  const changedGeneratedHash = lower({
    argumentFields: ["ids"],
    arrayArgumentFields: ["ids"],
    bundleCode,
    directAsyncBatches: [
      {
        ...authorization,
        generatedSourceSha256: "0".repeat(64),
      },
    ],
    documentFields: ["_id"],
    intrinsics: {},
    operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
  });
  assert.notEqual(changedGeneratedHash.loweringFingerprint, result.loweringFingerprint);
  assert.equal(changedGeneratedHash.codeSha256, result.codeSha256);

  const shiftedAuthorization = structuredClone(authorization);
  const generatedOffset = Buffer.byteLength(bundleCode) + 100;
  for (const field of ["generatedStart", "generatedEnd"]) {
    shiftedAuthorization[field] += generatedOffset;
  }
  for (const field of ["generatedIteratorStart", "generatedIteratorEnd"]) {
    shiftedAuthorization[field] += generatedOffset;
  }
  for (const argument of shiftedAuthorization.dynamicArguments) {
    argument.generatedStart += generatedOffset;
    argument.generatedEnd += generatedOffset;
  }
  const shiftedGeneratedProof = lower({
    argumentFields: ["ids"],
    arrayArgumentFields: ["ids"],
    bundleCode,
    directAsyncBatches: [shiftedAuthorization],
    documentFields: ["_id"],
    intrinsics: {},
    operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
  });
  assert.notEqual(shiftedGeneratedProof.loweringFingerprint, result.loweringFingerprint);
  assert.equal(shiftedGeneratedProof.codeSha256, result.codeSha256);
  assert.throws(
    () =>
      lower({
        argumentFields: ["ids"],
        arrayArgumentFields: ["ids"],
        bundleCode,
        directAsyncBatches: [
          {
            ...authorization,
            end: authorization.end + 1,
          },
        ],
        intrinsics: {},
        operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
      }),
    /original source does not match its compiler authorization/u
  );
  const changedGeneratedArgumentHash = lower({
    argumentFields: ["ids"],
    arrayArgumentFields: ["ids"],
    bundleCode,
    directAsyncBatches: [
      {
        ...authorization,
        dynamicArguments: [
          {
            ...authorization.dynamicArguments[0],
            generatedSha256: "0".repeat(64),
          },
        ],
      },
    ],
    documentFields: ["_id"],
    intrinsics: {},
    operations: [{ id: 11, kind: "databaseGet", table: "documents" }],
  });
  assert.notEqual(changedGeneratedArgumentHash.loweringFingerprint, result.loweringFingerprint);
  assert.equal(changedGeneratedArgumentHash.codeSha256, result.codeSha256);
});

test("mapped helper continuations authorize exact duplicate effect projections", () => {
  const generatedSource = 'Promise.all(args.ids.map((id) => ctx.db.get("documents", id)))';
  const authorization = directBatchAuthorization(generatedSource, 11);
  authorization.helperContinuationPrebound = true;
  authorization.operationKind = "databasePatch";
  authorization.resultKind = "undefined";
  authorization.dynamicArguments.push(structuredClone(authorization.dynamicArguments[0]));
  const options = {
    argumentFields: ["ids"],
    arrayArgumentFields: ["ids"],
    bundleCode:
      "function admittedHandler(ctx, args) { return __convexAsyncBatch(args.ids, 11, (id) => [id, id]); }",
    directAsyncBatches: [authorization],
    documentFields: [],
    intrinsics: {},
    operations: [{ id: 11, kind: "databasePatch", table: "documents" }],
  };

  assert.doesNotThrow(() => lower(options));
  authorization.helperContinuationPrebound = false;
  assert.throws(() => lower(options), /changed source or generated argument order/u);
});

test("assembles ordered heterogeneous fixed batches and rejects reordered authorizations", () => {
  const generatedSource =
    'Promise.all([ctx.db.get("documents", args.id), ctx.db.patch("documents", args.id, { state: "done" })])';
  const bundleCode = `function admittedHandler(ctx, args) {
    return __convexAsyncFixedBatch([11, 12], [[args.id], [args.id, { state: "done" }]]);
  }`;
  const authorization = fixedBatchAuthorization(generatedSource, [11, 12]);
  const options = {
    argumentFields: ["id"],
    bundleCode,
    directAsyncBatches: [authorization],
    documentFields: ["_id"],
    intrinsics: {},
    operations: [
      { id: 11, kind: "databaseGet", table: "documents" },
      { id: 12, kind: "databasePatch", table: "documents" },
    ],
  };
  const result = lower(options);

  assert.match(
    result.code,
    /return __convexAsyncFixedBatch\(\[11, 12\], \[\[args\.id\], \[args\.id, \{ state: "done" \}\]\]\);/u
  );
  assert.match(
    result.code,
    /__convexFromFixedBatchResultArrayTake\(resultArrayHandle, operationIds\)/u
  );
  assert.match(result.code, /__convexAsyncBatchResultKind\(operationIds\[index\]\)/u);
  assert.deepEqual(
    result.loweringInputs.directAsyncBatches[0].children.map((child) => ({
      operationId: child.operationId,
      resultKind: child.resultKind,
    })),
    [
      { operationId: 11, resultKind: "hostValue" },
      { operationId: 12, resultKind: "undefined" },
    ]
  );

  const duplicateArgument = authorization.children[1].dynamicArguments[0];
  const continuationAuthorization = structuredClone(authorization);
  continuationAuthorization.children[1].helperContinuationPrebound = true;
  continuationAuthorization.children[1].dynamicArguments = [
    duplicateArgument,
    structuredClone(duplicateArgument),
  ];
  assert.doesNotThrow(() =>
    lower({
      ...options,
      directAsyncBatches: [continuationAuthorization],
    })
  );
  continuationAuthorization.children[1].helperContinuationPrebound = false;
  assert.throws(
    () =>
      lower({
        ...options,
        directAsyncBatches: [continuationAuthorization],
      }),
    /changed source or generated argument order/u
  );

  assert.throws(
    () =>
      lower({
        ...options,
        directAsyncBatches: [{ ...authorization, children: [...authorization.children].reverse() }],
      }),
    /fixed children overlap or changed order/u
  );
  const changedGeneratedChildHash = lower({
    ...options,
    directAsyncBatches: [
      {
        ...authorization,
        children: authorization.children.map((child, index) =>
          index === 0 ? { ...child, generatedSourceSha256: "0".repeat(64) } : child
        ),
      },
    ],
  });
  assert.notEqual(changedGeneratedChildHash.loweringFingerprint, result.loweringFingerprint);
  assert.equal(changedGeneratedChildHash.codeSha256, result.codeSha256);
  assert.throws(
    () =>
      lower({
        ...options,
        directAsyncBatches: [
          {
            ...authorization,
            children: authorization.children.map((child, index) =>
              index === 1
                ? { ...child, dynamicArguments: [...child.dynamicArguments].reverse() }
                : child
            ),
          },
        ],
      }),
    /changed source or generated argument order/u
  );
  assert.throws(
    () =>
      lower({
        ...options,
        directAsyncBatches: [
          {
            ...authorization,
            children: authorization.children.map((child, index) =>
              index === 0 ? { ...child, operationId: 12 } : child
            ),
          },
        ],
      }),
    /does not identify its admitted operation descriptor/u
  );
});

test("marks admitted array-producing expressions for typed result encoding", () => {
  const result = lower({
    bundleCode: `
      function admittedHandler(_ctx, args) {
        const values = __convexMarkArray([args.key]);
        return __convexMarkArray(values.map((value) => value));
      }
    `,
    intrinsics: {},
    operations: [],
  });

  assert.match(result.code, /const values = __convexMarkArray\(\[args\.key\]\);/u);
  assert.match(result.code, /return __convexMarkArray\(values\.map\(\(value\) => value\)\);/u);
  assert.doesNotMatch(result.code, /Array\.isArray|instanceof Array/u);
});

test("rejects duplicate or malformed manifest operations", () => {
  const operation = {
    id: 1,
    kind: "databaseIndexQuery",
    table: "documents",
    index: "by_hash",
    constraints: [{ field: "hash", operator: "eq" }],
    limit: null,
    order: "ascending",
    terminal: "unique",
  };
  assert.throws(
    () => lower({ operations: [operation, { ...operation }] }),
    /Duplicate operation ID 1/
  );
  assert.throws(
    () => lower({ operations: [{ ...operation, terminal: "paginate" }] }),
    /terminal must be "collect", "first", "stream", or "unique"/
  );
  assert.throws(
    () => lower({ operationsSha256: "invalid" }),
    /operationsSha256 must be a lowercase SHA-256 digest/u
  );
});

test("binds the authenticated compiler operation identity into lowering identity", () => {
  const baseline = lower();
  const changed = lower({ operationsSha256: "f".repeat(64) });
  assert.equal(changed.codeSha256, baseline.codeSha256);
  assert.notEqual(changed.loweringFingerprint, baseline.loweringFingerprint);
  assert.equal(
    baseline.loweringInputs.operationsSha256,
    sha256(
      JSON.stringify([
        {
          id: 7,
          kind: "databaseIndexQuery",
          table: "documents",
          index: "by_hash",
          constraints: [{ field: "hash", operator: "eq" }],
          limit: null,
          order: "ascending",
          terminal: "unique",
        },
      ])
    )
  );
});

test("renders explicit convex-module WebAssembly imports", () => {
  const header = renderOpaqueAbiHeader();
  const lowered = lower().code;

  assert.match(header, /import_module\("convex"\)/);
  assert.match(header, /CONVEX_WASM_IMPORT\("convex_query_start_value"\)/);
  assert.match(header, /long long convex_db_get\(int operation_id, long long id_handle\);/u);
  assert.match(
    header,
    /long long convex_db_normalize_id\(int operation_id, long long consuming_value_handle\);/u
  );
  assert.match(header, /long long convex_async_batch_take\(long long invocations\);/u);
  assert.match(header, /int convex_async_operation_cancel_all\(void\);/u);
  assert.match(
    header,
    /CONVEX_WASM_IMPORT\("convex_async_operation_poll_ready"\)\s*int convex_async_operation_poll_ready\(void\);/u
  );
  assert.match(header, /int convex_value_array_len\(long long array_handle\);/u);
  assert.match(header, /long long convex_value_array_get\(long long array_handle, int index\);/u);
  assert.match(
    header,
    /long long convex_db_write\(\s*int operation_id,\s*long long first_handle,\s*long long second_handle\);/u
  );
  assert.match(
    header,
    /long long convex_scheduler_schedule\(\s*int operation_id,\s*double time_ms,\s*long long args_handle\);/u
  );
  assert.match(header, /CONVEX_WASM_IMPORT\("convex_function_result"\)/);
  assert.match(
    header,
    /CONVEX_WASM_IMPORT\("convex_crypto_get_random_values"\)\s*void convex_crypto_get_random_values\(\s*long long capability_identity,\s*char \*output,\s*int output_len\);/u
  );
  assert.match(
    header,
    /CONVEX_WASM_IMPORT\("convex_crypto_random_uuid"\)\s*void convex_crypto_random_uuid\(\s*long long capability_identity,\s*char \*output,\s*int output_len\);/u
  );
  assert.match(
    header,
    /CONVEX_WASM_IMPORT\("convex_math_random"\)\s*double convex_math_random\(long long capability_identity\);/u
  );
  assert.match(
    header,
    /CONVEX_WASM_IMPORT\("convex_console_message"\)\s*int convex_console_message\(\s*long long capability_identity,\s*int level,\s*const char \*messages_json,\s*int messages_json_len\);/u
  );
  assert.match(header, /long long convex_sha256_value\(int operation_id,/u);
  assert.match(header, /convex_value_release\(long long handle\)/u);
  assert.match(
    lowered,
    /function convex_value_field\(\s*handle: c_longlong,[\s\S]*\): c_longlong/u
  );
  assert.match(header, /#undef CONVEX_WASM_IMPORT/);

  const headerImports = [...header.matchAll(/CONVEX_WASM_IMPORT\("([^"]+)"\)/gu)]
    .map((match) => match[1])
    .sort();
  const loweredImports = [
    ...lowered.matchAll(
      /\{include: "convex_wasm_opaque_abi_v3\.h"\},\s*function (convex_[a-z0-9_]+)\(/gu
    ),
  ]
    .map((match) => match[1])
    .sort();
  assert.ok(loweredImports.every((name) => headerImports.includes(name)));
});

test("generates the complete guest-native byte ABI and excludes the opaque result import", () => {
  const header = renderOpaqueAbiHeader();
  const result = lower({
    argumentFields: [],
    bundleCode: "function admittedHandler(_ctx, args) { return {...args}; }",
    documentFields: [],
    intrinsics: {},
    operations: [],
    valueMode: "guest-native-json",
  });
  const imports = [
    ...result.code.matchAll(
      /\{include: "convex_wasm_opaque_abi_v3\.h"\},\s*function (convex_guest_value_[a-z0-9_]+)\(/gu
    ),
  ].map((match) => match[1]);
  assert.deepEqual(imports, [
    "convex_guest_value_request_len",
    "convex_guest_value_request_copy",
    "convex_guest_value_decode",
    "convex_guest_value_encode",
    "convex_guest_value_payload_len",
    "convex_guest_value_payload_copy",
    "convex_guest_value_payload_release",
    "convex_guest_value_result",
  ]);
  assert.doesNotMatch(result.code, /function convex_function_result\(/u);
  assert.doesNotMatch(result.code, /__convexHostFunctionResult/u);
  assert.doesNotMatch(result.code, /function __convexSetFunctionResult/u);
  assert.match(result.code, /const __convexArgs = __convexReadGuestRequest\(\);/u);
  assert.match(result.code, /__convexSetGuestFunctionResult\(__convexResult\)/u);
  assert.match(result.code, /function __convexGuestEncodeTagged\(/u);
  assert.match(result.code, /function __convexGuestRestoreTagged\(/u);
  assert.match(result.code, /function __convexGuestToHost\(/u);
  assert.match(result.code, /function __convexGuestFromHost\(/u);
  assert.match(result.code, /return globalThis\.Array\.isArray\(value\);/u);
  assert.equal(result.code.match(/Array\.isArray\(/gu)?.length, 1);
  assert.doesNotMatch(result.code, /instanceof (?:Map|Set)/u);
  assert.match(header, /int convex_guest_value_request_len\(void\);/u);
  assert.match(header, /int convex_guest_value_request_copy\(char \*destination, int capacity\);/u);
  assert.match(
    header,
    /long long convex_guest_value_decode\(const char \*value, int value_len\);/u
  );
  assert.match(header, /long long convex_guest_value_encode\(long long consuming_value_handle\);/u);
  assert.match(header, /int convex_guest_value_payload_len\(long long payload_handle\);/u);
  assert.match(
    header,
    /int convex_guest_value_payload_copy\(\s*long long payload_handle,\s*char \*destination,\s*int capacity\);/u
  );
  assert.match(header, /void convex_guest_value_payload_release\(long long payload_handle\);/u);
  assert.match(header, /void convex_guest_value_result\(const char \*value, int value_len\);/u);
  assert.equal(result.loweringInputs.valueMode, "guest-native-json");
  assert.throws(() => lower({ valueMode: undefined }), /valueMode must be opaque/u);
});

test("guest-native codec preserves __proto__, signed int64 values, and object-field invariants", () => {
  const codec = guestNativeCodec();

  const withPrototypeField = JSON.parse('{"__proto__":{"safe":true}}');
  const encoded = codec.encode(withPrototypeField, []);
  const restored = codec.restore(withPrototypeField);
  for (const value of [encoded, restored]) {
    assert.equal(Object.getPrototypeOf(value), Object.prototype);
    assert.equal(Object.hasOwn(value, "__proto__"), true);
    assert.deepEqual(value.__proto__, { safe: true });
  }

  for (const key of ["$float", "bad\u0001field", "non-ascii-é", "x".repeat(1025)]) {
    assert.throws(() => codec.encode({ [key]: "AAAAAAAA+H8=" }, []), /Convex object field name/u);
  }
  assert.ok(Number.isNaN(codec.restore({ $float: "AAAAAAAA+H8=" })));

  const integers = [
    [BigInt("0"), "AAAAAAAAAAA="],
    [BigInt("2"), "AgAAAAAAAAA="],
    [BigInt("-1"), "//////////8="],
    [BigInt("-9223372036854775808"), "AAAAAAAAAIA="],
    [BigInt("9223372036854775807"), "/////////38="],
  ];
  for (const [integer, encodedInteger] of integers) {
    assert.deepEqual(codec.encode(integer, []), { $integer: encodedInteger });
    assert.equal(codec.restore({ $integer: encodedInteger }), integer);
  }
  const nested = {
    values: integers.map(([integer]) => integer),
    nested: { minimum: BigInt("-9223372036854775808") },
  };
  assert.deepEqual(codec.restore(codec.encode(nested, [])), nested);
  assert.throws(() => codec.encode(BigInt("9223372036854775808"), []), /signed 64-bit range/u);
  assert.throws(() => codec.encode(BigInt("-9223372036854775809"), []), /signed 64-bit range/u);
  for (const encoded of [null, 0, "not base64", "AAAA"]) {
    assert.throws(() => codec.restore({ $integer: encoded }), /\$integer encoding/u);
  }
});

test("guest-native codec preserves ArrayBuffer values and omits nested undefined properties", () => {
  const codec = guestNativeCodec();

  const bytes = Uint8Array.from([0, 1, 127, 128, 255]).buffer;
  const value = {
    _id: "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y",
    bytes,
    flags: [null, false, "plain text", 1.25],
    nested: { bytes, omitted: undefined },
    omitted: undefined,
  };
  const encoded = codec.encode(value, []);
  assert.deepEqual(encoded, {
    _id: "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y",
    bytes: { $bytes: "AAF/gP8=" },
    flags: [null, false, "plain text", 1.25],
    nested: { bytes: { $bytes: "AAF/gP8=" } },
  });
  const restored = codec.restore(encoded);
  assert.equal(restored._id, value._id);
  assert.deepEqual([...new Uint8Array(restored.bytes)], [0, 1, 127, 128, 255]);
  assert.deepEqual([...new Uint8Array(restored.nested.bytes)], [0, 1, 127, 128, 255]);
  assert.equal(Object.hasOwn(restored, "omitted"), false);
  assert.equal(Object.hasOwn(restored.nested, "omitted"), false);

  assert.deepEqual(codec.encode(new ArrayBuffer(0), []), { $bytes: "" });
  assert.deepEqual([...new Uint8Array(codec.restore({ $bytes: "" }))], []);
  for (const encodedBytes of [null, 0, "not base64"]) {
    assert.throws(() => codec.restore({ $bytes: encodedBytes }), /\$bytes encoding/u);
  }
  assert.throws(() => codec.encode([undefined], []), /undefined is not a Convex value/u);
  assert.throws(
    () => codec.encode(new Uint8Array([1]), []),
    /Only plain objects are Convex values/u
  );
});

test("guest-native restoration returns mutable nested arrays and objects", () => {
  const codec = guestNativeCodec();
  const encoded = {
    arguments: { nested: { original: "argument", values: [1, 2] } },
    databaseResult: { nested: { original: "database", values: [3, 4] } },
  };
  const argumentsObject = encoded.arguments;
  const argumentsNested = encoded.arguments.nested;
  const argumentsValues = encoded.arguments.nested.values;
  const restored = codec.restore(encoded);

  assert.equal(restored, encoded);
  assert.equal(restored.arguments, argumentsObject);
  assert.equal(restored.arguments.nested, argumentsNested);
  assert.equal(restored.arguments.nested.values, argumentsValues);

  for (const [name, value] of Object.entries(restored)) {
    value.nested.values.push(`${name}-tail`);
    value.nested.values[8] = `${name}-sparse`;
    value.nested.values.named = name;
    value.nested.original = `${name}-replaced`;
    value.nested.added = `${name}-added`;
    delete value.nested.original;

    assert.equal(Object.isExtensible(value.nested.values), true);
    assert.equal(value.nested.values.length, 9);
    assert.equal(value.nested.values[2], `${name}-tail`);
    assert.equal(value.nested.values[8], `${name}-sparse`);
    assert.equal(value.nested.values.named, name);
    assert.equal(Object.isExtensible(value.nested), true);
    assert.equal(Object.hasOwn(value.nested, "original"), false);
    assert.equal(value.nested.added, `${name}-added`);
  }
});

test("guest-native codec matches Convex canonical committed-value vectors", () => {
  const codec = guestNativeCodec();
  const specialFloats = [
    [NaN, "AAAAAAAA+H8="],
    [Infinity, "AAAAAAAA8H8="],
    [-Infinity, "AAAAAAAA8P8="],
    [-0, "AAAAAAAAAIA="],
  ];
  for (const [value, encoding] of specialFloats) {
    const encoded = codec.encode(value, []);
    assert.deepEqual(encoded, { $float: encoding });
    assert.deepEqual(encoded, convexToJson(value));
    const restored = codec.restore(encoded);
    if (Number.isNaN(value)) {
      assert.ok(Number.isNaN(restored));
    } else {
      assert.ok(Object.is(restored, value));
    }
  }

  const payload = new Uint8Array(196_609);
  for (let index = 0; index < payload.length; index += 1) {
    payload[index] = (index * 37 + 11) & 0xff;
  }
  const noncanonicalNaN = { $float: "AQAAAAAA+H8=" };
  const canonicalValue = {
    _id: "j97b7xnjnh7ty0hnr4zfmf0bf17kry8y",
    bytes: payload.buffer,
    finite: -123.5,
    integer: BigInt("-9223372036854775808"),
    nested: {
      array: [BigInt("9223372036854775807"), NaN, -0],
      omitted: undefined,
      text: "canonical",
    },
    omitted: undefined,
  };
  const encoded = codec.encode(canonicalValue, []);
  assert.deepEqual(encoded, convexToJson(canonicalValue));
  const expected = jsonToConvex(encoded);
  assert.deepEqual(codec.restore(encoded), expected);
  assert.equal(Object.hasOwn(encoded, "omitted"), false);
  assert.equal(Object.hasOwn(encoded.nested, "omitted"), false);
  assert.deepEqual([...new Uint8Array(encoded.bytes)], [...payload]);

  const restoredNoncanonicalNaN = codec.restore(noncanonicalNaN);
  assert.ok(Number.isNaN(restoredNoncanonicalNaN));
  assert.ok(Number.isNaN(jsonToConvex(noncanonicalNaN)));
  const reencodedNoncanonicalNaN = codec.encode(restoredNoncanonicalNaN, []);
  assert.equal(typeof reencodedNoncanonicalNaN.$float, "string");
  assert.deepEqual(reencodedNoncanonicalNaN, convexToJson(restoredNoncanonicalNaN));
});

test("guest-native index queries transfer encoded values and consume returned handles once", () => {
  const code = lower({ valueMode: "guest-native-json" }).code;
  const uniqueStart = code.indexOf("    unique(): any {");
  const uniqueEnd = code.indexOf("    take(limit: any): any {", uniqueStart);
  assert.notEqual(uniqueStart, -1);
  assert.notEqual(uniqueEnd, -1);
  const uniqueSource = code.slice(uniqueStart, uniqueEnd);

  assert.match(code, /let valuesHandle = __convexGuestToHost\(__convexMarkArray\(values\)\);/u);
  assert.match(
    code,
    /const queryId = __convexHostQueryStartValue\(operationId, transferredValuesHandle\);/u
  );
  assert.match(uniqueSource, /const first = __convexGuestFromHost\(firstHandle\);/u);
  assert.match(uniqueSource, /const second = __convexGuestFromHost\(secondHandle\);/u);
  assert.doesNotMatch(uniqueSource, /__convexWrapObject/u);
  assert.doesNotMatch(uniqueSource, /__convexValueRelease\((?:first|second)Handle\)/u);
});

test("keeps opaque-handle externs behind typed JavaScript call boundaries", () => {
  const code = lower().code;
  assert.equal(convexWasmLoweringFormat, "convex-wasm-lowered-guest-v37");
  const boundaries = [
    ["__convexHostQueryNext", "__convexQueryNext"],
    ["__convexHostValueArrayNew", "__convexValueArrayNew"],
    ["__convexHostValueArrayPush", "__convexValueArrayPush"],
    ["__convexHostValueArrayLen", "__convexValueArrayLen"],
    ["__convexHostValueArrayGet", "__convexValueArrayGet"],
    ["__convexHostAsyncBatchTake", "__convexAsyncBatchTake"],
    ["__convexHostValueRelease", "__convexValueRelease"],
  ];

  for (const [hostBinding, boundary] of boundaries) {
    assert.equal(code.match(new RegExp(`${hostBinding}\\(`, "gu"))?.length, 1);
    assert.match(code, new RegExp(`function ${boundary}\\(`, "u"));
  }
  assert.match(code, /const firstHandle = __convexQueryNext\(queryId\);/u);
  assert.match(code, /const arrayHandle = __convexValueArrayNew\(\);/u);
  assert.match(code, /__convexValueArrayPush\(arrayHandle, valueHandle\);/u);
  assert.match(code, /__convexValueRelease\(firstHandle\);/u);
  assert.match(
    code,
    /const resultHandle = __convexToHost\(value\);\s*__convexReleaseLiveOpaqueValues\(\);\s*__convexHostFunctionResult\(resultHandle\);/u
  );
  assert.match(
    code,
    /function __convexWrapObject\(handle\) \{\s*return __convexTrackOpaqueValue\(\{/u
  );
  assert.match(
    code,
    /catch \(__convexError\) \{\s*__convexReleaseLiveOpaqueValues\(\);\s*__convexReportThrown/u
  );
});

test("lowers sequential authentication and normalizeId through their exact ABI paths", () => {
  const result = lower({
    bundleCode: `
      function authenticate(ctx) {
        const identity = ctx.auth.getUserIdentity();
        if (identity === null) throw new Error("Unauthorized");
        const normalizedId = ctx.db.normalizeId("user", identity.subject);
        if (normalizedId === null) throw new Error("Unauthorized");
        const user = ctx.db.get("user", normalizedId);
        if (user === null) throw new Error("Unauthorized");
        return { userId: user.userId, isAdmin: user.role === "admin" };
      }
      function admittedHandler(ctx) {
        return authenticate(ctx);
      }
    `,
    argumentFields: [],
    documentFields: ["role", "subject", "userId"],
    intrinsics: {},
    operations: [
      { id: 30, kind: "authenticationGetUserIdentity" },
      { id: 31, kind: "databaseNormalizeId", table: "user" },
      { id: 32, kind: "databaseGet", table: "user" },
    ],
  });

  assert.deepEqual(result.loweringInputs.directAsyncBatches, []);
  assert.match(
    result.code,
    /function __convexAuthenticationGetUserIdentity\(\): any \{[\s\S]*__convexAsyncBatch\(\[null\], operationId, \(\) => \[\]\)[\s\S]*return results\[0\];/u
  );
  assert.match(result.code, /function convex_db_normalize_id\(/u);
  assert.match(
    result.code,
    /const transferredValueHandle = valueHandle;\s*valueHandle = 0;\s*const resultHandle = __convexHostDatabaseNormalizeId\(operationId, transferredValueHandle\);/u
  );
  assert.match(result.code, /if \(resultHandle === -1\).*normalizeId failed/u);
  assert.match(result.code, /get "subject"\(\).*__convexReadField\(handle, "subject"\)/u);
  assert.match(result.code, /get "userId"\(\).*__convexReadField\(handle, "userId"\)/u);
  assert.match(result.code, /get "role"\(\).*__convexReadField\(handle, "role"\)/u);

  const generatedSource = 'Promise.all(args.ids.map((id) => ctx.db.get("documents", id)))';
  const rejectedBundle =
    "function admittedHandler(ctx, args) { return __convexAsyncBatch(args.ids, 30, (id) => [id]); }";
  const authorization = directBatchAuthorization(generatedSource, 30);
  assert.throws(
    () =>
      lower({
        bundleCode: rejectedBundle,
        directAsyncBatches: [
          {
            ...authorization,
            dynamicArguments: [],
            operationKind: "authenticationGetUserIdentity",
          },
        ],
        intrinsics: {},
        operations: [{ id: 30, kind: "authenticationGetUserIdentity" }],
      }),
    /not authorized for source Promise\.all lowering/u
  );
});

test("lowers function-handle creation with exact SDK address conversion and host-call semantics", () => {
  const operation = { id: 33, kind: "functionHandleCreate" };
  const result = lower({
    argumentFields: ["reference"],
    bundleCode:
      "function admittedHandler(ctx, args) { return __convexCreateFunctionHandle(args.reference); }",
    documentFields: [],
    intrinsics: {},
    operations: [operation],
  });
  assert.deepEqual(result.loweringInputs.operations, [operation]);
  assert.match(result.code, /function __convexFunctionHandleCreateOperationId/u);
  assert.match(
    result.code,
    /__convexAsyncBatch\(\[address\], operationId, \(value\) => \[value\]\)/u
  );
  assert.throws(
    () =>
      lower({
        intrinsics: {},
        operations: [{ ...operation, functionReference: "jobs:run" }],
      }),
    /not a valid functionHandleCreate operation/u
  );

  const calls = [];
  let hostResult = "function://created";
  const api = runInNewContext(
    `${executableFunctionHandleRuntime(result.code)}
     ({
       address: __convexFunctionHandleAddress,
       create: __convexCreateFunctionHandle,
       internalReference: __convexFunctionReference,
     });`,
    {
      __convexAsyncBatch(values, operationId, project) {
        calls.push({
          arguments: values.map((value) => project(value)),
          operationId,
        });
        return [hostResult];
      },
    }
  );
  const normalized = (value) => JSON.parse(JSON.stringify(value));
  assert.deepEqual(normalized(api.address("jobs:run")), { name: "jobs:run" });
  assert.deepEqual(normalized(api.address("function://existing")), {
    functionHandle: "function://existing",
  });
  assert.deepEqual(normalized(api.address(api.internalReference("_reference/function/jobs:run"))), {
    reference: "_reference/function/jobs:run",
  });
  assert.deepEqual(normalized(api.address({ [Symbol.for("functionName")]: "jobs:run" })), {
    name: "jobs:run",
  });
  assert.deepEqual(
    normalized(api.address({ [Symbol.for("toReferencePath")]: "_reference/function/jobs:run" })),
    { reference: "_reference/function/jobs:run" }
  );
  assert.deepEqual(
    normalized(
      api.address({
        __convexFunctionReference: "_reference/function/forged:run",
        [Symbol.for("functionName")]: "jobs:run",
        [Symbol.for("toReferencePath")]: "_reference/function/ignored:run",
      })
    ),
    { name: "jobs:run" }
  );
  assert.deepEqual(normalized(api.address("")), { name: "" });
  for (const invalid of [
    null,
    7,
    {},
    { __convexFunctionReference: "_reference/function/forged:run" },
    { [Symbol.for("functionName")]: "" },
    {
      [Symbol.for("functionName")]: "",
      [Symbol.for("toReferencePath")]: "",
    },
  ]) {
    assert.throws(() => api.address(invalid), /is not a functionReference/u);
  }

  assert.equal(api.create("function://existing"), "function://created");
  assert.deepEqual(normalized(calls), [
    {
      arguments: [[{ functionHandle: "function://existing" }]],
      operationId: 33,
    },
  ]);
  hostResult = { unexpected: true };
  assert.throws(
    () => api.create("jobs:run"),
    /function-handle creation returned a non-string result/u
  );
  assert.equal(calls.length, 2);
});

test("guest function-handle creation composes resolve, reject, and cleanup ownership", async () => {
  const result = lower({
    argumentFields: ["reference"],
    bundleCode:
      "function admittedHandler(ctx, args) { return __convexCreateFunctionHandle(args.reference); }",
    documentFields: [],
    effectExecutionMode: "guest-promise-event-loop",
    intrinsics: {},
    operations: [{ id: 44, kind: "functionHandleCreate" }],
  });
  assert.match(
    result.code,
    /__convexStartAsyncOperation\([\s\S]*\[__convexFunctionHandleAddress\(functionReference\)\][\s\S]*\.then\(\(result\) =>/u
  );

  const valueArrays = new Map();
  const values = new Map();
  const starts = [];
  let nextArrayHandle = 1;
  let nextValueHandle = 1;
  let nextOperationHandle = 1;
  const sandbox = {
    __convexAsyncBatchResultKind(operationId) {
      assert.equal(operationId, 44);
      return "hostValue";
    },
    __convexFromHost(handle) {
      assert.equal(values.has(handle), true);
      const value = values.get(handle);
      values.delete(handle);
      return value;
    },
    __convexFromHostArrayTake() {
      throw new Error("Unexpected array completion");
    },
    __convexHostAsyncOperationStartTake(operationId, argumentsHandle) {
      assert.equal(valueArrays.has(argumentsHandle), true);
      const operationHandle = nextOperationHandle;
      nextOperationHandle += 1;
      starts.push({
        arguments: valueArrays.get(argumentsHandle),
        operationHandle,
        operationId,
      });
      valueArrays.delete(argumentsHandle);
      return operationHandle;
    },
    __convexToHost(value) {
      const handle = nextValueHandle;
      nextValueHandle += 1;
      values.set(handle, value);
      return handle;
    },
    __convexValueArrayNew() {
      const handle = nextArrayHandle;
      nextArrayHandle += 1;
      valueArrays.set(handle, []);
      return handle;
    },
    __convexValueArrayPush(arrayHandle, valueHandle) {
      assert.equal(valueArrays.has(arrayHandle), true);
      assert.equal(values.has(valueHandle), true);
      valueArrays.get(arrayHandle).push(values.get(valueHandle));
      values.delete(valueHandle);
    },
    __convexValueRelease(handle) {
      valueArrays.delete(handle);
      values.delete(handle);
    },
    storePayload(value) {
      const handle = nextValueHandle;
      nextValueHandle += 1;
      values.set(handle, value);
      return handle;
    },
  };
  const api = runInNewContext(
    `${executableFunctionHandleRuntime(result.code, { guest: true })}
     ({
       cleanup: __convexWasmInvocationCleanup,
       create: __convexCreateFunctionHandle,
       settle: __convexWasmSettle,
     });`,
    sandbox
  );

  const existing = api.create("function://existing");
  assert.deepEqual(JSON.parse(JSON.stringify(starts)), [
    {
      arguments: [{ functionHandle: "function://existing" }],
      operationHandle: 1,
      operationId: 44,
    },
  ]);
  api.settle(1, 0, sandbox.storePayload("function://existing"));
  assert.equal(await existing, "function://existing");

  const nonString = api.create("jobs:run");
  api.settle(2, 0, sandbox.storePayload({ unexpected: true }));
  await assert.rejects(nonString, /function-handle creation returned a non-string result/u);

  const rejected = api.create("jobs:run");
  api.settle(3, 1, sandbox.storePayload("host rejected function-handle creation"));
  await assert.rejects(rejected, /host rejected function-handle creation/u);

  void api.create("jobs:run");
  assert.equal(api.cleanup(), 1);
  assert.equal(api.cleanup(), 0);
  assert.equal(valueArrays.size, 0);
  assert.equal(values.size, 0);
});

test("lowers generic database get and scheduler descriptors to opaque ABI v3", () => {
  const result = lower({
    bundleCode: `
      function admittedHandler(ctx, args) {
        const document = ctx.db.get("documents", args.id);
        const scheduledId = ctx.scheduler.runAfter(
          args.delayMs,
          internal.jobs.cleanup.run,
          { id: args.id },
        );
        return { document, scheduledId };
      }
    `,
    argumentFields: ["delayMs", "id"],
    documentFields: ["_id"],
    intrinsics: {},
    operations: [
      { id: 11, kind: "databaseGet", table: "documents" },
      {
        functionReference: "_reference/function/jobs/cleanup:run",
        id: 12,
        kind: "schedulerRunAfter",
      },
    ],
  });

  assert.match(result.code, /__convexHostDatabaseGet\(operationId, __convexToHost\(id\)\)/u);
  assert.match(
    result.code,
    /__convexHostSchedulerSchedule\(\s*operationId,\s*timeMilliseconds,\s*__convexToHost\(args\)/u
  );
  assert.match(result.code, /if \(resultHandle === -1\)/u);
  assert.match(result.code, /"_reference\/function\/jobs\/cleanup:run"/u);
  assert.match(result.code, /"cleanup": \{\s*"run": __convexFunctionReference/u);
});

test("lowers fixed-table database writes to the shared opaque ABI boundary", () => {
  const result = lower({
    bundleCode: `
      function admittedHandler(ctx, args) {
        const id = ctx.db.insert("documents", { enabled: true });
        ctx.db.patch("documents", id, { enabled: false });
        ctx.db.replace("documents", id, { enabled: true });
        ctx.db.delete("documents", id);
        return id;
      }
    `,
    intrinsics: {},
    operations: [
      { id: 20, kind: "databaseInsert", table: "documents" },
      { id: 21, kind: "databasePatch", table: "documents" },
      { id: 22, kind: "databaseReplace", table: "documents" },
      { id: 23, kind: "databaseDelete", table: "documents" },
    ],
  });

  assert.match(result.code, /function convex_db_write\(/u);
  for (const [kind, id] of [
    ["databaseInsert", 20],
    ["databasePatch", 21],
    ["databaseReplace", 22],
    ["databaseDelete", 23],
  ]) {
    assert.match(
      result.code,
      new RegExp(`kind === "${kind}" && table === "documents"\\) return ${id};`, "u")
    );
  }
  assert.match(
    result.code,
    /__convexHostDatabaseWrite\(\s*operationId,\s*firstHandle,\s*secondHandle/u
  );
  assert.doesNotMatch(
    result.code,
    /convex_query_start_value|convex_query_start_utf8|convex_query_next|__convexCreateQuery/u
  );
});

test("preserves compiler-widened mutable object builders without materializing omitted properties", () => {
  const result = lower({
    bundleCode: `
      function admittedHandler(ctx, args) {
        const document: any = {
          required: args.required,
        };
        if (args.optional) {
          document.optional = args.optional;
        }
        ctx.db.insert("documents", document);
      }
    `,
    argumentFields: ["optional", "required"],
    intrinsics: {},
    operations: [{ id: 20, kind: "databaseInsert", table: "documents" }],
  });

  assert.match(result.code, /const document: any = \{\s*required: args\.required,?\s*\};/u);
  assert.match(result.code, /if \(args\.optional\) \{\s*document\.optional = args\.optional;/u);
  assert.doesNotMatch(result.code, /optional: undefined/u);
});

test("renders the generic native capability target without operation-ID authority", () => {
  const header = renderOpaqueAbiHeader();
  const code = renderNativeDbGetCapabilityTarget({
    argumentFields: ["id"],
    compileProfileJavascript:
      'var __convexWasmCompileProfile = { getStatus: async (ctx, args) => await ctx.db.get("documents", args.id), observeScheduledExecution: async (ctx, args) => await ctx.db.insert("documents", args) };',
  });

  assert.match(code, /__convexCapabilityCreateContext/u);
  assert.match(code, /__convexApplicationCompileProfile\["__convexWasmSdkCommitTsPlaceholder"\]/u);
  assert.match(code, /__convexCommitTsPlaceholder = __convexLinkedCommitTsPlaceholder/u);
  assert.match(code, /__convexReadGuestRequest/u);
  assert.match(code, /__convexGuestToHost/u);
  assert.match(code, /__convexGuestFromHost/u);
  assert.match(code, /function __convexCapabilityRequestToHost\(/u);
  assert.match(code, /function convex_capability_request_decode\(/u);
  assert.match(code, /function convex_capability_request_release\(/u);
  assert.match(
    code,
    /Object\.defineProperty\(__convexTargetGlobal, "__convexWasmCapabilityBootstrap"/u
  );
  assert.match(code, /kind: isSystem \? "dbSystemGet" : "dbGet"/u);
  assert.doesNotMatch(code, /operators\[constraint\.type\]/u);
  assert.match(code, /if \(constraint\.type === "Eq"\) operator = "eq";/u);
  assert.match(code, /else if \(constraint\.type === "Lte"\) operator = "lte";/u);
  assert.doesNotMatch(code, /request\.table = table/u);
  assert.match(
    code,
    /if \(hasTable\) \{[^]*__convexCapabilityRequireTable\(args\.table, args\.isSystem, "get"\)[^]*id,[^]*table,[^]*"taggedJson"[^]*\}[^]*kind: args\.isSystem \? "dbSystemGet" : "dbGet",[^]*id,[^]*"taggedJson"/u
  );
  assert.match(
    code,
    /if \(hasTable\) \{[^]*id: arg1,[^]*table,[^]*"hostValue",[^]*\}[^]*id: arg0,[^]*"hostValue"/u
  );
  assert.match(code, /kind: "dbQuery"/u);
  assert.match(code, /kind: "dbNormalizeId"/u);
  assert.match(code, /kind: "dbInsert"/u);
  assert.match(code, /kind: "dbPatch"/u);
  assert.match(code, /kind: "dbReplace"/u);
  assert.match(code, /kind: "dbDelete"/u);
  assert.match(code, /kind: "storageGetUrl"/u);
  assert.match(code, /kind: "storageGetMetadata"/u);
  assert.match(code, /kind: "storageGenerateUploadUrl"/u);
  assert.match(code, /kind: "storageDelete"/u);
  assert.match(code, /context\.runQuery = function\(functionReference, args, options\)/u);
  assert.match(code, /udfType: useStaleSnapshot \? "snapshotQuery" : "query"/u);
  assert.match(code, /request\.udfType !== "query"/u);
  assert.match(code, /request\.udfType !== "snapshotQuery"/u);
  assert.match(code, /kind: "schedulerRunAfter"/u);
  assert.match(code, /kind: "schedulerRunAt"/u);
  assert.match(code, /kind: "schedulerCancel"/u);
  assert.match(code, /kind: "environmentVariableGet"/u);
  assert.match(code, /Object\.defineProperty\(__convexTargetGlobal, "process"/u);
  assert.match(code, /function convex_crypto_subtle_digest_sha256\(/u);
  assert.match(code, /function convex_crypto_get_random_values\(/u);
  assert.match(code, /function convex_crypto_random_uuid\(/u);
  assert.match(code, /function convex_math_random\(/u);
  assert.match(code, /Object\.defineProperty\(__convexTargetGlobal, "crypto"/u);
  assert.match(code, /kind: "performanceNow"/u);
  assert.match(code, /const performance: any = __convexPerformance/u);
  assert.match(code, /function __convexDatabaseUdfTimerDeveloperError\(message: string\): number/u);
  assert.doesNotMatch(code, /__convexDatabaseUdfTimerDeveloperError[^\n]*:\s*never\b/u);
  assert.match(code, /const setTimeout: any = \(/u);
  assert.match(code, /const setInterval: any = \(/u);
  assert.match(code, /const clearTimeout: any = \(_id: any\): void => \{\};/u);
  assert.match(code, /const clearInterval: any = \(_id: any\): void => \{\};/u);
  for (const name of ["clearInterval", "clearTimeout", "setInterval", "setTimeout"]) {
    assert.match(code, new RegExp(`Object\\.freeze\\(${name}\\)`, "u"), name);
  }
  assert.doesNotMatch(
    code,
    /function __convexPerformanceNow[^]*__convexTargetHostInvocationUnixTimestampMs/u
  );
  const startAsync = code.indexOf("function __convexCapabilityStartAsync(");
  const startAsyncEnd = code.indexOf("function __convexCapabilityRunSync(", startAsync);
  assert.ok(startAsync >= 0 && startAsyncEnd > startAsync);
  assert.match(
    code.slice(startAsync, startAsyncEnd),
    /__convexCapabilityRequestToHost\(request\)/u
  );
  assert.doesNotMatch(code.slice(startAsync, startAsyncEnd), /__convexGuestToHost\(request\)/u);
  assert.match(
    header,
    /convex_capability_request_decode\(const char \*request, int request_len\)/u
  );
  assert.match(header, /void convex_capability_request_release\(long long request_handle\)/u);
  assert.match(
    header,
    /int convex_capability_start_take\(\s*long long capability_identity,\s*long long request_handle\)/u
  );
  assert.match(code, /value === undefined \? null : value/u);
  assert.equal(code.match(/function __convexArrayPush\(/gu)?.length, 1);
  assert.doesNotMatch(code, /__convexReleaseLiveOpaqueValues/u);
  const runtimeMarker = "{\nfunction __convexArrayPush";
  const runtimeStart = code.indexOf(runtimeMarker) + 2;
  const runtimeEnd = code.lastIndexOf("\n}\n");
  assert.ok(runtimeStart >= runtimeMarker.length && runtimeEnd > runtimeStart);
  const runtimeWithoutArrayPush = code
    .slice(runtimeStart, runtimeEnd)
    .replace(
      /function __convexArrayPush\(values: any\[\], value: any\): void \{\s*\/\/ Static Hermes lowers this typed boundary to its FastArray push primitive\.\s*values\.push\(value\);\s*\}\s*/u,
      ""
    );
  assert.throws(
    () => assertNativeCapabilityHelperDefinitions(runtimeWithoutArrayPush),
    /undefined helpers: __convexArrayPush/u
  );
  assert.doesNotMatch(code, /__convexReadRequestField\("id"\)/u);
  assert.doesNotMatch(code, /operationId|ImportedOperationDescriptor/u);
  assert.doesNotMatch(
    code,
    /convex_async_operation_start_take|convex_db_get|perRouteTables|compilerCallsite/u
  );
  assert.doesNotMatch(
    code,
    /__convexWasmCompileProfileTargetBootstrap|__convexWasmSelectedHandler/u
  );
  const iifeExport = code.indexOf("var __convexWasmCompileProfile");
  const intrinsicHardening = code.indexOf("const __convexIntrinsicPolicySha256");
  const cryptoAdapter = code.indexOf("const __convexCryptoDigestBytes = 32;");
  const timerAdapter = code.indexOf("function __convexDatabaseUdfTimerDeveloperError");
  const processAdapter = code.indexOf('Object.defineProperty(__convexTargetGlobal, "process"');
  const sdkFacadeState = code.indexOf("let __convexSdkActiveUdfKind: ?string = null;");
  const sdkFacade = code.indexOf('Object.defineProperty(__convexTargetGlobal, "Convex"');
  const applicationFacade = code.indexOf(
    "const __convexWasmApplicationGlobalThis: any = __convexTargetGlobal.Object.create(null);"
  );
  const terminalTransport = code.indexOf(
    "__convexTargetGlobal.__convexWasmCompileProfile = __convexApplicationCompileProfile;"
  );
  const privilegedBootstrap = code.lastIndexOf(
    'Object.defineProperty(__convexTargetGlobal, "__convexWasmCapabilityBootstrap"'
  );
  assert.ok(iifeExport >= 0);
  assert.ok(code.indexOf("const __convexTargetNativeDate: any") < iifeExport);
  assert.ok(code.indexOf("const __convexTargetNativeDate: any") < intrinsicHardening);
  assert.ok(code.indexOf("__convexTargetGlobal.Math.random") < intrinsicHardening);
  assert.ok(intrinsicHardening < cryptoAdapter);
  assert.ok(intrinsicHardening < timerAdapter);
  assert.ok(timerAdapter < cryptoAdapter);
  assert.ok(cryptoAdapter < processAdapter);
  assert.ok(processAdapter < sdkFacadeState);
  assert.ok(sdkFacadeState < sdkFacade);
  assert.ok(sdkFacade < applicationFacade);
  assert.ok(applicationFacade < iifeExport);
  assert.ok(iifeExport < terminalTransport);
  assert.ok(terminalTransport < privilegedBootstrap);
  assert.equal(
    code.match(/function convex_invocation_unix_timestamp_ms\(\): c_double \{ throw 0; \}/gu)
      ?.length,
    1
  );
  assert.match(code, /value: __convexWasmCapabilityBootstrap/u);
  assert.doesNotMatch(code, /globalThis\.__convexWasmCapabilityBootstrap\s*=/u);
  assert.match(
    code,
    /let __convexApplicationCompileProfile: any;\s*try \{\s*__convexApplicationCompileProfile = \(function\(\): any \{\s*"use strict";/u
  );
  assert.match(
    code,
    /catch \(__convexInitializationError\) \{\s*__convexReportThrown\(__convexInitializationError\);\s*throw __convexInitializationError;\s*\}/u
  );
  assert.doesNotMatch(code, /Object\.freeze\(__convexWasmApplicationGlobalThis\)/u);
  assert.match(
    code.slice(sdkFacade, applicationFacade),
    /Object\.defineProperty\(__convexTargetGlobal, "Convex", \{\s*configurable: false,\s*enumerable: false,\s*value: __convexSdkFacade,\s*writable: false,\s*\}\);/u
  );
  assert.match(
    code.slice(sdkFacadeState, applicationFacade),
    /const __convexSdkFacade: any = Object\.freeze\(\{/u
  );
  assert.match(
    code.slice(applicationFacade, iifeExport),
    /"Date": \{enumerable: true, value: __convexTargetGlobal\.Date\}/u
  );
  assert.match(
    code.slice(applicationFacade, iifeExport),
    /"Convex": \{enumerable: true, value: __convexTargetGlobal\.Convex\}/u
  );
  assert.match(
    code,
    /install\(\s*__convexCapabilityCreateContext,\s*__convexCapabilityReadRequest,\s*__convexCapabilityInvoke,\s*__convexCapabilityDone,\s*__convexCapabilityCleanup,\s*__convexCapabilitySettle,\s*__convexCapabilityStatus,\s*__convexSdkActivate,\s*__convexCapabilityInvokeRegisteredWrapper,\s*__convexReadGuestRequestTaggedJson,\s*\);/u
  );
  const cleanupStart = code.indexOf("function __convexCapabilityCleanup(): number {");
  const cleanupEnd = code.indexOf("function __convexCapabilitySettle(", cleanupStart);
  assert.ok(cleanupStart >= 0 && cleanupEnd > cleanupStart);
  assert.match(
    code.slice(cleanupStart, cleanupEnd),
    /__convexSdkActiveUdfKind = null;\s*return abandoned;/u
  );
  assert.doesNotMatch(
    code.slice(applicationFacade, iifeExport),
    /"(?:Math|eval|gc|print|\$SHBuiltin|__convexWasmCapabilityBootstrap)":/u
  );
});

test("official wrapper request reader preserves tagged JSON for the SDK to parse", () => {
  const { bridgeJavascript } = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    compileProfileJavascript: "var __convexWasmCompileProfile = {};",
  });
  const start = bridgeJavascript.indexOf("function __convexReadGuestRequestJson(): string {");
  const end = bridgeJavascript.indexOf("\nfunction __convexGuestToHost(", start);
  assert.ok(start >= 0 && end > start);
  let source = JSON.stringify(convexToJson({ count: -7n, nested: ["value"] }));
  const sandbox = {
    JSON: {
      parse: () => {
        throw new Error("tagged wrapper arguments were parsed by the bridge");
      },
    },
    $SHBuiltin: { c_native_runtime: () => ({}) },
    __convexAsciizToString: (_runtime, pointer) => pointer.source,
    __convexGuestIsArray: Array.isArray,
    __convexGuestRestoreTagged: () => {
      throw new Error("tagged wrapper arguments were restored");
    },
    __convexGuestTransferScratch: () => ({}),
    __convexHostGuestRequestCopy: (pointer, length) => {
      pointer.source = source;
      return length;
    },
    __convexHostGuestRequestLen: () => Buffer.byteLength(source),
  };
  const javascript = ts.transpileModule(bridgeJavascript.slice(start, end), {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(`${javascript}\nglobalThis.readTagged = __convexReadGuestRequestTaggedJson;`, sandbox);
  assert.equal(sandbox.readTagged(), source);
  source = "[]";
  assert.throws(() => sandbox.readTagged(), /argument object/u);
  source = "null";
  assert.throws(() => sandbox.readTagged(), /argument object/u);
  source = "{";
  assert.throws(() => sandbox.readTagged(), /argument object/u);
});

test("splits the shared typed bridge from the ordinary application unit", () => {
  const compileProfileJavascript = `var applicationArray = [];
applicationArray[65] = "sparse";
applicationArray.named = true;
var __convexWasmCompileProfile = {
  __convexWasmSdkCommitTsPlaceholder: {},
  applicationArray,
};`;
  const { applicationJavascript, bridgeJavascript, formatterJavascript } =
    renderNativeDbGetCapabilityTargetUnits({
      argumentFields: [],
      compileProfileJavascript,
    });

  assert.doesNotMatch(bridgeJavascript, /var applicationArray = \[\]/u);
  assert.doesNotMatch(bridgeJavascript, /function inspect_\(/u);
  assert.match(applicationJavascript, /var applicationArray = \[\]/u);
  assert.match(applicationJavascript, /applicationArray\[65\] = "sparse"/u);
  assert.doesNotMatch(applicationJavascript, /__convexWasmCapabilityBootstrap/u);
  const targetPrelude = bridgeJavascript.indexOf("const __convexTargetGlobal");
  const hardening = bridgeJavascript.indexOf("const __convexIntrinsicPolicySha256");
  const facadeHandoff = bridgeJavascript.indexOf(
    'Object.defineProperty(__convexTargetGlobal, "__convexWasmApplicationGlobalThis"'
  );
  const bootstrap = bridgeJavascript.indexOf(
    'Object.defineProperty(__convexTargetGlobal, "__convexWasmCapabilityBootstrap"'
  );
  assert.ok(
    targetPrelude === 0 &&
      targetPrelude < hardening &&
      hardening < facadeHandoff &&
      facadeHandoff < bootstrap
  );
  assert.match(
    bridgeJavascript.slice(facadeHandoff, bootstrap),
    /configurable: true,[\s\S]*?writable: false/u
  );
  assert.match(
    bridgeJavascript,
    /function __convexCapabilityCreateContext\([\s\S]*?commitTsPlaceholder: any[\s\S]*?__convexCommitTsPlaceholder = commitTsPlaceholder/u
  );
  assert.match(
    applicationJavascript,
    /__convexWasmApplicationPublishCompileProfile\(__convexApplicationCompileProfile\)/u
  );
  assert.match(
    applicationJavascript,
    /catch \(__convexInitializationError\)[\s\S]*?__convexWasmApplicationReportThrown\(__convexInitializationError\)/u
  );
  assert.equal(formatterJavascript, renderNativeRuntimeSupportUnit());
  assert.equal(
    sha256(formatterJavascript),
    "33a6237a6eb39828f1bc200687363aa087fb36f46bc8744391c21ebbb847ac4e"
  );
  assert.equal(Buffer.byteLength(formatterJavascript), 609_458);
  assert.match(
    formatterJavascript,
    /globalThis\.__convexWasmApplicationInstallRuntimeSupport\(Object\.freeze\(\{consoleFormatter:/u
  );
  assert.match(
    formatterJavascript,
    /const supportKeys = Reflect\.ownKeys\(support\);[\s\S]*?supportKeys\.length !== 5/u
  );
  assert.match(
    formatterJavascript,
    /Object\.freeze\(support\.consoleFormatter\);[\s\S]*?__convexWasmFormatterHardenConstructor\(support\.DOMException\);[\s\S]*?__convexWasmFormatterHardenConstructor\(support\.Intl\.DateTimeFormat\);[\s\S]*?__convexWasmFormatterHardenConstructor\(support\.Intl\.NumberFormat\);[\s\S]*?Object\.freeze\(support\.Intl\);[\s\S]*?__convexWasmFormatterHardenConstructor\(support\.URL\);[\s\S]*?__convexWasmFormatterHardenConstructor\(support\.URLSearchParams\);/u
  );
  assert.doesNotMatch(formatterJavascript, /var applicationArray = \[\]/u);

  const installerStart = bridgeJavascript.indexOf(
    "function __convexWasmApplicationInstallRuntimeSupport(support: any): void {"
  );
  const installerEnd = bridgeJavascript.indexOf(
    "Object.freeze(__convexWasmApplicationInstallRuntimeSupport);",
    installerStart
  );
  assert.ok(installerStart > 0 && installerEnd > installerStart);
  const bridgeInstaller = bridgeJavascript.slice(installerStart, installerEnd);
  assert.doesNotMatch(
    bridgeInstaller,
    /Reflect\.ownKeys|Object\.keys|Object\.getOwnPropertyNames/u
  );
  assert.doesNotMatch(bridgeInstaller, /(?:const|let|var)\s+\w+\s*=\s*\[/u);
  assert.match(
    bridgeInstaller,
    /!Object\.isFrozen\(support\.consoleFormatter\)[\s\S]*?!Object\.isFrozen\(support\.DOMException\)[\s\S]*?!Object\.isFrozen\(support\.DOMException\.prototype\)[\s\S]*?!Object\.isFrozen\(support\.Intl\)[\s\S]*?!Object\.isFrozen\(support\.Intl\.DateTimeFormat\)[\s\S]*?!Object\.isFrozen\(support\.Intl\.DateTimeFormat\.prototype\)[\s\S]*?!Object\.isFrozen\(support\.Intl\.NumberFormat\)[\s\S]*?!Object\.isFrozen\(support\.Intl\.NumberFormat\.prototype\)[\s\S]*?!Object\.isFrozen\(support\.URL\)[\s\S]*?!Object\.isFrozen\(support\.URL\.prototype\)[\s\S]*?!Object\.isFrozen\(support\.URLSearchParams\)[\s\S]*?!Object\.isFrozen\(support\.URLSearchParams\.prototype\)/u
  );
  assert.doesNotMatch(bridgeInstaller, /Object\.freeze\(support\./u);

  const applicationGlobalThis = Object.create(null);
  let published;
  const reported = [];
  runInNewContext(applicationJavascript, {
    __convexWasmApplicationGlobalThis: applicationGlobalThis,
    __convexWasmApplicationPublishCompileProfile: (profile) => {
      published = profile;
    },
    __convexWasmApplicationReportThrown: (error) => reported.push(error),
  });
  assert.equal(reported.length, 0);
  assert.equal(published.applicationArray.length, 66);
  assert.equal(published.applicationArray[65], "sparse");
  assert.equal(published.applicationArray.named, true);
  assert.equal(Object.isExtensible(published.applicationArray), true);
});

test("the exact pinned runtime support is a standalone untyped Static Hermes unit", (context) => {
  const staticHermes = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (staticHermes === undefined) {
    context.diagnostic("set CONVEX_STATIC_HERMES_TEST_BINARY to compile the runtime-support unit");
    return;
  }
  const { bridgeJavascript, formatterJavascript } = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    compileProfileJavascript:
      "var __convexWasmCompileProfile = {__convexWasmSdkCommitTsPlaceholder: {}};",
  });
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "convex-wasm-runtime-support-unit-"));
  try {
    const sourcePath = join(temporaryDirectory, "formatter.js");
    const outputPath = join(temporaryDirectory, "formatter.c");
    writeFileSync(sourcePath, formatterJavascript);
    const emitResult = spawnSync(
      staticHermes,
      [
        "-O",
        "-Xenable-tdz",
        "-emit-c",
        "-exported-unit=convex_wasm_console_formatter_probe",
        "-o",
        outputPath,
        sourcePath,
      ],
      { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 60_000 }
    );
    assert.equal(emitResult.status, 0, emitResult.stderr);
    assert.ok(readFileSync(outputPath, "utf8").length > 0);

    const bridgeSourcePath = join(temporaryDirectory, "bridge.js");
    const bridgeOutputPath = join(temporaryDirectory, "bridge.c");
    writeFileSync(bridgeSourcePath, bridgeJavascript);
    const bridgeResult = spawnSync(
      staticHermes,
      [
        "-typed",
        "-O",
        "-Xenable-tdz",
        "-emit-c",
        "-exported-unit=convex_wasm_capability_bridge_probe",
        "-o",
        bridgeOutputPath,
        bridgeSourcePath,
      ],
      { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 60_000 }
    );
    assert.equal(bridgeResult.status, 0, bridgeResult.stderr);
    assert.ok(readFileSync(bridgeOutputPath, "utf8").length > 0);
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test("runtime support installation is single-use and clears its hidden handoff", () => {
  const harness = nativeConsoleHarness({ initializeRuntimeSupport: false });
  assert.equal(typeof harness.installRuntimeSupport, "function");
  assert.equal(Object.isFrozen(harness.installRuntimeSupport), true);
  assert.throws(() => harness.installRuntimeSupport(), /Convex Wasm runtime support is invalid/u);
  assert.throws(
    () => harness.installRuntimeSupport(Object.freeze({}), Object.freeze({})),
    /Convex Wasm runtime support is invalid/u
  );
  assert.equal(
    harness.evaluate("typeof globalThis.__convexWasmApplicationInstallRuntimeSupport"),
    "function"
  );
  harness.runRuntimeSupportUnit();
  assert.equal(
    harness.evaluate("typeof globalThis.__convexWasmApplicationInstallRuntimeSupport"),
    "undefined"
  );
  assert.throws(
    () => harness.installRuntimeSupport(Object.freeze({})),
    /Convex Wasm runtime support is already installed/u
  );
  assert.throws(
    () => harness.runRuntimeSupportUnit(),
    /Convex Wasm runtime-support installer is unavailable/u
  );
});

test("runtime support rejects extra string and symbol surface keys before bridge handoff", () => {
  const invocation =
    "globalThis.__convexWasmApplicationInstallRuntimeSupport(Object.freeze({consoleFormatter:";
  const surfaceStart = invocation.slice(0, invocation.length - "consoleFormatter:".length);
  const runtimeSupport = renderNativeRuntimeSupportUnit();
  assert.equal(runtimeSupport.split(invocation).length, 2);

  for (const extraProperty of ["extra:true,", '[Symbol("extra")]:true,']) {
    let handedOff = false;
    const invalidRuntimeSupport = runtimeSupport.replace(
      invocation,
      `${surfaceStart}${extraProperty}consoleFormatter:`
    );
    assert.throws(
      () =>
        runInNewContext(invalidRuntimeSupport, {
          TextDecoder,
          TextEncoder,
          __convexWasmApplicationInstallRuntimeSupport: () => {
            handedOff = true;
          },
        }),
      /Convex Wasm runtime support has an invalid surface/u
    );
    assert.equal(handedOff, false);
  }
});

test("shared guest runtime support implements Intl, DOMException, and the WHATWG URL family", () => {
  const harness = nativeConsoleHarness();
  const evaluateJson = (source) => JSON.parse(harness.evaluate(`JSON.stringify(${source})`));

  assert.deepEqual(
    evaluateJson(`(() => {
const abort = new DOMException("stopped", "AbortError");
const defaulted = new DOMException();
return {
  abort: [abort.name, abort.message, abort.code, String(abort)],
  constants: [DOMException.ABORT_ERR, abort.ABORT_ERR],
  defaulted: [defaulted.name, defaulted.message, defaulted.code],
  facadeIdentity:
    __convexWasmApplicationGlobalThis.DOMException === DOMException,
  inheritance: abort instanceof DOMException && abort instanceof Error,
  tag: Object.prototype.toString.call(abort),
};
})()`),
    {
      abort: ["AbortError", "stopped", 20, "AbortError: stopped"],
      constants: [20, 20],
      defaulted: ["Error", "", 0],
      facadeIdentity: true,
      inheritance: true,
      tag: "[object DOMException]",
    }
  );

  const urlResult = evaluateJson(`(() => {
const params = new URLSearchParams([
  ["b", "hello world"],
  ["a", "1"],
  ["a", "2"],
  ["symbol", "!*'()~"],
]);
params.sort();
const url = new URL(
  "../x y?" + params.toString() + "#section",
  "https://User:Pass@ma\u00f1ana.com:443/a/b/",
);
url.searchParams.append("q", "x y");
url.searchParams.set("a", "3");
const parsed = URL.parse("/next", url);
return {
  canParse: [URL.canParse("/ok", url), URL.canParse("//[", url)],
  facadeIdentity:
    __convexWasmApplicationGlobalThis.URL === URL &&
    __convexWasmApplicationGlobalThis.URLSearchParams === URLSearchParams,
  href: url.href,
  host: [url.origin, url.hostname, url.port, url.pathname, url.hash],
  params: [url.searchParams.getAll("a"), [...url.searchParams], url.search],
  parsed: parsed === null ? null : parsed.href,
  stableSearchParams: url.searchParams === url.searchParams,
};
})()`);
  assert.deepEqual(urlResult, {
    canParse: [true, false],
    facadeIdentity: true,
    href: "https://User:Pass@xn--maana-pta.com/a/x%20y?a=3&b=hello+world&symbol=%21*%27%28%29%7E&q=x+y#section",
    host: ["https://xn--maana-pta.com", "xn--maana-pta.com", "", "/a/x%20y", "#section"],
    params: [
      ["3"],
      [
        ["a", "3"],
        ["b", "hello world"],
        ["symbol", "!*'()~"],
        ["q", "x y"],
      ],
      "?a=3&b=hello+world&symbol=%21*%27%28%29%7E&q=x+y",
    ],
    parsed: "https://User:Pass@xn--maana-pta.com/next",
    stableSearchParams: true,
  });

  const deterministicProbe = `(() => {
const value = new URL("https://example.com/a/../b?x=1&x=2");
value.searchParams.append("space", "a b");
return [value.href, [...value.searchParams]];
})()`;
  assert.deepEqual(evaluateJson(deterministicProbe), evaluateJson(deterministicProbe));
  assert.equal(
    harness.evaluate(`
Object.isFrozen(DOMException) && Object.isFrozen(DOMException.prototype) &&
Object.isFrozen(Intl) &&
Object.isFrozen(Intl.DateTimeFormat) && Object.isFrozen(Intl.DateTimeFormat.prototype) &&
Object.isFrozen(Intl.NumberFormat) && Object.isFrozen(Intl.NumberFormat.prototype) &&
Object.isFrozen(URL) && Object.isFrozen(URL.prototype) &&
Object.isFrozen(URLSearchParams) && Object.isFrozen(URLSearchParams.prototype) &&
Object.isExtensible(__convexWasmApplicationGlobalThis) &&
Object.getPrototypeOf(__convexWasmApplicationGlobalThis) === null &&
Object.getOwnPropertyDescriptor(globalThis, "URL").writable === false
`),
    true
  );
});

test("the untyped application unit emits ordinary Hermes arrays", (context) => {
  const staticHermes = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (staticHermes === undefined) {
    context.diagnostic("set CONVEX_STATIC_HERMES_TEST_BINARY to inspect application-unit C");
    return;
  }
  const { applicationJavascript } = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    compileProfileJavascript: `var applicationArray = [];
applicationArray[65] = "sparse";
applicationArray.named = true;
var __convexWasmCompileProfile = {
  __convexWasmSdkCommitTsPlaceholder: {},
  applicationArray,
};`,
  });
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "convex-wasm-application-unit-"));
  try {
    const sourcePath = join(temporaryDirectory, "application.js");
    const outputPath = join(temporaryDirectory, "application.c");
    writeFileSync(sourcePath, applicationJavascript);
    const result = spawnSync(
      staticHermes,
      [
        "-O",
        "-Xenable-tdz",
        "-emit-c",
        "-exported-unit=convex_wasm_application_array_probe",
        "-o",
        outputPath,
        sourcePath,
      ],
      { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 60_000 }
    );
    assert.equal(result.status, 0, result.stderr);
    const generatedC = readFileSync(outputPath, "utf8");
    assert.match(generatedC, /_sh_ljs_new_array\(shr, 0\)/u);
    assert.doesNotMatch(generatedC, /_sh_new_fastarray_with_proto/u);
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test("the typed bridge restores mutable values for untyped application code", (context) => {
  const { bridgeJavascript } = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    compileProfileJavascript: "var __convexWasmCompileProfile = {};",
  });
  const restoreStart = bridgeJavascript.indexOf(
    "function __convexGuestRestoreTagged(value: any): any {"
  );
  const restoreEnd = bridgeJavascript.indexOf(
    "\nlet __convexGuestTransferScratchPointer",
    restoreStart
  );
  assert.ok(restoreStart > 0 && restoreEnd > restoreStart);
  const restoreSource = bridgeJavascript.slice(restoreStart, restoreEnd);
  assert.match(restoreSource, /value\[index\] = __convexGuestRestoreTagged\(value\[index\]\)/u);
  assert.match(
    restoreSource,
    /__convexGuestDefineObjectField\(value, key, __convexGuestRestoreTagged\(value\[key\]\)\)/u
  );
  assert.doesNotMatch(restoreSource, /__convexGuestNewMutable(?:Array|Object)/u);
  assert.doesNotMatch(restoreSource, /const output/u);

  const staticHermes = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (staticHermes === undefined) {
    context.diagnostic("set CONVEX_STATIC_HERMES_TEST_BINARY to run the mutable restore probe");
    return;
  }
  const codecStart = bridgeJavascript.indexOf("const __convexCommitTsUnresolved =");
  assert.ok(codecStart > 0 && restoreEnd > codecStart);
  const codecSource = bridgeJavascript.slice(codecStart, restoreEnd);
  const probe = `
function __convexArrayPush(values: any[], value: any): void {
  values.push(value);
}
${codecSource}
function mutateRestored(label: string, value: any): string {
  const nested: any = value.nested;
  const values: any = nested.values;
  values.push(label + "-tail");
  values[8] = label + "-sparse";
  values.named = label;
  nested.original = label + "-replaced";
  nested.added = label + "-added";
  delete nested.original;
  if (!Object.isExtensible(values) || !Object.isExtensible(nested)) {
    throw new Error("restored value is not extensible");
  }
  if ("original" in nested) throw new Error("restored object field was not deleted");
  return String(values.length) + ":" + values[2] + ":" + values[8] + ":" +
    values.named + ":" + nested.added;
}
const restoredArguments: any = __convexGuestRestoreTagged(
  JSON.parse(
    '{"nested":{"original":"argument","values":[1,2]}}',
  ),
);
const restoredDatabaseResult: any = __convexGuestRestoreTagged(
  JSON.parse(
    '{"nested":{"original":"database","values":[3,4]}}',
  ),
);
print(mutateRestored("arguments", restoredArguments));
print(mutateRestored("database", restoredDatabaseResult));
`;
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "convex-wasm-mutable-restore-"));
  try {
    const probePath = join(temporaryDirectory, "probe.js");
    writeFileSync(probePath, probe);
    const result = spawnSync(staticHermes, ["-typed", "-O", "-exec", probePath], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      timeout: 60_000,
    });
    assert.equal(
      result.status,
      0,
      JSON.stringify({
        error: result.error?.message,
        signal: result.signal,
        stderr: result.stderr,
        stdout: result.stdout,
      })
    );
    assert.deepEqual(result.stdout.trim().split(/\r?\n/u), [
      "9:arguments-tail:arguments-sparse:arguments:arguments-added",
      "9:database-tail:database-sparse:database:database-added",
    ]);
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test("the typed bridge releases old transfer scratch before growth", () => {
  const { bridgeJavascript } = renderNativeDbGetCapabilityTargetUnits({
    argumentFields: [],
    compileProfileJavascript: "var __convexWasmCompileProfile = {};",
  });
  const scratchStart = bridgeJavascript.indexOf(
    "function __convexGuestTransferScratch(minimumCapacity: number): c_ptr {"
  );
  const scratchEnd = bridgeJavascript.indexOf("\nfunction __convexReadGuestRequestJson", scratchStart);
  assert.ok(scratchStart > 0 && scratchEnd > scratchStart);
  const scratchSource = bridgeJavascript.slice(scratchStart, scratchEnd);
  const freeIndex = scratchSource.indexOf("__convexFree(__convexGuestTransferScratchPointer)");
  const allocateIndex = scratchSource.indexOf("const pointer = __convexMalloc(minimumCapacity)");
  assert.ok(freeIndex >= 0 && allocateIndex > freeIndex);
  assert.match(
    scratchSource,
    /__convexGuestTransferScratchPointer = __convexNullPointer;[\s\S]*__convexGuestTransferScratchCapacity = 0;/u
  );
});

test("native capability target installs Date before hardening and shares it with globalThis", () => {
  const code = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript: `var __convexWasmCompileProfile = {
  selected: () => __convexWasmApplicationGlobalThis.Date === Date,
};`,
  });
  const nativeDate = code.indexOf("const __convexTargetNativeDate: any");
  const dateProxy = code.indexOf("const __convexTargetDate: any = new __convexTargetGlobal.Proxy");
  const dateGlobal = code.indexOf(
    '__convexTargetGlobal.Object.defineProperty(__convexTargetGlobal, "Date", {'
  );
  const intrinsicHardening = code.indexOf("const __convexIntrinsicPolicySha256");
  const applicationFacade = code.indexOf(
    "const __convexWasmApplicationGlobalThis: any = __convexTargetGlobal.Object.create(null);"
  );
  const applicationBundle = code.indexOf("var __convexWasmCompileProfile");

  assert.ok(
    nativeDate >= 0 &&
      nativeDate < dateProxy &&
      dateProxy < dateGlobal &&
      dateGlobal < intrinsicHardening &&
      intrinsicHardening < applicationFacade &&
      applicationFacade < applicationBundle
  );
  assert.match(
    code.slice(dateGlobal, intrinsicHardening),
    /value: __convexTargetDate,\s*writable:/u
  );
  assert.match(
    code.slice(applicationFacade, applicationBundle),
    /"Date": \{enumerable: true, value: __convexTargetGlobal\.Date\}/u
  );
  assert.match(
    code.slice(applicationBundle),
    /selected: \(\) => __convexWasmApplicationGlobalThis\.Date === Date/u
  );
});

test("database UDF timer scheduling stays terminal after a local catch and clear calls are harmless", () => {
  const timeout = nativeDatabaseUdfTimerHarness();
  assert.doesNotThrow(() =>
    timeout.evaluate("__convexTimerHarness.clearTimeout(1); __convexTimerHarness.clearInterval(1);")
  );
  assert.deepEqual(timeout.developerErrors, []);
  const timeoutMessage = timeout.evaluate(`
let coercions = 0;
try {
  __convexTimerHarness.setTimeout(() => {}, {valueOf() { coercions += 1; return -1; }});
} catch (error) {
  globalThis.__convexTimerCoercions = coercions;
  error.message;
}`);
  assert.equal(timeout.evaluate("globalThis.__convexTimerCoercions"), 1);
  assert.equal(
    timeoutMessage,
    "Can't use setTimeout in queries and mutations. Please consider using an action. See https://docs.convex.dev/functions/actions for more details."
  );
  assert.deepEqual(timeout.developerErrors, [timeoutMessage]);

  const interval = nativeDatabaseUdfTimerHarness();
  const intervalMessage = interval.evaluate(`
try {
  __convexTimerHarness.setInterval(() => {}, 1);
} catch (error) {
  error.message;
}`);
  assert.equal(
    intervalMessage,
    "Can't use setInterval in queries and mutations. Please consider using an action. See https://docs.convex.dev/functions/actions for more details."
  );
  assert.deepEqual(interval.developerErrors, [intervalMessage]);

  const stringHandler = nativeDatabaseUdfTimerHarness();
  const stringMessage = stringHandler.evaluate(`
try {
  __convexTimerHarness.setTimeout("return 1", {valueOf() { throw new Error("not reached"); }});
} catch (error) {
  error.message;
}`);
  assert.equal(
    stringMessage,
    "Not implemented: code string argument for setTimeout. Consider calling an action defined in Node.js instead (https://docs.convex.dev/functions/actions)."
  );
  assert.deepEqual(stringHandler.developerErrors, [stringMessage]);
});

test("database UDF timer functions cannot retain state across reused invocations", () => {
  const runtime = nativeDatabaseUdfTimerHarness();
  for (const name of ["clearInterval", "clearTimeout", "setInterval", "setTimeout"]) {
    assert.equal(runtime.evaluate(`Object.isFrozen(__convexTimerHarness.${name})`), true, name);
    assert.equal(
      runtime.evaluate(`Object.isExtensible(__convexTimerHarness.${name})`),
      false,
      name
    );
    assert.throws(
      () =>
        runtime.evaluate(`(() => {
          "use strict";
          const timer = __convexTimerHarness.${name};
          timer.retainedAcrossInvocations = true;
        })()`),
      (error) => error?.name === "TypeError",
      `${name} alias mutation`
    );
    assert.throws(
      () =>
        runtime.evaluate(
          `Object.defineProperty(__convexTimerHarness.${name}, "reflectedState", {value: true})`
        ),
      (error) => error?.name === "TypeError",
      `${name} reflective mutation`
    );
    assert.throws(
      () => runtime.evaluate(`new __convexTimerHarness.${name}(() => {}, 1)`),
      (error) => error?.name === "TypeError",
      `${name} constructor`
    );
  }

  // The harness deliberately evaluates both phases in the same VM context, matching a retained
  // application runtime rather than proving isolation by constructing another global object.
  const retainedState = runtime.evaluate(`[
    __convexTimerHarness.clearInterval.retainedAcrossInvocations,
    __convexTimerHarness.clearTimeout.reflectedState,
    __convexTimerHarness.setInterval.retainedAcrossInvocations,
    __convexTimerHarness.setTimeout.reflectedState,
  ]`);
  assert.equal(retainedState.length, 4);
  for (const value of retainedState) assert.equal(value, undefined);
  assert.deepEqual(runtime.developerErrors, []);
});

test("native console preserves canonical levels, formatting, and immutable global flow", () => {
  const adapter = renderNativeRuntimeSupportAdapter();
  const formatter = renderNativeRuntimeSupportUnit();
  assert.doesNotMatch(adapter, /function inspect_\(obj, options, depth, seen\)/u);
  assert.doesNotMatch(adapter, /require\('\.\/util\.inspect'\)|module\.exports/u);
  assert.match(formatter, /__convexWasmApplicationInstallRuntimeSupport/u);
  assert.match(
    adapter,
    /formatter\(value, \{\s*maxStringLength: 32768,\s*indent: 2,\s*customInspect: true,/u
  );
  assert.match(adapter, /function __convexWasmApplicationInstallRuntimeSupport\(support: any\)/u);
  assert.match(formatter, /Object\.freeze\(support\.consoleFormatter\)/u);
  assert.doesNotMatch(adapter, /Object\.freeze\(support\.consoleFormatter\)/u);
  assert.match(
    adapter,
    /delete __convexTargetGlobal\.__convexWasmApplicationInstallRuntimeSupport/u
  );
  const harness = nativeConsoleHarness({ capabilityIdentity: 41 });
  harness.evaluate(`
const circular = {name: "root"};
circular.self = circular;
globalThis.__retainedConsoleWarn = console.warn;
console.debug("debug");
console.error(new Error("boom"));
console.info(new Set([1, "x"]));
console.log(
  "text",
  undefined,
  {a: [1, "x"], nested: {ok: true}},
  new Map([["a", 1], [2, {x: "y"}]]),
  circular,
  {inspect() { return "custom-output"; }},
  -0,
);
console.warn("warn");
`);

  assert.deepEqual(harness.calls, [
    { identity: 41, level: 0, messages: ["'debug'"] },
    { identity: 41, level: 1, messages: ["[Error: boom]"] },
    { identity: 41, level: 2, messages: ["Set (2) {\n  1,\n  'x'\n}"] },
    {
      identity: 41,
      level: 3,
      messages: [
        "'text'",
        "undefined",
        "{\n  a: [ 1, 'x' ],\n  nested: {\n    ok: true\n  }\n}",
        "Map (2) {\n  'a' => 1,\n  2 => {\n    x: 'y'\n  }\n}",
        "{\n  name: 'root',\n  self: [Circular]\n}",
        "custom-output",
        "-0",
      ],
    },
    { identity: 41, level: 4, messages: ["'warn'"] },
  ]);
  assert.equal(harness.capabilityLookups.length, 5);
  assert.equal(harness.freedPointers.length, 5);
  assert.equal(
    harness.evaluate(`
Object.isFrozen(console) &&
Object.isFrozen(console.log) &&
Object.getPrototypeOf(console) !== Object.prototype &&
Object.keys(Object.getPrototypeOf(console)).length === 0 &&
globalThis.console === console
`),
    true
  );
  assert.equal(
    harness.evaluate("typeof globalThis.__convexWasmApplicationInstallRuntimeSupport"),
    "undefined"
  );
  for (const source of [
    '"use strict"; console.log = () => {};',
    '"use strict"; globalThis.console = {};',
  ]) {
    assert.throws(
      () => harness.evaluate(source),
      (error) => error?.name === "TypeError"
    );
  }
});

test("retained console methods reacquire authority and reject unavailable or stale invocations", () => {
  const harness = nativeConsoleHarness({ capabilityIdentity: 51 });
  harness.evaluate("globalThis.__retainedConsoleLog = console.log; __retainedConsoleLog('first');");
  harness.setCapabilityIdentity(0);
  assert.throws(
    () => harness.evaluate("__retainedConsoleLog('revoked')"),
    /Invocation capability is unavailable/u
  );
  assert.equal(harness.calls.length, 1);

  harness.setCapabilityIdentity(52);
  harness.evaluate("__retainedConsoleLog('second');");
  harness.setCapabilityIdentity(53);
  harness.setHostStatus(-1);
  assert.throws(
    () => harness.evaluate("__retainedConsoleLog('stale')"),
    /Invocation capability is stale/u
  );
  assert.deepEqual(
    harness.calls.map(({ identity, messages }) => ({ identity, messages })),
    [
      { identity: 51, messages: ["'first'"] },
      { identity: 52, messages: ["'second'"] },
      { identity: 53, messages: ["'stale'"] },
    ]
  );
  assert.deepEqual(harness.capabilityLookups, [51, 0, 52, 53]);
  assert.equal(harness.freedPointers.length, 3);
});

test("authenticates exact runtime implementations and rejects named target gaps", () => {
  assert.match(convexWasmTargetRuntimeSurfacePolicySha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.date, {
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
  });
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.mathRandom, {
    hostImport: "convex_math_random",
    implementation: "invocation-seeded-chacha12-stream",
    state: "implemented",
  });
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.permittedCrypto, {
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
  });
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.performance, {
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
  });
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.environment.process, {
    environment: {
      implementation: "invocation-capability-proxy",
      missingValue: "undefined",
      state: "implemented",
    },
    implementation: "frozen-process-env-only",
    state: "implemented",
  });
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.globalObject.application, {
    adapterGlobals: ["clearInterval", "clearTimeout", "setInterval", "setTimeout"],
    capabilityGlobals: ["Convex", "Date", "console", "crypto", "performance", "process"],
    engineGlobals: convexWasmTargetRuntimeSurfacePolicy.globalObject.application.engineGlobals,
    implementation: "inventory-derived-extensible-null-prototype-immutable-builtins-facade",
    runtimeSupportGlobals: ["DOMException", "Intl", "URL", "URLSearchParams"],
    selfReference: "globalThis",
    state: "implemented",
  });
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.timers, {
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
  });
  assert.equal(
    convexWasmTargetRuntimeSurfacePolicy.globalObject.application.engineGlobals.includes("Object"),
    true
  );
  for (const name of ["Date", "Math", "globalThis", "eval", "gc", "print"]) {
    assert.equal(
      convexWasmTargetRuntimeSurfacePolicy.globalObject.application.engineGlobals.includes(name),
      false,
      name
    );
  }

  for (const [source, code] of [
    ["performance.now = () => 1", "ambient-global-write"],
    ["console.log = () => {}", "ambient-global-write"],
    ["globalThis.console.warn('value')", "raw-global-object-flow"],
    ["globalThis.Math.random()", "raw-global-object-flow"],
    ["globalThis.Date", "raw-global-object-flow"],
    ["globalThis.Object = Object", "raw-global-object-flow"],
    ["({ Object: globalThis.Object } = {})", "raw-global-object-flow"],
    ["globalThis['Obj' + 'ect']", "raw-global-object-flow"],
    ["(() => globalThis)()", "raw-global-object-flow"],
    [`${convexWasmApplicationGlobalThisBinding}.Object = Object`, "ambient-global-write"],
  ]) {
    assert.throws(
      () =>
        renderNativeDbGetCapabilityTarget({
          argumentFields: [],
          compileProfileJavascript: `var __convexWasmCompileProfile = { selected: () => ${source} };`,
        }),
      (error) => error?.name === "ConvexWasmTargetRuntimeSurfaceGap" && error.code === code,
      source
    );
  }

  assert.doesNotThrow(() =>
    renderNativeDbGetCapabilityTarget({
      argumentFields: [],
      compileProfileJavascript: `
var __convexWasmCompileProfile = {
  selected: () => {
    const DateAlias = Date;
    const now = DateAlias.now;
    const inputs = [2024, 0, 2];
    return [
    DateAlias(),
    now.call(DateAlias),
    new DateAlias().getTime(),
    new DateAlias(0).getTime(),
    new DateAlias(...inputs).getTime(),
    DateAlias.parse("2024-01-02T00:00:00.000Z"),
    DateAlias.UTC(2024, 0, 2),
    DateAlias.prototype,
    new DateAlias(0) instanceof DateAlias,
    Math.max(1, 2),
    Object.entries({ value: 1 }),
    Object.fromEntries([["value", 1]]),
    Math.random(),
    performance.now(),
    crypto.subtle.digest("SHA-256", new Uint8Array()),
    crypto.getRandomValues(new Uint8Array(4)),
    crypto.randomUUID(),
    clearTimeout(1),
    clearInterval(1),
    setTimeout,
    setInterval,
    ];
  },
};`,
    })
  );
  assert.doesNotThrow(() =>
    renderNativeDbGetCapabilityTarget({
      argumentFields: [],
      compileProfileJavascript: `var __convexWasmCompileProfile = {
  selected: () => [
    ${convexWasmApplicationGlobalThisBinding}.Object.entries({ value: 1 }),
    ${convexWasmApplicationGlobalThisBinding}["TextEncoder"],
    ${convexWasmApplicationGlobalThisBinding}.Date === Date,
    new ${convexWasmApplicationGlobalThisBinding}["Date"](0).getTime(),
    ${convexWasmApplicationGlobalThisBinding}.globalThis === ${convexWasmApplicationGlobalThisBinding},
    { ...${convexWasmApplicationGlobalThisBinding} },
  ],
};`,
    })
  );

  for (const source of [
    "var importedAt = Date.now(); var __convexWasmCompileProfile = { selected: () => importedAt };",
    "var __convexWasmCompileProfile = (() => { var importedAt = Date.now(); return { selected: () => importedAt }; })();",
    "var __convexWasmCompileProfile = (() => (() => Date.now())())();",
  ]) {
    assert.doesNotThrow(() =>
      renderNativeDbGetCapabilityTarget({
        argumentFields: [],
        compileProfileJavascript: source,
      })
    );
  }

  for (const source of [
    "var __convexWasmCompileProfile = { selected: () => { const clock = performance; return clock.now(); } };",
    "var __convexWasmCompileProfile = { selected: () => performance['now']() };",
    "var __convexWasmCompileProfile = { selected: () => { const now = performance.now; return now.call(performance); } };",
    "var __convexWasmCompileProfile = { selected: () => ({ ...performance }).now() };",
    "var __convexWasmCompileProfile = { selected: () => performance.timeOrigin };",
    "var importedAt = performance.now(); var __convexWasmCompileProfile = { selected: () => importedAt };",
  ]) {
    assert.doesNotThrow(() =>
      renderNativeDbGetCapabilityTarget({
        argumentFields: [],
        compileProfileJavascript: source,
      })
    );
  }

  for (const source of [
    "Math.random()",
    'Math["random"]()',
    "(() => { const random = Math.random; return random(); })()",
    'crypto.subtle.digest("SHA-256", new Uint8Array())',
    'crypto["subtle"]["digest"]({name: "SHA-256"}, new Uint8Array())',
    '(() => { const webCrypto = crypto; const subtle = webCrypto.subtle; return subtle.digest("SHA-256", new Uint8Array()); })()',
    "crypto.getRandomValues(new Uint8Array(4))",
    'crypto["getRandomValues"](new Uint8Array(4))',
    "(() => { const getRandomValues = crypto.getRandomValues; return getRandomValues(new Uint8Array(4)); })()",
    "crypto.randomUUID()",
    'crypto["randomUUID"]()',
    "(() => { const randomUUID = crypto.randomUUID; return randomUUID(); })()",
  ]) {
    assert.doesNotThrow(() =>
      renderNativeDbGetCapabilityTarget({
        argumentFields: [],
        compileProfileJavascript: `var __convexWasmCompileProfile = { selected: () => ${source} };`,
      })
    );
  }
});

test("native capability target leaves direct and indirect context operations to Static Hermes", () => {
  const code = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript: `
function contextReader(ctx) { return ctx.db.system; }
var __convexWasmCompileProfile = {
  direct: async (ctx, args) => ctx.db.system.get("_storage", args.id),
  aliased: async (ctx, args) => {
    const system = ctx.db.system;
    return system.get("_storage", args.id);
  },
  helperReturned: async (ctx, args) => contextReader(ctx).get("_storage", args.id),
  computed: async (ctx, args) => ctx["db"]["system"]["get"]("_storage", args.id),
};`,
  });

  assert.match(code, /ctx\.db\.system\.get\("_storage", args\.id\)/u);
  assert.match(code, /const system = ctx\.db\.system/u);
  assert.match(code, /contextReader\(ctx\)\.get\("_storage", args\.id\)/u);
  assert.match(code, /ctx\["db"\]\["system"\]\["get"\]\("_storage", args\.id\)/u);
  assert.doesNotMatch(code, /ImportedOperationDescriptor|operationId|compilerCallsite/u);
});

test("native performance uses the closed invocation capability and consumes handles exactly", () => {
  const harness = nativePerformanceHarness({ result: 42.7 });
  assert.equal(harness.now(), 42.7);
  assert.deepEqual(JSON.parse(JSON.stringify(harness.requests)), [
    { version: convexWasmCapabilityRequestAbiVersion, kind: "performanceNow" },
  ]);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.evaluate("performance['now']()"), 42.7);
  assert.equal(
    harness.evaluate("(() => { const now = performance.now; return now.call(performance); })()"),
    42.7
  );
  assert.equal(harness.evaluate("({ ...performance }).now()"), 42.7);
  assert.equal(harness.evaluate("performance.timeOrigin"), undefined);
  assert.equal(harness.outstandingHandles(), 0);

  const unavailable = nativePerformanceHarness({ capabilityIdentity: 0 });
  assert.throws(() => unavailable.now(), /capability is unavailable/u);
  assert.deepEqual(unavailable.requests, []);
  assert.equal(unavailable.outstandingHandles(), 0);

  const stale = nativePerformanceHarness({ syncResult: -2 });
  assert.throws(() => stale.now(), /capability is stale/u);
  assert.deepEqual(stale.requests, []);
  assert.equal(stale.outstandingHandles(), 0);
});

test("native WebCrypto SHA-256 accepts BufferSource views and snapshots input synchronously", async () => {
  const harness = nativeCryptoHarness({ capabilityIdentity: 17 });
  assert.equal(harness.evaluate("Object.isFrozen(crypto)"), true);
  assert.equal(harness.evaluate("Object.isFrozen(crypto.subtle)"), true);
  assert.equal(harness.evaluate("Object.isFrozen(crypto.subtle.digest)"), true);

  const stringPromise = harness.digest("SHA-256", new Uint8Array([0x61, 0x62, 0x63]));
  assert.equal(stringPromise instanceof Promise, true);
  const stringResult = await stringPromise;
  assert.equal(stringResult instanceof ArrayBuffer, true);
  assert.equal(stringResult.byteLength, 32);
  assert.equal(
    bufferHex(stringResult),
    createHash("sha256").update(Buffer.from("abc")).digest("hex")
  );

  const objectResult = await harness.digest(
    { name: "sha-256" },
    Uint8Array.from([0x00, 0x11, 0x22, 0x33]).buffer
  );
  assert.equal(objectResult instanceof ArrayBuffer, true);
  assert.equal(
    bufferHex(objectResult),
    createHash("sha256")
      .update(Uint8Array.from([0x00, 0x11, 0x22, 0x33]))
      .digest("hex")
  );

  const backing = Uint8Array.from([0xff, 0x10, 0x20, 0x30, 0xee]);
  const subview = new Uint8Array(backing.buffer, 1, 3);
  assert.equal(
    bufferHex(await harness.digest("SHA-256", subview)),
    createHash("sha256")
      .update(Uint8Array.from([0x10, 0x20, 0x30]))
      .digest("hex")
  );
  const dataView = new DataView(backing.buffer, 2, 2);
  assert.equal(
    bufferHex(await harness.digest({ name: "SHA-256" }, dataView)),
    createHash("sha256")
      .update(Uint8Array.from([0x20, 0x30]))
      .digest("hex")
  );

  const nonAscii = new TextEncoder().encode("Привет, 世界");
  assert.equal(
    bufferHex(await harness.digest("SHA-256", nonAscii)),
    createHash("sha256").update(nonAscii).digest("hex")
  );

  const mutable = Uint8Array.from([1, 2, 3, 4]);
  const snapshotted = harness.digest("SHA-256", mutable);
  mutable.fill(9);
  assert.equal(
    bufferHex(await snapshotted),
    createHash("sha256")
      .update(Uint8Array.from([1, 2, 3, 4]))
      .digest("hex")
  );

  const aliasDigest = harness.evaluate(
    "(() => { const webCrypto = crypto; const subtle = webCrypto['subtle']; return subtle['digest']; })()"
  );
  assert.equal(
    bufferHex(await aliasDigest("SHA-256", Uint8Array.from([5, 6]))),
    createHash("sha256")
      .update(Uint8Array.from([5, 6]))
      .digest("hex")
  );
  assert.equal(harness.outstandingAllocations(), 0);
});

test("native WebCrypto SHA-256 rejects through a Promise and reacquires invocation authority", async () => {
  const harness = nativeCryptoHarness({ capabilityIdentity: 31 });
  const unsupported = harness.digest("SHA-1", new Uint8Array());
  assert.equal(unsupported instanceof Promise, true);
  await assert.rejects(
    unsupported,
    (error) => error?.constructor?.name === "DOMException" && error.name === "NotSupportedError"
  );

  const missingName = harness.digest({}, new Uint8Array());
  assert.equal(missingName instanceof Promise, true);
  await assert.rejects(missingName, TypeError);
  const invalidSource = harness.digest("SHA-256", "abc");
  assert.equal(invalidSource instanceof Promise, true);
  await assert.rejects(invalidSource, TypeError);

  await harness.digest("SHA-256", Uint8Array.from([1]));
  harness.setCapabilityIdentity(32);
  await harness.digest({ name: "SHA-256" }, Uint8Array.from([2]));
  assert.deepEqual(
    harness.calls.map(({ identity, input }) => ({ identity, input: [...input] })),
    [
      { identity: 31, input: [1] },
      { identity: 32, input: [2] },
    ]
  );

  harness.setCapabilityIdentity(0);
  const unavailable = harness.digest("SHA-256", Uint8Array.from([3]));
  assert.equal(unavailable instanceof Promise, true);
  await assert.rejects(unavailable, /capability is unavailable/u);
  assert.equal(harness.outstandingAllocations(), 0);
});

test("native WebCrypto randomness accepts only integer typed-array bytes through the exact ceiling", () => {
  const harness = nativeCryptoHarness({ capabilityIdentity: 53 });
  assert.equal(harness.evaluate("Object.isFrozen(crypto.getRandomValues)"), true);
  assert.equal(harness.evaluate("Object.isFrozen(crypto.randomUUID)"), true);

  for (const TypedArray of [
    Int8Array,
    Uint8Array,
    Uint8ClampedArray,
    Int16Array,
    Uint16Array,
    Int32Array,
    Uint32Array,
    BigInt64Array,
    BigUint64Array,
  ]) {
    const elementBytes = TypedArray.BYTES_PER_ELEMENT;
    const backing = new Uint8Array(elementBytes * 4);
    backing.fill(0xaa);
    const view = new TypedArray(backing.buffer, elementBytes, 2);
    assert.strictEqual(harness.getRandomValues(view), view);
    assert.deepEqual([...backing.subarray(0, elementBytes)], Array(elementBytes).fill(0xaa));
    assert.deepEqual(
      [...backing.subarray(elementBytes, elementBytes * 3)],
      Array.from({ length: elementBytes * 2 }, (_, index) => (53 + index * 17) & 0xff)
    );
    assert.deepEqual([...backing.subarray(elementBytes * 3)], Array(elementBytes).fill(0xaa));

    const empty = new TypedArray(0);
    assert.strictEqual(harness.getRandomValues(empty), empty);
  }

  const maximum = new Uint8Array(65_536);
  assert.strictEqual(harness.getRandomValues(maximum), maximum);
  assert.equal(maximum[0], 53);
  assert.equal(maximum[65_535], (53 + 65_535 * 17) & 0xff);

  const lookupsBeforeRejections = harness.capabilityLookups.length;
  const callsBeforeRejections = harness.randomnessCalls.length;
  for (const view of [
    new Float32Array(1),
    new Float64Array(1),
    new DataView(new ArrayBuffer(1)),
    new Uint8Array(65_537),
  ]) {
    assert.throws(() => harness.getRandomValues(view));
  }
  assert.equal(harness.capabilityLookups.length, lookupsBeforeRejections);
  assert.equal(harness.randomnessCalls.length, callsBeforeRejections);
  assert.equal(harness.outstandingAllocations(), 0);
});

test("native UUID and Math randomness retained references reacquire invocation authority", () => {
  const harness = nativeCryptoHarness({ capabilityIdentity: 71 });
  const getRandomValues = harness.evaluate("crypto.getRandomValues");
  const randomUUID = harness.evaluate("crypto.randomUUID");
  const mathRandom = harness.evaluate("Math.random");
  assert.equal(harness.evaluate("Object.isFrozen(Math.random)"), true);

  assert.strictEqual(getRandomValues(new Uint8Array(1)).byteLength, 1);
  assert.equal(randomUUID(), "123e4567-e89b-42d3-a456-426614174000");
  assert.equal(mathRandom(), 0.71);
  harness.setCapabilityIdentity(72);
  assert.strictEqual(getRandomValues(new Uint8Array(1)).byteLength, 1);
  assert.equal(randomUUID(), "123e4567-e89b-42d3-a456-426614174000");
  assert.equal(mathRandom(), 0.72);

  assert.deepEqual(harness.capabilityLookups, [71, 71, 71, 72, 72, 72]);
  assert.deepEqual(harness.randomnessCalls, [
    { identity: 71, kind: "getRandomValues", length: 1 },
    { identity: 71, kind: "randomUUID" },
    { identity: 71, kind: "Math.random" },
    { identity: 72, kind: "getRandomValues", length: 1 },
    { identity: 72, kind: "randomUUID" },
    { identity: 72, kind: "Math.random" },
  ]);
  assert.equal(harness.outstandingAllocations(), 0);
});

test("unchanged shared SHA-256 helper consumes the native WebCrypto facade", async () => {
  const harness = nativeCryptoHarness({ capabilityIdentity: 41 });
  const sha256Hex = harness.loadSharedSha256();
  assert.equal(typeof sha256Hex, "function");
  const input = "платёж-世界";
  assert.equal(await sha256Hex(input), createHash("sha256").update(input).digest("hex"));
  assert.deepEqual(
    harness.calls.map(({ identity, input: bytes }) => ({ identity, input: [...bytes] })),
    [{ identity: 41, input: [...new TextEncoder().encode(input)] }]
  );
  assert.equal(harness.outstandingAllocations(), 0);
});

test("runtime-surface provenance keeps named function and class expressions local", () => {
  for (const source of [
    `const recursive = function e(value) {
  return value === 0 ? 0 : e(value - 1);
};
var __convexWasmCompileProfile = { selected: () => recursive(2) };`,
    `const Recursive = class e {
  static create() { return new e(); }
  constructor() { this.constructorValue = e; }
};
var __convexWasmCompileProfile = { selected: () => Recursive.create() };`,
    `const e = { e: 1 };
function read(e) { return e.e; }
var __convexWasmCompileProfile = { selected: () => read(e) };`,
  ]) {
    assert.doesNotThrow(() => assertConvexWasmTargetRuntimeSurface(source), source);
  }

  assert.equal(
    convexWasmTargetRuntimeSurfacePolicy.ambientGlobals.some(({ name }) => name === "e"),
    false
  );
  assert.throws(
    () =>
      assertConvexWasmTargetRuntimeSurface(
        "var __convexWasmCompileProfile = { selected: () => e };"
      ),
    (error) =>
      error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
      error.code === "ambient-global-unavailable" &&
      error.surface === "e"
  );

  for (const source of [
    "process.env.API_KEY",
    "process.env['API_' + 'KEY']",
    "const env = process.env; var __convexWasmCompileProfile = { selected: () => env.API_KEY };",
  ]) {
    assert.doesNotThrow(() =>
      renderNativeDbGetCapabilityTarget({
        argumentFields: [],
        compileProfileJavascript: source.includes("__convexWasmCompileProfile")
          ? source
          : `var __convexWasmCompileProfile = { selected: () => ${source} };`,
      })
    );
  }
  for (const source of [
    "process = { env: {} }",
    "process.env = {}",
    "process.env.API_KEY = 'forged'",
    "delete process.env.API_KEY",
  ]) {
    assert.throws(
      () =>
        renderNativeDbGetCapabilityTarget({
          argumentFields: [],
          compileProfileJavascript: `var __convexWasmCompileProfile = { selected: () => (${source}) };`,
        }),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      source
    );
  }
});

test("process.env resolves every read through the current nonretained capability", () => {
  const code = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript: `
const importedEnvironmentValue = process.env.IMPORT_VALUE;
var __convexWasmCompileProfile = {
  selected: () => [importedEnvironmentValue, process.env.INVOCATION_VALUE],
};`,
  });
  const adapter = code.slice(
    code.indexOf("function __convexEnvironmentVariableGet"),
    code.indexOf("let __convexSdkActiveUdfKind")
  );
  const lookupEnd = adapter.indexOf("\n}\n\nconst __convexProcessEnvironmentTarget") + 2;
  assert.ok(lookupEnd > 1);
  const lookup = adapter.slice(0, lookupEnd);
  assert.equal(lookup.match(/__convexHostCapabilityCurrent\(\)/gu)?.length, 1);
  assert.match(adapter, /const capabilityIdentity = __convexHostCapabilityCurrent\(\)/u);
  assert.doesNotMatch(adapter, /capabilityIdentity <= 0/u);
  assert.match(adapter, /__convexHostCapabilitySyncTake\(capabilityIdentity, requestHandle\)/u);
  assert.match(
    adapter,
    /get\(target, property, receiver\)[\s\S]*__convexEnvironmentVariableGet\(property\)/u
  );
  assert.doesNotMatch(adapter.slice(lookupEnd), /capabilityIdentity/u);
  assert.match(adapter, /Object\.freeze\(\{env: __convexProcessEnvironment\}\)/u);
  assert.match(adapter, /configurable: false[\s\S]*writable: false/u);
});

test("generic capability requests match installed Convex query, write, scheduler, time, and result semantics", async () => {
  const [{ setupReader, setupWriter }, { setupMutationScheduler }] = await Promise.all([
    import(
      new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
    ),
    import(
      new URL("../../node_modules/convex/dist/esm/server/impl/scheduler_impl.js", import.meta.url)
    ),
  ]);
  const harness = nativeCapabilityHarness();
  const queryContext = harness.createContext("query");
  const mutationContext = harness.createContext("mutation");
  const normalize = (value) => JSON.parse(JSON.stringify(value));
  const previousConvex = globalThis.Convex;
  const previousDateNow = Date.now;
  let sdkQuery;
  let sdkQueryPage;
  const sdkAsyncCalls = [];
  const takeSdkAsyncCall = (expectedName) => {
    const call = sdkAsyncCalls.shift();
    assert.equal(call?.name, expectedName);
    return call.args;
  };
  globalThis.Convex = {
    syscall(name, encodedArgs) {
      if (name === "1.0/queryCleanup") return JSON.stringify(null);
      assert.equal(name, "1.0/queryStream");
      sdkQuery = JSON.parse(encodedArgs);
      return JSON.stringify({ queryId: 7 });
    },
    async asyncSyscall(name, encodedArgs) {
      if (name === "1.0/queryPage") {
        sdkQueryPage = JSON.parse(encodedArgs);
        return JSON.stringify({
          page: [],
          isDone: false,
          continueCursor: "next-cursor",
          splitCursor: null,
          pageStatus: null,
        });
      }
      if (name === "1.0/queryStreamNext") {
        return JSON.stringify({ done: true, value: null });
      }
      assert.ok(
        ["1.0/cancel_job", "1.0/remove", "1.0/replace", "1.0/schedule"].includes(name),
        `unexpected SDK syscall ${name}`
      );
      sdkAsyncCalls.push({ args: JSON.parse(encodedArgs), name });
      return JSON.stringify(name === "1.0/schedule" ? "scheduled-id" : null);
    },
  };
  Date.now = () => 1_700_000_000_250;
  try {
    assert.equal(queryContext.db.insert, undefined);
    assert.equal(queryContext.db.patch, undefined);
    assert.equal(queryContext.db.replace, undefined);
    assert.equal(queryContext.db.delete, undefined);
    assert.equal(queryContext.scheduler, undefined);
    assert.equal(typeof mutationContext.db.replace, "function");
    assert.equal(typeof mutationContext.db.delete, "function");
    assert.equal(typeof mutationContext.scheduler.runAt, "function");
    assert.equal(typeof mutationContext.scheduler.cancel, "function");

    const sdkUnique = setupReader()
      .query("documents")
      .withIndex("by_tenant_sequence", (q) =>
        q.eq("tenant", "tenant-a").gt("sequence", 3).lte("sequence", 9)
      )
      .unique();
    assert.equal(await sdkUnique, null);

    const capabilityUnique = queryContext.db
      .query("documents")
      .withIndex("by_tenant_sequence", (q) =>
        q.eq("tenant", "tenant-a").gt("sequence", 3).lte("sequence", 9)
      )
      .unique();
    const queryRequest = normalize(harness.requests.shift());
    harness.settle(1, 0, harness.allocate(null));
    assert.equal(await capabilityUnique, null);
    assert.deepEqual(queryRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbQuery",
      table: "documents",
      source: {
        type: "indexRange",
        index: "by_tenant_sequence",
        constraints: sdkQuery.query.source.range.map(({ type, fieldPath, value }) => ({
          operator: type.toLowerCase(),
          field: fieldPath,
          value,
        })),
      },
      operators: sdkQuery.query.operators.map(({ limit }) => ({ type: "limit", limit })),
      order: sdkQuery.query.source.order,
      terminal: "unique",
    });
    assert.equal(queryRequest.order, null);

    const sdkSearch = setupReader()
      .query("documents")
      .withSearchIndex("by_content", (q) =>
        q.search("body", "needle phrase").eq("tenant", "tenant-a").eq("category", undefined)
      )
      .filter((q) => q.eq(q.field("status"), "ready"))
      .take(4);
    assert.deepEqual(await sdkSearch, []);
    const capabilitySearch = queryContext.db
      .query("documents")
      .withSearchIndex("by_content", (q) =>
        q.search("body", "needle phrase").eq("tenant", "tenant-a").eq("category", undefined)
      )
      .filter((q) => q.eq(q.field("status"), "ready"))
      .take(4);
    const searchRequest = normalize(harness.requests.shift());
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([]));
    assert.deepEqual(await capabilitySearch, []);
    assert.deepEqual(searchRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbQuery",
      table: "documents",
      source: {
        type: "search",
        index: "by_content",
        filters: sdkQuery.query.source.filters.map(({ type, fieldPath, value }) => ({
          type: type.toLowerCase(),
          field: fieldPath,
          value,
        })),
      },
      operators: sdkQuery.query.operators.map((operator) =>
        "filter" in operator
          ? { type: "filter", expression: operator.filter }
          : { type: "limit", limit: operator.limit }
      ),
      order: null,
      terminal: "collect",
    });
    assert.throws(
      () =>
        queryContext.db
          .query("documents")
          .withSearchIndex("by_content", (q) => q.search("body", "needle"))
          .order("asc"),
      /relevance order/u
    );

    const sdkCollect = setupReader()
      .query("documents")
      .order("desc")
      .filter((q) =>
        q.and(
          q.eq(q.field("tenant"), "tenant-a"),
          q.neq(q.field("disabled"), true),
          q.gte(q.add(q.field("sequence"), 1), 4)
        )
      )
      .collect();
    assert.deepEqual(await sdkCollect, []);
    const capabilityCollect = queryContext.db
      .query("documents")
      .order("desc")
      .filter((q) =>
        q.and(
          q.eq(q.field("tenant"), "tenant-a"),
          q.neq(q.field("disabled"), true),
          q.gte(q.add(q.field("sequence"), 1), 4)
        )
      )
      .collect();
    const collectRequest = normalize(harness.requests.shift());
    const collectedDocuments = [{ _id: "document-1", sequence: 3 }];
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(collectedDocuments));
    assert.deepEqual(normalize(await capabilityCollect), collectedDocuments);
    assert.deepEqual(collectRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbQuery",
      table: "documents",
      source: { type: "fullTableScan" },
      operators: sdkQuery.query.operators.map(({ filter }) => ({
        type: "filter",
        expression: filter,
      })),
      order: sdkQuery.query.source.order,
      terminal: "collect",
    });

    const sdkTake = setupReader()
      .query("documents")
      .withIndex("by_tenant_sequence", (q) => q.eq("tenant", "tenant-a"))
      .filter((q) => q.gt(q.field("sequence"), 2))
      .take(3);
    assert.deepEqual(await sdkTake, []);
    const capabilityTake = queryContext.db
      .query("documents")
      .withIndex("by_tenant_sequence", (q) => q.eq("tenant", "tenant-a"))
      .filter((q) => q.gt(q.field("sequence"), 2))
      .take(3);
    const takeRequest = normalize(harness.requests.shift());
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([]));
    assert.deepEqual(await capabilityTake, []);
    assert.deepEqual(takeRequest.operators, [
      { type: "filter", expression: sdkQuery.query.operators[0].filter },
      { type: "limit", limit: sdkQuery.query.operators[1].limit },
    ]);
    assert.equal(takeRequest.terminal, "collect");
    assert.equal(takeRequest.source.type, "indexRange");
    assert.equal(takeRequest.source.index, "by_tenant_sequence");

    const paginationOptions = {
      numItems: 2,
      cursor: "current-cursor",
      endCursor: "end-cursor",
      maximumRowsRead: 7,
      maximumBytesRead: 4096,
      ignored: "not part of the request envelope",
    };
    const sdkPagePromise = setupReader()
      .query("documents")
      .withIndex("by_tenant_sequence", (q) => q.eq("tenant", "tenant-a"))
      .order("desc")
      .paginate(paginationOptions);
    assert.deepEqual(await sdkPagePromise, {
      page: [],
      isDone: false,
      continueCursor: "next-cursor",
      splitCursor: null,
      pageStatus: null,
    });
    const capabilityPagePromise = queryContext.db
      .query("documents")
      .withIndex("by_tenant_sequence", (q) => q.eq("tenant", "tenant-a"))
      .order("desc")
      .paginate(paginationOptions);
    const paginateRequest = normalize(harness.requests.shift());
    const paginationResult = {
      page: [{ _id: "document-3", sequence: 5 }],
      isDone: false,
      continueCursor: "next-cursor",
      splitCursor: null,
      pageStatus: "SplitRecommended",
    };
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(paginationResult));
    assert.deepEqual(normalize(await capabilityPagePromise), paginationResult);
    assert.deepEqual(paginateRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbQuery",
      table: "documents",
      source: {
        type: "indexRange",
        index: "by_tenant_sequence",
        constraints: [{ operator: "eq", field: "tenant", value: "tenant-a" }],
      },
      operators: [],
      order: sdkQueryPage.query.source.order,
      pagination: {
        cursor: sdkQueryPage.cursor,
        endCursor: sdkQueryPage.endCursor,
        maximumBytesRead: sdkQueryPage.maximumBytesRead,
        maximumRowsRead: sdkQueryPage.maximumRowsRead,
        pageSize: sdkQueryPage.pageSize,
      },
      terminal: "paginate",
    });
    assert.equal(Object.hasOwn(paginateRequest.pagination, "ignored"), false);
    assert.throws(
      () => queryContext.db.query("documents").paginate({ numItems: -1, cursor: null }),
      /options\.numItems/u
    );
    assert.throws(
      () => queryContext.db.query("documents").paginate({ numItems: "2", cursor: null }),
      /options\.numItems/u
    );
    assert.throws(
      () => queryContext.db.query("documents").paginate({ cursor: null }),
      /options\.numItems/u
    );

    const first = queryContext.db.query("documents").first();
    const firstRequest = normalize(harness.requests.shift());
    const firstDocument = { _id: "document-2", sequence: 4 };
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(firstDocument));
    assert.deepEqual(normalize(await first), firstDocument);
    assert.deepEqual(firstRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbQuery",
      table: "documents",
      source: { type: "fullTableScan" },
      operators: [{ type: "limit", limit: 1 }],
      order: null,
      terminal: "first",
    });

    const oneShot = queryContext.db.query("documents").withIndex("by_tenant_sequence");
    const oneShotCollect = oneShot.collect();
    assert.throws(() => oneShot.first(), /query is closed/u);
    harness.requests.shift();
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([]));
    assert.deepEqual(await oneShotCollect, []);
    assert.throws(() => queryContext.db.query("documents").take(-1), /non-negative integer/u);

    const addresses = [
      {
        reference: { [Symbol.for("functionName")]: "tasks:run" },
        expected: { name: "tasks:run" },
      },
      {
        reference: { [Symbol.for("toReferencePath")]: "_reference/function/tasks:run" },
        expected: { reference: "_reference/function/tasks:run" },
      },
      {
        reference: "function://handle",
        expected: { functionHandle: "function://handle" },
      },
    ];
    for (let index = 0; index < addresses.length; index += 1) {
      const { reference, expected } = addresses[index];
      const sdkScheduled = setupMutationScheduler().runAfter(250, reference, { sequence: index });
      assert.equal(await sdkScheduled, "scheduled-id");
      const sdkSchedule = takeSdkAsyncCall("1.0/schedule");
      const capabilityScheduled = mutationContext.scheduler.runAfter(250, reference, {
        sequence: index,
      });
      const scheduleRequest = normalize(harness.requests.shift());
      harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate("scheduled-id"));
      assert.equal(await capabilityScheduled, "scheduled-id");
      assert.deepEqual(scheduleRequest.functionAddress, expected);
      assert.deepEqual(
        Object.fromEntries(
          Object.entries(sdkSchedule).filter(([key]) =>
            ["name", "reference", "functionHandle"].includes(key)
          )
        ),
        expected
      );
      assert.deepEqual(scheduleRequest.args, sdkSchedule.args);
      assert.equal((harness.now() + scheduleRequest.delayMilliseconds) / 1000, sdkSchedule.ts);
    }

    const patch = mutationContext.db.patch(
      "documents",
      "document-id",
      harness.guestValue("({ sequence: 4 })")
    );
    assert.equal(harness.requests.shift().kind, "dbPatch");
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await patch, undefined);

    const writer = setupWriter();
    await writer.replace("documents", "document-id", { sequence: 5 });
    const sdkReplace = takeSdkAsyncCall("1.0/replace");
    const replacement = mutationContext.db.replace("documents", "document-id", { sequence: 5 });
    const replaceRequest = normalize(harness.requests.shift());
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await replacement, undefined);
    assert.deepEqual(replaceRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbReplace",
      ...sdkReplace,
    });

    await writer.delete("documents", "document-id");
    const sdkDelete = takeSdkAsyncCall("1.0/remove");
    const deletion = mutationContext.db.delete("documents", "document-id");
    const deleteRequest = normalize(harness.requests.shift());
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await deletion, undefined);
    assert.deepEqual(deleteRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbDelete",
      ...sdkDelete,
    });

    const runAtTimes = [
      {
        capability: 1_700_000_100_250,
        sdk: 1_700_000_100_250,
      },
      {
        capability: harness.date(1_700_000_200_250),
        sdk: new Date(1_700_000_200_250),
      },
    ];
    for (let index = 0; index < runAtTimes.length; index += 1) {
      const scheduled = setupMutationScheduler().runAt(runAtTimes[index].sdk, "tasks:run", {
        sequence: index + 5,
      });
      assert.equal(await scheduled, "scheduled-id");
      const sdkRunAt = takeSdkAsyncCall("1.0/schedule");
      const capabilityScheduled = mutationContext.scheduler.runAt(
        runAtTimes[index].capability,
        "tasks:run",
        { sequence: index + 5 }
      );
      const runAtRequest = normalize(harness.requests.shift());
      harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate("scheduled-id"));
      assert.equal(await capabilityScheduled, "scheduled-id");
      assert.deepEqual(runAtRequest.functionAddress, { name: "tasks:run" });
      assert.deepEqual(runAtRequest.args, sdkRunAt.args);
      assert.equal(runAtRequest.timestampMilliseconds / 1000, sdkRunAt.ts);
    }

    await setupMutationScheduler().cancel("scheduled-id");
    const sdkCancel = takeSdkAsyncCall("1.0/cancel_job");
    const cancellation = mutationContext.scheduler.cancel("scheduled-id");
    const cancelRequest = normalize(harness.requests.shift());
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await cancellation, undefined);
    assert.deepEqual(cancelRequest, {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "schedulerCancel",
      ...sdkCancel,
    });
    assert.equal(sdkAsyncCalls.length, 0);

    const normalizeRequestCount = harness.requests.length;
    assert.equal(queryContext.db.normalizeId("documents", "bad-id"), null);
    assert.equal(harness.requests.length, normalizeRequestCount + 1);
    assert.equal(harness.requests.at(-1).kind, "dbNormalizeId");

    harness.invoke(() => undefined, queryContext, {});
    await drainCapabilityMicrotasks();
    assert.equal(harness.done(), true);
    assert.equal(harness.status(), 0);
    assert.deepEqual(harness.results, [null]);
    assert.equal(harness.cleanup(), 0);
  } finally {
    Date.now = previousDateNow;
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("generic capability search filters are single-use and fail closed", () => {
  const harness = nativeCapabilityHarness();
  const context = harness.createContext("mutation");

  assert.throws(
    () => context.db.query("documents").withSearchIndex("by_content"),
    /must be a function/u
  );
  assert.throws(
    () => context.db.query("documents").withSearchIndex("by_content", () => null),
    /invalid builder/u
  );
  assert.throws(
    () => context.db.query("documents").withSearchIndex("by_content", (q) => q),
    /must begin with a search filter/u
  );
  assert.throws(
    () => context.db.query("documents").withSearchIndex("by_content", (q) => q.eq("tenant", 1)),
    /must begin with a search filter/u
  );
  assert.throws(
    () => context.db.query("documents").withSearchIndex("by_content", (q) => q.search(3, "needle")),
    /field must be a string/u
  );
  assert.throws(
    () => context.db.query("documents").withSearchIndex("by_content", (q) => q.search("body", 3)),
    /query must be a string/u
  );
  assert.throws(
    () =>
      context.db
        .query("documents")
        .withSearchIndex("by_content", (q) => q.search("body", "first").search("body", "second")),
    /only one search filter/u
  );

  let initialBuilder;
  context.db.query("documents").withSearchIndex("by_content", (q) => {
    initialBuilder = q;
    return q.search("body", "needle");
  });
  assert.throws(
    () => initialBuilder.search("body", "again"),
    /SearchFilterBuilder has already been used/u
  );

  let finalBuilder;
  context.db.query("documents").withSearchIndex("by_content", (q) => {
    finalBuilder = q.search("body", "needle");
    return finalBuilder;
  });
  assert.throws(
    () => finalBuilder.eq("tenant", "tenant-b"),
    /SearchFilterBuilder has already been used/u
  );

  const commitTs = context.db.vars.commitTs;
  assert.throws(
    () =>
      context.db
        .query("documents")
        .withSearchIndex("by_content", (q) => q.search("body", "needle").eq("commitTs", commitTs))
        .collect(),
    /Pending commit timestamp is not allowed/u
  );
  assert.throws(
    () =>
      context.db
        .query("documents")
        .withSearchIndex("by_content", (q) =>
          q.search("body", "needle").eq("tenant", { $integer: "forged" })
        )
        .collect(),
    /reserved prefix/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
});

test("generic storage capabilities use authenticated v4 request envelopes", async () => {
  const harness = nativeCapabilityHarness();
  const queryContext = harness.createContext("query", undefined, 41);
  const mutationContext = harness.createContext("mutation", undefined, 73);

  const queryUrl = queryContext.storage.getUrl("storage-query-url");
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGetUrl",
    storageId: "storage-query-url",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.shift(),
    '{"kind":"storageGetUrl","storageId":"storage-query-url","version":4}'
  );
  harness.settle(
    harness.lastStartedOperationHandle(),
    0,
    harness.allocate("https://storage.example/query")
  );
  assert.equal(await queryUrl, "https://storage.example/query");

  const queryMetadata = queryContext.storage.getMetadata("storage-query-metadata");
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGetMetadata",
    storageId: "storage-query-metadata",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  const metadata = {
    contentType: "application/octet-stream",
    sha256: "digest",
    size: 17,
    storageId: "storage-query-metadata",
  };
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(metadata));
  assert.deepEqual(JSON.parse(JSON.stringify(await queryMetadata)), metadata);

  const mutationUrl = mutationContext.storage.getUrl("storage-mutation-url");
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGetUrl",
    storageId: "storage-mutation-url",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(null));
  assert.equal(await mutationUrl, null);

  const mutationMetadata = mutationContext.storage.getMetadata("storage-mutation-metadata");
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGetMetadata",
    storageId: "storage-mutation-metadata",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(null));
  assert.equal(await mutationMetadata, null);

  const uploadUrl = mutationContext.storage.generateUploadUrl();
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGenerateUploadUrl",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(harness.requestPayloads.at(-1), '{"kind":"storageGenerateUploadUrl","version":4}');
  harness.settle(
    harness.lastStartedOperationHandle(),
    0,
    harness.allocate("https://storage.example/upload")
  );
  assert.equal(await uploadUrl, "https://storage.example/upload");

  const deletion = mutationContext.storage.delete("storage-delete");
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageDelete",
    storageId: "storage-delete",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.at(-1),
    '{"kind":"storageDelete","storageId":"storage-delete","version":4}'
  );
  harness.settle(harness.lastStartedOperationHandle(), 0, 0);
  assert.equal(await deletion, undefined);

  assert.deepEqual(harness.requestCapabilityIdentities, [41, 41, 73, 73, 73, 73]);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
});

test("canonical SDK facade runs installed function-handle creation over ABI v4", async () => {
  const { createFunctionHandle } = await import(
    new URL("../../node_modules/convex/dist/esm/server/components/index.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("query");
    const queryCases = [
      {
        expectedAddress: { name: "tasks:read" },
        functionReference: "tasks:read",
      },
      {
        expectedAddress: { reference: "_reference/function/tasks:read" },
        functionReference: {
          [Symbol.for("toReferencePath")]: "_reference/function/tasks:read",
        },
      },
    ];
    for (let index = 0; index < queryCases.length; index += 1) {
      const { expectedAddress, functionReference } = queryCases[index];
      const created = createFunctionHandle(functionReference);
      const expectedRequest = {
        functionAddress: expectedAddress,
        kind: "functionHandleCreate",
        version: convexWasmCapabilityRequestAbiVersion,
      };
      assert.deepEqual(harness.requests.shift(), expectedRequest);
      assert.equal(harness.requestPayloads.shift(), JSON.stringify(expectedRequest));
      const functionHandle = `function://created-query-${String(index + 1)}`;
      harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(functionHandle));
      assert.equal(await created, functionHandle);
    }
    assert.equal(harness.cleanup(), 0);

    harness.activateSdk("mutation");
    const created = createFunctionHandle("function://existing-handle");
    const expectedRequest = {
      functionAddress: { functionHandle: "function://existing-handle" },
      kind: "functionHandleCreate",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(harness.requests.shift(), expectedRequest);
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(expectedRequest));
    harness.settle(
      harness.lastStartedOperationHandle(),
      0,
      harness.allocate("function://created-mutation")
    );
    assert.equal(await created, "function://created-mutation");

    assert.deepEqual(harness.requestCapabilityIdentities, [1, 1, 1]);
    assert.equal(harness.requests.length, 0);
    assert.equal(harness.requestPayloads.length, 0);
    assert.equal(harness.outstandingHandles(), 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade runs installed generic query and mutation nesting over ABI v4", async () => {
  const { mutationGeneric, queryGeneric } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/registration_impl.js", import.meta.url)
  );
  const previousConvex = globalThis.Convex;
  try {
    const queryHarness = nativeCapabilityHarness();
    globalThis.Convex = queryHarness.sdkFacade;
    queryHarness.activateSdk("query");
    const queryArgs = {
      bytes: Uint8Array.from([1, 2, 3]).buffer,
      count: -7n,
    };
    const queryWrapper = queryGeneric((ctx) =>
      ctx.runQuery("tasks:read", queryArgs, {
        transactionLimits: { bytesRead: 1024, documentsRead: 2 },
      })
    );
    const queryInvocation = queryWrapper.invokeQuery("[]");
    const expectedQueryRequest = {
      args: convexToJson(queryArgs),
      functionAddress: { name: "tasks:read" },
      kind: "runUdf",
      transactionLimits: { bytesRead: 1024, documentsRead: 2 },
      udfType: "query",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(queryHarness.requests.shift(), expectedQueryRequest);
    assert.equal(queryHarness.requestPayloads.shift(), JSON.stringify(expectedQueryRequest));
    const queryResult = { bytes: Uint8Array.from([4, 5]).buffer, count: 9n };
    queryHarness.settle(
      queryHarness.lastStartedOperationHandle(),
      0,
      queryHarness.allocate(queryResult)
    );
    assert.deepEqual(jsonToConvex(JSON.parse(await queryInvocation)), queryResult);
    assert.deepEqual(queryHarness.requestCapabilityIdentities, [1]);
    assert.equal(queryHarness.cleanup(), 0);

    const mutationHarness = nativeCapabilityHarness();
    globalThis.Convex = mutationHarness.sdkFacade;
    mutationHarness.activateSdk("mutation");
    const nestedMutationReference = {
      [Symbol.for("toReferencePath")]: "_reference/function/tasks:write",
    };
    const mutationWrapper = mutationGeneric(
      async (ctx) =>
        await Promise.all([
          ctx.runQuery("tasks:read", { mode: "current" }),
          ctx.runMutation(
            nestedMutationReference,
            { count: 11n },
            { transactionLimits: { documentsWritten: 1 } }
          ),
          ctx.runQuery(
            "function://stale-query",
            { bytes: Uint8Array.from([6, 7]).buffer },
            {
              transactionLimits: { databaseQueries: 1 },
              useStaleSnapshot: true,
            }
          ),
        ])
    );
    const mutationInvocation = mutationWrapper.invokeMutation("[]");
    const expectedMutationRequests = [
      {
        args: { mode: "current" },
        functionAddress: { name: "tasks:read" },
        kind: "runUdf",
        transactionLimits: null,
        udfType: "query",
        version: convexWasmCapabilityRequestAbiVersion,
      },
      {
        args: convexToJson({ count: 11n }),
        functionAddress: { reference: "_reference/function/tasks:write" },
        kind: "runUdf",
        transactionLimits: { documentsWritten: 1 },
        udfType: "mutation",
        version: convexWasmCapabilityRequestAbiVersion,
      },
      {
        args: convexToJson({ bytes: Uint8Array.from([6, 7]).buffer }),
        functionAddress: { functionHandle: "function://stale-query" },
        kind: "runUdf",
        transactionLimits: { databaseQueries: 1 },
        udfType: "snapshotQuery",
        version: convexWasmCapabilityRequestAbiVersion,
      },
    ];
    for (const expectedRequest of expectedMutationRequests) {
      assert.deepEqual(mutationHarness.requests.shift(), expectedRequest);
      assert.equal(mutationHarness.requestPayloads.shift(), JSON.stringify(expectedRequest));
    }
    const nestedResults = [{ count: 13n }, Uint8Array.from([8, 9]).buffer, { source: "snapshot" }];
    for (let index = 0; index < nestedResults.length; index += 1) {
      mutationHarness.settle(index + 1, 0, mutationHarness.allocate(nestedResults[index]));
    }
    assert.deepEqual(jsonToConvex(JSON.parse(await mutationInvocation)), nestedResults);
    assert.deepEqual(mutationHarness.requestCapabilityIdentities, [1, 1, 1]);
    assert.equal(mutationHarness.requests.length, 0);
    assert.equal(mutationHarness.requestPayloads.length, 0);
    assert.equal(mutationHarness.outstandingHandles(), 0);
    assert.equal(mutationHarness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("component and nested-function facade calls fail closed and clean invocation ownership", async () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.sdkFacade;
  const validCreateArguments = {
    name: "tasks:read",
    version: convexSdkVersion,
  };
  const validRunArguments = {
    args: {},
    name: "tasks:read",
    udfType: "query",
  };

  for (const [operation, args] of [
    ["1.0/createFunctionHandle", validCreateArguments],
    ["1.0/runUdf", validRunArguments],
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /SDK facade is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.activateSdk("query");
  const rejectedCalls = [
    [
      "create extra field",
      "1.0/createFunctionHandle",
      { ...validCreateArguments, extra: true },
      /invalid fields/u,
    ],
    [
      "create multiple addresses",
      "1.0/createFunctionHandle",
      { ...validCreateArguments, reference: "_reference/function/tasks:read" },
      /invalid fields/u,
    ],
    [
      "create missing address",
      "1.0/createFunctionHandle",
      { version: convexSdkVersion },
      /invalid fields/u,
    ],
    [
      "create non-string address",
      "1.0/createFunctionHandle",
      { ...validCreateArguments, name: 7 },
      /Function address must be a string/u,
    ],
    [
      "create wrong version",
      "1.0/createFunctionHandle",
      { ...validCreateArguments, version: "forged" },
      /version is invalid/u,
    ],
    ["run extra field", "1.0/runUdf", { ...validRunArguments, extra: true }, /invalid fields/u],
    [
      "run multiple addresses",
      "1.0/runUdf",
      { ...validRunArguments, reference: "_reference/function/tasks:read" },
      /invalid fields/u,
    ],
    ["run missing address", "1.0/runUdf", { args: {}, udfType: "query" }, /invalid fields/u],
    [
      "run unsupported UDF type",
      "1.0/runUdf",
      { ...validRunArguments, udfType: "action" },
      /UDF type is unsupported/u,
    ],
    [
      "run non-object arguments",
      "1.0/runUdf",
      { ...validRunArguments, args: [] },
      /function arguments must be a plain object/u,
    ],
    [
      "run invalid transaction limits",
      "1.0/runUdf",
      { ...validRunArguments, transactionLimits: { unknown: 1 } },
      /Transaction limit field is unsupported/u,
    ],
    [
      "query runs mutation",
      "1.0/runUdf",
      { ...validRunArguments, udfType: "mutation" },
      /unavailable in queries/u,
    ],
    [
      "query runs snapshot query",
      "1.0/runUdf",
      { ...validRunArguments, udfType: "snapshotQuery" },
      /unavailable in queries/u,
    ],
  ];
  for (const [name, operation, args, message] of rejectedCalls) {
    assert.throws(() => facade.asyncSyscall(operation, JSON.stringify(args)), message, name);
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);

  harness.activateSdk("mutation");
  harness.setCapabilityIdentity(0);
  for (const [operation, args] of [
    ["1.0/createFunctionHandle", validCreateArguments],
    ["1.0/runUdf", { ...validRunArguments, udfType: "mutation" }],
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /capability is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);

  harness.setCapabilityIdentity(53);
  harness.activateSdk("query");
  void facade.asyncSyscall("1.0/createFunctionHandle", JSON.stringify(validCreateArguments));
  void facade.asyncSyscall("1.0/runUdf", JSON.stringify(validRunArguments));
  assert.deepEqual(
    harness.requests.splice(0).map(({ kind }) => kind),
    ["functionHandleCreate", "runUdf"]
  );
  harness.requestPayloads.splice(0);
  assert.equal(harness.cleanup(), 2);
  assert.equal(harness.outstandingHandles(), 0);
  assert.throws(
    () => facade.asyncSyscall("1.0/runUdf", JSON.stringify(validRunArguments)),
    /SDK facade is unavailable/u
  );

  harness.restartOperationHandles();
  harness.setCapabilityIdentity(61);
  harness.activateSdk("mutation");
  const reused = facade.asyncSyscall(
    "1.0/runUdf",
    JSON.stringify({ ...validRunArguments, udfType: "mutation" })
  );
  assert.deepEqual(harness.requests.shift(), {
    args: {},
    functionAddress: { name: "tasks:read" },
    kind: "runUdf",
    transactionLimits: null,
    udfType: "mutation",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.requestPayloads.shift();
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate({ count: 17n }));
  assert.deepEqual(jsonToConvex(JSON.parse(await reused)), { count: 17n });
  assert.deepEqual(harness.requestCapabilityIdentities, [53, 53, 61]);
  assert.equal(harness.cleanup(), 0);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
});

test("canonical SDK facade maps the closed storage read and rejects authority before effects", async () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.rawSdkFacade;
  assert.equal(Object.isFrozen(facade), true);
  for (const method of ["asyncSyscall", "jsSyscall", "syscall"]) {
    assert.equal(Object.isFrozen(facade[method]), true);
    const descriptor = Object.getOwnPropertyDescriptor(facade, method);
    assert.equal(descriptor.configurable, false);
    assert.equal(descriptor.writable, false);
  }

  assert.throws(
    () =>
      facade.asyncSyscall(
        "1.0/storageGetUrl",
        JSON.stringify({ requestId: "", storageId: "storage-id", version: convexSdkVersion })
      ),
    /SDK facade is unavailable/u
  );
  assert.throws(() => harness.activateSdk("action"), /UDF kind is invalid/u);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.activateSdk("query");
  assert.throws(
    () => facade.asyncSyscall("1.0/actions/vectorSearch", "{}"),
    /async syscall operation is unsupported/u
  );
  assert.throws(
    () => facade.jsSyscall("storage/getBlob", {}),
    /JS syscall operation is unsupported/u
  );
  assert.throws(
    () =>
      facade.asyncSyscall(
        "1.0/storageGetUrl",
        JSON.stringify({
          extra: true,
          requestId: "",
          storageId: "storage-id",
          version: convexSdkVersion,
        })
      ),
    /invalid fields/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  const result = facade.asyncSyscall(
    "1.0/storageGetUrl",
    JSON.stringify({ requestId: "", storageId: "storage-id", version: convexSdkVersion })
  );
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGetUrl",
    storageId: "storage-id",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(
    harness.lastStartedOperationHandle(),
    0,
    harness.allocate("https://storage.example/object")
  );
  assert.equal(await result, '"https://storage.example/object"');
  assert.equal(harness.cleanup(), 0);
  assert.throws(() => facade.asyncSyscall("1.0/storageGetUrl", "{}"), /SDK facade is unavailable/u);
  assert.equal(harness.outstandingHandles(), 0);
});

test("canonical SDK facade runs the installed storage family over ABI v4", async () => {
  const { setupStorageReader, setupStorageWriter } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/storage_impl.js", import.meta.url)
  );
  const previousConvex = globalThis.Convex;
  try {
    const queryHarness = nativeCapabilityHarness();
    globalThis.Convex = queryHarness.sdkFacade;
    queryHarness.activateSdk("query");
    const reader = setupStorageReader("");

    const metadataPromise = reader.getMetadata("storage-metadata");
    const expectedMetadataRequest = {
      kind: "storageGetMetadata",
      storageId: "storage-metadata",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(queryHarness.requests.shift(), expectedMetadataRequest);
    assert.equal(queryHarness.requestPayloads.shift(), JSON.stringify(expectedMetadataRequest));
    const metadata = {
      contentType: "application/octet-stream",
      sha256: "storage-digest",
      size: 17,
      storageId: "storage-metadata",
    };
    queryHarness.settle(
      queryHarness.lastStartedOperationHandle(),
      0,
      queryHarness.allocate(metadata)
    );
    assert.deepEqual(await metadataPromise, metadata);

    const missingMetadataPromise = reader.getMetadata("storage-missing");
    const expectedMissingMetadataRequest = {
      kind: "storageGetMetadata",
      storageId: "storage-missing",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(queryHarness.requests.shift(), expectedMissingMetadataRequest);
    assert.equal(
      queryHarness.requestPayloads.shift(),
      JSON.stringify(expectedMissingMetadataRequest)
    );
    queryHarness.settle(queryHarness.lastStartedOperationHandle(), 0, queryHarness.allocate(null));
    assert.equal(await missingMetadataPromise, null);
    assert.deepEqual(queryHarness.requestCapabilityIdentities, [1, 1]);
    assert.equal(queryHarness.requests.length, 0);
    assert.equal(queryHarness.requestPayloads.length, 0);
    assert.equal(queryHarness.outstandingHandles(), 0);
    assert.equal(queryHarness.cleanup(), 0);

    const mutationHarness = nativeCapabilityHarness();
    globalThis.Convex = mutationHarness.sdkFacade;
    mutationHarness.activateSdk("mutation");
    const writer = setupStorageWriter("");

    const uploadUrlPromise = writer.generateUploadUrl();
    const expectedUploadRequest = {
      kind: "storageGenerateUploadUrl",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(mutationHarness.requests.shift(), expectedUploadRequest);
    assert.equal(mutationHarness.requestPayloads.shift(), JSON.stringify(expectedUploadRequest));
    mutationHarness.settle(
      mutationHarness.lastStartedOperationHandle(),
      0,
      mutationHarness.allocate("https://storage.example/upload")
    );
    assert.equal(await uploadUrlPromise, "https://storage.example/upload");

    const deletePromise = writer.delete("storage-delete");
    const expectedDeleteRequest = {
      kind: "storageDelete",
      storageId: "storage-delete",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(mutationHarness.requests.shift(), expectedDeleteRequest);
    assert.equal(mutationHarness.requestPayloads.shift(), JSON.stringify(expectedDeleteRequest));
    mutationHarness.settle(mutationHarness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await deletePromise, undefined);

    assert.deepEqual(mutationHarness.requestCapabilityIdentities, [1, 1]);
    assert.equal(mutationHarness.requests.length, 0);
    assert.equal(mutationHarness.requestPayloads.length, 0);
    assert.equal(mutationHarness.outstandingHandles(), 0);
    assert.equal(mutationHarness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade rejects malformed, wrong-kind, and unleased storage calls", () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.sdkFacade;
  const storageCalls = [
    [
      "1.0/storageDelete",
      { requestId: "", storageId: "storage-delete", version: convexSdkVersion },
    ],
    ["1.0/storageGenerateUploadUrl", { requestId: "", version: convexSdkVersion }],
    [
      "1.0/storageGetMetadata",
      { requestId: "", storageId: "storage-metadata", version: convexSdkVersion },
    ],
  ];

  for (const [operation, args] of storageCalls) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /SDK facade is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.activateSdk("query");
  for (const operation of ["1.0/storageDelete", "1.0/storageGenerateUploadUrl"]) {
    assert.throws(
      () => facade.asyncSyscall(operation, "not JSON"),
      /unavailable in queries/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.cleanup(), 0);

  harness.activateSdk("mutation");
  for (const [operation, args] of storageCalls) {
    const missingVersion = { ...args };
    delete missingVersion.version;
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(missingVersion)),
      /invalid fields/u,
      `${operation} missing field`
    );
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify({ ...args, extra: true })),
      /invalid fields/u,
      `${operation} extra field`
    );
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify({ ...args, requestId: "forged" })),
      /arguments are invalid/u,
      `${operation} request ID`
    );
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify({ ...args, version: "forged" })),
      /version is invalid/u,
      `${operation} SDK version`
    );
  }
  for (const operation of ["1.0/storageDelete", "1.0/storageGetMetadata"]) {
    assert.throws(
      () =>
        facade.asyncSyscall(
          operation,
          JSON.stringify({ requestId: "", storageId: 7, version: convexSdkVersion })
        ),
      /arguments are invalid/u,
      `${operation} storage ID`
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);

  harness.setCapabilityIdentity(0);
  for (const [operation, args] of storageCalls) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /capability is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
});

test("SDK value responses keep host tagged JSON until the official SDK consumes it", async () => {
  const harness = nativeCapabilityHarness();
  harness.activateSdk("query");
  assert.equal(harness.sdkFacade.queryCollect, true);
  const collected = harness.sdkFacade.asyncSyscall(
    "1.0/queryCollect",
    JSON.stringify({
      query: { operators: [], source: { order: null, tableName: "documents", type: "FullTableScan" } },
      version: convexSdkVersion,
    })
  );
  assert.equal(harness.requests.shift().terminal, "collect");
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([{ _id: "document-id" }]));
  assert.equal(await collected, '[{"_id":"document-id"}]');
  assert.deepEqual(harness.taggedTransfers, ['[{"_id":"document-id"}]']);

  const response = harness.sdkFacade.asyncSyscall(
    "1.0/get",
    JSON.stringify({ id: "document-id", isSystem: false, table: "documents", version: convexSdkVersion })
  );
  assert.equal(harness.requests.shift().kind, "dbGet");

  const document = {
    _id: "document-id",
    bytes: new Uint8Array([1, 2, 3]).buffer,
    count: -7n,
  };
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(document));
  const tagged = JSON.stringify(convexToJson(document));
  assert.equal(await response, tagged);
  assert.deepEqual(harness.taggedTransfers, ['[{"_id":"document-id"}]', tagged]);
  assert.equal(harness.restoredTransfers.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
});

test("SDK object arguments omit outer optional fields and retain the legacy string boundary", async () => {
  const harness = nativeCapabilityHarness();
  harness.activateSdk("mutation");
  const ordinary = harness.guestValue('({ table: "documents", value: { nested: { enabled: true } } })');
  const direct = harness.rawSdkFacade.asyncSyscallObjectArgs("1.0/insert", ordinary);
  assert.deepEqual(harness.requests.shift().value, { nested: { enabled: true } });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate("inserted-id"));
  assert.equal(await direct, '{"_id":"inserted-id"}');

  const tableless = harness.guestValue(
    '({ id: "document-id", isSystem: false, table: undefined, version })',
    { version: convexSdkVersion }
  );
  const get = harness.rawSdkFacade.asyncSyscallObjectArgs("1.0/get", tableless);
  assert.deepEqual(harness.requests.shift(), {
    version: convexWasmCapabilityRequestAbiVersion,
    kind: "dbGet",
    id: "document-id",
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(null));
  assert.equal(await get, "null");

  let brandReads = 0;
  const invalidStringArguments = {
    get brand() {
      brandReads += 1;
      throw new Error("brand getter ran");
    },
  };
  assert.throws(
    () => harness.rawSdkFacade.asyncSyscall("1.0/insert", invalidStringArguments),
    /arguments must be a JSON string/u
  );
  assert.equal(brandReads, 0);
  assert.equal(harness.cleanup(), 0);
});

test("SDK write and nested-call values cross the request envelope without guest re-encoding", async () => {
  const mutation = nativeCapabilityHarness();
  mutation.activateSdk("mutation");
  const insertedValue = convexToJson({
    bytes: new Uint8Array([4, 5]).buffer,
    commitTime: jsonToConvex({ $commitTs: null }),
    count: 9n,
  });
  const insert = mutation.sdkFacade.asyncSyscall(
    "1.0/insert",
    JSON.stringify({ table: "documents", value: insertedValue })
  );
  assert.deepEqual(mutation.requests.shift().value, insertedValue);
  assert.equal(mutation.guestEncodes.length, 0);
  mutation.settle(mutation.lastStartedOperationHandle(), 0, mutation.allocate("inserted-id"));
  assert.equal(await insert, '{"_id":"inserted-id"}');
  assert.equal(mutation.cleanup(), 0);

  const query = nativeCapabilityHarness();
  query.activateSdk("query");
  const nestedArgs = convexToJson({ bytes: new Uint8Array([6]).buffer, count: -3n });
  const nested = query.sdkFacade.asyncSyscall(
    "1.0/runUdf",
    JSON.stringify({ args: nestedArgs, name: "tasks:read", udfType: "query" })
  );
  assert.deepEqual(query.requests.shift().args, nestedArgs);
  assert.equal(query.guestEncodes.length, 0);
  query.settle(query.lastStartedOperationHandle(), 0, query.allocate({ count: -3n }));
  assert.equal(await nested, JSON.stringify(convexToJson({ count: -3n })));
  assert.equal(query.cleanup(), 0);
});

test("canonical SDK facade runs installed authentication and direct database readers over ABI v4", async () => {
  const [{ setupAuth }, { setupReader }] = await Promise.all([
    import(
      new URL(
        "../../node_modules/convex/dist/esm/server/impl/authentication_impl.js",
        import.meta.url
      )
    ),
    import(
      new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
    ),
  ]);
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("query");

    const identityPromise = setupAuth("").getUserIdentity();
    assert.deepEqual(harness.requests.shift(), {
      kind: "authGetUserIdentity",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    const identity = {
      issuer: "https://issuer.invalid",
      subject: "subject-a",
      tokenIdentifier: "https://issuer.invalid|subject-a",
    };
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(identity));
    assert.deepEqual(await identityPromise, identity);

    const reader = setupReader();
    const documentPromise = reader.get("documents", "document-a");
    assert.deepEqual(harness.requests.shift(), {
      id: "document-a",
      kind: "dbGet",
      table: "documents",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    const document = {
      _creationTime: 17,
      _id: "document-a",
      balance: 7n,
    };
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(document));
    assert.deepEqual(await documentPromise, document);

    const systemDocumentPromise = reader.system.get("_storage", "storage-a");
    assert.deepEqual(harness.requests.shift(), {
      id: "storage-a",
      kind: "dbSystemGet",
      table: "_storage",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(null));
    assert.equal(await systemDocumentPromise, null);

    harness.queueSdkSyncResult("document-normalized");
    assert.equal(reader.normalizeId("documents", "legacy-document"), "document-normalized");
    assert.deepEqual(harness.requests.shift(), {
      kind: "dbNormalizeId",
      table: "documents",
      value: "legacy-document",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    harness.queueSdkSyncResult("system-normalized");
    assert.equal(reader.system.normalizeId("_storage", "legacy-storage"), "system-normalized");
    assert.deepEqual(harness.requests.shift(), {
      kind: "dbNormalizeId",
      table: "_storage",
      value: "legacy-storage",
      version: convexWasmCapabilityRequestAbiVersion,
    });

    assert.deepEqual(harness.requestCapabilityIdentities, [1, 1, 1, 1, 1]);
    assert.equal(harness.requests.length, 0);
    assert.equal(harness.outstandingHandles(), 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("SDK mutation read-back retains the pending commit timestamp singleton for a patch", async () => {
  const { setupWriter } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("mutation");
    const writer = setupWriter();
    const read = writer.get("documents", "document-a");
    assert.equal(harness.requests.shift().kind, "dbGet");
    harness.settle(
      harness.lastStartedOperationHandle(),
      0,
      harness.allocate({ _id: "document-a", commitTime: writer.vars.commitTs })
    );
    const document = await read;
    assert.equal(document.commitTime, writer.vars.commitTs);
    assert.equal(harness.restoredTransfers.length, 0);

    const patch = writer.patch("documents", document._id, { commitTime: document.commitTime });
    assert.deepEqual(harness.requests.shift().patch, { commitTime: { $commitTs: null } });
    assert.deepEqual(harness.guestEncodes, ["document-a", "document-a"]);
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    await patch;
    assert.equal(harness.outstandingHandles(), 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade runs installed metadata readers over their closed ABI v4 envelopes", async () => {
  const { setupMutationMeta, setupQueryMeta } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/meta_impl.js", import.meta.url)
  );
  const previousConvex = globalThis.Convex;
  try {
    const queryHarness = nativeCapabilityHarness();
    globalThis.Convex = queryHarness.sdkFacade;
    queryHarness.activateSdk("query");
    const queryMeta = setupQueryMeta("public");

    const functionMetadataPromise = queryMeta.getFunctionMetadata();
    assert.deepEqual(queryHarness.requests.shift(), {
      kind: "getFunctionMetadata",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(
      queryHarness.requestPayloads.shift(),
      '{"kind":"getFunctionMetadata","version":4}'
    );
    queryHarness.settle(
      queryHarness.lastStartedOperationHandle(),
      0,
      queryHarness.allocate({ componentPath: "", name: "documents:list" })
    );
    assert.deepEqual(await functionMetadataPromise, {
      componentPath: "",
      name: "documents:list",
      type: "query",
      visibility: "public",
    });

    const deploymentMetadataPromise = queryMeta.getDeploymentMetadata();
    assert.deepEqual(queryHarness.requests.shift(), {
      kind: "getDeploymentMetadata",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(
      queryHarness.requestPayloads.shift(),
      '{"kind":"getDeploymentMetadata","version":4}'
    );
    queryHarness.settle(
      queryHarness.lastStartedOperationHandle(),
      0,
      queryHarness.allocate({ class: "s16", name: "self-hosted", region: null })
    );
    assert.deepEqual(await deploymentMetadataPromise, {
      class: "s16",
      name: "self-hosted",
      region: null,
    });

    const taggedMetrics = {
      bytesRead: { remaining: 1024, used: 7n },
      bytesWritten: {
        remaining: Uint8Array.from([4, 5, 6]).buffer,
        used: 3,
      },
    };
    const transactionMetricsPromise = queryMeta.getTransactionMetrics();
    assert.deepEqual(queryHarness.requests.shift(), {
      kind: "getTransactionMetrics",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(
      queryHarness.requestPayloads.shift(),
      '{"kind":"getTransactionMetrics","version":4}'
    );
    queryHarness.settle(
      queryHarness.lastStartedOperationHandle(),
      0,
      queryHarness.allocate(taggedMetrics)
    );
    assert.deepEqual(await transactionMetricsPromise, taggedMetrics);
    assert.deepEqual(queryHarness.requestCapabilityIdentities, [1, 1, 1]);
    assert.equal(queryHarness.requests.length, 0);
    assert.equal(queryHarness.outstandingHandles(), 0);
    assert.equal(queryHarness.cleanup(), 0);

    const mutationHarness = nativeCapabilityHarness();
    globalThis.Convex = mutationHarness.sdkFacade;
    mutationHarness.activateSdk("mutation");
    const mutationMeta = setupMutationMeta("internal");

    const mutationFunctionMetadataPromise = mutationMeta.getFunctionMetadata();
    assert.deepEqual(mutationHarness.requests.shift(), {
      kind: "getFunctionMetadata",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    mutationHarness.settle(
      mutationHarness.lastStartedOperationHandle(),
      0,
      mutationHarness.allocate({ componentPath: "component", name: "documents:update" })
    );
    assert.deepEqual(await mutationFunctionMetadataPromise, {
      componentPath: "component",
      name: "documents:update",
      type: "mutation",
      visibility: "internal",
    });

    const requestMetadataPromise = mutationMeta.getRequestMetadata();
    assert.deepEqual(mutationHarness.requests.shift(), {
      kind: "getRequestMetadata",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(
      mutationHarness.requestPayloads.at(-1),
      '{"kind":"getRequestMetadata","version":4}'
    );
    const requestMetadata = {
      authToken: null,
      ip: "203.0.113.10",
      requestId: "request-a",
      scheduledFunctionId: null,
      userAgent: "metadata-test",
    };
    mutationHarness.settle(
      mutationHarness.lastStartedOperationHandle(),
      0,
      mutationHarness.allocate(requestMetadata)
    );
    assert.deepEqual(await requestMetadataPromise, requestMetadata);
    assert.deepEqual(mutationHarness.requestCapabilityIdentities, [1, 1]);
    assert.equal(mutationHarness.requests.length, 0);
    assert.equal(mutationHarness.outstandingHandles(), 0);
    assert.equal(mutationHarness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade preserves installed audit sentinels in canonical ABI v4 JSON", async () => {
  const { log } = await import(
    new URL("../../node_modules/convex/dist/esm/server/log.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("query");
    const body = {
      source: {
        userAgent: log.vars.userAgent,
        requestId: log.vars.requestId,
        ip: log.vars.ip,
      },
      occurredAt: [log.vars.now, { actor: log.vars.convexActor }],
      action: "document.viewed",
    };
    const audited = log.audit(body);
    assert.deepEqual(harness.requests.shift(), {
      body: {
        action: "document.viewed",
        occurredAt: [{ $var: "now" }, { actor: { $var: "convexActor" } }],
        source: {
          ip: { $var: "ip" },
          requestId: { $var: "requestId" },
          userAgent: { $var: "userAgent" },
        },
      },
      kind: "auditLog",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(
      harness.requestPayloads.shift(),
      '{"body":{"action":"document.viewed","occurredAt":[{"$var":"now"},{"actor":{"$var":"convexActor"}}],"source":{"ip":{"$var":"ip"},"requestId":{"$var":"requestId"},"userAgent":{"$var":"userAgent"}}},"kind":"auditLog","version":4}'
    );
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await audited, undefined);
    assert.deepEqual(harness.requestCapabilityIdentities, [1]);
    assert.equal(harness.requests.length, 0);
    assert.equal(harness.outstandingHandles(), 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("metadata and audit facade validation rejects malformed or unauthorized calls before effects", () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.sdkFacade;
  const validAuditArguments = JSON.stringify({
    body: { action: "document.viewed" },
    version: convexSdkVersion,
  });

  assert.throws(
    () => facade.asyncSyscall("1.0/getFunctionMetadata", "{}"),
    /SDK facade is unavailable/u
  );
  assert.throws(
    () => facade.asyncSyscall("1.0/auditLog", validAuditArguments),
    /SDK facade is unavailable/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.activateSdk("query");
  assert.throws(
    () => facade.asyncSyscall("1.0/getRequestMetadata", "{}"),
    /unavailable in queries/u
  );
  for (const operation of [
    "1.0/getDeploymentMetadata",
    "1.0/getFunctionMetadata",
    "1.0/getTransactionMetrics",
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, '{"extra":true}'),
      /invalid fields/u,
      operation
    );
  }
  for (const [name, argumentsJson, message] of [
    [
      "extra argument",
      `{"body":{},"extra":true,"version":${JSON.stringify(convexSdkVersion)}}`,
      /invalid fields/u,
    ],
    ["wrong version", '{"body":{},"version":"forged"}', /version is invalid/u],
    [
      "non-object body",
      `{"body":null,"version":${JSON.stringify(convexSdkVersion)}}`,
      /must be a plain object/u,
    ],
    [
      "reserved body key",
      `{"body":{"$forged":true},"version":${JSON.stringify(convexSdkVersion)}}`,
      /must not start with \$/u,
    ],
    [
      "unknown sentinel",
      `{"body":{"source":{"$var":"forged"}},"version":${JSON.stringify(convexSdkVersion)}}`,
      /sentinel is invalid/u,
    ],
    [
      "sentinel fields",
      `{"body":{"source":{"$var":"ip","extra":true}},"version":${JSON.stringify(convexSdkVersion)}}`,
      /must not start with \$/u,
    ],
  ]) {
    assert.throws(() => facade.asyncSyscall("1.0/auditLog", argumentsJson), message, name);
  }
  for (const [name, source, message] of [
    [
      "sparse array",
      '__convexCapabilityRequestToHost({body: {values: Array(1)}, kind: "auditLog", version: 4})',
      /must not be sparse/u,
    ],
    [
      "accessor",
      '(() => { const nested = {}; Object.defineProperty(nested, "value", {enumerable: true, get() { return 1; }}); return __convexCapabilityRequestToHost({body: {nested}, kind: "auditLog", version: 4}); })()',
      /accessor properties/u,
    ],
    [
      "symbol property",
      '(() => { const nested = {}; nested[Symbol("audit")] = true; return __convexCapabilityRequestToHost({body: {nested}, kind: "auditLog", version: 4}); })()',
      /symbol properties/u,
    ],
    [
      "undefined value",
      '__convexCapabilityRequestToHost({body: {value: undefined}, kind: "auditLog", version: 4})',
      /must be JSON values/u,
    ],
  ]) {
    assert.throws(() => harness.guestValue(source), message, name);
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);

  harness.activateSdk("mutation");
  harness.setCapabilityIdentity(0);
  assert.throws(
    () => facade.asyncSyscall("1.0/getRequestMetadata", "{}"),
    /capability is unavailable/u
  );
  assert.throws(
    () => facade.asyncSyscall("1.0/auditLog", validAuditArguments),
    /capability is unavailable/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
});

test("canonical SDK facade runs installed direct database writers over ABI v4", async () => {
  const { setupWriter } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("mutation");
    const writer = setupWriter();
    const insertedValue = {
      balance: 9n,
      bytes: Uint8Array.from([1, 2, 3]).buffer,
      label: "inserted",
    };
    const inserted = writer.insert("documents", insertedValue);
    assert.deepEqual(harness.requests.shift(), {
      kind: "dbInsert",
      table: "documents",
      value: convexToJson(insertedValue),
      version: convexWasmCapabilityRequestAbiVersion,
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate("document-a"));
    assert.equal(await inserted, "document-a");

    const patched = writer.patch("documents", "document-a", {
      nested: { balance: 10n },
      removed: undefined,
    });
    assert.deepEqual(harness.requests.shift(), {
      id: "document-a",
      kind: "dbPatch",
      patch: {
        nested: convexToJson({ balance: 10n }),
        removed: { $undefined: null },
      },
      table: "documents",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await patched, undefined);

    const replacement = { balance: 11n, label: "replaced" };
    const replaced = writer.replace("documents", "document-a", replacement);
    assert.deepEqual(harness.requests.shift(), {
      id: "document-a",
      kind: "dbReplace",
      table: "documents",
      value: convexToJson(replacement),
      version: convexWasmCapabilityRequestAbiVersion,
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await replaced, undefined);

    const removed = writer.delete("documents", "document-a");
    assert.deepEqual(harness.requests.shift(), {
      id: "document-a",
      kind: "dbDelete",
      table: "documents",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await removed, undefined);

    assert.deepEqual(harness.requestCapabilityIdentities, [1, 1, 1, 1]);
    assert.equal(harness.requests.length, 0);
    assert.equal(harness.outstandingHandles(), 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade runs table-less database reads and keeps table-less writes incomplete", async () => {
  const { setupReader, setupWriter } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
  );
  const previousConvex = globalThis.Convex;
  try {
    const queryHarness = nativeCapabilityHarness();
    globalThis.Convex = queryHarness.sdkFacade;
    queryHarness.activateSdk("query");
    const reader = setupReader();
    const documentPromise = reader.get("document-a");
    assert.deepEqual(queryHarness.requests.shift(), {
      id: "document-a",
      kind: "dbGet",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    queryHarness.settle(
      queryHarness.lastStartedOperationHandle(),
      0,
      queryHarness.allocate({ _id: "document-a", status: "ready" })
    );
    assert.deepEqual(await documentPromise, { _id: "document-a", status: "ready" });

    const systemDocumentPromise = reader.system.get("storage-a");
    assert.deepEqual(queryHarness.requests.shift(), {
      id: "storage-a",
      kind: "dbSystemGet",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    queryHarness.settle(queryHarness.lastStartedOperationHandle(), 0, queryHarness.allocate(null));
    assert.equal(await systemDocumentPromise, null);
    assert.deepEqual(queryHarness.requestCapabilityIdentities, [1, 1]);
    assert.equal(queryHarness.requests.length, 0);
    assert.deepEqual(queryHarness.requestPayloads.splice(0), [
      JSON.stringify({
        id: "document-a",
        kind: "dbGet",
        version: convexWasmCapabilityRequestAbiVersion,
      }),
      JSON.stringify({
        id: "storage-a",
        kind: "dbSystemGet",
        version: convexWasmCapabilityRequestAbiVersion,
      }),
    ]);
    assert.equal(queryHarness.outstandingHandles(), 0);
    assert.equal(queryHarness.cleanup(), 0);

    const mutationHarness = nativeCapabilityHarness();
    globalThis.Convex = mutationHarness.sdkFacade;
    mutationHarness.activateSdk("mutation");
    const writer = setupWriter();
    await assert.rejects(writer.patch("document-a", { enabled: true }), /invalid fields/u);
    await assert.rejects(writer.replace("document-a", { enabled: true }), /invalid fields/u);
    await assert.rejects(writer.delete("document-a"), /invalid fields/u);
    assert.equal(mutationHarness.requests.length, 0);
    assert.equal(mutationHarness.requestPayloads.length, 0);
    assert.equal(mutationHarness.outstandingHandles(), 0);
    assert.equal(mutationHarness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade maps installed query and count envelopes onto generic ABI v4 requests", async () => {
  const { setupReader } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("query");
    const reader = setupReader();

    const countPromise = reader.query("documents").count();
    const countRequest = harness.requests.shift();
    assert.deepEqual(countRequest, {
      kind: "dbQuery",
      operators: [],
      order: null,
      source: { type: "fullTableScan" },
      table: "documents",
      terminal: "stream",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(countRequest));
    let countRead = harness.lastStartedOperationHandle();
    for (const document of [{ _id: "count-a" }, { _id: "count-b" }]) {
      harness.settle(countRead, 0, harness.allocate({ done: false, value: document }));
      for (
        let checkpoint = 0;
        checkpoint < 8 && harness.lastStartedOperationHandle() === countRead;
        checkpoint += 1
      ) {
        await drainCapabilityMicrotasks();
      }
      const nextRead = harness.lastStartedOperationHandle();
      assert.notEqual(nextRead, countRead);
      countRead = nextRead;
    }
    harness.settle(countRead, 0, harness.allocate({ done: true, value: null }));
    assert.equal(await countPromise, 2);

    const pagePromise = reader
      .query("documents")
      .withIndex("by_tenant_optional", (range) =>
        range.eq("tenant", "tenant-a").eq("optional", undefined)
      )
      .order("desc")
      .paginate({
        cursor: null,
        endCursor: "end-cursor",
        maximumRowsRead: 8,
        numItems: 2,
      });
    const pageRequest = harness.requests.shift();
    assert.deepEqual(pageRequest, {
      kind: "dbQuery",
      operators: [],
      order: "desc",
      pagination: {
        cursor: null,
        endCursor: "end-cursor",
        maximumBytesRead: null,
        maximumRowsRead: 8,
        pageSize: 2,
      },
      source: {
        constraints: [
          { field: "tenant", operator: "eq", value: "tenant-a" },
          { field: "optional", operator: "eq", value: { $undefined: null } },
        ],
        index: "by_tenant_optional",
        type: "indexRange",
      },
      table: "documents",
      terminal: "paginate",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(pageRequest));
    const pageResult = {
      continueCursor: "next-cursor",
      isDone: false,
      page: [{ _id: "document-page", sequence: 3n }],
      pageStatus: null,
      splitCursor: null,
    };
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(pageResult));
    assert.deepEqual(await pagePromise, pageResult);

    const collectPromise = reader
      .query("documents")
      .withSearchIndex("by_body", (search) =>
        search.search("body", "needle phrase").eq("optional", undefined)
      )
      .filter((filter) => filter.eq(filter.field("status"), "ready"))
      .collect();
    const collectRequest = harness.requests.shift();
    assert.deepEqual(collectRequest, {
      kind: "dbQuery",
      operators: [
        {
          expression: { $eq: [{ $field: "status" }, { $literal: "ready" }] },
          type: "filter",
        },
      ],
      order: null,
      source: {
        filters: [
          { field: "body", type: "search", value: "needle phrase" },
          { field: "optional", type: "eq", value: { $undefined: null } },
        ],
        index: "by_body",
        type: "search",
      },
      table: "documents",
      terminal: "collect",
      version: convexWasmCapabilityRequestAbiVersion,
    });
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(collectRequest));
    harness.settle(
      harness.lastStartedOperationHandle(),
      0,
      harness.allocate([{ _id: "document-stream", sequence: 4n }])
    );
    assert.deepEqual(await collectPromise, [{ _id: "document-stream", sequence: 4n }]);
    assert.ok(
      harness.taggedTransfers.some(
        (source) => source.includes('"document-stream"') && source.includes('"$integer"')
      )
    );

    assert.equal(harness.requests.length, 0);
    assert.equal(harness.requestPayloads.length, 0);
    assert.equal(harness.openQueryStreams.size, 0);
    assert.equal(harness.outstandingHandles(), 0);

    const returnedIterator = reader.query("documents")[Symbol.asyncIterator]();
    const returnedRequest = harness.requests.shift();
    assert.equal(returnedRequest.terminal, "stream");
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(returnedRequest));
    assert.deepEqual(await returnedIterator.return(), { done: true, value: undefined });
    assert.deepEqual(harness.closedQueryStreams, [2]);

    reader.query("documents")[Symbol.asyncIterator]();
    const abandonedRequest = harness.requests.shift();
    assert.equal(abandonedRequest.terminal, "stream");
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(abandonedRequest));
    assert.equal(harness.openQueryStreams.size, 1);
    assert.equal(harness.cleanup(), 0);
    assert.deepEqual(harness.closedQueryStreams, [2]);
    assert.equal(harness.openQueryStreams.size, 1);
    // The native invocation's following cancel_all owns these host cursors.
    harness.openQueryStreams.clear();

    harness.activateSdk("mutation");
    const mutationCount = setupReader().query("documents").count();
    const mutationCountRequest = harness.requests.shift();
    assert.equal(mutationCountRequest.terminal, "stream");
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(mutationCountRequest));
    harness.settle(
      harness.lastStartedOperationHandle(),
      0,
      harness.allocate({ done: true, value: null })
    );
    assert.equal(await mutationCount, 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("SDK invocation teardown does not synthesize an application iterator close", async () => {
  const { setupReader } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/database_impl.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  globalThis.Convex = harness.sdkFacade;
  try {
    harness.activateSdk("query");
    // A caller may read one head from several streams and return without
    // explicitly closing the remaining cursors. Host cancellation owns those
    // cursors after invocation; the SDK did not issue queryCleanup for them.
    const iterator = setupReader().query("documents")[Symbol.asyncIterator]();
    const first = iterator.next();
    harness.settle(
      harness.lastStartedOperationHandle(),
      0,
      harness.allocate({ done: false, value: { _id: "first" } })
    );
    assert.deepEqual(await first, { done: false, value: { _id: "first" } });
    assert.equal(harness.cleanup(), 0);
    assert.deepEqual(harness.closedQueryStreams, []);
    assert.equal(harness.openQueryStreams.size, 1);
    assert.equal(harness.outstandingHandles(), 0);
  } finally {
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK query facade rejects open-field and lifecycle violations before effects", () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.sdkFacade;
  const fullTableQuery = {
    operators: [],
    source: { order: null, tableName: "documents", type: "FullTableScan" },
  };
  const queryStreamArguments = {
    query: fullTableQuery,
    version: convexSdkVersion,
  };

  assert.throws(
    () => facade.syscall("1.0/queryStream", JSON.stringify(queryStreamArguments)),
    /SDK facade is unavailable/u
  );
  harness.activateSdk("query");
  for (const [operation, args] of [
    ["1.0/count", { extra: true, table: "documents" }],
    [
      "1.0/queryPage",
      {
        cursor: null,
        endCursor: null,
        extra: true,
        maximumRowsRead: null,
        pageSize: 2,
        query: fullTableQuery,
        version: convexSdkVersion,
      },
    ],
    ["1.0/queryStreamNext", { extra: true, queryId: 1 }],
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /invalid fields/u,
      operation
    );
  }
  assert.throws(
    () =>
      facade.syscall(
        "1.0/queryStream",
        JSON.stringify({
          ...queryStreamArguments,
          query: {
            ...fullTableQuery,
            source: { ...fullTableQuery.source, extra: true },
          },
        })
      ),
    /invalid fields/u
  );
  assert.throws(
    () => facade.asyncSyscall("1.0/queryStreamNext", '{"queryId":1}'),
    /stream is unavailable/u
  );
  assert.throws(
    () => facade.syscall("1.0/queryCleanup", '{"extra":true,"queryId":1}'),
    /invalid fields/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.setCapabilityIdentity(0);
  assert.throws(
    () => facade.syscall("1.0/queryStream", JSON.stringify(queryStreamArguments)),
    /capability is unavailable/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.cleanup(), 0);
});

test("canonical SDK facade rejects malformed, wrong-kind, and unleased database calls before effects", () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.sdkFacade;
  const writeCalls = [
    ["1.0/remove", { id: "document-a", table: "documents" }],
    ["1.0/replace", { id: "document-a", table: "documents", value: { status: "replaced" } }],
    ["1.0/shallowMerge", { id: "document-a", table: "documents", value: { status: "patched" } }],
  ];
  const getArguments = JSON.stringify({
    id: "document-a",
    isSystem: false,
    table: "documents",
    version: convexSdkVersion,
  });
  const normalizeArguments = JSON.stringify({ idString: "document-a", table: "documents" });

  assert.throws(() => facade.asyncSyscall("1.0/get", getArguments), /SDK facade is unavailable/u);
  assert.throws(
    () => facade.syscall("1.0/db/normalizeId", normalizeArguments),
    /SDK facade is unavailable/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.activateSdk("query");
  for (const [operation, args] of writeCalls) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /unavailable in queries/u,
      operation
    );
  }
  assert.throws(
    () => facade.asyncSyscall("1.0/getUserIdentity", '{"extra":true,"requestId":""}'),
    /invalid fields/u
  );
  assert.throws(
    () =>
      facade.asyncSyscall(
        "1.0/get",
        JSON.stringify({
          id: "storage-a",
          isSystem: false,
          table: "_storage",
          version: convexSdkVersion,
        })
      ),
    /System tables can only be accessed/u
  );
  assert.throws(
    () =>
      facade.asyncSyscall(
        "1.0/get",
        JSON.stringify({
          id: "document-a",
          isSystem: false,
          table: "documents",
          version: `${convexSdkVersion}-forged`,
        })
      ),
    /version is invalid/u
  );
  assert.throws(
    () => facade.syscall("1.0/db/normalizeId", '{"idString":"document-a"}'),
    /invalid fields/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.cleanup(), 0);

  harness.activateSdk("mutation");
  for (const [operation, args] of writeCalls) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify({ ...args, extra: true })),
      /invalid fields/u,
      operation
    );
  }
  assert.throws(
    () =>
      facade.asyncSyscall(
        "1.0/shallowMerge",
        JSON.stringify({
          id: "document-a",
          table: "documents",
          value: { removed: { $undefined: "forged" } },
        })
      ),
    /deletion marker is invalid/u
  );
  assert.throws(
    () =>
      facade.asyncSyscall(
        "1.0/insert",
        JSON.stringify({ extra: true, table: "documents", value: {} })
      ),
    /invalid fields/u
  );
  harness.setCapabilityIdentity(0);
  assert.throws(
    () => facade.asyncSyscall("1.0/getUserIdentity", '{"requestId":""}'),
    /capability is unavailable/u
  );
  assert.throws(
    () => facade.syscall("1.0/db/normalizeId", normalizeArguments),
    /capability is unavailable/u
  );
  for (const [operation, args] of writeCalls) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /capability is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
  assert.throws(() => facade.asyncSyscall("1.0/get", getArguments), /SDK facade is unavailable/u);
});

test("canonical SDK facade runs the installed mutation scheduler over ABI v4", async () => {
  const { setupMutationScheduler } = await import(
    new URL("../../node_modules/convex/dist/esm/server/impl/scheduler_impl.js", import.meta.url)
  );
  const harness = nativeCapabilityHarness();
  const previousConvex = globalThis.Convex;
  const previousDateNow = Date.now;
  globalThis.Convex = harness.sdkFacade;
  Date.now = () => 1_700_000_000_250;
  try {
    harness.activateSdk("mutation");
    const scheduler = setupMutationScheduler();
    const scheduleCases = [
      {
        expectedAddress: { name: "tasks:run" },
        functionReference: "tasks:run",
      },
      {
        expectedAddress: { reference: "_reference/function/tasks:run" },
        functionReference: {
          [Symbol.for("toReferencePath")]: "_reference/function/tasks:run",
        },
      },
      {
        expectedAddress: { functionHandle: "function://scheduled-task" },
        functionReference: "function://scheduled-task",
      },
    ];
    for (let index = 0; index < scheduleCases.length; index += 1) {
      const { expectedAddress, functionReference } = scheduleCases[index];
      const timestampMilliseconds = 1_710_000_000_125 + index;
      const functionArgs = { sequence: BigInt(index + 1) };
      const scheduled = scheduler.runAt(timestampMilliseconds, functionReference, functionArgs);
      const expectedRequest = {
        args: convexToJson(functionArgs),
        functionAddress: expectedAddress,
        kind: "schedulerRunAt",
        timestampMilliseconds,
        version: convexWasmCapabilityRequestAbiVersion,
      };
      assert.deepEqual(harness.requests.shift(), expectedRequest);
      assert.equal(harness.requestPayloads.shift(), JSON.stringify(expectedRequest));
      const scheduledId = `scheduled-${String(index + 1)}`;
      harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(scheduledId));
      assert.equal(await scheduled, scheduledId);
    }

    const delayed = scheduler.runAfter(375, "tasks:later");
    const expectedDelayedRequest = {
      args: {},
      functionAddress: { name: "tasks:later" },
      kind: "schedulerRunAt",
      timestampMilliseconds: 1_700_000_000_625,
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(harness.requests.shift(), expectedDelayedRequest);
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(expectedDelayedRequest));
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate("scheduled-after"));
    assert.equal(await delayed, "scheduled-after");

    const cancelled = scheduler.cancel("scheduled-after");
    const expectedCancelRequest = {
      id: "scheduled-after",
      kind: "schedulerCancel",
      version: convexWasmCapabilityRequestAbiVersion,
    };
    assert.deepEqual(harness.requests.shift(), expectedCancelRequest);
    assert.equal(harness.requestPayloads.shift(), JSON.stringify(expectedCancelRequest));
    harness.settle(harness.lastStartedOperationHandle(), 0, 0);
    assert.equal(await cancelled, undefined);

    assert.deepEqual(harness.requestCapabilityIdentities, [1, 1, 1, 1, 1]);
    assert.equal(harness.requests.length, 0);
    assert.equal(harness.requestPayloads.length, 0);
    assert.equal(harness.outstandingHandles(), 0);
    assert.equal(harness.cleanup(), 0);
  } finally {
    Date.now = previousDateNow;
    if (previousConvex === undefined) delete globalThis.Convex;
    else globalThis.Convex = previousConvex;
  }
});

test("canonical SDK facade rejects malformed, wrong-kind, and unleased scheduler calls before effects", () => {
  const harness = nativeCapabilityHarness();
  const facade = harness.sdkFacade;
  const validSchedule = {
    args: { sequence: 1 },
    name: "tasks:run",
    ts: 1_710_000_000.125,
    version: convexSdkVersion,
  };
  const validCancel = { id: "scheduled-1" };

  for (const [operation, args] of [
    ["1.0/schedule", validSchedule],
    ["1.0/cancel_job", validCancel],
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /SDK facade is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.activateSdk("query");
  for (const [operation, args] of [
    ["1.0/schedule", validSchedule],
    ["1.0/cancel_job", validCancel],
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /unavailable in queries/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.cleanup(), 0);

  harness.activateSdk("mutation");
  for (const [name, operation, args, message] of [
    ["schedule extra field", "1.0/schedule", { ...validSchedule, extra: true }, /invalid fields/u],
    [
      "schedule multiple addresses",
      "1.0/schedule",
      { ...validSchedule, reference: "_reference/function/tasks:run" },
      /invalid fields/u,
    ],
    [
      "schedule missing address",
      "1.0/schedule",
      { args: {}, ts: validSchedule.ts, version: convexSdkVersion },
      /invalid fields/u,
    ],
    [
      "schedule non-string address",
      "1.0/schedule",
      { ...validSchedule, name: 7 },
      /Function address must be a string/u,
    ],
    [
      "schedule non-finite timestamp",
      "1.0/schedule",
      { ...validSchedule, ts: "soon" },
      /finite number/u,
    ],
    [
      "schedule wrong version",
      "1.0/schedule",
      { ...validSchedule, version: `${convexSdkVersion}-forged` },
      /version is invalid/u,
    ],
    ["cancel extra field", "1.0/cancel_job", { ...validCancel, extra: true }, /invalid fields/u],
    ["cancel non-string ID", "1.0/cancel_job", { id: 7 }, /ID is invalid/u],
  ]) {
    assert.throws(() => facade.asyncSyscall(operation, JSON.stringify(args)), message, name);
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);

  harness.setCapabilityIdentity(0);
  for (const [operation, args] of [
    ["1.0/schedule", validSchedule],
    ["1.0/cancel_job", validCancel],
  ]) {
    assert.throws(
      () => facade.asyncSyscall(operation, JSON.stringify(args)),
      /capability is unavailable/u,
      operation
    );
  }
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
});

test("query storage rejects mutation authority before creating host requests", () => {
  const harness = nativeCapabilityHarness();
  const context = harness.createContext("query", undefined, 83);

  assert.equal(context.storage.generateUploadUrl, undefined);
  assert.equal(context.storage.delete, undefined);
  assert.throws(() => context.storage.generateUploadUrl(), /is not a function/u);
  assert.throws(() => context.storage.delete("storage-id"), /is not a function/u);
  assert.equal(harness.requestCapabilityIdentities.length, 0);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
  assert.equal(harness.cleanup(), 0);
});

test("storage request validation and reuse cleanup retain no guest handles", async () => {
  const harness = nativeCapabilityHarness();
  const firstContext = harness.createContext("mutation", undefined, 89);
  const commitTs = firstContext.db.vars.commitTs;

  for (const [name, request] of [
    ["get-url-number", () => firstContext.storage.getUrl(1)],
    ["get-metadata-missing", () => firstContext.storage.getMetadata()],
    ["delete-pending-commit-ts", () => firstContext.storage.delete(commitTs)],
  ]) {
    assert.throws(request, /Storage ID must be a string/u, name);
    assert.equal(harness.requestCapabilityIdentities.length, 0, name);
    assert.equal(harness.requests.length, 0, name);
    assert.equal(harness.requestPayloads.length, 0, name);
    assert.equal(harness.outstandingHandles(), 0, name);
  }

  void firstContext.storage.getUrl("abandoned-storage-id");
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGetUrl",
    storageId: "abandoned-storage-id",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(harness.cleanup(), 1);
  assert.equal(harness.outstandingHandles(), 0);

  harness.restartOperationHandles();
  const reusedContext = harness.createContext("mutation", undefined, 97);
  const freshUpload = reusedContext.storage.generateUploadUrl();
  assert.deepEqual(harness.requests.shift(), {
    kind: "storageGenerateUploadUrl",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(
    harness.lastStartedOperationHandle(),
    0,
    harness.allocate("https://storage.example/fresh-upload")
  );
  assert.equal(await freshUpload, "https://storage.example/fresh-upload");
  assert.deepEqual(harness.requestCapabilityIdentities, [89, 97]);
  assert.equal(harness.cleanup(), 0);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
});

test("native capability request envelopes isolate patch and query syntax from committed values", async () => {
  const harness = nativeCapabilityHarness();
  const context = harness.createContext("mutation");

  const patch = context.db.patch(
    "documents",
    "document-id",
    harness.guestValue("({ nested, removed: undefined })", {
      nested: { kept: 3, removed: undefined },
    })
  );
  assert.deepEqual(harness.requests.shift(), {
    id: "document-id",
    kind: "dbPatch",
    patch: {
      nested: { kept: 3 },
      removed: { $undefined: null },
    },
    table: "documents",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.shift(),
    '{"id":"document-id","kind":"dbPatch","patch":{"nested":{"kept":3},"removed":{"$undefined":null}},"table":"documents","version":4}'
  );
  harness.settle(harness.lastStartedOperationHandle(), 0, 0);
  assert.equal(await patch, undefined);

  const query = context.db
    .query("documents")
    .filter((q) => q.and(q.eq(q.field("status"), "ready"), q.eq(q.field("sequence"), 4)))
    .collect();
  assert.deepEqual(harness.requests.shift(), {
    kind: "dbQuery",
    operators: [
      {
        expression: {
          $and: [
            {
              $eq: [{ $field: "status" }, { $literal: "ready" }],
            },
            {
              $eq: [{ $field: "sequence" }, { $literal: 4 }],
            },
          ],
        },
        type: "filter",
      },
    ],
    order: null,
    source: { type: "fullTableScan" },
    table: "documents",
    terminal: "collect",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.shift(),
    '{"kind":"dbQuery","operators":[{"expression":{"$and":[{"$eq":[{"$field":"status"},{"$literal":"ready"}]},{"$eq":[{"$field":"sequence"},{"$literal":4}]}]},"type":"filter"}],"order":null,"source":{"type":"fullTableScan"},"table":"documents","terminal":"collect","version":4}'
  );
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([]));
  assert.deepEqual(await query, []);

  const { encode: encodeCommittedValue } = guestNativeCodec();
  assert.throws(() => encodeCommittedValue({ $literal: "not-a-value" }, []), /reserved prefix/u);
  assert.throws(() => context.db.insert("documents", { $eq: [1, 2] }), /reserved prefix/u);
  assert.throws(
    () =>
      context.db.patch(
        "documents",
        "document-id",
        harness.guestValue("({ nested })", { nested: { $undefined: null } })
      ),
    /reserved prefix/u
  );
  assert.throws(
    () =>
      context.db
        .query("documents")
        .filter((q) => q.eq(q.field("status"), { $field: "other" }))
        .collect(),
    /reserved prefix/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
});

test("native capability v4 exposes and encodes the pending commit timestamp by identity", async () => {
  const sdkCommitTsPlaceholder = jsonToConvex({ $commitTs: null });
  const codec = guestNativeCodec(sdkCommitTsPlaceholder);
  assert.equal(codec.commitTs, sdkCommitTsPlaceholder);
  assert.equal(codec.commitTs instanceof CommitTsPlaceholder, true);
  assert.deepEqual(convexToJson(codec.commitTs), { $commitTs: null });
  assert.equal(jsonToConvex(convexToJson(codec.commitTs)), codec.commitTs);
  assert.equal(compareValues(codec.commitTs, 9223372036854775807n), 0);
  assert.deepEqual(codec.encode(codec.commitTs, []), { $commitTs: null });
  assert.equal(codec.restore({ $commitTs: null }), codec.commitTs);
  assert.equal(String(codec.commitTs), "[unresolved commit timestamp]");
  assert.throws(() => Number(codec.commitTs), /commit timestamp is unresolved/u);
  assert.throws(() => JSON.stringify(codec.commitTs), /commit timestamp is unresolved/u);
  assert.throws(() => codec.encode({ $commitTs: null }, []), /reserved prefix/u);
  assert.throws(
    () => codec.restore({ $commitTs: "forged" }),
    /Invalid guest-native \$commitTs encoding/u
  );

  const harness = nativeCapabilityHarness();
  const queryContext = harness.createContext("query");
  const mutationContext = harness.createContext("mutation");
  assert.equal(queryContext.db.vars, undefined);
  const commitTs = mutationContext.db.vars.commitTs;
  assert.equal(mutationContext.db.vars.commitTs, commitTs);
  assert.equal(String(commitTs), "[unresolved commit timestamp]");

  const insert = mutationContext.db.insert("documents", {
    commitTs,
    nested: [{ commitTs }],
  });
  assert.deepEqual(harness.requests.shift(), {
    kind: "dbInsert",
    table: "documents",
    value: {
      commitTs: { $commitTs: null },
      nested: [{ commitTs: { $commitTs: null } }],
    },
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate("document-id"));
  assert.equal(await insert, "document-id");

  const pendingRows = mutationContext.db
    .query("documents")
    .withIndex("by_commit_ts", (range) => range.eq("commitTs", commitTs))
    .collect();
  assert.deepEqual(harness.requests.shift(), {
    kind: "dbQuery",
    operators: [],
    order: null,
    source: {
      constraints: [{ field: "commitTs", operator: "eq", value: { $commitTs: null } }],
      index: "by_commit_ts",
      type: "indexRange",
    },
    table: "documents",
    terminal: "collect",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([]));
  assert.deepEqual(await pendingRows, []);

  const patch = mutationContext.db.patch(
    "documents",
    "document-id",
    harness.guestValue("({ commitTs })", { commitTs })
  );
  assert.deepEqual(harness.requests.shift(), {
    id: "document-id",
    kind: "dbPatch",
    patch: {
      commitTs: { $commitTs: null },
    },
    table: "documents",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, 0);
  assert.equal(await patch, undefined);

  const replacement = mutationContext.db.replace("documents", "document-id", {
    commitTs,
    nested: [{ commitTs }],
  });
  assert.deepEqual(harness.requests.shift(), {
    id: "document-id",
    kind: "dbReplace",
    table: "documents",
    value: {
      commitTs: { $commitTs: null },
      nested: [{ commitTs: { $commitTs: null } }],
    },
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, 0);
  assert.equal(await replacement, undefined);
  assert.equal(harness.outstandingHandles(), 0);
});

test("native capability v4 rejects pending commit timestamps in every committed-only request position", () => {
  const harness = nativeCapabilityHarness();
  const context = harness.createContext("mutation");
  const commitTs = context.db.vars.commitTs;
  const rejectedRequests = [
    ["db-get-pending-id", () => context.db.get("documents", commitTs)],
    ["db-system-get-pending-id", () => context.db.system.get("_storage", commitTs)],
    ["db-patch-pending-id", () => context.db.patch("documents", commitTs, { status: "ready" })],
    ["db-replace-pending-id", () => context.db.replace("documents", commitTs, { status: "ready" })],
    ["db-delete-pending-id", () => context.db.delete("documents", commitTs)],
    [
      "db-query-pending-filter-literal",
      () =>
        context.db
          .query("documents")
          .filter((q) => q.eq(q.field("commitTs"), commitTs))
          .collect(),
    ],
    [
      "scheduler-run-after-pending-args",
      () => context.scheduler.runAfter(125, "tasks:run", { nested: [{ commitTs }] }),
    ],
    [
      "scheduler-run-at-pending-args",
      () => context.scheduler.runAt(1_710_000_000_000, "tasks:run", { nested: [{ commitTs }] }),
    ],
    ["scheduler-cancel-pending-id", () => context.scheduler.cancel(commitTs)],
  ];

  for (const [name, request] of rejectedRequests) {
    assert.throws(
      request,
      /Pending commit timestamp is not allowed in this capability request position/u,
      name
    );
    assert.equal(harness.requests.length, 0, name);
    assert.equal(harness.requestPayloads.length, 0, name);
    assert.equal(harness.outstandingHandles(), 0, name);
  }
});

test("native capability v4 emits generic nested mutation requests with pending arguments", async () => {
  const harness = nativeCapabilityHarness();
  const context = harness.createContext("mutation");
  const commitTs = context.db.vars.commitTs;
  const reference = {
    [Symbol.for("toReferencePath")]: "tasks:enqueueWithTimestamp",
  };
  const result = context.runMutation(
    reference,
    { payload: "queued", updatedAt: commitTs },
    { transactionLimits: { documentsWritten: 2, bytesWritten: 4096 } }
  );

  assert.deepEqual(harness.requests.shift(), {
    args: {
      payload: "queued",
      updatedAt: { $commitTs: null },
    },
    functionAddress: { reference: "tasks:enqueueWithTimestamp" },
    kind: "runUdf",
    transactionLimits: { bytesWritten: 4096, documentsWritten: 2 },
    udfType: "mutation",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(commitTs));
  assert.equal(await result, commitTs);
  assert.equal(harness.outstandingHandles(), 0);

  const queryContext = harness.createContext("query");
  assert.equal(queryContext.runMutation, undefined);
  assert.throws(
    () => context.runMutation("tasks:enqueue", {}, { transactionLimits: { unknown: 1 } }),
    /Transaction limit field is unsupported/u
  );
});

test("native capability v4 emits canonical nested query requests for query and mutation callers", async () => {
  const harness = nativeCapabilityHarness();
  const queryContext = harness.createContext("query");
  const mutationContext = harness.createContext("mutation");

  const queried = queryContext.runQuery(
    "tasks:read",
    {},
    { transactionLimits: { documentsRead: 2, bytesRead: 1024 } }
  );
  assert.deepEqual(harness.requests.shift(), {
    args: {},
    functionAddress: { name: "tasks:read" },
    kind: "runUdf",
    transactionLimits: { bytesRead: 1024, documentsRead: 2 },
    udfType: "query",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.shift(),
    '{"args":{},"functionAddress":{"name":"tasks:read"},"kind":"runUdf","transactionLimits":{"bytesRead":1024,"documentsRead":2},"udfType":"query","version":4}'
  );
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate({ status: "ready" }));
  assert.deepEqual(await queried, { status: "ready" });

  const commitTs = mutationContext.db.vars.commitTs;
  const reference = {
    [Symbol.for("toReferencePath")]: "tasks:readPending",
  };
  const pendingQuery = mutationContext.runQuery(
    reference,
    { payload: "pending", updatedAt: commitTs },
    { transactionLimits: { databaseQueries: 1 } }
  );
  assert.deepEqual(harness.requests.shift(), {
    args: {
      payload: "pending",
      updatedAt: { $commitTs: null },
    },
    functionAddress: { reference: "tasks:readPending" },
    kind: "runUdf",
    transactionLimits: { databaseQueries: 1 },
    udfType: "query",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.shift(),
    '{"args":{"payload":"pending","updatedAt":{"$commitTs":null}},"functionAddress":{"reference":"tasks:readPending"},"kind":"runUdf","transactionLimits":{"databaseQueries":1},"udfType":"query","version":4}'
  );
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate(commitTs));
  assert.equal(await pendingQuery, commitTs);

  const staleQuery = mutationContext.runQuery(
    "function://stale-query-handle",
    { updatedAt: commitTs },
    {
      transactionLimits: { bytesRead: 2048 },
      useStaleSnapshot: true,
    }
  );
  assert.deepEqual(harness.requests.shift(), {
    args: { updatedAt: { $commitTs: null } },
    functionAddress: { functionHandle: "function://stale-query-handle" },
    kind: "runUdf",
    transactionLimits: { bytesRead: 2048 },
    udfType: "snapshotQuery",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.equal(
    harness.requestPayloads.shift(),
    '{"args":{"updatedAt":{"$commitTs":null}},"functionAddress":{"functionHandle":"function://stale-query-handle"},"kind":"runUdf","transactionLimits":{"bytesRead":2048},"udfType":"snapshotQuery","version":4}'
  );
  harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate({ status: "stale" }));
  assert.deepEqual(await staleQuery, { status: "stale" });

  assert.equal(queryContext.db.vars, undefined);
  assert.throws(
    () => queryContext.runQuery("tasks:read", {}, { useStaleSnapshot: true }),
    /`useStaleSnapshot` is only supported in mutations, not queries\./u
  );
  assert.throws(
    () => queryContext.runQuery("tasks:read", {}, { transactionLimits: { unknown: 1 } }),
    /Transaction limit field is unsupported/u
  );
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.requestPayloads.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
});

test("generic capability queries iterate through one authenticated query stream", async () => {
  const harness = nativeCapabilityHarness();
  const context = harness.createContext("query");
  const query = context.db
    .query("documents")
    .withIndex("by_tenant", (range) => range.eq("tenant", "tenant-a"))
    .order("desc");
  const iterator = query[Symbol.asyncIterator]();
  assert.deepEqual(JSON.parse(JSON.stringify(harness.requests.shift())), {
    kind: "dbQuery",
    operators: [],
    order: "desc",
    source: {
      constraints: [{ field: "tenant", operator: "eq", value: "tenant-a" }],
      index: "by_tenant",
      type: "indexRange",
    },
    table: "documents",
    terminal: "stream",
    version: convexWasmCapabilityRequestAbiVersion,
  });
  assert.throws(() => query[Symbol.asyncIterator](), /Iteration can only begin/u);
  assert.throws(() => query.collect(), /query is closed/u);

  const first = iterator.next();
  await assert.rejects(iterator.next(), /already has a pending read/u);
  const firstOperation = harness.lastStartedOperationHandle();
  harness.settle(firstOperation, 0, harness.allocate({ done: false, value: { _id: "first" } }));
  assert.deepEqual(JSON.parse(JSON.stringify(await first)), {
    done: false,
    value: { _id: "first" },
  });

  const second = query.next();
  const secondOperation = harness.lastStartedOperationHandle();
  harness.settle(secondOperation, 0, harness.allocate({ done: false, value: { _id: "second" } }));
  assert.deepEqual(JSON.parse(JSON.stringify(await second)), {
    done: false,
    value: { _id: "second" },
  });
  const returned = await iterator.return();
  assert.equal(returned.done, true);
  assert.equal(returned.value, undefined);
  const afterReturn = await iterator.next();
  assert.equal(afterReturn.done, true);
  assert.equal(afterReturn.value, undefined);
  assert.deepEqual(harness.closedQueryStreams, [1]);
  assert.equal(harness.openQueryStreams.size, 0);
  assert.equal(harness.cleanup(), 0);

  const exhausted = context.db.query("documents")[Symbol.asyncIterator]();
  harness.requests.shift();
  const exhaustedNext = exhausted.next();
  harness.settle(
    harness.lastStartedOperationHandle(),
    0,
    harness.allocate({ done: true, value: null })
  );
  const exhaustion = await exhaustedNext;
  assert.equal(exhaustion.done, true);
  assert.equal(exhaustion.value, undefined);
  assert.equal(harness.openQueryStreams.size, 0);
  assert.equal(harness.cleanup(), 0);

  context.db.query("documents")[Symbol.asyncIterator]();
  harness.requests.shift();
  assert.equal(harness.openQueryStreams.size, 1);
  assert.equal(harness.cleanup(), 0);
  assert.deepEqual(harness.closedQueryStreams, [1]);
  assert.equal(harness.openQueryStreams.size, 1);
  assert.equal(harness.requests.length, 0);
  assert.equal(harness.outstandingHandles(), 0);
});

test("native capability terminal Promise failures close and clean the invocation", async () => {
  const harness = nativeCapabilityHarness();
  harness.invoke(
    async () => {
      throw new Error("expected terminal Promise failure");
    },
    harness.createContext("query"),
    {}
  );

  await drainCapabilityMicrotasks();
  assert.equal(harness.done(), true);
  assert.equal(harness.status(), 1);
  assert.equal(harness.cleanup(), 0);
  assert.equal(harness.outstandingHandles(), 0);

  harness.invoke(() => "reused", harness.createContext("query"), {});
  await drainCapabilityMicrotasks();
  assert.equal(harness.done(), true);
  assert.equal(harness.status(), 0);
  assert.equal(harness.cleanup(), 0);
  assert.deepEqual(harness.results, ["reused"]);
});

test("registered-wrapper invocation uses positional tagged JSON without double encoding", async () => {
  const harness = nativeCapabilityHarness();
  const calls = [];
  const wrapper = function registeredQueryCannotBeCalledDirectly() {
    throw new Error("registration wrapper was called directly");
  };
  wrapper.isQuery = true;
  wrapper.isPublic = true;
  wrapper._handler = () => {
    throw new Error("raw handler was called");
  };
  wrapper.invokeQuery = function invokeQuery(argsStr) {
    calls.push({ argsStr, receiver: this });
    return Promise.resolve(
      JSON.stringify(
        convexToJson({
          bytes: new Uint8Array([1, 2, 3]).buffer,
          count: 9n,
          nested: [null, "result"],
        })
      )
    );
  };

  harness.activateSdk("query");
  harness.invokeRegisteredWrapper(
    wrapper,
    JSON.stringify(convexToJson({ bytes: new Uint8Array([4, 5]).buffer, count: -7n }))
  );
  await drainCapabilityMicrotasks();

  assert.equal(calls.length, 1);
  assert.equal(calls[0].receiver, wrapper);
  assert.deepEqual(JSON.parse(calls[0].argsStr), [
    convexToJson({ bytes: new Uint8Array([4, 5]).buffer, count: -7n }),
  ]);
  assert.equal(harness.done(), true);
  assert.equal(harness.status(), 0);
  assert.equal(harness.results.length, 1);
  assert.equal(
    harness.taggedResultSources[0],
    JSON.stringify(
      convexToJson({ bytes: new Uint8Array([1, 2, 3]).buffer, count: 9n, nested: [null, "result"] })
    )
  );
  assert.equal(harness.results[0].count, 9n);
  assert.deepEqual([...new Uint8Array(harness.results[0].bytes)], [1, 2, 3]);
  assert.deepEqual(Array.from(harness.results[0].nested), [null, "result"]);
  assert.equal(harness.cleanup(), 0);

  harness.activateSdk("query");
  wrapper.invokeQuery = () => ({ invalid: true });
  harness.invokeRegisteredWrapper(wrapper, "{}");
  await drainCapabilityMicrotasks();
  assert.equal(harness.done(), true);
  assert.equal(harness.status(), 1);
  assert.equal(harness.results.length, 1);
  assert.equal(harness.cleanup(), 0);
});

test("native capability getStatus clears operation slots when handles restart", async () => {
  const harness = nativeCapabilityHarness();

  harness.invoke(
    (ctx) => {
      void ctx.auth.getUserIdentity();
      return "abandoned";
    },
    harness.createContext("query"),
    {}
  );
  await drainCapabilityMicrotasks();
  assert.deepEqual(JSON.parse(JSON.stringify(harness.requests.shift())), {
    version: convexWasmCapabilityRequestAbiVersion,
    kind: "authGetUserIdentity",
  });
  assert.equal(harness.lastStartedOperationHandle(), 1);
  assert.equal(harness.done(), true);
  assert.equal(harness.status(), 0);
  assert.equal(harness.cleanup(), 1);
  harness.restartOperationHandles();

  for (let sequence = 1; sequence <= 2; sequence += 1) {
    if (sequence > 1) harness.restartOperationHandles();
    harness.invoke(
      async (ctx) => {
        const identity = await ctx.auth.getUserIdentity();
        ctx.db.normalizeId("selfHostedExecutionProbeStates", "singleton");
        const state = await ctx.db.get("selfHostedExecutionProbeStates", "singleton");
        const rows = await ctx.db.query("selfHostedExecutionProbeStates").collect();
        return {
          authenticated: identity.subject === "synthetic-probe",
          rowCount: rows.length,
          sequence: state.sequence,
        };
      },
      harness.createContext("query"),
      {}
    );

    assert.deepEqual(JSON.parse(JSON.stringify(harness.requests.shift())), {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "authGetUserIdentity",
    });
    harness.settle(
      harness.lastStartedOperationHandle(),
      0,
      harness.allocate({ subject: "synthetic-probe" })
    );
    await drainCapabilityMicrotasks();
    assert.deepEqual(JSON.parse(JSON.stringify(harness.requests.shift())), {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbNormalizeId",
      table: "selfHostedExecutionProbeStates",
      value: "singleton",
    });
    assert.deepEqual(JSON.parse(JSON.stringify(harness.requests.shift())), {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbGet",
      table: "selfHostedExecutionProbeStates",
      id: "singleton",
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate({ sequence }));
    await drainCapabilityMicrotasks();
    assert.deepEqual(JSON.parse(JSON.stringify(harness.requests.shift())), {
      version: convexWasmCapabilityRequestAbiVersion,
      kind: "dbQuery",
      table: "selfHostedExecutionProbeStates",
      source: { type: "fullTableScan" },
      operators: [],
      order: null,
      terminal: "collect",
    });
    harness.settle(harness.lastStartedOperationHandle(), 0, harness.allocate([{ sequence }]));
    await drainCapabilityMicrotasks();

    assert.equal(harness.done(), true);
    assert.equal(harness.status(), 0);
    assert.equal(harness.cleanup(), 0);
    assert.equal(harness.outstandingHandles(), 0);
  }

  assert.deepEqual(JSON.parse(JSON.stringify(harness.results)), [
    "abandoned",
    { authenticated: true, rowCount: 1, sequence: 1 },
    { authenticated: true, rowCount: 1, sequence: 2 },
  ]);
});

test("preserves the canonical esbuild live-export helper across Node and Static Hermes", (context) => {
  const compileProfileJavascript = `
var __convexWasmCompileProfile = (() => {
  var defineProperty = Object.defineProperty;
  var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  var getOwnPropertyNames = Object.getOwnPropertyNames;
  var hasOwnProperty = Object.prototype.hasOwnProperty;
  var exportProperties = (target, definitions) => {
    for (var name in definitions)
      defineProperty(target, name, { get: definitions[name], enumerable: true });
  };
  var copyProperties = (target, source, except, descriptor) => {
    if (source && typeof source === "object" || typeof source === "function")
      for (let name of getOwnPropertyNames(source))
        !hasOwnProperty.call(target, name) && name !== except && defineProperty(target, name, { get: () => source[name], enumerable: !(descriptor = getOwnPropertyDescriptor(source, name)) || descriptor.enumerable });
    return target;
  };
  var first = "A0";
  var second = "B0";
  var setValues = (nextFirst, nextSecond) => {
    first = nextFirst;
    second = nextSecond;
  };
  var exportsObject = {};
  exportProperties(exportsObject, {
    first: () => first,
    aliasOfFirst: () => first,
    second: () => second,
    setValues: () => setValues,
  });
  return copyProperties(defineProperty({}, "__esModule", { value: true }), exportsObject);
})();
`;
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript,
  });
  assert.doesNotMatch(rendered, /get:\s*\(\)\s*=>\s*source\[name\]/u);
  assert.match(rendered, /for\s*\(\s*let\s+name\s+of\s+getOwnPropertyNames\(source\)\s*\)/u);
  assert.doesNotMatch(rendered, /for\s*\(\s*var\s+name\s+of\s+getOwnPropertyNames\(source\)\s*\)/u);
  assert.match(
    rendered,
    /get:\s*\(\(__convexWasmObject, __convexWasmProperty\)\s*=>\s*\(\)\s*=>\s*__convexWasmObject\[__convexWasmProperty\]\)\(source, name\)/u
  );
  const resultExpression = `
globalThis.__convexWasmCompileProfile.setValues("A1", "B1");
globalThis.__convexWasmExportProbe = JSON.stringify({
  names: Object.getOwnPropertyNames(globalThis.__convexWasmCompileProfile),
  first: globalThis.__convexWasmCompileProfile.first,
  aliasOfFirst: globalThis.__convexWasmCompileProfile.aliasOfFirst,
  second: globalThis.__convexWasmCompileProfile.second,
  distinct: globalThis.__convexWasmCompileProfile.first !== globalThis.__convexWasmCompileProfile.second,
  });`;
  const compileProfileStart = rendered.indexOf("var __convexWasmCompileProfile");
  assert.ok(compileProfileStart > 0);
  const compileProfileEnd = rendered.indexOf(
    "return __convexWasmCompileProfile;",
    compileProfileStart
  );
  assert.ok(compileProfileEnd > compileProfileStart);
  const compileProfileExport =
    "globalThis.__convexWasmCompileProfile = __convexWasmCompileProfile;";
  const probeSource =
    `${rendered.slice(compileProfileStart, compileProfileEnd)}${compileProfileExport}\n` +
    resultExpression;
  const nodeGlobal = {};
  runInNewContext(probeSource, nodeGlobal);
  const expected = JSON.stringify({
    names: ["__esModule", "first", "aliasOfFirst", "second", "setValues"],
    first: "A1",
    aliasOfFirst: "A1",
    second: "B1",
    distinct: true,
  });
  assert.equal(nodeGlobal.__convexWasmExportProbe, expected);

  const staticHermes = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (staticHermes === undefined) {
    context.diagnostic(
      "set CONVEX_STATIC_HERMES_TEST_BINARY to run the Node/Static Hermes differential"
    );
    return;
  }
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "convex-wasm-export-bindings-"));
  try {
    const probePath = join(temporaryDirectory, "probe.js");
    writeFileSync(probePath, `${probeSource}\nprint(globalThis.__convexWasmExportProbe);\n`);
    const result = spawnSync(staticHermes, ["-typed", "-O", "-exec", probePath], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), expected);
  } finally {
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
});

test("leaves unrelated lexical getter loops unchanged", () => {
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript: `
var values = { first: "A", second: "B" };
var target = {};
for (let key of Object.getOwnPropertyNames(values))
  Object.defineProperty(target, key, { get: () => values[key], enumerable: true });
var __convexWasmCompileProfile = { target };
`,
  });
  assert.match(
    rendered,
    /for\s*\(\s*let\s+key\s+of\s+Object\.getOwnPropertyNames\(values\)\s*\)\s*\n\s*Object\.defineProperty\(target, key, \{ get: \(\) => values\[key\]/u
  );
  assert.doesNotMatch(rendered, /__convexWasmObject, __convexWasmProperty\)\(values, key\)/u);
});

test("preserves the marked conditional esbuild live-export helper form", () => {
  const rendered = renderNativeDbGetCapabilityTarget({
    argumentFields: [],
    compileProfileJavascript: `
var defineProperty = Object.defineProperty;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var getOwnPropertyNames = Object.getOwnPropertyNames;
var hasOwnProperty = Object.prototype.hasOwnProperty;
var copyProperties = (target, source, except, descriptor) => {
  if (source && typeof source === "object" || typeof source === "function") {
    for (let name of getOwnPropertyNames(source))
      if (!hasOwnProperty.call(target, name) && name !== except)
        defineProperty(target, name, { get: () => source[name], enumerable: !(descriptor = getOwnPropertyDescriptor(source, name)) || descriptor.enumerable });
  }
  return target;
};
var __convexWasmCompileProfile = {};
//# sourceMappingURL=convex-wasm-compile-profile.js.map`,
  });
  assert.match(
    rendered,
    /get:\s*\(\(__convexWasmObject, __convexWasmProperty\)\s*=>\s*\(\)\s*=>\s*__convexWasmObject\[__convexWasmProperty\]\)\(source, name\)/u
  );
});

test("rejects an unmarked esbuild live-export helper that drifts from the canonical getter", () => {
  assert.throws(
    () =>
      renderNativeDbGetCapabilityTarget({
        argumentFields: [],
        compileProfileJavascript: `
var defineProperty = Object.defineProperty;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var getOwnPropertyNames = Object.getOwnPropertyNames;
var hasOwnProperty = Object.prototype.hasOwnProperty;
var copyProperties = (target, source, except, descriptor) => {
  if (source && typeof source === "object" || typeof source === "function")
    for (let name of getOwnPropertyNames(source))
      !hasOwnProperty.call(target, name) && name !== except && defineProperty(target, name, { get: () => source[name + ""], enumerable: !(descriptor = getOwnPropertyDescriptor(source, name)) || descriptor.enumerable });
  return target;
};
var __convexWasmCompileProfile = {};
`,
      }),
    /contains 1 esbuild live-export helper candidates but 0 recognized getters/u
  );
});

test("rejects marked compile-profile output when the esbuild export helper drifts", () => {
  assert.throws(
    () =>
      renderNativeDbGetCapabilityTarget({
        argumentFields: [],
        compileProfileJavascript:
          "var __convexWasmCompileProfile = {};\n" +
          "//# sourceMappingURL=convex-wasm-compile-profile.js.map",
      }),
    /exactly one recognized esbuild live-export helper; received 0/u
  );
});

test("native capability runtime isolates and retains split bridge and application units", () => {
  const source = readFileSync(
    new URL("./convex-wasm-native-capability-runtime-main.cpp", import.meta.url),
    "utf8"
  );
  const initializationDiagnosticStart = source.indexOf("enum class GuestInitializationErrorClass");
  const initializationReporterStart = source.indexOf(
    "Function guest_initialization_reporter",
    initializationDiagnosticStart
  );
  const initializationDiagnostic = source.slice(
    initializationDiagnosticStart,
    initializationReporterStart
  );
  const prepareStart = source.indexOf(
    'extern "C" int convex_wasm_udf_prepare_selected_entry(void)'
  );
  const runStart = source.indexOf('extern "C" int convex_wasm_udf_run(void)');
  const prepareSource = source.slice(prepareStart, runStart);
  const runSource = source.slice(runStart);
  const reserveOutput = source.indexOf("      reserve_compile_profile_output(js);", prepareStart);
  const initializeBridge = source.indexOf(
    "      js_error_phase = JSErrorPhase::InitializeBridgeUnit;",
    prepareStart
  );
  const validateRuntimeSupportInstaller = source.indexOf(
    "      validate_runtime_support_installer(js);",
    initializeBridge
  );
  const initializeRuntimeSupport = source.indexOf(
    "      js_error_phase = JSErrorPhase::InitializeFormatterUnit;",
    validateRuntimeSupportInstaller
  );
  const verifyRuntimeSupportInstallation = source.indexOf(
    "      verify_runtime_support_installation(js);",
    initializeRuntimeSupport
  );
  const retainBridgeBindings = source.indexOf(
    "      retain_bridge_bootstrap_and_application_bindings(js);",
    verifyRuntimeSupportInstallation
  );
  const openOutput = source.indexOf("      open_compile_profile_output(js);", retainBridgeBindings);
  const exposeApplicationBindings = source.indexOf(
    "      expose_application_initialization_bindings(js, initialization_slot);",
    openOutput
  );
  const initializeApplication = source.indexOf(
    "      js_error_phase = JSErrorPhase::InitializeApplicationUnit;",
    exposeApplicationBindings
  );
  const closeOutput = source.indexOf(
    "      close_compile_profile_output(js, initialization_slot);",
    initializeApplication
  );
  const clearApplicationBindings = source.indexOf(
    "      clear_application_initialization_bindings(js);",
    closeOutput
  );
  const releaseCompileProfileOutputSlot = source.indexOf(
    "      compile_profile_output_slot.reset();",
    clearApplicationBindings
  );
  const validateIntrinsicDescriptorState = source.indexOf(
    "      validate_intrinsic_descriptor_state(js);",
    releaseCompileProfileOutputSlot
  );
  const installBridge = source.indexOf(
    "      install_guest_bridge(js);",
    validateIntrinsicDescriptorState
  );
  const activateSdk = source.indexOf("guest_bridge->activate_sdk->call(", runStart);
  const readRequest = source.indexOf("guest_bridge->read_request->call(js)", activateSdk);
  const invokeRegisteredWrapper = source.indexOf(
    "guest_bridge->invoke_registered_wrapper->call(",
    readRequest
  );
  const createContext = source.indexOf("auto context = invocation_context(", readRequest);
  const invoke = source.indexOf("guest_bridge->invoke->call(", createContext);
  const firstMicrotaskCheckpoint = source.indexOf("js.drainMicrotasks()", invoke);

  assert.ok(prepareStart > 0);
  assert.ok(runStart > prepareStart);
  assert.ok(reserveOutput < initializeBridge);
  assert.ok(initializeBridge < validateRuntimeSupportInstaller);
  assert.ok(validateRuntimeSupportInstaller < initializeRuntimeSupport);
  assert.ok(initializeRuntimeSupport < verifyRuntimeSupportInstallation);
  assert.ok(verifyRuntimeSupportInstallation < retainBridgeBindings);
  assert.ok(retainBridgeBindings < openOutput);
  assert.ok(openOutput < exposeApplicationBindings);
  assert.ok(exposeApplicationBindings < initializeApplication);
  assert.ok(initializeApplication < closeOutput);
  assert.ok(closeOutput < clearApplicationBindings);
  assert.ok(releaseCompileProfileOutputSlot < validateIntrinsicDescriptorState);
  assert.ok(validateIntrinsicDescriptorState < installBridge);
  assert.ok(prepareStart < installBridge);
  assert.ok(installBridge < runStart);
  assert.ok(activateSdk < readRequest);
  assert.ok(readRequest < invokeRegisteredWrapper);
  assert.ok(invokeRegisteredWrapper < createContext);
  assert.ok(createContext < invoke);
  assert.ok(readRequest < invoke);
  assert.ok(invoke < firstMicrotaskCheckpoint);
  assert.match(
    source,
    /js_error_phase = JSErrorPhase::InitializeBridgeUnit;\s*if \(!_sh_initialize_units\(runtime, 1,\s*CONVEX_WASM_BRIDGE_EXPORTED_UNIT\)\) \{\s*reset_runtime_state\(\);\s*return static_cast<int32_t>\(js_error_phase\);\s*\}/u
  );
  assert.match(
    source,
    /js_error_phase = JSErrorPhase::ValidateRuntimeSupportInstaller;\s*validate_runtime_support_installer\(js\);\s*js_error_phase = JSErrorPhase::InitializeFormatterUnit;[\s\S]*?if \(!_sh_initialize_units\(runtime, 1,\s*CONVEX_WASM_FORMATTER_EXPORTED_UNIT\)\) \{\s*reset_runtime_state\(\);\s*return static_cast<int32_t>\(js_error_phase\);\s*\}[\s\S]*?formatter_unit_initialization_count \+= 1;[\s\S]*?js_error_phase = JSErrorPhase::VerifyRuntimeSupportInstallation;\s*verify_runtime_support_installation\(js\);[\s\S]*?js_error_phase = JSErrorPhase::RetainBridgeBootstrap;\s*retain_bridge_bootstrap_and_application_bindings\(js\);/u
  );
  assert.match(
    source,
    /#if !defined\(CONVEX_WASM_CHUNK_APPLICATION_UNIT\)\s*if \(!selected_entry_is_prepared\(entry_slot\)\) \{\s*const int32_t initialization_slot =[\s\S]*?const SHUnitCreator factory =\s*#if defined\(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT\)\s*convex_wasm_application_factory_by_unit_slot\(initialization_slot\);\s*#else\s*convex_wasm_application_factory_by_slot\(initialization_slot\);\s*#endif[\s\S]*?expose_application_initialization_bindings\(js, initialization_slot\);[\s\S]*?js_error_phase = JSErrorPhase::InitializeApplicationUnit;\s*evaluate_application_initializer\(js, factory, initialization_slot\);[\s\S]*?initialized_selected_application = true;/u
  );
  assert.match(
    source,
    /InitializeOfficialChunkUnit = 65,\s*InitializeOfficialEntryPublicationUnit = 66,/u
  );
  assert.match(
    source,
    /void initialize_official_chunk_entry\(Runtime &js,\s*int32_t entry_slot,\s*JSErrorPhase &js_error_phase\)/u
  );
  assert.match(
    source,
    /initialize_official_chunk_unit\(js, entry_chunk_slot\);[\s\S]*?InitializeOfficialEntryPublicationUnit[\s\S]*?expose_official_entry_publication_bindings\(\s*js, entry_slot, publication_unit_slot, entry_chunk_slot\)/u
  );
  assert.match(
    source,
    /extern "C" int32_t\s*convex_wasm_application_entry_publication_unit_slot_by_handoff_slot\(\s*int32_t entry_slot\);/u
  );
  assert.match(
    source,
    /void validate_official_chunk_application_topology\(Runtime &js\) \{[\s\S]*?chunk_slot_count \+ declared_application_entry_count !=\s*declared_application_unit_count[\s\S]*?std::array<bool, kMaxApplicationUnitSlots> publication_slots\{\};[\s\S]*?convex_wasm_application_entry_publication_unit_slot_by_handoff_slot\([\s\S]*?publication_slots\[publication_unit_slot\]/u
  );
  assert.doesNotMatch(
    source,
    /for \(int32_t chunk_slot = 0;\s*chunk_slot < chunk_slot_count;[\s\S]*?initialize_official_chunk_unit\(js, chunk_slot\)/u
  );
  assert.match(
    source,
    /#if defined\(CONVEX_WASM_CHUNK_APPLICATION_UNIT\)\s*if \(application_export_slots\[entry_slot\]\.exports == nullptr\) \{\s*js_error_phase = JSErrorPhase::InitializeOfficialChunkUnit;\s*initialize_official_chunk_entry\(js, entry_slot, js_error_phase\);[\s\S]*?validate_intrinsic_descriptor_state\(js\);/u
  );
  assert.match(
    source,
    /std::shared_ptr<GuestInitializationErrorConstructors>\s*capture_guest_initialization_error_constructors\(Runtime &js\) \{[\s\S]*?global\.getProperty\(js, "Error"\)[\s\S]*?global\.getProperty\(js, "TypeError"\)[\s\S]*?global\.getProperty\(js, "URIError"\)/u
  );
  assert.match(
    source,
    /Function guest_initialization_reporter\(Runtime &js, int32_t unit_slot\) \{[\s\S]*?guest_initialization_error_constructors == nullptr[\s\S]*?const auto constructors = guest_initialization_error_constructors;[\s\S]*?const Value \*arguments,\s*size_t count\)[\s\S]*?if \(count != 1\)[\s\S]*?guest_initialization_error_class\(\s*js, arguments\[0\], \*constructors\)[\s\S]*?#if defined\(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS\)\s*report_guest_initialization_failure_classified\(\s*js, unit_slot, error_class, arguments\[0\]\);\s*#else\s*report_guest_initialization_failure_classified\(\s*js, unit_slot, error_class\);\s*#endif/u
  );
  const initializerBoundary = source.match(
    /void evaluate_application_initializer\(Runtime &js,\s*SHUnitCreator factory,\s*int32_t unit_slot\) \{([\s\S]*?)\n\}/u
  );
  assert.ok(initializerBoundary);
  assert.match(source, /#include "hermes\/hermes\.h"/u);
  assert.match(
    initializerBoundary[1],
    /const uint64_t reports_before = guest_initialization_report_count;\s*try \{\s*_sh_get_hermes_runtime\(runtime\)->evaluateSHUnit\(factory\);\s*\} catch \(const JSError &error\) \{\s*if \(guest_initialization_report_count == reports_before\) \{\s*const auto error_class = guest_initialization_error_class\(\s*js, error\.value\(\), \*guest_initialization_error_constructors\);[\s\S]*?report_guest_initialization_failure_classified\(/u
  );
  assert.match(
    initializerBoundary[1],
    /#if defined\(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS\)\s*report_guest_initialization_failure_classified\(\s*js, unit_slot, error_class, error\.value\(\)\);\s*#else\s*report_guest_initialization_failure_classified\(js, unit_slot, error_class\);\s*#endif/u
  );
  assert.match(
    source,
    /Function guest_initialization_reporter\([\s\S]*?report_guest_initialization_failure_classified\([\s\S]*?guest_initialization_report_count \+= 1;/u
  );
  assert.doesNotMatch(
    initializerBoundary[1],
    /(?:\.what\(\)|\.getMessage\(\)|\.getStack\(\)|getProperty\(|getString\(|\.utf8\()/u
  );
  assert.match(
    initializationDiagnostic,
    /enum class GuestInitializationErrorClass : uint8_t \{\s*NonError,\s*Error,\s*TypeError,\s*RangeError,\s*ReferenceError,\s*SyntaxError,\s*EvalError,\s*URIError,\s*\};/u
  );
  assert.match(
    initializationDiagnostic,
    /GuestInitializationErrorClass guest_initialization_error_class\([\s\S]*?!value\.isObject\(\)[\s\S]*?object\.instanceOf\(js, \*constructors\.type_error\)[\s\S]*?object\.instanceOf\(js, \*constructors\.range_error\)[\s\S]*?object\.instanceOf\(js, \*constructors\.reference_error\)[\s\S]*?object\.instanceOf\(js, \*constructors\.syntax_error\)[\s\S]*?object\.instanceOf\(js, \*constructors\.eval_error\)[\s\S]*?object\.instanceOf\(js, \*constructors\.uri_error\)[\s\S]*?object\.instanceOf\(js, \*constructors\.error\)/u
  );
  assert.match(
    initializationDiagnostic,
    /void report_guest_initialization_failure_classified\([\s\S]*?GuestInitializationErrorClass error_class\s*#if defined\(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS\)\s*,\s*const Value &error\s*#endif\s*\)[\s\S]*?std::array<char, kGuestInitializationDiagnosticMaximumBytes> message\{\};[\s\S]*?#if defined\(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS\)\s*if \(write_guest_initialization_failure_message_with_exception\([\s\S]*?application_initializer_reporter->call\(\s*js, String::createFromAscii\(js, message\.data\(\)\)\);\s*return;\s*\}\s*#endif\s*const int message_length = std::snprintf\([\s\S]*?"Guest initialization failed: unit_slot=%d error_class=%s"[\s\S]*?application_initializer_reporter->call\(\s*js, String::createFromAscii\(js, message\.data\(\)\)\);/u
  );
  assert.match(
    source,
    /constexpr size_t kGuestInitializationDiagnosticMaximumBytes = 640;\s*#if defined\(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS\)\s*constexpr size_t kGuestInitializationExceptionMessageMaximumBytes = 512;\s*constexpr size_t kGuestInitializationExceptionMessageMaximumCodeUnits = 128;\s*#endif/u
  );
  assert.match(
    initializationDiagnostic,
    /#if defined\(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS\)\s*bool write_guest_initialization_failure_message_with_exception\([\s\S]*?error\.asObject\(js\)\.getProperty\(js, "message"\)[\s\S]*?exception_message_value\.getString\(js\)[\s\S]*?exception_message_string\.length\(js\) >\s*kGuestInitializationExceptionMessageMaximumCodeUnits[\s\S]*?exception_message_string\.utf8\(js\)[\s\S]*?kGuestInitializationExceptionMessageMaximumBytes[\s\S]*?exception_byte != '"' && exception_byte != '\\\\'[\s\S]*?"exception_message=\\"%s\\""[\s\S]*?catch \(const JSError &\)[\s\S]*?return false;[\s\S]*?#endif/u
  );
  assert.doesNotMatch(initializationDiagnostic, /(?:\.stack|getStack\(js\)|sourceURL)/u);
  const localExceptionReportStart = initializationDiagnostic.indexOf(
    "#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)",
    initializationDiagnostic.indexOf(
      "std::array<char, kGuestInitializationDiagnosticMaximumBytes> message{};"
    )
  );
  assert.ok(localExceptionReportStart >= 0);
  const productionClassOnlyReport = initializationDiagnostic.slice(
    initializationDiagnostic.indexOf("#endif", localExceptionReportStart) + "#endif".length
  );
  assert.doesNotMatch(
    productionClassOnlyReport,
    /(?:getProperty\(js, "message"\)|getString\(js\)|length\(js\)|utf8\(js\))/u
  );
  assert.match(
    source,
    /void expose_official_chunk_unit_bindings\(Runtime &js, int32_t unit_slot\) \{[\s\S]*?auto reporter = guest_initialization_reporter\(js, unit_slot\);[\s\S]*?kOfficialChunkReportThrownBinding,[\s\S]*?Value\(js, reporter\)\);/u
  );
  assert.match(
    source,
    /void expose_official_entry_publication_bindings\(Runtime &js,\s*int32_t entry_slot,\s*int32_t unit_slot,\s*int32_t chunk_slot\) \{[\s\S]*?auto reporter = guest_initialization_reporter\(js, unit_slot\);[\s\S]*?kOfficialChunkReportThrownBinding,[\s\S]*?Value\(js, reporter\)\);/u
  );
  assert.doesNotMatch(
    source,
    /OfficialChunkInitializationFailureStage|OfficialChunkInitializationErrorClass|official_chunk_initialization_error_class_from_code|official_chunk_initialization_reporter|kOfficialChunkReportHostBindingFailureBinding/u
  );
  assert.match(
    source,
    /Value initialize_official_chunk_unit\(Runtime &js, int32_t unit_slot\) \{[\s\S]*?if \(slot\.state == ChunkApplicationUnitState::Initialized\) \{[\s\S]*?return Value\(js, \*slot\.namespace_value\);[\s\S]*?if \(slot\.state == ChunkApplicationUnitState::Initializing\) \{[\s\S]*?return Value\(js, \*slot\.namespace_value\);[\s\S]*?evaluate_application_initializer\(js, factory, unit_slot\);[\s\S]*?slot\.state = ChunkApplicationUnitState::Initialized;[\s\S]*?clear_official_chunk_initialization_bindings\(js\);\s*validate_intrinsic_descriptor_state\(js\);[\s\S]*?catch \(\.\.\.\) \{[\s\S]*?official_chunk_initialization_dirty = true;\s*clear_official_chunk_initialization_bindings\(js\);\s*throw;/u
  );
  assert.match(
    source,
    /void clear_official_chunk_initialization_bindings\(Runtime &js\) \{[\s\S]*?kOfficialChunkBeginBinding,[\s\S]*?kOfficialChunkPublishBinding,[\s\S]*?kOfficialChunkPublishEntryBinding,[\s\S]*?kOfficialChunkReadNamespaceBinding,[\s\S]*?kOfficialChunkReportThrownBinding,[\s\S]*?kOfficialChunkRequireBinding,[\s\S]*?remove_hidden_global\(js, binding\);[\s\S]*?remove_hidden_global\(js, kApplicationGlobalFacadeBinding\);/u
  );
  assert.match(
    source,
    /PropNameID::forAscii\(js, "requireOfficialChunkNamespace"\)[\s\S]*?try \{[\s\S]*?Official chunk requested an undeclared dependency[\s\S]*?\} catch \(\.\.\.\) \{\s*official_chunk_initialization_dirty = true;\s*throw;/u
  );
  assert.match(
    source,
    /PropNameID::forAscii\(js, "beginOfficialChunkNamespace"\)[\s\S]*?\} catch \(\.\.\.\) \{\s*official_chunk_initialization_dirty = true;\s*throw;[\s\S]*?PropNameID::forAscii\(js, "publishOfficialChunkNamespace"\)[\s\S]*?\} catch \(\.\.\.\) \{\s*official_chunk_initialization_dirty = true;\s*throw;/u
  );
  assert.match(
    source,
    /PropNameID::forAscii\(js, "readOfficialChunkNamespace"\)[\s\S]*?\} catch \(\.\.\.\) \{\s*official_chunk_initialization_dirty = true;\s*throw;[\s\S]*?PropNameID::forAscii\(js, "publishOfficialEntryNamespace"\)[\s\S]*?\} catch \(\.\.\.\) \{\s*official_chunk_initialization_dirty = true;\s*throw;/u
  );
  assert.match(
    source,
    /void retain_bridge_bootstrap_and_application_bindings\(Runtime &js\) \{[\s\S]*?auto retained_intrinsic_descriptor_state_validator = guest_function\(\s*js, global\.getProperty\(js, kIntrinsicDescriptorStateValidatorBinding\)\);[\s\S]*?auto retained_error_constructors =\s*capture_guest_initialization_error_constructors\(js\);[\s\S]*?remove_hidden_global\(js, kCapabilityBootstrapBinding\);\s*remove_hidden_global\(js, kApplicationGlobalFacadeBinding\);\s*remove_hidden_global\(js, kApplicationInitializerReporterBinding\);\s*remove_hidden_global\(js, kIntrinsicDescriptorStateValidatorBinding\);[\s\S]*?bridge_bootstrap = std::move\(retained_bootstrap\);\s*intrinsic_descriptor_state_validator =\s*std::move\(retained_intrinsic_descriptor_state_validator\);[\s\S]*?guest_initialization_error_constructors =\s*std::move\(retained_error_constructors\);/u
  );
  assert.match(
    source,
    /constexpr const char \*kIntrinsicDescriptorStateValidatorBinding =\s*"__convexWasmValidateIntrinsicDescriptorState";/u
  );
  assert.match(
    source,
    /void validate_intrinsic_descriptor_state\(Runtime &js\) \{[\s\S]*?intrinsic_descriptor_state_validator == nullptr[\s\S]*?const auto valid = intrinsic_descriptor_state_validator->call\(js\);[\s\S]*?!valid\.isBool\(\) \|\| !valid\.getBool\(\)[\s\S]*?"Intrinsic descriptor state is contaminated"/u
  );
  assert.match(
    source,
    /void validate_runtime_support_installer\(Runtime &js\) \{[\s\S]*?getPropertyAsFunction\(js, "getOwnPropertyDescriptor"\)[\s\S]*?kRuntimeSupportInstallerBinding[\s\S]*?!configurable\.getBool\(\)[\s\S]*?enumerable\.getBool\(\)[\s\S]*?writable\.getBool\(\)[\s\S]*?getPropertyAsFunction\(js, "isFrozen"\)/u
  );
  assert.match(
    source,
    /void verify_runtime_support_installation\(Runtime &js\) \{\s*if \(js\.global\(\)\.hasProperty\(js, kRuntimeSupportInstallerBinding\)\) \{\s*throw JSError\(js, "Runtime-support installer was retained after installation"\);/u
  );
  assert.match(
    source,
    /void clear_application_initialization_bindings\(Runtime &js\) \{\s*remove_hidden_global\(js, kApplicationGlobalFacadeBinding\);\s*remove_hidden_global\(js, kApplicationProfilePublisherBinding\);\s*remove_hidden_global\(js, kApplicationInitializerReporterBinding\);\s*\}/u
  );
  assert.match(
    source,
    /bridge_bootstrap->call\(js, install\);[\s\S]*?if \(guest_bridge == nullptr\)[\s\S]*?bridge_bootstrap\.reset\(\);/u
  );
  assert.match(
    source,
    /PropNameID::forAscii\(js, "installCapabilityBridge"\),\s*10,[\s\S]*?if \(count != 10\)/u
  );
  assert.match(source, /const int64_t capability_identity = convex_capability_current\(\)/u);
  assert.match(source, /\[capability_identity\]/u);
  assert.match(source, /convex_capability_sync_take/u);
  assert.match(
    source,
    /Value context_arguments\[\] = \{[\s\S]*?Value\(js, commit_ts_placeholder\),\s*\};[\s\S]*?size_t\{4\}/u
  );
  assert.match(
    source,
    /auto commit_ts_placeholder =\s*selected_commit_ts_placeholder\(js, entry_slot\);\s*auto context = invocation_context\(\s*js, capability_identity, udf_kind, commit_ts_placeholder\);/u
  );
  assert.match(
    source,
    /if \(invocation_abi == kSelectedInvocationAbiOfficialWrapper\) \{[\s\S]*?guest_bridge->invoke_registered_wrapper->call\([\s\S]*?size_t\{2\}\);[\s\S]*?\} else \{[\s\S]*?selected_commit_ts_placeholder/u
  );
  assert.doesNotMatch(source, /is_registered_wrapper|invocation_method/u);
  assert.match(source, /handler_udf_kind\(convex_wasm_selected_handler_udf_kind\(\)\)/u);
  assert.match(source, /\.call\(js, global, "__convexWasmCompileProfile", descriptor\)/u);
  assert.match(source, /descriptor\.setProperty\(js, "configurable", false\)/u);
  assert.match(source, /descriptor\.setProperty\(js, "set", std::move\(setter\)\)/u);
  assert.doesNotMatch(source, /descriptor\.setProperty\(js, "get"/u);
  assert.match(source, /compile_profile_output_slot->closed = true/u);
  assert.match(
    source,
    /application_slot\.exports = std::move\(compile_profile_output_slot->output\)/u
  );
  assert.match(
    source,
    /bool retained_runtime_state_is_valid\(\) \{[\s\S]*?#else\s*if \(guest_bridge == nullptr \|\| bridge_bootstrap != nullptr \|\|\s*intrinsic_descriptor_state_validator == nullptr \|\|\s*application_global_facade == nullptr \|\|\s*application_initializer_reporter == nullptr \|\|\s*guest_initialization_error_constructors == nullptr \|\|\s*compile_profile_output_slot == nullptr \|\|\s*!compile_profile_output_slot->closed \|\|\s*compile_profile_output_slot->output != nullptr \|\|[\s\S]*?bridge_unit_initialization_count != 1 \|\|\s*formatter_unit_initialization_count != 1/u
  );
  assert.match(source, /convex_wasm_application_entry_count\(\)/u);
  assert.match(source, /convex_wasm_application_factory_by_slot\(int32_t entry_slot\)/u);
  assert.match(source, /const int32_t entry_slot = convex_wasm_selected_entry_slot\(\)/u);
  assert.match(
    source,
    /if \(package_entry_count <= 0 \|\|\s*package_entry_count > kMaxApplicationEntrySlots \|\| entry_slot < 0 \|\|\s*entry_slot >= package_entry_count \|\|[\s\S]*?export_name == nullptr \|\| udf_kind == nullptr \|\|\s*!valid_invocation_abi\(invocation_abi\)\)/u
  );
  assert.match(
    source,
    /std::array<ApplicationExportSlot, kMaxApplicationEntrySlots>\s*application_export_slots/u
  );
  assert.match(
    source,
    /const bool declared = entry_slot < declared_application_entry_count;[\s\S]*?const bool initialized = application_slot\.exports != nullptr \|\|\s*application_slot\.unit_initialization_count != 0;\s*if \(declared\s*\? initialized &&\s*\(application_slot\.exports == nullptr \|\|\s*application_slot\.unit_initialization_count != 1\)\s*: application_slot\.exports != nullptr \|\|\s*application_slot\.unit_initialization_count != 0\)/u
  );
  assert.match(
    source,
    /auto selected_export =\s*selected_application_export\(js, entry_slot, export_name\)/u
  );
  assert.match(
    source,
    /js_error_phase = JSErrorPhase::ActivateSdkFacade;\s*guest_bridge->activate_sdk->call\(\s*js, String::createFromAscii\(js, udf_kind\)\);\s*invocation_activated = true;/u
  );
  assert.match(
    source,
    /js_error_phase = JSErrorPhase::CleanupInvocation;\s*auto cleanup_result = guest_bridge->cleanup->call\(js\);[\s\S]*?invocation_activated = false;\s*const int32_t host_abandoned = convex_async_operation_cancel_all\(\);/u
  );
  assert.match(
    source,
    /if \(invocation_activated && guest_bridge != nullptr\) \{\s*try \{\s*auto cleanup_result = guest_bridge->cleanup->call\(js\);[\s\S]*?const int32_t host_abandoned = convex_async_operation_cancel_all\(\);/u
  );
  assert.match(
    source,
    /getProperty\(js, kCommitTsPlaceholderExportName\)[\s\S]*?Compile-profile SDK commit timestamp placeholder is invalid/u
  );
  assert.match(source, /Compile-profile output slot is closed/u);
  assert.match(source, /Compile-profile output was already published/u);
  assert.match(source, /convex_wasm_selected_handler_export_name\(\)/u);
  assert.match(source, /convex_wasm_selected_invocation_abi\(\)/u);
  assert.match(
    source,
    /close_compile_profile_output\(js, initialization_slot\);[\s\S]*?convex_wasm_application_invocation_abi_by_slot\([\s\S]*?if \(initialization_invocation_abi ==\s*kSelectedInvocationAbiLegacyHandler\) \{\s*\(void\)selected_commit_ts_placeholder\(js, initialization_slot\);/u
  );
  assert.doesNotMatch(
    source,
    /extern "C" int32_t convex_wasm_select_entry\(uint64_t entry_selector\)/u
  );
  assert.match(source, /case kSelectedUdfKindQuery:[\s\S]*?return "query"/u);
  assert.match(source, /case kSelectedUdfKindMutation:[\s\S]*?return "mutation"/u);
  assert.match(source, /~SelectedEntryLease\(\) \{ convex_wasm_clear_selected_entry\(\); \}/u);
  assert.doesNotMatch(source, /getById(?:Alternate)?/u);
  assert.doesNotMatch(source, /kDatabaseGet(?:Alternate)?EntrySelector/u);
  assert.doesNotMatch(source, /return "default"/u);
  assert.match(source, /if \(bridge_unit_initialization_count != 1\)/u);
  assert.match(source, /if \(formatter_unit_initialization_count != 1\)/u);
  assert.match(source, /if \(application_slot\.unit_initialization_count != 1\)/u);
  assert.equal(source.match(/_sh_initialize_units\(/gu)?.length, 2);
  assert.equal(source.match(/_sh_unit_init_guarded\(/gu)?.length ?? 0, 0);
  assert.equal(source.match(/evaluate_application_initializer\(/gu)?.length, 4);
  assert.match(
    source,
    /InitializeOfficialEntryPublicationUnit;[\s\S]*?expose_official_entry_publication_bindings\([\s\S]*?evaluate_application_initializer\(js, publication_factory, publication_unit_slot\);/u
  );
  assert.match(
    source,
    /void reset_runtime_state\(\) \{[\s\S]*?guest_initialization_error_constructors\.reset\(\);\s*guest_initialization_report_count = 0;[\s\S]*?_sh_done\(runtime\);/u
  );
  assert.match(
    source,
    /js_error_phase = JSErrorPhase::ValidateIntrinsicDescriptorState;\s*validate_intrinsic_descriptor_state\(js\);\s*js_error_phase = JSErrorPhase::InstallGuestBridge;[\s\S]*?js_error_phase = JSErrorPhase::ValidatePreparationAuthority;\s*if \(convex_capability_current\(\) != 0\) \{\s*reset_runtime_state\(\);\s*return static_cast<int32_t>\(js_error_phase\);\s*\}[\s\S]*?js_error_phase = JSErrorPhase::ValidatePreparationQuiescence;\s*if \(convex_async_operation_cancel_all\(\) != 0\) \{\s*reset_runtime_state\(\);\s*return static_cast<int32_t>\(js_error_phase\);\s*\}[\s\S]*?catch \(const JSError &\) \{\s*caught_status = static_cast<int32_t>\(js_error_phase\);\s*\}[\s\S]*?reset_runtime_state\(\);\s*return caught_status;/u
  );
  assert.match(
    prepareSource,
    /extern "C" int convex_wasm_udf_prepare_selected_entry\(void\)[\s\S]*?SelectedEntryLease selected_entry_lease;[\s\S]*?return 0;/u
  );
  assert.match(
    runSource,
    /if \(runtime == nullptr \|\|[\s\S]*?!retained_runtime_state_is_valid\(\) \|\|\s*!selected_entry_is_prepared\(entry_slot\)\) \{[\s\S]*?return 9;/u
  );
  assert.doesNotMatch(
    runSource,
    /initialize_runtime\(|reserve_compile_profile_output\(|_sh_initialize_units\(|initialize_official_chunk_entry\(/u
  );
  assert.match(
    source,
    /if \(runtime == nullptr\) \{\s*if \(!retained_runtime_state_is_empty\(\)\) \{\s*reset_runtime_state\(\);\s*return 9;\s*\}\s*runtime = initialize_runtime\(\);/u
  );
  assert.match(
    source,
    /void reset_runtime_state\(\) \{[\s\S]*?guest_bridge\.reset\(\);[\s\S]*?bridge_bootstrap\.reset\(\);[\s\S]*?intrinsic_descriptor_state_validator\.reset\(\);[\s\S]*?application_global_facade\.reset\(\);[\s\S]*?application_initializer_reporter\.reset\(\);[\s\S]*?compile_profile_output_slot\.reset\(\);[\s\S]*?application_slot\.exports\.reset\(\);[\s\S]*?application_slot\.unit_initialization_count = 0;[\s\S]*?bridge_unit_initialization_count = 0;\s*formatter_unit_initialization_count = 0;\s*declared_application_entry_count = 0;[\s\S]*?convex_wasm_clear_selected_entry\(\);[\s\S]*?_sh_done\(runtime\);\s*runtime = nullptr;/u
  );
  assert.match(
    source,
    /extern "C" void convex_wasm_udf_destroy_runtime\(void\) \{\s*reset_runtime_state\(\);\s*\}/u
  );
  const guestBridge = source.match(/struct GuestBridge \{([\s\S]*?)\n\};/u);
  assert.ok(guestBridge);
  assert.equal(guestBridge[1].match(/std::shared_ptr<Function>/gu)?.length, 10);
  assert.match(guestBridge[1], /std::shared_ptr<Function> activate_sdk;/u);
  assert.match(
    source,
    /invocation_abi == kSelectedInvocationAbiOfficialWrapper\s*\? guest_bridge->read_tagged_request->call\(js\)\s*: guest_bridge->read_request->call\(js\)/u
  );
  assert.doesNotMatch(guestBridge[1], /entry_selector|handler/u);
  assert.doesNotMatch(source, /guest_bridge->entry_selector/u);
  assert.doesNotMatch(source, /getProperty[^\n]*__convexWasmCompileProfile/u);
  assert.doesNotMatch(
    source,
    /__convexWasmCompileProfileTargetBootstrap|__convexWasmSelectedHandler/u
  );
  assert.doesNotMatch(source, /setProperty\(js, "convex_capability/u);
});

test("runtime event loops settle ready host completions before one microtask checkpoint", () => {
  const runtimeLoops = [
    {
      cleanupMarker: "js_error_phase = JSErrorPhase::CleanupInvocation;",
      source: readFileSync(
        new URL("./convex-wasm-native-capability-runtime-main.cpp", import.meta.url),
        "utf8"
      ),
    },
    {
      cleanupMarker: "guest_cleanup_attempted = true;",
      source: readFileSync(new URL("./convex-wasm-runtime-main.cpp", import.meta.url), "utf8"),
    },
  ];

  for (const { cleanupMarker, source } of runtimeLoops) {
    const waitAny = source.indexOf(
      "const int32_t operation_handle = convex_async_operation_wait_any();"
    );
    const initialSettle = source.indexOf("settle_operation(operation_handle);", waitAny);
    const pollReady = source.indexOf("convex_async_operation_poll_ready()", initialSettle);
    const readySettle = source.indexOf("settle_operation(ready_operation_handle);", pollReady);
    const checkpoint = source.indexOf("js.drainMicrotasks()", readySettle);
    const cleanup = source.indexOf(cleanupMarker, checkpoint);

    assert.ok(waitAny >= 0);
    assert.ok(initialSettle > waitAny);
    assert.ok(pollReady > initialSettle);
    assert.ok(readySettle > pollReady);
    assert.ok(checkpoint > readySettle);
    assert.ok(cleanup > checkpoint);
    assert.equal(source.match(/convex_async_operation_poll_ready\(\)/gu)?.length, 1);

    const batch = source.slice(waitAny, cleanup);
    assert.equal(batch.match(/settle_operation\(/gu)?.length, 2);
    assert.equal(batch.match(/js\.drainMicrotasks\(\)/gu)?.length, 1);
    assert.equal(
      source.slice(pollReady, checkpoint).match(/js\.drainMicrotasks\(\)/gu)?.length ?? 0,
      0
    );
    assert.match(
      source.slice(pollReady, checkpoint),
      /convex_async_operation_poll_ready\(\);\s*if \(ready_operation_handle == 0\) \{\s*break;\s*\}\s*if \(ready_operation_handle < 0\) \{\s*(?:throw InvocationFailure\{3\};|return 3;|return error_exit\(js, cleanup, guest_cleanup_attempted,\s*host_cancel_attempted, 3\);)\s*\}\s*settle_operation\(ready_operation_handle\);\s*\}/u
    );
  }
});
