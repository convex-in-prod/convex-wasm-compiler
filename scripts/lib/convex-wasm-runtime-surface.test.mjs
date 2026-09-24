import assert from "node:assert/strict";
import test from "node:test";
import { runInNewContext } from "node:vm";

import ts from "typescript";

import { renderConvexWasmIntrinsicHardeningPrelude } from "./convex-wasm-intrinsic-hardening.mjs";
import {
  assertConvexWasmTargetRuntimeSurface,
  convexWasmApplicationGlobalThisBinding,
  convexWasmApplicationInstallRuntimeSupportBinding,
  convexWasmApplicationPublishCompileProfileBinding,
  convexWasmApplicationReportThrownBinding,
  convexWasmTargetRuntimeSurfacePolicy,
  renderConvexWasmApplicationGlobalFacade,
  renderConvexWasmTargetRuntimeGlobalPrelude,
} from "./convex-wasm-runtime-surface.mjs";

test("application source cannot capture host-owned initialization handoffs", () => {
  for (const source of [
    `void ${convexWasmApplicationPublishCompileProfileBinding};`,
    `void ${convexWasmApplicationInstallRuntimeSupportBinding};`,
    `void ${convexWasmApplicationReportThrownBinding};`,
    `const ${convexWasmApplicationGlobalThisBinding} = {};`,
    `let ${convexWasmApplicationPublishCompileProfileBinding};`,
    `let ${convexWasmApplicationInstallRuntimeSupportBinding};`,
    `var ${convexWasmApplicationReportThrownBinding};`,
    `function ${convexWasmApplicationPublishCompileProfileBinding}() {}`,
    `class ${convexWasmApplicationReportThrownBinding} {}`,
    `function unreachable(${convexWasmApplicationGlobalThisBinding}) { return ${convexWasmApplicationGlobalThisBinding}; }`,
    `const {value: ${convexWasmApplicationPublishCompileProfileBinding}} = {value: null};`,
    `try {} catch (${convexWasmApplicationReportThrownBinding}) {}`,
  ]) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(source),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "reserved-initialization-handoff",
      source
    );
  }

  assert.doesNotThrow(() =>
    assertConvexWasmTargetRuntimeSurface(
      `const facade = ${convexWasmApplicationGlobalThisBinding}; void facade.Date;`
    )
  );
});

function dateHarness({ harden = false } = {}) {
  const prelude = renderConvexWasmTargetRuntimeGlobalPrelude();
  const start = prelude.indexOf("const __convexTargetNativeDate: any =");
  const end = prelude.indexOf("function __convexMathRandom(): number", start);
  assert.ok(start >= 0 && end > start);

  let capabilityIdentity = 0;
  let invocationUnixTimestampMs = 0;
  let timestampReads = 0;
  const sandbox = {
    __convexTargetHostCapabilityCurrent: () => capabilityIdentity,
    __convexTargetHostInvocationUnixTimestampMs: () => {
      assert.ok(capabilityIdentity > 0, "timestamp import ran without an active capability");
      timestampReads += 1;
      return invocationUnixTimestampMs;
    },
  };
  runInNewContext(
    `
for (const name of ["TextDecoder", "TextEncoder", "atob", "btoa", "queueMicrotask"]) {
  if (Object.getOwnPropertyDescriptor(globalThis, name) === undefined) {
    Object.defineProperty(globalThis, name, {
      configurable: true,
      value: function ConvexWasmHarnessGlobal() {},
      writable: true,
    });
  }
}
globalThis.__convexTargetGlobal = globalThis;
globalThis.__convexTestNativeDate = Date;
globalThis.__convexTestNativeDateNowDescriptor =
  Object.getOwnPropertyDescriptor(Date, "now");
globalThis.__convexTestNativeDateConstructorDescriptor =
  Object.getOwnPropertyDescriptor(Date.prototype, "constructor");
globalThis.__convexTestNativeDateGlobalDescriptor =
  Object.getOwnPropertyDescriptor(globalThis, "Date");
`,
    sandbox
  );
  const javascript = ts.transpileModule(prelude.slice(start, end), {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  runInNewContext(javascript, sandbox);
  if (harden) {
    const hardeningJavascript = ts.transpileModule(renderConvexWasmIntrinsicHardeningPrelude(), {
      compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
    }).outputText;
    runInNewContext(hardeningJavascript, sandbox);
  }

  return {
    evaluate: (source) => runInNewContext(source, sandbox),
    evaluateTypeScript(source) {
      const output = ts.transpileModule(source, {
        compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
      }).outputText;
      return runInNewContext(output, sandbox);
    },
    setInvocation(identity, timestamp) {
      capabilityIdentity = identity;
      invocationUnixTimestampMs = timestamp;
    },
    timestampReads: () => timestampReads,
  };
}

test("Date source admission is independent of call, member, alias, spread, and module shape", () => {
  assert.doesNotThrow(() =>
    assertConvexWasmTargetRuntimeSurface(`
const inputs = [2024, 0, 2];
const DateAlias = Date;
const DateFromGlobal = ${convexWasmApplicationGlobalThisBinding}["Date"];
const {Date: DestructuredDate} = ${convexWasmApplicationGlobalThisBinding};
const now = DateAlias.now;
const parse = DateAlias["parse"];
const utc = DateAlias.UTC;
const prototype = DateAlias.prototype;
const importedAt = now();
const constructedAtImport = new DateAlias();
const calledAtImport = DateAlias();
function read() {
  const explicit = new DateAlias(0);
  const spread = new DateAlias(...inputs);
  return [
    DateAlias,
    DateFromGlobal,
    DestructuredDate,
    now.call(DateAlias),
    parse("2024-01-02T00:00:00.000Z"),
    utc(2024, 0, 2),
    prototype,
    explicit instanceof DateAlias,
    spread,
    importedAt,
    constructedAtImport,
    calledAtImport,
  ];
}
`)
  );

  for (const source of ["Date = class {};", "Date.now = () => 0;"]) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(source),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      source
    );
  }
});

test("Date facade delegates explicit construction and native reflective behavior", () => {
  const runtime = dateHarness();
  runtime.setInvocation(11, 1_700_000_000_123);

  assert.equal(runtime.evaluate("Date.parse === __convexTestNativeDate.parse"), true);
  assert.equal(runtime.evaluate("Date.UTC === __convexTestNativeDate.UTC"), true);
  assert.equal(runtime.evaluate("Date.prototype === __convexTestNativeDate.prototype"), true);
  assert.equal(runtime.evaluate("Date.prototype.constructor === Date"), true);
  assert.equal(runtime.evaluate("Date.now === Date.now"), true);
  assert.equal(
    runtime.evaluate('Object.getOwnPropertyDescriptor(Date, "now").value === Date.now'),
    true
  );
  assert.equal(runtime.evaluate("Object.isFrozen(Date.now)"), true);
  assert.equal(runtime.evaluate("Date.now.name"), "now");
  assert.equal(runtime.evaluate("Date.now.length"), 0);
  assert.equal(
    runtime.evaluate(`(() => {
const current = Object.getOwnPropertyDescriptor(Date, "now");
const native = __convexTestNativeDateNowDescriptor;
return current.configurable === native.configurable &&
  current.enumerable === native.enumerable &&
  current.writable === native.writable &&
  current.value === Date.now;
})()`),
    true
  );
  assert.equal(
    runtime.evaluate(`(() => {
const current = Object.getOwnPropertyDescriptor(Date.prototype, "constructor");
const native = __convexTestNativeDateConstructorDescriptor;
return current.configurable === native.configurable &&
  current.enumerable === native.enumerable &&
  current.writable === native.writable &&
  current.value === Date;
})()`),
    true
  );
  assert.equal(
    runtime.evaluate(`(() => {
const current = Object.getOwnPropertyDescriptor(globalThis, "Date");
const native = __convexTestNativeDateGlobalDescriptor;
return current.configurable === native.configurable &&
  current.enumerable === native.enumerable &&
  current.writable === native.writable &&
  current.value === Date;
})()`),
    true
  );
  assert.throws(
    () => runtime.evaluate("new Date.now()"),
    (error) => error?.name === "TypeError"
  );

  for (const source of [
    "new Date(0).getTime() === new __convexTestNativeDate(0).getTime()",
    'new Date("2024-01-02T03:04:05.006Z").getTime() === new __convexTestNativeDate("2024-01-02T03:04:05.006Z").getTime()',
    "new Date(undefined).getTime() !== new Date(undefined).getTime()",
    "new Date(new __convexTestNativeDate(1234)).getTime() === 1234",
    "new Date(2024, 1, 2, 3, 4, 5, 6).getTime() === new __convexTestNativeDate(2024, 1, 2, 3, 4, 5, 6).getTime()",
    "new Date(...[2024, 1, 2, 3, 4, 5, 6]).getTime() === new __convexTestNativeDate(...[2024, 1, 2, 3, 4, 5, 6]).getTime()",
    'Date.parse("2024-01-02T03:04:05.006Z") === __convexTestNativeDate.parse("2024-01-02T03:04:05.006Z")',
    "Date.UTC(2024, 1, 2, 3, 4, 5, 6) === __convexTestNativeDate.UTC(2024, 1, 2, 3, 4, 5, 6)",
  ]) {
    assert.equal(runtime.evaluate(source), true, source);
  }

  assert.equal(
    runtime.evaluate(`(() => {
let coercions = 0;
const input = {valueOf() { coercions += 1; return 321; }};
const result = new Date(input);
return result.getTime() === 321 && coercions === 1;
})()
`),
    true
  );
  assert.throws(
    () => runtime.evaluate("new Date(Symbol('invalid'))"),
    (error) => error?.name === "TypeError"
  );
  assert.equal(
    runtime.evaluate(`(() => {
const DateAlias = Date;
const value = Reflect.construct(DateAlias, [456]);
return value.getTime() === 456 && value instanceof DateAlias && value instanceof __convexTestNativeDate;
})()
`),
    true
  );
  assert.equal(
    runtime.evaluate(`(() => {
class DerivedDate extends Date {}
const value = new DerivedDate(789);
return value.getTime() === 789 && value instanceof DerivedDate && value instanceof Date;
})()
`),
    true
  );
  assert.equal(runtime.timestampReads(), 0);
});

test("Date invocation-time paths share the active capability timestamp across reuse", () => {
  const runtime = dateHarness();
  const firstTimestamp = 1_700_000_000_123;
  runtime.setInvocation(21, firstTimestamp);
  runtime.evaluate(`
globalThis.__convexRetainedDate = Date;
globalThis.__convexRetainedDateNow = Date.now;
`);

  assert.equal(runtime.evaluate("Date.now()"), firstTimestamp);
  assert.equal(runtime.evaluate("Date['now']()"), firstTimestamp);
  assert.equal(runtime.evaluate("__convexRetainedDateNow.call(null)"), firstTimestamp);
  assert.equal(runtime.evaluate("new Date().getTime()"), firstTimestamp);
  assert.equal(runtime.evaluate("new Date(...[]).getTime()"), firstTimestamp);
  assert.equal(runtime.evaluate("new __convexRetainedDate().getTime()"), firstTimestamp);
  assert.equal(
    runtime.evaluate("Date()"),
    runtime.evaluate("new __convexTestNativeDate(1700000000123).toString()")
  );
  for (const source of [
    "Date(0)",
    "Date(undefined)",
    "Date(2024, 0, 2, 3, 4, 5, 6)",
    "Date(...[2024, 0, 2])",
    "Reflect.apply(Date, null, [0])",
  ]) {
    assert.equal(
      runtime.evaluate(source),
      runtime.evaluate("new __convexTestNativeDate(1700000000123).toString()"),
      source
    );
  }
  assert.equal(
    runtime.evaluate(`
let evaluations = 0;
let coercions = 0;
const input = {valueOf() { coercions += 1; return 0; }};
Date((evaluations += 1, input));
[evaluations, coercions].join(",");
`),
    "1,0"
  );
  assert.equal(
    runtime.evaluate(`(() => {
class DerivedDate extends Date {}
const value = new DerivedDate();
return value.getTime() === 1700000000123 &&
  value instanceof DerivedDate &&
  value instanceof Date &&
  value instanceof __convexTestNativeDate;
})()`),
    true
  );

  const readsBeforeRevocation = runtime.timestampReads();
  runtime.setInvocation(0, 0);
  for (const source of [
    "__convexRetainedDateNow()",
    "new __convexRetainedDate()",
    "__convexRetainedDate()",
  ]) {
    assert.throws(() => runtime.evaluate(source), /Invocation capability is unavailable/u, source);
  }
  assert.equal(runtime.timestampReads(), readsBeforeRevocation);
  assert.equal(runtime.evaluate("new __convexRetainedDate(987).getTime()"), 987);

  const secondTimestamp = 1_800_000_000_456;
  runtime.setInvocation(22, secondTimestamp);
  assert.equal(runtime.evaluate("__convexRetainedDateNow()"), secondTimestamp);
  assert.equal(runtime.evaluate("new __convexRetainedDate().getTime()"), secondTimestamp);
  assert.equal(
    runtime.evaluate("__convexRetainedDate()"),
    runtime.evaluate("new __convexTestNativeDate(1800000000456).toString()")
  );
  assert.equal(
    runtime.evaluate("__convexRetainedDate(0)"),
    runtime.evaluate("new __convexTestNativeDate(1800000000456).toString()")
  );
});

test("Date prelude keeps wall time separate from performance time and call-site shape", () => {
  const prelude = renderConvexWasmTargetRuntimeGlobalPrelude();
  const start = prelude.indexOf("const __convexTargetNativeDate: any =");
  const end = prelude.indexOf("function __convexMathRandom(): number", start);
  assert.ok(start >= 0 && end > start);
  const datePrelude = prelude.slice(start, end);

  assert.match(datePrelude, /new __convexTargetGlobal\.Proxy\(/u);
  assert.match(datePrelude, /apply\(target, _thisArgument, _argumentsList\)/u);
  assert.match(datePrelude, /if \(argumentsList\.length === 0\)/u);
  assert.match(datePrelude, /Reflect\.construct\(target, argumentsList, newTarget\)/u);
  assert.doesNotMatch(datePrelude, /performance/u);
});

test("application globalThis Date flow resolves to the same capability proxy", () => {
  const runtime = dateHarness();
  runtime.evaluate(`
globalThis.performance = {};
globalThis.process = {};
globalThis.crypto = {};
globalThis.setTimeout = () => {};
globalThis.setInterval = () => {};
globalThis.clearTimeout = () => {};
globalThis.clearInterval = () => {};
`);
  runtime.evaluateTypeScript(renderConvexWasmApplicationGlobalFacade());
  runtime.setInvocation(25, 1_850_000_000_654);

  assert.equal(runtime.evaluate(`${convexWasmApplicationGlobalThisBinding}.Date === Date`), true);
  assert.equal(
    runtime.evaluate(`${convexWasmApplicationGlobalThisBinding}["Date"].now()`),
    1_850_000_000_654
  );
  assert.equal(
    runtime.evaluate(`(() => {
      const {Date: DateAlias} = ${convexWasmApplicationGlobalThisBinding};
      return DateAlias === Date && new DateAlias(1357).getTime() === 1357;
    })()`),
    true
  );
});

test("application global facade retains application state while built-ins stay immutable", () => {
  const runtime = dateHarness();
  runtime.evaluate(`
globalThis.Convex = {};
globalThis.console = {};
globalThis.performance = {};
globalThis.process = {};
globalThis.crypto = {};
globalThis.setTimeout = () => {};
globalThis.setInterval = () => {};
globalThis.clearTimeout = () => {};
globalThis.clearInterval = () => {};
`);
  runtime.evaluateTypeScript(renderConvexWasmApplicationGlobalFacade());

  assert.deepEqual(
    Array.from(
      runtime.evaluate(`(() => {
      const facade = ${convexWasmApplicationGlobalThisBinding};
      const state = facade.__applicationOwnedState ?? (facade.__applicationOwnedState = {count: 0});
      state.count += 1;
      return [
        Object.isExtensible(facade),
        Object.getPrototypeOf(facade) === null,
        facade.__applicationOwnedState === state,
        state.count,
      ];
    })()`)
    ),
    [true, true, true, 1]
  );
  assert.equal(
    runtime.evaluate(
      `${convexWasmApplicationGlobalThisBinding}.__applicationOwnedState.count += 1`
    ),
    2
  );

  for (const name of ["Object", "Date", "Convex", "setTimeout"]) {
    assert.deepEqual(
      Array.from(
        runtime.evaluate(`(() => {
        const descriptor = Object.getOwnPropertyDescriptor(
          ${convexWasmApplicationGlobalThisBinding},
          ${JSON.stringify(name)},
        );
        return [
          Object.hasOwn(${convexWasmApplicationGlobalThisBinding}, ${JSON.stringify(name)}),
          descriptor.configurable,
          descriptor.writable,
        ];
      })()`)
      ),
      [true, false, false],
      name
    );
    assert.throws(
      () =>
        runtime.evaluate(
          `"use strict"; ${convexWasmApplicationGlobalThisBinding}[${JSON.stringify(name)}] = undefined;`
        ),
      (error) => error?.name === "TypeError",
      `${name} overwrite`
    );
    assert.throws(
      () =>
        runtime.evaluate(
          `"use strict"; delete ${convexWasmApplicationGlobalThisBinding}[${JSON.stringify(name)}];`
        ),
      (error) => error?.name === "TypeError",
      `${name} delete`
    );
  }
});

test("Date facade remains reflective after intrinsic hardening prevents extension on its inheritance participants", () => {
  const runtime = dateHarness({ harden: true });
  runtime.setInvocation(31, 1_900_000_000_789);

  assert.equal(runtime.evaluate("Object.isExtensible(Date)"), false);
  assert.equal(runtime.evaluate("Object.isFrozen(Date)"), false);
  assert.equal(runtime.evaluate("Object.isExtensible(Date.prototype)"), false);
  assert.equal(runtime.evaluate("Object.isFrozen(Date.prototype)"), false);
  assert.equal(runtime.evaluate("Object.isFrozen(Date.now)"), true);
  assert.equal(runtime.evaluate("Date.now === Date.now"), true);
  assert.equal(
    runtime.evaluate('Object.getOwnPropertyDescriptor(Date, "now").value === Date.now'),
    true
  );
  assert.equal(runtime.evaluate("Date.prototype.constructor === Date"), true);
  assert.equal(runtime.evaluate("new Date().getTime()"), 1_900_000_000_789);
  assert.equal(runtime.evaluate("new Date(2468).getTime()"), 2468);
});

test("Date runtime policy authenticates the native and invocation-owned split", () => {
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
  for (const code of [
    "date-ambient-object-flow",
    "date-function-call",
    "date-import-time",
    "date-multiple-input-constructor",
    "date-now-indirect",
    "date-spread-constructor",
    "date-zero-argument-constructor",
  ]) {
    assert.equal(Object.hasOwn(convexWasmTargetRuntimeSurfacePolicy.gaps, code), false, code);
  }
  assert.deepEqual(
    convexWasmTargetRuntimeSurfacePolicy.globalObject.application.capabilityGlobals,
    ["Convex", "Date", "console", "crypto", "performance", "process"]
  );
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.convexSdkFacade, {
    implementation: "frozen-closed-capability-request-facade",
    methods: ["asyncSyscall", "jsSyscall", "syscall"],
    moduleInitializationAuthority: false,
    retainedContextIsolation: {
      gap: "sdk-retained-context-isolation",
      state: "gap",
    },
    state: "implemented",
  });
});

test("console source admission accepts canonical methods and rejects ambient mutation", () => {
  assert.doesNotThrow(() =>
    assertConvexWasmTargetRuntimeSurface(`
console.debug("debug");
console.error("error");
console.info("info");
console.log("log");
console.warn("warn");
const retained = console.log;
retained("retained");
${convexWasmApplicationGlobalThisBinding}.console.warn("facade");
`)
  );
  for (const source of [
    "console = {};",
    "console.log = () => {};",
    "delete console.warn;",
    `${convexWasmApplicationGlobalThisBinding}.console = {};`,
    `${convexWasmApplicationGlobalThisBinding}.console.error = () => {};`,
  ]) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(source),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      source
    );
  }
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.console, {
    formatting: {
      browserBundleSha256: "b2fc88e4e9d5c776bca6384c7d7a1411ba7350866d9974055bc10dcfc423e190",
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
  });
  assert.equal(Object.hasOwn(convexWasmTargetRuntimeSurfacePolicy.gaps, "console-runtime"), false);
});

test("admits shared deterministic runtime globals through every ordinary read shape", () => {
  for (const source of [
    `const error = new DOMException("stopped", "AbortError");
     return [error.name, error instanceof DOMException];`,
    `const URLAlias = URL;
     return URLAlias.parse(args.value, args.base);`,
    `const Params = URLSearchParams;
     return new Params(args.entries).toString();`,
    `const DateTimeFormat = Intl.DateTimeFormat;
     return new DateTimeFormat("en-US", {timeZone: "UTC"}).format(args.timestamp);`,
    `const NumberFormat = Intl["NumberFormat"];
     return new NumberFormat("ru-RU", {maximumFractionDigits: 2}).format(args.value);`,
    `return ${convexWasmApplicationGlobalThisBinding}.DOMException;`,
    `return new ${convexWasmApplicationGlobalThisBinding}.URL(args.value, args.base);`,
    `const facade = ${convexWasmApplicationGlobalThisBinding};
     return new facade[args.constructorName](args.value);`,
  ]) {
    assert.doesNotThrow(() =>
      assertConvexWasmTargetRuntimeSurface(`function selected(args) { ${source} }`)
    );
  }
  for (const name of ["DOMException", "Intl", "URL", "URLSearchParams"]) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(`function selected() { ${name} = Object; }`),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      name
    );
  }
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.webStandards.globals, [
    "DOMException",
    "URL",
    "URLSearchParams",
  ]);
  assert.equal(convexWasmTargetRuntimeSurfacePolicy.webStandards.state, "implemented");
  assert.match(
    convexWasmTargetRuntimeSurfacePolicy.webStandards.runtimeSupportIdentitySha256,
    /^[a-f0-9]{64}$/u
  );
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.intl.locales, [
    "en",
    "en-CA",
    "en-US",
    "ru-RU",
  ]);
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.intl.timeZoneData, {
    aliases: 162,
    canonicalZones: 436,
    dataSha256: "ab71488450bcde8a12089115a1efc8f0e4da4ee49eb134230805fab384095495",
    licenseSha256: "6154bb6c9ac34c2ac3ff4217c948fd6b431e3e122a3428d665bebd6f730e9f69",
    sourceSha256: "af5c1d3bebe136d372c131bb1a45725f955a8cc2a5ae2fc5a31d3b372e145f49",
    version: "2026c",
  });
  assert.equal(convexWasmTargetRuntimeSurfacePolicy.intl.state, "implemented");
});
