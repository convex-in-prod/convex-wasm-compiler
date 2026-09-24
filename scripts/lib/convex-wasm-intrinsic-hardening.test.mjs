import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { runInNewContext } from "node:vm";

import ts from "typescript";

import {
  convexWasmIntrinsicDescriptorStateValidatorBinding,
  convexWasmIntrinsicHardeningPolicy,
  convexWasmIntrinsicHardeningPolicySha256,
  convexWasmIntrinsicHardeningSourceSha256,
  renderConvexWasmIntrinsicHardeningPrelude,
} from "./convex-wasm-intrinsic-hardening.mjs";

function executableSource(source) {
  return ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
  }).outputText;
}

const probeSource = String.raw`
function __attemptIntrinsicMutation(operation: any): boolean {
  try {
    return operation() === false;
  } catch (_error) {
    return true;
  }
}

function __attemptDynamicCode(operation: any): boolean {
  try {
    operation();
    return false;
  } catch (_error) {
    return true;
  }
}

const __hardeningDynamicGlobal: any = globalThis;
class __hardeningArrayConstructor extends Array<any> {}
__hardeningArrayConstructor = __hardeningDynamicGlobal.Array;
const __hardeningArrayPrototype: any = __hardeningDynamicGlobal.Object.getPrototypeOf([]);
const __hardeningObjectPrototype: any = __hardeningDynamicGlobal.Object.getPrototypeOf({});
const __hardeningOriginalPush: any = __hardeningArrayPrototype.push;
const __hardeningInitializedState: any = { count: 0 };
__hardeningInitializedState.count += 1;
const __hardeningFunctionLiteral: any = function(value: any): any { return value + 1; };
const __hardeningAsyncFunctionLiteral: any = async function(execution: any) {
  execution.ran = true;
  return 7;
};
const __hardeningGeneratorFunctionLiteral: any = function*(): any {
  yield 8;
  return 9;
};
const __hardeningMethod: any = new __hardeningDynamicGlobal.Map().set;
const __hardeningAliasedConstructor: any = __hardeningDynamicGlobal.parseInt.constructor;
const __hardeningFunctionPrototype: any =
  __hardeningDynamicGlobal.Object.getPrototypeOf(__hardeningDynamicGlobal.parseInt);
const __hardeningPrototypeConstructor: any = __hardeningFunctionPrototype.constructor;
const __hardeningReflectedConstructor: any =
  __hardeningDynamicGlobal.Reflect.get(__hardeningDynamicGlobal.parseInt, "constructor");
const __hardeningDescriptorConstructor: any =
  __hardeningDynamicGlobal.Object.getOwnPropertyDescriptor(
    __hardeningFunctionPrototype,
    "constructor",
  ).value;
const __hardeningFunctionName: any = __hardeningDynamicGlobal.Symbol.for("functionName");
__hardeningFunctionLiteral.useCount = 0;

function __hardeningCreateApi(pathParts: Array<string> = []): any {
  const handler: any = {
    get(_target: any, property: any): any {
      if (typeof property === "string") {
        const nextParts = [...pathParts, property];
        return __hardeningCreateApi(nextParts);
      }
      if (property === __hardeningFunctionName) {
        const modulePath = pathParts.slice(0, -1).join("/");
        return modulePath + ":" + pathParts[pathParts.length - 1];
      }
      return undefined;
    },
  };
  return new __hardeningDynamicGlobal.Proxy({}, handler);
}

function __runIntrinsicProbe(): any {
  const object: any = {};
  const localPrototype: any = { inherited: 3 };
  const functionHasOwn: any =
    __hardeningDynamicGlobal.Function.prototype.call.bind(
      __hardeningDynamicGlobal.Object.prototype.hasOwnProperty,
    );
  const attempts = {
    defineProperty: __attemptIntrinsicMutation(() => {
      __hardeningDynamicGlobal.Object.defineProperty(__hardeningArrayPrototype, "leak", { value: 1 });
    }),
    globalBinding: __attemptIntrinsicMutation(() => {
      __hardeningDynamicGlobal.Array = function() {};
    }),
    objectSetPrototypeOf: __attemptIntrinsicMutation(() => {
      __hardeningDynamicGlobal.Object.setPrototypeOf(__hardeningArrayPrototype, {});
    }),
    protoAlias: __attemptIntrinsicMutation(() => {
      object.__proto__.leak = 2;
    }),
    reflectSetPrototypeOf: __attemptIntrinsicMutation(() => {
      return __hardeningDynamicGlobal.Reflect.setPrototypeOf(__hardeningObjectPrototype, {});
    }),
  };
  const dynamicCode = {
    alias: __attemptDynamicCode(() => {
      __hardeningAliasedConstructor("return globalThis")();
    }),
    atob: __attemptDynamicCode(() => {
      __hardeningDynamicGlobal.atob.constructor("return globalThis")();
    }),
    asyncFunctionLiteral: __attemptDynamicCode(() => {
      __hardeningAsyncFunctionLiteral.constructor("return globalThis")();
    }),
    boundFunction: __attemptDynamicCode(() => {
      __hardeningDynamicGlobal.Function.bind(null, "return globalThis")();
    }),
    constructorChain: __attemptDynamicCode(() => {
      __hardeningDynamicGlobal.parseInt.constructor.constructor("return globalThis")();
    }),
    descriptor: __attemptDynamicCode(() => {
      __hardeningDescriptorConstructor("return globalThis")();
    }),
    directEval: __attemptDynamicCode(() => {
      __hardeningDynamicGlobal.eval("globalThis");
    }),
    directFunction: __attemptDynamicCode(() => {
      __hardeningDynamicGlobal.Function("return globalThis")();
    }),
    functionLiteral: __attemptDynamicCode(() => {
      __hardeningFunctionLiteral.constructor("return globalThis")();
    }),
    generatorFunctionLiteral: __attemptDynamicCode(() => {
      __hardeningGeneratorFunctionLiteral.constructor("return globalThis")();
    }),
    lexicalEval: __attemptDynamicCode(() => {
      eval("globalThis");
    }),
    lexicalFunction: __attemptDynamicCode(() => {
      Function("return globalThis")();
    }),
    method: __attemptDynamicCode(() => {
      __hardeningMethod.constructor("return globalThis")();
    }),
    newConstructor: __attemptDynamicCode(() => {
      new __hardeningAliasedConstructor("return globalThis");
    }),
    prototype: __attemptDynamicCode(() => {
      __hardeningPrototypeConstructor("return globalThis")();
    }),
    reflectConstruct: __attemptDynamicCode(() => {
      __hardeningDynamicGlobal.Reflect.construct(
        __hardeningAliasedConstructor,
        ["return globalThis"],
      );
    }),
    reflection: __attemptDynamicCode(() => {
      __hardeningReflectedConstructor("return globalThis")();
    }),
  };
  const local: any = {};
  local.first = 1;
  __hardeningDynamicGlobal.Object.defineProperty(local, "second", { configurable: true, value: 2, writable: true });
  __hardeningDynamicGlobal.Object.setPrototypeOf(local, localPrototype);
  const localArray: any[] = [];
  localArray.push(4);
  const longLike: any = function(): void {};
  longLike.prototype.toString = function(): string {
    return "long-like";
  };
  const arrayDescendant: any = __hardeningDynamicGlobal.Object.create(
    __hardeningArrayPrototype,
  );
  arrayDescendant.push = function(value: any): any {
    return value + 1;
  };
  class ArrayDescendant extends __hardeningArrayConstructor {
    static from(): string {
      return "array-descendant";
    }
  }
  __hardeningFunctionLiteral.useCount += 1;
  const asyncExecution: any = { ran: false };
  const asyncResult: any = __hardeningAsyncFunctionLiteral(asyncExecution);
  const generator: any = __hardeningGeneratorFunctionLiteral();
  const map: any = new __hardeningDynamicGlobal.Map();
  const methodResult: any = __hardeningMethod.call(map, "key", 10);
  const arrayBinding: any = __hardeningDynamicGlobal.Object.getOwnPropertyDescriptor(
    __hardeningDynamicGlobal,
    "Array",
  );
  return {
    attempts,
    descriptors: {
      arrayBinding: {
        configurable: arrayBinding.configurable,
        enumerable: arrayBinding.enumerable,
        valueUnchanged: arrayBinding.value === __hardeningDynamicGlobal.Array,
        writable: arrayBinding.writable,
      },
      arrayPrototypeExtensible: __hardeningDynamicGlobal.Object.isExtensible(
        __hardeningArrayPrototype,
      ),
      constructorExtensible: __hardeningDynamicGlobal.Object.isExtensible(
        __hardeningArrayConstructor,
      ),
      dynamicSentinelExtensible: __hardeningDynamicGlobal.Object.isExtensible(
        __hardeningAliasedConstructor,
      ),
      arrayPushFrozen: __hardeningDynamicGlobal.Object.isFrozen(__hardeningOriginalPush),
      evalBindingLocked:
        __hardeningDynamicGlobal.Object.getOwnPropertyDescriptor(
          __hardeningDynamicGlobal,
          "eval",
        ).configurable === false &&
        __hardeningDynamicGlobal.Object.getOwnPropertyDescriptor(
          __hardeningDynamicGlobal,
          "eval",
        ).writable === false,
      functionBindingLocked:
        __hardeningDynamicGlobal.Object.getOwnPropertyDescriptor(
          __hardeningDynamicGlobal,
          "Function",
        ).configurable === false &&
        __hardeningDynamicGlobal.Object.getOwnPropertyDescriptor(
          __hardeningDynamicGlobal,
          "Function",
        ).writable === false,
      functionCallBindWorks:
        functionHasOwn({ present: true }, "present") &&
        !functionHasOwn({ present: true }, "absent"),
      functionLiteralInstanceOfGlobalFunction:
        __hardeningFunctionLiteral instanceof __hardeningDynamicGlobal.Function,
      functionPrototypeConstructorTamed:
        __hardeningDynamicGlobal.Function.prototype.constructor ===
        __hardeningDynamicGlobal.Function,
      functionPrototypePreserved:
        __hardeningDynamicGlobal.Function.prototype === __hardeningFunctionPrototype,
      objectPrototypeExtensible: __hardeningDynamicGlobal.Object.isExtensible(
        __hardeningObjectPrototype,
      ),
    },
    dynamicCode,
    functionUseCount: __hardeningFunctionLiteral.useCount,
    initializedCount: __hardeningInitializedState.count,
    local: [local.first, local.second, local.inherited, localArray[0]],
    noLeak:
      __hardeningArrayPrototype.push === __hardeningOriginalPush &&
      __hardeningArrayPrototype.leak === undefined &&
      __hardeningObjectPrototype.leak === undefined,
    proxyPath:
      __hardeningCreateApi().sampleModule.sampleQuery[
        __hardeningFunctionName
      ],
    ordinaryExecution: [
      __hardeningFunctionLiteral(4),
      asyncExecution.ran,
      typeof asyncResult.then === "function",
      generator.next().value,
      generator.next().value,
      methodResult === map,
      map.get("key"),
      __hardeningDynamicGlobal.parseInt("11", 10),
    ],
    shadowing: [
      longLike.prototype.toString(),
      arrayDescendant.push(4),
      ArrayDescendant.from(),
    ],
  };
}

globalThis.__intrinsicHardeningProbe = [__runIntrinsicProbe(), __runIntrinsicProbe()];
`;

const nodeTargetGlobals = `
globalThis.TextDecoder = class TextDecoder {};
globalThis.TextEncoder = class TextEncoder {};
globalThis.atob = function(value) { return String(value); };
globalThis.btoa = function(value) { return String(value); };
globalThis.queueMicrotask = function(callback) { Promise.resolve().then(callback); };
`;

function createNodeRetainedRuntimeCandidate(applicationSource) {
  const context = {};
  runInNewContext(
    executableSource(`${nodeTargetGlobals}\n${renderConvexWasmIntrinsicHardeningPrelude()}`),
    context
  );
  const validatorDescriptor = Object.getOwnPropertyDescriptor(
    context,
    convexWasmIntrinsicDescriptorStateValidatorBinding
  );
  assert.deepEqual(
    {
      configurable: validatorDescriptor?.configurable,
      enumerable: validatorDescriptor?.enumerable,
      frozen: Object.isFrozen(validatorDescriptor?.value),
      valueType: typeof validatorDescriptor?.value,
      writable: validatorDescriptor?.writable,
    },
    {
      configurable: true,
      enumerable: false,
      frozen: true,
      valueType: "function",
      writable: false,
    }
  );
  const descriptorStateValidator = validatorDescriptor?.value;
  assert.equal(
    Reflect.deleteProperty(context, convexWasmIntrinsicDescriptorStateValidatorBinding),
    true
  );
  assert.equal(convexWasmIntrinsicDescriptorStateValidatorBinding in context, false);
  runInNewContext(executableSource(applicationSource), context);
  const descriptorStateValid = descriptorStateValidator();
  if (!descriptorStateValid) {
    return { descriptorStateValid, quarantined: true };
  }
  return {
    context,
    descriptorStateValid,
    descriptorStateValidator,
    quarantined: false,
  };
}

function executeNodeProbe() {
  const context = {};
  runInNewContext(
    executableSource(
      `${nodeTargetGlobals}\n${renderConvexWasmIntrinsicHardeningPrelude()}\n${probeSource}`
    ),
    context
  );
  return structuredClone(context.__intrinsicHardeningProbe);
}

test("binds the inventory-derived intrinsic hardening policy and source", () => {
  assert.equal(
    convexWasmIntrinsicHardeningPolicy.kind,
    "convex-wasm-effective-intrinsic-hardening-policy-v4"
  );
  assert.match(convexWasmIntrinsicHardeningPolicySha256, /^[a-f0-9]{64}$/u);
  assert.match(convexWasmIntrinsicHardeningSourceSha256, /^[a-f0-9]{64}$/u);
  assert.ok(convexWasmIntrinsicHardeningPolicy.discovery.globalRoots.includes("Array"));
  assert.ok(convexWasmIntrinsicHardeningPolicy.discovery.globalRoots.includes("TextEncoder"));
  assert.deepEqual(convexWasmIntrinsicHardeningPolicy.enforcement.dynamicCodeGeneration, {
    constructorFamilies: ["async-function", "function", "generator-function"],
    globalBindings: ["Function", "eval"],
    replacement: "throwing-sentinel",
  });
  assert.equal(
    convexWasmIntrinsicHardeningPolicy.enforcement.descriptorStateValidation,
    "hidden immutable validator after application evaluation before retained runtime publication"
  );
  assert.equal(
    convexWasmIntrinsicHardeningPolicy.enforcement.intrinsicInheritanceParticipants,
    "Object.preventExtensions for prototypes and constructor functions to preserve descendant shadowing"
  );
  assert.equal(
    convexWasmIntrinsicHardeningPolicy.lifecycle,
    "after-target-global-prelude-before-application-evaluation"
  );
});

test("accepts clean descendant shadowing and retains a descriptor-validated runtime", () => {
  const candidate = createNodeRetainedRuntimeCandidate(String.raw`
const __longLike = function(): void {};
__longLike.prototype.toString = function(): string {
  return "long-like";
};
const __arrayDescendant = Object.create(Object.getPrototypeOf([]));
__arrayDescendant.push = function(value: number): number {
  return value + 1;
};
let __retainedInvocationCount = 0;
globalThis.__convexDescriptorStateCleanInvoke = function(): Array<any> {
  __retainedInvocationCount += 1;
  return [
    __retainedInvocationCount,
    __longLike.prototype.toString(),
    __arrayDescendant.push(4),
  ];
};
`);

  assert.equal(candidate.descriptorStateValid, true);
  assert.equal(candidate.quarantined, false);
  assert.deepEqual(
    structuredClone(
      runInNewContext("globalThis.__convexDescriptorStateCleanInvoke()", candidate.context)
    ),
    [1, "long-like", 5]
  );
  assert.deepEqual(
    structuredClone(
      runInNewContext("globalThis.__convexDescriptorStateCleanInvoke()", candidate.context)
    ),
    [2, "long-like", 5]
  );
  assert.equal(candidate.descriptorStateValidator(), true);
});

test("quarantines a runtime when a reflective alias mutates an intrinsic descriptor", () => {
  const candidate = createNodeRetainedRuntimeCandidate(String.raw`
const __getPrototype = Object.getPrototypeOf;
const __readDescriptor = Reflect.getOwnPropertyDescriptor;
const __writeDescriptor = Reflect.defineProperty;
const __arrayPrototypeAlias = __getPrototype([]);
const __propertyAlias = "pu" + "sh";
const __pushDescriptor = __readDescriptor(
  __arrayPrototypeAlias,
  __propertyAlias,
);
__writeDescriptor(__arrayPrototypeAlias, __propertyAlias, {
  configurable: __pushDescriptor.configurable,
  enumerable: __pushDescriptor.enumerable,
  value: function(): string {
    return "contaminated";
  },
  writable: __pushDescriptor.writable,
});
const __arrayConstructorAlias = globalThis["Ar" + "ray"];
const __constructorPropertyAlias = "is" + "Array";
const __isArrayDescriptor = __readDescriptor(
  __arrayConstructorAlias,
  __constructorPropertyAlias,
);
__writeDescriptor(__arrayConstructorAlias, __constructorPropertyAlias, {
  configurable: __isArrayDescriptor.configurable,
  enumerable: __isArrayDescriptor.enumerable,
  value: function(): boolean {
    return true;
  },
  writable: __isArrayDescriptor.writable,
});
`);

  assert.equal(candidate.descriptorStateValid, false);
  assert.equal(candidate.quarantined, true);
  assert.equal("context" in candidate, false);
});

test("tames dynamic constructors while preserving descendant shadowing", () => {
  const [first, reused] = executeNodeProbe();
  const [fresh] = executeNodeProbe();
  for (const result of [first, reused, fresh]) {
    assert.deepEqual(result.attempts, {
      defineProperty: true,
      globalBinding: true,
      objectSetPrototypeOf: true,
      protoAlias: true,
      reflectSetPrototypeOf: true,
    });
    assert.deepEqual(result.descriptors.arrayBinding, {
      configurable: false,
      enumerable: false,
      valueUnchanged: true,
      writable: false,
    });
    assert.equal(result.descriptors.arrayPrototypeExtensible, false);
    assert.equal(result.descriptors.constructorExtensible, false);
    assert.equal(result.descriptors.dynamicSentinelExtensible, false);
    assert.equal(result.descriptors.arrayPushFrozen, true);
    assert.equal(result.descriptors.evalBindingLocked, true);
    assert.equal(result.descriptors.functionBindingLocked, true);
    assert.equal(result.descriptors.functionCallBindWorks, true);
    assert.equal(result.descriptors.functionLiteralInstanceOfGlobalFunction, true);
    assert.equal(result.descriptors.functionPrototypeConstructorTamed, true);
    assert.equal(result.descriptors.functionPrototypePreserved, true);
    assert.equal(result.descriptors.objectPrototypeExtensible, false);
    assert.equal(result.initializedCount, 1);
    assert.deepEqual(result.local, [1, 2, 3, 4]);
    assert.equal(result.noLeak, true);
    assert.equal(result.proxyPath, "sampleModule:sampleQuery");
    assert.deepEqual(result.ordinaryExecution, [5, true, true, 8, 9, true, 10, 11]);
    assert.deepEqual(result.shadowing, ["long-like", 5, "array-descendant"]);
    assert.equal(result.dynamicCode.boundFunction, true);
    assert.ok(Object.values(result.dynamicCode).every(Boolean));
  }
  assert.equal(first.functionUseCount, 1);
  assert.equal(reused.functionUseCount, 2);
  assert.equal(fresh.functionUseCount, 1);
});

test("exact Static Hermes executes API Proxy array spread before hardening", (context) => {
  const executable = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (executable === undefined) {
    context.skip("set CONVEX_STATIC_HERMES_TEST_BINARY to run the exact-target Proxy proof");
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), "convex-wasm-api-proxy-"));
  try {
    const sourcePath = join(directory, "probe.js");
    writeFileSync(
      sourcePath,
      String.raw`
const functionName: any = Symbol.for("functionName");
function createApi(pathParts: Array<string> = []): any {
  const handler: any = {
    get(_target: any, property: any): any {
      if (typeof property === "string") {
        const nextParts = [...pathParts, property];
        return createApi(nextParts);
      }
      if (property === functionName) {
        const modulePath = pathParts.slice(0, -1).join("/");
        return modulePath + ":" + pathParts[pathParts.length - 1];
      }
      return undefined;
    },
  };
  return new Proxy({}, handler);
}
function resolvePath(): string {
  return createApi().sampleModule.sampleQuery[functionName];
}
print(JSON.stringify([resolvePath(), resolvePath()]));
`
    );
    const first = spawnSync(executable, ["-typed", "-O", "-Xenable-tdz", "-exec", sourcePath], {
      encoding: "utf8",
    });
    const fresh = spawnSync(executable, ["-typed", "-O", "-Xenable-tdz", "-exec", sourcePath], {
      encoding: "utf8",
    });
    assert.equal(first.status, 0, `${first.stderr}\n${first.stdout}`);
    assert.equal(fresh.status, 0, fresh.stderr);
    assert.equal(fresh.stdout, first.stdout);
    assert.deepEqual(JSON.parse(first.stdout), [
      "sampleModule:sampleQuery",
      "sampleModule:sampleQuery",
    ]);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("exact Static Hermes rejects the unrepresented async-generator constructor family", (context) => {
  const executable = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (executable === undefined) {
    context.skip("set CONVEX_STATIC_HERMES_TEST_BINARY to run the exact-target syntax proof");
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), "convex-wasm-async-generator-"));
  try {
    const sourcePath = join(directory, "probe.js");
    writeFileSync(
      sourcePath,
      "const generator: any = async function*(): any { yield 1; }; print(typeof generator);\n"
    );
    const result = spawnSync(executable, ["-typed", "-O", "-Xenable-tdz", "-exec", sourcePath], {
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /async generators are unsupported/u);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("exact Static Hermes tames dynamic constructors across reused calls", (context) => {
  const executable = process.env.CONVEX_STATIC_HERMES_TEST_BINARY;
  if (executable === undefined) {
    context.skip("set CONVEX_STATIC_HERMES_TEST_BINARY to run the exact-target hardening proof");
    return;
  }
  const directory = mkdtempSync(join(tmpdir(), "convex-wasm-intrinsic-hardening-"));
  try {
    const sourcePath = join(directory, "probe.js");
    const targetProbe = `${renderConvexWasmIntrinsicHardeningPrelude()}\n${probeSource}\nprint(JSON.stringify(globalThis.__intrinsicHardeningProbe));\n`;
    writeFileSync(sourcePath, targetProbe);
    const first = spawnSync(executable, ["-typed", "-O", "-Xenable-tdz", "-exec", sourcePath], {
      encoding: "utf8",
    });
    const fresh = spawnSync(executable, ["-typed", "-O", "-Xenable-tdz", "-exec", sourcePath], {
      encoding: "utf8",
    });
    assert.equal(first.status, 0, first.stderr);
    assert.equal(fresh.status, 0, fresh.stderr);
    assert.equal(fresh.stdout, first.stdout);
    const results = JSON.parse(first.stdout);
    assert.equal(results.length, 2);
    for (const result of results) {
      assert.equal(result.noLeak, true);
      assert.equal(result.initializedCount, 1);
      assert.deepEqual(result.local, [1, 2, 3, 4]);
      assert.equal(result.proxyPath, "sampleModule:sampleQuery");
      assert.equal(result.descriptors.arrayBinding.configurable, false);
      assert.equal(result.descriptors.arrayBinding.writable, false);
      assert.equal(result.descriptors.arrayPrototypeExtensible, false);
      assert.equal(result.descriptors.constructorExtensible, false);
      assert.equal(result.descriptors.dynamicSentinelExtensible, false);
      assert.equal(result.descriptors.arrayPushFrozen, true);
      assert.equal(result.descriptors.evalBindingLocked, true);
      assert.equal(result.descriptors.functionBindingLocked, true);
      assert.equal(result.descriptors.functionCallBindWorks, true);
      assert.equal(result.descriptors.functionLiteralInstanceOfGlobalFunction, true);
      assert.equal(result.descriptors.functionPrototypeConstructorTamed, true);
      assert.equal(result.descriptors.functionPrototypePreserved, true);
      assert.equal(result.descriptors.objectPrototypeExtensible, false);
      assert.ok(Object.values(result.attempts).every(Boolean));
      assert.equal(result.dynamicCode.boundFunction, true);
      assert.ok(Object.values(result.dynamicCode).every(Boolean));
      assert.deepEqual(result.ordinaryExecution, [5, true, true, 8, 9, true, 10, 11]);
      assert.deepEqual(result.shadowing, ["long-like", 5, "array-descendant"]);
    }
    assert.equal(results[0].functionUseCount, 1);
    assert.equal(results[1].functionUseCount, 2);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
