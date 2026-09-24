import { createHash } from "node:crypto";

import {
  convexWasmAdmittedStaticHermesGlobals,
  convexWasmStaticHermesGlobalInventory,
  convexWasmStaticHermesGlobalInventorySha256,
} from "./convex-wasm-static-hermes-engine-globals.mjs";

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  return value;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export const convexWasmIntrinsicDescriptorStateValidatorBinding =
  "__convexWasmValidateIntrinsicDescriptorState";

export const convexWasmIntrinsicHardeningPolicy = deepFreeze({
  discovery: {
    globalInventory: {
      kind: convexWasmStaticHermesGlobalInventory.kind,
      sha256: convexWasmStaticHermesGlobalInventorySha256,
    },
    globalRoots: [...convexWasmAdmittedStaticHermesGlobals],
    representativeRoots: [
      "array-literal",
      "array-iterator",
      "async-function-literal",
      "function-literal",
      "generator-function-literal",
      "map-iterator",
      "object-literal",
      "regexp-literal",
      "set-iterator",
      "string-iterator",
    ],
    traversal: ["own-data-values", "own-accessor-functions", "prototype-chain"],
  },
  enforcement: {
    discoveredObjects: "Object.freeze except intrinsic inheritance participants",
    dynamicCodeGeneration: {
      constructorFamilies: ["async-function", "function", "generator-function"],
      globalBindings: ["Function", "eval"],
      replacement: "throwing-sentinel",
    },
    descriptorStateValidation:
      "hidden immutable validator after application evaluation before retained runtime publication",
    existingGlobalBindings: "non-configurable-and-non-writable",
    globalObject: "extensible",
    intrinsicInheritanceParticipants:
      "Object.preventExtensions for prototypes and constructor functions to preserve descendant shadowing",
  },
  kind: "convex-wasm-effective-intrinsic-hardening-policy-v4",
  lifecycle: "after-target-global-prelude-before-application-evaluation",
});

export const convexWasmIntrinsicHardeningPolicySha256 = createHash("sha256")
  .update(JSON.stringify(canonicalValue(convexWasmIntrinsicHardeningPolicy)))
  .digest("hex");

export function renderConvexWasmIntrinsicHardeningPrelude() {
  return String.raw`{
const __convexIntrinsicPolicySha256: string = ${JSON.stringify(
    convexWasmIntrinsicHardeningPolicySha256
  )};
const __convexIntrinsicGlobal: any = globalThis;
const __convexIntrinsicGlobalNames: Array<string> = ${JSON.stringify(
    convexWasmAdmittedStaticHermesGlobals
  )};
const __convexIntrinsicDynamicGlobalNames: Array<string> = ["Function", "eval"];
const __convexIntrinsicObject: any = __convexIntrinsicGlobal.Object;
const __convexIntrinsicReflect: any = __convexIntrinsicGlobal.Reflect;
const __convexIntrinsicFreeze: any = __convexIntrinsicObject.freeze;
const __convexIntrinsicIsFrozen: any = __convexIntrinsicObject.isFrozen;
const __convexIntrinsicPreventExtensions: any = __convexIntrinsicObject.preventExtensions;
const __convexIntrinsicIsExtensible: any = __convexIntrinsicObject.isExtensible;
const __convexIntrinsicSameValue: any = __convexIntrinsicObject.is;
const __convexIntrinsicGetOwnPropertyDescriptor: any =
  __convexIntrinsicObject.getOwnPropertyDescriptor;
const __convexIntrinsicGetPrototypeOf: any = __convexIntrinsicObject.getPrototypeOf;
const __convexIntrinsicDefineProperty: any = __convexIntrinsicObject.defineProperty;
const __convexIntrinsicOwnKeys: any = __convexIntrinsicReflect.ownKeys;
const __convexIntrinsicHasOwn: any = __convexIntrinsicObject.hasOwn;
if (
  typeof __convexIntrinsicPolicySha256 !== "string" ||
  typeof __convexIntrinsicFreeze !== "function" ||
  typeof __convexIntrinsicIsFrozen !== "function" ||
  typeof __convexIntrinsicPreventExtensions !== "function" ||
  typeof __convexIntrinsicIsExtensible !== "function" ||
  typeof __convexIntrinsicSameValue !== "function" ||
  typeof __convexIntrinsicGetOwnPropertyDescriptor !== "function" ||
  typeof __convexIntrinsicGetPrototypeOf !== "function" ||
  typeof __convexIntrinsicDefineProperty !== "function" ||
  typeof __convexIntrinsicOwnKeys !== "function" ||
  typeof __convexIntrinsicHasOwn !== "function"
) {
  throw new Error("Convex Wasm intrinsic hardening primitives are unavailable");
}

const __convexIntrinsicObjects: Array<any> = [];
const __convexIntrinsicSeen: any = new __convexIntrinsicGlobal.Set();
const __convexIntrinsicInheritanceParticipants: any = new __convexIntrinsicGlobal.Set();
function __convexIntrinsicAppend(values: Array<any>, value: any): void {
  values.push(value);
}
function __convexIntrinsicAdd(value: any): void {
  if (
    value !== __convexIntrinsicGlobal &&
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    !__convexIntrinsicSeen.has(value)
  ) {
    __convexIntrinsicSeen.add(value);
    __convexIntrinsicAppend(__convexIntrinsicObjects, value);
  }
}

function __convexIntrinsicAddPrototype(value: any): void {
  const __convexIntrinsicPrototype = __convexIntrinsicGetPrototypeOf(value);
  __convexIntrinsicAdd(__convexIntrinsicPrototype);
  if (__convexIntrinsicPrototype !== null) {
    __convexIntrinsicInheritanceParticipants.add(__convexIntrinsicPrototype);
  }
}

const __convexIntrinsicDynamicConstructors: any = new __convexIntrinsicGlobal.Set();
function __convexIntrinsicDynamicCodeUnavailable(): void {
  throw new __convexIntrinsicGlobal.TypeError("Dynamic code generation is unavailable");
}
const __convexIntrinsicFunctionPrototype: any = __convexIntrinsicGetPrototypeOf(
  __convexIntrinsicDynamicCodeUnavailable,
);
const __convexIntrinsicSentinelPrototypeDescriptor: any =
  __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicDynamicCodeUnavailable,
    "prototype",
  );
if (
  __convexIntrinsicSentinelPrototypeDescriptor === undefined ||
  !__convexIntrinsicHasOwn(__convexIntrinsicSentinelPrototypeDescriptor, "value") ||
  __convexIntrinsicSentinelPrototypeDescriptor.configurable !== false ||
  __convexIntrinsicSentinelPrototypeDescriptor.writable !== true
) {
  throw new Error("Convex Wasm dynamic-code sentinel prototype is unavailable");
}
__convexIntrinsicAdd(__convexIntrinsicDynamicCodeUnavailable);

function __convexIntrinsicAddDynamicConstructor(value: any): void {
  const __convexIntrinsicCandidateFunctionPrototype = __convexIntrinsicGetPrototypeOf(value);
  const __convexIntrinsicConstructorDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicCandidateFunctionPrototype,
    "constructor",
  );
  if (
    __convexIntrinsicConstructorDescriptor === undefined ||
    !__convexIntrinsicHasOwn(__convexIntrinsicConstructorDescriptor, "value") ||
    typeof __convexIntrinsicConstructorDescriptor.value !== "function"
  ) {
    throw new Error("Convex Wasm dynamic function constructor is unavailable");
  }
  __convexIntrinsicDynamicConstructors.add(__convexIntrinsicConstructorDescriptor.value);
  __convexIntrinsicInheritanceParticipants.add(__convexIntrinsicCandidateFunctionPrototype);
  __convexIntrinsicAdd(__convexIntrinsicCandidateFunctionPrototype);
  __convexIntrinsicAdd(__convexIntrinsicConstructorDescriptor.value);
}

__convexIntrinsicAddDynamicConstructor(function __convexIntrinsicFunctionLiteral(): void {});
__convexIntrinsicAddDynamicConstructor(async function __convexIntrinsicAsyncFunctionLiteral() {});
__convexIntrinsicAddDynamicConstructor(function* __convexIntrinsicGeneratorFunctionLiteral(): any {});

const __convexIntrinsicGlobalKeys: Array<any> = [];
const __convexIntrinsicGlobalDescriptors: Array<any> = [];
for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicGlobalNames.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicKey = __convexIntrinsicGlobalNames[__convexIntrinsicIndex];
  const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicGlobal,
    __convexIntrinsicKey,
  );
  if (__convexIntrinsicDescriptor === undefined) {
    throw new Error("Convex Wasm admitted intrinsic global is unavailable");
  }
  __convexIntrinsicAppend(__convexIntrinsicGlobalKeys, __convexIntrinsicKey);
  __convexIntrinsicAppend(__convexIntrinsicGlobalDescriptors, __convexIntrinsicDescriptor);
  if (__convexIntrinsicHasOwn(__convexIntrinsicDescriptor, "value")) {
    __convexIntrinsicAdd(__convexIntrinsicDescriptor.value);
  } else {
    __convexIntrinsicAdd(__convexIntrinsicDescriptor.get);
    __convexIntrinsicAdd(__convexIntrinsicDescriptor.set);
  }
}

__convexIntrinsicAddPrototype([]);
__convexIntrinsicAddPrototype({});
__convexIntrinsicAddPrototype(/(?:)/);
const __convexIntrinsicIterator: any = __convexIntrinsicGlobal.Symbol.iterator;
const __convexIntrinsicArrayLiteral: any = [];
const __convexIntrinsicStringLiteral: any = "";
const __convexIntrinsicMapLiteral: any = new __convexIntrinsicGlobal.Map();
const __convexIntrinsicSetLiteral: any = new __convexIntrinsicGlobal.Set();
function __convexIntrinsicAddIteratorPrototype(value: any): void {
  const __convexIntrinsicIteratorFactory = value[__convexIntrinsicIterator];
  if (typeof __convexIntrinsicIteratorFactory === "function") {
    __convexIntrinsicAddPrototype(__convexIntrinsicIteratorFactory.call(value));
  }
}
__convexIntrinsicAddIteratorPrototype(__convexIntrinsicArrayLiteral);
__convexIntrinsicAddIteratorPrototype(__convexIntrinsicStringLiteral);
__convexIntrinsicAddIteratorPrototype(__convexIntrinsicMapLiteral);
__convexIntrinsicAddIteratorPrototype(__convexIntrinsicSetLiteral);

const __convexIntrinsicDynamicGlobalKeys: Array<any> = [];
const __convexIntrinsicDynamicGlobalDescriptors: Array<any> = [];
for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicDynamicGlobalNames.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicKey = __convexIntrinsicDynamicGlobalNames[__convexIntrinsicIndex];
  const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicGlobal,
    __convexIntrinsicKey,
  );
  if (
    __convexIntrinsicDescriptor === undefined ||
    !__convexIntrinsicHasOwn(__convexIntrinsicDescriptor, "value") ||
    typeof __convexIntrinsicDescriptor.value !== "function" ||
    (__convexIntrinsicKey === "Function" &&
      !__convexIntrinsicDynamicConstructors.has(__convexIntrinsicDescriptor.value))
  ) {
    throw new Error("Convex Wasm dynamic-code global is unavailable");
  }
  __convexIntrinsicAppend(__convexIntrinsicDynamicGlobalKeys, __convexIntrinsicKey);
  __convexIntrinsicAppend(
    __convexIntrinsicDynamicGlobalDescriptors,
    __convexIntrinsicDescriptor,
  );
  __convexIntrinsicAdd(__convexIntrinsicDescriptor.value);
}

for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicObjects.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicValue = __convexIntrinsicObjects[__convexIntrinsicIndex];
  __convexIntrinsicAddPrototype(__convexIntrinsicValue);
  const __convexIntrinsicKeys: any = __convexIntrinsicOwnKeys(__convexIntrinsicValue);
  for (
    let __convexIntrinsicKeyIndex = 0;
    __convexIntrinsicKeyIndex < __convexIntrinsicKeys.length;
    __convexIntrinsicKeyIndex += 1
  ) {
    const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
      __convexIntrinsicValue,
      __convexIntrinsicKeys[__convexIntrinsicKeyIndex],
    );
    if (__convexIntrinsicDescriptor === undefined) {
      throw new Error("Convex Wasm intrinsic descriptor disappeared");
    }
    if (__convexIntrinsicHasOwn(__convexIntrinsicDescriptor, "value")) {
      __convexIntrinsicAdd(__convexIntrinsicDescriptor.value);
      if (
        __convexIntrinsicKeys[__convexIntrinsicKeyIndex] === "prototype" &&
        (__convexIntrinsicDescriptor.value === null ||
          typeof __convexIntrinsicDescriptor.value === "object")
      ) {
        __convexIntrinsicInheritanceParticipants.add(__convexIntrinsicDescriptor.value);
        if (typeof __convexIntrinsicValue === "function") {
          __convexIntrinsicInheritanceParticipants.add(__convexIntrinsicValue);
        }
      }
    } else {
      __convexIntrinsicAdd(__convexIntrinsicDescriptor.get);
      __convexIntrinsicAdd(__convexIntrinsicDescriptor.set);
    }
  }
}

// Freezing a dynamic constructor does not disable calls, so replace every discovered reference first.
for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicObjects.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicValue = __convexIntrinsicObjects[__convexIntrinsicIndex];
  const __convexIntrinsicKeys: any = __convexIntrinsicOwnKeys(__convexIntrinsicValue);
  for (
    let __convexIntrinsicKeyIndex = 0;
    __convexIntrinsicKeyIndex < __convexIntrinsicKeys.length;
    __convexIntrinsicKeyIndex += 1
  ) {
    const __convexIntrinsicKey = __convexIntrinsicKeys[__convexIntrinsicKeyIndex];
    const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
      __convexIntrinsicValue,
      __convexIntrinsicKey,
    );
    if (
      __convexIntrinsicDescriptor !== undefined &&
      __convexIntrinsicHasOwn(__convexIntrinsicDescriptor, "value") &&
      __convexIntrinsicDynamicConstructors.has(__convexIntrinsicDescriptor.value)
    ) {
      if (
        __convexIntrinsicDescriptor.configurable === false &&
        __convexIntrinsicDescriptor.writable === false
      ) {
        throw new Error("Convex Wasm dynamic function constructor cannot be neutralized");
      }
      __convexIntrinsicDefineProperty(__convexIntrinsicValue, __convexIntrinsicKey, {
        configurable: __convexIntrinsicDescriptor.configurable,
        enumerable: __convexIntrinsicDescriptor.enumerable,
        value: __convexIntrinsicDynamicCodeUnavailable,
        writable: __convexIntrinsicDescriptor.writable,
      });
    }
  }
}

// Keep the standard Function.prototype surface on the throwing sentinel. The
// constructor property on this prototype was replaced with the sentinel above,
// so linking it here does not restore dynamic code generation.
__convexIntrinsicDefineProperty(__convexIntrinsicDynamicCodeUnavailable, "prototype", {
  configurable: __convexIntrinsicSentinelPrototypeDescriptor.configurable,
  enumerable: __convexIntrinsicSentinelPrototypeDescriptor.enumerable,
  value: __convexIntrinsicFunctionPrototype,
  writable: __convexIntrinsicSentinelPrototypeDescriptor.writable,
});
const __convexIntrinsicLinkedSentinelPrototypeDescriptor: any =
  __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicDynamicCodeUnavailable,
    "prototype",
  );
const __convexIntrinsicLinkedConstructorDescriptor: any =
  __convexIntrinsicGetOwnPropertyDescriptor(__convexIntrinsicFunctionPrototype, "constructor");
if (
  __convexIntrinsicLinkedSentinelPrototypeDescriptor === undefined ||
  !__convexIntrinsicHasOwn(__convexIntrinsicLinkedSentinelPrototypeDescriptor, "value") ||
  !__convexIntrinsicSameValue(
    __convexIntrinsicLinkedSentinelPrototypeDescriptor.value,
    __convexIntrinsicFunctionPrototype,
  ) ||
  __convexIntrinsicLinkedConstructorDescriptor === undefined ||
  !__convexIntrinsicHasOwn(__convexIntrinsicLinkedConstructorDescriptor, "value") ||
  !__convexIntrinsicSameValue(
    __convexIntrinsicLinkedConstructorDescriptor.value,
    __convexIntrinsicDynamicCodeUnavailable,
  )
) {
  throw new Error("Convex Wasm Function prototype was not safely retained");
}

for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicDynamicGlobalKeys.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicKey = __convexIntrinsicDynamicGlobalKeys[__convexIntrinsicIndex];
  const __convexIntrinsicDescriptor =
    __convexIntrinsicDynamicGlobalDescriptors[__convexIntrinsicIndex];
  __convexIntrinsicDefineProperty(__convexIntrinsicGlobal, __convexIntrinsicKey, {
    configurable: false,
    enumerable: __convexIntrinsicDescriptor.enumerable,
    value: __convexIntrinsicDynamicCodeUnavailable,
    writable: false,
  });
}

for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicObjects.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicValue = __convexIntrinsicObjects[__convexIntrinsicIndex];
  const __convexIntrinsicKeys: any = __convexIntrinsicOwnKeys(__convexIntrinsicValue);
  for (
    let __convexIntrinsicKeyIndex = 0;
    __convexIntrinsicKeyIndex < __convexIntrinsicKeys.length;
    __convexIntrinsicKeyIndex += 1
  ) {
    const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
      __convexIntrinsicValue,
      __convexIntrinsicKeys[__convexIntrinsicKeyIndex],
    );
    if (
      __convexIntrinsicDescriptor !== undefined &&
      __convexIntrinsicHasOwn(__convexIntrinsicDescriptor, "value") &&
      __convexIntrinsicDynamicConstructors.has(__convexIntrinsicDescriptor.value)
    ) {
      throw new Error("Convex Wasm dynamic function constructor remained reachable");
    }
  }
}

for (
  let __convexIntrinsicIndex = __convexIntrinsicObjects.length - 1;
  __convexIntrinsicIndex >= 0;
  __convexIntrinsicIndex -= 1
) {
  const __convexIntrinsicValue = __convexIntrinsicObjects[__convexIntrinsicIndex];
  if (__convexIntrinsicInheritanceParticipants.has(__convexIntrinsicValue)) {
    __convexIntrinsicPreventExtensions(__convexIntrinsicValue);
    if (__convexIntrinsicIsExtensible(__convexIntrinsicValue)) {
      throw new Error("Convex Wasm intrinsic prototype remained extensible");
    }
  } else {
    __convexIntrinsicFreeze(__convexIntrinsicValue);
    if (!__convexIntrinsicIsFrozen(__convexIntrinsicValue)) {
      throw new Error("Convex Wasm intrinsic object remained mutable");
    }
  }
}

for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicGlobalKeys.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicKey = __convexIntrinsicGlobalKeys[__convexIntrinsicIndex];
  const __convexIntrinsicDescriptor = __convexIntrinsicGlobalDescriptors[__convexIntrinsicIndex];
  if (__convexIntrinsicHasOwn(__convexIntrinsicDescriptor, "value")) {
    __convexIntrinsicDefineProperty(__convexIntrinsicGlobal, __convexIntrinsicKey, {
      configurable: false,
      enumerable: __convexIntrinsicDescriptor.enumerable,
      value: __convexIntrinsicDescriptor.value,
      writable: false,
    });
  } else {
    __convexIntrinsicDefineProperty(__convexIntrinsicGlobal, __convexIntrinsicKey, {
      configurable: false,
      enumerable: __convexIntrinsicDescriptor.enumerable,
      get: __convexIntrinsicDescriptor.get,
      set: __convexIntrinsicDescriptor.set,
    });
  }
  const __convexIntrinsicLockedDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicGlobal,
    __convexIntrinsicKey,
  );
  if (
    __convexIntrinsicLockedDescriptor === undefined ||
    __convexIntrinsicLockedDescriptor.configurable !== false ||
    (__convexIntrinsicHasOwn(__convexIntrinsicLockedDescriptor, "value") &&
      (__convexIntrinsicLockedDescriptor.writable !== false ||
        !__convexIntrinsicSameValue(
          __convexIntrinsicLockedDescriptor.value,
          __convexIntrinsicDescriptor.value,
        )))
  ) {
    throw new Error("Convex Wasm intrinsic global binding remained mutable");
  }
}

const __convexIntrinsicDescriptorStates: Array<any> = [];
for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicObjects.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicValue = __convexIntrinsicObjects[__convexIntrinsicIndex];
  const __convexIntrinsicKeys: any = __convexIntrinsicOwnKeys(__convexIntrinsicValue);
  const __convexIntrinsicDescriptors: Array<any> = [];
  for (
    let __convexIntrinsicKeyIndex = 0;
    __convexIntrinsicKeyIndex < __convexIntrinsicKeys.length;
    __convexIntrinsicKeyIndex += 1
  ) {
    const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
      __convexIntrinsicValue,
      __convexIntrinsicKeys[__convexIntrinsicKeyIndex],
    );
    if (__convexIntrinsicDescriptor === undefined) {
      throw new Error("Convex Wasm intrinsic descriptor disappeared");
    }
    __convexIntrinsicAppend(__convexIntrinsicDescriptors, __convexIntrinsicDescriptor);
  }
  __convexIntrinsicAppend(__convexIntrinsicDescriptorStates, {
    descriptors: __convexIntrinsicDescriptors,
    keys: __convexIntrinsicKeys,
    value: __convexIntrinsicValue,
  });
}

const __convexIntrinsicGlobalDescriptorStates: Array<any> = [];
for (
  let __convexIntrinsicIndex = 0;
  __convexIntrinsicIndex < __convexIntrinsicGlobalKeys.length;
  __convexIntrinsicIndex += 1
) {
  const __convexIntrinsicKey = __convexIntrinsicGlobalKeys[__convexIntrinsicIndex];
  const __convexIntrinsicDescriptor = __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicGlobal,
    __convexIntrinsicKey,
  );
  if (__convexIntrinsicDescriptor === undefined) {
    throw new Error("Convex Wasm intrinsic global descriptor disappeared");
  }
  __convexIntrinsicAppend(__convexIntrinsicGlobalDescriptorStates, {
    descriptor: __convexIntrinsicDescriptor,
    key: __convexIntrinsicKey,
  });
}

function __convexIntrinsicDescriptorEquals(expected: any, actual: any): boolean {
  if (
    actual === undefined ||
    expected.configurable !== actual.configurable ||
    expected.enumerable !== actual.enumerable
  ) {
    return false;
  }
  const __convexIntrinsicExpectedData = __convexIntrinsicHasOwn(expected, "value");
  if (__convexIntrinsicExpectedData !== __convexIntrinsicHasOwn(actual, "value")) {
    return false;
  }
  if (__convexIntrinsicExpectedData) {
    return (
      expected.writable === actual.writable &&
      __convexIntrinsicSameValue(expected.value, actual.value)
    );
  }
  return (
    __convexIntrinsicSameValue(expected.get, actual.get) &&
    __convexIntrinsicSameValue(expected.set, actual.set)
  );
}

function __convexIntrinsicDescriptorStateIsValid(): boolean {
  for (
    let __convexIntrinsicIndex = 0;
    __convexIntrinsicIndex < __convexIntrinsicDescriptorStates.length;
    __convexIntrinsicIndex += 1
  ) {
    const __convexIntrinsicState = __convexIntrinsicDescriptorStates[__convexIntrinsicIndex];
    const __convexIntrinsicKeys: any = __convexIntrinsicOwnKeys(
      __convexIntrinsicState.value,
    );
    if (__convexIntrinsicKeys.length !== __convexIntrinsicState.keys.length) {
      return false;
    }
    for (
      let __convexIntrinsicKeyIndex = 0;
      __convexIntrinsicKeyIndex < __convexIntrinsicKeys.length;
      __convexIntrinsicKeyIndex += 1
    ) {
      const __convexIntrinsicKey = __convexIntrinsicKeys[__convexIntrinsicKeyIndex];
      if (
        !__convexIntrinsicSameValue(
          __convexIntrinsicKey,
          __convexIntrinsicState.keys[__convexIntrinsicKeyIndex],
        ) ||
        !__convexIntrinsicDescriptorEquals(
          __convexIntrinsicState.descriptors[__convexIntrinsicKeyIndex],
          __convexIntrinsicGetOwnPropertyDescriptor(
            __convexIntrinsicState.value,
            __convexIntrinsicKey,
          ),
        )
      ) {
        return false;
      }
    }
  }
  for (
    let __convexIntrinsicIndex = 0;
    __convexIntrinsicIndex < __convexIntrinsicGlobalDescriptorStates.length;
    __convexIntrinsicIndex += 1
  ) {
    const __convexIntrinsicState =
      __convexIntrinsicGlobalDescriptorStates[__convexIntrinsicIndex];
    if (
      !__convexIntrinsicDescriptorEquals(
        __convexIntrinsicState.descriptor,
        __convexIntrinsicGetOwnPropertyDescriptor(
          __convexIntrinsicGlobal,
          __convexIntrinsicState.key,
        ),
      )
    ) {
      return false;
    }
  }
  return true;
}

__convexIntrinsicFreeze(__convexIntrinsicDescriptorStateIsValid);
__convexIntrinsicDefineProperty(
  __convexIntrinsicGlobal,
  ${JSON.stringify(convexWasmIntrinsicDescriptorStateValidatorBinding)},
  {
    configurable: true,
    enumerable: false,
    value: __convexIntrinsicDescriptorStateIsValid,
    writable: false,
  },
);
const __convexIntrinsicDescriptorStateValidatorDescriptor: any =
  __convexIntrinsicGetOwnPropertyDescriptor(
    __convexIntrinsicGlobal,
    ${JSON.stringify(convexWasmIntrinsicDescriptorStateValidatorBinding)},
  );
if (
  __convexIntrinsicDescriptorStateValidatorDescriptor === undefined ||
  __convexIntrinsicDescriptorStateValidatorDescriptor.configurable !== true ||
  __convexIntrinsicDescriptorStateValidatorDescriptor.enumerable !== false ||
  __convexIntrinsicDescriptorStateValidatorDescriptor.writable !== false ||
  !__convexIntrinsicSameValue(
    __convexIntrinsicDescriptorStateValidatorDescriptor.value,
    __convexIntrinsicDescriptorStateIsValid,
  )
) {
  throw new Error("Convex Wasm intrinsic descriptor validator is unavailable");
}
}`;
}

export const convexWasmIntrinsicHardeningSourceSha256 = createHash("sha256")
  .update(renderConvexWasmIntrinsicHardeningPrelude())
  .digest("hex");
