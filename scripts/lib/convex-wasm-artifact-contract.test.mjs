import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { canonicalJson, fingerprintJson, normalizeJson } from "./convex-wasm-artifact-contract.mjs";

function freezeJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) freezeJsonTree(nested);
    Object.freeze(value);
  }
  return value;
}

test("canonical JSON preserves output while using already-sorted objects directly", () => {
  const canonical = { alpha: [1, { beta: true, gamma: null }], omega: "value" };
  assert.equal(canonicalJson(canonical), JSON.stringify(canonical));
  assert.equal(canonicalJson({ omega: "value", alpha: 1 }), '{"alpha":1,"omega":"value"}');
});

test("canonical JSON keeps fail-closed behavior for unsupported values and prototypes", () => {
  assert.throws(() => canonicalJson({ value: undefined }), /must be a plain object/u);
  assert.throws(() => canonicalJson({ value: Number.NaN }), /non-finite number/u);
  assert.throws(() => canonicalJson(new Date(0)), /must be a plain object/u);
  const sparse = [];
  sparse.length = 1;
  assert.equal(canonicalJson(sparse), "[null]");
  const customArray = [];
  Object.setPrototypeOf(
    customArray,
    Object.create(Array.prototype, { toJSON: { value: () => "wrong" } })
  );
  assert.equal(canonicalJson(customArray), "[]");
  assert.deepEqual(normalizeJson({ omega: "value", alpha: 1 }, "fixture"), {
    alpha: 1,
    omega: "value",
  });
  const prototypeKey = JSON.parse('{"__proto__":{"value":1},"alpha":2}');
  const normalizedPrototypeKey = normalizeJson(prototypeKey, "fixture");
  assert.equal(Object.getPrototypeOf(normalizedPrototypeKey), Object.prototype);
  assert.deepEqual(Object.keys(normalizedPrototypeKey), ["__proto__", "alpha"]);
  assert.deepEqual(normalizedPrototypeKey.__proto__, { value: 1 });
  assert.equal(canonicalJson(prototypeKey), '{"__proto__":{"value":1},"alpha":2}');
});

test("JSON normalization materializes sparse slots but rejects explicit undefined values", () => {
  const sparse = new Array(4);
  sparse[1] = { omega: 2, alpha: 1 };
  const normalized = normalizeJson({ sparse }, "fixture");
  assert.deepEqual(normalized, { sparse: [null, { alpha: 1, omega: 2 }, null, null] });
  assert.equal(JSON.stringify(normalized), '{"sparse":[null,{"alpha":1,"omega":2},null,null]}');

  sparse[2] = undefined;
  assert.throws(() => normalizeJson({ sparse }, "fixture"), {
    message: "Convex Wasm artifact pipeline: fixture.sparse[2] must be a plain object",
  });
});

test("canonical JSON memoizes only an exact deeply frozen plain-data object", () => {
  const originalStringify = JSON.stringify;
  let stringifyCalls = 0;
  JSON.stringify = function countedStringify(...argumentsList) {
    stringifyCalls += 1;
    return Reflect.apply(originalStringify, JSON, argumentsList);
  };
  try {
    const exact = freezeJsonTree({ omega: { value: 2 }, alpha: [1] });
    assert.equal(canonicalJson(exact), '{"alpha":[1],"omega":{"value":2}}');
    assert.equal(canonicalJson(exact), '{"alpha":[1],"omega":{"value":2}}');
    assert.equal(stringifyCalls, 1);

    const clone = freezeJsonTree(structuredClone(exact));
    assert.equal(canonicalJson(clone), canonicalJson(exact));
    assert.equal(stringifyCalls, 2);

    const serialized = freezeJsonTree(JSON.parse('{"alpha":[1],"omega":{"value":2}}'));
    assert.equal(canonicalJson(serialized), canonicalJson(exact));
    assert.equal(stringifyCalls, 3);

    const forged = freezeJsonTree({ omega: { value: Number.NaN }, alpha: [1] });
    assert.throws(() => canonicalJson(forged), /non-finite number/u);
    assert.throws(() => fingerprintJson(forged), /non-finite number/u);
  } finally {
    JSON.stringify = originalStringify;
  }
});

test("canonical JSON does not memoize mutable, proxy, or accessor input", () => {
  const nested = { value: 1 };
  const partiallyFrozen = Object.freeze({ nested });
  assert.equal(canonicalJson(partiallyFrozen), '{"nested":{"value":1}}');
  nested.value = 2;
  assert.equal(canonicalJson(partiallyFrozen), '{"nested":{"value":2}}');

  let proxyReads = 0;
  const proxy = new Proxy(Object.freeze({ value: 1 }), {
    get(target, key, receiver) {
      if (key === "value") proxyReads += 1;
      return Reflect.get(target, key, receiver);
    },
  });
  assert.equal(canonicalJson(proxy), '{"value":1}');
  const readsAfterFirstCall = proxyReads;
  assert.equal(canonicalJson(proxy), '{"value":1}');
  assert.ok(proxyReads > readsAfterFirstCall);

  let accessorValue = 0;
  const accessor = {};
  Object.defineProperty(accessor, "value", {
    enumerable: true,
    get() {
      accessorValue += 1;
      return accessorValue;
    },
  });
  Object.freeze(accessor);
  assert.notEqual(canonicalJson(accessor), canonicalJson(accessor));
  assert.notEqual(fingerprintJson(accessor), fingerprintJson(accessor));
});

test("canonical JSON samples accessor values once through normalization", () => {
  for (const createValue of [
    (getter) =>
      Object.create(Object.prototype, {
        value: { configurable: true, enumerable: true, get: getter },
      }),
    (getter) => {
      const value = [];
      Object.defineProperty(value, "0", {
        configurable: true,
        enumerable: true,
        get: getter,
      });
      return value;
    },
  ]) {
    let reads = 0;
    const value = createValue(() => {
      reads += 1;
      return reads === 1 ? 1 : undefined;
    });
    assert.equal(canonicalJson(value), Array.isArray(value) ? "[1]" : '{"value":1}');
    assert.equal(reads, 1);
  }

  let proxyReads = 0;
  const proxy = new Proxy(
    { value: 1 },
    {
      get(target, key, receiver) {
        if (key !== "value") return Reflect.get(target, key, receiver);
        proxyReads += 1;
        return proxyReads === 1 ? 1 : undefined;
      },
    }
  );
  assert.equal(canonicalJson(proxy), '{"value":1}');
  assert.equal(proxyReads, 1);

  let proxyArrayLengthReads = 0;
  const proxyArray = new Proxy([1], {
    get(target, key, receiver) {
      if (key !== "length") return Reflect.get(target, key, receiver);
      proxyArrayLengthReads += 1;
      return proxyArrayLengthReads === 1 ? 1 : 0;
    },
  });
  assert.equal(canonicalJson(proxyArray), "[1]");
  assert.equal(proxyArrayLengthReads, 1);
});

test("canonical JSON does not let an own non-enumerable toJSON bypass normalization", () => {
  for (const value of [{ value: 1 }, [1]]) {
    let toJsonCalls = 0;
    Object.defineProperty(value, "toJSON", {
      value() {
        toJsonCalls += 1;
        return { bypassed: true };
      },
    });
    assert.equal(canonicalJson(value), Array.isArray(value) ? "[1]" : '{"value":1}');
    assert.equal(toJsonCalls, 0);
  }
});

test("fingerprint memo reuses only the canonical bytes of each mutable value", () => {
  const first = { value: 1 };
  const second = { value: 1 };
  assert.equal(fingerprintJson(first), fingerprintJson(second));
  first.value = 2;
  assert.notEqual(fingerprintJson(first), fingerprintJson(second));
});

test("an unretained UTF-8 fingerprint does not evict retained canonical sources", () => {
  const sentinel = "fingerprint-source-cache-retention-sentinel";
  const sentinelSource = JSON.stringify(sentinel);
  const hashPrototype = Object.getPrototypeOf(createHash("sha256"));
  const originalUpdate = hashPrototype.update;
  let sentinelHashCount = 0;
  hashPrototype.update = function countedUpdate(value, ...argumentsList) {
    if (value === sentinelSource) sentinelHashCount += 1;
    return Reflect.apply(originalUpdate, this, [value, ...argumentsList]);
  };
  try {
    fingerprintJson(sentinel);
    // This is below the 8-MiB UTF-16 fast-rejection threshold but above the 8-MiB UTF-8 cache
    // bound. It must be hashed without displacing the retained sentinel.
    fingerprintJson("€".repeat(3 * 1024 * 1024));
    fingerprintJson(sentinel);
  } finally {
    hashPrototype.update = originalUpdate;
  }
  assert.equal(sentinelHashCount, 1);
});
