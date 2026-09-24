import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const CONTROL_CHARACTER_PATTERN = /\p{Control}/u;
const WHITESPACE_PATTERN = /\p{White_Space}/u;
// A memo applies only to the exact object that completed canonicalization. It is never
// copied to structurally equal input, and only deeply frozen ordinary data trees can retain one.
// Proxies and accessors continue through the full path on every call.
const canonicalJsonByExactImmutableValue = new WeakMap();
const fingerprintJsonByExactImmutableValue = new WeakMap();
const fingerprintJsonByCanonicalSource = new Map();
let fingerprintJsonCanonicalSourceBytes = 0;
const FINGERPRINT_SOURCE_CACHE_MAX_BYTES = 8 * 1024 * 1024;
const FINGERPRINT_SOURCE_CACHE_MAX_ENTRIES = 2048;

// Keep the historical error prefix while these contract helpers are shared by the pipeline's
// smaller modules. Callers and cache tests rely on the fail-closed wording, not this file name.
function fail(message) {
  throw new Error(`Convex Wasm artifact pipeline: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertExactKeys(value, allowedKeys, description) {
  const unknownKeys = Object.keys(value).filter((key) => !allowedKeys.has(key));
  if (unknownKeys.length > 0) {
    fail(`${description} has unknown field(s): ${unknownKeys.sort().join(", ")}`);
  }
}

function assertPlainObject(value, description) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${description} must be a plain object`);
  }
}

function requireExactPlainObject(value, keys, description) {
  assertPlainObject(value, description);
  assertExactKeys(value, new Set(keys), description);
  if (Object.keys(value).length !== keys.length) {
    fail(`${description} must contain exactly ${[...keys].sort(compareStrings).join(", ")}`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function requireManifestString(value, description, maximumBytes, allowWhitespace) {
  requireString(value, description);
  if (Buffer.byteLength(value) > maximumBytes) {
    fail(`${description} must contain at most ${maximumBytes} UTF-8 bytes`);
  }
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    fail(`${description} must not contain control characters`);
  }
  if (!allowWhitespace && WHITESPACE_PATTERN.test(value)) {
    fail(`${description} must not contain whitespace`);
  }
  return value;
}

function requireSha256(value, description) {
  requireString(value, description);
  if (!SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireStringArray(value, description) {
  if (!Array.isArray(value)) {
    fail(`${description} must be an array`);
  }
  return value.map((item, index) => requireString(item, `${description}[${index}]`));
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requirePositiveU32(value, description) {
  requirePositiveInteger(value, description);
  if (value > 0xffffffff) {
    fail(`${description} must fit in an unsigned 32-bit integer`);
  }
  return value;
}

function requireBoolean(value, description) {
  if (typeof value !== "boolean") {
    fail(`${description} must be a boolean`);
  }
  return value;
}

function requireEnum(value, allowedValues, description) {
  requireString(value, description);
  if (!allowedValues.has(value)) {
    fail(`${description} must be one of: ${[...allowedValues].join(", ")}`);
  }
  return value;
}

function normalizeJsonPath(description, path) {
  let rendered = description;
  for (const part of path) {
    rendered += typeof part === "number" ? `[${part}]` : `.${part}`;
  }
  return rendered;
}

function normalizeJsonValue(value, description, path) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail(`${normalizeJsonPath(description, path)} contains a non-finite number`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    // A Proxy can report a different virtual length on every read. Bind the normalized sequence
    // to the same single length observation that allocated it.
    const length = value.length;
    return Array.from({ length }, (_, index) => {
      // JSON.stringify renders a true hole as null. Materialize that value now so a later dynamic
      // child read cannot add an inherited index after this one-read normalization sampled it.
      if (!(index in value)) {
        return null;
      }
      path.push(index);
      const nested = normalizeJsonValue(value[index], description, path);
      path.pop();
      return nested;
    });
  }
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${normalizeJsonPath(description, path)} must be a plain object`);
  }
  const keys = Object.keys(value).sort(compareStrings);
  // The built-ins create own data properties, including __proto__, without invoking inherited
  // setters. Avoid constructing a property descriptor for every field of large compiler records.
  return Object.fromEntries(
    keys.map((key) => {
      path.push(key);
      const nested = normalizeJsonValue(value[key], description, path);
      path.pop();
      return [key, nested];
    })
  );
}

function normalizeJson(value, description) {
  return normalizeJsonValue(value, description, []);
}

// Parsed canonical manifests and the objects assembled from them are already in the required
// UTF-16 key order. Avoid allocating a second normalized object in that common case. The check is
// deliberately strict about JSON values so this fast path has exactly the same fail-closed
// behavior as normalizeJson for unsupported values, prototypes, and non-finite numbers.
function isCanonicalJsonValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "object" && isProxy(value)) return false;
  // Normalization deliberately strips non-JSON fields. An own non-enumerable toJSON method is
  // behavior, not JSON data, but JSON.stringify would invoke it if the fast path kept this exact
  // value.
  if (typeof value === "object" && Object.hasOwn(value, "toJSON")) return false;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) return false;
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined) {
        continue;
      }
      if (!("value" in descriptor) || !isCanonicalJsonValue(descriptor.value)) return false;
    }
    return true;
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  let previousKey;
  const keys = Object.keys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (previousKey !== undefined && key < previousKey) return false;
    previousKey = key;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    // Accessors must take the normalized path. Otherwise the canonicality probe and
    // JSON.stringify can observe different values, including a supported value followed by one
    // that this contract must reject.
    if (descriptor === undefined || !("value" in descriptor)) return false;
    if (!isCanonicalJsonValue(descriptor.value)) return false;
  }
  return true;
}

function isDeeplyFrozenPlainJsonData(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || isProxy(value) || !Object.isFrozen(value)) {
    return false;
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) return false;
  } else if (Object.getPrototypeOf(value) !== Object.prototype) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) return false;
    if (!isDeeplyFrozenPlainJsonData(descriptor.value)) return false;
  }
  return true;
}

export {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  normalizeJson,
  requireBoolean,
  requireEnum,
  requireExactPlainObject,
  requireManifestString,
  requirePositiveInteger,
  requirePositiveU32,
  requireSha256,
  requireString,
  requireStringArray,
};

function canonicalJson(value) {
  const isObject = value !== null && typeof value === "object";
  if (isObject) {
    const cached = canonicalJsonByExactImmutableValue.get(value);
    if (cached !== undefined) return cached;
  }
  const canonicalValue = isCanonicalJsonValue(value)
    ? value
    : normalizeJson(value, "canonical JSON value");
  const serialized = JSON.stringify(canonicalValue);
  if (isObject && isDeeplyFrozenPlainJsonData(value)) {
    canonicalJsonByExactImmutableValue.set(value, serialized);
  }
  return serialized;
}

function fingerprintJson(value) {
  const isObject = value !== null && typeof value === "object";
  if (isObject) {
    const cached = fingerprintJsonByExactImmutableValue.get(value);
    if (cached !== undefined) return cached;
  }
  const source = canonicalJson(value);
  let fingerprint;
  if (source.length > FINGERPRINT_SOURCE_CACHE_MAX_BYTES) {
    fingerprint = createHash("sha256").update(source).digest("hex");
  } else {
    fingerprint = fingerprintJsonByCanonicalSource.get(source);
    if (fingerprint !== undefined) {
      // Refresh the entry so frequently reused identities remain available within the bounded
      // process-local cache.
      fingerprintJsonByCanonicalSource.delete(source);
      fingerprintJsonByCanonicalSource.set(source, fingerprint);
    } else {
      const sourceBytes = Buffer.byteLength(source);
      fingerprint = createHash("sha256").update(source).digest("hex");
      // The cheap UTF-16 length check above can admit a source whose UTF-8 bytes exceed the cache
      // bound. Hash it without evicting retained entries for a value that cannot itself be kept.
      if (sourceBytes <= FINGERPRINT_SOURCE_CACHE_MAX_BYTES) {
        while (
          fingerprintJsonByCanonicalSource.size >= FINGERPRINT_SOURCE_CACHE_MAX_ENTRIES ||
          (fingerprintJsonByCanonicalSource.size > 0 &&
            fingerprintJsonCanonicalSourceBytes + sourceBytes > FINGERPRINT_SOURCE_CACHE_MAX_BYTES)
        ) {
          const oldestSource = fingerprintJsonByCanonicalSource.keys().next().value;
          fingerprintJsonCanonicalSourceBytes -= Buffer.byteLength(oldestSource);
          fingerprintJsonByCanonicalSource.delete(oldestSource);
        }
        fingerprintJsonByCanonicalSource.set(source, fingerprint);
        fingerprintJsonCanonicalSourceBytes += sourceBytes;
      }
    }
  }
  if (isObject && canonicalJsonByExactImmutableValue.has(value)) {
    fingerprintJsonByExactImmutableValue.set(value, fingerprint);
  }
  return fingerprint;
}
