import { compareStrings, fingerprintJson, normalizeJson } from "./convex-wasm-artifact-contract.mjs";

export const convexWasmOfficialOutputCohortCapsuleKind =
  "convex-wasm-official-output-cohort-planning-capsule-v6";
export const convexWasmOfficialOutputCohortCapsuleStage = "module-graph-cohort-planning-capsule";

const CAPSULE_SCHEMA_VERSION = 6;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const authenticatedCapsuleIdentities = new WeakSet();

function fail(message) {
  throw new Error(`Convex Wasm official-output cohort capsule: ${message}`);
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireExactKeys(value, expected, description) {
  const object = requireObject(value, description);
  const actual = Object.keys(object).sort(compareStrings);
  const keys = [...expected].sort(compareStrings);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    fail(`${description} has unsupported fields`);
  }
  return object;
}

function freezeJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeJsonTree(child);
    Object.freeze(value);
  }
  return value;
}

export function normalizeConvexWasmOfficialOutputCohortCapsuleIdentity(
  rawIdentity,
  description = "cohort capsule identity"
) {
  if (authenticatedCapsuleIdentities.has(rawIdentity)) return rawIdentity;
  const value = requireObject(rawIdentity, description);
  const expectedKeys = new Set([
    "chunkBindingSha256",
    "cohort",
    "esbuild",
    "kind",
    "policies",
    "schemaVersion",
    "sha256",
    "sourceEnvelope",
  ]);
  if (Object.hasOwn(value, "compilerRecordIdentity")) {
    expectedKeys.add("compilerRecordIdentity");
  }
  if (Object.hasOwn(value, "effectExecutionMode")) {
    expectedKeys.add("effectExecutionMode");
  }
  requireExactKeys(value, expectedKeys, description);
  const normalized = normalizeJson(value, description);
  requireSha256(normalized.chunkBindingSha256, `${description} chunk binding SHA-256`);
  const { sha256, ...payload } = normalized;
  if (
    payload.kind !== convexWasmOfficialOutputCohortCapsuleKind ||
    payload.schemaVersion !== CAPSULE_SCHEMA_VERSION
  ) {
    fail(`${description} has an unsupported schema`);
  }
  if (requireSha256(sha256, `${description} SHA-256`) !== fingerprintJson(payload)) {
    fail(`${description} digest is invalid`);
  }
  const identity = freezeJsonTree({ ...payload, sha256 });
  authenticatedCapsuleIdentities.add(identity);
  return identity;
}
