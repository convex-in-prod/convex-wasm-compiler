import { compareStrings, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";

const COHORT_IDENTITY_KIND = "convex-context-reuse-cohort-analysis";
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

function fail(message) {
  throw new Error(`Convex context-reuse cohort analysis identity ${message}.`);
}

function validSha256(value) {
  return typeof value === "string" && SHA256_PATTERN.test(value);
}

function validPath(value) {
  return (
    typeof value === "string" &&
    value.isWellFormed() &&
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.includes("\0") &&
    value.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..")
  );
}

function normalizedEntryGraphs(entryGraphs, description) {
  if (!Array.isArray(entryGraphs) || entryGraphs.length === 0) {
    throw new Error(`${description} must not be empty.`);
  }
  const normalized = entryGraphs.map((entry, index) => {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      Object.keys(entry).sort().join(",") !== "dependencyGraphSha256,entryPath" ||
      !validPath(entry.entryPath) ||
      !validSha256(entry.dependencyGraphSha256)
    ) {
      throw new Error(`${description} entry ${index} is invalid.`);
    }
    return {
      dependencyGraphSha256: entry.dependencyGraphSha256,
      entryPath: entry.entryPath,
    };
  });
  const sorted = [...normalized].sort((left, right) =>
    compareStrings(left.entryPath, right.entryPath)
  );
  if (
    JSON.stringify(sorted) !== JSON.stringify(normalized) ||
    new Set(normalized.map(({ entryPath }) => entryPath)).size !== normalized.length
  ) {
    throw new Error(`${description} must be sorted and unique.`);
  }
  return normalized;
}

function normalizedThirdPartyMaterialFingerprints(value) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.entries(value).some(
      ([target, fingerprint]) =>
        !target.startsWith("node_modules/") || !validPath(target) || !validSha256(fingerprint)
    )
  ) {
    fail("third-party material fingerprints are invalid");
  }
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => compareStrings(left, right))
  );
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export function authenticateConvexContextReuseCohortAnalysisIdentity(
  value,
  { expectedEntryGraphs } = {}
) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "entries,entryGraphSha256s,kind,policyFingerprint,resultSha256,sharedAnalysisSha256,thirdPartyMaterialFingerprints" ||
    value.kind !== COHORT_IDENTITY_KIND ||
    !validSha256(value.policyFingerprint) ||
    !validSha256(value.sharedAnalysisSha256) ||
    !validSha256(value.resultSha256) ||
    !Array.isArray(value.entries) ||
    !Array.isArray(value.entryGraphSha256s) ||
    value.entries.length === 0 ||
    value.entries.length !== value.entryGraphSha256s.length
  ) {
    fail("is invalid");
  }
  const entryGraphs = normalizedEntryGraphs(
    value.entries.map((entryPath, index) => ({
      dependencyGraphSha256: value.entryGraphSha256s[index],
      entryPath,
    })),
    "Convex context-reuse cohort analysis identity entry graphs"
  );
  const payload = {
    entries: entryGraphs.map(({ entryPath }) => entryPath),
    entryGraphSha256s: entryGraphs.map(({ dependencyGraphSha256 }) => dependencyGraphSha256),
    kind: value.kind,
    policyFingerprint: value.policyFingerprint,
    sharedAnalysisSha256: value.sharedAnalysisSha256,
    thirdPartyMaterialFingerprints: normalizedThirdPartyMaterialFingerprints(
      value.thirdPartyMaterialFingerprints
    ),
  };
  if (fingerprintJson(payload) !== value.resultSha256) fail("digest is invalid");
  if (
    expectedEntryGraphs !== undefined &&
    JSON.stringify(entryGraphs) !==
      JSON.stringify(
        normalizedEntryGraphs(
          expectedEntryGraphs,
          "expected Convex context-reuse cohort analysis entry graphs"
        )
      )
  ) {
    fail("has the wrong entry graph");
  }
  return deepFreeze({ ...payload, resultSha256: value.resultSha256 });
}
