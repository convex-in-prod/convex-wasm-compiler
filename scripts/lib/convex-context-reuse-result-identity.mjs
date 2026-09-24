const RESULT_KIND = "convex-context-reuse-analysis";
const SHA256 = /^[a-f0-9]{64}$/u;

function compareRustStrings(left, right) {
  // The analyzer sorts UTF-8 strings by scalar value, including non-BMP characters.
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftCodePoint = left.codePointAt(leftIndex);
    const rightCodePoint = right.codePointAt(rightIndex);
    if (leftCodePoint !== rightCodePoint) return leftCodePoint < rightCodePoint ? -1 : 1;
    leftIndex += leftCodePoint > 0xffff ? 2 : 1;
    rightIndex += rightCodePoint > 0xffff ? 2 : 1;
  }
  return leftIndex < left.length ? 1 : rightIndex < right.length ? -1 : 0;
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

function sortedEntries(entries, description) {
  if (!Array.isArray(entries) || entries.some((entry) => !validPath(entry))) {
    throw new Error(`${description} must contain normalized entry paths.`);
  }
  const sorted = [...entries].sort(compareRustStrings);
  if (JSON.stringify(sorted) !== JSON.stringify(entries) || new Set(entries).size !== entries.length) {
    throw new Error(`${description} must be sorted and unique.`);
  }
  return sorted;
}

export function authenticateConvexContextReuseResultIdentity(value, { expectedEntries } = {}) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).some((key) => {
      if (typeof key !== "string") return true;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor === undefined || !descriptor.enumerable || !("value" in descriptor);
    }) ||
    Object.keys(value).sort().join(",") !== "entries,kind,policyFingerprint,resultSha256" ||
    value.kind !== RESULT_KIND ||
    typeof value.policyFingerprint !== "string" ||
    !SHA256.test(value.policyFingerprint) ||
    typeof value.resultSha256 !== "string" ||
    !SHA256.test(value.resultSha256)
  ) {
    throw new Error("Convex context-reuse result identity is invalid.");
  }
  const entries = sortedEntries(value.entries, "Convex context-reuse result identity entries");
  if (expectedEntries !== undefined) {
    const expected = [...expectedEntries].sort(compareRustStrings);
    if (JSON.stringify(sortedEntries(expected, "expected context-reuse entries")) !== JSON.stringify(entries)) {
      throw new Error("Convex context-reuse result identity entries do not match the selected graph.");
    }
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    kind: value.kind,
    policyFingerprint: value.policyFingerprint,
    resultSha256: value.resultSha256,
  });
}
