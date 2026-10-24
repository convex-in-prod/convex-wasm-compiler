import { posix } from "node:path";

/** Omitted action policy preserves fresh actions for existing projects. */
export function contextReuseActionPolicy(value) {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => key !== "entries" && key !== "grouping") ||
    !Array.isArray(value.entries)
  ) {
    throw new Error(
      "Context-reuse actions must contain an entries array and optional grouping boolean."
    );
  }
  const grouping = value.grouping === undefined ? true : value.grouping;
  if (typeof grouping !== "boolean") {
    throw new Error("Context-reuse action grouping must be a boolean.");
  }
  const entries = value.entries
    .map((entry) => {
      if (
        typeof entry !== "string" ||
        entry === "" ||
        entry.includes("\\") ||
        posix.isAbsolute(entry) ||
        posix.normalize(entry) !== entry ||
        entry === ".." ||
        entry.startsWith("../")
      ) {
        throw new Error(
          "Context-reuse action entries must be normalized paths relative to the functions directory."
        );
      }
      return entry;
    })
    .sort();
  if (new Set(entries).size !== entries.length) {
    throw new Error("Context-reuse action entries must be unique.");
  }
  return { entries, grouping };
}

/** Selected action graphs cannot inherit a database mutator-analysis exception. */
export function requireStrictContextReuseEntries(admission, strictEntries) {
  if (!Array.isArray(strictEntries)) {
    throw new Error("Strict context-reuse entries must be an array.");
  }
  const selected = new Set(strictEntries);
  for (const entry of selected) {
    if (!admission.identity.entries.includes(entry)) {
      throw new Error(`Selected action entry is missing from context-reuse analysis: ${entry}`);
    }
  }
  for (const entry of admission.applicationAdmission?.entryAdmissions ?? []) {
    if (selected.has(entry.entry) && entry.disposition !== "analysis-safe") {
      throw new Error(
        `Action context reuse requires supported analysis without admitted findings: ${entry.entry}`
      );
    }
  }
}
