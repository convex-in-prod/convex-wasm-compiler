import assert from "node:assert/strict";
import test from "node:test";
import {
  contextReuseActionPolicy,
  requireStrictContextReuseEntries,
} from "./convex-context-reuse-action-policy.mjs";

test("action policy defaults preserve fresh actions and normalize explicit selection", () => {
  assert.equal(contextReuseActionPolicy(undefined), undefined);
  assert.deepEqual(contextReuseActionPolicy({ entries: ["nested/b.ts", "a.ts"] }), {
    entries: ["a.ts", "nested/b.ts"],
    grouping: true,
  });
  assert.deepEqual(contextReuseActionPolicy({ entries: [], grouping: false }), {
    entries: [],
    grouping: false,
  });
});

test("action selection rejects malformed paths, duplicate entries, and unknown policy", () => {
  for (const entry of ["", "..", "../a.ts", "/a.ts", "a/../b.ts", "a\\b.ts", "a//b.ts"]) {
    assert.throws(() => contextReuseActionPolicy({ entries: [entry] }), /normalized paths/u);
  }
  for (const policy of [null, true, {}, { entries: "a.ts" }, { entries: [], unexpected: true }]) {
    assert.throws(() => contextReuseActionPolicy(policy), /entries array/u);
  }
  assert.throws(() => contextReuseActionPolicy({ entries: ["a.ts", "a.ts"] }), /unique/u);
  assert.throws(() => contextReuseActionPolicy({ entries: [], grouping: "true" }), /boolean/u);
});

test("strict action admission rejects unresolved findings only for selected action entries", () => {
  const admission = {
    identity: { entries: ["functions/action.ts", "functions/query.ts"] },
    applicationAdmission: {
      entryAdmissions: [
        { entry: "functions/action.ts", disposition: "analysis-safe" },
        {
          entry: "functions/query.ts",
          disposition: "conservative-local-mutator-application",
        },
      ],
    },
  };
  requireStrictContextReuseEntries(admission, ["functions/action.ts"]);
  assert.throws(
    () => requireStrictContextReuseEntries(admission, ["functions/query.ts"]),
    /without admitted findings/u
  );
  requireStrictContextReuseEntries(admission, ["functions/query.ts"], ["functions/query.ts"]);
  assert.throws(
    () =>
      requireStrictContextReuseEntries(admission, ["functions/query.ts"], ["functions/action.ts"]),
    /without admitted findings/u
  );
  assert.throws(
    () =>
      requireStrictContextReuseEntries(
        admission,
        ["functions/missing.ts"],
        ["functions/missing.ts"]
      ),
    /missing/u
  );
  assert.throws(
    () =>
      requireStrictContextReuseEntries(
        {
          ...admission,
          applicationAdmission: {
            entryAdmissions: [{ entry: "functions/query.ts", disposition: "hard" }],
          },
        },
        ["functions/query.ts"],
        ["functions/query.ts"]
      ),
    /without admitted findings/u
  );
  assert.throws(
    () => requireStrictContextReuseEntries(admission, ["functions/missing.ts"]),
    /missing/u
  );
  for (const entries of [null, undefined, "functions/action.ts", new Set()]) {
    assert.throws(() => requireStrictContextReuseEntries(admission, entries), /must be an array/u);
  }
});
