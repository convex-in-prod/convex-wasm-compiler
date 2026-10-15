import assert from "node:assert/strict";
import test from "node:test";

import { planConvexWasmEntryGroups } from "./convex-wasm-entry-grouping.mjs";

function fixture() {
  return {
    modules: [
      { id: "base", cost: 100 },
      { id: "large-library", cost: 10_000 },
      { id: "medium-library", cost: 1_000 },
      ...["a", "b", "c", "d", "e", "f"].map((id) => ({ id, cost: 10 })),
    ],
    entries: [
      { entryPath: "a", dependencies: ["base", "large-library", "a"] },
      { entryPath: "b", dependencies: ["base", "b"] },
      { entryPath: "c", dependencies: ["base", "large-library", "c"] },
      { entryPath: "d", dependencies: ["base", "medium-library", "d"] },
      { entryPath: "e", dependencies: ["base", "large-library", "e"] },
      { entryPath: "f", dependencies: ["base", "f"] },
    ],
    maximumCostInflation: 1.5,
  };
}

test("dependency costs produce unequal groups without a prescribed count", () => {
  const result = planConvexWasmEntryGroups(fixture());
  assert.deepEqual(result.entryGroups, [["a", "c", "e"], ["b", "f"], ["d"]]);
  assert.equal(result.modeledInventoryCost, 11_360);
  assert(result.groups.every((group) => group.costInflation <= 1.5));
});

test("input ordering and module labels do not change membership", () => {
  const original = fixture();
  const reversed = {
    ...original,
    modules: original.modules.toReversed().map(({ id, cost }) => ({ id: `renamed-${id}`, cost })),
    entries: original.entries.toReversed().map((entry) => ({
      ...entry,
      dependencies: entry.dependencies.toReversed().map((id) => `renamed-${id}`),
    })),
  };
  assert.deepEqual(planConvexWasmEntryGroups(reversed), planConvexWasmEntryGroups(original));
});

test("small body-cost changes preserve this partition while a dependency change can move entries", () => {
  const input = fixture();
  const baseline = planConvexWasmEntryGroups(input);
  input.modules.find(({ id }) => id === "c").cost += 1;
  assert.deepEqual(planConvexWasmEntryGroups(input).entryGroups, baseline.entryGroups);
  input.entries.find(({ entryPath }) => entryPath === "b").dependencies.push("large-library");
  assert.deepEqual(planConvexWasmEntryGroups(input).entryGroups, [
    ["a", "b", "c", "e"],
    ["d"],
    ["f"],
  ]);
});

test("universal dependencies produce linear candidates and split only at the logical-unit bound", () => {
  const count = 2_000;
  const result = planConvexWasmEntryGroups({
    modules: [{ id: "common", cost: 100 }],
    entries: Array.from({ length: count }, (_, index) => ({
      entryPath: `entry-${String(index).padStart(5, "0")}`,
      dependencies: ["common"],
    })),
    maximumCostInflation: 1,
  });
  assert.deepEqual(
    result.entryGroups.map((group) => group.length),
    [1023, 977]
  );
  assert.equal(result.diagnostics.candidatePairs, count - 1);
  assert.equal(result.modeledInventoryCost, 200);
});

test("disjoint closures stay separate even with a permissive inflation bound", () => {
  const result = planConvexWasmEntryGroups({
    modules: [
      { id: "first", cost: 1 },
      { id: "second", cost: 1 },
    ],
    entries: [
      { entryPath: "a", dependencies: ["first"] },
      { entryPath: "b", dependencies: ["second"] },
    ],
    maximumCostInflation: 100,
  });
  assert.deepEqual(result.entryGroups, [["a"], ["b"]]);
});

test("the union bound applies to every member, including after successive merges", () => {
  const modules = [
    { id: "common", cost: 100 },
    ...["a", "b", "c", "d"].map((id) => ({ id, cost: 40 })),
  ];
  const entries = ["a", "b", "c", "d"].map((entryPath) => ({
    entryPath,
    dependencies: ["common", entryPath],
  }));
  const result = planConvexWasmEntryGroups({ modules, entries, maximumCostInflation: 1.5 });
  assert.deepEqual(result.entryGroups, [
    ["a", "b"],
    ["c", "d"],
  ]);
  assert(result.groups.every((group) => group.cost <= 1.5 * group.minimumMemberCost));
});

test("malformed closures, duplicate entries and invalid costs fail", () => {
  for (const mutate of [
    (input) => input.entries.push(input.entries[0]),
    (input) => input.entries[0].dependencies.push("unknown"),
    (input) => input.entries[0].dependencies.push("base"),
    (input) => input.modules.push(input.modules[0]),
    (input) => {
      input.modules[0].cost = 0;
    },
    (input) => {
      input.modules[0].cost = Number.MAX_SAFE_INTEGER;
    },
    (input) => {
      input.maximumCostInflation = Infinity;
    },
  ]) {
    const input = fixture();
    mutate(input);
    assert.throws(() => planConvexWasmEntryGroups(input), /Convex Wasm entry grouping/);
  }
});

test("logical-unit bounds include each entry publication and admit the exact boundary", () => {
  const input = {
    modules: [{ id: "common", cost: 100 }, ...["a", "b", "c"].map((id) => ({ id, cost: 1 }))],
    entries: ["a", "b", "c"].map((entryPath) => ({
      entryPath,
      dependencies: ["common", entryPath],
    })),
    maximumCostInflation: 1.5,
    maximumLogicalUnits: 5,
  };
  assert.deepEqual(planConvexWasmEntryGroups(input).entryGroups, [["a", "b"], ["c"]]);
  assert.deepEqual(planConvexWasmEntryGroups({ ...input, maximumLogicalUnits: 4 }).entryGroups, [
    ["a"],
    ["b"],
    ["c"],
  ]);
  assert.throws(
    () => planConvexWasmEntryGroups({ ...input, maximumLogicalUnits: 2 }),
    /exceeds the logical-unit limit/u
  );
  for (const invalid of [0, 1, 2.5, Infinity, "5"]) {
    assert.throws(
      () => planConvexWasmEntryGroups({ ...input, maximumLogicalUnits: invalid }),
      /logical-unit limit must be/u
    );
  }
});
