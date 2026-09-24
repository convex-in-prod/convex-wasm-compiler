import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  authenticateConvexWasmPhysicalShardLogicalUnit,
  convexWasmPhysicalShardLogicalUnitKind,
  convexWasmPhysicalShardPlanKind,
  convexWasmPhysicalShardPlanningRequestKind,
  convexWasmPhysicalShardPolicyKind,
  planConvexWasmPhysicalShards,
} from "./convex-wasm-physical-shard-planner.mjs";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function codeIdentity(name) {
  return sha256(`code:${name}`);
}

function bindingIdentity(name) {
  return sha256(`binding:${name}`);
}

function cohortIdentity(name) {
  return sha256(`cohort:${name}`);
}

function unit({
  name,
  bindingName = name,
  codeMaterial = name,
  dependencyNames = [],
  cohortNames = ["first", "second"],
  shareable = true,
  weight = 1,
  picMaterial = name,
}) {
  return authenticateConvexWasmPhysicalShardLogicalUnit({
    bindingIdentitySha256: bindingIdentity(bindingName),
    codeIdentitySha256: codeIdentity(codeMaterial),
    dependencies: dependencyNames.map(codeIdentity).sort(),
    kind: convexWasmPhysicalShardLogicalUnitKind,
    occurrences: cohortNames.map(cohortIdentity).sort(),
    picObject: { byteWeight: weight, sha256: sha256(`pic:${picMaterial}`) },
    shareable,
  });
}

function request(logicalUnits, { targetShardWeight = 10, minimumCohortCount } = {}) {
  return {
    kind: convexWasmPhysicalShardPlanningRequestKind,
    logicalUnits,
    policy: {
      ...(minimumCohortCount === undefined ? {} : { minimumCohortCount }),
      kind: convexWasmPhysicalShardPolicyKind,
      targetShardWeight,
    },
  };
}

function componentSha256ForCode(plan, name) {
  const component = plan.components.find((candidate) =>
    candidate.codeIdentitySha256s.includes(codeIdentity(name))
  );
  assert.ok(component, `missing component for ${name}`);
  return component.componentSha256;
}

function shardForCode(plan, name) {
  const componentSha256 = componentSha256ForCode(plan, name);
  const shard = plan.sharedShards.find((candidate) =>
    candidate.componentSha256s.includes(componentSha256)
  );
  assert.ok(shard, `missing shard for ${name}`);
  return shard;
}

function residualReasonForCode(plan, name) {
  const componentSha256 = componentSha256ForCode(plan, name);
  const residual = plan.residualComponents.find(
    (candidate) => candidate.componentSha256 === componentSha256
  );
  assert.ok(residual, `missing residual component for ${name}`);
  return residual.reason;
}

function assertShardOrderIsValid(plan) {
  const positionByShardSha256 = new Map(
    plan.shardOrder.map((shardSha256, index) => [shardSha256, index])
  );
  assert.equal(positionByShardSha256.size, plan.sharedShards.length);
  for (const shard of plan.sharedShards) {
    for (const dependencyShardSha256 of shard.dependencies) {
      assert.ok(
        positionByShardSha256.get(dependencyShardSha256) <
          positionByShardSha256.get(shard.shardSha256)
      );
    }
  }
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function membershipKey(componentSha256s) {
  return [...componentSha256s].sort(compareStrings).join("");
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sortedMemberships(componentGroups) {
  return componentGroups
    .map((componentSha256s) => [...componentSha256s].sort(compareStrings))
    .sort((left, right) => compareStrings(membershipKey(left), membershipKey(right)));
}

function rebuildQuotientTopologicalOrder(components, componentGroups) {
  const componentBySha256 = new Map(
    components.map((component) => [component.componentSha256, component])
  );
  assert.equal(componentBySha256.size, components.length);

  const groupIndexByComponentSha256 = new Map();
  for (const [groupIndex, componentSha256s] of componentGroups.entries()) {
    assert.ok(componentSha256s.length > 0);
    for (const componentSha256 of componentSha256s) {
      assert.ok(componentBySha256.has(componentSha256));
      assert.ok(!groupIndexByComponentSha256.has(componentSha256));
      groupIndexByComponentSha256.set(componentSha256, groupIndex);
    }
  }
  assert.equal(groupIndexByComponentSha256.size, components.length);

  const dependenciesByGroup = componentGroups.map(() => new Set());
  const dependentsByGroup = componentGroups.map(() => new Set());
  for (const component of components) {
    const groupIndex = groupIndexByComponentSha256.get(component.componentSha256);
    for (const dependencyComponentSha256 of component.dependencies) {
      const dependencyGroupIndex = groupIndexByComponentSha256.get(dependencyComponentSha256);
      assert.notEqual(dependencyGroupIndex, undefined);
      if (groupIndex === dependencyGroupIndex) continue;
      dependenciesByGroup[groupIndex].add(dependencyGroupIndex);
      dependentsByGroup[dependencyGroupIndex].add(groupIndex);
    }
  }

  const remainingDependencyCounts = dependenciesByGroup.map((dependencies) => dependencies.size);
  const ready = remainingDependencyCounts
    .map((count, groupIndex) => ({ count, groupIndex }))
    .filter(({ count }) => count === 0)
    .map(({ groupIndex }) => groupIndex);
  const order = [];
  while (ready.length > 0) {
    const groupIndex = ready.pop();
    order.push(groupIndex);
    for (const dependentGroupIndex of dependentsByGroup[groupIndex]) {
      remainingDependencyCounts[dependentGroupIndex] -= 1;
      if (remainingDependencyCounts[dependentGroupIndex] === 0) ready.push(dependentGroupIndex);
    }
  }
  return order.length === componentGroups.length ? order : undefined;
}

function referenceMergedGroups(componentGroups, targetComponentSha256, sourceComponentSha256) {
  const targetGroup = componentGroups.find((componentSha256s) =>
    componentSha256s.includes(targetComponentSha256)
  );
  const sourceGroup = componentGroups.find((componentSha256s) =>
    componentSha256s.includes(sourceComponentSha256)
  );
  assert.ok(targetGroup);
  assert.ok(sourceGroup);
  assert.notEqual(targetGroup, sourceGroup);
  assert.equal(sourceGroup.length, 1);
  return [
    ...componentGroups.filter(
      (componentSha256s) => componentSha256s !== targetGroup && componentSha256s !== sourceGroup
    ),
    [...targetGroup, ...sourceGroup].sort(compareStrings),
  ];
}

function referencePlaceSharedComponents(components, policy) {
  let componentGroups = components.map((component) => [component.componentSha256]);
  assert.ok(rebuildQuotientTopologicalOrder(components, componentGroups));
  const bins = components
    .filter(
      (component) =>
        component.sharedEligible && component.picObjectByteWeight > policy.targetShardWeight
    )
    .sort((left, right) => compareStrings(left.componentSha256, right.componentSha256))
    .map((component) => ({
      componentSha256s: [component.componentSha256],
      occurrenceCohortSha256s: component.occurrenceCohortSha256s,
      picObjectByteWeight: component.picObjectByteWeight,
    }));
  const normalComponents = components
    .filter(
      (component) =>
        component.sharedEligible && component.picObjectByteWeight <= policy.targetShardWeight
    )
    .sort((left, right) => {
      if (left.picObjectByteWeight !== right.picObjectByteWeight) {
        return left.picObjectByteWeight > right.picObjectByteWeight ? -1 : 1;
      }
      return compareStrings(left.componentSha256, right.componentSha256);
    });

  for (const component of normalComponents) {
    const candidates = bins
      .filter(
        (bin) =>
          component.picObjectByteWeight <= policy.targetShardWeight - bin.picObjectByteWeight &&
          arraysEqual(component.occurrenceCohortSha256s, bin.occurrenceCohortSha256s)
      )
      .sort((left, right) => {
        if (left.picObjectByteWeight !== right.picObjectByteWeight) {
          return left.picObjectByteWeight < right.picObjectByteWeight ? -1 : 1;
        }
        return compareStrings(
          membershipKey(left.componentSha256s),
          membershipKey(right.componentSha256s)
        );
      });
    let placed = false;
    for (const bin of candidates) {
      const candidateGroups = referenceMergedGroups(
        componentGroups,
        bin.componentSha256s[0],
        component.componentSha256
      );
      // This intentionally rebuilds the complete quotient for every candidate instead of
      // consulting the incremental quotient maintained by the planner.
      if (rebuildQuotientTopologicalOrder(components, candidateGroups) === undefined) continue;
      componentGroups = candidateGroups;
      bin.componentSha256s = [...bin.componentSha256s, component.componentSha256].sort(
        compareStrings
      );
      bin.picObjectByteWeight += component.picObjectByteWeight;
      placed = true;
      break;
    }
    if (!placed) {
      bins.push({
        componentSha256s: [component.componentSha256],
        occurrenceCohortSha256s: component.occurrenceCohortSha256s,
        picObjectByteWeight: component.picObjectByteWeight,
      });
    }
  }
  assert.ok(rebuildQuotientTopologicalOrder(components, componentGroups));
  return bins;
}

function assertPlanMatchesReferencePlacement(plan) {
  assert.deepEqual(
    sortedMemberships(plan.sharedShards.map((shard) => shard.componentSha256s)),
    sortedMemberships(
      referencePlaceSharedComponents(plan.components, plan.policy).map(
        (bin) => bin.componentSha256s
      )
    )
  );
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    return state;
  };
}

function randomInteger(random, exclusiveUpperBound) {
  return Math.floor((random() / 0x1_0000_0000) * exclusiveUpperBound);
}

function shuffled(values, random) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInteger(random, index + 1);
    [result[index], result[swapIndex]] = [result[swapIndex], result[index]];
  }
  return result;
}

function randomCohortNames(random) {
  const cohortNames = ["first", "second", "third", "fourth"].filter(
    () => randomInteger(random, 2) === 1
  );
  return cohortNames.length > 0 ? cohortNames : ["first"];
}

test("planning is invariant to authenticated logical-unit input order", () => {
  const units = [
    unit({ name: "entry", dependencyNames: ["support"], weight: 3 }),
    unit({ name: "support", weight: 5 }),
    unit({ name: "optional", cohortNames: ["first"], weight: 2 }),
  ];

  const first = planConvexWasmPhysicalShards(request(units));
  const reordered = planConvexWasmPhysicalShards(request([...units].reverse()));

  assert.deepEqual(first, reordered);
  assert.equal(first.kind, convexWasmPhysicalShardPlanKind);
});

test("a plan with no eligible shared components keeps residual components", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "single-occurrence", cohortNames: ["first"] }),
      unit({ name: "not-shareable", shareable: false }),
    ])
  );

  assert.deepEqual(plan.sharedShards, []);
  assert.equal(plan.residualComponents.length, 2);
  assert.deepEqual(
    new Set(plan.residualComponents.map((component) => component.reason)),
    new Set(["contains-non-shareable-logical-unit", "insufficient-cohort-occurrences"])
  );
});

test("cohort multiplicity is a policy-controlled sharing threshold with a default of two", () => {
  const reusable = unit({ name: "reusable", cohortNames: ["first", "second"] });
  const defaultPlan = planConvexWasmPhysicalShards(request([reusable]));
  const stricterPlan = planConvexWasmPhysicalShards(request([reusable], { minimumCohortCount: 3 }));

  assert.equal(defaultPlan.policy.minimumCohortCount, 2);
  assert.equal(defaultPlan.sharedShards.length, 1);
  assert.equal(stricterPlan.sharedShards.length, 0);
  assert.deepEqual(stricterPlan.residualComponents[0].reason, "insufficient-cohort-occurrences");
});

test("sharing requires a fully shared dependency closure", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "single-cohort-leaf", cohortNames: ["first"] }),
      unit({ name: "direct-dependent", dependencyNames: ["single-cohort-leaf"] }),
      unit({ name: "bridge", dependencyNames: ["single-cohort-leaf"] }),
      unit({ name: "transitive-dependent", dependencyNames: ["bridge"] }),
    ])
  );

  assert.deepEqual(plan.sharedShards, []);
  assert.equal(
    residualReasonForCode(plan, "single-cohort-leaf"),
    "insufficient-cohort-occurrences"
  );
  assert.equal(residualReasonForCode(plan, "direct-dependent"), "depends-on-residual-component");
  assert.equal(residualReasonForCode(plan, "bridge"), "depends-on-residual-component");
  assert.equal(
    residualReasonForCode(plan, "transitive-dependent"),
    "depends-on-residual-component"
  );
});

test("cyclic logical units stay atomic and must have coherent occurrence evidence", () => {
  const first = unit({ name: "cycle-first", dependencyNames: ["cycle-second"], weight: 3 });
  const second = unit({ name: "cycle-second", dependencyNames: ["cycle-first"], weight: 4 });
  const plan = planConvexWasmPhysicalShards(request([second, first]));

  assert.equal(plan.components.length, 1);
  assert.deepEqual(
    plan.components[0].codeIdentitySha256s,
    [codeIdentity("cycle-first"), codeIdentity("cycle-second")].sort()
  );
  assert.equal(plan.sharedShards.length, 1);
  assert.equal(plan.sharedShards[0].componentSha256s.length, 1);

  const incoherentSecond = unit({
    name: "cycle-second",
    dependencyNames: ["cycle-first"],
    cohortNames: ["first", "other"],
  });
  assert.throws(
    () => planConvexWasmPhysicalShards(request([first, incoherentSecond])),
    /incoherent occurrence evidence/u
  );
});

test("an eligible component larger than the target remains a singleton shared shard", () => {
  const plan = planConvexWasmPhysicalShards(
    request([unit({ name: "large", weight: 11 })], { targetShardWeight: 10 })
  );

  assert.equal(plan.sharedShards.length, 1);
  assert.equal(plan.sharedShards[0].componentSha256s.length, 1);
  assert.equal(plan.sharedShards[0].picObjectByteWeight, 11);
  assert.equal(plan.sharedShards[0].oversize, true);
});

test("largest-first placement uses stable binding identities to break equal-weight shard ties", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "six-left", weight: 6 }),
      unit({ name: "six-right", weight: 6 }),
      unit({ name: "four-left", weight: 4 }),
      unit({ name: "four-right", weight: 4 }),
    ])
  );
  const sixComponents = plan.components
    .filter((component) => component.picObjectByteWeight === 6)
    .sort((left, right) =>
      compareStrings(left.componentBindingSha256, right.componentBindingSha256)
    );
  const fourComponents = plan.components
    .filter((component) => component.picObjectByteWeight === 4)
    .sort((left, right) =>
      compareStrings(left.componentBindingSha256, right.componentBindingSha256)
    );

  assert.equal(plan.sharedShards.length, 2);
  for (const shard of plan.sharedShards) assert.equal(shard.picObjectByteWeight, 10);
  assert.deepEqual(
    shardForCode(plan, "six-left").componentSha256s,
    shardForCode(plan, "six-left").componentSha256s.slice().sort()
  );
  const shardForFirstSix = plan.sharedShards.find((shard) =>
    shard.componentSha256s.includes(sixComponents[0].componentSha256)
  );
  const shardForSecondSix = plan.sharedShards.find((shard) =>
    shard.componentSha256s.includes(sixComponents[1].componentSha256)
  );
  assert.ok(shardForFirstSix.componentSha256s.includes(fourComponents[0].componentSha256));
  assert.ok(shardForSecondSix.componentSha256s.includes(fourComponents[1].componentSha256));
});

test("a shared shard never combines components with different cohort occurrence sets", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "first-second", cohortNames: ["first", "second"], weight: 4 }),
      unit({ name: "second-third", cohortNames: ["second", "third"], weight: 4 }),
    ])
  );
  const componentsBySha256 = new Map(
    plan.components.map((component) => [component.componentSha256, component])
  );

  assert.equal(plan.sharedShards.length, 2);
  for (const shard of plan.sharedShards) {
    const occurrenceSets = shard.componentSha256s.map(
      (componentSha256) => componentsBySha256.get(componentSha256).occurrenceCohortSha256s
    );
    assert.deepEqual(occurrenceSets, [occurrenceSets[0]]);
  }
});

test("input authentication rejects duplicate dependencies, and planning rejects missing or duplicate units", () => {
  const duplicateDependency = {
    bindingIdentitySha256: bindingIdentity("duplicate-dependency"),
    codeIdentitySha256: codeIdentity("duplicate-dependency"),
    dependencies: [codeIdentity("same"), codeIdentity("same")],
    kind: convexWasmPhysicalShardLogicalUnitKind,
    occurrences: [cohortIdentity("first")],
    picObject: { byteWeight: 1, sha256: sha256("pic:duplicate-dependency") },
    shareable: true,
  };
  assert.throws(
    () => authenticateConvexWasmPhysicalShardLogicalUnit(duplicateDependency),
    /sorted without duplicates/u
  );

  const missingDependency = unit({ name: "missing", dependencyNames: ["unknown"] });
  assert.throws(
    () => planConvexWasmPhysicalShards(request([missingDependency])),
    /references unknown dependency/u
  );

  const duplicate = unit({ name: "duplicate" });
  assert.throws(
    () => planConvexWasmPhysicalShards(request([duplicate, structuredClone(duplicate)])),
    /repeats code identity/u
  );

  const tampered = structuredClone(unit({ name: "authenticated" }));
  tampered.picObject.byteWeight = 2;
  assert.throws(
    () => planConvexWasmPhysicalShards(request([tampered])),
    /authenticated identity is invalid/u
  );
});

test("component weight aggregation rejects sums outside the safe integer range", () => {
  const first = unit({
    name: "large-first",
    dependencyNames: ["large-second"],
    weight: Number.MAX_SAFE_INTEGER,
  });
  const second = unit({
    name: "large-second",
    dependencyNames: ["large-first"],
    weight: 1,
  });

  assert.throws(
    () => planConvexWasmPhysicalShards(request([first, second])),
    /exceeds the safe integer range/u
  );
});

test("the reusable plan has no application-local route, path, or slot material", () => {
  const plan = planConvexWasmPhysicalShards(request([unit({ name: "generic" })]));
  assert.doesNotMatch(JSON.stringify(plan), /(?:route|path|slot)/iu);
});

test("component dependencies become an acyclic shard DAG with dependency-first order", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "dependent-left", dependencyNames: ["base"], weight: 6 }),
      unit({ name: "base", weight: 6 }),
      unit({ name: "dependent-right", dependencyNames: ["base"], weight: 6 }),
    ])
  );
  const baseShard = shardForCode(plan, "base");
  const leftShard = shardForCode(plan, "dependent-left");
  const rightShard = shardForCode(plan, "dependent-right");

  assert.ok(leftShard.dependencies.includes(baseShard.shardSha256));
  assert.ok(rightShard.dependencies.includes(baseShard.shardSha256));
  assertShardOrderIsValid(plan);
});

test("a direct quotient edge becomes internal when its components share a shard", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "dependent", dependencyNames: ["dependency"], weight: 6 }),
      unit({ name: "dependency", weight: 4 }),
    ])
  );

  assert.equal(plan.sharedShards.length, 1);
  assert.equal(
    shardForCode(plan, "dependent").shardSha256,
    shardForCode(plan, "dependency").shardSha256
  );
  assert.deepEqual(plan.sharedShards[0].dependencies, []);
});

test("an indirect quotient path rejects a cyclic candidate merge with deterministic output", () => {
  const units = [
    unit({ name: "top-left", dependencyNames: ["bottom-right"], weight: 6 }),
    unit({ name: "top-right", dependencyNames: ["bottom-left"], weight: 6 }),
    unit({ name: "bottom-left", weight: 4 }),
    unit({ name: "bottom-right", weight: 4 }),
  ];
  const plan = planConvexWasmPhysicalShards(request(units));
  const reordered = planConvexWasmPhysicalShards(request([...units].reverse()));

  assert.equal(plan.sharedShards.length, 3);
  assert.deepEqual(plan, reordered);
  assert.equal(
    shardForCode(plan, "top-left").shardSha256,
    shardForCode(plan, "bottom-left").shardSha256
  );
  assert.notEqual(
    shardForCode(plan, "top-right").shardSha256,
    shardForCode(plan, "bottom-right").shardSha256
  );
  assertShardOrderIsValid(plan);
  const directedEdges = plan.sharedShards.flatMap((shard) =>
    shard.dependencies.map((dependency) => `${shard.shardSha256}:${dependency}`)
  );
  assert.equal(new Set(directedEdges).size, directedEdges.length);
});

test("a collapsed cyclic component remains an indirect quotient merge barrier", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "barrier-top", dependencyNames: ["barrier-cycle-first"], weight: 9 }),
      unit({ name: "barrier-middle", dependencyNames: ["barrier-bottom"], weight: 8 }),
      unit({ name: "barrier-bottom", weight: 1 }),
      unit({
        name: "barrier-cycle-first",
        dependencyNames: ["barrier-cycle-second"],
        weight: 1,
      }),
      unit({
        name: "barrier-cycle-second",
        dependencyNames: ["barrier-cycle-first"],
        weight: 1,
      }),
    ])
  );

  assert.equal(plan.components.length, 4);
  assert.equal(plan.sharedShards.length, 3);
  assert.equal(
    shardForCode(plan, "barrier-middle").shardSha256,
    shardForCode(plan, "barrier-cycle-first").shardSha256
  );
  assert.equal(
    shardForCode(plan, "barrier-cycle-first").shardSha256,
    shardForCode(plan, "barrier-cycle-second").shardSha256
  );
  assert.notEqual(
    shardForCode(plan, "barrier-top").shardSha256,
    shardForCode(plan, "barrier-bottom").shardSha256
  );
  assertPlanMatchesReferencePlacement(plan);
  assertShardOrderIsValid(plan);
});

test("a candidate can join an already multi-component target shard when its quotient stays acyclic", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "accepted-base", weight: 5 }),
      unit({ name: "accepted-middle", dependencyNames: ["accepted-base"], weight: 3 }),
      unit({ name: "accepted-top", dependencyNames: ["accepted-middle"], weight: 2 }),
    ])
  );

  assert.equal(plan.sharedShards.length, 1);
  assert.deepEqual(
    plan.sharedShards[0].componentSha256s,
    ["accepted-base", "accepted-middle", "accepted-top"]
      .map((name) => componentSha256ForCode(plan, name))
      .sort(compareStrings)
  );
  assertPlanMatchesReferencePlacement(plan);
  assertShardOrderIsValid(plan);
});

test("an indirect path rejects a candidate into an already multi-component target shard", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "rejected-source", weight: 2 }),
      unit({ name: "rejected-oversize", dependencyNames: ["rejected-source"], weight: 11 }),
      unit({ name: "rejected-target-base", dependencyNames: ["rejected-oversize"], weight: 5 }),
      unit({
        name: "rejected-target-middle",
        dependencyNames: ["rejected-target-base"],
        weight: 3,
      }),
    ])
  );

  assert.equal(plan.sharedShards.length, 3);
  assert.ok(shardForCode(plan, "rejected-oversize").oversize);
  assert.equal(
    shardForCode(plan, "rejected-target-base").shardSha256,
    shardForCode(plan, "rejected-target-middle").shardSha256
  );
  assert.notEqual(
    shardForCode(plan, "rejected-source").shardSha256,
    shardForCode(plan, "rejected-target-base").shardSha256
  );
  assertPlanMatchesReferencePlacement(plan);
  assertShardOrderIsValid(plan);
});

test("oversize shards remain isolated while residual components stay out of shared placement", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({ name: "oversize", weight: 11 }),
      unit({ name: "regular-left", weight: 6 }),
      unit({ name: "regular-right", weight: 4 }),
      unit({ name: "single-cohort", cohortNames: ["first"] }),
      unit({ name: "residual-dependent", dependencyNames: ["single-cohort"] }),
    ])
  );

  assert.equal(plan.sharedShards.length, 2);
  assert.ok(shardForCode(plan, "oversize").oversize);
  assert.equal(
    shardForCode(plan, "regular-left").shardSha256,
    shardForCode(plan, "regular-right").shardSha256
  );
  assert.equal(residualReasonForCode(plan, "single-cohort"), "insufficient-cohort-occurrences");
  assert.equal(residualReasonForCode(plan, "residual-dependent"), "depends-on-residual-component");
  assertPlanMatchesReferencePlacement(plan);
});

test("seeded DAG placements match the full quotient-rebuild reference", () => {
  const random = seededRandom(0x5eedc0de);
  const sampleCount = 48;
  let sawDagEdge = false;
  let sawNonShareable = false;
  let sawOversize = false;
  const cohortSets = new Set();

  for (let sampleIndex = 0; sampleIndex < sampleCount; sampleIndex += 1) {
    const targetShardWeight = 8 + randomInteger(random, 5);
    const unitCount = 8 + randomInteger(random, 6);
    const units = [];
    for (let unitIndex = 0; unitIndex < unitCount; unitIndex += 1) {
      const dependencyNames = [];
      for (let dependencyIndex = 0; dependencyIndex < unitIndex; dependencyIndex += 1) {
        if (randomInteger(random, 4) === 0) {
          dependencyNames.push(`seeded-${sampleIndex}-${dependencyIndex}`);
        }
      }
      if (unitIndex > 0 && unitIndex % 5 === 0 && dependencyNames.length === 0) {
        dependencyNames.push(`seeded-${sampleIndex}-${unitIndex - 1}`);
      }
      const forcedOversize = unitIndex === 0;
      const cohortNames = forcedOversize
        ? ["first", "second", "third", "fourth"]
        : randomCohortNames(random);
      const shareable = forcedOversize || randomInteger(random, 5) !== 0;
      const weight = forcedOversize
        ? targetShardWeight + 1 + randomInteger(random, 4)
        : 1 + randomInteger(random, targetShardWeight);
      units.push(
        unit({
          name: `seeded-${sampleIndex}-${unitIndex}`,
          dependencyNames,
          cohortNames,
          shareable,
          weight,
        })
      );
      sawDagEdge ||= dependencyNames.length > 0;
      sawNonShareable ||= !shareable;
      sawOversize ||= weight > targetShardWeight;
      cohortSets.add(cohortNames.join(","));
    }

    const plan = planConvexWasmPhysicalShards(
      request(shuffled(units, random), {
        minimumCohortCount: 2 + randomInteger(random, 2),
        targetShardWeight,
      })
    );
    assertPlanMatchesReferencePlacement(plan);
    assertShardOrderIsValid(plan);
  }

  assert.ok(sawDagEdge);
  assert.ok(sawNonShareable);
  assert.ok(sawOversize);
  assert.ok(cohortSets.size > 4);
});

test("material and policy changes produce new authenticated identities", () => {
  const baseline = planConvexWasmPhysicalShards(request([unit({ name: "identity", weight: 4 })]));
  const changedMaterial = planConvexWasmPhysicalShards(
    request([
      unit({
        name: "identity",
        codeMaterial: "identity-changed",
        weight: 4,
        picMaterial: "changed",
      }),
    ])
  );
  const changedPolicy = planConvexWasmPhysicalShards(
    request([unit({ name: "identity", weight: 4 })], { targetShardWeight: 9 })
  );

  assert.notEqual(
    baseline.components[0].componentSha256,
    changedMaterial.components[0].componentSha256
  );
  assert.equal(
    baseline.components[0].componentBindingSha256,
    changedMaterial.components[0].componentBindingSha256
  );
  assert.notDeepEqual(
    baseline.sharedShards[0].componentSha256s,
    changedMaterial.sharedShards[0].componentSha256s
  );
  assert.deepEqual(
    baseline.sharedShards[0].componentBindingSha256s,
    changedMaterial.sharedShards[0].componentBindingSha256s
  );
  assert.equal(baseline.sharedShards[0].shardSha256, changedMaterial.sharedShards[0].shardSha256);
  assert.notEqual(baseline.planSha256, changedMaterial.planSha256);
  assert.notEqual(baseline.policy.policySha256, changedPolicy.policy.policySha256);
  assert.notEqual(baseline.planSha256, changedPolicy.planSha256);
});

test("dependency material rotates the exact closure without rotating stable shard roles", () => {
  const baseline = planConvexWasmPhysicalShards(
    request([
      unit({ name: "dependency", weight: 6 }),
      unit({ name: "importer", dependencyNames: ["dependency"], weight: 6 }),
    ])
  );
  const changed = planConvexWasmPhysicalShards(
    request([
      unit({
        name: "dependency",
        codeMaterial: "dependency-changed",
        picMaterial: "dependency-changed",
        weight: 6,
      }),
      unit({ name: "importer", dependencyNames: ["dependency-changed"], weight: 6 }),
    ])
  );
  const componentsByBinding = (plan) =>
    new Map(plan.components.map((component) => [component.bindingIdentitySha256s[0], component]));
  const baselineComponents = componentsByBinding(baseline);
  const changedComponents = componentsByBinding(changed);

  assert.deepEqual([...changedComponents.keys()], [...baselineComponents.keys()]);
  for (const [bindingSha256, baselineComponent] of baselineComponents) {
    const changedComponent = changedComponents.get(bindingSha256);
    assert.equal(changedComponent.componentBindingSha256, baselineComponent.componentBindingSha256);
    assert.notEqual(changedComponent.componentSha256, baselineComponent.componentSha256);
  }
  assert.deepEqual(
    changed.sharedShards.map(({ componentBindingSha256s, shardSha256 }) => ({
      componentBindingSha256s,
      shardSha256,
    })),
    baseline.sharedShards.map(({ componentBindingSha256s, shardSha256 }) => ({
      componentBindingSha256s,
      shardSha256,
    }))
  );
  assert.notDeepEqual(
    changed.sharedShards.map(({ componentSha256s }) => componentSha256s),
    baseline.sharedShards.map(({ componentSha256s }) => componentSha256s)
  );
  assert.notEqual(changed.planSha256, baseline.planSha256);
});

test("incompatible exact variants with one stable binding remain separate", () => {
  const plan = planConvexWasmPhysicalShards(
    request([
      unit({
        name: "first-variant",
        bindingName: "shared-binding",
        cohortNames: ["first", "second"],
      }),
      unit({
        name: "second-variant",
        bindingName: "shared-binding",
        cohortNames: ["third", "fourth"],
      }),
    ])
  );

  assert.equal(plan.components.length, 2);
  assert.equal(plan.sharedShards.length, 2);
  assert.deepEqual(
    plan.components.map(({ bindingIdentitySha256s }) => bindingIdentitySha256s),
    [[bindingIdentity("shared-binding")], [bindingIdentity("shared-binding")]]
  );
  assert.equal(
    new Set(plan.components.map(({ componentBindingSha256 }) => componentBindingSha256)).size,
    2
  );
  assert.equal(new Set(plan.sharedShards.map(({ shardSha256 }) => shardSha256)).size, 2);

  assert.throws(
    () =>
      planConvexWasmPhysicalShards(
        request([
          unit({
            name: "overlapping-first-variant",
            bindingName: "overlapping-binding",
            cohortNames: ["first", "second"],
          }),
          unit({
            name: "overlapping-second-variant",
            bindingName: "overlapping-binding",
            cohortNames: ["second", "third"],
          }),
        ])
      ),
    /selects multiple exact variants for stable binding .* in one cohort/u
  );
});
