import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputChunkApplicationMaximumUnits } from "./convex-wasm-official-output-chunk-application-unit.mjs";
import {
  createConvexWasmDeploymentOutputClosureAuthentication,
  projectConvexWasmDeploymentOutputChunkGraph,
  selectConvexWasmDeploymentOutputClosure,
} from "./convex-wasm-output-closure.mjs";

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireName(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Convex Wasm entry grouping: ${description} must be a non-empty string`);
  }
  return value;
}

function addCost(left, right) {
  const result = left + right;
  if (!Number.isSafeInteger(result)) {
    throw new Error("Convex Wasm entry grouping: accumulated cost exceeds safe integer precision");
  }
  return result;
}

// Dependencies are complete logical-module closures, including every member of a reached cycle.
// The caller derives them from the authenticated graph; this planner supplies no source authority.
export function planConvexWasmEntryGroups({
  modules,
  entries,
  maximumCostInflation,
  maximumLogicalUnits = convexWasmOfficialOutputChunkApplicationMaximumUnits,
}) {
  if (
    !Array.isArray(modules) ||
    modules.length === 0 ||
    !Array.isArray(entries) ||
    entries.length === 0
  ) {
    throw new Error("Convex Wasm entry grouping: non-empty module and entry arrays are required");
  }
  if (!Number.isFinite(maximumCostInflation) || maximumCostInflation < 1) {
    throw new Error(
      "Convex Wasm entry grouping: maximum cost inflation must be finite and at least one"
    );
  }
  if (!Number.isSafeInteger(maximumLogicalUnits) || maximumLogicalUnits < 2) {
    throw new Error(
      "Convex Wasm entry grouping: logical-unit limit must be a safe integer of at least two"
    );
  }
  const costs = new Map();
  for (const module of modules) {
    const id = requireName(module.id, "module identity");
    if (costs.has(id) || !Number.isSafeInteger(module.cost) || module.cost <= 0) {
      throw new Error(
        "Convex Wasm entry grouping: module identities must be unique with positive integer costs"
      );
    }
    costs.set(id, module.cost);
  }
  const normalized = entries
    .map((entry) => {
      const entryPath = requireName(entry.entryPath, "entry path");
      if (!Array.isArray(entry.dependencies) || entry.dependencies.length === 0) {
        throw new Error("Convex Wasm entry grouping: each entry requires its dependency closure");
      }
      const dependencies = new Set();
      let cost = 0;
      for (const id of entry.dependencies) {
        if (!costs.has(id) || dependencies.has(id)) {
          throw new Error("Convex Wasm entry grouping: dependency is unknown or repeated");
        }
        dependencies.add(id);
        cost = addCost(cost, costs.get(id));
      }
      if (dependencies.size + 1 > maximumLogicalUnits) {
        throw new Error(
          `Convex Wasm entry grouping: entry ${JSON.stringify(entryPath)} exceeds the logical-unit limit`
        );
      }
      return { entryPath, dependencies, cost };
    })
    .sort((left, right) => compareStrings(left.entryPath, right.entryPath));
  if (new Set(normalized.map(({ entryPath }) => entryPath)).size !== normalized.length) {
    throw new Error("Convex Wasm entry grouping: entry paths must be unique");
  }
  const occurrences = new Map();
  for (const [index, entry] of normalized.entries()) {
    for (const id of entry.dependencies) {
      const members = occurrences.get(id);
      if (members === undefined) occurrences.set(id, [index]);
      else members.push(index);
    }
  }

  // Neighbor chains keep candidate storage linear in closure memberships. A universal
  // dependency must not produce a quadratic graph. A coarse cost-order chain also connects
  // similarly sized entries whose only overlap is universal. Stable path order breaks ties.
  const pairs = new Map();
  const connect = (left, right) => {
    if (right < left) [left, right] = [right, left];
    const key = `${left}:${right}`;
    if (!pairs.has(key)) pairs.set(key, { left, right });
  };
  for (const members of occurrences.values()) {
    if (members.length === normalized.length) continue;
    for (let index = 1; index < members.length; index++)
      connect(members[index - 1], members[index]);
  }
  const costOrder = normalized
    .map((entry, index) => ({
      index,
      bucket: Math.ceil(Math.log2(entry.cost)),
    }))
    .sort((left, right) => left.bucket - right.bucket || left.index - right.index);
  for (let index = 1; index < costOrder.length; index++) {
    connect(costOrder[index - 1].index, costOrder[index].index);
  }
  const scored = [...pairs.values()]
    .map((pair) => {
      const left = normalized[pair.left].dependencies;
      const right = normalized[pair.right].dependencies;
      const smaller = left.size <= right.size ? left : right;
      const larger = smaller === left ? right : left;
      let score = 0;
      for (const id of smaller) {
        const frequency = occurrences.get(id).length;
        if (larger.has(id) && frequency < normalized.length) {
          // Discount broadly shared modules when ordering merges, but count their full cost
          // in the actual savings and inflation bound below.
          score = addCost(score, Math.max(1, Math.floor(costs.get(id) / frequency)));
        }
      }
      return { ...pair, score };
    })
    .sort(
      (left, right) =>
        right.score - left.score || left.left - right.left || left.right - right.right
    );

  const groups = normalized.map((entry, index) => ({
    parent: index,
    members: [index],
    dependencies: new Set(entry.dependencies),
    cost: entry.cost,
    minimumMemberCost: entry.cost,
  }));
  const root = (index) => {
    let current = index;
    while (groups[current].parent !== current) current = groups[current].parent;
    while (index !== current) {
      const next = groups[index].parent;
      groups[index].parent = current;
      index = next;
    }
    return current;
  };
  let attemptedMerges = 0;
  let acceptedMerges = 0;
  for (const pair of scored) {
    const leftIndex = root(pair.left);
    const rightIndex = root(pair.right);
    if (leftIndex === rightIndex) continue;
    attemptedMerges++;
    const left = groups[leftIndex];
    const right = groups[rightIndex];
    const smaller = left.dependencies.size <= right.dependencies.size ? left : right;
    const larger = smaller === left ? right : left;
    let sharedCost = 0;
    let additionalCost = 0;
    let additionalUnits = 0;
    for (const id of smaller.dependencies) {
      if (larger.dependencies.has(id)) sharedCost = addCost(sharedCost, costs.get(id));
      else {
        additionalCost = addCost(additionalCost, costs.get(id));
        additionalUnits++;
      }
    }
    const unionCost = addCost(larger.cost, additionalCost);
    const minimumMemberCost = Math.min(left.minimumMemberCost, right.minimumMemberCost);
    // Each selected entry adds a publication unit beyond the union of logical modules.
    // Enforce the actual guest bound while merging, rather than rejecting a finished build.
    const logicalUnits =
      larger.dependencies.size + additionalUnits + left.members.length + right.members.length;
    if (
      sharedCost === 0 ||
      unionCost / minimumMemberCost > maximumCostInflation ||
      logicalUnits > maximumLogicalUnits
    )
      continue;
    const retainedIndex = left.members.length >= right.members.length ? leftIndex : rightIndex;
    const removedIndex = retainedIndex === leftIndex ? rightIndex : leftIndex;
    const retained = groups[retainedIndex];
    const removed = groups[removedIndex];
    for (const id of removed.dependencies) retained.dependencies.add(id);
    for (const member of removed.members) retained.members.push(member);
    retained.cost = unionCost;
    retained.minimumMemberCost = minimumMemberCost;
    groups[removedIndex].parent = retainedIndex;
    // The merged set owns these memberships; retaining copies would grow memory with merge depth.
    removed.dependencies.clear();
    removed.members = [];
    acceptedMerges++;
  }

  const resultGroups = groups
    .filter((group, index) => group.parent === index)
    .map((group) => ({
      entries: group.members.map((index) => normalized[index].entryPath).sort(compareStrings),
      cost: group.cost,
      minimumMemberCost: group.minimumMemberCost,
      costInflation: group.cost / group.minimumMemberCost,
      dependencyCount: group.dependencies.size,
    }))
    .sort((left, right) => compareStrings(left.entries[0], right.entries[0]));
  const policy = {
    kind: "convex-wasm-dependency-cost-entry-grouping-v1",
    maximumCostInflation,
    maximumLogicalUnits,
  };
  const entryGroups = resultGroups.map((group) => group.entries);
  return {
    policy,
    entryGroups,
    groups: resultGroups,
    modeledInventoryCost: resultGroups.reduce((sum, group) => addCost(sum, group.cost), 0),
    diagnostics: {
      candidatePairs: pairs.size,
      attemptedMerges,
      acceptedMerges,
      closureMemberships: normalized.reduce((sum, entry) => sum + entry.dependencies.size, 0),
    },
    partitionSha256: fingerprintJson({ policy, entryGroups }),
  };
}

// Build policy is source-derived: no profiler state, previous partition or application settings.
// Round source bytes to reduce sensitivity to small body edits; this is a cost proxy, not time.
export function planConvexWasmOfficialOutputEntryGroups({ graphSession, entryPaths }) {
  if (!Array.isArray(entryPaths) || entryPaths.length === 0) {
    throw new Error("Convex Wasm entry grouping: selected entry paths are required");
  }
  const authentication = createConvexWasmDeploymentOutputClosureAuthentication(graphSession);
  const graph = projectConvexWasmDeploymentOutputChunkGraph({ authentication, graphSession });
  const selectedModules = new Set();
  const entries = entryPaths.map((entryPath) => {
    const closure = selectConvexWasmDeploymentOutputClosure({
      authentication,
      graphSession,
      entryPath,
    });
    const dependencies = closure.identity.modules.map(({ path }) => path);
    for (const path of dependencies) selectedModules.add(path);
    return { entryPath, dependencies };
  });
  return planConvexWasmEntryGroups({
    modules: graph.modules
      .filter(({ identity }) => selectedModules.has(identity.path))
      .map(({ identity }) => ({
        id: identity.path,
        cost: Math.max(1, Math.ceil(identity.sourceSize / 4096)) * 4096,
      })),
    entries,
    maximumCostInflation: 1.5,
  });
}
