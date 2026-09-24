import { createHash } from "node:crypto";

export const convexWasmPhysicalShardPlanningRequestKind =
  "convex-wasm-physical-shard-planning-request-v2";
export const convexWasmPhysicalShardLogicalUnitKind = "convex-wasm-physical-shard-logical-unit-v2";
export const convexWasmPhysicalShardPolicyKind = "convex-wasm-physical-shard-policy-v2";
export const convexWasmPhysicalShardComponentKind = "convex-wasm-physical-shard-component-v2";
export const convexWasmPhysicalShardKind = "convex-wasm-physical-shard-v2";
export const convexWasmPhysicalShardPlanKind = "convex-wasm-physical-shard-plan-v2";
export const convexWasmPhysicalShardDefaultMinimumCohortCount = 2;

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex Wasm physical shard planner: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requirePlainObject(value, description) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${description} must be a plain object`);
  }
  return value;
}

function requireExactKeys(value, keys, description) {
  const object = requirePlainObject(value, description);
  const actual = Object.keys(object).sort(compareStrings);
  const expected = [...keys].sort(compareStrings);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${description} has unexpected fields`);
  }
  return object;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireBoolean(value, description) {
  if (typeof value !== "boolean") fail(`${description} must be a boolean`);
  return value;
}

function requirePositiveSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireNonNegativeSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a non-negative safe integer`);
  }
  return value;
}

function requireCanonicalSha256Set(value, description, { allowEmpty }) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    fail(`${description} must be ${allowEmpty ? "an array" : "a non-empty array"}`);
  }
  const normalized = value.map((member, index) => requireSha256(member, `${description} ${index}`));
  for (let index = 1; index < normalized.length; index += 1) {
    if (compareStrings(normalized[index - 1], normalized[index]) >= 0) {
      fail(`${description} must be sorted without duplicates`);
    }
  }
  return normalized;
}

function canonicalValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      fail("canonical JSON contains an invalid number");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("canonical JSON contains a non-plain object");
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareStrings)
      .map((key) => [key, canonicalValue(value[key])])
  );
}

export function canonicalConvexWasmPhysicalShardJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function fingerprintConvexWasmPhysicalShardJson(value) {
  return createHash("sha256").update(canonicalConvexWasmPhysicalShardJson(value)).digest("hex");
}

function addSafeIntegers(left, right, description) {
  if (right > Number.MAX_SAFE_INTEGER - left) {
    fail(`${description} exceeds the safe integer range`);
  }
  return left + right;
}

function normalizeLogicalUnitMaterial(rawUnit, description) {
  const unit = requireExactKeys(
    rawUnit,
    new Set([
      "codeIdentitySha256",
      "bindingIdentitySha256",
      "dependencies",
      "kind",
      "occurrences",
      "picObject",
      "shareable",
    ]),
    description
  );
  if (unit.kind !== convexWasmPhysicalShardLogicalUnitKind) {
    fail(`${description} kind is unsupported`);
  }
  const picObject = requireExactKeys(
    unit.picObject,
    new Set(["byteWeight", "sha256"]),
    `${description} PIC object`
  );
  return {
    bindingIdentitySha256: requireSha256(
      unit.bindingIdentitySha256,
      `${description} binding identity`
    ),
    codeIdentitySha256: requireSha256(unit.codeIdentitySha256, `${description} code identity`),
    dependencies: requireCanonicalSha256Set(unit.dependencies, `${description} dependencies`, {
      allowEmpty: true,
    }),
    kind: unit.kind,
    occurrences: requireCanonicalSha256Set(unit.occurrences, `${description} occurrences`, {
      allowEmpty: false,
    }),
    picObject: {
      byteWeight: requireNonNegativeSafeInteger(
        picObject.byteWeight,
        `${description} PIC object byte weight`
      ),
      sha256: requireSha256(picObject.sha256, `${description} PIC object SHA-256`),
    },
    shareable: requireBoolean(unit.shareable, `${description} shareable`),
  };
}

function logicalUnitIdentityPayload(unit) {
  return {
    domain: "convex-wasm-physical-shard-logical-unit-identity-v2",
    logicalUnit: unit,
  };
}

export function authenticateConvexWasmPhysicalShardLogicalUnit(rawUnit) {
  const unit = normalizeLogicalUnitMaterial(rawUnit, "logical unit");
  return deepFreeze({
    ...unit,
    logicalUnitSha256: fingerprintConvexWasmPhysicalShardJson(logicalUnitIdentityPayload(unit)),
  });
}

function normalizeAuthenticatedLogicalUnit(rawUnit, index) {
  const description = `logical unit ${index}`;
  const unit = requireExactKeys(
    rawUnit,
    new Set([
      "codeIdentitySha256",
      "bindingIdentitySha256",
      "dependencies",
      "kind",
      "logicalUnitSha256",
      "occurrences",
      "picObject",
      "shareable",
    ]),
    description
  );
  const { logicalUnitSha256, ...material } = unit;
  const normalized = normalizeLogicalUnitMaterial(material, description);
  const authenticatedIdentity = requireSha256(
    logicalUnitSha256,
    `${description} authenticated identity`
  );
  const expectedIdentity = fingerprintConvexWasmPhysicalShardJson(
    logicalUnitIdentityPayload(normalized)
  );
  if (authenticatedIdentity !== expectedIdentity) {
    fail(`${description} authenticated identity is invalid`);
  }
  return { ...normalized, logicalUnitSha256: authenticatedIdentity };
}

function normalizePolicy(rawPolicy) {
  const policy = requirePlainObject(rawPolicy, "physical shard policy");
  const fields = Object.keys(policy).sort(compareStrings);
  const allowedWithoutMinimum = ["kind", "targetShardWeight"];
  const allowedWithMinimum = ["kind", "minimumCohortCount", "targetShardWeight"].sort(
    compareStrings
  );
  const allowed =
    canonicalConvexWasmPhysicalShardJson(fields) ===
    canonicalConvexWasmPhysicalShardJson(allowedWithoutMinimum)
      ? allowedWithoutMinimum
      : allowedWithMinimum;
  if (fields.length !== allowed.length || fields.some((field, index) => field !== allowed[index])) {
    fail("physical shard policy has unexpected fields");
  }
  if (policy.kind !== convexWasmPhysicalShardPolicyKind) {
    fail("physical shard policy kind is unsupported");
  }
  const normalized = {
    kind: policy.kind,
    minimumCohortCount:
      policy.minimumCohortCount === undefined
        ? convexWasmPhysicalShardDefaultMinimumCohortCount
        : requirePositiveSafeInteger(
            policy.minimumCohortCount,
            "physical shard policy minimum cohort count"
          ),
    targetShardWeight: requirePositiveSafeInteger(
      policy.targetShardWeight,
      "physical shard policy target shard weight"
    ),
  };
  return {
    ...normalized,
    policySha256: fingerprintConvexWasmPhysicalShardJson({
      domain: "convex-wasm-physical-shard-policy-identity-v2",
      policy: normalized,
    }),
  };
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function stronglyConnectedComponents(unitsByCodeIdentity) {
  let nextIndex = 0;
  const indexes = new Map();
  const lowLinks = new Map();
  const stack = [];
  const onStack = new Set();
  const components = [];

  function visit(codeIdentitySha256) {
    indexes.set(codeIdentitySha256, nextIndex);
    lowLinks.set(codeIdentitySha256, nextIndex);
    nextIndex += 1;
    stack.push(codeIdentitySha256);
    onStack.add(codeIdentitySha256);

    const unit = unitsByCodeIdentity.get(codeIdentitySha256);
    for (const dependencyCodeIdentitySha256 of unit.dependencies) {
      if (!indexes.has(dependencyCodeIdentitySha256)) {
        visit(dependencyCodeIdentitySha256);
        lowLinks.set(
          codeIdentitySha256,
          Math.min(lowLinks.get(codeIdentitySha256), lowLinks.get(dependencyCodeIdentitySha256))
        );
      } else if (onStack.has(dependencyCodeIdentitySha256)) {
        lowLinks.set(
          codeIdentitySha256,
          Math.min(indexes.get(dependencyCodeIdentitySha256), lowLinks.get(codeIdentitySha256))
        );
      }
    }

    if (lowLinks.get(codeIdentitySha256) !== indexes.get(codeIdentitySha256)) return;
    const componentCodeIdentities = [];
    while (true) {
      const member = stack.pop();
      onStack.delete(member);
      componentCodeIdentities.push(member);
      if (member === codeIdentitySha256) break;
    }
    components.push(componentCodeIdentities.sort(compareStrings));
  }

  for (const codeIdentitySha256 of [...unitsByCodeIdentity.keys()].sort(compareStrings)) {
    if (!indexes.has(codeIdentitySha256)) visit(codeIdentitySha256);
  }
  return components;
}

function buildComponents(unitsByCodeIdentity, policy) {
  const componentCodeIdentitySets = stronglyConnectedComponents(unitsByCodeIdentity);
  const componentByCodeIdentity = new Map();
  const components = [];

  for (const codeIdentitySha256s of componentCodeIdentitySets) {
    const units = codeIdentitySha256s.map((codeIdentitySha256) =>
      unitsByCodeIdentity.get(codeIdentitySha256)
    );
    const isCyclic =
      units.length > 1 || units[0].dependencies.includes(units[0].codeIdentitySha256);
    const occurrenceCohortSha256s = units[0].occurrences;
    if (isCyclic && units.some((unit) => !arraysEqual(unit.occurrences, occurrenceCohortSha256s))) {
      fail(
        `cyclic component containing ${codeIdentitySha256s.join(", ")} has incoherent occurrence evidence`
      );
    }
    const picObjectByteWeight = units.reduce(
      (total, unit) =>
        addSafeIntegers(
          total,
          unit.picObject.byteWeight,
          `component containing ${codeIdentitySha256s.join(", ")} PIC object weight`
        ),
      0
    );
    const bindingIdentitySha256s = units
      .map((unit) => unit.bindingIdentitySha256)
      .sort(compareStrings);
    const componentBindingSha256 = fingerprintConvexWasmPhysicalShardJson({
      component: {
        kind: convexWasmPhysicalShardComponentKind,
        units: units
          .map((unit) => ({
            bindingIdentitySha256: unit.bindingIdentitySha256,
            dependencies: unit.dependencies
              .map((dependency) => unitsByCodeIdentity.get(dependency).bindingIdentitySha256)
              .sort(compareStrings),
            picObjectByteWeight: unit.picObject.byteWeight,
            shareable: unit.shareable,
          }))
          .sort((left, right) =>
            compareStrings(left.bindingIdentitySha256, right.bindingIdentitySha256)
          ),
      },
      domain: "convex-wasm-physical-shard-component-binding-identity-v1",
    });
    const componentSha256 = fingerprintConvexWasmPhysicalShardJson({
      component: {
        kind: convexWasmPhysicalShardComponentKind,
        units: units.map((unit) => ({
          codeIdentitySha256: unit.codeIdentitySha256,
          dependencies: unit.dependencies,
          picObject: unit.picObject,
        })),
      },
      domain: "convex-wasm-physical-shard-component-material-identity-v2",
    });
    const component = {
      bindingIdentitySha256s,
      codeIdentitySha256s,
      componentBindingSha256,
      componentSha256,
      dependencyComponentSha256s: [],
      logicalUnitSha256s: units.map((unit) => unit.logicalUnitSha256),
      occurrenceCohortSha256s,
      picObjectByteWeight,
      shareable: units.every((unit) => unit.shareable),
    };
    components.push(component);
    for (const codeIdentitySha256 of codeIdentitySha256s) {
      componentByCodeIdentity.set(codeIdentitySha256, component);
    }
  }

  const componentsByBinding = new Map();
  for (const component of components) {
    const variants = componentsByBinding.get(component.componentBindingSha256) ?? [];
    variants.push(component);
    componentsByBinding.set(component.componentBindingSha256, variants);
  }
  for (const variants of componentsByBinding.values()) {
    if (variants.length < 2) continue;
    for (const component of variants) {
      component.componentBindingSha256 = fingerprintConvexWasmPhysicalShardJson({
        ambiguousStableBindingSha256: component.componentBindingSha256,
        componentMaterialSha256: component.componentSha256,
        domain: "convex-wasm-physical-shard-ambiguous-component-binding-v1",
      });
    }
  }

  for (const component of components) {
    const dependencies = new Set();
    for (const codeIdentitySha256 of component.codeIdentitySha256s) {
      const unit = unitsByCodeIdentity.get(codeIdentitySha256);
      for (const dependencyCodeIdentitySha256 of unit.dependencies) {
        const dependencyComponent = componentByCodeIdentity.get(dependencyCodeIdentitySha256);
        if (dependencyComponent !== component)
          dependencies.add(dependencyComponent.componentSha256);
      }
    }
    component.dependencyComponentSha256s = [...dependencies].sort(compareStrings);
    component.sharedCandidate =
      component.shareable && component.occurrenceCohortSha256s.length >= policy.minimumCohortCount;
  }
  const componentBySha256 = new Map(
    components.map((component) => [component.componentSha256, component])
  );
  const resolving = new Set();
  function resolveSharedEligibility(component) {
    if (component.sharedEligible !== undefined) return component.sharedEligible;
    if (!component.sharedCandidate) {
      component.sharedEligible = false;
      return false;
    }
    if (resolving.has(component.componentSha256)) {
      fail("component dependency graph contains a cycle after SCC collapse");
    }
    resolving.add(component.componentSha256);
    component.sharedEligible = component.dependencyComponentSha256s.every((dependencySha256) =>
      resolveSharedEligibility(componentBySha256.get(dependencySha256))
    );
    resolving.delete(component.componentSha256);
    return component.sharedEligible;
  }
  for (const component of components) resolveSharedEligibility(component);
  return components.sort((left, right) =>
    compareStrings(left.componentBindingSha256, right.componentBindingSha256)
  );
}

function createPhysicalShardQuotient(components) {
  const activeBins = new Set();
  const binByComponentSha256 = new Map();
  for (const component of components) {
    if (binByComponentSha256.has(component.componentSha256)) {
      fail("physical shard grouping repeats a component");
    }
    const bin = {
      componentSha256s: new Set([component.componentSha256]),
      dependencies: new Set(),
      dependents: new Set(),
    };
    activeBins.add(bin);
    binByComponentSha256.set(component.componentSha256, bin);
  }
  for (const component of components) {
    const bin = binByComponentSha256.get(component.componentSha256);
    for (const dependencyComponentSha256 of component.dependencyComponentSha256s) {
      const dependencyBin = binByComponentSha256.get(dependencyComponentSha256);
      if (dependencyBin === undefined) {
        fail("physical shard grouping omits a component");
      }
      if (bin === dependencyBin) continue;
      bin.dependencies.add(dependencyBin);
      dependencyBin.dependents.add(bin);
    }
  }
  return { activeBins, binByComponentSha256 };
}

function quotientBinForComponent(quotient, componentSha256) {
  const bin = quotient.binByComponentSha256.get(componentSha256);
  if (bin === undefined) fail("physical shard grouping omits a component");
  if (!quotient.activeBins.has(bin)) fail("physical shard grouping uses an inactive quotient bin");
  return bin;
}

function quotientHasIndirectPath(from, to) {
  const visited = new Set([from]);
  const pending = [];
  for (const dependency of from.dependencies) {
    if (dependency !== to) pending.push(dependency);
  }
  while (pending.length > 0) {
    const bin = pending.pop();
    if (bin === to) return true;
    if (visited.has(bin)) continue;
    visited.add(bin);
    for (const dependency of bin.dependencies) {
      if (!visited.has(dependency)) pending.push(dependency);
    }
  }
  return false;
}

function quotientCanMerge(quotient, targetBin, sourceBin) {
  if (!quotient.activeBins.has(targetBin) || !quotient.activeBins.has(sourceBin)) {
    fail("physical shard grouping uses an inactive quotient bin");
  }
  if (targetBin === sourceBin) fail("physical shard grouping repeats a component");

  // Contracting two quotient vertices creates a cycle exactly when an indirect path already
  // connects them. A direct edge becomes an internal shard edge and is deliberately removed.
  return (
    !quotientHasIndirectPath(targetBin, sourceBin) && !quotientHasIndirectPath(sourceBin, targetBin)
  );
}

function mergeQuotientBins(quotient, targetBin, sourceBin) {
  if (!quotientCanMerge(quotient, targetBin, sourceBin)) return false;
  for (const dependency of sourceBin.dependencies) {
    dependency.dependents.delete(sourceBin);
    if (dependency === targetBin) continue;
    targetBin.dependencies.add(dependency);
    dependency.dependents.add(targetBin);
  }
  for (const dependent of sourceBin.dependents) {
    dependent.dependencies.delete(sourceBin);
    if (dependent === targetBin) continue;
    targetBin.dependents.add(dependent);
    dependent.dependencies.add(targetBin);
  }
  targetBin.dependencies.delete(sourceBin);
  targetBin.dependents.delete(sourceBin);
  for (const componentSha256 of sourceBin.componentSha256s) {
    targetBin.componentSha256s.add(componentSha256);
    quotient.binByComponentSha256.set(componentSha256, targetBin);
  }
  sourceBin.componentSha256s.clear();
  sourceBin.dependencies.clear();
  sourceBin.dependents.clear();
  quotient.activeBins.delete(sourceBin);
  return true;
}

function validatePhysicalShardQuotient(quotient, bins, components) {
  const physicalBinByComponentSha256 = new Map();
  for (const bin of bins) {
    let quotientBin;
    for (const componentSha256 of bin.componentSha256s) {
      if (physicalBinByComponentSha256.has(componentSha256)) {
        fail("physical shard grouping repeats a component");
      }
      physicalBinByComponentSha256.set(componentSha256, bin);
      const componentQuotientBin = quotientBinForComponent(quotient, componentSha256);
      if (quotientBin !== undefined && quotientBin !== componentQuotientBin) {
        fail("physical shard grouping splits a quotient bin");
      }
      quotientBin = componentQuotientBin;
    }
    if (quotientBin.componentSha256s.size !== bin.componentSha256s.length) {
      fail("physical shard grouping omits a component from a quotient bin");
    }
  }
  for (const component of components) {
    const physicalBin = physicalBinByComponentSha256.get(component.componentSha256);
    const quotientBin = quotientBinForComponent(quotient, component.componentSha256);
    if (component.sharedEligible !== (physicalBin !== undefined)) {
      fail("physical shard placement must assign exactly the shared components");
    }
    if (physicalBin === undefined && quotientBin.componentSha256s.size !== 1) {
      fail("physical shard grouping merges a residual component");
    }
  }
  // The component graph is an SCC condensation DAG. This quotient starts with one bin per
  // component, and mergeQuotientBins contracts bins only after quotientCanMerge rejects every
  // non-direct path between them. That condition is exactly the cycle-creating contraction case,
  // so a final full quotient traversal would only repeat the maintained acyclicity invariant.
}

function binMembershipKey(bin, componentBySha256) {
  return [...bin.componentSha256s]
    .map((componentSha256) => componentBySha256.get(componentSha256).componentBindingSha256)
    .sort(compareStrings)
    .join("");
}

function placeSharedComponents(components, policy) {
  const componentBySha256 = new Map(
    components.map((component) => [component.componentSha256, component])
  );
  const quotient = createPhysicalShardQuotient(components);
  const oversize = components
    .filter(
      (component) =>
        component.sharedEligible && component.picObjectByteWeight > policy.targetShardWeight
    )
    .sort((left, right) =>
      compareStrings(left.componentBindingSha256, right.componentBindingSha256)
    );
  const bins = oversize.map((component) => ({
    componentSha256s: [component.componentSha256],
    occurrenceCohortSha256s: component.occurrenceCohortSha256s,
    picObjectByteWeight: component.picObjectByteWeight,
    oversize: true,
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
      return compareStrings(left.componentBindingSha256, right.componentBindingSha256);
    });

  for (const component of normalComponents) {
    const candidates = bins
      .map((bin, index) => ({ bin, index }))
      .filter(
        ({ bin }) =>
          component.picObjectByteWeight <= policy.targetShardWeight - bin.picObjectByteWeight &&
          // A consumer loads a whole shard. Different occurrence sets would otherwise add code
          // to a cohort where it did not occur, which is unsafe without a non-observability proof.
          arraysEqual(component.occurrenceCohortSha256s, bin.occurrenceCohortSha256s)
      )
      .sort((left, right) => {
        if (left.bin.picObjectByteWeight !== right.bin.picObjectByteWeight) {
          return left.bin.picObjectByteWeight < right.bin.picObjectByteWeight ? -1 : 1;
        }
        return compareStrings(
          binMembershipKey(left.bin, componentBySha256),
          binMembershipKey(right.bin, componentBySha256)
        );
      });
    let placed = false;
    for (const { index } of candidates) {
      const bin = bins[index];
      const targetBin = quotientBinForComponent(quotient, bin.componentSha256s[0]);
      const sourceBin = quotientBinForComponent(quotient, component.componentSha256);
      if (mergeQuotientBins(quotient, targetBin, sourceBin)) {
        bins.splice(index, 1, {
          ...bin,
          componentSha256s: [...bin.componentSha256s, component.componentSha256],
          picObjectByteWeight: addSafeIntegers(
            bin.picObjectByteWeight,
            component.picObjectByteWeight,
            "physical shard PIC object weight"
          ),
        });
        placed = true;
        break;
      }
    }
    if (!placed) {
      bins.push({
        componentSha256s: [component.componentSha256],
        occurrenceCohortSha256s: component.occurrenceCohortSha256s,
        picObjectByteWeight: component.picObjectByteWeight,
        oversize: false,
      });
    }
  }

  validatePhysicalShardQuotient(quotient, bins, components);
  return bins;
}

function buildSharedShards(bins, components) {
  const componentBySha256 = new Map(
    components.map((component) => [component.componentSha256, component])
  );
  const shardByComponentSha256 = new Map();
  const shards = bins.map((bin) => {
    const componentSha256s = [...bin.componentSha256s].sort(compareStrings);
    const componentBindingSha256s = componentSha256s
      .map((componentSha256) => componentBySha256.get(componentSha256).componentBindingSha256)
      .sort(compareStrings);
    const shardSha256 = fingerprintConvexWasmPhysicalShardJson({
      domain: "convex-wasm-physical-shard-binding-identity-v2",
      shard: { componentBindingSha256s, kind: convexWasmPhysicalShardKind },
    });
    for (const componentSha256 of componentSha256s) {
      if (shardByComponentSha256.has(componentSha256)) {
        fail("physical shard placement repeats a shared component");
      }
      shardByComponentSha256.set(componentSha256, shardSha256);
    }
    return {
      componentBindingSha256s,
      componentSha256s,
      dependencies: [],
      kind: convexWasmPhysicalShardKind,
      oversize: bin.oversize,
      picObjectByteWeight: bin.picObjectByteWeight,
      shardSha256,
    };
  });
  const shardBySha256 = new Map(shards.map((shard) => [shard.shardSha256, shard]));
  if (shardBySha256.size !== shards.length) fail("physical shard identities collide");

  for (const shard of shards) {
    const dependencies = new Set();
    for (const componentSha256 of shard.componentSha256s) {
      const component = componentBySha256.get(componentSha256);
      for (const dependencyComponentSha256 of component.dependencyComponentSha256s) {
        const dependencyShardSha256 = shardByComponentSha256.get(dependencyComponentSha256);
        if (dependencyShardSha256 !== undefined && dependencyShardSha256 !== shard.shardSha256) {
          dependencies.add(dependencyShardSha256);
        }
      }
    }
    shard.dependencies = [...dependencies].sort(compareStrings);
  }
  return shards.sort((left, right) => compareStrings(left.shardSha256, right.shardSha256));
}

function orderShards(shards) {
  const shardBySha256 = new Map(shards.map((shard) => [shard.shardSha256, shard]));
  const remainingDependencyCounts = new Map(
    shards.map((shard) => [shard.shardSha256, shard.dependencies.length])
  );
  const dependentsByShardSha256 = new Map(shards.map((shard) => [shard.shardSha256, []]));
  for (const shard of shards) {
    for (const dependencyShardSha256 of shard.dependencies) {
      if (!shardBySha256.has(dependencyShardSha256)) {
        fail("physical shard dependency references an unknown shard");
      }
      dependentsByShardSha256.get(dependencyShardSha256).push(shard.shardSha256);
    }
  }
  const ready = shards
    .filter((shard) => remainingDependencyCounts.get(shard.shardSha256) === 0)
    .map((shard) => shard.shardSha256)
    .sort(compareStrings);
  const order = [];
  while (ready.length > 0) {
    const shardSha256 = ready.shift();
    order.push(shardSha256);
    for (const dependentShardSha256 of dependentsByShardSha256
      .get(shardSha256)
      .sort(compareStrings)) {
      const remaining = remainingDependencyCounts.get(dependentShardSha256) - 1;
      remainingDependencyCounts.set(dependentShardSha256, remaining);
      if (remaining === 0) ready.push(dependentShardSha256);
    }
    ready.sort(compareStrings);
  }
  if (order.length !== shards.length) fail("physical shard dependencies contain a cycle");
  return order;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

/**
 * Build a reusable-code plan only. Cohort-local slots and runtime bindings are deliberately absent.
 */
export function planConvexWasmPhysicalShards(rawInput) {
  const input = requireExactKeys(
    rawInput,
    new Set(["kind", "logicalUnits", "policy"]),
    "physical shard planning request"
  );
  if (input.kind !== convexWasmPhysicalShardPlanningRequestKind) {
    fail("physical shard planning request kind is unsupported");
  }
  if (!Array.isArray(input.logicalUnits)) {
    fail("physical shard planning request logical units must be an array");
  }
  const policy = normalizePolicy(input.policy);
  const unitsByCodeIdentity = new Map();
  const unitsByBindingIdentity = new Map();
  const logicalUnitIdentities = new Set();
  for (const [index, rawUnit] of input.logicalUnits.entries()) {
    const unit = normalizeAuthenticatedLogicalUnit(rawUnit, index);
    if (unitsByCodeIdentity.has(unit.codeIdentitySha256)) {
      fail(`physical shard planning request repeats code identity ${unit.codeIdentitySha256}`);
    }
    if (logicalUnitIdentities.has(unit.logicalUnitSha256)) {
      fail(
        `physical shard planning request repeats logical unit identity ${unit.logicalUnitSha256}`
      );
    }
    const bindingVariants = unitsByBindingIdentity.get(unit.bindingIdentitySha256) ?? [];
    const occurrenceSet = new Set(unit.occurrences);
    if (
      bindingVariants.some((variant) =>
        variant.occurrences.some((occurrence) => occurrenceSet.has(occurrence))
      )
    ) {
      fail(
        `physical shard planning request selects multiple exact variants for stable binding ${unit.bindingIdentitySha256} in one cohort`
      );
    }
    bindingVariants.push(unit);
    unitsByBindingIdentity.set(unit.bindingIdentitySha256, bindingVariants);
    unitsByCodeIdentity.set(unit.codeIdentitySha256, unit);
    logicalUnitIdentities.add(unit.logicalUnitSha256);
  }
  for (const unit of unitsByCodeIdentity.values()) {
    for (const dependencyCodeIdentitySha256 of unit.dependencies) {
      if (!unitsByCodeIdentity.has(dependencyCodeIdentitySha256)) {
        fail(
          `logical unit ${unit.codeIdentitySha256} references unknown dependency ${dependencyCodeIdentitySha256}`
        );
      }
    }
  }

  const components = buildComponents(unitsByCodeIdentity, policy);
  const bins = placeSharedComponents(components, policy);
  const sharedShards = buildSharedShards(bins, components);
  const residualComponents = components
    .filter((component) => !component.sharedEligible)
    .map((component) => ({
      componentSha256: component.componentSha256,
      reason: !component.shareable
        ? "contains-non-shareable-logical-unit"
        : component.occurrenceCohortSha256s.length < policy.minimumCohortCount
          ? "insufficient-cohort-occurrences"
          : "depends-on-residual-component",
    }))
    .sort((left, right) => compareStrings(left.componentSha256, right.componentSha256));
  const plan = {
    components: components.map((component) => ({
      bindingIdentitySha256s: component.bindingIdentitySha256s,
      codeIdentitySha256s: component.codeIdentitySha256s,
      componentBindingSha256: component.componentBindingSha256,
      componentSha256: component.componentSha256,
      dependencies: component.dependencyComponentSha256s,
      logicalUnitSha256s: component.logicalUnitSha256s,
      occurrenceCohortSha256s: component.occurrenceCohortSha256s,
      picObjectByteWeight: component.picObjectByteWeight,
      shareable: component.shareable,
      sharedEligible: component.sharedEligible,
    })),
    kind: convexWasmPhysicalShardPlanKind,
    policy,
    residualComponents,
    sharedShards,
    shardOrder: orderShards(sharedShards),
  };
  return deepFreeze({
    ...plan,
    planSha256: fingerprintConvexWasmPhysicalShardJson({
      domain: "convex-wasm-physical-shard-plan-identity-v2",
      plan,
    }),
  });
}
