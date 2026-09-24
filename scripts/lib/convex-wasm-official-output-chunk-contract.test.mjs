import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  compareStrings,
  fingerprintJson,
} from "./convex-wasm-artifact-contract.mjs";
import {
  createConvexWasmOfficialOutputExecutableDependencySpecifier,
  deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s,
  validateConvexWasmOfficialOutputChunkDependencyTopology,
} from "./convex-wasm-official-output-chunk-contract.mjs";

test("reusable chunk identities retain canonical dependency order", () => {
  const units = Array.from({ length: 4 }, (_, index) => ({
    applicationUnitSlot: index,
    dependencies: [],
    entryPublication: false,
    javascript: { sha256: String(index).repeat(64), size: index + 1 },
    kind: "fixture-chunk",
    module: { path: `chunk-${index}.js` },
    nativeSymbolLocator: { sourceMembershipSha256: String(index).repeat(64) },
    transform: { kind: "fixture-transform" },
  }));
  units[0].dependencies = [3, 1, 2, 1].map((slot, index) => ({
    executableSpecifier: `./dependency-${index}.js`,
    kind: index % 2 === 0 ? "import-statement" : "dynamic-import",
    path: units[slot].module.path,
  }));
  const intrinsicIdentities = units.map((unit) =>
    fingerprintJson({
      domain: "convex-wasm-official-output-chunk-intrinsic-code-v3",
      javascript: unit.javascript,
      kind: unit.kind,
      nativeSymbolLocator: unit.nativeSymbolLocator,
      transform: unit.transform,
    })
  );
  const expected = units.map((unit, index) =>
    fingerprintJson({
      dependencies: unit.dependencies
        .map(({ executableSpecifier, kind }) => ({ executableSpecifier, kind }))
        .sort((left, right) => compareStrings(canonicalJson(left), canonicalJson(right))),
      domain: "convex-wasm-official-output-chunk-reusable-code-v3",
      intrinsicIdentitySha256: intrinsicIdentities[index],
    })
  );
  assert.deepEqual(
    deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
      chunkSlotCount: units.length,
      units,
    }),
    expected
  );
  units[0].dependencies.reverse();
  assert.deepEqual(
    deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
      chunkSlotCount: units.length,
      units,
    }),
    expected
  );
  units[1].javascript = { sha256: "f".repeat(64), size: 20 };
  const dependencyChanged = deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
    chunkSlotCount: units.length,
    units,
  });
  assert.equal(dependencyChanged[0], expected[0]);
  assert.notEqual(dependencyChanged[1], expected[1]);
});

test("chunk topology requires strictly increasing dependency identities within each unit", () => {
  const units = Array.from({ length: 4 }, (_, index) => ({
    dependencies: [],
    module: { path: `chunk-${index}.js` },
    nativeSymbolIdentitySha256: String(index).repeat(64),
  }));
  const dependencies = [1, 2, 3].map((slot, occurrence) => ({
    executableSpecifier: createConvexWasmOfficialOutputExecutableDependencySpecifier({
      kind: "import-statement",
      nativeSymbolIdentitySha256: units[slot].nativeSymbolIdentitySha256,
      occurrence,
    }),
    kind: "import-statement",
    path: units[slot].module.path,
    slot,
    specifier: `./${units[slot].module.path}`,
  }));
  units[0].dependencies = dependencies;
  // This next unit starts below the preceding unit's last identity; ordering is per unit.
  units[3].dependencies = dependencies.slice(0, 2);
  const validate = () =>
    validateConvexWasmOfficialOutputChunkDependencyTopology({
      chunkSlotCount: units.length,
      description: "fixture topology",
      units,
    });
  assert.doesNotThrow(validate);
  for (const invalid of [
    [dependencies[1], dependencies[0], dependencies[2]],
    [dependencies[0], dependencies[2], dependencies[1]],
    [dependencies[0], dependencies[1], dependencies[1]],
  ]) {
    units[0].dependencies = invalid;
    assert.throws(validate, /unit 0 dependencies are not canonical/u);
  }
  units[0].dependencies = dependencies.slice(0, 1);
  assert.doesNotThrow(validate);
  units[0].dependencies = [];
  assert.doesNotThrow(validate);
});
