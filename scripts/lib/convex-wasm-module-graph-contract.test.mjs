import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  MODULE_GRAPH_BASE_ROLE,
  MODULE_GRAPH_LEAF_ROLE,
  MODULE_GRAPH_SOURCE_PROVENANCE_KIND,
  moduleGraphRoleClass,
  moduleGraphRoles,
  moduleGraphSharedRole,
  moduleGraphSharedShardSha256,
  normalizeModuleGraphContract,
  normalizeModuleGraphHostAbi,
  normalizeModuleGraphModule,
  normalizeModuleGraphRoleSequence,
  requireModuleGraphAbiFunctionExport,
  validateModuleGraphProviders,
} from "./convex-wasm-module-graph-contract.mjs";

const ENGINE_SHA256 = "1".repeat(64);
const INSPECTION_SHA256 = "2".repeat(64);
const DYLINK_SHA256 = "3".repeat(64);
const SHARD_SHA256 = "4".repeat(64);

function emptyContract() {
  const authority = {
    engineCompatibilitySha256: ENGINE_SHA256,
    inspectionSha256: INSPECTION_SHA256,
    kind: "convex-wasm-wasmtime-module-contract-v1",
  };
  const dylink = { first: true, sha256: DYLINK_SHA256, weakImports: [] };
  const contract = { authority, dylink, exports: [], imports: [] };
  return { ...contract, contractSha256: fingerprintJson(contract) };
}

function sourceProvenance(role) {
  const payload = { role };
  return {
    kind: MODULE_GRAPH_SOURCE_PROVENANCE_KIND,
    payload,
    sha256: fingerprintJson({ kind: MODULE_GRAPH_SOURCE_PROVENANCE_KIND, payload }),
  };
}

function moduleContract(role) {
  const base = role === MODULE_GRAPH_BASE_ROLE;
  return {
    contract: emptyContract(),
    layout: {
      memoryAlign: 0,
      memoryBase: 0,
      memorySize: 0,
      tableAlign: 0,
      tableBase: 0,
      tableSize: 0,
    },
    link: { flags: [base ? "-sMAIN_MODULE=2" : "-sSIDE_MODULE=2"], kind: base ? "main" : "side" },
    objectCompilation: {
      flags: base ? [] : ["-fPIC"],
      kind: base ? "main-module-object" : "side-module-object",
    },
    ownership: {
      memory: base ? "defined" : "base",
      stackPointer: base ? "defined" : "base",
      table: base ? "defined" : "base",
      tags: ["__c_longjmp"],
    },
    providers: [],
    role,
    sourceProvenance: sourceProvenance(role),
  };
}

test("normalizes content-addressed module graph roles", () => {
  const sharedRole = moduleGraphSharedRole(SHARD_SHA256);
  assert.equal(moduleGraphSharedShardSha256(sharedRole), SHARD_SHA256);
  assert.equal(moduleGraphRoleClass(sharedRole), "shared");
  assert.deepEqual(
    normalizeModuleGraphRoleSequence(
      [{ role: MODULE_GRAPH_BASE_ROLE }, { role: sharedRole }, { role: MODULE_GRAPH_LEAF_ROLE }],
      "test modules"
    ),
    [MODULE_GRAPH_BASE_ROLE, sharedRole, MODULE_GRAPH_LEAF_ROLE]
  );
  assert.throws(
    () =>
      normalizeModuleGraphRoleSequence(
        [
          { role: MODULE_GRAPH_BASE_ROLE },
          { role: "common" },
          { role: sharedRole },
          { role: MODULE_GRAPH_LEAF_ROLE },
        ],
        "test modules"
      ),
    /may contain legacy common only as its sole shared module/u
  );
});

test("normalizes graph contracts and rejects a different inspection engine", () => {
  const contract = emptyContract();
  assert.deepEqual(normalizeModuleGraphContract(contract, "base", ENGINE_SHA256), contract);
  assert.throws(
    () => normalizeModuleGraphContract(contract, "base", "5".repeat(64)),
    /different Wasmtime engine compatibility identity/u
  );
});

test("normalizes the closed host ABI in canonical import order", () => {
  const imports = [
    { module: "convex", name: "a", typeSha256: "6".repeat(64) },
    { module: "env", name: "z", typeSha256: "7".repeat(64) },
  ];
  const kind = "convex-wasm-module-graph-host-abi-v1";
  const hostAbi = {
    imports: [...imports].reverse(),
    kind,
    sha256: fingerprintJson({ imports, kind }),
  };
  assert.deepEqual(normalizeModuleGraphHostAbi(hostAbi), { imports, kind, sha256: hostAbi.sha256 });
});

test("normalizes a closed base/leaf topology and validates its providers", () => {
  const roles = [MODULE_GRAPH_BASE_ROLE, MODULE_GRAPH_LEAF_ROLE];
  const modules = roles.map((role) =>
    normalizeModuleGraphModule(moduleContract(role), role, roles, ENGINE_SHA256)
  );
  assert.deepEqual(moduleGraphRoles(modules), roles);
  assert.doesNotThrow(() =>
    validateModuleGraphProviders(modules, {
      imports: [],
      kind: "convex-wasm-module-graph-host-abi-v1",
      sha256: fingerprintJson({ imports: [], kind: "convex-wasm-module-graph-host-abi-v1" }),
    })
  );
});

test("requires the graph ABI function export signature", () => {
  const inspection = {
    contract: {
      exports: [{ name: "entry", type: { canonical: "func()->(i32)", kind: "func" } }],
    },
  };
  assert.doesNotThrow(() => requireModuleGraphAbiFunctionExport(inspection, "entry", "fixture"));
  assert.throws(
    () => requireModuleGraphAbiFunctionExport(inspection, "missing", "fixture"),
    /must export missing as func\(\)->\(i32\)/u
  );
});
