import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  assertConvexWasmRuntimeApiBlockerReconciliationIdentity,
  buildConvexWasmRuntimeApiBlockerReconciliation,
} from "./convex-wasm-runtime-api-blocker-reconciliation.mjs";

function failure(surface, code, layer) {
  return {
    classification: "runtime-api",
    diagnostics: [
      {
        code: "named-runtime-gap",
        gap: { code, layer, surface },
        reason: `${surface} fixture`,
      },
    ],
    kind: "failure",
    stage: "bridge-render",
  };
}

function report(facilities) {
  const entries = facilities.map(({ code, layer, name }, index) => ({
    entryPath: `convex/fixture${String(index)}.ts`,
    outcome: failure(name, code, layer),
  }));
  entries.push({
    entryPath: "convex/unclassified.ts",
    outcome: {
      classification: "static-engine",
      diagnostics: [{ code: "static-hermes-type-rejection", reason: "fixture rejection" }],
      kind: "failure",
      stage: "static-hermes",
    },
  });
  const routes = entries.map((entry, index) => ({
    entryPath: entry.entryPath,
    exportName: `route${String(index)}`,
    modulePath: entry.entryPath.slice(7, -3),
    outcome: entry.outcome,
  }));
  const payload = {
    entries,
    evidence: { artifact: false, routingReady: false },
    inputs: {},
    kind: "convex-wasm-runtime-capability-compile-preflight-report-v2",
    routes,
    schemaVersion: 2,
    summary: {},
  };
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

test("joins named blockers to inventory facts and preserves unclassified diagnostics", () => {
  const fullReport = report([
    { code: "atob-engine", layer: "engine", name: "atob" },
    { code: "web-global-conformance", layer: "engine", name: "TextDecoder" },
    { code: "process-adapter", layer: "adapter", name: "process" },
    { code: "ambient-global-unavailable", layer: "engine", name: "URL" },
    {
      code: "ambient-global-unavailable",
      layer: "engine",
      name: "encodeURIComponent",
    },
  ]);
  const representativeReport = report([
    { code: "date-ambient-object-flow", layer: "adapter", name: "Date" },
    { code: "ambient-global-unavailable", layer: "engine", name: "fixtureMinifiedBinding" },
  ]);
  const reconciliation = buildConvexWasmRuntimeApiBlockerReconciliation({
    fullReport,
    representativeReport,
  });
  assert.doesNotThrow(() =>
    assertConvexWasmRuntimeApiBlockerReconciliationIdentity(reconciliation)
  );
  const categories = Object.fromEntries(
    reconciliation.facilities.map(({ category, name }) => [name, category])
  );
  assert.deepEqual(categories, {
    atob: "runtime-present + untyped but bridgeable",
    Date: "adapter/host-mediated",
    encodeURIComponent: "runtime-present + typed + eligible",
    fixtureMinifiedBinding: "unclassified",
    process: "adapter/host-mediated",
    TextDecoder: "runtime-present + untyped but bridgeable",
    URL: "shared-runtime-support + eligible",
  });
  assert.equal(reconciliation.batch.candidates.includes("encodeURIComponent"), false);
  assert.equal(reconciliation.batch.candidates.includes("TextDecoder"), false);
  const textDecoder = reconciliation.facilities.find(({ name }) => name === "TextDecoder");
  assert.equal(textDecoder.genericBatch.admitted, true);
  assert.equal(textDecoder.genericBatch.selected, false);
  assert.equal(textDecoder.inventory.access.read, "ordinary-lexical-value");
  assert.deepEqual(
    {
      applicationGlobalFacade: textDecoder.inventory.access.applicationGlobalFacade,
      applicationGlobalFacadeComputedAccess:
        textDecoder.inventory.access.applicationGlobalFacadeComputedAccess,
      applicationGlobalFacadeFlow: textDecoder.inventory.access.applicationGlobalFacadeFlow,
      globalBindingWrites: textDecoder.inventory.access.globalBindingWrites,
      rawGlobalObjectFlow: textDecoder.inventory.access.rawGlobalObjectFlow,
    },
    {
      applicationGlobalFacade: "inventory-derived-extensible-null-prototype-immutable-builtins",
      applicationGlobalFacadeComputedAccess: "admitted",
      applicationGlobalFacadeFlow: "admitted",
      globalBindingWrites: "rejected",
      rawGlobalObjectFlow: "rejected",
    }
  );
  assert.equal(
    reconciliation.nextBlockers.some(({ name }) => name === "TextDecoder"),
    false
  );
  assert.equal(reconciliation.unclassified.fullDiagnostics.length, 1);
  const representativeOnly = reconciliation.nextBlockers.find(
    ({ name }) => name === "fixtureMinifiedBinding"
  );
  assert.equal(representativeOnly.observed.full.entries, 0);
  assert.equal(representativeOnly.observed.representative.entries, 1);
  assert.equal(reconciliation.routingReady, false);
});

test("rejects preflight and reconciliation identity drift", () => {
  const fullReport = report([{ code: "atob-engine", layer: "engine", name: "atob" }]);
  const representativeReport = report([]);
  fullReport.entries[0].entryPath = "convex/drift.ts";
  assert.throws(
    () => buildConvexWasmRuntimeApiBlockerReconciliation({ fullReport, representativeReport }),
    /identity does not match/u
  );
  const validFullReport = report([{ code: "atob-engine", layer: "engine", name: "atob" }]);
  const reconciliation = buildConvexWasmRuntimeApiBlockerReconciliation({
    fullReport: validFullReport,
    representativeReport,
  });
  const drifted = structuredClone(reconciliation);
  drifted.routingReady = true;
  assert.throws(
    () => assertConvexWasmRuntimeApiBlockerReconciliationIdentity(drifted),
    /identity does not match/u
  );
});
