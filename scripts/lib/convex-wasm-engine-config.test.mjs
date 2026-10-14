import assert from "node:assert/strict";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { normalizeEngineConfig, validatePrecompilerEngineRequest } from "./convex-wasm-engine-config.mjs";

const legacy = {
  consumeFuel: true,
  epochInterruption: true,
  profilingStrategy: "perf-map",
  wasmExceptions: true,
};
const legacyContract = {
  ...legacy,
  engineIdentityKind: "convex-wasm-wasmtime-engine-identity",
  targetCpu: "baseline",
};

test("polling is opt-in and preserves the legacy configuration identity", () => {
  assert.deepEqual(normalizeEngineConfig(legacy, "config"), legacy);
  assert.equal(fingerprintJson(normalizeEngineConfig(legacy, "config")), fingerprintJson(legacy));
  const polling = { ...legacy, fuelEpochPollInterval: 100_000 };
  assert.deepEqual(normalizeEngineConfig(polling, "config"), polling);
  assert.notEqual(fingerprintJson(polling), fingerprintJson(legacy));
  assert.notEqual(fingerprintJson(polling), fingerprintJson({ ...polling, fuelEpochPollInterval: 200_000 }));
  for (const value of [0, -1, 0.5, "100000", undefined, null, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => normalizeEngineConfig({ ...legacy, fuelEpochPollInterval: value }, "config"), /positive safe integer/u);
  }
  for (const key of ["consumeFuel", "epochInterruption"]) {
    assert.throws(() => normalizeEngineConfig({ ...polling, [key]: false }, "config"), /requires fuel and epoch/u);
  }
  assert.throws(() => normalizeEngineConfig({ ...legacy, unknown: true }, "config"), /unknown field/u);
});

test("native target capabilities govern polling without rejecting legacy targets", () => {
  const polling = { ...legacy, fuelEpochPollInterval: 100_000 };
  const capable = { ...legacyContract, fuelEpochPolling: true };
  validatePrecompilerEngineRequest(legacy, legacyContract, "baseline");
  validatePrecompilerEngineRequest(legacy, capable, "baseline");
  validatePrecompilerEngineRequest(polling, capable, "baseline");
  assert.throws(() => validatePrecompilerEngineRequest(polling, legacyContract, "baseline"), /does not support/u);
  assert.throws(() => validatePrecompilerEngineRequest(polling, capable, "native"), /engine contract/u);
  assert.throws(() => validatePrecompilerEngineRequest(polling, { ...capable, wasmExceptions: false }, "baseline"), /engine contract/u);
});
