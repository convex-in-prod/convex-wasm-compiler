import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  fail,
  requireBoolean,
  requireEnum,
  requirePositiveInteger,
} from "./convex-wasm-artifact-contract.mjs";

// Omission is the historical zero-interval mode. Preserve its exact JSON shape
// so existing configuration hashes and authenticated artifacts remain valid.
export function normalizeEngineConfig(engineConfig, description) {
  assertPlainObject(engineConfig, description);
  assertExactKeys(
    engineConfig,
    new Set(["consumeFuel", "epochInterruption", "fuelEpochPollInterval", "profilingStrategy", "wasmExceptions"]),
    description
  );
  const config = {
    consumeFuel: requireBoolean(engineConfig.consumeFuel, `${description}.consumeFuel`),
    epochInterruption: requireBoolean(engineConfig.epochInterruption, `${description}.epochInterruption`),
    profilingStrategy: requireEnum(engineConfig.profilingStrategy, new Set(["perf-map"]), `${description}.profilingStrategy`),
    wasmExceptions: requireBoolean(engineConfig.wasmExceptions, `${description}.wasmExceptions`),
  };
  if (Object.hasOwn(engineConfig, "fuelEpochPollInterval")) {
    config.fuelEpochPollInterval = requirePositiveInteger(engineConfig.fuelEpochPollInterval, `${description}.fuelEpochPollInterval`);
    if (!config.consumeFuel || !config.epochInterruption) {
      fail(`${description}.fuelEpochPollInterval requires fuel and epoch interruption`);
    }
  }
  return config;
}

export function validatePrecompilerEngineRequest(engineConfig, engineContract, targetCpu) {
  const { fuelEpochPollInterval, ...baseConfig } = normalizeEngineConfig(engineConfig, "requested engine config");
  const { fuelEpochPolling, ...baseContract } = engineContract;
  const expected = {
    ...baseConfig,
    engineIdentityKind: "convex-wasm-wasmtime-engine-identity",
    targetCpu,
  };
  if (canonicalJson(baseContract) !== canonicalJson(expected)) {
    fail("precompiler package does not match the configured engine contract");
  }
  if (fuelEpochPollInterval !== undefined && fuelEpochPolling !== true) {
    fail("precompiler package does not support fuel-scheduled epoch polling");
  }
}
