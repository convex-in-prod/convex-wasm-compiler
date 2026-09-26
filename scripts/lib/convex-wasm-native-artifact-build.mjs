import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  assertPlainObject,
  fail,
  fingerprintJson,
  normalizeJson,
  requirePositiveInteger,
  requireStringArray,
} from "./convex-wasm-artifact-contract.mjs";
import {
  decodeUtf8,
  hashPrivateRegularFile,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-stage.mjs";
import { normalizeEngineIdentity } from "./convex-wasm-module-graph-package.mjs";
import {
  authenticateNativeStagedInputs,
  copyNativeStagedInputs,
  normalizeNativeStagedInputs,
} from "./convex-wasm-native-staged-inputs.mjs";

const MAX_CORE_WASM_BYTES = 320 * 1024 * 1024;
const MAX_AOT_BYTES = 1024 * 1024 * 1024;
const MAX_ENGINE_IDENTITY_BYTES = 64 * 1024;
async function readEngineIdentity(path, engineConfig, target) {
  const source = decodeUtf8(
    await readPrivateRegularFile(path, MAX_ENGINE_IDENTITY_BYTES, "Wasmtime engine identity"),
    "Wasmtime engine identity"
  );
  let value;
  try {
    value = JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm engine identity is invalid JSON", { cause: error });
  }
  return normalizeEngineIdentity(value, engineConfig, target);
}

export async function buildConvexWasmCoreWasmAndAot({
  cacheLayout,
  cacheRoot,
  commands,
  engineConfig,
  identities,
  limits,
  linkInputs,
  runCommand,
  target,
  verifyMaterials,
}) {
  if (typeof runCommand !== "function" || typeof verifyMaterials !== "function") {
    fail("Core Wasm and AOT building requires command and material-verification functions");
  }
  assertPlainObject(identities.coreWasm, "Core Wasm identity");
  assertPlainObject(identities.wasmtimeAot, "Wasmtime AOT identity");
  if (
    Object.hasOwn(identities.coreWasm, "stagedInputs") ||
    Object.hasOwn(identities.coreWasm, "commandArgumentsSha256")
  ) {
    fail("Core Wasm identity staged inputs and command arguments are owned by the builder");
  }
  if (
    Object.hasOwn(identities.wasmtimeAot, "coreWasm") ||
    Object.hasOwn(identities.wasmtimeAot, "commandArgumentsSha256")
  ) {
    fail("Wasmtime AOT identity Core Wasm material and command arguments are owned by the builder");
  }
  const linkArguments = requireStringArray(commands.link.args, "Core Wasm link command arguments");
  const aotArguments = requireStringArray(commands.precompile.args, "Wasmtime AOT command arguments");
  const inputs = normalizeNativeStagedInputs(linkInputs, "Core Wasm");
  const coreWasmIdentity = normalizeJson({
    ...identities.coreWasm,
    commandArgumentsSha256: fingerprintJson(linkArguments),
    stagedInputs: inputs.map(({ name, sha256, size }) => ({ name, sha256, size })),
  }, "Core Wasm stage identity");
  const authenticateLinkInputs = async () => {
    await authenticateNativeStagedInputs(inputs, "Core Wasm");
    await verifyMaterials("link");
  };
  // Every caller checks its own source paths before joining a process-wide cache flight.
  await authenticateLinkInputs();
  const coreWasm = await ensureArtifactStage({
    authenticatePublicationPrerequisite: authenticateLinkInputs,
    build: async (workPath) => {
      await copyNativeStagedInputs(inputs, "Core Wasm", workPath);
      await verifyMaterials("link");
      const timing = await runCommand({ command: commands.link, stage: "core-wasm", workPath });
      return { metadata: null, outputPath: join(workPath, "module.wasm"), timing };
    },
    cacheLayout,
    cacheRoot,
    extension: "wasm",
    identity: coreWasmIdentity,
    maxArtifactBytes: Math.min(
      requirePositiveInteger(limits.coreWasmBytes, "Core Wasm byte limit"),
      MAX_CORE_WASM_BYTES
    ),
    stage: "core-wasm",
  });
  const aotIdentity = normalizeJson({
    ...identities.wasmtimeAot,
    commandArgumentsSha256: fingerprintJson(aotArguments),
    coreWasm: {
      sha256: coreWasm.entry.artifactSha256,
      size: coreWasm.entry.artifactSize,
    },
  }, "Wasmtime AOT stage identity");
  const authenticateAotInput = async () => {
    const digest = await hashPrivateRegularFile(
      coreWasm.entry.artifactPath,
      coreWasm.entry.artifactSize,
      "Wasmtime AOT Core Wasm cache input"
    );
    if (
      digest.size !== coreWasm.entry.artifactSize ||
      digest.sha256 !== coreWasm.entry.artifactSha256
    ) {
      fail("Wasmtime AOT Core Wasm cache input does not match its identity");
    }
    await verifyMaterials("aot");
  };
  await authenticateAotInput();
  const wasmtimeAot = await ensureArtifactStage({
    authenticatePublicationPrerequisite: authenticateAotInput,
    build: async (workPath) => {
      const inputPath = join(workPath, "module.wasm");
      await fs.copyFile(coreWasm.entry.artifactPath, inputPath);
      await fs.chmod(inputPath, 0o600);
      const copied = await hashPrivateRegularFile(
        inputPath,
        coreWasm.entry.artifactSize,
        "Wasmtime AOT Core Wasm input"
      );
      if (
        copied.size !== coreWasm.entry.artifactSize ||
        copied.sha256 !== coreWasm.entry.artifactSha256
      ) {
        fail("Wasmtime AOT Core Wasm input does not match its cache entry");
      }
      await verifyMaterials("aot");
      const timing = await runCommand({
        command: commands.precompile,
        stage: "wasmtime-aot",
        workPath,
      });
      const engineIdentity = await readEngineIdentity(
        join(workPath, "engine-identity.json"), engineConfig, target
      );
      return {
        metadata: engineIdentity,
        outputPath: join(workPath, "module.cwasm"),
        timing,
      };
    },
    cacheLayout,
    cacheRoot,
    extension: "cwasm",
    identity: aotIdentity,
    maxArtifactBytes: Math.min(
      requirePositiveInteger(limits.aotBytes, "Wasmtime AOT byte limit"),
      MAX_AOT_BYTES
    ),
    stage: "wasmtime-aot",
  });
  return { coreWasm, wasmtimeAot, engineIdentity: normalizeEngineIdentity(
    wasmtimeAot.entry.metadata, engineConfig, target
  ) };
}
