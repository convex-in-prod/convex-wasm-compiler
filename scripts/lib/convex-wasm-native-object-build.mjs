import { join } from "node:path";

import {
  assertPlainObject,
  fail,
  fingerprintJson,
  normalizeJson,
  requirePositiveInteger,
  requireString,
  requireStringArray,
} from "./convex-wasm-artifact-contract.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-stage.mjs";
import {
  authenticateNativeStagedInputs,
  copyNativeStagedInputs,
  normalizeNativeStagedInputs,
} from "./convex-wasm-native-staged-inputs.mjs";

const MAX_OBJECT_BYTES = 320 * 1024 * 1024;
const STAGE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const OBJECT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\.o$/u;

export async function buildConvexWasmNativeObject({
  cacheLayout,
  cacheRoot,
  command,
  identity,
  inputs,
  maxObjectBytes,
  outputName,
  runCommand,
  sourceName,
  stage,
  verifyMaterials,
}) {
  if (typeof runCommand !== "function" || typeof verifyMaterials !== "function") {
    fail("native object building requires command and material-verification functions");
  }
  requireString(stage, "native object stage");
  if (!STAGE_PATTERN.test(stage)) fail("native object stage must be a path-safe name");
  requireString(outputName, "native object output name");
  if (!OBJECT_NAME_PATTERN.test(outputName)) {
    fail("native object output must name an object file in the work directory");
  }
  requireString(sourceName, "native object source name");
  const stagedInputs = normalizeNativeStagedInputs(inputs, "native object");
  if (!stagedInputs.some(({ name }) => name === sourceName)) {
    fail("native object source must be a staged input");
  }
  if (stagedInputs.some(({ name }) => name === outputName)) {
    fail("native object output must differ from staged inputs");
  }
  const args = requireStringArray(command.args, "native object command arguments");
  const outputIndex = args.indexOf("-o");
  if (
    outputIndex < 0 ||
    outputIndex !== args.lastIndexOf("-o") ||
    args[outputIndex + 1] !== outputName ||
    !args.includes(sourceName)
  ) {
    fail("native object command must compile its staged source to its declared output");
  }
  assertPlainObject(identity, "native object identity");
  if (
    Object.hasOwn(identity, "stagedInputs") ||
    Object.hasOwn(identity, "commandArgumentsSha256") ||
    Object.hasOwn(identity, "sourceName") ||
    Object.hasOwn(identity, "outputName")
  ) {
    fail("native object identity input and command fields are owned by the builder");
  }
  const stageIdentity = normalizeJson({
    ...identity,
    commandArgumentsSha256: fingerprintJson(args),
    outputName,
    sourceName,
    stagedInputs: stagedInputs.map(({ name, sha256, size }) => ({ name, sha256, size })),
  }, "native object stage identity");
  const authenticateInputs = async () => {
    await authenticateNativeStagedInputs(stagedInputs, "native object");
    await verifyMaterials(stage);
  };
  // A cache hit or another caller's in-flight build cannot waive this caller's input check.
  await authenticateInputs();
  return ensureArtifactStage({
    authenticatePublicationPrerequisite: authenticateInputs,
    build: async (workPath) => {
      await copyNativeStagedInputs(stagedInputs, "native object", workPath);
      await verifyMaterials(stage);
      const timing = await runCommand({ command, stage, workPath });
      return { metadata: null, outputPath: join(workPath, outputName), timing };
    },
    cacheLayout,
    cacheRoot,
    extension: "o",
    identity: stageIdentity,
    maxArtifactBytes: Math.min(
      requirePositiveInteger(maxObjectBytes, "native object byte limit"),
      MAX_OBJECT_BYTES
    ),
    stage,
  });
}
