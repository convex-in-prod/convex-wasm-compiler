import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";

import { canonicalJson, fail, requirePositiveInteger } from "./convex-wasm-artifact-contract.mjs";
import { hashPrivateRegularFile } from "./convex-wasm-artifact-material.mjs";
import {
  authenticateStaticHermesCBundle,
  staticHermesCBundleEnabled,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import {
  createStaticHermesPrecompileRequest,
  readStaticHermesPrecompileResponse,
} from "./convex-wasm-static-hermes-precompile-protocol.mjs";

const OUTPUT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;

function launcherFileName(args, flag, separator) {
  const index = args.indexOf(flag);
  if (index < 0 || index >= separator - 1 || args.indexOf(flag, index + 1) >= 0) {
    fail(`Static Hermes launcher must supply exactly one ${flag}`);
  }
  const name = args[index + 1];
  if (typeof name !== "string" || !OUTPUT_NAME_PATTERN.test(name)) {
    fail(`Static Hermes launcher ${flag} must name a file in its work directory`);
  }
  return name;
}

export async function runStaticHermesSourceStage({
  command,
  generatedJavaScript,
  materials,
  maxGeneratedCBytes,
  runCommand,
  verifyMaterials,
  workPath,
}) {
  if (typeof generatedJavaScript !== "string" || generatedJavaScript.length === 0) {
    fail("Static Hermes source stage requires nonempty generated JavaScript");
  }
  requirePositiveInteger(maxGeneratedCBytes, "Static Hermes generated-C byte limit");
  if (typeof runCommand !== "function" || typeof verifyMaterials !== "function") {
    fail("Static Hermes source stage requires command and material-verification functions");
  }
  const separator = command.args.indexOf("--");
  if (separator < 0 || command.args.at(-1) !== "input.js") {
    fail("Static Hermes launcher must compile input.js after its argument separator");
  }
  const requestName = launcherFileName(command.args, "--request", separator);
  const responseName = launcherFileName(command.args, "--response", separator);
  if (requestName === responseName || requestName === "input.js" || responseName === "input.js") {
    fail("Static Hermes launcher input, request, and response files must differ");
  }
  const bundleOutput = staticHermesCBundleEnabled(command.args.slice(separator + 1));
  const sourceBytes = Buffer.from(generatedJavaScript, "utf8");
  const generatedSource = {
    sha256: createHash("sha256").update(sourceBytes).digest("hex"),
    size: sourceBytes.length,
  };
  const request = createStaticHermesPrecompileRequest(command, generatedSource, materials);
  await verifyMaterials();
  await fs.writeFile(join(workPath, "input.js"), sourceBytes, { flag: "wx", mode: 0o600 });
  await fs.writeFile(join(workPath, requestName), `${canonicalJson(request)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  const timing = await runCommand({ command, stage: "static-hermes", workPath });
  const response = await readStaticHermesPrecompileResponse(join(workPath, responseName), request);
  await verifyMaterials();
  if (response.kind === "sourceRejected") {
    return { generatedSource, kind: "sourceRejected", rejection: response, timing };
  }
  if (bundleOutput !== (response.output !== undefined)) {
    fail("Static Hermes response does not match the configured C output mode");
  }
  if (response.output !== undefined) {
    const artifact = await authenticateStaticHermesCBundle(
      workPath,
      response.output,
      maxGeneratedCBytes
    );
    return { artifact, generatedSource, kind: "success", timing };
  }
  const outputPath = join(workPath, "unit.c");
  const artifact = await hashPrivateRegularFile(
    outputPath,
    maxGeneratedCBytes,
    "Static Hermes generated C"
  );
  if (artifact.size === 0) fail("Static Hermes produced empty C output");
  return { artifact, generatedSource, kind: "success", outputPath, timing };
}
