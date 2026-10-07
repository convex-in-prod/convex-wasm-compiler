import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { join } from "node:path";

import {
  canonicalJson,
  fail,
  requirePositiveInteger,
} from "./convex-wasm-artifact-contract.mjs";
import {
  hashPrivateRegularFile,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";
import {
  authenticateStaticHermesCBundle,
  staticHermesCBundleEnabled,
} from "./convex-wasm-static-hermes-c-bundle.mjs";
import {
  createStaticHermesPrecompileRequest,
  readStaticHermesPrecompileResponse,
  staticHermesRetainedLayoutInvocation,
} from "./convex-wasm-static-hermes-precompile-protocol.mjs";

const OUTPUT_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;

function launcherFileName(args, flag, separator) {
  const index = args.indexOf(flag);
  if (
    index < 0 ||
    index >= separator - 1 ||
    args.indexOf(flag, index + 1) >= 0
  ) {
    fail(`Static Hermes launcher must supply exactly one ${flag}`);
  }
  const name = args[index + 1];
  if (typeof name !== "string" || !OUTPUT_NAME_PATTERN.test(name)) {
    fail(
      `Static Hermes launcher ${flag} must name a file in its work directory`,
    );
  }
  return name;
}

export async function prepareStaticHermesSourceInput({
  command,
  generatedJavaScript,
  materials,
  retainedLayout,
  workPath,
}) {
  if (
    (typeof generatedJavaScript !== "string" &&
      !Buffer.isBuffer(generatedJavaScript)) ||
    generatedJavaScript.length === 0
  ) {
    fail("Static Hermes source stage requires nonempty generated JavaScript");
  }
  const separator = command.args.indexOf("--");
  if (separator < 0 || command.args.at(-1) !== "input.js") {
    fail(
      "Static Hermes launcher must compile input.js after its argument separator",
    );
  }
  const requestName = launcherFileName(command.args, "--request", separator);
  const responseName = launcherFileName(command.args, "--response", separator);
  if (
    requestName === responseName ||
    requestName === "input.js" ||
    responseName === "input.js"
  ) {
    fail(
      "Static Hermes launcher input, request, and response files must differ",
    );
  }
  const bundleOutput = staticHermesCBundleEnabled(
    command.args.slice(separator + 1),
  );
  const invocationCommand =
    retainedLayout === undefined
      ? command
      : {
          ...command,
          args: [
            ...command.args.slice(0, -1),
            "-Xc-layout-input=retained-layout.json",
            "input.js",
          ],
        };
  const layoutInvocation = staticHermesRetainedLayoutInvocation(
    invocationCommand.args.slice(separator + 1),
  );
  const sourceBytes = Buffer.from(generatedJavaScript, "utf8");
  const generatedSource = {
    sha256: createHash("sha256").update(sourceBytes).digest("hex"),
    size: sourceBytes.length,
  };
  const layoutInput =
    retainedLayout === undefined
      ? undefined
      : {
          path: "retained-layout.json",
          sha256: retainedLayout.sha256,
          size: retainedLayout.size,
        };
  const request = createStaticHermesPrecompileRequest(
    invocationCommand,
    generatedSource,
    materials,
    layoutInput,
  );
  if (retainedLayout !== undefined) {
    const bytes = await readPrivateRegularFile(
      retainedLayout.path,
      retainedLayout.size,
      "retained layout input",
    );
    if (
      bytes.length !== retainedLayout.size ||
      createHash("sha256").update(bytes).digest("hex") !== retainedLayout.sha256
    ) {
      fail("retained layout input does not match its identity");
    }
    await fs.writeFile(join(workPath, layoutInput.path), bytes, {
      flag: "wx",
      mode: 0o600,
    });
  }
  await fs.writeFile(join(workPath, "input.js"), sourceBytes, {
    flag: "wx",
    mode: 0o600,
  });
  await fs.writeFile(
    join(workPath, requestName),
    `${canonicalJson(request)}\n`,
    {
      flag: "wx",
      mode: 0o600,
    },
  );
  return {
    command: invocationCommand,
    request,
    responsePath: join(workPath, responseName),
    generatedSource,
    bundleOutput,
    layoutInvocation,
  };
}

export async function runStaticHermesSourceStage({
  command,
  generatedJavaScript,
  materials,
  maxGeneratedCBytes,
  retainedLayout,
  runCommand,
  verifyMaterials,
  workPath,
}) {
  requirePositiveInteger(
    maxGeneratedCBytes,
    "Static Hermes generated-C byte limit",
  );
  if (
    typeof runCommand !== "function" ||
    typeof verifyMaterials !== "function"
  ) {
    fail(
      "Static Hermes source stage requires command and material-verification functions",
    );
  }
  await verifyMaterials();
  const {
    command: invocationCommand,
    request,
    responsePath,
    generatedSource,
    bundleOutput,
    layoutInvocation,
  } = await prepareStaticHermesSourceInput({
    command,
    generatedJavaScript,
    materials,
    retainedLayout,
    workPath,
  });
  const timing = await runCommand({
    command: invocationCommand,
    stage: "static-hermes",
    workPath,
  });
  const response = await readStaticHermesPrecompileResponse(
    responsePath,
    request,
  );
  await verifyMaterials();
  if (response.kind === "sourceRejected") {
    return {
      generatedSource,
      kind: "sourceRejected",
      rejection: response,
      timing,
    };
  }
  if (bundleOutput !== (response.output !== undefined)) {
    fail("Static Hermes response does not match the configured C output mode");
  }
  if (response.output?.layout?.path !== layoutInvocation?.outputPath) {
    fail("Static Hermes retained layout output does not match its invocation");
  }
  if (response.output !== undefined) {
    const artifact = await authenticateStaticHermesCBundle(
      workPath,
      response.output,
      maxGeneratedCBytes,
    );
    return { artifact, generatedSource, kind: "success", timing };
  }
  const outputPath = join(workPath, "unit.c");
  const artifact = await hashPrivateRegularFile(
    outputPath,
    maxGeneratedCBytes,
    "Static Hermes generated C",
  );
  if (artifact.size === 0) fail("Static Hermes produced empty C output");
  return { artifact, generatedSource, kind: "success", outputPath, timing };
}
