import { createHash } from "node:crypto";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";

export const MAX_ANALYSIS_ENVIRONMENT_BYTES = 1024 * 1024;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function parseSyntheticAnalysisEnvironment(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_ANALYSIS_ENVIRONMENT_BYTES) {
    throw new Error("analysis environment must be a nonempty bounded file");
  }
  let values;
  try {
    values = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("analysis environment is not valid JSON");
  }
  if (values === null || typeof values !== "object" || Array.isArray(values)) {
    throw new Error("analysis environment must be an object");
  }
  const names = Object.keys(values).sort();
  if (names.length === 0) {
    throw new Error("analysis environment must contain at least one variable");
  }
  for (const name of names) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name) || typeof values[name] !== "string" || values[name].length === 0) {
      throw new Error("analysis environment has an invalid variable name or value");
    }
  }
  if (bytes.toString("utf8") !== `${canonicalJson(values)}\n`) {
    throw new Error("analysis environment must be canonical JSON with one trailing newline");
  }
  return {
    values,
    evidence: {
      fileSha256: sha256(bytes),
      names,
      values: names.map((name) => ({ name, valueSha256: sha256(values[name]) })),
    },
  };
}
