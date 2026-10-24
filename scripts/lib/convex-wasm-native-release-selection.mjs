import { isAbsolute, join, resolve } from "node:path";

import {
  acquireNativePackage,
  validateNativePackageReference,
} from "./convex-wasm-native-package-acquisition.mjs";

export const nativeReleaseTargets = Object.freeze({
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-gnu",
});
const KINDS = Object.freeze(["compiler", "precompiler"]);

function exactKeys(value, keys, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${description} has unexpected fields`);
  }
}

export function validateNativeReleaseSelection(selection) {
  exactKeys(selection, ["kind", "packages"], "native release selection");
  if (selection.kind !== "convex-wasm-native-package-selection") {
    throw new Error("native release selection kind is unsupported");
  }
  exactKeys(selection.packages, Object.keys(nativeReleaseTargets), "native release platforms");
  for (const [runtime, targetTriple] of Object.entries(nativeReleaseTargets)) {
    const packages = selection.packages[runtime];
    exactKeys(packages, KINDS, `${runtime} native packages`);
    for (const kind of KINDS) {
      const reference = packages[kind];
      validateNativePackageReference(reference);
      if (reference.targetTriple !== targetTriple) {
        throw new Error(`${runtime} ${kind} target does not match its platform`);
      }
    }
  }
  return selection;
}

export async function acquireNativeReleaseForHost({ selection, cacheRoot, signal }) {
  validateNativeReleaseSelection(selection);
  if (typeof cacheRoot !== "string" || !isAbsolute(cacheRoot) || resolve(cacheRoot) !== cacheRoot) {
    throw new Error("native package cache root must be a normalized absolute path");
  }
  const runtime = `${process.platform}-${process.arch}`;
  const references = selection.packages[runtime];
  if (references === undefined) {
    throw new Error(`native packages are unavailable for ${runtime}`);
  }
  const [compiler, precompiler] = await Promise.all(
    KINDS.map((kind) =>
      acquireNativePackage({
        kind,
        reference: references[kind],
        packageRoot: join(cacheRoot, kind),
        signal,
      })
    )
  );
  return Object.freeze({ compiler, precompiler });
}
