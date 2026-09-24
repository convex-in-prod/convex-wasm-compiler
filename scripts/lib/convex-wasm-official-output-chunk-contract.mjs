import { posix } from "node:path";

import {
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  requireExactPlainObject,
  requireManifestString,
} from "./convex-wasm-artifact-contract.mjs";

export const convexWasmModuleGraphCompilerDescriptorKind =
  "convex-wasm-official-output-module-graph-compiler-descriptor-v2";
export const convexWasmModuleGraphCompilerDescriptorSchemaVersion = 2;
export const convexWasmOfficialOutputChunkNativeApplicationDescriptorKind =
  "convex-wasm-official-output-chunk-native-application-descriptor-v3";
export const convexWasmOfficialOutputChunkApplicationUnitKind =
  "convex-wasm-official-output-chunk-application-unit-v3";
export const convexWasmOfficialOutputChunkUnitsKind = "convex-wasm-official-output-chunk-units-v3";
export const convexWasmOfficialOutputChunkUnitKind = "convex-wasm-official-output-chunk-unit-v2";
export const convexWasmOfficialOutputChunkEntryPublicationUnitKind =
  "convex-wasm-official-output-chunk-entry-publication-unit-v2";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MAX_MANIFEST_STRING_BYTES = 4 * 1024;
const EXECUTABLE_DEPENDENCY_SPECIFIER_PATTERN =
  /^\.\/__convex_wasm_dependency_(dynamic_import|import_statement)_([0-9a-f]{64})_([0-9]{8})\.js$/u;

export function createConvexWasmOfficialOutputExecutableDependencySpecifier({
  kind,
  nativeSymbolIdentitySha256,
  occurrence,
}) {
  if (
    (kind !== "dynamic-import" && kind !== "import-statement") ||
    typeof nativeSymbolIdentitySha256 !== "string" ||
    !SHA256_PATTERN.test(nativeSymbolIdentitySha256) ||
    !Number.isSafeInteger(occurrence) ||
    occurrence < 0 ||
    occurrence > 99_999_999
  ) {
    fail("official-output executable dependency identity is invalid");
  }
  return `./__convex_wasm_dependency_${kind.replaceAll("-", "_")}_${nativeSymbolIdentitySha256}_${String(occurrence).padStart(8, "0")}.js`;
}

export function parseConvexWasmOfficialOutputExecutableDependencySpecifier(specifier) {
  const match =
    typeof specifier === "string" ? EXECUTABLE_DEPENDENCY_SPECIFIER_PATTERN.exec(specifier) : null;
  if (match === null) {
    fail("official-output executable dependency specifier is invalid");
  }
  return Object.freeze({
    kind: match[1].replaceAll("_", "-"),
    nativeSymbolIdentitySha256: match[2],
    occurrence: Number(match[3]),
  });
}

function isNormalizedConvexWasmOfficialOutputDependencySpecifier(specifier) {
  if (specifier.includes("\\")) return false;
  const components = specifier.split("/");
  if (components[0] === ".") {
    components.shift();
  } else {
    let parentCount = 0;
    while (components[0] === "..") {
      components.shift();
      parentCount += 1;
    }
    if (parentCount === 0) return false;
  }
  return (
    components.length > 0 &&
    components.every((component) => component.length > 0 && component !== "." && component !== "..")
  );
}

export function normalizeConvexWasmOfficialOutputChunkDependencies({
  dependencies,
  namespaceSlotCount,
  unitDescription,
}) {
  if (!Array.isArray(dependencies)) {
    fail(`${unitDescription} dependencies are invalid`);
  }
  const normalized = dependencies.map((dependency, dependencyIndex) => {
    const value = requireExactPlainObject(
      dependency,
      ["executableSpecifier", "kind", "path", "slot", "specifier"],
      `${unitDescription} dependency ${dependencyIndex}`
    );
    if (
      (value.kind !== "dynamic-import" && value.kind !== "import-statement") ||
      !Number.isSafeInteger(value.slot) ||
      value.slot < 0 ||
      value.slot >= namespaceSlotCount
    ) {
      fail(`${unitDescription} dependency ${dependencyIndex} is invalid`);
    }
    const executableSpecifier = requireManifestString(
      value.executableSpecifier,
      `${unitDescription} dependency ${dependencyIndex} executable specifier`,
      MAX_MANIFEST_STRING_BYTES,
      false
    );
    const executableIdentity =
      parseConvexWasmOfficialOutputExecutableDependencySpecifier(executableSpecifier);
    if (executableIdentity.kind !== value.kind) {
      fail(`${unitDescription} dependency ${dependencyIndex} executable specifier kind is invalid`);
    }
    return {
      executableSpecifier,
      kind: value.kind,
      path: requireManifestString(
        value.path,
        `${unitDescription} dependency ${dependencyIndex} path`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
      slot: value.slot,
      specifier: requireManifestString(
        value.specifier,
        `${unitDescription} dependency ${dependencyIndex} specifier`,
        MAX_MANIFEST_STRING_BYTES,
        false
      ),
    };
  });
  if (
    new Set(normalized.map(({ executableSpecifier }) => executableSpecifier)).size !==
    normalized.length
  ) {
    fail(`${unitDescription} repeats an executable dependency specifier`);
  }
  const executableOccurrences = normalized
    .map(({ executableSpecifier }) =>
      parseConvexWasmOfficialOutputExecutableDependencySpecifier(executableSpecifier)
    )
    .map(({ occurrence }) => occurrence)
    .sort((left, right) => left - right);
  if (executableOccurrences.some((occurrence, index) => occurrence !== index)) {
    fail(`${unitDescription} executable dependency occurrences are invalid`);
  }
  return normalized;
}

export function validateConvexWasmOfficialOutputChunkDependencyTopology({
  chunkSlotCount,
  description,
  units,
}) {
  for (const [unitIndex, unit] of units.slice(0, chunkSlotCount).entries()) {
    let previousDependencyCanonical;
    for (const [dependencyIndex, dependency] of unit.dependencies.entries()) {
      if (unit.dependencies.length > 1) {
        const dependencyCanonical = canonicalJson(dependency);
        if (dependencyIndex > 0 && previousDependencyCanonical >= dependencyCanonical) {
          fail(`${description} unit ${unitIndex} dependencies are not canonical`);
        }
        previousDependencyCanonical = dependencyCanonical;
      }
      if (
        !isNormalizedConvexWasmOfficialOutputDependencySpecifier(dependency.executableSpecifier) ||
        !isNormalizedConvexWasmOfficialOutputDependencySpecifier(dependency.specifier) ||
        posix.normalize(posix.join(posix.dirname(unit.module.path), dependency.specifier)) !==
          dependency.path
      ) {
        fail(
          `${description} unit ${unitIndex} dependency ${dependencyIndex} does not resolve to its module path`
        );
      }
      if (dependency.slot === unitIndex) {
        fail(
          `${description} unit ${unitIndex} dependency ${dependencyIndex} cannot bind its own slot`
        );
      }
      if (units[dependency.slot].module.path !== dependency.path) {
        fail(
          `${description} unit ${unitIndex} dependency ${dependencyIndex} slot does not bind its module path`
        );
      }
      const executableIdentity = parseConvexWasmOfficialOutputExecutableDependencySpecifier(
        dependency.executableSpecifier
      );
      if (
        executableIdentity.nativeSymbolIdentitySha256 !==
        units[dependency.slot].nativeSymbolIdentitySha256
      ) {
        fail(
          `${description} unit ${unitIndex} dependency ${dependencyIndex} executable specifier does not bind its module slot`
        );
      }
    }
  }
}

export function deriveConvexWasmOfficialOutputReusableCodeIdentitySha256s({
  chunkSlotCount,
  units,
}) {
  if (
    !Array.isArray(units) ||
    !Number.isSafeInteger(chunkSlotCount) ||
    chunkSlotCount < 1 ||
    chunkSlotCount > units.length ||
    units.some(({ entryPublication }, index) => entryPublication !== index >= chunkSlotCount)
  ) {
    fail("official-output reusable-code identity units have an invalid publication boundary");
  }
  const intrinsicIdentitySha256ByPath = new Map(
    units.slice(0, chunkSlotCount).map((unit) => [
      unit.module.path,
      fingerprintJson({
        domain: "convex-wasm-official-output-chunk-intrinsic-code-v3",
        javascript: unit.javascript,
        kind: unit.kind,
        nativeSymbolLocator: unit.nativeSymbolLocator,
        transform: unit.transform,
      }),
    ])
  );
  if (intrinsicIdentitySha256ByPath.size !== chunkSlotCount) {
    fail("official-output reusable-code identity units repeat a chunk module path");
  }
  return units.map((unit) => {
    if (unit.entryPublication) {
      return fingerprintJson({
        domain: "convex-wasm-official-output-entry-publication-code-v2",
        javascript: unit.javascript,
        kind: unit.kind,
      });
    }
    if (unit.dependencies.some(({ path }) => !intrinsicIdentitySha256ByPath.has(path))) {
      fail(
        `official-output reusable-code identity unit ${unit.applicationUnitSlot} has an absent dependency`
      );
    }
    const dependencyLogicalIdentities = unit.dependencies.map(({ executableSpecifier, kind }) => ({
      executableSpecifier,
      kind,
    }));
    // Sorting must use the same canonical JSON order as the identity contract, but each
    // dependency needs serialization only once, not on every comparator invocation.
    const sortedDependencyLogicalIdentities = dependencyLogicalIdentities
      .map((identity) => ({ canonical: canonicalJson(identity), identity }))
      .sort((left, right) => compareStrings(left.canonical, right.canonical))
      .map(({ identity }) => identity);
    return fingerprintJson({
      dependencies: sortedDependencyLogicalIdentities,
      domain: "convex-wasm-official-output-chunk-reusable-code-v3",
      intrinsicIdentitySha256: intrinsicIdentitySha256ByPath.get(unit.module.path),
    });
  });
}
