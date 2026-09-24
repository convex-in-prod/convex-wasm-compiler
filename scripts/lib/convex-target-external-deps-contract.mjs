import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(`Convex target external dependencies: ${message}`);
}

export function validateTargetExternalDepsSelection(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort()) !== canonicalJson(["id", "sha256"]) ||
    typeof value.id !== "string" ||
    value.id.length === 0 ||
    typeof value.sha256 !== "string" ||
    !SHA256.test(value.sha256)
  )
    fail("invalid exact package selection");
  return Object.freeze({ id: value.id, sha256: value.sha256 });
}

export function validateTargetExternalDepsDescriptor(value, nodeDependencies) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    canonicalJson(Object.keys(value).sort()) !==
      canonicalJson(["dependencies", "id", "kind", "sha256", "size", "storageKey"]) ||
    value.kind !== "convex-external-deps-package-v1" ||
    typeof value.storageKey !== "string" ||
    value.storageKey.length === 0 ||
    !Number.isSafeInteger(value.size) ||
    value.size <= 0 ||
    value.size > MAX_ARCHIVE_BYTES ||
    !Array.isArray(nodeDependencies) ||
    nodeDependencies.length === 0
  )
    fail("invalid admitted package descriptor");
  validateTargetExternalDepsSelection({ id: value.id, sha256: value.sha256 });
  const dependencies = nodeDependencies
    .map(({ name, version }) => {
      if (
        typeof name !== "string" ||
        name.length === 0 ||
        typeof version !== "string" ||
        version.length === 0
      ) {
        fail("invalid dependency declaration");
      }
      return { package: name, version };
    })
    .sort((left, right) =>
      left.package < right.package ? -1 : left.package > right.package ? 1 : 0
    );
  if (
    new Set(dependencies.map(({ package: name }) => name)).size !== dependencies.length ||
    canonicalJson(dependencies) !== canonicalJson(value.dependencies)
  ) {
    fail("admitted dependency declarations differ from request");
  }
  return Object.freeze({ ...value, dependencies: Object.freeze(dependencies.map(Object.freeze)) });
}
