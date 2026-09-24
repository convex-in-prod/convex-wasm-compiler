import { createHash } from "node:crypto";
import { posix } from "node:path";

export const convexWasmOfficialOutputNativeSymbolLocatorDomain =
  "convex-wasm-official-output-native-symbol-locator-v6";
export const convexWasmOfficialOutputSourceMembershipDomain =
  "convex-wasm-official-output-source-membership-v2";
export const convexWasmOfficialOutputChunkNativeSymbolLocatorKind =
  "convex-wasm-official-output-chunk-native-symbol-locator-v5";
export const convexWasmOfficialOutputChunkNativeSymbolAbi =
  "convex-wasm-official-output-chunk-native-symbol-abi-v1";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const supportedImportKinds = new Set(["dynamic-import", "import-statement"]);

function fail(message) {
  throw new Error(`Convex Wasm native symbol identity: ${message}`);
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireExactKeys(value, expectedKeys, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpectedKeys.length ||
    actualKeys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    fail(`${description} fields are invalid`);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  fail("locator contains an unsupported value");
}

function normalizeSourceMapMembershipName(value) {
  const suffixIndex = value.search(/[?#]/u);
  const hierarchy = suffixIndex === -1 ? value : value.slice(0, suffixIndex);
  const suffix = suffixIndex === -1 ? "" : value.slice(suffixIndex);
  const authority = /^([a-z][a-z\d+.-]*:)?\/\/([^/]*)(.*)$/iu.exec(hierarchy);
  if (authority !== null) {
    const path = posix.normalize(authority[3].length === 0 ? "/" : authority[3]);
    return `${authority[1] ?? ""}//${authority[2]}${path.startsWith("/") ? path : `/${path}`}${suffix}`;
  }
  if (/^file:/iu.test(hierarchy)) {
    const rawPath = hierarchy.slice("file:".length);
    const path = posix.normalize(rawPath.startsWith("/") ? rawPath : `/${rawPath}`);
    return `file://${path}${suffix}`;
  }
  const hierarchicalScheme = /^([a-z][a-z\d+.-]*:)(\/.*)$/iu.exec(hierarchy);
  if (hierarchicalScheme !== null) {
    return `${hierarchicalScheme[1]}${posix.normalize(hierarchicalScheme[2])}${suffix}`;
  }
  // Other scheme-prefixed names are opaque URI references, so path normalization must not
  // reinterpret their payload as hierarchical source-map membership.
  if (/^[a-z][a-z\d+.-]*:/iu.test(hierarchy)) return value;
  if (hierarchy.length === 0) return suffix;
  const normalizedPath = posix.normalize(hierarchy);
  // Preserve relative-reference classification when dot-segment removal exposes a colon in the first
  // remaining segment. Without the marker, that path would collide with an opaque URI spelling.
  const relativePath = /^[a-z][a-z\d+.-]*:/iu.test(normalizedPath)
    ? `./${normalizedPath}`
    : normalizedPath;
  return `${relativePath}${suffix}`;
}

function effectiveSourceMapMembershipName(sourceRoot, source) {
  if (sourceRoot === undefined || sourceRoot.length === 0) {
    return normalizeSourceMapMembershipName(source);
  }
  const separator = sourceRoot.endsWith("/") || source.startsWith("/") ? "" : "/";
  return normalizeSourceMapMembershipName(`${sourceRoot}${separator}${source}`);
}

export function convexWasmOfficialOutputSourceMembershipIdentitySha256({ sourceRoot, sources }) {
  if (!Array.isArray(sources)) {
    fail("source-map sources must be an array");
  }
  if (sourceRoot !== undefined && (typeof sourceRoot !== "string" || sourceRoot.includes("\0"))) {
    fail("source-map sourceRoot must be a string without NUL bytes when present");
  }
  const canonicalSources = sources.map((source, index) =>
    effectiveSourceMapMembershipName(
      sourceRoot,
      requireString(source, `source-map source ${index}`)
    )
  );
  canonicalSources.sort();
  const uniqueSources = canonicalSources.filter(
    (source, index) => index === 0 || canonicalSources[index - 1] !== source
  );
  return createHash("sha256")
    .update(
      canonicalJson({
        domain: convexWasmOfficialOutputSourceMembershipDomain,
        sources: uniqueSources,
      })
    )
    .digest("hex");
}

export function convexWasmOfficialOutputChunkNativeSymbolLocator({
  bindingPath,
  canonicalEntryPath,
  sourceMembershipSha256,
  symbolAbi = convexWasmOfficialOutputChunkNativeSymbolAbi,
}) {
  if (canonicalEntryPath !== null) {
    requireString(canonicalEntryPath, "chunk canonical entry path");
  }
  if (symbolAbi !== convexWasmOfficialOutputChunkNativeSymbolAbi) {
    fail("chunk native-symbol ABI is unsupported");
  }
  const normalizedBindingPath = normalizeChunkBindingPath(bindingPath);
  if (
    canonicalEntryPath !== null &&
    (normalizedBindingPath.entryPath !== canonicalEntryPath ||
      normalizedBindingPath.imports.length !== 0)
  ) {
    fail("chunk canonical entry path disagrees with its stable binding path");
  }
  return Object.freeze({
    bindingPath: normalizedBindingPath,
    canonicalEntryPath,
    kind: convexWasmOfficialOutputChunkNativeSymbolLocatorKind,
    sourceMembershipSha256: requireSha256(
      sourceMembershipSha256,
      "chunk source-membership identity"
    ),
    symbolAbi,
  });
}

function normalizeChunkBindingPath(value) {
  const bindingPath = requireExactKeys(value, ["entryPath", "imports"], "chunk binding path");
  if (!Array.isArray(bindingPath.imports)) {
    fail("chunk binding path imports must be an array");
  }
  return Object.freeze({
    entryPath: requireString(bindingPath.entryPath, "chunk binding path entry path"),
    imports: Object.freeze(
      bindingPath.imports.map((imported, index) => {
        const edge = requireExactKeys(
          imported,
          ["kind", "occurrence"],
          `chunk binding path import ${index}`
        );
        if (!supportedImportKinds.has(edge.kind)) {
          fail(`chunk binding path import ${index} kind is unsupported`);
        }
        if (!Number.isSafeInteger(edge.occurrence) || edge.occurrence < 0) {
          fail(`chunk binding path import ${index} occurrence is invalid`);
        }
        return Object.freeze({ kind: edge.kind, occurrence: edge.occurrence });
      })
    ),
  });
}

function normalizeChunkNativeSymbolLocator(value) {
  const locator = requireExactKeys(
    value,
    ["bindingPath", "canonicalEntryPath", "kind", "sourceMembershipSha256", "symbolAbi"],
    "chunk native symbol locator"
  );
  if (locator.kind !== convexWasmOfficialOutputChunkNativeSymbolLocatorKind) {
    fail("chunk native symbol locator kind is unsupported");
  }
  return convexWasmOfficialOutputChunkNativeSymbolLocator(locator);
}

/**
 * Derive the stable external C symbol namespace for one physical application unit.
 *
 * This locator is intentionally independent of executable content, generated JavaScript, and
 * reusable-code identity. Canonical source membership names ordinary shared output. The rooted
 * binding path distinguishes equal-membership and source-less chunks without using transport output
 * names; each path edge binds the import kind and source occurrence. symbolAbi names the factory
 * interface. Exact module and executable content remains authenticated by the surrounding unit and
 * application identities.
 */
export function convexWasmOfficialOutputNativeSymbolIdentitySha256({
  entryPath,
  entryPublication,
  nativeSymbolLocator,
}) {
  if (typeof entryPublication !== "boolean") {
    fail("entry-publication flag must be boolean");
  }
  const locator = entryPublication
    ? {
        entryPath: requireString(entryPath, "entry-publication entry path"),
        kind: "entry-publication",
      }
    : {
        kind: "chunk",
        nativeSymbolLocator: normalizeChunkNativeSymbolLocator(nativeSymbolLocator),
      };
  return createHash("sha256")
    .update(
      canonicalJson({
        domain: convexWasmOfficialOutputNativeSymbolLocatorDomain,
        locator,
      })
    )
    .digest("hex");
}
