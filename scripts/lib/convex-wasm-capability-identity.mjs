import {
  assertExactKeys,
  assertPlainObject,
  fail,
  fingerprintJson,
  normalizeJson,
  requireEnum,
  requireManifestString,
  requirePositiveInteger,
  requirePositiveU32,
  requireSha256,
} from "./convex-wasm-artifact-contract.mjs";

const MAX_MANIFEST_IDENTIFIER_BYTES = 256;
const MAX_MANIFEST_STRING_BYTES = 4 * 1024;
const GUEST_NATIVE_JSON_CODEC_IDENTITY_KIND = "convex-wasm-guest-native-json-codec-identity";
const LEGACY_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND =
  "convex-wasm-capability-request-envelope-identity-v1";
const PAGINATION_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND =
  "convex-wasm-capability-request-envelope-identity-v2";
const PRE_STORAGE_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND =
  "convex-wasm-capability-request-envelope-identity-v3";
const GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND =
  "convex-wasm-capability-request-envelope-identity-v4";
const CANONICAL_CONVEX_VALUE_VECTOR_CORPUS_KIND =
  "convex-wasm-canonical-convex-value-vector-corpus-v1";
const CANONICAL_CONVEX_VALUE_VECTOR_PRODUCER_KIND =
  "convex-sdk-backend-canonical-value-producer-v1";
const LEGACY_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND =
  "convex-wasm-canonical-capability-request-envelope-vector-corpus-v1";
const PAGINATION_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND =
  "convex-wasm-canonical-capability-request-envelope-vector-corpus-v2";
const PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND =
  "convex-wasm-canonical-capability-request-envelope-vector-corpus-v3";
const CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND =
  "convex-wasm-canonical-capability-request-envelope-vector-corpus-v4";
const LEGACY_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND =
  "convex-sdk-backend-capability-request-envelope-producer-v1";
const PAGINATION_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND =
  "convex-sdk-backend-capability-request-envelope-producer-v2";
const PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND =
  "convex-sdk-backend-capability-request-envelope-producer-v3";
const CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND =
  "convex-sdk-backend-capability-request-envelope-producer-v4";
export function convexWasmCapabilitySourcePipelineSha256(localProfiles) {
  if (!Array.isArray(localProfiles) || localProfiles.length === 0 || localProfiles.length > 8) {
    fail("capability source pipeline requires between one and eight local profiles");
  }
  const profileSha256s = localProfiles.map((profile, index) => {
    assertPlainObject(profile, `capability local profile ${index}`);
    return requireSha256(profile.sha256, `capability local profile ${index} SHA-256`);
  });
  return profileSha256s.length === 1
    ? profileSha256s[0]
    : fingerprintJson({
        domain: "convex-wasm-capability-package-source-pipeline-v2",
        profiles: profileSha256s,
      });
}

export function normalizeConvexWasmSourceIdentity(source) {
  assertPlainObject(source, "source");
  assertExactKeys(
    source,
    new Set([
      "exportName",
      "exportSha256",
      "modulePath",
      "resolvedGraphSha256",
      "runtimeModulePath",
      "udfKind",
    ]),
    "source"
  );
  const runtimeModulePath = requireManifestString(
    source.runtimeModulePath,
    "source.runtimeModulePath",
    MAX_MANIFEST_STRING_BYTES,
    false
  );
  if (
    runtimeModulePath.startsWith("/") ||
    runtimeModulePath.includes("\\") ||
    !runtimeModulePath.endsWith(".js") ||
    runtimeModulePath.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    fail("source.runtimeModulePath must be a normalized relative .js path");
  }
  return {
    exportName: requireManifestString(
      source.exportName,
      "source.exportName",
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    ),
    exportSha256: requireSha256(source.exportSha256, "source.exportSha256"),
    modulePath: requireManifestString(
      source.modulePath,
      "source.modulePath",
      MAX_MANIFEST_STRING_BYTES,
      true
    ),
    resolvedGraphSha256: requireSha256(source.resolvedGraphSha256, "source.resolvedGraphSha256"),
    runtimeModulePath,
    udfKind: requireEnum(source.udfKind, new Set(["mutation", "query"]), "source.udfKind"),
  };
}

function normalizeCanonicalConvexValueVectorCorpus(value, description) {
  assertPlainObject(value, description);
  assertExactKeys(value, new Set(["kind", "producer", "schemaVersion", "sha256"]), description);
  if (value.kind !== CANONICAL_CONVEX_VALUE_VECTOR_CORPUS_KIND || value.schemaVersion !== 1) {
    fail(`${description} kind or schema version is unsupported`);
  }
  assertPlainObject(value.producer, `${description}.producer`);
  assertExactKeys(value.producer, new Set(["kind", "sourceSha256"]), `${description}.producer`);
  if (value.producer.kind !== CANONICAL_CONVEX_VALUE_VECTOR_PRODUCER_KIND) {
    fail(`${description}.producer.kind is unsupported`);
  }
  return {
    kind: value.kind,
    producer: {
      kind: value.producer.kind,
      sourceSha256: requireSha256(
        value.producer.sourceSha256,
        `${description}.producer.sourceSha256`
      ),
    },
    schemaVersion: value.schemaVersion,
    sha256: requireSha256(value.sha256, `${description}.sha256`),
  };
}

function normalizeGuestNativeJsonCodecInput(valueMode, valueCodec) {
  if (valueMode === "opaque") {
    if (valueCodec !== undefined) {
      fail("opaque artifacts must not name a guest-native value codec");
    }
    return undefined;
  }
  assertPlainObject(valueCodec, "valueCodec");
  assertExactKeys(valueCodec, new Set(["canonicalVectorCorpus"]), "valueCodec");
  return {
    canonicalVectorCorpus: normalizeCanonicalConvexValueVectorCorpus(
      valueCodec.canonicalVectorCorpus,
      "valueCodec.canonicalVectorCorpus"
    ),
  };
}

function normalizeCanonicalCapabilityRequestEnvelopeVectorCorpus(value, description) {
  assertPlainObject(value, description);
  assertExactKeys(value, new Set(["kind", "producer", "schemaVersion", "sha256"]), description);
  if (value.schemaVersion !== 1) {
    fail(`${description} kind or schema version is unsupported`);
  }
  assertPlainObject(value.producer, `${description}.producer`);
  assertExactKeys(value.producer, new Set(["kind", "sourceSha256"]), `${description}.producer`);
  const legacyContract =
    value.kind === LEGACY_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND &&
    value.producer.kind === LEGACY_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND;
  const paginationContract =
    value.kind === PAGINATION_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND &&
    value.producer.kind === PAGINATION_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND;
  const preStorageContract =
    value.kind === PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND &&
    value.producer.kind === PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND;
  const currentContract =
    value.kind === CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND &&
    value.producer.kind === CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_PRODUCER_KIND;
  if (!legacyContract && !paginationContract && !preStorageContract && !currentContract) {
    fail(`${description}.producer.kind is unsupported`);
  }
  return {
    kind: value.kind,
    producer: {
      kind: value.producer.kind,
      sourceSha256: requireSha256(
        value.producer.sourceSha256,
        `${description}.producer.sourceSha256`
      ),
    },
    schemaVersion: value.schemaVersion,
    sha256: requireSha256(value.sha256, `${description}.sha256`),
  };
}

function normalizeCapabilityRequestEnvelopeInput(valueMode, requestEnvelope) {
  if (requestEnvelope === undefined) return undefined;
  if (valueMode !== "guest-native-json") {
    fail("request envelopes require guest-native Convex JSON values");
  }
  assertPlainObject(requestEnvelope, "requestEnvelope");
  assertExactKeys(
    requestEnvelope,
    new Set(["capabilityRequestAbiVersion", "canonicalVectorCorpus"]),
    "requestEnvelope"
  );
  const capabilityRequestAbiVersion = requirePositiveU32(
    requestEnvelope.capabilityRequestAbiVersion,
    "requestEnvelope.capabilityRequestAbiVersion"
  );
  if (
    capabilityRequestAbiVersion !== 1 &&
    capabilityRequestAbiVersion !== 2 &&
    capabilityRequestAbiVersion !== 3 &&
    capabilityRequestAbiVersion !== 4
  ) {
    fail("requestEnvelope.capabilityRequestAbiVersion is unsupported");
  }
  const canonicalVectorCorpus = normalizeCanonicalCapabilityRequestEnvelopeVectorCorpus(
    requestEnvelope.canonicalVectorCorpus,
    "requestEnvelope.canonicalVectorCorpus"
  );
  const legacyContract = capabilityRequestAbiVersion === 1 || capabilityRequestAbiVersion === 2;
  const paginationContract = capabilityRequestAbiVersion === 3;
  const versionFourContract =
    canonicalVectorCorpus.kind ===
      PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND ||
    canonicalVectorCorpus.kind === CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND;
  if (
    (legacyContract &&
      canonicalVectorCorpus.kind !==
        LEGACY_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND) ||
    (paginationContract &&
      canonicalVectorCorpus.kind !==
        PAGINATION_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND) ||
    (!legacyContract && !paginationContract && !versionFourContract)
  ) {
    fail("requestEnvelope canonical vector corpus disagrees with its ABI version");
  }
  return {
    capabilityRequestAbiVersion,
    canonicalVectorCorpus,
  };
}

export function createConvexWasmGuestNativeJsonCodecInput({ canonicalVectorCorpus }) {
  return normalizeGuestNativeJsonCodecInput("guest-native-json", {
    canonicalVectorCorpus,
  });
}

export function createConvexWasmCapabilityRequestEnvelopeInput({
  capabilityRequestAbiVersion,
  canonicalVectorCorpus,
}) {
  return normalizeCapabilityRequestEnvelopeInput("guest-native-json", {
    capabilityRequestAbiVersion,
    canonicalVectorCorpus,
  });
}

export function createConvexWasmGuestNativeJsonCodecIdentity({
  canonicalVectorCorpus,
  generatedSource,
  loweringPipelineSha256,
}) {
  assertPlainObject(generatedSource, "guest-native codec generated source");
  assertExactKeys(
    generatedSource,
    new Set(["sha256", "size"]),
    "guest-native codec generated source"
  );
  return normalizeJson(
    {
      canonicalVectorCorpus: normalizeCanonicalConvexValueVectorCorpus(
        canonicalVectorCorpus,
        "guest-native codec canonical vector corpus"
      ),
      generatedSource: {
        sha256: requireSha256(generatedSource.sha256, "guest-native codec generated source.sha256"),
        size: requirePositiveInteger(
          generatedSource.size,
          "guest-native codec generated source.size"
        ),
      },
      kind: GUEST_NATIVE_JSON_CODEC_IDENTITY_KIND,
      loweringPipelineSha256: requireSha256(
        loweringPipelineSha256,
        "guest-native codec lowering pipeline SHA-256"
      ),
      schemaVersion: 1,
    },
    "guest-native codec identity"
  );
}

export function normalizeConvexWasmGuestNativeJsonCodecIdentity(
  value,
  description = "guest-native codec identity"
) {
  assertPlainObject(value, description);
  assertExactKeys(
    value,
    new Set([
      "canonicalVectorCorpus",
      "generatedSource",
      "kind",
      "loweringPipelineSha256",
      "schemaVersion",
    ]),
    description
  );
  if (value.kind !== GUEST_NATIVE_JSON_CODEC_IDENTITY_KIND || value.schemaVersion !== 1) {
    fail(`${description} kind or schema version is unsupported`);
  }
  return createConvexWasmGuestNativeJsonCodecIdentity({
    canonicalVectorCorpus: value.canonicalVectorCorpus,
    generatedSource: value.generatedSource,
    loweringPipelineSha256: value.loweringPipelineSha256,
  });
}

export function createConvexWasmCapabilityRequestEnvelopeIdentity({
  capabilityRequestAbiVersion,
  canonicalVectorCorpus,
  generatedSource,
  loweringPipelineSha256,
}) {
  assertPlainObject(generatedSource, "request-envelope generated source");
  assertExactKeys(
    generatedSource,
    new Set(["sha256", "size"]),
    "request-envelope generated source"
  );
  const requestEnvelope = createConvexWasmCapabilityRequestEnvelopeInput({
    capabilityRequestAbiVersion,
    canonicalVectorCorpus,
  });
  return normalizeJson(
    {
      ...requestEnvelope,
      generatedSource: {
        sha256: requireSha256(generatedSource.sha256, "request-envelope generated source.sha256"),
        size: requirePositiveInteger(
          generatedSource.size,
          "request-envelope generated source.size"
        ),
      },
      kind:
        requestEnvelope.capabilityRequestAbiVersion === 4
          ? requestEnvelope.canonicalVectorCorpus.kind ===
            PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND
            ? PRE_STORAGE_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND
            : GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND
          : requestEnvelope.capabilityRequestAbiVersion === 3
            ? PAGINATION_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND
            : LEGACY_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND,
      loweringPipelineSha256: requireSha256(
        loweringPipelineSha256,
        "request-envelope lowering pipeline SHA-256"
      ),
      schemaVersion: 1,
    },
    "request-envelope identity"
  );
}

export function normalizeConvexWasmCapabilityRequestEnvelopeIdentity(
  value,
  description = "request-envelope identity"
) {
  assertPlainObject(value, description);
  assertExactKeys(
    value,
    new Set([
      "capabilityRequestAbiVersion",
      "canonicalVectorCorpus",
      "generatedSource",
      "kind",
      "loweringPipelineSha256",
      "schemaVersion",
    ]),
    description
  );
  const expectedKind =
    value.capabilityRequestAbiVersion === 4
      ? value.canonicalVectorCorpus?.kind ===
        PRE_STORAGE_CANONICAL_CAPABILITY_REQUEST_ENVELOPE_VECTOR_CORPUS_KIND
        ? PRE_STORAGE_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND
        : GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND
      : value.capabilityRequestAbiVersion === 3
        ? PAGINATION_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND
        : LEGACY_GUEST_NATIVE_REQUEST_ENVELOPE_IDENTITY_KIND;
  if (value.kind !== expectedKind || value.schemaVersion !== 1) {
    fail(`${description} kind or schema version is unsupported`);
  }
  return createConvexWasmCapabilityRequestEnvelopeIdentity({
    capabilityRequestAbiVersion: value.capabilityRequestAbiVersion,
    canonicalVectorCorpus: value.canonicalVectorCorpus,
    generatedSource: value.generatedSource,
    loweringPipelineSha256: value.loweringPipelineSha256,
  });
}
