import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";

import {
  canonicalJson,
  fail,
  fingerprintJson,
  normalizeJson,
  requirePositiveInteger,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import {
  copyAuthenticatedArtifactCacheEntry,
  publishArtifactCacheEntry,
  publishArtifactCacheEntryFromMaterial,
  readAndValidateArtifactCacheEntry,
  validateArtifactCacheEntry,
  validateArtifactCacheEntryInValidationScope,
} from "./convex-wasm-artifact-cache-entry.mjs";
import { ConvexWasmArtifactByteLimitError } from "./convex-wasm-artifact-material.mjs";
import { normalizeConvexWasmCacheLayout } from "./convex-wasm-cache-layout.mjs";
import { requirePrivateCacheDirectory } from "./convex-wasm-private-cache.mjs";

const PIPELINE_KIND = "convex-wasm-artifact-pipeline-v9";
const immutableArtifactStageFlights = new Map();
const observedArtifactCacheMissBindings = new WeakMap();

class ArtifactStageByteLimitError extends Error {
  constructor(stage, key, cause) {
    super(cause.message, { cause });
    this.name = "ArtifactStageByteLimitError";
    this.actualBytes = cause.actualBytes;
    this.maximumBytes = cause.maximumBytes;
    this.stage = stage;
    this.key = key;
  }
}

function isOperationalArtifactStageByteLimit(error, stage, maximumBytes) {
  // The completed copy can exceed the earlier source stat; classify both publication checks
  // identically so a more permissive process-flight follower can still retry.
  return (
    error instanceof ConvexWasmArtifactByteLimitError &&
    error.maximumBytes === maximumBytes &&
    (error.description === `${stage} produced` ||
      error.description === `${stage} produced artifact has` ||
      error.description === `${stage} cached artifact has`)
  );
}

function identityDifferences(previous, current, prefix = "") {
  if (canonicalJson(previous) === canonicalJson(current)) {
    return [];
  }
  if (Array.isArray(previous) || Array.isArray(current)) {
    if (!Array.isArray(previous) || !Array.isArray(current)) {
      return [prefix];
    }
    const differences = [];
    const sharedLength = Math.min(previous.length, current.length);
    for (let index = 0; index < sharedLength; index += 1) {
      differences.push(
        ...identityDifferences(previous[index], current[index], `${prefix}[${String(index)}]`)
      );
    }
    if (previous.length !== current.length) {
      differences.push(`${prefix}.length`);
    }
    return differences;
  }
  if (
    previous === null ||
    current === null ||
    typeof previous !== "object" ||
    typeof current !== "object"
  ) {
    return [prefix];
  }
  const differences = [];
  const keys = new Set([...Object.keys(previous), ...Object.keys(current)]);
  for (const key of [...keys].sort()) {
    const path = prefix.length === 0 ? key : `${prefix}.${key}`;
    if (!(key in previous) || !(key in current)) {
      differences.push(path);
      continue;
    }
    differences.push(...identityDifferences(previous[key], current[key], path));
  }
  return differences;
}

async function measureCriticalPathActivity(criticalPath, activity, stage, operation) {
  const measurement = criticalPath?.beginCriticalPathActivity(activity, stage);
  try {
    const result = await operation();
    measurement?.finish();
    return result;
  } catch (error) {
    measurement?.finish({ outcome: "failed" });
    throw error;
  }
}

async function ensureArtifactStageUnshared(
  {
    authenticatePublicationPrerequisite,
    build,
    cacheLayout,
    cacheRoot,
    criticalPath,
    extension,
    identity,
    immutableCacheValidationMemo,
    maxArtifactBytes,
    onCacheMiss,
    previousIdentity,
    readCachedArtifactContents = false,
    readPublishedArtifactContents = false,
    skipInitialCacheValidation = false,
    stage,
  },
  precomputedKey
) {
  const activity = criticalPath?.beginCriticalPathActivity("immutable-artifact-stage", stage);
  let activityResult;
  let activityCompleted = false;
  try {
    const producerImplementation = identity.producerImplementation;
    const key = precomputedKey ?? fingerprintJson({ kind: PIPELINE_KIND, stage, identity });
    const invalidationReasons =
      previousIdentity === undefined
        ? ["no-prior-export-state"]
        : identityDifferences(previousIdentity, identity).map(
            (path) => `identity-input-changed:${path}`
          );
    let cached;
    if (!skipInitialCacheValidation) {
      try {
        cached = await measureCriticalPathActivity(
          criticalPath,
          "immutable-cache-validation",
          stage,
          async () =>
            readCachedArtifactContents
              ? await readAndValidateArtifactCacheEntry(
                  cacheRoot,
                  cacheLayout,
                  stage,
                  key,
                  extension,
                  maxArtifactBytes
                )
              : immutableCacheValidationMemo === undefined
                ? await validateArtifactCacheEntry(
                    cacheRoot,
                    cacheLayout,
                    stage,
                    key,
                    extension,
                    maxArtifactBytes
                  )
                : await validateArtifactCacheEntryInValidationScope(
                    immutableCacheValidationMemo,
                    cacheRoot,
                    cacheLayout,
                    stage,
                    key,
                    extension,
                    maxArtifactBytes
                  )
        );
      } catch (error) {
        if (isOperationalArtifactStageByteLimit(error, stage, maxArtifactBytes)) {
          throw new ArtifactStageByteLimitError(stage, key, error);
        }
        throw error;
      }
    }
    if (cached !== undefined) {
      if (authenticatePublicationPrerequisite !== undefined) {
        await authenticatePublicationPrerequisite();
      }
      if (cached.artifactSize > maxArtifactBytes) {
        throw new ArtifactStageByteLimitError(
          stage,
          key,
          new ConvexWasmArtifactByteLimitError(
            `${stage} cached artifact has`,
            cached.artifactSize,
            maxArtifactBytes
          )
        );
      }
      activityResult = { cache: "hit" };
      activityCompleted = true;
      return {
        entry: cached,
        report: {
          cache: "hit",
          cacheKey: key,
          invalidationReasons,
          reason: "complete-content-addressed-entry-present",
          ...(producerImplementation === undefined ? {} : { producerImplementation }),
          stage,
          timing: null,
        },
      };
    }

    // This unshared path belongs to the process-flight producer. Invoke the hook only after exact
    // absence is authenticated so cache hits and every same-key waiter remain lazy.
    onCacheMiss?.();

    const workRoot = cacheLayout.work.scratch;
    await fs.mkdir(workRoot, { recursive: true, mode: 0o700 });
    await requirePrivateCacheDirectory(cacheRoot, workRoot);
    const workPath = await fs.mkdtemp(join(workRoot, `${stage}-`));
    await requirePrivateCacheDirectory(cacheRoot, workPath);
    try {
      const { metadata, outputPath, timing } = await measureCriticalPathActivity(
        criticalPath,
        "artifact-stage-build",
        stage,
        async () => await build(workPath)
      );
      normalizeJson(metadata, `${stage} cache metadata`);
      // A dependent immutable entry may prepare its cache validation and private scratch while its
      // authority record publishes, but it must not become visible before that record authenticates.
      if (authenticatePublicationPrerequisite !== undefined) {
        await authenticatePublicationPrerequisite();
      }
      let entry;
      try {
        entry = await measureCriticalPathActivity(
          criticalPath,
          "immutable-cache-publication",
          stage,
          async () =>
            await publishArtifactCacheEntry({
              artifactPath: outputPath,
              cacheLayout,
              cacheRoot,
              extension,
              identity,
              immutableCacheValidationMemo,
              key,
              maxArtifactBytes,
              metadata,
              readPublishedArtifactContents,
              stage,
            })
        );
      } catch (error) {
        if (isOperationalArtifactStageByteLimit(error, stage, maxArtifactBytes)) {
          throw new ArtifactStageByteLimitError(stage, key, error);
        }
        throw error;
      }
      activityResult = { cache: "miss" };
      return {
        entry,
        report: {
          cache: "miss",
          cacheKey: key,
          invalidationReasons,
          reason: "complete-content-addressed-entry-absent",
          ...(producerImplementation === undefined ? {} : { producerImplementation }),
          stage,
          timing,
        },
      };
    } finally {
      await measureCriticalPathActivity(
        criticalPath,
        "artifact-work-cleanup",
        stage,
        async () => await fs.rm(workPath, { recursive: true, force: true })
      );
      activityCompleted = true;
    }
  } finally {
    activity?.finish(activityCompleted ? activityResult : { outcome: "failed" });
  }
}

function observedArtifactCacheMissBinding({
  cacheLayout,
  cacheRoot,
  extension,
  identity,
  maxArtifactBytes,
  readCachedArtifactContents,
  readPublishedArtifactContents,
  stage,
}) {
  const resolvedCacheRoot = resolve(requireString(cacheRoot, "cacheRoot"));
  const normalizedCacheLayout = normalizeConvexWasmCacheLayout(cacheLayout);
  if (normalizedCacheLayout.cacheRoot !== resolvedCacheRoot) {
    fail("observed cache miss root does not match its cache layout");
  }
  if (readCachedArtifactContents !== undefined && typeof readCachedArtifactContents !== "boolean") {
    fail("observed cache miss read mode must be a boolean");
  }
  if (
    readPublishedArtifactContents !== undefined &&
    typeof readPublishedArtifactContents !== "boolean"
  ) {
    fail("observed cache miss published-read mode must be a boolean");
  }
  if (readPublishedArtifactContents === true && readCachedArtifactContents !== true) {
    fail("observed cache miss published-read mode requires read mode");
  }
  return canonicalJson({
    cacheLayout: normalizedCacheLayout,
    cacheRoot: resolvedCacheRoot,
    extension: requireString(extension, "observed cache miss extension"),
    identity,
    key: fingerprintJson({ identity, kind: PIPELINE_KIND, stage }),
    maxArtifactBytes: requirePositiveInteger(maxArtifactBytes, "observed cache miss byte limit"),
    readPublishedArtifactContents: readPublishedArtifactContents === true,
    readMode: readCachedArtifactContents === true ? "read" : "hash",
    stage: requireString(stage, "observed cache miss stage"),
  });
}

export async function observeArtifactCacheMiss(options) {
  const binding = observedArtifactCacheMissBinding(options);
  if (options.readCachedArtifactContents === true && options.immutableCacheValidationMemo !== undefined) {
    fail("artifact-content reads cannot use a hash-only validation memo");
  }
  const key = fingerprintJson({ identity: options.identity, kind: PIPELINE_KIND, stage: options.stage });
  const cached = options.readCachedArtifactContents === true
    ? await readAndValidateArtifactCacheEntry(
        options.cacheRoot, options.cacheLayout, options.stage, key, options.extension,
        options.maxArtifactBytes
      )
    : options.immutableCacheValidationMemo === undefined
      ? await validateArtifactCacheEntry(
          options.cacheRoot, options.cacheLayout, options.stage, key, options.extension,
          options.maxArtifactBytes
        )
      : await validateArtifactCacheEntryInValidationScope(
          options.immutableCacheValidationMemo, options.cacheRoot, options.cacheLayout,
          options.stage, key, options.extension, options.maxArtifactBytes
        );
  if (cached !== undefined) return { kind: "hit", entry: cached };
  const token = Object.freeze(Object.create(null));
  observedArtifactCacheMissBindings.set(token, binding);
  return { kind: "miss", token };
}

function consumeObservedArtifactCacheMiss(token, options) {
  const observedBinding = observedArtifactCacheMissBindings.get(token);
  if (observedBinding === undefined) {
    fail("observed cache miss token is invalid or already consumed");
  }
  // Delete before validating the caller and before consulting the process single-flight. A bad
  // binding, a replay, or an already-running producer cannot preserve this one-use capability.
  observedArtifactCacheMissBindings.delete(token);
  if (observedBinding !== observedArtifactCacheMissBinding(options)) {
    fail("observed cache miss token does not match the artifact stage");
  }
}

export function ensureArtifactStageAfterObservedMiss(options, observedMiss) {
  consumeObservedArtifactCacheMiss(observedMiss, options);
  return ensureArtifactStageInternal(options, true);
}

async function ensureArtifactStageInternal(
  options,
  skipInitialCacheValidation,
  speculative = false
) {
  if (
    options.authenticatePublicationPrerequisite !== undefined &&
    typeof options.authenticatePublicationPrerequisite !== "function"
  ) {
    fail("authenticatePublicationPrerequisite must be a function");
  }
  if (options.onCacheMiss !== undefined && typeof options.onCacheMiss !== "function") {
    fail("onCacheMiss must be a function");
  }
  if (
    options.readCachedArtifactContents !== undefined &&
    typeof options.readCachedArtifactContents !== "boolean"
  ) {
    fail("readCachedArtifactContents must be a boolean");
  }
  if (
    options.readPublishedArtifactContents !== undefined &&
    typeof options.readPublishedArtifactContents !== "boolean"
  ) {
    fail("readPublishedArtifactContents must be a boolean");
  }
  if (
    options.readPublishedArtifactContents === true &&
    options.readCachedArtifactContents !== true
  ) {
    fail("readPublishedArtifactContents requires readCachedArtifactContents");
  }
  if (
    (options.readCachedArtifactContents === true ||
      options.readPublishedArtifactContents === true) &&
    options.immutableCacheValidationMemo !== undefined
  ) {
    fail("artifact-content reads cannot use a hash-only validation memo");
  }
  const key = fingerprintJson({
    identity: options.identity,
    kind: PIPELINE_KIND,
    stage: options.stage,
  });
  // Extension is not part of the immutable key. Keep it in the process-flight identity so a
  // correctly bound observed miss cannot inherit another caller's artifact family.
  const flightKey = `${resolve(options.cacheRoot)}\0${options.stage}\0${key}\0${
    options.extension
  }\0${options.readCachedArtifactContents === true ? "read" : "hash"}\0${
    options.readPublishedArtifactContents === true ? "read-published" : "hash-published"
  }`;
  let flight = immutableArtifactStageFlights.get(flightKey);
  let producer = false;
  if (flight === undefined) {
    producer = true;
    flight = Object.freeze({
      result: ensureArtifactStageUnshared({ ...options, skipInitialCacheValidation }, key),
      speculative,
    });
    immutableArtifactStageFlights.set(flightKey, flight);
    const clearFlight = () => {
      if (immutableArtifactStageFlights.get(flightKey) === flight) {
        immutableArtifactStageFlights.delete(flightKey);
      }
    };
    void flight.result.then(clearFlight, clearFlight);
  }
  let result;
  try {
    result = await flight.result;
  } catch (error) {
    if (
      error instanceof ArtifactStageByteLimitError &&
      error.stage === options.stage &&
      error.key === key
    ) {
      if (error.actualBytes > options.maxArtifactBytes) {
        if (error.maximumBytes === options.maxArtifactBytes) throw error;
        throw new ArtifactStageByteLimitError(
          options.stage,
          key,
          new ConvexWasmArtifactByteLimitError(
            `${options.stage} process-shared artifact has`,
            error.actualBytes,
            options.maxArtifactBytes
          )
        );
      }
      // The producer's operational limit rejected factual bytes that this caller admits. Remove
      // only that settled flight so all admissible waiters coalesce on one retry.
      if (immutableArtifactStageFlights.get(flightKey) === flight) {
        immutableArtifactStageFlights.delete(flightKey);
      }
      return await ensureArtifactStageInternal(options, false, speculative);
    }
    if (!producer && !speculative && flight.speculative) {
      // A process follower must not inherit failure authority from another session's speculative
      // producer. Remove only the settled flight so authoritative followers join one ordinary retry.
      if (immutableArtifactStageFlights.get(flightKey) === flight) {
        immutableArtifactStageFlights.delete(flightKey);
      }
      return await ensureArtifactStageInternal(options, false);
    }
    throw error;
  }
  if (result.entry.artifactSize > options.maxArtifactBytes) {
    throw new ArtifactStageByteLimitError(
      options.stage,
      key,
      new ConvexWasmArtifactByteLimitError(
        `${options.stage} process-shared artifact has`,
        result.entry.artifactSize,
        options.maxArtifactBytes
      )
    );
  }
  // Read-mode callers consume their outer entry independently. Keep the authenticated Buffer
  // shared and immutable by convention while preventing one caller from deleting another's field.
  return options.readCachedArtifactContents === true
    ? { ...result, entry: copyAuthenticatedArtifactCacheEntry(result.entry) }
    : result;
}

export async function ensureArtifactStage(options) {
  return await ensureArtifactStageInternal(options, false);
}

export async function ensureArtifactControlStageFromMaterial({
  build,
  cacheLayout,
  cacheRoot,
  extension,
  identity,
  immutableCacheValidationMemo,
  materialIdentity,
  materialStage,
  maxArtifactBytes,
  previousIdentity,
  stage,
}) {
  const key = fingerprintJson({ identity, kind: PIPELINE_KIND, stage });
  const invalidationReasons =
    previousIdentity === undefined
      ? ["no-prior-export-state"]
      : identityDifferences(previousIdentity, identity).map(
          (path) => `identity-input-changed:${path}`
        );
  const cached =
    immutableCacheValidationMemo === undefined
      ? await validateArtifactCacheEntry(
          cacheRoot, cacheLayout, stage, key, extension, maxArtifactBytes
        )
      : await validateArtifactCacheEntryInValidationScope(
          immutableCacheValidationMemo,
          cacheRoot,
          cacheLayout,
          stage,
          key,
          extension,
          maxArtifactBytes
        );
  const producerImplementation = identity.producerImplementation;
  if (cached !== undefined) {
    return {
      entry: cached,
      report: {
        cache: "hit",
        cacheKey: key,
        invalidationReasons,
        reason: "complete-content-addressed-entry-present",
        ...(producerImplementation === undefined ? {} : { producerImplementation }),
        stage,
        timing: null,
      },
    };
  }
  const material = await ensureArtifactStage({
    build,
    cacheLayout,
    cacheRoot,
    extension,
    identity: materialIdentity,
    immutableCacheValidationMemo,
    maxArtifactBytes,
    stage: materialStage,
  });
  const publication = await publishArtifactCacheEntryFromMaterial({
    cacheLayout,
    cacheRoot,
    extension,
    identity,
    immutableCacheValidationMemo,
    key,
    maxArtifactBytes,
    sourceEntry: material.entry,
    stage,
  });
  return {
    entry: publication.entry,
    report: {
      cache: publication.publication === "existing" ? "hit" : material.report.cache,
      cacheKey: key,
      invalidationReasons,
      materialCacheKey: material.report.cacheKey,
      materialStage,
      reason:
        publication.publication === "existing"
          ? "complete-content-addressed-entry-present"
          : material.report.cache === "hit"
            ? "complete-material-content-addressed-entry-present"
            : "complete-material-content-addressed-entry-absent",
      ...(producerImplementation === undefined ? {} : { producerImplementation }),
      stage,
      timing: material.report.timing,
    },
  };
}

export async function ensureSpeculativeArtifactStage(options) {
  return await ensureArtifactStageInternal(options, false, true);
}
