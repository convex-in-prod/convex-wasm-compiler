import { createHash } from "node:crypto";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmSourceEnvelopeKind,
  retainedConvexWasmSourceEnvelopeEntryNamespaces,
  validateConvexWasmSourceEnvelope,
} from "./convex-wasm-source-envelope.mjs";

export const convexWasmOfficialOutputCohortScheduleKind =
  "convex-wasm-official-output-cohort-schedule-v1";
export const convexWasmOfficialOutputCohortPartitionPolicy = Object.freeze({
  kind: "convex-wasm-official-output-lexical-entry-partition-v1",
  maximumEntries: 8,
  order: "entry-path-utf16-ascending-contiguous",
});

const COHORT_ID_DOMAIN = "convex-wasm-official-output-cohort-v1";
const ENTRY_ID_DOMAIN = "convex-wasm-official-output-cohort-entry-v1";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const authenticatedCohortSchedules = new WeakSet();
const retainedScheduleEntries = new WeakMap();
const retainedCohortsByFirstEntry = new WeakMap();
const retainedCohortRecords = new WeakSet();

function fail(message) {
  throw new Error(`Convex Wasm official-output cohort schedule: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function requireString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requireExactKeys(value, keys, description) {
  const object = requireObject(value, description);
  const actual = Object.keys(object).sort(compareStrings);
  const expected = [...keys].sort(compareStrings);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${description} has unsupported fields`);
  }
  return object;
}

function routeKey(route) {
  return `${route.entryPath}\0${route.exportName}`;
}

function normalizeSourceEnvelopeFileIdentity(options) {
  // Prototype values cannot establish physical authority for a schedule.
  const sourceEnvelopeFileSha256 = Object.hasOwn(options, "sourceEnvelopeFileSha256")
    ? options.sourceEnvelopeFileSha256
    : undefined;
  const sourceEnvelopeFileSize = Object.hasOwn(options, "sourceEnvelopeFileSize")
    ? options.sourceEnvelopeFileSize
    : undefined;
  if ((sourceEnvelopeFileSha256 === undefined) !== (sourceEnvelopeFileSize === undefined)) {
    fail("source-envelope file SHA-256 and size must be provided together");
  }
  if (sourceEnvelopeFileSha256 === undefined) return undefined;
  return {
    sha256: requireSha256(sourceEnvelopeFileSha256, "source-envelope file SHA-256"),
    size: requirePositiveInteger(sourceEnvelopeFileSize, "source-envelope file size"),
  };
}

function expectedEntryIdentity(entry) {
  return fingerprintJson({
    dependencyGraphSha256: entry.dependencyGraphSha256,
    domain: ENTRY_ID_DOMAIN,
    entryPath: entry.entryPath,
    modulePath: entry.modulePath,
    routes: entry.routes,
    runtimeModulePath: entry.runtimeModulePath,
  });
}

function expectedCohortId(entries) {
  return fingerprintJson({
    domain: COHORT_ID_DOMAIN,
    entryIds: entries.map(({ entryId }) => entryId),
    partitionPolicy: convexWasmOfficialOutputCohortPartitionPolicy,
  });
}

function selectedEntriesFromSourceEnvelope(sourceEnvelope) {
  const selectedRoutesByEntryPath = new Map();
  for (const route of sourceEnvelope.selectedRoutes) {
    const routes = selectedRoutesByEntryPath.get(route.entryPath) ?? [];
    routes.push(route);
    selectedRoutesByEntryPath.set(route.entryPath, routes);
  }
  const routesByEntryPath = new Map();
  for (const route of sourceEnvelope.routes) {
    const routes = routesByEntryPath.get(route.entryPath) ?? [];
    routes.push(route);
    routesByEntryPath.set(route.entryPath, routes);
  }
  return sourceEnvelope.entryPaths.map((entryPath) => {
    const selectedRoutes = selectedRoutesByEntryPath.get(entryPath);
    const allRoutes = routesByEntryPath.get(entryPath);
    if (selectedRoutes === undefined || allRoutes === undefined) {
      fail(`source envelope omits selected entry ${entryPath}`);
    }
    const selectedByKey = new Map(selectedRoutes.map((route) => [routeKey(route), route]));
    if (
      selectedByKey.size !== allRoutes.length ||
      allRoutes.some((route) => !selectedByKey.has(routeKey(route)))
    ) {
      fail(
        `selected entry ${entryPath} does not retain its complete authenticated query/mutation namespace`
      );
    }
    const first = selectedRoutes[0];
    if (
      selectedRoutes.some(
        (route) =>
          route.modulePath !== first.modulePath ||
          route.runtimeModulePath !== first.runtimeModulePath ||
          route.dependencyGraphSha256 !== first.dependencyGraphSha256
      )
    ) {
      fail(`selected entry ${entryPath} has inconsistent authenticated route authority`);
    }
    const routes = selectedRoutes
      .map(({ exportName, udfKind, visibility }) => ({ exportName, udfKind, visibility }))
      .sort((left, right) => compareStrings(left.exportName, right.exportName));
    const entry = {
      dependencyGraphSha256: first.dependencyGraphSha256,
      entryPath,
      modulePath: first.modulePath,
      routes,
      runtimeModulePath: first.runtimeModulePath,
    };
    return { ...entry, entryId: expectedEntryIdentity(entry) };
  });
}

function createCohorts(entries) {
  const cohorts = [];
  for (
    let offset = 0;
    offset < entries.length;
    offset += convexWasmOfficialOutputCohortPartitionPolicy.maximumEntries
  ) {
    const members = entries.slice(
      offset,
      offset + convexWasmOfficialOutputCohortPartitionPolicy.maximumEntries
    );
    cohorts.push({
      cohortId: expectedCohortId(members),
      entries: members,
      entryCount: members.length,
    });
  }
  return cohorts;
}

function retainedCohorts(namespaces) {
  const entries = namespaces.map((namespace) => {
    let entry = retainedScheduleEntries.get(namespace);
    if (entry === undefined) {
      entry = Object.freeze({ ...namespace, entryId: expectedEntryIdentity(namespace) });
      retainedScheduleEntries.set(namespace, entry);
    }
    return entry;
  });
  const cohorts = [];
  for (
    let offset = 0;
    offset < entries.length;
    offset += convexWasmOfficialOutputCohortPartitionPolicy.maximumEntries
  ) {
    const count = Math.min(
      convexWasmOfficialOutputCohortPartitionPolicy.maximumEntries,
      entries.length - offset
    );
    let cohort = retainedCohortsByFirstEntry.get(entries[offset]);
    if (
      cohort === undefined ||
      cohort.entries.length !== count ||
      cohort.entries.some((entry, index) => entry !== entries[offset + index])
    ) {
      const members = Object.freeze(entries.slice(offset, offset + count));
      cohort = Object.freeze({
        cohortId: expectedCohortId(members),
        entries: members,
        entryCount: count,
      });
      retainedCohortsByFirstEntry.set(entries[offset], cohort);
      retainedCohortRecords.add(cohort);
    }
    cohorts.push(cohort);
  }
  return cohorts;
}

export function isRetainedConvexWasmOfficialOutputCohort(cohort) {
  // A later partition with the same first entry must not revoke an older live schedule's
  // immutable records. The lookup above selects reuse candidates; it does not own their lifetime.
  return retainedCohortRecords.has(cohort);
}

function sourceEnvelopeProvenance(sourceEnvelope, sourceEnvelopeFileIdentity) {
  return {
    sourceEnvelope: {
      ...(sourceEnvelopeFileIdentity === undefined ? {} : { file: sourceEnvelopeFileIdentity }),
      kind: convexWasmSourceEnvelopeKind,
      sha256: sourceEnvelope.sourceEnvelopeSha256,
    },
    toolchain: sourceEnvelope.graph.toolchain,
  };
}

function scheduleIdentity({ cohorts, provenance }) {
  return {
    cohorts,
    kind: convexWasmOfficialOutputCohortScheduleKind,
    partitionPolicy: convexWasmOfficialOutputCohortPartitionPolicy,
    provenance,
  };
}

function retainedScheduleIdentitySha256(identity) {
  // Keep the persisted canonical schema unchanged, but encode each immutable cohort only once.
  // New generations hash the retained encodings with fresh complete generation provenance.
  const hash = createHash("sha256").update('{"cohorts":[');
  identity.cohorts.forEach((cohort, index) => {
    if (index > 0) hash.update(",");
    hash.update(canonicalJson(cohort));
  });
  return hash
    .update(`],"kind":${canonicalJson(identity.kind)},"partitionPolicy":`)
    .update(canonicalJson(identity.partitionPolicy))
    .update(',"provenance":')
    .update(canonicalJson(identity.provenance))
    .update("}")
    .digest("hex");
}

function freezeJsonTree(value) {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeJsonTree(child);
    Object.freeze(value);
  }
  return value;
}

function validateAuthenticatedScheduleSourceAuthority({
  schedule,
  sourceEnvelope,
  sourceEnvelopeFileIdentity,
}) {
  const provenance = schedule.identity.provenance;
  const provenanceSourceEnvelope = provenance.sourceEnvelope;
  if (
    provenanceSourceEnvelope.kind !== convexWasmSourceEnvelopeKind ||
    provenanceSourceEnvelope.sha256 !== sourceEnvelope.sourceEnvelopeSha256
  ) {
    fail("source envelope SHA-256 does not match the authenticated schedule provenance");
  }
  // Optional physical authority exists only when the serialized schedule owns the field.
  const provenanceFile = Object.hasOwn(provenanceSourceEnvelope, "file")
    ? provenanceSourceEnvelope.file
    : undefined;
  if ((provenanceFile === undefined) !== (sourceEnvelopeFileIdentity === undefined)) {
    fail("source-envelope file identity does not match the authenticated schedule provenance");
  }
  if (
    provenanceFile !== undefined &&
    (provenanceFile.sha256 !== sourceEnvelopeFileIdentity.sha256 ||
      provenanceFile.size !== sourceEnvelopeFileIdentity.size)
  ) {
    fail("source-envelope file identity does not match the authenticated schedule provenance");
  }
  if (canonicalJson(provenance.toolchain) !== canonicalJson(sourceEnvelope.graph.toolchain)) {
    fail("source-envelope toolchain does not match the authenticated schedule provenance");
  }
}

export function createConvexWasmOfficialOutputCohortSchedule(options) {
  const rawSourceEnvelope = options.sourceEnvelope;
  const sourceEnvelope = validateConvexWasmSourceEnvelope(rawSourceEnvelope);
  const sourceEnvelopeFileIdentity = normalizeSourceEnvelopeFileIdentity(options);
  const namespaces = retainedConvexWasmSourceEnvelopeEntryNamespaces(sourceEnvelope);
  const cohorts =
    namespaces === undefined
      ? createCohorts(selectedEntriesFromSourceEnvelope(sourceEnvelope))
      : retainedCohorts(namespaces);
  if (cohorts.length === 0) {
    fail("source envelope selects no complete entry namespaces");
  }
  const provenance = sourceEnvelopeProvenance(sourceEnvelope, sourceEnvelopeFileIdentity);
  if (namespaces !== undefined) freezeJsonTree(provenance);
  const identity = scheduleIdentity({ cohorts, provenance });
  const schedule = Object.freeze({
    cohorts: Object.freeze(cohorts),
    identity: Object.freeze({
      ...identity,
      sha256:
        namespaces === undefined
          ? fingerprintJson(identity)
          : retainedScheduleIdentitySha256(identity),
    }),
    kind: convexWasmOfficialOutputCohortScheduleKind,
  });
  if (namespaces !== undefined) {
    // The graph-owned namespaces already prove full selection, and this producer owns partitioning
    // and generation provenance. Do not expand and authenticate those same records a second time.
    authenticatedCohortSchedules.add(schedule);
  }
  return schedule;
}

function validateProvenance(provenance) {
  const value = requireExactKeys(
    provenance,
    new Set(["sourceEnvelope", "toolchain"]),
    "schedule provenance"
  );
  const sourceEnvelope = requireObject(value.sourceEnvelope, "schedule provenance source envelope");
  const keys = Object.keys(sourceEnvelope).sort(compareStrings);
  const hasFile = Object.hasOwn(sourceEnvelope, "file");
  const expectedKeys = hasFile ? ["file", "kind", "sha256"] : ["kind", "sha256"];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail("schedule provenance source envelope has unsupported fields");
  }
  if (sourceEnvelope.kind !== convexWasmSourceEnvelopeKind) {
    fail("schedule provenance source envelope kind is invalid");
  }
  requireSha256(sourceEnvelope.sha256, "schedule provenance source envelope SHA-256");
  if (hasFile) {
    const file = requireExactKeys(
      sourceEnvelope.file,
      new Set(["sha256", "size"]),
      "schedule provenance source-envelope file"
    );
    requireSha256(file.sha256, "schedule provenance source-envelope file SHA-256");
    requirePositiveInteger(file.size, "schedule provenance source-envelope file size");
  }
  requireObject(value.toolchain, "schedule provenance toolchain");
  return value;
}

function validateEntry(entry, cohortIndex, entryIndex) {
  const description = `cohort ${cohortIndex} entry ${entryIndex}`;
  const value = requireExactKeys(
    entry,
    new Set([
      "dependencyGraphSha256",
      "entryId",
      "entryPath",
      "modulePath",
      "routes",
      "runtimeModulePath",
    ]),
    description
  );
  const normalized = {
    dependencyGraphSha256: requireSha256(
      value.dependencyGraphSha256,
      `${description} dependency graph SHA-256`
    ),
    entryPath: requireString(value.entryPath, `${description} entry path`),
    modulePath: requireString(value.modulePath, `${description} module path`),
    routes: value.routes,
    runtimeModulePath: requireString(value.runtimeModulePath, `${description} runtime module path`),
  };
  if (!Array.isArray(normalized.routes) || normalized.routes.length === 0) {
    fail(`${description} routes must be a non-empty array`);
  }
  normalized.routes = normalized.routes.map((route, routeIndex) => {
    const routeDescription = `${description} route ${routeIndex}`;
    const routeValue = requireExactKeys(
      route,
      new Set(["exportName", "udfKind", "visibility"]),
      routeDescription
    );
    const normalizedRoute = {
      exportName: requireString(routeValue.exportName, `${routeDescription} export name`),
      udfKind: routeValue.udfKind,
      visibility: routeValue.visibility,
    };
    if (
      (normalizedRoute.udfKind !== "query" && normalizedRoute.udfKind !== "mutation") ||
      (normalizedRoute.visibility !== "internal" && normalizedRoute.visibility !== "public")
    ) {
      fail(`${routeDescription} has unsupported route authority`);
    }
    if (
      routeIndex > 0 &&
      compareStrings(normalized.routes[routeIndex - 1].exportName, normalizedRoute.exportName) >= 0
    ) {
      fail(`${description} routes are not sorted and unique`);
    }
    return normalizedRoute;
  });
  if (value.entryId !== expectedEntryIdentity(normalized)) {
    fail(`${description} identity does not match its complete namespace`);
  }
  return { ...normalized, entryId: value.entryId };
}

export function authenticateConvexWasmOfficialOutputCohortSchedule(options) {
  const rawSchedule = options.schedule;
  const rawSourceEnvelope = options.sourceEnvelope;
  if (authenticatedCohortSchedules.has(rawSchedule)) {
    const sourceEnvelope = validateConvexWasmSourceEnvelope(rawSourceEnvelope);
    const sourceEnvelopeFileIdentity = normalizeSourceEnvelopeFileIdentity(options);
    validateAuthenticatedScheduleSourceAuthority({
      schedule: rawSchedule,
      sourceEnvelope,
      sourceEnvelopeFileIdentity,
    });
    return rawSchedule;
  }
  const schedule = requireExactKeys(
    rawSchedule,
    new Set(["cohorts", "identity", "kind"]),
    "cohort schedule"
  );
  if (schedule.kind !== convexWasmOfficialOutputCohortScheduleKind) {
    fail("cohort schedule kind is invalid");
  }
  if (!Array.isArray(schedule.cohorts) || schedule.cohorts.length === 0) {
    fail("cohort schedule must contain at least one cohort");
  }
  schedule.cohorts.forEach((cohort, cohortIndex) => {
    const value = requireExactKeys(
      cohort,
      new Set(["cohortId", "entries", "entryCount"]),
      `cohort ${cohortIndex}`
    );
    if (!Array.isArray(value.entries) || value.entries.length === 0) {
      fail(`cohort ${cohortIndex} entries must be a non-empty array`);
    }
    if (
      value.entries.length > convexWasmOfficialOutputCohortPartitionPolicy.maximumEntries ||
      value.entryCount !== value.entries.length
    ) {
      fail(`cohort ${cohortIndex} violates the maximum entry count`);
    }
    const entries = value.entries.map((entry, entryIndex) =>
      validateEntry(entry, cohortIndex, entryIndex)
    );
    if (value.cohortId !== expectedCohortId(entries)) {
      fail(`cohort ${cohortIndex} identity does not match its members`);
    }
  });
  const provenance = validateProvenance(schedule.identity?.provenance);
  const identity = requireExactKeys(
    schedule.identity,
    new Set(["cohorts", "kind", "partitionPolicy", "provenance", "sha256"]),
    "cohort schedule identity"
  );
  const { sha256, ...identityPayload } = identity;
  if (
    identity.kind !== convexWasmOfficialOutputCohortScheduleKind ||
    canonicalJson(identity.partitionPolicy) !==
      canonicalJson(convexWasmOfficialOutputCohortPartitionPolicy) ||
    canonicalJson(identity.cohorts) !== canonicalJson(schedule.cohorts) ||
    canonicalJson(identity.provenance) !== canonicalJson(provenance) ||
    sha256 !== fingerprintJson(identityPayload)
  ) {
    fail("cohort schedule identity is invalid");
  }
  const sourceEnvelope = validateConvexWasmSourceEnvelope(rawSourceEnvelope);
  const sourceEnvelopeFileIdentity = normalizeSourceEnvelopeFileIdentity(options);
  const expected = createConvexWasmOfficialOutputCohortSchedule({
    sourceEnvelope,
    ...(sourceEnvelopeFileIdentity === undefined
      ? {}
      : {
          sourceEnvelopeFileSha256: sourceEnvelopeFileIdentity.sha256,
          sourceEnvelopeFileSize: sourceEnvelopeFileIdentity.size,
        }),
  });
  if (canonicalJson(schedule) !== canonicalJson(expected)) {
    fail("cohort schedule does not match the authenticated source envelope and toolchain");
  }
  const authenticated = freezeJsonTree(expected);
  authenticatedCohortSchedules.add(authenticated);
  return authenticated;
}

export async function scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule({
  build,
  concurrency,
  schedule: authenticated,
}) {
  if (typeof build !== "function") {
    fail("cohort build operation must be a function");
  }
  requirePositiveInteger(concurrency, "cohort build concurrency");
  if (!authenticatedCohortSchedules.has(authenticated)) {
    fail("cohort build requires a schedule authenticated by this module");
  }
  const results = new Array(authenticated.cohorts.length);
  let nextIndex = 0;
  let failed = false;
  let firstError;
  const workers = Array.from(
    { length: Math.min(concurrency, authenticated.cohorts.length) },
    async () => {
      while (!failed) {
        const index = nextIndex;
        nextIndex += 1;
        if (index >= authenticated.cohorts.length) return;
        try {
          results[index] = await build({
            cohort: authenticated.cohorts[index],
            cohortIndex: index,
            scheduleIdentity: authenticated.identity.sha256,
          });
        } catch (error) {
          if (!failed) {
            failed = true;
            firstError = error;
          }
          return;
        }
      }
    }
  );
  await Promise.all(workers);
  if (failed) throw firstError;
  return results;
}

export async function scheduleConvexWasmOfficialOutputCohortBuilds(options) {
  const authenticated = authenticateConvexWasmOfficialOutputCohortSchedule(options);
  return await scheduleConvexWasmOfficialOutputCohortBuildsFromAuthenticatedSchedule({
    build: options.build,
    concurrency: options.concurrency,
    schedule: authenticated,
  });
}
