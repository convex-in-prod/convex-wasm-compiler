import { createHash } from "node:crypto";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmRoutingEligibleStaticHermesGlobals,
  convexWasmStaticHermesGlobalInventory,
  convexWasmStaticHermesGlobalInventorySha256,
} from "./convex-wasm-static-hermes-engine-globals.mjs";

const RECONCILIATION_KIND = "convex-wasm-runtime-api-blocker-reconciliation-v2";
const PREFLIGHT_KIND = "convex-wasm-runtime-capability-compile-preflight-report-v2";
const deterministicClasses = new Set(["deterministic-ecmascript", "deterministic-web-like"]);

function normalizeJson(value) {
  if (Array.isArray(value)) return value.map(normalizeJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, normalizeJson(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(normalizeJson(value));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object.`);
  }
  return value;
}

function authenticatedPreflightIdentity(report, description) {
  requireObject(report, description);
  if (report.kind !== PREFLIGHT_KIND || report.schemaVersion !== 2) {
    throw new Error(`${description} kind or schema version is unsupported.`);
  }
  if (typeof report.reportSha256 !== "string") {
    throw new Error(`${description} has no report identity.`);
  }
  const payload = { ...report };
  delete payload.reportSha256;
  const recomputed = fingerprintJson(payload);
  if (recomputed !== report.reportSha256) {
    throw new Error(`${description} identity does not match its contents.`);
  }
  if (!Array.isArray(report.entries) || !Array.isArray(report.routes)) {
    throw new Error(`${description} populations must be arrays.`);
  }
  return {
    entries: report.entries.length,
    evidence: report.evidence,
    reportSha256: report.reportSha256,
    routes: report.routes.length,
  };
}

function diagnosticKey(diagnostic) {
  return canonicalJson({
    classification: diagnostic.classification ?? null,
    code: diagnostic.code,
    reason: diagnostic.reason,
  });
}

function collectBlockers(items, itemKey) {
  const named = new Map();
  const unclassified = new Map();
  for (const item of items) {
    const outcome = item.outcome;
    if (outcome?.kind !== "failure") continue;
    for (const diagnostic of outcome.diagnostics ?? []) {
      if (
        diagnostic.code === "named-runtime-gap" &&
        typeof diagnostic.gap?.surface === "string" &&
        typeof diagnostic.gap.code === "string" &&
        typeof diagnostic.gap.layer === "string"
      ) {
        let facility = named.get(diagnostic.gap.surface);
        if (facility === undefined) {
          facility = { codes: new Set(), itemKeys: new Set(), layers: new Set() };
          named.set(diagnostic.gap.surface, facility);
        }
        facility.codes.add(diagnostic.gap.code);
        facility.layers.add(diagnostic.gap.layer);
        facility.itemKeys.add(itemKey(item));
      } else {
        const key = diagnosticKey({ ...diagnostic, classification: outcome.classification });
        let blocker = unclassified.get(key);
        if (blocker === undefined) {
          blocker = {
            classification: outcome.classification ?? null,
            code: diagnostic.code ?? null,
            itemKeys: new Set(),
            reason: diagnostic.reason ?? null,
          };
          unclassified.set(key, blocker);
        }
        blocker.itemKeys.add(itemKey(item));
      }
    }
  }
  return { named, unclassified };
}

function itemPopulation(report) {
  return {
    entries: collectBlockers(report.entries, (entry) => entry.entryPath),
    routes: collectBlockers(
      report.routes,
      (route) => `${route.modulePath}\0${route.exportName}\0${route.entryPath}`
    ),
  };
}

function genericBatchCandidate(name) {
  const semantic = convexWasmStaticHermesGlobalInventory.semantics[name];
  if (semantic === undefined) return false;
  const targetPresent =
    convexWasmStaticHermesGlobalInventory.targetRuntimeProbe.globals.includes(name);
  const typed =
    convexWasmStaticHermesGlobalInventory.staticHermesTypedDeclarations.globals.includes(name);
  return (
    targetPresent &&
    typed &&
    semantic.provider === "engine-typed" &&
    deterministicClasses.has(semantic.class) &&
    semantic.read.state === "gap"
  );
}

function facilityCategory(name, layers) {
  if (layers.has("adapter") || layers.has("runtime")) return "adapter/host-mediated";
  const semantic = convexWasmStaticHermesGlobalInventory.semantics[name];
  if (semantic === undefined) return "unclassified";
  const targetPresent =
    convexWasmStaticHermesGlobalInventory.targetRuntimeProbe.globals.includes(name);
  const typed =
    convexWasmStaticHermesGlobalInventory.staticHermesTypedDeclarations.globals.includes(name);
  if (!targetPresent && !typed && semantic.provider === "unavailable") return "genuinely absent";
  if (
    semantic.provider === "shared-untyped-runtime-support" &&
    convexWasmRoutingEligibleStaticHermesGlobals.includes(name)
  ) {
    return "shared-runtime-support + eligible";
  }
  if (targetPresent && !typed && semantic.provider.startsWith("engine-runtime-untyped")) {
    return "runtime-present + untyped but bridgeable";
  }
  if (
    targetPresent &&
    typed &&
    (genericBatchCandidate(name) || convexWasmRoutingEligibleStaticHermesGlobals.includes(name))
  ) {
    return "runtime-present + typed + eligible";
  }
  return "unclassified";
}

function blockerFacts(population, name) {
  const entries = population.entries.named.get(name);
  const routes = population.routes.named.get(name);
  return {
    codes: [...new Set([...(entries?.codes ?? []), ...(routes?.codes ?? [])])].sort(),
    entries: entries?.itemKeys.size ?? 0,
    layers: [...new Set([...(entries?.layers ?? []), ...(routes?.layers ?? [])])].sort(),
    routes: routes?.itemKeys.size ?? 0,
  };
}

function unclassifiedFacts(population) {
  const keys = new Set([
    ...population.entries.unclassified.keys(),
    ...population.routes.unclassified.keys(),
  ]);
  return [...keys].sort().map((key) => {
    const entries = population.entries.unclassified.get(key);
    const routes = population.routes.unclassified.get(key);
    const exemplar = entries ?? routes;
    return {
      classification: exemplar.classification,
      code: exemplar.code,
      entries: entries?.itemKeys.size ?? 0,
      reason: exemplar.reason,
      routes: routes?.itemKeys.size ?? 0,
    };
  });
}

function inventoryFacts(name, selected) {
  const semantic = convexWasmStaticHermesGlobalInventory.semantics[name];
  const applicationAccess = convexWasmStaticHermesGlobalInventory.accessPolicy;
  if (semantic === undefined) {
    return {
      access: {
        ...applicationAccess,
        read: selected ? "lexical-direct-call" : "host-or-adapter-specific",
      },
      provider: null,
      runtimePresent: null,
      semanticClass: null,
      typedDeclarationPresent: null,
    };
  }
  return {
    access: {
      ...applicationAccess,
      read:
        deterministicClasses.has(semantic.class) &&
        convexWasmRoutingEligibleStaticHermesGlobals.includes(name)
          ? "ordinary-lexical-value"
          : selected
            ? "candidate-lexical-direct-call"
            : semantic.read,
    },
    provider: semantic.provider,
    runtimePresent: convexWasmStaticHermesGlobalInventory.targetRuntimeProbe.globals.includes(name),
    semanticClass: semantic.class,
    typedDeclarationPresent:
      convexWasmStaticHermesGlobalInventory.staticHermesTypedDeclarations.globals.includes(name),
  };
}

function populationCeiling(report, surfaces) {
  const entries = new Set();
  const routes = new Set();
  for (const entry of report.entries) {
    if (
      entry.outcome?.diagnostics?.some(
        (diagnostic) =>
          diagnostic.code === "named-runtime-gap" && surfaces.has(diagnostic.gap?.surface)
      )
    ) {
      entries.add(entry.entryPath);
    }
  }
  for (const route of report.routes) {
    if (
      route.outcome?.diagnostics?.some(
        (diagnostic) =>
          diagnostic.code === "named-runtime-gap" && surfaces.has(diagnostic.gap?.surface)
      )
    ) {
      routes.add(`${route.modulePath}\0${route.exportName}\0${route.entryPath}`);
    }
  }
  return { entries: entries.size, routes: routes.size };
}

function reportCeilings(report, selected, historicallyAdvanced) {
  const combined = new Set([...selected, ...historicallyAdvanced]);
  return {
    batchSelected: populationCeiling(report, selected),
    combinedWithCurrentPolicy: populationCeiling(report, combined),
    currentPolicyAdvanced: populationCeiling(report, historicallyAdvanced),
    interpretation: "first-blocker ceiling only; not a routing forecast",
    routingReady: false,
  };
}

export function buildConvexWasmRuntimeApiBlockerReconciliation({
  fullReport,
  representativeReport,
}) {
  const fullIdentity = authenticatedPreflightIdentity(fullReport, "full preflight report");
  const representativeIdentity = authenticatedPreflightIdentity(
    representativeReport,
    "representative preflight report"
  );
  const fullPopulation = itemPopulation(fullReport);
  const representativePopulation = itemPopulation(representativeReport);
  const selected = new Set(
    Object.keys(convexWasmStaticHermesGlobalInventory.semantics).filter((name) =>
      genericBatchCandidate(name)
    )
  );
  const historicallyAdvanced = new Set(
    [...fullPopulation.entries.named.keys()].filter((name) =>
      convexWasmRoutingEligibleStaticHermesGlobals.includes(name)
    )
  );
  const facilityNames = [
    ...new Set([
      ...fullPopulation.entries.named.keys(),
      ...fullPopulation.routes.named.keys(),
      ...representativePopulation.entries.named.keys(),
      ...representativePopulation.routes.named.keys(),
    ]),
  ].sort();
  const facilities = facilityNames.map((name) => {
    const full = blockerFacts(fullPopulation, name);
    const representative = blockerFacts(representativePopulation, name);
    const layers = new Set([...full.layers, ...representative.layers]);
    return {
      category: facilityCategory(name, layers),
      genericBatch: {
        admitted: convexWasmRoutingEligibleStaticHermesGlobals.includes(name),
        selected: selected.has(name),
        state: selected.has(name) ? "deferred-intrinsic-freeze" : "not-selected",
      },
      inventory: inventoryFacts(name, selected.has(name)),
      name,
      observed: { full, representative },
    };
  });
  const nextBlockers = facilities
    .filter(({ name }) => !selected.has(name) && !historicallyAdvanced.has(name))
    .map(({ category, name, observed }) => ({ category, name, observed }));
  const payload = {
    batch: {
      accessForm: "lexical-direct-call",
      candidates: [...selected].sort(),
      admissionState: "deferred-intrinsic-freeze",
      rule: {
        deterministicSemanticClass: true,
        engineTypedProvider: true,
        exactTargetRuntimePresent: true,
        staticHermesTypedDeclarationPresent: true,
      },
    },
    ceilings: {
      full: reportCeilings(fullReport, selected, historicallyAdvanced),
      representative: reportCeilings(representativeReport, selected, historicallyAdvanced),
    },
    facilities,
    inputs: {
      fullReport: fullIdentity,
      representativeReport: representativeIdentity,
      staticHermesGlobalInventory: {
        buildRevision: convexWasmStaticHermesGlobalInventory.sourceIdentity.buildRevision,
        observedCheckoutRevision:
          convexWasmStaticHermesGlobalInventory.sourceIdentity.observedCheckoutRevision,
        sha256: convexWasmStaticHermesGlobalInventorySha256,
        sourceRevision: convexWasmStaticHermesGlobalInventory.sourceIdentity.sourceRevision,
      },
    },
    kind: RECONCILIATION_KIND,
    nextBlockers,
    routingReady: false,
    schemaVersion: 2,
    unclassified: {
      facilities: facilities
        .filter(({ category }) => category === "unclassified")
        .map(({ name }) => name),
      fullDiagnostics: unclassifiedFacts(fullPopulation),
      representativeDiagnostics: unclassifiedFacts(representativePopulation),
    },
  };
  return Object.freeze({
    ...payload,
    reconciliationSha256: sha256(canonicalJson(payload)),
  });
}

export function assertConvexWasmRuntimeApiBlockerReconciliationIdentity(report) {
  requireObject(report, "runtime API blocker reconciliation");
  const payload = { ...report };
  delete payload.reconciliationSha256;
  const recomputed = sha256(canonicalJson(payload));
  if (recomputed !== report.reconciliationSha256) {
    throw new Error("runtime API blocker reconciliation identity does not match its contents.");
  }
}
