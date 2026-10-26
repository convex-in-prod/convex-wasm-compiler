import { authenticateConvexWasmModuleGraphCompilerDescriptor as authenticateModuleGraphCompilerDescriptor } from "./convex-wasm-module-graph-compiler-descriptor.mjs";
import { normalizeConvexWasmCapabilityChunkApplicationDescriptor } from "./convex-wasm-capability-application-descriptor.mjs";
import { parseConvexWasmOfficialOutputExecutableDependencySpecifier } from "./convex-wasm-official-output-chunk-contract.mjs";
import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  compareStrings,
  fail,
  requireEnum,
  requireManifestString,
} from "./convex-wasm-artifact-contract.mjs";

const MAX_MANIFEST_IDENTIFIER_BYTES = 256;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
export const convexWasmCapabilityLegacyInvocationAbi =
  "convex-wasm-legacy-custom-context-handler-v1";
export const convexWasmCapabilityOfficialWrapperInvocationAbi =
  "convex-sdk-registration-wrapper-tagged-json-v1";
const CAPABILITY_INVOCATION_ABIS = new Set([
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
]);
export const convexWasmCapabilityApplicationEntryCountSymbol =
  "convex_wasm_application_entry_count";
export const convexWasmCapabilityApplicationFactoryBySlotSymbol =
  "convex_wasm_application_factory_by_slot";
export const convexWasmCapabilityApplicationUnitCountSymbol = "convex_wasm_application_unit_count";
export const convexWasmCapabilityApplicationFactoryByUnitSlotSymbol =
  "convex_wasm_application_factory_by_unit_slot";
export const convexWasmModuleGraphSelectorRegistrationSymbol =
  "convex_wasm_register_application_selector_surface";
const CAPABILITY_APPLICATION_ENTRY_COUNT_SYMBOL = convexWasmCapabilityApplicationEntryCountSymbol;
const CAPABILITY_APPLICATION_FACTORY_BY_SLOT_SYMBOL =
  convexWasmCapabilityApplicationFactoryBySlotSymbol;
const CAPABILITY_APPLICATION_UNIT_COUNT_SYMBOL = convexWasmCapabilityApplicationUnitCountSymbol;
const CAPABILITY_APPLICATION_FACTORY_BY_UNIT_SLOT_SYMBOL =
  convexWasmCapabilityApplicationFactoryByUnitSlotSymbol;
const MODULE_GRAPH_SELECTOR_REGISTRATION_SYMBOL = convexWasmModuleGraphSelectorRegistrationSymbol;

export function renderConvexWasmCohortSelector(members) {
  const declarations = members
    .map(({ entrySymbol }) => `extern SHUnit *${entrySymbol}(void);`)
    .join("\n");
  const cases = members
    .map(
      ({ entrySelectorId, entrySymbol }) =>
        `    case UINT64_C(0x${entrySelectorId}): convex_wasm_selected_factory = ${entrySymbol}; return 0;`
    )
    .join("\n");
  return `#include <stdint.h>
typedef struct SHUnit SHUnit;
${declarations}
static SHUnit *(*convex_wasm_selected_factory)(void);
int32_t convex_wasm_select_entry(uint64_t entry) {
  switch (entry) {
${cases}
    default: convex_wasm_selected_factory = 0; return -1;
  }
}
SHUnit *convex_wasm_selected_exported_unit(void) {
  return convex_wasm_selected_factory == 0
    ? (SHUnit *)0
    : convex_wasm_selected_factory();
}
`;
}

function capabilityInvocationAbiEnum(invocationAbi, description) {
  const normalized = requireEnum(invocationAbi, CAPABILITY_INVOCATION_ABIS, description);
  return normalized === convexWasmCapabilityOfficialWrapperInvocationAbi
    ? "CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER"
    : "CONVEX_WASM_INVOCATION_ABI_LEGACY_HANDLER";
}

export function renderConvexWasmCapabilityCohortSelector(members, orderedEntrySymbols) {
  if (!Array.isArray(members) || members.length === 0) {
    fail("capability cohort selector must contain at least one route");
  }
  const selectors = new Set();
  const entrySymbols = new Set();
  const normalizedMembers = members.map((member, index) => {
    assertPlainObject(member, `capability cohort selector member ${index}`);
    assertExactKeys(
      member,
      new Set([
        "entrySelectorId",
        "entrySymbol",
        "handlerExportName",
        "handlerUdfKind",
        "invocationAbi",
      ]),
      `capability cohort selector member ${index}`
    );
    if (
      typeof member.entrySelectorId !== "string" ||
      !/^[0-9a-f]{16}$/u.test(member.entrySelectorId)
    ) {
      fail(`capability cohort selector member ${index} has an invalid selector ID`);
    }
    if (selectors.has(member.entrySelectorId)) {
      fail("capability cohort selector contains duplicate selector IDs");
    }
    selectors.add(member.entrySelectorId);
    const entrySymbol = requireManifestString(
      member.entrySymbol,
      `capability cohort selector member ${index} entry symbol`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (!IDENTIFIER_PATTERN.test(entrySymbol)) {
      fail(`capability cohort selector member ${index} entry symbol must be a C identifier`);
    }
    entrySymbols.add(entrySymbol);
    const handlerExportName = requireManifestString(
      member.handlerExportName,
      `capability cohort selector member ${index} export name`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (!IDENTIFIER_PATTERN.test(handlerExportName)) {
      fail(`capability cohort selector member ${index} export name must be an identifier`);
    }
    const handlerUdfKind = requireEnum(
      member.handlerUdfKind,
      new Set(["mutation", "query"]),
      `capability cohort selector member ${index} UDF kind`
    );
    const invocationAbi = requireEnum(
      member.invocationAbi,
      CAPABILITY_INVOCATION_ABIS,
      `capability cohort selector member ${index} invocation ABI`
    );
    return {
      entrySelectorId: member.entrySelectorId,
      entrySymbol,
      handlerExportName,
      handlerUdfKind,
      invocationAbi,
    };
  });
  const normalizedEntrySymbols =
    orderedEntrySymbols === undefined
      ? [...entrySymbols].sort(compareStrings)
      : orderedEntrySymbols.map((entrySymbol, index) => {
          const normalized = requireManifestString(
            entrySymbol,
            `capability cohort entry ${index} symbol`,
            MAX_MANIFEST_IDENTIFIER_BYTES,
            false
          );
          if (!IDENTIFIER_PATTERN.test(normalized) || !entrySymbols.has(normalized)) {
            fail(`capability cohort entry ${index} symbol is invalid or has no route`);
          }
          return normalized;
        });
  if (
    normalizedEntrySymbols.length !== entrySymbols.size ||
    new Set(normalizedEntrySymbols).size !== normalizedEntrySymbols.length
  ) {
    fail("capability cohort entry table must contain every routed entry exactly once");
  }
  const invocationAbiByEntrySymbol = new Map();
  for (const { entrySymbol, invocationAbi } of normalizedMembers) {
    const existing = invocationAbiByEntrySymbol.get(entrySymbol);
    if (existing !== undefined && existing !== invocationAbi) {
      fail(`capability cohort entry ${entrySymbol} mixes invocation ABIs`);
    }
    invocationAbiByEntrySymbol.set(entrySymbol, invocationAbi);
  }
  const entrySlots = new Map(
    normalizedEntrySymbols.map((entrySymbol, entrySlot) => [entrySymbol, entrySlot])
  );
  const declarations = normalizedEntrySymbols
    .map((entrySymbol) => `extern SHUnit *${entrySymbol}(void);`)
    .join("\n");
  const cases = normalizedMembers.map((member) => {
    const kind =
      member.handlerUdfKind === "query"
        ? "CONVEX_WASM_UDF_KIND_QUERY"
        : "CONVEX_WASM_UDF_KIND_MUTATION";
    const invocationAbi = capabilityInvocationAbiEnum(
      member.invocationAbi,
      "capability cohort selector member invocation ABI"
    );
    return (
      `    case UINT64_C(0x${member.entrySelectorId}): ` +
      `convex_wasm_selected_factory = ${member.entrySymbol}; ` +
      `convex_wasm_selected_entry_slot_value = ${String(entrySlots.get(member.entrySymbol))}; ` +
      `convex_wasm_selected_handler_export_name_value = ${JSON.stringify(member.handlerExportName)}; ` +
      `convex_wasm_selected_handler_udf_kind_value = ${kind}; ` +
      `convex_wasm_selected_invocation_abi_value = ${invocationAbi}; return 0;`
    );
  });
  const factoryCases = normalizedEntrySymbols
    .map((entrySymbol, entrySlot) => `    case ${String(entrySlot)}: return ${entrySymbol};`)
    .join("\n");
  const invocationAbiCases = normalizedEntrySymbols
    .map(
      (entrySymbol, entrySlot) =>
        `    case ${String(entrySlot)}: return ${capabilityInvocationAbiEnum(
          invocationAbiByEntrySymbol.get(entrySymbol),
          `capability cohort entry ${entrySlot} invocation ABI`
        )};`
    )
    .join("\n");
  return `#include <stdint.h>
typedef struct SHUnit SHUnit;
typedef SHUnit *(*ConvexWasmApplicationFactory)(void);
${declarations}
enum {
  CONVEX_WASM_UDF_KIND_NONE = 0,
  CONVEX_WASM_UDF_KIND_QUERY = 1,
  CONVEX_WASM_UDF_KIND_MUTATION = 2,
};
enum {
  CONVEX_WASM_INVOCATION_ABI_NONE = 0,
  CONVEX_WASM_INVOCATION_ABI_LEGACY_HANDLER = 1,
  CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER = 2,
};
static SHUnit *(*convex_wasm_selected_factory)(void);
static int32_t convex_wasm_selected_entry_slot_value = -1;
static const char *convex_wasm_selected_handler_export_name_value;
static int32_t convex_wasm_selected_handler_udf_kind_value;
static int32_t convex_wasm_selected_invocation_abi_value;
int32_t ${CAPABILITY_APPLICATION_ENTRY_COUNT_SYMBOL}(void) {
  return ${String(normalizedEntrySymbols.length)};
}
ConvexWasmApplicationFactory ${CAPABILITY_APPLICATION_FACTORY_BY_SLOT_SYMBOL}(int32_t entry_slot) {
  switch (entry_slot) {
${factoryCases}
    default: return (ConvexWasmApplicationFactory)0;
  }
}
int32_t convex_wasm_application_invocation_abi_by_slot(int32_t entry_slot) {
  switch (entry_slot) {
${invocationAbiCases}
    default: return CONVEX_WASM_INVOCATION_ABI_NONE;
  }
}
int32_t convex_wasm_select_entry(uint64_t entry) {
  switch (entry) {
${cases.join("\n")}
    default: convex_wasm_selected_factory = 0; convex_wasm_selected_entry_slot_value = -1; convex_wasm_selected_handler_export_name_value = 0; convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE; convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE; return -1;
  }
}
SHUnit *convex_wasm_selected_exported_unit(void) {
  return convex_wasm_selected_factory == 0
    ? (SHUnit *)0
    : convex_wasm_selected_factory();
}
const char *convex_wasm_selected_handler_export_name(void) {
  return convex_wasm_selected_handler_export_name_value;
}
int32_t convex_wasm_selected_handler_udf_kind(void) {
  return convex_wasm_selected_handler_udf_kind_value;
}
int32_t convex_wasm_selected_invocation_abi(void) {
  return convex_wasm_selected_invocation_abi_value;
}
int32_t convex_wasm_selected_entry_slot(void) {
  return convex_wasm_selected_entry_slot_value;
}
void convex_wasm_clear_selected_entry(void) {
  convex_wasm_selected_factory = 0;
  convex_wasm_selected_entry_slot_value = -1;
  convex_wasm_selected_handler_export_name_value = 0;
  convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE;
  convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE;
}
`;
}

export function renderConvexWasmCapabilityMultiEntryUnitSelector({
  applicationUnitEntrySymbol,
  members,
  orderedEntrySymbols,
}) {
  const normalizedApplicationUnitEntrySymbol = requireManifestString(
    applicationUnitEntrySymbol,
    "multi-entry application unit symbol",
    MAX_MANIFEST_IDENTIFIER_BYTES,
    false
  );
  if (!IDENTIFIER_PATTERN.test(normalizedApplicationUnitEntrySymbol)) {
    fail("multi-entry application unit symbol must be a C identifier");
  }
  if (
    !Array.isArray(orderedEntrySymbols) ||
    orderedEntrySymbols.length < 2 ||
    orderedEntrySymbols.length > 8
  ) {
    fail("multi-entry application unit requires between two and eight ordered entries");
  }
  const entrySlots = new Map(
    orderedEntrySymbols.map((entrySymbol, entrySlot) => {
      const normalized = requireManifestString(
        entrySymbol,
        `multi-entry logical entry ${entrySlot} symbol`,
        MAX_MANIFEST_IDENTIFIER_BYTES,
        false
      );
      if (!IDENTIFIER_PATTERN.test(normalized)) {
        fail(`multi-entry logical entry ${entrySlot} symbol must be a C identifier`);
      }
      return [normalized, entrySlot];
    })
  );
  if (entrySlots.size !== orderedEntrySymbols.length) {
    fail("multi-entry application unit repeats a logical entry symbol");
  }
  const invocationAbiByEntrySymbol = new Map();
  const selectors = new Set();
  const cases = members.map((member, index) => {
    assertPlainObject(member, `multi-entry selector member ${index}`);
    assertExactKeys(
      member,
      new Set([
        "entrySelectorId",
        "entrySymbol",
        "handlerExportName",
        "handlerUdfKind",
        "invocationAbi",
      ]),
      `multi-entry selector member ${index}`
    );
    if (!/^[0-9a-f]{16}$/u.test(member.entrySelectorId) || selectors.has(member.entrySelectorId)) {
      fail(`multi-entry selector member ${index} has an invalid or duplicate selector ID`);
    }
    selectors.add(member.entrySelectorId);
    const entrySlot = entrySlots.get(member.entrySymbol);
    if (entrySlot === undefined) {
      fail(`multi-entry selector member ${index} has no logical handoff slot`);
    }
    const invocationAbi = requireEnum(
      member.invocationAbi,
      CAPABILITY_INVOCATION_ABIS,
      `multi-entry selector member ${index} invocation ABI`
    );
    const existingInvocationAbi = invocationAbiByEntrySymbol.get(member.entrySymbol);
    if (existingInvocationAbi !== undefined && existingInvocationAbi !== invocationAbi) {
      fail(`multi-entry logical entry ${member.entrySymbol} mixes invocation ABIs`);
    }
    invocationAbiByEntrySymbol.set(member.entrySymbol, invocationAbi);
    const udfKind = requireEnum(
      member.handlerUdfKind,
      new Set(["mutation", "query"]),
      `multi-entry selector member ${index} UDF kind`
    );
    const exportName = requireManifestString(
      member.handlerExportName,
      `multi-entry selector member ${index} export name`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (!IDENTIFIER_PATTERN.test(exportName)) {
      fail(`multi-entry selector member ${index} export name must be an identifier`);
    }
    return (
      `    case UINT64_C(0x${member.entrySelectorId}): ` +
      `convex_wasm_selected_entry_slot_value = ${String(entrySlot)}; ` +
      `convex_wasm_selected_handler_export_name_value = ${JSON.stringify(exportName)}; ` +
      `convex_wasm_selected_handler_udf_kind_value = ${
        udfKind === "query" ? "CONVEX_WASM_UDF_KIND_QUERY" : "CONVEX_WASM_UDF_KIND_MUTATION"
      }; ` +
      `convex_wasm_selected_invocation_abi_value = ${capabilityInvocationAbiEnum(
        invocationAbi,
        "multi-entry selector invocation ABI"
      )}; return 0;`
    );
  });
  if (invocationAbiByEntrySymbol.size !== orderedEntrySymbols.length) {
    fail("multi-entry selector routes do not cover every logical entry");
  }
  const invocationAbiCases = orderedEntrySymbols
    .map(
      (entrySymbol, entrySlot) =>
        `    case ${String(entrySlot)}: return ${capabilityInvocationAbiEnum(
          invocationAbiByEntrySymbol.get(entrySymbol),
          `multi-entry logical entry ${entrySlot} invocation ABI`
        )};`
    )
    .join("\n");
  return `#include <stdint.h>
typedef struct SHUnit SHUnit;
typedef SHUnit *(*ConvexWasmApplicationFactory)(void);
extern SHUnit *${normalizedApplicationUnitEntrySymbol}(void);
enum {
  CONVEX_WASM_UDF_KIND_NONE = 0,
  CONVEX_WASM_UDF_KIND_QUERY = 1,
  CONVEX_WASM_UDF_KIND_MUTATION = 2,
};
enum {
  CONVEX_WASM_INVOCATION_ABI_NONE = 0,
  CONVEX_WASM_INVOCATION_ABI_LEGACY_HANDLER = 1,
  CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER = 2,
};
static int32_t convex_wasm_selected_entry_slot_value = -1;
static const char *convex_wasm_selected_handler_export_name_value;
static int32_t convex_wasm_selected_handler_udf_kind_value;
static int32_t convex_wasm_selected_invocation_abi_value;
int32_t ${CAPABILITY_APPLICATION_ENTRY_COUNT_SYMBOL}(void) {
  return ${String(orderedEntrySymbols.length)};
}
int32_t ${CAPABILITY_APPLICATION_UNIT_COUNT_SYMBOL}(void) {
  return 1;
}
ConvexWasmApplicationFactory ${CAPABILITY_APPLICATION_FACTORY_BY_UNIT_SLOT_SYMBOL}(int32_t unit_slot) {
  return unit_slot == 0 ? ${normalizedApplicationUnitEntrySymbol} : (ConvexWasmApplicationFactory)0;
}
int32_t convex_wasm_application_invocation_abi_by_slot(int32_t entry_slot) {
  switch (entry_slot) {
${invocationAbiCases}
    default: return CONVEX_WASM_INVOCATION_ABI_NONE;
  }
}
int32_t convex_wasm_select_entry(uint64_t entry) {
  switch (entry) {
${cases.join("\n")}
    default: convex_wasm_selected_entry_slot_value = -1; convex_wasm_selected_handler_export_name_value = 0; convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE; convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE; return -1;
  }
}
SHUnit *convex_wasm_selected_exported_unit(void) {
  return convex_wasm_selected_entry_slot_value < 0 ? (SHUnit *)0 : ${normalizedApplicationUnitEntrySymbol}();
}
const char *convex_wasm_selected_handler_export_name(void) {
  return convex_wasm_selected_handler_export_name_value;
}
int32_t convex_wasm_selected_handler_udf_kind(void) {
  return convex_wasm_selected_handler_udf_kind_value;
}
int32_t convex_wasm_selected_invocation_abi(void) {
  return convex_wasm_selected_invocation_abi_value;
}
int32_t convex_wasm_selected_entry_slot(void) {
  return convex_wasm_selected_entry_slot_value;
}
void convex_wasm_clear_selected_entry(void) {
  convex_wasm_selected_entry_slot_value = -1;
  convex_wasm_selected_handler_export_name_value = 0;
  convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE;
  convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE;
}
`;
}

export function renderConvexWasmCapabilityChunkApplicationSelector({
  applicationDescriptor,
  members,
  orderedEntrySymbols,
}) {
  const descriptor = normalizeModuleGraphSelectorDescriptor(
    applicationDescriptor,
    "capability chunk application descriptor"
  );
  if (
    !Array.isArray(orderedEntrySymbols) ||
    orderedEntrySymbols.length !== descriptor.entries.length
  ) {
    fail("chunk application selector entry table is incomplete");
  }
  const entrySlots = new Map(
    orderedEntrySymbols.map((entrySymbol, entrySlot) => {
      const normalized = requireManifestString(
        entrySymbol,
        `chunk application logical entry ${entrySlot} symbol`,
        MAX_MANIFEST_IDENTIFIER_BYTES,
        false
      );
      if (!IDENTIFIER_PATTERN.test(normalized)) {
        fail(`chunk application logical entry ${entrySlot} symbol must be a C identifier`);
      }
      return [normalized, entrySlot];
    })
  );
  if (entrySlots.size !== orderedEntrySymbols.length) {
    fail("chunk application selector repeats a logical entry symbol");
  }
  if (!Array.isArray(members) || members.length === 0) {
    fail("chunk application selector must contain at least one route");
  }
  const selectors = new Set();
  const routesByEntrySlot = descriptor.entries.map(() => []);
  const cases = members.map((member, index) => {
    assertPlainObject(member, `chunk application selector member ${index}`);
    assertExactKeys(
      member,
      new Set([
        "entrySelectorId",
        "entrySymbol",
        "handlerExportName",
        "handlerUdfKind",
        "invocationAbi",
      ]),
      `chunk application selector member ${index}`
    );
    if (
      typeof member.entrySelectorId !== "string" ||
      !/^[0-9a-f]{16}$/u.test(member.entrySelectorId) ||
      selectors.has(member.entrySelectorId)
    ) {
      fail(`chunk application selector member ${index} has an invalid or duplicate selector ID`);
    }
    selectors.add(member.entrySelectorId);
    const entrySlot = entrySlots.get(member.entrySymbol);
    if (entrySlot === undefined) {
      fail(`chunk application selector member ${index} has no logical handoff slot`);
    }
    const exportName = requireManifestString(
      member.handlerExportName,
      `chunk application selector member ${index} export name`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (!IDENTIFIER_PATTERN.test(exportName)) {
      fail(`chunk application selector member ${index} export name must be an identifier`);
    }
    const udfKind = requireEnum(
      member.handlerUdfKind,
      new Set(["mutation", "query"]),
      `chunk application selector member ${index} UDF kind`
    );
    if (member.invocationAbi !== convexWasmCapabilityOfficialWrapperInvocationAbi) {
      fail(`chunk application selector member ${index} must use the official wrapper ABI`);
    }
    routesByEntrySlot[entrySlot].push({ exportName, udfKind });
    return (
      `    case UINT64_C(0x${member.entrySelectorId}): ` +
      `convex_wasm_selected_application_unit_slot_value = ${String(
        descriptor.entries[entrySlot].entryPublicationUnitSlot
      )}; ` +
      `convex_wasm_selected_entry_slot_value = ${String(entrySlot)}; ` +
      `convex_wasm_selected_handler_export_name_value = ${JSON.stringify(exportName)}; ` +
      `convex_wasm_selected_handler_udf_kind_value = ${
        udfKind === "query" ? "CONVEX_WASM_UDF_KIND_QUERY" : "CONVEX_WASM_UDF_KIND_MUTATION"
      }; ` +
      "convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER; return 0;"
    );
  });
  for (const [entrySlot, expectedEntry] of descriptor.entries.entries()) {
    const expectedRoutes = expectedEntry.routes
      .map(({ exportName, udfKind }) => ({ exportName, udfKind }))
      .sort((left, right) => compareStrings(canonicalJson(left), canonicalJson(right)));
    const actualRoutes = routesByEntrySlot[entrySlot].sort((left, right) =>
      compareStrings(canonicalJson(left), canonicalJson(right))
    );
    if (canonicalJson(actualRoutes) !== canonicalJson(expectedRoutes)) {
      fail(`chunk application selector routes do not match logical entry ${entrySlot}`);
    }
  }
  const declarations = descriptor.units
    .map(({ entrySymbol }) => `extern SHUnit *${entrySymbol}(void);`)
    .join("\n");
  const factoryCases = descriptor.units
    .map(({ entrySymbol }, unitSlot) => `    case ${String(unitSlot)}: return ${entrySymbol};`)
    .join("\n");
  const dependencyRows = [];
  const dependencyRanges = descriptor.units
    .slice(0, descriptor.initialization.chunkSlotCount)
    .map(({ dependencies }) => {
      const offset = dependencyRows.length;
      // Authentication guarantees dense per-unit occurrences. Keep the complete
      // specifier as the authority; its occurrence only selects a candidate.
      const ordered = dependencies
        .map((dependency) => ({
          ...dependency,
          occurrence: parseConvexWasmOfficialOutputExecutableDependencySpecifier(
            dependency.executableSpecifier
          ).occurrence,
        }))
        .sort((left, right) => left.occurrence - right.occurrence);
      for (const { executableSpecifier, slot } of ordered) {
        dependencyRows.push(`  { ${JSON.stringify(executableSpecifier)}, ${String(slot)} },`);
      }
      return `  { ${String(offset)}, ${String(dependencies.length)} },`;
    })
    .join("\n");
  const entryChunkCases = descriptor.entries
    .map(
      ({ entrySlot }, handoffSlot) =>
        `    case ${String(handoffSlot)}: return ${String(entrySlot)};`
    )
    .join("\n");
  const entryPublicationCases = descriptor.entries
    .map(
      ({ entryPublicationUnitSlot }, handoffSlot) =>
        `    case ${String(handoffSlot)}: return ${String(entryPublicationUnitSlot)};`
    )
    .join("\n");
  const invocationAbiCases = descriptor.entries
    .map(
      (_, entrySlot) =>
        `    case ${String(entrySlot)}: return CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER;`
    )
    .join("\n");
  return `#include <stdint.h>
#include <string.h>
typedef struct SHUnit SHUnit;
typedef SHUnit *(*ConvexWasmApplicationFactory)(void);
${declarations}
enum {
  CONVEX_WASM_UDF_KIND_NONE = 0,
  CONVEX_WASM_UDF_KIND_QUERY = 1,
  CONVEX_WASM_UDF_KIND_MUTATION = 2,
};
enum {
  CONVEX_WASM_INVOCATION_ABI_NONE = 0,
  CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER = 2,
};
static int32_t convex_wasm_selected_application_unit_slot_value = -1;
static int32_t convex_wasm_selected_entry_slot_value = -1;
static const char *convex_wasm_selected_handler_export_name_value;
static int32_t convex_wasm_selected_handler_udf_kind_value;
static int32_t convex_wasm_selected_invocation_abi_value;
int32_t ${CAPABILITY_APPLICATION_ENTRY_COUNT_SYMBOL}(void) {
  return ${String(descriptor.entries.length)};
}
int32_t ${CAPABILITY_APPLICATION_UNIT_COUNT_SYMBOL}(void) {
  return ${String(descriptor.units.length)};
}
int32_t convex_wasm_application_chunk_slot_count(void) {
  return ${String(descriptor.initialization.chunkSlotCount)};
}
int32_t convex_wasm_application_entry_publication_unit_slot_by_handoff_slot(int32_t entry_slot) {
  switch (entry_slot) {
${entryPublicationCases}
    default: return -1;
  }
}
ConvexWasmApplicationFactory ${CAPABILITY_APPLICATION_FACTORY_BY_UNIT_SLOT_SYMBOL}(int32_t unit_slot) {
  switch (unit_slot) {
${factoryCases}
    default: return (ConvexWasmApplicationFactory)0;
  }
}
static const struct {
  const char *specifier;
  int32_t slot;
} convex_wasm_application_dependencies[] = {
${dependencyRows.length === 0 ? "  { (const char *)0, -1 }," : dependencyRows.join("\n")}
};
static const struct {
  uint32_t offset;
  uint32_t count;
} convex_wasm_application_dependency_ranges[] = {
${dependencyRanges}
};
int32_t convex_wasm_application_chunk_dependency_by_specifier(int32_t unit_slot, const char *specifier) {
  if (specifier == (const char *)0 || unit_slot < 0 ||
      (uint32_t)unit_slot >= ${String(descriptor.initialization.chunkSlotCount)}) return -1;
  uint32_t count = convex_wasm_application_dependency_ranges[unit_slot].count;
  if (count == 0) return -1;
  uint32_t occurrence = 0;
  if (count > 1) {
    size_t length = strlen(specifier);
    if (length < 11) return -1;
    /* The eight-digit occurrence precedes ".js". It selects a candidate only:
       the full comparison below also rejects malformed or foreign specifiers. */
    for (size_t index = length - 11; index < length - 3; ++index) {
      uint32_t digit = (uint32_t)(unsigned char)specifier[index] - (uint32_t)'0';
      if (digit > 9) return -1;
      occurrence = occurrence * 10 + digit;
    }
    if (occurrence >= count) return -1;
  }
  uint32_t index = convex_wasm_application_dependency_ranges[unit_slot].offset + occurrence;
  return strcmp(specifier, convex_wasm_application_dependencies[index].specifier) == 0
    ? convex_wasm_application_dependencies[index].slot : -1;
}
int32_t convex_wasm_application_entry_chunk_slot_by_handoff_slot(int32_t entry_slot) {
  switch (entry_slot) {
${entryChunkCases}
    default: return -1;
  }
}
int32_t convex_wasm_application_invocation_abi_by_slot(int32_t entry_slot) {
  switch (entry_slot) {
${invocationAbiCases}
    default: return CONVEX_WASM_INVOCATION_ABI_NONE;
  }
}
int32_t convex_wasm_select_entry(uint64_t entry) {
  switch (entry) {
${cases.join("\n")}
    default: convex_wasm_selected_application_unit_slot_value = -1; convex_wasm_selected_entry_slot_value = -1; convex_wasm_selected_handler_export_name_value = 0; convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE; convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE; return -1;
  }
}
SHUnit *convex_wasm_selected_exported_unit(void) {
  ConvexWasmApplicationFactory factory = ${CAPABILITY_APPLICATION_FACTORY_BY_UNIT_SLOT_SYMBOL}(convex_wasm_selected_application_unit_slot_value);
  return factory == (ConvexWasmApplicationFactory)0 ? (SHUnit *)0 : factory();
}
const char *convex_wasm_selected_handler_export_name(void) {
  return convex_wasm_selected_handler_export_name_value;
}
int32_t convex_wasm_selected_handler_udf_kind(void) {
  return convex_wasm_selected_handler_udf_kind_value;
}
int32_t convex_wasm_selected_invocation_abi(void) {
  return convex_wasm_selected_invocation_abi_value;
}
int32_t convex_wasm_selected_entry_slot(void) {
  return convex_wasm_selected_entry_slot_value;
}
void convex_wasm_clear_selected_entry(void) {
  convex_wasm_selected_application_unit_slot_value = -1;
  convex_wasm_selected_entry_slot_value = -1;
  convex_wasm_selected_handler_export_name_value = 0;
  convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE;
  convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE;
}
`;
}

export function renderConvexWasmModuleGraphBaseSelectorBridge() {
  return `#include <stdint.h>
#include <stdlib.h>
typedef struct SHUnit SHUnit;
typedef SHUnit *(*ConvexWasmApplicationFactory)(void);
typedef struct {
  int32_t (*application_entry_count)(void);
  int32_t (*application_unit_count)(void);
  int32_t (*chunk_slot_count)(void);
  int32_t (*entry_publication_unit_slot_by_handoff_slot)(int32_t);
  ConvexWasmApplicationFactory (*factory_by_unit_slot)(int32_t);
  int32_t (*chunk_dependency_by_specifier)(int32_t, const char *);
  int32_t (*entry_chunk_slot_by_handoff_slot)(int32_t);
  int32_t (*invocation_abi_by_slot)(int32_t);
  const char *(*selected_handler_export_name)(void);
  int32_t (*selected_handler_udf_kind)(void);
  int32_t (*selected_invocation_abi)(void);
  int32_t (*selected_entry_slot)(void);
  void (*clear_selected_entry)(void);
  int32_t (*select_entry)(uint64_t);
} ConvexWasmSelectorSurface;
static ConvexWasmSelectorSurface convex_wasm_selector_surface;
static int32_t convex_wasm_selector_surface_registered;
static const ConvexWasmSelectorSurface *convex_wasm_selector(void) {
  if (!convex_wasm_selector_surface_registered) __builtin_trap();
  return &convex_wasm_selector_surface;
}
int32_t ${MODULE_GRAPH_SELECTOR_REGISTRATION_SYMBOL}(
    int32_t (*application_entry_count)(void),
    int32_t (*application_unit_count)(void),
    int32_t (*chunk_slot_count)(void),
    int32_t (*entry_publication_unit_slot_by_handoff_slot)(int32_t),
    ConvexWasmApplicationFactory (*factory_by_unit_slot)(int32_t),
    int32_t (*chunk_dependency_by_specifier)(int32_t, const char *),
    int32_t (*entry_chunk_slot_by_handoff_slot)(int32_t),
    int32_t (*invocation_abi_by_slot)(int32_t),
    const char *(*selected_handler_export_name)(void),
    int32_t (*selected_handler_udf_kind)(void),
    int32_t (*selected_invocation_abi)(void),
    int32_t (*selected_entry_slot)(void),
    void (*clear_selected_entry)(void),
    int32_t (*select_entry)(uint64_t)) {
  if (convex_wasm_selector_surface_registered ||
      application_entry_count == 0 || application_unit_count == 0 ||
      chunk_slot_count == 0 || entry_publication_unit_slot_by_handoff_slot == 0 ||
      factory_by_unit_slot == 0 || chunk_dependency_by_specifier == 0 ||
      entry_chunk_slot_by_handoff_slot == 0 || invocation_abi_by_slot == 0 ||
      selected_handler_export_name == 0 || selected_handler_udf_kind == 0 ||
      selected_invocation_abi == 0 || selected_entry_slot == 0 ||
      clear_selected_entry == 0 || select_entry == 0) return -1;
  convex_wasm_selector_surface = (ConvexWasmSelectorSurface){
    application_entry_count, application_unit_count, chunk_slot_count,
    entry_publication_unit_slot_by_handoff_slot, factory_by_unit_slot,
    chunk_dependency_by_specifier, entry_chunk_slot_by_handoff_slot,
    invocation_abi_by_slot, selected_handler_export_name,
    selected_handler_udf_kind, selected_invocation_abi,
    selected_entry_slot, clear_selected_entry, select_entry
  };
  convex_wasm_selector_surface_registered = 1;
  return 0;
}
int32_t convex_wasm_graph_application_entry_count(void) { return convex_wasm_selector()->application_entry_count(); }
int32_t convex_wasm_graph_application_unit_count(void) { return convex_wasm_selector()->application_unit_count(); }
int32_t convex_wasm_graph_application_chunk_slot_count(void) { return convex_wasm_selector()->chunk_slot_count(); }
int32_t convex_wasm_graph_application_entry_publication_unit_slot_by_handoff_slot(int32_t slot) { return convex_wasm_selector()->entry_publication_unit_slot_by_handoff_slot(slot); }
ConvexWasmApplicationFactory convex_wasm_graph_application_factory_by_unit_slot(int32_t slot) { return convex_wasm_selector()->factory_by_unit_slot(slot); }
int32_t convex_wasm_graph_application_chunk_dependency_by_specifier(int32_t slot, const char *specifier) { return convex_wasm_selector()->chunk_dependency_by_specifier(slot, specifier); }
int32_t convex_wasm_graph_application_entry_chunk_slot_by_handoff_slot(int32_t slot) { return convex_wasm_selector()->entry_chunk_slot_by_handoff_slot(slot); }
int32_t convex_wasm_graph_application_invocation_abi_by_slot(int32_t slot) { return convex_wasm_selector()->invocation_abi_by_slot(slot); }
const char *convex_wasm_graph_selected_handler_export_name(void) { return convex_wasm_selector()->selected_handler_export_name(); }
int32_t convex_wasm_graph_selected_handler_udf_kind(void) { return convex_wasm_selector()->selected_handler_udf_kind(); }
int32_t convex_wasm_graph_selected_invocation_abi(void) { return convex_wasm_selector()->selected_invocation_abi(); }
int32_t convex_wasm_graph_selected_entry_slot(void) { return convex_wasm_selector()->selected_entry_slot(); }
void convex_wasm_graph_clear_selected_entry(void) { convex_wasm_selector()->clear_selected_entry(); }
int32_t convex_wasm_graph_select_entry(uint64_t entry) { return convex_wasm_selector()->select_entry(entry); }
`;
}

function normalizeModuleGraphChunkApplicationDescriptor(rawDescriptor, description) {
  const compact = authenticateModuleGraphCompilerDescriptor(rawDescriptor, description);
  return {
    applicationIdentity: compact.applicationIdentity,
    chunkUnitsIdentity: compact.chunkUnitsIdentity,
    entries: compact.entries,
    identitySha256: compact.identitySha256,
    initialization: compact.initialization,
    kind: compact.nativeApplicationDescriptorKind,
    nativeDescriptor: compact.nativeDescriptor,
    units: compact.units,
  };
}

function normalizeModuleGraphSelectorDescriptor(rawDescriptor, description) {
  assertPlainObject(rawDescriptor, description);
  return Object.hasOwn(rawDescriptor, "nativeApplicationDescriptorKind")
    ? normalizeModuleGraphChunkApplicationDescriptor(rawDescriptor, description)
    : normalizeConvexWasmCapabilityChunkApplicationDescriptor(rawDescriptor);
}

export function renderConvexWasmModuleGraphLeafSelector({
  applicationDescriptor,
  cohortIndex,
  commonUnits,
  members,
  orderedEntrySymbols,
}) {
  let source = renderConvexWasmCapabilityChunkApplicationSelector({
    applicationDescriptor,
    members,
    orderedEntrySymbols,
  });
  if (!Number.isSafeInteger(cohortIndex) || cohortIndex < 0) {
    fail("module graph leaf cohort index must be a nonnegative safe integer");
  }
  for (const [index, common] of commonUnits.entries()) {
    const occurrence = common.occurrences.find(
      (candidate) => candidate.cohortIndex === cohortIndex
    );
    if (occurrence === undefined) continue;
    const sourceSymbol = occurrence.unit.entrySymbol;
    if (!source.includes(sourceSymbol)) {
      fail(`module graph common unit ${index} is absent from its leaf selector`);
    }
    source = source.replaceAll(sourceSymbol, common.factorySymbol);
  }
  return `${source}
extern int32_t ${MODULE_GRAPH_SELECTOR_REGISTRATION_SYMBOL}(
    int32_t (*)(void), int32_t (*)(void), int32_t (*)(void), int32_t (*)(int32_t),
    ConvexWasmApplicationFactory (*)(int32_t), int32_t (*)(int32_t, const char *),
    int32_t (*)(int32_t), int32_t (*)(int32_t), const char *(*)(void),
    int32_t (*)(void), int32_t (*)(void), int32_t (*)(void), void (*)(void),
    int32_t (*)(uint64_t));
__attribute__((constructor)) static void convex_wasm_register_leaf_selector_surface(void) {
  if (${MODULE_GRAPH_SELECTOR_REGISTRATION_SYMBOL}(
      convex_wasm_application_entry_count,
      convex_wasm_application_unit_count,
      convex_wasm_application_chunk_slot_count,
      convex_wasm_application_entry_publication_unit_slot_by_handoff_slot,
      convex_wasm_application_factory_by_unit_slot,
      convex_wasm_application_chunk_dependency_by_specifier,
      convex_wasm_application_entry_chunk_slot_by_handoff_slot,
      convex_wasm_application_invocation_abi_by_slot,
      convex_wasm_selected_handler_export_name,
      convex_wasm_selected_handler_udf_kind,
      convex_wasm_selected_invocation_abi,
      convex_wasm_selected_entry_slot,
      convex_wasm_clear_selected_entry,
      convex_wasm_select_entry) != 0) __builtin_trap();
}
`;
}
export function renderConvexWasmCapabilityEntrySelector({ entrySymbol, members }) {
  const normalizedEntrySymbol = requireManifestString(
    entrySymbol,
    "capability entry selector symbol",
    MAX_MANIFEST_IDENTIFIER_BYTES,
    false
  );
  if (!IDENTIFIER_PATTERN.test(normalizedEntrySymbol)) {
    fail("capability entry selector symbol must be a C identifier");
  }
  if (!Array.isArray(members) || members.length === 0) {
    fail("capability entry selector must contain at least one sibling export");
  }
  const selectors = new Set();
  let entryInvocationAbi;
  const cases = members.map((member, index) => {
    assertPlainObject(member, `capability entry selector member ${index}`);
    assertExactKeys(
      member,
      new Set(["entrySelectorId", "handlerExportName", "handlerUdfKind", "invocationAbi"]),
      `capability entry selector member ${index}`
    );
    if (
      typeof member.entrySelectorId !== "string" ||
      !/^[0-9a-f]{16}$/u.test(member.entrySelectorId)
    ) {
      fail(`capability entry selector member ${index} has an invalid selector ID`);
    }
    if (selectors.has(member.entrySelectorId)) {
      fail("capability entry selector contains duplicate selector IDs");
    }
    selectors.add(member.entrySelectorId);
    const handlerExportName = requireManifestString(
      member.handlerExportName,
      `capability entry selector member ${index} export name`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (!IDENTIFIER_PATTERN.test(handlerExportName)) {
      fail(`capability entry selector member ${index} export name must be an identifier`);
    }
    const handlerUdfKind = requireEnum(
      member.handlerUdfKind,
      new Set(["mutation", "query"]),
      `capability entry selector member ${index} UDF kind`
    );
    const kind =
      handlerUdfKind === "query" ? "CONVEX_WASM_UDF_KIND_QUERY" : "CONVEX_WASM_UDF_KIND_MUTATION";
    const normalizedInvocationAbi = requireEnum(
      member.invocationAbi,
      CAPABILITY_INVOCATION_ABIS,
      `capability entry selector member ${index} invocation ABI`
    );
    if (entryInvocationAbi !== undefined && entryInvocationAbi !== normalizedInvocationAbi) {
      fail("capability entry selector mixes invocation ABIs");
    }
    entryInvocationAbi = normalizedInvocationAbi;
    const invocationAbi = capabilityInvocationAbiEnum(
      normalizedInvocationAbi,
      `capability entry selector member ${index} invocation ABI`
    );
    return (
      `    case UINT64_C(0x${member.entrySelectorId}): ` +
      `convex_wasm_selected_handler_export_name_value = ${JSON.stringify(handlerExportName)}; ` +
      `convex_wasm_selected_handler_udf_kind_value = ${kind}; ` +
      `convex_wasm_selected_invocation_abi_value = ${invocationAbi}; return 0;`
    );
  });
  return `#include <stdint.h>
typedef struct SHUnit SHUnit;
typedef SHUnit *(*ConvexWasmApplicationFactory)(void);
extern SHUnit *${normalizedEntrySymbol}(void);
enum {
  CONVEX_WASM_UDF_KIND_NONE = 0,
  CONVEX_WASM_UDF_KIND_QUERY = 1,
  CONVEX_WASM_UDF_KIND_MUTATION = 2,
};
enum {
  CONVEX_WASM_INVOCATION_ABI_NONE = 0,
  CONVEX_WASM_INVOCATION_ABI_LEGACY_HANDLER = 1,
  CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER = 2,
};
static int32_t convex_wasm_has_selected_entry;
static int32_t convex_wasm_selected_entry_slot_value = -1;
static const char *convex_wasm_selected_handler_export_name_value;
static int32_t convex_wasm_selected_handler_udf_kind_value;
static int32_t convex_wasm_selected_invocation_abi_value;
int32_t ${CAPABILITY_APPLICATION_ENTRY_COUNT_SYMBOL}(void) {
  return 1;
}
ConvexWasmApplicationFactory ${CAPABILITY_APPLICATION_FACTORY_BY_SLOT_SYMBOL}(int32_t entry_slot) {
  return entry_slot == 0
    ? ${normalizedEntrySymbol}
    : (ConvexWasmApplicationFactory)0;
}
int32_t convex_wasm_application_invocation_abi_by_slot(int32_t entry_slot) {
  return entry_slot == 0
    ? ${capabilityInvocationAbiEnum(entryInvocationAbi, "capability entry invocation ABI")}
    : CONVEX_WASM_INVOCATION_ABI_NONE;
}
int32_t convex_wasm_select_entry(uint64_t entry) {
  convex_wasm_has_selected_entry = 1;
  convex_wasm_selected_entry_slot_value = 0;
  switch (entry) {
${cases.join("\n")}
    default: convex_wasm_has_selected_entry = 0; convex_wasm_selected_entry_slot_value = -1; convex_wasm_selected_handler_export_name_value = 0; convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE; convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE; return -1;
  }
}
SHUnit *convex_wasm_selected_exported_unit(void) {
  return convex_wasm_has_selected_entry == 0
    ? (SHUnit *)0
    : ${normalizedEntrySymbol}();
}
const char *convex_wasm_selected_handler_export_name(void) {
  return convex_wasm_selected_handler_export_name_value;
}
int32_t convex_wasm_selected_handler_udf_kind(void) {
  return convex_wasm_selected_handler_udf_kind_value;
}
int32_t convex_wasm_selected_invocation_abi(void) {
  return convex_wasm_selected_invocation_abi_value;
}
int32_t convex_wasm_selected_entry_slot(void) {
  return convex_wasm_selected_entry_slot_value;
}
void convex_wasm_clear_selected_entry(void) {
  convex_wasm_has_selected_entry = 0;
  convex_wasm_selected_entry_slot_value = -1;
  convex_wasm_selected_handler_export_name_value = 0;
  convex_wasm_selected_handler_udf_kind_value = CONVEX_WASM_UDF_KIND_NONE;
  convex_wasm_selected_invocation_abi_value = CONVEX_WASM_INVOCATION_ABI_NONE;
}
`;
}
