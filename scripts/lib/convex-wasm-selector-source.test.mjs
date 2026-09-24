import assert from "node:assert/strict";
import test from "node:test";

import { normalizeConvexWasmCapabilityChunkApplicationDescriptor } from "./convex-wasm-capability-application-descriptor.mjs";
import { convexWasmOfficialOutputChunkNativeApplicationDescriptorKind } from "./convex-wasm-module-graph-compiler-descriptor.mjs";
import {
  convexWasmCapabilityApplicationEntryCountSymbol,
  convexWasmCapabilityApplicationFactoryBySlotSymbol,
  convexWasmCapabilityApplicationFactoryByUnitSlotSymbol,
  convexWasmCapabilityApplicationUnitCountSymbol,
  convexWasmCapabilityLegacyInvocationAbi,
  convexWasmCapabilityOfficialWrapperInvocationAbi,
  convexWasmModuleGraphSelectorRegistrationSymbol,
  renderConvexWasmCapabilityChunkApplicationSelector,
  renderConvexWasmCapabilityCohortSelector,
  renderConvexWasmCapabilityEntrySelector,
  renderConvexWasmCapabilityMultiEntryUnitSelector,
  renderConvexWasmCohortSelector,
  renderConvexWasmModuleGraphBaseSelectorBridge,
  renderConvexWasmModuleGraphLeafSelector,
} from "./convex-wasm-selector-source.mjs";

test("selector source exports the stable native symbol interface", () => {
  assert.deepEqual(
    {
      applicationEntryCount: convexWasmCapabilityApplicationEntryCountSymbol,
      applicationFactoryBySlot: convexWasmCapabilityApplicationFactoryBySlotSymbol,
      applicationFactoryByUnitSlot: convexWasmCapabilityApplicationFactoryByUnitSlotSymbol,
      applicationUnitCount: convexWasmCapabilityApplicationUnitCountSymbol,
      moduleGraphRegistration: convexWasmModuleGraphSelectorRegistrationSymbol,
    },
    {
      applicationEntryCount: "convex_wasm_application_entry_count",
      applicationFactoryBySlot: "convex_wasm_application_factory_by_slot",
      applicationFactoryByUnitSlot: "convex_wasm_application_factory_by_unit_slot",
      applicationUnitCount: "convex_wasm_application_unit_count",
      moduleGraphRegistration: "convex_wasm_register_application_selector_surface",
    }
  );
});

test("selector source generation retains exact stable route identities", () => {
  const source = renderConvexWasmCapabilityEntrySelector({
    entrySymbol: "sh_export_probe",
    members: [
      {
        entrySelectorId: "0123456789abcdef",
        handlerExportName: "readProbe",
        handlerUdfKind: "query",
        invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi,
      },
    ],
  });

  assert.match(source, /case UINT64_C\(0x0123456789abcdef\)/u);
  assert.match(source, /convex_wasm_selected_handler_export_name_value = "readProbe"/u);
  assert.match(source, /CONVEX_WASM_INVOCATION_ABI_OFFICIAL_WRAPPER/u);
  assert.match(source, /extern SHUnit \*sh_export_probe\(void\);/u);
});

test("selector source generation fails closed on duplicate route identities", () => {
  const member = {
    entrySelectorId: "0123456789abcdef",
    handlerExportName: "readProbe",
    handlerUdfKind: "query",
    invocationAbi: convexWasmCapabilityLegacyInvocationAbi,
  };

  assert.throws(
    () =>
      renderConvexWasmCapabilityEntrySelector({
        entrySymbol: "sh_export_probe",
        members: [member, { ...member, handlerExportName: "readOtherProbe" }],
      }),
    /duplicate selector IDs/u
  );
});

test("chunk application descriptor normalization fails closed on unsupported input", () => {
  assert.throws(
    () => normalizeConvexWasmCapabilityChunkApplicationDescriptor({}),
    /capability chunk application descriptor kind is unsupported/u
  );

  assert.throws(
    () =>
      normalizeConvexWasmCapabilityChunkApplicationDescriptor({
        kind: convexWasmOfficialOutputChunkNativeApplicationDescriptorKind,
        unexpected: true,
      }),
    /capability chunk application descriptor has unknown field\(s\): unexpected/u
  );
});
