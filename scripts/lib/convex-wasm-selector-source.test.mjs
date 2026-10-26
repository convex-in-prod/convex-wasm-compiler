import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as esbuild from "esbuild";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { authenticateConvexWasmOfficialOutputSelectionFixtures } from "../test-fixtures/official-output-selection.mjs";
import { buildConvexWasmOfficialOutputChunkUnits } from "./convex-wasm-official-output-chunk-unit.mjs";
import {
  buildConvexWasmOfficialOutputChunkApplicationUnit,
  projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor,
} from "./convex-wasm-official-output-chunk-application-unit.mjs";
import {
  convexWasmOfficialOutputChunkNativeApplicationDescriptorKind,
  projectConvexWasmModuleGraphCompilerDescriptorFromCapabilityDescriptor,
} from "./convex-wasm-module-graph-compiler-descriptor.mjs";
import { parseConvexWasmOfficialOutputExecutableDependencySpecifier } from "./convex-wasm-official-output-chunk-contract.mjs";

import { normalizeConvexWasmCapabilityChunkApplicationDescriptor } from "./convex-wasm-capability-application-descriptor.mjs";
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

async function dependencySelectorFixture(dependencyCount) {
  const sources = Object.fromEntries([
    [
      "entry.js",
      Array.from(
        { length: dependencyCount },
        (_, index) =>
          `import { value as value${index} } from "./dep${String(index).padStart(3, "0")}.js";`
      ).join("\n") +
        `\nexport function run() { return [${Array.from(
          { length: dependencyCount },
          (_, index) => `value${index}`
        ).join(",")}]; }` +
        (dependencyCount === 0 ? "" : '\nexport function later() { return import("./lazy.js"); }')
    ],
    ...Array.from({ length: dependencyCount }, (_, index) => [
      `dep${String(index).padStart(3, "0")}.js`,
      index === 0 && dependencyCount > 1
        ? 'export { value } from "./dep001.js";'
        : `export const value = ${index};`
    ])
  ]);
  if (dependencyCount > 0) sources["lazy.js"] = "export const value = 42;";
  const modules = Object.entries(sources).map(([path, source]) => {
    const sources = [`fixture:///${path}`];
    const sourceMap = JSON.stringify({ sources, version: 3 });
    const hash = (value) => createHash("sha256").update(value).digest("hex");
    return {
      source,
      sourceMap,
      identity: {
        path,
        environment: "isolate",
        sourceMembershipSha256: convexWasmOfficialOutputSourceMembershipIdentitySha256({ sources }),
        sourceSha256: hash(source),
        sourceSize: Buffer.byteLength(source),
        sourceMap: {
          sha256: hash(sourceMap),
          size: Buffer.byteLength(sourceMap),
          sourcesCount: 1,
          sourcesContentCount: 0
        },
        moduleSha256: hash(source + sourceMap)
      }
    };
  });
  const imports = Array.from({ length: dependencyCount }, (_, index) => ({
    external: false,
    importerPath: "entry.js",
    kind: "import-statement",
    path: `dep${String(index).padStart(3, "0")}.js`
  }));
  if (dependencyCount > 0)
    imports.push({
      external: false,
      importerPath: "entry.js",
      kind: "dynamic-import",
      path: "lazy.js"
    });
  imports.sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0
  );
  if (dependencyCount > 1)
    imports.push({
      external: false,
      importerPath: "dep000.js",
      kind: "import-statement",
      path: "dep001.js"
    });
  const closure = {
    entryModulePath: "entry.js",
    kind: "fixture-closure-v1",
    imports,
    modules: modules.map(({ identity }) => identity)
  };
  const selections = authenticateConvexWasmOfficialOutputSelectionFixtures([
    {
      closure: { identity: { ...closure, sha256: fingerprintJson(closure) }, modules },
      manifestMembership: {
        dependencyGraphSha256: "b".repeat(64),
        inventoryKind: "fixture-inventory-v1",
        sourceEnvelopeSha256: "a".repeat(64)
      },
      route: {
        entryPath: "convex/entry.ts",
        exportName: "run",
        modulePath: "entry",
        runtimeModulePath: "entry.js",
        udfKind: "query",
        visibility: "public"
      },
      toolchain: { esbuild: esbuild.version }
    }
  ]).selections;
  const chunkUnits = await buildConvexWasmOfficialOutputChunkUnits({ esbuild, selections });
  const applicationDescriptor = projectConvexWasmOfficialOutputChunkNativeApplicationDescriptor(
    buildConvexWasmOfficialOutputChunkApplicationUnit({ chunkUnits })
  );
  return {
    applicationDescriptor,
    orderedEntrySymbols: ["sh_export_entry"],
    members: [
      {
        entrySelectorId: "0123456789abcdef",
        entrySymbol: "sh_export_entry",
        handlerExportName: "run",
        handlerUdfKind: "query",
        invocationAbi: convexWasmCapabilityOfficialWrapperInvocationAbi
      }
    ]
  };
}

test("dependency selectors preserve authenticated descriptors through persistence", async () => {
  for (const count of [0, 1, 130]) {
    const fixture = await dependencySelectorFixture(count);
    const source = renderConvexWasmCapabilityChunkApplicationSelector(fixture);
    const compact = projectConvexWasmModuleGraphCompilerDescriptorFromCapabilityDescriptor(
      fixture.applicationDescriptor,
      "selector fixture"
    );
    assert.equal(
      renderConvexWasmCapabilityChunkApplicationSelector({
        ...fixture,
        applicationDescriptor: JSON.parse(JSON.stringify(compact))
      }),
      source
    );
    if (count > 1) {
      const dependencies = fixture.applicationDescriptor.units.find(
        ({ dependencies }) => dependencies.length > 100
      ).dependencies;
      assert.notDeepEqual(
        dependencies.map(
          ({ executableSpecifier }) =>
            parseConvexWasmOfficialOutputExecutableDependencySpecifier(executableSpecifier)
              .occurrence
        ),
        Array.from({ length: dependencies.length }, (_, index) => index)
      );
    }
  }
});

test(
  "generated Wasm resolves exact per-unit dependency names and rejects near misses",
  {
    skip: !process.env.CONVEX_WASM_TEST_CLANG && !process.env.CONVEX_WASM_TEST_LD
  },
  async (t) => {
    const clang = process.env.CONVEX_WASM_TEST_CLANG;
    const linker = process.env.CONVEX_WASM_TEST_LD;
    assert(clang && linker, "Both Wasm compiler and linker are required");
    const directory = mkdtempSync(join(tmpdir(), "convex-selector-"));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    writeFileSync(
      join(directory, "string.h"),
      `#include <stddef.h>
int strcmp(const char *, const char *);
size_t strlen(const char *);
`
    );
    for (const count of [0, 130]) {
      const fixture = await dependencySelectorFixture(count);
      const descriptor = fixture.applicationDescriptor;
      const source = renderConvexWasmModuleGraphLeafSelector({
        ...fixture,
        cohortIndex: 0,
        commonUnits: []
      });
      writeFileSync(
        join(directory, "selector.c"),
        source +
          "\n" +
          descriptor.units
            .map(
              ({ entrySymbol }, index) =>
                `SHUnit *${entrySymbol}(void) { return (SHUnit *)(uintptr_t)${index + 1}; }`
            )
            .join("\n") +
          `
int strcmp(const char *a, const char *b) {
  while (*a && *a == *b) { ++a; ++b; }
  return (unsigned char)*a - (unsigned char)*b;
}
size_t strlen(const char *s) { const char *p = s; while (*p) ++p; return (size_t)(p - s); }
char scratch[4096];
char *scratch_address(void) { return scratch; }
`
      );
      const options = { cwd: directory, timeout: 30_000, maxBuffer: 1024 * 1024 };
      execFileSync(
        clang,
        [
          "--target=wasm32",
          "-ffreestanding",
          "-O2",
          "-fPIC",
          "-I.",
          "-c",
          "selector.c",
          "-o",
          "selector.o"
        ],
        options
      );
      execFileSync(
        linker,
        ["--no-entry", "--export-all", "--allow-undefined", "selector.o", "-o", "selector.wasm"],
        options
      );
      let registeredCallbacks;
      const { exports } = new WebAssembly.Instance(
        new WebAssembly.Module(readFileSync(join(directory, "selector.wasm"))),
        {
          env: {
            convex_wasm_register_application_selector_surface(...callbacks) {
              registeredCallbacks = callbacks;
              return 0;
            }
          }
        }
      );
      exports.__wasm_call_ctors();
      assert.equal(registeredCallbacks.length, 14);
      const registeredLookup = exports.__indirect_function_table.get(registeredCallbacks[5]);
      assert.equal(registeredLookup, exports.convex_wasm_application_chunk_dependency_by_specifier);
      const address = exports.scratch_address();
      const memory = new Uint8Array(exports.memory.buffer);
      const lookup = (slot, specifier) => {
        if (specifier === null) return registeredLookup(slot, 0);
        const bytes = Buffer.from(specifier + "\0");
        assert(bytes.length <= 4096);
        memory.set(bytes, address);
        return registeredLookup(slot, address);
      };
      const allSpecifiers = descriptor.units.flatMap(({ dependencies }) =>
        dependencies.map(({ executableSpecifier }) => executableSpecifier)
      );
      for (const [unitSlot, unit] of descriptor.units.entries()) {
        const expected = new Map(
          unit.dependencies.map(({ executableSpecifier, slot }) => [executableSpecifier, slot])
        );
        for (const specifier of allSpecifiers) {
          assert.equal(lookup(unitSlot, specifier), expected.get(specifier) ?? -1);
        }
        for (const value of [null, "", ".js", "00000000.js", "99999999.js", "not-a-dependency"]) {
          assert.equal(lookup(unitSlot, value), -1);
        }
        for (const { executableSpecifier: valid, slot } of unit.dependencies) {
          assert.equal(lookup(unitSlot, valid), slot);
          // Every truncation, and every single-byte substitution, must be rejected.
          for (let index = 0; index < valid.length; ++index) {
            assert.equal(lookup(unitSlot, valid.slice(0, index)), -1);
            assert.equal(
              lookup(unitSlot, valid.slice(0, index) + "!" + valid.slice(index + 1)),
              -1
            );
          }
          for (const invalid of [
            valid + "x",
            "x" + valid,
            valid.replace(/_[0-9]{8}\.js$/u, "_99999999.js"),
            valid.replace(/_[0-9]{8}\.js$/u, "_0000000/.js"),
            valid.replace(/_[0-9]{8}\.js$/u, "_0000000:.js"),
            valid.replace("import_statement", "dynamic_import")
          ]) {
            assert.equal(lookup(unitSlot, invalid), expected.get(invalid) ?? -1);
          }
        }
      }
      for (const slot of [-2147483648, -1, descriptor.units.length, 2147483647]) {
        assert.equal(lookup(slot, allSpecifiers[0] ?? ""), -1);
      }
      assert.equal(exports.convex_wasm_select_entry(0x0123456789abcdefn), 0);
      assert.equal(
        exports.convex_wasm_selected_exported_unit(),
        descriptor.entries[0].entryPublicationUnitSlot + 1
      );
      assert.equal(exports.convex_wasm_selected_entry_slot(), 0);
      assert.equal(exports.convex_wasm_selected_handler_udf_kind(), 1);
      assert.equal(exports.convex_wasm_select_entry(0n), -1);
      assert.equal(exports.convex_wasm_selected_exported_unit(), 0);
    }
  }
);
