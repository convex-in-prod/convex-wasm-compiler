import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { gateRevisions } from "./convex-wasm-gate-pins.mjs";
import {
  assertConvexWasmQueryMutationVisibleDeterministicGlobals,
  assertConvexWasmStaticHermesTargetRuntimeGlobals,
  assertConvexWasmStaticHermesTypedDeclarationGlobals,
  canonicalConvexWasmStaticHermesGlobalInventoryJson,
  convexWasmAdmittedStaticHermesGlobals,
  convexWasmApplicationGlobalFacadeEngineGlobals,
  convexWasmQueryMutationVisibleDeterministicGlobals,
  convexWasmRoutingEligibleStaticHermesGlobals,
  convexWasmSharedRuntimeSupportGlobals,
  convexWasmStaticHermesGlobalInventory,
  convexWasmStaticHermesGlobalInventorySha256,
  convexWasmStaticHermesTargetRuntimeGlobals,
  convexWasmStaticHermesTypedDeclarationGlobals,
  validateConvexWasmStaticHermesGlobalInventory,
} from "./convex-wasm-static-hermes-engine-globals.mjs";
import {
  assertConvexWasmTargetRuntimeSurface,
  convexWasmApplicationGlobalThisBinding,
  convexWasmTargetRuntimeSurfacePolicy,
  renderConvexWasmApplicationGlobalFacade,
  renderConvexWasmTargetRuntimeGlobalPrelude,
} from "./convex-wasm-runtime-surface.mjs";

test("provenance refresh preserves both policies and emitted hardening while evidence stays checked", (t) => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const fixture = mkdtempSync(join(tmpdir(), "hermes-policy-"));
  t.after(() => rmSync(fixture, { recursive: true, force: true }));
  for (const file of [
    "scripts/lib/convex-wasm-static-hermes-engine-globals.mjs",
    "scripts/lib/convex-wasm-runtime-surface.mjs",
    "scripts/lib/convex-wasm-intrinsic-hardening.mjs",
    "scripts/lib/convex-wasm-runtime-support.mjs",
    "scripts/convex-wasm-static-hermes-engine-globals.json",
    "scripts/convex-wasm-static-hermes-global-probe-report.json",
    "scripts/convex-wasm-runtime-surface-policy-identity.json",
    "scripts/generate-convex-wasm-static-hermes-global-probe.mjs",
    "scripts/test-fixtures/convex-wasm-runtime-surface/static-hermes-global-probe.js",
    "scripts/lib/convex-wasm-static-hermes-global-probe-runtime-main.cpp",
  ]) {
    mkdirSync(dirname(join(fixture, file)), { recursive: true });
    copyFileSync(join(root, file), join(fixture, file));
  }
  symlinkSync(join(root, "scripts/vendor"), join(fixture, "scripts/vendor"));
  symlinkSync(join(root, "node_modules"), join(fixture, "node_modules"));
  const inspect = () => JSON.parse(execFileSync(process.execPath, ["--input-type=module", "--eval", `
    import * as globals from './scripts/lib/convex-wasm-static-hermes-engine-globals.mjs';
    import * as surface from './scripts/lib/convex-wasm-runtime-surface.mjs';
    import * as hardening from './scripts/lib/convex-wasm-intrinsic-hardening.mjs';
    console.log(JSON.stringify({
      inventory: globals.convexWasmStaticHermesGlobalInventorySha256,
      identity: surface.convexWasmTargetRuntimeSurfacePolicyIdentity,
      hardening: hardening.convexWasmIntrinsicHardeningPolicySha256,
      legacySource: hardening.convexWasmIntrinsicHardeningSourceSha256,
      nativeSource: hardening.convexWasmNativeIntrinsicHardeningSourceSha256,
    }));
  `], { cwd: fixture, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const before = inspect();
  const inventoryPath = join(fixture, "scripts/convex-wasm-static-hermes-engine-globals.json");
  const reportPath = join(fixture, "scripts/convex-wasm-static-hermes-global-probe-report.json");
  const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
  const report = JSON.parse(readFileSync(reportPath, "utf8"));
  for (const field of ["buildRevision", "sourceRevision", "observedCheckoutRevision"]) {
    report.build[field] = inventory.sourceIdentity[field] = "1".repeat(40);
  }
  for (const [field, material] of [
    ["libhermesDeclarationSha256", report.build.sourceMaterials.libhermesDeclaration],
    ["typedArraysDeclarationSha256", report.build.sourceMaterials.typedArraysDeclaration],
    ["globalObjectSourceSha256", report.build.sourceMaterials.globalObject],
    ["hostCmakeCacheSha256", report.build.cmake.host.identity],
    ["hostShermesSha256", report.tools.shermes],
    ["wasmCmakeCacheSha256", report.build.cmake.wasm.identity],
    ["wasmLibhermesvmArchiveSha256", report.target.wasmLibhermesvmArchive],
  ]) {
    material.sha256 = inventory.sourceIdentity[field] = "2".repeat(64);
  }
  const writeEvidence = () => {
    const { reportSha256: _previous, ...payload } = report;
    report.reportSha256 = createHash("sha256")
      .update(canonicalConvexWasmStaticHermesGlobalInventoryJson(payload)).digest("hex");
    const bytes = `${JSON.stringify(report, null, 2)}\n`;
    inventory.targetRuntimeProbe.reportSha256 = report.reportSha256;
    inventory.targetRuntimeProbe.reportFileSha256 = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(reportPath, bytes);
    writeFileSync(inventoryPath, JSON.stringify(inventory));
  };
  writeEvidence();
  const after = inspect();
  assert.notEqual(after.inventory, before.inventory);
  assert.deepEqual({ ...after, inventory: before.inventory }, before);

  inventory.targetRuntimeProbe.reportFileSha256 = "0".repeat(64);
  writeFileSync(inventoryPath, JSON.stringify(inventory));
  assert.throws(inspect, /probe report is not bound by the inventory/u);
  writeEvidence();

  // A real surface change must invalidate the stored identity and both emitted
  // validators, even if all build provenance stays the same.
  inventory.targetRuntimeProbe.globals.push("zFixtureGlobal");
  inventory.semantics.zFixtureGlobal = {
    class: "deterministic-ecmascript",
    provider: "engine-runtime-untyped+typed-bridge",
    read: { state: "admitted" },
  };
  for (const snapshot of Object.values(report.observation)) {
    snapshot.keys.push("zFixtureGlobal");
    snapshot.valueTypes.zFixtureGlobal = "function";
  }
  writeEvidence();
  assert.throws(inspect, /runtime-surface policy identity is stale/u);
  execFileSync(process.execPath, ["scripts/lib/convex-wasm-runtime-surface.mjs", "--write-identity"], { cwd: fixture });
  const changed = inspect();
  assert.notEqual(changed.identity.inventorySha256, after.identity.inventorySha256);
  assert.notEqual(changed.identity.runtimeSurfacePolicySha256, after.identity.runtimeSurfacePolicySha256);
  for (const field of ["hardening", "legacySource", "nativeSource"]) {
    assert.notEqual(changed[field], after[field], field);
  }
});

test("admits ordinary pinned runtime globals from availability and access policy", () => {
  assert.equal(convexWasmStaticHermesTargetRuntimeGlobals.length, 71);
  assert.equal(convexWasmStaticHermesGlobalInventorySha256.length, 64);
  for (const name of ["TextDecoder", "atob", "btoa", "queueMicrotask"]) {
    assert.equal(convexWasmStaticHermesTargetRuntimeGlobals.includes(name), true, name);
    assert.equal(convexWasmStaticHermesTypedDeclarationGlobals.includes(name), false, name);
  }
  for (const name of ["TextDecoder", "atob", "btoa", "queueMicrotask"]) {
    assert.equal(convexWasmAdmittedStaticHermesGlobals.includes(name), true, name);
    assert.equal(convexWasmRoutingEligibleStaticHermesGlobals.includes(name), true, name);
    assert.equal(
      convexWasmStaticHermesGlobalInventory.semantics[name].class,
      "deterministic-web-like",
      name
    );
    assert.equal(
      convexWasmStaticHermesGlobalInventory.semantics[name].provider,
      "engine-runtime-untyped+typed-bridge",
      name
    );
  }
  assert.equal(convexWasmStaticHermesTypedDeclarationGlobals.includes("Worker"), true);
  assert.equal(convexWasmStaticHermesTargetRuntimeGlobals.includes("Worker"), false);
  for (const name of ["DOMException", "Intl", "URL", "URLSearchParams"]) {
    assert.equal(convexWasmStaticHermesTargetRuntimeGlobals.includes(name), false, name);
    assert.equal(convexWasmStaticHermesTypedDeclarationGlobals.includes(name), false, name);
    assert.equal(convexWasmSharedRuntimeSupportGlobals.includes(name), true, name);
    assert.equal(convexWasmRoutingEligibleStaticHermesGlobals.includes(name), true, name);
    assert.equal(
      convexWasmStaticHermesGlobalInventory.semantics[name].provider,
      "shared-untyped-runtime-support",
      name
    );
    assert.equal(
      convexWasmStaticHermesGlobalInventory.semantics[name].read.state,
      "admitted",
      name
    );
  }
  assert.equal(convexWasmAdmittedStaticHermesGlobals.includes("TextEncoder"), true);
  assert.equal(convexWasmRoutingEligibleStaticHermesGlobals.includes("TextEncoder"), true);
  assert.equal(convexWasmStaticHermesGlobalInventory.semantics.TextDecoder.access, undefined);
  assert.equal(convexWasmAdmittedStaticHermesGlobals.includes("AggregateError"), true);
  assert.equal(convexWasmRoutingEligibleStaticHermesGlobals.includes("AggregateError"), true);
  assert.equal(
    convexWasmStaticHermesGlobalInventory.semantics.Iterator.provider,
    "engine-runtime-untyped+typed-bridge"
  );
  const runtimeGlobals = new Set(convexWasmStaticHermesTargetRuntimeGlobals);
  for (const [name, semantic] of Object.entries(convexWasmStaticHermesGlobalInventory.semantics)) {
    if (
      runtimeGlobals.has(name) &&
      ["deterministic-ecmascript", "deterministic-web-like"].includes(semantic.class)
    ) {
      assert.equal(semantic.read.state, "admitted", name);
      assert.equal(convexWasmRoutingEligibleStaticHermesGlobals.includes(name), true, name);
    }
  }
  const targetPrelude = renderConvexWasmTargetRuntimeGlobalPrelude();
  for (const name of ["Iterator", "Promise", "TextDecoder", "atob", "btoa", "queueMicrotask"]) {
    assert.match(
      targetPrelude,
      new RegExp(`const ${name}: any = __convexTargetGlobal\\.${name};`, "u")
    );
  }
  assert.equal(Object.hasOwn(convexWasmStaticHermesGlobalInventory, "conformanceFixtures"), false);
  assert.equal(Object.hasOwn(convexWasmStaticHermesGlobalInventory, "semanticEvidence"), false);
  assert.equal(Object.hasOwn(convexWasmStaticHermesGlobalInventory, "semanticPolicies"), false);
  assert.equal(convexWasmApplicationGlobalFacadeEngineGlobals.includes("Object"), true);
  for (const name of ["Date", "Math", "globalThis", "eval", "gc", "print"]) {
    assert.equal(convexWasmApplicationGlobalFacadeEngineGlobals.includes(name), false, name);
  }
  assert.deepEqual(convexWasmStaticHermesGlobalInventory.accessPolicy, {
    applicationGlobalFacade: "inventory-derived-extensible-null-prototype-immutable-builtins",
    applicationGlobalFacadeComputedAccess: "admitted",
    applicationGlobalFacadeFlow: "admitted",
    globalBindingWrites: "rejected",
    rawGlobalObjectFlow: "rejected",
  });
});

test("binds only global availability and value types from the target probe", () => {
  const report = JSON.parse(
    readFileSync(
      new URL("../convex-wasm-static-hermes-global-probe-report.json", import.meta.url),
      "utf8"
    )
  );
  for (const field of ["raw", "effectiveFirst", "effectiveSecond"]) {
    const snapshot = report.observation[field];
    assert.deepEqual(Object.keys(snapshot).sort(), ["keys", "valueTypes"]);
    assert.deepEqual(Object.keys(snapshot.valueTypes).sort(), [...snapshot.keys].sort());
    assert.equal(snapshot.valueTypes.atob, "function");
    assert.equal(snapshot.valueTypes.btoa, "function");
  }
});

test("fails closed on runtime, typed-declaration, and classification drift", () => {
  assert.doesNotThrow(() =>
    assertConvexWasmStaticHermesTargetRuntimeGlobals([
      ...convexWasmStaticHermesTargetRuntimeGlobals,
    ])
  );
  assert.doesNotThrow(() =>
    assertConvexWasmQueryMutationVisibleDeterministicGlobals([
      ...convexWasmQueryMutationVisibleDeterministicGlobals,
    ])
  );
  assert.doesNotThrow(() =>
    assertConvexWasmStaticHermesTypedDeclarationGlobals([
      ...convexWasmStaticHermesTypedDeclarationGlobals,
    ])
  );
  const addedRuntimeGlobal = [
    ...convexWasmStaticHermesTargetRuntimeGlobals,
    "zFixtureGlobal",
  ].sort();
  assert.throws(
    () => assertConvexWasmStaticHermesTargetRuntimeGlobals(addedRuntimeGlobal),
    /added=\["zFixtureGlobal"\], removed=\[\]/u
  );
  assert.throws(
    () =>
      assertConvexWasmQueryMutationVisibleDeterministicGlobals(
        [...convexWasmQueryMutationVisibleDeterministicGlobals, "zFixtureGlobal"].sort()
      ),
    /added=\["zFixtureGlobal"\], removed=\[\]/u
  );
  assert.throws(
    () =>
      assertConvexWasmQueryMutationVisibleDeterministicGlobals(
        convexWasmQueryMutationVisibleDeterministicGlobals.filter((name) => name !== "URL")
      ),
    /added=\[\], removed=\["URL"\]/u
  );
  assert.throws(
    () =>
      assertConvexWasmStaticHermesTargetRuntimeGlobals(
        convexWasmStaticHermesTargetRuntimeGlobals.filter((name) => name !== "atob")
      ),
    /added=\[\], removed=\["atob"\]/u
  );
  assert.throws(
    () =>
      assertConvexWasmStaticHermesTypedDeclarationGlobals(
        convexWasmStaticHermesTypedDeclarationGlobals.filter((name) => name !== "Worker")
      ),
    /added=\[\], removed=\["Worker"\]/u
  );

  const unclassified = structuredClone(convexWasmStaticHermesGlobalInventory);
  unclassified.targetRuntimeProbe.globals.push("zFixtureGlobal");
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(unclassified),
    /classified Static Hermes globals drifted/u
  );
  const writePolicyWidening = structuredClone(convexWasmStaticHermesGlobalInventory);
  writePolicyWidening.accessPolicy.globalBindingWrites = "admitted";
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(writePolicyWidening),
    /application-facade and raw-global access policies changed/u
  );

  const sourceShapePolicy = structuredClone(convexWasmStaticHermesGlobalInventory);
  sourceShapePolicy.semantics.TextDecoder.access = { kind: "direct-call" };
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(sourceShapePolicy),
    /semantics\.TextDecoder has unsupported or missing fields/u
  );

  const deterministicGap = structuredClone(convexWasmStaticHermesGlobalInventory);
  deterministicGap.semantics.AggregateError.read = {
    gap: "static-hermes-semantic-review",
    state: "gap",
  };
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(deterministicGap),
    /must admit the pinned runtime semantics/u
  );

  const missingTypedBridge = structuredClone(convexWasmStaticHermesGlobalInventory);
  missingTypedBridge.semantics.Iterator.provider = "engine-runtime-untyped";
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(missingTypedBridge),
    /must use the mechanical typed bridge/u
  );

  const unavailableSharedSupport = structuredClone(convexWasmStaticHermesGlobalInventory);
  unavailableSharedSupport.semantics.URL.read = {
    gap: "ambient-global-unavailable",
    state: "gap",
  };
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(unavailableSharedSupport),
    /shared runtime support must be an admitted deterministic global/u
  );

  const sourceRevisionDrift = structuredClone(convexWasmStaticHermesGlobalInventory);
  sourceRevisionDrift.sourceIdentity.sourceRevision = "0".repeat(40);
  assert.throws(
    () => validateConvexWasmStaticHermesGlobalInventory(sourceRevisionDrift),
    /source revision must match the authenticated build revision/u
  );

  for (const legacyField of ["conformanceFixtures", "semanticEvidence", "semanticPolicies"]) {
    const legacyIdentityInput = structuredClone(convexWasmStaticHermesGlobalInventory);
    legacyIdentityInput[legacyField] = {};
    assert.throws(
      () => validateConvexWasmStaticHermesGlobalInventory(legacyIdentityInput),
      /unsupported or missing fields/u,
      legacyField
    );
  }
});

test("binds authenticated build sources to the observed checkout", () => {
  const identity = convexWasmStaticHermesGlobalInventory.sourceIdentity;
  assert.equal(identity.buildRevision, gateRevisions.hermes);
  assert.equal(identity.sourceRevision, identity.buildRevision);
  assert.equal(identity.observedCheckoutRevision, identity.buildRevision);
  for (const field of [
    "hostCmakeCacheSha256",
    "hostShermesSha256",
    "wasmCmakeCacheSha256",
    "wasmLibhermesvmArchiveSha256",
  ]) {
    assert.match(identity[field], /^[a-f0-9]{64}$/u, field);
  }
});

test("rejects every direct write form through the generated admitted-global policy", () => {
  const sources = [
    ...convexWasmAdmittedStaticHermesGlobals.map((name) => `${name} = Object`),
    "Array++",
    "({ Array } = {})",
    "({ value: Promise } = {})",
    "[TextEncoder] = []",
    "Object.prototype = null",
  ];
  for (const source of sources) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(`function selected() { ${source}; }`),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      source
    );
  }
  assert.doesNotThrow(() =>
    assertConvexWasmTargetRuntimeSurface(
      "function selected(Array, Promise, TextEncoder, Object) { Array = Object; Promise++; ({ TextEncoder } = {}); }"
    )
  );
});

test("admits arbitrary ordinary Base64 reads and calls through the application facade", () => {
  for (const source of [
    "return atob('YQ==')",
    "return btoa('a')",
    "const decode = atob; return decode('YQ==')",
    "return atob.call(null, 'YQ==')",
    "return atob(...['YQ=='])",
    "return atob",
  ]) {
    assert.doesNotThrow(() =>
      assertConvexWasmTargetRuntimeSurface(`function selected() { ${source}; }`)
    );
  }
  for (const source of [
    `return ${convexWasmApplicationGlobalThisBinding}.atob('YQ==')`,
    `return ${convexWasmApplicationGlobalThisBinding}.btoa`,
    `const applicationGlobal = ${convexWasmApplicationGlobalThisBinding}; return applicationGlobal['atob']('YQ==')`,
    `return {...${convexWasmApplicationGlobalThisBinding}}.Object`,
    `return ${convexWasmApplicationGlobalThisBinding}.globalThis === ${convexWasmApplicationGlobalThisBinding}`,
  ]) {
    assert.doesNotThrow(() =>
      assertConvexWasmTargetRuntimeSurface(`function selected() { ${source}; }`)
    );
  }
});

test("admits the database UDF timer family and rejects binding writes", () => {
  const timerNames = ["clearInterval", "clearTimeout", "setInterval", "setTimeout"];
  for (const name of timerNames) {
    assert.doesNotThrow(() =>
      assertConvexWasmTargetRuntimeSurface(`function selected() { return ${name}; }`)
    );
    assert.doesNotThrow(() =>
      assertConvexWasmTargetRuntimeSurface(
        `function selected() { return ${convexWasmApplicationGlobalThisBinding}.${name}; }`
      )
    );
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(`function selected() { ${name} = Object; }`),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      name
    );
  }
  assert.deepEqual(
    convexWasmTargetRuntimeSurfacePolicy.globalObject.application.adapterGlobals,
    timerNames
  );
});

test("admits arbitrary ordinary TextDecoder reads, construction, and instance use", () => {
  for (const source of [
    "return new TextDecoder().decode(new Uint8Array([65]))",
    `const decoder = new TextDecoder(args.encoding, args.options);
     const first = decoder.decode(args.first, args.decodeOptions);
     const second = decoder.decode(args.second);
     return [first, second, decoder instanceof TextDecoder]`,
    "return args.value instanceof TextDecoder",
    "const Decoder = TextDecoder; return new Decoder()",
    "return new TextDecoder(...args.values).decode(args.first)",
    "return new TextDecoder(1, 2, 3).decode(args.first)",
    "return new TextDecoder().decode(args.first, {}, 3)",
    "const decoder = new TextDecoder(); return decoder.encoding",
    "const decoder = new TextDecoder(); const decode = decoder.decode; return decode.call(decoder, args.first)",
    "const decoder = new TextDecoder(); return decoder.decode.call(decoder, args.first)",
    "const decoder = new TextDecoder(); return decoder",
    "const decoder = new TextDecoder(); return decoder instanceof Object",
    "return TextDecoder(...args.values)",
    "const decoder = new TextDecoder(); return decoder[args.member](...args.values)",
  ]) {
    assert.doesNotThrow(() =>
      assertConvexWasmTargetRuntimeSurface(`function selected(args) { ${source}; }`)
    );
  }
  assert.doesNotThrow(() =>
    assertConvexWasmTargetRuntimeSurface(
      `function selected() { return new ${convexWasmApplicationGlobalThisBinding}.TextDecoder(); }`
    )
  );
});

test("rejects explicit unsafe runtime facilities", () => {
  for (const name of [
    "$SHBuiltin",
    "FinalizationRegistry",
    "Function",
    "Hermes",
    "HermesAsyncIteratorsInternal",
    "HermesInternal",
    "QuitError",
    "TimeoutError",
    "WeakRef",
    "Worker",
    "eval",
    "gc",
    "print",
  ]) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(`function selected() { return ${name}; }`),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-rejected",
      name
    );
  }
  assert.throws(
    () => assertConvexWasmTargetRuntimeSurface("function selected() { return globalThis; }"),
    (error) =>
      error?.name === "ConvexWasmTargetRuntimeSurfaceGap" && error.code === "raw-global-object-flow"
  );
});

test("renders an extensible application facade with immutable built-ins and rejects rooted writes", () => {
  const facade = renderConvexWasmApplicationGlobalFacade();
  for (const name of ["Object", "TextDecoder", "atob", "btoa", "queueMicrotask"]) {
    assert.match(
      facade,
      new RegExp(`${JSON.stringify(name)}: \\{enumerable: true, value: __convexTargetGlobal`, "u"),
      name
    );
  }
  for (const name of ["clearInterval", "clearTimeout", "setInterval", "setTimeout"]) {
    assert.match(
      facade,
      new RegExp(`${JSON.stringify(name)}: \\{enumerable: true, value: ${name}\\}`, "u"),
      name
    );
  }
  assert.deepEqual(convexWasmTargetRuntimeSurfacePolicy.timers.functions, {
    constructible: false,
    extensible: false,
    implementation: "frozen-arrow-functions",
    state: "implemented",
  });
  for (const name of [
    "DOMException",
    "Math",
    "URL",
    "URLSearchParams",
    "eval",
    "gc",
    "print",
    "$SHBuiltin",
  ]) {
    assert.doesNotMatch(facade, new RegExp(`${JSON.stringify(name)}:`, "u"), name);
  }
  assert.match(facade, /Object\.create\(null\)/u);
  assert.match(
    facade,
    /"globalThis": \{enumerable: true, value: __convexWasmApplicationGlobalThis\}/u
  );
  assert.doesNotMatch(facade, /Object\.freeze\(__convexWasmApplicationGlobalThis\)/u);

  for (const source of [
    `${convexWasmApplicationGlobalThisBinding}.Object = Object`,
    `delete ${convexWasmApplicationGlobalThisBinding}.Object`,
    `({Object: ${convexWasmApplicationGlobalThisBinding}.Object} = {})`,
  ]) {
    assert.throws(
      () => assertConvexWasmTargetRuntimeSurface(`function selected() { ${source}; }`),
      (error) =>
        error?.name === "ConvexWasmTargetRuntimeSurfaceGap" &&
        error.code === "ambient-global-write",
      source
    );
  }
});
