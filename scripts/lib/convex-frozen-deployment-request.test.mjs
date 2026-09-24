import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { brotliDecompressSync } from "node:zlib";
import test from "node:test";

import { version as convexSdkVersion } from "convex";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import { createConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";
import {
  createFrozenPushPreflight,
  executeFrozenPushProtocol,
  inspectFrozenStartPushRequestAgainstFrozenAuthority,
  inspectFrozenStartPushRequest,
  rebindFrozenStartPushAdminKey,
  validateFrozenPushPreflight,
} from "./convex-frozen-deployment-request.mjs";

const digest = (character) => character.repeat(64);

function contextReuseAnalysisIdentity(entries) {
  return {
    entries: [...entries].sort(),
    kind: "convex-context-reuse-analysis",
    policyFingerprint: digest("e"),
    resultSha256: digest("f"),
  };
}

function moduleConfig(
  path,
  source,
  sourceMap = undefined,
  environment = "isolate",
  nodePool = undefined
) {
  return {
    environment,
    ...(nodePool === undefined ? {} : { nodePool }),
    path,
    source,
    ...(sourceMap === undefined ? {} : { sourceMap }),
  };
}

function moduleIdentity(path, source, sourceMap = undefined, environment = "isolate") {
  const parsedSourceMap = sourceMap === undefined ? undefined : JSON.parse(sourceMap);
  return {
    environment,
    moduleSha256: fingerprintBytes(`${source}${sourceMap ?? ""}`),
    path,
    sourceMap:
      sourceMap === undefined
        ? null
        : {
            sha256: fingerprintBytes(sourceMap),
            size: Buffer.byteLength(sourceMap),
            sourcesContentCount: 0,
            sourcesCount: 1,
          },
    sourceMembershipSha256:
      parsedSourceMap === undefined || environment === "node"
        ? null
        : convexWasmOfficialOutputSourceMembershipIdentitySha256({
            sourceRoot: parsedSourceMap.sourceRoot,
            sources: parsedSourceMap.sources,
          }),
    sourceSha256: fingerprintBytes(source),
    sourceSize: Buffer.byteLength(source),
  };
}

function fixture(kind = "convex-wasm-deployment-v2") {
  const source = "export const read = 1;\n";
  const sourceMap = JSON.stringify({
    mappings: "",
    names: [],
    sources: ["../convex/read.ts"],
    sourcesContent: [],
    version: 3,
  });
  const graphModule = moduleIdentity("read.js", source, sourceMap);
  const graphSha256 = digest("1");
  const manifestWithoutIdentity = {
    counts: {
      ...(kind === "convex-wasm-deployment-v4" ? { artifactFallback: 0 } : {}),
      eligible: 1,
      selectedWasm: 1,
      total: 1,
      unselectedEligible: 0,
    },
    exports: [
      {
        entryPath: "convex/read.ts",
        exportName: "read",
        routing: { decision: "wasm" },
        runtimeModulePath: "read.js",
        udfKind: "query",
      },
    ],
    graph: { sha256: graphSha256 },
    kind,
    mode: "compile",
  };
  const deploymentManifest = {
    ...manifestWithoutIdentity,
    deploymentSha256: fingerprintJson(manifestWithoutIdentity),
  };
  const request = {
    adminKey: "local-admin-key",
    appDefinition: {
      changedModules: [moduleConfig("read.js", source, sourceMap)],
      unchangedModuleHashes: [],
    },
    componentDefinitions: [],
    dryRun: false,
    forCodegen: false,
    functions: "convex/",
    nodeDependencies: [],
  };
  return {
    deploymentManifest,
    graphSession: {
      bundleModulesByPath: new Map([["read.js", graphModule]]),
      deploymentConfigurationModulesByPath: new Map(),
      graphSha256,
      nodeModulesByPath: new Map(),
    },
    request,
    requestBytes: Buffer.from(JSON.stringify(request)),
  };
}

function fingerprintBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function preflightForFixture(value) {
  const inspected = inspectFrozenStartPushRequest(value);
  return createFrozenPushPreflight({
    deploymentManifest: value.deploymentManifest,
    deploymentManifestFileSha256: digest("2"),
    requestEvidence: inspected.evidence,
    target: {
      backend: { database: "convex_wasm_ab", instanceName: "convex-wasm-ab" },
    },
  });
}

function preflightForRequestBytes(preflight, requestBytes) {
  const changed = structuredClone(preflight);
  changed.request.requestSha256 = fingerprintBytes(requestBytes);
  changed.request.requestSize = requestBytes.length;
  delete changed.preflightSha256;
  changed.preflightSha256 = fingerprintJson(changed);
  return changed;
}

function frozenAuthorityFixture() {
  const firstSource = "export const first = 1;\n";
  const secondSource = "export const second = 2;\n";
  const firstSourceMap = JSON.stringify({
    mappings: "",
    names: [],
    sources: ["../convex/first.ts"],
    sourcesContent: [],
    version: 3,
  });
  const secondSourceMap = JSON.stringify({
    mappings: "",
    names: [],
    sources: ["../convex/second.ts"],
    sourcesContent: [],
    version: 3,
  });
  const request = {
    adminKey: "local-request-only-placeholder",
    appDefinition: {
      changedModules: [
        moduleConfig("first.js", firstSource, firstSourceMap),
        moduleConfig("second.js", secondSource, secondSourceMap),
      ],
      unchangedModuleHashes: [],
    },
    componentDefinitions: [],
    dryRun: false,
    forCodegen: false,
    functions: "convex/",
    nodeDependencies: [],
  };
  const requestBytes = Buffer.from(canonicalJson(request));
  const graphSha256 = digest("a");
  const graphSession = {
    bundleModulesByPath: new Map([
      ["first.js", moduleIdentity("first.js", firstSource, firstSourceMap)],
      ["second.js", moduleIdentity("second.js", secondSource, secondSourceMap)],
    ]),
    contextReuseAnalysisIdentity: contextReuseAnalysisIdentity([
      "convex/first.ts",
      "convex/second.ts",
    ]),
    contextReuseEnabledByEntry: new Map([
      ["convex/first.ts", true],
      ["convex/second.ts", true],
    ]),
    dependencyGraphByEntry: new Map([
      ["convex/first.ts", { sha256: digest("b") }],
      ["convex/second.ts", { sha256: digest("c") }],
    ]),
    deploymentConfigurationModulesByPath: new Map(),
    effectExecutionMode: "guest-promise-event-loop",
    graphSha256,
    inputCount: 2,
    nodeModulesByPath: new Map(),
    runtimeModulePathByEntry: new Map([
      ["convex/first.ts", "first.js"],
      ["convex/second.ts", "second.js"],
    ]),
    toolchain: { convex: "fixture", esbuild: "fixture" },
  };
  const inventory = {
    actions: [],
    functions: [
      {
        entryPath: "convex/first.ts",
        exportName: "first",
        modulePath: "first",
        udfKind: "query",
        visibility: "public",
      },
      {
        entryPath: "convex/second.ts",
        exportName: "second",
        modulePath: "second",
        udfKind: "mutation",
        visibility: "internal",
      },
    ],
    kind: "convex-generated-api-inventory-v1",
    snapshot: { sha256: digest("d") },
  };
  const sourceAuthority = createConvexWasmSourceEnvelope({
    graphSession,
    inventory,
    selectedExports: [
      { exportName: "first", modulePath: "first" },
      { exportName: "second", modulePath: "second" },
    ],
  });
  const sourceAuthorityBytes = Buffer.from(`${canonicalJson(sourceAuthority)}\n`);
  const sourceInspected = inspectFrozenStartPushRequest({
    graphSession,
    inventory,
    requestBytes,
    sourceAuthority,
  });
  const sourcePackageBytes = Buffer.from("frozen source package");
  const sourcePackageSha256 = fingerprintBytes(sourcePackageBytes);
  const identity = {
    kind: "convex-deployed-runtime-binding-authority-v1",
    modules: sourceInspected.evidence.selectedModules.map((module) => ({
      environment: "isolate",
      moduleHashVerified: true,
      moduleSha256: module.moduleSha256,
      path: module.path,
      sourceMap: module.sourceMap,
      sourcePackageHashVerified: true,
      sourcePackageSha256,
      sourceSha256: module.sourceSha256,
    })),
    sourcePackageFileSha256: [sourcePackageSha256],
  };
  const inputPayload = {
    kind: "convex-isolated-full-frozen-graph-input-v1",
    request: sourceInspected.evidence,
    sourceEnvelope: {
      fileSha256: fingerprintBytes(sourceAuthorityBytes),
      fileSize: sourceAuthorityBytes.length,
      graphSha256: sourceAuthority.graph.sha256,
      kind: sourceAuthority.kind,
      sha256: sourceAuthority.sourceEnvelopeSha256,
    },
  };
  const bindingPayload = {
    deployedRuntimeAuthoritySha256: fingerprintJson(identity),
    inputAuthority: {
      ...inputPayload,
      inputAuthoritySha256: fingerprintJson(inputPayload),
    },
    kind: "convex-isolated-full-frozen-graph-binding-v1",
    runtimeModulePaths: sourceInspected.evidence.selectedModules.map(({ path }) => path),
    sourcePackage: { sha256: sourcePackageSha256, size: sourcePackageBytes.length },
  };
  const deployedRuntimeAuthority = {
    ...identity,
    authoritySha256: fingerprintJson(identity),
    frozenGraphBinding: {
      ...bindingPayload,
      bindingSha256: fingerprintJson(bindingPayload),
    },
  };
  return {
    deployedRuntimeAuthority,
    request,
    requestBytes,
    sourceAuthority,
    sourceAuthorityBytes,
    sourcePackageBytes,
  };
}

test("authenticates a push-all-modules request against the installed bundler session", () => {
  const value = fixture();
  const inspected = inspectFrozenStartPushRequest(value);
  assert.equal(inspected.evidence.authoritativeIsolateModuleCount, 1);
  assert.equal(inspected.evidence.authoritativeUdfIsolateModuleCount, 1);
  assert.equal(inspected.evidence.authoritativeDeploymentConfigurationModuleCount, 0);
  assert.equal(inspected.evidence.authoritativeNodeModuleCount, 0);
  assert.equal(inspected.evidence.authoritativeModuleCount, 1);
  assert.equal(
    inspected.evidence.authoritativeModulesSha256,
    inspected.evidence.requestModulesSha256
  );
  assert.equal(inspected.evidence.requestModuleCount, 1);
  assert.equal(inspected.evidence.selectedModuleCount, 1);
  assert.equal(inspected.evidence.selectedRouteCount, 1);
  assert.equal(inspected.evidence.selectedModules[0].path, "read.js");

  const preflight = createFrozenPushPreflight({
    deploymentManifest: value.deploymentManifest,
    deploymentManifestFileSha256: digest("2"),
    requestEvidence: inspected.evidence,
    target: {
      backend: {
        database: "convex_wasm_ab",
        instanceName: "convex-wasm-ab",
      },
      backendContainerId: digest("3"),
    },
  });
  assert.deepEqual(validateFrozenPushPreflight(preflight), preflight);
  assert.throws(
    () =>
      createFrozenPushPreflight({
        deploymentManifest: value.deploymentManifest,
        deploymentManifestFileSha256: digest("2"),
        requestEvidence: inspected.evidence,
        target: {
          backend: {
            database: "convex_self_hosted",
            instanceName: "convex-wasm-ab",
          },
        },
      }),
    /resolves to convex_wasm_ab, not "convex_self_hosted"/u
  );
});

test("rebinds only the frozen admin key and derived request identity", () => {
  const value = fixture();
  value.request.nodeDependencies = [{ name: "impers", version: "0.0.9" }];
  value.request.externalDepsPackage = { id: "admitted-target-package", sha256: digest("a") };
  value.requestBytes = Buffer.from(JSON.stringify(value.request));
  const preflight = preflightForFixture(value);
  const rebound = rebindFrozenStartPushAdminKey({
    adminKey: "ephemeral-admin-key",
    preflight,
    requestBytes: value.requestBytes,
  });
  assert.equal(rebound.request.adminKey, "ephemeral-admin-key");
  assert.deepEqual(rebound.request.externalDepsPackage, value.request.externalDepsPackage);
  assert.equal(
    canonicalJson({ ...rebound.request, adminKey: value.request.adminKey }),
    canonicalJson(value.request)
  );
  for (const [key, storedValue] of Object.entries(preflight.request)) {
    if (key !== "requestSha256" && key !== "requestSize") {
      assert.deepEqual(rebound.evidence[key], storedValue, key);
    }
  }
  assert.equal(rebound.evidence.requestSha256, fingerprintBytes(rebound.requestBytes));
  assert.equal(rebound.evidence.requestSize, rebound.requestBytes.length);
  assert.notEqual(rebound.evidence.requestSha256, preflight.request.requestSha256);
  for (const selection of [
    { ...value.request.externalDepsPackage, id: "different-target-package" },
    { ...value.request.externalDepsPackage, sha256: digest("b") },
  ]) {
    assert.throws(
      () =>
        rebindFrozenStartPushAdminKey({
          adminKey: "ephemeral-admin-key",
          preflight,
          requestBytes: Buffer.from(
            JSON.stringify({ ...value.request, externalDepsPackage: selection })
          ),
        }),
      /do not match their stored preflight/
    );
  }
});

test("rebind rejects changed nonselected module through the complete census", () => {
  const value = fixture();
  const extraSource = "export const other = 2;\n";
  const extraSourceMap = '{"sources":["../convex/other.ts"],"version":3}';
  const extraModule = moduleConfig("other.js", extraSource, extraSourceMap);
  value.graphSession.bundleModulesByPath.set(
    extraModule.path,
    moduleIdentity(extraModule.path, extraModule.source, extraSourceMap)
  );
  value.request.appDefinition.changedModules.push(extraModule);
  value.requestBytes = Buffer.from(JSON.stringify(value.request));
  const preflight = preflightForFixture(value);
  const changedRequest = structuredClone(value.request);
  changedRequest.appDefinition.changedModules.find(({ path }) => path === "other.js").source +=
    "changed\n";
  const changedBytes = Buffer.from(JSON.stringify(changedRequest));
  assert.throws(
    () =>
      rebindFrozenStartPushAdminKey({
        adminKey: "ephemeral-admin-key",
        preflight: preflightForRequestBytes(preflight, changedBytes),
        requestBytes: changedBytes,
      }),
    /module census differs from its stored preflight/u
  );
});

test("rebind rejects changed selected module through its exact identity", () => {
  const value = fixture();
  const preflight = preflightForFixture(value);
  const changedRequest = structuredClone(value.request);
  changedRequest.appDefinition.changedModules[0].source += "changed\n";
  const changedBytes = Buffer.from(JSON.stringify(changedRequest));
  assert.throws(
    () =>
      rebindFrozenStartPushAdminKey({
        adminKey: "ephemeral-admin-key",
        preflight: preflightForRequestBytes(preflight, changedBytes),
        requestBytes: changedBytes,
      }),
    /selected module read\.js differs from its stored preflight/u
  );
});

test("rebind rejects stale frozen request hash and size", () => {
  const value = fixture();
  const preflight = preflightForFixture(value);
  for (const mutate of [
    (changed) => {
      changed.request.requestSha256 = digest("f");
    },
    (changed) => {
      changed.request.requestSize += 1;
    },
  ]) {
    const changed = structuredClone(preflight);
    mutate(changed);
    delete changed.preflightSha256;
    changed.preflightSha256 = fingerprintJson(changed);
    assert.throws(
      () =>
        rebindFrozenStartPushAdminKey({
          adminKey: "ephemeral-admin-key",
          preflight: changed,
          requestBytes: value.requestBytes,
        }),
      /bytes do not match their stored preflight/u
    );
  }
});

test("accepts deployment v4 and rejects unknown or inconsistent deployment contracts", () => {
  const value = fixture("convex-wasm-deployment-v4");
  assert.equal(inspectFrozenStartPushRequest(value).evidence.selectedRouteCount, 1);
  assert.equal(
    inspectFrozenStartPushRequest({
      ...fixture("convex-wasm-deployment-v8"),
    }).evidence.selectedRouteCount,
    1
  );

  for (const mutate of [
    (manifest) => {
      manifest.kind = "convex-wasm-deployment-v5";
    },
    (manifest) => {
      manifest.counts.artifactFallback = 1;
    },
  ]) {
    const deploymentManifest = structuredClone(value.deploymentManifest);
    delete deploymentManifest.deploymentSha256;
    mutate(deploymentManifest);
    deploymentManifest.deploymentSha256 = fingerprintJson(deploymentManifest);
    assert.throws(
      () => inspectFrozenStartPushRequest({ ...value, deploymentManifest }),
      /compiled convex-wasm-deployment-v2, v4, or v8|inconsistent eligible-selection counts/u
    );
  }
});

test("authenticates an explicit source envelope without compiler eligibility claims", () => {
  const value = fixture();
  value.graphSession.inputCount = 1;
  value.graphSession.dependencyGraphByEntry = new Map([
    ["convex/read.ts", { sha256: digest("8") }],
  ]);
  value.graphSession.contextReuseAnalysisIdentity = contextReuseAnalysisIdentity([
    "convex/read.ts",
  ]);
  value.graphSession.contextReuseEnabledByEntry = new Map([["convex/read.ts", true]]);
  value.graphSession.effectExecutionMode = "guest-promise-event-loop";
  value.graphSession.runtimeModulePathByEntry = new Map([["convex/read.ts", "read.js"]]);
  value.graphSession.toolchain = { convex: "fixture", esbuild: "fixture" };
  const inventory = {
    actions: [],
    functions: [
      {
        entryPath: "convex/read.ts",
        exportName: "read",
        modulePath: "read",
        udfKind: "query",
        visibility: "public",
      },
    ],
    kind: "convex-generated-api-inventory-v1",
    snapshot: { sha256: digest("6") },
  };
  const sourceAuthority = createConvexWasmSourceEnvelope({
    graphSession: value.graphSession,
    inventory,
    selectedExports: [{ exportName: "read", modulePath: "read" }],
  });
  const inspected = inspectFrozenStartPushRequest({
    graphSession: value.graphSession,
    inventory,
    requestBytes: value.requestBytes,
    sourceAuthority,
  });
  assert.equal(inspected.evidence.selectedRouteCount, 1);
  assert.equal(inspected.evidence.selectedModules[0].path, "read.js");
  const preflight = createFrozenPushPreflight({
    requestEvidence: inspected.evidence,
    sourceAuthority,
    sourceAuthorityFileSha256: digest("7"),
    target: {
      backend: { database: "convex_wasm_ab", instanceName: "convex-wasm-ab" },
    },
  });
  assert.equal(preflight.kind, "convex-local-frozen-push-preflight-v2");
  assert.equal(preflight.source.kind, "convex-wasm-source-envelope-v2");
  assert.deepEqual(validateFrozenPushPreflight(preflight), preflight);

  const changedInventory = structuredClone(inventory);
  changedInventory.functions[0].visibility = "internal";
  assert.throws(
    () =>
      inspectFrozenStartPushRequest({
        graphSession: value.graphSession,
        inventory: changedInventory,
        requestBytes: value.requestBytes,
        sourceAuthority,
      }),
    /current generated API inventory does not match/u
  );
});

test("authenticates an immutable complete request against frozen deployed-runtime authority", () => {
  const value = frozenAuthorityFixture();
  const inspected = inspectFrozenStartPushRequestAgainstFrozenAuthority({
    deployedRuntimeAuthority: value.deployedRuntimeAuthority,
    requestBytes: value.requestBytes,
    sourceAuthority: value.sourceAuthority,
    sourceAuthorityFileSha256: fingerprintBytes(value.sourceAuthorityBytes),
    sourceAuthorityFileSize: value.sourceAuthorityBytes.length,
    sourcePackageBytes: value.sourcePackageBytes,
  });

  assert.equal(inspected.requestEvidence.requestModuleCount, 2);
  assert.equal(inspected.requestEvidence.selectedModuleCount, 2);
  assert.equal(inspected.binding.sourcePackage.sha256, fingerprintBytes(value.sourcePackageBytes));
  const authorityFileBytes = Buffer.from(canonicalJson(value.deployedRuntimeAuthority));
  const preflight = createFrozenPushPreflight({
    frozenSourceAuthority: {
      authorityFileSha256: fingerprintBytes(authorityFileBytes),
      authoritySha256: inspected.normalizedAuthority.sha256,
      bindingSha256: inspected.binding.bindingSha256,
      sourcePackageSha256: inspected.binding.sourcePackage.sha256,
      sourcePackageSize: inspected.binding.sourcePackage.size,
    },
    requestEvidence: inspected.requestEvidence,
    sourceAuthority: value.sourceAuthority,
    sourceAuthorityFileSha256: fingerprintBytes(value.sourceAuthorityBytes),
    target: {
      backend: { database: "convex_wasm_ab", instanceName: "convex-wasm-ab" },
    },
  });
  assert.equal(preflight.kind, "convex-local-frozen-push-preflight-v3");
  assert.deepEqual(validateFrozenPushPreflight(preflight), preflight);

  const changedRequest = structuredClone(value.request);
  changedRequest.appDefinition.changedModules[1].source += "changed\n";
  assert.throws(
    () =>
      inspectFrozenStartPushRequestAgainstFrozenAuthority({
        deployedRuntimeAuthority: value.deployedRuntimeAuthority,
        requestBytes: Buffer.from(canonicalJson(changedRequest)),
        sourceAuthority: value.sourceAuthority,
        sourceAuthorityFileSha256: fingerprintBytes(value.sourceAuthorityBytes),
        sourceAuthorityFileSize: value.sourceAuthorityBytes.length,
        sourcePackageBytes: value.sourcePackageBytes,
      }),
    /module census differs from deployed-runtime authority/u
  );
  assert.throws(
    () =>
      inspectFrozenStartPushRequestAgainstFrozenAuthority({
        deployedRuntimeAuthority: value.deployedRuntimeAuthority,
        requestBytes: value.requestBytes,
        sourceAuthority: value.sourceAuthority,
        sourceAuthorityFileSha256: fingerprintBytes(value.sourceAuthorityBytes),
        sourceAuthorityFileSize: value.sourceAuthorityBytes.length,
        sourcePackageBytes: Buffer.from("changed source package"),
      }),
    /source-package bytes do not match/u
  );
});

test("rejects isolate modules without authenticated source-membership provenance", () => {
  const value = fixture();
  const invalidSourceMaps = [
    {
      description: "missing source map",
      mutate(module) {
        delete module.sourceMap;
      },
      pattern: /isolate module must contain source-map provenance/u,
    },
    {
      description: "invalid source-map JSON",
      mutate(module) {
        module.sourceMap = "{";
      },
      pattern: /source map is not valid JSON/u,
    },
    {
      description: "invalid source-map schema",
      mutate(module) {
        module.sourceMap = JSON.stringify({ sources: [], version: 2 });
      },
      pattern: /source map has invalid source-membership provenance/u,
    },
  ];

  for (const { description, mutate, pattern } of invalidSourceMaps) {
    const request = structuredClone(value.request);
    mutate(request.appDefinition.changedModules[0]);
    assert.throws(
      () =>
        inspectFrozenStartPushRequest({
          ...value,
          requestBytes: Buffer.from(canonicalJson(request)),
        }),
      pattern,
      description
    );
  }
});

test("rejects missing or malformed frozen source-membership authority", () => {
  for (const mutate of [
    (module) => {
      module.sourceMap = null;
    },
    (module) => {
      delete module.sourceMembershipSha256;
    },
    (module) => {
      module.sourceMembershipSha256 = "not-a-digest";
    },
  ]) {
    const value = frozenAuthorityFixture();
    const binding = value.deployedRuntimeAuthority.frozenGraphBinding;
    const inputAuthority = binding.inputAuthority;
    mutate(inputAuthority.request.selectedModules[0]);
    inputAuthority.request.selectedModulesSha256 = fingerprintJson(
      inputAuthority.request.selectedModules
    );
    delete inputAuthority.inputAuthoritySha256;
    inputAuthority.inputAuthoritySha256 = fingerprintJson(inputAuthority);
    delete binding.bindingSha256;
    binding.bindingSha256 = fingerprintJson(binding);

    assert.throws(
      () =>
        inspectFrozenStartPushRequestAgainstFrozenAuthority({
          deployedRuntimeAuthority: value.deployedRuntimeAuthority,
          requestBytes: value.requestBytes,
          sourceAuthority: value.sourceAuthority,
          sourceAuthorityFileSha256: fingerprintBytes(value.sourceAuthorityBytes),
          sourceAuthorityFileSize: value.sourceAuthorityBytes.length,
          sourcePackageBytes: value.sourcePackageBytes,
        }),
      /source-map provenance|source-membership SHA-256|selected module 0 fields are invalid/u
    );
  }
});

test("authenticates every Node module in the complete deployment set", () => {
  const value = fixture();
  const source = '"use node"; export const run = 1;\n';
  const sourceMap = JSON.stringify({
    mappings: "",
    names: [],
    sources: ["../convex/runNode.ts"],
    sourcesContent: [],
    version: 3,
  });
  value.graphSession.nodeModulesByPath.set(
    "runNode.js",
    moduleIdentity("runNode.js", source, sourceMap, "node")
  );
  value.request.appDefinition.changedModules.push(
    moduleConfig("runNode.js", source, sourceMap, "node:pool:workers", "workers")
  );
  value.requestBytes = Buffer.from(JSON.stringify(value.request));

  const inspected = inspectFrozenStartPushRequest(value);
  assert.equal(inspected.evidence.authoritativeNodeModuleCount, 1);
  assert.equal(inspected.evidence.authoritativeModuleCount, 2);
  assert.equal(
    inspected.evidence.authoritativeModulesSha256,
    inspected.evidence.requestModulesSha256
  );

  const mutations = [
    {
      description: "Node source bytes",
      mutate(request) {
        request.appDefinition.changedModules.find(({ path }) => path === "runNode.js").source +=
          "changed\n";
      },
      pattern: /does not match the installed Convex bundler output/u,
    },
    {
      description: "Node source-map bytes",
      mutate(request) {
        request.appDefinition.changedModules.find(({ path }) => path === "runNode.js").sourceMap +=
          " ";
      },
      pattern: /does not match the installed Convex bundler output/u,
    },
    {
      description: "mismatched Node pool metadata",
      mutate(request) {
        request.appDefinition.changedModules.find(({ path }) => path === "runNode.js").nodePool =
          "other";
      },
      pattern: /Node pool metadata must match the module environment/u,
    },
    {
      description: "missing Node module",
      mutate(request) {
        request.appDefinition.changedModules = request.appDefinition.changedModules.filter(
          ({ path }) => path !== "runNode.js"
        );
      },
      pattern: /Node module count 0/u,
    },
    {
      description: "extra Node module",
      mutate(request) {
        request.appDefinition.changedModules.push(
          moduleConfig("extraNode.js", source, sourceMap, "node")
        );
      },
      pattern: /Node module count 2/u,
    },
    {
      description: "wrong Node environment",
      mutate(request) {
        const module = request.appDefinition.changedModules.find(
          ({ path }) => path === "runNode.js"
        );
        module.environment = "isolate";
        delete module.nodePool;
      },
      pattern: /isolate module count 2/u,
    },
  ];
  for (const { description, mutate, pattern } of mutations) {
    const changedRequest = structuredClone(value.request);
    mutate(changedRequest);
    assert.throws(
      () =>
        inspectFrozenStartPushRequest({
          ...value,
          requestBytes: Buffer.from(JSON.stringify(changedRequest)),
        }),
      pattern,
      description
    );
  }
});

test("authenticates the separately bundled auth config in the complete isolate set", () => {
  const value = fixture();
  const source = "export default { providers: [] };\n";
  const sourceMap = JSON.stringify({
    mappings: "",
    names: [],
    sources: ["../convex/auth.config.ts"],
    sourcesContent: [],
    version: 3,
  });
  value.graphSession.deploymentConfigurationModulesByPath.set(
    "auth.config.js",
    moduleIdentity("auth.config.js", source, sourceMap)
  );
  value.request.appDefinition.changedModules.push(
    moduleConfig("auth.config.js", source, sourceMap)
  );
  value.requestBytes = Buffer.from(JSON.stringify(value.request));

  const inspected = inspectFrozenStartPushRequest(value);
  assert.equal(inspected.evidence.authoritativeIsolateModuleCount, 2);
  assert.equal(inspected.evidence.authoritativeUdfIsolateModuleCount, 1);
  assert.equal(inspected.evidence.authoritativeDeploymentConfigurationModuleCount, 1);

  const changedRequest = structuredClone(value.request);
  changedRequest.appDefinition.changedModules.find(
    ({ path }) => path === "auth.config.js"
  ).source += "changed\n";
  assert.throws(
    () =>
      inspectFrozenStartPushRequest({
        ...value,
        requestBytes: Buffer.from(JSON.stringify(changedRequest)),
      }),
    /does not match the installed Convex bundler output/u
  );
});

test("counts multiple selected exports from one authenticated runtime module", () => {
  const value = fixture();
  const manifestWithoutIdentity = {
    ...value.deploymentManifest,
    counts: {
      ...value.deploymentManifest.counts,
      eligible: 2,
      selectedWasm: 2,
    },
    exports: [
      ...value.deploymentManifest.exports,
      {
        ...value.deploymentManifest.exports[0],
        exportName: "readSecond",
      },
    ],
  };
  delete manifestWithoutIdentity.deploymentSha256;
  const deploymentManifest = {
    ...manifestWithoutIdentity,
    deploymentSha256: fingerprintJson(manifestWithoutIdentity),
  };
  const inspected = inspectFrozenStartPushRequest({
    ...value,
    deploymentManifest,
  });
  assert.equal(inspected.evidence.selectedModuleCount, 1);
  assert.equal(inspected.evidence.selectedRouteCount, 2);
});

test("rejects changed bytes, partial module requests, and changed graph material", () => {
  const value = fixture();
  const changedRequest = structuredClone(value.request);
  changedRequest.appDefinition.changedModules[0].source += "changed\n";
  assert.throws(
    () =>
      inspectFrozenStartPushRequest({
        ...value,
        requestBytes: Buffer.from(JSON.stringify(changedRequest)),
      }),
    /does not match the installed Convex bundler output/u
  );

  const partialRequest = structuredClone(value.request);
  partialRequest.appDefinition.unchangedModuleHashes.push({
    environment: "isolate",
    path: "read.js",
    sha256: digest("4"),
  });
  assert.throws(
    () =>
      inspectFrozenStartPushRequest({
        ...value,
        requestBytes: Buffer.from(JSON.stringify(partialRequest)),
      }),
    /all modules/u
  );

  assert.throws(
    () =>
      inspectFrozenStartPushRequest({
        ...value,
        graphSession: { ...value.graphSession, graphSha256: digest("5") },
      }),
    /source graph/u
  );
});

test("applies only start, schema wait, and finish with the exact frozen request", async () => {
  const value = fixture();
  value.request.nodeDependencies = [{ name: "impers", version: "0.0.9" }];
  value.request.externalDepsPackage = { id: "admitted-target-package", sha256: digest("a") };
  value.requestBytes = Buffer.from(JSON.stringify(value.request));
  const sourceKeyedRuntimeActivation = {
    expectedPrior: {
      runtimeGeneration: {
        deploymentSha256: digest("1"),
        generationManifestSha256: digest("2"),
        generationSha256: digest("3"),
      },
      sourcePackageId: "source-package-id",
      sourcePackageRuntimeContentSha256: digest("5"),
      sourcePackageSha256: digest("4"),
    },
    targetGeneration: {
      deploymentSha256: digest("6"),
      generationManifestSha256: digest("7"),
      generationSha256: digest("8"),
    },
  };
  const calls = [];
  const phases = [];
  const responses = [
    {
      analysis: {},
      app: {},
      appAuth: [],
      componentDefinitionPackages: {
        "": {
          runtimeContentSha256: { $bytes: Buffer.from(digest("a"), "hex").toString("base64") },
        },
      },
      environmentVariables: {},
      externalDepsId: null,
      schemaChange: {},
    },
    { type: "complete" },
    { authDiff: {}, componentDiffs: {}, definitionDiffs: {} },
  ];
  const fetchImplementation = async (url, options) => {
    calls.push({ options, path: url.pathname });
    return new Response(JSON.stringify(responses.shift()), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };
  const result = await executeFrozenPushProtocol({
    adminKey: value.request.adminKey,
    expectedSourcePackageRuntimeContentSha256: digest("a"),
    beforeStartPush: async () => {},
    fetchImplementation,
    onPhase: async (phase) => phases.push(phase.phase),
    requestBytes: value.requestBytes,
    requestSha256: fingerprintBytes(value.requestBytes),
    sourceKeyedRuntimeActivation,
    url: "http://127.0.0.1:3210",
  });

  assert.deepEqual(
    calls.map(({ path }) => path),
    ["/api/deploy2/start_push", "/api/deploy2/wait_for_schema", "/api/deploy2/finish_push"]
  );
  assert.deepEqual(phases, [
    "sendingStartPush",
    "startPushReturned",
    "schemaReady",
    "sendingFinishPush",
    "finishPushReturned",
  ]);
  assert.deepEqual(
    JSON.parse(brotliDecompressSync(calls[0].options.body).toString("utf8")),
    value.request
  );
  assert.deepEqual(
    JSON.parse(brotliDecompressSync(calls[2].options.body).toString("utf8"))
      .sourceKeyedRuntimeActivation,
    sourceKeyedRuntimeActivation
  );
  assert.equal(
    calls.every(({ options }) => options.redirect === "error"),
    true
  );
  assert.deepEqual(
    calls.map(({ options }) => options.headers["Convex-Client"]),
    Array(3).fill(`npm-cli-${convexSdkVersion}`)
  );
  assert.equal(typeof result.finishPushSha256, "string");
  const bodyBytes = calls.map(({ options }) => Buffer.byteLength(options.body));
  assert.deepEqual(result.requestBodyBytes, {
    startPush: bodyBytes[0],
    waitForSchema: bodyBytes[1],
    finishPush: bodyBytes[2],
    total: bodyBytes.reduce((total, bytes) => total + bytes, 0),
  });
});

test("push transfer accounting includes every schema poll's encoded UTF-8 body", async () => {
  const value = fixture();
  const responses = [
    { schemaChange: { fixture: "unicode-\u00e9" } },
    { type: "inProgress" },
    { type: "inProgress" },
    { type: "complete" },
    {},
  ];
  const bodies = [];
  const result = await executeFrozenPushProtocol({
    adminKey: value.request.adminKey,
    beforeStartPush: async () => {},
    fetchImplementation: async (_url, options) => {
      bodies.push(Buffer.from(options.body));
      return Response.json(responses.shift());
    },
    requestBytes: value.requestBytes,
    requestSha256: fingerprintBytes(value.requestBytes),
    url: "http://127.0.0.1:3210",
  });
  assert.equal(result.schemaPollCount, 3);
  assert.deepEqual(result.requestBodyBytes, {
    startPush: bodies[0].length,
    waitForSchema: bodies.slice(1, 4).reduce((total, body) => total + body.length, 0),
    finishPush: bodies[4].length,
    total: bodies.reduce((total, body) => total + body.length, 0),
  });
});

for (const returnedDigest of [
  undefined,
  { $bytes: "malformed" },
  { $bytes: Buffer.alloc(32, 1).toString("base64") },
]) {
  test("mismatched or malformed root runtime digest prevents schema wait and finish", async () => {
    const value = fixture();
    const calls = [];
    await assert.rejects(
      executeFrozenPushProtocol({
        adminKey: value.request.adminKey,
        beforeStartPush: async () => {},
        expectedSourcePackageRuntimeContentSha256: digest("a"),
        fetchImplementation: async (url) => {
          calls.push(url.pathname);
          return Response.json({
            schemaChange: {},
            componentDefinitionPackages: { "": { runtimeContentSha256: returnedDigest } },
          });
        },
        requestBytes: value.requestBytes,
        requestSha256: fingerprintBytes(value.requestBytes),
        url: "http://127.0.0.1:3210",
      }),
      /root runtime-content SHA-256/u
    );
    assert.deepEqual(calls, ["/api/deploy2/start_push"]);
  });
}

test("provides an analysis projection callback no complete start_push response", async () => {
  const value = fixture();
  const startPush = {
    analysis: { "": { functions: {} } },
    app: {},
    appAuth: [],
    componentDefinitionPackages: {},
    environmentVariables: { SECRET: "must-not-reach-projection" },
    externalDepsId: null,
    schemaChange: {},
  };
  const responses = [
    startPush,
    { type: "complete" },
    { authDiff: {}, componentDiffs: {}, definitionDiffs: {} },
  ];
  let callbackInput;
  await executeFrozenPushProtocol({
    adminKey: value.request.adminKey,
    beforeStartPush: async () => {},
    fetchImplementation: async () =>
      new Response(JSON.stringify(responses.shift()), {
        headers: { "Content-Type": "application/json" },
        status: 200,
      }),
    onStartPushAnalysisProjection: async (input) => {
      callbackInput = input;
    },
    requestBytes: value.requestBytes,
    requestSha256: fingerprintBytes(value.requestBytes),
    url: "http://127.0.0.1:3210",
  });

  assert.deepEqual(Object.keys(callbackInput).sort(), [
    "analysis",
    "requestSha256",
    "startPushSha256",
  ]);
  assert.deepEqual(callbackInput.analysis, startPush.analysis);
  assert.equal(callbackInput.environmentVariables, undefined);
  assert.equal(callbackInput.requestSha256, fingerprintBytes(value.requestBytes));
  assert.equal(callbackInput.startPushSha256, fingerprintJson(startPush));
});

test("does not retry an ambiguous start_push failure", async () => {
  const value = fixture();
  let calls = 0;
  await assert.rejects(
    executeFrozenPushProtocol({
      adminKey: value.request.adminKey,
      beforeStartPush: async () => {},
      fetchImplementation: async () => {
        calls += 1;
        throw new Error("connection reset");
      },
      requestBytes: value.requestBytes,
      requestSha256: fingerprintBytes(value.requestBytes),
      url: "http://127.0.0.1:3210",
    }),
    /mutation state is unknown/u
  );
  assert.equal(calls, 1);
});

test("reports bounded structured start_push rejection details", async () => {
  const value = fixture();
  await assert.rejects(
    executeFrozenPushProtocol({
      adminKey: value.request.adminKey,
      beforeStartPush: async () => {},
      fetchImplementation: async () =>
        new Response(JSON.stringify({ code: "InvalidDeployment", message: "fixture rejection" }), {
          status: 400,
        }),
      requestBytes: value.requestBytes,
      requestSha256: fingerprintBytes(value.requestBytes),
      url: "http://127.0.0.1:3210",
    }),
    /HTTP 400 with code "InvalidDeployment" and message "fixture rejection"/u
  );
});

test("rechecks the final precondition after compression and before start_push", async () => {
  const value = fixture();
  let calls = 0;
  await assert.rejects(
    executeFrozenPushProtocol({
      adminKey: value.request.adminKey,
      beforeStartPush: async () => {
        throw new Error("runtime registry current changed");
      },
      fetchImplementation: async () => {
        calls += 1;
        throw new Error("must not send");
      },
      requestBytes: value.requestBytes,
      requestSha256: fingerprintBytes(value.requestBytes),
      url: "http://127.0.0.1:3210",
    }),
    /runtime registry current changed/u
  );
  assert.equal(calls, 0);
});
