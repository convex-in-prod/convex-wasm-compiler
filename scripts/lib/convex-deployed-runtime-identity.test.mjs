import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  bindDeployedRuntimeIdentity,
  normalizeDeployedRuntimeAuthority,
  verifyFrozenGraphBindingSourceEnvelope,
} from "./convex-deployed-runtime-identity.mjs";
import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import {
  convexWasmSourceEnvelopeKind,
  createConvexWasmSourceEnvelope,
} from "./convex-wasm-source-envelope.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function bundleModule({
  path = "example.js",
  source = "export const value = 1;\n",
  sourceMap = '{"version":3,"sources":["example.ts"],"sourcesContent":[],"mappings":""}\n',
} = {}) {
  const parsedSourceMap = sourceMap === null ? null : JSON.parse(sourceMap);
  return {
    environment: "isolate",
    moduleSha256: sha256(`${source}${sourceMap ?? ""}`),
    path,
    sourceMap:
      sourceMap === null
        ? null
        : {
            sha256: sha256(sourceMap),
            size: Buffer.byteLength(sourceMap),
            sourcesContentCount: 0,
            sourcesCount: 1,
          },
    sourceMembershipSha256:
      parsedSourceMap === null
        ? null
        : convexWasmOfficialOutputSourceMembershipIdentitySha256({
            sourceRoot: parsedSourceMap.sourceRoot,
            sources: parsedSourceMap.sources,
          }),
    sourceSha256: sha256(source),
    sourceSize: Buffer.byteLength(source),
  };
}

function authority(
  module,
  sourcePackageSha256 = sha256("package"),
  sourcePackageRuntimeContentSha256 = sha256("runtime content")
) {
  return normalizeDeployedRuntimeAuthority({
    kind: "convex-deployed-runtime-binding-authority-v1",
    modules: [
      {
        environment: "isolate",
        moduleHashVerified: true,
        moduleSha256: module.moduleSha256,
        path: module.path,
        sourceMap: module.sourceMap,
        sourcePackageHashVerified: true,
        sourcePackageSha256,
        ...(sourcePackageRuntimeContentSha256 === null
          ? {}
          : { sourcePackageRuntimeContentSha256 }),
        sourceSha256: module.sourceSha256,
      },
    ],
    sourcePackageFileSha256: [sourcePackageSha256],
  });
}

function frozenAuthority() {
  const modules = [bundleModule({ path: "first.js" }), bundleModule({ path: "second.js" })];
  const sourcePackageSha256 = sha256("frozen package");
  const identity = {
    kind: "convex-deployed-runtime-binding-authority-v1",
    modules: modules.map((module) => ({
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
  const request = {
    authoritativeDeploymentConfigurationModuleCount: 0,
    authoritativeDeploymentConfigurationModulesSha256: sha256("deployment configuration"),
    authoritativeIsolateModuleCount: 2,
    authoritativeIsolateModulesSha256: sha256("isolate modules"),
    authoritativeModuleCount: 2,
    authoritativeModulesSha256: sha256("all modules"),
    authoritativeNodeModuleCount: 0,
    authoritativeNodeModulesSha256: sha256("node modules"),
    authoritativeUdfIsolateModuleCount: 2,
    authoritativeUdfIsolateModulesSha256: sha256("UDF isolate modules"),
    requestModuleCount: 2,
    requestModulesSha256: sha256("all modules"),
    requestSha256: sha256("start push"),
    requestSize: 123,
    selectedModuleCount: 2,
    selectedModules: modules,
    selectedModulesSha256: fingerprintJson(modules),
    selectedRouteCount: 2,
  };
  const inputPayload = {
    kind: "convex-isolated-full-frozen-graph-input-v1",
    request,
    sourceEnvelope: {
      fileSha256: sha256("source envelope file"),
      fileSize: 456,
      graphSha256: sha256("source graph"),
      kind: convexWasmSourceEnvelopeKind,
      sha256: sha256("source envelope"),
    },
  };
  const bindingPayload = {
    deployedRuntimeAuthoritySha256: fingerprintJson(identity),
    inputAuthority: {
      ...inputPayload,
      inputAuthoritySha256: fingerprintJson(inputPayload),
    },
    kind: "convex-isolated-full-frozen-graph-binding-v1",
    runtimeModulePaths: modules.map(({ path }) => path),
    sourcePackage: { sha256: sourcePackageSha256, size: 789 },
  };
  return {
    ...identity,
    authoritySha256: fingerprintJson(identity),
    frozenGraphBinding: {
      ...bindingPayload,
      bindingSha256: fingerprintJson(bindingPayload),
    },
  };
}

function rehashFrozenAuthority(authorityValue) {
  const inputAuthority = authorityValue.frozenGraphBinding.inputAuthority;
  const { inputAuthoritySha256: ignoredInputSha256, ...inputPayload } = inputAuthority;
  inputAuthority.inputAuthoritySha256 = fingerprintJson(inputPayload);
  const binding = authorityValue.frozenGraphBinding;
  const { bindingSha256: ignoredBindingSha256, ...bindingPayload } = binding;
  binding.bindingSha256 = fingerprintJson(bindingPayload);
}

function frozenSourceEnvelope() {
  return createConvexWasmSourceEnvelope({
    graphSession: {
      bundleModulesByPath: new Map([
        ["first.js", {}],
        ["second.js", {}],
      ]),
      contextReuseAnalysisIdentity: {
        entries: ["convex/first.ts", "convex/second.ts"],
        kind: "convex-context-reuse-analysis",
        policyFingerprint: sha256("context-reuse policy"),
        resultSha256: sha256("context-reuse result"),
      },
      contextReuseEnabledByEntry: new Map([
        ["convex/first.ts", true],
        ["convex/second.ts", true],
      ]),
      dependencyGraphByEntry: new Map([
        ["convex/first.ts", { sha256: sha256("first dependency graph") }],
        ["convex/second.ts", { sha256: sha256("second dependency graph") }],
      ]),
      effectExecutionMode: "guest-promise-event-loop",
      graphSha256: sha256("source graph"),
      inputCount: 2,
      runtimeModulePathByEntry: new Map([
        ["convex/first.ts", "first.js"],
        ["convex/second.ts", "second.js"],
      ]),
      toolchain: { convex: "fixture", esbuild: "fixture" },
    },
    inventory: {
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
      snapshot: { sha256: sha256("inventory") },
    },
    selectedExports: [
      { exportName: "first", modulePath: "first" },
      { exportName: "second", modulePath: "second" },
    ],
  });
}

function bindFrozenSourceEnvelope(authorityValue, sourceEnvelope) {
  const bytes = Buffer.from(`${canonicalJson(sourceEnvelope)}\n`);
  authorityValue.frozenGraphBinding.inputAuthority.sourceEnvelope = {
    fileSha256: sha256(bytes),
    fileSize: bytes.length,
    graphSha256: sourceEnvelope.graph.sha256,
    kind: sourceEnvelope.kind,
    sha256: sourceEnvelope.sourceEnvelopeSha256,
  };
  rehashFrozenAuthority(authorityValue);
}

test("exact installed-Convex bytes prove a binding without sourcesContent", () => {
  const module = bundleModule();
  const deployedAuthority = authority(module);
  const first = bindDeployedRuntimeIdentity({
    authority: deployedAuthority,
    bundleModule: module,
    runtimeModulePath: module.path,
  });
  const second = bindDeployedRuntimeIdentity({
    authority: deployedAuthority,
    bundleModule: module,
    runtimeModulePath: module.path,
  });

  assert.deepEqual(first, second);
  assert.deepEqual(first, {
    diagnostic: null,
    identity: {
      kind: "convex-deployed-runtime-module-v2",
      moduleSha256: module.moduleSha256,
      sourcePackageRuntimeContentSha256: sha256("runtime content"),
    },
  });
  assert.equal(module.sourceMap.sourcesContentCount, 0);
});

test("changed JavaScript and source-map bytes fail closed with distinct diagnostics", () => {
  const deployed = bundleModule();
  const deployedAuthority = authority(deployed);
  const changedJavaScript = bundleModule({ source: "export const value = 2;\n" });
  const changedSourceMap = bundleModule({
    sourceMap: '{"version":3,"sources":["moved/example.ts"],"sourcesContent":[],"mappings":""}\n',
  });

  const javascriptBinding = bindDeployedRuntimeIdentity({
    authority: deployedAuthority,
    bundleModule: changedJavaScript,
    runtimeModulePath: deployed.path,
  });
  const sourceMapBinding = bindDeployedRuntimeIdentity({
    authority: deployedAuthority,
    bundleModule: changedSourceMap,
    runtimeModulePath: deployed.path,
  });

  assert.equal(javascriptBinding.identity, null);
  assert.deepEqual(
    javascriptBinding.diagnostic.reasons.map(({ code }) => code),
    ["AUTHORITATIVE_BUNDLE_JAVASCRIPT_MISMATCH"]
  );
  assert.equal(sourceMapBinding.identity, null);
  assert.deepEqual(
    sourceMapBinding.diagnostic.reasons.map(({ code }) => code),
    ["AUTHORITATIVE_BUNDLE_SOURCE_MAP_MISMATCH"]
  );
});

test("source-package storage-only changes do not change semantic module identity", () => {
  const module = bundleModule();
  const firstPackage = sha256("first package");
  const secondPackage = sha256("second package");
  const runtimeContentSha256 = sha256("same runtime content");
  const first = bindDeployedRuntimeIdentity({
    authority: authority(module, firstPackage, runtimeContentSha256),
    bundleModule: module,
    runtimeModulePath: module.path,
  });
  const second = bindDeployedRuntimeIdentity({
    authority: authority(module, secondPackage, runtimeContentSha256),
    bundleModule: module,
    runtimeModulePath: module.path,
  });

  assert.deepEqual(first.identity, second.identity);
  assert.throws(
    () =>
      normalizeDeployedRuntimeAuthority({
        kind: "convex-deployed-runtime-binding-authority-v1",
        modules: [
          {
            environment: "isolate",
            moduleHashVerified: true,
            moduleSha256: module.moduleSha256,
            path: module.path,
            sourceMap: module.sourceMap,
            sourcePackageHashVerified: true,
            sourcePackageSha256: secondPackage,
            sourceSha256: module.sourceSha256,
          },
        ],
        sourcePackageFileSha256: [firstPackage],
      }),
    /without authenticated blob material/u
  );
});

test("legacy source packages without a runtime-content digest are unprovable", () => {
  const module = bundleModule();
  const binding = bindDeployedRuntimeIdentity({
    authority: authority(module, sha256("legacy package"), null),
    bundleModule: module,
    runtimeModulePath: module.path,
  });

  assert.equal(binding.identity, null);
  assert.equal(binding.diagnostic.verdict, "unprovable");
  assert.deepEqual(
    binding.diagnostic.reasons.map(({ code }) => code),
    ["DEPLOYED_SOURCE_PACKAGE_RUNTIME_CONTENT_DIGEST_NOT_FOUND"]
  );
});

test("missing authority and missing bundle output remain structured unprovable results", () => {
  const module = bundleModule();
  const withoutAuthority = bindDeployedRuntimeIdentity({
    authority: undefined,
    bundleModule: module,
    runtimeModulePath: module.path,
  });
  const withoutBundle = bindDeployedRuntimeIdentity({
    authority: authority(module),
    bundleModule: undefined,
    runtimeModulePath: module.path,
  });

  assert.equal(withoutAuthority.diagnostic.verdict, "unprovable");
  assert.equal(
    withoutAuthority.diagnostic.reasons[0].code,
    "DEPLOYED_RUNTIME_AUTHORITY_NOT_PROVIDED"
  );
  assert.equal(withoutBundle.diagnostic.verdict, "unprovable");
  assert.equal(withoutBundle.diagnostic.reasons[0].code, "AUTHORITATIVE_BUNDLE_MODULE_NOT_FOUND");
});

test("normalizes a complete frozen-graph binding without changing base authority identity", () => {
  const value = frozenAuthority();
  const normalized = normalizeDeployedRuntimeAuthority(value);

  assert.equal(normalized.sha256, value.authoritySha256);
  assert.equal(normalized.frozenGraphBinding.bindingSha256, value.frozenGraphBinding.bindingSha256);
  assert.deepEqual(normalized.frozenGraphBindingIdentity, {
    kind: "convex-isolated-full-frozen-graph-binding-v1",
    sha256: value.frozenGraphBinding.bindingSha256,
  });
});

test("rejects independently tampered frozen-graph binding material", () => {
  const cases = [
    {
      message: /binding digest is invalid/u,
      mutate: (value) => {
        value.frozenGraphBinding.sourcePackage.size += 1;
      },
    },
    {
      message: /input authority digest is invalid/u,
      mutate: (value) => {
        value.frozenGraphBinding.inputAuthority.request.requestSize += 1;
        const binding = value.frozenGraphBinding;
        const { bindingSha256: ignoredBindingSha256, ...bindingPayload } = binding;
        binding.bindingSha256 = fingerprintJson(bindingPayload);
      },
    },
    {
      message: /does not reference the normalized deployed-runtime authority/u,
      mutate: (value) => {
        value.frozenGraphBinding.deployedRuntimeAuthoritySha256 = sha256("other authority");
        rehashFrozenAuthority(value);
      },
    },
    {
      message: /runtime module paths differ from its input authority/u,
      mutate: (value) => {
        value.frozenGraphBinding.runtimeModulePaths.reverse();
        rehashFrozenAuthority(value);
      },
    },
    {
      message: /module second\.js differs from runtime authority/u,
      mutate: (value) => {
        const request = value.frozenGraphBinding.inputAuthority.request;
        request.selectedModules[1].moduleSha256 = sha256("other module");
        request.selectedModulesSha256 = fingerprintJson(request.selectedModules);
        rehashFrozenAuthority(value);
      },
    },
    {
      message: /source package differs from runtime authority/u,
      mutate: (value) => {
        value.frozenGraphBinding.sourcePackage.sha256 = sha256("other package");
        rehashFrozenAuthority(value);
      },
    },
    {
      message: /source-envelope file size must be a positive safe integer/u,
      mutate: (value) => {
        value.frozenGraphBinding.inputAuthority.sourceEnvelope.fileSize = 0;
        rehashFrozenAuthority(value);
      },
    },
  ];

  for (const { message, mutate } of cases) {
    const value = frozenAuthority();
    mutate(value);
    assert.throws(() => normalizeDeployedRuntimeAuthority(value), message);
  }
});

test("links a normalized frozen-graph binding to the exact source-envelope file", () => {
  const sourceEnvelope = frozenSourceEnvelope();
  const value = frozenAuthority();
  bindFrozenSourceEnvelope(value, sourceEnvelope);
  const normalized = normalizeDeployedRuntimeAuthority(value);

  assert.equal(
    verifyFrozenGraphBindingSourceEnvelope({
      normalizedAuthority: normalized,
      sourceEnvelope,
    }).bindingSha256,
    value.frozenGraphBinding.bindingSha256
  );

  assert.throws(
    () =>
      verifyFrozenGraphBindingSourceEnvelope({
        normalizedAuthority: normalized,
        sourceEnvelope,
        sourceEnvelopeFileSha256: sha256("other source envelope file"),
        sourceEnvelopeFileSize: Buffer.byteLength(`${canonicalJson(sourceEnvelope)}\n`),
      }),
    /source-envelope evidence is invalid/u
  );
});
