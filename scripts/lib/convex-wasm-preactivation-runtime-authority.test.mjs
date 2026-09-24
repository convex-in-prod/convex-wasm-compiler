import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";
import {
  normalizeDeployedRuntimeAuthority,
  verifyFrozenGraphBindingSourceEnvelope,
} from "./convex-deployed-runtime-identity.mjs";
import {
  convexRuntimeContentAlgorithm,
  createPreactivationRuntimeAuthority,
  executeRuntimeContentHelperInBackendImage,
  inspectRuntimeContentHelper,
  normalizePreactivationHelperAuthority,
} from "./convex-wasm-preactivation-runtime-authority.mjs";
import { createConvexWasmSourceEnvelope } from "./convex-wasm-source-envelope.mjs";

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function withTemporaryDirectory(execute) {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-preactivation-authority-"));
  try {
    return await execute(directory);
  } finally {
    await fs.rm(directory, { force: true, recursive: true });
  }
}

function runtimeModule({
  environment = "isolate",
  nodePool = null,
  path,
  role = "udfIsolate",
  source,
  sourceMap = null,
}) {
  const sourceMapIdentity =
    sourceMap === null
      ? null
      : {
          sha256: digest(sourceMap),
          size: Buffer.byteLength(sourceMap),
          sourcesContentCount: 1,
          sourcesCount: 1,
        };
  return {
    environment,
    moduleSha256: digest(`${source}${sourceMap ?? ""}`),
    nodePool,
    path,
    role,
    sourceMap: sourceMapIdentity,
    sourceSha256: digest(source),
    sourceSize: Buffer.byteLength(source),
  };
}

function fixture() {
  const firstSource = "export const first = 1;\n";
  const secondSource = "export const second = 2;\n";
  const authConfigSource = "export default {};\n";
  const moduleInputs = [
    {
      path: "first.js",
      source: firstSource,
      sourceMap: JSON.stringify({
        mappings: "",
        names: [],
        sources: ["../convex/first.ts"],
        sourcesContent: [firstSource],
        version: 3,
      }),
    },
    {
      path: "second.js",
      source: secondSource,
      sourceMap: JSON.stringify({
        mappings: "",
        names: [],
        sources: ["../convex/second.ts"],
        sourcesContent: [secondSource],
        version: 3,
      }),
    },
    {
      path: "auth.config.js",
      role: "deploymentConfiguration",
      source: authConfigSource,
      sourceMap: JSON.stringify({
        mappings: "",
        names: [],
        sources: ["../convex/auth.config.ts"],
        sourcesContent: [authConfigSource],
        version: 3,
      }),
    },
    {
      environment: "node",
      nodePool: "workers",
      path: "actions/run.js",
      role: "node",
      source: '"use node"; export default 3;\n',
    },
  ];
  const runtimeModules = moduleInputs.map(runtimeModule);
  const selected = runtimeModules.slice(0, 2);
  const routes = selected.map((module, index) => ({
    entryPath: `convex/${index === 0 ? "first" : "second"}.ts`,
    exportName: index === 0 ? "first" : "second",
    modulePath: index === 0 ? "first" : "second",
    runtimeModulePath: module.path,
    udfKind: "query",
    visibility: "public",
  }));
  const graphSession = {
    bundleModulesByPath: new Map(selected.map((module) => [module.path, module])),
    contextReuseAnalysisIdentity: {
      entries: routes.map(({ entryPath }) => entryPath).sort(),
      kind: "convex-context-reuse-analysis",
      policyFingerprint: digest("context-reuse policy"),
      resultSha256: digest("context-reuse result"),
    },
    contextReuseEnabledByEntry: new Map(routes.map(({ entryPath }) => [entryPath, true])),
    dependencyGraphByEntry: new Map(
      routes.map((route) => [route.entryPath, { sha256: digest(`graph:${route.entryPath}`) }])
    ),
    deploymentConfigurationModulesByPath: new Map(),
    effectExecutionMode: "guest-promise-event-loop",
    graphSha256: digest("fixture graph"),
    inputCount: routes.length,
    nodeModulesByPath: new Map(),
    runtimeModulePathByEntry: new Map(
      routes.map((route) => [route.entryPath, route.runtimeModulePath])
    ),
    toolchain: { convex: "fixture", esbuild: "fixture" },
    verifyBundleEntryPaths: async () => {},
  };
  const inventory = {
    actions: [],
    functions: routes,
    kind: "convex-generated-api-inventory-v1",
    snapshot: { sha256: digest("fixture inventory") },
  };
  const sourceEnvelope = createConvexWasmSourceEnvelope({
    graphSession,
    inventory,
    selectedExports: routes.map(({ exportName, modulePath }) => ({ exportName, modulePath })),
  });
  const startPushBytes = Buffer.from(
    `${canonicalJson({
      appDefinition: {
        changedModules: moduleInputs.map(
          ({ environment = "isolate", nodePool = null, path, source, sourceMap = null }) => ({
            environment: nodePool === null ? environment : `node:pool:${nodePool}`,
            ...(nodePool === null ? {} : { nodePool }),
            path,
            source,
            ...(sourceMap === null ? {} : { sourceMap }),
          })
        ),
      },
      nodeVersion: "24",
      official: "start_push",
    })}\n`
  );
  const sourcePackageBytes = Buffer.from("canonical backend source package bytes");
  const externalDepsPackageBytes = Buffer.from("canonical dependency archive bytes");
  const helper = {
    path: "/owner/source-package-preactivation-authority",
    sha256: "a".repeat(64),
    size: 8192,
  };
  const producerCertificate = {
    externalDepsPackage: {
      sha256: digest(externalDepsPackageBytes),
      size: externalDepsPackageBytes.length,
      storageKey: "external-deps-storage-key",
    },
    identity: {
      dependencies: [
        { package: "impers", version: "0.0.9" },
        { package: "proxy-agent", version: "8.0.2" },
      ],
      helper: { sha256: helper.sha256, size: helper.size },
      runtimeContentAlgorithm: convexRuntimeContentAlgorithm,
    },
  };
  const helperAuthority = {
    externalDepsPackage: {
      dependencies: producerCertificate.identity.dependencies,
      sha256: digest(externalDepsPackageBytes),
      size: externalDepsPackageBytes.length,
      storageKey: "external-deps-storage-key",
    },
    kind: "convex-source-package-preactivation-authority-v1",
    nodeVersion: "24",
    packageModuleCount: 6,
    request: { sha256: digest(startPushBytes), size: startPushBytes.length },
    runtimeContentAlgorithm: convexRuntimeContentAlgorithm,
    runtimeContentSha256: "b".repeat(64),
    runtimeModuleCount: runtimeModules.length,
    runtimeModules,
    sourcePackage: { sha256: digest(sourcePackageBytes), size: sourcePackageBytes.length },
  };
  return {
    externalDepsPackageBytes,
    helper,
    helperAuthority,
    producerCertificate,
    runtimeModules,
    sourceEnvelope,
    sourceEnvelopeBytes: Buffer.from(`${canonicalJson(sourceEnvelope)}\n`),
    sourcePackageBytes,
    startPushBytes,
  };
}

test("direct preactivation authority binds canonical helper output to the frozen graph", async () => {
  await withTemporaryDirectory(async (directory) => {
    const value = fixture();
    const authorityOutputPath = join(directory, "authority.json");
    const externalDepsPackagePath = join(directory, "external-deps-package.zip");
    const sourcePackageOutputPath = join(directory, "source-package.zip");
    const startPushPath = join(directory, "start-push.json");
    await Promise.all([
      fs.writeFile(externalDepsPackagePath, value.externalDepsPackageBytes, { mode: 0o600 }),
      fs.writeFile(startPushPath, value.startPushBytes, { mode: 0o600 }),
    ]);

    const result = await createPreactivationRuntimeAuthority(
      {
        authorityOutputPath,
        externalDepsPackagePath,
        helper: value.helper,
        producerCertificate: value.producerCertificate,
        sourceEnvelope: value.sourceEnvelope,
        sourceEnvelopeBytes: value.sourceEnvelopeBytes,
        sourcePackageOutputPath,
        startPushBytes: value.startPushBytes,
        startPushPath,
      },
      {
        executeHelperImplementation: async (arguments_) => {
          assert.deepEqual(arguments_, {
            externalDepsPackagePath,
            externalDepsStorageKey: "external-deps-storage-key",
            helperPath: value.helper.path,
            sourcePackageOutputPath,
            startPushPath,
          });
          await fs.writeFile(sourcePackageOutputPath, value.sourcePackageBytes, { mode: 0o600 });
          return value.helperAuthority;
        },
      }
    );

    const authorityBytes = await fs.readFile(authorityOutputPath);
    const authority = JSON.parse(authorityBytes.toString("utf8"));
    const normalized = normalizeDeployedRuntimeAuthority(authority);
    const binding = verifyFrozenGraphBindingSourceEnvelope({
      normalizedAuthority: normalized,
      sourceEnvelope: value.sourceEnvelope,
      sourceEnvelopeFileSha256: digest(value.sourceEnvelopeBytes),
      sourceEnvelopeFileSize: value.sourceEnvelopeBytes.length,
    });
    assert.equal(result.authoritySha256, normalized.sha256);
    assert.equal(result.sourcePackageRuntimeContentSha256, "b".repeat(64));
    assert.equal(binding.inputAuthority.request.requestSha256, digest(value.startPushBytes));
    assert.equal(binding.inputAuthority.request.authoritativeNodeModuleCount, 1);
    assert.equal(binding.inputAuthority.request.authoritativeDeploymentConfigurationModuleCount, 1);
    assert.equal(
      result.derivation.runtimeModules.find(({ path }) => path === "auth.config.js").sourceSize,
      Buffer.byteLength("export default {};\n")
    );
    assert.equal(
      result.derivation.runtimeModules.find(({ path }) => path === "actions/run.js").nodePool,
      "workers"
    );
    assert.deepEqual(
      binding.inputAuthority.request.selectedModules.find(({ path }) => path === "first.js")
        .sourceMap,
      value.runtimeModules[0].sourceMap
    );
    assert.deepEqual(await fs.readFile(sourcePackageOutputPath), value.sourcePackageBytes);
    assert.equal((await fs.lstat(authorityOutputPath)).mode & 0o777, 0o600);
  });
});

test("preactivation source membership normalizes Node pools without weakening isolate provenance", () => {
  for (const { environment, nodePool, helperPool, sourceMap, pattern } of [
    { environment: "node:pool:workers", nodePool: "workers", helperPool: "workers" },
    { environment: "node:pool:workers", helperPool: "workers" },
    {
      environment: "node:pool:workers",
      nodePool: "workers",
      helperPool: "workers",
      sourceMap: JSON.stringify({ version: 3, sources: ["../convex/actions/run.ts"] }),
    },
    { environment: "node", helperPool: null },
    {
      environment: "node:pool:workers",
      nodePool: "other",
      helperPool: "workers",
      pattern: /Node pool metadata must match/,
    },
    ...["", "default", "Workers", "workers-invalid", "a".repeat(33)].map((pool) => ({
      environment: `node:pool:${pool}`,
      helperPool: "workers",
      pattern: /Node pool metadata must match/,
    })),
    ...["node", "isolate"].map((environment) => ({
      environment,
      nodePool: "workers",
      helperPool: "workers",
      pattern: /Node pool metadata requires a pool-bearing Node environment/,
    })),
    {
      environment: "node:pool:workers",
      helperPool: "other",
      pattern: /inconsistent Node pool metadata/,
    },
    {
      environment: "node",
      helperPool: "workers",
      pattern: /inconsistent Node pool metadata/,
    },
    {
      environment: "isolate",
      helperPool: null,
      pattern: /isolate source-map provenance is missing/,
    },
  ]) {
    const value = fixture();
    const request = JSON.parse(value.startPushBytes.toString("utf8"));
    const nodeModule = request.appDefinition.changedModules.find(
      ({ path }) => path === "actions/run.js"
    );
    nodeModule.environment = environment;
    delete nodeModule.nodePool;
    if (nodePool !== undefined) nodeModule.nodePool = nodePool;
    if (sourceMap !== undefined) nodeModule.sourceMap = sourceMap;
    const startPushBytes = Buffer.from(canonicalJson(request));
    value.helperAuthority.request = { sha256: digest(startPushBytes), size: startPushBytes.length };
    value.helperAuthority.runtimeModules.find(({ path }) => path === "actions/run.js").nodePool =
      helperPool;
    const normalize = () =>
      normalizePreactivationHelperAuthority(value.helperAuthority, {
        producerCertificate: value.producerCertificate,
        sourcePackage: value.helperAuthority.sourcePackage,
        startPushBytes,
      });
    if (pattern !== undefined) {
      assert.throws(normalize, pattern);
    } else {
      const normalized = normalize();
      const node = normalized.runtimeModules.find(({ path }) => path === "actions/run.js");
      assert.equal(node.environment, "node");
      assert.equal(node.nodePool, helperPool);
      assert.equal(node.sourceMembershipSha256, null);
      assert.match(
        normalized.runtimeModules.find(({ path }) => path === "first.js").sourceMembershipSha256,
        /^[0-9a-f]{64}$/u
      );
    }
  }
});

test("preactivation helper authority rejects mismatched authenticated material", () => {
  const value = fixture();
  const normalize = (authority, overrides = {}) =>
    normalizePreactivationHelperAuthority(authority, {
      producerCertificate: value.producerCertificate,
      sourcePackage: {
        sha256: digest(value.sourcePackageBytes),
        size: value.sourcePackageBytes.length,
      },
      startPushBytes: value.startPushBytes,
      ...overrides,
    });

  for (const [description, mutate, pattern] of [
    [
      "request bytes",
      (authority) => {
        authority.request.sha256 = "0".repeat(64);
      },
      /request identity differs/u,
    ],
    [
      "source package",
      (authority) => {
        authority.sourcePackage.sha256 = "1".repeat(64);
      },
      /source-package identity differs/u,
    ],
    [
      "dependency archive",
      (authority) => {
        authority.externalDepsPackage.sha256 = "2".repeat(64);
      },
      /dependency material differs/u,
    ],
    [
      "algorithm",
      (authority) => {
        authority.runtimeContentAlgorithm = "unknown-runtime-content-v2";
      },
      /kind or runtime-content algorithm is invalid/u,
    ],
  ]) {
    const changed = structuredClone(value.helperAuthority);
    mutate(changed);
    assert.throws(() => normalize(changed), pattern, description);
  }
});

test("direct preactivation rejects a helper outside the certified implementation identity", async () => {
  await withTemporaryDirectory(async (directory) => {
    const value = fixture();
    await assert.rejects(
      createPreactivationRuntimeAuthority(
        {
          authorityOutputPath: join(directory, "authority.json"),
          externalDepsPackagePath: join(directory, "external-deps-package.zip"),
          helper: { ...value.helper, sha256: "f".repeat(64) },
          producerCertificate: value.producerCertificate,
          sourceEnvelope: value.sourceEnvelope,
          sourceEnvelopeBytes: value.sourceEnvelopeBytes,
          sourcePackageOutputPath: join(directory, "source-package.zip"),
          startPushBytes: value.startPushBytes,
          startPushPath: join(directory, "start-push.json"),
        },
        {
          executeHelperImplementation: async () => {
            throw new Error("must not execute");
          },
        }
      ),
      /helper differs from the producer certificate/u
    );
  });
});

test("runtime-content helper inspection authenticates a canonical owner-controlled executable", async () => {
  await withTemporaryDirectory(async (directory) => {
    const helperPath = join(directory, "source-package-preactivation-authority");
    const helperBytes = Buffer.from("#!/bin/sh\nexit 0\n");
    await fs.writeFile(helperPath, helperBytes, { mode: 0o700 });
    assert.deepEqual(await inspectRuntimeContentHelper(helperPath), {
      path: helperPath,
      sha256: digest(helperBytes),
      size: helperBytes.length,
    });

    await fs.chmod(helperPath, 0o722);
    await assert.rejects(
      inspectRuntimeContentHelper(helperPath),
      /canonical owner-controlled executable/u
    );
  });
});

test("image-backed helper rejects mutable image names and mount delimiters before Docker", async () => {
  const input = {
    backendImageId: `sha256:${"a".repeat(64)}`,
    sourcePackageOutputPath: "/tmp/source-package.zip",
    startPushPath: "/tmp/start-push.json",
  };
  await assert.rejects(
    executeRuntimeContentHelperInBackendImage({ ...input, backendImageId: "backend:latest" }),
    /immutable SHA-256 identity/u
  );
  await assert.rejects(
    executeRuntimeContentHelperInBackendImage({ ...input, startPushPath: "/tmp/input,readonly=false" }),
    /Docker mount delimiters/u
  );
});
