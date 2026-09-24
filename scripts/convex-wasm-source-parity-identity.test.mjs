import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { DatabaseSync } from "node:sqlite";

import {
  bindDeployedRuntimeIdentity,
  normalizeDeployedRuntimeAuthority,
} from "./lib/convex-deployed-runtime-identity.mjs";
import { fingerprintJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  collectSqliteRuntimeBindingAuthority,
  createRuntimeModuleEvidence,
  createSourceParityIdentityReport,
  readStableSourceParityInput,
  resolveLatestSourcePackageAuthority,
  validateBackendDatabaseSelection,
  withMysqlConsistentSnapshot,
  writeStableOutput,
} from "./convex-wasm-source-parity-identity.mjs";

const sha = (character) => character.repeat(64);
const BASE32_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

test("rejects a replaced source-parity output during stable reuse", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-parity-output-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const outputPath = join(root, "source-parity.json");
  const replacementPath = join(root, "replacement.json");
  await writeStableOutput(outputPath, { value: "a" });
  await fs.writeFile(replacementPath, '{"value":"b"}\n', { mode: 0o600 });

  const originalOpen = fs.open;
  let replaced = false;
  fs.open = async (path, ...argumentsList) => {
    const handle = await originalOpen(path, ...argumentsList);
    if (path !== outputPath) return handle;
    return new Proxy(handle, {
      get(target, property) {
        if (property === "readFile") {
          return async (...readArguments) => {
            const contents = await target.readFile(...readArguments);
            await fs.rename(replacementPath, outputPath);
            replaced = true;
            return contents;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  try {
    await assert.rejects(
      writeStableOutput(outputPath, { value: "a" }),
      /identity evidence changed while it was read/u
    );
  } finally {
    fs.open = originalOpen;
  }
  assert.equal(replaced, true);
  assert.equal(await fs.readFile(outputPath, "utf8"), '{"value":"b"}\n');
});

test("rejects a replaced deployment manifest during source-parity input authentication", async (t) => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-parity-input-"));
  t.after(async () => await fs.rm(root, { force: true, recursive: true }));
  const inputPath = join(root, "deployment.json");
  const replacementPath = join(root, "replacement.json");
  const input = Buffer.from('{"value":"a"}\n');
  await fs.writeFile(inputPath, input, { mode: 0o600 });
  await fs.writeFile(replacementPath, '{"value":"b"}\n', { mode: 0o600 });

  const originalOpen = fs.open;
  let replaced = false;
  fs.open = async (path, ...argumentsList) => {
    const handle = await originalOpen(path, ...argumentsList);
    if (path !== inputPath) return handle;
    return new Proxy(handle, {
      get(target, property) {
        if (property === "read") {
          return async (...readArguments) => {
            const result = await target.read(...readArguments);
            if (!replaced && result.bytesRead === input.length) {
              await fs.rename(replacementPath, inputPath);
              replaced = true;
            }
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
  try {
    await assert.rejects(
      readStableSourceParityInput(inputPath, 1024, "deployment manifest"),
      /deployment manifest changed while it was read/u
    );
  } finally {
    fs.open = originalOpen;
  }
  assert.equal(replaced, true);
});

function digest(...sources) {
  const hash = createHash("sha256");
  for (const source of sources) {
    hash.update(source);
  }
  return hash.digest("hex");
}

function developerDocumentId(tableNumber, internalIdHex) {
  const bytes = [];
  let remainingTableNumber = tableNumber;
  while (remainingTableNumber >= 0x80) {
    bytes.push((remainingTableNumber & 0x7f) | 0x80);
    remainingTableNumber = Math.floor(remainingTableNumber / 0x80);
  }
  bytes.push(remainingTableNumber);
  bytes.push(...Buffer.from(internalIdHex, "hex"));
  let checksum0 = 0;
  let checksum1 = 0;
  for (const byte of bytes) {
    checksum0 = (checksum0 + byte) & 0xff;
    checksum1 = (checksum1 + checksum0) & 0xff;
  }
  bytes.push(checksum0, checksum1);

  let accumulator = 0;
  let bitCount = 0;
  let encoded = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      encoded += BASE32_ALPHABET[(accumulator >> bitCount) & 0x1f];
    }
    accumulator &= (1 << bitCount) - 1;
  }
  if (bitCount > 0) {
    encoded += BASE32_ALPHABET[(accumulator << (5 - bitCount)) & 0x1f];
  }
  return encoded;
}

function encodedDigest(value) {
  return Buffer.from(value, "hex").toString("base64");
}

function encodedInteger(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(BigInt(value));
  return { $integer: bytes.toString("base64") };
}

function sourcePackageRow({
  creationTime,
  idHex,
  packageSha256,
  runtimeContentSha256 = null,
  storageKey,
}) {
  return {
    creationTime,
    document: {
      sha256: { $bytes: encodedDigest(packageSha256) },
      ...(runtimeContentSha256 === null
        ? {}
        : { runtimeContentSha256: { $bytes: encodedDigest(runtimeContentSha256) } }),
      storageKey,
    },
    idHex,
  };
}

function moduleRow({ environment = "isolate", idHex, moduleSha256, path, sourcePackageId }) {
  return {
    creationTime: 1,
    document: {
      environment,
      path,
      sha256: encodedDigest(moduleSha256),
      sourcePackageId,
    },
    idHex,
  };
}

test("reads changing MySQL state through one repeatable-read snapshot session", async () => {
  let currentValue = "before";
  let openedSessions = 0;
  const commands = [];
  const result = await withMysqlConsistentSnapshot({
    containerId: "local-mysql",
    database: "convex_self_hosted",
    openSession: async () => {
      openedSessions += 1;
      let closed = false;
      let snapshotValue = null;
      return {
        async close() {
          assert.equal(closed, false);
          closed = true;
        },
        async query(query) {
          assert.equal(closed, false);
          commands.push(query);
          if (query === "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ") {
            return "";
          }
          if (query === "START TRANSACTION WITH CONSISTENT SNAPSHOT") {
            snapshotValue = currentValue;
            return "";
          }
          if (query === "SELECT snapshot_value") {
            assert.notEqual(snapshotValue, null);
            return `${snapshotValue}\n`;
          }
          if (query === "COMMIT") {
            snapshotValue = null;
            return "";
          }
          throw new Error(`unexpected fake query ${query}`);
        },
      };
    },
    read: async (query) => {
      const first = (await query("SELECT snapshot_value")).trim();
      currentValue = "after";
      const second = (await query("SELECT snapshot_value")).trim();
      return { first, second };
    },
  });
  assert.equal(openedSessions, 1);
  assert.deepEqual(result, { first: "before", second: "before" });
  assert.deepEqual(commands, [
    "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
    "START TRANSACTION WITH CONSISTENT SNAPSHOT",
    "SELECT snapshot_value",
    "SELECT snapshot_value",
    "COMMIT",
  ]);
});

test("uses the newest committed source package when unchanged modules retain older IDs", () => {
  const sourcePackagesTableNumber = 42;
  const olderIdHex = "11".repeat(16);
  const newerIdHex = "22".repeat(16);
  const unreferencedIdHex = "55".repeat(16);
  const olderDeveloperId = developerDocumentId(sourcePackagesTableNumber, olderIdHex);
  const newerDeveloperId = developerDocumentId(sourcePackagesTableNumber, newerIdHex);
  const olderPackageSha256 = sha("a");
  const newerPackageSha256 = sha("b");
  const latestPackageSha256 = sha("d");
  const latestRuntimeContentSha256 = sha("e");
  const targetSource = Buffer.from("export const unchanged = 1;\n");
  const targetSourceMap = Buffer.from(
    JSON.stringify({
      mappings: "",
      names: [],
      sources: ["../convex/target.ts"],
      sourcesContent: ["export const unchanged = 1;\n"],
      version: 3,
    })
  );
  const targetModuleSha256 = digest(targetSource, targetSourceMap);
  const resolution = resolveLatestSourcePackageAuthority({
    moduleRows: [
      moduleRow({
        idHex: "10".repeat(16),
        moduleSha256: targetModuleSha256,
        path: "target.js",
        sourcePackageId: olderDeveloperId,
      }),
      moduleRow({
        idHex: "20".repeat(16),
        moduleSha256: sha("c"),
        path: "changed.js",
        sourcePackageId: newerDeveloperId,
      }),
    ],
    sourcePackageRows: [
      sourcePackageRow({
        creationTime: 1000,
        idHex: olderIdHex,
        packageSha256: olderPackageSha256,
        storageKey: "older-package",
      }),
      sourcePackageRow({
        creationTime: 2000,
        idHex: newerIdHex,
        packageSha256: newerPackageSha256,
        storageKey: "newer-package",
      }),
      sourcePackageRow({
        creationTime: 3000,
        idHex: unreferencedIdHex,
        packageSha256: latestPackageSha256,
        runtimeContentSha256: latestRuntimeContentSha256,
        storageKey: "unreferenced-package",
      }),
    ],
    sourcePackagesTableNumber,
  });

  const targetModule = resolution.activeModules.find(({ path }) => path === "target.js");
  assert.equal(targetModule.retainedSourcePackage.developerId, olderDeveloperId);
  assert.equal(targetModule.retainedSourcePackage.packageSha256, olderPackageSha256);
  assert.deepEqual(resolution.latestCommittedSourcePackage, {
    creationTime: 3000,
    developerId: developerDocumentId(sourcePackagesTableNumber, unreferencedIdHex),
    internalIdHex: unreferencedIdHex,
    packageSha256: latestPackageSha256,
    runtimeContentSha256: latestRuntimeContentSha256,
    storageKey: "unreferenced-package",
  });
  assert.deepEqual(resolution.v8LoadPackageIdentity, resolution.latestCommittedSourcePackage);

  const evidence = createRuntimeModuleEvidence({
    loadPackageMaterial: {
      sha256: latestPackageSha256,
      runtimeContentSha256: latestRuntimeContentSha256,
      sourcePackageHashVerified: true,
    },
    module: targetModule,
    runtimeModulePath: "target.js",
    source: targetSource,
    sourceMap: targetSourceMap,
  });
  assert.equal(evidence.moduleHashVerified, true);
  assert.equal(evidence.sourceSha256, digest(targetSource));
  assert.equal(evidence.sourceMap.sha256, digest(targetSourceMap));
  assert.equal(evidence.sourceMap.sourcesContentCount, 1);
  assert.equal(evidence.sourcePackageSha256, latestPackageSha256);
  assert.equal(evidence.sourcePackageRuntimeContentSha256, latestRuntimeContentSha256);
  assert.equal(evidence.retainedSourcePackage.packageSha256, olderPackageSha256);
});

test("equal source-package creation times select the highest source-package ID", () => {
  const sourcePackagesTableNumber = 42;
  const firstIdHex = "33".repeat(16);
  const secondIdHex = "44".repeat(16);
  const firstDeveloperId = developerDocumentId(sourcePackagesTableNumber, firstIdHex);
  const secondDeveloperId = developerDocumentId(sourcePackagesTableNumber, secondIdHex);
  const resolution = resolveLatestSourcePackageAuthority({
    moduleRows: [
      moduleRow({
        idHex: "01".repeat(16),
        moduleSha256: sha("a"),
        path: "first.js",
        sourcePackageId: firstDeveloperId,
      }),
      moduleRow({
        idHex: "02".repeat(16),
        moduleSha256: sha("b"),
        path: "second.js",
        sourcePackageId: secondDeveloperId,
      }),
    ],
    sourcePackageRows: [
      sourcePackageRow({
        creationTime: 3000,
        idHex: firstIdHex,
        packageSha256: sha("c"),
        storageKey: "first-package",
      }),
      sourcePackageRow({
        creationTime: 3000,
        idHex: secondIdHex,
        packageSha256: sha("d"),
        storageKey: "second-package",
      }),
    ],
    sourcePackagesTableNumber,
  });

  assert.equal(resolution.v8LoadPackageIdentity.developerId, secondDeveloperId);
});

test("an empty active module table produces explicit no-load-package evidence", () => {
  const resolution = resolveLatestSourcePackageAuthority({
    moduleRows: [],
    sourcePackageRows: [],
    sourcePackagesTableNumber: 42,
  });
  assert.deepEqual(resolution, {
    activeModules: [],
    latestCommittedSourcePackage: null,
    v8LoadPackageIdentity: null,
  });
  assert.deepEqual(
    createRuntimeModuleEvidence({
      loadPackageMaterial: null,
      module: null,
      runtimeModulePath: "missing.js",
      source: null,
      sourceMap: null,
    }),
    {
      environment: null,
      moduleHashVerified: false,
      path: "missing.js",
      retainedSourcePackage: null,
      sha256: null,
      sourceMap: {
        sha256: null,
        size: 0,
        sourcesContentCount: 0,
        sourcesCount: 0,
      },
      sourcePackageHashVerified: false,
      sourcePackageSha256: null,
      sourcePackageRuntimeContentSha256: null,
      sourceSha256: null,
    }
  );
});

test("rejects a database that does not belong to the inspected backend instance", () => {
  const backend = {
    Config: {
      Env: ["INSTANCE_NAME=convex-wasm-ab"],
    },
  };
  assert.deepEqual(validateBackendDatabaseSelection(backend, "convex_wasm_ab"), {
    database: "convex_wasm_ab",
    instanceName: "convex-wasm-ab",
  });
  assert.throws(
    () => validateBackendDatabaseSelection(backend, "convex_self_hosted"),
    /does not match backend instance convex-wasm-ab resolved database convex_wasm_ab/u
  );
});

function candidate({
  boundIdentity,
  exportName,
  modulePath,
  moduleSha256,
  runtimeContentSha256 = sha("f"),
}) {
  const source = {
    exportName,
    exportSha256: sha("1"),
    modulePath: `convex/${modulePath.replace(/\.js$/u, ".ts")}`,
    resolvedGraphSha256: sha("2"),
    udfKind: "query",
    ...(boundIdentity
      ? {
          deployedRuntimeIdentity: {
            kind: "convex-deployed-runtime-module-v2",
            moduleSha256,
            sourcePackageRuntimeContentSha256: runtimeContentSha256,
          },
        }
      : {}),
  };
  const executionManifest = {
    source: {
      exportName,
      exportSha256: source.exportSha256,
      modulePath: source.modulePath,
      resolvedGraphSha256: source.resolvedGraphSha256,
      runtimeModulePath: modulePath,
      udfKind: "query",
    },
  };
  return {
    artifact: { executionManifest },
    exportName,
    packageReference: { cacheKey: fingerprintJson(executionManifest) },
    routing: { decision: "wasm", reason: "staticEligibility" },
    runtimeModulePath: modulePath,
    source,
    udfKind: "query",
  };
}

function manifest(exports, kind = "convex-wasm-deployment-v2") {
  const payload = {
    counts: {
      ...(kind === "convex-wasm-deployment-v4" ? { artifactFallback: 0 } : {}),
      eligible: exports.length,
      selectedWasm: exports.length,
      unselectedEligible: 0,
    },
    exports,
    graph: { sha256: sha("3") },
    kind,
    mode: "compile",
  };
  return { ...payload, deploymentSha256: fingerprintJson(payload) };
}

function cohortCandidate(options) {
  const entry = candidate(options);
  const cohortPackageId = sha("8");
  const entryId = sha("9");
  const entrySelectorId = entryId.slice(0, 16);
  entry.packageReference = {
    cohortPackageId,
    entryId,
    entrySelectorId,
    kind: "convex-wasm-cohort-route-reference-v1",
  };
  entry.artifact.executionManifest.artifact = {
    cohort: {
      manifestSha256: cohortPackageId,
      packageId: cohortPackageId,
    },
    entryId,
    entrySelectorId,
  };
  entry.artifact.executionManifest.route = {
    exportName: entry.exportName,
    kind: "convex-wasm-runtime-route-v1",
    runtimeModulePath: entry.runtimeModulePath,
    udfKind: entry.udfKind,
  };
  entry.artifact.executionManifest.routing = { decision: "wasm" };
  return entry;
}

function moduleEvidence(
  path,
  moduleSha256,
  packageSha256,
  sourcesContentCount = 0,
  runtimeContentSha256 = sha("f")
) {
  return {
    environment: "isolate",
    moduleHashVerified: true,
    path,
    sha256: moduleSha256,
    sourceMap: {
      sha256: sha("4"),
      size: 69,
      sourcesContentCount,
      sourcesCount: sourcesContentCount,
    },
    sourcePackageHashVerified: true,
    sourcePackageSha256: packageSha256,
    sourcePackageRuntimeContentSha256: runtimeContentSha256,
  };
}

test("absent runtime authority emits only the explicit module-absence diagnosis", () => {
  const deploymentManifest = manifest([
    candidate({
      boundIdentity: true,
      exportName: "missing",
      modulePath: "missing.js",
      moduleSha256: sha("b"),
      packageSha256: sha("a"),
    }),
  ]);
  const report = createSourceParityIdentityReport({
    database: {
      authority: {
        backendMaterial: {
          sourcePackageCount: 0,
          sourcePackageFileSha256: [],
          v8LoadPackage: null,
        },
        fixture: true,
      },
      modules: [
        createRuntimeModuleEvidence({
          loadPackageMaterial: null,
          module: null,
          runtimeModulePath: "missing.js",
          source: null,
          sourceMap: null,
        }),
      ],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  });

  assert.deepEqual(report.counts, {
    mismatch: 1,
    proven: 0,
    totalEligibleCandidates: 1,
    unprovable: 0,
  });
  assert.equal(report.routeMatrix[0].deployedRuntime, null);
  assert.deepEqual(report.routeMatrix[0].reasons, [
    {
      code: "DEPLOYED_RUNTIME_MODULE_NOT_FOUND",
      detail: "the active _modules snapshot has no missing.js",
    },
  ]);
});

test("identity matrix proves only authenticated exact runtime bindings", () => {
  const packageSha256 = sha("a");
  const provenModuleSha256 = sha("b");
  const unprovableModuleSha256 = sha("c");
  const mismatchModuleSha256 = sha("d");
  const deploymentManifest = manifest([
    candidate({
      boundIdentity: true,
      exportName: "proven",
      modulePath: "first.js",
      moduleSha256: provenModuleSha256,
      packageSha256,
    }),
    candidate({
      boundIdentity: false,
      exportName: "nameOnly",
      modulePath: "second.js",
      moduleSha256: unprovableModuleSha256,
      packageSha256,
    }),
    candidate({
      boundIdentity: true,
      exportName: "mismatch",
      modulePath: "third.js",
      moduleSha256: sha("e"),
      packageSha256,
    }),
  ]);
  const report = createSourceParityIdentityReport({
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [
        moduleEvidence("first.js", provenModuleSha256, packageSha256),
        moduleEvidence("second.js", unprovableModuleSha256, packageSha256),
        moduleEvidence("third.js", mismatchModuleSha256, packageSha256),
      ],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  });

  assert.deepEqual(report.counts, {
    mismatch: 1,
    proven: 1,
    totalEligibleCandidates: 3,
    unprovable: 1,
  });
  assert.equal(report.gatePass, false);
  assert.deepEqual(
    report.routeMatrix.map(({ route, verdict }) => [route, verdict]),
    [
      ["first.js:proven", "proven"],
      ["second.js:nameOnly", "unprovable"],
      ["third.js:mismatch", "mismatch"],
    ]
  );
  assert.deepEqual(
    report.routeMatrix[1].reasons.map(({ code }) => code),
    ["DEPLOYED_RUNTIME_IDENTITY_NOT_BOUND", "DEPLOYED_SOURCE_MAP_HAS_NO_SOURCES_CONTENT"]
  );
  assert.deepEqual(
    report.routeMatrix[2].reasons.map(({ code }) => code),
    ["DEPLOYED_RUNTIME_IDENTITY_BINDING_MISMATCH"]
  );
  const { reportSha256: _reportSha256, ...payload } = report;
  assert.equal(report.reportSha256, fingerprintJson(payload));
});

test("accepts authenticated deployment v4 cohorts and rejects malformed deployment contracts", () => {
  const packageSha256 = sha("a");
  const moduleSha256 = sha("b");
  const route = cohortCandidate({
    boundIdentity: true,
    exportName: "cohortRoute",
    modulePath: "cohort.js",
    moduleSha256,
    packageSha256,
  });
  const deploymentManifest = manifest([route], "convex-wasm-deployment-v4");
  const input = {
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [moduleEvidence("cohort.js", moduleSha256, packageSha256)],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  };
  const report = createSourceParityIdentityReport(input);
  assert.equal(report.gatePass, true);
  assert.equal(report.routeMatrix[0].artifact.packageKey, route.packageReference.cohortPackageId);

  for (const mutate of [
    (manifestValue) => {
      manifestValue.kind = "convex-wasm-deployment-v5";
    },
    (manifestValue) => {
      manifestValue.counts.artifactFallback = 1;
    },
  ]) {
    const malformed = structuredClone(deploymentManifest);
    delete malformed.deploymentSha256;
    mutate(malformed);
    malformed.deploymentSha256 = fingerprintJson(malformed);
    assert.throws(
      () => createSourceParityIdentityReport({ ...input, deploymentManifest: malformed }),
      /compiled convex-wasm-deployment-v2 or v4|inconsistent eligible-selection counts/u
    );
  }
});

test("matching route names without compiler-to-bundle identity stay unprovable", () => {
  const packageSha256 = sha("a");
  const moduleSha256 = sha("b");
  const deploymentManifest = manifest([
    candidate({
      boundIdentity: false,
      exportName: "sameName",
      modulePath: "same.js",
      moduleSha256,
      packageSha256,
    }),
  ]);
  const input = {
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [moduleEvidence("same.js", moduleSha256, packageSha256, 1)],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  };

  const first = createSourceParityIdentityReport(input);
  const second = createSourceParityIdentityReport(input);
  assert.equal(first.routeMatrix[0].verdict, "unprovable");
  assert.deepEqual(
    first.routeMatrix[0].reasons.map(({ code }) => code),
    ["DEPLOYED_RUNTIME_IDENTITY_NOT_BOUND"]
  );
  assert.equal(first.reportSha256, second.reportSha256);
});

test("legacy raw archive bindings remain parseable but cannot prove runtime identity", () => {
  const packageSha256 = sha("a");
  const moduleSha256 = sha("b");
  const route = candidate({
    boundIdentity: true,
    exportName: "legacy",
    modulePath: "legacy.js",
    moduleSha256,
    packageSha256,
  });
  route.source.deployedRuntimeIdentity = {
    kind: "convex-deployed-runtime-module-v1",
    moduleSha256,
    sourcePackageSha256: packageSha256,
  };
  const deploymentManifest = manifest([route]);
  const report = createSourceParityIdentityReport({
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [moduleEvidence("legacy.js", moduleSha256, packageSha256)],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  });

  assert.equal(report.routeMatrix[0].verdict, "unprovable");
  assert.deepEqual(
    report.routeMatrix[0].reasons.map(({ code }) => code),
    ["DEPLOYED_RUNTIME_IDENTITY_LEGACY_RAW_ARCHIVE_ONLY"]
  );
});

test("missing persisted runtime-content digests remain unprovable", () => {
  const packageSha256 = sha("a");
  const moduleSha256 = sha("b");
  const deploymentManifest = manifest([
    candidate({
      boundIdentity: true,
      exportName: "legacySourcePackage",
      modulePath: "legacy-source-package.js",
      moduleSha256,
      packageSha256,
    }),
  ]);
  const runtimeModule = moduleEvidence("legacy-source-package.js", moduleSha256, packageSha256);
  runtimeModule.sourcePackageRuntimeContentSha256 = null;
  const report = createSourceParityIdentityReport({
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [runtimeModule],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  });

  assert.equal(report.routeMatrix[0].verdict, "unprovable");
  assert.deepEqual(
    report.routeMatrix[0].reasons.map(({ code }) => code),
    ["DEPLOYED_SOURCE_PACKAGE_RUNTIME_CONTENT_DIGEST_NOT_FOUND"]
  );
});

test("binding authority uses the consumer's canonical mixed-case path order", () => {
  const packageSha256 = sha("a");
  const apiModuleSha256 = sha("b");
  const evalModuleSha256 = sha("c");
  const deploymentManifest = manifest([
    candidate({
      boundIdentity: true,
      exportName: "eval",
      modulePath: "aiEvals.js",
      moduleSha256: evalModuleSha256,
      packageSha256,
    }),
    candidate({
      boundIdentity: true,
      exportName: "validate",
      modulePath: "API/apiKeys.js",
      moduleSha256: apiModuleSha256,
      packageSha256,
    }),
  ]);
  const report = createSourceParityIdentityReport({
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [
        moduleEvidence("aiEvals.js", evalModuleSha256, packageSha256),
        moduleEvidence("API/apiKeys.js", apiModuleSha256, packageSha256),
      ],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  });

  assert.deepEqual(
    report.bindingAuthority.modules.map(({ path }) => path),
    ["API/apiKeys.js", "aiEvals.js"]
  );
  assert.equal(
    normalizeDeployedRuntimeAuthority(report).sha256,
    report.bindingAuthority.authoritySha256
  );
});

test("stopped SQLite deployment produces a normalized runtime binding authority", async () => {
  const root = await fs.mkdtemp(join(tmpdir(), "convex-sqlite-authority-test-"));
  try {
    const databasePath = join(root, "db.sqlite3");
    const storageRoot = join(root, "storage");
    const modulesRoot = join(storageRoot, "modules");
    const archiveRoot = join(root, "archive");
    const archiveModulesRoot = join(archiveRoot, "modules");
    await Promise.all([
      fs.mkdir(modulesRoot, { recursive: true }),
      fs.mkdir(archiveModulesRoot, { recursive: true }),
    ]);
    const runtimeModulePath = "selfHostedExecutionProbe.js";
    const moduleSource = "export const getStatus = () => ({ configured: true });\n";
    const sourceMap = JSON.stringify({
      mappings: "",
      names: [],
      sources: ["../convex/selfHostedExecutionProbe.ts"],
      sourcesContent: ["export const getStatus = query(() => ({ configured: true }));\n"],
      version: 3,
    });
    await Promise.all([
      fs.writeFile(join(archiveModulesRoot, runtimeModulePath), moduleSource),
      fs.writeFile(join(archiveModulesRoot, `${runtimeModulePath}.map`), sourceMap),
    ]);
    const storageKey = "fixture-package";
    const blobPath = join(modulesRoot, `${storageKey}.blob`);
    const zipped = spawnSync("zip", ["-q", "-r", blobPath, "modules"], {
      cwd: archiveRoot,
      encoding: "utf8",
    });
    assert.equal(zipped.status, 0, zipped.stderr);
    const packageSha256 = digest(await fs.readFile(blobPath));
    const runtimeContentSha256 = digest("runtime-content");
    const moduleSha256 = digest(moduleSource, sourceMap);

    const tablesTabletHex = "11".repeat(16).toUpperCase();
    const modulesTabletHex = "22".repeat(16).toUpperCase();
    const sourcePackagesTabletHex = "33".repeat(16).toUpperCase();
    const tablesTableNumber = 510;
    const modulesTableNumber = 521;
    const sourcePackagesTableNumber = 524;
    const sourcePackageInternalId = "44".repeat(16).toUpperCase();
    const sourcePackageId = developerDocumentId(sourcePackagesTableNumber, sourcePackageInternalId);
    const database = new DatabaseSync(databasePath);
    database.exec(`
      CREATE TABLE documents (
        id BLOB NOT NULL,
        ts INTEGER NOT NULL,
        table_id BLOB NOT NULL,
        json_value TEXT NULL,
        deleted INTEGER NOT NULL,
        prev_ts INTEGER,
        PRIMARY KEY (ts, table_id, id)
      );
      CREATE TABLE persistence_globals (
        key TEXT NOT NULL PRIMARY KEY,
        json_value TEXT NOT NULL
      );
    `);
    database
      .prepare("INSERT INTO persistence_globals (key, json_value) VALUES (?, ?)")
      .run(
        "tables_table_id",
        JSON.stringify(Buffer.from(tablesTabletHex, "hex").toString("base64"))
      );
    const insertDocument = database.prepare(
      "INSERT INTO documents (id, ts, table_id, json_value, deleted, prev_ts) VALUES (?, ?, ?, ?, 0, NULL)"
    );
    const insertFixtureDocument = ({
      creationTime,
      document,
      documentTableNumber,
      idHex,
      tableHex,
      timestamp,
    }) =>
      insertDocument.run(
        Buffer.from(idHex, "hex"),
        timestamp,
        Buffer.from(tableHex, "hex"),
        JSON.stringify({
          ...document,
          _creationTime: creationTime,
          _id: developerDocumentId(documentTableNumber, idHex),
        })
      );
    insertFixtureDocument({
      creationTime: 1,
      document: {
        name: "_modules",
        number: encodedInteger(521),
        state: "active",
      },
      documentTableNumber: tablesTableNumber,
      idHex: modulesTabletHex,
      tableHex: tablesTabletHex,
      timestamp: 1,
    });
    insertFixtureDocument({
      creationTime: 2,
      document: {
        name: "_source_packages",
        number: encodedInteger(sourcePackagesTableNumber),
        state: "active",
      },
      documentTableNumber: tablesTableNumber,
      idHex: sourcePackagesTabletHex,
      tableHex: tablesTabletHex,
      timestamp: 2,
    });
    insertFixtureDocument({
      creationTime: 3,
      document: {
        sha256: { $bytes: encodedDigest(packageSha256) },
        runtimeContentSha256: { $bytes: encodedDigest(runtimeContentSha256) },
        storageKey,
      },
      documentTableNumber: sourcePackagesTableNumber,
      idHex: sourcePackageInternalId,
      tableHex: sourcePackagesTabletHex,
      timestamp: 3,
    });
    insertFixtureDocument({
      creationTime: 4,
      document: {
        environment: "isolate",
        path: runtimeModulePath,
        sha256: encodedDigest(moduleSha256),
        sourcePackageId,
      },
      documentTableNumber: modulesTableNumber,
      idHex: "55".repeat(16).toUpperCase(),
      tableHex: modulesTabletHex,
      timestamp: 4,
    });
    database.close();

    const collected = await collectSqliteRuntimeBindingAuthority({
      databasePath,
      instanceName: "isolated-fixture",
      runtimeModulePaths: [runtimeModulePath],
      storageRoot,
    });
    assert.deepEqual(collected.bindingAuthority.sourcePackageFileSha256, [packageSha256]);
    assert.deepEqual(collected.bindingAuthority.modules, [
      {
        environment: "isolate",
        moduleHashVerified: true,
        moduleSha256,
        path: runtimeModulePath,
        sourceMap: {
          sha256: digest(sourceMap),
          size: Buffer.byteLength(sourceMap),
          sourcesContentCount: 1,
          sourcesCount: 1,
        },
        sourcePackageHashVerified: true,
        sourcePackageSha256: packageSha256,
        sourcePackageRuntimeContentSha256: runtimeContentSha256,
        sourceSha256: digest(moduleSource),
      },
    ]);
    assert.equal(
      normalizeDeployedRuntimeAuthority(collected.bindingAuthority).sha256,
      collected.bindingAuthority.authoritySha256
    );

    const tamperedDatabase = new DatabaseSync(databasePath);
    const moduleRow = tamperedDatabase
      .prepare("SELECT json_value AS jsonValue FROM documents WHERE id=?")
      .get(Buffer.from("55".repeat(16), "hex"));
    const tamperedModule = JSON.parse(moduleRow.jsonValue);
    tamperedModule._id = developerDocumentId(modulesTableNumber, "66".repeat(16));
    tamperedDatabase
      .prepare("UPDATE documents SET json_value=? WHERE id=?")
      .run(JSON.stringify(tamperedModule), Buffer.from("55".repeat(16), "hex"));
    tamperedDatabase.close();
    await assert.rejects(
      collectSqliteRuntimeBindingAuthority({
        databasePath,
        instanceName: "isolated-fixture",
        runtimeModulePaths: [runtimeModulePath],
        storageRoot,
      }),
      /_id differs from its SQLite row ID/u
    );
  } finally {
    await fs.rm(root, { force: true, recursive: true });
  }
});

test("invalid authenticated deployment identity fails closed", () => {
  const deploymentManifest = manifest([
    candidate({
      boundIdentity: false,
      exportName: "route",
      modulePath: "route.js",
      moduleSha256: sha("b"),
      packageSha256: sha("a"),
    }),
  ]);
  deploymentManifest.graph.sha256 = sha("9");

  assert.throws(
    () =>
      createSourceParityIdentityReport({
        database: { authority: {}, modules: [] },
        deploymentManifest,
        deploymentManifestFileSha256: sha("f"),
      }),
    /deployment manifest digest is invalid/u
  );
});

test("partial Wasm selections require an explicit diagnostic policy", () => {
  const packageSha256 = sha("a");
  const moduleSha256 = sha("b");
  const selected = candidate({
    boundIdentity: true,
    exportName: "selected",
    modulePath: "selected.js",
    moduleSha256,
    packageSha256,
  });
  const unselected = {
    ...candidate({
      boundIdentity: false,
      exportName: "unselected",
      modulePath: "unselected.js",
      moduleSha256: sha("c"),
      packageSha256,
    }),
    routing: { decision: "existingRuntime", reason: "not-selected" },
  };
  const payload = {
    counts: {
      eligible: 2,
      selectedWasm: 1,
      unselectedEligible: 1,
    },
    exports: [selected, unselected],
    graph: { sha256: sha("3") },
    kind: "convex-wasm-deployment-v2",
    mode: "compile",
  };
  const deploymentManifest = {
    ...payload,
    deploymentSha256: fingerprintJson(payload),
  };
  const input = {
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [moduleEvidence("selected.js", moduleSha256, packageSha256)],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  };

  assert.throws(
    () => createSourceParityIdentityReport(input),
    /not an accepted all-eligible selection/u
  );
  const report = createSourceParityIdentityReport({
    ...input,
    selectionPolicy: "selected-wasm",
  });
  assert.deepEqual(report.selection, {
    manifestEligible: 2,
    policy: "selected-wasm",
    selectedWasm: 1,
    unselectedEligible: 1,
  });
  assert.equal(report.counts.totalEligibleCandidates, 1);
  assert.equal(report.routeMatrix[0].route, "selected.js:selected");
  assert.equal(report.gatePass, true);
});

test("compiler-produced exact bundle binding is the only path to a proven gate row", () => {
  const packageSha256 = sha("a");
  const runtimeContentSha256 = sha("f");
  const moduleSha256 = sha("b");
  const bundleModule = {
    environment: "isolate",
    moduleSha256,
    path: "same.js",
    sourceMap: {
      sha256: sha("4"),
      size: 69,
      sourcesContentCount: 0,
      sourcesCount: 1,
    },
    sourceSha256: sha("5"),
    sourceSize: 10,
  };
  const authority = normalizeDeployedRuntimeAuthority({
    kind: "convex-deployed-runtime-binding-authority-v1",
    modules: [
      {
        ...bundleModule,
        moduleHashVerified: true,
        sourcePackageHashVerified: true,
        sourcePackageSha256: packageSha256,
        sourcePackageRuntimeContentSha256: runtimeContentSha256,
      },
    ],
    sourcePackageFileSha256: [packageSha256],
  });
  const binding = bindDeployedRuntimeIdentity({
    authority,
    bundleModule,
    runtimeModulePath: bundleModule.path,
  });
  assert.equal(binding.diagnostic, null);

  const deploymentManifest = manifest([
    candidate({
      boundIdentity: true,
      exportName: "sameSource",
      modulePath: bundleModule.path,
      moduleSha256: binding.identity.moduleSha256,
      packageSha256,
      runtimeContentSha256: binding.identity.sourcePackageRuntimeContentSha256,
    }),
  ]);
  const report = createSourceParityIdentityReport({
    database: {
      authority: {
        backendMaterial: { sourcePackageFileSha256: [packageSha256] },
        fixture: true,
      },
      modules: [
        moduleEvidence(bundleModule.path, moduleSha256, packageSha256, 0, runtimeContentSha256),
      ],
    },
    deploymentManifest,
    deploymentManifestFileSha256: sha("f"),
  });

  assert.equal(report.routeMatrix[0].verdict, "proven");
  assert.equal(report.routeMatrix[0].sameSourceEligible, true);
});
