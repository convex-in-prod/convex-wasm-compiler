#!/usr/bin/env node

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

import { databaseIdentityFromDockerInspection } from "./lib/convex-local-backend-database.mjs";
import { normalizeDeployedRuntimeAuthority } from "./lib/convex-deployed-runtime-identity.mjs";
import { canonicalJson, fingerprintJson } from "./lib/convex-wasm-artifact-contract.mjs";

const REPORT_KIND = "convex-wasm-source-parity-identity-v1";
const RUNTIME_IDENTITY_KIND_V1 = "convex-deployed-runtime-module-v1";
const RUNTIME_IDENTITY_KIND_V2 = "convex-deployed-runtime-module-v2";
const SUPPORTED_DEPLOYMENT_KINDS = new Set([
  "convex-wasm-deployment-v2",
  "convex-wasm-deployment-v4",
]);
const MYSQL_SECRET = "/run/secrets/mysql-root-password";
const MYSQL_SESSION_MAX_OUTPUT_BYTES = 128 * 1024 * 1024;
const MYSQL_SESSION_QUERY_TIMEOUT_MS = 30_000;
const DEPLOYMENT_MANIFEST_MAX_BYTES = 64 * 1024 * 1024;
const HEX_SHA256 = /^[0-9a-f]{64}$/u;
const HEX_ID = /^[0-9A-F]{32}$/u;
const BASE32_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

export async function readStableSourceParityInput(path, maximumBytes, description) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail(`${description} reads require O_NOFOLLOW`);
  }
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    fail(`${description} maximum bytes must be a positive safe integer`);
  }
  const [canonical, beforePath] = await Promise.all([fs.realpath(path), fs.lstat(path)]);
  if (
    canonical !== path ||
    !beforePath.isFile() ||
    beforePath.size <= 0 ||
    beforePath.size > maximumBytes ||
    (beforePath.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && beforePath.uid !== process.getuid())
  ) {
    fail(`${description} must be a canonical owner-only bounded regular file`);
  }
  const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!sameFileState(beforePath, opened)) {
      fail(`${description} changed while it was opened`);
    }
    const bytes = Buffer.allocUnsafe(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead === 0) fail(`${description} changed while it was read`);
      offset += read.bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    const trailing = await handle.read(extra, 0, 1, offset);
    const [after, afterPath, afterCanonical] = await Promise.all([
      handle.stat(),
      fs.lstat(path),
      fs.realpath(path),
    ]);
    if (
      trailing.bytesRead !== 0 ||
      !sameFileState(opened, after) ||
      !sameFileState(opened, afterPath) ||
      afterCanonical !== path
    ) {
      fail(`${description} changed while it was read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function expectString(value, description) {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a nonempty string`);
  }
  return value;
}

function expectSha256(value, description) {
  const digest = expectString(value, description);
  if (!HEX_SHA256.test(digest)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return digest;
}

function expectObject(value, description) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  return value;
}

function expectCreationTime(value, description) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || Object.is(value, -0)) {
    fail(`${description} must be a finite nonnegative creation time`);
  }
  return value;
}

function decodeBase64Integer(value, description) {
  const encoded = expectString(
    expectObject(value, description).$integer,
    `${description}.$integer`
  );
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== 8) {
    fail(`${description} must contain an eight-byte Convex integer`);
  }
  const result = bytes.readBigInt64LE();
  if (result < 0n || result > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${description} is outside the supported nonnegative integer range`);
  }
  return Number(result);
}

function decodeBase32(value, description) {
  const outputLength = Math.floor((value.length * 5) / 8);
  const output = [];
  for (let offset = 0; offset < value.length; offset += 8) {
    const indexes = Array.from({ length: 8 }, () => 0);
    const chunk = value.slice(offset, offset + 8);
    for (let index = 0; index < chunk.length; index += 1) {
      const decoded = BASE32_ALPHABET.indexOf(chunk[index]);
      if (decoded < 0) {
        fail(`${description} is not a canonical Convex document ID`);
      }
      indexes[index] = decoded;
    }
    output.push(
      (indexes[0] << 3) | (indexes[1] >> 2),
      (indexes[1] << 6) | (indexes[2] << 1) | (indexes[3] >> 4),
      (indexes[3] << 4) | (indexes[4] >> 1),
      (indexes[4] << 7) | (indexes[5] << 2) | (indexes[6] >> 3),
      (indexes[6] << 5) | indexes[7]
    );
  }
  return Buffer.from(output.slice(0, outputLength));
}

function decodeDeveloperDocumentId(value, description) {
  const bytes = decodeBase32(expectString(value, description), description);
  let tableNumber = 0;
  let shift = 0;
  let offset = 0;
  let completeTableNumber = false;
  for (; offset < 5; offset += 1) {
    const byte = bytes[offset];
    if (byte === undefined) {
      fail(`${description} has a truncated table number`);
    }
    tableNumber += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if ((byte & 0x80) === 0) {
      offset += 1;
      completeTableNumber = true;
      break;
    }
  }
  const internalId = bytes.subarray(offset, offset + 16);
  if (
    !completeTableNumber ||
    tableNumber === 0 ||
    tableNumber > 0xffff_ffff ||
    internalId.length !== 16 ||
    bytes.length !== offset + 18
  ) {
    fail(`${description} has an invalid Convex document ID layout`);
  }
  let checksum0 = 0;
  let checksum1 = 0;
  for (const byte of bytes.subarray(0, bytes.length - 2)) {
    checksum0 = (checksum0 + byte) & 0xff;
    checksum1 = (checksum1 + checksum0) & 0xff;
  }
  const expectedChecksum = (checksum1 << 8) | checksum0;
  if (bytes.readUInt16LE(bytes.length - 2) !== expectedChecksum) {
    fail(`${description} has an invalid Convex document ID checksum`);
  }
  return { internalIdHex: internalId.toString("hex").toUpperCase(), tableNumber };
}

function encodeDeveloperDocumentId(tableNumber, internalIdHex) {
  if (
    !Number.isSafeInteger(tableNumber) ||
    tableNumber <= 0 ||
    tableNumber > 0xffff_ffff ||
    !HEX_ID.test(internalIdHex)
  ) {
    fail("cannot encode an invalid Convex document ID");
  }
  const bytes = [];
  let remainingTableNumber = tableNumber;
  while (remainingTableNumber >= 0x80) {
    bytes.push((remainingTableNumber & 0x7f) | 0x80);
    remainingTableNumber = Math.floor(remainingTableNumber / 0x80);
  }
  bytes.push(remainingTableNumber, ...Buffer.from(internalIdHex, "hex"));
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

function decodeRequiredSha256Bytes(value, description) {
  const bytes = Buffer.from(
    expectString(expectObject(value, description).$bytes, `${description}.$bytes`),
    "base64"
  );
  if (bytes.length !== 32) {
    fail(`${description} must contain exactly 32 bytes`);
  }
  return expectSha256(bytes.toString("hex"), description);
}

function decodeOptionalSha256Bytes(value, description) {
  return value === undefined ? null : decodeRequiredSha256Bytes(value, description);
}

function deploymentDigest(manifest) {
  const { deploymentSha256: _deploymentSha256, ...payload } = manifest;
  return fingerprintJson(payload);
}

function routeKey(entry) {
  return `${entry.runtimeModulePath}:${entry.exportName}`;
}

function executionSourceMatches(entry) {
  const source = entry.artifact?.executionManifest?.source;
  return (
    source?.modulePath === entry.source?.modulePath &&
    source?.runtimeModulePath === entry.runtimeModulePath &&
    source?.exportName === entry.exportName &&
    source?.udfKind === entry.udfKind &&
    source?.exportSha256 === entry.source?.exportSha256 &&
    source?.resolvedGraphSha256 === entry.source?.resolvedGraphSha256
  );
}

function artifactPackageIdentity(entry, manifestKind) {
  const executionManifest = entry.artifact?.executionManifest;
  if (manifestKind === "convex-wasm-deployment-v2") {
    const packageKey = entry.packageReference?.cacheKey;
    return {
      matches:
        typeof packageKey === "string" &&
        executionManifest !== undefined &&
        fingerprintJson(executionManifest) === packageKey,
      packageKey,
    };
  }

  const artifact = executionManifest?.artifact;
  const cohort = artifact?.cohort;
  const reference = entry.packageReference;
  const route = executionManifest?.route;
  const packageKey = reference?.cohortPackageId;
  return {
    matches:
      reference?.kind === "convex-wasm-cohort-route-reference-v1" &&
      typeof packageKey === "string" &&
      HEX_SHA256.test(packageKey) &&
      reference.entryId === artifact?.entryId &&
      reference.entrySelectorId === artifact?.entrySelectorId &&
      cohort?.packageId === packageKey &&
      cohort?.manifestSha256 === packageKey &&
      route?.kind === "convex-wasm-runtime-route-v1" &&
      route.runtimeModulePath === entry.runtimeModulePath &&
      route.exportName === entry.exportName &&
      route.udfKind === entry.udfKind &&
      executionManifest?.routing?.decision === "wasm",
    packageKey,
  };
}

function validateDeploymentManifest(manifest, selectionPolicy = "all-eligible") {
  if (!["all-eligible", "selected-wasm"].includes(selectionPolicy)) {
    fail("selection policy must be all-eligible or selected-wasm");
  }
  expectObject(manifest, "deployment manifest");
  if (!SUPPORTED_DEPLOYMENT_KINDS.has(manifest.kind) || manifest.mode !== "compile") {
    fail("deployment manifest must be a compiled convex-wasm-deployment-v2 or v4 manifest");
  }
  if (!Array.isArray(manifest.exports)) {
    fail("deployment manifest exports must be an array");
  }
  const expectedDigest = deploymentDigest(manifest);
  if (manifest.deploymentSha256 !== expectedDigest) {
    fail("deployment manifest digest is invalid");
  }
  const candidates = manifest.exports.filter((entry) => entry.routing?.decision === "wasm");
  if (candidates.length === 0) {
    fail("deployment manifest has no Wasm candidates");
  }
  const artifactFallback =
    manifest.kind === "convex-wasm-deployment-v4" ? manifest.counts?.artifactFallback : 0;
  if (
    !Number.isSafeInteger(manifest.counts?.eligible) ||
    !Number.isSafeInteger(manifest.counts?.selectedWasm) ||
    !Number.isSafeInteger(manifest.counts?.unselectedEligible) ||
    !Number.isSafeInteger(artifactFallback) ||
    manifest.counts.eligible < 0 ||
    manifest.counts.selectedWasm < 0 ||
    manifest.counts.unselectedEligible < 0 ||
    artifactFallback < 0 ||
    manifest.counts.selectedWasm !== candidates.length ||
    manifest.counts.eligible !==
      manifest.counts.selectedWasm + manifest.counts.unselectedEligible + artifactFallback
  ) {
    fail("deployment manifest has inconsistent eligible-selection counts");
  }
  if (selectionPolicy === "all-eligible" && manifest.counts.unselectedEligible !== 0) {
    fail("deployment manifest is not an accepted all-eligible selection");
  }
  const keys = candidates.map(routeKey);
  if (new Set(keys).size !== keys.length) {
    fail("deployment manifest has duplicate Wasm route identities");
  }
  return candidates.sort((left, right) => compareStrings(routeKey(left), routeKey(right)));
}

function mismatch(code, detail) {
  return { code, detail };
}

export function createDeployedRuntimeBindingAuthority(database) {
  const sourcePackageFileSha256 = database.authority?.backendMaterial?.sourcePackageFileSha256;
  if (!Array.isArray(sourcePackageFileSha256)) {
    fail("database authority does not authenticate source-package file material");
  }
  const identity = {
    kind: "convex-deployed-runtime-binding-authority-v1",
    modules: database.modules
      .filter(
        (module) =>
          module.environment === "isolate" &&
          typeof module.sha256 === "string" &&
          typeof module.sourcePackageSha256 === "string"
      )
      .map((module) => {
        const sourcePackageRuntimeContentSha256 = module.sourcePackageRuntimeContentSha256 ?? null;
        return {
          environment: module.environment,
          moduleHashVerified: module.moduleHashVerified === true,
          moduleSha256: module.sha256,
          path: module.path,
          sourceMap: module.sourceMap,
          sourcePackageHashVerified: module.sourcePackageHashVerified === true,
          sourcePackageSha256: module.sourcePackageSha256,
          ...(sourcePackageRuntimeContentSha256 === null
            ? {}
            : { sourcePackageRuntimeContentSha256 }),
          sourceSha256: module.sourceSha256 ?? null,
        };
      })
      .sort((left, right) => compareStrings(left.path, right.path)),
    sourcePackageFileSha256: [...sourcePackageFileSha256].sort(),
  };
  if (identity.sourcePackageFileSha256.length > 0) {
    const normalized = normalizeDeployedRuntimeAuthority(identity);
    return { ...normalized.identity, authoritySha256: normalized.sha256 };
  }
  return { ...identity, authoritySha256: fingerprintJson(identity) };
}

export function createSourceParityIdentityReport({
  database,
  deploymentManifest,
  deploymentManifestFileSha256,
  selectionPolicy = "all-eligible",
}) {
  const candidates = validateDeploymentManifest(deploymentManifest, selectionPolicy);
  expectObject(database, "database evidence");
  if (!Array.isArray(database.modules)) {
    fail("database evidence modules must be an array");
  }
  const modules = new Map(database.modules.map((module) => [module.path, module]));
  if (modules.size !== database.modules.length) {
    fail("database evidence has duplicate runtime module paths");
  }
  const routeMatrix = candidates.map((entry) => {
    const reasons = [];
    const runtimeModule = modules.get(entry.runtimeModulePath);
    const hasRuntimeModuleMetadata = runtimeModule !== undefined && runtimeModule.sha256 !== null;
    const sourcePackageRuntimeContentSha256 =
      runtimeModule?.sourcePackageRuntimeContentSha256 ?? null;
    const { matches: packageIdentityMatches, packageKey } = artifactPackageIdentity(
      entry,
      deploymentManifest.kind
    );

    if (!hasRuntimeModuleMetadata) {
      reasons.push(
        mismatch(
          "DEPLOYED_RUNTIME_MODULE_NOT_FOUND",
          `the active _modules snapshot has no ${entry.runtimeModulePath}`
        )
      );
    } else {
      if (runtimeModule.sourceSha256 === null) {
        reasons.push(
          mismatch(
            "DEPLOYED_RUNTIME_MODULE_SOURCE_NOT_FOUND",
            "the active V8 load package has no bytes for the runtime module"
          )
        );
      } else if (!runtimeModule.moduleHashVerified) {
        reasons.push(
          mismatch(
            "DEPLOYED_RUNTIME_MODULE_HASH_FAILED",
            "the source-package bytes do not reproduce the active _modules SHA-256"
          )
        );
      }
      if (runtimeModule.sourcePackageSha256 === null) {
        reasons.push(
          mismatch(
            "DEPLOYED_SOURCE_PACKAGE_NOT_FOUND",
            "the active _modules snapshot references no available V8 load package"
          )
        );
      } else if (!runtimeModule.sourcePackageHashVerified) {
        reasons.push(
          mismatch(
            "DEPLOYED_SOURCE_PACKAGE_HASH_FAILED",
            "the stored source-package bytes do not reproduce the active _source_packages SHA-256"
          )
        );
      }
      if (sourcePackageRuntimeContentSha256 === null) {
        reasons.push(
          mismatch(
            "DEPLOYED_SOURCE_PACKAGE_RUNTIME_CONTENT_DIGEST_NOT_FOUND",
            "the active SourcePackage predates the persisted runtime-content digest"
          )
        );
      }
      if (runtimeModule.environment !== "isolate") {
        reasons.push(
          mismatch(
            "DEPLOYED_RUNTIME_ENVIRONMENT_MISMATCH",
            "the active runtime module is not an isolate/V8 module"
          )
        );
      }
    }
    if (!executionSourceMatches(entry)) {
      reasons.push(
        mismatch(
          "ARTIFACT_EXECUTION_SOURCE_MISMATCH",
          "the embedded execution source identity disagrees with the deployment route"
        )
      );
    }
    if (!packageIdentityMatches) {
      reasons.push(
        mismatch(
          "ARTIFACT_PACKAGE_ID_MISMATCH",
          "the artifact package key does not authenticate its execution manifest"
        )
      );
    }

    const boundIdentity = entry.source?.deployedRuntimeIdentity;
    // The missing active module is the complete route-level diagnosis. Binding and source-map
    // comparisons require runtime material and would make the absence report misleading.
    if (hasRuntimeModuleMetadata) {
      if (boundIdentity === undefined) {
        reasons.push(
          mismatch(
            "DEPLOYED_RUNTIME_IDENTITY_NOT_BOUND",
            "the authenticated compiler manifest does not bind the uploaded module and source-package digests"
          )
        );
        if (runtimeModule.sourceMap.sourcesContentCount === 0) {
          reasons.push(
            mismatch(
              "DEPLOYED_SOURCE_MAP_HAS_NO_SOURCES_CONTENT",
              "the deployed source map retains no original source content for an independent bridge"
            )
          );
        }
      } else if (boundIdentity.kind === RUNTIME_IDENTITY_KIND_V1) {
        if (
          boundIdentity.moduleSha256 !== runtimeModule.sha256 ||
          boundIdentity.sourcePackageSha256 !== runtimeModule.sourcePackageSha256
        ) {
          reasons.push(
            mismatch(
              "DEPLOYED_RUNTIME_IDENTITY_BINDING_MISMATCH",
              "the compiler-bound uploaded module identity does not match the active database material"
            )
          );
        } else {
          reasons.push(
            mismatch(
              "DEPLOYED_RUNTIME_IDENTITY_LEGACY_RAW_ARCHIVE_ONLY",
              "the compiler binding uses a source-package archive digest instead of persisted runtime content"
            )
          );
        }
      } else if (
        boundIdentity.kind !== RUNTIME_IDENTITY_KIND_V2 ||
        boundIdentity.moduleSha256 !== runtimeModule.sha256 ||
        (sourcePackageRuntimeContentSha256 !== null &&
          boundIdentity.sourcePackageRuntimeContentSha256 !== sourcePackageRuntimeContentSha256)
      ) {
        reasons.push(
          mismatch(
            "DEPLOYED_RUNTIME_IDENTITY_BINDING_MISMATCH",
            "the compiler-bound uploaded module identity does not match the active database material"
          )
        );
      }
    }

    const hasMaterialMismatch = reasons.some(
      ({ code }) =>
        code !== "DEPLOYED_RUNTIME_IDENTITY_NOT_BOUND" &&
        code !== "DEPLOYED_SOURCE_MAP_HAS_NO_SOURCES_CONTENT" &&
        code !== "DEPLOYED_SOURCE_PACKAGE_RUNTIME_CONTENT_DIGEST_NOT_FOUND" &&
        code !== "DEPLOYED_RUNTIME_IDENTITY_LEGACY_RAW_ARCHIVE_ONLY"
    );
    const verdict =
      reasons.length === 0 ? "proven" : hasMaterialMismatch ? "mismatch" : "unprovable";
    return {
      artifact: {
        packageKey: typeof packageKey === "string" ? packageKey : null,
        source: entry.source,
      },
      deployedRuntime: hasRuntimeModuleMetadata
        ? {
            environment: runtimeModule.environment,
            moduleSha256: runtimeModule.sha256,
            path: runtimeModule.path,
            sourceSha256: runtimeModule.sourceSha256 ?? null,
            sourceMap: runtimeModule.sourceMap,
            sourcePackageSha256: runtimeModule.sourcePackageSha256,
            sourcePackageRuntimeContentSha256,
          }
        : null,
      exportName: entry.exportName,
      reasons,
      route: routeKey(entry),
      runtimeModulePath: entry.runtimeModulePath,
      sameSourceEligible: verdict === "proven",
      udfKind: entry.udfKind,
      verdict,
    };
  });

  const counts = {
    mismatch: routeMatrix.filter(({ verdict }) => verdict === "mismatch").length,
    proven: routeMatrix.filter(({ verdict }) => verdict === "proven").length,
    totalEligibleCandidates: routeMatrix.length,
    unprovable: routeMatrix.filter(({ verdict }) => verdict === "unprovable").length,
  };
  const payload = {
    authority: {
      compiler: {
        deploymentFileSha256: expectSha256(
          deploymentManifestFileSha256,
          "deployment manifest file SHA-256"
        ),
        deploymentSha256: deploymentManifest.deploymentSha256,
        graphSha256: deploymentManifest.graph?.sha256 ?? null,
      },
      deployedRuntime: database.authority,
    },
    bindingAuthority: createDeployedRuntimeBindingAuthority(database),
    consumerContract: {
      eligibleVerdict: "proven",
      identityKind: RUNTIME_IDENTITY_KIND_V2,
      rule: "A broader V8/Wasm A/B selector may consume only routes whose verdict is proven; names, results, and unprovable routes are not source identity.",
    },
    counts,
    gatePass: counts.proven > 0 && counts.proven === counts.totalEligibleCandidates,
    kind: REPORT_KIND,
    routeMatrix,
    selection: {
      manifestEligible: deploymentManifest.counts.eligible,
      policy: selectionPolicy,
      selectedWasm: deploymentManifest.counts.selectedWasm,
      unselectedEligible: deploymentManifest.counts.unselectedEligible,
    },
  };
  return { ...payload, reportSha256: fingerprintJson(payload) };
}

function run(command, arguments_, options = {}) {
  return execFileSync(command, arguments_, {
    encoding: Object.hasOwn(options, "encoding") ? options.encoding : "utf8",
    input: options.input,
    maxBuffer: 128 * 1024 * 1024,
    stdio: options.stdio,
  });
}

function dockerInspect(containerId) {
  const [container] = JSON.parse(run("docker", ["inspect", containerId]));
  if (!container || container.Id !== containerId) {
    fail(`Docker did not resolve exact container ${containerId}`);
  }
  return container;
}

function mysqlQuery(containerId, database, query) {
  return run("docker", [
    "exec",
    containerId,
    "sh",
    "-c",
    `MYSQL_PWD="$(cat ${MYSQL_SECRET})" exec mysql --batch --raw --skip-column-names -uroot -D "$1" -e "$2"`,
    "convex-wasm-source-parity-identity",
    database,
    query,
  ]);
}

function openLocalMysqlSession({ containerId, database, spawnImplementation = spawn }) {
  const child = spawnImplementation(
    "docker",
    [
      "exec",
      "-i",
      containerId,
      "sh",
      "-c",
      `MYSQL_PWD="$(cat ${MYSQL_SECRET})" exec mysql --batch --raw --skip-column-names --unbuffered -uroot -D "$1"`,
      "convex-wasm-source-parity-identity",
      database,
    ],
    { stdio: ["pipe", "pipe", "pipe"] }
  );
  let buffered = "";
  let outputBytes = 0;
  let pending = null;
  let processFailure = null;
  let stderrBytes = 0;
  const rejectPending = (message) => {
    if (pending === null) {
      return;
    }
    const current = pending;
    pending = null;
    clearTimeout(current.timeout);
    current.reject(new Error(message));
  };
  const exit = new Promise((resolveExit) => {
    child.once("error", () => {
      processFailure = "failed to start";
      rejectPending("local MySQL snapshot client failed to start");
    });
    child.once("close", (code, signal) => {
      if (code !== 0 || signal !== null) {
        processFailure = "exited unsuccessfully";
        rejectPending("local MySQL snapshot client exited unsuccessfully");
      } else if (pending !== null) {
        processFailure = "exited before returning a result";
        rejectPending("local MySQL snapshot client exited before returning a result");
      }
      resolveExit({ code, signal });
    });
  });
  child.stdin.on("error", () => {
    processFailure = "input failed";
    rejectPending("local MySQL snapshot client input failed");
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > MYSQL_SESSION_MAX_OUTPUT_BYTES) {
      processFailure = "stderr limit exceeded";
      child.kill("SIGKILL");
      rejectPending("local MySQL snapshot client stderr exceeded its limit");
    }
  });
  child.stdout.on("data", (chunk) => {
    outputBytes += chunk.length;
    if (outputBytes > MYSQL_SESSION_MAX_OUTPUT_BYTES) {
      processFailure = "output limit exceeded";
      child.kill("SIGKILL");
      rejectPending("local MySQL snapshot client output exceeded its limit");
      return;
    }
    buffered += chunk.toString("utf8");
    while (true) {
      const newline = buffered.indexOf("\n");
      if (newline < 0) {
        break;
      }
      const line = buffered.slice(0, newline).replace(/\r$/u, "");
      buffered = buffered.slice(newline + 1);
      if (pending === null) {
        processFailure = "returned unframed output";
        child.kill("SIGKILL");
        return;
      }
      if (line === pending.marker) {
        const current = pending;
        pending = null;
        clearTimeout(current.timeout);
        current.resolve(current.lines.length === 0 ? "" : `${current.lines.join("\n")}\n`);
      } else {
        pending.lines.push(line);
      }
    }
  });

  return {
    async close() {
      if (child.exitCode === null && child.signalCode === null) {
        child.stdin.end();
      }
      const result = await exit;
      if (
        processFailure !== null ||
        result.code !== 0 ||
        result.signal !== null ||
        buffered.length !== 0 ||
        pending !== null
      ) {
        fail("local MySQL snapshot client did not close cleanly");
      }
    },
    async query(query) {
      if (
        typeof query !== "string" ||
        query.length === 0 ||
        query.includes("\u0000") ||
        pending !== null ||
        processFailure !== null ||
        child.exitCode !== null ||
        child.signalCode !== null
      ) {
        fail("local MySQL snapshot client is not ready for one query");
      }
      const marker = `__convex_snapshot_${randomBytes(16).toString("hex")}__`;
      const result = new Promise((resolveQuery, rejectQuery) => {
        pending = {
          lines: [],
          marker,
          reject: rejectQuery,
          resolve: resolveQuery,
          timeout: setTimeout(() => {
            processFailure = "query timed out";
            child.kill("SIGKILL");
            rejectPending("local MySQL snapshot query timed out");
          }, MYSQL_SESSION_QUERY_TIMEOUT_MS),
        };
      });
      try {
        await new Promise((resolveWrite, rejectWrite) => {
          child.stdin.write(`${query};\nSELECT '${marker}';\n`, (error) => {
            if (error === null || error === undefined) {
              resolveWrite();
            } else {
              processFailure = "query write failed";
              rejectPending("local MySQL snapshot query write failed");
              rejectWrite(new Error("local MySQL snapshot query write failed"));
            }
          });
        });
      } catch (error) {
        await result.catch(() => {});
        throw error;
      }
      return result;
    },
  };
}

export async function withMysqlConsistentSnapshot({
  containerId,
  database,
  openSession = openLocalMysqlSession,
  read,
}) {
  if (typeof read !== "function") {
    fail("local MySQL snapshot read callback is required");
  }
  const session = await openSession({ containerId, database });
  let transactionStarted = false;
  let primaryError = null;
  let result;
  try {
    await session.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    await session.query("START TRANSACTION WITH CONSISTENT SNAPSHOT");
    transactionStarted = true;
    result = await read((query) => session.query(query));
    await session.query("COMMIT");
    transactionStarted = false;
  } catch (error) {
    primaryError = error;
    if (transactionStarted) {
      try {
        await session.query("ROLLBACK");
      } catch {
        // The original snapshot failure is authoritative; rollback is cleanup only.
      }
    }
  }
  try {
    await session.close();
  } catch (error) {
    if (primaryError === null) {
      primaryError = error;
    }
  }
  if (primaryError !== null) {
    throw primaryError;
  }
  return result;
}

function currentRowsQuery(tabletHex) {
  if (!HEX_ID.test(tabletHex)) {
    fail(`invalid MySQL tablet ID ${tabletHex}`);
  }
  return [
    "SELECT HEX(d.id), HEX(d.json_value)",
    "FROM documents d",
    "JOIN (",
    "  SELECT id, MAX(ts) AS ts",
    "  FROM documents",
    `  WHERE table_id=UNHEX("${tabletHex}")`,
    "  GROUP BY id",
    ") latest ON d.id=latest.id AND d.ts=latest.ts",
    `WHERE d.table_id=UNHEX("${tabletHex}") AND d.deleted=0`,
    "ORDER BY d.id",
  ].join(" ");
}

async function decodeRows(rowsSource, decoder, temporaryDirectory, label) {
  const rows = rowsSource
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [idHex, encodedDocument, ...rest] = line.split("\t");
      if (!HEX_ID.test(idHex) || !/^[0-9A-F]+$/u.test(encodedDocument) || rest.length !== 0) {
        fail(`${label} query returned malformed encoded document data`);
      }
      return { encodedDocument, idHex };
    });
  if (rows.length === 0) {
    return [];
  }
  const outputPath = join(temporaryDirectory, `${label}.jsonl`);
  run(decoder, [outputPath], {
    input: `${rows.map(({ encodedDocument }) => encodedDocument).join("\n")}\n`,
    stdio: ["pipe", "ignore", "pipe"],
  });
  const envelopes = (await fs.readFile(outputPath, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line, index) => {
      const envelope = expectObject(JSON.parse(line), `${label} decoder row ${index}`);
      if (
        Object.keys(envelope).length !== 2 ||
        !Object.hasOwn(envelope, "creationTime") ||
        !Object.hasOwn(envelope, "document")
      ) {
        fail(`${label} decoder row ${index} must contain only creationTime and document`);
      }
      return {
        creationTime: expectCreationTime(
          envelope.creationTime,
          `${label} decoder row ${index} creationTime`
        ),
        document: expectObject(envelope.document, `${label} decoder row ${index} document`),
      };
    });
  if (envelopes.length !== rows.length) {
    fail(`${label} decoder output count does not match its MySQL row count`);
  }
  return envelopes.map((envelope, index) => ({
    ...envelope,
    idHex: rows[index].idHex,
  }));
}

export function resolveLatestSourcePackageAuthority({
  moduleRows,
  sourcePackageRows,
  sourcePackagesTableNumber,
}) {
  if (!Array.isArray(moduleRows) || !Array.isArray(sourcePackageRows)) {
    fail("decoded module and source-package rows must be arrays");
  }
  if (
    !Number.isSafeInteger(sourcePackagesTableNumber) ||
    sourcePackagesTableNumber <= 0 ||
    sourcePackagesTableNumber > 0xffff_ffff
  ) {
    fail("source-packages table number must be a positive 32-bit integer");
  }

  const sourcePackageRowsById = new Map();
  for (const [index, row] of sourcePackageRows.entries()) {
    const idHex = expectString(row?.idHex, `_source_packages row ${index} ID`);
    if (!HEX_ID.test(idHex)) {
      fail(`_source_packages row ${index} has an invalid internal ID`);
    }
    if (sourcePackageRowsById.has(idHex)) {
      fail(`_source_packages contains duplicate internal ID ${idHex}`);
    }
    const document = expectObject(row.document, `_source_packages ${idHex} document`);
    sourcePackageRowsById.set(idHex, {
      creationTime: expectCreationTime(row.creationTime, `_source_packages ${idHex} creationTime`),
      developerId: encodeDeveloperDocumentId(sourcePackagesTableNumber, idHex),
      internalIdHex: idHex,
      packageSha256: decodeRequiredSha256Bytes(document.sha256, `_source_packages ${idHex}.sha256`),
      runtimeContentSha256: decodeOptionalSha256Bytes(
        document.runtimeContentSha256,
        `_source_packages ${idHex}.runtimeContentSha256`
      ),
      storageKey: expectString(document.storageKey, `_source_packages ${idHex}.storageKey`),
    });
  }

  const activeModules = [];
  const modulePaths = new Set();
  let previousModuleIdHex = null;
  for (const [index, row] of moduleRows.entries()) {
    const idHex = expectString(row?.idHex, `_modules row ${index} ID`);
    if (!HEX_ID.test(idHex)) {
      fail(`_modules row ${index} has an invalid internal ID`);
    }
    if (previousModuleIdHex !== null && idHex <= previousModuleIdHex) {
      fail("_modules rows must preserve the backend by-ID scan order");
    }
    previousModuleIdHex = idHex;

    const document = expectObject(row.document, `_modules ${idHex} document`);
    const path = expectString(document.path, `_modules ${idHex}.path`);
    if (modulePaths.has(path)) {
      fail(`active _modules contains duplicate path ${path}`);
    }
    modulePaths.add(path);

    const developerId = expectString(document.sourcePackageId, `${path}.sourcePackageId`);
    const sourcePackageId = decodeDeveloperDocumentId(developerId, `${path}.sourcePackageId`);
    if (sourcePackageId.tableNumber !== sourcePackagesTableNumber) {
      fail(`${path} references a source package from the wrong table`);
    }
    const sourcePackageRow = sourcePackageRowsById.get(sourcePackageId.internalIdHex);
    if (!sourcePackageRow) {
      fail(`${path} references an unavailable active source package`);
    }

    const retainedSourcePackage = sourcePackageRow;
    if (retainedSourcePackage.developerId !== developerId) {
      fail(`${path} has an inconsistent source-package developer ID`);
    }

    activeModules.push({
      environment: expectString(document.environment, `${path}.environment`),
      idHex,
      path,
      retainedSourcePackage,
      sha256: expectSha256(
        Buffer.from(expectString(document.sha256, `${path}.sha256`), "base64").toString("hex"),
        `${path}.sha256`
      ),
    });
  }

  let latestCommittedSourcePackage = null;
  for (const sourcePackage of sourcePackageRowsById.values()) {
    if (
      latestCommittedSourcePackage === null ||
      sourcePackage.creationTime > latestCommittedSourcePackage.creationTime ||
      (sourcePackage.creationTime === latestCommittedSourcePackage.creationTime &&
        sourcePackage.internalIdHex > latestCommittedSourcePackage.internalIdHex)
    ) {
      latestCommittedSourcePackage = sourcePackage;
    }
  }
  if (latestCommittedSourcePackage === null) {
    return {
      activeModules,
      latestCommittedSourcePackage: null,
      v8LoadPackageIdentity: null,
    };
  }

  return {
    activeModules,
    latestCommittedSourcePackage,
    v8LoadPackageIdentity: {
      creationTime: latestCommittedSourcePackage.creationTime,
      developerId: latestCommittedSourcePackage.developerId,
      internalIdHex: latestCommittedSourcePackage.internalIdHex,
      packageSha256: latestCommittedSourcePackage.packageSha256,
      runtimeContentSha256: latestCommittedSourcePackage.runtimeContentSha256,
      storageKey: latestCommittedSourcePackage.storageKey,
    },
  };
}

function parseSourceMap(source) {
  if (source === null) {
    return {
      sha256: null,
      size: 0,
      sourcesContentCount: 0,
      sourcesCount: 0,
    };
  }
  const parsed = JSON.parse(source.toString("utf8"));
  const sources = Array.isArray(parsed.sources) ? parsed.sources : [];
  const sourcesContent = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];
  return {
    sha256: sha256(source),
    size: source.length,
    sourcesContentCount: sourcesContent.filter((value) => typeof value === "string").length,
    sourcesCount: sources.length,
  };
}

export function createRuntimeModuleEvidence({
  loadPackageMaterial,
  module,
  runtimeModulePath,
  source,
  sourceMap,
}) {
  const path = expectString(runtimeModulePath, "runtime module path");
  if (loadPackageMaterial === null) {
    if (module !== null || source !== null || sourceMap !== null) {
      fail("V8 cannot have module bytes without a latest load package");
    }
    return {
      environment: null,
      moduleHashVerified: false,
      path,
      retainedSourcePackage: null,
      sha256: null,
      sourceMap: parseSourceMap(null),
      sourcePackageHashVerified: false,
      sourcePackageSha256: null,
      sourcePackageRuntimeContentSha256: null,
      sourceSha256: null,
    };
  }
  expectObject(loadPackageMaterial, "V8 load-package material");
  const sourcePackageSha256 = expectSha256(
    loadPackageMaterial.sha256,
    "V8 load-package material SHA-256"
  );
  const sourcePackageRuntimeContentSha256 =
    loadPackageMaterial.runtimeContentSha256 === null ||
    loadPackageMaterial.runtimeContentSha256 === undefined
      ? null
      : expectSha256(
          loadPackageMaterial.runtimeContentSha256,
          "V8 load-package runtime-content SHA-256"
        );
  if (typeof loadPackageMaterial.sourcePackageHashVerified !== "boolean") {
    fail("V8 load-package hash verdict must be boolean");
  }
  if (module === null) {
    if (source !== null || sourceMap !== null) {
      fail(`missing runtime module ${path} cannot have package bytes`);
    }
    return {
      environment: null,
      moduleHashVerified: false,
      path,
      retainedSourcePackage: null,
      sha256: null,
      sourceMap: parseSourceMap(null),
      sourcePackageHashVerified: loadPackageMaterial.sourcePackageHashVerified,
      sourcePackageSha256,
      sourcePackageRuntimeContentSha256,
      sourceSha256: null,
    };
  }

  expectObject(module, `${path} module metadata`);
  const retainedSourcePackage = expectObject(
    module.retainedSourcePackage,
    `${path} retained source-package diagnostics`
  );
  const moduleSha256 = expectSha256(module.sha256, `${path} module SHA-256`);
  if (source === null) {
    if (sourceMap !== null) {
      fail(`missing runtime module source ${path} cannot have a source map`);
    }
    return {
      environment: expectString(module.environment, `${path} environment`),
      moduleHashVerified: false,
      path,
      retainedSourcePackage,
      sha256: moduleSha256,
      sourceMap: parseSourceMap(null),
      sourcePackageHashVerified: loadPackageMaterial.sourcePackageHashVerified,
      sourcePackageSha256,
      sourcePackageRuntimeContentSha256,
      sourceSha256: null,
    };
  }
  if (!Buffer.isBuffer(source) || (sourceMap !== null && !Buffer.isBuffer(sourceMap))) {
    fail(`${path} package source and source map must be buffers`);
  }
  return {
    environment: expectString(module.environment, `${path} environment`),
    moduleHashVerified:
      sha256(sourceMap === null ? source : Buffer.concat([source, sourceMap])) === moduleSha256,
    path,
    retainedSourcePackage,
    sha256: moduleSha256,
    sourceMap: parseSourceMap(sourceMap),
    sourcePackageHashVerified: loadPackageMaterial.sourcePackageHashVerified,
    sourcePackageSha256,
    sourcePackageRuntimeContentSha256,
    sourceSha256: sha256(source),
  };
}

function parseZipListing(source) {
  return new Set(source.trim().split("\n").filter(Boolean));
}

export function validateBackendDatabaseSelection(backend, database) {
  const identity = databaseIdentityFromDockerInspection(backend);
  if (database !== identity.database) {
    fail(
      `requested MySQL database ${database} does not match backend instance ${identity.instanceName} resolved database ${identity.database}`
    );
  }
  return identity;
}

async function collectDatabaseEvidence(options, runtimeModulePaths) {
  const before = dockerInspect(options.mysqlContainer);
  if (before.State?.StartedAt !== options.expectedMysqlStart) {
    fail("MySQL container start identity changed");
  }
  const mysqlMount = before.Mounts?.find(
    (mount) => mount.Name === options.expectedMysqlVolume && mount.Destination === "/var/lib/mysql"
  );
  if (!mysqlMount) {
    fail("MySQL container no longer uses the expected data volume");
  }
  const backend = dockerInspect(options.backendContainer);
  const backendMount = backend.Mounts?.find(
    (mount) => mount.Name === options.expectedBackendVolume && mount.Destination === "/convex/data"
  );
  if (!backendMount) {
    fail("backend container no longer exposes the expected source-package volume");
  }
  const backendDatabase = validateBackendDatabaseSelection(backend, options.database);

  const temporaryDirectory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-source-identity-"));
  try {
    const startMaxTs = expectString(
      mysqlQuery(options.mysqlContainer, options.database, "SELECT MAX(ts) FROM documents").trim(),
      "starting MySQL maximum timestamp"
    );
    const { moduleRows, requiredTables, sourcePackageRows, tablesTabletHex } =
      await withMysqlConsistentSnapshot({
        containerId: options.mysqlContainer,
        database: options.database,
        read: async (query) => {
          const snapshotMaxTs = expectString(
            (await query("SELECT MAX(ts) FROM documents")).trim(),
            "snapshot MySQL maximum timestamp"
          );
          if (snapshotMaxTs !== startMaxTs) {
            fail("MySQL changed before the consistent identity snapshot started");
          }
          const tablesIdSource = (
            await query(
              "SELECT JSON_UNQUOTE(CAST(json_value AS CHAR)) FROM persistence_globals WHERE `key`='tables_table_id'"
            )
          ).trim();
          const tablesTabletHex = Buffer.from(tablesIdSource, "base64")
            .toString("hex")
            .toUpperCase();
          if (!HEX_ID.test(tablesTabletHex)) {
            fail("tables_table_id persistence global is invalid");
          }
          const tables = await decodeRows(
            await query(currentRowsQuery(tablesTabletHex)),
            options.decoder,
            temporaryDirectory,
            "tables"
          );
          const requiredTables = new Map();
          for (const name of ["_modules", "_source_packages"]) {
            const matches = tables.filter(
              ({ document }) =>
                document.name === name &&
                document.state === "active" &&
                document.namespace === undefined
            );
            if (matches.length !== 1) {
              fail(`expected one active global ${name} table, found ${matches.length}`);
            }
            requiredTables.set(name, {
              ...matches[0],
              number: decodeBase64Integer(matches[0].document.number, `${name}.number`),
            });
          }
          const moduleRows = await decodeRows(
            await query(currentRowsQuery(requiredTables.get("_modules").idHex)),
            options.decoder,
            temporaryDirectory,
            "modules"
          );
          const sourcePackageRows = await decodeRows(
            await query(currentRowsQuery(requiredTables.get("_source_packages").idHex)),
            options.decoder,
            temporaryDirectory,
            "source-packages"
          );
          return { moduleRows, requiredTables, sourcePackageRows, tablesTabletHex };
        },
      });
    const { activeModules, latestCommittedSourcePackage, v8LoadPackageIdentity } =
      resolveLatestSourcePackageAuthority({
        moduleRows,
        sourcePackageRows,
        sourcePackagesTableNumber: requiredTables.get("_source_packages").number,
      });
    const allModules = new Map(activeModules.map((module) => [module.path, module]));

    let loadPackageMaterial = null;
    if (v8LoadPackageIdentity !== null) {
      const blobPath = join(
        temporaryDirectory,
        `${v8LoadPackageIdentity.storageKey}.source-package.zip`
      );
      run("docker", [
        "cp",
        `${options.backendContainer}:/convex/data/storage/modules/${v8LoadPackageIdentity.storageKey}.blob`,
        blobPath,
      ]);
      const sourcePackageBytes = await fs.readFile(blobPath);
      const sourcePackageSha256 = sha256(sourcePackageBytes);
      loadPackageMaterial = {
        blobPath,
        sha256: sourcePackageSha256,
        size: sourcePackageBytes.length,
        runtimeContentSha256: v8LoadPackageIdentity.runtimeContentSha256,
        sourcePackageHashVerified: sourcePackageSha256 === v8LoadPackageIdentity.packageSha256,
        zipEntries: parseZipListing(run("unzip", ["-Z1", blobPath])),
      };
    }
    const relevantModules = [];
    for (const runtimeModulePath of [...runtimeModulePaths].sort()) {
      const module = allModules.get(runtimeModulePath);
      if (!module) {
        relevantModules.push(
          createRuntimeModuleEvidence({
            loadPackageMaterial,
            module: null,
            runtimeModulePath,
            source: null,
            sourceMap: null,
          })
        );
        continue;
      }
      const sourcePath = `modules/${runtimeModulePath}`;
      if (loadPackageMaterial === null) {
        fail("active module metadata exists without a V8 load package");
      }
      if (!loadPackageMaterial.zipEntries.has(sourcePath)) {
        relevantModules.push(
          createRuntimeModuleEvidence({
            loadPackageMaterial,
            module,
            runtimeModulePath,
            source: null,
            sourceMap: null,
          })
        );
        continue;
      }
      const source = run("unzip", ["-p", loadPackageMaterial.blobPath, sourcePath], {
        encoding: "buffer",
      });
      const sourceMapPath = `${sourcePath}.map`;
      const sourceMap = loadPackageMaterial.zipEntries.has(sourceMapPath)
        ? run("unzip", ["-p", loadPackageMaterial.blobPath, sourceMapPath], {
            encoding: "buffer",
          })
        : null;
      relevantModules.push(
        createRuntimeModuleEvidence({
          loadPackageMaterial,
          module,
          runtimeModulePath,
          source,
          sourceMap,
        })
      );
    }

    const endMaxTs = expectString(
      mysqlQuery(options.mysqlContainer, options.database, "SELECT MAX(ts) FROM documents").trim(),
      "ending MySQL maximum timestamp"
    );
    if (startMaxTs !== endMaxTs) {
      fail("MySQL changed during the identity snapshot");
    }
    const after = dockerInspect(options.mysqlContainer);
    if (
      after.Id !== before.Id ||
      after.State?.StartedAt !== before.State?.StartedAt ||
      !after.Mounts?.some(
        (mount) =>
          mount.Name === options.expectedMysqlVolume && mount.Destination === "/var/lib/mysql"
      )
    ) {
      fail("MySQL container identity changed during the identity snapshot");
    }
    return {
      authority: {
        backendMaterial: {
          containerId: backend.Id,
          containerState: backend.State?.Status ?? null,
          database: backendDatabase.database,
          instanceName: backendDatabase.instanceName,
          sourcePackageCount: loadPackageMaterial === null ? 0 : 1,
          sourcePackageFileSha256: loadPackageMaterial === null ? [] : [loadPackageMaterial.sha256],
          v8LoadPackage: v8LoadPackageIdentity,
          volume: options.expectedBackendVolume,
        },
        database: {
          database: options.database,
          maxTimestamp: startMaxTs,
          modulesTable: {
            liveDocumentCount: moduleRows.length,
            number: requiredTables.get("_modules").number,
            tabletIdHex: requiredTables.get("_modules").idHex,
          },
          sourcePackagesTable: {
            liveDocumentCount: sourcePackageRows.length,
            number: requiredTables.get("_source_packages").number,
            tabletIdHex: requiredTables.get("_source_packages").idHex,
          },
          tablesTabletIdHex: tablesTabletHex,
        },
        latestCommittedSourcePackage,
        moduleHashAlgorithm: "sha256(uploaded JavaScript bytes || optional source-map bytes)",
        mysqlContainer: {
          id: before.Id,
          startedAt: before.State.StartedAt,
          volume: options.expectedMysqlVolume,
        },
        sourcePackageHashAlgorithm: "sha256(exact stored source-package zip bytes)",
      },
      modules: relevantModules,
    };
  } finally {
    await fs.rm(temporaryDirectory, { force: true, recursive: true });
  }
}

function sqliteCurrentRows(database, tabletHex, label) {
  if (!HEX_ID.test(tabletHex)) {
    fail(`invalid SQLite tablet ID ${tabletHex}`);
  }
  const rows = database
    .prepare(
      [
        "SELECT UPPER(HEX(d.id)) AS idHex, d.json_value AS jsonValue",
        "FROM documents d",
        "JOIN (",
        "  SELECT id, MAX(ts) AS ts",
        "  FROM documents",
        "  WHERE table_id=@tablet",
        "  GROUP BY id",
        ") latest ON d.id=latest.id AND d.ts=latest.ts",
        "WHERE d.table_id=@tablet AND d.deleted=0",
        "ORDER BY d.id",
      ].join(" ")
    )
    .all({ tablet: Buffer.from(tabletHex, "hex") });
  return rows.map(({ idHex, jsonValue }, index) => {
    if (!HEX_ID.test(idHex) || typeof jsonValue !== "string") {
      fail(`${label} row ${index} contains invalid SQLite document material`);
    }
    let storedDocument;
    try {
      storedDocument = expectObject(JSON.parse(jsonValue), `${label} row ${index} document`);
    } catch (error) {
      if (error instanceof SyntaxError) {
        fail(`${label} row ${index} is not valid Convex JSON`);
      }
      throw error;
    }
    const developerId = decodeDeveloperDocumentId(storedDocument._id, `${label} row ${index} _id`);
    if (developerId.internalIdHex !== idHex) {
      fail(`${label} row ${index} _id differs from its SQLite row ID`);
    }
    const creationTime = expectCreationTime(
      storedDocument._creationTime,
      `${label} row ${index} _creationTime`
    );
    const document = { ...storedDocument };
    delete document._creationTime;
    delete document._id;
    return {
      creationTime,
      document,
      idHex,
    };
  });
}

export async function collectSqliteRuntimeBindingAuthority({
  databasePath,
  instanceName,
  runtimeModulePaths,
  storageRoot,
}) {
  expectString(databasePath, "SQLite database path");
  expectString(instanceName, "SQLite backend instance name");
  expectString(storageRoot, "SQLite backend storage root");
  if (
    !Array.isArray(runtimeModulePaths) ||
    runtimeModulePaths.length === 0 ||
    runtimeModulePaths.some((path) => typeof path !== "string" || path.length === 0)
  ) {
    fail("SQLite runtime module paths must be a nonempty string array");
  }
  const uniqueRuntimeModulePaths = [...new Set(runtimeModulePaths)].sort(compareStrings);
  if (uniqueRuntimeModulePaths.length !== runtimeModulePaths.length) {
    fail("SQLite runtime module paths must be unique");
  }

  const canonicalDatabasePath = await fs.realpath(databasePath);
  const canonicalStorageRoot = await fs.realpath(storageRoot);
  const databaseStat = await fs.lstat(canonicalDatabasePath);
  const storageStat = await fs.lstat(canonicalStorageRoot);
  if (!databaseStat.isFile() || !storageStat.isDirectory()) {
    fail("SQLite authority input must contain a regular database and storage directory");
  }

  const database = new DatabaseSync(canonicalDatabasePath, { readOnly: true });
  try {
    database.exec("PRAGMA query_only = ON");
    if (database.prepare("PRAGMA integrity_check").get()?.integrity_check !== "ok") {
      fail("SQLite database integrity check failed");
    }
    const maximumTimestamp = database
      .prepare("SELECT CAST(MAX(ts) AS TEXT) AS value FROM documents")
      .get()?.value;
    const startMaxTs = expectString(maximumTimestamp, "SQLite maximum timestamp");
    const tablesGlobal = database
      .prepare("SELECT json_value AS value FROM persistence_globals WHERE key=?")
      .get("tables_table_id")?.value;
    const tablesIdSource = expectString(
      JSON.parse(expectString(tablesGlobal, "SQLite tables_table_id persistence global")),
      "SQLite tables_table_id value"
    );
    const tablesTabletHex = Buffer.from(tablesIdSource, "base64").toString("hex").toUpperCase();
    if (!HEX_ID.test(tablesTabletHex)) {
      fail("SQLite tables_table_id persistence global is invalid");
    }
    const tables = sqliteCurrentRows(database, tablesTabletHex, "sqlite-tables");
    const requiredTables = new Map();
    for (const name of ["_modules", "_source_packages"]) {
      const matches = tables.filter(
        ({ document }) =>
          document.name === name && document.state === "active" && document.namespace === undefined
      );
      if (matches.length !== 1) {
        fail(`expected one active global ${name} SQLite table, found ${matches.length}`);
      }
      requiredTables.set(name, {
        ...matches[0],
        number: decodeBase64Integer(matches[0].document.number, `${name}.number`),
      });
    }
    const moduleRows = sqliteCurrentRows(
      database,
      requiredTables.get("_modules").idHex,
      "sqlite-modules"
    );
    const sourcePackageRows = sqliteCurrentRows(
      database,
      requiredTables.get("_source_packages").idHex,
      "sqlite-source-packages"
    );
    const { activeModules, latestCommittedSourcePackage, v8LoadPackageIdentity } =
      resolveLatestSourcePackageAuthority({
        moduleRows,
        sourcePackageRows,
        sourcePackagesTableNumber: requiredTables.get("_source_packages").number,
      });
    if (v8LoadPackageIdentity === null) {
      fail("SQLite deployment has no active V8 source package");
    }
    if (!/^[A-Za-z0-9-]+$/u.test(v8LoadPackageIdentity.storageKey)) {
      fail("SQLite source package storage key is invalid");
    }
    const blobPath = await fs.realpath(
      join(canonicalStorageRoot, "modules", `${v8LoadPackageIdentity.storageKey}.blob`)
    );
    if (!blobPath.startsWith(`${canonicalStorageRoot}/`)) {
      fail("SQLite source package blob is outside the authenticated storage root");
    }
    const sourcePackageBytes = await fs.readFile(blobPath);
    const sourcePackageSha256 = sha256(sourcePackageBytes);
    const loadPackageMaterial = {
      blobPath,
      sha256: sourcePackageSha256,
      size: sourcePackageBytes.length,
      runtimeContentSha256: v8LoadPackageIdentity.runtimeContentSha256,
      sourcePackageHashVerified: sourcePackageSha256 === v8LoadPackageIdentity.packageSha256,
      zipEntries: parseZipListing(run("unzip", ["-Z1", blobPath])),
    };
    const allModules = new Map(activeModules.map((module) => [module.path, module]));
    const relevantModules = uniqueRuntimeModulePaths.map((runtimeModulePath) => {
      const module = allModules.get(runtimeModulePath) ?? null;
      const sourcePath = `modules/${runtimeModulePath}`;
      const source = loadPackageMaterial.zipEntries.has(sourcePath)
        ? run("unzip", ["-p", blobPath, sourcePath], { encoding: "buffer" })
        : null;
      const sourceMapPath = `${sourcePath}.map`;
      const sourceMap = loadPackageMaterial.zipEntries.has(sourceMapPath)
        ? run("unzip", ["-p", blobPath, sourceMapPath], { encoding: "buffer" })
        : null;
      return createRuntimeModuleEvidence({
        loadPackageMaterial,
        module,
        runtimeModulePath,
        source,
        sourceMap,
      });
    });
    const endMaxTs = expectString(
      database.prepare("SELECT CAST(MAX(ts) AS TEXT) AS value FROM documents").get()?.value,
      "ending SQLite maximum timestamp"
    );
    if (startMaxTs !== endMaxTs) {
      fail("SQLite database changed during the identity snapshot");
    }
    const evidence = {
      authority: {
        backendMaterial: {
          databaseKind: "sqlite",
          instanceName,
          sourcePackageCount: 1,
          sourcePackageFileSha256: [sourcePackageSha256],
          v8LoadPackage: v8LoadPackageIdentity,
        },
        database: {
          databaseFileSha256: sha256(await fs.readFile(canonicalDatabasePath)),
          maxTimestamp: startMaxTs,
          modulesTable: {
            liveDocumentCount: moduleRows.length,
            number: requiredTables.get("_modules").number,
            tabletIdHex: requiredTables.get("_modules").idHex,
          },
          sourcePackagesTable: {
            liveDocumentCount: sourcePackageRows.length,
            number: requiredTables.get("_source_packages").number,
            tabletIdHex: requiredTables.get("_source_packages").idHex,
          },
          tablesTabletIdHex: tablesTabletHex,
        },
        latestCommittedSourcePackage,
        moduleHashAlgorithm: "sha256(uploaded JavaScript bytes || optional source-map bytes)",
        sourcePackageHashAlgorithm: "sha256(exact stored source-package zip bytes)",
      },
      modules: relevantModules,
    };
    return {
      bindingAuthority: createDeployedRuntimeBindingAuthority(evidence),
      evidence,
    };
  } finally {
    database.close();
  }
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      fail("all CLI options must be --name VALUE pairs");
    }
    if (values.has(name)) {
      fail(`duplicate option ${name}`);
    }
    values.set(name, value);
  }
  const required = [
    "--deployment-manifest",
    "--decoder",
    "--mysql-container",
    "--database",
    "--expected-mysql-start",
    "--expected-mysql-volume",
    "--backend-container",
    "--expected-backend-volume",
    "--output",
  ];
  for (const name of required) {
    if (!values.has(name)) {
      fail(`missing required option ${name}`);
    }
  }
  if (!/^[A-Za-z0-9_]+$/u.test(values.get("--database"))) {
    fail("--database contains unsupported characters");
  }
  const selectionPolicy = values.get("--selection-policy") ?? "all-eligible";
  if (!["all-eligible", "selected-wasm"].includes(selectionPolicy)) {
    fail("--selection-policy must be all-eligible or selected-wasm");
  }
  return {
    backendContainer: values.get("--backend-container"),
    database: values.get("--database"),
    decoder: values.get("--decoder"),
    deploymentManifest: values.get("--deployment-manifest"),
    expectedBackendVolume: values.get("--expected-backend-volume"),
    expectedMysqlStart: values.get("--expected-mysql-start"),
    expectedMysqlVolume: values.get("--expected-mysql-volume"),
    mysqlContainer: values.get("--mysql-container"),
    output: values.get("--output"),
    selectionPolicy,
  };
}

export async function writeStableOutput(path, report) {
  const source = `${canonicalJson(report)}\n`;
  const parent = dirname(path);
  await fs.mkdir(parent, { recursive: true });
  try {
    const handle = await fs.open(
      path,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
      0o600
    );
    try {
      await handle.writeFile(source);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const directoryHandle = await fs.open(parent, "r");
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  } catch (error) {
    if (error?.code !== "EEXIST") {
      throw error;
    }
    if (fsConstants.O_NOFOLLOW === undefined) {
      fail("stable identity evidence reads require O_NOFOLLOW");
    }
    const handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    let existing;
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size !== Buffer.byteLength(source)) {
        fail(`refusing to reuse invalid identity evidence at ${path}`);
      }
      existing = await handle.readFile({ encoding: "utf8" });
      const [after, pathAfter] = await Promise.all([handle.stat(), fs.lstat(path)]);
      if (
        !sameFileState(before, after) ||
        !sameFileState(after, pathAfter) ||
        Buffer.byteLength(existing) !== before.size
      ) {
        fail(`identity evidence changed while it was read at ${path}`);
      }
    } finally {
      await handle.close();
    }
    if (existing !== source) {
      fail(`refusing to overwrite different identity evidence at ${path}`);
    }
  }
}

async function main(argv) {
  const options = parseArguments(argv);
  await fs.access(options.decoder, fsConstants.X_OK);
  const deploymentBytes = await readStableSourceParityInput(
    options.deploymentManifest,
    DEPLOYMENT_MANIFEST_MAX_BYTES,
    "deployment manifest"
  );
  const deploymentManifest = JSON.parse(deploymentBytes.toString("utf8"));
  const candidates = validateDeploymentManifest(deploymentManifest, options.selectionPolicy);
  const database = await collectDatabaseEvidence(
    options,
    new Set(candidates.map(({ runtimeModulePath }) => runtimeModulePath))
  );
  const report = createSourceParityIdentityReport({
    database,
    deploymentManifest,
    deploymentManifestFileSha256: sha256(deploymentBytes),
    selectionPolicy: options.selectionPolicy,
  });
  await writeStableOutput(options.output, report);
  process.stdout.write(
    `${canonicalJson({
      counts: report.counts,
      gatePass: report.gatePass,
      output: options.output,
      reportSha256: report.reportSha256,
    })}\n`
  );
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
