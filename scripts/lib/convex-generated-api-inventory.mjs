import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { defaultConvexWasmCacheRoot } from "./convex-wasm-cache-layout.mjs";
import {
  convexApiFunctionsRoot,
  convexApiReadStableFile,
  convexApiRouteOutput,
} from "./convex-api-flattener-reuse.mjs";
import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { publishConvexWasmGitSourceSnapshotFile } from "./convex-wasm-git-source-snapshot.mjs";

const INVENTORY_KIND = "convex-generated-api-inventory-v1";
const SNAPSHOT_INVENTORY_KIND = "convex-generated-api-snapshot-inventory-v3";
const SNAPSHOT_RESULT_KIND = "convex-generated-api-snapshot-result-v3";
const ROUTE_SNAPSHOT_INVENTORY_KIND = "convex-api-route-snapshot-inventory-v1";
const ROUTE_SNAPSHOT_RESULT_KIND = "convex-api-route-snapshot-result-v1";
const SOURCE_INVENTORY_KIND = "convex-wasm-source-inventory";
const OUTPUT_HASH_PATTERN = / \* Output hash: ([a-f0-9]{64})\n/u;
const OUTPUT_HASH_PLACEHOLDER = "0".repeat(64);

function fail(message) {
  throw new Error(`Convex generated API inventory: ${message}`);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireExactKeys(value, keys, description) {
  const actual = Object.keys(value).sort(compareStrings);
  const expected = [...keys].sort(compareStrings);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${description} fields are invalid`);
  }
}

function requireTarget(value, description, includeKind) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} is not an object`);
  }
  if (
    typeof value.entryPath !== "string" ||
    value.entryPath.length === 0 ||
    value.entryPath.startsWith("/") ||
    value.entryPath.includes("\\") ||
    value.entryPath.split("/").some((part) => part === "." || part === ".." || part.length === 0) ||
    typeof value.exportName !== "string" ||
    !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(value.exportName)
  ) {
    fail(`${description} target is invalid`);
  }
  if (includeKind && !["action", "mutation", "query"].includes(value.udfKind)) {
    fail(`${description} udfKind is invalid`);
  }
  return value;
}

function requireSourceSpan(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} is not an object`);
  }
  requireExactKeys(value, ["column", "end", "endColumn", "endLine", "line", "start"], description);
  for (const field of ["column", "end", "endColumn", "endLine", "line", "start"]) {
    const minimum = field === "start" || field === "end" ? 0 : 1;
    if (!Number.isSafeInteger(value[field]) || value[field] < minimum) {
      fail(`${description}.${field} is invalid`);
    }
  }
  if (value.end <= value.start) {
    fail(`${description} offsets are invalid`);
  }
  return value;
}

function requireRegistrationCall(value, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} is not an object`);
  }
  requireExactKeys(value, ["callSpan", "calleeSpan", "sourcePath", "sourceSha256"], description);
  if (
    typeof value.sourcePath !== "string" ||
    value.sourcePath.length === 0 ||
    value.sourcePath.startsWith("/") ||
    value.sourcePath.includes("\\") ||
    value.sourcePath
      .split("/")
      .some((part) => part === "." || part === ".." || part.length === 0) ||
    typeof value.sourceSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.sourceSha256)
  ) {
    fail(`${description} source identity is invalid`);
  }
  for (const [name, span] of [
    ["callSpan", value.callSpan],
    ["calleeSpan", value.calleeSpan],
  ]) {
    if (typeof span !== "object" || span === null || Array.isArray(span)) {
      fail(`${description}.${name} is not an object`);
    }
    requireExactKeys(span, ["end", "start"], `${description}.${name}`);
    if (
      !Number.isSafeInteger(span.start) ||
      span.start < 0 ||
      !Number.isSafeInteger(span.end) ||
      span.end <= span.start
    ) {
      fail(`${description}.${name} UTF-8 byte offsets are invalid`);
    }
  }
  if (value.calleeSpan.start < value.callSpan.start || value.calleeSpan.end > value.callSpan.end) {
    fail(`${description} calleeSpan is outside callSpan`);
  }
  return value;
}

function targetKey(target) {
  return `${target.entryPath}\0${target.exportName}`;
}

function requireSortedUniqueTargets(values, description) {
  let previous;
  for (const [index, value] of values.entries()) {
    const key = targetKey(value);
    if (previous !== undefined && compareStrings(previous, key) >= 0) {
      fail(`${description} must be sorted and contain no duplicate targets at index ${index}`);
    }
    previous = key;
  }
}

function requireSourceInventory(sourceInventory) {
  if (
    typeof sourceInventory !== "object" ||
    sourceInventory === null ||
    Array.isArray(sourceInventory)
  ) {
    fail("compiler source inventory is not an object");
  }
  requireExactKeys(
    sourceInventory,
    ["diagnostics", "functions", "graphSha256", "kind", "unresolvedExports"],
    "compiler source inventory"
  );
  if (
    sourceInventory.kind !== SOURCE_INVENTORY_KIND ||
    typeof sourceInventory.graphSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(sourceInventory.graphSha256) ||
    !Array.isArray(sourceInventory.functions) ||
    !Array.isArray(sourceInventory.unresolvedExports) ||
    !Array.isArray(sourceInventory.diagnostics)
  ) {
    fail("compiler source inventory is incomplete");
  }

  const sourceHashes = new Map();
  for (const [index, value] of sourceInventory.functions.entries()) {
    const description = `compiler source inventory function ${index}`;
    requireExactKeys(
      requireTarget(value, description, true),
      [
        "dependencyChain",
        "direct",
        "entryPath",
        "exportName",
        "registrationBuilder",
        "registrationCall",
        "sourceSpan",
        "udfKind",
      ],
      description
    );
    if (
      typeof value.direct !== "boolean" ||
      typeof value.registrationBuilder !== "string" ||
      value.registrationBuilder.length === 0 ||
      !Array.isArray(value.dependencyChain)
    ) {
      fail(`${description} is incomplete`);
    }
    requireRegistrationCall(value.registrationCall, `${description} registrationCall`);
    if (value.direct && value.registrationCall.sourcePath !== value.entryPath) {
      fail(`${description} direct registration call sourcePath disagrees with entryPath`);
    }
    const priorSourceHash = sourceHashes.get(value.registrationCall.sourcePath);
    if (priorSourceHash !== undefined && priorSourceHash !== value.registrationCall.sourceSha256) {
      fail(`${description} registration call source hash disagrees with another route`);
    }
    sourceHashes.set(value.registrationCall.sourcePath, value.registrationCall.sourceSha256);
    requireSourceSpan(value.sourceSpan, `${description} sourceSpan`);
  }
  requireSortedUniqueTargets(sourceInventory.functions, "compiler source inventory functions");

  for (const [index, value] of sourceInventory.unresolvedExports.entries()) {
    const description = `compiler source inventory unresolved export ${index}`;
    requireExactKeys(
      requireTarget(value, description, false),
      ["classification", "entryPath", "exportName", "sourceSpan"],
      description
    );
    if (value.classification !== "objectDestructure") {
      fail(`${description} has unsupported classification ${JSON.stringify(value.classification)}`);
    }
    requireSourceSpan(value.sourceSpan, `${description} sourceSpan`);
  }
  requireSortedUniqueTargets(
    sourceInventory.unresolvedExports,
    "compiler source inventory unresolved exports"
  );
  return sourceInventory;
}

export function reconcileConvexGeneratedApiSourceInventory({
  generatedInventory,
  sourceInventory,
}) {
  if (
    typeof generatedInventory !== "object" ||
    generatedInventory === null ||
    Array.isArray(generatedInventory) ||
    generatedInventory.kind !== INVENTORY_KIND ||
    !Array.isArray(generatedInventory.functions) ||
    !Array.isArray(generatedInventory.actions)
  ) {
    fail("generated inventory is incomplete");
  }
  requireSourceInventory(sourceInventory);

  const generatedFunctions = [...generatedInventory.functions, ...generatedInventory.actions]
    .map((value, index) => {
      const description = `generated inventory function ${index}`;
      requireTarget(value, description, true);
      if (
        typeof value.modulePath !== "string" ||
        value.modulePath.length === 0 ||
        !["internal", "public"].includes(value.visibility)
      ) {
        fail(`${description} is incomplete`);
      }
      return value;
    })
    .sort((left, right) => compareStrings(targetKey(left), targetKey(right)));
  requireSortedUniqueTargets(generatedFunctions, "generated inventory functions");

  const sourceFunctions = new Map(
    sourceInventory.functions.map((sourceFunction) => [targetKey(sourceFunction), sourceFunction])
  );
  const unresolvedExports = new Map(
    sourceInventory.unresolvedExports.map((unresolvedExport) => [
      targetKey(unresolvedExport),
      unresolvedExport,
    ])
  );
  for (const key of sourceFunctions.keys()) {
    if (unresolvedExports.has(key)) {
      fail(`compiler source inventory contains conflicting evidence for ${key.replace("\0", ":")}`);
    }
  }

  const generatedKeys = new Set(generatedFunctions.map(targetKey));
  const unexplainedMismatches = sourceInventory.functions
    .filter((sourceFunction) => !generatedKeys.has(targetKey(sourceFunction)))
    .map((sourceFunction) => ({
      entryPath: sourceFunction.entryPath,
      exportName: sourceFunction.exportName,
      generatedUdfKind: null,
      message: `Current Oxc source inventory classifies ${sourceFunction.entryPath}:${sourceFunction.exportName} as ${sourceFunction.udfKind}, but generated inventory does not contain that function.`,
      reason: "generated-source-registration-mismatch",
      sourceUdfKind: sourceFunction.udfKind,
    }));
  const functions = generatedFunctions.map((generatedFunction) => {
    const key = targetKey(generatedFunction);
    const sourceFunction = sourceFunctions.get(key);
    const unresolvedExport = unresolvedExports.get(key);
    if (sourceFunction === undefined && unresolvedExport === undefined) {
      if (generatedFunction.udfKind === "action") {
        return {
          entryPath: generatedFunction.entryPath,
          evidence: { kind: "actionRuntime" },
          exportName: generatedFunction.exportName,
          selection: { decision: "v8Fallback", reason: "action-runtime" },
          udfKind: generatedFunction.udfKind,
        };
      }
      const mismatch = {
        entryPath: generatedFunction.entryPath,
        exportName: generatedFunction.exportName,
        generatedUdfKind: generatedFunction.udfKind,
        message: `Generated inventory classifies ${generatedFunction.entryPath}:${generatedFunction.exportName} as ${generatedFunction.udfKind}, but current Oxc source inventory has no matching registration or object-destructure export evidence.`,
        reason: "generated-source-registration-mismatch",
        sourceUdfKind: null,
      };
      unexplainedMismatches.push(mismatch);
      return {
        entryPath: generatedFunction.entryPath,
        evidence: { kind: "missing" },
        exportName: generatedFunction.exportName,
        selection: { decision: "v8Fallback", reason: mismatch.reason },
        udfKind: generatedFunction.udfKind,
      };
    }
    if (sourceFunction !== undefined && sourceFunction.udfKind !== generatedFunction.udfKind) {
      const mismatch = {
        entryPath: generatedFunction.entryPath,
        exportName: generatedFunction.exportName,
        generatedUdfKind: generatedFunction.udfKind,
        message: `Generated inventory classifies ${generatedFunction.entryPath}:${generatedFunction.exportName} as ${generatedFunction.udfKind}, but current Oxc source inventory classifies it as ${sourceFunction.udfKind}.`,
        reason: "generated-source-kind-mismatch",
        sourceUdfKind: sourceFunction.udfKind,
      };
      unexplainedMismatches.push(mismatch);
      return {
        entryPath: generatedFunction.entryPath,
        evidence: {
          kind: "kindDisagreement",
          registrationCall: sourceFunction.registrationCall,
          sourceSpan: sourceFunction.sourceSpan,
          sourceUdfKind: sourceFunction.udfKind,
        },
        exportName: generatedFunction.exportName,
        selection: { decision: "v8Fallback", reason: mismatch.reason },
        udfKind: generatedFunction.udfKind,
      };
    }
    if (unresolvedExport !== undefined) {
      return {
        entryPath: generatedFunction.entryPath,
        evidence: {
          classification: unresolvedExport.classification,
          kind: "unresolvedExport",
          sourceSpan: unresolvedExport.sourceSpan,
        },
        exportName: generatedFunction.exportName,
        selection: {
          decision: "v8Fallback",
          reason:
            generatedFunction.udfKind === "action"
              ? "action-runtime"
              : "unsupported-registration-builder",
        },
        udfKind: generatedFunction.udfKind,
      };
    }
    return {
      entryPath: generatedFunction.entryPath,
      evidence: {
        dependencyChain: sourceFunction.dependencyChain,
        kind: sourceFunction.direct ? "directRegistration" : "namedReexport",
        registrationBuilder: sourceFunction.registrationBuilder,
        registrationCall: sourceFunction.registrationCall,
        sourceSpan: sourceFunction.sourceSpan,
      },
      exportName: generatedFunction.exportName,
      selection:
        generatedFunction.udfKind === "action"
          ? { decision: "v8Fallback", reason: "action-runtime" }
          : sourceFunction.direct
            ? { decision: "analyze" }
            : { decision: "v8Fallback", reason: "registration-reexport" },
      udfKind: generatedFunction.udfKind,
    };
  });
  unexplainedMismatches.sort((left, right) => compareStrings(targetKey(left), targetKey(right)));
  return {
    functions,
    graphSha256: sourceInventory.graphSha256,
    kind: "convex-generated-api-source-reconciliation-v1",
    unexplainedMismatches,
  };
}

function outputHash(source) {
  const reported = source.match(OUTPUT_HASH_PATTERN)?.[1];
  if (reported === undefined) {
    fail("snapshot API declaration has no output hash");
  }
  const normalized = source.replace(
    OUTPUT_HASH_PATTERN,
    ` * Output hash: ${OUTPUT_HASH_PLACEHOLDER}\n`
  );
  if (sha256(normalized) !== reported) {
    fail("snapshot API declaration output hash is corrupt");
  }
  return reported;
}

function requireSnapshotReport(value, cacheRoot) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    ![SNAPSHOT_RESULT_KIND, ROUTE_SNAPSHOT_RESULT_KIND].includes(value.kind) ||
    !["hit", "miss"].includes(value.cache) ||
    !["hit", "miss"].includes(value.generatorCache) ||
    typeof value.inputSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.inputSha256) ||
    typeof value.inventorySha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.inventorySha256) ||
    typeof value.outputSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.outputSha256) ||
    typeof value.snapshotPath !== "string" ||
    !isAbsolute(value.snapshotPath)
  ) {
    fail("flattener returned an invalid snapshot report");
  }
  const normalizedCacheRoot = resolve(cacheRoot);
  const normalizedSnapshot = resolve(value.snapshotPath);
  const version = value.kind === ROUTE_SNAPSHOT_RESULT_KIND ? "routes-v1" : "v3";
  if (
    normalizedSnapshot !== resolve(normalizedCacheRoot, version, "snapshots", value.inputSha256)
  ) {
    fail("flattener returned an unexpected snapshot path");
  }
  return { ...value, snapshotPath: normalizedSnapshot };
}

async function runFlattener(repoRoot, configPath, cacheRoot, flattenerPath, gitSourceSnapshotPath) {
  const child = spawn(
    process.execPath,
    [
      flattenerPath,
      "--route-inventory-snapshot",
      cacheRoot,
      ...(configPath === undefined ? [] : ["--config", configPath]),
      ...(gitSourceSnapshotPath === undefined
        ? []
        : ["--git-source-snapshot", gitSourceSnapshotPath]),
      "--project-root",
      repoRoot,
    ],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );
  const stdout = [];
  const stderr = [];
  let outputBytes = 0;
  let exceededOutputLimit = false;
  const append = (chunks, chunk) => {
    outputBytes += chunk.length;
    if (outputBytes <= 1024 * 1024) {
      chunks.push(chunk);
    } else if (!exceededOutputLimit) {
      exceededOutputLimit = true;
      child.kill("SIGKILL");
    }
  };
  child.stdout.on("data", (chunk) => append(stdout, chunk));
  child.stderr.on("data", (chunk) => append(stderr, chunk));
  const status = await new Promise((resolvePromise, rejectPromise) => {
    child.once("error", rejectPromise);
    child.once("close", (code, signal) => resolvePromise({ code, signal }));
  });
  if (exceededOutputLimit) {
    fail("flattener exceeded 1 MiB of output");
  }
  if (status.code !== 0) {
    const rendered = Buffer.concat([...stderr, ...stdout])
      .toString("utf8")
      .trim();
    fail(
      `flattener failed with code ${String(status.code)} and signal ${String(status.signal)}${
        rendered.length === 0 ? "" : `: ${rendered}`
      }`
    );
  }
  let report;
  try {
    report = JSON.parse(Buffer.concat(stdout).toString("utf8"));
  } catch (error) {
    throw new Error("Convex generated API inventory: flattener returned invalid JSON", {
      cause: error,
    });
  }
  return requireSnapshotReport(report, cacheRoot);
}

function sameFileState(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function requirePrivateSnapshotDirectory(path) {
  const status = await fs.lstat(path, { bigint: true });
  if (
    !status.isDirectory() ||
    status.isSymbolicLink() ||
    (status.mode & 0o777n) !== 0o700n ||
    (typeof process.getuid === "function" && status.uid !== BigInt(process.getuid()))
  ) {
    fail(`snapshot directory is not private: ${path}`);
  }
  return status;
}

async function preparePrivateCacheDirectory(path) {
  if (fsConstants.O_NOFOLLOW === undefined || fsConstants.O_DIRECTORY === undefined) {
    fail("cache-root preparation requires O_NOFOLLOW and O_DIRECTORY");
  }
  await fs.mkdir(path, { mode: 0o700, recursive: true });
  const descriptor = await fs.open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
  );
  try {
    const status = await descriptor.stat({ bigint: true });
    if (
      !status.isDirectory() ||
      (typeof process.getuid === "function" && status.uid !== BigInt(process.getuid()))
    ) {
      fail(`cache root is not an owner-bound directory: ${path}`);
    }
    await descriptor.chmod(0o700);
  } finally {
    await descriptor.close();
  }
  await requirePrivateSnapshotDirectory(path);
}

async function readPrivateSnapshotFile(path, maximumBytes) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("snapshot reads require O_NOFOLLOW");
  }
  const before = await fs.lstat(path, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.size <= 0n ||
    before.size > BigInt(maximumBytes) ||
    (before.mode & 0o777n) !== 0o600n ||
    (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))
  ) {
    fail(`snapshot file is not a private bounded file: ${path}`);
  }
  const descriptor = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await descriptor.stat({ bigint: true });
    if (!opened.isFile() || !sameFileState(before, opened)) {
      fail(`snapshot file changed while it was opened: ${path}`);
    }
    const source = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < source.length) {
      const { bytesRead } = await descriptor.read(source, offset, source.length - offset, offset);
      if (bytesRead === 0) {
        fail(`snapshot file ended before its authenticated size: ${path}`);
      }
      offset += bytesRead;
    }
    const [after, afterPath] = await Promise.all([
      descriptor.stat({ bigint: true }),
      fs.lstat(path, { bigint: true }),
    ]);
    if (
      !sameFileState(opened, after) ||
      !afterPath.isFile() ||
      afterPath.isSymbolicLink() ||
      !sameFileState(opened, afterPath)
    ) {
      fail(`snapshot file changed while it was read: ${path}`);
    }
    return source;
  } finally {
    await descriptor.close();
  }
}

async function readSnapshot(report, cacheRoot, functionsRoot) {
  const path = report.snapshotPath;
  const routeInventoryOnly = report.kind === ROUTE_SNAPSHOT_RESULT_KIND;
  const version = routeInventoryOnly ? "routes-v1" : "v3";
  const artifactName = routeInventoryOnly ? "api-routes.json" : "api.d.ts";
  const expectedNames = ["COMPLETE", artifactName, "inventory.json"];
  const directoryPaths = [
    resolve(cacheRoot),
    resolve(cacheRoot, version),
    resolve(cacheRoot, version, "snapshots"),
    path,
  ];
  const directoryStates = await Promise.all(
    directoryPaths.map((directoryPath) => requirePrivateSnapshotDirectory(directoryPath))
  );
  const beforeDirectory = directoryStates.at(-1);
  const names = await fs.readdir(path);
  if (JSON.stringify(names.sort(compareStrings)) !== JSON.stringify(expectedNames)) {
    fail(`snapshot has invalid files: ${path}`);
  }
  const [completionSource, apiBuffer, metadataBuffer] = await Promise.all([
    readPrivateSnapshotFile(resolve(path, "COMPLETE"), 128),
    readPrivateSnapshotFile(resolve(path, artifactName), 64 * 1024 * 1024),
    readPrivateSnapshotFile(resolve(path, "inventory.json"), 64 * 1024 * 1024),
  ]);
  const [namesAfter, afterDirectory] = await Promise.all([
    fs.readdir(path),
    requirePrivateSnapshotDirectory(path),
  ]);
  if (
    beforeDirectory === undefined ||
    !sameFileState(beforeDirectory, afterDirectory) ||
    JSON.stringify(namesAfter.sort(compareStrings)) !== JSON.stringify(expectedNames)
  ) {
    fail(`snapshot changed while it was read: ${path}`);
  }
  if (completionSource.toString("utf8") !== `${report.inputSha256}\n`) {
    fail(`snapshot completion marker is corrupt: ${path}`);
  }
  const apiSource = apiBuffer.toString("utf8");
  const metadataSource = metadataBuffer.toString("utf8");
  if (sha256(metadataBuffer) !== report.inventorySha256) {
    fail(`snapshot metadata digest is corrupt: ${path}`);
  }
  let metadata;
  try {
    metadata = JSON.parse(metadataSource);
  } catch (error) {
    throw new Error(`Convex generated API inventory: snapshot metadata is corrupt: ${path}`, {
      cause: error,
    });
  }
  if (
    metadata.kind !==
      (routeInventoryOnly ? ROUTE_SNAPSHOT_INVENTORY_KIND : SNAPSHOT_INVENTORY_KIND) ||
    metadata.inputSha256 !== report.inputSha256 ||
    metadata.outputSha256 !== report.outputSha256 ||
    (routeInventoryOnly ? sha256(apiSource) : outputHash(apiSource)) !== metadata.outputSha256 ||
    typeof metadata.materialIdentity !== "object" ||
    metadata.materialIdentity === null ||
    metadata.materialIdentity.inputSha256 !== report.inputSha256 ||
    !Array.isArray(metadata.functions) ||
    !Array.isArray(metadata.programMaterialPaths) ||
    metadata.programMaterialPaths.some(
      (path) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.startsWith("/") ||
        path.includes("\\") ||
        path.split("/").some((part) => part.length === 0 || part === "." || part === "..")
    ) ||
    JSON.stringify(metadata.programMaterialPaths) !==
      JSON.stringify([...new Set(metadata.programMaterialPaths)].sort(compareStrings))
  ) {
    fail(`snapshot metadata is corrupt: ${path}`);
  }
  const unresolvedFunctions = [];
  for (const entry of metadata.functions) {
    const sourceExtension = [".ts", ".tsx", ".mts", ".cts"].find((extension) =>
      entry?.entryPath?.endsWith(extension)
    );
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      JSON.stringify(Object.keys(entry).sort(compareStrings)) !==
        JSON.stringify(
          ["entryPath", "exportName", "kind", "modulePath", "visibility"].sort(compareStrings)
        ) ||
      typeof entry.entryPath !== "string" ||
      sourceExtension === undefined ||
      entry.entryPath !== `${functionsRoot}/${entry.modulePath}${sourceExtension}` ||
      typeof entry.modulePath !== "string" ||
      entry.modulePath.length === 0 ||
      entry.modulePath.startsWith("/") ||
      entry.modulePath.includes("\\") ||
      entry.modulePath
        .split("/")
        .some((part) => part === "." || part === ".." || part.length === 0) ||
      typeof entry.exportName !== "string" ||
      !["action", "mutation", "query"].includes(entry.kind) ||
      !["internal", "public"].includes(entry.visibility)
    ) {
      fail(`snapshot contains an invalid function entry: ${path}`);
    }
    unresolvedFunctions.push({
      entryPath: entry.entryPath,
      exportName: entry.exportName,
      modulePath: entry.modulePath,
      udfKind: entry.kind,
      visibility: entry.visibility,
    });
  }
  const functions = unresolvedFunctions;
  if (routeInventoryOnly && apiSource !== convexApiRouteOutput(metadata.functions)) {
    fail(`snapshot metadata disagrees with the API route artifact: ${path}`);
  }
  functions.sort((left, right) => {
    const entryOrder = compareStrings(left.entryPath, right.entryPath);
    return entryOrder === 0 ? compareStrings(left.exportName, right.exportName) : entryOrder;
  });
  const seen = new Set();
  for (const func of functions) {
    const key = `${func.entryPath}:${func.exportName}`;
    if (seen.has(key)) {
      fail(`snapshot contains duplicate function ${key}`);
    }
    seen.add(key);
  }
  return {
    actions: functions.filter((func) => func.udfKind === "action"),
    functions: functions.filter((func) => func.udfKind === "query" || func.udfKind === "mutation"),
    kind: INVENTORY_KIND,
    snapshot: {
      // This identity envelope binds the API artifact, which is api-routes.json for route
      // snapshots and api.d.ts for legacy full declarations. Neither digest grants type authority.
      apiSha256: sha256(apiSource),
      inputSha256: report.inputSha256,
      materialIdentity: metadata.materialIdentity,
      materialSha256: fingerprintJson(metadata.materialIdentity),
      outputSha256: metadata.outputSha256,
      programMaterialPaths: metadata.programMaterialPaths,
    },
  };
}

export async function loadConvexGeneratedApiInventory({
  cacheRoot = resolve(defaultConvexWasmCacheRoot(), "convex-generated-api-inventory"),
  configPath,
  flattenerPath,
  gitSourceSnapshot,
  gitSourceSnapshotPath,
  repoRoot,
}) {
  const normalizedRoot = resolve(repoRoot);
  const functionsRoot = convexApiFunctionsRoot(
    JSON.parse(
      convexApiReadStableFile(
        resolve(normalizedRoot, "convex.json"),
        "Convex project configuration"
      )
    )
  );
  const normalizedFlattenerPath = resolve(
    flattenerPath ?? resolve(dirname(fileURLToPath(import.meta.url)), "../flatten-convex-api.mjs")
  );
  const normalizedCacheRoot = resolve(cacheRoot);
  if (gitSourceSnapshot !== undefined && gitSourceSnapshotPath !== undefined) {
    fail("provide an admitted Git source snapshot or a snapshot path, not both");
  }
  if (gitSourceSnapshot !== undefined && resolve(gitSourceSnapshot.repoRoot) !== normalizedRoot) {
    fail("admitted Git source snapshot belongs to a different repository root");
  }
  let normalizedGitSourceSnapshotPath =
    gitSourceSnapshotPath === undefined ? undefined : resolve(gitSourceSnapshotPath);
  await preparePrivateCacheDirectory(normalizedCacheRoot);
  const started = performance.now();
  const handoffDirectory =
    gitSourceSnapshot === undefined
      ? undefined
      : await fs.mkdtemp(resolve(normalizedCacheRoot, "git-source-handoff-"));
  let report;
  try {
    if (handoffDirectory !== undefined) {
      // Bind the subprocess to the analyzer's admitted tree so its retained surface
      // manifest can reuse unchanged registration projections.
      normalizedGitSourceSnapshotPath = await publishConvexWasmGitSourceSnapshotFile({
        outputPath: resolve(handoffDirectory, "snapshot.json"),
        snapshot: gitSourceSnapshot.snapshot,
      });
    }
    report = await runFlattener(
      normalizedRoot,
      configPath === undefined ? undefined : resolve(normalizedRoot, configPath),
      normalizedCacheRoot,
      normalizedFlattenerPath,
      normalizedGitSourceSnapshotPath
    );
  } finally {
    if (handoffDirectory !== undefined) {
      await fs.rm(handoffDirectory, { recursive: true, force: true });
    }
  }
  const inventory = await readSnapshot(report, normalizedCacheRoot, functionsRoot);
  inventory.authority = {
    sourceRoot: functionsRoot,
    snapshot: inventory.snapshot,
  };
  return {
    cache: report.cache,
    generatorCache: report.generatorCache,
    inventory,
    phaseTimingsMilliseconds: {
      flattenerAndValidation: performance.now() - started,
    },
    snapshotPath: report.snapshotPath,
  };
}

export async function convexGeneratedApiMaterialIdentity(options) {
  const loaded = await loadConvexGeneratedApiInventory(options);
  return {
    identity: loaded.inventory.snapshot.materialIdentity,
    inputSha256: loaded.inventory.snapshot.inputSha256,
    materialSha256: loaded.inventory.snapshot.materialSha256,
  };
}
