#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants, promises as fs } from "node:fs";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

const REQUEST_KIND = "convex-wasm-static-hermes-precompile-request-v1";
const RESPONSE_KIND = "convex-wasm-static-hermes-precompile-response-v1";
const C_BUNDLE_KIND = "static-hermes-c-bundle-v1";
const C_BUNDLE_MANIFEST_PATH = "unit.c.json";
const C_BUNDLE_ARGUMENT = "-Xemit-c-bundle";
const C_BUNDLE_SHARD_SIZE = 2_097_152;
const C_BUNDLE_SHARD_SIZE_ARGUMENT = `-Xemit-c-shard-size=${String(C_BUNDLE_SHARD_SIZE)}`;
const C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO = 0;
const C_BUNDLE_OVERSIZE_REASONS = new Set(["no-outlineable-run", "single-instruction"]);
const MAX_C_BUNDLE_MANIFEST_BYTES = 16 * 1024 * 1024;
// The producer's file limit includes the manifest, header, and metadata translation unit.
const MAX_C_BUNDLE_MEMBERS = 65_536;
const MAX_C_BUNDLE_FUNCTION_MEMBERS = MAX_C_BUNDLE_MEMBERS - 3;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const BUNDLE_BASENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const CONTROL_CHARACTER_PATTERN = /\p{Control}/u;
const DIAGNOSTIC_HEADER_PATTERN = /^input\.js:([1-9][0-9]*):([1-9][0-9]*): error: ([^\r\n]+)$/gmu;
const FINAL_ERROR_COUNT_PATTERN = /(?:^|\n)Emitted ([1-9][0-9]*) errors\. exiting\.\n?$/u;
const FLOW_BINARY_INCOMPATIBILITY_PATTERN =
  /^ft: incompatible binary operation: \S(?:[^\r\n]{0,2046}\S)?$/u;
const FLOW_BINARY_INCOMPATIBILITY_CATEGORY = "flow-type-incompatible-binary-operation";
const FLOW_SPREAD_ARGUMENT_PATTERN = /^ft: spread argument must be an exact object type$/u;
const FLOW_SPREAD_ARGUMENT_CATEGORY = "flow-type-spread-argument-not-exact-object";
const FLOW_ARRAY_SPREAD_ARGUMENT_PATTERN = /^ft: spread argument must be an array$/u;
const FLOW_ARRAY_SPREAD_ARGUMENT_CATEGORY = "flow-type-spread-argument-not-array";
const FLOW_CONSTRUCTOR_ARITY_PATTERN =
  /^ft: class [A-Za-z_$][A-Za-z0-9_$]* constructor expects at most [0-9]+ arguments?, but [0-9]+ supplied$/u;
const FLOW_CONSTRUCTOR_ARITY_CATEGORY = "flow-type-constructor-arity-mismatch";
const FLOW_GENERIC_METHOD_INFERENCE_PATTERN =
  /^ft: could not infer type arguments for generic method$/u;
const FLOW_GENERIC_METHOD_INFERENCE_CATEGORY = "flow-type-generic-method-inference";
const FORWARDED_SIGNALS = ["SIGINT", "SIGTERM"];

function fail(message) {
  throw new Error(`Convex Wasm Static Hermes precompiler: ${message}`);
}

function canonicalValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("canonical JSON contains a non-finite number");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("canonical JSON contains a non-plain object");
  }
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalValue(value[key])])
  );
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireExactKeys(value, keys, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${description} has unexpected fields`);
  }
  return value;
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requirePositiveInteger(value, description) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${description} must be a positive safe integer`);
  }
  return value;
}

function requirePositiveU32(value, description) {
  requirePositiveInteger(value, description);
  if (value > 0xffffffff) {
    fail(`${description} must fit in an unsigned 32-bit integer`);
  }
  return value;
}

async function hashRegularFile(path, expectedSize, description, { rejectSymlink = false } = {}) {
  if (rejectSymlink && fsConstants.O_NOFOLLOW === undefined) {
    fail("this platform does not provide O_NOFOLLOW for authenticated files");
  }
  let handle;
  try {
    handle = await fs.open(
      path,
      fsConstants.O_RDONLY | (rejectSymlink ? fsConstants.O_NOFOLLOW : 0)
    );
  } catch {
    fail(`${description} is not the expected regular file`);
  }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size !== expectedSize) {
      fail(`${description} is not the expected regular file`);
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await handle.read(
        buffer,
        0,
        Math.min(buffer.length, before.size - offset),
        offset
      );
      if (bytesRead === 0) {
        fail(`${description} changed while it was read`);
      }
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      fail(`${description} changed while it was read`);
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
}

function requireBundleBasename(value, description, extension) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value === "." ||
    value === ".." ||
    isAbsolute(value) ||
    value.includes("/") ||
    value.includes("\\") ||
    CONTROL_CHARACTER_PATTERN.test(value) ||
    !BUNDLE_BASENAME_PATTERN.test(value) ||
    !value.endsWith(extension)
  ) {
    fail(`${description} must be a safe relative ${extension} basename`);
  }
  return value;
}

function requireNonnegativeU32(value, description) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    fail(`${description} must be an unsigned 32-bit integer`);
  }
  return value;
}

function normalizeBundleMember(value, description) {
  const isFunction = value?.role === "function";
  const isPlainObject = typeof value === "object" && value !== null && !Array.isArray(value);
  const hasCOptimizationLevel = isPlainObject && Object.hasOwn(value, "cOptimizationLevel");
  const hasOversizeReason = isPlainObject && Object.hasOwn(value, "oversizeReason");
  const hasFunctionFragmentIndex = isPlainObject && Object.hasOwn(value, "functionFragmentIndex");
  const hasFunctionFragmentCount = isPlainObject && Object.hasOwn(value, "functionFragmentCount");
  if (hasFunctionFragmentIndex !== hasFunctionFragmentCount) {
    fail(`${description} function fragment identity must include index and count`);
  }
  const member = requireExactKeys(
    value,
    isFunction
      ? [
          ...(hasCOptimizationLevel ? ["cOptimizationLevel"] : []),
          "firstFunctionId",
          ...(hasFunctionFragmentIndex ? ["functionFragmentCount", "functionFragmentIndex"] : []),
          "functionCount",
          "lastFunctionId",
          "oversize",
          ...(hasOversizeReason ? ["oversizeReason"] : []),
          "path",
          "role",
          "sha256",
          "size",
          "targetBytes",
        ]
      : ["path", "role", "sha256", "size"],
    description
  );
  if (!["function", "header", "metadata"].includes(member.role)) {
    fail(`${description} role is unsupported`);
  }
  const size = requirePositiveInteger(member.size, `${description} size`);
  let functionIdentity;
  if (isFunction) {
    const firstFunctionId = requireNonnegativeU32(
      member.firstFunctionId,
      `${description} firstFunctionId`
    );
    const lastFunctionId = requireNonnegativeU32(
      member.lastFunctionId,
      `${description} lastFunctionId`
    );
    const functionCount = requirePositiveU32(member.functionCount, `${description} functionCount`);
    if (
      lastFunctionId < firstFunctionId ||
      functionCount !== lastFunctionId - firstFunctionId + 1
    ) {
      fail(`${description} function range and count disagree`);
    }
    if (member.targetBytes !== C_BUNDLE_SHARD_SIZE || typeof member.oversize !== "boolean") {
      fail(`${description} targetBytes or oversize marker is invalid`);
    }
    // targetBytes is the producer's aggregate function-body budget. The emitted file also carries
    // declarations and externs, so a multi-function shard may exceed it without being oversized.
    if (
      (functionCount === 1 && member.oversize !== size > member.targetBytes) ||
      (member.oversize && functionCount !== 1)
    ) {
      fail(`${description} oversize marker does not match its size and function count`);
    }
    let oversizeReason;
    if (member.oversize) {
      if (!hasOversizeReason) {
        fail(`${description} oversize member must declare an oversizeReason`);
      }
      if (!C_BUNDLE_OVERSIZE_REASONS.has(member.oversizeReason)) {
        fail(`${description} oversizeReason is unsupported`);
      }
      oversizeReason = member.oversizeReason;
    } else if (hasOversizeReason) {
      fail(`${description} non-oversize member must not declare an oversizeReason`);
    }
    let cOptimizationLevel;
    if (hasCOptimizationLevel) {
      if (member.cOptimizationLevel !== C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO) {
        fail(
          `${description} cOptimizationLevel must be ${String(C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO)}`
        );
      }
      if (functionCount !== 1) {
        fail(`${description} cOptimizationLevel=0 member must contain exactly one function`);
      }
      cOptimizationLevel = C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO;
    }
    let functionFragmentIdentity;
    if (hasFunctionFragmentIndex) {
      const functionFragmentCount = requirePositiveInteger(
        member.functionFragmentCount,
        `${description} functionFragmentCount`
      );
      const functionFragmentIndex = requireNonnegativeU32(
        member.functionFragmentIndex,
        `${description} functionFragmentIndex`
      );
      if (
        functionCount !== 1 ||
        functionFragmentCount < 2 ||
        functionFragmentCount > MAX_C_BUNDLE_FUNCTION_MEMBERS ||
        functionFragmentIndex >= functionFragmentCount
      ) {
        fail(`${description} function fragment identity is invalid`);
      }
      functionFragmentIdentity = { functionFragmentCount, functionFragmentIndex };
    }
    if (
      functionFragmentIdentity?.functionFragmentIndex !== undefined &&
      functionFragmentIdentity.functionFragmentIndex !== 0 &&
      oversizeReason === "no-outlineable-run"
    ) {
      fail(`${description} function fragment oversizeReason must be single-instruction`);
    }
    if (
      cOptimizationLevel !== undefined &&
      functionFragmentIdentity !== undefined &&
      functionFragmentIdentity.functionFragmentIndex !== 0
    ) {
      fail(`${description} cOptimizationLevel=0 function fragment must be the wrapper at index 0`);
    }
    functionIdentity = {
      ...(cOptimizationLevel === undefined ? {} : { cOptimizationLevel }),
      firstFunctionId,
      functionCount,
      lastFunctionId,
      oversize: member.oversize,
      ...(oversizeReason === undefined ? {} : { oversizeReason }),
      ...(functionFragmentIdentity ?? {}),
    };
  }
  return {
    ...(functionIdentity ?? {}),
    path: requireBundleBasename(
      member.path,
      `${description} path`,
      member.role === "header" ? ".h" : ".c"
    ),
    role: member.role,
    sha256: requireSha256(member.sha256, `${description} SHA-256`),
    size,
    ...(isFunction ? { targetBytes: member.targetBytes } : {}),
  };
}

function validateBundleFunctionLayout(functionMembers) {
  let previous;
  for (const member of functionMembers) {
    const hasFunctionFragmentIdentity = member.functionFragmentIndex !== undefined;
    if (previous === undefined) {
      if (member.firstFunctionId !== 0) {
        fail("C bundle function member ranges must start at zero");
      }
      if (hasFunctionFragmentIdentity && member.functionFragmentIndex !== 0) {
        fail("C bundle function fragment sequence must start at zero");
      }
    } else if (member.firstFunctionId === previous.lastFunctionId + 1) {
      if (
        previous.functionFragmentIndex !== undefined &&
        previous.functionFragmentIndex !== previous.functionFragmentCount - 1
      ) {
        fail("C bundle function fragment sequence is incomplete");
      }
      if (hasFunctionFragmentIdentity && member.functionFragmentIndex !== 0) {
        fail("C bundle function fragment sequence must start at zero");
      }
    } else if (
      member.firstFunctionId === previous.firstFunctionId &&
      member.lastFunctionId === previous.lastFunctionId
    ) {
      if (
        previous.functionFragmentIndex === undefined ||
        !hasFunctionFragmentIdentity ||
        member.functionFragmentCount !== previous.functionFragmentCount ||
        member.functionFragmentIndex !== previous.functionFragmentIndex + 1
      ) {
        fail("C bundle function fragment sequence is invalid");
      }
    } else {
      fail("C bundle function member ranges are not contiguous and ordered");
    }
    previous = member;
  }
  if (
    previous?.functionFragmentIndex !== undefined &&
    previous.functionFragmentIndex !== previous.functionFragmentCount - 1
  ) {
    fail("C bundle function fragment sequence is incomplete");
  }
}

async function replaceBundleManifestWithCanonicalJson(path, source) {
  const temporaryPath = `.${path}.${randomUUID()}.canonical`;
  let replaced = false;
  try {
    const handle = await fs.open(
      temporaryPath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
      0o600
    );
    try {
      await handle.writeFile(source);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporaryPath, path);
    replaced = true;
  } finally {
    if (!replaced) {
      await fs.unlink(temporaryPath).catch(() => {});
    }
  }
}

async function readCanonicalBundleManifest(path) {
  if (fsConstants.O_NOFOLLOW === undefined) {
    fail("this platform does not provide O_NOFOLLOW for authenticated C bundle manifests");
  }
  let handle;
  try {
    handle = await fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    fail("C bundle manifest is not an allowed nonempty regular file");
  }
  let bytes;
  try {
    const status = await handle.stat();
    if (!status.isFile() || status.size <= 0 || status.size > MAX_C_BUNDLE_MANIFEST_BYTES) {
      fail("C bundle manifest is not an allowed nonempty regular file");
    }
    bytes = Buffer.alloc(status.size);
    let offset = 0;
    while (offset < status.size) {
      const { bytesRead } = await handle.read(bytes, offset, status.size - offset, offset);
      if (bytesRead === 0) {
        fail("C bundle manifest changed while it was read");
      }
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (
      status.dev !== after.dev ||
      status.ino !== after.ino ||
      status.size !== after.size ||
      status.mtimeMs !== after.mtimeMs ||
      status.ctimeMs !== after.ctimeMs
    ) {
      fail("C bundle manifest changed while it was read");
    }
  } finally {
    await handle.close();
  }
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error("Convex Wasm Static Hermes precompiler: C bundle manifest is not UTF-8", {
      cause: error,
    });
  }
  let rawManifest;
  try {
    rawManifest = JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm Static Hermes precompiler: C bundle manifest is not valid JSON", {
      cause: error,
    });
  }
  const manifestObject = requireExactKeys(
    rawManifest,
    ["header", "kind", "schemaVersion", "translationUnits"],
    "C bundle manifest"
  );
  if (manifestObject.kind !== C_BUNDLE_KIND || manifestObject.schemaVersion !== 1) {
    fail("C bundle manifest kind or schema version is unsupported");
  }
  const header = normalizeBundleMember(manifestObject.header, "C bundle header");
  if (header.role !== "header") {
    fail("C bundle header must have the header role");
  }
  if (!Array.isArray(manifestObject.translationUnits)) {
    fail("C bundle translationUnits must be an array");
  }
  if (
    manifestObject.translationUnits.length < 2 ||
    manifestObject.translationUnits.length > MAX_C_BUNDLE_MEMBERS - 2
  ) {
    fail("C bundle must contain header, metadata, and function members");
  }
  const translationUnits = manifestObject.translationUnits.map((member, index) =>
    normalizeBundleMember(member, `C bundle translationUnits[${String(index)}]`)
  );
  if (
    translationUnits[0].role !== "metadata" ||
    translationUnits.slice(1).some(({ role }) => role !== "function")
  ) {
    fail("C bundle translation units are not in metadata, then function order");
  }
  validateBundleFunctionLayout(translationUnits.slice(1));
  const members = [header, ...translationUnits];
  const paths = new Set();
  for (const member of members) {
    if (paths.has(member.path)) {
      fail(`C bundle contains duplicate path ${JSON.stringify(member.path)}`);
    }
    paths.add(member.path);
  }
  const manifest = {
    header,
    kind: C_BUNDLE_KIND,
    schemaVersion: 1,
    translationUnits,
  };
  const canonicalSource = `${canonicalJson(manifest)}\n`;
  if (canonicalSource !== source) {
    await replaceBundleManifestWithCanonicalJson(path, canonicalSource);
  }
  return {
    bytes: Buffer.from(canonicalSource),
    manifest,
  };
}

async function authenticateBundleOutput(namesBeforeCompiler) {
  const { bytes, manifest } = await readCanonicalBundleManifest(C_BUNDLE_MANIFEST_PATH);
  const members = [manifest.header, ...manifest.translationUnits];
  for (const member of members) {
    if (namesBeforeCompiler.has(member.path)) {
      fail(`C bundle member path existed before compilation: ${JSON.stringify(member.path)}`);
    }
    const digest = await hashRegularFile(
      member.path,
      member.size,
      `C bundle member ${member.path}`,
      { rejectSymlink: true }
    );
    if (digest !== member.sha256) {
      fail(`C bundle member ${member.path} SHA-256 does not match its manifest identity`);
    }
  }
  const expectedOutputNames = [C_BUNDLE_MANIFEST_PATH, ...members.map(({ path }) => path)].sort();
  const outputNames = (await fs.readdir("."))
    .filter((name) => !namesBeforeCompiler.has(name))
    .sort();
  if (canonicalJson(outputNames) !== canonicalJson(expectedOutputNames)) {
    fail("successful compiler produced missing or extra C bundle files");
  }
  return {
    header: manifest.header,
    kind: C_BUNDLE_KIND,
    manifest: {
      path: C_BUNDLE_MANIFEST_PATH,
      sha256: sha256(bytes),
      size: bytes.length,
    },
    schemaVersion: 1,
    translationUnits: manifest.translationUnits,
  };
}

async function readCanonicalRequest(path) {
  const source = await fs.readFile(path, "utf8");
  let request;
  try {
    request = JSON.parse(source);
  } catch (error) {
    throw new Error("Convex Wasm Static Hermes precompiler: request is not valid JSON", {
      cause: error,
    });
  }
  requireExactKeys(
    request,
    [
      "argumentsSha256",
      "compiler",
      "generatedSource",
      "kind",
      "materialSha256",
      "nonce",
      "schemaVersion",
    ],
    "request"
  );
  if (request.kind !== REQUEST_KIND || request.schemaVersion !== 1) {
    fail("request kind or schema version is unsupported");
  }
  requireSha256(request.argumentsSha256, "request arguments SHA-256");
  requireSha256(request.materialSha256, "request material SHA-256");
  requireSha256(request.nonce, "request nonce");
  for (const [field, description] of [
    ["compiler", "request compiler"],
    ["generatedSource", "request generated source"],
  ]) {
    const identity = requireExactKeys(request[field], ["sha256", "size"], description);
    requireSha256(identity.sha256, `${description} SHA-256`);
    requirePositiveInteger(identity.size, `${description} size`);
  }
  if (`${canonicalJson(request)}\n` !== source) {
    fail("request is not canonical JSON");
  }
  return { request, requestSha256: sha256(canonicalJson(request)) };
}

export function parseStaticHermesPrecompilerArguments(argumentsList) {
  const separator = argumentsList.indexOf("--");
  if (separator < 0) {
    fail("arguments must contain -- before Static Hermes arguments");
  }
  const options = argumentsList.slice(0, separator);
  const compilerArguments = argumentsList.slice(separator + 1);
  const values = new Map();
  for (let index = 0; index < options.length; index += 2) {
    const name = options[index];
    const value = options[index + 1];
    if (
      !["--compiler", "--max-output-bytes", "--request", "--response"].includes(name) ||
      value === undefined ||
      values.has(name)
    ) {
      fail("launcher options are incomplete, duplicated, or unknown");
    }
    values.set(name, value);
  }
  if (values.size !== 4 || compilerArguments.length === 0) {
    fail("launcher requires compiler, request, response, output limit, and compiler arguments");
  }
  const compiler = values.get("--compiler");
  if (!isAbsolute(compiler)) {
    fail("compiler path must be absolute");
  }
  const maxOutputBytes = Number(values.get("--max-output-bytes"));
  requirePositiveInteger(maxOutputBytes, "maximum output bytes");
  return {
    compiler,
    compilerArguments,
    maxOutputBytes,
    requestPath: values.get("--request"),
    responsePath: values.get("--response"),
  };
}

async function runCompiler({ compiler, compilerArguments, maxOutputBytes }) {
  const child = spawn(compiler, compilerArguments, { stdio: ["ignore", "pipe", "pipe"] });
  const stdout = [];
  const stderr = [];
  let outputBytes = 0;
  let overflow = false;
  const capture = (destination) => (chunk) => {
    outputBytes += chunk.length;
    if (outputBytes > maxOutputBytes) {
      overflow = true;
      child.kill("SIGKILL");
      return;
    }
    destination.push(chunk);
  };
  child.stdout.on("data", capture(stdout));
  child.stderr.on("data", capture(stderr));
  const signalHandlers = new Map(
    FORWARDED_SIGNALS.map((signal) => [signal, () => child.kill(signal)])
  );
  for (const [signal, handler] of signalHandlers) {
    process.once(signal, handler);
  }
  try {
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    if (overflow) {
      fail(`compiler output exceeded ${String(maxOutputBytes)} bytes`);
    }
    return {
      ...result,
      stderr: Buffer.concat(stderr),
      stdout: Buffer.concat(stdout),
    };
  } finally {
    for (const [signal, handler] of signalHandlers) {
      process.off(signal, handler);
    }
  }
}

function parseSourceRejection(result) {
  if (result.code !== 1 || result.signal !== null || result.stdout.length !== 0) {
    return undefined;
  }
  let stderr;
  try {
    stderr = new TextDecoder("utf-8", { fatal: true }).decode(result.stderr);
  } catch {
    return undefined;
  }
  const finalCount = stderr.match(FINAL_ERROR_COUNT_PATTERN);
  if (finalCount === null) {
    return undefined;
  }
  const expectedCount = Number(finalCount[1]);
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 1 || expectedCount > 256) {
    return undefined;
  }
  const diagnostics = [...stderr.matchAll(DIAGNOSTIC_HEADER_PATTERN)].map((match) => {
    const message = match[3];
    let category;
    if (!message.includes("\0")) {
      if (FLOW_BINARY_INCOMPATIBILITY_PATTERN.test(message)) {
        category = FLOW_BINARY_INCOMPATIBILITY_CATEGORY;
      } else if (FLOW_SPREAD_ARGUMENT_PATTERN.test(message)) {
        category = FLOW_SPREAD_ARGUMENT_CATEGORY;
      } else if (FLOW_ARRAY_SPREAD_ARGUMENT_PATTERN.test(message)) {
        category = FLOW_ARRAY_SPREAD_ARGUMENT_CATEGORY;
      } else if (FLOW_CONSTRUCTOR_ARITY_PATTERN.test(message)) {
        category = FLOW_CONSTRUCTOR_ARITY_CATEGORY;
      } else if (FLOW_GENERIC_METHOD_INFERENCE_PATTERN.test(message)) {
        category = FLOW_GENERIC_METHOD_INFERENCE_CATEGORY;
      }
    }
    return {
      category,
      column: Number(match[2]),
      line: Number(match[1]),
    };
  });
  if (
    diagnostics.length !== expectedCount ||
    diagnostics.some(
      ({ category, column, line }) =>
        category === undefined ||
        !Number.isSafeInteger(column) ||
        !Number.isSafeInteger(line) ||
        column < 1 ||
        line < 1 ||
        column > 0xffffffff ||
        line > 0xffffffff
    )
  ) {
    return undefined;
  }
  return {
    diagnostics,
    kind: "sourceRejected",
    rawDiagnosticSha256: sha256(result.stderr),
  };
}

async function writeResponse(path, requestSha256, result) {
  const handle = await fs.open(
    path,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600
  );
  try {
    await handle.writeFile(
      `${canonicalJson({ kind: RESPONSE_KIND, requestSha256, result, schemaVersion: 1 })}\n`
    );
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function runStaticHermesPrecompiler(options) {
  const { request, requestSha256 } = await readCanonicalRequest(options.requestPath);
  if (sha256(canonicalJson(options.compilerArguments)) !== request.argumentsSha256) {
    fail("compiler arguments do not match the authenticated request");
  }
  if (
    (await hashRegularFile(options.compiler, request.compiler.size, "compiler", {
      rejectSymlink: true,
    })) !== request.compiler.sha256
  ) {
    fail("compiler does not match the authenticated request");
  }
  const inputPath = options.compilerArguments.at(-1);
  if (inputPath !== "input.js") {
    fail("authenticated invocation must compile input.js");
  }
  if (
    (await hashRegularFile(inputPath, request.generatedSource.size, "generated source", {
      rejectSymlink: true,
    })) !== request.generatedSource.sha256
  ) {
    fail("generated source does not match the authenticated request");
  }
  const bundleOutput = options.compilerArguments.includes(C_BUNDLE_ARGUMENT);
  if (bundleOutput) {
    const outputIndexes = options.compilerArguments.flatMap((argument, index) =>
      argument === "-o" ? [index] : []
    );
    if (
      options.compilerArguments.filter((argument) => argument === C_BUNDLE_ARGUMENT).length !== 1 ||
      options.compilerArguments.filter((argument) => argument === C_BUNDLE_SHARD_SIZE_ARGUMENT)
        .length !== 1 ||
      !options.compilerArguments.includes("-emit-c") ||
      outputIndexes.length !== 1 ||
      options.compilerArguments[outputIndexes[0] + 1] !== C_BUNDLE_MANIFEST_PATH
    ) {
      fail(
        `authenticated C bundle invocation must use ${C_BUNDLE_ARGUMENT}, ${C_BUNDLE_SHARD_SIZE_ARGUMENT}, and -o ${C_BUNDLE_MANIFEST_PATH}`
      );
    }
  }
  const namesBeforeCompiler = new Set(await fs.readdir("."));
  if (bundleOutput && namesBeforeCompiler.has(C_BUNDLE_MANIFEST_PATH)) {
    fail("C bundle manifest existed before compilation");
  }
  const result = await runCompiler(options);
  // The compiler and input are opened by the child process after the initial
  // identity checks. Re-authenticate both paths after it exits so a concurrent
  // replacement cannot turn an otherwise successful response into authority for
  // bytes that were never covered by the request envelope.
  if (
    (await hashRegularFile(options.compiler, request.compiler.size, "compiler", {
      rejectSymlink: true,
    })) !== request.compiler.sha256
  ) {
    fail("compiler changed during execution");
  }
  if (
    (await hashRegularFile(inputPath, request.generatedSource.size, "generated source", {
      rejectSymlink: true,
    })) !== request.generatedSource.sha256
  ) {
    fail("generated source changed during execution");
  }
  if (result.code === 0 && result.signal === null) {
    if (bundleOutput) {
      const output = await authenticateBundleOutput(namesBeforeCompiler);
      await writeResponse(options.responsePath, requestSha256, {
        kind: "success",
        output,
      });
      return { code: 0, signal: null };
    }
    const output = await fs.stat("unit.c");
    if (!output.isFile() || output.size === 0) {
      fail("successful compiler did not produce a nonempty unit.c regular file");
    }
    await writeResponse(options.responsePath, requestSha256, { kind: "success" });
    return { code: 0, signal: null };
  }
  const rejection = parseSourceRejection(result);
  if (rejection !== undefined) {
    await writeResponse(options.responsePath, requestSha256, rejection);
    return { code: 0, signal: null };
  }
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  return { code: result.code, signal: result.signal };
}

export async function main(argumentsList) {
  const result = await runStaticHermesPrecompiler(
    parseStaticHermesPrecompilerArguments(argumentsList)
  );
  if (result.signal !== null) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.code;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main(process.argv.slice(2));
}
