import { createHash } from "node:crypto";
import { isAbsolute, join } from "node:path";

import {
  assertExactKeys,
  assertPlainObject,
  canonicalJson,
  fail,
  fingerprintJson,
  requirePositiveInteger,
  requirePositiveU32,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import {
  decodeUtf8,
  hashPrivateRegularFile,
  readPrivateRegularFile,
} from "./convex-wasm-artifact-material.mjs";

export const C_BUNDLE_CACHE_ENTRY_KIND = "convex-wasm-c-bundle-cache-entry-v1";
export const C_BUNDLE_KIND = "static-hermes-c-bundle-v1";
export const C_BUNDLE_MANIFEST_PATH = "unit.c.json";
const C_BUNDLE_ARGUMENT = "-Xemit-c-bundle";
export const staticHermesCBundleShardTargetBytes = 2_097_152;
export const staticHermesLargeCBundleMemberBytesThreshold = 2 * staticHermesCBundleShardTargetBytes;
const C_BUNDLE_SHARD_SIZE_ARGUMENT = `-Xemit-c-shard-size=${String(staticHermesCBundleShardTargetBytes)}`;
const C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO = 0;
const C_BUNDLE_OVERSIZE_REASONS = new Set(["no-outlineable-run", "single-instruction"]);
// The producer's 65,536-file limit includes the manifest, header, and metadata translation unit.
const MAX_STATIC_HERMES_C_BUNDLE_MEMBERS = 65_536;
const MAX_STATIC_HERMES_C_BUNDLE_FUNCTION_MEMBERS = MAX_STATIC_HERMES_C_BUNDLE_MEMBERS - 3;
const MAX_STATIC_HERMES_C_BUNDLE_MANIFEST_BYTES = 16 * 1024 * 1024;
const STATIC_HERMES_C_BUNDLE_AUTHENTICATION_CONCURRENCY = 4;
const C_BUNDLE_BASENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
export const C_COMPILER_OPTIMIZATION_FLAG_PATTERN = /^-O(?:[0-9]|[gsz]|fast)?$/u;
export const C_OPTIMIZATION_LEVEL_ZERO_C_BUNDLE_MEMBER_OBJECT_STAGE =
  "c-optimization-level-zero-c-bundle-member-object";
const CONTROL_CHARACTER_PATTERN = /\p{Control}/u;

export const convexWasmStaticHermesCBundleMemberCompilationPolicy = Object.freeze({
  cOptimizationLevelZero: Object.freeze({
    cOptimizationLevel: C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO,
    functionCount: 1,
    optimizationFlag: "-O0",
    role: "function",
    stage: C_OPTIMIZATION_LEVEL_ZERO_C_BUNDLE_MEMBER_OBJECT_STAGE,
  }),
  largeFunctionMember: Object.freeze({
    appliesToFunctionFragments: false,
    minimumMemberBytes: staticHermesLargeCBundleMemberBytesThreshold,
    optimizationFlag: "-Oz",
    role: "function",
  }),
  kind: "convex-wasm-static-hermes-c-bundle-member-compilation-v4",
  // An exceptional function can exceed the shard target. Keep only that member
  // size-oriented; unrelated members in the same bundle compile for speed.
  normalOptimizationFlag: "-O2",
});

export const staticHermesCBundleMemberCompilationBaselinePolicy = Object.freeze({
  ...convexWasmStaticHermesCBundleMemberCompilationPolicy,
  normalOptimizationFlag: "-O2",
});

export function staticHermesCBundleEnabled(flags) {
  const bundleCount = flags.filter((flag) => flag === C_BUNDLE_ARGUMENT).length;
  const shardArguments = flags.filter((flag) => flag.startsWith("-Xemit-c-shard-size="));
  if (bundleCount === 0 && shardArguments.length === 0) {
    return false;
  }
  if (
    bundleCount !== 1 ||
    shardArguments.length !== 1 ||
    shardArguments[0] !== C_BUNDLE_SHARD_SIZE_ARGUMENT ||
    !flags.includes("-emit-c")
  ) {
    fail(
      `Static Hermes C bundle flags must contain exactly one ${C_BUNDLE_ARGUMENT} and ${C_BUNDLE_SHARD_SIZE_ARGUMENT} alongside -emit-c`
    );
  }
  return true;
}

export function isStaticHermesCBundleEntry(entry) {
  return entry.kind === C_BUNDLE_CACHE_ENTRY_KIND;
}

export function staticHermesCBundleTranslationUnitBytes(bundle) {
  if (!Array.isArray(bundle.translationUnits)) {
    fail("Static Hermes C bundle translation units must be an array");
  }
  let bytes = 0;
  for (const member of bundle.translationUnits) {
    bytes += requirePositiveInteger(member.size, "Static Hermes C bundle member size");
    if (!Number.isSafeInteger(bytes)) {
      fail("Static Hermes C bundle translation-unit byte total is not a safe integer");
    }
  }
  return bytes;
}

export function staticHermesCBundleMemberCompilation(
  member,
  command,
  ordinaryStage,
  memberCompilationPolicy,
  translationUnitBytes
) {
  requirePositiveInteger(
    translationUnitBytes,
    "Static Hermes C bundle compilation translation-unit bytes"
  );
  const optimizationFlags = command.args.filter((argument) =>
    C_COMPILER_OPTIMIZATION_FLAG_PATTERN.test(argument)
  );
  if (
    optimizationFlags.length !== 1 ||
    optimizationFlags[0] !==
      staticHermesCBundleMemberCompilationBaselinePolicy.normalOptimizationFlag
  ) {
    fail("Static Hermes C bundle members must start with exactly one -O2 flag");
  }
  const largeFunctionMember = memberCompilationPolicy.largeFunctionMember;
  if (largeFunctionMember.appliesToFunctionFragments !== false) {
    fail("Static Hermes large-member optimization policy must exclude function fragments");
  }
  if (
    member.role === "function" &&
    member.cOptimizationLevel === C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO
  ) {
    return {
      command: {
        executable: command.executable,
        args: [
          ...command.args.filter(
            (argument) => !C_COMPILER_OPTIMIZATION_FLAG_PATTERN.test(argument)
          ),
          memberCompilationPolicy.cOptimizationLevelZero.optimizationFlag,
        ],
      },
      optimization: memberCompilationPolicy.cOptimizationLevelZero.optimizationFlag,
      stage: memberCompilationPolicy.cOptimizationLevelZero.stage,
    };
  }
  const optimizationFlag =
    member.role === largeFunctionMember.role &&
    member.functionFragmentCount === undefined &&
    member.size >= largeFunctionMember.minimumMemberBytes
      ? largeFunctionMember.optimizationFlag
      : memberCompilationPolicy.normalOptimizationFlag;
  return {
    command: {
      executable: command.executable,
      args: command.args.map((argument) =>
        argument === staticHermesCBundleMemberCompilationBaselinePolicy.normalOptimizationFlag
          ? optimizationFlag
          : argument
      ),
    },
    optimization: optimizationFlag,
    stage: ordinaryStage,
  };
}

export function staticHermesCBundleMemberTimingIdentity(member) {
  return {
    path: member.path,
    role: member.role,
    ...(member.role === "function"
      ? {
          ...(member.cOptimizationLevel === undefined
            ? {}
            : { cOptimizationLevel: member.cOptimizationLevel }),
          firstFunctionId: member.firstFunctionId,
          ...(member.functionFragmentCount === undefined
            ? {}
            : {
                functionFragmentCount: member.functionFragmentCount,
                functionFragmentIndex: member.functionFragmentIndex,
              }),
          functionCount: member.functionCount,
          lastFunctionId: member.lastFunctionId,
          oversize: member.oversize,
          ...(member.oversizeReason === undefined ? {} : { oversizeReason: member.oversizeReason }),
          targetBytes: member.targetBytes,
        }
      : {}),
  };
}

export function staticHermesCBundleMemberCompilationIdentity(
  bundle,
  commands,
  ordinaryStage,
  memberCompilationPolicy
) {
  const translationUnitBytes = staticHermesCBundleTranslationUnitBytes(bundle);
  const objectNames = bundle.translationUnits.map(
    (_, index) => `member-${String(index).padStart(5, "0")}.o`
  );
  const memberCompilations = bundle.translationUnits.map((member, index) => {
    const compilation = staticHermesCBundleMemberCompilation(
      member,
      {
        executable: commands.compileExportMember.executable,
        args: [...commands.compileExportMember.args, member.path, "-o", objectNames[index]],
      },
      ordinaryStage,
      memberCompilationPolicy,
      translationUnitBytes
    );
    return {
      effectiveArguments: compilation.command.args,
      member: staticHermesCBundleMemberTimingIdentity(member),
      optimization: compilation.optimization,
      stage: compilation.stage,
    };
  });
  return {
    kind: "convex-wasm-static-hermes-c-bundle-member-command-identity-v3",
    memberCompilationPolicy,
    memberCompilations,
    memberArchive: {
      format: "gnu-ar",
      kind: "convex-wasm-static-hermes-c-bundle-member-archive-v1",
      memberNames: objectNames,
    },
  };
}

export function staticHermesCBundlePackageCompilationSha256({
  capabilityBridge,
  capabilityFormatter,
  cohortMembers,
}) {
  const applications = cohortMembers.map(({ assignment, memberIdentities }) => {
    const generatedC = memberIdentities.generatedC.staticHermes.precompileProcess;
    const object = memberIdentities.exportObject.staticHermesCBundleMemberCompilation;
    if (object === undefined) {
      if (generatedC.cBundleMemberCompilationPolicy !== undefined) {
        fail("Static Hermes C bundle generated-C identity has no member compilation identity");
      }
      return undefined;
    }
    return {
      generatedC,
      object,
      routeId: assignment.routeId,
    };
  });
  const bridge =
    capabilityBridge === undefined
      ? undefined
      : {
          generatedC: capabilityBridge.generatedCIdentity.staticHermes.precompileProcess,
          object: capabilityBridge.objectIdentity.staticHermesCBundleMemberCompilation,
        };
  const formatter =
    capabilityFormatter === undefined
      ? undefined
      : {
          generatedC: capabilityFormatter.generatedCIdentity.staticHermes.precompileProcess,
          object: capabilityFormatter.objectIdentity.staticHermesCBundleMemberCompilation,
        };
  if (
    applications.every((application) => application === undefined) &&
    (bridge === undefined || bridge.object === undefined) &&
    (formatter === undefined || formatter.object === undefined)
  ) {
    return undefined;
  }
  if (
    applications.some((application) => application === undefined) ||
    (bridge !== undefined && bridge.object === undefined) ||
    (formatter !== undefined && formatter.object === undefined)
  ) {
    fail("Static Hermes C bundle compilation identities are incomplete");
  }
  return fingerprintJson({
    applications,
    ...(bridge === undefined ? {} : { bridge }),
    ...(formatter === undefined ? {} : { formatter }),
    kind: "convex-wasm-static-hermes-c-bundle-package-compilation-v1",
  });
}

export function staticHermesPrecompileProcessIdentity(command, memberCompilationPolicy) {
  const separator = command.args.indexOf("--");
  if (separator < 0 || command.args.indexOf("--", separator + 1) >= 0) {
    fail("Static Hermes launcher command must contain exactly one argument separator");
  }
  const compilerOptionIndex = command.args.indexOf("--compiler");
  if (
    compilerOptionIndex < 0 ||
    compilerOptionIndex + 1 >= separator ||
    command.args.indexOf("--compiler", compilerOptionIndex + 1) >= 0
  ) {
    fail("Static Hermes launcher command must contain exactly one compiler option");
  }
  // The compiler file is represented by authenticated Static Hermes materials, not its checkout path.
  const compilerArguments = command.args.slice(separator + 1);
  const cBundleEnabled = staticHermesCBundleEnabled(compilerArguments);
  if (cBundleEnabled && memberCompilationPolicy === undefined) {
    fail("Static Hermes C bundle precompile identity requires a member compilation policy");
  }
  return {
    compilerArgumentsSha256: fingerprintJson(compilerArguments),
    ...(cBundleEnabled
      ? {
          cBundleMemberCompilationPolicy: memberCompilationPolicy,
        }
      : {}),
    kind: "convex-wasm-static-hermes-precompile-process-identity-v1",
    launcherArgumentsSha256: fingerprintJson([
      ...command.args.slice(0, compilerOptionIndex),
      ...command.args.slice(compilerOptionIndex + 2, separator),
    ]),
  };
}

function requireStaticHermesCBundleBasename(value, description, extension) {
  requireString(value, description);
  if (
    value === "." ||
    value === ".." ||
    isAbsolute(value) ||
    value.includes("/") ||
    value.includes("\\") ||
    CONTROL_CHARACTER_PATTERN.test(value) ||
    !C_BUNDLE_BASENAME_PATTERN.test(value) ||
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

export function normalizeStaticHermesCBundleMember(value, description) {
  assertPlainObject(value, description);
  const isFunction = value.role === "function";
  const hasCOptimizationLevel = Object.hasOwn(value, "cOptimizationLevel");
  const hasFunctionFragmentIndex = Object.hasOwn(value, "functionFragmentIndex");
  const hasFunctionFragmentCount = Object.hasOwn(value, "functionFragmentCount");
  const hasOversizeReason = Object.hasOwn(value, "oversizeReason");
  if (hasFunctionFragmentIndex !== hasFunctionFragmentCount) {
    fail(`${description} function fragment identity must include index and count`);
  }
  assertExactKeys(
    value,
    new Set(
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
        : ["path", "role", "sha256", "size"]
    ),
    description
  );
  if (!["function", "header", "metadata"].includes(value.role)) {
    fail(`${description}.role is unsupported`);
  }
  const size = requirePositiveInteger(value.size, `${description}.size`);
  let functionIdentity;
  if (isFunction) {
    const firstFunctionId = requireNonnegativeU32(
      value.firstFunctionId,
      `${description}.firstFunctionId`
    );
    const lastFunctionId = requireNonnegativeU32(
      value.lastFunctionId,
      `${description}.lastFunctionId`
    );
    const functionCount = requirePositiveU32(value.functionCount, `${description}.functionCount`);
    if (
      lastFunctionId < firstFunctionId ||
      functionCount !== lastFunctionId - firstFunctionId + 1
    ) {
      fail(`${description} function range and count disagree`);
    }
    if (
      value.targetBytes !== staticHermesCBundleShardTargetBytes ||
      typeof value.oversize !== "boolean"
    ) {
      fail(`${description} targetBytes or oversize marker is invalid`);
    }
    // targetBytes is the producer's aggregate function-body budget. The emitted file also carries
    // declarations and externs, so a multi-function shard may exceed it without being oversized.
    if (
      (functionCount === 1 && value.oversize !== size > value.targetBytes) ||
      (value.oversize && functionCount !== 1)
    ) {
      fail(`${description} oversize marker does not match its size and function count`);
    }
    let oversizeReason;
    if (value.oversize) {
      if (!hasOversizeReason) {
        fail(`${description} oversize member must declare an oversizeReason`);
      }
      if (!C_BUNDLE_OVERSIZE_REASONS.has(value.oversizeReason)) {
        fail(`${description}.oversizeReason is unsupported`);
      }
      oversizeReason = value.oversizeReason;
    } else if (hasOversizeReason) {
      fail(`${description} non-oversize member must not declare an oversizeReason`);
    }
    let cOptimizationLevel;
    if (hasCOptimizationLevel) {
      if (value.cOptimizationLevel !== C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO) {
        fail(
          `${description}.cOptimizationLevel must be ${String(C_BUNDLE_C_OPTIMIZATION_LEVEL_ZERO)}`
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
        value.functionFragmentCount,
        `${description}.functionFragmentCount`
      );
      const functionFragmentIndex = requireNonnegativeU32(
        value.functionFragmentIndex,
        `${description}.functionFragmentIndex`
      );
      if (
        functionCount !== 1 ||
        functionFragmentCount < 2 ||
        functionFragmentCount > MAX_STATIC_HERMES_C_BUNDLE_FUNCTION_MEMBERS ||
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
      oversize: value.oversize,
      ...(oversizeReason === undefined ? {} : { oversizeReason }),
      ...(functionFragmentIdentity ?? {}),
    };
  }
  return {
    ...(functionIdentity ?? {}),
    path: requireStaticHermesCBundleBasename(
      value.path,
      `${description}.path`,
      value.role === "header" ? ".h" : ".c"
    ),
    role: value.role,
    sha256: requireSha256(value.sha256, `${description}.sha256`),
    size,
    ...(isFunction ? { targetBytes: value.targetBytes } : {}),
  };
}

function validateStaticHermesCBundleFunctionLayout(functionMembers, description) {
  let previous;
  for (const member of functionMembers) {
    const hasFunctionFragmentIdentity = member.functionFragmentIndex !== undefined;
    if (previous === undefined) {
      if (member.firstFunctionId !== 0) {
        fail(`${description} function ranges must start at zero`);
      }
      if (hasFunctionFragmentIdentity && member.functionFragmentIndex !== 0) {
        fail(`${description} function fragment sequence must start at zero`);
      }
    } else if (member.firstFunctionId === previous.lastFunctionId + 1) {
      if (
        previous.functionFragmentIndex !== undefined &&
        previous.functionFragmentIndex !== previous.functionFragmentCount - 1
      ) {
        fail(`${description} function fragment sequence is incomplete`);
      }
      if (hasFunctionFragmentIdentity && member.functionFragmentIndex !== 0) {
        fail(`${description} function fragment sequence must start at zero`);
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
        fail(`${description} function fragment sequence is invalid`);
      }
    } else {
      fail(`${description} function ranges are not contiguous and ordered`);
    }
    previous = member;
  }
  if (
    previous?.functionFragmentIndex !== undefined &&
    previous.functionFragmentIndex !== previous.functionFragmentCount - 1
  ) {
    fail(`${description} function fragment sequence is incomplete`);
  }
}

function normalizeStaticHermesCBundleLayout(headerValue, translationUnitValues, description) {
  const header = normalizeStaticHermesCBundleMember(headerValue, `${description}.header`);
  if (header.role !== "header") {
    fail(`${description}.header must have the header role`);
  }
  if (
    !Array.isArray(translationUnitValues) ||
    translationUnitValues.length < 2 ||
    translationUnitValues.length > MAX_STATIC_HERMES_C_BUNDLE_MEMBERS - 2
  ) {
    fail(`${description} must contain header, metadata, and function members`);
  }
  const translationUnits = translationUnitValues.map((member, index) =>
    normalizeStaticHermesCBundleMember(member, `${description}.translationUnits[${String(index)}]`)
  );
  if (
    translationUnits[0].role !== "metadata" ||
    translationUnits.slice(1).some(({ role }) => role !== "function")
  ) {
    fail(`${description}.translationUnits must be ordered as metadata, then functions`);
  }
  const members = [header, ...translationUnits];
  const paths = new Set();
  for (const member of members) {
    if (paths.has(member.path)) {
      fail(`${description} contains duplicate path ${JSON.stringify(member.path)}`);
    }
    paths.add(member.path);
  }
  validateStaticHermesCBundleFunctionLayout(translationUnits.slice(1), description);
  return { header, translationUnits };
}

function normalizeStaticHermesCBundleManifest(value, description) {
  assertPlainObject(value, description);
  assertExactKeys(
    value,
    new Set(["header", "kind", "schemaVersion", "translationUnits"]),
    description
  );
  if (value.kind !== C_BUNDLE_KIND || value.schemaVersion !== 1) {
    fail(`${description} kind or schema version is unsupported`);
  }
  const layout = normalizeStaticHermesCBundleLayout(
    value.header,
    value.translationUnits,
    description
  );
  return {
    header: layout.header,
    kind: C_BUNDLE_KIND,
    schemaVersion: 1,
    translationUnits: layout.translationUnits,
  };
}

export function normalizeStaticHermesCBundleOutput(value, description) {
  assertPlainObject(value, description);
  assertExactKeys(
    value,
    new Set(["header", "kind", "manifest", "schemaVersion", "translationUnits"]),
    description
  );
  const manifest = value.manifest;
  assertPlainObject(manifest, `${description}.manifest`);
  assertExactKeys(manifest, new Set(["path", "sha256", "size"]), `${description}.manifest`);
  if (value.kind !== C_BUNDLE_KIND || value.schemaVersion !== 1) {
    fail(`${description} kind or schema version is unsupported`);
  }
  const layout = normalizeStaticHermesCBundleLayout(
    value.header,
    value.translationUnits,
    description
  );
  return {
    header: layout.header,
    kind: C_BUNDLE_KIND,
    manifest: {
      path: (() => {
        const path = requireStaticHermesCBundleBasename(
          manifest.path,
          `${description}.manifest.path`,
          ".json"
        );
        if (path !== C_BUNDLE_MANIFEST_PATH) {
          fail(`${description}.manifest.path must be ${C_BUNDLE_MANIFEST_PATH}`);
        }
        return path;
      })(),
      sha256: requireSha256(manifest.sha256, `${description}.manifest.sha256`),
      size: requirePositiveInteger(manifest.size, `${description}.manifest.size`),
    },
    schemaVersion: 1,
    translationUnits: layout.translationUnits,
  };
}

export function staticHermesCBundleMembers(bundle) {
  return [bundle.header, ...bundle.translationUnits];
}

async function runStaticHermesCBundleFileOperationsBounded(
  files,
  scheduler,
  operation,
  { collectResults, description, operationDescription }
) {
  if (!Array.isArray(files)) {
    fail(`${description} files must be an array`);
  }
  if (typeof operation !== "function") {
    fail(`${description} ${operationDescription} must be a function`);
  }
  const concurrency =
    scheduler === undefined
      ? STATIC_HERMES_C_BUNDLE_AUTHENTICATION_CONCURRENCY
      : requirePositiveInteger(scheduler.concurrency, `${description} scheduler concurrency`);
  if (scheduler !== undefined && typeof scheduler.run !== "function") {
    fail(`${description} scheduler must provide run()`);
  }
  const results = collectResults ? new Array(files.length) : undefined;
  const failures = new Map();
  let nextIndex = 0;
  let stopped = false;
  const runOperation = async (file, index) => {
    if (stopped) return;
    try {
      const result = await operation(file, index);
      if (results !== undefined) {
        results[index] = result;
      }
    } catch (error) {
      failures.set(index, error);
      stopped = true;
    }
  };
  const workers = Array.from({ length: Math.min(concurrency, files.length) }, async () => {
    while (!stopped) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= files.length) return;
      if (scheduler === undefined) {
        await runOperation(files[index], index);
      } else {
        try {
          await scheduler.run(async () => await runOperation(files[index], index));
        } catch (error) {
          failures.set(index, error);
          stopped = true;
        }
      }
    }
  });
  await Promise.all(workers);
  let failureIndex;
  // Admitted file operations can fail in completion order; retain the bundle-member order.
  for (const index of failures.keys()) {
    if (failureIndex === undefined || index < failureIndex) {
      failureIndex = index;
    }
  }
  if (failureIndex !== undefined) throw failures.get(failureIndex);
  return results;
}

export async function runStaticHermesCBundleFileOperations(files, scheduler, operation) {
  await runStaticHermesCBundleFileOperationsBounded(files, scheduler, operation, {
    collectResults: false,
    description: "Static Hermes C bundle file operation",
    operationDescription: "operation",
  });
}

export async function runStaticHermesCBundleFileAuthentications(
  files,
  scheduler,
  authenticateFile
) {
  return await runStaticHermesCBundleFileOperationsBounded(files, scheduler, authenticateFile, {
    collectResults: true,
    description: "Static Hermes C bundle authentication",
    operationDescription: "authenticator",
  });
}

function staticHermesCBundleAuthenticatedFileIdentity(authenticatedFileIdentities, path) {
  if (authenticatedFileIdentities === undefined) {
    return undefined;
  }
  if (!(authenticatedFileIdentities instanceof Map)) {
    fail("Static Hermes C bundle authenticated file identities must be a Map");
  }
  const identity = authenticatedFileIdentities.get(path);
  if (identity === undefined) {
    fail(`Static Hermes C bundle authenticated file identity is absent for ${path}`);
  }
  return identity;
}

export async function authenticateStaticHermesCBundle(
  root,
  expectedBundle,
  maxArtifactBytes,
  memberScheduler,
  authenticatedFileIdentities
) {
  requirePositiveInteger(maxArtifactBytes, "Static Hermes C bundle generated-C byte limit");
  const bundle = normalizeStaticHermesCBundleOutput(
    expectedBundle,
    "authenticated Static Hermes C bundle"
  );
  const manifestBytes = await readPrivateRegularFile(
    join(root, bundle.manifest.path),
    MAX_STATIC_HERMES_C_BUNDLE_MANIFEST_BYTES,
    "Static Hermes C bundle manifest",
    staticHermesCBundleAuthenticatedFileIdentity(authenticatedFileIdentities, bundle.manifest.path)
  );
  if (
    manifestBytes.length !== bundle.manifest.size ||
    createHash("sha256").update(manifestBytes).digest("hex") !== bundle.manifest.sha256
  ) {
    fail("Static Hermes C bundle manifest does not match its authenticated identity");
  }
  const manifestSource = decodeUtf8(manifestBytes, "Static Hermes C bundle manifest");
  let rawManifest;
  try {
    rawManifest = JSON.parse(manifestSource);
  } catch (error) {
    throw new Error("Convex Wasm artifact pipeline: Static Hermes C bundle manifest is not JSON", {
      cause: error,
    });
  }
  const manifest = normalizeStaticHermesCBundleManifest(
    rawManifest,
    "Static Hermes C bundle manifest"
  );
  const canonicalManifest = canonicalJson(manifest);
  if (`${canonicalManifest}\n` !== manifestSource) {
    fail("Static Hermes C bundle manifest is not canonical JSON");
  }
  if (
    canonicalManifest !==
    canonicalJson({
      header: bundle.header,
      kind: bundle.kind,
      schemaVersion: bundle.schemaVersion,
      translationUnits: bundle.translationUnits,
    })
  ) {
    fail("Static Hermes C bundle manifest members do not match the authenticated response");
  }
  const members = staticHermesCBundleMembers(bundle);
  let artifactSize = 0;
  for (const member of members) {
    artifactSize += member.size;
    if (!Number.isSafeInteger(artifactSize) || artifactSize > maxArtifactBytes) {
      fail(
        `Static Hermes C bundle has more than the ${String(maxArtifactBytes)}-byte generated-C limit`
      );
    }
  }
  await runStaticHermesCBundleFileAuthentications(members, memberScheduler, async (member) => {
    const digest = await hashPrivateRegularFile(
      join(root, member.path),
      member.size,
      `Static Hermes C bundle member ${member.path}`,
      staticHermesCBundleAuthenticatedFileIdentity(authenticatedFileIdentities, member.path)
    );
    if (digest.size !== member.size || digest.sha256 !== member.sha256) {
      fail(`Static Hermes C bundle member ${member.path} does not match its identity`);
    }
  });
  return {
    artifactSha256: bundle.manifest.sha256,
    artifactSize,
    bundle,
  };
}
