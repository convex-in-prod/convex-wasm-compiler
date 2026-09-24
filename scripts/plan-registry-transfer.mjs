#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson, fingerprintJson } from "./lib/convex-wasm-artifact-contract.mjs";
import {
  deriveRuntimeRegistryTransferPlan,
  validateRuntimeRegistrySourceCatalog,
} from "./lib/runtime-registry-transfer-closure.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function fail(message) {
  throw new Error(message);
}

function requireSha256(value, description) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    fail(`${description} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function readRegistryControlFile(registryRoot, name) {
  const filePath = path.join(registryRoot, name);
  const state = lstatSync(filePath);
  if (!state.isFile() || state.size === 0 || state.size > 4 * 1024 * 1024) {
    fail(`runtime registry ${name} must be a bounded regular file`);
  }
  const bytes = readFileSync(filePath);
  const value = JSON.parse(bytes.toString("utf8"));
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) {
    fail(`runtime registry ${name} must contain canonical JSON followed by one newline`);
  }
  return { bytes, value };
}

export function parseRuntimeRegistryTransferClosureArguments(argv) {
  if (argv.length < 8 || argv.length > 20 || argv.length % 2 !== 0) {
    fail(
      "Usage: plan-registry-transfer.mjs --preflight ABSOLUTE_PATH " +
        "--registry-root ABSOLUTE_PATH " +
        "--hardlinks-output ABSOLUTE_PATH --source-catalog-output ABSOLUTE_PATH " +
        "[--selected-current-output ABSOLUTE_PATH] " +
        "[--deployment-sha256 SHA256 " +
        "--generation-manifest-sha256 SHA256 --generation-sha256 SHA256 " +
        "--source-package-runtime-content-sha256 SHA256] " +
        "[--retained-source-catalog ABSOLUTE_PATH]"
    );
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    if (values.has(option)) fail(`repeated runtime registry transfer option ${option}`);
    values.set(option, argv[index + 1]);
  }
  const registryRoot = values.get("--registry-root");
  const preflightPath = values.get("--preflight");
  const hardlinksOutput = values.get("--hardlinks-output");
  const sourceCatalogOutput = values.get("--source-catalog-output");
  const selectedCurrentOutput = values.get("--selected-current-output");
  const retainedSourceCatalogPath = values.get("--retained-source-catalog");
  if (
    !path.isAbsolute(registryRoot ?? "") ||
    !path.isAbsolute(preflightPath ?? "") ||
    !path.isAbsolute(hardlinksOutput ?? "") ||
    !path.isAbsolute(sourceCatalogOutput ?? "") ||
    (selectedCurrentOutput !== undefined && !path.isAbsolute(selectedCurrentOutput)) ||
    (retainedSourceCatalogPath !== undefined && !path.isAbsolute(retainedSourceCatalogPath))
  ) {
    fail("runtime registry transfer paths must be absolute");
  }
  const pairOptions = [
    ["--deployment-sha256", "deploymentSha256"],
    ["--generation-manifest-sha256", "generationManifestSha256"],
    ["--generation-sha256", "generationSha256"],
    ["--source-package-runtime-content-sha256", "sourcePackageRuntimeContentSha256"],
  ];
  const allowedOptions = new Set([
    "--registry-root",
    "--preflight",
    "--hardlinks-output",
    "--source-catalog-output",
    "--selected-current-output",
    "--retained-source-catalog",
    ...pairOptions.map(([option]) => option),
  ]);
  for (const option of values.keys()) {
    if (!allowedOptions.has(option)) fail(`unknown runtime registry transfer option ${option}`);
  }
  const presentPairOptions = pairOptions.filter(([option]) => values.has(option));
  if (presentPairOptions.length !== 0 && presentPairOptions.length !== pairOptions.length) {
    fail("runtime registry transfer pair identity must be complete");
  }
  const pair =
    presentPairOptions.length === 0
      ? undefined
      : Object.fromEntries(
          pairOptions.map(([option, name]) => [
            name,
            requireSha256(values.get(option), `runtime registry transfer ${name}`),
          ])
        );
  return {
    hardlinksOutput,
    pair,
    preflightPath,
    registryRoot,
    retainedSourceCatalogPath,
    ...(selectedCurrentOutput === undefined ? {} : { selectedCurrentOutput }),
    sourceCatalogOutput,
  };
}

function main(argv) {
  const {
    hardlinksOutput,
    pair,
    preflightPath,
    registryRoot,
    retainedSourceCatalogPath,
    selectedCurrentOutput,
    sourceCatalogOutput,
  } = parseRuntimeRegistryTransferClosureArguments(argv);
  const preflightState = lstatSync(preflightPath);
  if (!preflightState.isFile() || preflightState.size === 0 || preflightState.size > 128 * 1024 * 1024) {
    fail("runtime registry preflight must be a bounded regular file");
  }
  const preflight = JSON.parse(readFileSync(preflightPath, "utf8"));
  if (preflight?.runtimeRegistry?.path !== registryRoot) {
    fail("runtime registry preflight path differs from the selected registry root");
  }
  // The backend preflight exposes an authenticated catalog projection; `kind` is present only
  // in the registry's control file. Check that file before using the projection for selection.
  const catalog = validateRuntimeRegistrySourceCatalog(
    readRegistryControlFile(registryRoot, "source-catalog.json").value
  );
  if (
    preflight.runtimeRegistry.sourceCatalog?.catalogSha256 !== catalog.catalogSha256 ||
    canonicalJson(preflight.runtimeRegistry.sourceCatalog.entries) !== canonicalJson(catalog.entries)
  ) {
    fail("runtime registry source catalog differs from the preflight");
  }
  const current = readRegistryControlFile(registryRoot, "current").value;
  const { currentSha256, ...currentContent } = current;
  if (
    current.kind !== "convex-wasm-runtime-registry-current-v1" ||
    canonicalJson(Object.keys(current).sort()) !==
      canonicalJson(["currentSha256", "deploymentSha256", "generation", "generationSha256", "kind"].sort()) ||
    canonicalJson(Object.keys(current.generation ?? {}).sort()) !== canonicalJson(["sha256", "size"]) ||
    !Number.isSafeInteger(current.generation.size) ||
    current.generation.size <= 0 ||
    current.generation.size > 4 * 1024 * 1024 ||
    !SHA256_PATTERN.test(current.deploymentSha256) ||
    !SHA256_PATTERN.test(current.generationSha256) ||
    !SHA256_PATTERN.test(current.generation.sha256) ||
    requireSha256(currentSha256, "runtime registry current identity") !==
      fingerprintJson(currentContent) ||
    preflight.runtimeRegistry.currentSha256 !== currentSha256
  ) {
    fail("runtime registry current differs from the preflight");
  }
  const references = preflight.runtimeRegistry.generationReferences;
  if (!Array.isArray(references) || references.length !== 1) {
    fail("registry transfer requires a preflight of exactly one selected generation");
  }
  const reference = references[0];
  const deploymentSha256 = requireSha256(reference.deploymentSha256, "selected deployment identity");
  const generationSha256 = requireSha256(reference.generationSha256, "selected generation identity");
  const generation = readRegistryControlFile(
    registryRoot,
    `generations/${deploymentSha256}/${generationSha256}/generation.json`
  );
  if (
    generation.bytes.length !== reference.generation?.size ||
    createHash("sha256").update(generation.bytes).digest("hex") !== reference.generation?.sha256
  ) {
    fail("runtime registry generation differs from the preflight");
  }
  const selectedIsCurrent =
    deploymentSha256 === current.deploymentSha256 &&
    generationSha256 === current.generationSha256 &&
    canonicalJson(reference.generation) === canonicalJson(current.generation);
  if (reference.current !== selectedIsCurrent || (pair === undefined && !selectedIsCurrent)) {
    fail("runtime registry preflight selection differs from the current pointer");
  }
  if (
    pair !== undefined &&
    Object.entries(pair).some(([name, value]) => references[0][name] !== value &&
      (name !== "generationManifestSha256" || references[0].generation?.sha256 !== value))
  ) {
    fail("runtime registry preflight does not match the selected pair");
  }
  let retainedSourceCatalog;
  if (retainedSourceCatalogPath !== undefined) {
    const retainedSourceCatalogBytes = readFileSync(retainedSourceCatalogPath);
    let value;
    try {
      value = JSON.parse(retainedSourceCatalogBytes.toString("utf8"));
    } catch {
      fail("retained destination source catalog must contain JSON");
    }
    if (!retainedSourceCatalogBytes.equals(Buffer.from(`${JSON.stringify(value)}\n`))) {
      fail(
        "retained destination source catalog must contain canonical JSON followed by one newline"
      );
    }
    retainedSourceCatalog = value;
  }
  const { hardlinks, paths, sourceCatalogBytes } = deriveRuntimeRegistryTransferPlan(preflight, {
    retainedSourceCatalog,
  });
  const hardlinkLines = hardlinks.flatMap(({ source, target }) => [source, target]);
  writeFileSync(
    hardlinksOutput,
    hardlinkLines.length === 0 ? "" : `${hardlinkLines.join("\n")}\n`,
    { mode: 0o600 }
  );
  writeFileSync(sourceCatalogOutput, sourceCatalogBytes, { mode: 0o600 });
  if (selectedCurrentOutput !== undefined) {
    const reference = references[0];
    const withoutIdentity = {
      deploymentSha256: reference.deploymentSha256,
      generation: {
        sha256: reference.generation.sha256,
        size: reference.generation.size,
      },
      generationSha256: reference.generationSha256,
      kind: "convex-wasm-runtime-registry-current-v1",
    };
    const current = { ...withoutIdentity, currentSha256: fingerprintJson(withoutIdentity) };
    writeFileSync(selectedCurrentOutput, `${canonicalJson(current)}\n`, { mode: 0o600 });
  }
  process.stdout.write(Buffer.from(`${paths.join("\0")}\0`));
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
