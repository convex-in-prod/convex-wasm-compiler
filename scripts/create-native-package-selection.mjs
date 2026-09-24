#!/usr/bin/env node

import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalCompilerPackageJson } from "./lib/convex-wasm-compiler-package.mjs";
import {
  nativeReleaseTargets,
  validateNativeReleaseSelection,
} from "./lib/convex-wasm-native-release-selection.mjs";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function exactKeys(value, keys, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${description} has unexpected fields`);
  }
}

function releaseAssetBaseUrl(repository, tag) {
  if (
    typeof repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(repository) ||
    repository.split("/").some((part) => part === "." || part === "..")
  ) {
    throw new Error("release repository must be an owner/name pair");
  }
  if (
    typeof tag !== "string" ||
    tag.length === 0 ||
    tag === "." ||
    tag === ".." ||
    tag.includes("/") ||
    tag.includes("\\")
  ) {
    throw new Error("release tag must be a non-empty path-safe name");
  }
  return `https://github.com/${repository}/releases/download/${encodeURIComponent(tag)}/`;
}

async function requireRegularAsset(path) {
  const state = await fs.lstat(path);
  if (!state.isFile() || state.size === 0) {
    throw new Error(`native release asset is missing or empty: ${path}`);
  }
}

export async function createNativePackageSelection({ assetsRoot, output, repository, tag }) {
  const root = resolve(assetsRoot);
  const baseUrl = releaseAssetBaseUrl(repository, tag);
  const packages = {};
  for (const [runtime, targetTriple] of Object.entries(nativeReleaseTargets)) {
    const indexPath = join(root, `${targetTriple}-index.json`);
    const index = JSON.parse(await fs.readFile(indexPath, "utf8"));
    exactKeys(
      index,
      ["compiler", "evidenceSha256", "kind", "precompiler", "schemaVersion", "targetTriple"],
      `${runtime} release index`
    );
    if (
      index.kind !== "convex-wasm-native-release" ||
      index.schemaVersion !== 1 ||
      index.targetTriple !== targetTriple ||
      typeof index.evidenceSha256 !== "string" ||
      !SHA256_PATTERN.test(index.evidenceSha256)
    ) {
      throw new Error(`${runtime} release index has an invalid identity`);
    }
    const references = {};
    for (const kind of ["compiler", "precompiler"]) {
      const entry = index[kind];
      exactKeys(entry, ["packageId", "path"], `${runtime} ${kind} release package`);
      if (
        typeof entry.packageId !== "string" ||
        !SHA256_PATTERN.test(entry.packageId) ||
        entry.path !== `packages/${kind}/${targetTriple}/${entry.packageId}`
      ) {
        throw new Error(`${runtime} ${kind} release package has an invalid identity`);
      }
      const assetName = `${targetTriple}-${kind}-${entry.packageId}`;
      await Promise.all([
        requireRegularAsset(join(root, assetName)),
        requireRegularAsset(join(root, `${assetName}-manifest.json`)),
      ]);
      references[kind] = {
        download: {
          binaryUrl: new URL(assetName, baseUrl).href,
          manifestUrl: new URL(`${assetName}-manifest.json`, baseUrl).href,
        },
        packageId: entry.packageId,
        targetTriple,
      };
    }
    packages[runtime] = references;
  }
  const selection = validateNativeReleaseSelection({
    kind: "convex-wasm-native-package-selection",
    packages,
  });
  await fs.writeFile(resolve(output), `${canonicalCompilerPackageJson(selection)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return selection;
}

export async function main(argumentsList) {
  const values = new Map();
  for (let index = 0; index < argumentsList.length; index += 2) {
    const option = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !["--assets-root", "--output", "--repository", "--tag"].includes(option) ||
      value === undefined ||
      value.length === 0 ||
      values.has(option)
    ) {
      throw new Error("usage: create-native-package-selection.mjs --assets-root PATH --output PATH --repository OWNER/NAME --tag TAG");
    }
    values.set(option, value);
  }
  if (values.size !== 4) {
    throw new Error("native release selection requires assets root, output, repository, and tag");
  }
  const selection = await createNativePackageSelection({
    assetsRoot: values.get("--assets-root"),
    output: values.get("--output"),
    repository: values.get("--repository"),
    tag: values.get("--tag"),
  });
  process.stdout.write(`${canonicalCompilerPackageJson(selection)}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
