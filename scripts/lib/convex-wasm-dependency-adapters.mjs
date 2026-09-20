import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

import { parse as parseBabelAst } from "@babel/parser";

const DESCRIPTOR_KIND = "convex-wasm-dependency-adapter-descriptor";
const MATERIAL_KIND = "convex-wasm-dependency-adapter-material";
const DESCRIPTOR_PATH = "scripts/convex-wasm-dependency-adapters.json";
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const SEMANTIC_KINDS = new Set([
  "databaseGetBatch",
  "databaseGetBatchOrThrow",
  "databaseIndexCollect",
  "databaseIndexUnique",
  "databaseIndexUniqueOrThrow",
  "functionHandleCreate",
]);

function fail(message) {
  throw new Error(`Convex Wasm dependency adapters: ${message}`);
}

function exactKeys(value, keys, description) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${description} has unsupported fields`);
  }
}

function string(value, description) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    fail(`${description} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function identifier(value, description) {
  string(value, description);
  if (!IDENTIFIER_PATTERN.test(value)) fail(`${description} must be a JavaScript identifier`);
  return value;
}

function sha256(value, description) {
  string(value, description);
  if (!SHA256_PATTERN.test(value)) fail(`${description} must be a lowercase SHA-256 digest`);
  return value;
}

function modulePath(value, description) {
  string(value, description);
  if (
    value.startsWith("/") ||
    value.includes("\\") ||
    value.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`${description} must be a normalized repository-relative path`);
  }
  return value;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function hashBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function readRepositoryFile(repoRoot, repositoryPath, description) {
  const requestedPath = resolve(repoRoot, repositoryPath);
  const requestedRelative = relative(repoRoot, requestedPath);
  if (
    isAbsolute(requestedRelative) ||
    requestedRelative === ".." ||
    requestedRelative.startsWith(`..${sep}`)
  ) {
    fail(`${description} escapes the repository root`);
  }
  const canonicalPath = await realpath(requestedPath);
  const canonicalRelative = relative(repoRoot, canonicalPath);
  if (
    isAbsolute(canonicalRelative) ||
    canonicalRelative === ".." ||
    canonicalRelative.startsWith(`..${sep}`)
  ) {
    fail(`${description} resolves outside the repository root`);
  }
  return readFile(canonicalPath);
}

function validateLock(value, description) {
  exactKeys(value, ["entrySha256", "packageKey", "path"], description);
  return {
    entrySha256: sha256(value.entrySha256, `${description}.entrySha256`),
    packageKey: modulePath(value.packageKey, `${description}.packageKey`),
    path: modulePath(value.path, `${description}.path`),
  };
}

function validateSemanticSource(value, description) {
  exactKeys(value, ["path", "sourceSha256", "units"], description);
  if (!Array.isArray(value.units) || value.units.length === 0) {
    fail(`${description}.units must be a non-empty array`);
  }
  const units = value.units.map((unit, index) => {
    const unitDescription = `${description}.units[${index}]`;
    exactKeys(unit, ["unitName", "unitSourceSha256"], unitDescription);
    return {
      unitName: identifier(unit.unitName, `${unitDescription}.unitName`),
      unitSourceSha256: sha256(unit.unitSourceSha256, `${unitDescription}.unitSourceSha256`),
    };
  });
  for (let index = 1; index < units.length; index += 1) {
    if (units[index - 1].unitName >= units[index].unitName) {
      fail(`${description}.units must be sorted by unique unit name`);
    }
  }
  return {
    path: modulePath(value.path, `${description}.path`),
    sourceSha256: sha256(value.sourceSha256, `${description}.sourceSha256`),
    units,
  };
}

function validateSubstitution(value, description) {
  exactKeys(value, ["exportName", "moduleSpecifier", "unitSourceSha256"], description);
  return {
    exportName: identifier(value.exportName, `${description}.exportName`),
    moduleSpecifier: modulePath(value.moduleSpecifier, `${description}.moduleSpecifier`),
    unitSourceSha256: sha256(value.unitSourceSha256, `${description}.unitSourceSha256`),
  };
}

function validateAdapter(value, index) {
  const description = `adapter ${index}`;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${description} must be an object`);
  }
  const hasSubstitution = Object.hasOwn(value, "substitution");
  exactKeys(
    value,
    ["export", "id", "material", "semantic", ...(hasSubstitution ? ["substitution"] : [])],
    description
  );
  exactKeys(
    value.export,
    ["exportName", "modulePath", "unitSourceSha256"],
    `${description}.export`
  );
  exactKeys(
    value.material,
    ["installedLock", "moduleSourceSha256", "packageJson", "packageLock", "semanticSources"],
    `${description}.material`
  );
  exactKeys(
    value.material.packageJson,
    ["path", "sha256", "version"],
    `${description}.packageJson`
  );
  exactKeys(value.semantic, ["kind"], `${description}.semantic`);
  if (!Array.isArray(value.material.semanticSources)) {
    fail(`${description}.semanticSources must be an array`);
  }
  const semanticKind = string(value.semantic.kind, `${description}.semantic.kind`);
  if (!SEMANTIC_KINDS.has(semanticKind)) {
    fail(`${description}.semantic.kind is unsupported`);
  }
  if ((semanticKind === "functionHandleCreate") !== hasSubstitution) {
    fail(`${description}.substitution must be present only for functionHandleCreate`);
  }
  const semanticSources = value.material.semanticSources.map((source, index) =>
    validateSemanticSource(source, `${description}.semanticSources[${index}]`)
  );
  for (let index = 1; index < semanticSources.length; index += 1) {
    if (semanticSources[index - 1].path >= semanticSources[index].path) {
      fail(`${description}.semanticSources must be sorted by unique path`);
    }
  }
  return {
    export: {
      exportName: identifier(value.export.exportName, `${description}.export.exportName`),
      modulePath: modulePath(value.export.modulePath, `${description}.export.modulePath`),
      unitSourceSha256: sha256(
        value.export.unitSourceSha256,
        `${description}.export.unitSourceSha256`
      ),
    },
    id: identifier(value.id, `${description}.id`),
    material: {
      installedLock: validateLock(value.material.installedLock, `${description}.installedLock`),
      moduleSourceSha256: sha256(
        value.material.moduleSourceSha256,
        `${description}.material.moduleSourceSha256`
      ),
      packageJson: {
        path: modulePath(value.material.packageJson.path, `${description}.packageJson.path`),
        sha256: sha256(value.material.packageJson.sha256, `${description}.packageJson.sha256`),
        version: string(value.material.packageJson.version, `${description}.packageJson.version`),
      },
      packageLock: validateLock(value.material.packageLock, `${description}.packageLock`),
      semanticSources,
    },
    semantic: { kind: semanticKind },
    ...(hasSubstitution
      ? { substitution: validateSubstitution(value.substitution, `${description}.substitution`) }
      : {}),
  };
}

async function currentLockMaterial(repoRoot, expected, description) {
  const contents = await readRepositoryFile(repoRoot, expected.path, description);
  const parsed = JSON.parse(contents.toString("utf8"));
  const entry = parsed.packages?.[expected.packageKey];
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    fail(`${description} has no object packages[${JSON.stringify(expected.packageKey)}] entry`);
  }
  return {
    entrySha256: hashBytes(canonicalJson(entry)),
    packageKey: expected.packageKey,
    path: expected.path,
  };
}

async function currentFileMaterial(repoRoot, path) {
  const contents = await readRepositoryFile(repoRoot, path, `file material ${path}`);
  return { bytes: contents.length, path, sha256: hashBytes(contents) };
}

export async function loadConvexWasmDependencyAdapterMaterial(repoRoot) {
  const normalizedRoot = await realpath(resolve(repoRoot));
  const absolutePath = await realpath(resolve(normalizedRoot, DESCRIPTOR_PATH));
  const relativePath = relative(normalizedRoot, absolutePath).split(sep).join("/");
  if (isAbsolute(relativePath) || relativePath !== DESCRIPTOR_PATH) {
    fail("dependency adapter descriptor path is inconsistent");
  }
  const contents = await readFile(absolutePath);
  const parsed = JSON.parse(contents.toString("utf8"));
  exactKeys(parsed, ["adapters", "kind"], "descriptor");
  if (parsed.kind !== DESCRIPTOR_KIND) fail(`unsupported descriptor kind ${parsed.kind}`);
  if (!Array.isArray(parsed.adapters)) {
    fail("descriptor.adapters must be an array");
  }
  const adapters = parsed.adapters.map(validateAdapter);
  const ids = new Set();
  for (let index = 0; index < adapters.length; index += 1) {
    const adapter = adapters[index];
    if (ids.has(adapter.id)) fail("descriptor adapter IDs must be unique");
    ids.add(adapter.id);
    if (index > 0) {
      const previous = adapters[index - 1];
      const previousKey = `${previous.export.modulePath}\0${previous.export.exportName}`;
      const currentKey = `${adapter.export.modulePath}\0${adapter.export.exportName}`;
      if (previousKey >= currentKey) {
        fail("descriptor adapters must be sorted by unique resolved export identity");
      }
    }
  }
  return {
    current: { files: [], locks: [] },
    descriptor: { adapters, kind: DESCRIPTOR_KIND },
    kind: MATERIAL_KIND,
    source: {
      bytes: contents.length,
      path: relativePath,
      sha256: hashBytes(contents),
    },
  };
}

export async function selectConvexWasmDependencyAdapters(repoRoot, metafile, material) {
  const normalizedRoot = await realpath(resolve(repoRoot));
  const importedExports = new Set();
  const importedSubstitutions = new Set();
  const adapterModulePaths = new Set(
    material.descriptor.adapters.map((adapter) => adapter.export.modulePath)
  );
  const substitutionSpecifiers = new Set(
    material.descriptor.adapters.flatMap((adapter) =>
      adapter.substitution === undefined ? [] : [adapter.substitution.moduleSpecifier]
    )
  );
  const importers = [];
  for (const [inputPath, input] of Object.entries(metafile.inputs)) {
    const resolutionsBySpecifier = new Map();
    for (const imported of input.imports ?? []) {
      if (imported.external || typeof imported.original !== "string") continue;
      const existing = resolutionsBySpecifier.get(imported.original);
      if (existing !== undefined && existing !== imported.path) {
        fail(
          `dependency adapter import ${imported.original} from ${inputPath} has inconsistent emitted resolutions`
        );
      }
      resolutionsBySpecifier.set(imported.original, imported.path);
    }
    if (
      inputPath.startsWith("<") ||
      (![...resolutionsBySpecifier.values()].some((path) => adapterModulePaths.has(path)) &&
        ![...resolutionsBySpecifier.keys()].some((specifier) =>
          substitutionSpecifiers.has(specifier)
        ))
    ) {
      continue;
    }
    importers.push({ inputPath, resolutionsBySpecifier });
  }
  return Promise.all(
    importers.map(async ({ inputPath, resolutionsBySpecifier }) => {
      let ast;
      try {
        const contents = await readRepositoryFile(
          normalizedRoot,
          inputPath,
          `dependency-adapter importer ${inputPath}`
        );
        ast = parseBabelAst(contents.toString("utf8"), {
          plugins: ["jsx", "typescript"],
          sourceType: "module",
        });
      } catch (error) {
        fail(
          `cannot parse emitted dependency-adapter importer ${inputPath}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      for (const statement of ast.program.body) {
        if (statement.type !== "ImportDeclaration") continue;
        const resolved = resolutionsBySpecifier.get(statement.source.value);
        if (resolved === undefined) continue;
        for (const specifier of statement.specifiers) {
          if (specifier.type !== "ImportSpecifier" || specifier.importKind === "type") continue;
          const imported =
            specifier.imported.type === "Identifier"
              ? specifier.imported.name
              : specifier.imported.value;
          importedExports.add(`${resolved}\0${imported}`);
          if (
            substitutionSpecifiers.has(statement.source.value) &&
            /^(?:node_modules\/convex\/server\.js|node_modules\/convex\/dist\/(?:esm|cjs)\/server\/index\.js)$/u.test(
              resolved
            )
          ) {
            importedSubstitutions.add(`${statement.source.value}\0${imported}`);
          }
        }
      }
    })
  ).then(() =>
    material.descriptor.adapters.filter(
      (adapter) =>
        importedExports.has(`${adapter.export.modulePath}\0${adapter.export.exportName}`) ||
        (adapter.substitution !== undefined &&
          importedSubstitutions.has(
            `${adapter.substitution.moduleSpecifier}\0${adapter.substitution.exportName}`
          ))
    )
  );
}

export async function hydrateConvexWasmDependencyAdapterMaterial(repoRoot, material, adapters) {
  const normalizedRoot = await realpath(resolve(repoRoot));
  const filePaths = new Set();
  const locks = new Map();
  for (const adapter of adapters) {
    filePaths.add(adapter.export.modulePath);
    filePaths.add(adapter.material.packageJson.path);
    for (const source of adapter.material.semanticSources) filePaths.add(source.path);
    for (const lock of [adapter.material.packageLock, adapter.material.installedLock]) {
      locks.set(`${lock.path}\0${lock.packageKey}`, lock);
    }
  }
  const files = await Promise.all(
    [...filePaths].sort().map((path) => currentFileMaterial(normalizedRoot, path))
  );
  const currentLocks = await Promise.all(
    [...locks.values()]
      .sort((left, right) =>
        left.path === right.path
          ? compareStrings(left.packageKey, right.packageKey)
          : compareStrings(left.path, right.path)
      )
      .map((lock, index) => currentLockMaterial(normalizedRoot, lock, `lock material ${index}`))
  );
  return { ...material, current: { files, locks: currentLocks } };
}

export function projectConvexWasmActiveDependencyAdapterIdentity(material, adapters) {
  const filePaths = new Set();
  const lockKeys = new Set();
  for (const adapter of adapters) {
    filePaths.add(adapter.export.modulePath);
    filePaths.add(adapter.material.packageJson.path);
    for (const source of adapter.material.semanticSources) filePaths.add(source.path);
    for (const lock of [adapter.material.packageLock, adapter.material.installedLock]) {
      lockKeys.add(`${lock.path}\0${lock.packageKey}`);
    }
  }
  return {
    adapters,
    current: {
      files: material.current.files.filter((file) => filePaths.has(file.path)),
      locks: material.current.locks.filter((lock) =>
        lockKeys.has(`${lock.path}\0${lock.packageKey}`)
      ),
    },
    kind: "convex-wasm-active-dependency-adapters",
  };
}

export const convexWasmDependencyAdapterDescriptorPath = DESCRIPTOR_PATH;
