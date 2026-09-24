import { createHash } from "node:crypto";

import {
  assertPlainObject,
  canonicalJson,
  compareStrings,
  fail,
  fingerprintJson,
  normalizeJson,
  requireEnum,
  requireExactPlainObject,
  requirePositiveInteger,
  requireSha256,
  requireString,
  requireStringArray,
} from "./convex-wasm-artifact-contract.mjs";

export const MODULE_GRAPH_BASE_ROLE = "base";
export const MODULE_GRAPH_LEGACY_SHARED_ROLE = "common";
const MODULE_GRAPH_SHARED_ROLE_PREFIX = "shared-";
export const MODULE_GRAPH_LEAF_ROLE = "leaf";
export const MODULE_GRAPH_SOURCE_PROVENANCE_KIND = "convex-wasm-module-role-source-provenance-v1";

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireNonnegativeSafeInteger(value, description) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${description} must be a nonnegative safe integer`);
  }
  return value;
}

export function moduleGraphSharedRole(shardSha256) {
  return `${MODULE_GRAPH_SHARED_ROLE_PREFIX}${requireSha256(
    shardSha256,
    "module graph shared shard SHA-256"
  )}`;
}

export function moduleGraphSharedShardSha256(role) {
  if (
    typeof role !== "string" ||
    !role.startsWith(MODULE_GRAPH_SHARED_ROLE_PREFIX) ||
    role.length !== MODULE_GRAPH_SHARED_ROLE_PREFIX.length + 64
  ) {
    return undefined;
  }
  const shardSha256 = role.slice(MODULE_GRAPH_SHARED_ROLE_PREFIX.length);
  return SHA256_PATTERN.test(shardSha256) ? shardSha256 : undefined;
}

function isModuleGraphSharedRole(role) {
  return (
    role === MODULE_GRAPH_LEGACY_SHARED_ROLE || moduleGraphSharedShardSha256(role) !== undefined
  );
}

export function moduleGraphRoleClass(role) {
  if (role === MODULE_GRAPH_BASE_ROLE) return MODULE_GRAPH_BASE_ROLE;
  if (role === MODULE_GRAPH_LEAF_ROLE) return MODULE_GRAPH_LEAF_ROLE;
  if (isModuleGraphSharedRole(role)) return "shared";
  fail(`module graph has an unsupported role: ${String(role)}`);
}

export function moduleGraphRoles(modules) {
  return modules.map(({ role }) => role);
}

export function moduleGraphSharedRoles(modules) {
  return modules.slice(1, -1).map(({ role }) => role);
}

export function normalizeModuleGraphRoleSequence(rawModules, description) {
  if (!Array.isArray(rawModules) || rawModules.length < 2) {
    fail(`${description} must contain base, zero or more shared modules, and leaf`);
  }
  const roles = rawModules.map((module, index) => {
    assertPlainObject(module, `${description}[${index}]`);
    return requireString(module.role, `${description}[${index}].role`);
  });
  if (
    roles[0] !== MODULE_GRAPH_BASE_ROLE ||
    roles.at(-1) !== MODULE_GRAPH_LEAF_ROLE ||
    roles.slice(1, -1).some((role) => !isModuleGraphSharedRole(role)) ||
    new Set(roles).size !== roles.length
  ) {
    fail(`${description} must be ordered base, shared modules, then leaf`);
  }
  if (
    roles.includes(MODULE_GRAPH_LEGACY_SHARED_ROLE) &&
    (roles.length !== 3 || roles[1] !== MODULE_GRAPH_LEGACY_SHARED_ROLE)
  ) {
    fail(`${description} may contain legacy common only as its sole shared module`);
  }
  return roles;
}

export function requireModuleGraphAbiFunctionExport(inspection, name, description) {
  const exported = inspection.contract.exports.find((candidate) => candidate.name === name);
  if (exported?.type.kind !== "func" || exported.type.canonical !== "func()->(i32)") {
    fail(`${description} must export ${name} as func()->(i32)`);
  }
}

function normalizeModuleGraphExternalType(value, description) {
  requireExactPlainObject(value, ["canonical", "kind", "sha256"], description);
  const kind = requireEnum(
    value.kind,
    new Set(["func", "global", "memory", "table", "tag"]),
    `${description}.kind`
  );
  const canonical = requireString(value.canonical, `${description}.canonical`);
  const sha256 = requireSha256(value.sha256, `${description}.sha256`);
  if (sha256 !== hashBytes(Buffer.from(canonical))) {
    fail(`${description}.sha256 does not authenticate its canonical type`);
  }
  return { canonical, kind, sha256 };
}

function normalizeModuleGraphExternal(value, imported, index, description) {
  requireExactPlainObject(
    value,
    imported ? ["index", "module", "name", "type"] : ["index", "name", "type"],
    description
  );
  if (value.index !== index) {
    fail(`${description}.index must preserve the exact Wasmtime contract order`);
  }
  return {
    index,
    ...(imported ? { module: requireString(value.module, `${description}.module`) } : {}),
    name: requireString(value.name, `${description}.name`),
    type: normalizeModuleGraphExternalType(value.type, `${description}.type`),
  };
}

function normalizeModuleGraphWeakImport(value, index, description) {
  requireExactPlainObject(value, ["module", "name"], `${description}[${index}]`);
  return {
    module: requireString(value.module, `${description}[${index}].module`),
    name: requireString(value.name, `${description}[${index}].name`),
  };
}

export function normalizeModuleGraphContract(value, role, engineCompatibilitySha256) {
  const description = `${role} module contract`;
  requireExactPlainObject(
    value,
    ["authority", "contractSha256", "dylink", "exports", "imports"],
    description
  );
  requireExactPlainObject(
    value.authority,
    ["engineCompatibilitySha256", "inspectionSha256", "kind"],
    `${description}.authority`
  );
  if (value.authority.kind !== "convex-wasm-wasmtime-module-contract-v1") {
    fail(`${description}.authority.kind is unsupported`);
  }
  const authority = {
    engineCompatibilitySha256: requireSha256(
      value.authority.engineCompatibilitySha256,
      `${description}.authority.engineCompatibilitySha256`
    ),
    inspectionSha256: requireSha256(
      value.authority.inspectionSha256,
      `${description}.authority.inspectionSha256`
    ),
    kind: value.authority.kind,
  };
  if (authority.engineCompatibilitySha256 !== engineCompatibilitySha256) {
    fail(`${description} was inspected under a different Wasmtime engine compatibility identity`);
  }
  requireExactPlainObject(
    value.dylink,
    ["first", "sha256", "weakImports"],
    `${description}.dylink`
  );
  if (value.dylink.first !== true) {
    fail(`${description} must authenticate dylink.0 as the first custom section`);
  }
  if (!Array.isArray(value.dylink.weakImports)) {
    fail(`${description}.dylink.weakImports must be an array`);
  }
  const weakImports = value.dylink.weakImports.map((item, index) =>
    normalizeModuleGraphWeakImport(item, index, `${description}.dylink.weakImports`)
  );
  const weakImportKeys = weakImports.map(({ module, name }) => `${module}\0${name}`);
  if (
    new Set(weakImportKeys).size !== weakImportKeys.length ||
    canonicalJson(weakImports) !==
      canonicalJson(
        [...weakImports].sort((left, right) => {
          const moduleOrder = compareStrings(left.module, right.module);
          return moduleOrder === 0 ? compareStrings(left.name, right.name) : moduleOrder;
        })
      )
  ) {
    fail(`${description}.dylink.weakImports must be sorted and unique`);
  }
  const dylink = {
    first: true,
    sha256: requireSha256(value.dylink.sha256, `${description}.dylink.sha256`),
    weakImports,
  };
  if (!Array.isArray(value.imports) || !Array.isArray(value.exports)) {
    fail(`${description} imports and exports must be arrays`);
  }
  const imports = value.imports.map((item, index) =>
    normalizeModuleGraphExternal(item, true, index, `${description}.imports[${index}]`)
  );
  const exports = value.exports.map((item, index) =>
    normalizeModuleGraphExternal(item, false, index, `${description}.exports[${index}]`)
  );
  if (new Set(exports.map(({ name }) => name)).size !== exports.length) {
    fail(`${description} exports contain duplicate names`);
  }
  const contractPayload = { authority, dylink, exports, imports };
  const contractSha256 = requireSha256(value.contractSha256, `${description}.contractSha256`);
  if (contractSha256 !== fingerprintJson(contractPayload)) {
    fail(`${description}.contractSha256 is invalid`);
  }
  return { ...contractPayload, contractSha256 };
}

function normalizeModuleGraphOwnership(value, role) {
  const description = `${role} module ownership`;
  requireExactPlainObject(value, ["memory", "stackPointer", "table", "tags"], description);
  const expected = moduleGraphRoleClass(role) === MODULE_GRAPH_BASE_ROLE ? "defined" : "base";
  if (value.memory !== expected || value.stackPointer !== expected || value.table !== expected) {
    fail(`${description} does not preserve base-owned memory, table, and stack pointer`);
  }
  const tags = requireStringArray(value.tags, `${description}.tags`);
  if (
    tags.length === 0 ||
    !tags.includes("__c_longjmp") ||
    new Set(tags).size !== tags.length ||
    canonicalJson(tags) !== canonicalJson([...tags].sort(compareStrings))
  ) {
    fail(`${description}.tags must be a sorted unique shared tag set containing __c_longjmp`);
  }
  return { memory: expected, stackPointer: expected, table: expected, tags };
}

function normalizeModuleGraphLayout(value, role) {
  const description = `${role} module layout`;
  requireExactPlainObject(
    value,
    ["memoryAlign", "memoryBase", "memorySize", "tableAlign", "tableBase", "tableSize"],
    description
  );
  const layout = Object.fromEntries(
    ["memoryAlign", "memoryBase", "memorySize", "tableAlign", "tableBase", "tableSize"].map(
      (field) => [field, requireNonnegativeSafeInteger(value[field], `${description}.${field}`)]
    )
  );
  if (layout.memoryAlign > 31 || layout.tableAlign > 31) {
    fail(`${description} alignment exponents must be at most 31`);
  }
  if (
    moduleGraphRoleClass(role) === MODULE_GRAPH_BASE_ROLE &&
    (layout.memoryBase !== 0 ||
      layout.tableBase !== 0 ||
      layout.memorySize !== 0 ||
      layout.tableSize !== 0)
  ) {
    fail("base module layout must use zero relocation bases and side-module reservations");
  }
  return layout;
}

function normalizeModuleGraphProvider(value, role, index, roles) {
  const description = `${role} module provider ${index}`;
  requireExactPlainObject(
    value,
    [
      "consumer",
      "importIndex",
      "importedModule",
      "importedName",
      "provider",
      "providerExport",
      "typeSha256",
      "weak",
    ],
    description
  );
  if (value.consumer !== role || value.importIndex !== index) {
    fail(`${description} does not preserve the exact ordered consumer import`);
  }
  const provider = requireString(value.provider, `${description}.provider`);
  if (!new Set([...roles, "host", "loader", "weak-zero"]).has(provider)) {
    fail(`${description}.provider is unsupported`);
  }
  if (typeof value.weak !== "boolean") {
    fail(`${description}.weak must be a boolean`);
  }
  if (value.providerExport !== null && typeof value.providerExport !== "string") {
    fail(`${description}.providerExport must be a string or null`);
  }
  return {
    consumer: role,
    importIndex: index,
    importedModule: requireString(value.importedModule, `${description}.importedModule`),
    importedName: requireString(value.importedName, `${description}.importedName`),
    provider,
    providerExport:
      value.providerExport === null
        ? null
        : requireString(value.providerExport, `${description}.providerExport`),
    typeSha256: requireSha256(value.typeSha256, `${description}.typeSha256`),
    weak: value.weak,
  };
}

function normalizeModuleGraphSourceProvenance(value, role) {
  const description = `${role} module source provenance`;
  requireExactPlainObject(value, ["kind", "payload", "sha256"], description);
  if (value.kind !== MODULE_GRAPH_SOURCE_PROVENANCE_KIND) {
    fail(`${description}.kind is unsupported`);
  }
  const payload = normalizeJson(value.payload, `${description}.payload`);
  const sha256 = requireSha256(value.sha256, `${description}.sha256`);
  if (sha256 !== fingerprintJson({ kind: value.kind, payload })) {
    fail(`${description}.sha256 is invalid`);
  }
  return { kind: value.kind, payload, sha256 };
}

function normalizeModuleGraphCoreWasmInput(value, role) {
  const description = `${role} module Core Wasm input`;
  requireExactPlainObject(value, ["sha256", "size"], description);
  return {
    sha256: requireSha256(value.sha256, `${description}.sha256`),
    size: requirePositiveInteger(value.size, `${description}.size`),
  };
}

export function normalizeModuleGraphCoreWasmInputs(value, roles) {
  requireExactPlainObject(value, roles, "module graph Core Wasm inputs");
  return Object.fromEntries(
    roles.map((role) => [role, normalizeModuleGraphCoreWasmInput(value[role], role)])
  );
}

function normalizeModuleGraphLinkIdentity(value, role) {
  const description = `${role} module link identity`;
  requireExactPlainObject(value, ["flags", "kind"], description);
  const expectedKind = moduleGraphRoleClass(role) === MODULE_GRAPH_BASE_ROLE ? "main" : "side";
  if (value.kind !== expectedKind) {
    fail(`${description}.kind must be ${expectedKind}`);
  }
  const flags = requireStringArray(value.flags, `${description}.flags`);
  const requiredFlag =
    moduleGraphRoleClass(role) === MODULE_GRAPH_BASE_ROLE ? "-sMAIN_MODULE=2" : "-sSIDE_MODULE=2";
  if (!flags.includes(requiredFlag)) {
    fail(`${description}.flags must contain ${requiredFlag}`);
  }
  return { flags, kind: expectedKind };
}

function normalizeModuleGraphObjectCompilation(value, role) {
  const description = `${role} module object compilation`;
  requireExactPlainObject(value, ["flags", "kind"], description);
  const expectedKind =
    moduleGraphRoleClass(role) === MODULE_GRAPH_BASE_ROLE
      ? "main-module-object"
      : "side-module-object";
  if (value.kind !== expectedKind) {
    fail(`${description}.kind must be ${expectedKind}`);
  }
  const flags = requireStringArray(value.flags, `${description}.flags`);
  if (moduleGraphRoleClass(role) !== MODULE_GRAPH_BASE_ROLE && !flags.includes("-fPIC")) {
    fail(`${description}.flags must authenticate PIC side-module objects`);
  }
  return { flags, kind: expectedKind };
}

export function normalizeModuleGraphModule(value, role, roles, engineCompatibilitySha256) {
  const description = `${role} module`;
  const sharedShardSha256 = moduleGraphSharedShardSha256(role);
  requireExactPlainObject(
    value,
    sharedShardSha256 === undefined
      ? [
          "contract",
          "layout",
          "link",
          "objectCompilation",
          "ownership",
          "providers",
          "role",
          "sourceProvenance",
        ]
      : [
          "contract",
          "layout",
          "link",
          "objectCompilation",
          "ownership",
          "providers",
          "role",
          "sharedShardSha256",
          "sourceProvenance",
        ],
    description
  );
  if (value.role !== role) {
    fail(`module graph roles must be ordered ${roles.join(", ")}`);
  }
  if (
    (sharedShardSha256 === undefined && Object.hasOwn(value, "sharedShardSha256")) ||
    (sharedShardSha256 !== undefined && value.sharedShardSha256 !== sharedShardSha256)
  ) {
    fail(`${description} shared shard identity does not match its content-addressed role`);
  }
  const contract = normalizeModuleGraphContract(value.contract, role, engineCompatibilitySha256);
  if (!Array.isArray(value.providers) || value.providers.length !== contract.imports.length) {
    fail(`${description}.providers must resolve every exact contract import once`);
  }
  return {
    contract,
    layout: normalizeModuleGraphLayout(value.layout, role),
    link: normalizeModuleGraphLinkIdentity(value.link, role),
    objectCompilation: normalizeModuleGraphObjectCompilation(value.objectCompilation, role),
    ownership: normalizeModuleGraphOwnership(value.ownership, role),
    providers: value.providers.map((provider, index) =>
      normalizeModuleGraphProvider(provider, role, index, roles)
    ),
    role,
    ...(sharedShardSha256 === undefined ? {} : { sharedShardSha256 }),
    sourceProvenance: normalizeModuleGraphSourceProvenance(value.sourceProvenance, role),
  };
}

export function normalizeModuleGraphHostAbi(value) {
  const description = "module graph host ABI";
  requireExactPlainObject(value, ["imports", "kind", "sha256"], description);
  if (value.kind !== "convex-wasm-module-graph-host-abi-v1") {
    fail(`${description}.kind is unsupported`);
  }
  if (!Array.isArray(value.imports)) {
    fail(`${description}.imports must be an array`);
  }
  const imports = value.imports
    .map((imported, index) => {
      const importDescription = `${description}.imports[${index}]`;
      requireExactPlainObject(imported, ["module", "name", "typeSha256"], importDescription);
      return {
        module: requireString(imported.module, `${importDescription}.module`),
        name: requireString(imported.name, `${importDescription}.name`),
        typeSha256: requireSha256(imported.typeSha256, `${importDescription}.typeSha256`),
      };
    })
    .sort((left, right) => {
      const moduleOrder = compareStrings(left.module, right.module);
      return moduleOrder === 0 ? compareStrings(left.name, right.name) : moduleOrder;
    });
  const keys = imports.map(({ module, name }) => `${module}\0${name}`);
  if (new Set(keys).size !== keys.length) {
    fail(`${description}.imports contain duplicate module/name pairs`);
  }
  const sha256 = requireSha256(value.sha256, `${description}.sha256`);
  if (sha256 !== fingerprintJson({ imports, kind: value.kind })) {
    fail(`${description}.sha256 is invalid`);
  }
  return { imports, kind: value.kind, sha256 };
}

export function validateModuleGraphProviders(modules, hostAbi) {
  const roles = moduleGraphRoles(modules);
  const roleIndex = new Map(roles.map((role, index) => [role, index]));
  const exportsByRole = new Map(
    modules.map((module) => [
      module.role,
      new Map(module.contract.exports.map((exported) => [exported.name, exported])),
    ])
  );
  for (const module of modules) {
    const consumerIndex = roleIndex.get(module.role);
    module.providers.forEach((resolution, index) => {
      const imported = module.contract.imports[index];
      if (
        resolution.importedModule !== imported.module ||
        resolution.importedName !== imported.name ||
        resolution.typeSha256 !== imported.type.sha256
      ) {
        fail(`${module.role} module provider ${index} disagrees with its exact import contract`);
      }
      if (resolution.provider === "host") {
        if (
          module.role !== MODULE_GRAPH_BASE_ROLE ||
          resolution.providerExport !== null ||
          resolution.weak
        ) {
          fail("only base-module imports may bind the bounded host ABI");
        }
        const allowed = hostAbi.imports.find(
          (candidate) => candidate.module === imported.module && candidate.name === imported.name
        );
        if (allowed === undefined || allowed.typeSha256 !== imported.type.sha256) {
          fail(`base module provider ${index} is outside the authenticated closed host ABI`);
        }
        return;
      }
      if (resolution.provider === "loader") {
        if (
          module.role === MODULE_GRAPH_BASE_ROLE ||
          imported.module !== "env" ||
          !new Set(["__memory_base", "__table_base"]).has(imported.name) ||
          imported.type.canonical !== "global(i32,const)" ||
          resolution.providerExport !== null ||
          resolution.weak
        ) {
          fail(`${module.role} module provider ${index} has an invalid relocation-base binding`);
        }
        return;
      }
      if (resolution.provider === "weak-zero") {
        const declaredWeak = module.contract.dylink.weakImports.some(
          (candidate) => candidate.module === imported.module && candidate.name === imported.name
        );
        if (
          module.role === MODULE_GRAPH_BASE_ROLE ||
          resolution.providerExport !== null ||
          !resolution.weak ||
          !new Set(["GOT.func", "GOT.mem"]).has(imported.module) ||
          imported.type.canonical !== "global(i32,var)" ||
          !declaredWeak
        ) {
          fail(`${module.role} module provider ${index} has an unsupported weak-zero binding`);
        }
        return;
      }
      const providerIndex = roleIndex.get(resolution.provider);
      const selfGot =
        providerIndex === consumerIndex && new Set(["GOT.func", "GOT.mem"]).has(imported.module);
      if (providerIndex > consumerIndex || (providerIndex === consumerIndex && !selfGot)) {
        fail(`${module.role} module provider ${index} creates a later-module dependency`);
      }
      if (resolution.providerExport === null || resolution.weak) {
        fail(`${module.role} module provider ${index} has an invalid exact provider binding`);
      }
      const exported = exportsByRole.get(resolution.provider).get(resolution.providerExport);
      const direct = exported?.type.sha256 === imported.type.sha256;
      const gotFunction =
        imported.module === "GOT.func" &&
        imported.type.canonical === "global(i32,var)" &&
        exported?.type.kind === "func";
      const gotMemory =
        imported.module === "GOT.mem" &&
        imported.type.canonical === "global(i32,var)" &&
        exported?.type.kind === "global" &&
        exported.type.canonical.startsWith("global(i32,");
      const baseResource =
        resolution.provider === "base" &&
        imported.module === "env" &&
        new Set(["memory", "__indirect_function_table"]).has(imported.name) &&
        exported?.type.kind === imported.type.kind;
      if (exported === undefined || (!direct && !gotFunction && !gotMemory && !baseResource)) {
        fail(`${module.role} module provider ${index} does not match its provider export type`);
      }
    });
    // dylink.0 records linker weak-symbol metadata, not only live Core Wasm imports. A weak
    // symbol may resolve to a concrete provider, or the final link may remove its import.
    // The weak-zero fallback above is the only binding that requires matching dylink evidence.
  }
}
