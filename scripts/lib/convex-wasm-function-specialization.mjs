import { createHash } from "node:crypto";
import { promises as fs, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, posix } from "node:path";
import { parse } from "@babel/parser";
import traverseModule from "@babel/traverse";
import { z } from "zod";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";
import { decodeUtf8, mapBounded } from "./convex-wasm-artifact-material.mjs";
import { ensureArtifactStage } from "./convex-wasm-artifact-stage.mjs";

const traverse = traverseModule.default;
const require = createRequire(import.meta.url);
const summaries = new WeakMap();
const maximumBodyNodes = 180;
const maximumBodyBytes = 4096;
const maximumImportedBodies = 32;
const maximumImportedBytes = 32 * 1024;
const summaryStage = "official-output-function-summary";
const summaryKind = "convex-wasm-function-summary-v2";

function hash(source) {
  return createHash("sha256").update(source).digest("hex");
}

// Traversal's binding predicates also depend on its resolved helpers/types.
// A downstream install can resolve different transitive versions even when
// the two direct Babel dependencies remain pinned.
function analysisDependencyVersions() {
  const visited = new Set();
  const versions = new Set();
  const pending = ["@babel/parser", "@babel/traverse"].map((name) => ({
    name,
    resolveFrom: require,
  }));
  while (pending.length > 0) {
    const { name, resolveFrom } = pending.pop();
    const path = resolveFrom.resolve(`${name}/package.json`);
    if (visited.has(path)) continue;
    visited.add(path);
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    versions.add(`${manifest.name}@${manifest.version}`);
    const childRequire = createRequire(path);
    for (const dependency of Object.keys(manifest.dependencies ?? {}))
      pending.push({ name: dependency, resolveFrom: childRequire });
  }
  return Object.freeze([...versions].sort());
}

export const convexWasmFunctionSpecializationIdentity = Object.freeze({
  kind: "convex-wasm-function-specialization-v1",
  sourceSha256: hash(readFileSync(new URL(import.meta.url))),
  parserVersion: require("@babel/parser/package.json").version,
  traversalVersion: require("@babel/traverse/package.json").version,
  analysisDependencies: analysisDependencyVersions(),
});

const rangeSchema = z
  .object({ start: z.int().nonnegative(), end: z.int().positive() })
  .strict()
  .refine(({ start, end }) => end > start);
const helperSchema = z
  .object({
    name: z.string(),
    parameters: z.string(),
    body: z.string(),
    nodes: z.int().positive().max(maximumBodyNodes),
    fieldReads: z.int().nonnegative(),
    bytes: z.int().positive().max(maximumBodyBytes),
  })
  .strict()
  .refine(
    ({ parameters, body, bytes }) =>
      bytes === Buffer.byteLength(parameters) + Buffer.byteLength(body)
  );
const bodySchema = z
  .object({
    parameters: z.string(),
    body: z.string(),
    helpers: z.array(helperSchema).max(maximumImportedBodies - 1),
    globals: z.array(z.string()),
    nodes: z.int().positive().max(maximumBodyNodes),
    fieldReads: z.int().nonnegative(),
    bytes: z.int().positive().max(maximumBodyBytes),
    sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  })
  .strict()
  .refine(
    ({ parameters, body, helpers, globals, bytes, sha256 }) =>
      bytes ===
        Buffer.byteLength(parameters) +
          Buffer.byteLength(body) +
          helpers.reduce((sum, helper) => sum + helper.bytes, 0) &&
      sha256 === hash(canonicalJson({ parameters, body, helpers, globals }))
  );
const summarySchema = z
  .object({
    kind: z.literal(summaryKind),
    names: z.array(z.string()),
    bindings: z.array(z.string()),
    bindingFacts: z
      .object({
        opaque: z.boolean(),
        dependencies: z.array(z.string()),
        immutable: z.array(z.string()),
        imports: z.array(
          z
            .object({
              start: z.int().nonnegative(),
              specifier: z.string(),
              names: z.array(z.string()),
            })
            .strict()
        ),
      })
      .strict(),
    exports: z.array(z.object({ name: z.string(), body: bodySchema }).strict()),
    imports: z.array(
      z
        .object({
          start: z.int().nonnegative(),
          specifier: z.string(),
          bindings: z.array(
            z
              .object({
                imported: z.string(),
                local: z.string(),
                freshObjectFields: z.int().nonnegative(),
                calls: z.array(rangeSchema),
              })
              .strict()
          ),
        })
        .strict()
    ),
  })
  .strict();

function analyzeModule(source) {
  let ast;
  try {
    ast = parse(source, {
      plugins: ["importAttributes"],
      sourceType: "module",
    });
  } catch (error) {
    throw new Error("Convex Wasm official-output module source is not parseable", { cause: error });
  }
  const names = new Set();
  const exports = [];
  const imports = [];
  const analyzedBodies = new Map();
  const declarations = new Map();
  const writes = new Set();
  const dependencies = new Set();
  const initialized = new Set();
  const exportedBindings = new Map();
  let opaque = false;
  let program;
  const writtenPattern = (node) => {
    if (node?.type === "Identifier") writes.add(node.name);
    else if (node?.type === "AssignmentPattern") writtenPattern(node.left);
    else if (node?.type === "RestElement") writtenPattern(node.argument);
    else if (node?.type === "ArrayPattern") node.elements.forEach(writtenPattern);
    else if (node?.type === "ObjectPattern")
      node.properties.forEach((property) =>
        writtenPattern(property.type === "RestElement" ? property.argument : property.value)
      );
  };
  traverse(ast, {
    Program(path) {
      program = path;
    },
    Identifier(path) {
      names.add(path.node.name);
      if (["eval", "module", "require"].includes(path.node.name)) opaque = true;
    },
    AssignmentExpression(path) {
      writtenPattern(path.node.left);
    },
    UpdateExpression(path) {
      writtenPattern(path.node.argument);
    },
    "ForInStatement|ForOfStatement"(path) {
      writtenPattern(path.node.left);
    },
    "VariableDeclarator|FunctionDeclaration|ClassDeclaration"(path) {
      const id = path.node.id;
      if (id?.type === "Identifier")
        declarations.set(id.name, (declarations.get(id.name) ?? 0) + 1);
    },
    "ImportDeclaration|ExportNamedDeclaration|ExportAllDeclaration"(path) {
      if (path.node.source) dependencies.add(path.node.source.value);
    },
    "CallExpression|ImportExpression"(path) {
      const node = path.node;
      const dynamicImport = node.type === "ImportExpression" || node.callee?.type === "Import";
      if (!dynamicImport && !(node.callee?.type === "Identifier" && node.callee.name === "require"))
        return;
      const literal = node.type === "ImportExpression" ? node.source : node.arguments[0];
      if (literal?.type !== "StringLiteral" || (node.arguments && node.arguments.length !== 1))
        opaque = true;
      else dependencies.add(literal.value);
    },
  });

  const analyzing = new Set();
  const bodyFor = (binding, anonymousDefault) => {
    const declaration = binding?.path;
    const fn =
      anonymousDefault ??
      (declaration?.isVariableDeclarator() ? declaration.get("init") : declaration);
    if (
      !fn?.isFunction() ||
      fn.node.async ||
      fn.node.generator ||
      (binding !== undefined && !binding.constant)
    )
      return undefined;
    if (analyzedBodies.has(fn.node)) return analyzedBodies.get(fn.node);
    // Recursive dependency groups remain ordinary calls. Bound the analysis
    // before traversing source, independently of the emitted-body budget.
    if (analyzing.has(fn.node) || analyzing.size >= 8) return undefined;
    analyzing.add(fn.node);
    let eligible = true;
    let nodes = 1;
    let fieldReads = 0;
    const globals = new Set();
    const dependencies = new Map();
    fn.traverse({
      enter(path) {
        ++nodes;
        if (nodes > maximumBodyNodes) {
          eligible = false;
          path.stop();
        }
      },
      "ThisExpression|Super|MetaProperty|ImportExpression|TaggedTemplateExpression"(path) {
        eligible = false;
        path.stop();
      },
      CallExpression(path) {
        if (path.node.callee.type === "Import") {
          eligible = false;
          path.stop();
        }
      },
      Identifier(path) {
        if (
          path.node === fn.node.id ||
          (!path.isReferencedIdentifier() && !path.isBindingIdentifier())
        )
          return;
        const referenced = path.scope.getBinding(path.node.name);
        const node = referenced?.path.node;
        if ((binding !== undefined && referenced === binding) || node === fn.node) {
          eligible = false;
          path.stop();
          return;
        }
        if (node !== undefined && node.start >= fn.node.start && node.end <= fn.node.end) return;
        if (node === undefined) {
          // Preserve dynamic global reads, including replaced constructors.
          // The importer must not shadow them. Wrapper-local names and implicit
          // arguments cannot be transported as realm-global references.
          if (
            !path.isReferencedIdentifier() ||
            path.isBindingIdentifier() ||
            ["arguments", "eval", "module", "require", "exports", "globalThis"].includes(
              path.node.name
            ) ||
            path.node.name.startsWith("__convex")
          ) {
            eligible = false;
            path.stop();
          } else globals.add(path.node.name);
          return;
        }
        const call = path.parentPath;
        if (
          referenced.scope !== program.scope ||
          !referenced.path.isFunctionDeclaration() ||
          !referenced.constant ||
          declarations.get(path.node.name) !== 1 ||
          writes.has(path.node.name) ||
          !call.isCallExpression() ||
          call.node.optional ||
          call.node.callee !== path.node
        ) {
          eligible = false;
          path.stop();
          return;
        }
        dependencies.set(path.node.name, referenced);
      },
      "MemberExpression|OptionalMemberExpression"() {
        ++fieldReads;
      },
    });
    const helpers = new Map();
    if (eligible) {
      for (const [name, dependency] of dependencies) {
        const closed = bodyFor(dependency);
        if (closed === undefined) {
          eligible = false;
          break;
        }
        closed.helpers.forEach((helper) => helpers.set(helper.name, helper));
        helpers.set(name, {
          name,
          parameters: closed.parameters,
          body: closed.body,
          nodes: closed.nodes - closed.helpers.reduce((sum, helper) => sum + helper.nodes, 0),
          fieldReads:
            closed.fieldReads - closed.helpers.reduce((sum, helper) => sum + helper.fieldReads, 0),
          bytes: Buffer.byteLength(closed.parameters) + Buffer.byteLength(closed.body),
        });
        closed.globals.forEach((name) => globals.add(name));
      }
    }
    let body;
    if (eligible) {
      const parameters = fn.node.params.map((p) => source.slice(p.start, p.end)).join(", ");
      const originalBody = source.slice(fn.node.body.start, fn.node.body.end);
      const text =
        fn.node.body.type === "BlockStatement" ? originalBody : `{ return (${originalBody}); }`;
      const helperList = [...helpers.values()].sort((a, b) => a.name.localeCompare(b.name, "en"));
      const bytes =
        Buffer.byteLength(parameters) +
        Buffer.byteLength(text) +
        helperList.reduce((sum, helper) => sum + helper.bytes, 0);
      nodes += helperList.reduce((sum, helper) => sum + helper.nodes, 0);
      fieldReads += helperList.reduce((sum, helper) => sum + helper.fieldReads, 0);
      const material = {
        parameters,
        body: text,
        helpers: helperList,
        globals: [...globals].sort(),
      };
      if (
        bytes <= maximumBodyBytes &&
        nodes <= maximumBodyNodes &&
        helpers.size < maximumImportedBodies
      )
        body = { ...material, nodes, fieldReads, bytes, sha256: hash(canonicalJson(material)) };
    }
    analyzing.delete(fn.node);
    analyzedBodies.set(fn.node, body);
    return body;
  };

  const exported = (name, local) => {
    const body = bodyFor(program.scope.getBinding(local));
    if (body !== undefined) exports.push({ name, body });
  };
  for (const statement of program.get("body")) {
    const declaration =
      statement.isExportNamedDeclaration() || statement.isExportDefaultDeclaration()
        ? statement.node.declaration
        : statement.node;
    if (declaration?.type === "VariableDeclaration") {
      for (const item of declaration.declarations)
        if (item.id.type === "Identifier" && item.init !== null) initialized.add(item.id.name);
    } else if (
      ["FunctionDeclaration", "ClassDeclaration"].includes(declaration?.type) &&
      declaration.id !== null
    )
      initialized.add(declaration.id.name);
    if (statement.isExportNamedDeclaration() && statement.node.source === null) {
      if (declaration?.type === "VariableDeclaration") {
        for (const item of declaration.declarations)
          if (item.id.type === "Identifier") exportedBindings.set(item.id.name, item.id.name);
      } else if (declaration?.id?.type === "Identifier")
        exportedBindings.set(declaration.id.name, declaration.id.name);
      for (const specifier of statement.node.specifiers)
        if (specifier.type === "ExportSpecifier")
          exportedBindings.set(
            specifier.exported.name ?? specifier.exported.value,
            specifier.local.name
          );
    } else if (statement.isExportDefaultDeclaration()) {
      // Expression defaults capture their value; named declarations retain a binding.
      exportedBindings.set(
        "default",
        ["FunctionDeclaration", "ClassDeclaration"].includes(declaration.type) &&
          declaration.id !== null
          ? declaration.id.name
          : null
      );
    }
    if (statement.isImportDeclaration()) {
      const bindings = [];
      for (const specifier of statement.get("specifiers")) {
        if (specifier.isImportNamespaceSpecifier()) continue;
        const local = specifier.node.local.name;
        const binding = program.scope.getBinding(local);
        if (!binding.constant) continue;
        let freshObjectFields = 0;
        const calls = binding.referencePaths.flatMap((reference) => {
          const call = reference.parentPath;
          // Values used as callbacks, constructors, tagged templates or method
          // receivers retain the original closure and its observable identity.
          if (!call.isCallExpression() || call.node.optional || call.node.callee !== reference.node)
            return [];
          for (const argument of call.node.arguments)
            if (argument.type === "ObjectExpression")
              freshObjectFields += argument.properties.filter(
                (property) => property.type === "ObjectProperty" && !property.computed
              ).length;
          return [{ start: reference.node.start, end: reference.node.end }];
        });
        bindings.push({
          imported: specifier.isImportDefaultSpecifier()
            ? "default"
            : (specifier.node.imported.name ?? specifier.node.imported.value),
          local,
          freshObjectFields,
          calls,
        });
      }
      imports.push({
        start: statement.node.source.start,
        specifier: statement.node.source.value,
        bindings,
      });
    } else if (statement.isExportNamedDeclaration() && statement.node.source === null) {
      const declaration = statement.get("declaration");
      if (declaration.isFunctionDeclaration())
        exported(declaration.node.id.name, declaration.node.id.name);
      else if (declaration.isVariableDeclaration()) {
        for (const item of declaration.node.declarations)
          if (item.id.type === "Identifier") exported(item.id.name, item.id.name);
      }
      for (const specifier of statement.node.specifiers) {
        if (specifier.type === "ExportSpecifier")
          exported(specifier.exported.name ?? specifier.exported.value, specifier.local.name);
      }
    } else if (statement.isExportDefaultDeclaration()) {
      const declaration = statement.get("declaration");
      if (declaration.isIdentifier()) exported("default", declaration.node.name);
      else if (declaration.isFunction()) {
        const binding =
          declaration.node.id === null || declaration.node.id === undefined
            ? undefined
            : program.scope.getBinding(declaration.node.id.name);
        const body = bodyFor(binding, declaration);
        if (body !== undefined) exports.push({ name: "default", body });
      }
    }
  }
  const immutable = opaque
    ? []
    : [...exportedBindings]
        .filter(
          ([, local]) =>
            local === null ||
            (initialized.has(local) && declarations.get(local) === 1 && !writes.has(local))
        )
        .map(([name]) => name);
  return {
    kind: summaryKind,
    names: [...names].sort(),
    bindings: Object.keys(program.scope.bindings).sort(),
    exports,
    imports,
    bindingFacts: {
      opaque,
      dependencies: [...dependencies],
      immutable,
      imports: ast.program.body
        .filter((node) => node.type === "ImportDeclaration")
        .map((node) => ({
          start: node.source.start,
          specifier: node.source.value,
          names: node.specifiers.flatMap((specifier) =>
            specifier.type === "ImportSpecifier"
              ? [specifier.imported.name ?? specifier.imported.value]
              : specifier.type === "ImportDefaultSpecifier"
                ? ["default"]
                : []
          ),
        })),
    },
  };
}

export function convexWasmModuleSummary(module) {
  let summary = summaries.get(module);
  if (summary === undefined) {
    summary = analyzeModule(module.source);
    summaries.set(module, summary);
  }
  return summary;
}

// Persist source-local proofs independently of graph slots and dependency
// contents. A fresh build can reuse these computations after unrelated edits.
export async function prepareConvexWasmFunctionSpecialization(modules, persistentCache) {
  const report = { memoryHits: 0, cacheHits: 0, cacheMisses: 0 };
  await mapBounded(modules, 4, async (module) => {
    if (summaries.has(module)) {
      ++report.memoryHits;
      return;
    }
    if (persistentCache === undefined) {
      convexWasmModuleSummary(module);
      ++report.cacheMisses;
      return;
    }
    const identity = {
      implementation: convexWasmFunctionSpecializationIdentity,
      sourceSha256: hash(module.source),
    };
    const cached = await ensureArtifactStage({
      build: async (workPath) => {
        const outputPath = join(workPath, "summary.json");
        await fs.writeFile(outputPath, `${canonicalJson(analyzeModule(module.source))}\n`, {
          flag: "wx",
          mode: 0o600,
        });
        return { metadata: null, outputPath, timing: null };
      },
      cacheLayout: persistentCache.cacheLayout,
      cacheRoot: persistentCache.cacheRoot,
      extension: "json",
      identity,
      maxArtifactBytes: 16 * 1024 * 1024,
      readCachedArtifactContents: true,
      readPublishedArtifactContents: true,
      stage: summaryStage,
    });
    if (!Buffer.isBuffer(cached.entry.artifactContents))
      throw new Error("Function summary cache lacks authenticated bytes");
    const source = decodeUtf8(cached.entry.artifactContents, "function summary");
    const summary = summarySchema.parse(JSON.parse(source));
    if (`${canonicalJson(summary)}\n` !== source)
      throw new Error("Function summary cache is not canonical");
    summaries.set(module, summary);
    if (cached.report.cache === "hit") ++report.cacheHits;
    else ++report.cacheMisses;
  });
  return report;
}

export function planConvexWasmFunctionImports(module, modulesByPath, immutableImports) {
  const summary = convexWasmModuleSummary(module);
  const allowed = new Map(immutableImports.map(({ start, names }) => [start, new Set(names)]));
  const names = new Set(summary.names);
  const bodies = new Map();
  const calls = [];
  let bytes = 0;
  let bodyCount = 0;
  const bindings = new Set(summary.bindings);
  let rejectedBindings = 0;
  const candidates = [];
  for (const imported of summary.imports) {
    const immutable = allowed.get(imported.start);
    if (immutable === undefined) continue;
    const targetPath = posix.normalize(
      posix.join(posix.dirname(module.identity.path), imported.specifier)
    );
    const target = modulesByPath.get(targetPath);
    if (target === undefined) throw new Error("Function import has no authenticated dependency");
    const exports = new Map(
      convexWasmModuleSummary(target).exports.map((entry) => [entry.name, entry.body])
    );
    for (const binding of imported.bindings) {
      if (!immutable.has(binding.imported) || binding.calls.length === 0) continue;
      const body = exports.get(binding.imported);
      if (body === undefined || body.globals.some((name) => bindings.has(name))) {
        ++rejectedBindings;
        continue;
      }
      candidates.push({
        binding,
        body,
        freshFields: Math.min(binding.freshObjectFields, body.fieldReads * binding.calls.length),
        readDensity: (body.fieldReads * binding.calls.length) / body.nodes,
      });
    }
  }
  // Import order is unrelated to removable work. Prefer fresh argument fields,
  // then repeatedly exposed field reads within the same bounded code budget.
  // These are profitability hints; Hermes still proves inlining and escape.
  candidates.sort((a, b) => b.freshFields - a.freshFields || b.readDensity - a.readDensity);
  for (const { binding, body } of candidates) {
    let selected = bodies.get(body.sha256);
    if (selected === undefined) {
      if (
        bodyCount + 1 + body.helpers.length > maximumImportedBodies ||
        bytes + body.bytes > maximumImportedBytes
      ) {
        ++rejectedBindings;
        continue;
      }
      let suffix = bodies.size;
      let name;
      do {
        name = `__convexImportedBody${suffix++}`;
      } while (names.has(name));
      names.add(name);
      selected = { ...body, name };
      bodies.set(body.sha256, selected);
      bytes += body.bytes;
      bodyCount += 1 + body.helpers.length;
    }
    for (const call of binding.calls) calls.push({ ...call, name: selected.name });
  }
  return { bodies: [...bodies.values()], calls, rejectedBindings };
}

export function renderConvexWasmSpecializedModuleSource(source, dependencies, plan) {
  const edits = [
    ...dependencies.map(({ start, end, executableSpecifier }) => ({
      start,
      end,
      text: JSON.stringify(executableSpecifier),
    })),
    ...plan.calls.map(({ start, end, name }) => ({ start, end, text: name })),
  ].sort((a, b) => b.start - a.start);
  let previous = source.length;
  for (const edit of edits) {
    if (edit.start < 0 || edit.end <= edit.start || edit.end > previous)
      throw new Error("Function specialization has overlapping or invalid source edits");
    source = source.slice(0, edit.start) + edit.text + source.slice(edit.end);
    previous = edit.start;
  }
  // Transport source-map trailers are not executable material. Original source
  // and map identities remain independently authenticated by the caller.
  source = source.replace(/(^|\n)\/\/# sourceMappingURL=[^\n]*\n?$/u, "$1");
  const factories = [];
  for (const { name, parameters, body, helpers } of plan.bodies) {
    if (helpers.length === 0) {
      source += `\nfunction ${name}(${parameters}) ${body}\n`;
    } else {
      // A private lexical scope preserves helper references without capturing
      // importer locals or exposing new exports. Initialization creates only
      // functions; dependencies still evaluate through the original imports.
      // Place it before executable importer statements, including early calls.
      factories.push(`const ${name} = (() => {\n${helpers
        .map((helper) => `function ${helper.name}(${helper.parameters}) ${helper.body}\n`)
        .join("")}
return function(${parameters}) ${body};\n})();\n`);
    }
  }
  if (factories.length > 0) {
    const ast = parse(source, { plugins: ["importAttributes"], sourceType: "module" });
    const firstBody = ast.program.body.find((statement) => statement.type !== "ImportDeclaration");
    const start = firstBody === undefined ? source.length : firstBody.start;
    source = source.slice(0, start) + factories.join("") + source.slice(start);
  }
  return source;
}
