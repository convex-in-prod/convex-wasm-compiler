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
const summaryKind = "convex-wasm-function-summary-v1";

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
const bodySchema = z
  .object({
    parameters: z.string(),
    body: z.string(),
    nodes: z.int().positive().max(maximumBodyNodes),
    fieldReads: z.int().nonnegative(),
    bytes: z.int().positive().max(maximumBodyBytes),
    sha256: z.string().regex(/^[0-9a-f]{64}$/u),
  })
  .strict()
  .refine(
    ({ parameters, body, bytes, sha256 }) =>
      bytes === Buffer.byteLength(parameters) + Buffer.byteLength(body) &&
      sha256 === hash(canonicalJson({ parameters, body }))
  );
const summarySchema = z
  .object({
    kind: z.literal(summaryKind),
    names: z.array(z.string()),
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
    // A copied body may only see its own parameters/locals. Even a read-only
    // module binding can capture mutable state or an initialization-time value.
    let eligible = true;
    let nodes = 1;
    let fieldReads = 0;
    fn.traverse({
      enter(path) {
        ++nodes;
        if (nodes > maximumBodyNodes) {
          eligible = false;
          path.stop();
        }
      },
      "ThisExpression|Super|MetaProperty|ImportExpression|TaggedTemplateExpression"(path) {
        // Tagged template objects belong to one original source site. Copies
        // across importers would expose distinct identities to the tag.
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
        // Binding positions include writes and destructuring targets, which
        // ReferencedIdentifier alone does not visit. The root function's own
        // binding must also stay hidden, including a named expression's name.
        if (
          referenced === binding ||
          node === fn.node ||
          node === undefined ||
          node.start < fn.node.start ||
          node.end > fn.node.end
        ) {
          eligible = false;
          path.stop();
        }
      },
      "MemberExpression|OptionalMemberExpression"() {
        ++fieldReads;
      },
    });
    let body;
    if (eligible) {
      const parameters = fn.node.params.map((p) => source.slice(p.start, p.end)).join(", ");
      const originalBody = source.slice(fn.node.body.start, fn.node.body.end);
      const text =
        fn.node.body.type === "BlockStatement" ? originalBody : `{ return (${originalBody}); }`;
      const bytes = Buffer.byteLength(parameters) + Buffer.byteLength(text);
      if (bytes <= maximumBodyBytes)
        body = {
          parameters,
          body: text,
          nodes,
          fieldReads,
          bytes,
          sha256: hash(canonicalJson({ parameters, body: text })),
        };
    }
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
        const calls = binding.referencePaths.flatMap((reference) => {
          const call = reference.parentPath;
          // Values used as callbacks, constructors, tagged templates or method
          // receivers retain the original closure and its observable identity.
          return call.isCallExpression() &&
            !call.node.optional &&
            call.node.callee === reference.node
            ? [{ start: reference.node.start, end: reference.node.end }]
            : [];
        });
        bindings.push({
          imported: specifier.isImportDefaultSpecifier()
            ? "default"
            : (specifier.node.imported.name ?? specifier.node.imported.value),
          local,
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
  let rejectedBindings = 0;
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
      if (body === undefined) {
        ++rejectedBindings;
        continue;
      }
      let selected = bodies.get(body.sha256);
      if (selected === undefined) {
        if (bodies.size >= maximumImportedBodies || bytes + body.bytes > maximumImportedBytes) {
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
      }
      for (const call of binding.calls) calls.push({ ...call, name: selected.name });
    }
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
  if (plan.bodies.length > 0)
    source +=
      "\n" +
      plan.bodies
        .map(({ name, parameters, body }) => `function ${name}(${parameters}) ${body}\n`)
        .join("");
  return source;
}
