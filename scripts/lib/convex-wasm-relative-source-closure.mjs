import { posix } from "node:path";
import { TextDecoder } from "node:util";

import { API } from "tsrs/unstable/sync";
import * as ts from "tsrs/unstable/ast";
import { parseTsrsSource } from "./tsrs-source.mjs";

const JAVASCRIPT_SOURCE_EXTENSIONS = new Set([".cjs", ".js", ".mjs"]);

function fail(message) {
  throw new Error(`Convex Wasm relative source closure: ${message}`);
}

export function requireConvexWasmRepositoryRelativePath(path, description) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.includes("\\") ||
    path.includes("\0") ||
    posix.isAbsolute(path) ||
    posix.normalize(path) !== path ||
    path === "." ||
    path === ".." ||
    path.startsWith("../")
  ) {
    fail(`${description} must be a normalized repository-relative POSIX path`);
  }
  return path;
}

export function requireConvexWasmSortedUniquePaths(
  paths,
  description,
  { allowEmpty = false } = {}
) {
  if (!Array.isArray(paths) || (!allowEmpty && paths.length === 0)) {
    fail(`${description} must be ${allowEmpty ? "an" : "a non-empty"} array`);
  }
  let previous;
  for (const [index, path] of paths.entries()) {
    requireConvexWasmRepositoryRelativePath(path, `${description}[${index}]`);
    if (previous !== undefined && path <= previous) {
      fail(`${description} must be sorted and unique`);
    }
    previous = path;
  }
  return paths;
}

function relativeImports(api, relativePath, contents) {
  if (!JAVASCRIPT_SOURCE_EXTENSIONS.has(posix.extname(relativePath))) return [];
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(contents);
  } catch (error) {
    throw new Error(`Convex Wasm relative source closure: ${relativePath} is not valid UTF-8`, {
      cause: error,
    });
  }
  const sourceFile = parseTsrsSource(api, ts, relativePath, source);
  if (sourceFile === undefined) fail(`${relativePath} is not valid JavaScript`);
  const specifiers = [];
  function collectSpecifier(node) {
    if (
      node !== undefined &&
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      (node.text.startsWith("./") || node.text.startsWith("../"))
    ) {
      specifiers.push(node.text);
    }
  }
  function visit(node) {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      collectSpecifier(node.moduleSpecifier);
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isIdentifier(callee)
        ? callee.text
        : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
      if (callee.kind === ts.SyntaxKind.ImportKeyword || name === "require") {
        collectSpecifier(node.arguments[0]);
      } else if (name === "define") {
        const first = node.arguments[0];
        const dependencies = first !== undefined && ts.isStringLiteral(first)
          ? node.arguments[1]
          : first;
        if (dependencies !== undefined && ts.isArrayLiteralExpression(dependencies)) {
          dependencies.elements.forEach(collectSpecifier);
        }
      }
    }
    // Traverse executable syntax. SourceFile.imports also includes JSDoc type dependencies
    // and omits property-form require calls and AMD dependency arrays.
    node.forEachChild(visit);
  }
  visit(sourceFile);
  return specifiers;
}

export async function collectConvexWasmRelativeSourceClosure({
  materials = [],
  readSource,
  roots,
}) {
  requireConvexWasmSortedUniquePaths(roots, "source roots");
  requireConvexWasmSortedUniquePaths(materials, "source materials", { allowEmpty: true });
  if (typeof readSource !== "function") fail("readSource must be a function");

  if (process.env.TSRS_BINARY !== undefined) {
    throw new Error("Source analysis requires the installed tsrs binary; unset TSRS_BINARY.");
  }
  const api = new API();
  try {
    const contentsByPath = new Map();
    const modulePaths = new Set();
    const pending = [...roots];
    for (let index = 0; index < pending.length; index += 1) {
      const relativePath = pending[index];
      if (modulePaths.has(relativePath)) continue;
      modulePaths.add(relativePath);
      const contents = await readSource(relativePath);
      if (!(contents instanceof Uint8Array)) {
        fail(`readSource must return bytes for ${relativePath}`);
      }
      contentsByPath.set(relativePath, contents);
      for (const specifier of relativeImports(api, relativePath, contents)) {
        const importedPath = posix.normalize(posix.join(posix.dirname(relativePath), specifier));
        requireConvexWasmRepositoryRelativePath(
          importedPath,
          `relative import ${JSON.stringify(specifier)} from ${relativePath}`
        );
        if (!modulePaths.has(importedPath)) pending.push(importedPath);
      }
    }

    for (const relativePath of materials) {
      if (contentsByPath.has(relativePath)) {
        fail(`source material is already reachable from a root: ${relativePath}`);
      }
      const contents = await readSource(relativePath);
      if (!(contents instanceof Uint8Array)) {
        fail(`readSource must return bytes for ${relativePath}`);
      }
      contentsByPath.set(relativePath, contents);
    }

    return Object.freeze({
      contentsByPath,
      modulePaths: Object.freeze([...modulePaths].sort()),
      paths: Object.freeze([...contentsByPath.keys()].sort()),
    });
  } finally {
    api.close();
  }
}
