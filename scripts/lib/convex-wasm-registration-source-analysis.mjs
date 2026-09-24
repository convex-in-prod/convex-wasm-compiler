import { extname } from "node:path";

export function createConvexWasmRegistrationSourceAnalyzer(ts) {
  if (typeof ts?.createSourceFile !== "function" || typeof ts.version !== "string") {
    throw new Error("registration source analyzer requires a TypeScript runtime");
  }
  function scriptKind(path) {
    return {
      ".cjs": ts.ScriptKind.JS,
      ".cts": ts.ScriptKind.TS,
      ".js": ts.ScriptKind.JS,
      ".jsx": ts.ScriptKind.JSX,
      ".mjs": ts.ScriptKind.JS,
      ".mts": ts.ScriptKind.TS,
      ".ts": ts.ScriptKind.TS,
      ".tsx": ts.ScriptKind.TSX,
    }[extname(path)];
  }

  function transparentExpression(expression) {
    let current = expression;
    while (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
    }
    return current;
  }

  function staticObjectPropertyText(name) {
    if (
      ts.isIdentifier(name) ||
      ts.isStringLiteral(name) ||
      ts.isNumericLiteral(name) ||
      ts.isNoSubstitutionTemplateLiteral(name)
    ) {
      return name.text;
    }
    return undefined;
  }

  function declarativeRegistrationDefinition(expression) {
    const current = transparentExpression(expression);
    if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) return true;
    if (!ts.isObjectLiteralExpression(current)) return false;
    // An own data property prevents definition.handler from reaching a mutated Object prototype.
    let ownsHandler = false;
    const supported = current.properties.every((property) => {
      if (ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property)) {
        return false;
      }
      if (
        ts.isPropertyAssignment(property) &&
        staticObjectPropertyText(property.name) === "__proto__"
      ) {
        // registerFunction reads definition.handler. A prototype mutation can make that read invoke
        // inherited application code, so the registration call is not a declarative boundary.
        return false;
      }
      if (
        (ts.isPropertyAssignment(property) ||
          ts.isShorthandPropertyAssignment(property) ||
          ts.isMethodDeclaration(property)) &&
        staticObjectPropertyText(property.name) === "handler"
      ) {
        ownsHandler = true;
      }
      return (
        ts.isPropertyAssignment(property) ||
        ts.isShorthandPropertyAssignment(property) ||
        ts.isMethodDeclaration(property) ||
        ts.isSpreadAssignment(property)
      );
    });
    return supported && ownsHandler;
  }

  function immutableRegistrationAnalysis(analysis) {
    const freezeValue = (value) => {
      if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
      for (const child of Array.isArray(value) ? value : Object.values(value)) {
        freezeValue(child);
      }
      return Object.freeze(value);
    };
    for (const name of ["aliases", "candidates", "exports", "imports"]) {
      for (const entry of analysis[name]) {
        freezeValue(entry);
      }
      Object.freeze(analysis[name]);
    }
    Object.freeze(analysis.starExports);
    return Object.freeze(analysis);
  }

  function registrationInputAnalysis({ absolutePath, input, inputPath, material }) {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(material.contents);
    const sourceFile = ts.createSourceFile(
      absolutePath,
      source,
      ts.ScriptTarget.ESNext,
      true,
      scriptKind(absolutePath)
    );
    const resolvedImports = new Map();
    for (const imported of input.imports ?? []) {
      if (
        imported.kind === "import-statement" &&
        typeof imported.original === "string" &&
        !resolvedImports.has(imported.original)
      ) {
        resolvedImports.set(imported.original, imported.path);
      }
    }
    const record = {
      aliases: new Map(),
      exports: new Map(),
      imports: new Map(),
      starExports: [],
    };
    for (const statement of sourceFile.statements) {
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
        const target = resolvedImports.get(statement.moduleSpecifier.text);
        const clause = statement.importClause;
        if (target === undefined || clause === undefined || clause.isTypeOnly) continue;
        if (clause.name !== undefined) {
          record.imports.set(clause.name.text, { importedName: "default", target });
        }
        if (clause.namedBindings !== undefined) {
          if (ts.isNamespaceImport(clause.namedBindings)) {
            record.imports.set(clause.namedBindings.name.text, { importedName: "*", target });
          } else {
            for (const specifier of clause.namedBindings.elements) {
              if (specifier.isTypeOnly) continue;
              record.imports.set(specifier.name.text, {
                importedName: (specifier.propertyName ?? specifier.name).text,
                target,
              });
            }
          }
        }
        continue;
      }
      if (ts.isVariableStatement(statement)) {
        const exported = statement.modifiers?.some(
          ({ kind }) => kind === ts.SyntaxKind.ExportKeyword
        );
        const immutable =
          (statement.declarationList.flags & ts.NodeFlags.Const) === ts.NodeFlags.Const;
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name)) continue;
          const localName = declaration.name.text;
          const initializer =
            declaration.initializer === undefined
              ? undefined
              : transparentExpression(declaration.initializer);
          if (immutable && initializer !== undefined && ts.isIdentifier(initializer)) {
            record.aliases.set(localName, initializer.text);
          }
          if (exported) {
            record.exports.set(localName, { localName });
          }
        }
        continue;
      }
      if (!ts.isExportDeclaration(statement)) continue;
      const target =
        statement.moduleSpecifier !== undefined && ts.isStringLiteral(statement.moduleSpecifier)
          ? resolvedImports.get(statement.moduleSpecifier.text)
          : undefined;
      if (statement.exportClause === undefined) {
        if (target !== undefined) record.starExports.push(target);
        continue;
      }
      if (!ts.isNamedExports(statement.exportClause)) continue;
      for (const specifier of statement.exportClause.elements) {
        if (specifier.isTypeOnly) continue;
        const exportName = specifier.name.text;
        const importedName = (specifier.propertyName ?? specifier.name).text;
        if (target === undefined) {
          record.exports.set(exportName, { localName: importedName });
        } else {
          record.exports.set(exportName, { importedName, target });
        }
      }
    }
    const candidates = [];
    for (const statement of sourceFile.statements) {
      if (!ts.isVariableStatement(statement) || statement.declarationList.declarations.length !== 1) {
        continue;
      }
      const declaration = statement.declarationList.declarations[0];
      if (
        !ts.isIdentifier(declaration.name) ||
        declaration.initializer === undefined ||
        !ts.isCallExpression(transparentExpression(declaration.initializer))
      ) {
        continue;
      }
      const call = transparentExpression(declaration.initializer);
      const callee = transparentExpression(call.expression);
      if (
        !ts.isIdentifier(callee) ||
        call.arguments.length !== 1 ||
        ts.isSpreadElement(call.arguments[0]) ||
        !declarativeRegistrationDefinition(call.arguments[0])
      ) {
        continue;
      }
      candidates.push({
        callee: callee.text,
        initializerStart: call.getStart(sourceFile),
      });
    }
    return immutableRegistrationAnalysis({
      absolutePath,
      aliases: [...record.aliases],
      candidates,
      exports: [...record.exports],
      imports: [...record.imports],
      inputPath,
      source,
      starExports: [...record.starExports],
    });
  }

  return registrationInputAnalysis;
}
