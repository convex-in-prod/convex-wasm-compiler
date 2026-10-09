// Record interfaces describe a private calling convention. Callers must separately
// prove a fresh, unaliased ordinary record with the required own fields or proved
// absence. These summaries do not make arbitrary object reads pure.

const maximumFunctions = 8;
const maximumFields = 8;
const maximumNodes = 2400;
const maximumGraphNodes = 8192;
const maximumBytes = 64 * 1024;
const maximumReferences = 256;

export function isReadOnlyRecordField(member) {
  if (
    !member.isMemberExpression() ||
    member.node.computed ||
    member.node.property.type !== "Identifier"
  )
    return false;
  const use = member.parentPath;
  if (
    ((use.isCallExpression() || use.isOptionalCallExpression()) &&
      use.node.callee === member.node) ||
    (use.isAssignmentExpression() && use.node.left === member.node) ||
    (use.isAssignmentPattern() && use.node.left === member.node) ||
    use.isUpdateExpression() ||
    use.isUnaryExpression({ operator: "delete" }) ||
    use.isArrayPattern() ||
    use.isRestElement() ||
    (use.isObjectProperty() && use.parentPath.isObjectPattern()) ||
    ((use.isForInStatement() || use.isForOfStatement()) && use.node.left === member.node)
  )
    return false;
  return true;
}

export function analyzeConvexWasmRecordInterface(binding, parameterIndex, source) {
  const programScope = binding.scope;
  const functions = new Map();
  const active = new Set();
  let totalNodes = 0;
  let totalBytes = 0;
  const visit = (calleeBinding, index) => {
    const prior = functions.get(calleeBinding);
    if (active.has(calleeBinding)) return undefined;
    if (prior !== undefined) return prior.parameterIndex === index ? prior : undefined;
    const fn = calleeBinding.path;
    if (
      functions.size >= maximumFunctions ||
      calleeBinding.scope !== programScope ||
      !calleeBinding.constant ||
      !fn.isFunctionDeclaration() ||
      fn.node.async ||
      fn.node.generator ||
      fn.node.params.length > 8 ||
      fn.node.params.some((parameter) => parameter.type !== "Identifier") ||
      index >= fn.node.params.length
    )
      return undefined;
    const parameter = fn.scope.getBinding(fn.node.params[index].name);
    if (!parameter.constant || parameter.referencePaths.length > maximumReferences)
      return undefined;
    let nodes = 0;
    let eligible = true;
    fn.traverse({
      enter(path) {
        if (++nodes > maximumNodes || ++totalNodes > maximumGraphNodes) {
          eligible = false;
          path.stop();
        }
      },
      Identifier(path) {
        if (path.isReferencedIdentifier() && ["arguments", "eval"].includes(path.node.name)) {
          eligible = false;
          path.stop();
        }
      },
      "TaggedTemplateExpression|ImportExpression|CallExpression"(path) {
        if (path.isCallExpression() && path.node.callee.type !== "Import") return;
        eligible = false;
        path.stop();
      },
    });
    if (!eligible) return undefined;
    const bodyStart = fn.node.body.start;
    const bodyEnd = fn.node.body.end;
    const parameters = fn.node.params.map((parameter) => parameter.name);
    const body = source.slice(bodyStart, bodyEnd);
    totalBytes += Buffer.byteLength(body) + Buffer.byteLength(parameters.join(", "));
    if (totalBytes > maximumBytes) return undefined;
    const result = {
      local: fn.node.id.name,
      parameterIndex: index,
      parameters,
      bodyStart,
      bodyEnd,
      body,
      nodes,
      fields: [],
      reads: [],
      forwards: [],
    };
    functions.set(calleeBinding, result);
    active.add(calleeBinding);
    const fields = new Set();
    for (const reference of parameter.referencePaths) {
      const use = reference.parentPath;
      if (use.node.object === reference.node && isReadOnlyRecordField(use)) {
        const field = use.node.property.name;
        fields.add(field);
        result.reads.push({ start: use.node.start, end: use.node.end, field });
      } else {
        // Forward only to a fixed declaration in this lexical module. Imported
        // calls need their own authenticated interface, not an assumed effect.
        if (
          !use.isCallExpression() ||
          use.node.optional ||
          use.node.callee.type !== "Identifier" ||
          use.node.arguments.some((argument) => argument.type === "SpreadElement")
        )
          return undefined;
        const target = use.scope.getBinding(use.node.callee.name);
        const argumentIndex = use.node.arguments.indexOf(reference.node);
        if (target === undefined || argumentIndex < 0) return undefined;
        const duplicate = use.get("arguments").some(
          (argument, i) =>
            i !== argumentIndex &&
            argument.isIdentifier() &&
            argument.scope.getBinding(argument.node.name) === parameter
        );
        if (duplicate) return undefined;
        const child = visit(target, argumentIndex);
        if (child === undefined) return undefined;
        child.fields.forEach((field) => fields.add(field));
        result.forwards.push({
          start: use.node.start,
          end: use.node.end,
          target: child.local,
          parameterIndex: argumentIndex,
          arguments: use.node.arguments.map(({ start, end }) => ({ start, end })),
        });
      }
      if (fields.size > maximumFields) return undefined;
    }
    active.delete(calleeBinding);
    result.fields = [...fields].sort();
    return result.fields.length === 0 ? undefined : result;
  };
  const entry = visit(binding, parameterIndex);
  if (entry === undefined) return undefined;
  return {
    local: entry.local,
    parameterIndex,
    fields: entry.fields,
    nodes: totalNodes,
    bytes: totalBytes,
    functions: [...functions.values()].sort((a, b) => a.bodyStart - b.bodyStart),
  };
}

export function renderConvexWasmRecordInterface(source, summary, sourceNames) {
  const names = new Set(sourceNames);
  const declarations = new Map();
  const allocateName = (stem) => {
    let name = stem;
    for (let suffix = 1; names.has(name); ++suffix) name = `${stem}_${suffix}`;
    names.add(name);
    return name;
  };
  for (const fn of summary.functions) {
    if (source.slice(fn.bodyStart, fn.bodyEnd) !== fn.body)
      throw new Error("Record interface does not match its source body");
    const stem = `__convexRecord_${fn.local}_${fn.parameterIndex}`;
    declarations.set(fn.local, {
      name: allocateName(stem),
      fields: new Map(fn.fields.map((field, i) => [field, allocateName(`${stem}_field${i}`)])),
    });
  }
  const bodies = [];
  for (const fn of summary.functions) {
    const declaration = declarations.get(fn.local);
    const edits = [...fn.reads, ...fn.forwards].sort((a, b) => a.start - b.start || b.end - a.end);
    const renderRange = (start, end) => {
      let text = "";
      let position = start;
      for (const edit of edits) {
        if (edit.start < position || edit.end > end) continue;
        text += source.slice(position, edit.start);
        if ("field" in edit) {
          text += declaration.fields.get(edit.field);
        } else {
          const target = declarations.get(edit.target);
          const argumentsText = edit.arguments.flatMap((argument, i) =>
            i === edit.parameterIndex
              ? [...target.fields.keys()].map((field) => declaration.fields.get(field))
              : [renderRange(argument.start, argument.end)]
          );
          text += `${target.name}(${argumentsText.join(", ")})`;
        }
        position = edit.end;
      }
      return text + source.slice(position, end);
    };
    const parameters = fn.parameters.flatMap((parameter, i) =>
      i === fn.parameterIndex ? [...declaration.fields.values()] : [parameter]
    );
    bodies.push(`function ${declaration.name}(${parameters.join(", ")}) ${renderRange(fn.bodyStart, fn.bodyEnd)}\n`);
  }
  return {
    entry: declarations.get(summary.local).name,
    fields: summary.fields,
    parameterIndex: summary.parameterIndex,
    source: bodies.join("\n"),
  };
}
