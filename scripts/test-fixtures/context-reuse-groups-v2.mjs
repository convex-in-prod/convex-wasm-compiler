// SDK six-argument grouping contract. Keep this fixture independent of the
// compiler adapter so legacy installed packages can exercise version 2 output.
import { createHash } from "node:crypto";
import path from "node:path";
import { parse } from "@babel/parser";

export async function contextReuseGroups(
  ctx,
  outputFiles,
  metafile,
  includedOutputs,
  chunksFolder,
  kind
) {
  if (kind !== "database" && kind !== "action") {
    return await ctx.crash({ printedMessage: "An explicit context kind is required" });
  }
  const groups = new Map();
  for (const file of outputFiles) {
    if (!includedOutputs.has(file.path)) continue;
    const outputPath = path.relative(process.cwd(), file.path).split(path.sep).join("/");
    const output = metafile.outputs[outputPath];
    if (
      output === undefined ||
      output.imports.length === 0 ||
      output.imports.some(
        (dependency) =>
          dependency.external ||
          dependency.kind !== "import-statement" ||
          metafile.outputs[dependency.path] === undefined ||
          metafile.outputs[dependency.path].entryPoint !== undefined
      )
    ) continue;
    const ast = parse(file.text, { sourceType: "module" });
    if (
      ast.program.directives.length !== 0 ||
      !ast.program.body.every(
        (statement) =>
          statement.type === "ImportDeclaration" ||
          statement.type === "ExportAllDeclaration" ||
          (statement.type === "ExportNamedDeclaration" && statement.declaration === null) ||
          statement.type === "EmptyStatement"
      )
    ) continue;
    const imports = ast.program.body.flatMap((statement) =>
      "source" in statement && statement.source
        ? [path.posix.normalize(path.posix.join(path.posix.dirname(outputPath), statement.source.value))]
        : []
    );
    const signature = JSON.stringify(imports);
    const members = groups.get(signature) ?? [];
    members.push({
      path: path.relative("out", file.path).split(path.sep).join("/"),
      source: file.text,
    });
    groups.set(signature, members);
  }
  const initializers = [];
  const initializerByOutput = new Map();
  for (const [imports, members] of groups) {
    if (members.length < 2) continue;
    members.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    const hash = createHash("sha256")
      .update(JSON.stringify([kind, imports, members]))
      .digest("hex")
      .slice(0, 48);
    const initializerPath = path.posix.join(
      chunksFolder.split(path.sep).join("/"),
      `context_init_${hash}.js`
    );
    if (metafile.outputs[path.posix.join("out", initializerPath)] !== undefined) {
      return await ctx.crash({ printedMessage: "Context initializer collides with bundled output" });
    }
    const source = members.map((member) => {
      const relativePath = path.posix.relative(path.posix.dirname(initializerPath), member.path);
      const specifier = relativePath.startsWith(".") ? relativePath : `./${relativePath}`;
      initializerByOutput.set(path.resolve("out", member.path), initializerPath);
      return `import ${JSON.stringify(specifier)};\n`;
    }).join("");
    initializers.push({ path: initializerPath, source });
  }
  return { initializers, initializerByOutput };
}
