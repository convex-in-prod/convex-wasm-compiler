import { verifyConvexApiInstalledMaterial } from "./convex-api-flattener-material.mjs";

const loadedTsrsMaterials = new Map();

export function authenticateTsrsRuntimeMaterial(runtimePath, capture) {
  const previous = loadedTsrsMaterials.get(runtimePath);
  // Node shares imported API/AST modules across source-analysis callers. Retain
  // states as well as hashes: restoring bytes cannot repair that import window.
  if (previous !== undefined) {
    if (previous.identity.nodeModulesSha256 !== capture.identity.nodeModulesSha256) {
      throw new Error("Installed tsrs material changed after it was loaded; restart the process.");
    }
    try {
      verifyConvexApiInstalledMaterial(previous);
    } catch (cause) {
      throw new Error(
        "Installed tsrs material changed after it was loaded; restart the process.",
        { cause }
      );
    }
  }
  loadedTsrsMaterials.set(runtimePath, capture);
}

export function parseTsrsSource(api, ts, fileName, source) {
  const retained = api.createSourceFile(fileName, source);
  try {
    const { sourceFile } = retained;
    // tsrs marks the source root when any descendant has a parse error. The local
    // syntax tree owns its bytes; only remote semantic operations need the lease.
    const parseErrorFlags = ts.NodeFlags.ThisNodeHasError | ts.NodeFlags.ThisNodeOrAnySubNodesHasError;
    return (sourceFile.flags & parseErrorFlags) === 0
      ? sourceFile
      : undefined;
  } finally {
    retained.dispose();
  }
}
