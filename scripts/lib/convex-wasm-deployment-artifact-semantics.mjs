import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import {
  convexWasmCompilerOutputContract,
  convexWasmCompilerOutputKind,
} from "./convex-wasm-compiler-contract.mjs";

// The deployment builder is operational and its bytes do not rekey graph identities. Bump this
// revision for graph-construction semantic edits not represented by the literal assumptions below.
export const convexWasmDeploymentGraphConstructionSemanticRevision =
  "convex-wasm-deployment-graph-construction";

export const convexWasmDeploymentGraphAssumptions = Object.freeze({
  conditions: Object.freeze(["convex", "module"]),
  format: "esm",
  graphConstructionSemanticRevision: convexWasmDeploymentGraphConstructionSemanticRevision,
  platform: "browser",
  plugins: Object.freeze([
    "convex-source-material-snapshot",
    "convex-async-hooks-shim",
    "convex-server-only",
    "convex-node-externals(empty-browser-map)",
    "convex-wasm",
  ]),
  productionArtifact: false,
  resolutionAuthority: "esbuild-metafile",
  splitting: true,
  target: "esnext",
});

export const convexWasmDeploymentCompilerBatchSemantics = Object.freeze({
  allEligibleSelection: Object.freeze({ kind: "allEligible" }),
  cacheKind: "convex-wasm-deployment-batch-cache",
  explicitAuthoritySelection: Object.freeze({ kind: "explicitAuthority" }),
  requestKind: "convex-wasm-compiler-batch-request",
  responseKind: "convex-wasm-compiler-batch-response",
  semanticRevision: "convex-wasm-deployment-compiler-batch",
});

// The deployment module is operational and its bytes do not rekey artifacts. Any artifact-semantic
// edit to either handoff site must bump the applicable revision here. Both paths bind the resulting
// producer SHA into native/package identities, and the identities below also bind the revision into
// the deployment policy.
export const convexWasmDeploymentDirectArtifactHandoffSemanticRevision =
  "convex-wasm-deployment-direct-artifact-handoff-v1";
export const convexWasmDeploymentLegacyArtifactHandoffSemanticRevision =
  "convex-wasm-deployment-legacy-artifact-handoff-v1";

export function createConvexWasmDeploymentArtifactHandoffIdentity(semanticRevision) {
  if (typeof semanticRevision !== "string" || semanticRevision.length === 0) {
    throw new Error("Convex Wasm deployment artifact handoff revision must be a non-empty string");
  }
  const identity = {
    kind: "convex-wasm-deployment-artifact-handoff-identity-v1",
    semanticRevision,
  };
  return Object.freeze({ ...identity, sha256: fingerprintJson(identity) });
}

export const convexWasmDeploymentDirectArtifactHandoffIdentity =
  createConvexWasmDeploymentArtifactHandoffIdentity(
    convexWasmDeploymentDirectArtifactHandoffSemanticRevision
  );
export const convexWasmDeploymentLegacyArtifactHandoffIdentity =
  createConvexWasmDeploymentArtifactHandoffIdentity(
    convexWasmDeploymentLegacyArtifactHandoffSemanticRevision
  );

export const convexWasmDeploymentOfficialOutputCompilerRecordIdentity = Object.freeze({
  admittedLanguageVersion: 29,
  compilerRevision: "runtime-capability-entry-v1",
  kind: "convex-wasm-official-output-compiler-record-v1",
});

export const convexWasmDeploymentArtifactAdmissionPolicy = Object.freeze({
  artifactFallback:
    "authenticated-static-hermes-flow-type-rejection-mapped-to-reachable-user-unit-v1",
  artifactCompilation: "stable-route-id-16-bucket-cohorts-with-bounded-object-link",
  artifactHandoff: convexWasmDeploymentLegacyArtifactHandoffIdentity,
  authoritativeInventory: "flattened-generated-api",
  batchContracts: Object.freeze({
    request: convexWasmDeploymentCompilerBatchSemantics.requestKind,
    response: convexWasmDeploymentCompilerBatchSemantics.responseKind,
  }),
  batchOutput:
    "primary-fallback-analysis-all-eligible-and-explicit-authority-scoped-compile-source-v1",
  batchSemanticRevision: convexWasmDeploymentCompilerBatchSemantics.semanticRevision,
  compilerOutputContract: convexWasmCompilerOutputContract,
  compilerOutputKind: convexWasmCompilerOutputKind,
  compileSelection: "authority-preserving-explicit-or-all-compiler-eligible-batch-bound",
  dependencyAuthority: "convex-bundler-esbuild-metafile",
  kind: "convex-wasm-deployment-admission-policy-v4",
  staticFallbacks: Object.freeze([
    "action-runtime",
    "generated-source-kind-mismatch",
    "generated-source-registration-mismatch",
    "registration-reexport",
    "unsupported-registration-builder",
  ]),
});

export const convexWasmDeploymentArtifactAdmissionPolicySha256 = fingerprintJson(
  convexWasmDeploymentArtifactAdmissionPolicy
);
