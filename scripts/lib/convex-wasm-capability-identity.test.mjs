import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmCapabilitySourcePipelineSha256 } from "./convex-wasm-capability-identity.mjs";
import { convexWasmCapabilitySourcePipelineSha256 as pipelineIdentity } from "./convex-wasm-artifact-pipeline.mjs";

test("profile identity has no runtime grouping limit and retains its existing hash contract", () => {
  const profiles = Array.from({ length: 12 }, (_, index) => ({
    sha256: createHash("sha256").update(`profile-${index}`).digest("hex"),
  }));
  assert.equal(pipelineIdentity, convexWasmCapabilitySourcePipelineSha256);
  assert.equal(pipelineIdentity([profiles[0]]), profiles[0].sha256);
  for (const length of [2, 8, 12]) {
    const selected = profiles.slice(0, length);
    assert.equal(pipelineIdentity(selected), fingerprintJson({
      domain: "convex-wasm-capability-package-source-pipeline-v2",
      profiles: selected.map(({ sha256 }) => sha256),
    }));
  }
  assert.notEqual(pipelineIdentity(profiles), pipelineIdentity(profiles.toReversed()));
  assert.throws(() => pipelineIdentity([]), /at least one local profile/);
  assert.throws(() => pipelineIdentity([...profiles, { sha256: "invalid" }]), /SHA-256/);
});
