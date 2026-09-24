import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readConvexWasmPrivateEvidenceJson } from "./convex-wasm-private-evidence.mjs";

test("reads only bounded canonical private evidence from a stable path", async () => {
  const directory = await fs.mkdtemp(join(tmpdir(), "convex-wasm-private-evidence-test-"));
  const evidencePath = join(directory, "evidence.json");
  try {
    await fs.writeFile(evidencePath, '{"kind":"test"}\n', { mode: 0o600 });
    assert.deepEqual(
      (await readConvexWasmPrivateEvidenceJson(evidencePath, "test evidence")).value,
      {
        kind: "test",
      }
    );

    const symlinkPath = join(directory, "evidence-link.json");
    await fs.symlink(evidencePath, symlinkPath);
    await assert.rejects(
      readConvexWasmPrivateEvidenceJson(symlinkPath, "linked evidence"),
      /canonical bounded mode-0600 file/u
    );

    const oversizedPath = join(directory, "oversized.json");
    await fs.writeFile(oversizedPath, '{"kind":"oversized"}\n', { mode: 0o600 });
    await assert.rejects(
      readConvexWasmPrivateEvidenceJson(oversizedPath, "oversized evidence", 4),
      /canonical bounded mode-0600 file/u
    );

    const noncanonicalPath = join(directory, "noncanonical.json");
    await fs.writeFile(noncanonicalPath, '{ "kind": "test" }\n', { mode: 0o600 });
    await assert.rejects(
      readConvexWasmPrivateEvidenceJson(noncanonicalPath, "noncanonical evidence"),
      /not canonical JSON/u
    );
  } finally {
    await fs.rm(directory, { force: true, recursive: true });
  }
});
