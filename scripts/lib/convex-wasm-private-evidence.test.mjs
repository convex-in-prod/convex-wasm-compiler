import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readConvexWasmPrivateEvidenceJson } from "./convex-wasm-private-evidence.mjs";

test("reads only bounded canonical private evidence from a stable path", async (t) => {
  const directory = await fs.realpath(
    await fs.mkdtemp(join(tmpdir(), "convex-wasm-private-evidence-test-"))
  );
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

    for (const [boundary, targetRead] of [["initial", 1], ["final", 2]]) {
      await t.test(`${boundary} verification drains sibling reads before rejecting`, async (t) => {
        const paused = Promise.withResolvers();
        const resume = Promise.withResolvers();
        const siblingDone = Promise.withResolvers();
        const failure = new Error(`synthetic ${boundary} realpath failure`);
        const lstat = fs.lstat;
        const realpath = fs.realpath;
        let statReads = 0;
        let canonicalReads = 0;
        let siblingFinished = false;
        let finished = false;
        t.mock.method(fs, "lstat", async (path, ...args) => {
          if (path !== evidencePath || ++statReads !== targetRead) return await lstat(path, ...args);
          paused.resolve();
          await resume.promise;
          try {
            const status = await lstat(path, ...args);
            siblingFinished = true;
            return status;
          } finally {
            siblingDone.resolve();
          }
        });
        t.mock.method(fs, "realpath", async (path, ...args) => {
          if (path !== evidencePath || ++canonicalReads !== targetRead) return await realpath(path, ...args);
          await paused.promise;
          throw failure;
        });
        const result = readConvexWasmPrivateEvidenceJson(evidencePath, "test evidence")
          .catch((error) => error)
          .finally(() => { finished = true; });
        try {
          await paused.promise;
          // Allow rejection and final-handle cleanup to finish while the sibling stays paused.
          await Promise.race([result, new Promise((resolve) => setTimeout(resolve, 100))]);
          assert.equal(finished, false);
        } finally {
          resume.resolve();
          const error = await result;
          await siblingDone.promise;
          assert.equal(error, failure);
        }
        assert.equal(siblingFinished, true);
      });
    }
  } finally {
    await fs.rm(directory, { force: true, recursive: true });
  }
});
