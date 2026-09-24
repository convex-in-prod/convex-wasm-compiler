import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runBoundedNativeCommand } from "./bounded-native-command.mjs";
import { createConvexWasmNativeCommandRunner } from "./convex-wasm-native-command-runner.mjs";

test("bounded native commands return cancellation without starting an already-aborted process", async () => {
  const controller = new AbortController();
  controller.abort();
  const result = await runBoundedNativeCommand({
    arguments: ["-e", "throw new Error('must not start')"],
    command: process.execPath,
    cwd: tmpdir(),
    environment: process.env,
    maxOutputBytes: 1024,
    operation: "synthetic-native-stage",
    signal: controller.signal,
    timeoutMs: 1000,
  });
  assert.deepEqual(result.termination, { kind: "aborted" });
});

test("native command runner bounds execution and keeps process output out of errors", async (t) => {
  const workPath = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-runner-"));
  t.after(() => fs.rm(workPath, { force: true, recursive: true }));
  const runner = createConvexWasmNativeCommandRunner({
    environment: process.env,
    maxOutputBytes: 1024,
    timeoutMs: 5000,
  });
  const timing = await runner({
    command: { executable: process.execPath, args: ["-e", "process.stdout.write('ok')"] },
    stage: "synthetic-stage",
    workPath,
  });
  assert.equal(timing.wallMilliseconds > 0, true);
  await assert.rejects(
    runner({
      command: {
        executable: process.execPath,
        args: ["-e", "process.stderr.write('private fixture text');process.exit(7)"],
      },
      stage: "synthetic-stage",
      workPath,
    }),
    (error) => {
      assert.equal(error.nativeFailure.kind, "command-exit");
      assert.equal(error.nativeFailure.code, 7);
      assert.equal(error.message.includes("private fixture text"), false);
      return true;
    }
  );
  await assert.rejects(
    runner({
      command: { executable: join(workPath, "missing-command"), args: [] },
      stage: "synthetic-stage",
      workPath,
    }),
    (error) => {
      assert.deepEqual(error.nativeFailure, { kind: "command-start", reason: "ENOENT" });
      assert.equal(error.message.includes(workPath), false);
      return true;
    }
  );
});

test("native command runner cancels a process and classifies interruption", async (t) => {
  const workPath = await fs.mkdtemp(join(tmpdir(), "convex-wasm-native-cancel-"));
  t.after(() => fs.rm(workPath, { force: true, recursive: true }));
  const controller = new AbortController();
  const runner = createConvexWasmNativeCommandRunner({
    environment: process.env,
    maxOutputBytes: 1024,
    signal: controller.signal,
    timeoutMs: 5000,
  });
  const running = runner({
    command: { executable: process.execPath, args: ["-e", "setInterval(() => {}, 1000)"] },
    stage: "synthetic-stage",
    workPath,
  });
  setTimeout(() => controller.abort(), 25);
  await assert.rejects(running, (error) => {
    assert.deepEqual(error.nativeFailure, {
      kind: "guard-termination",
      terminationKind: "interrupted",
    });
    return true;
  });
});
