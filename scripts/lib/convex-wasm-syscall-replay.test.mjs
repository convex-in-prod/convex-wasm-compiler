import assert from "node:assert/strict";
import test from "node:test";
import { createConvexWasmSyscallReplay, prepareConvexWasmSyscallReplay } from "./convex-wasm-syscall-replay.mjs";

function call(sequence, operation, args, result) {
  return { sequence, channel: ["1.0/queryStream", "1.0/queryCleanup"].includes(operation) ? "syscall" : "asyncSyscall", startedEvent: sequence * 2, completedEvent: sequence * 2 + 1, operation, arguments: JSON.stringify(args), result: JSON.stringify(result) };
}

test("independent reads can reorder but writes retain their request and position", async () => {
  const input = [call(0, "1.0/get", { id: "a" }, { count: 1 }), call(1, "1.0/get", { id: "b" }, null), call(2, "1.0/shallowMerge", { id: "a", value: { count: 2 } }, {}), call(3, "1.0/get", { id: "a" }, { count: 2 })];
  const prepared = prepareConvexWasmSyscallReplay(input);
  const run = createConvexWasmSyscallReplay(prepared);
  assert.equal(await run.Convex.asyncSyscall("1.0/get", '{"id":"b"}'), 'null');
  assert.equal(await run.Convex.asyncSyscall("1.0/get", '{"id":"a"}'), '{"count":1}');
  await run.Convex.asyncSyscall("1.0/shallowMerge", '{"value":{"count":2},"id":"a"}');
  assert.equal(await run.Convex.asyncSyscall("1.0/get", '{"id":"a"}'), '{"count":2}');
  assert.deepEqual(run.assertComplete(), { calls: 4, writeEpochs: 1 });
  assert.throws(() => createConvexWasmSyscallReplay(prepared).Convex.asyncSyscall("1.0/shallowMerge", input[2].arguments), /Replay write differs/);
});

test("query handles are local and every captured result must be consumed", async () => {
  const input = [call(0, "1.0/queryStream", { query: { source: {} } }, { queryId: 91 }), call(1, "1.0/queryStreamNext", { queryId: 91 }, { done: false, value: { n: 1 } }), call(2, "1.0/queryStreamNext", { queryId: 91 }, { done: true, value: null }), call(3, "1.0/queryCleanup", { queryId: 91 }, {})];
  const prepared = prepareConvexWasmSyscallReplay(input);
  const run = createConvexWasmSyscallReplay(prepared);
  const handle = run.Convex.syscall("1.0/queryStream", input[0].arguments);
  assert.equal(handle, '{"queryId":1}');
  assert.equal(await run.Convex.asyncSyscall("1.0/queryStreamNext", handle), input[1].result);
  assert.equal(await run.Convex.asyncSyscall("1.0/queryStreamNext", handle), input[2].result);
  run.Convex.syscall("1.0/queryCleanup", handle);
  run.assertComplete();
  const early = createConvexWasmSyscallReplay(prepared);
  early.Convex.syscall("1.0/queryStream", input[0].arguments);
  assert.throws(() => early.Convex.syscall("1.0/queryCleanup", handle), /unread results/);
});

test("rejects changed requests without exposing values or weakening missing/null distinctions", () => {
  const input = [call(0, "1.0/get", { id: "private-original" }, null)];
  for (const args of ['{"id":"private-changed"}', '{}', '{"id":null}', '[]']) {
    const run = createConvexWasmSyscallReplay(prepareConvexWasmSyscallReplay(input));
    assert.throws(() => run.Convex.asyncSyscall("1.0/get", args), { message: "Replay read differs in epoch 0 (1.0/get)" });
    assert.throws(() => run.assertComplete(), /Replay read differs/);
  }
});

test("rejects incomplete and duplicate events and reads spanning a write", () => {
  const read = call(0, "1.0/get", { id: "a" }, null);
  assert.throws(() => prepareConvexWasmSyscallReplay([{ ...read, completedEvent: 2 }]), /Invalid/);
  assert.throws(() => prepareConvexWasmSyscallReplay([read, { ...read, sequence: 1 }]), /Invalid/);
  assert.throws(() => prepareConvexWasmSyscallReplay([{ ...read, completedEvent: 3 }, { ...call(1, "1.0/remove", { id: "a" }, {}), startedEvent: 1, completedEvent: 2 }]), /overlapping a write/);
  assert.throws(() => createConvexWasmSyscallReplay(prepareConvexWasmSyscallReplay([read])).assertComplete(), /Incomplete/);
});

test("keeps concurrent write starts ordered and rejects reads before their completion", async () => {
  const first = { ...call(0, "1.0/remove", { id: "a" }, {}), completedEvent: 3 };
  const second = { ...call(1, "1.0/remove", { id: "b" }, {}), startedEvent: 1, completedEvent: 2 };
  const input = [first, second, call(2, "1.0/get", { id: "a" }, null)];
  const prepared = prepareConvexWasmSyscallReplay(input);
  const run = createConvexWasmSyscallReplay(prepared);
  await Promise.all([run.Convex.asyncSyscall(first.operation, first.arguments), run.Convex.asyncSyscall(second.operation, second.arguments)]);
  await run.Convex.asyncSyscall("1.0/get", '{"id":"a"}');
  run.assertComplete();
  assert.throws(() => createConvexWasmSyscallReplay(prepared).Convex.asyncSyscall(second.operation, second.arguments), /write differs/);
  assert.throws(() => prepareConvexWasmSyscallReplay([first, { ...call(1, "1.0/get", { id: "a" }, null), startedEvent: 1, completedEvent: 2 }]), /overlapping a write/);
});

test("query corruption, changed predicates and unsupported calls fail closed", () => {
  const start = call(0, "1.0/queryStream", { query: { source: { tableName: "items" } } }, { queryId: 4 });
  const end = call(1, "1.0/queryStreamNext", { queryId: 4 }, { done: true, value: null });
  const cleanup = call(2, "1.0/queryCleanup", { queryId: 4 }, {});
  const prepared = prepareConvexWasmSyscallReplay([start, end, cleanup]);
  assert.throws(() => createConvexWasmSyscallReplay(prepared).Convex.syscall(start.operation, '{"query":{"source":{"tableName":"changed"}}}'), /read differs/);
  assert.throws(() => prepareConvexWasmSyscallReplay([start, end]), /unclosed/);
  assert.throws(() => prepareConvexWasmSyscallReplay([start, end, call(2, "1.0/queryStreamNext", { queryId: 4 }, { done: false, value: {} }), { ...cleanup, sequence: 3, startedEvent: 6, completedEvent: 7 }]), /continuation/);
  assert.throws(() => prepareConvexWasmSyscallReplay([call(0, "unknown", {}, {})]), /Unsupported/);
  assert.throws(() => prepareConvexWasmSyscallReplay([{ ...call(0, "1.0/get", {}, null), arguments: '{"private-original"' }]), { message: "Malformed replay JSON" });
  const malformed = createConvexWasmSyscallReplay(prepareConvexWasmSyscallReplay([call(0, "1.0/get", {}, null)]));
  assert.throws(() => malformed.Convex.asyncSyscall("1.0/get", '{"private-original"'), /Malformed replay JSON/);
  assert.throws(() => malformed.assertComplete(), /Malformed replay JSON/);
});
