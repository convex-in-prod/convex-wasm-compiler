import assert from "node:assert/strict";
import test from "node:test";

import { analyzeIncrementalCacheTrace } from "./convex-wasm-incremental-cache-trace.mjs";

const key = "b".repeat(64);

function records() {
  return [
    {
      kind: "convex-wasm-incremental-cache-trace-v1",
      namespace: "a".repeat(64),
      recordHeaderBytes: 72,
      tiers: [{ sets: 16, ways: 4, recordLimitBytes: 128 }],
    },
    {
      event: "lookup",
      key,
      result: "miss",
      valueBytes: null,
      lookupNanoseconds: 10,
    },
    {
      event: "insert",
      key,
      valueBytes: 16,
      result: { kind: "stored", tier: 0, displacedRecordBytes: 90 },
      compileInterval: {
        kind: "matched",
        precedingLookup: "miss",
        wallNanoseconds: 90,
        threadCpuNanoseconds: 80,
      },
    },
    {
      event: "lookup",
      key,
      result: "hit",
      valueBytes: 16,
      lookupNanoseconds: 20,
    },
    {
      event: "insert",
      key,
      valueBytes: 64,
      result: { kind: "oversized" },
      compileInterval: {
        kind: "matched",
        precedingLookup: "hit",
        wallNanoseconds: 900,
        threadCpuNanoseconds: 800,
      },
    },
    {
      event: "complete",
      counters: {
        hits: 1,
        misses: 1,
        inserts: 1,
        evictions: 1,
        oversizedValues: 1,
        rejectedRecords: 0,
      },
    },
  ];
}

function encode(events) {
  return Buffer.from(
    `${events.map((event) => JSON.stringify(event)).join("\n")}\n`,
  );
}

test("attributes result sizes and miss versus post-hit compilation cost", () => {
  const report = analyzeIncrementalCacheTrace(encode(records()));
  assert.deepEqual(report.lookupNanoseconds, { hit: 20, miss: 10 });
  assert.deepEqual(report.sizeBuckets, [
    {
      maximumValueBytes: 4096,
      stored: 1,
      oversized: 1,
      valueBytes: 80,
      displacedRecordBytes: 90,
      matchedMissIntervals: 1,
      matchedHitIntervals: 1,
      unmatchedIntervals: 0,
      missThreadCpuNanoseconds: 80,
      hitThreadCpuNanoseconds: 800,
      compileWallNanoseconds: 990,
    },
  ]);
  assert.equal(report.mostExpensiveInsertions[0].result.kind, "oversized");
  assert.match(report.traceSha256, /^[0-9a-f]{64}$/u);
});

test("does not fabricate compilation cost for an insertion without a lookup", () => {
  const events = records();
  events.splice(1, 1);
  events[1].compileInterval = { kind: "unmatched" };
  events.at(-1).counters.misses = 0;
  const report = analyzeIncrementalCacheTrace(encode(events));
  assert.equal(report.sizeBuckets[0].unmatchedIntervals, 1);
  assert.equal(report.sizeBuckets[0].missThreadCpuNanoseconds, 0);
  assert.equal(report.mostExpensiveInsertions.length, 1);
});

test("rejects incomplete or inconsistent evidence", async (t) => {
  for (const [name, change] of [
    ["missing completion", (events) => events.pop()],
    [
      "wrong count",
      (events) => {
        events.at(-1).counters.evictions = 0;
      },
    ],
    [
      "wrong tier",
      (events) => {
        events[2].result.tier = 1;
      },
    ],
    [
      "false oversized",
      (events) => {
        events[4].valueBytes = 8;
      },
    ],
    [
      "unmatched key",
      (events) => {
        events[2].key = "c".repeat(64);
      },
    ],
    [
      "negative duration",
      (events) => {
        events[2].compileInterval.threadCpuNanoseconds = -1;
      },
    ],
    [
      "unknown event",
      (events) => {
        events[1].event = "unknown";
      },
    ],
    [
      "unknown fields",
      (events) => {
        events[2].unexpected = true;
      },
    ],
    [
      "invalid size",
      (events) => {
        events[2].valueBytes = null;
      },
    ],
  ]) {
    await t.test(name, () => {
      const events = records();
      change(events);
      assert.throws(
        () => analyzeIncrementalCacheTrace(encode(events)),
        /Incremental cache trace:/u,
      );
    });
  }
  assert.throws(
    () => analyzeIncrementalCacheTrace(encode(records()).subarray(0, -1)),
    /incomplete/u,
  );
});
