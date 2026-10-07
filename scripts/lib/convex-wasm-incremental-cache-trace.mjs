import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

const MAX_TRACE_BYTES = 64 * 1024 * 1024;
const SIZE_LIMITS = [
  4096,
  8192,
  16384,
  32768,
  65536,
  131072,
  262144,
  524288,
  1048576,
  4194304,
  16777216,
  Number.MAX_SAFE_INTEGER,
];

function fail(message) {
  throw new Error(`Incremental cache trace: ${message}`);
}

function object(value, keys, description) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== [...keys].sort().join(",")
  ) {
    fail(`${description} has unexpected fields`);
  }
}

function integer(value, description) {
  if (!Number.isSafeInteger(value) || value < 0)
    fail(`${description} must be a nonnegative safe integer`);
}

function key(value, description) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value))
    fail(`${description} must be a SHA-256 hex key`);
}

export function analyzeIncrementalCacheTrace(bytes) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    bytes.length > MAX_TRACE_BYTES
  ) {
    fail("input must be a nonempty buffer of at most 64 MiB");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!text.endsWith("\n")) fail("input is incomplete");
  const lines = text.slice(0, -1).split("\n");
  const records = lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      fail(`invalid JSON on line ${index + 1}`);
    }
  });
  const header = records.shift();
  object(header, ["kind", "namespace", "recordHeaderBytes", "tiers"], "header");
  if (header.kind !== "convex-wasm-incremental-cache-trace-v1")
    fail("unsupported trace kind");
  key(header.namespace, "namespace");
  integer(header.recordHeaderBytes, "recordHeaderBytes");
  if (
    header.recordHeaderBytes === 0 ||
    !Array.isArray(header.tiers) ||
    header.tiers.length === 0
  ) {
    fail("record layout must be nonempty");
  }
  let previousLimit = header.recordHeaderBytes;
  for (const tier of header.tiers) {
    object(tier, ["sets", "ways", "recordLimitBytes"], "tier");
    for (const [name, value] of Object.entries(tier)) integer(value, name);
    if (
      tier.sets === 0 ||
      tier.ways === 0 ||
      tier.recordLimitBytes <= previousLimit
    ) {
      fail("tiers must have positive capacity and increasing record limits");
    }
    previousLimit = tier.recordLimitBytes;
  }
  const completion = records.pop();
  object(completion, ["event", "counters"], "completion");
  if (completion.event !== "complete") fail("missing completion event");
  object(
    completion.counters,
    [
      "hits",
      "misses",
      "inserts",
      "evictions",
      "rejectedRecords",
      "oversizedValues",
    ],
    "counters",
  );
  for (const [name, value] of Object.entries(completion.counters))
    integer(value, name);

  const observed = {
    hits: 0,
    misses: 0,
    inserts: 0,
    evictions: 0,
    oversizedValues: 0,
  };
  const lookupNanoseconds = { hit: 0, miss: 0 };
  const buckets = SIZE_LIMITS.map((maximumValueBytes) => ({
    maximumValueBytes,
    stored: 0,
    oversized: 0,
    valueBytes: 0,
    displacedRecordBytes: 0,
    matchedMissIntervals: 0,
    matchedHitIntervals: 0,
    unmatchedIntervals: 0,
    missThreadCpuNanoseconds: 0,
    hitThreadCpuNanoseconds: 0,
    compileWallNanoseconds: 0,
  }));
  const expensive = [];
  const observedLookups = new Map();
  for (const event of records) {
    if (event?.event === "lookup") {
      object(
        event,
        ["event", "key", "result", "valueBytes", "lookupNanoseconds"],
        "lookup",
      );
      key(event.key, "lookup key");
      integer(event.lookupNanoseconds, "lookupNanoseconds");
      if (event.result === "hit") {
        integer(event.valueBytes, "hit valueBytes");
        observed.hits++;
      } else if (event.result === "miss" && event.valueBytes === null) {
        observed.misses++;
      } else fail("invalid lookup result");
      lookupNanoseconds[event.result] += event.lookupNanoseconds;
      const identity = `${event.key}/${event.result}`;
      observedLookups.set(identity, (observedLookups.get(identity) ?? 0) + 1);
      continue;
    }
    object(
      event,
      ["event", "key", "valueBytes", "result", "compileInterval"],
      "insert",
    );
    if (event.event !== "insert") fail("unknown event");
    key(event.key, "insert key");
    integer(event.valueBytes, "insert valueBytes");
    const bucket = buckets.find(
      ({ maximumValueBytes }) => event.valueBytes <= maximumValueBytes,
    );
    bucket.valueBytes += event.valueBytes;
    if (event.result?.kind === "stored") {
      object(
        event.result,
        ["kind", "tier", "displacedRecordBytes"],
        "stored result",
      );
      integer(event.result.tier, "stored tier");
      const expectedTier = header.tiers.findIndex(
        ({ recordLimitBytes }) =>
          event.valueBytes <= recordLimitBytes - header.recordHeaderBytes,
      );
      if (expectedTier !== event.result.tier)
        fail("stored record differs from tier layout");
      if (event.result.displacedRecordBytes !== null) {
        integer(event.result.displacedRecordBytes, "displacedRecordBytes");
        observed.evictions++;
        bucket.displacedRecordBytes += event.result.displacedRecordBytes;
      }
      observed.inserts++;
      bucket.stored++;
    } else if (event.result?.kind === "oversized") {
      object(event.result, ["kind"], "oversized result");
      if (event.valueBytes <= previousLimit - header.recordHeaderBytes)
        fail("oversized result fits a tier");
      observed.oversizedValues++;
      bucket.oversized++;
    } else fail("unknown insertion result");
    const interval = event.compileInterval;
    if (interval?.kind === "matched") {
      object(
        interval,
        ["kind", "precedingLookup", "wallNanoseconds", "threadCpuNanoseconds"],
        "matched interval",
      );
      integer(interval.wallNanoseconds, "wallNanoseconds");
      integer(interval.threadCpuNanoseconds, "threadCpuNanoseconds");
      if (!["hit", "miss"].includes(interval.precedingLookup))
        fail("invalid preceding lookup");
      const identity = `${event.key}/${interval.precedingLookup}`;
      const lookups = observedLookups.get(identity);
      if (lookups === undefined || lookups === 0)
        fail("matched insertion has no preceding lookup");
      observedLookups.set(identity, lookups - 1);
      if (interval.precedingLookup === "miss") {
        bucket.matchedMissIntervals++;
        bucket.missThreadCpuNanoseconds += interval.threadCpuNanoseconds;
      } else {
        bucket.matchedHitIntervals++;
        bucket.hitThreadCpuNanoseconds += interval.threadCpuNanoseconds;
      }
      bucket.compileWallNanoseconds += interval.wallNanoseconds;
      expensive.push(event);
      expensive.sort(
        (a, b) =>
          b.compileInterval.threadCpuNanoseconds -
          a.compileInterval.threadCpuNanoseconds,
      );
      if (expensive.length > 20) expensive.pop();
    } else {
      object(interval, ["kind"], "unmatched interval");
      if (interval.kind !== "unmatched") fail("unknown compilation interval");
      bucket.unmatchedIntervals++;
    }
  }
  for (const [name, value] of Object.entries(observed)) {
    if (completion.counters[name] !== value)
      fail(`${name} differs from completion counters`);
  }
  for (const value of Object.values(lookupNanoseconds))
    integer(value, "total lookup duration");
  for (const bucket of buckets)
    for (const value of Object.values(bucket))
      integer(value, "size bucket total");
  return {
    kind: "convex-wasm-incremental-cache-analysis-v1",
    traceSha256: createHash("sha256").update(bytes).digest("hex"),
    namespace: header.namespace,
    recordHeaderBytes: header.recordHeaderBytes,
    tiers: header.tiers,
    counters: completion.counters,
    lookupNanoseconds,
    sizeBuckets: buckets.filter(
      ({ stored, oversized }) => stored + oversized > 0,
    ),
    mostExpensiveInsertions: expensive,
  };
}
