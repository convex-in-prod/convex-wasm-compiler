import { createReadStream, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { isDeepStrictEqual } from 'node:util';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const name = process.argv[2] ?? 'bindings';
if (!['bindings', 'construction', 'ranges', 'date-ranges', 'collator', 'bootstrap', 'hardening'].includes(name)) throw new Error('Unknown lifecycle corpus');
const expected = JSON.parse(readFileSync(new URL(name + '-reference.json', root)));
const evidence = readFileSync(new URL('lifecycle-stderr.jsonl', root), 'utf8').trim().split('\n').map(JSON.parse);
if (evidence.length !== 33) throw new Error('Incomplete lifecycle evidence');
const allocatedBytes = [];
const icuRequestedBytes = [];
const icuAllocationCount = [];
let cycle = 0;
// Keep one corpus in memory at a time; large range matrices produce hundreds
// of megabytes across the sixteen runtime outputs.
const lines = createInterface({ input: createReadStream(new URL('lifecycle-actual.jsonl', root)), crlfDelay: Infinity });
for await (const line of lines) {
  if (cycle >= 16) throw new Error('Incomplete lifecycle evidence');
  if (!isDeepStrictEqual(JSON.parse(line), expected)) throw new Error('Lifecycle output differs at cycle ' + cycle);
  const row = evidence[cycle * 2 + 1];
  if (row.lifecycleCycle !== cycle || !Number.isSafeInteger(row.nativeAllocatedBytes) || row.nativeAllocatedBytes <= 0)
    throw new Error('Invalid lifecycle allocation evidence');
  allocatedBytes.push(row.nativeAllocatedBytes);
  for (const key of ['icuRequestedBytes', 'icuAllocationCount'])
    if (!Number.isSafeInteger(row[key]) || row[key] < 0) throw new Error('Invalid ICU allocation evidence');
  icuRequestedBytes.push(row.icuRequestedBytes);
  icuAllocationCount.push(row.icuAllocationCount);
  ++cycle;
}
if (cycle !== 16) throw new Error('Incomplete lifecycle evidence');
// malloc counts rounded chunks. Identical workloads can alternate between
// allocation layouts, so accept only an exactly repeating final pattern, with
// at least two repetitions. No byte tolerance conceals gradual growth.
const tail = allocatedBytes.slice(8);
const allocatorPeriod = [1, 2, 4].find(period => tail.every((value, index) => value === tail[index % period]));
if (allocatorPeriod === undefined) throw new Error('Native allocations do not stabilize across the final eight cycles');
for (const values of [icuRequestedBytes, icuAllocationCount])
  if (!values.slice(8).every(value => value === values[8])) throw new Error('ICU live allocations do not stabilize');
const cleanup = evidence[32];
if (cleanup.lifecycleCleanup !== true || cleanup.icuRequestedBytes !== 0 || cleanup.icuAllocationCount !== 0)
  throw new Error('ICU allocations remain after cleanup');
const result = { cycles: cycle, casesPerCycle: expected.rows.length,
  matchingExecutions: cycle * expected.rows.length, allocatedBytes,
  allocatorPeriod, icuRequestedBytes, icuAllocationCount, cleanup };
writeFileSync(new URL('lifecycle-comparison.json', root), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result));
