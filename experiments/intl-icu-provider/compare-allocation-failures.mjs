import { readFileSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const reference = JSON.parse(readFileSync(new URL('allocation-failures-reference.json', root)));
const actual = JSON.parse(readFileSync(new URL('allocation-failures-actual.json', root)));
const evidence = readFileSync(new URL('allocation-failures-stderr.jsonl', root), 'utf8').trim().split('\n').map(JSON.parse);
if (actual.rows.length !== reference.rows.length || actual.rows.length === 0)
  throw new Error('Incomplete allocation-failure cases');
const cases = [];
const injections = evidence.filter(row => Object.hasOwn(row, 'allocationCase'));
let nextInjection = 0;
for (let index = 0; index < reference.rows.length; ++index) {
  const expected = reference.rows[index];
  const row = actual.rows[index];
  if (row.id !== expected.id || !isDeepStrictEqual(row.baseline, expected.baseline))
    throw new Error('Allocation-failure baseline differs: ' + expected.id);
  if (!Number.isSafeInteger(row.baselineAllocationAttempts) || row.baselineAllocationAttempts <= 0 ||
      row.faults.length !== row.baselineAllocationAttempts)
    throw new Error('Incomplete allocation failure sweep: ' + row.id);
  const outcomes = {};
  for (let position = 0; position < row.faults.length; ++position) {
    const fault = row.faults[position];
    const injection = injections[nextInjection++];
    if (fault.allocation !== position + 1 || fault.injected !== true ||
        !Number.isSafeInteger(fault.attempts) || fault.attempts < fault.allocation ||
        !['matched', 'Error', 'RangeError', 'TypeError'].includes(fault.outcome) ||
        injection?.allocationCase !== row.id || injection.allocationIndex !== fault.allocation)
      throw new Error('Incomplete allocation-failure evidence: ' + row.id);
    outcomes[fault.outcome] = (outcomes[fault.outcome] ?? 0) + 1;
  }
  cases.push({ id: row.id, injections: row.faults.length, outcomes });
}
if (nextInjection !== injections.length) throw new Error('Unexpected allocation-failure evidence');
const cleanup = evidence.at(-1);
if (cleanup.lifecycleCleanup !== true || cleanup.icuRequestedBytes !== 0 || cleanup.icuAllocationCount !== 0)
  throw new Error('ICU allocations remain after failure cleanup');
const result = { cases, injections: nextInjection, cleanup };
writeFileSync(new URL('allocation-failures-comparison.json', root), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result));
