import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { runProbe } from './probe-wasi.mjs';
import { finished } from 'node:stream/promises';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
if (typeof global.gc !== 'function') throw new Error('Run with --expose-gc to bound discarded instance retention');
const bytes = readFileSync(new URL('allocation-failures-standalone.wasm', root));
const module = await WebAssembly.compile(bytes);
const reference = JSON.parse(readFileSync(new URL('allocation-failures-reference.json', root)));
assert.equal(reference.rows.length, 6, 'Incomplete allocation-failure reference');
const log = createWriteStream(new URL('allocation-traps-evidence.jsonl', root));

function run(caseIndex, allocationIndex) {
  const result = runProbe(module,
    exports => exports.intl_probe_allocation_failure_configure(caseIndex, allocationIndex),
    'intl_probe_allocation_failures_run');
  const { status, error } = result;
  const output = result.stdout.trim().split('\n').map(JSON.parse);
  const evidence = result.stderr.trim().split('\n').map(JSON.parse);
  assert.equal(output.length, 1, 'Missing or extra baseline output');
  const expected = reference.rows[caseIndex];
  assert.equal(output[0].id, expected.id);
  assert.deepEqual(output[0].baseline, expected.baseline);
  const attempts = output[0].baselineAllocationAttempts;
  assert.ok(Number.isSafeInteger(attempts) && attempts > 0);
  if (allocationIndex === 0) {
    if (error) throw error;
    assert.equal(status, 0);
    assert.deepEqual(evidence.at(-1), { lifecycleCleanup: true, icuRequestedBytes: 0, icuAllocationCount: 0 });
  } else {
    assert.ok(error instanceof WebAssembly.RuntimeError, 'Expected an uncatchable Wasm trap');
    assert.equal(error.message, 'unreachable');
    assert.equal(status, undefined);
    assert.deepEqual(evidence, [
      { allocationCase: expected.id, allocationIndex },
      { icuAllocationFailure: true, allocationIndex },
    ], 'Trap must immediately follow the selected ICU allocation failure');
  }
  log.write(JSON.stringify({ caseIndex, allocationIndex, id: expected.id, attempts,
    outcome: allocationIndex === 0 ? 'matched' : 'allocation-trap', evidence }) + '\n');
  // No further guest execution or cleanup follows a trap. Dropping every
  // reference discards the instance; the next test creates independent state.
  return attempts;
}

const cases = [];
try {
  for (let caseIndex = 0; caseIndex < reference.rows.length; ++caseIndex) {
    const attempts = run(caseIndex, 0);
    for (let allocationIndex = 1; allocationIndex <= attempts; ++allocationIndex) {
      assert.equal(run(caseIndex, allocationIndex), attempts, 'Fresh baseline allocation count changed');
      if (allocationIndex % 4 === 0) global.gc();
    }
    global.gc();
    cases.push({ id: reference.rows[caseIndex].id, injections: attempts });
    console.log(JSON.stringify(cases.at(-1)));
  }
} finally { log.end(); await finished(log); }
const summary = {
  wasmSha256: createHash('sha256').update(bytes).digest('hex'),
  cases, injections: cases.reduce((sum, row) => sum + row.injections, 0),
  scope: 'Warm ICU allocation failures in fresh Node-hosted Wasm instances; trapped instances are discarded.',
};
writeFileSync(new URL('allocation-traps-comparison.json', root), JSON.stringify(summary, null, 2) + '\n');
