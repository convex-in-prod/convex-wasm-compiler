import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { finished } from 'node:stream/promises';
import { runProbe } from './probe-wasi.mjs';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
if (typeof global.gc !== 'function') throw new Error('Run with --expose-gc to bound discarded instance retention');
const bytes = readFileSync(new URL('cold-allocations-standalone.wasm', root));
const module = await WebAssembly.compile(bytes);
const reference = JSON.parse(readFileSync(new URL('cold-allocations-reference.json', root)));
const baseline = runProbe(module, exports => exports.intl_probe_cold_allocation_configure(0), 'intl_probe_cold_allocations_run');
if (baseline.error) throw baseline.error;
assert.equal(baseline.status, 0);
assert.deepEqual(JSON.parse(baseline.stdout), reference);
const baselineEvidence = baseline.stderr.trim().split('\n').map(JSON.parse);
assert.equal(baselineEvidence.length, 3);
assert.deepEqual(baselineEvidence[2], { lifecycleCleanup: true, icuRequestedBytes: 0, icuAllocationCount: 0 });
const attempts = baselineEvidence[1].coldAllocationAttempts;
assert.ok(Number.isSafeInteger(attempts) && attempts > 0);
// Warm-operation tests cover every allocation. Cold setup enumerates thousands
// of locale resources through the same allocator; sample its middle uniformly
// and exhaust both ends without turning integration into another ICU audit.
const indices = new Set();
for (let index = 1; index <= Math.min(128, attempts); ++index) {
  indices.add(index);
  indices.add(attempts + 1 - index);
}
for (let index = 1; index < 128; ++index) indices.add(Math.ceil(attempts * index / 128));
const selectedIndices = [...indices].sort((a, b) => a - b);
console.log(JSON.stringify({ coldAllocationAttempts: attempts, selected: selectedIndices.length }));
const log = createWriteStream(new URL('cold-allocation-traps-evidence.jsonl', root));
try {
  for (const allocationIndex of selectedIndices) {
    const result = runProbe(module, exports => exports.intl_probe_cold_allocation_configure(allocationIndex), 'intl_probe_cold_allocations_run');
    assert.ok(result.error instanceof WebAssembly.RuntimeError, 'Expected an uncatchable Wasm trap');
    assert.equal(result.error.message, 'unreachable');
    assert.equal(result.status, undefined);
    const evidence = result.stderr.trim().split('\n').map(JSON.parse);
    assert.deepEqual(evidence.at(-1), { icuAllocationFailure: true, allocationIndex }, 'Trap must follow the injected failure immediately');
    // Allocations after the JS result or version report may also be swept. Only
    // exact complete baseline output and its prefix evidence are valid then.
    if (result.stdout.length !== 0) assert.deepEqual(JSON.parse(result.stdout), reference);
    assert.ok(evidence.length <= 2);
    if (evidence.length === 2) assert.equal(evidence[0].icu, baselineEvidence[0].icu);
    log.write(JSON.stringify({ allocationIndex, outcome: 'allocation-trap', evidence }) + '\n');
    global.gc();
  }
} finally { log.end(); await finished(log); }
const summary = { wasmSha256: createHash('sha256').update(bytes).digest('hex'),
  allocationAttempts: attempts, injections: selectedIndices.length, selectedIndices,
  baselineMemoryBytes: baseline.memoryBytes, cleanup: baselineEvidence[2],
  scope: 'Sampled cold runtime and first formatter ICU allocations in fresh Node-hosted Wasm instances; every trapped instance is discarded.' };
writeFileSync(new URL('cold-allocation-traps-comparison.json', root), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify(summary));
