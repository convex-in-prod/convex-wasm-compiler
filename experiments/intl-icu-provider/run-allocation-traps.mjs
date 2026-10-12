import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { WASI } from 'node:wasi';
import { finished } from 'node:stream/promises';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
if (typeof global.gc !== 'function') throw new Error('Run with --expose-gc to bound discarded instance retention');
const bytes = readFileSync(new URL('allocation-failures-standalone.wasm', root));
const module = await WebAssembly.compile(bytes);
const reference = JSON.parse(readFileSync(new URL('allocation-failures-reference.json', root)));
assert.equal(reference.rows.length, 6, 'Incomplete allocation-failure reference');
const log = createWriteStream(new URL('allocation-traps-evidence.jsonl', root));

function run(caseIndex, allocationIndex) {
  const stdout = [], stderr = [];
  const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
  let instance;
  const imports = wasi.getImportObject();
  // Capture writes immediately: a Wasm trap bypasses guest stdio cleanup.
  imports.wasi_snapshot_preview1.fd_write = (fd, vectors, count, written) => {
    if (fd !== 1 && fd !== 2) return 8;
    const data = new DataView(instance.exports.memory.buffer);
    let total = 0;
    for (let index = 0; index < count; ++index) {
      const pointer = data.getUint32(vectors + index * 8, true);
      const length = data.getUint32(vectors + index * 8 + 4, true);
      const value = Buffer.from(new Uint8Array(instance.exports.memory.buffer, pointer, length));
      (fd === 1 ? stdout : stderr).push(value);
      total += length;
    }
    data.setUint32(written, total, true);
    return 0;
  };
  imports.env = { emscripten_notify_memory_growth() {}, __syscall_unlinkat() { return -2; } };
  instance = new WebAssembly.Instance(module, imports);
  wasi.initialize(instance);
  instance.exports.intl_probe_allocation_failure_configure(caseIndex, allocationIndex);
  let status, error;
  try { status = instance.exports.intl_probe_allocation_failures_run(); }
  catch (caught) { error = caught; }
  const output = Buffer.concat(stdout).toString('utf8').trim().split('\n').map(JSON.parse);
  const evidence = Buffer.concat(stderr).toString('utf8').trim().split('\n').map(JSON.parse);
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
