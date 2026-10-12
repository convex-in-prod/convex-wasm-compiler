import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

function compare(change) {
  const directory = mkdtempSync(join(tmpdir(), 'intl-allocation-failures-'));
  try {
    const reference = { rows: [{ id: 'example', baseline: { text: '1–2' } }] };
    const actual = structuredClone(reference);
    actual.rows[0].baselineAllocationAttempts = 3;
    actual.rows[0].faults = ['Error', 'matched', 'RangeError'].map((outcome, index) => ({
      allocation: index + 1, attempts: index + 2, injected: true, outcome,
    }));
    const evidence = actual.rows[0].faults.map(fault => ({ allocationCase: 'example', allocationIndex: fault.allocation }));
    evidence.push({ lifecycleCleanup: true, icuRequestedBytes: 0, icuAllocationCount: 0 });
    change(actual, evidence);
    for (const [name, value] of [['reference', reference], ['actual', actual]])
      writeFileSync(join(directory, `allocation-failures-${name}.json`), JSON.stringify(value));
    writeFileSync(join(directory, 'allocation-failures-stderr.jsonl'), evidence.map(value => JSON.stringify(value)).join('\n'));
    return spawnSync(process.execPath, [fileURLToPath(new URL('compare-allocation-failures.mjs', import.meta.url))], {
      encoding: 'utf8', timeout: 10_000,
      env: { ...process.env, INTL_EXPERIMENT_URL: pathToFileURL(directory + '/').href },
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('accepts complete injection, recovery, baseline and cleanup evidence', () => {
  const result = compare(() => {});
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).injections, 3);
});

const rejections = [
  ['changed baseline', actual => { actual.rows[0].baseline.text = 'wrong'; }, /baseline differs/],
  ['missing case', actual => { actual.rows.pop(); }, /Incomplete allocation-failure cases/],
  ['partial sweep', actual => { actual.rows[0].faults.pop(); }, /Incomplete allocation failure sweep/],
  ['uninjected fault', actual => { actual.rows[0].faults[0].injected = false; }, /Incomplete allocation-failure evidence/],
  ['skipped index', actual => { actual.rows[0].faults[1].allocation = 3; }, /Incomplete allocation-failure evidence/],
  ['impossible attempt count', actual => { actual.rows[0].faults[2].attempts = 2; }, /Incomplete allocation-failure evidence/],
  ['invalid outcome', actual => { actual.rows[0].faults[2].outcome = 'SyntaxError'; }, /Incomplete allocation-failure evidence/],
  ['missing injection log', (_actual, evidence) => { evidence.splice(1, 1); }, /Incomplete allocation-failure evidence/],
  ['extra injection log', (_actual, evidence) => { evidence.splice(3, 0, { allocationCase: 'example', allocationIndex: 4 }); }, /Unexpected allocation-failure evidence/],
  ['retained allocation', (_actual, evidence) => { evidence.at(-1).icuAllocationCount = 1; }, /remain after failure cleanup/],
];
for (const [name, change, error] of rejections) test('rejects ' + name, () => {
  const result = compare(change);
  assert.equal(result.status, 1);
  assert.match(result.stderr, error);
});
