import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

function compare(change) {
  const directory = mkdtempSync(join(tmpdir(), 'intl-lifecycle-'));
  try {
    const expected = { rows: [{ id: 'example', value: '1–2' }] };
    const outputs = Array.from({ length: 16 }, () => structuredClone(expected));
    const evidence = [];
    for (let cycle = 0; cycle < 16; ++cycle) evidence.push({ icu: '78.2' }, {
      lifecycleCycle: cycle, nativeAllocatedBytes: 1000 + (cycle % 2) * 8,
      icuRequestedBytes: 500, icuAllocationCount: 5,
    });
    evidence.push({ lifecycleCleanup: true, icuRequestedBytes: 0, icuAllocationCount: 0 });
    change(outputs, evidence);
    writeFileSync(join(directory, 'ranges-reference.json'), JSON.stringify(expected));
    writeFileSync(join(directory, 'lifecycle-actual.jsonl'), outputs.map(value => JSON.stringify(value)).join('\n'));
    writeFileSync(join(directory, 'lifecycle-stderr.jsonl'), evidence.map(value => JSON.stringify(value)).join('\n'));
    return spawnSync(process.execPath, [fileURLToPath(new URL('compare-lifecycle.mjs', import.meta.url)), 'ranges'], {
      encoding: 'utf8', timeout: 10_000,
      env: { ...process.env, INTL_EXPERIMENT_URL: pathToFileURL(directory + '/').href },
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('accepts repeated allocator layouts with stable ICU payload and complete cleanup', () => {
  const result = compare(() => {});
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).allocatorPeriod, 2);
});

for (const field of ['nativeAllocatedBytes', 'icuRequestedBytes', 'icuAllocationCount']) {
  test('rejects retained growth in ' + field, () => {
    const result = compare((_outputs, evidence) => {
      for (let cycle = 0; cycle < 16; ++cycle) evidence[cycle * 2 + 1][field] += cycle;
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /do not stabilize/);
  });
}

test('rejects ICU allocations surviving cleanup', () => {
  const result = compare((_outputs, evidence) => { evidence[32].icuAllocationCount = 1; });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /remain after cleanup/);
});

test('rejects changed output in a later runtime', () => {
  const result = compare(outputs => { outputs[15].rows[0].value = 'wrong'; });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /output differs at cycle 15/);
});
