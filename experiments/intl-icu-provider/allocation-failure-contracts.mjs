import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
process.env.TZ = 'UTC';
const evaluate = String(function run() {
  const rows = [];
  const operations = [
    ['number', () => {
      const f = new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR', notation: 'compact', roundingMode: 'halfEven' });
      return { resolved: f.resolvedOptions(), text: f.format('123456.789'), parts: f.formatToParts(123456.789) };
    }],
    ['number-range', () => {
      const f = new Intl.NumberFormat('ar-EG', { style: 'unit', unit: 'meter-per-second', maximumFractionDigits: 2 });
      return { text: f.formatRange(1.234, 5.678), parts: f.formatRangeToParts(1.234, 5.678) };
    }],
    ['date', () => {
      const f = new Intl.DateTimeFormat('ja-JP-u-ca-japanese', { dateStyle: 'full', timeStyle: 'long', timeZone: 'UTC' });
      return { resolved: f.resolvedOptions(), text: f.format(1577836800000), parts: f.formatToParts(1577836800000) };
    }],
    ['date-range', () => {
      const f = new Intl.DateTimeFormat('en-US', { dateStyle: 'full', timeStyle: 'short', timeZone: 'America/New_York' });
      return { text: f.formatRange(1577836800000, 1577923200000), parts: f.formatRangeToParts(1577836800000, 1577923200000) };
    }],
    ['collator', () => {
      const f = new Intl.Collator('de-u-co-phonebk', { numeric: true, caseFirst: 'upper', sensitivity: 'base' });
      return { resolved: f.resolvedOptions(), compared: f.compare('ä2', 'ae10') };
    }],
    ['canonical', () => Intl.getCanonicalLocales(['EN-latn-us-u-ca-gregory', 'sh-RS', 'en-x-' + Array(32).fill('abcdefgh').join('-')])],
  ];
  const selection = typeof icuAllocationSelection === 'function' ? icuAllocationSelection() : undefined;
  if (selection !== undefined) {
    if (!Number.isInteger(selection.caseIndex) || selection.caseIndex < 0 || selection.caseIndex >= operations.length)
      throw new Error('Invalid allocation case selection');
    const [id, operation] = operations[selection.caseIndex];
    const expected = JSON.stringify(operation());
    gc();
    icuAllocationFault(0);
    if (JSON.stringify(operation()) !== expected) throw new Error('Warm baseline differs: ' + id);
    const baseline = icuAllocationFault(0);
    if (baseline.attempts === 0) throw new Error('No ICU allocations in case: ' + id);
    gc();
    print(JSON.stringify({ id, baseline: JSON.parse(expected), baselineAllocationAttempts: baseline.attempts }));
    if (selection.allocationIndex === 0) return;
    if (selection.allocationIndex > baseline.attempts) throw new Error('Selected allocation is out of range');
    icuAllocationCase(id, selection.allocationIndex);
    icuAllocationFault(selection.allocationIndex);
    operation();
    throw new Error('Allocation exhaustion did not trap');
  }
  for (const [id, operation] of operations) {
    const expected = JSON.stringify(operation());
    const faults = [];
    let baselineAllocationAttempts = 0;
    if (typeof icuAllocationFault === 'function') {
      gc();
      icuAllocationFault(0);
      if (JSON.stringify(operation()) !== expected) throw new Error('Warm baseline differs: ' + id);
      const baseline = icuAllocationFault(0);
      if (baseline.attempts === 0) throw new Error('No ICU allocations in case: ' + id);
      baselineAllocationAttempts = baseline.attempts;
      gc();
      for (let allocation = 1; allocation <= baseline.attempts; ++allocation) {
        let output;
        let errorName;
        // Reporting precedes arming so a trap identifies the exact operation
        // and allocation even when the engine cannot return a JS exception.
        icuAllocationCase(id, allocation);
        icuAllocationFault(allocation);
        try { output = JSON.stringify(operation()); }
        catch (error) { errorName = error.name; }
        const evidence = icuAllocationFault(0);
        if (!evidence.injected) throw new Error('Fault did not reach an allocation: ' + id + '/' + allocation);
        if (errorName === undefined && output !== expected) {
          print(JSON.stringify({ failure: { id, allocation, expected: JSON.parse(expected), actual: JSON.parse(output) } }));
          throw new Error('Allocation failure changed output: ' + id + '/' + allocation);
        }
        if (errorName !== undefined && !['Error', 'RangeError', 'TypeError'].includes(errorName))
          throw new Error('Unexpected allocation failure class: ' + id + '/' + allocation + '/' + errorName);
        gc();
        if (JSON.stringify(operation()) !== expected)
          throw new Error('Allocation failure broke recovery: ' + id + '/' + allocation);
        gc();
        faults.push({ allocation, attempts: evidence.attempts, injected: evidence.injected,
          outcome: errorName === undefined ? 'matched' : errorName });
      }
    }
    rows.push({ id, baseline: JSON.parse(expected), baselineAllocationAttempts, faults });
  }
  print(JSON.stringify({ rows }));
});
const source = `(${evaluate})();\n`;
writeFileSync(new URL('allocation-failures.js', root), source);
runInNewContext(source, { print: line => writeFileSync(new URL('allocation-failures-reference.json', root), line + '\n') });
writeFileSync(new URL('allocation-failures-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
