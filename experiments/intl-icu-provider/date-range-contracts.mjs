import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { rangeBindingContracts } from './range-binding-contracts.mjs';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
process.env.TZ = 'UTC';
const evaluate = String(function run(rangeBindings) {
  const rows = [];
  function capture(id, body) {
    const trace = [];
    try { rows.push({ id, trace, value: body(trace) }); }
    catch (error) { rows.push({ id, trace, error: error.name }); }
  }
  const locales = ['en-US', 'de-DE', 'fr-FR', 'ar-EG', 'hi-IN', 'ja-JP', 'pl-PL'];
  const zones = ['UTC', 'America/New_York', 'Europe/Paris', '+05:45'];
  const profiles = [
    {}, { year: 'numeric', month: 'long', day: 'numeric' },
    { weekday: 'short', month: 'short', day: '2-digit' },
    { month: 'narrow', day: 'numeric' }, { year: '2-digit' },
    { minute: '2-digit' }, { fractionalSecondDigits: 3 },
    { hour: 'numeric', dayPeriod: 'long' },
    ...['h11', 'h12', 'h23', 'h24'].map(hourCycle => ({ hour: '2-digit', minute: '2-digit', hourCycle })),
    ...['full', 'long', 'medium', 'short'].map(dateStyle => ({ dateStyle })),
    { timeStyle: 'full' }, { timeStyle: 'short', hour12: false },
    { dateStyle: 'full', timeStyle: 'long' }, { dateStyle: 'short', timeStyle: 'short', hour12: true },
    { year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric', fractionalSecondDigits: 3 },
    { hour: 'numeric', timeZoneName: 'longOffset' },
    ...['japanese', 'hebrew', 'chinese', 'islamic'].map(calendar => ({ calendar, year: 'numeric', month: 'long', day: 'numeric', era: 'short' })),
    { year: 'numeric', month: 'numeric', day: 'numeric', numberingSystem: 'arab' },
  ];
  const base = 1577836800000;
  const ranges = [[0, 0], [0, 1], [-0.9, 0.9], [base, base + 1234],
    [base, base + 3600000], [base, base + 86400000], [base, base + 32 * 86400000],
    [base + 32 * 86400000, base],
    [1583650799000, 1583650800000], [1604210399000, 1604210400000],
    [-14831769600000, -14831726400000], [-62167219200000, -62135596800000],
    [8.64e15 - 86400000, 8.64e15], [null, true], [String(base), new Date(base + 86400000)]];
  for (const locale of locales) for (const timeZone of zones) for (let p = 0; p < profiles.length; ++p) {
    const formatter = new Intl.DateTimeFormat(locale, { ...profiles[p], timeZone });
    for (let n = 0; n < ranges.length; ++n) capture(locale + '/' + timeZone + '/' + p + '/' + n, () => {
      const [start, end] = ranges[n];
      const format = formatter.formatRange(start, end);
      const parts = formatter.formatRangeToParts(start, end);
      return { format, parts, keys: parts.map(Object.keys),
        startParts: formatter.formatToParts(start), endParts: formatter.formatToParts(end),
        roundtrip: parts.map(part => part.value).join('') === format };
    });
  }
  rangeBindings('DateTimeFormat', capture);
  print(JSON.stringify({ rows }));
});
if (typeof globalThis.gc !== 'function') throw new Error('Run date-range reference with --expose-gc');
const source = `(${evaluate})(${rangeBindingContracts});\n`;
writeFileSync(new URL('date-ranges.js', root), source);
runInNewContext(source, { gc: globalThis.gc,
  print: line => writeFileSync(new URL('date-ranges-reference.json', root), line + '\n') });
writeFileSync(new URL('date-ranges-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
