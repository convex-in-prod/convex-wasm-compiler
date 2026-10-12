import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { rangeBindingContracts } from './range-binding-contracts.mjs';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const evaluate = String(function run(rangeBindings) {
  const rows = [];
  function capture(id, body) {
    const trace = [];
    try { rows.push({ id, trace, value: body(trace) }); }
    catch (error) { rows.push({ id, trace, error: error.name }); }
  }
  const locales = ['en-US', 'de-DE', 'fr-FR', 'ar-EG', 'hi-IN', 'ja-JP', 'pl-PL'];
  const profiles = [
    {}, { maximumFractionDigits: 0 }, { maximumSignificantDigits: 3 },
    { notation: 'scientific' }, { notation: 'engineering' },
    { notation: 'compact' }, { notation: 'compact', compactDisplay: 'long' },
    { style: 'currency', currency: 'USD' },
    { style: 'currency', currency: 'EUR', currencySign: 'accounting', signDisplay: 'always' },
    { style: 'currency', currency: 'JPY', currencyDisplay: 'name' },
    { style: 'unit', unit: 'meter', unitDisplay: 'long' },
    { style: 'unit', unit: 'percent' }, { style: 'percent' },
    { signDisplay: 'exceptZero' }, { signDisplay: 'negative' },
    { roundingIncrement: 5, minimumFractionDigits: 2, maximumFractionDigits: 2 },
    { minimumFractionDigits: 2, trailingZeroDisplay: 'stripIfInteger' },
    { numberingSystem: 'arab', signDisplay: 'always' },
  ];
  const ranges = [
    [1, 3], [1, 1], [1.001, 1.002], [3, 1], [-3, -1], [-1, 1],
    [-0, 0], [0, -0], [-0, -0], [0, 0], [1234.5, 6789.01],
    [-Infinity, Infinity], [Infinity, Infinity], [Infinity, -Infinity],
    [123456789012345678901n, 123456789012345678999n],
    ['9007199254740993.00001', '9007199254740993.00002'],
    ['1.005', 1.025], [1.005, '1.025'], [1n, 1], [1, 1n],
    ['0xff', '0x100'], ['1e-320', '2e-320'],
    [0.1 + 0.2, '0.3'], ['0.3', 0.1 + 0.2],
    [9007199254740992, '9007199254740993'], [null, true],
  ];
  for (const locale of locales) for (let p = 0; p < profiles.length; ++p) {
    const formatter = new Intl.NumberFormat(locale, profiles[p]);
    for (let n = 0; n < ranges.length; ++n) capture(locale + '/' + p + '/' + n, () => {
      const [start, end] = ranges[n];
      const format = formatter.formatRange(start, end);
      const parts = formatter.formatRangeToParts(start, end);
      return { format, parts, keys: parts.map(Object.keys),
        startParts: formatter.formatToParts(start), endParts: formatter.formatToParts(end),
        roundtrip: parts.map(part => part.value).join('') === format };
    });
  }
  rangeBindings('NumberFormat', capture);
  print(JSON.stringify({ rows }));
});
if (typeof globalThis.gc !== 'function') throw new Error('Run range reference with --expose-gc');
const source = `(${evaluate})(${rangeBindingContracts});\n`;
writeFileSync(new URL('ranges.js', root), source);
runInNewContext(source, { gc: globalThis.gc,
  print: line => writeFileSync(new URL('ranges-reference.json', root), line + '\n') });
writeFileSync(new URL('ranges-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
