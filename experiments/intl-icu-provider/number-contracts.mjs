import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const locales = ['en-US', 'de-DE', 'fr-FR', 'ar-EG', 'hi-IN', 'ja-JP', 'pl-PL'];
const values = ['0', '-0', '1', '-1', '1.005', '-1.005', '1.025', '-1.025',
  '0.0001234', '-0.0001234', '1234.567', '1234567.89', 'NaN', 'Infinity', '-Infinity'];
const profiles = [
  {},
  ...['scientific', 'engineering', 'compact'].map(notation => ({ notation })),
  { notation: 'compact', compactDisplay: 'long' },
  ...['auto', 'always', 'min2', false, true, 'false', 'true'].map(useGrouping => ({ useGrouping })),
  ...['auto', 'always', 'never', 'exceptZero', 'negative'].map(signDisplay => ({ signDisplay })),
  ...['USD', 'EUR', 'JPY', 'KWD', 'CLP'].map(currency => ({ style: 'currency', currency })),
  ...['code', 'name', 'narrowSymbol'].map(currencyDisplay => ({ style: 'currency', currency: 'USD', currencyDisplay })),
  { style: 'currency', currency: 'EUR', currencySign: 'accounting', signDisplay: 'always' },
  { style: 'unit', unit: 'kilometer-per-hour', unitDisplay: 'long', maximumFractionDigits: 1 },
  { style: 'unit', unit: 'celsius', unitDisplay: 'narrow', minimumFractionDigits: 2 },
  { style: 'percent', maximumFractionDigits: 1 },
  { minimumIntegerDigits: 4, minimumSignificantDigits: 2, maximumSignificantDigits: 5 },
  { numberingSystem: 'arab' },
  { numberingSystem: 'hanidec' },
  { numberingSystem: 'foobar' },
  ...['ceil', 'floor', 'expand', 'trunc', 'halfCeil', 'halfFloor', 'halfExpand', 'halfTrunc', 'halfEven']
    .map(roundingMode => ({ roundingMode, maximumFractionDigits: 2 })),
  ...['morePrecision', 'lessPrecision'].map(roundingPriority => ({
    roundingPriority, minimumFractionDigits: 1, maximumFractionDigits: 2,
    minimumSignificantDigits: 2, maximumSignificantDigits: 3,
  })),
  { roundingIncrement: 5, minimumFractionDigits: 2, maximumFractionDigits: 2 },
  { roundingIncrement: 25, minimumFractionDigits: 2, maximumFractionDigits: 2 },
  { trailingZeroDisplay: 'stripIfInteger', minimumFractionDigits: 2, maximumFractionDigits: 2 },
];
const cases = [];
for (const locale of locales) {
  for (let profile = 0; profile < profiles.length; ++profile) {
    for (const value of values) cases.push({ id: `${locale}/${profile}/${value}`, locale,
      options: profiles[profile], value, input: 'number' });
  }
}
for (const options of [
  { roundingIncrement: 3 }, { roundingIncrement: 5, maximumFractionDigits: 3 },
  { roundingIncrement: 5, maximumSignificantDigits: 3 }, { maximumFractionDigits: 101 },
  { minimumSignificantDigits: 0 }, { roundingMode: 'invalid' }, { useGrouping: 'invalid' },
  { signDisplay: 'invalid' }, { numberingSystem: '' }, { style: 'currency' },
  { style: 'unit', unit: 'invalid' }, { currency: 'US' },
  { style: 'unit', unit: '' }, { unit: '' },
]) cases.push({ id: `invalid/${cases.length}`, locale: 'en-US', options, value: '1', input: 'number' });
for (const value of ['9007199254740993', '-9007199254740993', '12345678901234567890.123456789',
  '0x20000000000001', '0b100000000000000000000000000000000000000000000000000001',
  '  -0  ', '\u00a01234567890123456789\u2029', '1e309', '1e-400', '', 'invalid']) {
  cases.push({ id: `string/${cases.length}`, locale: 'en-US', options: { maximumFractionDigits: 20 }, value, input: 'string' });
}
for (const value of ['9007199254740993', '-123456789012345678901234567890']) {
  cases.push({ id: `bigint/${cases.length}`, locale: 'en-US', options: {}, value, input: 'bigint' });
}
cases.push({ id: 'locale-list', locale: ['zz-ZZ', 'de-DE'], options: {}, value: '1234.5', input: 'number' });
cases.push({ id: 'locale-extension', locale: 'en-US-u-nu-arab', options: {}, value: '1234.5', input: 'number' });

const evaluate = String(function run(cases) {
  const rows = [];
  for (const row of cases) {
    try {
      const f = new Intl.NumberFormat(row.locale, row.options);
      const value = row.input === 'number' ? Number(row.value)
        : row.input === 'bigint' ? BigInt(row.value) : row.value;
      rows.push({ id: row.id, format: f.format(value), parts: f.formatToParts(value), resolved: f.resolvedOptions() });
    } catch (error) {
      rows.push({ id: row.id, error: { name: error.name, message: error.message } });
    }
  }
  print(JSON.stringify({ rows }));
});
const source = `(${evaluate})(${JSON.stringify(cases)});\n`;
writeFileSync(new URL('contracts.js', root), source);
writeFileSync(new URL('contracts-corpus.json', root), JSON.stringify({ versions: process.versions, cases }, null, 2) + '\n');
runInNewContext(source, { print: line => writeFileSync(new URL('contracts-reference.json', root), line + '\n') });
console.log(JSON.stringify({ cases: cases.length, profiles: profiles.length }));
