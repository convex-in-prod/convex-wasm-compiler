import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const locales = ['en-US', 'en-GB', 'de-DE', 'ar-EG', 'ja-JP', 'th-TH', 'zh-CN'];
const values = [0, Date.UTC(2024, 1, 29, 0, 5, 7, 123), Date.UTC(2024, 1, 29, 12, 5, 7, 987),
  Date.UTC(2024, 2, 10, 6, 59, 59), Date.UTC(2024, 2, 10, 7), Date.UTC(2024, 10, 3, 6),
  Date.UTC(1500, 0, 1)];
const profiles = [
  {}, { month: 'long', day: 'numeric' }, { minute: '2-digit' },
  ...['h11', 'h12', 'h23', 'h24'].map(hourCycle => ({ hourCycle, hour: '2-digit', minute: '2-digit' })),
  { hour12: true, hour: 'numeric' }, { hour12: false, hour: 'numeric' },
  { dateStyle: 'full' }, { timeStyle: 'short' }, { dateStyle: 'long', timeStyle: 'medium' },
  ...['h11', 'h12', 'h23', 'h24'].map(hourCycle => ({ hourCycle, dateStyle: 'short', timeStyle: 'long' })),
  { hour: 'numeric', minute: 'numeric', second: 'numeric', fractionalSecondDigits: 3 },
  { fractionalSecondDigits: 2 }, { dayPeriod: 'long', hour: 'numeric', hour12: true },
  { calendar: 'japanese', era: 'long', year: 'numeric', month: 'long', day: 'numeric' },
  { calendar: 'chinese', year: 'numeric', month: 'long', day: 'numeric' },
  { calendar: 'foobar', year: 'numeric', month: 'numeric', day: 'numeric' },
  { numberingSystem: 'arab', year: 'numeric', month: 'numeric', day: 'numeric' },
  { numberingSystem: 'foobar', year: 'numeric', month: 'numeric', day: 'numeric' },
  { timeZone: 'America/New_York', year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', timeZoneName: 'long' },
  { timeZone: '+02:30', hour: 'numeric', minute: '2-digit' },
];
const cases = [];
for (const locale of locales) for (let profile = 0; profile < profiles.length; ++profile) {
  for (let i = 0; i < values.length; ++i) cases.push({ id: `${locale}/${profile}/${i}`, locale,
    options: { timeZone: 'UTC', ...profiles[profile] }, value: values[i] });
}
for (const options of [{ hourCycle: 'bad' }, { timeZone: 'bad' }, { calendar: '' },
  { fractionalSecondDigits: 4 }, { dateStyle: 'short', year: 'numeric' }]) {
  cases.push({ id: `invalid/${cases.length}`, locale: 'en-US', options, value: 0 });
}
cases.push({ id: 'locale-list', locale: ['zz-ZZ', 'de-DE'], options: { timeZone: 'UTC', month: 'long' }, value: 0 });
cases.push({ id: 'locale-extension', locale: 'en-US-u-hc-h23-ca-japanese-nu-arab',
  options: { timeZone: 'UTC', year: 'numeric', hour: 'numeric' }, value: 0 });

const evaluate = String(function run(cases) {
  const rows = [];
  for (const row of cases) {
    try {
      const f = new Intl.DateTimeFormat(row.locale, row.options);
      rows.push({ id: row.id, format: f.format(row.value), parts: f.formatToParts(row.value), resolved: f.resolvedOptions() });
    } catch (error) {
      rows.push({ id: row.id, error: { name: error.name, message: error.message } });
    }
  }
  print(JSON.stringify({ rows }));
});
const source = `(${evaluate})(${JSON.stringify(cases)});\n`;
writeFileSync(new URL('dates.js', root), source);
writeFileSync(new URL('dates-corpus.json', root), JSON.stringify({ versions: process.versions, cases }, null, 2) + '\n');
runInNewContext(source, { print: line => writeFileSync(new URL('dates-reference.json', root), line + '\n') });
console.log(JSON.stringify({ cases: cases.length, profiles: profiles.length }));
