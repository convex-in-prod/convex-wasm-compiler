import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

process.env.TZ = 'UTC';
if (new Intl.NumberFormat().resolvedOptions().locale !== 'en-US')
  throw new Error('Run the bootstrap reference with LANG=en_US.UTF-8');
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const evaluate = String(function run() {
  const rows = [];
  function capture(id, body) {
    rows.push({ id, value: body() });
  }
  for (const service of ['NumberFormat', 'DateTimeFormat', 'Collator']) {
    capture(service + '/no-arguments', () => new Intl[service]().resolvedOptions());
    const locales = [undefined, [], ['zz-ZZ'], ['und'], 'fr-FR', ['zz-ZZ', 'ja-JP']];
    for (let i = 0; i < locales.length; ++i) {
      const locale = locales[i];
      capture(service + '/locale/' + i, () => {
        const formatter = new Intl[service](locale);
        return {
          resolved: formatter.resolvedOptions(),
          output: service === 'Collator' ? formatter.compare('café', 'cafe')
            : formatter.format(service === 'NumberFormat' ? 1234567.89 : 0),
        };
      });
    }
  }
  const profiles = [undefined, {}, { dateStyle: 'full', timeStyle: 'long' },
    { hour: 'numeric', minute: 'numeric', timeZoneName: 'long' },
    { calendar: 'japanese', era: 'short', year: 'numeric', month: 'long' },
    { timeZone: 'America/New_York', dateStyle: 'full', timeStyle: 'long' }];
  for (let i = 0; i < profiles.length; ++i) {
    capture('DateTimeFormat/profile/' + i, () => {
      const formatter = new Intl.DateTimeFormat(undefined, profiles[i]);
      return { resolved: formatter.resolvedOptions(), format: formatter.format(0),
        parts: formatter.formatToParts(0), range: formatter.formatRange(0, 86400000),
        rangeParts: formatter.formatRangeToParts(0, 86400000) };
    });
  }
  for (const method of ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString'])
    capture('Date/' + method, () => new Date(0)[method]());
  capture('Number/toLocaleString', () => (1234567.89).toLocaleString());
  capture('BigInt/toLocaleString', () => (123456789012345678901n).toLocaleString());
  capture('String/localeCompare', () => 'café'.localeCompare('cafe'));
  print(JSON.stringify({ rows }));
});
const source = `(${evaluate})();\n`;
writeFileSync(new URL('bootstrap.js', root), source);
runInNewContext(source, {
  print: line => writeFileSync(new URL('bootstrap-reference.json', root), line + '\n'),
});
writeFileSync(new URL('bootstrap-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
