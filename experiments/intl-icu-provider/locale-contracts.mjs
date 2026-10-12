import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
process.env.TZ = 'UTC';
const evaluate = String(function run() {
  const rows = [];
  function capture(id, body) {
    try { rows.push({ id, trace: [], value: body() }); }
    catch (error) { rows.push({ id, trace: [], error: error.name }); }
  }
  const tags = [];
  // Exhaust the two-letter language space, including unsupported languages.
  for (let a = 97; a <= 122; ++a) for (let b = 97; b <= 122; ++b)
    tags.push(String.fromCharCode(a, b));
  tags.push('iw-IL', 'in-ID', 'ji', 'sh', 'mo', 'tl', 'cmn', 'yue',
    'de-DD', 'en-BU', 'sr-CS', 'zh-cmn', 'en-Latn-US', 'EN-us',
    'de-1901', 'sl-rozaj-biske-1994', 'en-t-en-us-h0-hybrid',
    'en-u-ca-gregory-nu-latn', 'en-u-kn-true', 'en-u-kn-yes', 'en-u-ca-yes',
    'en-u-tz-est', 'en-x-test', 'en-a-foobar-b-baz', 'en-u-attr-ca-buddhist',
    'en-u-attr-attr-ca-gregory', 'en-u-ca-gregory-ca-buddhist',
    'und', 'zxx', 'mul', 'i-klingon', 'x-private', 'en_US', '',
    'en-abcde-abcde', 'en-a-foo-a-bar', 'en-1234', 'en-123456789',
    'en-\u00e9', '\ud800', 'en\u0000-US');
  for (const base of ['en', 'fr', 'zh', 'sr', 'ff', 'ar'])
    for (const suffix of ['-ZZ', '-Latn', '-Latn-ZZ', '-u-nu-arab', '-u-ca-buddhist'])
      tags.push(base + suffix);
  for (const length of [16, 32, 64]) tags.push('en-x-' + Array(length).fill('abcdefgh').join('-'));
  tags.push('BH', 'Tw', 'tw-Latn', 'BH-IN', 'TW-GH', 'bh-x-test',
    'de-1996', 'en-0abc', 'en-abcd', 'en-abc', 'en-abcde', 'en-1234-1234');
  for (let index = 0; index < tags.length; ++index) {
    const tag = tags[index];
    capture('canonical/' + index, () => Intl.getCanonicalLocales(tag));
    for (const service of ['NumberFormat', 'DateTimeFormat']) {
      for (const matcher of ['lookup', 'best fit']) {
        capture(service + '/supported/' + matcher + '/' + index,
          () => Intl[service].supportedLocalesOf([tag], { localeMatcher: matcher }));
        capture(service + '/resolved/' + matcher + '/' + index, () =>
          new Intl[service]([tag], service === 'DateTimeFormat'
            ? { localeMatcher: matcher, timeZone: 'UTC' } : { localeMatcher: matcher }).resolvedOptions().locale);
      }
    }
  }
  for (const locales of [[], ['zz', 'fr-CA'], ['zh-Latn', 'fr-CA'],
    ['en-x-test', 'de'], ['iw', 'he'], ['en-u-ca-buddhist', 'fr'],
    ['ff-Latn-ZZ', 'fr-CA']]) for (const service of ['NumberFormat', 'DateTimeFormat']) {
    for (const matcher of ['lookup', 'best fit']) capture(service + '/list/' + matcher + '/' + JSON.stringify(locales), () => ({
      supported: Intl[service].supportedLocalesOf(locales, { localeMatcher: matcher }),
      resolved: new Intl[service](locales, service === 'DateTimeFormat'
        ? { localeMatcher: matcher, timeZone: 'UTC' } : { localeMatcher: matcher }).resolvedOptions().locale,
    }));
  }
  print(JSON.stringify({ rows }));
});
const source = `(${evaluate})();\n`;
writeFileSync(new URL('locales.js', root), source);
runInNewContext(source, { print: line => writeFileSync(new URL('locales-reference.json', root), line + '\n') });
writeFileSync(new URL('locales-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
