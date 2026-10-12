import { readFileSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const name = process.argv.slice(2).find(value => !value.startsWith('--')) ?? 'bindings';
if (!['bindings', 'construction', 'locales', 'ranges', 'date-ranges', 'collator'].includes(name)) throw new Error('Unknown binding corpus');
const expected = JSON.parse(readFileSync(new URL(name + '-reference.json', root))).rows;
const actual = JSON.parse(readFileSync(new URL(name + '-actual.json', root))).rows;
if (expected.length !== actual.length) throw new Error('Case count differs');
const differences = [];
for (let i = 0; i < expected.length; ++i) {
  if (expected[i].id !== actual[i].id) throw new Error('Case identity differs');
  if (!isDeepStrictEqual(expected[i], actual[i])) differences.push({ id: expected[i].id, expected: expected[i], actual: actual[i] });
}
const totals = { cases: expected.length, matches: expected.length - differences.length };
writeFileSync(new URL(name + '-comparison.json', root), JSON.stringify({ totals, differences }, null, 2) + '\n');
console.log(JSON.stringify(totals));
if (process.argv.includes('--require-parity') && differences.length) process.exitCode = 1;
