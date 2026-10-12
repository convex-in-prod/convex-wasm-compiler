import { readFileSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const name = process.argv[2];
if (!['contracts', 'dates'].includes(name)) throw new Error('Expected contracts or dates');
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const expected = JSON.parse(readFileSync(new URL(name + '-reference.json', root))).rows;
const actual = JSON.parse(readFileSync(new URL(name + '-actual.json', root))).rows;
if (expected.length !== actual.length) throw new Error('Case count differs');
const totals = { cases: actual.length, format: 0, parts: 0, resolved: 0, propertyOrder: 0,
  expectedErrors: 0, matchingErrors: 0, unexpectedErrors: 0, partsRoundtripFailures: 0 };
const groups = {};
const differences = [];
for (let index = 0; index < expected.length; ++index) {
  const want = expected[index];
  const got = actual[index];
  if (want.id !== got.id) throw new Error('Case identity differs');
  if (want.error) totals.expectedErrors++;
  if (want.error || got.error) {
    const matchingError = Boolean(want.error && got.error && want.error.name === got.error.name);
    if (matchingError) totals.matchingErrors++;
    else {
      totals.unexpectedErrors++;
      differences.push({ id: want.id, expected: want, actual: got });
    }
    continue;
  }
  const match = { format: want.format === got.format, parts: isDeepStrictEqual(want.parts, got.parts),
    resolved: isDeepStrictEqual(want.resolved, got.resolved),
    propertyOrder: JSON.stringify(Object.keys(want.resolved)) === JSON.stringify(Object.keys(got.resolved)) &&
      got.parts.every(part => JSON.stringify(Object.keys(part)) === '["type","value"]') };
  if (want.parts.map(part => part.value).join('') === want.format && got.parts.map(part => part.value).join('') !== got.format) totals.partsRoundtripFailures++;
  const segments = want.id.split('/');
  const group = segments.length === 3 ? `profile/${segments[1]}` : segments[0];
  groups[group] ??= { cases: 0, format: 0, parts: 0, resolved: 0, propertyOrder: 0 };
  groups[group].cases++;
  for (const metric of Object.keys(match)) {
    totals[metric] += Number(match[metric]);
    groups[group][metric] += Number(match[metric]);
  }
  if (!Object.values(match).every(Boolean)) differences.push({ id: want.id, match, expected: want, actual: got });
}
const summary = { totals, groups };
writeFileSync(new URL(name + '-comparison.json', root), JSON.stringify({ ...summary, differences }, null, 2) + '\n');
console.log(JSON.stringify(summary, null, 2));
if (process.argv.includes('--require-parity') && differences.length !== 0) process.exitCode = 1;
