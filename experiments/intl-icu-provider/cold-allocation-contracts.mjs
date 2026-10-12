import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

process.env.TZ = 'UTC';
if (new Intl.NumberFormat().resolvedOptions().locale !== 'en-US')
  throw new Error('Run the cold allocation reference with LANG=en_US.UTF-8');
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const evaluate = String(function run() {
  // No warm-up: cover provider initialization and the first formatter creation.
  const number = new Intl.NumberFormat(undefined, { style: 'currency', currency: 'EUR' });
  const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'full', timeStyle: 'short' });
  const collator = new Intl.Collator();
  print(JSON.stringify({ number: { resolved: number.resolvedOptions(), text: number.format(123456.789) },
    date: { resolved: date.resolvedOptions(), text: date.format(0) },
    collator: { resolved: collator.resolvedOptions(), value: collator.compare('café', 'cafe') } }));
});
const source = `(${evaluate})();\n`;
writeFileSync(new URL('cold-allocations.js', root), source);
runInNewContext(source, {
  print: line => writeFileSync(new URL('cold-allocations-reference.json', root), line + '\n'),
});
