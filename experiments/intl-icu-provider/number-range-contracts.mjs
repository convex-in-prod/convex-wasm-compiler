import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const evaluate = String(function run() {
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
  for (const method of ['formatRange', 'formatRangeToParts']) {
    const formatter = new Intl.NumberFormat('en-US');
    const invoke = (receiver, start, end) => Intl.NumberFormat.prototype[method].call(receiver, start, end);
    capture(method + '/descriptor', () => {
      const d = Object.getOwnPropertyDescriptor(Intl.NumberFormat.prototype, method);
      return { name: d.value.name, length: d.value.length,
        writable: d.writable, enumerable: d.enumerable, configurable: d.configurable,
        prototype: Object.hasOwn(d.value, 'prototype') };
    });
    capture(method + '/constructor', () => new (formatter[method])(1, 2));
    for (const kind of ['plain', 'proxy', 'wrong-service', 'chained', 'undefined', 'null', 'primitive'])
      capture(method + '/receiver/' + kind, trace => {
        const chained = Object.create(Intl.NumberFormat.prototype);
        Intl.NumberFormat.call(chained, 'en-US');
        const receiver = kind === 'plain' ? {} : kind === 'proxy' ? new Proxy(formatter, {})
          : kind === 'wrong-service' ? new Intl.DateTimeFormat('en-US')
          : kind === 'chained' ? chained : kind === 'undefined' ? undefined : kind === 'null' ? null : 1;
        return invoke(receiver, { valueOf() { trace.push('start'); return 1; } }, 2);
      });
    const values = [undefined, NaN, 'NaN', Symbol('endpoint'), 'bad', {}, { valueOf() { throw new SyntaxError('endpoint'); } }];
    for (let i = 0; i < values.length; ++i) for (const side of ['start', 'end'])
      capture(method + '/invalid/' + side + '/' + i, trace => {
        const other = { valueOf() { trace.push('other'); return 1; } };
        return side === 'start' ? invoke(formatter, values[i], other) : invoke(formatter, other, values[i]);
      });
    for (const first of [NaN, 'NaN', 1, '1']) for (const throws of [false, true])
      capture(method + '/coercion/' + String(first) + '/' + typeof first + '/' + throws, trace => {
        return invoke(formatter, { [Symbol.toPrimitive](hint) {
          trace.push('start:' + hint); return first;
        } }, { [Symbol.toPrimitive](hint) {
          trace.push('end:' + hint);
          if (throws) throw new SyntaxError('second conversion');
          return '2';
        } });
      });
    capture(method + '/gc-reentrancy', trace => {
      const start = { valueOf() {
        trace.push('start'); gc();
        trace.push(formatter.formatRange(10, 20));
        return 123456789012345678901n;
      } };
      const end = { valueOf() {
        trace.push('end'); gc();
        trace.push(formatter.formatRange(30, 40));
        return '123456789012345678999';
      } };
      return invoke(formatter, start, end);
    });
    capture(method + '/subclass', () => {
      class RangeFormat extends Intl.NumberFormat {}
      return invoke(new RangeFormat('de-DE'), 1, 3);
    });
  }
  print(JSON.stringify({ rows }));
});
if (typeof globalThis.gc !== 'function') throw new Error('Run range reference with --expose-gc');
const source = `(${evaluate})();\n`;
writeFileSync(new URL('ranges.js', root), source);
runInNewContext(source, { gc: globalThis.gc,
  print: line => writeFileSync(new URL('ranges-reference.json', root), line + '\n') });
writeFileSync(new URL('ranges-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
