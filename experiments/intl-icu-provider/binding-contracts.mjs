import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

// Compare default-option behavior under the same explicit host timezone.
process.env.TZ = 'UTC';
if (typeof globalThis.gc !== 'function') throw new Error('Run binding reference with --expose-gc');
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const evaluate = String(function run() {
  const rows = [];
  function capture(id, body) {
    const trace = [];
    try { rows.push({ id, trace, value: body(trace) }); }
    catch (error) { rows.push({ id, trace, error: error.name }); }
  }
  const services = {
    NumberFormat: { localeMatcher: 'best fit', numberingSystem: 'latn', style: 'decimal',
      currency: 'USD', currencyDisplay: 'symbol', currencySign: 'standard',
      unit: 'meter', unitDisplay: 'short', notation: 'standard',
      minimumIntegerDigits: 1, minimumFractionDigits: 0, maximumFractionDigits: 3,
      minimumSignificantDigits: 1, maximumSignificantDigits: 21,
      roundingIncrement: 1, roundingMode: 'halfExpand', roundingPriority: 'auto',
      trailingZeroDisplay: 'auto', compactDisplay: 'short', useGrouping: 'auto', signDisplay: 'auto' },
    DateTimeFormat: { localeMatcher: 'best fit', calendar: 'gregory', numberingSystem: 'latn',
      hour12: false, hourCycle: 'h23', timeZone: 'UTC', weekday: 'short', era: 'short',
      year: 'numeric', month: 'numeric', day: 'numeric', dayPeriod: 'short',
      hour: 'numeric', minute: 'numeric', second: 'numeric', fractionalSecondDigits: 3,
      timeZoneName: 'short', formatMatcher: 'best fit', dateStyle: undefined, timeStyle: undefined },
  };
  for (const service of Object.keys(services)) {
    const defaults = services[service];
    const keys = Object.keys(defaults);
    function options(trace, settings) {
      return new Proxy({}, { get(target, key) {
        trace.push('get:' + String(key));
        if (settings.throwAt === key) throw new SyntaxError('getter');
        let value = Object.prototype.hasOwnProperty.call(settings.values, key)
          ? settings.values[key] : settings.omitted ? undefined : defaults[key];
        if (settings.box && value !== undefined && key !== 'hour12') {
          return { [Symbol.toPrimitive](hint) {
            trace.push('coerce:' + String(key) + ':' + hint);
            return value;
          } };
        }
        return value;
      }, has(target, key) { trace.push('has:' + String(key)); return false; },
      ownKeys() { trace.push('ownKeys'); return []; } });
    }
    for (const box of [false, true]) {
      capture(service + '/ordered/' + box, trace =>
        new Intl[service]('en-US', options(trace, { box, values: {} })).resolvedOptions());
      for (const throwAt of keys) capture(service + '/throw/' + box + '/' + throwAt, trace => {
        new Intl[service]('en-US', options(trace, { box, values: {}, throwAt }));
        return 'constructed';
      });
    }
    const invalid = service === 'NumberFormat' ? [
      { localeMatcher: 'invalid' }, { numberingSystem: '' }, { style: 'invalid' },
      { style: 'currency', currency: undefined }, { currency: 'US' },
      { currencyDisplay: 'invalid' }, { currencySign: 'invalid' },
      { style: 'unit', unit: undefined }, { unit: '' }, { unitDisplay: 'invalid' },
      { notation: 'invalid' }, { minimumIntegerDigits: 0 },
      { minimumFractionDigits: -1, minimumSignificantDigits: undefined, maximumSignificantDigits: undefined },
      { minimumSignificantDigits: 0 }, { maximumSignificantDigits: 0 },
      { roundingIncrement: 3 }, { roundingMode: 'invalid' }, { roundingPriority: 'invalid' },
      { trailingZeroDisplay: 'invalid' }, { compactDisplay: 'invalid' },
      { useGrouping: 'invalid' }, { signDisplay: 'invalid' },
      // Unused precision values are read but must not be converted or validated.
      { minimumFractionDigits: -1, maximumFractionDigits: -1 },
      { minimumSignificantDigits: undefined, maximumSignificantDigits: undefined,
        minimumFractionDigits: 0, maximumFractionDigits: 1 },
      { roundingPriority: 'morePrecision', minimumFractionDigits: 5, maximumFractionDigits: 2 },
    ] : [
      { localeMatcher: 'invalid' }, { calendar: '' }, { numberingSystem: '' },
      { hourCycle: 'invalid' }, { timeZone: 'invalid' }, { weekday: 'invalid' },
      { era: 'invalid' }, { year: 'invalid' }, { month: 'invalid' }, { day: 'invalid' },
      { dayPeriod: 'invalid' }, { hour: 'invalid' }, { minute: 'invalid' }, { second: 'invalid' },
      { fractionalSecondDigits: 0 }, { timeZoneName: 'invalid' }, { formatMatcher: 'invalid' },
      { dateStyle: 'invalid' }, { timeStyle: 'invalid' }, { dateStyle: 'short' },
    ];
    for (let i = 0; i < invalid.length; ++i) for (const box of [false, true]) {
      capture(service + '/validation/' + i + '/' + box, trace =>
        new Intl[service]('en-US', options(trace, { box, values: invalid[i] })).resolvedOptions());
    }
    capture(service + '/invalid-locale-before-options', trace =>
      new Intl[service]('bad_tag', options(trace, { values: {} })).resolvedOptions());
    capture(service + '/locale-elements', trace => {
      const locales = { length: 2, get 0() { trace.push('locale:0'); return 'bad_tag'; },
        get 1() { trace.push('locale:1'); return 'en-US'; } };
      return new Intl[service](locales, options(trace, { values: {} })).resolvedOptions();
    });
    capture(service + '/boxed-options', trace => {
      Object.defineProperty(Number.prototype, 'localeMatcher', { configurable: true, get() {
        trace.push('boxed:localeMatcher'); return 'invalid';
      } });
      try { return new Intl[service]('en-US', 42).resolvedOptions(); }
      finally { delete Number.prototype.localeMatcher; }
    });
    capture(service + '/new-target-order', trace => {
      const target = new Proxy(function Derived() {}, { get(target, key, receiver) {
        trace.push('target:' + String(key)); return Reflect.get(target, key, receiver);
      } });
      const instance = Reflect.construct(Intl[service], ['en-US', options(trace, { values: {}, omitted: true })], target);
      return Object.getPrototypeOf(instance) === target.prototype;
    });
    capture(service + '/throwing-new-target', trace => {
      const target = new Proxy(function Derived() {}, { get() {
        trace.push('prototype'); throw new SyntaxError('prototype');
      } });
      return Reflect.construct(Intl[service], ['bad_tag', null], target);
    });
    for (const present of [false, true]) capture(service + '/locale-hole/' + present, trace => {
      const locales = new Proxy({ length: 2, 1: 'en-US' }, {
        has(target, key) { trace.push('has:' + String(key)); return key === '0' ? present : key in target; },
        get(target, key) { trace.push('get:' + String(key)); return target[key]; },
      });
      return Intl[service].supportedLocalesOf(locales);
    });
    capture(service + '/locale-duplicate-coercion', trace => {
      const locale = { toString() { trace.push('locale:string'); return 'en-us'; } };
      return Intl[service].supportedLocalesOf([locale, locale, 'en-US']);
    });
    for (const value of [undefined, null, 42, true, 'text', 1n, Symbol('option')]) {
      capture(service + '/primitive-options/' + String(value), () => new Intl[service]('en-US', value).resolvedOptions());
      capture(service + '/supported-options/' + String(value), () => Intl[service].supportedLocalesOf(['en-US'], value));
    }
    capture(service + '/supported-boxed-getter', trace => {
      Object.defineProperty(Number.prototype, 'localeMatcher', { configurable: true, get() {
        trace.push('localeMatcher'); return 'invalid';
      } });
      try { return Intl[service].supportedLocalesOf(['en-US'], 42); }
      finally { delete Number.prototype.localeMatcher; }
    });
    const methods = service === 'DateTimeFormat'
      ? ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString'] : ['number', 'bigint'];
    for (const method of methods) {
      const invoke = opts => method === 'number' ? (1234567.89).toLocaleString('en-US', opts)
        : method === 'bigint' ? (123456789012345678901n).toLocaleString('en-US', opts)
        : new Date(1700000000123)[method]('en-US', opts);
      for (const box of [false, true]) {
        capture(method + '/ordered/' + box, trace => invoke(options(trace, { box, values: {} })));
        for (const throwAt of keys) capture(method + '/throw/' + box + '/' + throwAt, trace =>
          invoke(options(trace, { box, values: {}, throwAt })));
      }
      for (const value of [undefined, null, 42, true, 'text', 1n, Symbol('option')])
        capture(method + '/primitive-options/' + String(value), () => invoke(value));
      if (service === 'DateTimeFormat') for (const fields of [
        {}, { hour: 'numeric' }, { year: 'numeric' }, { era: 'short' },
        { dayPeriod: 'short' }, { fractionalSecondDigits: 2 }, { timeZoneName: 'short' },
        { dateStyle: 'short' }, { timeStyle: 'short' }, { dateStyle: 'short', timeStyle: 'short' },
      ]) capture(method + '/defaults/' + JSON.stringify(fields), () => invoke({ timeZone: 'UTC', ...fields }));
    }
  }
  for (const ignored of [false, true]) for (const shouldThrow of [false, true]) {
    capture('deferred-value/' + ignored + '/' + shouldThrow, trace => {
      let digits = 0;
      function coerceDigits() {
        trace.push('digits:' + digits);
        if (shouldThrow) throw new SyntaxError('digits');
        // Reenter the same provider while the outer option values remain live.
        trace.push(new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(2.5));
        return digits;
      }
      // Each getter returns an otherwise unreachable object. The native reader
      // must retain roots through the later getter's collection and reentrancy.
      const opts = { get minimumFractionDigits() { return { valueOf: coerceDigits }; },
        get maximumFractionDigits() { return { valueOf: coerceDigits }; },
        get roundingMode() {
          digits = 2; trace.push('roundingMode');
          gc();
          return 'halfExpand';
        } };
      if (ignored) opts.minimumSignificantDigits = 3;
      const formatter = new Intl.NumberFormat('en-US', opts);
      return { output: formatter.format(1.234), resolved: formatter.resolvedOptions() };
    });
  }
  for (const method of ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString']) {
    capture(method + '/invalid-date', () => new Date(NaN)[method]('bad_tag', null));
    capture(method + '/wrong-receiver', () => Date.prototype[method].call({}, 'bad_tag', null));
  }
  capture('number/wrong-receiver', () => Number.prototype.toLocaleString.call(1n, 'bad_tag', null));
  capture('bigint/wrong-receiver', () => BigInt.prototype.toLocaleString.call(1, 'bad_tag', null));
  capture('bigint/boxed', () => Object(123456789012345678901n).toLocaleString('en-US'));
  print(JSON.stringify({ rows }));
});
const source = `(${evaluate})();\n`;
writeFileSync(new URL('bindings.js', root), source);
runInNewContext(source, {
  gc: globalThis.gc,
  print: line => writeFileSync(new URL('bindings-reference.json', root), line + '\n'),
});
writeFileSync(new URL('bindings-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
