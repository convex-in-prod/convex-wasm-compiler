import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
process.env.TZ = 'UTC';
const evaluate = String(function run() {
  const rows = [];
  function capture(id, body) {
    const trace = [];
    try { rows.push({ id, trace, value: body(trace) }); }
    catch (error) { rows.push({ id, trace, error: error.name }); }
  }
  function descriptor(object, key) {
    const value = Object.getOwnPropertyDescriptor(object, key);
    if (!value) return null;
    const result = { enumerable: value.enumerable, configurable: value.configurable };
    if ('value' in value) {
      result.writable = value.writable;
      result.type = typeof value.value;
      if (typeof value.value === 'function') {
        result.name = value.value.name; result.length = value.value.length;
      } else if (typeof value.value !== 'object') result.value = value.value;
    } else {
      result.get = value.get ? { name: value.get.name, length: value.get.length } : null;
      result.set = value.set ? { name: value.set.name, length: value.set.length } : null;
    }
    return result;
  }
  for (const service of ['NumberFormat', 'DateTimeFormat']) {
    const Ctor = Intl[service];
    const prototype = Ctor.prototype;
    const options = service === 'DateTimeFormat' ? { timeZone: 'UTC', year: 'numeric' } : {};
    const sample = service === 'DateTimeFormat' ? 1700000000000 : 1234.5;
    const fresh = () => new Ctor('en-US', options);
    const fake = () => Object.create(prototype);
    const chain = object => Ctor.call(object, 'en-US', options);
    const formatGetter = Object.getOwnPropertyDescriptor(prototype, 'format').get;
    function invoke(method, receiver) {
      if (method === 'format') return formatGetter.call(receiver)(sample);
      return prototype[method].call(receiver, sample);
    }
    for (const key of ['name', 'length', 'prototype', 'supportedLocalesOf'])
      capture(service + '/constructor-descriptor/' + key, () => descriptor(Ctor, key));
    for (const key of ['constructor', 'format', 'formatToParts', 'resolvedOptions', Symbol.toStringTag])
      capture(service + '/prototype-descriptor/' + String(key), () => descriptor(prototype, key));
    capture(service + '/global-leak', () => typeof globalThis[service]);
    capture(service + '/instance-keys', () => Reflect.ownKeys(fresh()).map(String));
    capture(service + '/format-descriptors', () => {
      const object = fresh();
      const format = object.format;
      return { same: format === object.format, length: descriptor(format, 'length'),
        name: descriptor(format, 'name'), prototype: descriptor(format, 'prototype'),
        detached: format.call(null, sample) };
    });
    capture(service + '/format-not-constructor', () => new (fresh().format)(sample));
    for (const kind of ['fake', 'real', 'plain', 'null', 'primitive']) {
      capture(service + '/chain/' + kind, () => {
        const receiver = kind === 'fake' ? fake() : kind === 'real' ? fresh()
          : kind === 'plain' ? {} : kind === 'null' ? null : 12;
        const result = chain(receiver);
        return { same: receiver === result, output: result.format(sample),
          keys: Reflect.ownKeys(result).map(String), resolved: result.resolvedOptions() };
      });
    }
    for (const method of ['format', 'formatToParts', 'resolvedOptions']) {
      for (const kind of ['fake', 'chained', 'inherited', 'proxy', 'real-proxy', 'wrong-service']) {
        capture(service + '/' + method + '/' + kind, trace => {
          const wrapper = fake(); chain(wrapper);
          const receiver = kind === 'fake' ? fake() : kind === 'chained' ? wrapper
            : kind === 'inherited' ? Object.create(wrapper)
            : kind === 'proxy' ? new Proxy(wrapper, { getPrototypeOf(target) {
              trace.push('getPrototypeOf'); return Reflect.getPrototypeOf(target);
            }, get(target, key, receiver) {
              trace.push('get:' + String(key)); return Reflect.get(target, key, receiver);
            } })
            : kind === 'real-proxy' ? new Proxy(fresh(), {})
            : new Intl[service === 'NumberFormat' ? 'DateTimeFormat' : 'NumberFormat']('en-US');
          return invoke(method, receiver);
        });
      }
      for (const value of [null, undefined, 1, 'string', true, 1n, Symbol('receiver'), {}])
        capture(service + '/' + method + '/invalid/' + String(value), () => invoke(method, value));
    }
    capture(service + '/fallback-descriptor', () => {
      const wrapper = fake(); chain(wrapper);
      const symbols = Object.getOwnPropertySymbols(wrapper);
      return symbols.map(symbol => ({ name: String(symbol), registry: Symbol.keyFor(symbol),
        descriptor: descriptor(wrapper, symbol), valid: wrapper[symbol] instanceof Ctor }));
    });
    capture(service + '/chain-twice', trace => {
      const wrapper = fake(); chain(wrapper);
      return Ctor.call(wrapper, 'en-US', { get localeMatcher() {
        trace.push('localeMatcher'); return 'best fit';
      }, ...options });
    });
    capture(service + '/chain-nonextensible', trace => {
      const wrapper = Object.preventExtensions(fake());
      return Ctor.call(wrapper, 'en-US', { get localeMatcher() {
        trace.push('localeMatcher'); return 'best fit';
      }, ...options });
    });
    for (const deny of [false, true]) capture(service + '/chain-proxy/' + deny, trace => {
      const target = fake();
      const wrapper = new Proxy(target, {
        getPrototypeOf(target) { trace.push('getPrototypeOf'); return Reflect.getPrototypeOf(target); },
        defineProperty(target, key, value) {
          trace.push('define:' + String(key) + ':' + [value.writable, value.enumerable, value.configurable].join(','));
          return deny ? false : Reflect.defineProperty(target, key, value);
        },
      });
      return Ctor.call(wrapper, 'en-US', { get localeMatcher() {
        trace.push('localeMatcher'); return 'best fit';
      }, ...options }) === wrapper;
    });
    capture(service + '/ignore-custom-has-instance', trace => {
      Object.defineProperty(Ctor, Symbol.hasInstance, { configurable: true, value() {
        trace.push('hasInstance'); throw new SyntaxError('hasInstance');
      } });
      try { const wrapper = fake(); return chain(wrapper) === wrapper && typeof wrapper.format === 'function'; }
      finally { delete Ctor[Symbol.hasInstance]; }
    });
    for (const method of ['format', 'resolvedOptions']) {
      for (const trap of ['getter', 'prototype']) capture(service + '/unwrap-throw/' + method + '/' + trap, trace => {
        const wrapper = fake(); chain(wrapper);
        const symbol = Object.getOwnPropertySymbols(wrapper)[0];
        const target = fake();
        Object.defineProperty(target, symbol, { get() {
          trace.push('fallback'); gc(); throw new SyntaxError('fallback');
        } });
        const receiver = trap === 'getter' ? target : new Proxy(target, { getPrototypeOf() {
          trace.push('prototype'); throw new SyntaxError('prototype');
        } });
        return invoke(method, receiver);
      });
      capture(service + '/unwrap-temporary/' + method, trace => {
        const wrapper = fake(); chain(wrapper);
        const symbol = Object.getOwnPropertySymbols(wrapper)[0];
        const target = fake();
        Object.defineProperty(target, symbol, { get() {
          trace.push('fallback'); gc(); return fresh();
        } });
        return invoke(method, target);
      });
    }
    capture(service + '/real-keeps-original', () => {
      const object = fresh(); const initial = object.format;
      const result = Ctor.call(object, 'de-DE', options);
      return { same: object === result, sameFormat: initial === object.format, locale: object.resolvedOptions().locale };
    });
  }
  capture('shared-legacy-symbol', () => {
    const number = Object.create(Intl.NumberFormat.prototype);
    const date = Object.create(Intl.DateTimeFormat.prototype);
    Intl.NumberFormat.call(number); Intl.DateTimeFormat.call(date);
    return Object.getOwnPropertySymbols(number)[0] === Object.getOwnPropertySymbols(date)[0];
  });
  capture('Collator/global-leak', () => typeof globalThis.Collator);
  capture('bigint/toLocaleString-length', () => descriptor(BigInt.prototype.toLocaleString, 'length'));
  print(JSON.stringify({ rows }));
});
if (typeof globalThis.gc !== 'function') throw new Error('Run construction reference with --expose-gc');
const source = `(${evaluate})();\n`;
writeFileSync(new URL('construction.js', root), source);
runInNewContext(source, { gc: globalThis.gc,
  print: line => writeFileSync(new URL('construction-reference.json', root), line + '\n') });
writeFileSync(new URL('construction-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
