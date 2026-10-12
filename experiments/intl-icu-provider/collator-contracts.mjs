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
  const locales = ['en-US', 'de-DE', 'fr-FR', 'sv-SE', 'da-DK', 'tr-TR', 'th-TH', 'ja-JP', 'zh-TW', 'ar-EG',
    'de-u-co-phonebk', 'zh-u-co-stroke', 'en-u-kn-kf-upper', 'en-u-co-search', 'zz'];
  const profiles = [{}, { usage: 'search' }, { usage: 'sort' }, { numeric: true }, { numeric: false },
    { caseFirst: 'upper' }, { caseFirst: 'lower' }, { caseFirst: 'false' },
    { ignorePunctuation: true }, { ignorePunctuation: false },
    ...['base', 'accent', 'case', 'variant'].flatMap(sensitivity => [{ sensitivity }, { usage: 'search', sensitivity }]),
    { collation: 'phonebk' }, { collation: 'emoji' }, { collation: 'search' }, { collation: 'standard' },
    { collation: 'invalid' }, { collation: 'PHONEBK' },
    { collation: 'SEARCH' }, { collation: 'STANDARD' }, { collation: 'PhOnEbK' },
    { numeric: true, caseFirst: 'lower', sensitivity: 'case', ignorePunctuation: true },
    { localeMatcher: 'lookup' }, { localeMatcher: 'best fit' }];
  const pairs = [['a', 'b'], ['a', 'A'], ['a', 'á'], ['ä', 'z'], ['ä', 'ae'], ['2', '10'], ['02', '2'],
    ['a-b', 'ab'], ['ab', 'a b'], ['a_b', 'ab'], ['é', 'e\u0301'], ['Å', 'A\u030a'], ['I', 'ı'],
    ['i', 'İ'], ['a\u0000b', 'ab'], ['\ud800', '\ud801'], ['\udc00', 'x'], ['😀', 'a'], ['は', 'ハ'], ['一', '二'],
    ['', ''], ['a', ''], ['10.2', '10.10']];
  for (const locale of locales) for (let p = 0; p < profiles.length; ++p)
    capture(locale + '/' + p, () => {
      const formatter = new Intl.Collator(locale, profiles[p]);
      const resolved = formatter.resolvedOptions();
      return { resolved, keys: Object.keys(resolved), comparisons: pairs.map(pair => formatter.compare(...pair)),
        convenience: pairs.map(pair => pair[0].localeCompare(pair[1], locale, profiles[p])) };
    });
  for (let a = 97; a <= 122; ++a) for (let b = 97; b <= 122; ++b) {
    const tag = String.fromCharCode(a, b);
    capture('locale/' + tag, () => ({ supported: Intl.Collator.supportedLocalesOf(tag),
      resolved: new Intl.Collator(tag).resolvedOptions().locale }));
  }
  const optionOrder = ['usage', 'localeMatcher', 'collation', 'numeric', 'caseFirst', 'sensitivity', 'ignorePunctuation'];
  const defaults = { usage: 'sort', localeMatcher: 'best fit', collation: 'phonebk', numeric: true,
    caseFirst: 'upper', sensitivity: 'variant', ignorePunctuation: false };
  for (const entry of ['constructor', 'convenience']) {
    function invoke(options) {
      return entry === 'constructor' ? new Intl.Collator('de', options).resolvedOptions()
        : 'ä'.localeCompare('ae', 'de', options);
    }
    for (const stop of [null, ...optionOrder]) for (const mode of ['valid', 'invalid', 'throw-get', 'throw-convert'])
      capture(entry + '/options/' + stop + '/' + mode, trace => {
        const options = new Proxy({}, { get(_target, name) {
          trace.push('get:' + name);
          if (name === stop && mode === 'throw-get') throw new SyntaxError('getter');
          if (name === 'numeric' || name === 'ignorePunctuation')
            return { valueOf() { trace.push('unexpected boolean conversion'); throw new SyntaxError('boolean'); } };
          return { toString() {
            trace.push('convert:' + name); gc();
            if (name === stop && mode === 'throw-convert') throw new SyntaxError('conversion');
            return name === stop && mode === 'invalid' ? '' : defaults[name];
          } };
        } });
        return invoke(options);
      });
    for (const options of [undefined, null, false, 1, '', Symbol('options'), 1n])
      capture(entry + '/primitive-options/' + typeof options + '/' + String(options), () => invoke(options));
  }
  capture('constructor/order', trace => {
    const target = new Proxy(function Example() {}, { get(object, key) {
      trace.push('newTarget:' + String(key)); return Reflect.get(object, key);
    } });
    const locales = new Proxy(['en-US'], { get(object, key) {
      trace.push('locale:' + String(key)); return Reflect.get(object, key);
    }, has(object, key) { trace.push('has:' + String(key)); return Reflect.has(object, key); } });
    const options = new Proxy({}, { get(_object, key) { trace.push('option:' + String(key)); } });
    const instance = Reflect.construct(Intl.Collator, [locales, options], target);
    return { prototype: Object.getPrototypeOf(instance) === target.prototype,
      resolved: Intl.Collator.prototype.resolvedOptions.call(instance) };
  });
  capture('constructor/call', () => {
    const receiver = Object.create(Intl.Collator.prototype);
    const result = Intl.Collator.call(receiver, 'en-US');
    return { same: result === receiver, receiverKeys: Reflect.ownKeys(receiver), value: result.resolvedOptions() };
  });
  capture('constructor/subclass', () => {
    class Derived extends Intl.Collator {}
    const instance = new Derived('en-US');
    return { subclass: instance instanceof Derived, compared: instance.compare('a', 'b') };
  });
  const compareGetter = Object.getOwnPropertyDescriptor(Intl.Collator.prototype, 'compare').get;
  for (const receiver of [undefined, null, 1, {}, Intl.Collator.prototype, new Proxy(new Intl.Collator(), {}), new Intl.NumberFormat()]) {
    const label = receiver === null ? 'null' : typeof receiver + '/' + rows.length;
    capture('receiver/compare/' + label, () => compareGetter.call(receiver));
    capture('receiver/resolved/' + label, () => Intl.Collator.prototype.resolvedOptions.call(receiver));
  }
  capture('compare/identity', () => {
    const formatter = new Intl.Collator('en');
    return { same: formatter.compare === formatter.compare, name: formatter.compare.name, length: formatter.compare.length,
      prototype: Object.hasOwn(formatter.compare, 'prototype') };
  });
  capture('compare/coercion-gc', trace => {
    const compare = new Intl.Collator('en').compare;
    return compare({ toString() { trace.push('first'); gc(); return 'a'; } },
      { toString() { trace.push('second'); gc(); trace.push(compare('c', 'd')); return 'b'; } });
  });
  capture('compare/first-throws', trace => new Intl.Collator().compare(Symbol('first'), {
    toString() { trace.push('second'); return 'a'; }
  }));
  print(JSON.stringify({ rows }));
});
if (typeof globalThis.gc !== 'function') throw new Error('Run Collator reference with --expose-gc');
const source = `(${evaluate})();\n`;
writeFileSync(new URL('collator.js', root), source);
runInNewContext(source, { gc: globalThis.gc,
  print: line => writeFileSync(new URL('collator-reference.json', root), line + '\n') });
writeFileSync(new URL('collator-reference-versions.json', root), JSON.stringify(process.versions, null, 2) + '\n');
