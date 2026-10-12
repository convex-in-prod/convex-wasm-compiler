export function rangeBindingContracts(service, capture) {
  const Ctor = Intl[service];
  for (const method of ['formatRange', 'formatRangeToParts']) {
    const options = service === 'DateTimeFormat' ? { timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit' } : {};
    const formatter = new Ctor('en-US', options);
    const invoke = (receiver, start, end) => Ctor.prototype[method].call(receiver, start, end);
    capture(method + '/descriptor', () => {
      const d = Object.getOwnPropertyDescriptor(Ctor.prototype, method);
      return { name: d.value.name, length: d.value.length,
        writable: d.writable, enumerable: d.enumerable, configurable: d.configurable,
        prototype: Object.hasOwn(d.value, 'prototype') };
    });
    capture(method + '/constructor', () => new (formatter[method])(1, 2));
    for (const kind of ['plain', 'proxy', 'wrong-service', 'chained', 'undefined', 'null', 'primitive'])
      capture(method + '/receiver/' + kind, trace => {
        const chained = Object.create(Ctor.prototype);
        Ctor.call(chained, 'en-US', options);
        const receiver = kind === 'plain' ? {} : kind === 'proxy' ? new Proxy(formatter, {})
          : kind === 'wrong-service' ? new Intl[service === 'NumberFormat' ? 'DateTimeFormat' : 'NumberFormat']('en-US')
          : kind === 'chained' ? chained : kind === 'undefined' ? undefined : kind === 'null' ? null : 1;
        return invoke(receiver, { valueOf() { trace.push('start'); return 1; } }, 2);
      });
    const values = [undefined, NaN, 'NaN', Symbol('endpoint'), 'bad', {}, { valueOf() { throw new SyntaxError('endpoint'); } }];
    if (service === 'DateTimeFormat') values.push(1n, Infinity, -Infinity, 8.64e15 + 1);
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
        return service === 'DateTimeFormat' ? 1577836800000 : 123456789012345678901n;
      } };
      const end = { valueOf() {
        trace.push('end'); gc();
        trace.push(formatter.formatRange(30, 40));
        return service === 'DateTimeFormat' ? '1577923200000' : '123456789012345678999';
      } };
      return invoke(formatter, start, end);
    });
    capture(method + '/subclass', () => {
      class RangeFormat extends Ctor {}
      return invoke(new RangeFormat('de-DE', options), 1, 3);
    });
  }
}
