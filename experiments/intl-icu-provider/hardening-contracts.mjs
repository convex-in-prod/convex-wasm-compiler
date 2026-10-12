import { writeFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { renderConvexWasmIntrinsicHardeningPrelude } from '../../scripts/lib/convex-wasm-intrinsic-hardening.mjs';

process.env.TZ = 'UTC';
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const hardening = ts.transpileModule(renderConvexWasmIntrinsicHardeningPrelude(), {
  compilerOptions: { module: ts.ModuleKind.None, target: ts.ScriptTarget.ES2022 },
}).outputText;
const evaluate = String(function run() {
  const rows = [];
  const validate = globalThis.__convexWasmValidateIntrinsicDescriptorState;
  if (!delete globalThis.__convexWasmValidateIntrinsicDescriptorState) throw new Error('Validator handoff failed');
  function capture(id, body) { rows.push({ id, value: body() }); }
  capture('namespace', () => ({ frozen: Object.isFrozen(Intl), valid: validate() }));
  for (const service of ['NumberFormat', 'DateTimeFormat', 'Collator']) {
    const Parent = Intl[service];
    const options = service === 'DateTimeFormat' ? { timeZone: 'UTC' } : {};
    capture(service + '/subclass', () => {
      class Derived extends Parent {}
      const value = new Derived('en-US', options);
      return { derived: value instanceof Derived, parent: value instanceof Parent,
        prototype: Object.getPrototypeOf(value) === Derived.prototype,
        resolved: value.resolvedOptions(), result: service === 'Collator'
          ? value.compare('café', 'cafe') : value.format(123456789), valid: validate() };
    });
    capture(service + '/extension', () => ({
      constructor: Reflect.defineProperty(Parent, 'unexpected', { value: 1 }),
      prototype: Reflect.defineProperty(Parent.prototype, 'unexpected', { value: 1 }),
      valid: validate(),
    }));
    capture(service + '/descriptor-mutation', () => {
      const before = Object.getOwnPropertyDescriptor(Parent.prototype, 'resolvedOptions');
      const changed = Reflect.defineProperty(Parent.prototype, 'resolvedOptions', {
        ...before, value() { return {}; },
      });
      const invalid = !validate();
      Object.defineProperty(Parent.prototype, 'resolvedOptions', before);
      return { changed, invalid, restored: validate() };
    });
    if (service !== 'Collator') capture(service + '/legacy-receiver', () => {
      const receiver = Object.create(Parent.prototype);
      const result = Parent.call(receiver, 'en-US', options);
      return { identity: result === receiver, format: result.format(0), valid: validate() };
    });
  }
  capture('number/range', () => new Intl.NumberFormat('de-DE').formatRange(1n, 9007199254740993n));
  capture('date/range', () => new Intl.DateTimeFormat('ja-JP', { timeZone: 'UTC', dateStyle: 'full' }).formatRange(0, 86400000));
  capture('final-descriptors', () => validate());
  print(JSON.stringify({ rows }));
});
const source = `${hardening}\n(${evaluate})();\n`;
writeFileSync(new URL('hardening.js', root), source);
// Node contexts lack some unrelated admitted Hermes globals. These roots are
// only hardening inputs; the Intl operations use Node's native implementation.
const nodeGlobals = `
globalThis.TextDecoder = class TextDecoder {};
globalThis.TextEncoder = class TextEncoder {};
globalThis.atob = function(value) { return String(value); };
globalThis.btoa = function(value) { return String(value); };
globalThis.queueMicrotask = function(callback) { Promise.resolve().then(callback); };
`;
runInNewContext(nodeGlobals + source, {
  print: line => writeFileSync(new URL('hardening-reference.json', root), line + '\n'),
});
