import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { WASI } from 'node:wasi';
const root = new URL('./', process.env.INTL_EXPERIMENT_URL);
const bytes = readFileSync(new URL('allocation-boundaries.wasm', root));
const module = await WebAssembly.compile(bytes);
const cases = ['zero-size-semantics', 'malloc-failure', 'realloc-failure', 'calloc-overflow'];
for (const [mode, name] of cases.entries()) {
  const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
  const instance = new WebAssembly.Instance(module, wasi.getImportObject());
  wasi.initialize(instance);
  const run = () => instance.exports.intl_allocation_boundary_run(mode);
  if (mode === 0) assert.equal(run(), 0, name);
  else assert.throws(run, error => error instanceof WebAssembly.RuntimeError && error.message === 'unreachable', name);
}
const summary = { cases, wasmSha256: createHash('sha256').update(bytes).digest('hex') };
writeFileSync(new URL('allocation-boundaries-comparison.json', root), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify(summary));
