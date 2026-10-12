import { WASI } from 'node:wasi';

// Capture guest output before a possible trap and keep instance ownership local
// to one call. No guest cleanup runs after a trap; callers receive only evidence.
export function runProbe(module, configure, entry) {
  const stdout = [], stderr = [];
  const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
  let instance;
  const imports = wasi.getImportObject();
  imports.wasi_snapshot_preview1.fd_write = (fd, vectors, count, written) => {
    if (fd !== 1 && fd !== 2) return 8;
    const data = new DataView(instance.exports.memory.buffer);
    let total = 0;
    for (let index = 0; index < count; ++index) {
      const pointer = data.getUint32(vectors + index * 8, true);
      const length = data.getUint32(vectors + index * 8 + 4, true);
      const value = Buffer.from(new Uint8Array(instance.exports.memory.buffer, pointer, length));
      (fd === 1 ? stdout : stderr).push(value);
      total += length;
    }
    data.setUint32(written, total, true);
    return 0;
  };
  imports.env = { emscripten_notify_memory_growth() {}, __syscall_unlinkat() { return -2; } };
  instance = new WebAssembly.Instance(module, imports);
  wasi.initialize(instance);
  configure(instance.exports);
  let status, error;
  try { status = instance.exports[entry](); }
  catch (caught) { error = caught; }
  return { status, error, memoryBytes: instance.exports.memory.buffer.byteLength,
    stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
}
