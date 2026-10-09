# Bounded Binaryen candidates

These patches target Binaryen revision
`55dff6b2430aee4fee7e5cf748af07222b079742`, the version 131 build included in
Emscripten 6.0.5. `source.json` records the revision, the GitHub source archive
hash and the patch hashes. The Apache 2.0 license is included.

Gate setup checks out the pinned revision and applies both authenticated patches
to the index. It verifies the resulting Git tree against `source.json` and rejects
additional source changes. The native `wasm-opt` build is retained for incremental
setup runs. `binaryen-tools` holds the optimizer and links to the unchanged helper
tools from Emscripten; the installed SDK is not modified. Its receipt records the
recipe and all tool hashes. Gate checks verify the patched source, build freshness,
settings, and tool identities without rebuilding. Setup relinks a stale optimizer
from retained native objects before publishing a replacement receipt. Generated configurations select
this directory with `EM_BINARYEN_ROOT` and include the receipt and tools as artifact
material inputs. These tools are built on the current supported Linux or macOS host.

## Ownership and scheduling

The original binary writer generates and retains StackIR for every function
before emitting any function. Its temporary `StackInst` nodes also live in the
module arena, so releasing the instruction vectors alone cannot reclaim them.

The patched writer generates and optimizes one batch at a time, bounded by the
configured worker count. Each function owns its temporary instruction arena.
After the workers join, the main thread emits functions in their original order
and releases the batch. Original and synthetic expression nodes still belong to
the module: binary-location, source-map and DWARF metadata can refer to them after
StackIR has been emitted. Whole-module StackIR printing retains its existing
interface, with a separate arena owned by that temporary representation.

The main optimization passes and StackIR optimization are unchanged. Temporary
instruction memory depends on the active batch rather than the whole module.
This is not a constant-memory writer: the module IR, output buffer, function
index and individual large functions still consume memory. Enforce the caller's
resource limits while evaluating a build.

## Cumulative inlining budget

`cumulative-inline-budget.patch` fixes the selection loop's size accounting.
Previously, every candidate call was checked against the caller's original size.
Earlier selections in the same iteration were not charged, so many individually
admissible calls could greatly exceed the configured combined-size limit.

The patch retains a cumulative expression estimate while selecting actions for
each caller. It preserves the configured limit and the existing bytes-per-expression
heuristic; it does not introduce an exact encoded-size proof. Subsequent iterations
remeasure the modified IR as before. This avoids unbounded growth within an
iteration while allowing further inlining after optimization reduces the body.
The new fixture demonstrates the old failure and preserves imported-call order
under both a restrictive and a permissive budget. Existing limit expectations
are updated to account for cumulative growth.

## Build and compare

Apply the patches to the exact revision using `git apply`. To isolate the writer,
build with only `bounded-stackir.patch` first. A native build can use:

```sh
cmake -S SOURCE -B BUILD -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_LLVM_DWARF=ON \
  -DBYN_ENABLE_ASSERTIONS=ON
cmake --build BUILD --target wasm-opt -j2
```

`compare-writers.py` uses the pinned source's existing fixtures and compares
binary output, StackIR text and source maps at one, two and four workers. It
covers generation with and without StackIR optimization, `-O2`, `-O3`, and the
direct IR writer. Fixtures include both exception representations, non-nullable
locals, multivalue operations, annotations, DWARF, imports and incomplete batches.
Results and tool hashes are written to the output directory.
Use the writer-only candidate for byte-identity comparisons; the inlining patch
intentionally changes optimization choices when cumulative growth reaches the
configured limit.

```sh
python3 compare-writers.py --baseline ORIGINAL_WASM_OPT \
  --candidate PATCHED_WASM_OPT --source SOURCE --output COMPARISON
```

`measure-writer-memory.py` generates a many-function module, verifies identical
binaries, and records peak RSS and elapsed/CPU time. It requires Linux GNU
`/usr/bin/time`. Use original and patched tools built with identical native
compiler, allocator and CMake settings when attributing a memory change.

```sh
python3 measure-writer-memory.py --baseline ORIGINAL_WASM_OPT \
  --candidate PATCHED_WASM_OPT --output MEMORY_COMPARISON
```

After applying the inlining patch, run its fixed upstream fixtures and the
execution-order check with Python, Node.js and LLVM FileCheck:

```sh
python3 check-inlining-budget.py --baseline ORIGINAL_INLINER_WASM_OPT \
  --candidate CORRECTED_INLINER_WASM_OPT --source SOURCE \
  --filecheck FILECHECK --output INLINING_COMPARISON
```

The original inliner is expected to fail the new restrictive-budget assertion;
the corrected inliner must pass. Both must preserve the expected call sequence.

These scripts are explicit native integration checks. They are not part of the
ordinary JavaScript test suite.
