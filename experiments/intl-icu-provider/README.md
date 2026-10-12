# Native Intl Wasm experiment

This standalone implementation ports Microsoft's ICU-backed Hermes adapter to a
static Wasm build and replaces its date/number formatter paths. It is **not part
of the released compiler or guest runtime**. Compiled Static Hermes JavaScript
calls native Hermes `Intl`; ICU code and locale data execute inside Wasm.
Emscripten supplies Node host glue. Formatting is not delegated to host `Intl`.

Pinned inputs:

- Hermes: `4ae2b227fd777b46008e84bf695daeb4586c5f63`.
- [Microsoft adapter and ICU source](https://github.com/microsoft/hermes-windows/tree/680ae7651c2f55cbbacaed0cc11519fe6c253f72):
  `680ae7651c2f55cbbacaed0cc11519fe6c253f72`.
- ICU 78.2, CLDR 48.0, bundled timezone data 2025c.
- Emscripten 6.0.5, standard Wasm exceptions, compatible host `shermes` and
  `ImportHostCompilers.cmake`.
- Local reference: Node 24.15.0, V8 13.6.233.17-node.48, ICU 78.2, CLDR 48.0,
  timezone data 2026a. This is a local reference, not a deployment identity.

`prepare.py` verifies the source archive SHA-256, extracts the adapter and ICU,
records file hashes, and creates a detached Hermes worktree. Microsoft MIT
notices and ICU licensing files remain with those sources. `port.py` removes
Windows loading and fallback selection, supplies a required static provider,
and adds an opt-in CMake implementation.

## Implementation

`formatters.patch` contains the reviewable C++ changes. `apply-formatters.py`
checks every input hash and the patch hash before applying it, then checks all
output hashes. It rejects an unexpected source tree or duplicate application.
The patch follows `fix-adapter.py`, preserving the earlier diagnostic baseline.
Provider-specific interface changes are guarded by
`HERMES_USE_STATIC_INTL_PROVIDER`; other platform signatures remain available.

`bindings.patch` is a separate follow-up against that exact formatter baseline.
Apply it with `apply-formatters.py --stage bindings`; `bindings-source.json`
authenticates its inputs and outputs. Date/number initialization reads options
on demand in specified order. Numeric precision values remain rooted until the
initializer determines whether to convert them; unused precision values are read
without conversion. Locale elements are canonicalized before the next element
is read, including proxy `has`/`get` behavior and holes. Derived constructors read
and use `newTarget.prototype` before locale and option processing.

The same ordered reader handles date/number convenience methods and supported
locale queries. Date convenience methods pass their required/default component
modes into the provider. BigInt `toLocaleString` now uses the exact-number
formatter instead of ignoring its locale/options arguments.

`construction.patch` follows the bindings stage. It implements legacy constructor
chaining with a rooted, shared non-registry symbol and immutable fallback slots.
Only `format` and `resolvedOptions` unwrap compatible legacy receivers;
`formatToParts` requires native slots. Native slots take precedence on genuine
instances. Intrinsic constructors no longer leak onto the global object.

`locales.patch` follows construction. It fixes BCP47 variant grammar and removes
the canonicalizer's fixed output limit. Canonicalization uses ICU LocaleBuilder
and CLDR aliases, including the reference V8's lowercase language-tag fast path.
Date and number locale sets validate their corresponding ICU resources.
With its default flags, the pinned V8 uses lookup for both `localeMatcher` values;
this provider follows that behavior. This does not establish compatibility with
V8's experimental best-fit flag or other V8 versions.

`number-ranges.patch` follows locales. It adds `NumberFormat.formatRange` and
`formatRangeToParts` with strict receivers, ordered endpoint conversion, exact
mixed decimal/BigInt/double inputs and lazy native formatter reuse. Number and
range parts share field partitioning. V8 assigns source ownership to complete
parts: a literal crossing an endpoint span is `shared`, without splitting it at
the span boundary. This rule handles accounting punctuation and bidi literals
without locale-specific exceptions.

`icu-cleanup.patch` fixes an ICU 78.2 shutdown ordering defect found by the
allocation harness. Unified-cache destruction can recreate locale caches after
their earlier cleanup slot. Locale cleanup now follows the unified cache and
precedes resource-bundle cleanup. The code patch is separate from the unchanged
pinned locale dataset.

Number strings and parts use the same modern ICU `unumf` formatter and formatted
value APIs. The implementation handles units, currencies, accounting signs,
scientific/engineering/compact notation, grouping, fraction/significant precision,
rounding priority, rounding modes/increments and trailing-zero policy. ICU field
ranges are partitioned without duplicating grouped digits. The VM preserves
exact numeric strings and BigInt and emits object properties in specified order.

Date formatting resolves locale lists, calendar and numbering options through
ICU. It handles all four hour cycles, style conversion, day periods, fractional
seconds, fixed-offset zones and proleptic Gregorian dates. Parts include standalone
months, related years, year names and the different timezone fields. Date/number
formatting failures propagate as JavaScript errors; empty strings and fabricated
literal parts are no longer used to hide those failures. Date parts use a sized
buffer and validate field bounds and non-overlap.

Compatibility with the reference V8 includes rules outside ICU itself:

- `format()` replaces U+202F with ordinary spaces; date parts preserve ICU text.
- Hour-cycle symbols are enforced after ICU pattern selection. Style changes
  between 12/24 hours regenerate patterns, including day-period placement.
- Preferred 12/24-hour cycles follow the reference V8's CLDR-derived rule.
- Date `resolvedOptions()` uses V8's ordered pattern-substring matching, including
  its treatment of quoted text and omission of one/two-letter era patterns.
  Consequently metadata can include a component that is not formatted. This
  compatibility metadata does not drive the actual ICU formatter.

These rules were checked against the pinned Node source's
[`js-date-time-format.cc`](https://github.com/nodejs/node/blob/v24.15.0/deps/v8/src/objects/js-date-time-format.cc)
and [`intl-objects.cc`](https://github.com/nodejs/node/blob/v24.15.0/deps/v8/src/objects/intl-objects.cc).
Locale selection uses ICU data, without application-specific locale tables.

## Reproduce

Prerequisites: Python 3.11+, Node 24, Git, CMake, Ninja, Emscripten 6.0.5,
Binaryen and a compatible host Hermes build. Use the resource guard required by
your environment for downloads/builds. The driver uses four C++ workers and two
Emscripten/Binaryen workers. Outputs belong outside this repository; imported
host compiler paths must remain valid. SDK paths are canonicalized to avoid
invalidating Emscripten caches when aliases point at the same installation.

From this directory, with caller-selected absolute paths:

```sh
export INTL_EXPERIMENT_ROOT=/absolute/path/to/experiment
export INTL_EXPERIMENT_URL="file://$INTL_EXPERIMENT_ROOT/"
export INTL_HERMES_SOURCE=/absolute/path/to/hermes
export INTL_HOST_BUILD=/absolute/path/to/host-build
export EMSDK=/absolute/path/to/emsdk
export EM_BINARYEN_ROOT=/absolute/path/to/binaryen

python3 prepare.py --output "$INTL_EXPERIMENT_ROOT" --hermes-source "$INTL_HERMES_SOURCE"
python3 fix-adapter.py "$INTL_EXPERIMENT_ROOT"
python3 apply-formatters.py "$INTL_EXPERIMENT_ROOT"
python3 apply-formatters.py "$INTL_EXPERIMENT_ROOT" --stage bindings
python3 apply-formatters.py "$INTL_EXPERIMENT_ROOT" --stage construction
python3 apply-formatters.py "$INTL_EXPERIMENT_ROOT" --stage locales
python3 apply-formatters.py "$INTL_EXPERIMENT_ROOT" --stage number-ranges
python3 apply-formatters.py "$INTL_EXPERIMENT_ROOT" --stage icu-cleanup
python3 build.py runtime --root "$INTL_EXPERIMENT_ROOT" --host-build "$INTL_HOST_BUILD" --emsdk "$EMSDK" --binaryen "$EM_BINARYEN_ROOT"
node make-corpus.mjs
node number-contracts.mjs
node date-contracts.mjs
node --expose-gc binding-contracts.mjs
node --expose-gc construction-contracts.mjs
node locale-contracts.mjs
node --expose-gc number-range-contracts.mjs
for variant in probe contracts dates bindings construction locales ranges; do
  python3 build.py "$variant" --root "$INTL_EXPERIMENT_ROOT" --host-build "$INTL_HOST_BUILD" --emsdk "$EMSDK" --binaryen "$EM_BINARYEN_ROOT"
  node run-probe.mjs "$variant" > "$INTL_EXPERIMENT_ROOT/$variant-actual.json" 2> "$INTL_EXPERIMENT_ROOT/$variant-stderr.log"
done
node compare.mjs probe --require-parity
node compare-contracts.mjs contracts --require-parity
node compare-contracts.mjs dates --require-parity
node compare-bindings.mjs --require-parity
node compare-bindings.mjs construction --require-parity
node compare-bindings.mjs locales --require-parity
node compare-bindings.mjs ranges --require-parity
```

The comparators save complete differences and exit unsuccessfully when a row
differs under `--require-parity`. Expected errors compare exception classes,
not implementation-specific messages. Capability inventory still records missing
date-range methods; number-range support does not imply complete Intl coverage.

To reproduce historical variants, build/run the original corpus before
`fix-adapter.py`, then after that script and before `apply-formatters.py`.
Save each variant's outputs separately. Historical summaries retain the original
harness and Wasm hashes. The current harness adds explicit defaults, forced GC,
and lifecycle exports; rebuilding an older implementation stage with it checks
behavior but need not reproduce the historical Wasm bytes. The linker explicitly assembles the ICU
data object because the parent Hermes project does not enable ASM. `.mjs`
outputs are factories; `run-probe.mjs` instantiates and executes them.

For the existing compiler Wasmtime diagnostic runner, link standalone reactors
and check repeated runtime destruction in one Wasm instance:

```sh
export INTL_WASMTIME_RUNNER=/absolute/path/to/convex-wasm-wasmtime-runner
export RAYON_NUM_THREADS=2
for variant in construction bindings ranges; do
  python3 build.py "$variant" --standalone --root "$INTL_EXPERIMENT_ROOT" --host-build "$INTL_HOST_BUILD" --emsdk "$EMSDK" --binaryen "$EM_BINARYEN_ROOT"
  mkdir -p "$INTL_EXPERIMENT_ROOT/standalone-$variant"
  cp "$INTL_EXPERIMENT_ROOT/$variant-reference.json" "$INTL_EXPERIMENT_ROOT/standalone-$variant/$variant-reference.json"
  "$INTL_WASMTIME_RUNNER" "$INTL_EXPERIMENT_ROOT/$variant-standalone.wasm" intl_probe_lifecycle_run > "$INTL_EXPERIMENT_ROOT/standalone-$variant/lifecycle-actual.jsonl" 2> "$INTL_EXPERIMENT_ROOT/standalone-$variant/lifecycle-stderr.jsonl"
  INTL_EXPERIMENT_URL="file://$INTL_EXPERIMENT_ROOT/standalone-$variant/" node compare-lifecycle.mjs "$variant"
done
```

Use the same resource guard for linking and Wasmtime compilation/execution.
The lifecycle comparator requires parity, an exactly repeating allocator pattern
over the final eight cycles, constant ICU requested bytes and allocation count,
and zero ICU allocations after cleanup. The `intl_probe_run` export runs the
corpus once. Run `node --test compare-lifecycle.test.mjs` for the comparator's
retention-growth, cleanup and output-mismatch rejection checks.

## Recorded results

| Corpus | Valid rows matching strings, ordered parts and resolved metadata | Matching expected errors |
| --- | ---: | ---: |
| Original mixed corpus | 1,263 / 1,263 | 0 |
| Expanded number contracts | 4,950 / 4,950 | 14 / 14 |
| Expanded date contracts | 1,276 / 1,276 | 5 / 5 |

All **7,508 cases** match the checked outputs. Original rows also match raw JSON;
expanded corpora check property insertion order explicitly. There are no
unexpected exceptions, parts reconstruction failures, or lost prior matches.
The original corpus spans ten generic locales; expanded matrices cover 47 number
profiles and 26 date profiles, plus coercion, locale-list and invalid-option
controls. These are bounded differential tests, not full ECMA-402 conformance.

`formatter-result-summary.json` records counts and source/corpus/artifact hashes.
`result-summary.json` preserves the historical initial-port results: 999/1,263
strings and 744 parts, then 1,059 strings and 1,011 parts after two corrections.
The new implementation resolves the ignored options, split unit formatter,
coercion, locale, date pattern and output-order defects exposed there.

The binding follow-up passes **514 / 514** cases: 111 successful results and
403 expected exceptions, with matching observable access/conversion traces.
The formatter-only baseline matched just 37 / 184 of the initial binding cases.
Expanded controls cover throwing getters, primitive options, sparse/proxy locale
lists, subclass construction, all five date/number/BigInt convenience methods,
and invalid receivers. Forced collection occurs after otherwise-unreferenced
numeric option objects have been read; later coercion reenters Intl. The three
formatter corpora still pass all 7,508 cases after this change.

The standalone harness pins ICU defaults to `en-US` and `UTC`; reference and
Node execution also use UTC. This avoids host-dependent default-zone metadata
from Emscripten glue. It does not establish the production runtime's default
contract. `binding-result-summary.json` retains counts and hashes separately
from the completed formatter baseline.

The standalone Wasmtime reactor also passes all **514 / 514** binding cases,
without Node glue. Its 11 import names and function signatures are present in
the compiler's existing host allowlist; the summary records those imports and
the compared allowlist identity. No host ABI or backend change was needed for
this diagnostic. This does not validate production entry initialization,
intrinsic hardening, authenticated package construction or deployed pairing.

The lifecycle export creates and destroys 16 Hermes runtimes in the same Wasm
instance. All 8,224 repeated case executions match. Allocator-reported live bytes
at the binding checkpoint remain exactly 664,040 throughout; the comparator requires
an exact plateau over the last eight cycles. This measure excludes embedded ICU
data and reserved Wasm memory. It demonstrates bounded retention for this corpus,
not complete native-memory accounting or allocation-failure safety.

The construction follow-up passes **149 / 149** cases, up from 103 / 149. It
covers descriptors, global visibility, legacy receivers, immutable fallback
slots, proxies, subclasses, forced GC and native-slot precedence. The locale
follow-up passes **6,886 / 6,886** cases; its initial baseline matched 6,672 of
6,778. Coverage includes all two-letter language tags, aliases, scripts, variant
grammar, malformed and long private-use tags, priority lists and service-specific
supported/resolved locale behavior. All earlier 7,508 formatter and 514 binding
cases still pass against the combined implementation.

`conformance-result-summary.json` records this checkpoint separately. In Wasmtime,
16 repeated runtimes pass all 2,384 construction and 8,224 binding executions.
Live allocated bytes after every destruction remain 824,872 for the construction
workload and 846,136 for bindings. These counts include the new validated locale
caches. They are workload-specific plateaus, not a requirement to retain the
older checkpoint's absolute count.

The number-range implementation passes **3,342 / 3,342** cases, including
56 matching expected errors. Its first comparison matched 3,240; all 102 remaining
differences were part boundaries/source ownership, while strings already matched.
Correct field partitioning resolves those differences. The seven corpora together
pass **18,399** cases. Range controls cover collapsed/approximate output, rounding,
accounting, bidi literals, units, exact mixed inputs, infinities, negative zero,
reversed endpoints, reflection, coercion order, GC and reentrancy.

In standalone Wasmtime, all **53,472** range executions match across 16 runtimes.
ICU retains exactly **806,130 requested bytes / 6,986 allocations** after each
runtime is destroyed. Aggregate malloc bytes alternate between **1,003,960** and
**1,003,968**. The initial uninstrumented allocator count also alternated by eight
bytes (958,480 / 958,488), failing the older fixed-count check. The comparator now
requires an exactly repeating final allocator pattern and exact ICU payload/count
stability; it does not allow a byte tolerance for growing retention.

The first explicit ICU shutdown left five allocations totaling 2,322 bytes. A
cleanup-phase trace located their creation during unified-cache destruction,
after locale cleanup. With `icu-cleanup.patch`, tracked ICU bytes and allocation
count both reach zero after one `u_cleanup`. Native provider C++ caches, static
data and reserved Wasm memory are outside that zero-allocation claim. Allocation
failure handling and production budget integration still require their own work.

`number-range-result-summary.json` retains these results, the initially failed
allocator evidence, current source/harness/artifact hashes and all 11 verified
host import signatures. Earlier corpus artifacts were built at the number-range
stage; the final standalone artifact also includes the cleanup fix and accounting
harness. All six patch stages reconstruct the 15 modified source files exactly.

## Limits and integration boundary

Date/number options now use an ordered reader with the bounded coverage above.
Constructor/reflection and locale behavior have the directed coverage above;
date-range methods remain absent. Number ranges have the coverage above.
Collator still uses the old eager option map. These matrices do not establish
full Test262 conformance or compatibility with V8's experimental best-fit matcher.
Additional ICU fallback/error paths in shared locale and collator code remain
outside this formatter audit.

The original-corpus Wasm is 38,914,963 bytes (about 37.11 MiB), including the full
33,107,248-byte ICU dataset. Its data SHA-256 is
`a3d49eacd189624769dc77457c6aa1789a89219fb217a6d87d5b076c269aaf1f`.
Wasm uses 128 MiB initial memory and a 512 MiB cap. No performance or incremental
backend-cost claim follows from this correctness experiment.

Production integration still requires authenticated compiler imports/builds and
hardening, deterministic defaults, code/data packaging, native-memory and GC
lifecycle accounting, allocation-failure checks, and cancellation/fuel behavior.
Explicit final GC and the bounded repeated-runtime lifecycle check pass.
Forced mid-initialization collection with deferred numeric values also passes.
ICU/CLDR match the local reference but timezone datasets differ. Compare with the
actual adopting V8 runtime before claiming paired compatibility. Keep the released
runtime's limitations documented separately in
[the runtime compatibility inventory](../../docs/runtime-compatibility.md).
