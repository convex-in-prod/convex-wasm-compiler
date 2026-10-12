# Guest runtime compatibility

The guest runtime is Static Hermes with compiler-owned capability adapters.
Successful execution in V8 alone does not establish guest compatibility. The
[authenticated runtime surface](../scripts/lib/convex-wasm-runtime-surface.mjs)
records the available APIs, defaults and semantic dependencies. This document
describes the native Intl configuration in the current source tree; compiler
releases through v0.2.30 used a smaller handwritten JavaScript adapter.

## Native Intl

The target builds Hermes's static ICU provider and links its code and complete
locale dataset as one reusable archive. Intl is an engine global. The shared
JavaScript support bundle supplies DOMException and URL APIs and does not
replace Intl. Setup requires the same static provider in the host Hermes build
because native codec and request validation execute it there as well.

The provider exposes:

- `Intl.DateTimeFormat`, including `format`, `formatToParts`, `formatRange`,
  `formatRangeToParts`, `resolvedOptions` and `supportedLocalesOf`.
- `Intl.NumberFormat`, with the corresponding methods and exact numeric-string
  and BigInt inputs.
- `Intl.Collator`, including bound comparison, resolved options and locale
  support queries.
- `Intl.getCanonicalLocales` and the native date, number, BigInt and string
  locale convenience methods.

Locale support comes from the selected ICU service resources, with standard
lookup fallback. There is no application-selected locale allowlist. Date and
number options include calendars, numbering systems, named/fixed-offset zones,
styles, units, currencies, rounding and notation. Passing the differential
corpus establishes only the cases actually exercised, not every possible
combination or complete ECMA-402 conformance.

## Differences from V8

The implementation is not a byte-identical replacement for every V8 build.
The [native provider identity](../scripts/lib/convex-wasm-native-intl.mjs)
authenticates its semantic inputs. Current boundaries are:

| Boundary | Guest behavior | Consequence for comparison |
| --- | --- | --- |
| Default locale and timezone | en-US and UTC, independent of the embedding process | V8 hosts with different defaults can produce different text and resolved options. Use explicit options when defaults are not the intended contract. |
| Data versions | ICU 78.2, CLDR 48, timezone data 2025c | Locale names, patterns, calendar data, zone aliases and offsets can differ from a host with other data. The local Node reference has timezone data 2026a. |
| Constructor families | DateTimeFormat, NumberFormat and Collator | Locale, PluralRules, RelativeTimeFormat, ListFormat, DisplayNames, Segmenter and DurationFormat are absent. `Intl.supportedValuesOf` is also absent. |
| Locale matching | Lookup for both `lookup` and `best fit` | Matches the pinned V8's default configuration; its experimental best-fit matcher and other engine configurations are not covered. |
| Clock observations | Native date formatting with an omitted value reads the guest realtime clock | The embedding host must provide the invocation clock and account for that observation. A JavaScript Date facade alone does not intercept it. |
| Error text | Native Hermes/provider error messages | Error classes and observable coercion order are tested; messages and stack traces are not V8-identical. |
| Intrinsic hardening | Compiler policy prevents extension and validates intrinsic descriptors | Ordinary V8 objects may permit mutations that the retained guest runtime rejects. |
| Native allocation failure | ICU exhaustion traps the Wasm instance | This is not a catchable JavaScript error. The host must discard the instance without further guest calls or cleanup. |

Matching data versions alone is insufficient. The provider also implements
explicit compatibility behavior from Node 24.15.0 / V8
13.6.233.17-node.48: date strings normalize U+202F while parts preserve it;
resolved date fields follow V8's pattern rules; collapsed date ranges preserve
its fractional-time behavior; and range-part source labels follow its ownership
rules. These decisions are covered by generic differential corpora, not a promise
about future V8 versions.

The retained [port and conformance evidence](https://github.com/convex-in-prod/convex-wasm-compiler/tree/main/experiments/intl-icu-provider)
identifies the exact source stages, references, artifact hashes and limitations.
Full native-memory accounting, host fuel/cancellation behavior, trapped-instance
discard and adopting-host comparisons are separate integration acceptance checks.
A formatter corpus does not establish those properties.

Consumers can run their own formatting cases with
`scripts/lib/convex-wasm-native-runtime-probe.mjs`. Its
`runNativeRuntimeProbe` function takes typed JavaScript defining
`globalThis.__convexNativeRuntimeProbe` and a configuration returned by
`nativeRuntimeProbeConfiguration`. The synchronous probe returns a
JSON-serializable value. It runs three times in each of three runtimes, with GC
between calls and native intrinsic validation before and after each call. The
builder returns all nine results and hashes of the generated program, linked
Wasm, runtime archives and C++ fixture. Input cases remain with the consumer.

The caller runs native compilation under its resource guard and configures
`CONVEX_HERMES_TEST_SOURCE_ROOT`, `CONVEX_HERMES_TEST_BUILD_ROOT`,
`CONVEX_HERMES_TEST_WASM_BUILD_ROOT`, `CONVEX_WASM_EMCC` and
`CONVEX_WASM_RUNNER`. The probe uses a 128 MiB linear-memory maximum, a 512 KiB
stack, and a 2 MiB initial heap. It rejects capability and randomness requests.
This diagnostic uses the actual runtime initializer and descriptor validator;
it does not execute a backend capability package or establish host admission,
fuel accounting, cancellation or instance-discard behavior.

The same module exports `runNativeResourceProbe`. It initializes native Intl,
then exercises libc malloc/realloc and C++ container growth outside the ICU and
Hermes GC counters. With a 64 MiB host limit below the module's 128 MiB maximum,
all three stress cases trap on denied memory growth; a small-allocation control
returns and destroys its runtime normally. The diagnostic runner reads only
host-owned evidence after a trap and destroys the Store without guest reentry.
This establishes bounded allocation/admission behavior, not exhaustive allocator
failure injection or an adopting backend's disposal policy. The
[resource results](https://github.com/convex-in-prod/convex-wasm-compiler/blob/main/experiments/intl-icu-provider/native-resource-result-summary.json)
identify the exact module and archives. Adapter and ICU licenses ship in
`scripts/vendor/convex-wasm-native-intl/`.

## Application responsibilities

Keep exact paired-result comparisons. Review locale-sensitive operations that
feed stored values, hashes, cursors or ordering as carefully as displayed text.
Where output is a fixed application convention, make that convention explicit
in application code and execute the same code in both engines. Do not infer
cross-engine parity from formatting examples alone or weaken paired comparison
to conceal a difference.
