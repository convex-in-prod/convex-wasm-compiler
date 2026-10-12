# Runtime compatibility

This document describes the guest runtime shipped in **v0.2.30**. It is not a
complete ECMAScript/ECMA-402 implementation or a byte-for-byte V8 replacement.
The compiler's language admission checks and authenticated runtime inventory do
not prove identical output, exceptions, or reflective behavior for arbitrary
programs. A policy entry marked `implemented` means that the described surface
exists, not that every standard behavior is implemented.

The [runtime-surface policy](../scripts/lib/convex-wasm-runtime-surface.mjs)
records installed capabilities, unavailable globals, and host-specific behavior.
The [Intl source](../scripts/vendor/convex-wasm-runtime-support/intl-subset.js.txt)
is the authority for the details below. This inventory covers the known Intl
limitations; it is not an exhaustive audit of every Hermes/V8 difference.

## Intl installation and locale selection

Native Hermes Intl is disabled in the packaged toolchain. The guest installs a
handwritten JavaScript adapter with only `Intl.DateTimeFormat` and
`Intl.NumberFormat`. It does not connect these constructors to a general ICU
implementation. Other constructors, including `Collator`, `PluralRules`,
`RelativeTimeFormat`, `ListFormat`, `DisplayNames`, `Segmenter`, and `Locale`,
are absent. So are `getCanonicalLocales`, `supportedValuesOf`, and both
constructors' `supportedLocalesOf` methods.

Locale support is a finite, case-insensitive lookup table. The exact admitted
tags are in `convexWasmTargetRuntimeSurfacePolicy.intl.locales` in the linked
policy; there is no general BCP 47 canonicalization, Unicode extension handling,
parent-locale fallback, or locale negotiation. Only a string or an array of
strings is accepted. **Every array member must be supported**, even after a
supported first choice. Locale objects and other array-like objects are rejected.
An omitted locale or empty array selects the fixed `en-US` default; it does not
consult the host's locale. The first admitted array member is selected.

## DateTimeFormat

| Surface                                            | Guest behavior                                                                                                                                                                              |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Methods                                            | `format`, `formatToParts`, `resolvedOptions`; no `formatRange` or `formatRangeToParts`.                                                                                                     |
| Calendar / numbering                               | Omitted or exactly `gregory` / `latn`. Other values throw `RangeError`.                                                                                                                     |
| `year`, `month`, `day`, `hour`, `minute`, `second` | Omitted, `numeric`, or `2-digit`. Month names of any width are rejected.                                                                                                                    |
| `weekday`                                          | Omitted or `short`; `long` and `narrow` are rejected.                                                                                                                                       |
| No component fields                                | Defaults to numeric year, month, and day.                                                                                                                                                   |
| Hours                                              | Only `h23`. An hour field requires explicit `hour12: false` or `hourCycle: "h23"`. Truthy `hour12` values are rejected; falsy values are accepted through Boolean conversion.               |
| Time zone                                          | Defaults to `UTC`. Named zones and aliases use pinned IANA **2026c** data. Signed offsets accept `±HH`, `±HHMM`, or `±HH:MM`, up to 23:59. Both zero-offset signs canonicalize to `+00:00`. |
| Input                                              | Omitted/undefined uses `Date.now()`; otherwise `Number(input)`, followed by finite/date-range checks and truncation toward zero.                                                            |

These present, non-undefined options always throw `RangeError`: `dateStyle`,
`dayPeriod`, `era`, `formatMatcher`, `fractionalSecondDigits`, `localeMatcher`,
`timeStyle`, and `timeZoneName`. This includes standard default-valued requests
such as `localeMatcher: "best fit"`.

Accepted component options do **not** guarantee V8 output parity. The adapter
assembles parts with fixed locale patterns, separators, ordering, and width
adjustments; it does not implement ICU/CLDR pattern selection. Partial field
sets can differ in values, punctuation, padding, parts, and `resolvedOptions()`.
Time-zone aliases and historical/future offsets can also differ when the host
uses another tzdata version. Full IANA zone coverage is not full Intl support.

## NumberFormat

| Surface                                | Guest behavior                                                                                                                                                        |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Methods                                | `format`, `resolvedOptions`; no `formatToParts`, `formatRange`, or `formatRangeToParts`.                                                                              |
| `style`, `notation`, `numberingSystem` | Omitted or exactly `decimal`, `standard`, `latn`, respectively.                                                                                                       |
| `useGrouping`                          | Omitted, `true`, or `"auto"`; grouping cannot be disabled. Groups contain three digits.                                                                               |
| `minimumIntegerDigits`                 | Omitted or converts with `Number(...)` to exactly 1.                                                                                                                  |
| `maximumFractionDigits`                | Required; converts with `Number(...)` to exactly 0 or 2. The standard default is not implemented.                                                                     |
| `minimumFractionDigits`                | Defaults to 0; converts to exactly 0 or 2 and must not exceed the maximum.                                                                                            |
| Input                                  | Primitive BigInt is formatted exactly; every other input first goes through `Number(input)`. Numeric strings and BigInt wrapper objects can therefore lose precision. |
| Rounding                               | Handwritten decimal rounding from the number's `toString()` representation, with half ties away from zero. This is not a general ICU rounding implementation.         |

These present, non-undefined options always throw `RangeError`: `compactDisplay`,
`currency`, `currencyDisplay`, `currencySign`, `maximumSignificantDigits`,
`minimumSignificantDigits`, `roundingIncrement`, `roundingMode`, `roundingPriority`,
`scale`, `signDisplay`, `trailingZeroDisplay`, `unit`, and `unitDisplay`.
Even explicit default settings such as `roundingMode: "halfExpand"` are rejected,
although `resolvedOptions()` reports that value.

## Demonstrated differences from V8

The following examples were checked against Node **24.15.0**, V8
**13.6.233.17-node.48**, ICU **78.2**, and host tzdata **2026a**. `GuestIntl` means
the linked adapter initialized with its packaged timezone data. These are
library comparisons, not compiled-Wasm execution tests. V8/ICU versions can
change formatting, so the reference version is part of the evidence.

| Expression (replace `I` with `GuestIntl` or native `Intl`)                           | Guest                     | Reference V8              |
| ------------------------------------------------------------------------------------ | ------------------------- | ------------------------- |
| `new I.DateTimeFormat("en-US", {timeZone: "UTC", minute: "2-digit"}).format(0)`      | `"00"`                    | `"0"`                     |
| The same formatter's `resolvedOptions().minute`                                      | `"2-digit"`               | `"numeric"`               |
| `new I.DateTimeFormat("en-US", {timeZone: "UTC", year: "numeric"}).format(0n)`       | `"1970"`                  | Throws `TypeError`        |
| `new I.NumberFormat("en-US", {maximumFractionDigits: 0}).format("9007199254740993")` | `"9,007,199,254,740,992"` | `"9,007,199,254,740,993"` |
| `new I.NumberFormat("en-US")`                                                        | Throws `RangeError`       | Constructs a formatter    |
| `new I.DateTimeFormat("en-US", {timeZone: "UTC", month: "long"}).format(0)`          | Throws `RangeError`       | `"January"`               |

## Construction, reflection, and related expressions

Options are ordinary property reads with adapter-specific order and conversions.
For example, component styles must already be exact strings; an object with a
`toString()` returning `"numeric"` is rejected. The tables enumerate checked
options, **not** a blanket rejection of every unknown key: unexamined keys are
ignored, and NumberFormat does not inspect `localeMatcher`. Null options throw
`TypeError`; other primitives are boxed. Getters, proxies, coercion side effects,
exception wording, and which error occurs first are not ECMA-402-equivalent.

Constructors can be called with or without `new`, but use ordinary JavaScript
functions and WeakMap slots. Standard legacy constructor chaining and its hidden
fallback receiver semantics are not implemented. Function metadata and property
descriptors differ. The guest also freezes the Intl object, both constructors,
their prototypes, and method functions as part of runtime hardening; mutation
does not behave like an ordinary unfrozen V8 environment.

Installing this adapter does not implement ICU collation or retrofit the engine's
`String.prototype.localeCompare`, `toLocaleLowerCase`, `toLocaleUpperCase`, or
the Number/BigInt/Date/Array `toLocaleString` family. `toLocaleDateString` and
`toLocaleTimeString` are not aliases of these guest constructors. Do not infer
parity for those expressions from a passing Intl constructor test.

## Application compatibility boundary

Keep exact comparison of results, errors, and database effects. If presentation
does not require locale-selected text, define the presentation in application
code and execute the same implementation in both engines. Preserve meaningful
calendar, time-zone, precision, and scheduling semantics. A deterministic label
is not a reason to replace a named time zone with a fixed offset.

For remaining Intl uses, review the exact locale/options, methods, input types,
and value domain. Compare the consumed output against the deployed V8 version,
including boundary dates, transitions, rounding, and non-ASCII literals. Merely
accepting the constructor options is insufficient. Syntax lint can block
unreviewed calls, aliases, unsupported methods, and locale-sensitive convenience
expressions, but cannot establish equivalence for all runtime values or arbitrary
property access. Compatibility gaps remain documented here even when no adopting
application currently exercises them.
