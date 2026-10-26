# Changelog

Release changes and upgrade notes. For the complete history, see
[GitHub releases](https://github.com/convex-in-prod/convex-wasm-compiler/releases).

## 0.2.54

- Scale leaf-selector AOT worker reservations with the authenticated input working
  set, matching shared-library AOT scheduling. Small selectors leave worker slots
  available for independent compilation and linking jobs.
- Pass the reserved worker count to the precompiler while preserving configured
  ceilings, memory admission, and oversized-job isolation.

This JavaScript-only release reuses the native compiler and precompiler package
selection from 0.2.53. Native binaries, backend ABI, and generated runtime behavior
are unchanged.

## 0.2.53

- Generate dependency dispatch as static tables indexed by the authenticated
  per-module occurrence, followed by an exact specifier comparison. This avoids
  optimizing large chains of string comparisons when compiling application
  selectors and bounds runtime lookup to one candidate, without allocations.
- Preserve function selection, dependency authorization, and the backend ABI.
  Existing native toolchain packages remain compatible; the generated selector
  source and compiler producer identities invalidate affected cached artifacts.

## 0.2.52

- Support the SDK's separate database and action initializer groups. Database
  groups retain all eligible forwarding entries; action groups include only
  selected actions. Disabling action grouping preserves database grouping.
- Preserve the legacy SDK helper's disjoint groups and string initializer policy.
  Reject unknown helper signatures and authenticate imported helper code by its
  source digest when an SDK is replaced in a running process.
- Pin the development and example SDK to the compatible split-initializer producer.
- Cover initializer membership, exclusions, SDK replacement, and exact deployment
  source and source-map parity with generic regression fixtures.

Upgrade the backend before deploying version 2 grouped initializer metadata.
Native compiler and precompiler sources, Wasmtime artifact compatibility, and
the backend ABI are unchanged from 0.2.51.

## 0.2.51

- Use tsrs throughout source analysis, removing the classic TypeScript compiler
  dependency. Authenticate installed compiler material and dependency observations
  before publishing API inventories, including missing dependencies and symlinked
  or nested native packages.
- Put API result caches under the shared, project-scoped `TSRS_CACHE_DIR` root.
  These store analysis results; they do not add incremental semantic snapshots
  or consume CLI `.tsbuildinfo` files. See
  [source analysis and tsrs caches](README.md#source-analysis-and-tsrs-caches)
  for dependency, platform, and retention requirements. The pinned tsrs package
  has no macOS x64 binary, so full application builds on Intel macOS are unsupported.
- Continue immutable cache cleanup until measured occupancy reaches the
  configured high watermark or no more entries can be reclaimed. Remove the
  entry-count and reclaimed-byte ceilings and align pressure with reported occupancy.
- Hold the cache lock during binding and registry publication, including all
  pending reads and artifact copies on failure, so cleanup cannot evict their inputs.
- Clarify the compiler/backend boundary and link the build, runtime, and
  context-reuse documentation.

Native compiler and precompiler sources, Wasmtime artifact compatibility, and
the backend ABI are unchanged from 0.2.50.

## 0.2.45

Extend bounded Static Hermes RegExp matchers to non-Unicode case-insensitive
UTF-16 literals and capture-free forward alternatives. Ordered backtracking and
existing matcher budgets are preserved. Unsupported patterns retain ordinary
execution. The Rust compiler and precompiler packages, Wasmtime artifact format,
and backend ABI are unchanged; native packages from 0.2.44 are reused.

## 0.2.44

Adopt guarded whole-operation RegExp specialization and bounded AOT matchers in
Static Hermes. Eligible literals avoid repeated interpreter work and intermediate
match/replacement allocations; unsupported operands and observable builtin
overrides retain ordinary execution. The Wasmtime artifact format and backend
ABI are unchanged.

## 0.2.43

Refresh Hermes, Oxc, and Wasmtime from upstream. Wasmtime's changed tunables and
builtin layout require new native artifact metadata. The precompiler and matching
backend use Wasmtime `ba13bdffaa34c4cfa6af8ceb58275e761593a885`; native artifacts
from the previous engine must be regenerated before activating the backend with
those application generations. Portable Core Wasm remains compatible. Retain the
previous backend and its native artifacts together for rollback; changing a
package version or manifest cannot convert old AOT bytes.
