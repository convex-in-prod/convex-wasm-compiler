# Cranelift frontend source

This crate comes from `cranelift/frontend` in
[Wasmtime revision 7ad2e732ab9ca8665d3cdd91f9c395315eeafc81](https://github.com/bytecodealliance/wasmtime/tree/7ad2e732ab9ca8665d3cdd91f9c395315eeafc81/cranelift/frontend).
Its upstream license is retained in `LICENSE`. The standalone manifest expands
the upstream workspace dependency declarations; Cranelift code generation stays
pinned to the same Wasmtime revision.

The local change is confined to `src/frontend/safepoints.rs`:

- Collect GC-reference definitions, uses and safepoints once per function,
  preserving their reverse instruction order. Reuse these sparse block summaries
  during fixed-point iteration and final safepoint recording.
- Omit empty safepoint sets and skip the rewrite traversal when no reference is
  live across any safepoint. Keep ordinary liveness, spill placement, exception
  handling and stack-slot reuse rules.
- Check context reuse across functions with dead and live references at calls.

The crate lives within the precompiler's recursively authenticated source tree.
Its source, manifest, license and this provenance record therefore participate
in native-package source identity and ship with the source package. Native
packaging runs the frontend's library tests alongside the precompiler checks.
