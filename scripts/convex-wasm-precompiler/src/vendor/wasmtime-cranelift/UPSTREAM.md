# Wasmtime Cranelift integration source

This crate comes from `crates/cranelift` in
[Wasmtime revision 7ad2e732ab9ca8665d3cdd91f9c395315eeafc81](https://github.com/bytecodealliance/wasmtime/tree/7ad2e732ab9ca8665d3cdd91f9c395315eeafc81/crates/cranelift).
The upstream license is retained. The standalone manifest expands the upstream
workspace dependencies, keeping internal crates at that exact revision.

The local change in `src/func_environ.rs` marks fuel exhaustion blocks cold and
calls the existing register-preserving trampolines for fuel and epoch handlers.
The caller reloads the authoritative epoch deadline after the handler returns.
Fuel charges, exhaustion, yielding, cancellation and trap handling are retained.
This changes generated code; it does not change the host runtime's builtin ABI.

The crate is inside the precompiler's recursively authenticated source tree.
Native package identities cover its source, manifest and provenance. The
authenticated compiler package identity participates in AOT cache keys separately from the unchanged
runtime ABI compatibility hash. Incremental function caches additionally bind
to the precompiler executable's hash. This preserves runtime compatibility while
preventing a changed producer from reusing an earlier producer's compiled code.

The precompiler's library tests include `metering_tests.rs`, covering live
integer, floating-point and SIMD values through fuel refills and epoch updates,
trap and exception boundaries, and cancellation followed by Store reuse.
