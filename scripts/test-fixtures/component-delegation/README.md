# Component delegation runtime test

This fixture compiles the current bridge and native adapter with a source SDK
checkout. It emits SDK-wrapper and direct-handler selectors in one Core Wasm
module and precompiles it, plus bundles the same handlers for V8. The backend
application test installs an active child component and resolves its exported
functions normally. No server or deployment credentials are needed.

From the compiler checkout, using an installed gate toolchain:

```sh
node scripts/test-fixtures/component-delegation/build.mjs \
  "$GATE_ROOT" "$SDK_SOURCE_ROOT" "$PRECOMPILER_PACKAGE" "$FIXTURE_DIRECTORY"
```

From the backend checkout:

```sh
CONVEX_WASM_COMPONENT_FIXTURE="$FIXTURE_DIRECTORY" \
  scripts/run_cargo.sh test -p application \
  --features testing,static-hermes-wasmtime-gate --lib \
  compiled_wasm_component_delegation -- --ignored --test-threads=1
```

Run these native commands with the host's usual build resource limits. The
fixture directory contains disposable generated sources, objects and Wasm. Use
an absolute fixture path and a release precompiler compatible with the backend.

The test compares V8 and Wasm query/mutation outcomes, structured error class
identity, null/false/bigint/bytes data, catch/rethrow and edited error data. A child
mutation also wraps a real missing-document failure in `ConvexError` with a cause.
Both engines must preserve its host-operation attribution on rethrow and clear
it on catch or unrelated replacement. The test checks the canonical attribution
and operation traces consumed by shadow comparison. A detached rejection must
still terminate execution and clear the returned error's attribution. The test
does not exercise shadow sampling, registry publication, source admission or
artifact authentication.
