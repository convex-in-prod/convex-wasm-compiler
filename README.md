# Convex Wasm Compiler

This repository contains native tooling for compiling selected Convex query and
mutation modules for Static Hermes execution in a Wasmtime-backed self-hosted
Convex runtime.

The repository currently provides:

- a source-graph compiler that validates the supported JavaScript and
  TypeScript surface and emits authenticated lowering material;
- a Wasmtime precompiler that converts compatible Core Wasm modules into
  target-specific AOT artifacts; and
- compiler regression and invariant-validation corpora.

The context-reuse analyzer embeds reusable reviewed dispositions for public
dependencies. Its optional `--third-party-policy <path>` input lets a downstream
application provide exact package fingerprints and imported names without
adding downstream dependency identities to this repository. The supplemental
file uses the embedded policy schema and must not collide with its surface IDs
or package fingerprints.

The corresponding self-hosted Convex runtime patch is maintained separately.
Downstream applications remain responsible for selecting eligible modules,
supplying dependency and registration adapter descriptors, building Static
Hermes Core Wasm, and publishing artifacts accepted by their patched backend.

## Development

The compiler and precompiler use their own pinned Rust toolchains and lockfiles.
Install the repository-local JavaScript parser dependency before checking the
source-graph tooling. Convex and esbuild are resolved from the downstream
application whose source graph is being built, so this repository does not pin
an application SDK version.

```sh
npm ci
npm run check:js
cargo test --locked --manifest-path scripts/convex-wasm-compiler/Cargo.toml
cargo test --locked --manifest-path scripts/convex-wasm-precompiler/Cargo.toml
cargo test --locked \
  --manifest-path scripts/convex-wasm-compiler/invariant-validation/Cargo.toml
```

Release binaries are native executables. Build and test macOS binaries on the
matching Apple Silicon or Intel macOS host; build and test Linux binaries on the
matching Linux host.

The precompiler accepts Core Wasm inputs up to 320 MiB and publishes AOT
artifacts up to 640 MiB, matching the self-hosted runtime artifact contract.
Its AOT and engine-identity output paths must not already exist.

This is not an official Convex project.

## Versioning

Repository releases use semantic versions. Serialized package manifests use an
unversioned `kind` and a numeric `schemaVersion`; the schema number changes only
when readers must distinguish incompatible manifest layouts. Protocol choices
are named by behavior rather than by the order in which they were introduced.

Exact source, toolchain, and artifact compatibility is authenticated by the
recorded hashes and revisions. Filenames, Rust type names, cache directories,
and protocol kinds do not carry historical `vN` suffixes.
