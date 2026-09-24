# Convex Wasm Compiler

This repository contains native tooling for compiling selected Convex query and
mutation modules for Static Hermes execution in a Wasmtime-backed self-hosted
Convex runtime.

The repository currently provides:

- a source-graph compiler that validates the supported JavaScript and
  TypeScript surface and emits authenticated lowering material;
- a Wasmtime precompiler that converts compatible Core Wasm modules into
  target-specific AOT artifacts;
- pinned browser-style runtime support for guest code, with a reproducible
  generator and checked vendored inputs;
- authenticated Static Hermes global inventory, intrinsic-hardening and
  application runtime-surface policies, with focused tests;
- authenticated artifact material, Static Hermes C-bundle helpers, and native
  member duplicate-work diagnostics;
- Core Wasm import inspection and module-graph contract validation for topology
  and host ABI, with chunk dependency, native-symbol, and compiler topology
  identity contracts and a physical shard planner;
- module-graph selector C sources for reviewed common factories, host imports,
  and structural traps;
- application-descriptor validation, compiler topology projection, and native
  selector generation for artifact construction;
- authenticated context-reuse cohort identities for module-graph packages;
- module-graph package construction from caller-supplied modules and Core Wasm/AOT
  builders, with explicit concurrency and authentication of the published package;
- artifact construction from caller-supplied official-output chunk units and
  authenticated compiler outputs, with a caller-owned native resource guard;
- common-partition selection with an explicit reviewed authority supplied by
  the adopting application;
- common/leaf membership derivation from complete-entry chunk dependencies,
  with sharing limited by that reviewed authority;
- Core Wasm and AOT module staging with authenticated material reuse across
  distinct module-graph control identities;
- native phase scheduling with explicit memory and worker limits;
- verified native compiler/precompiler package acquisition from caller-selected
  HTTPS release assets into a shared immutable cache;
- authenticated Static Hermes request/response validation and C or C-bundle
  source-stage execution through a caller-owned native command runner, plus
  command construction for Emscripten and Wasmtime AOT stages;
- native C/C++ object construction from authenticated staged source files,
  with immutable cache reuse;
- generated-C assembly into a cached linker input, including ordered C-bundle
  member compilation and archive construction;
- a generic source-to-AOT verification command with explicit Static Hermes, Emscripten,
  runtime-header, and authenticated precompiler-package inputs;
- Core Wasm linking and Wasmtime AOT staging over authenticated input bytes,
  with engine-identity validation and immutable cache reuse;
- a native command runner with explicit environment, timeout, output limit, and
  cancellation inputs;
- a cross-checkout cache layout, private cache-entry authentication, immutable
  artifact-stage publication and process sharing, runtime-header snapshot
  authentication, and cache retention with a cross-process cache lock;
- the guest bridge and native entry generator, with an explicit SDK version
  input and a generic regression suite;
- committed-value and request-envelope matrix generators, report validators,
  scoped request evidence authority, and native execution runners, with their
  canonical vectors and source identities;
- verified Static Hermes gate configuration from a caller-supplied runtime and
  platform policy, with the runtime source taken from this package;
- application-root package resolvers that record installed Convex and esbuild
  identities, plus TypeScript for profile analysis;
- TypeScript-driven registration source analysis that accepts the adopting
  application's resolved TypeScript runtime;
- source-level compile-profile construction with explicit application root,
  package root, and configuration file paths;
- authenticated source-envelope selection and owner-private publication from
  an application graph session;
- authenticated, deterministic cohort scheduling over complete selected entry
  namespaces, with bounded build concurrency and stable result order;
- authenticated cohort contracts and deployment-v8 module-graph binding that
  require complete route, engine, source, and producer identities;
- authenticated raw Git blob reads, staged source snapshots, and source-graph
  snapshots with immutable cache lookup and changed-input invalidation;
- deployment graph sessions built from an adopting application's Convex config,
  installed SDK, generated inventory, and optional staged Git snapshot;
- generated API route inventory from the adopting application's configured
  functions directory, with authenticated source and installed-material cache reuse;
- context-reuse graph construction and native analysis using the adopting
  application's configured functions directory and additional source roots;
- a source-closure producer identity bound to this toolchain's source manifest,
  with operational files reported separately from artifact semantics; and
- compiler regression and invariant-validation corpora.

The context-reuse analyzer embeds reusable reviewed dispositions for public
dependencies. Its optional `--third-party-policy <path>` input lets a downstream
application provide exact package fingerprints and imported names without
adding downstream dependency identities to this repository. The supplemental
file uses the embedded policy schema and must not collide with its surface IDs
or package fingerprints.

`analyzeContextReuse` in `scripts/lib/convex-context-reuse.mjs` accepts an
application `repoRoot`, an authenticated `compilerPackage`, optional
`inventoryOptions.configPath` for additional registration builders, and
`sourceRoots` for first-party directories outside the configured functions
directory. The graph passes that functions directory to the native compiler, so
generated-server registrations are recognized at the configured path. A native
compiler package built before this source change does not support that graph
field; use a matching compiler build until a new package is released.

The corresponding self-hosted Convex runtime patch is maintained separately.
Downstream applications remain responsible for selecting eligible modules,
supplying dependency and registration adapter descriptors, and transferring
artifacts to their patched backend. The project commands below build an
authenticated package and deployment manifest. They do not transfer or activate
that manifest, or install Static Hermes and Emscripten.

The matrix runners use the installed Convex SDK package to construct canonical
vectors and identify the SDK source files they exercised. The project command
accepts their reports or generates them from configured native runner paths.
The gate-config producer also remains a lower-level input to that workflow. Its
`--policy` file supplies platform limits, execution limits, host command limits,
explicit `HOME` and `PATH` values, the GNU time executable path, and
guest-initialization diagnostic mode. It
verifies the pinned Static Hermes and Emscripten checkouts and the matching
precompiler package before writing private config files. Application runtime
limits remain with the caller.

## Project artifact build

Install the JavaScript package from the matching tagged release into a project
that already depends on a compatible Convex SDK. For example, after the
`v0.2.0` release is published:

```sh
npm install --save-dev https://github.com/convex-in-prod/convex-wasm-compiler/releases/download/v0.2.0/convex-wasm-compiler-0.2.0.tgz
```

The project owns its Convex SDK dependency; the compiler resolves that installed
SDK for source analysis and matrix generation. Run
`npx convex-wasm-build --config convex-wasm.project.json` from the project.
The project config selects complete query and mutation entry namespaces,
staged Git paths, a verified native release or local native packages, the pinned
Static Hermes gate, and private work/cache directories. For example:

```json
{
  "schemaVersion": 1,
  "projectRoot": ".",
  "workRoot": ".cache/convex-wasm-work",
  "gateRoot": ".local/convex-wasm-gate",
  "gatePolicy": "convex-wasm-gate-policy.json",
  "sourceAuthority": {
    "backendImageId": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "helper": ".local/source-package-authority",
    "producerCertificate": ".local/source-package-producer.json"
  },
  "sourcePathspecs": ["convex.json", "convex", "shared", "package-lock.json"],
  "sourceRoots": ["shared/"],
  "selectedExports": ["items/read:get", "items/write:put"],
  "matrixReports": {
    "codec": ".cache/codec-matrix.json",
    "request": ".cache/request-matrix.json"
  },
  "jobs": 1,
  "aotWorkers": 1,
  "memoryMaxMiB": 5120
}
```

Paths resolve relative to the config file. The selected source must be staged in
Git, including changes to the listed pathspecs. `matrixTools` with `runner` and
`cxx` paths can replace `matrixReports`; the command then creates both reports.
The tagged JavaScript package includes its matching native selection, so the
build downloads and verifies the compiler and precompiler into the default
per-user cache. Set `nativeReleaseSelection` to use another pinned selection,
or set both `compilerPackage` and `precompilerPackage` to use local verified
packages. `nativePackageCacheRoot` overrides the default cache location.
The gate policy has the exact shape accepted by `create-gate-config.mjs`.
`memoryMaxMiB` controls native scheduling, not an operating-system memory cap.
The command writes an artifact report naming verified module-graph packages,
the authenticated cohort schedule, its route contracts, and the context-reuse
policy. It also records the installed Convex CLI's complete source request in
the private build directory. The CLI writes this request locally without
uploading it. A source-package authority helper built from the matching patched
backend can construct the exact source package and frozen authority from this
request without activating a deployment. Configure its executable and producer
certificate under `sourceAuthority`, then run:

```sh
npx convex-wasm-authority --config convex-wasm.project.json \
  --artifact-report .cache/convex-wasm-work/build-.../artifact-report.json
```

The command writes `source-package.zip` and `source-authority.json` beside the
report. For a request with external Node dependencies, `sourceAuthority` also
requires `externalDepsPackage` and `targetExternalDepsPackage` paths naming the
matched archive and its admitted descriptor. Supply a genuine report from the
matching patched backend's isolated source-package producer to establish the
producer certificate in the same command:

```sh
npx convex-wasm-authority --config convex-wasm.project.json \
  --artifact-report .cache/convex-wasm-work/build-.../artifact-report.json \
  --backend-report .local/backend-source-package-report.json
```

The report must name the backend-produced authority, source package, and any
external dependency archive. The command compares those files with output from
the configured helper before caching the certificate. Without `--backend-report`,
`producerCertificate` must already name a complete
`convex-runtime-content-producer-certificate-v1` file for that backend image and
helper. This package does not supply a patched-backend helper or backend report.

The reusable certificate and authority-cache operations live in
`scripts/lib/source-producer-conformance.mjs` and
`scripts/lib/source-authority-cache.mjs`. Backend
operators can compare helper-derived material with their local backend
producer, then cache a certificate tied to the helper, backend image,
dependencies, and source-package bytes. Bind the packages to the matching
source with:

```sh
npx convex-wasm-bind --config convex-wasm.project.json \
  --artifact-report .cache/convex-wasm-work/build-.../artifact-report.json \
  --output .cache/deployment-v8.json
```

Binding reads the generated `source-authority.json` when `sourceAuthority` is
configured. An operator may instead name an existing private
`deployedRuntimeAuthority` file for the exact source package being bound.
Binding checks the selected runtime modules against that authority, constructs
the deployment from the authenticated source envelope, checks the complete
source request against the frozen-graph binding, verifies each package,
and writes an authenticated deployment-v8 manifest. Backend
registry transfer and activation remain separate steps.

## Development

The compiler and precompiler use their own pinned Rust toolchains and lockfiles.
Install the repository-local JavaScript dependencies before checking the
source-graph tooling. The lowering tests pin one public Convex SDK fixture;
guest generation takes the adopting application's SDK version explicitly.
Source-graph construction resolves Convex and esbuild from the application
whose source graph is being built. Profile analysis also resolves TypeScript
from that application. The package identities record manifest SHA-256 digests
without checkout paths, so identical installed inputs retain the same identity
across checkouts.
`loadConvexGeneratedApiInventory` now runs the bundled route flattener against
the application's `convex.json` functions directory. The application supplies
TypeScript and native TypeScript in its installed package set. An optional
project-owned flattener config lists additional registration builders, exact
generated-registry exports, additional `sourceRoots`, and `inputFiles` such as
the application's lockfile or base TypeScript configuration. `patchFiles`
lists application files that affect source analysis. The functions directory
comes from `convex.json`; projects without components need no
`convex.config.ts`.
`buildConvexWasmDeploymentGraphSession` in
`scripts/lib/convex-wasm-deployment-graph.mjs` accepts `repoRoot`, `inventory`,
and a positive `materialVerificationConcurrency`. The optional
`gitSourceSnapshot` binds a staged source tree. The session exposes selected
entry dependency graphs and material-verification functions; callers still
choose entries and publication policy. For guest-promise builds, the same module
captures exact analyzer input, reads first-party source from caller-selected
roots, and binds the analyzer result back to the staged graph before producing
a source envelope. The caller supplies the functions root and sorted source
roots for that source-text capture.
Artifact adapters take the installed Convex version as a separate
`sdkPackageVersion` argument when generating the guest bridge.
The registration analyzer accepts that resolved TypeScript runtime as an input;
it does not load TypeScript from the compiler checkout.
Source-graph snapshots take an explicit application root and selected Git
pathspecs. A deployment snapshot rejects unstaged or untracked changes within
those paths, while unrelated staged files may change. The snapshot cache binds
the selected paths, graph assumptions, installed package identities, and staged
source identities before reusing a graph.
Producer identity reads the toolchain's own source manifest and uses a pinned
TypeScript parser to include relative imports. Adding a toolchain source file
requires updating `scripts/convex-wasm-artifact-producer-source-manifest.json`.
The manifest currently covers the source modules present here; it will expand
as build and publication modules move into this repository.
Target compile profiles currently require the authenticated Zod 4.4.3 package
and its root lock entry. The adopting application supplies
`sourceConfigurationPaths` for the files that affect its source build. The
source-preparation test builds a profile from a separate synthetic application
whose function directory is `functions/`.
Cache layouts share immutable artifacts across application checkouts while
keeping checkout state and build work separate. The default root is
`convex-wasm-compiler` under the platform cache directory; callers can supply
an explicit absolute root. The public cache layout does not choose deployment
policy or producer identity.
Native package acquisition accepts an explicit package reference with its
SHA-256 package ID, target triple, and optional HTTPS asset URLs. It validates
the manifest and executable before publishing them into the shared cache.
Applications choose the package release and cache root; acquisition does not
select a deployment or install the remaining Static Hermes and Emscripten tools.
New releases include `native-package-selection.json`, which names the compiler
and precompiler assets for the three supported hosts. The JavaScript package
bundles this file; install both native packages ahead of a build with:

```sh
npx convex-wasm-acquire-native
```

The build command also acquires them automatically. The acquisition command
returns verified executable and manifest paths; repeated use checks the local
packages without downloading them again. `--selection PATH` and
`--cache-root PATH` override the bundled selection and cache location. Upgrade by changing
the JavaScript release package; its selection pins the matching native assets.

The source-to-AOT verification compiles the repository's generic Static Hermes probe,
its runtime entry, Core Wasm, and compatible AOT. It checks both a cold build
and unchanged-input cache reuse. Supply a matching Static Hermes/Emscripten
installation and a verified precompiler package:

```sh
npm run verify:source-to-aot -- \
  --mode single --aot-workers 2 \
  --shermes /path/to/shermes --emcc /path/to/emcc \
  --emsdk-root /path/to/emsdk --hermes-source /path/to/hermes \
  --wasm-build /path/to/wasm-build \
  --precompiler-package /path/to/verified-precompiler-package \
  --cache-root "$HOME/.cache/convex-wasm-verification"
```

Use `--mode bundle` to exercise ordered C-bundle member compilation and archive
linking. The verification command authenticates the named compiler tools, runtime headers,
archives, and precompiler package before use. It does not publish a deployment
or execute a backend UDF.

The common-partition selector requires an explicit authority. An application
with no reviewed shared unit supplies an empty authority; any reviewed content
and its engine, AOT, and generated-C evidence stay in that application's
configuration.
Artifact-entry admission binds the completed payload to its identity and
metadata. Validation checks private file identities across reads and
reauthenticates changed payloads before reuse.
Runtime-header snapshots copy authenticated include directories into the
immutable cache and verify their bytes and filesystem state on reuse.
The artifact pipeline accepts a caller-owned `resourceGuard` for native work.
The guard must carry `convexWasmBuildResourceGuardKind`, an active `released`
state, a normalized launch policy with aggregate memory, jobs, and AOT-worker
limits, and `runCommand` and `describeTermination` methods. The caller owns
host resource admission and guard release; the compiler does not choose host
reserve policy. A generic test constructs a legacy package, an official-output
module-graph package, Core Wasm, and AOT with synthetic native tools, then
independently verifies the module-graph package. This verifies the library
boundary. A separate application test builds and verifies a module-graph
package from an official SDK query through the public graph and artifact
builders using those synthetic tools. Publication and backend execution are
still separate steps.
Cache maintenance defaults to a dry run. It authenticates recent-success
snapshots and referenced packages before planning immutable eviction. An
explicit sweep currently removes eligible artifact and C-bundle entries; it
leaves package and certificate roots in place. Use the same cache root for
builds and maintenance. A caller assembling a build from the exported modules
must acquire `acquireConvexWasmCacheLock`, create a work lease with
`createConvexWasmBuildWorkLease`, and hold the lock through the build and the
lease's `complete` or `fail` transition. The library builders do not acquire
the lock for the caller. `verify:source-to-aot` acquires it around its own build.

```sh
npx convex-wasm-cache --cache-root "$HOME/.cache/convex-wasm-compiler"
npx convex-wasm-cache --cache-root "$HOME/.cache/convex-wasm-compiler" --apply --immutable-sweep --immutable-high-watermark-bytes "$CACHE_HIGH_WATERMARK_BYTES"
```

`--automatic --apply` runs immutable sweeping only above an explicitly configured
high watermark. Supply `--immutable-high-watermark-bytes` or
`CONVEX_WASM_CACHE_HIGH_WATERMARK_BYTES` for either sweep mode; choose the value
for the adopting host. The command uses the default cache root when `--cache-root`
is omitted.

```sh
npm ci
npm run check:js
npm run check:runtime-support
npm run test:runtime-support
npm run test:runtime-policy
npm run test:artifact-material
npm run test:module-graph
npm run test:native-build
npm run test:native-scheduling
npm run test:native-package-acquisition
npm run test:cache-layout
npm run test:producer-identity
npm run test:lowering
npm run test:source-preparation
cargo test --locked --manifest-path scripts/convex-wasm-compiler/Cargo.toml
cargo test --locked --manifest-path scripts/convex-wasm-precompiler/Cargo.toml
cargo test --locked \
  --manifest-path scripts/convex-wasm-compiler/invariant-validation/Cargo.toml
```

Release binaries are native executables. Build and test macOS binaries on the
matching Apple Silicon or Intel macOS host; build and test Linux binaries on the
matching Linux host.

Tagged releases publish the installable JavaScript package and authenticated
compiler and precompiler packages for all three supported hosts. The release
workflow installs and imports the packed JavaScript commands before publication.
It keeps the native control manifests, package IDs, binaries, and host selection
together as release assets. A downstream tool can select a release by tag and
verify the native manifest and binary hashes before placing the package in its
content-addressed cache. A release can be consumed without this source checkout.

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
