# Bundled toolchain releases

The toolchain archive contains one `convex-wasm` launcher, the JavaScript
orchestrator and its locked dependencies, the native compiler and Wasmtime
precompiler, Static Hermes, Wasm runtime archives and headers, Emscripten/LLVM,
patched Binaryen and GNU time. Installation does not build Hermes or require
Rust, CMake or a host C++ compiler.

Install Node.js 24+ and Python 3.10+ on PATH (`node` and `python3`). These general
purpose runtimes and npm are not bundled. Python runs the Emscripten driver;
Node runs the JavaScript orchestrator. The application still needs its own
installed dependencies and Git checkout.
Deployment authority and backend connection settings remain application inputs.
The bundle does not install or configure a backend.

API inventory generation and compile-profile registration analysis resolve tsrs
from the application's installed dependencies. Producer source closure and
runtime-surface checks use the compiler's bundled tsrs package. The pinned version
has Linux x64/arm64 and macOS arm64 binaries, but no macOS Intel binary. Native
compiler and precompiler availability on Intel macOS does not establish complete
application build support: both tsrs installations need a matching platform
package, which this pin does not provide. The native release smoke checks below
do not exercise application inventory or compile-profile analysis.

## Install and run

Download the `convex-wasm-toolchain-VERSION-PLATFORM.tar.gz` archive and its
`.sha256` file from the same tagged GitHub release. Verify that checksum before
extracting or executing it. On Linux use `sha256sum -c FILE.sha256`; on macOS use
`shasum -a 256 -c FILE.sha256`. Extract as the user who will run the compiler,
preserving permissions. Native packages require owner-private directories and
manifests; do not install this archive as a shared, world-writable toolchain.

```sh
tar -xzf convex-wasm-toolchain-VERSION-PLATFORM.tar.gz
./convex-wasm-compiler/convex-wasm verify
./convex-wasm-compiler/convex-wasm smoke --cache-root "$HOME/.cache/convex-wasm-smoke"
./convex-wasm-compiler/convex-wasm build --config ./compiler-project.json
```

The launcher chooses the tools and validation reports from its own installation.
The project config therefore omits `gateRoot`, native package selection and
`matrixTools`/`matrixReports`. Keep the application's route selection, source
paths, work/cache directories, resource limits and deployment authority settings.
Its gate policy has the usual execution/platform limits and diagnostic mode;
`command` contains only `maxOutputBytes` and `phaseTimeoutMs`. The bundle supplies
the tool environment and timing executable.

An application using the npm API can instead set `toolchain` to an extracted
bundle directory. It is mutually exclusive with `gateRoot` and individual tool
or matrix overrides. Source-build configs keep their existing explicit fields.

The installation is relocatable. Emscripten's writable system-library cache is
seeded under the selected cache root and separated by toolchain package ID.
The seed receipt lives outside the SDK cache because Emscripten clears that
cache when its sanity identity changes, including after installation relocation.
Compilation does not fetch or reconstruct Hermes, and does not write into the
installation. Moving the installation can cause existing path-sensitive artifact
caches to miss; it does not require rebuilding the compiler itself.

### Direct compiler diagnostics

Benchmarks and probes that invoke bundled `emcc` directly must use the same
environment as the launcher. Verify the installation with
`verifyToolchainPackage`, then obtain its environment with
`toolchainEnvironment(toolchainRoot, manifest, cacheRoot)` from
`scripts/lib/convex-wasm-toolchain-package.mjs`. Pass
`{ ...process.env, ...environment }` to every compiler subprocess, and verify
the installation again after the diagnostic. Use the application's selected
cache root or `defaultConvexWasmCacheRoot()` from
`scripts/lib/convex-wasm-cache-layout.mjs`; do not reconstruct the package ID or
cache path in the caller.

Bare `emcc` defaults to the cache inside the installation and can erase its
shipped contents when its sanity identity changes. It also defaults to ordinary
Python, which writes bytecode beside the installed modules.
`PYTHONDONTWRITEBYTECODE=1` alone does not prevent this: the driver invokes Python
with `-E`, which ignores Python environment variables. The environment helper
sets both the external `EM_CACHE` and `EMSDK_PYTHON`, whose packaged wrapper uses
`-B` to disable bytecode writes, including recursive compiler invocations.
Resource-admission wrappers do not select this toolchain environment.

## Windows with WSL2

Download `convex-wasm-toolchain-VERSION-windows-x64-wsl2.zip` and verify its
`.sha256` using `Get-FileHash -Algorithm SHA256`. Extract it and run:

```powershell
.\convex-wasm.ps1 -Distribution Ubuntu-24.04 verify
.\convex-wasm.ps1 -Distribution Ubuntu-24.04 build --config /home/USER/project/compiler-project.json
```

This is a WSL2 package, not a native Windows executable. It includes the complete
Linux x64 archive; the first launch verifies and extracts it into the selected
Linux user's `~/.local/share/convex-wasm-compiler/`, then runs it. Later launches
reuse that installation. Omitting `-Distribution` selects the default WSL
distribution. Use Ubuntu 24.04 or a compatible x86-64 Linux distribution with
glibc at least as recent as the release build host.

Install and initialize WSL2 separately if it is not already available:
`wsl --install -d Ubuntu-24.04`. The compiler launcher does not change Windows
features, install a distribution, or request administrator privileges. Install
Node.js 24+ and Python 3.10+ inside the selected WSL distribution, with `node` and
`python3` available on its PATH. Windows installations of these tools do not
satisfy that requirement. If the PowerShell execution policy blocks the
downloaded script, inspect it and use the normal local policy for scripts you
trust.

CLI paths are Linux paths. Keep the project, its installed dependencies and
private work/cache directories in the Linux filesystem, not `/mnt/c`; the
compiler relies on Unix ownership and file permissions. Windows release CI
installs and runs this package under WSL2 on `windows-2025`, using the same
source-to-AOT verification as the Unix releases.

## Source and release identity

`scripts/lib/convex-wasm-gate-pins.mjs` pins an exact Hermes `patch-history` commit,
its upstream commit and `RESULT_TREE`. Release setup fetches that snapshot,
applies its ordered patches in a dedicated checkout and checks the resulting
tree. The synthetic source commit is provenance, not an identity check. A
rewritten development branch cannot invalidate an installed release.

Source-build gates must also be clean and match that tree. The historical
`gateRevisions.hermes` identifies the checked-in global probe's original build;
it is not used to fetch or authenticate a gate checkout. Artifact configuration
uses the source tree identity and still authenticates compiler binaries, runtime
archives, headers, ABI and engine/artifact contracts.

`toolchain.json` inventories all shipped files with their hashes and executable
bits. It detects corruption and local modification; the release archive checksum
is the external release identity. A self-consistent rewritten manifest alone is
not proof that an archive came from the release publisher.

The packaged Emscripten driver preserves the explicit Python wrapper when it
launches recursive compiler processes. That wrapper disables bytecode writes;
the upstream reset to `sys.executable` would lose that flag. The builder rejects
drift in the pinned adaptation and records both source and packaged file hashes.

Release jobs build on the matching Linux x64, macOS ARM64 or macOS Intel runner.
They generate the codec and request-envelope evidence using those release
inputs, then extract the archive into a new path and compile a generic source
fixture through C, Core Wasm and AOT with the bundled compiler tools and host
Node/Python runtimes. This also checks cache reuse across separate launcher
invocations and verifies that the installation remains unchanged. A target is only
publishable if its own smoke test passes.

Tag pushes build and validate every platform before publishing. To publish an
already successful `Native release binaries` run from `main`, use
`gh workflow run release.yml -f native_run_id=RUN_ID`. This path requires the
whole run, including Windows WSL2, to have passed. It packages the JavaScript
release from that run's source commit and publishes its existing native and
toolchain artifacts. The version comes from the tested `package.json`; an
existing version tag must point to the same commit.
If the tag is absent, publication creates it atomically after packaging so a
concurrent publisher cannot substitute another source commit. A publication
failure can leave that tag behind; inspect the run before retrying.

### JavaScript-only releases

For changes that preserve the native source contract, bump the npm package version
and lockfile, push the source to `main`, and wait for its normal CI run to succeed.
Then dispatch the dedicated workflow, naming that CI run and the previous release
whose native selection is being reused:

```sh
gh workflow run release-javascript.yml --ref main \
  -f ci_run_id=RUN_ID -f native_selection_release=vPREVIOUS_VERSION
```

Do not push the new version tag or create its release manually. The JavaScript
workflow creates the tag with `GITHUB_TOKEN`, which does not trigger another
workflow. Creating a tag through the GitHub API with a personal token still fires
the native release workflow, just like a Git tag push.

The workflow packages the exact successful CI commit. Release scripts come from
the workflow's own revision, so the tested commit can predate those scripts;
source collectors and package readers come from the tested checkout. It checks
the previous release's selection against GitHub's asset SHA-256, verifies every selected
compiler and precompiler manifest, binary hash and platform header, and copies the
selection without changing its URLs or package IDs. All three native platforms
remain available; their original build and smoke-test provenance remains intact.
It compares the complete native source closures against the selected previous
release, including Rust includes outside the crate. Only the package's own version
fields in `package-lock.json` may differ; dependency changes require the native
release path. This comparison preserves the previously released combination; it
does not claim the retained binaries were rebuilt from the new JavaScript commit.

Both release paths use the same package installation and command/import checks.
The JavaScript path publishes only the npm tarball, its checksum and the verified
native selection. It does not rebuild or republish bundled toolchains. Existing
tags are rejected, and a failed verification never publishes a release. Normal CI
continues to run for both kinds of source changes.

After verification, the workflow atomically creates the version tag before
uploading the release. If publication fails after that point, the tag may remain;
inspect that run and any draft release before removing the unused tag to retry.
The workflow never overwrites a tag or an existing release.

## Building a release locally

Run `npm ci`, build a source gate with `npm run setup:gate`, and create native
packages with `npm run release:native`. Then run:

```sh
node scripts/build-toolchain-release.mjs \
  --gate-root /absolute/gate \
  --compiler-package /absolute/compiler/PACKAGE_ID \
  --precompiler-package /absolute/precompiler/PACKAGE_ID \
  --output /absolute/new-output-directory \
  --cxx /absolute/path/to/c++ --jobs 2
```

The builder downloads checksum-pinned GNU time source. Native library
dependencies still establish the minimum supported host OS; the archive is not a virtual machine. Bundling changes installation, not the
existing restrictions on supported application code or receiving Wasmtime ABI.
