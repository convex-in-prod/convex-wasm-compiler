# Items project

This is a small Convex project with one public query, `items/read:get`, and one
public mutation, `items/write:put`. The mutation inserts a named item and the
query returns the number of items. Copy this directory outside the compiler
checkout before using it as an independent project.

The supplied gate policy targets Linux hosts with `/usr/bin/c++` and GNU
`/usr/bin/time`. Set the command paths, `HOME`, `PATH`, and execution limits for
your test host before building. The `sourceAuthority.backendImageId` value is
only a placeholder; replace it with the immutable ID of the patched backend
image that produced the configured authority helper.

1. Configure the Convex CLI for a disposable patched backend. After the matching
   compiler release is published, use the release URL described in
   [Project artifact build](../../README.md#project-artifact-build):

   ```sh
   npm install
   npm install --save-dev https://github.com/convex-in-prod/convex-wasm-compiler/releases/download/v0.2.0/convex-wasm-compiler-0.2.0.tgz
   npx convex codegen
   git init
   git add convex.json convex scripts package.json package-lock.json
   ```

   Codegen must produce `convex/_generated/server` for the two functions. The
   `scripts/` directory contains empty adapter descriptors because this project
   uses only the standard Convex registrations and SDK dependencies. Stage the
   source again after any project edit before building.
2. Install the pinned gate with `npx convex-wasm-setup-gate --gate-root
   .local/convex-wasm-gate --jobs 2`. The command builds native tools on the
   first run. The backend-report command installs `sourceAuthority.helper` from
   the patched image named by `sourceAuthority.backendImageId` when it is absent.
   On macOS, the authority command runs that helper inside the same image. The
   backend-report and authority commands create the certificate at
   `sourceAuthority.producerCertificate` as described in the main README.
3. Run `npx convex-wasm-build --config convex-wasm.project.json`. Use the
   `artifactReport` path printed by that command in the following commands:

   ```sh
   ARTIFACT_REPORT=/absolute/path/printed/by/convex-wasm-build
   npx convex-wasm-backend-report --config convex-wasm.project.json \
     --artifact-report "$ARTIFACT_REPORT"
   npx convex-wasm-authority --config convex-wasm.project.json \
     --artifact-report "$ARTIFACT_REPORT" \
     --backend-report "$(dirname "$ARTIFACT_REPORT")/backend-source-package-report.json"
   npx convex-wasm-bind --config convex-wasm.project.json \
     --artifact-report "$ARTIFACT_REPORT" \
     --output .cache/deployment-v8.json
   install -d -m 700 .private
   npx convex-wasm-publish-registry --config convex-wasm.project.json \
     --artifact-report "$ARTIFACT_REPORT" \
     --deployment .cache/deployment-v8.json \
     --registry-root .private/runtime-registry \
     --publication shadow-only \
     --preflight-output .private/registry-preflight.json
   ```

Replace the example `ARTIFACT_REPORT` value with the exact printed path. The
backend-report command creates its report from a fresh disposable instance of
the configured patched backend image. The publisher creates a local registry. Have that backend
preflight the registry and separately arrange transfer, readiness, and
activation; the publication command does not activate routes. For an execution
check, activate the generation as a V8-primary shadow, invoke
`items/write:put` once with a distinct name, and inspect the backend's paired
V8/Wasm result under the same initial database state. Then invoke
`items/read:get` and compare its paired count.
