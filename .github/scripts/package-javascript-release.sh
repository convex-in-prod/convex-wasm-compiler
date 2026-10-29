#!/usr/bin/env bash
set -euo pipefail
package_version=$(node -p "require('./package.json').version")
test "$RELEASE_TAG" = "v$package_version"
cp release-assets/native-package-selection.json scripts/native-package-selection.json
npm pack --pack-destination release-assets --quiet
package_filename="convex-wasm-compiler-$package_version.tgz"
package_archive="$PWD/release-assets/$package_filename"
test -f "$package_archive"
sdk_package=$(node -p "require('./package.json').devDependencies.convex")
npm install --prefix "$RUNNER_TEMP/convex-wasm-package" \
  --omit=dev --no-save "$package_archive" "$sdk_package"
package_root="$RUNNER_TEMP/convex-wasm-package/node_modules/convex-wasm-compiler"
cmp release-assets/native-package-selection.json "$package_root/scripts/native-package-selection.json"
for required in docs/runtime-compatibility.md docs/memory-reclamation.md docs/guest-memory-maintenance.md scripts/build-wasm-allocator.py scripts/lib/convex-wasm-allocator.h scripts/lib/convex-wasm-allocator.c scripts/vendor/convex-wasm-native-intl/ADAPTER-LICENSE.txt scripts/vendor/convex-wasm-native-intl/ICU-LICENSE.txt scripts/test-fixtures/native-values/resource-probe.cpp scripts/test-fixtures/convex-wasm-request-envelope/report-fixture.mjs; do
  test -s "$package_root/$required"
done
for command in convex-wasm-build convex-wasm-backend-report convex-wasm-authority convex-wasm-bind convex-wasm-acquire-native convex-wasm-setup-gate convex-wasm-cache convex-wasm-publish-registry convex-wasm-transfer-registry; do
  test -x "$RUNNER_TEMP/convex-wasm-package/node_modules/.bin/$command"
  if "$RUNNER_TEMP/convex-wasm-package/node_modules/.bin/$command" --invalid-option >"$RUNNER_TEMP/$command.stdout" 2>"$RUNNER_TEMP/$command.stderr"; then
    echo "Installed command did not reject an invalid option: $command" >&2
    exit 1
  fi
done
PACKAGE_ROOT="$package_root" node --input-type=module -e '
  const root = process.env.PACKAGE_ROOT;
  await Promise.all([
    import(`${root}/scripts/build-convex-wasm.mjs`),
    import(`${root}/scripts/backend-report.mjs`),
    import(`${root}/scripts/authority-project.mjs`),
    import(`${root}/scripts/bind-convex-wasm.mjs`),
    import(`${root}/scripts/acquire-convex-wasm-native-release.mjs`),
    import(`${root}/scripts/setup-gate.mjs`),
    import(`${root}/scripts/maintain-convex-wasm-cache.mjs`),
    import(`${root}/scripts/plan-registry-transfer.mjs`),
    import(`${root}/scripts/publish-registry.mjs`),
  ]);
'
(cd release-assets && sha256sum "$package_filename" >"$package_filename.sha256")
