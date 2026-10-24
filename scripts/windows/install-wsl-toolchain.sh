#!/bin/sh
set -eu

archive=$1
digest=$2
shift 2
case "$(uname -r)" in
  *microsoft-standard*WSL2*) ;;
  *) echo 'This package requires WSL2. Convert the selected distribution with wsl --set-version DISTRIBUTION 2.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64) ;;
  *) echo 'This release requires an x86-64 WSL2 distribution.' >&2; exit 1 ;;
esac
case "$digest" in
  *[!0-9a-f]*|'') echo 'Invalid release digest.' >&2; exit 1 ;;
esac
[ "${#digest}" = 64 ] || { echo 'Invalid release digest length.' >&2; exit 1; }
umask 077
parent="$HOME/.local/share/convex-wasm-compiler"
installation="$parent/$digest"
mkdir -p "$parent"
if [ ! -d "$installation" ]; then
  actual=$(sha256sum "$archive")
  [ "${actual%% *}" = "$digest" ] || { echo 'Toolchain archive checksum differs.' >&2; exit 1; }
  stage=$(mktemp -d "$parent/.install-XXXXXX")
  trap 'rm -rf "$stage"' EXIT HUP INT TERM
  tar -xzf "$archive" --no-same-owner --same-permissions -C "$stage"
  "$stage/convex-wasm-compiler/convex-wasm" verify >/dev/null
  # Concurrent first launches can publish the same immutable release. GNU mv -Tn
  # leaves an already-published installation intact instead of nesting directories.
  mv -Tn "$stage/convex-wasm-compiler" "$installation"
  rm -rf "$stage"
  trap - EXIT HUP INT TERM
fi
exec "$installation/convex-wasm" "$@"
