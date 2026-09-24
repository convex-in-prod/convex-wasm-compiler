#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  convex-wasm-transfer-registry \
    --local-root LOCAL_REGISTRY \
    --preflight VERIFIED_PREFLIGHT.json \
    --ssh-target SSH_TARGET \
    --remote-root REMOTE_REGISTRY \
    [--deployment-sha256 SHA256 \
     --generation-manifest-sha256 SHA256 \
     --generation-sha256 SHA256 \
     --source-package-runtime-content-sha256 SHA256]

Transfers an already published local Wasm runtime registry to one self-hosted Convex host.
With an explicit pair, only that pair's payloads are transferred and an existing destination
compatibility pointer is preserved. On a fresh destination, the selected pair becomes current.
Without an explicit pair, the local compatibility current generation is transferred.
An already-retained destination catalog is preserved additively without retransmitting its payloads.
Generation and package payloads are installed first, followed by source-catalog.json and current.
The transfer preserves hard links and uses Zstandard level 6 when both rsync endpoints support it.
Compatible locally produced AOT is included so readiness need not repeat its compilation.
EOF
}

local_root=""
preflight_json=""
ssh_target=""
remote_root=""
deployment_sha256=""
generation_manifest_sha256=""
generation_sha256=""
source_package_runtime_content_sha256=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local-root)
      local_root="${2-}"
      shift 2
      ;;
    --preflight)
      preflight_json="${2-}"
      shift 2
      ;;
    --ssh-target)
      ssh_target="${2-}"
      shift 2
      ;;
    --remote-root)
      remote_root="${2-}"
      shift 2
      ;;
    --deployment-sha256)
      deployment_sha256="${2-}"
      shift 2
      ;;
    --generation-manifest-sha256)
      generation_manifest_sha256="${2-}"
      shift 2
      ;;
    --generation-sha256)
      generation_sha256="${2-}"
      shift 2
      ;;
    --source-package-runtime-content-sha256)
      source_package_runtime_content_sha256="${2-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$local_root" || -z "$preflight_json" || -z "$ssh_target" || -z "$remote_root" ]]; then
  usage
  exit 1
fi
if [[ "$local_root" != /* || "$local_root" == "/" ]]; then
  echo "--local-root must be an absolute non-root path." >&2
  exit 1
fi
if [[ "$preflight_json" != /* || ! -f "$preflight_json" || -L "$preflight_json" ]]; then
  echo "--preflight must name an absolute regular file." >&2
  exit 1
fi
if [[ "$remote_root" != /* || "$remote_root" == "/" ||
      ! "$remote_root" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
  echo "--remote-root must be a safe absolute non-root path." >&2
  exit 1
fi
if [[ "$ssh_target" == -* || ! "$ssh_target" =~ ^[A-Za-z0-9_.@:-]+$ ]]; then
  echo "--ssh-target contains unsupported characters." >&2
  exit 1
fi
pair_values=(
  "$deployment_sha256"
  "$generation_manifest_sha256"
  "$generation_sha256"
  "$source_package_runtime_content_sha256"
)
pair_value_count=0
for pair_value in "${pair_values[@]}"; do
  if [[ -n "$pair_value" ]]; then
    pair_value_count=$((pair_value_count + 1))
    if [[ ! "$pair_value" =~ ^[0-9a-f]{64}$ ]]; then
      echo "Runtime registry pair identities must be lowercase SHA-256 digests." >&2
      exit 1
    fi
  fi
done
if [[ "$pair_value_count" -ne 0 && "$pair_value_count" -ne 4 ]]; then
  echo "Runtime registry pair identity options must be supplied together." >&2
  exit 1
fi

for command_name in awk mktemp node rsync ssh; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command is unavailable: $command_name" >&2
    exit 1
  fi
done
if command -v sha256sum >/dev/null 2>&1; then
  local_hash=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  local_hash=(shasum -a 256)
else
  echo "A local SHA-256 file command is required." >&2
  exit 1
fi

ssh_options=(-o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=4)
rsync_shell="ssh -o ConnectTimeout=15 -o ServerAliveInterval=30 -o ServerAliveCountMax=4"

local_root="${local_root%/}"
if [[ ! -d "$local_root" || -L "$local_root" ]]; then
  echo "The local runtime registry must be a real directory." >&2
  exit 1
fi
for control_name in source-catalog.json current; do
  control_path="$local_root/$control_name"
  if [[ ! -f "$control_path" || -L "$control_path" ]]; then
    echo "The local runtime registry is missing regular $control_name." >&2
    exit 1
  fi
done

script_path="${BASH_SOURCE[0]}"
while [[ -L "$script_path" ]]; do
  script_directory="$(cd -- "$(dirname -- "$script_path")" && pwd -P)"
  script_path="$(readlink -- "$script_path")"
  if [[ "$script_path" != /* ]]; then
    script_path="$script_directory/$script_path"
  fi
done
script_directory="$(cd -- "$(dirname -- "$script_path")" && pwd -P)"
payload_list="$(mktemp)"
hardlink_list="$(mktemp)"
source_catalog="$(mktemp)"
retained_source_catalog="$(mktemp)"
selected_current="$(mktemp)"
cleanup() {
  rm -f -- \
    "$payload_list" \
    "$hardlink_list" \
    "$source_catalog" \
    "$retained_source_catalog" \
    "$selected_current"
}
trap cleanup EXIT
closure_arguments=(
  --registry-root "$local_root"
  --preflight "$preflight_json"
  --hardlinks-output "$hardlink_list"
  --source-catalog-output "$source_catalog"
  --selected-current-output "$selected_current"
)
if [[ "$pair_value_count" -eq 4 ]]; then
  closure_arguments+=(
    --deployment-sha256 "$deployment_sha256"
    --generation-manifest-sha256 "$generation_manifest_sha256"
    --generation-sha256 "$generation_sha256"
    --source-package-runtime-content-sha256 "$source_package_runtime_content_sha256"
  )
fi

# Transfer publishes the new pair additively so the previous catalog remains valid until
# activation commits. Post-activation compaction retains only the committed pair.
# An explicit pair does not make the destination's unrelated compatibility generation a
# local validation or transfer input.
remote_catalog_path="$remote_root/source-catalog.json"
remote_current_path="$remote_root/current"
remote_control_state="$(
  ssh "${ssh_options[@]}" -- "$ssh_target" \
    "if test -L '$remote_catalog_path' || test -L '$remote_current_path'; then exit 1; elif test -e '$remote_catalog_path'; then test -f '$remote_catalog_path' && test -s '$remote_catalog_path' && test -f '$remote_current_path' && test -s '$remote_current_path' && printf 'present:' && sha256sum '$remote_current_path' | awk '{print \$1}'; elif test -e '$remote_current_path'; then exit 1; else printf absent; fi"
)"
remote_current_sha256=""
case "$remote_control_state" in
  present:*)
    remote_current_sha256="${remote_control_state#present:}"
    if [[ ! "$remote_current_sha256" =~ ^[0-9a-f]{64}$ ]]; then
      echo "The remote runtime registry current identity is invalid." >&2
      exit 1
    fi
    ssh "${ssh_options[@]}" -- "$ssh_target" "cat '$remote_catalog_path'" >"$retained_source_catalog"
    closure_arguments+=(--retained-source-catalog "$retained_source_catalog")
    ;;
  absent) : ;;
  *)
    echo "The remote runtime registry source catalog has an invalid state." >&2
    exit 1
    ;;
esac
node "$script_directory/plan-registry-transfer.mjs" \
  "${closure_arguments[@]}" >"$payload_list"
if [[ ! -s "$payload_list" ]]; then
  echo "The authenticated runtime registry transfer closure is empty." >&2
  exit 1
fi
hardlink_alias_count="$(
  awk 'END { if (NR % 2 != 0) exit 1; print NR / 2 }' "$hardlink_list"
)"

remote_preflight="$(
  ssh "${ssh_options[@]}" -- "$ssh_target" \
    "command -v ln >/dev/null && test -d '$remote_root' && test ! -L '$remote_root' && stat -c '%a:%u:%g' '$remote_root'"
)"
if [[ "$remote_preflight" != "700:0:0" ]]; then
  echo "The remote runtime registry must be an existing root-owned mode-0700 directory." >&2
  exit 1
fi

local_rsync_version="$(rsync --version)"
remote_rsync_version="$(ssh "${ssh_options[@]}" -- "$ssh_target" rsync --version)"
compression=(--compress)
compression_name="negotiated-default"
if [[ "$local_rsync_version" == *zstd* && "$remote_rsync_version" == *zstd* ]]; then
  compression=(--compress-choice=zstd --compress-level=6)
  compression_name="zstd-6"
fi

common=(
  -a
  --chown=0:0
  --protect-args
  --stats
  --timeout=300
  -e "$rsync_shell"
  "${compression[@]}"
)
destination="$ssh_target:$remote_root/"

# Do not delete generations during transfer: activation has not committed the new pair yet.
# Root control files are installed only after every payload path is present remotely.
rsync "${common[@]}" -H \
  --files-from="$payload_list" \
  --from0 \
  --no-recursive \
  --relative \
  "$local_root/" \
  "$destination"
if [[ -s "$hardlink_list" ]]; then
  ssh "${ssh_options[@]}" -- "$ssh_target" "
set -eu
remote_root='$remote_root'
while IFS= read -r source && IFS= read -r target; do
  source_path=\"\$remote_root/\$source\"
  target_path=\"\$remote_root/\$target\"
  test -f \"\$source_path\" && test ! -L \"\$source_path\"
  if test -e \"\$target_path\" && test \"\$source_path\" -ef \"\$target_path\"; then
    continue
  fi
  ln -f -- \"\$source_path\" \"\$target_path\"
done
" <"$hardlink_list"
fi
rsync "${common[@]}" "$source_catalog" "$destination/source-catalog.json"
current_source="$selected_current"
preserve_remote_current=false
if [[ "$pair_value_count" -eq 4 ]]; then
  if [[ "$remote_control_state" == present:* ]]; then
    preserve_remote_current=true
  fi
fi
if [[ "$preserve_remote_current" == false ]]; then
  rsync "${common[@]}" "$current_source" "$destination/current"
fi

local_catalog_sha256="$("${local_hash[@]}" "$source_catalog" | awk '{print $1}')"
if [[ "$preserve_remote_current" == true ]]; then
  expected_current_sha256="$remote_current_sha256"
else
  expected_current_sha256="$("${local_hash[@]}" "$current_source" | awk '{print $1}')"
fi
remote_identities="$(
  ssh "${ssh_options[@]}" -- "$ssh_target" \
    "sha256sum '$remote_root/source-catalog.json' '$remote_root/current' | awk '{print \$1}'"
)"
expected_identities="$local_catalog_sha256"$'\n'"$expected_current_sha256"
if [[ "$remote_identities" != "$expected_identities" ]]; then
  echo "Remote runtime registry control-file verification failed." >&2
  exit 1
fi

printf 'runtime_registry_transfer=complete compression=%s hardlink_aliases=%s source_catalog_sha256=%s current_sha256=%s\n' \
  "$compression_name" \
  "$hardlink_alias_count" \
  "$local_catalog_sha256" \
  "$expected_current_sha256"
