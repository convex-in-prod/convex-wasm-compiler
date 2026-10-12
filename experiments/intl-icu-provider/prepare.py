"""Fetch pinned public inputs and create an isolated Hermes worktree."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--hermes-source", required=True, type=Path)
args = parser.parse_args()
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=True)
revision = "680ae7651c2f55cbbacaed0cc11519fe6c253f72"
archive_sha = "bc25711ba5758c8b4f95d4b30473a06b23dbfbe032b29ade7ad26bb3428e4ce7"
baseline = "4ae2b227fd777b46008e84bf695daeb4586c5f63"
archive = root / "upstream.tar.gz"
if (root / "hermes").exists():
    raise RuntimeError("The output already has a Hermes worktree; choose a fresh directory")
if not archive.exists():
    temporary = root / "upstream.tar.gz.partial"
    try:
        with urllib.request.urlopen(
            "https://codeload.github.com/microsoft/hermes-windows/tar.gz/" + revision,
            timeout=60,
        ) as response, temporary.open("wb") as target:
            while chunk := response.read(1024 * 1024):
                target.write(chunk)
        temporary.rename(archive)
    finally:
        temporary.unlink(missing_ok=True)
with archive.open("rb") as source:
    if hashlib.file_digest(source, "sha256").hexdigest() != archive_sha:
        raise RuntimeError("Pinned source archive digest differs")

adapter_files = {
    "lib/Platform/Intl/impl_win/PlatformIntlWin.cpp",
    "lib/Platform/Intl/impl_win/WinIntlUtils.cpp",
    "lib/Platform/Intl/impl_win/WinIntlUtils.h",
    "include/hermes/Platform/Intl/hermes_icu.h",
    "include/hermes/Platform/Intl/icu_types.h",
}
rows = []
with tarfile.open(archive, "r:gz") as source:
    for entry in source:
        relative = entry.name.partition("/")[2]
        if not entry.isfile() or not (
            relative in adapter_files or relative.startswith("external/icu-small/")
        ):
            continue
        if ".." in Path(relative).parts or Path(relative).is_absolute():
            raise RuntimeError("Invalid archive member path")
        output = root / "upstream" / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        data = source.extractfile(entry).read()
        output.write_bytes(data)
        rows.append({
            "path": relative, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
if not adapter_files.issubset({row["path"] for row in rows}):
    raise RuntimeError("Pinned archive is missing adapter inputs")
(root / "source-manifest.json").write_text(json.dumps({
    "microsoftRevision": revision, "archiveSha256": archive_sha,
    "hermesRevision": baseline, "files": rows,
}, indent=2) + "\n")
subprocess.run(
    ["git", "worktree", "add", "--detach", str(root / "hermes"), baseline],
    cwd=args.hermes_source, timeout=120, check=True,
)
subprocess.run(
    ["python3", str(Path(__file__).with_name("port.py")), str(root)],
    timeout=120, check=True,
)
