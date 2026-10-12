"""Apply a verified native Intl stage to its exact source baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("root", type=Path)
parser.add_argument("--stage", choices=["formatters", "bindings", "construction", "locales", "number-ranges", "icu-cleanup"], default="formatters")
args = parser.parse_args()
source = args.root.resolve() / "hermes"
scripts = Path(__file__).resolve().parent
manifest = json.loads((scripts / (args.stage + "-source.json")).read_text())
patch = scripts / (args.stage + ".patch")
if hashlib.sha256(patch.read_bytes()).hexdigest() != manifest["patchSha256"]:
    raise RuntimeError(args.stage + " patch digest differs")
for row in manifest["files"]:
    path = source / row["path"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["before"]:
        raise RuntimeError(args.stage + " baseline differs: " + row["path"])
subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, check=True, timeout=30)
subprocess.run(["git", "apply", str(patch)], cwd=source, check=True, timeout=30)
for row in manifest["files"]:
    if hashlib.sha256((source / row["path"]).read_bytes()).hexdigest() != row["after"]:
        raise RuntimeError("Applied " + args.stage + " source differs: " + row["path"])
print("Applied verified native ICU " + args.stage + " implementation")
