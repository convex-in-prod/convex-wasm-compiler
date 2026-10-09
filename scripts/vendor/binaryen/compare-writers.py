#!/usr/bin/env python3
"""Compare a bounded StackIR writer with its pinned, unmodified tool."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--baseline", required=True, type=Path)
parser.add_argument("--candidate", required=True, type=Path)
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location(
    "binaryen_test_support", args.source / "scripts/test/support.py"
)
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)

fixtures = [
    "test/lit/passes/optimize-stack-ir.wast",
    "test/lit/passes/optimize-stack-ir-multivalue.wast",
    "test/lit/passes/stack-ir-eh.wast",
    "test/lit/passes/stack-ir-eh-legacy.wast",
    "test/lit/passes/stack-ir-non-nullable.wast",
    "test/lit/passes/stack-ir-dce.wast",
    "test/lit/branch-hinting-stack-ir.wast",
    "test/lit/branch-hinting-try.wast",
    "test/lit/merge/annotations-func-only.wat",
    "test/lit/merge/annotations.wat",
    "test/passes/dwarf_with_exceptions.wasm",
    "test/passes/dwarf-local-order.wasm",
    "test/passes/fib2_dwarf.wasm",
    "test/passes/epilogue_begin_dwarf.wasm",
    "test/passes/inlined_to_start_dwarf.wasm",
    "test/passes/fannkuch3_manyopts_dwarf.wasm",
]

cases = []
for relative in fixtures:
    for index, (module, _) in enumerate(support.split_wast(str(args.source / relative))):
        assert module is not None, relative
        path = args.output / (Path(relative).name + "." + str(index))
        path.write_bytes(module if isinstance(module, bytes) else module.encode())
        cases.append((relative + ":" + str(index), path, []))

# More functions than any tested batch, with imports and an incomplete last batch.
module = ['(module (import "env" "observe" (func $observe (param i32)))']
for index in range(17):
    module.append(f'''(func $f{index} (export "f{index}") (param $x i32) (result i32)
      (local $saved i32)
      (local.set $saved (i32.add (local.get $x) (i32.const {index})))
      (call $observe (local.get $saved))
      (if (result i32) (local.get $x)
        (then (local.get $saved)) (else (i32.const {index}))))''')
module.append(')')
for name, contents in [
    ("batches", "\n".join(module)),
    ("empty", "(module)"),
    ("imports-only", '(module (import "env" "f" (func)))'),
]:
    path = args.output / (name + ".wat")
    path.write_text(contents)
    cases.append((name, path, []))
map_stem = args.source / "test/lit/sourcemap-sourceroot-file.wat"
cases.append(("source-map", Path(str(map_stem) + ".wasm"), [
    "--input-source-map=" + str(map_stem) + ".map",
    "--output-source-map-url=fixture.map",
]))

records = []
for name, path, extra in cases:
    for mode in [
        ["--generate-stack-ir"],
        ["--generate-stack-ir", "--optimize-stack-ir", "--print-stack-ir"],
        ["-O2"],
        ["-O3"],
        ["--no-stack-ir"],
    ]:
        expected = None
        for label, tool, cores in [
            ("baseline", args.baseline, 1),
            ("candidate-1", args.candidate, 1),
            ("candidate-2", args.candidate, 2),
            ("candidate-4", args.candidate, 4),
        ]:
            output = args.output / "output.wasm"
            source_map = args.output / "output.map"
            command = [str(tool), str(path), "--all-features", "-g", *mode,
                       *extra, "-o", str(output)]
            if name == "source-map":
                command += ["--output-source-map=" + str(source_map)]
            result = subprocess.run(command, capture_output=True, timeout=60,
                                    env={**os.environ, "BINARYEN_CORES": str(cores)})
            assert result.returncode == 0, (name, label, command, result.stderr.decode())
            observed = (output.read_bytes(), result.stdout,
                        source_map.read_bytes() if name == "source-map" else b"")
            if expected is None:
                expected = observed
            assert observed == expected, (name, label, mode, "output mismatch")
            records.append({"fixture": name, "mode": mode, "tool": label,
                            "bytes": len(observed[0]),
                            "sha256": hashlib.sha256(observed[0]).hexdigest()})
    print("identical:", name, flush=True)

(args.output / "results.json").write_text(json.dumps({
    "baselineSha256": hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
    "candidateSha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
    "cases": len(cases), "records": records,
}, indent=2) + "\n")
print(f"All {len(cases)} fixtures match in five modes at 1, 2 and 4 workers.", flush=True)
