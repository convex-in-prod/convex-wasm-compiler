#!/usr/bin/env python3
"""Measure writer memory using equivalent builds and a generic many-function input."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--baseline', type=Path, required=True)
parser.add_argument('--candidate', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
source = args.output / 'many-functions.wat'
with source.open('w') as stream:
    stream.write('(module (import "env" "observe" (func $observe (param i32)))\n')
    for i in range(2500):
        stream.write(f'(func $f{i} (param $x i32)\n')
        for j in range(256):
            stream.write(f'(call $observe (i32.add (local.get $x) (i32.const {j})))\n')
        stream.write(')\n')
    stream.write(')\n')

records = []
for label, tool in [('baseline', args.baseline), ('candidate', args.candidate)]:
    output = args.output / (label + '.wasm')
    usage = args.output / (label + '.usage')
    command = ['/usr/bin/time', '-f', '%e %U %S %M', '-o', str(usage),
               str(tool), str(source), '--generate-stack-ir', '--optimize-stack-ir',
               '-o', str(output)]
    result = subprocess.run(command, capture_output=True, timeout=180,
                            env={**os.environ, 'BINARYEN_CORES': '2'})
    assert result.returncode == 0, (command, result.stderr.decode())
    elapsed, user, system, rss = usage.read_text().split()
    record = {'tool': label, 'wallSeconds': float(elapsed),
              'userSeconds': float(user), 'systemSeconds': float(system),
              'peakRssKiB': int(rss), 'outputBytes': output.stat().st_size,
              'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}
    records.append(record)
    print(json.dumps(record), flush=True)
assert records[0]['sha256'] == records[1]['sha256']
(args.output / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
