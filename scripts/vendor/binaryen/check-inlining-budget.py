#!/usr/bin/env python3
from pathlib import Path
import argparse
import json
import os
import subprocess

parser = argparse.ArgumentParser(description='Validate cumulative inlining budgets and execution order.')
parser.add_argument('--baseline', required=True, type=Path)
parser.add_argument('--candidate', required=True, type=Path)
parser.add_argument('--source', required=True, type=Path)
parser.add_argument('--filecheck', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
root = args.output
root.mkdir(parents=True, exist_ok=True)
source = args.source
fixture = source / 'test/lit/passes/inlining-cumulative-size.wat'
check = str(args.filecheck)
env = {**os.environ, 'BINARYEN_CORES': '2'}
records = []
for label, binary in [('original', args.baseline), ('corrected', args.candidate)]:
    for limit, prefix in [(50, 'BOUNDED'), (250, 'LARGE')]:
        command = [str(binary), str(fixture), '--inlining', f'--inline-max-combined-binary-size={limit}']
        result = subprocess.run([*command, '-S', '-o', '-'], capture_output=True, check=True, env=env, timeout=30)
        (root / f'inlining-{label}-{limit}.wat').write_bytes(result.stdout)
        checked = subprocess.run([check, str(fixture), '--check-prefix=' + prefix],
                                 input=result.stdout, capture_output=True, timeout=30)
        expect_failure = label == 'original' and limit == 50
        assert (checked.returncode != 0) == expect_failure, checked.stderr.decode()
        wasm = root / f'inlining-{label}-{limit}.wasm'
        subprocess.run([*command, '-o', str(wasm)], check=True, env=env, timeout=30)
        execution = subprocess.run(['node', '--input-type=module', '-e', '''
            import { readFileSync } from 'node:fs';
            import assert from 'node:assert/strict';
            const values = [];
            const { instance } = await WebAssembly.instantiate(readFileSync(process.argv[1]),
              { env: { observe: value => values.push(value) } });
            instance.exports.main();
            assert.deepEqual(values, Array.from({ length: 16 }, (_, i) => i));
        ''', str(wasm)], check=True, env=env, timeout=30)
        records.append({'binary': label, 'limit': limit, 'expectedRegressionFailure': expect_failure,
                        'fileCheckExit': checked.returncode, 'executionExit': execution.returncode})

fixture = source / 'test/lit/passes/inlining-max-combined-size.wat'
for limit, prefix in [(None, 'DEFAULT'), (96, 'IMCBS96'), (90, 'IMCBS90'), (0, 'IMCBS0')]:
    command = ['python3', str(source / 'scripts/foreach.py'), str(fixture), str(root / 'foreach-temp'),
               str(args.candidate), '-O3', '-S', '-o', '-']
    if limit is not None:
        command.append(f'--inline-max-combined-binary-size={limit}')
    result = subprocess.run(command, capture_output=True, check=True, env=env, timeout=60)
    subprocess.run([check, str(fixture), '--check-prefix=' + prefix], input=result.stdout,
                   capture_output=True, check=True, timeout=30)
    records.append({'existingFixture': prefix, 'passed': True})
(root / 'inlining-checks.json').write_text(json.dumps(records, indent=2) + '\n')
print('Cumulative-budget regression fails on original and passes on correction; all executions and existing updated checks pass.', flush=True)
