#!/usr/bin/env python3
"""Build/run frozen workloads with cargo-openvm v1.7; compare all public bytes.

No proofs or wall-time benchmarks. The CLI's meter cost is estimated cells;
segment mode reports segmentation. Individual features still execute ALL APIs.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SHA = '425913bdc743ef44236daf472ec53c2c05b75fa1'
SOURCE = f'git+https://github.com/openvm-org/openvm.git?tag=v1.7.0#{SHA}'
VARIANTS = ('software', 'accelerated', 'openvm-sha256', 'openvm-keccak256', 'openvm-k256', 'openvm-p256')
EXPECTED = {
    'planchet-openvm-verify': 'd0125c20e1feb62adbf3d98b84440beeeb03a1f51cec7aae0057374e98c4a375',
    'payment': '4a848e4b4529c481e5d39ac685ef4b9505615abd41f35624745a0108ff39d13c',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', choices=EXPECTED, default='planchet-openvm-verify')
    parser.add_argument('--variants', nargs='+', choices=VARIANTS, default=VARIANTS)
    parser.add_argument('--modes', nargs='+', choices=('pure', 'meter', 'segment'), default=('meter', 'segment'))
    args = parser.parse_args()
    env = dict(os.environ, OPENVM_RUST_TOOLCHAIN='nightly-2026-03-17', CARGO_TERM_COLOR='never')
    env['RUSTC'] = subprocess.check_output(
        ['rustup', 'which', '--toolchain', env['OPENVM_RUST_TOOLCHAIN'], 'rustc'], text=True).strip()
    version = subprocess.check_output(['cargo', 'openvm', '--version'], cwd=ROOT, env=env, text=True).strip()
    if version != 'cargo-openvm v1.7.0 (425913bd)':
        raise SystemExit(f'Expected cargo-openvm v1.7.0 (425913bd), got {version!r}')
    lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())
    sources = {p['source'] for p in lock['package'] if p.get('source', '').startswith('git+https://github.com/openvm-org/openvm.git')}
    if sources != {SOURCE}:
        raise SystemExit(f'Unexpected OpenVM source IDs: {sources!r}')

    logs = ROOT / 'logs' / args.bin
    logs.mkdir(parents=True, exist_ok=True)
    report = {
        'cli': version,
        'rustc': subprocess.check_output([env['RUSTC'], '--version'], text=True).strip(),
        'openvm_source': SOURCE,
        'environment': {
            'OPENVM_RUST_TOOLCHAIN': env['OPENVM_RUST_TOOLCHAIN'],
            'RUSTC': '$(rustup which --toolchain nightly-2026-03-17 rustc)',
        },
        'bin': args.bin,
        'commands': [],
        'results': {},
    }
    (logs / 'environment.json').write_text(json.dumps(
        {k: env[k] for k in ('OPENVM_RUST_TOOLCHAIN', 'RUSTC')}, indent=2) + '\n')

    def run(cmd, log_name):
        command = shlex.join(cmd)
        print(f'+ {command}', flush=True)
        report['commands'].append(command)
        with (logs / log_name).open('w') as log:
            result = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        output = (logs / log_name).read_text()
        if result.returncode:
            print(output, flush=True)
            raise SystemExit(f'Exit {result.returncode}: {command}; log: {logs / log_name}')
        return output

    reference = None
    for variant in args.variants:
        features = [] if variant == 'software' else [variant]
        if args.bin == 'payment':
            features.append('payment')
        output_dir = f'target/runs/{args.bin}/{variant}'
        build = ['cargo', 'openvm', 'build', '--locked', '--no-default-features', '--bin', args.bin,
                 '--config', 'openvm.toml', '--output-dir', output_dir]
        if features:
            build.extend(['--features', ','.join(features)])
        run(build, f'{variant}-build.log')
        modes = {}
        for mode in args.modes:
            output = run(['cargo', 'openvm', 'run', '--locked', '--bin', args.bin,
                          '--exe', f'{output_dir}/{args.bin}.vmexe', '--config', 'openvm.toml',
                          '--mode', mode], f'{variant}-{mode}.log')
            match = re.search(r'Execution output: (\[[^\n]+\])', output)
            if not match:
                raise SystemExit(f'Missing public output: {variant}/{mode}')
            public = ast.literal_eval(match[1])
            if len(public) < 32 or public[:32] != list(bytes.fromhex(EXPECTED[args.bin])):
                raise SystemExit(f'Wrong public output: {variant}/{mode}: {public}')
            if reference is None:
                reference = public
            if public != reference:
                raise SystemExit(f'Public outputs differ: {variant}/{mode}')
            metrics = {'public_output': public}
            for label, key in (('Number of instructions executed', 'instret'), ('Total cost', 'estimated_cells'), ('Total segments', 'segments')):
                match = re.search(re.escape(label) + r': (\d+)', output)
                if match:
                    metrics[key] = int(match[1])
            required = {'meter': ('instret', 'estimated_cells'), 'segment': ('instret', 'segments'), 'pure': ()}[mode]
            if any(key not in metrics for key in required):
                raise SystemExit(f'Missing {mode} metrics: {variant}: {output}')
            modes[mode] = metrics
            print(f'{variant}/{mode}: ' + json.dumps(metrics), flush=True)
        report['results'][variant] = modes
        (logs / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'All complete public outputs match; results: {logs / "results.json"}', flush=True)


if __name__ == '__main__':
    main()
