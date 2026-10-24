"""Run every PhishGuard test. Usage (from the folder that contains phishguard-extension and tests):

    python3 tests/run_all.py                    # everything, including the real-Chromium install test
    python3 tests/run_all.py --skip-real-browser
"""
import subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXT = HERE.parent / 'phishguard-extension'
steps = [[ 'node', '--check', str(p)] for p in sorted(EXT.glob('*.js'))]
steps += [
    ['node', str(HERE / 'check_urls.js')],
    ['node', str(HERE / 'test_background.js')],
    [sys.executable, str(HERE / 'check_content.py')],
    [sys.executable, str(HERE / 'test_dynamic_forms.py')],
    [sys.executable, str(HERE / 'test_popup.py')],
]
if '--skip-real-browser' not in sys.argv:
    steps.append([sys.executable, str(HERE / 'test_real_chromium.py')])

failed = 0
for cmd in steps:
    name = Path(cmd[-1]).name if cmd[1] != '--check' else f'syntax {Path(cmd[-1]).name}'
    res = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True)
    ok = res.returncode == 0
    failed += not ok
    last = (res.stdout.strip().splitlines() or [''])[-1]
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {last}" if ok and last.startswith('PASS') else ''))
    if not ok:
        print(res.stdout[-3000:], res.stderr[-3000:], sep='\n')
print(f'\n{len(steps) - failed}/{len(steps)} passed')
sys.exit(1 if failed else 0)
