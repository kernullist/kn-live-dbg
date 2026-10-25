"""Supervise owned-fixture runner failures, including exit without Python finally.

The runner waits on an event before creating test resources. Assign it to a
kill-on-close Windows job first, so every helper is contained even on abrupt
runner exit. Recovery validates the exact owned service image before unloading
and deleting it; failed tests and failed recovery remain distinct evidence.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import importlib.util
import json
import pathlib
import subprocess
import sys
import time
import traceback
import uuid
import winreg

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('query', ROOT / 'tools/run-pending-query-e2e.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
p, kernel = q.p, q.kernel
STAGES = ('reader-start', 'after-gates', 'during-race', 'reader-error',
    'after-unload', 'audit', 'cleanup-audit', 'cleanup-log', 'cleanup-command-log', 'runner-exit')


class BasicLimits(c.Structure):
    _fields_ = [('ProcessTime', c.c_int64), ('JobTime', c.c_int64), ('Flags', w.DWORD),
        ('MinWorkingSet', c.c_size_t), ('MaxWorkingSet', c.c_size_t), ('ActiveLimit', w.DWORD),
        ('Affinity', c.c_size_t), ('Priority', w.DWORD), ('Scheduling', w.DWORD)]


class ExtendedLimits(c.Structure):
    _fields_ = [('Basic', BasicLimits), ('IoCounters', c.c_uint64 * 6),
        ('ProcessMemory', c.c_size_t), ('JobMemory', c.c_size_t),
        ('PeakProcessMemory', c.c_size_t), ('PeakJobMemory', c.c_size_t)]


class Accounting(c.Structure):
    _fields_ = [('Times', c.c_int64 * 4), ('PageFaults', w.DWORD),
        ('TotalProcesses', w.DWORD), ('ActiveProcesses', w.DWORD), ('TerminatedProcesses', w.DWORD)]


kernel.CreateJobObjectW.argtypes, kernel.CreateJobObjectW.restype = [c.c_void_p, w.LPCWSTR], w.HANDLE
kernel.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
kernel.QueryInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]
kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
kernel.CreateEventW.argtypes, kernel.CreateEventW.restype = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR], w.HANDLE
kernel.SetEvent.argtypes = [w.HANDLE]


def native(ok):
    if not ok:
        raise c.WinError(c.get_last_error())
    return ok


def command(*args):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)


def recover(output):
    query = command('sc.exe', 'query', p.NAME)
    if query.returncode == 1060:
        filters = command('fltmc.exe', 'filters')
        assert filters.returncode == 0 and p.NAME.encode() not in filters.stdout
        return None
    assert query.returncode == 0, query.stdout
    # setup() refused any pre-existing service before starting this runner. Do
    # not act on a service whose image changed during the test.
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p.SERVICE) as key:
        path, kind = winreg.QueryValueEx(key, 'ImagePath')
    assert kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ)
    if path.startswith('\\??\\'):
        path = path[4:]
    fixture = ROOT / 'x64/Release' / (p.NAME + '.sys')
    assert pathlib.Path(path).resolve() == fixture.resolve(), path
    suite = q.Suite(output / 'recovery', 8)
    suite.owned = True
    filters = suite.run('fltmc.exe', 'filters')
    suite.loaded = p.NAME.encode() in filters.stdout
    validated = False
    try:
        if not suite.loaded:
            suite.audit('already-unloaded')
        validated = True
    finally:
        errors = suite.cleanup()
        (suite.output / 'result.json').write_text(json.dumps(dict(passed=validated and not errors,
            cleanup_errors=errors, fixture_sha256=suite.hash), indent=2), encoding='utf-8')
    assert not errors, errors
    return dict(audits=suite.audits, checks=suite.checks, fixture_sha256=suite.hash)


def run_case(output, stage, readers, seed, change):
    output.mkdir(parents=True, exist_ok=False)
    assert command('sc.exe', 'query', p.NAME).returncode == 1060, 'fixture service must be absent'
    event_name = 'Local\\KnLiveDbgQueryRunner-' + str(uuid.uuid4())
    job = native(kernel.CreateJobObjectW(None, None))
    event, process, accounting, cleanup_errors = None, None, Accounting(), []
    recovery, exit_code = None, None
    try:
        limits = ExtendedLimits()
        limits.Basic.Flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        native(kernel.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)))
        event = native(kernel.CreateEventW(None, True, False, event_name))
        args = [sys.executable, str(ROOT / 'tools/run-pending-query-e2e.py'), '--output', str(output / 'runner'),
            '--case', 'races', '--iterations', '1', '--readers', str(readers), '--seed', str(seed),
            '--last-close', '--reply-change', change, '--inject-failure', stage, '--start-event', event_name]
        with open(output / 'runner.log', 'wb') as log:
            process = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW)
            native(kernel.AssignProcessToJobObject(job, w.HANDLE(int(process._handle))))
            native(kernel.SetEvent(event))
            exit_code = process.wait(90)
    finally:
        original = traceback.format_exc() if sys.exc_info()[0] else None
        try:
            # A failed runner may leave owner/requester helpers alive. Reap only
            # processes in its job before unloading the fixture from this parent.
            native(kernel.TerminateJobObject(job, 88))
            deadline = time.monotonic() + 10
            while True:
                native(kernel.QueryInformationJobObject(job, 1, c.byref(accounting), c.sizeof(accounting), None))
                if accounting.ActiveProcesses == 0:
                    break
                assert time.monotonic() < deadline, 'job helpers did not terminate'
                time.sleep(.01)
            if process is not None:
                if process.poll() is None:  # Assignment failure: it never passed the start event.
                    process.terminate()
                process.wait(10)
        except BaseException:
            cleanup_errors.append(traceback.format_exc())
        finally:
            kernel.CloseHandle(job)
            if event:
                kernel.CloseHandle(event)
        try:
            recovery = recover(output)
        except BaseException:
            cleanup_errors.append(traceback.format_exc())
        evidence = dict(stage=stage, exit_code=exit_code, original_error=original,
            job_total=accounting.TotalProcesses, job_active=accounting.ActiveProcesses,
            job_terminated=accounting.TerminatedProcesses, recovery=recovery, cleanup_errors=cleanup_errors)
        (output / 'supervisor.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    assert not cleanup_errors, cleanup_errors
    expected_exit = 86 if stage == 'runner-exit' else 1
    assert exit_code == expected_exit, (stage, exit_code)
    assert accounting.ActiveProcesses == 0
    if stage == 'runner-exit':
        journal = [json.loads(line) for line in (output / 'runner/journal.jsonl').read_text().splitlines()]
        windows = [row for row in journal if row['kind'] == 'runner-failure-window']
        assert len(windows) == 1 and windows[0]['live_queries'] > 0, windows
        assert windows[0]['buffers_changed'] and windows[0]['original_closing'] and windows[0]['root_closing']
        assert recovery and recovery['audits'] and not (output / 'runner/result.json').exists()
    else:
        result = json.loads((output / 'runner/result.json').read_text())
        failure = (output / 'runner/failure.txt').read_text()
        assert not result['passed'] and result['injected_failure'] == stage
        assert 'injected runner failure: ' + stage in failure, failure
        expected_cleanup = {'reader-error': 'injected reader assertion',
            'cleanup-audit': 'injected cleanup audit failure',
            'cleanup-log': 'injected cleanup evidence failure',
            'cleanup-command-log': 'cleanup-command-log:'}.get(stage)
        if expected_cleanup:
            assert len(result['cleanup_errors']) == (3 if stage in ('cleanup-log', 'cleanup-command-log') else 1), result
            assert all(expected_cleanup in error for error in result['cleanup_errors']), result
        else:
            assert not result['cleanup_errors'], result
        # Structured failures must clean themselves without supervisor recovery.
        assert recovery is None, recovery
        audits = json.loads((output / 'runner/unload-audits.json').read_text())
        assert len(audits) == 1 and audits[0]['QueryActive'] == 0
        checks = json.loads((output / 'runner/checks.json').read_text())
        assert all(row['passed'] for row in checks) and any(row['name'].endswith('-resources-closed') for row in checks)
    assert command('sc.exe', 'query', p.NAME).returncode == 1060
    evidence['verified_expected_failure'] = True
    (output / 'verified.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(stage, 'EXPECTED FAILURE, CLEANUP PASS', flush=True)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--iterations', type=int, default=2)
    parser.add_argument('--readers', type=int, choices=(2, 4, 8, 16), default=8)
    parser.add_argument('--case', choices=('all', *STAGES), default='all')
    parser.add_argument('--seed', type=int, default=251400)
    parser.add_argument('--reply-change', choices=('mixed', *q.ReplyBuffer.MODES), default='mixed')
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows, completed = [], False
    try:
        stages = STAGES if args.case == 'all' else (args.case,)
        for iteration in range(args.iterations):
            for stage in stages:
                rows.append(run_case(output / f'{iteration}-{stage}', stage, args.readers,
                    args.seed + iteration * len(STAGES) + STAGES.index(stage), args.reply_change))
        completed = True
    finally:
        if sys.exc_info()[0]:
            (output / 'failure.txt').write_text(traceback.format_exc(), encoding='utf-8')
        (output / 'result.json').write_text(json.dumps(dict(passed=completed, verified=len(rows),
            iterations=args.iterations, readers=args.readers, case=args.case, results=rows), indent=2), encoding='utf-8')


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
