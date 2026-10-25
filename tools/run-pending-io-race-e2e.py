"""Adversarial, elevated pending-I/O tests for the owned minifilter fixture.

Kernel gates keep the same I/O alive while cancellation, owner/requestor death
and FilterUnload overlap. The runner rejects a round that misses that window.
No external filter, callback address, security setting or existing service changes.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import importlib.util
import json
import os
import pathlib
import queue
import random
import subprocess
import sys
import threading
import time
import traceback
import winreg

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pending', ROOT / 'tools/run-pending-io-e2e.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
kernel, flt = p.kernel, p.flt


def io_child(path):
    """Two independent IRPs on one FileObject; cancellation runs in this process."""
    class Overlapped(c.Structure):
        _fields_ = [('Internal', c.c_size_t), ('InternalHigh', c.c_size_t),
            ('Offset', w.DWORD), ('OffsetHigh', w.DWORD), ('Event', w.HANDLE)]
    kernel.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.POINTER(Overlapped)]
    kernel.GetOverlappedResult.argtypes = [w.HANDLE, c.POINTER(Overlapped), c.POINTER(w.DWORD), w.BOOL]
    kernel.CancelIoEx.argtypes = [w.HANDLE, c.POINTER(Overlapped)]
    kernel.CancelIoEx.restype = w.BOOL
    kernel.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
    kernel.CreateEventW.restype = w.HANDLE
    kernel.ResetEvent.argtypes = [w.HANDLE]
    handle = kernel.CreateFileW(path, 0x80000000, 7, None, 3, 0x60000000, None)
    assert handle != w.HANDLE(-1).value, c.get_last_error()
    output_lock = threading.Lock()
    slots = [dict(work=queue.Queue(), ready=threading.Event(), read=False,
        overlap=Overlapped(), event=kernel.CreateEventW(None, True, False, None),
        buffer=kernel.VirtualAlloc(None, 4096, 0x3000, 4)) for _ in range(2)]
    assert all(s['buffer'] and s['event'] for s in slots)

    def emit(value):
        with output_lock:
            print(json.dumps(value), flush=True)

    def worker(index):
        slot = slots[index]
        slot['tid'] = kernel.GetCurrentThreadId()
        slot['thread'] = kernel.OpenThread(1, False, slot['tid'])
        assert slot['thread']
        slot['ready'].set()
        while True:
            command = slot['work'].get()
            if command is None:
                return
            slot['read'] = bool(command.get('read'))
            started = time.perf_counter_ns()
            if slot['read']:
                c.memset(c.byref(slot['overlap']), 0, c.sizeof(Overlapped))
                slot['overlap'].Event = slot['event']
                kernel.ResetEvent(slot['event'])
                transferred = w.DWORD()
                ok = kernel.ReadFile(handle, slot['buffer'], 4096, c.byref(transferred), c.byref(slot['overlap']))
                error = 0 if ok else c.get_last_error()
                if not ok and error == 997:
                    ok = kernel.GetOverlappedResult(handle, c.byref(slot['overlap']), c.byref(transferred), True)
                    error = 0 if ok else c.get_last_error()
                result = dict(ok=bool(ok), error=error, bytes=transferred.value)
                if ok:
                    result['data_matches'] = c.string_at(slot['buffer'], transferred.value) == b'P' * 4096
            else:
                opened = kernel.CreateFileW(path, 0x80000000, 7, None, 3, 0x80, None)
                ok = opened != w.HANDLE(-1).value
                result = dict(ok=ok, error=0 if ok else c.get_last_error())
                if ok:
                    kernel.CloseHandle(opened)
            emit(dict(kind='io', slot=index, started=started, finished=time.perf_counter_ns(), **result))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(2)]
    for thread in threads:
        thread.start()
    for slot in slots:
        assert slot['ready'].wait(5)
    emit(dict(pid=os.getpid(), tids=[s['tid'] for s in slots]))
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command.get('exit'):
                break
            index = command.get('slot', 0)
            if command.get('cancel'):
                slot = slots[index]
                started = time.perf_counter_ns()
                ok = (kernel.CancelIoEx(handle, c.byref(slot['overlap'])) if slot['read'] else
                    kernel.CancelSynchronousIo(slot['thread']))
                error = 0 if ok else c.get_last_error()
                emit(dict(kind='cancel', slot=index, ok=bool(ok), error=error,
                    started=started, finished=time.perf_counter_ns()))
            else:
                slots[index]['work'].put(command)
    finally:
        kernel.CancelIoEx(handle, None)
        for slot in slots:
            kernel.CancelSynchronousIo(slot['thread'])
            slot['work'].put(None)
        for thread in threads:
            thread.join(10)
            assert not thread.is_alive()
        for slot in slots:
            kernel.CloseHandle(slot['thread'])
            kernel.CloseHandle(slot['event'])
            kernel.VirtualFree(slot['buffer'], 0, 0x8000)
        kernel.CloseHandle(handle)


class Suite:
    def __init__(self, output):
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.checks, self.audits, self.children = [], [], []
        self.owned, self.loaded = False, False
        self.path = self.output / 'target.tmp'
        self.path.write_bytes(b'P' * 4096)
        self.fixture = ROOT / 'x64/Release' / (p.NAME + '.sys')
        self.hash = hashlib.sha256(self.fixture.read_bytes()).hexdigest()

    def record(self, kind, **detail):
        with open(self.output / 'journal.jsonl', 'a', encoding='utf-8') as log:
            log.write(json.dumps(dict(kind=kind, time=time.time(), **detail)) + '\n')
            log.flush()
            os.fsync(log.fileno())

    def check(self, name, condition, **detail):
        value = dict(name=name, passed=bool(condition), **detail)
        self.checks.append(value)
        self.record('check', **value)
        (self.output / 'checks.json').write_text(json.dumps(self.checks, indent=2), encoding='utf-8')
        print(name, 'PASS' if condition else 'FAIL', flush=True)
        assert condition, value

    def run(self, *args, expected=0):
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        with open(self.output / 'lifecycle.log', 'ab') as log:
            log.write((' '.join(args) + '\n').encode() + result.stdout)
        if expected is not None:
            assert result.returncode == expected, (args, result.returncode, result.stdout)
        return result

    def setup(self):
        self.check('service-absent', self.run('sc.exe', 'query', p.NAME, expected=None).returncode == 1060)
        self.run('sc.exe', 'create', p.NAME, 'type=', 'filesys', 'start=', 'demand',
            'binPath=', str(self.fixture), 'depend=', 'FltMgr')
        self.owned = True
        for branch in ('Instances', 'Parameters\\Instances'):
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, p.SERVICE + '\\' + branch) as key:
                winreg.SetValueEx(key, 'DefaultInstance', 0, winreg.REG_SZ, p.INSTANCE)
            for name, altitude in ((p.INSTANCE, '370030.12345'), (p.LOWER, '370029.12345')):
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, p.SERVICE + '\\' + branch + '\\' + name) as key:
                    winreg.SetValueEx(key, 'Altitude', 0, winreg.REG_SZ, altitude)
                    winreg.SetValueEx(key, 'Flags', 0, winreg.REG_DWORD, 1)

    def load(self):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p.SERVICE + '\\Parameters', 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, 'PendingIoFinalAudit')
            except FileNotFoundError:
                pass
        self.run('fltmc.exe', 'load', p.NAME)
        self.loaded = True
        for name, altitude in ((p.INSTANCE, '370030.12345'), (p.LOWER, '370029.12345')):
            self.run('fltmc.exe', 'attach', p.NAME, 'C:', '-i', name, '-a', altitude)
        with p.Port() as port:
            state = p.wait_state(port, lambda s: s.WorkerAlive == 1)
            assert p.balanced(state) and state.Created == state.OwnerPid == state.ArmedMode == 0

    def audit(self, name):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p.SERVICE + '\\Parameters') as key:
            raw, kind = winreg.QueryValueEx(key, 'PendingIoFinalAudit')
        assert kind == winreg.REG_BINARY and len(raw) == c.sizeof(p.Status)
        state = p.Status.from_buffer_copy(raw)
        self.audits.append(dict(name=name, **p.fields(state)))
        (self.output / 'unload-audits.json').write_text(json.dumps(self.audits, indent=2), encoding='utf-8')
        self.check(name + '-ledger', state.Magic == p.MAGIC and state.Version == p.VERSION and
            state.Size == c.sizeof(p.Status) and p.balanced(state) and state.Stopping == 1 and
            state.WorkerAlive == state.LiveInstances == state.Connections == state.OwnerPid == state.ArmedMode == 0
            and state.InstanceStarts == state.InstanceCompletes, state=p.fields(state))
        return state

    def child(self, io=False):
        value = (p.Child('--io-child', self.path, script=__file__) if io else p.Child('--owner-child'))
        self.children.append(value)
        return value

    def unload(self, name):
        with p.managed.driver_load_privilege():
            hr = flt.FilterUnload(p.NAME)
        assert hr >= 0, f'unload: 0x{hr & 0xffffffff:08x}'
        self.loaded = False
        return self.audit(name)

    def regressions(self, iterations, cases):
        for iteration in range(iterations):
            for case in cases:
                self.load()
                target, owner = self.child(io=True), self.child()
                with p.Port() as observer:
                    before = observer.send()
                    owner.send(action=4, mode=4, pid=target.proc.pid, delay=500, Reserved=4)
                    owner.receive()
                    target.send(read=True, slot=0)
                    held = p.wait_state(observer, lambda s: s.BeforeLowerEntered == before.BeforeLowerEntered + 1 and
                        s.BeforeLowerCompleted == before.BeforeLowerCompleted)
                    self.record('early-gate', case=case, iteration=iteration, state=p.fields(held))
                    if case == 'stale':
                        owner.close(force=True)
                        released = observer.send()
                        assert released.OwnerPid == 0 and released.BeforeLowerCompleted == before.BeforeLowerCompleted
                        result = target.receive()
                        state = p.wait_state(observer, p.balanced)
                        self.check(f'stale-owner-before-lower-{iteration}', result['ok'] and result['data_matches'] and
                            state.Created == before.Created + 1 and state.PreQueued == before.PreQueued and
                            state.StaleLowerRejected == before.StaleLowerRejected + 1,
                            released=p.fields(released), after=p.fields(state), result=result)
                    else:
                        # Same handle/process/offset/length, but a different buffer
                        # and callback-data identity. It must not claim slot 0's pair.
                        target.send(read=True, slot=1)
                        try:
                            result = target.receive(timeout=.4)
                        except queue.Empty:
                            self.check(f'unrelated-read-not-claimed-{iteration}', False,
                                during=p.fields(observer.send()), reason='unrelated READ was delayed')
                        during = observer.send()
                        self.check(f'unrelated-read-not-claimed-{iteration}', result['slot'] == 1 and result['ok'] and
                            result['data_matches'] and during.BeforeLowerCompleted == before.BeforeLowerCompleted and
                            during.PreQueued == before.PreQueued and during.OtherReadSkipped > before.OtherReadSkipped,
                            during=p.fields(during), result=result)
                        p.wait_state(observer, lambda s: s.PreQueued == before.PreQueued + 1)
                        owner.send(action=2)
                        owner.receive()
                        result = target.receive()
                        after = p.wait_state(observer, p.balanced)
                        self.check(f'paired-read-still-completes-{iteration}', result['slot'] == 0 and result['ok'] and
                            result['data_matches'] and after.Created == before.Created + 2, after=p.fields(after))
                    owner.close()
                    target.close()
                self.unload(f'{case}-{iteration}')

    def races(self, iterations, seed, gated=True):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for mode, phase in ((1, 'pre'), (2, 'post'), (3, 'pre'), (3, 'post'), (4, 'pre')):
                label = f'race-{iteration}-{mode}-{phase}'
                self.load()
                target, owner = self.child(io=True), self.child()
                duplicate = w.HANDLE()
                if iteration % 2:
                    assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                        w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                observer = p.Port()
                outcomes, errors = {}, []
                barrier = threading.Barrier(4)
                # The requestor survives alternate rounds, giving a user-mode
                # result in addition to the final kernel ledger. Owner always dies.
                kill_requestor = iteration % 2 == 0
                order = rng.sample(['cancel', 'kill', 'unload'], 3)
                delays = {action: order.index(action) * .002 for action in order}

                def actor(action):
                    try:
                        barrier.wait(5)
                        time.sleep(delays[action])
                        begin = time.perf_counter_ns()
                        detail = {}
                        if action == 'cancel':
                            try:
                                target.send(cancel=True, slot=0)
                                detail['sent'] = True
                            except (BrokenPipeError, OSError):
                                detail['sent'] = False
                        elif action == 'kill':
                            owner.proc.terminate()
                            if kill_requestor:
                                target.proc.terminate()
                            owner.proc.wait(10)
                            detail['owner_exit'] = owner.proc.returncode
                        else:
                            with p.managed.driver_load_privilege():
                                hr = flt.FilterUnload(p.NAME)
                            assert hr >= 0, f'FilterUnload: 0x{hr & 0xffffffff:08x}'
                            self.loaded = False
                        outcomes[action] = dict(begin=begin, end=time.perf_counter_ns(), **detail)
                    except BaseException:
                        errors.append(traceback.format_exc())

                actors = [threading.Thread(target=actor, args=(name,), daemon=True) for name in order]
                for thread in actors:
                    thread.start()
                try:
                    before = observer.send()
                    owner.send(action=4 if gated else 1, mode=mode, pid=target.proc.pid,
                        delay=500 if gated else 2000, Reserved=(2 if phase == 'post' else 1) if gated else 0)
                    owner.receive()
                    target.send(read=mode == 4, slot=0)
                    if mode == 3 and phase == 'post':
                        p.wait_state(observer, lambda s: s.PreQueued == before.PreQueued + 1)
                        owner.send(action=2)
                        owner.receive()
                    held = p.wait_state(observer, lambda s: (s.RaceEntered == before.RaceEntered + 1 and
                        s.RaceCompleted == before.RaceCompleted) if gated else
                        (getattr(s, phase.title() + 'Queued') == getattr(before, phase.title() + 'Queued') + 1 and
                         getattr(s, phase.title() + 'Completed') == getattr(before, phase.title() + 'Completed')))
                    self.record('race-release', label=label, gated=gated, kill_requestor=kill_requestor,
                        order=order, held=p.fields(held))
                    barrier.wait(5)
                    for thread in actors:
                        thread.join(15)
                    assert not errors and all(not t.is_alive() for t in actors), errors
                    messages = []
                    if kill_requestor:
                        target.proc.wait(10)
                        while not target.lines.empty():
                            line = target.lines.get_nowait()
                            if line:
                                messages.append(json.loads(line))
                    else:
                        # A surviving requestor must report exactly one I/O and
                        # one cancellation outcome. ERROR_NOT_FOUND is legal if
                        # completion/unload won; it is not claimed as a cancel win.
                        messages = [target.receive(), target.receive()]
                        ios = [m for m in messages if m['kind'] == 'io']
                        cancels = [m for m in messages if m['kind'] == 'cancel']
                        assert len(ios) == len(cancels) == 1, messages
                        assert cancels[0]['ok'] or cancels[0]['error'] == 1168, messages
                        assert ios[0]['ok'] or ios[0]['error'] == 995, messages
                        if ios[0]['ok'] and mode == 4:
                            assert ios[0]['data_matches'], messages
                    state = self.audit(label)
                    # The owner must actually exit before unload returns, and
                    # the cancel actor must enter that same held-I/O window.
                    # For a surviving requestor, verify native cancel entry, not
                    # just command dispatch. Its return can be scheduled after
                    # unload's return; RaceCancelSeen proves the pre IRP cancel.
                    overlap = (outcomes['kill']['end'] < outcomes['unload']['end'] and
                        outcomes['cancel']['begin'] < outcomes['unload']['end'] and
                        (kill_requestor or cancels[0]['started'] < outcomes['unload']['end']))
                    self.check(label + '-overlap', not gated or (state.RaceEntered == state.RaceCompleted == 1 and
                        state.RaceStopSeen == 1 and (phase == 'post' or state.RaceCancelSeen == 1) and overlap),
                        order=order, kill_requestor=kill_requestor, calls=outcomes, messages=messages,
                        state=p.fields(state))
                    try:
                        observer.send()
                        raise AssertionError('unloaded control port still responds')
                    except OSError:
                        pass
                finally:
                    barrier.abort()
                    for thread in actors:
                        thread.join(15)
                    observer.close()
                    if duplicate.value:
                        kernel.CloseHandle(duplicate)
                    owner.close(force=True)
                    target.close(force=True)

    def cleanup(self):
        errors = []
        for child in reversed(self.children):
            try:
                child.close(force=True)
            except BaseException:
                errors.append(traceback.format_exc())
        if self.owned:
            try:
                if self.loaded:
                    self.unload('cleanup')
                self.check('no-filter-residue', p.NAME.encode() not in self.run('fltmc.exe', 'filters').stdout)
                self.run('sc.exe', 'delete', p.NAME)
                self.check('no-service-residue', self.run('sc.exe', 'query', p.NAME, expected=None).returncode == 1060)
            except BaseException:
                errors.append(traceback.format_exc())
        return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--iterations', type=int, default=12)
    parser.add_argument('--case', choices=('stale', 'identity', 'regressions', 'races', 'all'), default='all')
    parser.add_argument('--seed', type=int, default=20261025)
    parser.add_argument('--ungated', action='store_true', help='also exercise ordinary completion scheduling')
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100
    suite, completed, started = Suite(args.output), False, time.monotonic()
    try:
        suite.setup()
        if args.case != 'races':
            suite.regressions(args.iterations, ['stale', 'identity'] if args.case in ('all', 'regressions') else [args.case])
        if args.case in ('all', 'races'):
            suite.races(args.iterations, args.seed, gated=not args.ungated)
        completed = True
    finally:
        errors = suite.cleanup()
        result = dict(passed=completed and not errors and all(x['passed'] for x in suite.checks),
            checks=len(suite.checks), iterations=args.iterations, case=args.case, seed=args.seed,
            gated=not args.ungated, seconds=time.monotonic() - started, fixture_sha256=suite.hash,
            cleanup_errors=errors)
        (suite.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if errors:
            raise RuntimeError(errors)


if __name__ == '__main__':
    try:
        if sys.argv[1:2] == ['--io-child']:
            io_child(sys.argv[2])
        else:
            main()
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
