"""Elevated E2E for pending I/O in our owned, harmless minifilter fixture.

Creates one named service, refuses an existing service, and removes it on exit.
The target issues real CREATE and unbuffered overlapped READ requests. No external
filter, callback pointer, security policy, or reboot setting is modified.
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
import subprocess
import sys
import threading
import time
import traceback
import winreg

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('managed', ROOT / 'tools/run-managed-callback-e2e.py')
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)
NAME, INSTANCE = managed.NAME, managed.INSTANCE
LOWER = NAME + '.Lower'
PORT = '\\' + NAME + 'PendingIo'
MAGIC = 0x4B50494F
SERVICE = 'SYSTEM\\CurrentControlSet\\Services\\' + NAME
flt, kernel = managed.flt, managed.kernel
flt.FilterDetach.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR]
flt.FilterDetach.restype = c.c_long
kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
kernel.CreateFileW.restype = w.HANDLE
kernel.GetCurrentThreadId.restype = w.DWORD
kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
kernel.OpenThread.restype = w.HANDLE
kernel.CancelSynchronousIo.argtypes = [w.HANDLE]
kernel.CancelSynchronousIo.restype = w.BOOL


class Request(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('Magic', 'Version', 'Size', 'Action',
        'Mode', 'TargetPid', 'DelayMilliseconds', 'Reserved')]


class Status(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('Magic', 'Version', 'Size', 'Stopping',
        'ArmedMode', 'OwnerPid', 'Connections', 'WorkerAlive', 'ActiveWorkers',
        'QueueDepth', 'LiveContexts', 'LiveInstances')] + [(n, c.c_uint64) for n in (
        'Created', 'Freed', 'LogicalCompleted', 'PreQueued', 'PreCompleted', 'PostCalled',
        'PostQueued', 'PostCompleted', 'PostDrained', 'PreCancelled', 'AllocFailed',
        'QueueFailed', 'OwnerRestores', 'InstanceStarts', 'InstanceCompletes',
        'BufferLocks', 'BufferLockFailures', 'Violations')]


assert c.sizeof(Request) == 32 and c.sizeof(Status) == 192


def fields(state):
    return {name: getattr(state, name) for name, _ in Status._fields_}


def balanced(state):
    return (state.LiveContexts == state.ActiveWorkers == state.QueueDepth == state.Violations == 0
        and state.Created == state.Freed == state.LogicalCompleted
        and state.PreQueued == state.PreCompleted and state.PostQueued == state.PostCompleted)


class Port:
    def __init__(self):
        self.handle = w.HANDLE()
        hr = flt.FilterConnectCommunicationPort(PORT, 0, None, 0, None, c.byref(self.handle))
        if hr < 0:
            raise OSError(f'connect: 0x{hr & 0xffffffff:08x}')

    def send(self, action=0, mode=0, pid=0, delay=0, **overrides):
        request = Request(MAGIC, 1, c.sizeof(Request), action, mode, pid, delay, 0)
        for key, value in overrides.items():
            setattr(request, key, value)
        state, returned = Status(), w.DWORD()
        hr = flt.FilterSendMessage(self.handle, c.byref(request), c.sizeof(request),
            c.byref(state), c.sizeof(state), c.byref(returned))
        if hr < 0:
            raise OSError(f'message: 0x{hr & 0xffffffff:08x}')
        assert returned.value == c.sizeof(state) and state.Magic == MAGIC and state.Version == 1
        return state

    def close(self):
        if self.handle.value:
            kernel.CloseHandle(self.handle)
            self.handle = w.HANDLE()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def wait_state(port, predicate, timeout=8):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        state = port.send()
        if predicate(state):
            return state
        time.sleep(.003)
    raise TimeoutError(fields(state))


class Child:
    """Bounded protocol reads, so a stuck kernel I/O cannot hang the test runner."""
    def __init__(self, role, *args):
        self.proc = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), role, *map(str, args)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.ready = self.receive()
        except BaseException:
            self.close(force=True)
            raise

    def _read(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def send(self, **command):
        self.proc.stdin.write(json.dumps(command) + '\n')
        self.proc.stdin.flush()

    def receive(self, timeout=10):
        line = self.lines.get(timeout=timeout)
        if line is None:
            raise RuntimeError(f'child exited: {self.proc.stderr.read()}')
        return json.loads(line)

    def close(self, force=False):
        if self.proc.poll() is None:
            if force:
                self.proc.terminate()
            else:
                self.send(exit=True)
            self.proc.wait(10)
        self.reader.join(2)
        assert not self.reader.is_alive()
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            stream.close()


def child_io(path):
    # Prepare an unbuffered, overlapped handle before arming any operation.
    class Overlapped(c.Structure):
        _fields_ = [('Internal', c.c_size_t), ('InternalHigh', c.c_size_t),
                    ('Offset', w.DWORD), ('OffsetHigh', w.DWORD), ('Event', w.HANDLE)]
    kernel.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.POINTER(Overlapped)]
    kernel.GetOverlappedResult.argtypes = [w.HANDLE, c.POINTER(Overlapped), c.POINTER(w.DWORD), w.BOOL]
    read_handle = kernel.CreateFileW(path, 0x80000000, 7, None, 3, 0x60000000, None)
    assert read_handle != w.HANDLE(-1).value, c.get_last_error()
    buffer = kernel.VirtualAlloc(None, 4096, 0x3000, 4)
    assert buffer
    print(json.dumps(dict(pid=os.getpid(), tid=kernel.GetCurrentThreadId())), flush=True)
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command.get('exit'):
                break
            start = time.monotonic()
            if command.get('read'):
                overlap, transferred = Overlapped(), w.DWORD()
                ok = kernel.ReadFile(read_handle, buffer, 4096, c.byref(transferred), c.byref(overlap))
                error = 0 if ok else c.get_last_error()
                if not ok and error == 997:
                    ok = kernel.GetOverlappedResult(read_handle, c.byref(overlap), c.byref(transferred), True)
                    error = 0 if ok else c.get_last_error()
                result = dict(ok=bool(ok), error=error, bytes=transferred.value)
                if ok:
                    result['data_matches'] = c.string_at(buffer, transferred.value) == b'P' * 4096
                    assert result['data_matches'], result
            else:
                handle = kernel.CreateFileW(path, 0x80000000, 7, None, 3, 0x80, None)
                ok = handle != w.HANDLE(-1).value
                result = dict(ok=ok, error=0 if ok else c.get_last_error())
                if ok:
                    kernel.CloseHandle(handle)
            result['seconds'] = time.monotonic() - start
            print(json.dumps(result), flush=True)
    finally:
        kernel.VirtualFree(buffer, 0, 0x8000)
        kernel.CloseHandle(read_handle)


def child_owner():
    with Port() as owner:
        print(json.dumps(dict(pid=os.getpid(), handle=owner.handle.value)), flush=True)
        for line in sys.stdin:
            command = json.loads(line)
            if command.pop('exit', False):
                return
            print(json.dumps(fields(owner.send(**command))), flush=True)


def main():
    started, started_at = time.monotonic(), time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--cycles', type=int, default=12)
    parser.add_argument('--smoke', action='store_true')
    parser.add_argument('--read-only', action='store_true', help='focus on paired READ buffer/draining regression')
    args = parser.parse_args()
    assert 1 <= args.cycles <= 1000
    assert not (args.smoke and args.read_only)
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    checks, audits, children = [], [], []
    owned, completed, target = False, False, None
    fixture = ROOT / 'x64/Release' / (NAME + '.sys')
    fixture_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    path = output / 'target.tmp'
    path.write_bytes(b'P' * 4096)

    def journal(kind, **detail):
        with open(output / 'journal.jsonl', 'a', encoding='utf-8') as log:
            log.write(json.dumps(dict(time=time.time(), kind=kind, **detail)) + '\n')
            log.flush()
            os.fsync(log.fileno())

    def check(name, condition, **detail):
        checks.append(dict(name=name, passed=bool(condition), **detail))
        journal('check', **checks[-1])
        (output / 'checks.json').write_text(json.dumps(checks, indent=2), encoding='utf-8')
        print(name, 'PASS' if condition else 'FAIL', flush=True)
        assert condition, (name, detail)

    def run(*argv, expected=0):
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        with open(output / 'lifecycle.log', 'ab') as log:
            log.write((' '.join(argv) + '\n').encode() + result.stdout)
        if expected is not None:
            assert result.returncode == expected, (argv, result.returncode, result.stdout)
        return result

    def attach(lower=False):
        run('fltmc.exe', 'attach', NAME, 'C:', '-i', LOWER if lower else INSTANCE,
            '-a', '370029.12345' if lower else '370030.12345')

    def load():
        # A missing audit must never be hidden by a previous generation's value.
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE + '\\Parameters', 0, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, 'PendingIoFinalAudit')
            except FileNotFoundError:
                pass
        run('fltmc.exe', 'load', NAME)
        attach()
        with Port() as port:
            state = wait_state(port, lambda s: s.WorkerAlive == 1)
            check('fresh-load', balanced(state) and state.Created == state.OwnerPid == state.ArmedMode == 0,
                state=fields(state))

    def audit(name):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE + '\\Parameters') as key:
            raw, kind = winreg.QueryValueEx(key, 'PendingIoFinalAudit')
        assert kind == winreg.REG_BINARY and len(raw) == c.sizeof(Status)
        state = Status.from_buffer_copy(raw)
        audits.append(dict(name=name, **fields(state)))
        (output / 'unload-audits.json').write_text(json.dumps(audits, indent=2), encoding='utf-8')
        check(name + '-final-ledger', state.Magic == MAGIC and state.Version == 1 and
            state.Size == c.sizeof(Status) and balanced(state) and state.Stopping == 1 and
            state.WorkerAlive == state.LiveInstances == state.Connections == state.OwnerPid == state.ArmedMode == 0
            and state.InstanceStarts == state.InstanceCompletes, state=fields(state))

    def new_child(role):
        child = Child(role, *([path] if role == '--io-child' else []))
        children.append(child)
        return child

    def start(owner, observer, mode, phase='pre', delay=2000):
        before = observer.send()
        journal('arm', mode=mode, phase=phase, target_pid=target.proc.pid, before=fields(before))
        if isinstance(owner, Child):
            owner.send(action=1, mode=mode, pid=target.proc.pid, delay=delay)
            owner.receive()
        else:
            owner.send(1, mode, target.proc.pid, delay)
        target.send(read=mode in (4, 8))
        which = 'Post' if mode in (2, 6) else 'Pre'
        held = wait_state(observer, lambda s: getattr(s, which + 'Queued') == getattr(before, which + 'Queued') + 1
            and getattr(s, which + 'Completed') == getattr(before, which + 'Completed') and s.LiveContexts > 0)
        if mode == 3 and phase == 'post':
            resume(owner)
            held = wait_state(observer, lambda s: s.PostQueued == before.PostQueued + 1 and
                s.PostCompleted == before.PostCompleted)
        assert held.ActiveWorkers + held.QueueDepth > 0
        journal('held', mode=mode, phase=phase, held=fields(held))
        return before, held

    def resume(owner):
        if isinstance(owner, Child):
            owner.send(action=2)
            owner.receive()
        else:
            owner.send(2)

    def finish(observer, success=True, error=995):
        result = target.receive()
        assert result['ok'] == success and (success or result['error'] == error), result
        state = wait_state(observer, balanced)
        assert state.ArmedMode == 0
        return result, state

    def detach(instance=INSTANCE):
        journal('detach', instance=instance)
        with managed.driver_load_privilege():
            hr = flt.FilterDetach(NAME, 'C:', instance)
        assert hr >= 0, f'detach 0x{hr & 0xffffffff:08x}'

    def read_cases(observer, iterations):
        nonlocal target
        # Two owned instances hold a real noncached async READ below the upper
        # pre/post context, so FltMgr itself emits DRAINING. The lower pre must
        # lock the user buffer before dispatching it from the System worker.
        attach(lower=True)
        with Port() as owner:
            before = observer.send()
            owner.send(1, 8, target.proc.pid, 2000)
            target.send(read=True)
            result, state = finish(observer, success=False, error=1450)
            check('read-lock-failure-safe-completion', state.BufferLockFailures == before.BufferLockFailures + 1
                and state.PreQueued == before.PreQueued and state.Created == before.Created + 2
                and result['bytes'] == 0, state=fields(state), result=result)
        for iteration in range(iterations):
            with Port() as owner:
                before, held = start(owner, observer, 4)
                assert held.Created == before.Created + 2 and held.BufferLocks == before.BufferLocks + 1, fields(held)
                detach()
                drained = observer.send()
                check('real-draining-post-' + str(iteration), drained.PostDrained == before.PostDrained + 1
                    and drained.PreCompleted == before.PreCompleted and drained.LiveContexts == 1,
                    held=fields(held), drained=fields(drained))
                resume(owner)
                result, state = finish(observer)
                check('lower-read-completes-' + str(iteration), result['bytes'] == 4096 and balanced(state),
                    state=fields(state), result=result)
            attach()
        for force in (False, True):
            owner_child = new_child('--owner-child')
            before, held = start(owner_child, observer, 4)
            owner_child.close(force=force)
            result, state = finish(observer, success=False)
            check('read-owner-exit-' + str(force), state.OwnerPid == 0 and
                state.PreCancelled == before.PreCancelled + 1, held=fields(held), result=result)
        with Port() as owner:
            before, held = start(owner, observer, 4)
            target.close(force=True)
            state = wait_state(observer, balanced)
            check('read-requestor-force-exit', state.PreCancelled == before.PreCancelled + 1,
                held=fields(held), state=fields(state))
        target = new_child('--io-child')
        detach(LOWER)

    try:
        check('service-absent', run('sc.exe', 'query', NAME, expected=None).returncode == 1060)
        run('sc.exe', 'create', NAME, 'type=', 'filesys', 'start=', 'demand',
            'binPath=', str(fixture), 'depend=', 'FltMgr')
        owned = True
        for branch in ('Instances', 'Parameters\\Instances'):
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, SERVICE + '\\' + branch) as key:
                winreg.SetValueEx(key, 'DefaultInstance', 0, winreg.REG_SZ, INSTANCE)
            for instance, altitude in ((INSTANCE, '370030.12345'), (LOWER, '370029.12345')):
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, SERVICE + '\\' + branch + '\\' + instance) as key:
                    winreg.SetValueEx(key, 'Altitude', 0, winreg.REG_SZ, altitude)
                    winreg.SetValueEx(key, 'Flags', 0, winreg.REG_DWORD, 1)
        load()
        target = new_child('--io-child')
        if args.read_only:
            with Port() as observer:
                read_cases(observer, args.cycles)
            completed = True
            return
        with Port() as observer, Port() as owner:
            for mode in (1, 2, 3):
                for iteration in range(args.cycles):
                    before, held = start(owner, observer, mode)
                    resume(owner)
                    if mode == 3:
                        wait_state(observer, lambda s: s.PostQueued == before.PostQueued + 1 and
                            s.PostCompleted == before.PostCompleted)
                        resume(owner)
                    result, state = finish(observer)
                    check(f'resume-{mode}-{iteration}', state.Created == before.Created + 1,
                        held=fields(held), result=result)
            if not args.smoke:
                # Immediate downstream post may run inside the pre completion call.
                before = observer.send()
                for _ in range(args.cycles * 10):
                    owner.send(1, 3, target.proc.pid, 1)
                    target.send(read=False)
                    finish(observer)
                check('immediate-pre-post-tail', balanced(observer.send()), operations=args.cycles * 10,
                    before=fields(before), after=fields(observer.send()))
                for mode in (5, 6, 7):
                    before = observer.send()
                    owner.send(1, mode, target.proc.pid, 100)
                    target.send(read=False)
                    _, state = finish(observer)
                    check('injected-failure-' + str(mode), (state.AllocFailed == before.AllocFailed + 1 if mode == 7
                        else state.QueueFailed == before.QueueFailed + 1), state=fields(state))
                for mode in (1, 2, 3):
                    with managed.Port() as bodies:
                        before, held = start(owner, observer, mode)
                        paused = bodies.send(1, 3)
                        assert paused.ActivePre == paused.ActivePost == paused.EnabledMask == 0
                        resume(owner)
                        if mode == 3:
                            wait_state(observer, lambda s: s.PostQueued == before.PostQueued + 1)
                            resume(owner)
                        _, state = finish(observer)
                        bodies.send(2, 3)
                        check('context-cleanup-while-bodies-paused-' + str(mode), balanced(state), held=fields(held))
                for bad in (dict(Version=2), dict(Reserved=1), dict(Action=99), dict(Mode=1),
                            dict(Action=1, Mode=1, TargetPid=4, DelayMilliseconds=100),
                            dict(Action=1, Mode=1, TargetPid=target.proc.pid, DelayMilliseconds=2001)):
                    try:
                        owner.send(**bad)
                        raise AssertionError('accepted malformed command')
                    except OSError:
                        pass
                check('malformed-commands-rejected', balanced(observer.send()))
                before, _ = start(owner, observer, 1)
                for competitor in (owner, observer):
                    try:
                        competitor.send(1, 1, target.proc.pid, 100)
                        raise AssertionError('accepted overlapping arm')
                    except OSError:
                        pass
                thread = kernel.OpenThread(1, False, target.ready['tid'])
                assert thread
                try:
                    cancelled_at = time.monotonic()
                    assert kernel.CancelSynchronousIo(thread), c.get_last_error()
                finally:
                    kernel.CloseHandle(thread)
                result, state = finish(observer, success=False)
                cancellation_seconds = time.monotonic() - cancelled_at
                check('cancel-synchronous-pending-pre', state.PreCancelled == before.PreCancelled + 1 and
                    cancellation_seconds < 1, result=result, cancellation_seconds=cancellation_seconds,
                    before=fields(before), after=fields(state))
            owner.send(3)

        if not args.smoke:
            with Port() as observer:
                for force in (False, True):
                    for iteration in range(3):
                        for mode, phase in ((1, 'pre'), (2, 'post'), (3, 'pre'), (3, 'post')):
                            owner_child = new_child('--owner-child')
                            before, held = start(owner_child, observer, mode, phase)
                            owner_child.close(force=force)
                            result, state = finish(observer, success=phase == 'post')
                            check(f'owner-exit-{force}-{iteration}-{mode}-{phase}', state.OwnerPid == 0 and
                                state.OwnerRestores == before.OwnerRestores + 1, held=fields(held), result=result)
                owner_child = new_child('--owner-child')
                duplicate = w.HANDLE()
                assert kernel.DuplicateHandle(w.HANDLE(int(owner_child.proc._handle)),
                    w.HANDLE(owner_child.ready['handle']), w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                try:
                    before, _ = start(owner_child, observer, 1)
                    owner_child.close(force=True)
                    _, state = finish(observer, success=False)
                    check('owner-exit-with-duplicated-port', state.OwnerPid == 0 and
                        state.OwnerRestores == before.OwnerRestores + 1)
                finally:
                    kernel.CloseHandle(duplicate)
                for mode in (1, 2):
                    with Port() as owner:
                        before, held = start(owner, observer, mode)
                        target.close(force=True)
                        state = wait_state(observer, balanced)
                        check('requestor-force-exit-' + str(mode), balanced(state), held=fields(held), state=fields(state))
                    target = new_child('--io-child')
                for mode in (1, 2):
                    with Port() as owner:
                        before, held = start(owner, observer, mode)
                        detach()
                        result, state = finish(observer, success=mode == 2)
                        check('detach-pending-' + str(mode), state.InstanceStarts == before.InstanceStarts + 1
                            and state.InstanceCompletes == before.InstanceCompletes + 1, result=result, held=fields(held))
                    attach()
                read_cases(observer, 3)

            for method in ('direct', 'service'):
                for iteration in range(3):
                    for mode, phase in ((1, 'pre'), (2, 'post'), (3, 'post'), (4, 'pre')):
                        if mode == 4:
                            attach(lower=True)
                        with Port() as observer, Port() as owner:
                            before, held = start(owner, observer, mode, phase)
                            began = time.monotonic()
                            if method == 'direct':
                                with managed.driver_load_privilege():
                                    hr = flt.FilterUnload(NAME)
                                assert hr >= 0, f'unload 0x{hr & 0xffffffff:08x}'
                            else:
                                run('sc.exe', 'stop', NAME)
                            result = target.receive()
                            assert result['ok'] == (phase == 'post'), result
                            label = f'{method}-unload-{iteration}-{mode}-{phase}'
                            check(label, time.monotonic() - began < 10, held=fields(held), result=result)
                            try:
                                owner.send()
                                raise AssertionError('unloaded port still responds')
                            except OSError:
                                pass
                        audit(label)
                        load()
        completed = True
    finally:
        cleanup_errors = []
        for child in reversed(children):
            try:
                child.close(force=True)
            except BaseException:
                cleanup_errors.append(traceback.format_exc())
        if owned:
            try:
                result = run('fltmc.exe', 'unload', NAME, expected=None)
                assert NAME.encode() not in run('fltmc.exe', 'filters').stdout, result.stdout
                audit('cleanup')
                run('sc.exe', 'delete', NAME)
                check('fixture-removed', run('sc.exe', 'query', NAME, expected=None).returncode == 1060)
            except BaseException:
                cleanup_errors.append(traceback.format_exc())
        (output / 'result.json').write_text(json.dumps(dict(
            passed=completed and not cleanup_errors and all(x['passed'] for x in checks),
            checks=len(checks), cycles=args.cycles, smoke=args.smoke, read_only=args.read_only, fixture_sha256=fixture_hash,
            started_at=started_at, seconds=time.monotonic() - started,
            cleanup_errors=cleanup_errors), indent=2), encoding='utf-8')
        if cleanup_errors:
            raise RuntimeError(cleanup_errors)


if __name__ == '__main__':
    try:
        if sys.argv[1:2] == ['--io-child']:
            child_io(sys.argv[2])
        elif sys.argv[1:2] == ['--owner-child']:
            child_owner()
        else:
            main()
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
