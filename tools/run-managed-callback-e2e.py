"""Elevated Windows E2E for the cooperative, harmless CREATE test provider.

Usage: python tools/run-managed-callback-e2e.py --output .build/managed-callback/run1
Requires a built/test-signed Release tree. Refuses pre-existing fixture services.
Never loads or modifies another filter, security policy, or callback pointer.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import traceback
import winreg

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAME = 'KnLiveDbgMiniFilterFixture'
INSTANCE = NAME + '.Instance'
PORT = '\\' + NAME + 'Control'
EXE = ROOT / 'x64/Release/KnLiveDbg.exe'
MAGIC = 0x4B4D4342
flt = c.WinDLL('fltlib.dll')
kernel = c.WinDLL('kernel32.dll', use_last_error=True)
flt.FilterConnectCommunicationPort.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p, w.WORD, c.c_void_p, c.POINTER(w.HANDLE)]
flt.FilterConnectCommunicationPort.restype = c.c_long
flt.FilterSendMessage.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
flt.FilterSendMessage.restype = c.c_long
kernel.CloseHandle.argtypes = [w.HANDLE]
kernel.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
kernel.VirtualAlloc.argtypes = [c.c_void_p, c.c_size_t, w.DWORD, w.DWORD]
kernel.VirtualAlloc.restype = c.c_void_p
kernel.VirtualProtect.argtypes = [c.c_void_p, c.c_size_t, w.DWORD, c.POINTER(w.DWORD)]
kernel.VirtualFree.argtypes = [c.c_void_p, c.c_size_t, w.DWORD]


class Request(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('Magic', 'Version', 'Size', 'Action', 'Mask',
        'HoldMilliseconds', 'HoldProcessId', 'Reserved')] + [('ExpectedFilter', c.c_uint64)]


class Status(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('Magic', 'Version', 'Size', 'SupportedMask',
        'EnabledMask', 'PreviousEnabledMask', 'DrainingMask', 'Stopping', 'OwnerPid',
        'Connections', 'ActivePre', 'ActivePost')] + [(n, c.c_uint64) for n in (
        'OwnerConnection', 'Filter', 'Generation', 'AutomaticRestores', 'PreEntered',
        'PostEntered', 'PreSkipped', 'PostSkipped', 'HoldEntered', 'HoldCompleted')]


assert c.sizeof(Request) == 40 and c.sizeof(Status) == 128


class Port:
    def __init__(self):
        self.handle = w.HANDLE()
        hr = flt.FilterConnectCommunicationPort(PORT, 0, None, 0, None, c.byref(self.handle))
        if hr < 0:
            raise OSError(f'connect: 0x{hr & 0xffffffff:08x}')
        self.identity = self.send().Filter

    def send(self, action=0, mask=0, hold_ms=0, hold_pid=0, **overrides):
        request = Request(MAGIC, 1, c.sizeof(Request), action, mask, hold_ms, hold_pid,
                          0, getattr(self, 'identity', 0))
        for name, value in overrides.items():
            setattr(request, name, value)
        response, returned = Status(), w.DWORD()
        hr = flt.FilterSendMessage(self.handle, c.byref(request), c.sizeof(request),
                                  c.byref(response), c.sizeof(response), c.byref(returned))
        if hr < 0:
            raise OSError(f'message: 0x{hr & 0xffffffff:08x}')
        assert returned.value == 128 and response.Magic == MAGIC and response.Version == 1
        return response

    def close(self):
        if self.handle.value:
            kernel.CloseHandle(self.handle)
            self.handle = w.HANDLE()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Native:
    def __init__(self, output, name):
        self.path = output / name
        self.path.mkdir()
        self.log = open(self.path / 'console.log', 'wb')
        self.proc = subprocess.Popen([str(EXE)], stdin=subprocess.PIPE, stdout=self.log,
            stderr=subprocess.STDOUT, cwd=EXE.parent, creationflags=subprocess.CREATE_NO_WINDOW)
        self.offset = 0
        self.prompt()

    def prompt(self, timeout=120):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            data = (self.path / 'console.log').read_bytes()[self.offset:]
            if data.endswith(b'knkd> '):
                self.offset += len(data)
                return data.decode('utf-8', errors='replace')
            if self.proc.poll() is not None:
                raise RuntimeError(f'controller exited: {data[-1000:]!r}')
            time.sleep(.03)
        raise TimeoutError(f'controller prompt: {self.path}')

    def command(self, line):
        self.proc.stdin.write((line + '\n').encode())
        self.proc.stdin.flush()
        return self.prompt()

    def json_command(self, line, name):
        path = self.path / (name + '.json')
        self.command(line + f' /json "{path}"')
        return json.loads(path.read_text(encoding='utf-8-sig'))

    def close(self, force=False):
        if self.proc.poll() is None:
            if force:
                self.proc.terminate()
            else:
                self.proc.stdin.write(b'exit\n')
                self.proc.stdin.flush()
            self.proc.wait(30)
        self.log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--cycles', default=100, type=int)
    parser.add_argument('--close-race-executable', type=pathlib.Path)
    args = parser.parse_args()
    if not 1 <= args.cycles <= 1000:
        raise ValueError('cycles must be between 1 and 1000')
    if not c.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('run elevated')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    checks = []
    owned = False
    native = None
    completed = False
    io_stop = threading.Event()
    io_errors, io_counts, workers = [], [0] * 4, []

    def check(name, value, **detail):
        checks.append(dict(name=name, passed=bool(value), **detail))
        (output / 'checks.json').write_text(json.dumps(checks, indent=2), encoding='utf-8')
        print(name, 'PASS' if value else 'FAIL', flush=True)
        assert value, (name, detail)

    def run(*argv, expected=0):
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
        with open(output / 'lifecycle.log', 'ab') as log:
            log.write((' '.join(argv) + '\n').encode() + result.stdout)
        if expected is not None:
            assert result.returncode == expected, (argv, result.returncode, result.stdout)
        return result

    def load():
        run('fltmc.exe', 'load', NAME)
        run('fltmc.exe', 'attach', NAME, 'C:', '-i', INSTANCE, '-a', '370030.12345')

    def io(count=20):
        path = output / ('io-' + str(threading.get_ident()) + '.tmp')
        for _ in range(count):
            path.write_bytes(b'cooperative-callback-fixture\n')
            assert path.read_bytes() == b'cooperative-callback-fixture\n'
            path.unlink()

    def background_io(index):
        try:
            while not io_stop.is_set():
                io(1)
                io_counts[index] += 1
        except BaseException:
            io_errors.append(traceback.format_exc())

    def wait_default(observer):
        until = time.monotonic() + 10
        while time.monotonic() < until:
            state = observer.send()
            if state.EnabledMask == 3 and state.OwnerPid == 0 and state.DrainingMask == 0:
                return state
            time.sleep(.01)
        raise TimeoutError('kernel did not release control lease')

    def hold_body(owner, observer, bit, milliseconds=500):
        before = observer.send()
        owner.send(4, bit, milliseconds, os.getpid())
        until = time.monotonic() + 5
        while time.monotonic() < until:
            state = observer.send()
            if state.HoldEntered == before.HoldEntered + 1 and state.HoldCompleted == before.HoldCompleted:
                assert getattr(state, 'ActivePre' if bit == 1 else 'ActivePost') > 0
                return state
            time.sleep(.001)
        raise TimeoutError('real callback hold was not observed')

    def cleanup_main():
        path = r'SYSTEM\CurrentControlSet\Services\KnLiveDbg'
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                image = winreg.QueryValueEx(key, 'ImagePath')[0]
        except FileNotFoundError:
            return
        assert pathlib.Path(image.removeprefix('\\??\\').strip('"')).resolve() == (EXE.parent / 'KnLiveDbg.sys').resolve()
        stopped = run('sc.exe', 'stop', 'KnLiveDbg', expected=None)
        assert stopped.returncode in (0, 1062)
        run('sc.exe', 'delete', 'KnLiveDbg')

    try:
        check('fixture-service-absent', run('sc.exe', 'query', NAME, expected=None).returncode == 1060)
        check('controller-service-absent', run('sc.exe', 'query', 'KnLiveDbg', expected=None).returncode == 1060)
        run('sc.exe', 'create', NAME, 'type=', 'filesys', 'start=', 'demand',
            'binPath=', str(EXE.parent / (NAME + '.sys')), 'depend=', 'FltMgr')
        owned = True
        service_key = 'SYSTEM\\CurrentControlSet\\Services\\' + NAME
        for branch in ('Instances', 'Parameters\\Instances'):
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, service_key + '\\' + branch) as key:
                winreg.SetValueEx(key, 'DefaultInstance', 0, winreg.REG_SZ, INSTANCE)
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, service_key + '\\' + branch + '\\' + INSTANCE) as key:
                winreg.SetValueEx(key, 'Altitude', 0, winreg.REG_SZ, '370030.12345')
                winreg.SetValueEx(key, 'Flags', 0, winreg.REG_DWORD, 1)
        load()
        with Port() as observer:
            initial = observer.send()
            io()
            current = observer.send()
            check('real-pre-post-callbacks', current.PreEntered > initial.PreEntered and current.PostEntered > initial.PostEntered)
            if args.close_race_executable:
                run(str(args.close_race_executable.resolve()))
                check('concurrent-device-close', observer.send().OwnerPid == 0 and observer.send().Connections == 1)
            for index in range(4):
                worker = threading.Thread(target=background_io, args=(index,), daemon=True)
                workers.append(worker)
                worker.start()
            with Port() as owner:
                before = owner.send(1, 3)
                io()
                after = observer.send()
                check('paused-bodies-no-new-entry', after.EnabledMask == 0 and after.ActivePre == after.ActivePost == 0 and
                      after.PreEntered == before.PreEntered and after.PostEntered == before.PostEntered and
                      after.PreSkipped > before.PreSkipped and after.PostSkipped > before.PostSkipped)
                for changes in (dict(Version=2), dict(Mask=4), dict(Reserved=1), dict(ExpectedFilter=1)):
                    try:
                        owner.send(1, 3, **changes) if 'Mask' not in changes else owner.send(1, **changes)
                        raise AssertionError('malformed request accepted')
                    except OSError:
                        pass
                check('malformed-requests-leave-owner-state', observer.send().EnabledMask == 0)
                try:
                    observer.send(2, 3)
                    raise AssertionError('second controller stole lease')
                except OSError:
                    pass
                check('second-owner-rejected', observer.send().EnabledMask == 0)
                run('fltmc.exe', 'detach', NAME, 'C:', INSTANCE)
                run('fltmc.exe', 'attach', NAME, 'C:', '-i', INSTANCE, '-a', '370030.12345')
                io()
                attached = observer.send()
                check('new-instance-inherits-pause', attached.EnabledMask == 0 and
                      attached.PreEntered == before.PreEntered and attached.PostEntered == before.PostEntered)
                query_stop, query_started = threading.Event(), threading.Event()
                query_results = dict(count=0, errors=[])
                def concurrent_query():
                    try:
                        while not query_stop.is_set():
                            state = observer.send()
                            query_results['count'] += 1
                            assert state.PreviousEnabledMask == state.EnabledMask
                            query_started.set()
                    except BaseException:
                        query_results['errors'].append(traceback.format_exc())
                        query_started.set()
                query_thread = threading.Thread(target=concurrent_query, daemon=True)
                query_thread.start()
                try:
                    assert query_started.wait(5)
                    for _ in range(args.cycles):
                        for bit in (1, 2, 3):
                            owner.send(2, 3)
                            state = owner.send(1, bit)
                            assert state.EnabledMask == 3 & ~bit
                            assert (not bit & 1 or state.ActivePre == 0) and (not bit & 2 or state.ActivePost == 0)
                finally:
                    query_stop.set()
                    query_thread.join(10)
                check('concurrent-query-consistent-snapshot', not query_thread.is_alive() and
                      query_results['count'] > 0 and not query_results['errors'], **query_results)
                check('repeated-transitions', True, cycles=args.cycles, transitions=args.cycles * 6)
                owner.send(2, 3)
                for bit, active in ((1, 'ActivePre'), (2, 'ActivePost')):
                    held = hold_body(owner, observer, bit, 400)
                    check('inflight-observed-' + str(bit), getattr(held, active) > 0)
                    start = time.monotonic()
                    state = owner.send(1, bit)
                    duration = time.monotonic() - start
                    check('rundown-waits-' + str(bit), duration > .1 and
                          getattr(state, active) == 0 and state.HoldCompleted == held.HoldEntered,
                          seconds=round(duration, 3))
                    owner.send(2, 3)
                # Revoke a reply buffer after ProbeForWrite but while disable
                # waits for a held body. The failed reply must release the lease.
                hold_body(owner, observer, 1)
                buffer = kernel.VirtualAlloc(None, 4096, 0x3000, 4)
                assert buffer
                reply = {}
                request = Request(MAGIC, 1, 40, 1, 1, 0, 0, 0, owner.identity)
                def lost_reply():
                    returned = w.DWORD()
                    reply['hr'] = flt.FilterSendMessage(owner.handle, c.byref(request), 40,
                        buffer, 128, c.byref(returned))
                sender = threading.Thread(target=lost_reply)
                sender.start()
                until = time.monotonic() + 5
                while time.monotonic() < until and not observer.send().DrainingMask & 1:
                    time.sleep(.001)
                assert observer.send().DrainingMask & 1
                old = w.DWORD()
                assert kernel.VirtualProtect(buffer, 4096, 1, c.byref(old))
                sender.join(10)
                assert not sender.is_alive()
                assert kernel.VirtualProtect(buffer, 4096, 4, c.byref(old))
                assert kernel.VirtualFree(buffer, 0, 0x8000)
                state = wait_default(observer)
                check('lost-reply-restores-defaults', reply['hr'] < 0 and state.OwnerPid == 0)
                owner.send(1, 3)
            check('port-close-restores-defaults', wait_default(observer).AutomaticRestores > initial.AutomaticRestores)

            child = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), '--lease-child'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW)
            duplicate = w.HANDLE()
            try:
                info = json.loads(child.stdout.readline())
                check('duplicate-handle-owner-active', observer.send().OwnerPid == child.pid)
                assert kernel.DuplicateHandle(w.HANDLE(int(child._handle)), w.HANDLE(info['handle']),
                    w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                before = observer.send()
                child.terminate()
                child.wait(10)
                restored = wait_default(observer)
                check('process-exit-with-duplicated-handle', restored.AutomaticRestores == before.AutomaticRestores + 1 and
                      restored.Connections == before.Connections)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(10)
                if duplicate.value:
                    kernel.CloseHandle(duplicate)

            child = subprocess.Popen([sys.executable, str(pathlib.Path(__file__).resolve()), '--lease-child'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                json.loads(child.stdout.readline())
                def child_request(action, mask, **more):
                    child.stdin.write((json.dumps(dict(action=action, mask=mask, **more)) + '\n').encode())
                    child.stdin.flush()
                child_request(2, 3)
                json.loads(child.stdout.readline())
                before = observer.send()
                child_request(4, 1, hold_ms=500, hold_pid=os.getpid())
                json.loads(child.stdout.readline())
                until = time.monotonic() + 5
                while time.monotonic() < until and observer.send().HoldEntered == before.HoldEntered:
                    time.sleep(.001)
                child_request(1, 1)
                until = time.monotonic() + 5
                while time.monotonic() < until and not observer.send().DrainingMask & 1:
                    time.sleep(.001)
                check('forced-exit-transition-observed', observer.send().DrainingMask & 1)
                child.terminate()
                child.wait(10)
                check('forced-exit-during-rundown', wait_default(observer).OwnerPid == 0)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(10)

            for force in (False, True):
                for iteration in range(3):
                    tag = ('forced' if force else 'normal') + '-' + str(iteration)
                    native = Native(output, tag)
                    native.command('write on')
                    if not force and iteration == 0:
                        for selector, expected in (('pre', 2), ('post', 1)):
                            changed = native.json_command('!minifilter disable ' + NAME + ' CREATE /' + selector, selector)
                            check('native-' + selector + '-only', changed['managed']['enabledMask'] == expected and
                                  not changed['preChanged'] and not changed['postChanged'] and
                                  changed['managed'][selector + 'BodyChanged'])
                            native.command('!minifilter enable-all ' + NAME)
                        changed = native.json_command('!fltmgr disable ' + NAME + ' all /both', 'fltmgr')
                        check('native-fltmgr-alias', changed['changes'][0]['managed']['enabledMask'] == 0)
                        native.command('!minifilter enable-all ' + NAME)
                    baseline = native.json_command('!minifilter show ' + NAME, 'before')['filters']
                    baseline = next(x for x in baseline if x['name'] == NAME)
                    state = native.json_command('!minifilter disable ' + NAME + ' CREATE /both', 'disable')
                    check(tag + '-disabled', state['managed']['enabledMask'] == 0 and state['managed']['ownerPid'] == native.proc.pid)
                    after = native.json_command('!minifilter show ' + NAME, 'after')['filters']
                    after = next(x for x in after if x['name'] == NAME)
                    check(tag + '-registered-pointers-unchanged', baseline['slots'] == after['slots'] and
                          baseline['liveCallbackCount'] == after['liveCallbackCount'])
                    if not force:
                        native.command('!callbacks enable-all ' + NAME + '.sys')
                        check(tag + '-callback-alias-enable', observer.send().EnabledMask == 3)
                        native.command('!callbacks disable minifilter ' + NAME)
                        check(tag + '-callback-alias-disable', observer.send().EnabledMask == 0)
                        refusal = native.command('!callbacks disable object ' + NAME)
                        check(tag + '-unsupported-scope-refused', 'callback mutation is unavailable' in refusal and observer.send().EnabledMask == 0)
                    native.close(force=force)
                    native = None
                    restored = wait_default(observer)
                    io()
                    check(tag + '-kernel-restored', observer.send().PreEntered > restored.PreEntered)
                    if force:
                        cleanup_main()

            native = Native(output, 'explicit-controller-unload')
            native.command('write on')
            native.command('!minifilter disable-all ' + NAME)
            check('controller-unload-paused', observer.send().EnabledMask == 0)
            native.proc.stdin.write(b'unload\n')
            native.proc.stdin.flush()
            native.proc.wait(30)
            native.close()
            native = None
            check('controller-unload-restores', wait_default(observer).OwnerPid == 0 and
                  run('sc.exe', 'query', 'KnLiveDbg', expected=None).returncode == 1060)

        # Keep owner/observer handles open while unloading the provider. No
        # pointer in FltMgr is owned by the debugger driver or controller.
        for mode in ('fltmc', 'service'):
            for iteration in range(3):
                with Port() as owner:
                    # Alternate a paused provider with a real in-flight pre or
                    # post body. Background I/O continues through every unload.
                    if iteration == 0:
                        owner.send(1, 3)
                    else:
                        bit = iteration
                        with Port() as observer:
                            held = hold_body(owner, observer, bit)
                            check(f'{mode}-unload-inflight-{bit}', getattr(held, 'ActivePre' if bit == 1 else 'ActivePost') > 0)
                    if mode == 'fltmc':
                        run('fltmc.exe', 'unload', NAME)
                    else:
                        run('sc.exe', 'stop', NAME)
                    try:
                        owner.send()
                        raise AssertionError('unloaded provider still responds')
                    except OSError:
                        pass
                io()
                check(f'{mode}-unload-{iteration}', NAME.encode() not in run('fltmc.exe', 'filters').stdout)
                load()
                with Port() as observer:
                    check(f'{mode}-reload-{iteration}', observer.send().EnabledMask == 3 and observer.send().OwnerPid == 0)
        io_stop.set()
        for worker in workers:
            worker.join(10)
        check('concurrent-io-clean', not io_errors and all(not worker.is_alive() for worker in workers),
              cycles=io_counts, errors=io_errors)
        check('all-scenarios', True)
        completed = True
    finally:
        io_stop.set()
        for worker in workers:
            worker.join(10)
        if native is not None:
            native.close(force=True)
            cleanup_main()
        if owned:
            result = run('fltmc.exe', 'unload', NAME, expected=None)
            run('sc.exe', 'delete', NAME)
            check('fixture-cleanup', run('sc.exe', 'query', NAME, expected=None).returncode == 1060 and
                  NAME.encode() not in run('fltmc.exe', 'filters').stdout)
        (output / 'result.json').write_text(json.dumps(dict(passed=completed and all(x['passed'] for x in checks),
            checks=len(checks), exe_sha256=__import__('hashlib').sha256(EXE.read_bytes()).hexdigest()), indent=2))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--lease-child']:
            with Port() as owner:
                owner.send(1, 3)
                print(json.dumps(dict(handle=owner.handle.value)), flush=True)
                for line in sys.stdin:
                    state = owner.send(**json.loads(line))
                    print(json.dumps(dict(enabled=state.EnabledMask)), flush=True)
        else:
            main()
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
