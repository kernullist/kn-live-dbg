"""Measure real Toolhelp observations against the lifetimes of owned Windows processes."""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes as c
from ctypes import wintypes as w
import json
import msvcrt
import os
from pathlib import Path
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import uuid


SCHEMA = 'kn.owned_module_workload.v1'
ROUNDS = 16
CADENCE_MS = 25
k = c.WinDLL('kernel32', use_last_error=True)


def api(name, result, *args):
    fn = getattr(k, name)
    fn.argtypes, fn.restype = args, result
    return fn


tick = api('GetTickCount64', c.c_uint64)
performance_counter = api('QueryPerformanceCounter', w.BOOL, c.POINTER(c.c_int64))
performance_frequency = api('QueryPerformanceFrequency', w.BOOL, c.POINTER(c.c_int64))
self_handle = api('GetCurrentProcess', w.HANDLE)
peer_pid = api('GetProcessId', w.DWORD, w.HANDLE)
module_base = api('GetModuleHandleW', w.HMODULE, w.LPCWSTR)
create_job = api('CreateJobObjectW', w.HANDLE, c.c_void_p, w.LPCWSTR)
set_job = api('SetInformationJobObject', w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD)
query_job = api('QueryInformationJobObject', w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p)
assign_job = api('AssignProcessToJobObject', w.BOOL, w.HANDLE, w.HANDLE)
terminate_job = api('TerminateJobObject', w.BOOL, w.HANDLE, w.UINT)
close_handle = api('CloseHandle', w.BOOL, w.HANDLE)
duplicate = api('DuplicateHandle', w.BOOL, w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD)
open_process = api('OpenProcess', w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
wait = api('WaitForSingleObject', w.DWORD, w.HANDLE, w.DWORD)
process_exit = api('GetExitCodeProcess', w.BOOL, w.HANDLE, c.POINTER(w.DWORD))
process_times = api('GetProcessTimes', w.BOOL, w.HANDLE, *(c.POINTER(w.FILETIME),) * 4)
open_file = api('CreateFileW', w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE)
file_info = api('GetFileInformationByHandleEx', w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD)
process_image = api('QueryFullProcessImageNameW', w.BOOL, w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD))


def native(result):
    if not result:
        raise c.WinError(c.get_last_error())
    return result


def require(ok, why):
    if not ok:
        raise AssertionError(why)


def creation(handle):
    times = [w.FILETIME() for _ in range(4)]
    native(process_times(handle, *(c.byref(v) for v in times)))
    return times[0].dwHighDateTime << 32 | times[0].dwLowDateTime


class BasicLimits(c.Structure):
    _fields_ = [('process_time', c.c_int64), ('job_time', c.c_int64), ('flags', w.DWORD),
                ('min_ws', c.c_size_t), ('max_ws', c.c_size_t), ('active_limit', w.DWORD),
                ('affinity', c.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]


class ExtendedLimits(c.Structure):
    _fields_ = [('basic', BasicLimits), ('io', c.c_uint64 * 6), ('memory', c.c_size_t * 4)]


class ProcessMemory(c.Structure):
    _fields_ = [('cb', w.DWORD), ('page_faults', w.DWORD),
                ('peak_working_set', c.c_size_t), ('working_set', c.c_size_t),
                ('other_memory', c.c_size_t * 6)]


process_io = api('GetProcessIoCounters', w.BOOL, w.HANDLE, c.POINTER(c.c_uint64 * 6))
process_memory = api('K32GetProcessMemoryInfo', w.BOOL, w.HANDLE, c.POINTER(ProcessMemory), w.DWORD)


def performance_value(query):
    value = c.c_int64()
    native(query(c.byref(value)))
    return value.value


def collector_sample(handle):
    from owned_module_benchmark import IO_FIELDS
    begin_ms, begin_qpc = tick(), performance_value(performance_counter)
    times = [w.FILETIME() for _ in range(4)]
    native(process_times(handle, *(c.byref(v) for v in times)))
    created, _, kernel, user = [(t.dwHighDateTime << 32) | t.dwLowDateTime for t in times]
    pid = native(peer_pid(handle))
    io = (c.c_uint64 * 6)()
    io_error = None if process_io(handle, c.byref(io)) else c.get_last_error()
    memory = ProcessMemory()
    memory.cb = c.sizeof(memory)
    memory_error = None if process_memory(handle, c.byref(memory), memory.cb) else c.get_last_error()
    end_qpc, end_ms = performance_value(performance_counter), tick()
    return dict(process=[pid, str(created)], begin_ms=begin_ms, end_ms=end_ms,
                begin_qpc=str(begin_qpc), end_qpc=str(end_qpc), kernel_100ns=str(kernel), user_100ns=str(user),
                io_error=io_error, io=dict(zip(IO_FIELDS, map(str, io))) if io_error is None else None,
                memory_error=memory_error, working_set_bytes=str(memory.working_set) if memory_error is None else None)


class Accounting(c.Structure):
    _fields_ = [('times', c.c_int64 * 4), ('faults', w.DWORD), ('total', w.DWORD), ('active', w.DWORD), ('terminated', w.DWORD)]


class JobUsage(c.Structure):
    _fields_ = [('basic', Accounting), ('io', c.c_uint64 * 6)]


@contextmanager
def leased_file(path):
    # Deny write/delete sharing while image names are resolved and the children run.
    handle = open_file(str(path), 0x80000000, 1, None, 3, 0, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        close_handle(handle)
        raise
    with os.fdopen(fd, 'rb') as stream:
        info = (c.c_ubyte * 24)()  # FILE_ID_INFO: volume serial and 128-bit file ID.
        native(file_info(handle, 18, c.byref(info), c.sizeof(info)))
        yield stream, bytes(info).hex()


class BenchmarkCapture:
    def __init__(self, stack, exe, ticket=None, paired_costs=False):
        from owned_module_benchmark import LIMITS
        self.run_id = ticket or uuid.uuid4().hex
        self.parts, self.file_ids, self.worlds = {}, {}, []
        self.owner_loss = None
        self.paired_costs = paired_costs
        self.qpc_hz = performance_value(performance_frequency) if paired_costs else None
        self.measured_requests = {'inventory': 0, 'dispatch': 0}
        for name, path in [('collector.bin', exe), ('target.bin', sys.executable), ('controller.py', __file__)]:
            stream, self.file_ids[name] = stack.enter_context(leased_file(path))
            data = stream.read(LIMITS[name] + 1)
            require(0 < len(data) <= LIMITS[name], 'leased input exceeds capture bound')
            self.parts[name] = data

    def image_id(self, handle, name):
        path = c.create_unicode_buffer(32768)
        size = w.DWORD(len(path))
        native(process_image(handle, 0, path, c.byref(size)))
        with leased_file(path.value) as (_, identifier):
            require(identifier == self.file_ids[name], 'running process image differs from the retained file')
            return identifier

    def begin(self, name):
        self.worlds.append(dict(name=name, events=[]))
        self.parts[name + '.jsonl'] = bytearray()
        return self.parts[name + '.jsonl']

    def event(self, kind, **values):
        self.worlds[-1]['events'].append(dict(kind=kind, **values))

    def request(self, peer, kind):
        from owned_module_benchmark import arm_order
        arms = []
        if self.paired_costs and self.worlds[-1]['name'] == 'fixed':
            ordinal = self.measured_requests[kind]
            self.measured_requests[kind] += 1
            for mode in arm_order(self.run_id, kind, ordinal):
                before = collector_sample(int(peer.proc._handle))
                reply = peer.request(kind if mode == 'observe' else 'idle', measured=True)
                after = collector_sample(int(peer.proc._handle))
                arms.append(dict(mode=mode, before=before, start=reply['controller_start'],
                                 end=reply['controller_end'], after=after))
                if mode == 'observe':
                    source = reply
        else:
            source = peer.request(kind)
        event = dict(start=source['controller_start'], end=source['controller_end'])
        if arms:
            event['arms'] = arms
        self.event(kind, **event)
        return source

    def publish(self, destination):
        from owned_module_benchmark import PAIRED_SCHEMA, encoded, write_bundle
        self.parts['truth.json'] = encoded(dict(schema='kn.owned_module_truth.v2' if self.paired_costs else 'kn.owned_module_truth.v1', run_id=self.run_id,
                                                worlds=self.worlds, owner_loss=self.owner_loss))
        machine = platform.machine().lower()
        arch = {'amd64': 'amd64', 'arm64': 'arm64', 'x86': 'x86'}.get(machine, 'unknown')
        manifest = dict(schema=PAIRED_SCHEMA if self.paired_costs else 'kn.owned_module_benchmark.v1', run_id=self.run_id, clock='GetTickCount64_ms',
                        rounds=ROUNDS, cadence_ms=CADENCE_MS, collector_file_id=self.file_ids['collector.bin'],
                        target_file_id=self.file_ids['target.bin'],
                        environment=dict(os_build=str(sys.getwindowsversion().build), architecture=arch))
        if self.paired_costs:
            manifest["qpc_hz"] = str(self.qpc_hz)
        return write_bundle(destination, manifest, self.parts)


@contextmanager
def owned_job():
    handle = native(create_job(None, None))
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        native(set_job(handle, 9, c.byref(limits), c.sizeof(limits)))
        yield handle
    finally:
        native(close_handle(handle))


class Peer:
    """Each peer has one private stdin writer. EOF releases it if its parent exits."""

    def __init__(self, argv, startupinfo=None, transcript=None):
        # A detached interpreter uses its pipes without adding a console host
        # to the job's independently enumerated population.
        self.transcript = transcript
        self.transcript_overflow = False
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True, startupinfo=startupinfo,
                                     creationflags=subprocess.DETACHED_PROCESS)
        self.lines = queue.Queue()
        self.closed = False
        self.reader = threading.Thread(target=self.pump, daemon=True)
        try:
            self.reader.start()
        except RuntimeError:
            self.proc.stdin.close()
            self.proc.kill()
            self.proc.wait(timeout=10)
            self.proc.stdout.close()
            self.proc._handle.Close()
            raise

    def pump(self):
        try:
            while line := self.proc.stdout.readline(4 * 1024 * 1024 + 1):
                if self.transcript is not None:
                    if len(self.transcript) + len(line) > 4 * 1024 * 1024:
                        self.transcript_overflow = True
                        break
                    self.transcript.extend(line)
                self.lines.put(line)
            if self.transcript_overflow:
                self.lines.put(None)
                while self.proc.stdout.read(64 * 1024):
                    pass
        finally:
            self.lines.put(None)

    def receive(self, kind):
        line = self.lines.get(timeout=30)
        require(line is not None, f'{kind}: peer exited before acknowledgement')
        wire = json.loads(line.decode('utf-8'))
        require(wire['schema'] == SCHEMA, 'private workload evidence schema')
        data = wire['payload']
        require(data.get('kind') == kind, f'expected {kind} acknowledgement')
        return data

    def request(self, kind, measured=False):
        command = ('timed ' if measured else '') + kind
        start = tick()
        self.proc.stdin.write((command + '\n').encode('ascii'))
        self.proc.stdin.flush()
        row = self.receive(kind)
        row['controller_start'], row['controller_end'] = start, tick()
        return row

    def close(self):
        if self.closed:
            return self.proc.returncode
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            code = self.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)
            raise
        finally:
            self.reader.join(timeout=5)
            self.proc.stdout.close()
            self.proc._handle.Close()
            self.closed = True
        require(not self.reader.is_alive() and not self.transcript_overflow, 'incomplete or oversized peer output')
        return code


def collector(stack, exe, job, transcript=None):
    query = w.HANDLE()
    # The endpoint can query membership. Only the independent controller can
    # assign processes or change job limits.
    native(duplicate(self_handle(), job, self_handle(), c.byref(query), 0x0004, True, 0))
    try:
        startup = subprocess.STARTUPINFO(lpAttributeList={'handle_list': [query.value]})
        peer = Peer([str(exe), '--owned-user-module-workload', str(query.value)], startup, transcript)
        stack.callback(peer.close)
    finally:
        native(close_handle(query))
    peer.receive('ready')
    return peer


def announce(payload):
    print(json.dumps(dict(schema=SCHEMA, payload=payload)), flush=True)


def child():
    announce(dict(kind='ready', pid=os.getpid(), generation=str(creation(self_handle())),
                  base=native(module_base(None)), ready=tick()))
    sys.stdin.buffer.read()  # The controller closes its writer to end this lifetime.
    announce(dict(kind='exit', tick=tick()))


class Population:
    def __init__(self, stack, job, capture=None):
        self.stack, self.job = stack, job
        self.capture = capture
        self.children = {}
        self.rows = {}

    def start(self, role, member=True):
        launched = tick()
        peer = Peer([sys.executable, str(Path(__file__).resolve()), '--child'])
        self.stack.callback(peer.close)
        if member:
            native(assign_job(self.job, int(peer.proc._handle)))
        row = peer.receive('ready')
        key = row['pid'], row['generation']
        parent = native(peer_pid(int(peer.proc._handle))), str(creation(int(peer.proc._handle)))
        confirmed = tick()
        require(key == parent and parent[0] == peer.proc.pid and key not in self.rows and launched <= row['ready'] <= confirmed and row['base'],
                'child and parent lifetime evidence')
        if self.capture is not None:
            self.capture.event('ready', child=key, parent=parent,
                               image_file_id=self.capture.image_id(int(peer.proc._handle), 'target.bin'),
                               role=role, member=member, base=row['base'], launch=launched, ready=row['ready'], confirmed=confirmed)
        row.update(role=role, member=member, launch=launched, exit=None, admission=None, attempts=[], successes=[])
        self.rows[key], self.children[key] = row, peer
        return key

    def live(self):
        return {key for key, row in self.rows.items() if row['member'] and row['exit'] is None}

    def stop(self, key):
        peer, row = self.children[key], self.rows[key]
        require(row['exit'] is None, 'duplicate child stop')
        requested = tick()
        peer.proc.stdin.close()
        ended = peer.receive('exit')['tick']
        code = peer.close()
        require(code == 0 and requested <= ended <= tick(), 'child exit acknowledgement and OS process termination')
        row['exit_request'], row['exit'], row['exit_confirmed'] = requested, ended, tick()
        if self.capture is not None:
            self.capture.event('exit', key=key, request=requested, ack=ended, confirmed=row['exit_confirmed'], code=code)


def exact(times):
    ordered = sorted(times)
    def percentile(p):
        return ordered[(p * len(times) + 99) // 100 - 1] if times else None
    return dict(n=len(times), p50=percentile(50), p95=percentile(95), p99=percentile(99), maximum=max(times, default=None))


def histogram(state, times):
    stats = exact(times)
    bucket = lambda n: (1 << n.bit_length()) - 1 if n is not None else 0
    require({k: int(v) for k, v in state.items()} ==
            dict(samples=stats['n'], max_ms=stats['maximum'] or 0, p95_upper_ms=bucket(stats['p95']),
                 p99_upper_ms=bucket(stats['p99'])), 'source timing versus individual acquired intervals')


def verify_inventory(frame, population, number):
    live = set(map(tuple, frame['controller_members']))
    members = list(map(tuple, frame['members']))
    selected = list(map(tuple, frame['selected']))
    require(set(members) == live and len(members) == len(live), 'census versus independent job population')
    admission = frame['admission']
    require(frame['controller_start'] <= frame['start'] <= admission <= frame['controller_end'], 'census clock bounds')
    for key in live:
        row = population.rows[key]
        if row['admission'] is None:
            row['admission'] = admission
        require(row['ready'] <= admission, 'child acknowledged before admission')
    sizes = [sum((pid // 4) % 3 == tier for pid, _ in live) for tier in range(3)]
    watched = min(4, sizes[0])
    quotas = [watched, min(6 - watched, sizes[1]), min(2, sizes[2])]
    require(set(selected) <= live and len(selected) == len(set(selected)) and
            [sum((pid // 4) % 3 == tier for pid, _ in selected) for tier in range(3)] == quotas, 'actual tier selection')
    expected = (0, '0')
    if number % 4 == 0 and live:
        candidates = []
        for key in live:
            row = population.rows[key]
            previous = row['attempts'][-1] if row['attempts'] else None
            if row.get('unsupported') or (previous and previous['result'] != 'observed' and admission - previous['start'] < 30000):
                continue
            since = row['successes'][-1] if row['successes'] else row['admission']
            candidates.append((since, previous is not None, previous['start'] if previous else 0, key))
        if candidates:
            expected = min(candidates)[-1]
    require(tuple(frame['loan']) == expected and (not expected[0] or expected in selected), 'overdue generation and slot')
    return selected


def verify_visit(visit, key, population):
    row = population.rows[key]
    require(tuple(visit['key']) == key and visit['controller_start'] <= visit['start'] <= visit['end'] <= visit['controller_end'],
            'dispatch identity, order and independent clock bounds')
    witness = (visit['before'] == visit['after'] == key[1] and visit['rows'] > 0 and visit['complete'] and
               visit['terminal'] == 18 and visit['base'] == row['base'])
    require((visit['result'] == 'observed') == witness, 'source result versus generation fences, EOF and child executable base')
    if witness:
        at = visit['last_success']
        require(row['exit'] is None and visit['start'] <= at <= visit['end'] and row['ready'] <= at,
                'successful source acquisition within a known live interval')
        row['successes'].append(at)
        row['unsupported'] = False
    else:
        require(visit['last_success'] == (row['successes'][-1] if row['successes'] else None),
                'unsuccessful visit preserves source success')
        if visit['result'] == 'access_denied':
            require(visit['win32_error'] == 5, 'access denial preserves Win32 error')
        if row['exit'] is not None:
            require(row['exit_confirmed'] <= visit['controller_start'] and not visit['rows'] and
                    not visit['base'] and not visit['complete'] and
                    visit['result'] in ('identity_unavailable', 'generation_changed', 'access_denied'),
                    'an exited selection cannot pay another generation or enter the module reader')
        if visit['result'] == 'unsupported':
            row['unsupported'] = True
    row['attempts'].append(visit)


def summarize(population, frames, ledger, cutoff):
    rows = [r for r in population.rows.values() if r['member']]
    acquired = [r for r in rows if r['successes']]
    missed = [r for r in rows if not r['successes']]
    all_visits = [v for r in rows for v in r['attempts']]
    first_wait = [r['successes'][0] - r['admission'] for r in acquired]
    ready_wait = [r['successes'][0] - r['ready'] for r in acquired]
    revisits = [b - a for r in acquired for a, b in zip(r['successes'], r['successes'][1:])]
    service = [v['last_success'] - v['start'] for v in all_visits if v['result'] == 'observed']
    outcomes = {name: sum(v['result'] == name for v in all_visits) for name in ledger['outcomes']}
    require(outcomes == {k: int(v) for k, v in ledger['outcomes'].items()} and int(ledger['attempts']) == len(all_visits),
            'qualified and failed visits both in the denominator')
    loans = sum(f['loan'] != [0, '0'] for f in frames)
    require(int(ledger['loan_offers']) == int(ledger['loan_entries']) == loans and int(ledger['complete_censuses']) == len(frames),
            'offered and entered reservations reconcile')
    require(int(ledger['retired_absent']) == sum(r['exit'] is not None and r['admission'] is not None for r in rows) and
            int(ledger['retained']) == len(population.live()) and int(ledger['untracked_outcomes']) == 0, 'retirement and retained population')
    histogram(ledger['first_observation_wait'], first_wait)
    histogram(ledger['successful_revisit'], revisits)
    histogram(ledger['observed_service'], service)
    require(int(ledger['failed_service']['samples']) == len(all_visits) - len(service), 'failed service samples')
    longest = []
    for r in rows:
        end = cutoff if r['exit'] is None else r['exit']
        boundaries = [r['ready'], *r['successes'], end]
        require(boundaries == sorted(boundaries), 'ordered lifetime, acquisitions and censoring boundary')
        gaps = [b - a for a, b in zip(boundaries, boundaries[1:])]
        r['window_end'] = end
        r['end_kind'] = 'workload_cutoff' if r['exit'] is None else 'child_exit'
        r['longest_unobserved_ms'] = max(gaps)
        longest.append(max(gaps))
    return dict(ready=len(rows), admitted=sum(r['admission'] is not None for r in rows),
                ever_observed=len(acquired), missed=len(missed), missed_roles=sorted(r['role'] for r in missed),
                right_censored=len(population.live()), visits=len(all_visits), outcomes=outcomes, loans=loans,
                ready_to_first_ms=exact(ready_wait), admission_to_first_ms=exact(first_wait),
                revisit_ms=exact(revisits), observed_service_ms=exact(service),
                longest_unobserved_per_generation_ms=exact(longest))


def world(exe, changing, trace, capture=None):
    with owned_job() as job, ExitStack() as stack:
        name = 'changing' if changing else 'fixed'
        peer = collector(stack, exe, job, capture.begin(name) if capture is not None else None)
        if capture is not None:
            capture.worlds[-1].update(collector=[peer.proc.pid, str(creation(int(peer.proc._handle)))],
                                      collector_file_id=capture.image_id(int(peer.proc._handle), 'collector.bin'))
        population = Population(stack, job, capture)
        outside = population.start('out_of_scope', member=False)
        if changing:
            population.stop(population.start('exit_before_census'))
        for _ in range(12):
            population.start('initial')
        frames = []
        for i in range(ROUNDS):
            if changing and i in (1, 2, 3):
                for _ in range(2):
                    population.start('growth')
            if changing and i in (5, 8, 11):
                seen = [key for key in population.live() if population.rows[key]['successes']]
                require(seen, 'positive source observation before controlled removal')
                population.stop(min(seen, key=lambda key: (population.rows[key]['ready'], key)))
                population.start('replacement')
            if frames:
                due = frames[-1]['admission'] + CADENCE_MS
                while (remaining := due - tick()) > 0:
                    time.sleep(remaining / 1000)
            expected_members = sorted(population.live())
            frame = capture.request(peer, 'inventory') if capture else peer.request('inventory')
            frame['controller_members'] = expected_members
            selected = verify_inventory(frame, population, i + 1)
            if frames:
                require(frame['start'] >= frames[-1]['admission'] + CADENCE_MS, 'measured census pacing')
            frames.append(frame)
            if changing and i == 0:
                victim = selected[0]
                population.rows[victim]['role'] = 'exit_after_selection'
                population.stop(victim)
            for key in selected:
                visit = capture.request(peer, 'dispatch') if capture else peer.request('dispatch')
                verify_visit(visit, key, population)
        finish = peer.request('finish')
        ledger = finish['ledger']
        cutoff = tick()
        code = peer.close()
        require(code == 0, 'normal collector termination')
        if capture is not None:
            capture.event('finish', start=finish['controller_start'], end=finish['controller_end'], cutoff=cutoff, code=code)
        summary = summarize(population, frames, ledger, cutoff)
        expected_misses = ['exit_after_selection', 'exit_before_census'] if changing else []
        passed = (summary['ready'] == (22 if changing else 12) and summary['missed_roles'] == expected_misses and
                  summary['revisit_ms']['n'] > 0 and
                  summary['visits'] == summary['outcomes']['observed'] + int(changing))
        for key in sorted(population.live()):
            population.stop(key)
        population.stop(outside)
        accounting = Accounting()
        native(query_job(job, 1, c.byref(accounting), c.sizeof(accounting), None))
        require(accounting.active == 0 and accounting.total == summary['ready'], 'final job accounting versus every launched member')
        if capture is not None:
            capture.worlds[-1].update(job_total=accounting.total, job_active_after_cleanup=accounting.active)
        result = dict(name='changing' if changing else 'fixed', passed=passed, inventories=ROUNDS, cadence_ms=CADENCE_MS,
                      summary=summary, job_total=accounting.total, job_active_after_cleanup=accounting.active)
        if trace:
            result.update(generations=list(population.rows.values()), inventories_raw=frames, ledger=ledger, cutoff=cutoff)
        return result


def interrupted_controller(exe):
    with owned_job() as job, ExitStack() as stack:
        peer = collector(stack, exe, job)
        population = Population(stack, job)
        key = population.start('interruption')
        frame = peer.request('inventory')
        require(list(map(tuple, frame['selected'])) == [key], 'interruption synchronized after real selection')
        announce(dict(kind='armed', target=key, collector=[peer.proc.pid, str(creation(int(peer.proc._handle)))]))
        sys.stdin.buffer.read()


def interruption(exe, capture=None):
    with ExitStack() as stack:
        supervisor = Peer([sys.executable, str(Path(__file__).resolve()), '--interrupt-controller', '--core-exe', str(exe)])
        stack.callback(supervisor.close)
        identities = supervisor.receive('armed')
        handles, peers = [], {}
        for label in ('target', 'collector'):
            pid, generation = identities[label]
            handle = native(open_process(0x00101000, False, pid))  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
            stack.callback(close_handle, handle)
            pinned = [peer_pid(handle), str(creation(handle))]
            before = wait(handle, 0)
            require(pinned == [pid, generation] and before == 258, 'pin exact live process before owner interruption')
            peers[label] = dict(announced=[pid, generation], pinned=pinned, before=before)
            if capture is not None:
                peers[label]['image_file_id'] = capture.image_id(handle, label + '.bin')
            handles.append(handle)
        supervisor.proc.kill()
        code = supervisor.close()
        require(code != 0, 'abrupt controller termination')
        for row, handle in zip(peers.values(), handles):
            row['after'] = wait(handle, 10000)
        require(all(row['after'] == 0 for row in peers.values()), 'owned collector and target terminated after owner loss')
        if capture is not None:
            capture.owner_loss = dict(controller_exit=code, peers=peers)
        return True


def final_job_usage(job, end):
    usage = JobUsage()
    native(query_job(job, 8, c.byref(usage), c.sizeof(usage), None))
    if usage.basic.active:
        native(terminate_job(job, 1))
        end["forced_cleanup"] = True
        until = time.monotonic() + 10
        while usage.basic.active and time.monotonic() < until:
            time.sleep(0.02)
            native(query_job(job, 8, c.byref(usage), c.sizeof(usage), None))
    limits = ExtendedLimits()
    peak_known = query_job(job, 9, c.byref(limits), c.sizeof(limits), None)
    peak_error = None if peak_known else c.get_last_error()
    return dict(total=usage.basic.total, active=usage.basic.active, user_100ns=str(usage.basic.times[0]),
                kernel_100ns=str(usage.basic.times[1]), read_operations=str(usage.io[0]),
                write_operations=str(usage.io[1]), other_operations=str(usage.io[2]),
                read_bytes=str(usage.io[3]), written_bytes=str(usage.io[4]), other_bytes=str(usage.io[5]),
                peak_job_bytes=str(limits.memory[3]) if peak_known else None, peak_error=peak_error)


def wait_for_worker(worker, ticket, deadline):
    grant = (ticket + '\n').encode('ascii')
    while True:
        try:
            stdout, _ = worker.communicate(input=grant, timeout=max(0, deadline - tick()) / 1000)
            return stdout
        except subprocess.TimeoutExpired:
            if tick() >= deadline:
                raise
            grant = None  # communicate resumes the original pipe operation.


def finish_worker(worker, job, bound, end):
    if worker.poll() is None:
        if bound is not None:
            end["forced_cleanup"] = True
            try:
                native(terminate_job(job, 1))
            except OSError as exc:
                end["error_code"] = exc.winerror
                worker.kill()
        else:
            worker.kill()  # An ungranted worker cannot create descendants.
        try:
            worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            end["error_code"] = 258
    if bound is not None:
        code = worker.poll()
        end["worker_exit"] = None if code is None else code & 0xffffffff
        try:
            end["job"] = final_job_usage(job, end)
        except OSError as exc:
            end["accounting_error"] = exc.winerror if exc.winerror is not None else 0


def supervised_attempt(args):
    import owned_module_campaign as campaign
    from owned_module_benchmark import PAIRED_SCHEMA, read_bundle

    admission = dict(supervisor=[os.getpid(), str(creation(self_handle()))], tick_ms=tick())
    plan, admission = campaign.admit(args.campaign, args.plan_sha256, args.slot, admission)
    ticket = plan["tickets"][args.slot - 1]
    destination = campaign.package_path(args.campaign, ticket)
    end = dict(outcome="startup_error", worker_exit=None, worker_failure=None, package_sha256=None, error_code=None,
               job=None, accounting_error=None, forced_cleanup=False)
    bound = None
    try:
        with ExitStack() as stack:
            inputs = {}
            end["outcome"] = "input_unavailable"
            for name, path in campaign.input_paths(args.core_exe).items():
                stream, _ = stack.enter_context(leased_file(path))
                inputs[name] = campaign.input_hash(stream, name)
            if inputs != plan["inputs"]:
                end["outcome"] = "input_mismatch"
            else:
                end["outcome"] = "startup_error"
                if destination.exists():
                    raise FileExistsError("registered output is already occupied")
                argv = [sys.executable, str(Path(__file__).resolve()), "--campaign-worker", "--core-exe",
                        str(args.core_exe.resolve()), "--benchmark-out", str(destination.resolve())]
                if plan.get("paired_costs"):
                    argv.append("--paired-costs")
                with owned_job() as job:
                    worker = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True,
                                              creationflags=subprocess.DETACHED_PROCESS)
                    stack.callback(worker._handle.Close)
                    stack.callback(worker.stdout.close)
                    stack.callback(worker.stdin.close)
                    try:
                        handle = int(worker._handle)
                        native(assign_job(job, handle))
                        witness = dict(worker=[native(peer_pid(handle)), str(creation(handle))], tick_ms=tick())
                        bound = campaign.record(args.campaign, args.plan_sha256, args.slot, admission, "bound", witness)
                        end["outcome"] = "worker_error"
                        signal = wait_for_worker(worker, ticket, witness["tick_ms"] + plan["timeout_ms"])
                        if worker.returncode == 3 and signal:
                            end["outcome"] = "protocol_error"
                            require(len(signal) <= 512, "oversized worker diagnostic")
                            failure = json.loads(signal)
                            campaign.check_worker_failure(failure, ticket)
                            end.update(outcome="worker_error", worker_failure=failure)
                        elif worker.returncode == 0 or (worker.returncode == 1 and signal):
                            end["outcome"] = "protocol_error"
                            require(re.fullmatch(rb"[0-9a-f]{64}\r?\n", signal), "invalid publication acknowledgement")
                            pin = signal.strip().decode('ascii')
                            end["outcome"] = "invalid_package"
                            manifest, _ = read_bundle(destination, pin, json.loads)
                            require(manifest["run_id"] == ticket and
                                     (manifest["schema"] == PAIRED_SCHEMA) == plan.get("paired_costs", False) and
                                    all(manifest["artifacts"][k] == inputs[k] for k in campaign.IMAGES), "package differs from registered inputs")
                            end.update(outcome="published", package_sha256=pin)
                    except subprocess.TimeoutExpired:
                        end["outcome"] = "timed_out"
                    except KeyboardInterrupt:
                        end["outcome"] = "interrupted"
                    finally:
                        finish_worker(worker, job, bound, end)
    except KeyboardInterrupt:
        if end["outcome"] == "published":
            end["error_code"] = 995
        else:
            end["outcome"] = "interrupted"
    except (OSError, ValueError, AssertionError) as exc:
        end["error_code"] = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    end["tick_ms"] = tick()
    end = campaign.record(args.campaign, args.plan_sha256, args.slot, admission, "ended", end, bound)
    row = dict(slot=args.slot, ticket=ticket, admitted=admission, bound=bound, ended=end, loss=None)
    print(json.dumps(dict(schema="kn.owned_module_attempt.v1", **row)))
    return 0 if campaign.passed(end) else 1


def watch_owner(args):
    import owned_module_campaign as campaign
    snapshot = campaign.current_snapshot(args.campaign, args.plan_sha256)
    seconds = 60 if args.watch_seconds is None else args.watch_seconds
    if not 1 <= args.slot <= len(snapshot["attempts"]) or not 1 <= seconds <= 3600:
        raise ValueError("invalid observation slot or timeout")
    row = snapshot["attempts"][args.slot - 1]
    if row["bound"] is None or row["ended"] is not None or row["loss"] is not None:
        raise ValueError("watch requires a pending job-bound worker")
    observation = dict(observer=[os.getpid(), str(creation(self_handle()))], before_ms=tick())
    with ExitStack() as stack:
        handles = {}
        for name, key in (("supervisor", row["admitted"]["supervisor"]), ("worker", row["bound"]["worker"])):
            handle = native(open_process(0x00101000, False, key[0]))
            stack.callback(close_handle, handle)
            pinned = [native(peer_pid(handle)), str(creation(handle))]
            before = wait(handle, 0)
            if pinned != key or before != 258:
                raise ValueError("original live process unavailable for observation")
            handles[name] = handle
            observation[name] = dict(key=pinned, before=before)
        print(json.dumps(dict(schema="kn.owned_module_watch.v1", status="armed", slot=args.slot)), flush=True)
        deadline = tick() + seconds * 1000
        for name, handle in handles.items():
            after = wait(handle, max(deadline - tick(), 0))
            if after == 258:
                print(json.dumps(dict(schema="kn.owned_module_watch.v1", status="observation_timeout", slot=args.slot)))
                return 1
            if after != 0:
                raise c.WinError(c.get_last_error())
            code = w.DWORD()
            native(process_exit(handle, c.byref(code)))
            observation[name].update(after=after, exit_code=code.value)
        observation["after_ms"] = tick()
        receipt = campaign.record(args.campaign, args.plan_sha256, args.slot, row["admitted"], "loss", observation, row["bound"])
    status = "owner_lost" if receipt is not None else "already_recorded"
    print(json.dumps(dict(schema="kn.owned_module_watch.v1", status=status, slot=args.slot)))
    return 0


def run_workload(args, ticket):
    phase = "inputs"
    try:
        exe = args.core_exe.resolve()
        with ExitStack() as stack:
            capture = BenchmarkCapture(stack, exe, ticket, args.paired_costs) if args.benchmark_out else None
            worlds = []
            for changing in (False, True):
                phase = "changing" if changing else "fixed"
                worlds.append(world(exe, changing, args.trace, capture))
            phase = "interruption"
            cleaned = interruption(exe, capture)
            passed = all(w["passed"] for w in worlds) and cleaned
            report = dict(schema=SCHEMA, passed=passed, clock="GetTickCount64_ms", interrupted_owner_cleanup=cleaned, worlds=worlds)
            phase = "publication"
            if capture is not None:
                report["benchmark_sha256"] = capture.publish(args.benchmark_out)
        print(report["benchmark_sha256"] if ticket else json.dumps(report))
        return 0 if passed else 1
    except (OSError, AssertionError, ValueError, KeyError, TypeError, IndexError, RuntimeError, queue.Empty, subprocess.TimeoutExpired) as exc:
        if ticket is None:
            raise
        code = None
        if isinstance(exc, OSError):
            domain = "os"
            if getattr(exc, "winerror", None) is not None:
                domain, code = "win32", exc.winerror
            elif exc.errno is not None:
                domain, code = "errno", exc.errno
        elif isinstance(exc, AssertionError):
            domain = "assertion"
        elif isinstance(exc, (queue.Empty, subprocess.TimeoutExpired)):
            domain = "timeout"
        else:
            domain = "runtime" if isinstance(exc, RuntimeError) else "invalid_data"
        print(json.dumps(dict(schema="kn.owned_module_worker_failure.v1", ticket=ticket, phase=phase, domain=domain, code=code)))
        return 3


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-exe', type=Path)
    parser.add_argument('--paired-costs', action='store_true', help='pair each fixed-job census and visit with an idle request')
    parser.add_argument('--trace', action='store_true', help='include private generation and acquisition evidence on stdout')
    parser.add_argument('--benchmark-out', type=Path, help='publish a new private replay package and return its SHA-256 pin')
    parser.add_argument('--campaign', type=Path, help='run one pre-registered acquisition slot')
    parser.add_argument('--slot', type=int)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--watch-owner', action='store_true', help='observe a running supervisor and worker through pinned handles')
    parser.add_argument('--watch-seconds', type=int)
    parser.add_argument('--campaign-worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--interrupt-controller', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.paired_costs and (not args.benchmark_out or not args.core_exe or args.child or args.interrupt_controller):
        parser.error('--paired-costs requires --benchmark-out and --core-exe')
    if args.watch_owner or any(x is not None for x in (args.campaign, args.slot, args.plan_sha256, args.watch_seconds)):
        import sqlite3
        if (not all(x is not None for x in (args.campaign, args.slot, args.plan_sha256)) or
                (not args.watch_owner and (args.core_exe is None or args.watch_seconds is not None)) or
                (args.watch_owner and args.core_exe is not None) or
                args.trace or args.benchmark_out or args.campaign_worker or args.child or args.interrupt_controller):
            parser.error('a registered campaign slot requires --core-exe for acquisition or --watch-owner for observation')
        try:
            sys.exit(watch_owner(args) if args.watch_owner else supervised_attempt(args))
        except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
            print(f'campaign acquisition failed: {exc}', file=sys.stderr)
            sys.exit(2)
    ticket = None
    if args.campaign_worker:
        if not args.benchmark_out or not args.core_exe or args.trace or args.child or args.interrupt_controller:
            parser.error('invalid supervised worker invocation')
        grant = sys.stdin.buffer.readline(34)
        if not re.fullmatch(rb'[0-9a-f]{32}\n', grant):
            sys.exit(2)
        ticket = grant[:-1].decode('ascii')
    if args.child:
        child()
    elif not args.core_exe:
        parser.error('--core-exe is required')
    elif args.interrupt_controller:
        interrupted_controller(args.core_exe.resolve())
    else:
        if args.benchmark_out and args.benchmark_out.exists():
            parser.error('benchmark destination already exists')
        sys.exit(run_workload(args, ticket))
