"""Measure real Toolhelp observations against the lifetimes of owned Windows processes."""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time


SCHEMA = 'kn.owned_module_workload.v1'
ROUNDS = 16
CADENCE_MS = 25
k = c.WinDLL('kernel32', use_last_error=True)


def api(name, result, *args):
    fn = getattr(k, name)
    fn.argtypes, fn.restype = args, result
    return fn


tick = api('GetTickCount64', c.c_uint64)
self_handle = api('GetCurrentProcess', w.HANDLE)
module_base = api('GetModuleHandleW', w.HMODULE, w.LPCWSTR)
create_job = api('CreateJobObjectW', w.HANDLE, c.c_void_p, w.LPCWSTR)
set_job = api('SetInformationJobObject', w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD)
query_job = api('QueryInformationJobObject', w.BOOL, w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p)
assign_job = api('AssignProcessToJobObject', w.BOOL, w.HANDLE, w.HANDLE)
close_handle = api('CloseHandle', w.BOOL, w.HANDLE)
duplicate = api('DuplicateHandle', w.BOOL, w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD)
open_process = api('OpenProcess', w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
wait = api('WaitForSingleObject', w.DWORD, w.HANDLE, w.DWORD)
process_times = api('GetProcessTimes', w.BOOL, w.HANDLE, *(c.POINTER(w.FILETIME),) * 4)


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


class Accounting(c.Structure):
    _fields_ = [('times', c.c_int64 * 4), ('faults', w.DWORD), ('total', w.DWORD), ('active', w.DWORD), ('terminated', w.DWORD)]


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

    def __init__(self, argv, startupinfo=None):
        # A detached interpreter uses its pipes without adding a console host
        # to the job's independently enumerated population.
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     encoding='utf-8', close_fds=True, startupinfo=startupinfo,
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
            for line in self.proc.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def receive(self, kind):
        line = self.lines.get(timeout=30)
        require(line is not None, f'{kind}: peer exited before acknowledgement')
        wire = json.loads(line)
        require(wire['schema'] == SCHEMA, 'private workload evidence schema')
        data = wire['payload']
        require(data.get('kind') == kind, f'expected {kind} acknowledgement')
        return data

    def request(self, kind):
        start = tick()
        self.proc.stdin.write(kind + '\n')
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
        return code


def collector(stack, exe, job):
    query = w.HANDLE()
    # The endpoint can query membership. Only the independent controller can
    # assign processes or change job limits.
    native(duplicate(self_handle(), job, self_handle(), c.byref(query), 0x0004, True, 0))
    try:
        startup = subprocess.STARTUPINFO(lpAttributeList={'handle_list': [query.value]})
        peer = Peer([str(exe), '--owned-user-module-workload', str(query.value)], startup)
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
    def __init__(self, stack, job):
        self.stack, self.job = stack, job
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
        require(key == (peer.proc.pid, str(creation(int(peer.proc._handle)))) and key not in self.rows and
                launched <= row['ready'] <= tick() and row['base'], 'child and parent lifetime evidence')
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
        require(peer.close() == 0 and requested <= ended <= tick(), 'child exit acknowledgement and OS process termination')
        row['exit_request'], row['exit'], row['exit_confirmed'] = requested, ended, tick()


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


def world(exe, changing, trace):
    with owned_job() as job, ExitStack() as stack:
        peer = collector(stack, exe, job)
        population = Population(stack, job)
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
            frame = peer.request('inventory')
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
                verify_visit(peer.request('dispatch'), key, population)
        ledger = peer.request('finish')['ledger']
        cutoff = tick()
        require(peer.close() == 0, 'normal collector termination')
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


def interruption(exe):
    with ExitStack() as stack:
        supervisor = Peer([sys.executable, str(Path(__file__).resolve()), '--interrupt-controller', '--core-exe', str(exe)])
        stack.callback(supervisor.close)
        identities = supervisor.receive('armed')
        handles = []
        for label in ('target', 'collector'):
            pid, generation = identities[label]
            handle = native(open_process(0x00101000, False, pid))  # SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
            stack.callback(close_handle, handle)
            require(str(creation(handle)) == generation and wait(handle, 0) == 258, 'pin exact live process before owner interruption')
            handles.append(handle)
        supervisor.proc.kill()
        require(supervisor.close() != 0, 'abrupt controller termination')
        require([wait(handle, 10000) for handle in handles] == [0, 0], 'owned collector and target terminated after owner loss')
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core-exe', type=Path)
    parser.add_argument('--trace', action='store_true', help='include private generation and acquisition evidence on stdout')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--interrupt-controller', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        child()
    elif not args.core_exe:
        parser.error('--core-exe is required')
    elif args.interrupt_controller:
        interrupted_controller(args.core_exe.resolve())
    else:
        exe = args.core_exe.resolve()
        worlds = [world(exe, changing, args.trace) for changing in (False, True)]
        cleaned = interruption(exe)
        passed = all(w['passed'] for w in worlds) and cleaned
        print(json.dumps(dict(schema=SCHEMA, passed=passed, clock='GetTickCount64_ms',
                              interrupted_owner_cleanup=cleaned, worlds=worlds)))
        sys.exit(0 if passed else 1)
