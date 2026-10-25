"""Owned-fixture query snapshots against port and filter lifetime transitions."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import importlib.util
import json
import os
import pathlib
import random
import sys
import threading
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('watch', ROOT / 'tools/run-pending-watch-e2e.py')
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)
p, kernel, flt = watch.p, watch.kernel, watch.flt


def duplicate(handle, process=-1):
    result = w.HANDLE()
    assert kernel.DuplicateHandle(w.HANDLE(process), handle, w.HANDLE(-1), c.byref(result), 0, False, 2)
    return result


def borrowed(handle):
    port = p.Port.__new__(p.Port)
    port.handle = handle
    return port


def raw_query(handle, delay=0, output=None):
    request = p.Request(p.MAGIC, p.VERSION, c.sizeof(p.Request), 6 if delay else 0, 0, 0, delay, 0)
    state, returned = p.Status(), w.DWORD()
    hr = flt.FilterSendMessage(handle, c.byref(request), c.sizeof(request),
        output if output is not None else c.byref(state), c.sizeof(state), c.byref(returned))
    result = dict(hr=hr & 0xffffffff, returned=returned.value)
    if hr >= 0:
        assert returned.value == c.sizeof(state)
        if output is None:
            coherent(state)
            result['state'] = p.fields(state)
    return result


def coherent(state):
    assert state.Magic == p.MAGIC and state.Version == p.VERSION and state.Size == c.sizeof(p.Status)
    assert state.Connections <= 16 and state.ActiveWorkers <= 1 and state.Violations == 0
    assert state.Freed <= state.LogicalCompleted <= state.Created
    assert state.Created - state.Freed == state.LiveContexts
    assert state.PreCompleted <= state.PreQueued and state.PostCompleted <= state.PostQueued
    assert state.InstanceCompletes <= state.InstanceStarts
    assert state.ArmedRemaining <= 8
    if state.ArmedMode:
        assert state.OwnerPid and state.ArmedRemaining and state.ArmedGeneration == state.TopologyGeneration
    else:
        assert state.ArmedRemaining == state.ArmedGeneration == 0
    for entered, completed in [('RaceEntered', 'RaceCompleted'), ('BeforeLowerEntered', 'BeforeLowerCompleted'),
        ('WatchGateEntered', 'WatchGateCompleted'), ('TargetExitGateEntered', 'TargetExitGateCompleted')]:
        assert getattr(state, completed) <= getattr(state, entered)
    if hasattr(state, 'QueryActive'):
        assert state.QueryStarted == state.QueryCompleted + state.QueryActive
        assert state.QueryGateCompleted <= state.QueryGateEntered


class Readers:
    def __init__(self, sources, count, fail_start=False):
        self.stop, self.unloading = threading.Event(), threading.Event()
        self.errors, self.rows, self.threads = [], [], []
        try:
            for index in range(count):
                if fail_start and index == 1:
                    raise RuntimeError('injected runner failure: reader-start')
                source, allowed = sources[index % len(sources)]
                row = dict(index=index, allowed=allowed, successes=0, denied=0, closed=0, max_us=0,
                    owners=set(), generations=set())
                port = borrowed(duplicate(source))
                worker = threading.Thread(target=self.run, args=(port, row))
                try:
                    worker.start()
                except BaseException:
                    port.close()
                    raise
                self.rows.append(row)
                self.threads.append(worker)
        except BaseException as error:
            # The caller never receives a partially constructed Readers object.
            # Stop/join leases already started before propagating its failure.
            try:
                self.finish()
            except BaseException:
                error.add_note('partial reader cleanup:\n' + traceback.format_exc())
            raise

    def run(self, port, row):
        previous = None
        try:
            while not self.stop.is_set():
                began = time.perf_counter_ns()
                try:
                    state = port.send()
                    assert row['allowed'], 'foreign duplicated port was accepted'
                    coherent(state)
                    current = [getattr(state, name) for name in ('Created', 'Freed', 'PreQueued', 'PreCompleted',
                        'TopologyGeneration', 'InstanceStarts', 'InstanceCompletes')]
                    assert previous is None or all(a <= b for a, b in zip(previous, current))
                    previous = current
                    row['successes'] += 1
                    row['owners'].add(state.OwnerPid)
                    row['generations'].add(state.TopologyGeneration)
                except OSError as error:
                    if str(error) == 'message: 0x80070005' and not row['allowed']:
                        row['denied'] += 1
                    elif self.unloading.is_set() and str(error) in ('message: 0x80070006', 'message: 0x801f000b'):
                        row['closed'] += 1
                        break
                    else:
                        raise
                row['max_us'] = max(row['max_us'], (time.perf_counter_ns() - began) / 1000)
                if (row['successes'] + row['denied']) % 16 == 0:
                    time.sleep(.0002)
        except BaseException:
            self.errors.append(traceback.format_exc())
        finally:
            port.close()

    def warmed(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            assert not self.errors, self.errors
            if all(row['successes'] + row['denied'] >= 100 for row in self.rows):
                return
            time.sleep(.002)
        raise TimeoutError(self.rows)

    def finish(self):
        self.stop.set()
        for worker in self.threads:
            worker.join(15)
        assert all(not worker.is_alive() for worker in self.threads) and not self.errors, self.errors
        return [dict(row, owners=sorted(row['owners']), generations=sorted(row['generations'])) for row in self.rows]


class ReplyBuffer:
    """Owned two-page reply crossing a page boundary; never read a dead page."""
    MODES = ('noaccess', 'readonly', 'decommit', 'release', 'overwrite')

    def __init__(self, mode):
        self.mode = mode
        self.base = kernel.VirtualAlloc(None, 8192, 0x3000, 4)
        assert self.base
        self.output = self.base + 4096 - 256
        self.changed = False
        c.memset(self.base, 0xa5, 8192)

    def change(self):
        if self.mode in ('noaccess', 'readonly'):
            old = w.DWORD()
            assert kernel.VirtualProtect(self.base + 4096, 4096,
                1 if self.mode == 'noaccess' else 2, c.byref(old))
        elif self.mode == 'decommit':
            assert kernel.VirtualFree(self.base + 4096, 4096, 0x4000)
        elif self.mode == 'release':
            address = self.base
            assert kernel.VirtualFree(address, 0, 0x8000)
            self.base = None
            # Keep this VA inaccessible until the reply returns. Unrelated
            # Python allocations must not reuse a deliberately released reply.
            reserved = kernel.VirtualAlloc(address, 8192, 0x2000, 1)
            if reserved != address:
                if reserved:
                    kernel.VirtualFree(reserved, 0, 0x8000)
                raise RuntimeError('could not reserve released reply address')
            self.base = reserved
        else:
            assert self.mode == 'overwrite'
            c.memset(self.output, 0x5a, c.sizeof(p.Status))
        self.changed = True

    def verify(self, reply, held):
        assert self.changed
        if self.mode == 'overwrite':
            assert reply['hr'] == 0 and reply['returned'] == c.sizeof(p.Status), reply
            state = p.Status.from_buffer_copy(c.string_at(self.output, c.sizeof(p.Status)))
            coherent(state)
            assert state.OwnerPid == held.OwnerPid and state.ArmedRemaining == held.ArmedRemaining
            assert state.ArmedGeneration == held.ArmedGeneration
            reply['state'] = p.fields(state)
        else:
            assert reply['hr'] == 0x800703e6 and reply['returned'] == 0, reply
        if self.mode in ('noaccess', 'readonly'):
            old = w.DWORD()
            assert kernel.VirtualProtect(self.base + 4096, 4096, 4, c.byref(old))
        if self.mode != 'release':
            assert c.string_at(self.output - 64, 64) == b'\xa5' * 64, 'reply prefix overwritten'
        if self.mode not in ('release', 'decommit'):
            assert c.string_at(self.output + c.sizeof(p.Status), 64) == b'\xa5' * 64, 'reply suffix overwritten'
        return dict(mode=self.mode, **reply)

    def close(self):
        if self.base:
            assert kernel.VirtualFree(self.base, 0, 0x8000)
            self.base = None


class Suite(watch.Suite):
    def record(self, kind, **detail):
        if self.cleanup_in_progress and getattr(self, 'inject_failure', None) == 'cleanup-log':
            raise OSError('injected cleanup evidence failure')
        return super().record(kind, **detail)

    def inject(self, stage):
        if getattr(self, 'inject_failure', None) == stage:
            if stage == 'cleanup-command-log':
                log = self.output / 'lifecycle.log'
                log.rename(self.output / 'lifecycle-before-failure.log')
                log.mkdir()  # Force real append failures during cleanup commands.
            raise RuntimeError('injected runner failure: ' + stage)

    def query_hold(self, monitor, count):
        state = p.wait_state(monitor, lambda s: s.QueryGateEntered == count and s.QueryGateCompleted == 0)
        coherent(state)
        assert state.QueryActive >= count + 1, p.fields(state)
        return state

    def query_controls(self, iterations):
        for iteration in range(iterations):
            for case in ('snapshot', 'duplicate-close', 'last-close', 'unload', 'last-close-unload',
                'reply-protect', 'reply-free', 'owner-exit'):
                label = f'query-control-{case}-{iteration}'
                self.load()
                target, replacement = self.reader(), self.reader()
                monitor, owner, sender = p.Port(), None, None
                work, closer, unloader, exited, memory = None, None, None, None, None
                child = self.child() if case == 'owner-exit' else None
                try:
                    if child is not None:
                        self.arm(child, target)
                        sender = borrowed(duplicate(w.HANDLE(child.ready['handle']), int(child.proc._handle)))
                        denied = raw_query(sender.handle, delay=500)
                        assert denied['hr'] == 0x80070005 and monitor.send().QueryGateEntered == 0
                        child.send(action=6, delay=500)
                    else:
                        owner = p.Port()
                        owner.send(action=5, mode=4, pid=target.proc.pid, delay=500, Reserved=8)
                        sender = borrowed(duplicate(owner.handle)) if case == 'duplicate-close' else owner
                        if case.startswith('reply-'):
                            memory = kernel.VirtualAlloc(None, 4096, 0x3000, 4)
                            assert memory
                        # Hold the value only after submission is confirmed in
                        # the kernel. Do not issue another call after closing it.
                        handle = w.HANDLE(sender.handle.value)
                        work = self.background(lambda: raw_query(handle, delay=500, output=memory))
                    held = self.query_hold(monitor, 1)
                    self.record('query-held', label=label, state=p.fields(held))
                    if case == 'snapshot':
                        owner.send(action=3)
                        with p.managed.driver_load_privilege():
                            assert flt.FilterDetach(p.NAME, 'C:', p.INSTANCE) >= 0
                            assert self.attach(p.INSTANCE) >= 0
                        owner.send(action=5, mode=4, pid=replacement.proc.pid, delay=500, Reserved=2)
                        changed = monitor.send()
                        assert changed.QueryGateCompleted == 0 and changed.ArmedRemaining == 2
                        reply = self.joined(work)
                        state = monitor.send()
                        self.check(label + '-point-in-time', reply['hr'] == 0 and reply['state']['ArmedRemaining'] == 8 and
                            reply['state']['ArmedGeneration'] == held.ArmedGeneration and
                            state.ArmedRemaining == 2 and state.ArmedGeneration == state.TopologyGeneration > held.TopologyGeneration,
                            held=p.fields(held), changed=p.fields(changed), after=p.fields(state), reply=reply)
                        self.read(replacement, 0)
                        p.wait_state(monitor, lambda s: s.PreQueued == 1 and s.RaceEntered == 1)
                        owner.send(action=2)
                        self.results([replacement.receive()], [0])
                    elif case == 'duplicate-close':
                        owner.close()
                        during = monitor.send()
                        assert during.OwnerPid and during.ArmedRemaining == 8 and during.QueryGateCompleted == 0
                        reply = self.joined(work)
                        assert reply['hr'] == 0
                        sender.close()
                        state = p.wait_state(monitor, lambda s: s.OwnerPid == s.ArmedRemaining == 0)
                        self.check(label + '-last-lease-restores', state.OwnerRestores == 1,
                            during=p.fields(during), state=p.fields(state), reply=reply)
                    elif case == 'owner-exit':
                        exited = self.background(lambda: self.terminate(child))
                        during = monitor.send()
                        code = self.joined(exited)
                        assert code == 259
                        state = p.wait_state(monitor, lambda s: s.OwnerPid == s.ArmedRemaining == 0 and p.balanced(s))
                        denied = raw_query(sender.handle)
                        self.check(label + '-no-foreign-lease', denied['hr'] == 0x80070005 and state.OwnerRestores == 1 and
                            state.QueryGateEntered == state.QueryGateCompleted == 1,
                            during=p.fields(during), state=p.fields(state), denied=denied)
                    elif case.startswith('reply-'):
                        address = memory
                        if case == 'reply-protect':
                            old = w.DWORD()
                            assert kernel.VirtualProtect(address, 4096, 1, c.byref(old))
                        else:
                            assert kernel.VirtualFree(address, 0, 0x8000)
                            memory = None
                        reply = self.joined(work)
                        state = monitor.send()
                        self.check(label + '-fault-isolated', reply['hr'] == 0x800703e6 and reply['returned'] == 0 and
                            state.QueryReplyFailures == 1 and state.OwnerPid == held.OwnerPid and state.ArmedRemaining == 8,
                            held=p.fields(held), state=p.fields(state), reply=reply)
                    else:
                        with p.managed.driver_load_privilege():
                            if case.startswith('last-close'):
                                closer = self.background(sender.close)
                            if case.endswith('unload'):
                                unloader = self.background(lambda: flt.FilterUnload(p.NAME))
                                assert not unloader[1].wait(.025), 'unload returned with a held Message callback'
                            reply = self.joined(work)
                            assert reply['hr'] == 0, reply
                            if closer is not None:
                                self.joined(closer)
                            if unloader is not None:
                                assert self.joined(unloader) >= 0
                                self.loaded = False
                                state = self.audit(label)
                            else:
                                state = p.wait_state(monitor, lambda s: s.OwnerPid == s.ArmedRemaining == 0)
                        self.check(label + '-drained', state.QueryGateEntered == state.QueryGateCompleted == 1 and
                            (self.loaded or p.final_balanced(state)), state=p.fields(state), reply=reply)
                    if self.loaded:
                        if owner is not None and owner.handle.value:
                            owner.send(action=3)
                        state = p.wait_state(monitor, p.balanced)
                        assert state.QueryGateEntered == state.QueryGateCompleted == 1
                        self.unload(label)
                    try:
                        monitor.send()
                        raise AssertionError('unloaded query port still responds')
                    except OSError:
                        pass
                finally:
                    for operation in (work, closer, unloader, exited):
                        if operation is not None:
                            operation[0].join(15)
                    if memory:
                        kernel.VirtualFree(memory, 0, 0x8000)
                    if sender is not None:
                        sender.close()
                    if owner is not None:
                        owner.close()
                    monitor.close()
                    if child is not None:
                        child.close(force=True)
                    target.close(force=True)
                    replacement.close(force=True)

    def stress(self, iterations, readers, seed):
        rng = random.Random(seed)
        for iteration in range(iterations):
            label = f'query-stress-{iteration}'
            self.load()
            target, replacement, owner, next_owner = self.reader(), self.reader(), self.child(), self.child()
            monitor, source = p.Port(), p.Port()
            foreign = duplicate(w.HANDLE(owner.ready['handle']), int(owner.proc._handle))
            root, clients, churn = duplicate(source.handle), None, None
            churn_stop, churn_errors, churn_stats = threading.Event(), [], dict(queries=0)

            def churn_ports():
                try:
                    while not churn_stop.is_set():
                        # The root stays owned until join, avoiding user-handle
                        # reuse/ABA while DuplicateHandle captures each lease.
                        port = borrowed(duplicate(root))
                        try:
                            coherent(port.send())
                            churn_stats['queries'] += 1
                        except OSError as error:
                            assert clients.unloading.is_set() and str(error) in (
                                'message: 0x80070006', 'message: 0x801f000b'), error
                            break
                        finally:
                            port.close()
                        time.sleep(.0002)
                except BaseException:
                    churn_errors.append(traceback.format_exc())

            try:
                self.arm(owner, target)
                clients = Readers([(root, True), (foreign, False)], readers)
                churn = threading.Thread(target=churn_ports)
                churn.start()
                clients.warmed()
                source.close()
                kernel.CloseHandle(foreign)
                foreign = w.HANDLE()
                # Reader leases keep both original client objects alive while
                # originals close, including a foreign owner's dead endpoint.
                if iteration % 2:
                    assert self.terminate(owner) == 259
                else:
                    owner.close()
                released = p.wait_state(monitor, lambda s: s.OwnerPid == s.ArmedRemaining == 0)
                self.arm(next_owner, replacement)
                with p.managed.driver_load_privilege():
                    for _ in range(4):
                        instance = rng.choice((p.INSTANCE, p.LOWER))
                        assert flt.FilterDetach(p.NAME, 'C:', instance) >= 0
                        assert self.attach(instance) >= 0
                        assert monitor.send().ArmedRemaining == 0
                        self.arm(next_owner, replacement)
                    self.read(replacement, 0)
                    p.wait_state(monitor, lambda s: s.PreQueued == 1 and s.RaceEntered == 1)
                    next_owner.send(action=2)
                    next_owner.receive()
                    self.results([replacement.receive()], [0])
                    clients.unloading.set()
                    hr = flt.FilterUnload(p.NAME)
                    assert hr >= 0, hr
                self.loaded = False
                state = self.audit(label)
                rows = clients.finish()
                churn_stop.set()
                churn.join(15)
                assert not churn.is_alive() and not churn_errors, churn_errors
                self.check(label + '-snapshots-and-close', all(row['successes'] >= 100 if row['allowed'] else
                    row['successes'] == 0 and row['denied'] >= 100 for row in rows) and churn_stats['queries'] > 0,
                    released=p.fields(released), state=p.fields(state), readers=rows, churn=churn_stats,
                    forced_owner=(iteration % 2 == 1))
            finally:
                churn_stop.set()
                if clients is not None:
                    clients.stop.set()
                if churn is not None:
                    churn.join(15)
                if clients is not None:
                    self.cleanup_steps(('readers', clients.finish))
                self.cleanup_steps(('source', source.close), ('monitor', monitor.close),
                    ('root', lambda: kernel.CloseHandle(root)),
                    ('foreign', lambda: kernel.CloseHandle(foreign) if foreign.value else None),
                    *((f'child-{child.proc.pid}', lambda child=child: child.close(force=True))
                      for child in (owner, next_owner, target, replacement)))

    def races(self, iterations, readers, seed, last_close=False, reply_change='none'):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for owner_query in (False, True):
                label = f'query-{"last-close" if last_close else "race"}-{iteration}-owner-{"query" if owner_query else "idle"}'
                self.load()
                target, replacement, owner, next_owner = self.reader(), self.reader(), self.child(), self.child()
                monitor, source = p.Port(), p.Port()
                foreign = borrowed(duplicate(w.HANDLE(owner.ready['handle']), int(owner.proc._handle)))
                duplication_root = borrowed(duplicate(source.handle))
                clients, gates, buffers = None, [], []
                actions = ['close', 'duplicate', 'kill', 'arm', 'topology', 'unload']
                if reply_change != 'none':
                    actions.append('buffer')
                order = rng.sample(actions, len(actions))
                barrier, errors, calls = threading.Barrier(len(actions) + 1), [], {}
                original_closing, root_closing, duplicate_observed = threading.Event(), threading.Event(), threading.Event()
                buffers_changed, unload_started = threading.Event(), threading.Event()
                query_count = min(readers, 4)
                unload_delay = rng.choice((.02, .04, .07))

                def actor(action):
                    try:
                        barrier.wait(5)
                        time.sleep(order.index(action) * .002 + (unload_delay if action == 'unload' else 0))
                        began, detail = time.perf_counter_ns(), {}
                        if action == 'buffer':
                            before = monitor.send()
                            assert before.QueryGateCompleted == 0
                            for buffer in buffers:
                                buffer.change()
                            detail['modes'] = [buffer.mode for buffer in buffers]
                            detail['before'] = p.fields(before)
                            buffers_changed.set()
                        elif action == 'close':
                            # Every send on this exact handle is already inside
                            # Message. No user-handle value is used after close.
                            if last_close:
                                before = monitor.send()
                                assert before.QueryGateEntered - before.QueryGateCompleted >= query_count
                                detail['before_close'] = p.fields(before)
                                original_closing.set()
                            source.close()
                            foreign.close()
                        elif action == 'duplicate':
                            detail['queries'] = 0
                            while not clients.unloading.is_set() and (not last_close or detail['queries'] < 16):
                                lease = borrowed(duplicate(duplication_root.handle))
                                try:
                                    coherent(lease.send())
                                    detail['queries'] += 1
                                except OSError as error:
                                    assert clients.unloading.is_set() and str(error) in (
                                        'message: 0x80070006', 'message: 0x801f000b'), error
                                    break
                                finally:
                                    lease.close()
                                duplicate_observed.set()
                                time.sleep(.0002)
                            assert detail['queries'] > 0
                            if last_close:
                                # Finish our own DuplicateHandle calls before
                                # closing their root. With the original closing
                                # concurrently, this exercises last-handle cleanup
                                # while all confirmed Message calls remain live.
                                before = monitor.send()
                                assert before.QueryGateEntered - before.QueryGateCompleted >= query_count
                                detail['before_close'] = p.fields(before)
                                root_closing.set()
                                detail['root_close_started'] = time.perf_counter_ns()
                                duplication_root.close()
                                detail['root_close_completed'] = time.perf_counter_ns()
                        elif action == 'kill':
                            detail['exit'] = self.terminate(owner)
                            assert detail['exit'] == 259
                        elif action == 'arm':
                            replies, deadline = [], time.monotonic() + 3
                            while time.monotonic() < deadline:
                                reply = self.attempt(next_owner, replacement)
                                replies.append(reply)
                                if 'error' not in reply:
                                    self.read(replacement, 0)
                                    detail['read_sent'] = True
                                    break
                                assert reply['error'] in ('message: 0x800700aa', 'message: 0x801f000b',
                                    'message: 0x80070006'), reply
                                if reply['error'] != 'message: 0x800700aa':
                                    break
                                time.sleep(.002)
                            assert replies and (detail.get('read_sent') or replies[-1].get('error') != 'message: 0x800700aa')
                            detail['replies'] = replies
                        elif action == 'topology':
                            instance = p.INSTANCE if iteration % 2 == 0 else p.LOWER
                            hr = flt.FilterDetach(p.NAME, 'C:', instance)
                            detail['detach'] = hr & 0xffffffff
                            assert hr >= 0 or detail['detach'] in (0x801f000b, 0x801f0013, 0x801f0015), detail
                            hr = self.attach(instance)
                            detail['attach'] = hr & 0xffffffff
                            assert hr >= 0 or detail['attach'] in (0x801f000b, 0x801f0013), detail
                        else:
                            # Scheduling jitter may exceed a chosen stagger.
                            # Observe a real duplicate/query/close cycle before
                            # initiating unload instead of assuming it ran.
                            assert duplicate_observed.wait(5)
                            if buffers:
                                assert buffers_changed.wait(5)
                            if last_close:
                                # Both remaining user handles begin closing while
                                # the queries are held. Do not wait for CloseHandle
                                # to return before starting the concurrent unload.
                                assert original_closing.wait(5) and root_closing.wait(5)
                            before = monitor.send()
                            assert before.QueryGateEntered - before.QueryGateCompleted >= query_count, p.fields(before)
                            detail['before'] = p.fields(before)
                            clients.unloading.set()
                            unload_started.set()
                            hr = flt.FilterUnload(p.NAME)
                            assert hr >= 0, hr
                            self.loaded = False
                            detail['hr'] = hr
                        calls[action] = dict(start=began, end=time.perf_counter_ns(), **detail)
                    except BaseException:
                        errors.append(dict(actor=action, error=traceback.format_exc()))

                workers = [threading.Thread(target=actor, args=(action,)) for action in order]
                try:
                    self.arm(owner, target)
                    clients = Readers([(monitor.handle, True), (foreign.handle, False)], readers,
                        fail_start=getattr(self, 'inject_failure', None) == 'reader-start')
                    clients.warmed()
                    if reply_change != 'none':
                        for index in range(query_count):
                            mode = (ReplyBuffer.MODES[(iteration * query_count + index) % len(ReplyBuffer.MODES)]
                                if reply_change == 'mixed' else reply_change)
                            buffers.append(ReplyBuffer(mode))
                    with p.managed.driver_load_privilege():
                        actors_released = False
                        try:
                            for worker in workers:
                                worker.start()
                            handle = w.HANDLE(source.handle.value)
                            gates = [self.background(lambda index=index: raw_query(handle, delay=500,
                                output=buffers[index].output if buffers else None)) for index in range(query_count)]
                            if owner_query:
                                owner.send(action=6, delay=500)
                            held = self.query_hold(monitor, query_count + int(owner_query))
                            self.inject('after-gates')
                            self.inject('cleanup-audit')
                            self.inject('cleanup-log')
                            self.inject('cleanup-command-log')
                            barrier.wait(5)
                            actors_released = True
                            if getattr(self, 'inject_failure', None) in ('during-race', 'reader-error', 'runner-exit'):
                                assert unload_started.wait(5)
                                assert not all(gate[1].is_set() for gate in gates), 'failure missed the live queries'
                                self.record('runner-failure-window', label=label, failure=self.inject_failure,
                                    live_queries=sum(not gate[1].is_set() for gate in gates),
                                    buffer_modes=[buffer.mode for buffer in buffers],
                                    buffers_changed=buffers_changed.is_set(),
                                    original_closing=original_closing.is_set(), root_closing=root_closing.is_set())
                                if self.inject_failure == 'runner-exit':
                                    os._exit(86)  # The supervising job owns crash cleanup.
                                if self.inject_failure == 'reader-error':
                                    clients.errors.append('injected reader assertion')
                                self.inject(self.inject_failure)
                        finally:
                            # Keep SeLoadDriverPrivilege until every native actor
                            # has returned, even when the test body raises early.
                            if not actors_released:
                                barrier.abort()
                            for worker in workers:
                                if worker.ident is not None:
                                    worker.join(15)
                    self.record('query-race-calls', label=label, held=p.fields(held), calls=calls, errors=errors, order=order)
                    state = self.audit(label) if not self.loaded else None
                    self.inject('after-unload')
                    if getattr(self, 'inject_post_unload_failure', False):
                        raise AssertionError('injected failure after observed unload')
                    assert not errors and all(not worker.is_alive() for worker in workers), errors
                    assert state is not None, 'unload did not complete'
                    replies = [self.joined(gate) for gate in gates]
                    if buffers:
                        replies = [buffer.verify(reply, held) for buffer, reply in zip(buffers, replies)]
                        assert state.QueryReplyFailures == sum(buffer.mode != 'overwrite' for buffer in buffers)
                    else:
                        assert all(reply['hr'] == 0 for reply in replies), replies
                    rows = clients.finish()
                    result = None
                    if calls['arm'].get('read_sent'):
                        result = replacement.receive()
                        self.results([result], [0], cancelled=[] if result['ok'] else [0])
                    self.check(label + '-drained', state.QueryActive == 0 and state.QueryStarted == state.QueryCompleted and
                        state.QueryGateEntered == state.QueryGateCompleted == query_count + int(owner_query) and
                        state.OwnerPid == state.ArmedRemaining == state.Connections == 0,
                        held=p.fields(held), state=p.fields(state), calls=calls, order=order,
                        readers=rows, replies=replies, result=result, unload_delay=unload_delay)
                finally:
                    barrier.abort()
                    for worker in workers:
                        if worker.ident is not None:
                            worker.join(15)
                    for gate in gates:
                        gate[0].join(15)
                    self.cleanup_steps(('race-evidence', lambda: self.record('query-race-finally',
                        label=label, calls=calls, errors=errors, queries=[gate[2] for gate in gates],
                        live_actors=[worker.name for worker in workers if worker.is_alive()],
                        live_queries=sum(gate[0].is_alive() for gate in gates))))
                    if not self.loaded and not any(audit['name'] == label for audit in self.audits):
                        self.cleanup_steps(('race-final-audit', lambda: self.audit(label)))
                    # Never unmap an output still in use by a live send.
                    if all(not gate[0].is_alive() for gate in gates):
                        self.cleanup_steps(*((f'reply-buffer-{index}', buffer.close) for index, buffer in enumerate(buffers)))
                    if clients is not None:
                        self.cleanup_steps(('readers', clients.finish))
                    self.cleanup_steps(('source', source.close), ('foreign', foreign.close),
                        ('duplication-root', duplication_root.close), ('monitor', monitor.close),
                        *((f'child-{child.proc.pid}', lambda child=child: child.close(force=True))
                          for child in (owner, next_owner, target, replacement)))
                    self.cleanup_steps(('race-resources', lambda: self.check(label + '-resources-closed',
                        all(not worker.is_alive() for worker in workers) and
                        all(not gate[0].is_alive() for gate in gates) and
                        (clients is None or all(not worker.is_alive() for worker in clients.threads)) and
                        all(not port.handle.value for port in (source, foreign, duplication_root, monitor)) and
                        all(child.proc.poll() is not None for child in (owner, next_owner, target, replacement)))))

    def audit(self, name):
        state = super().audit(name)
        self.inject('audit')
        if name == 'cleanup' and getattr(self, 'inject_failure', None) == 'cleanup-audit':
            raise RuntimeError('injected cleanup audit failure')
        return state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--iterations', type=int, default=4)
    parser.add_argument('--readers', type=int, choices=(2, 4, 8, 16), default=8)
    parser.add_argument('--case', choices=('stress', 'controls', 'races', 'all'), default='all')
    parser.add_argument('--seed', type=int, default=251025)
    parser.add_argument('--last-close', action='store_true', help='close the duplication root during gated races')
    parser.add_argument('--reply-change', choices=('none', 'mixed', *ReplyBuffer.MODES), default='none')
    parser.add_argument('--inject-failure', choices=('reader-start', 'after-gates', 'during-race',
        'reader-error', 'after-unload', 'audit', 'cleanup-audit', 'cleanup-log', 'cleanup-command-log', 'runner-exit'),
        help='fail one race deliberately; exit 1 and recorded failure are expected')
    parser.add_argument('--start-event', help=argparse.SUPPRESS)
    parser.add_argument('--inject-post-unload-failure', action='store_true',
        help='deliberately fail one race after unload to verify failure cleanup (exit 1 expected)')
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100
    assert not args.inject_post_unload_failure or args.case == 'races' and args.iterations == 1
    assert not args.inject_failure or args.case == 'races' and args.iterations == 1
    assert args.inject_failure != 'runner-exit' or args.start_event, 'runner-exit needs the failure supervisor'
    if args.start_event:
        kernel.OpenEventW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
        kernel.OpenEventW.restype = w.HANDLE
        event = kernel.OpenEventW(0x100000, False, args.start_event)
        assert event
        try:
            assert kernel.WaitForSingleObject(event, 30000) == 0, 'supervisor did not assign the job'
        finally:
            kernel.CloseHandle(event)
    suite, completed, started = Suite(args.output, 8), False, time.monotonic()
    suite.inject_post_unload_failure = args.inject_post_unload_failure
    suite.inject_failure = args.inject_failure
    try:
        suite.setup()
        if args.case in ('stress', 'all'):
            suite.stress(args.iterations, args.readers, args.seed)
        if args.case in ('controls', 'all'):
            suite.query_controls(args.iterations)
        if args.case in ('races', 'all'):
            suite.races(args.iterations, args.readers, args.seed, args.last_close, args.reply_change)
        completed = True
    finally:
        original_failure = traceback.format_exc() if sys.exc_info()[0] is not None else None
        if original_failure:
            suite.cleanup_steps(('failure-report', lambda: (suite.output / 'failure.txt').write_text(
                original_failure, encoding='utf-8')))
        errors = suite.cleanup()
        result = dict(passed=completed and not errors and all(row['passed'] for row in suite.checks),
            checks=len(suite.checks), iterations=args.iterations, readers=args.readers,
            case=args.case, seed=args.seed, last_close=args.last_close,
            reply_change=args.reply_change, injected_failure=args.inject_failure or args.inject_post_unload_failure,
            seconds=time.monotonic() - started,
            fixture_sha256=suite.hash, cleanup_errors=errors)
        (suite.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if errors and not original_failure:
            raise RuntimeError(errors)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
