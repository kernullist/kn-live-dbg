"""Owned-fixture target-watch snapshots against ARM and lifecycle transitions."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import importlib.util
import json
import pathlib
import random
import sys
import threading
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rearm', ROOT / 'tools/run-pending-rearm-e2e.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p, kernel, flt = r.p, r.kernel, r.flt


class Suite(r.Suite):
    def watch_arm(self, owner, target, gate):
        owner.send(action=4, mode=4, pid=target.proc.pid, delay=500, Reserved=gate)
        return owner.receive()

    def watch_hold(self, observer, gate):
        samples, deadline = [], time.monotonic() + 2
        while time.monotonic() < deadline:
            began = time.perf_counter_ns()
            state = observer.send()
            samples.append(dict(microseconds=(time.perf_counter_ns() - began) / 1000,
                entered=state.WatchGateEntered, completed=state.WatchGateCompleted))
            if state.WatchGateEntered and state.WatchGateKind == gate:
                break
            time.sleep(.001)
        return state, samples

    def enter_watch(self, label, owner, target, observer, gate):
        if gate == 32:
            # Admit after the exit notification's cancellation sweep, while a
            # code-259 process is not yet signaled. The watch must detect it.
            self.watch_arm(owner, target, 8)
            assert kernel.TerminateProcess(w.HANDLE(int(target.proc._handle)), 259)
            tail = p.wait_state(observer, lambda s: s.TargetExitGateEntered == 1 and s.TargetExitGateCompleted == 0)
            assert tail.ArmedRemaining == 0
            self.watch_arm(owner, target, gate)
            admitted = observer.send()
            assert admitted.TargetExitGateCompleted == 0 and admitted.ArmedRemaining == 1
            target.proc.wait(10)
            assert target.proc.returncode == 259
            self.record('exit-tail-watch-admission', label=label, tail=p.fields(tail), admitted=p.fields(admitted))
        else:
            self.watch_arm(owner, target, gate)
        held, samples = self.watch_hold(observer, gate)
        self.check(label + '-watch-held', held.WatchGateEntered == 1 and held.WatchGateCompleted == 0 and
            held.WatchGateKind == gate and held.WatchGateTargetPid == target.proc.pid and
            held.WatchGateStatus == (259 if gate == 16 else 0xc000010a), held=p.fields(held), samples=samples)
        return held

    @staticmethod
    def background(call):
        outcome, entered, done = {}, threading.Event(), threading.Event()

        def run():
            entered.set()
            try:
                outcome['value'] = call()
            except BaseException:
                outcome['error'] = traceback.format_exc()
            finally:
                done.set()

        worker = threading.Thread(target=run)
        worker.start()
        assert entered.wait(2)
        return worker, done, outcome

    def blocked(self, label, observer, work):
        worker, done, outcome = work
        done.wait(.025)
        state = observer.send()
        self.check(label + '-serialized', state.WatchGateCompleted == 0 and not done.is_set(),
            state=p.fields(state), outcome=outcome)
        return state

    @staticmethod
    def joined(work):
        worker, done, outcome = work
        worker.join(15)
        assert not worker.is_alive() and done.is_set() and 'error' not in outcome, outcome
        return outcome['value']

    @staticmethod
    def terminate(child):
        assert kernel.TerminateProcess(w.HANDLE(int(child.proc._handle)), 259)
        return child.proc.wait(10)

    @staticmethod
    def release(owner):
        owner.send(action=3)
        return owner.receive()

    def controls(self, iterations):
        cases = [(16, 'same-upper'), (16, 'new-upper'), (16, 'new-lower'),
            (32, 'new-upper'), (32, 'new-lower'), (32, 'retire'),
            (16, 'release'), (32, 'release'), (16, 'owner-exit'), (32, 'owner-exit'),
            (16, 'target-exit'), (16, 'cancel'), (16, 'unload'), (32, 'unload')]
        for iteration in range(iterations):
            for gate, case in cases:
                label = f'watch-{gate}-{case}-{iteration}'
                self.load()
                target, live, owner = self.reader(), self.reader(), self.child()
                observer, duplicate, work = p.Port(), w.HANDLE(), None
                assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                    w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                try:
                    # All actors and ports exist before the bounded kernel hold.
                    with p.managed.driver_load_privilege():
                        held = self.enter_watch(label, owner, target, observer, gate)
                        if case.startswith(('same-', 'new-')):
                            instance = p.LOWER if case.endswith('lower') else p.INSTANCE
                            assert flt.FilterDetach(p.NAME, 'C:', instance) >= 0
                            assert self.attach(instance) >= 0
                            replaced = observer.send()
                            assert replaced.WatchGateCompleted == 0 and replaced.ArmedRemaining == 0
                            next_target = target if case.startswith('same-') else live
                            work = self.background(lambda: self.attempt(owner, next_target))
                            self.blocked(label, observer, work)
                            reply = self.joined(work)
                            assert 'error' not in reply and reply['WatchGateCompleted'] == 1
                            self.read(next_target, 0)
                            p.wait_state(observer, lambda s: s.PreQueued == 1 and s.RaceEntered == 1)
                            owner.send(action=2)
                            owner.receive()
                            result = next_target.receive()
                            self.results([result], [0])
                            # An old live requestor must not consume the new arm.
                            if gate == 16 and next_target is live:
                                self.read(target, 1)
                                self.results([target.receive()], [1])
                            state = p.wait_state(observer, p.balanced)
                            self.check(label + '-new-arm-preserved', state.TargetWatchStaleResults == 1 and
                                state.TargetWatchRetires == 0 and state.ArmedRemaining == self.count - 1 and
                                state.ArmedGeneration == state.TopologyGeneration and state.PreQueued == 1,
                                held=p.fields(held), replaced=p.fields(replaced), state=p.fields(state), reply=reply)
                            self.release(owner)
                        elif case == 'retire':
                            state = p.wait_state(observer, lambda s: p.balanced(s) and s.ArmedRemaining == 0)
                            self.check(label + '-retired', state.TargetWatchRetires == 1 and
                                state.TargetWatchStaleResults == 0 and state.OwnerPid == owner.proc.pid,
                                state=p.fields(state))
                        elif case == 'cancel':
                            self.read(target, 0)
                            queued = p.wait_state(observer, lambda s: s.PreQueued == 1 and s.QueueDepth == 1)
                            assert queued.ActiveWorkers == 0 and queued.WatchGateCompleted == 0
                            for slot in range(1, self.count):
                                self.read(target, slot)
                            self.results([target.receive() for _ in range(1, self.count)], range(1, self.count))
                            self.read(live, 0)
                            self.results([live.receive()], [0])
                            target.send(cancel=True, slot=0)
                            cancelled = target.receive()
                            during = observer.send()
                            assert cancelled['kind'] == 'cancel' and cancelled['ok'] and during.WatchGateCompleted == 0
                            result = target.receive()
                            self.results([result], [0], cancelled=[0])
                            state = p.wait_state(observer, p.balanced)
                            self.check(label + '-only-held-read-cancelled', state.Created == 2 and
                                state.PreQueued == state.PreCancelled == state.TargetWatchStaleResults == 1,
                                queued=p.fields(queued), during=p.fields(during), state=p.fields(state), result=result)
                            self.release(owner)
                        else:
                            call = (lambda: self.release(owner)) if case == 'release' else (
                                (lambda: self.terminate(owner)) if case == 'owner-exit' else (
                                (lambda: self.terminate(target)) if case == 'target-exit' else
                                (lambda: flt.FilterUnload(p.NAME))))
                            work = self.background(call)
                            self.blocked(label, observer, work)
                            value = self.joined(work)
                            if case == 'unload':
                                assert value >= 0, value
                                self.loaded = False
                                state = self.audit(label)
                                self.check(label + '-joined-watch', state.WatchGateEntered == state.WatchGateCompleted == 1,
                                    state=p.fields(state))
                                try:
                                    observer.send()
                                    raise AssertionError('unloaded port still responds')
                                except OSError:
                                    pass
                            else:
                                state = p.wait_state(observer, lambda s: p.balanced(s) and s.ArmedRemaining == 0)
                                self.check(label + '-retired', state.OwnerPid == (owner.proc.pid if case == 'target-exit' else 0)
                                    and (case != 'owner-exit' or state.OwnerRestores == 1), state=p.fields(state), reply=value)
                    if self.loaded:
                        if case == 'owner-exit':
                            owner = self.child()
                        self.fresh_arm(label, owner, live, observer)
                        owner.close()
                        target.close(force=gate == 32 or case == 'target-exit')
                        live.close()
                        self.unload(label)
                finally:
                    if work is not None:
                        work[0].join(15)
                    observer.close()
                    if duplicate.value:
                        kernel.CloseHandle(duplicate)
                    owner.close(force=True)
                    target.close(force=True)
                    live.close(force=True)

    def query_watch(self, iterations):
        for iteration in range(iterations):
            label = f'query-watch-{iteration}'
            self.load()
            target, owner = self.reader(), self.child()
            with p.Port() as observer:
                duplicate = w.HANDLE()
                assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                    w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                try:
                    self.enter_watch(label, owner, target, observer, 16)
                    borrowed = p.Port.__new__(p.Port)
                    borrowed.handle = duplicate
                    try:
                        borrowed.send()
                        raise AssertionError('foreign process queried a duplicated client')
                    except OSError as error:
                        assert str(error) == 'message: 0x80070005', error
                    state = observer.send()
                    self.check(label + '-identity-preserved', state.WatchGateCompleted == 0 and
                        state.OwnerPid == owner.proc.pid and state.ArmedRemaining == 1, state=p.fields(state))
                    self.release(owner)
                finally:
                    kernel.CloseHandle(duplicate)
                p.wait_state(observer, p.balanced)
                self.fresh_arm(label, owner, target, observer)
                owner.close()
                target.close()
            self.unload(label)

    def watch_races(self, iterations, seed):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for gate in (16, 32):
                for killed in ('owner', 'target', 'both'):
                    label = f'watch-race-{gate}-{killed}-{iteration}'
                    self.load()
                    target, live, owner = self.reader(), self.reader(), self.child()
                    observer, duplicate = p.Port(), w.HANDLE()
                    assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                        w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                    requestor = target if gate == 16 else live
                    # For the failed-result phase the old requestor has already
                    # exited. The replacement's completed slot is a negative
                    # cancellation control, not evidence of pending cancellation.
                    if gate == 32:
                        self.read(live, 0)
                        self.results([live.receive()], [0])
                    order = rng.sample(['arm', 'cancel', 'kill', 'topology', 'late', 'unload'], 6)
                    barrier, cancel_done, command_lock = threading.Barrier(7), threading.Event(), threading.Lock()
                    calls, errors, messages = {}, [], []

                    def actor(action):
                        try:
                            barrier.wait(5)
                            time.sleep(order.index(action) * .002)
                            began, detail = time.perf_counter_ns(), {}
                            if action == 'arm':
                                try:
                                    detail['reply'] = self.attempt(owner, live)
                                except (OSError, RuntimeError):
                                    assert killed in ('owner', 'both')
                                    assert owner.proc.wait(10) == 259
                                    detail['owner_exited_before_reply'] = True
                            elif action == 'cancel':
                                with command_lock:
                                    requestor.send(cancel=True, slot=0)
                                while True:
                                    message = requestor.receive()
                                    if message['kind'] == 'cancel':
                                        detail['result'] = message
                                        assert message['ok'] if gate == 16 else (message['ok'] or message['error'] == 1168)
                                        break
                                    messages.append(message)
                                cancel_done.set()
                            elif action == 'kill':
                                # Confirm native cancellation before forced exit
                                # can destroy the child's reply pipe. Both still
                                # overlap the held watch, re-ARM and unload.
                                assert cancel_done.wait(5)
                                detail['after_native_cancel'] = True
                                if killed in ('owner', 'both'):
                                    assert kernel.TerminateProcess(w.HANDLE(int(owner.proc._handle)), 259)
                                if killed in ('target', 'both'):
                                    assert kernel.TerminateProcess(w.HANDLE(int(requestor.proc._handle)), 259)
                                if killed in ('owner', 'both'):
                                    detail['owner_exit'] = owner.proc.wait(10)
                                    assert detail['owner_exit'] == 259
                                if killed in ('target', 'both'):
                                    detail['requestor_exit'] = requestor.proc.wait(10)
                                    assert detail['requestor_exit'] == 259
                            elif action == 'topology':
                                instance = p.INSTANCE if iteration % 2 == 0 else p.LOWER
                                hr = flt.FilterDetach(p.NAME, 'C:', instance)
                                detail['detach'] = hr & 0xffffffff
                                assert hr >= 0 or detail['detach'] in (0x801f000b, 0x801f0013, 0x801f0015), detail
                                hr = self.attach(instance)
                                detail['attach'] = hr & 0xffffffff
                                assert hr >= 0 or detail['attach'] in (0x801f000b, 0x801f0013), detail
                            elif action == 'late':
                                detail['sent'] = 0
                                for slot in range(1, self.count):
                                    try:
                                        with command_lock:
                                            self.read(live, slot)
                                        detail['sent'] += 1
                                    except OSError:
                                        assert gate == 32 and killed in ('target', 'both')
                                        break
                            else:
                                hr = flt.FilterUnload(p.NAME)
                                assert hr >= 0, hr
                                detail['unload'] = hr
                            calls[action] = dict(start=began, end=time.perf_counter_ns(), **detail)
                        except BaseException:
                            errors.append(dict(actor=action, error=traceback.format_exc()))

                    workers = [threading.Thread(target=actor, args=(action,)) for action in order]
                    try:
                        with p.managed.driver_load_privilege():
                            for worker in workers:
                                worker.start()
                            held = self.enter_watch(label, owner, target, observer, gate)
                            if gate == 16:
                                self.read(target, 0)
                                queued = p.wait_state(observer, lambda s: s.PreQueued == 1 and s.QueueDepth == 1)
                                assert queued.WatchGateCompleted == queued.ActiveWorkers == 0
                            barrier.wait(5)
                            time.sleep(.04)
                            during = observer.send()
                            assert during.WatchGateCompleted == 0, p.fields(during)
                            for worker in workers:
                                worker.join(15)
                            assert not errors and all(not worker.is_alive() for worker in workers), errors
                        self.loaded = False
                        state = self.audit(label)
                        reply = calls['arm'].get('reply')
                        if reply and 'error' in reply:
                            assert reply['error'] in ('message: 0x800700aa', 'message: 0x801f000b',
                                'message: 0x80070006', 'message: 0x80070005'), reply
                            if reply['error'] == 'message: 0x80070005':
                                assert state.TargetArmRejected > 0
                        if gate == 16 and killed == 'owner':
                            self.results([target.receive()], [0], cancelled=[0])
                        if gate == 16 or killed == 'owner':
                            expected = calls['late']['sent']
                            while len(messages) < expected:
                                messages.append(live.receive())
                            self.results(messages, range(1, expected + 1))
                        self.check(label + '-settled', state.WatchGateEntered == state.WatchGateCompleted == 1 and
                            state.TargetWatchStaleResults + state.TargetWatchRetires == 1 and
                            (gate != 16 or state.PreQueued >= 1 and state.PreCancelled >= 1),
                            held=p.fields(held), during=p.fields(during), state=p.fields(state), calls=calls,
                            order=order, messages=messages, actual_pending_cancel=(gate == 16))
                        try:
                            observer.send()
                            raise AssertionError('unloaded port still responds')
                        except OSError:
                            pass
                    finally:
                        barrier.abort()
                        for worker in workers:
                            if worker.ident is not None:
                                worker.join(15)
                        observer.close()
                        if duplicate.value:
                            kernel.CloseHandle(duplicate)
                        owner.close(force=True)
                        target.close(force=True)
                        live.close(force=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--iterations', type=int, default=4)
    parser.add_argument('--reads', type=int, default=8, choices=(2, 4, 8))
    parser.add_argument('--case', choices=('query', 'controls', 'races', 'all'), default='all')
    parser.add_argument('--seed', type=int, default=251025)
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100
    suite, completed, started = Suite(args.output, args.reads), False, time.monotonic()
    try:
        suite.setup()
        if args.case in ('query', 'all'):
            suite.query_watch(args.iterations)
        if args.case in ('controls', 'all'):
            suite.controls(args.iterations)
        if args.case in ('races', 'all'):
            suite.watch_races(args.iterations, args.seed)
        completed = True
    finally:
        if sys.exc_info()[0] is not None:
            (suite.output / 'failure.txt').write_text(traceback.format_exc(), encoding='utf-8')
        errors = suite.cleanup()
        result = dict(passed=completed and not errors and all(row['passed'] for row in suite.checks),
            checks=len(suite.checks), iterations=args.iterations, reads=args.reads,
            case=args.case, seed=args.seed, seconds=time.monotonic() - started,
            fixture_sha256=suite.hash, cleanup_errors=errors)
        (suite.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if errors:
            raise RuntimeError(errors)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
