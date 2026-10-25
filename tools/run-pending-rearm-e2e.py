"""Owned-fixture ARM admission across target exit and instance replacement."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import importlib.util
import json
import pathlib
import queue
import random
import sys
import threading
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('partial', ROOT / 'tools/run-pending-partial-e2e.py')
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
p, kernel, flt = q.p, q.kernel, q.flt
kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
kernel.TerminateProcess.restype = w.BOOL


class Suite(q.Suite):
    def attempt(self, owner, target):
        owner.send(action=5, mode=4, pid=target.proc.pid, delay=500,
            Reserved=self.count, expect_error=True)
        return owner.receive()

    def dead_target(self, iterations, methods):
        for iteration in range(iterations):
            for method in methods:
                label = f'dead-{method}-{iteration}'
                self.load()
                target, owner = self.reader(), self.child()
                with p.Port() as observer:
                    before = observer.send()
                    if method == 'normal':
                        target.close()
                    else:
                        code = 259 if method == 'pending-status' else 1
                        assert kernel.TerminateProcess(w.HANDLE(int(target.proc._handle)), code)
                        target.proc.wait(10)
                    # Popen's process handle remains open. A referenceable process
                    # object must not be mistaken for a process still able to issue I/O.
                    reply = self.attempt(owner, target)
                    state = observer.send()
                    self.check(label + '-rejected', 'error' in reply and
                        state.ArmedMode == state.ArmedRemaining == state.OwnerPid == 0 and state.TargetArmRejected == 1,
                        before=p.fields(before), state=p.fields(state), reply=reply,
                        target_pid=target.proc.pid, target_exit=target.proc.returncode)
                    live = self.reader()
                    self.fresh_arm(label, owner, live, observer)
                    live.close()
                    owner.close()
                    target.close(force=True)
                self.unload(label)

    def exit_tail(self, iterations):
        for iteration in range(iterations):
            for method in ('retire', 'new-target', 'unload'):
                label = f'exit-tail-{method}-{iteration}'
                self.load()
                target, owner = self.reader(), self.child()
                # Process startup is unbounded relative to the 500 ms gate.
                # Prepare the replacement before entering the measured window.
                live = self.reader() if method == 'new-target' else target
                observer = p.Port()
                try:
                    owner.send(action=4, mode=4, pid=target.proc.pid, delay=500, Reserved=8)
                    owner.receive()
                    assert kernel.TerminateProcess(w.HANDLE(int(target.proc._handle)), 259)
                    held = p.wait_state(observer, lambda s: s.TargetExitGateEntered == 1 and s.TargetExitGateCompleted == 0)
                    assert held.ArmedRemaining == 0 and held.OwnerPid == owner.proc.pid, p.fields(held)
                    reply = self.attempt(owner, live)
                    assert 'error' not in reply, reply
                    during = observer.send()
                    self.record('exit-tail-rearmed', label=label, target_pid=target.proc.pid,
                        new_target_pid=live.proc.pid, held=p.fields(held), during=p.fields(during), reply=reply)
                    assert during.TargetExitGateCompleted == 0 and during.ArmedRemaining == self.count, p.fields(during)
                    if method == 'unload':
                        began = time.perf_counter_ns()
                        state = self.unload(label)
                        target.proc.wait(10)
                        self.check(label + '-joined', state.TargetExitGateEntered == state.TargetExitGateCompleted ==
                            state.TargetExitGateStopSeen == 1, held=p.fields(held), during=p.fields(during),
                            state=p.fields(state), duration_ms=(time.perf_counter_ns() - began) / 1e6)
                        try:
                            observer.send()
                            raise AssertionError('unloaded port still responds')
                        except OSError:
                            pass
                    elif method == 'new-target':
                        self.read(live, 0)
                        p.wait_state(observer, lambda s: s.PreQueued == 1 and s.RaceEntered == 1 and s.RaceCompleted == 0)
                        target.proc.wait(10)
                        owner.send(action=2)
                        owner.receive()
                        result = live.receive()
                        self.results([result], [0])
                        state = p.wait_state(observer, p.balanced)
                        self.check(label + '-preserved', state.ArmedRemaining == self.count - 1 and
                            state.TargetWatchRetires == 0 and state.TargetExitGateCompleted == 1,
                            held=p.fields(held), during=p.fields(during), state=p.fields(state), result=result)
                        owner.send(action=3)
                        owner.receive()
                        live.close()
                    else:
                        target.proc.wait(10)
                        state = p.wait_state(observer, lambda s: p.balanced(s) and s.ArmedRemaining == 0)
                        self.check(label + '-retired', state.TargetWatchRetires == 1 and
                            state.OwnerPid == owner.proc.pid and state.ArmedGeneration == 0,
                            held=p.fields(held), during=p.fields(during), state=p.fields(state), reply=reply)
                        live = self.reader()
                        self.fresh_arm(label, owner, live, observer)
                        live.close()
                    owner.close()
                    target.close(force=True)
                finally:
                    observer.close()
                if self.loaded:
                    self.unload(label)

    def rebind(self, iterations, submitted, seed):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for instance in (p.INSTANCE, p.LOWER):
                label = f'rebind-{iteration}-{"upper" if instance == p.INSTANCE else "lower"}'
                self.load()
                target, owner = self.reader(), self.child()
                with p.Port() as observer:
                    held = self.partial(owner, target, observer, submitted)
                    with p.managed.driver_load_privilege():
                        assert flt.FilterDetach(p.NAME, 'C:', instance) >= 0
                    owner.send(action=2)
                    owner.receive()
                    old = [target.receive() for _ in range(submitted)]
                    self.results(old, range(submitted), cancelled=range(submitted) if instance == p.LOWER else ())
                    p.wait_state(observer, p.balanced)
                    barrier, outcomes, errors = threading.Barrier(4), {}, []
                    order = rng.sample(['arm', 'attach', 'late'], 3)

                    def actor(action):
                        try:
                            barrier.wait(5)
                            time.sleep(order.index(action) * .002)
                            began = time.perf_counter_ns()
                            if action == 'arm':
                                detail = dict(reply=self.attempt(owner, target))
                            elif action == 'attach':
                                hr = self.attach(instance)
                                assert hr >= 0, hr
                                detail = dict(hr=hr)
                            else:
                                for slot in range(submitted, self.count):
                                    self.read(target, slot)
                                detail = dict(sent=self.count - submitted)
                            outcomes[action] = dict(start=began, end=time.perf_counter_ns(), **detail)
                        except BaseException:
                            errors.append(traceback.format_exc())

                    workers = [threading.Thread(target=actor, args=(action,)) for action in order]
                    with p.managed.driver_load_privilege():
                        for worker in workers:
                            worker.start()
                        barrier.wait(5)
                        for worker in workers:
                            worker.join(15)
                        assert not errors and all(not worker.is_alive() for worker in workers), errors
                    assert 'error' not in outcomes['arm']['reply'], outcomes
                    # Submission can precede or follow admission. Resume every
                    # observed cohort until all commands have completed.
                    messages, deadline = [], time.monotonic() + 5
                    while len(messages) < self.count - submitted and time.monotonic() < deadline:
                        owner.send(action=2)
                        owner.receive()
                        try:
                            messages.append(target.receive(timeout=.02))
                        except queue.Empty:
                            pass
                    self.results(messages, range(submitted, self.count))
                    state = p.wait_state(observer, p.balanced)
                    self.check(label + '-generation', state.BatchArms == 2 and state.LiveInstances == 2 and
                        (state.ArmedMode == 0 or state.ArmedGeneration == state.TopologyGeneration),
                        held=p.fields(held), state=p.fields(state), calls=outcomes, order=order, old=old, messages=messages)
                    owner.send(action=3)
                    owner.receive()
                    self.fresh_arm(label, owner, target, observer)
                    owner.close()
                    target.close()
                self.unload(label)

    def admission_races(self, iterations, submitted, seed):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for killed in ('owner', 'target', 'both'):
                label = f'admission-{iteration}-{killed}'
                self.load()
                target, owner = self.reader(), self.child()
                observer, duplicate = p.Port(), w.HANDLE()
                assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                    w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                order = rng.sample(['arm', 'kill', 'topology', 'late', 'cancel'], 5)
                barrier, commands = threading.Barrier(6), threading.Lock()
                outcomes, errors = {}, []

                def actor(action):
                    try:
                        barrier.wait(5)
                        time.sleep(order.index(action) * .002)
                        began, detail = time.perf_counter_ns(), {}
                        if action == 'arm':
                            try:
                                detail['reply'] = self.attempt(owner, target)
                            except (OSError, RuntimeError):
                                assert killed in ('owner', 'both')
                                owner.proc.wait(10)
                                detail['owner_exited'] = owner.proc.returncode
                        elif action == 'kill':
                            if killed in ('owner', 'both'):
                                owner.proc.terminate()
                            if killed in ('target', 'both'):
                                code = 259 if iteration % 2 else 1
                                assert kernel.TerminateProcess(w.HANDLE(int(target.proc._handle)), code)
                                detail['target_code'] = code
                            if killed in ('owner', 'both'):
                                owner.proc.wait(10)
                        elif action == 'topology':
                            assert flt.FilterDetach(p.NAME, 'C:', p.LOWER) >= 0
                            assert self.attach(p.LOWER) >= 0
                        else:
                            detail['sent'] = 0
                            try:
                                slots = range(submitted) if action == 'late' else [0]
                                for slot in slots:
                                    with commands:
                                        if action == 'late':
                                            self.read(target, slot)
                                        else:
                                            target.send(cancel=True, slot=slot)
                                    detail['sent'] += 1
                            except OSError:
                                assert killed in ('target', 'both')
                        outcomes[action] = dict(start=began, end=time.perf_counter_ns(), **detail)
                    except BaseException:
                        errors.append(dict(actor=action, error=traceback.format_exc()))

                workers = [threading.Thread(target=actor, args=(action,)) for action in order]
                try:
                    with p.managed.driver_load_privilege():
                        for worker in workers:
                            worker.start()
                        barrier.wait(5)
                        for worker in workers:
                            worker.join(15)
                        assert not errors and all(not worker.is_alive() for worker in workers), errors
                    messages = []
                    if killed in ('target', 'both'):
                        target.proc.wait(10)
                    else:
                        messages = [target.receive() for _ in range(submitted + 1)]
                        ios = [row for row in messages if row['kind'] == 'io']
                        cancels = [row for row in messages if row['kind'] == 'cancel']
                        assert len(ios) == submitted and {row['slot'] for row in ios} == set(range(submitted))
                        assert len(cancels) == 1 and (cancels[0]['ok'] or cancels[0]['error'] == 1168)
                        for row in ios:
                            assert (row['ok'] and row['bytes'] == 4096 and row['data_matches']) or (
                                not row['ok'] and row['error'] == 995 and row['bytes'] == 0), row
                    state = p.wait_state(observer, lambda s: p.balanced(s) and s.ArmedRemaining == 0)
                    reply = outcomes['arm'].get('reply')
                    if reply is not None:
                        error = reply.get('error')
                        if error:
                            assert ((error == 'message: 0x80070005' and state.TargetArmRejected == 1) or
                                (error == 'message: 0x800700aa' and state.ArmDuringTeardownRejected == 1)), reply
                        else:
                            assert state.BatchArms == 1
                    self.check(label + '-settled-before-unload', state.Stopping == 0 and state.ArmedGeneration == 0 and
                        state.BatchArms in (0, 1) and state.LiveInstances == 2 and
                        (killed == 'target' or state.OwnerPid == 0),
                        state=p.fields(state), calls=outcomes, order=order, messages=messages, killed=killed)
                    self.unload(label)
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--iterations', type=int, default=4)
    parser.add_argument('--reads', type=int, default=8, choices=(2, 4, 8))
    parser.add_argument('--case', choices=('normal', 'forced', 'pending-status', 'dead', 'exit-tail', 'rebind',
        'admission', 'races', 'all'), default='all')
    parser.add_argument('--submitted', type=int, default=2)
    parser.add_argument('--seed', type=int, default=251025)
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100 and 1 <= args.submitted < args.reads
    suite, completed, started = Suite(args.output, args.reads), False, time.monotonic()
    try:
        suite.setup()
        if args.case in ('normal', 'forced', 'pending-status', 'dead', 'all'):
            suite.dead_target(args.iterations,
                ['normal', 'forced', 'pending-status'] if args.case in ('dead', 'all') else [args.case])
        if args.case in ('exit-tail', 'all'):
            suite.exit_tail(args.iterations)
        if args.case in ('rebind', 'all'):
            suite.rebind(args.iterations, args.submitted, args.seed)
        if args.case in ('races', 'all'):
            suite.partial_races(args.iterations, args.submitted, args.seed, rearm=True)
        if args.case in ('admission', 'all'):
            suite.admission_races(args.iterations, args.submitted, args.seed)
        completed = True
    finally:
        if sys.exc_info()[0] is not None:
            (suite.output / 'failure.txt').write_text(traceback.format_exc(), encoding='utf-8')
        errors = suite.cleanup()
        result = dict(passed=completed and not errors and all(row['passed'] for row in suite.checks),
            checks=len(suite.checks), iterations=args.iterations, reads=args.reads,
            case=args.case, submitted=args.submitted, seed=args.seed, seconds=time.monotonic() - started,
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
