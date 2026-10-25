"""Owned-fixture READ batches across cancellation, detach and unload.

Every surviving READ is checked by slot and content. Each round requires an
observed kernel hold; manual-first rounds also require teardown before unload.
"""
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
spec = importlib.util.spec_from_file_location('race', ROOT / 'tools/run-pending-io-race-e2e.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p, kernel, flt = r.p, r.kernel, r.flt


class Suite(r.Suite):
    def __init__(self, output, count):
        super().__init__(output)
        self.count = count
        self.path.write_bytes(b''.join(bytes([65 + i]) * 4096 for i in range(4)))

    def reader(self):
        child = p.Child('--io-child', self.path, 2 * self.count, script=r.__file__)
        self.children.append(child)
        return child

    @staticmethod
    def read(target, slot, alias=False):
        page = 0 if alias else slot % 4
        target.send(read=True, slot=slot, offset=4096 * page, value=65 + page)

    def arm(self, owner, target, early=False):
        owner.send(action=4 if early else 5, mode=4, pid=target.proc.pid,
            delay=500, Reserved=4 if early else self.count)
        owner.receive()

    def hold(self, observer, admitted, early=False):
        if early:
            predicate = lambda s: s.BeforeLowerEntered == 1 and s.BeforeLowerCompleted == 0
        else:
            predicate = lambda s: (s.PreQueued == admitted and s.QueueDepth == admitted - 1 and
                s.ActiveWorkers == 1 and s.RaceEntered == 1 and s.RaceCompleted == 0 and
                s.Created == admitted * 2 and s.BufferLocks == admitted)
        state = p.wait_state(observer, predicate)
        self.record('held', early=early, state=p.fields(state))
        return state

    @staticmethod
    def results(messages, slots, cancelled=()):
        ios = [m for m in messages if m['kind'] == 'io']
        assert len(ios) == len(slots) and {m['slot'] for m in ios} == set(slots), messages
        for result in ios:
            if result['slot'] in cancelled:
                assert not result['ok'] and result['error'] == 995 and result['bytes'] == 0, result
            else:
                assert result['ok'] and result['bytes'] == 4096 and result['data_matches'], result

    def controls(self, iterations):
        for iteration in range(iterations):
            for case in ('selective', 'partial-exit', 'partial-target-exit', 'upper-drain', 'lower-detach'):
                label = f'control-{iteration}-{case}'
                self.load()
                target, owner = self.reader(), self.child()
                with p.Port() as observer:
                    self.arm(owner, target)
                    admitted = max(1, self.count // 2) if case.startswith('partial-') else self.count
                    for slot in range(admitted):
                        self.read(target, slot)
                    held = self.hold(observer, admitted)
                    assert held.ArmedRemaining == self.count - admitted
                    self.check(label + '-held', held.LiveContexts == admitted * 2, state=p.fields(held))
                    if case == 'selective':
                        # These requests share the same handle, offsets and sizes
                        # with the pending batch, but must complete independently.
                        extras = range(self.count, self.count * 2)
                        for slot in extras:
                            self.read(target, slot)
                        messages = [target.receive() for _ in extras]
                        self.results(messages, extras)
                        during = observer.send()
                        assert during.RaceCompleted == 0 and during.PreQueued == self.count
                        target.send(cancel=True, slot=0)
                        owner.send(action=2)
                        owner.receive()
                        messages += [target.receive() for _ in range(self.count + 1)]
                        self.results(messages, range(2 * self.count), cancelled=(0,))
                        cancels = [m for m in messages if m['kind'] == 'cancel']
                        assert len(cancels) == 1 and cancels[0]['ok'], messages
                        state = p.wait_state(observer, p.balanced)
                        self.check(label + '-isolated-cancel', state.PreCancelled == 1 and
                            state.Created == self.count * 2 and state.ArmedRemaining == 0,
                            state=p.fields(state), messages=messages)
                    elif case == 'partial-exit':
                        owner.close(force=bool(iteration % 2))
                        messages = [target.receive() for _ in range(admitted)]
                        self.results(messages, range(admitted), cancelled=range(admitted))
                        state = p.wait_state(observer, p.balanced)
                        self.read(target, self.count)
                        self.results([target.receive()], [self.count])
                        self.check(label + '-disarmed', state.ArmedRemaining == state.ArmedMode == state.OwnerPid == 0
                            and state.OwnerRestores == 1 and state.PreCancelled == admitted,
                            state=p.fields(state), messages=messages)
                    elif case == 'partial-target-exit':
                        target.close(force=True)
                        state = p.wait_state(observer, p.balanced)
                        self.check(label + '-disarmed', state.ArmedRemaining == state.ArmedMode == 0 and
                            state.OwnerPid == owner.proc.pid and state.PreCancelled == admitted,
                            state=p.fields(state))
                        # The owner survives and must be able to arm another
                        # process after both the admitted and unused refs drain.
                        target = self.reader()
                        self.arm(owner, target)
                        owner.send(action=3)
                        owner.receive()
                        self.read(target, self.count)
                        self.results([target.receive()], [self.count])
                        self.check(label + '-new-target', observer.send().ArmedRemaining == 0)
                    else:
                        instance = p.INSTANCE if case == 'upper-drain' else p.LOWER
                        with p.managed.driver_load_privilege():
                            hr = flt.FilterDetach(p.NAME, 'C:', instance)
                        assert hr >= 0, f'detach: 0x{hr & 0xffffffff:08x}'
                        if case == 'upper-drain':
                            drained = observer.send()
                            self.check(label + '-upper-freed-before-lower', drained.PostDrained == self.count and
                                drained.LiveContexts == self.count and drained.PreCompleted == 0 and
                                drained.RaceCompleted == 0, state=p.fields(drained))
                            owner.send(action=2)
                            owner.receive()
                        messages = [target.receive() for _ in range(self.count)]
                        self.results(messages, range(self.count),
                            cancelled=range(self.count) if case == 'lower-detach' else ())
                        state = p.wait_state(observer, p.balanced)
                        self.check(label + '-detached', state.ManualTeardowns == 1 and
                            state.InstanceStarts == state.InstanceCompletes == 1 and state.LiveInstances == 1,
                            state=p.fields(state), messages=messages)
                        altitude = '370030.12345' if case == 'upper-drain' else '370029.12345'
                        self.run('fltmc.exe', 'attach', p.NAME, 'C:', '-i', instance, '-a', altitude)
                        self.read(target, self.count)
                        self.results([target.receive()], [self.count])
                        self.check(label + '-reattached', observer.send().LiveInstances == 2)
                    owner.close()
                    target.close()
                self.unload(label)

    def races(self, iterations, seed):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for early in (False, True):
                for manual_first in (True, False):
                    label = f'race-{iteration}-{"early" if early else "batch"}-{"manual" if manual_first else "free"}'
                    self.load()
                    target, owner = self.reader(), self.child()
                    observer, duplicate = p.Port(), w.HANDLE()
                    kill_requestor = bool(iteration % 2)
                    if not kill_requestor:
                        assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                            w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                    order = rng.sample(['cancel', 'kill', 'upper', 'lower', 'unload'], 5)
                    barrier, manual_seen = threading.Barrier(6), threading.Event()
                    outcomes, errors = {}, []

                    def actor(action):
                        try:
                            barrier.wait(5)
                            time.sleep(order.index(action) * .002)
                            if action == 'unload' and manual_first:
                                assert manual_seen.wait(2), 'manual teardown did not enter'
                            begin, detail = time.perf_counter_ns(), {}
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
                            elif action == 'unload':
                                hr = flt.FilterUnload(p.NAME)
                                detail['hr'] = hr & 0xffffffff
                                assert hr >= 0, detail
                                self.loaded = False
                            else:
                                hr = flt.FilterDetach(p.NAME, 'C:', p.INSTANCE if action == 'upper' else p.LOWER)
                                detail['hr'] = hr & 0xffffffff
                                # Teardown/unload may win the lookup. Other errors
                                # (including privilege failures) are not accepted.
                                assert hr >= 0 or detail['hr'] in (0x801f000b, 0x801f0013, 0x801f0015), detail
                            outcomes[action] = dict(begin=begin, end=time.perf_counter_ns(), **detail)
                        except BaseException:
                            errors.append(traceback.format_exc())

                    actors = [threading.Thread(target=actor, args=(action,), daemon=True) for action in order]
                    try:
                        # All native lifecycle calls share one process token.
                        # Enable once around the group; per-actor restoration
                        # could remove another actor's still-needed privilege.
                        with p.managed.driver_load_privilege():
                            for thread in actors:
                                thread.start()
                            self.arm(owner, target, early)
                            self.read(target, 0, alias=early)
                            if not early:
                                # Submission order is not kernel arrival order.
                                # Observe slot 0's worker hold before submitting
                                # the rest, so its explicit cancel is sampled by
                                # RaceCancelSeen rather than an arbitrary READ.
                                self.hold(observer, 1)
                                for slot in rng.sample(range(1, self.count), self.count - 1):
                                    self.read(target, slot)
                            held = self.hold(observer, 1 if early else self.count, early)
                            background = []
                            if early:
                                for slot in range(1, self.count * 2):
                                    self.read(target, slot, alias=True)
                                background = [target.receive() for _ in range(self.count * 2 - 1)]
                                self.results(background, range(1, self.count * 2))
                                during = observer.send()
                                assert during.BeforeLowerCompleted == 0 and during.PreQueued == 0
                                assert during.OtherReadSkipped == self.count * 2 - 1
                            self.record('race-release', label=label, order=order, held=p.fields(held),
                                manual_first=manual_first, kill_requestor=kill_requestor, background=background)
                            barrier.wait(5)
                            if manual_first:
                                manual = p.wait_state(observer, lambda s: s.ManualTeardowns > 0, timeout=1)
                                assert manual.Stopping == 0 and (manual.BeforeLowerCompleted if early else manual.RaceCompleted) == 0
                                self.record('manual-observed', label=label, state=p.fields(manual))
                                manual_seen.set()
                            for thread in actors:
                                thread.join(15)
                            assert not errors and all(not t.is_alive() for t in actors), errors
                        messages = []
                        if kill_requestor:
                            target.proc.wait(10)
                        else:
                            amount = 1 if early else self.count
                            messages = [target.receive() for _ in range(amount + 1)]
                            ios = [m for m in messages if m['kind'] == 'io']
                            cancels = [m for m in messages if m['kind'] == 'cancel']
                            assert len(ios) == amount and {m['slot'] for m in ios} == set(range(amount)), messages
                            assert len(cancels) == 1 and (cancels[0]['ok'] or cancels[0]['error'] == 1168), messages
                            assert cancels[0]['started'] < outcomes['unload']['end'], messages
                            for result in ios:
                                assert (result['ok'] and result['bytes'] == 4096 and result['data_matches']) or (
                                    not result['ok'] and result['error'] == 995 and result['bytes'] == 0), result
                            if not early:
                                self.results(messages, range(self.count), cancelled=range(self.count))
                        state = self.audit(label)
                        if early:
                            observed = state.BeforeLowerEntered == state.BeforeLowerCompleted == state.BeforeLowerStopSeen == 1
                        else:
                            observed = state.RaceEntered == state.RaceCompleted == state.RaceCancelSeen == state.RaceStopSeen == 1
                        self.check(label + '-overlap', observed and state.InstanceStarts == state.InstanceCompletes == 2 and
                            state.ManualTeardowns + state.UnloadTeardowns == 2 and
                            (not manual_first or state.ManualTeardowns > 0) and
                            outcomes['kill']['end'] < outcomes['unload']['end'],
                            state=p.fields(state), order=order, calls=outcomes, messages=messages,
                            kill_requestor=kill_requestor, manual_first=manual_first)
                        try:
                            observer.send()
                            raise AssertionError('unloaded port still responds')
                        except OSError:
                            pass
                    finally:
                        barrier.abort()
                        manual_seen.set()
                        for thread in actors:
                            if thread.ident is not None:
                                thread.join(15)
                        observer.close()
                        if duplicate.value:
                            kernel.CloseHandle(duplicate)
                        owner.close(force=True)
                        target.close(force=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--iterations', type=int, default=12)
    parser.add_argument('--reads', type=int, default=8, choices=(2, 4, 8))
    parser.add_argument('--case', choices=('controls', 'races', 'all'), default='all')
    parser.add_argument('--seed', type=int, default=20261025)
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100
    suite, completed, started = Suite(args.output, args.reads), False, time.monotonic()
    try:
        suite.setup()
        if args.case != 'races':
            suite.controls(args.iterations)
        if args.case != 'controls':
            suite.races(args.iterations, args.seed)
        completed = True
    finally:
        errors = suite.cleanup()
        result = dict(passed=completed and not errors and all(x['passed'] for x in suite.checks),
            checks=len(suite.checks), iterations=args.iterations, reads=args.reads, case=args.case,
            seed=args.seed, fixture_sha256=suite.hash, seconds=time.monotonic() - started, cleanup_errors=errors)
        (suite.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        if errors:
            raise RuntimeError(errors)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        traceback.print_exc()
        sys.exit(1)
