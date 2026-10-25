"""Owned-fixture partial READ reservations across topology and owner changes.

Only this repository's fixture is attached/detached. The first READ's bounded
kernel gate must be observed before concurrent cancellation and lifecycle calls.
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
spec = importlib.util.spec_from_file_location('multi', ROOT / 'tools/run-pending-multiread-e2e.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
p, kernel, flt = m.p, m.kernel, m.flt
flt.FilterAttachAtAltitude.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.LPCWSTR, w.DWORD, w.LPWSTR]
flt.FilterAttachAtAltitude.restype = c.c_long


class Suite(m.Suite):
    @staticmethod
    def attach(instance):
        altitude = '370030.12345' if instance == p.INSTANCE else '370029.12345'
        return flt.FilterAttachAtAltitude(p.NAME, 'C:', altitude, instance, 0, None)

    def fresh_arm(self, label, owner, target, observer):
        before = observer.send()
        self.arm(owner, target)
        armed = observer.send()
        assert armed.ArmedGeneration == armed.TopologyGeneration and armed.ArmedRemaining == self.count
        self.read(target, 0)
        held = p.wait_state(observer, lambda s: s.PreQueued == before.PreQueued + 1 and
            s.RaceEntered == before.RaceEntered + 1 and s.RaceCompleted == before.RaceCompleted)
        owner.send(action=3)
        owner.receive()
        result = target.receive()
        self.results([result], [0], cancelled=[0])
        state = p.wait_state(observer, p.balanced)
        self.check(label + '-fresh-arm', state.ArmedMode == state.ArmedRemaining == state.OwnerPid == 0,
            held=p.fields(held), after=p.fields(state), result=result)

    def partial(self, owner, target, observer, submitted):
        self.arm(owner, target)
        # Arrival order need not match submission order. Establish slot zero as
        # the gated IRP before sending the other commands, so CancelIoEx targets it.
        self.read(target, 0)
        self.hold(observer, 1)
        for slot in range(1, submitted):
            self.read(target, slot)
        held = self.hold(observer, submitted)
        assert held.ArmedRemaining == self.count - submitted > 0
        assert held.ArmedGeneration == held.TopologyGeneration
        return held

    def regressions(self, iterations, cases, submitted):
        for iteration in range(iterations):
            for case in cases:
                label = f'{case}-{iteration}'
                self.load()
                target, owner = self.reader(), self.child()
                with p.Port() as observer:
                    if case == 'pair':
                        self.arm(owner, target, early=True)
                        self.read(target, 0)
                        held = self.hold(observer, 1, early=True)
                        with p.managed.driver_load_privilege():
                            assert flt.FilterDetach(p.NAME, 'C:', p.LOWER) >= 0
                            assert self.attach(p.LOWER) >= 0
                        replaced = observer.send()
                        assert replaced.BeforeLowerCompleted == 0 and replaced.OwnerPid == owner.proc.pid
                        result = target.receive()
                        state = p.wait_state(observer, p.balanced)
                        self.results([result], [0])
                        self.check(label + '-old-upper-new-lower', state.Created == 1 and state.PreQueued == 0 and
                            state.GenerationLowerRejected == 1,
                            held=p.fields(held), replaced=p.fields(replaced), after=p.fields(state), result=result)
                    else:
                        held = self.partial(owner, target, observer, submitted)
                        instance = p.INSTANCE if case == 'reservation-upper' else p.LOWER
                        with p.managed.driver_load_privilege():
                            assert flt.FilterDetach(p.NAME, 'C:', instance) >= 0
                        owner.send(action=2)
                        owner.receive()
                        results = [target.receive() for _ in range(submitted)]
                        self.results(results, range(submitted),
                            cancelled=range(submitted) if instance == p.LOWER else ())
                        p.wait_state(observer, p.balanced)
                        if case == 'reservation-lower-gap':
                            # An explicit new reservation made with only the
                            # upper instance present must also retire on attach.
                            self.arm(owner, target)
                            gap = observer.send()
                            assert gap.ArmedRemaining == self.count and gap.LiveInstances == 1
                            assert gap.ArmedGeneration == gap.TopologyGeneration
                            self.record('armed-between-instances', label=label, state=p.fields(gap))
                        with p.managed.driver_load_privilege():
                            assert self.attach(instance) >= 0
                        replaced = observer.send()
                        self.read(target, self.count)
                        result = target.receive()
                        self.results([result], [self.count])
                        state = p.wait_state(observer, p.balanced)
                        self.check(label + '-no-inherited-reservation', replaced.ArmedRemaining == replaced.ArmedMode == 0 and
                            replaced.ArmedGeneration == 0 and
                            state.TopologyDisarms == (2 if case == 'reservation-lower-gap' else 1) and
                            state.Created == submitted * 2 and state.PreQueued == submitted,
                            held=p.fields(held), replaced=p.fields(replaced), after=p.fields(state), result=result)
                    self.fresh_arm(label, owner, target, observer)
                    owner.close()
                    target.close()
                self.unload(label)

    def controls(self, iterations, submitted):
        for iteration in range(iterations):
            for case in ('native-cancel', 'teardown-arm'):
                label = f'control-{iteration}-{case}'
                self.load()
                target, owner = self.reader(), self.child()
                with p.Port() as observer:
                    held = self.partial(owner, target, observer, submitted)
                    if case == 'native-cancel':
                        target.send(cancel=True, slot=0)
                        cancel = target.receive()
                        assert cancel['kind'] == 'cancel' and cancel['ok'], cancel
                        owner.send(action=2)
                        owner.receive()
                        messages = [target.receive() for _ in range(submitted)]
                        self.results(messages, range(submitted), cancelled=[0])
                        state = p.wait_state(observer, p.balanced)
                        self.check(label + '-remaining-valid', state.ArmedRemaining == self.count - submitted and
                            state.ArmedGeneration == held.TopologyGeneration and state.TopologyDisarms == 0 and
                            state.PreCancelled == 1, state=p.fields(state), messages=messages, cancel=cancel)
                        self.read(target, self.count)
                        late = p.wait_state(observer, lambda s: s.PreQueued == submitted + 1)
                        owner.send(action=2)
                        owner.receive()
                        result = target.receive()
                        self.results([result], [self.count])
                        p.wait_state(observer, p.balanced)
                        owner.send(action=3)
                        owner.receive()
                        self.read(target, self.count + 1)
                        self.results([target.receive()], [self.count + 1])
                        state = observer.send()
                        self.check(label + '-late-member', state.PreQueued == submitted + 1 and
                            state.ArmedRemaining == state.ArmedGeneration == state.OwnerPid == 0,
                            late=p.fields(late), after=p.fields(state), result=result)
                    else:
                        detached, errors = {}, []

                        def detach():
                            try:
                                detached['hr'] = flt.FilterDetach(p.NAME, 'C:', p.LOWER)
                            except BaseException:
                                errors.append(traceback.format_exc())

                        worker = threading.Thread(target=detach)
                        with p.managed.driver_load_privilege():
                            worker.start()
                            try:
                                during = p.wait_state(observer, lambda s: s.InstanceStarts > s.InstanceCompletes)
                                assert during.RaceCompleted == 0 and during.ArmedRemaining == during.ArmedGeneration == 0
                                owner.send(action=5, mode=4, pid=target.proc.pid, delay=500,
                                    Reserved=self.count, expect_error=True)
                                rejected = owner.receive()
                                state = observer.send()
                                self.check(label + '-busy', 'error' in rejected and
                                    state.ArmDuringTeardownRejected == 1 and state.ArmedRemaining == 0,
                                    during=p.fields(during), after=p.fields(state), response=rejected)
                            finally:
                                worker.join(15)
                            assert not worker.is_alive() and not errors and detached['hr'] >= 0, (detached, errors)
                            messages = [target.receive() for _ in range(submitted)]
                            self.results(messages, range(submitted), cancelled=range(submitted))
                            p.wait_state(observer, p.balanced)
                            assert flt.FilterDetach(p.NAME, 'C:', p.INSTANCE) >= 0
                            empty = p.wait_state(observer, lambda s: s.LiveInstances == 0)
                            owner.send(action=5, mode=4, pid=target.proc.pid, delay=500,
                                Reserved=self.count, expect_error=True)
                            rejected = owner.receive()
                            self.check(label + '-no-instance', 'error' in rejected and observer.send().ArmedRemaining == 0,
                                empty=p.fields(empty), response=rejected)
                            assert self.attach(p.INSTANCE) >= 0 and self.attach(p.LOWER) >= 0
                        self.fresh_arm(label, owner, target, observer)
                    owner.close()
                    target.close()
                self.unload(label)

    def partial_races(self, iterations, submitted, seed, rearm=False):
        rng = random.Random(seed)
        for iteration in range(iterations):
            for topology in ('reconnect-first', 'free-upper', 'free-lower'):
                for killed in ('owner', 'target', 'both'):
                    label = f'race-{iteration}-{topology}-{killed}'
                    self.load()
                    target, owner = self.reader(), self.child()
                    observer, duplicate = p.Port(), w.HANDLE()
                    # A live duplicate must not suppress the owner's exit cleanup.
                    assert kernel.DuplicateHandle(w.HANDLE(int(owner.proc._handle)), w.HANDLE(owner.ready['handle']),
                        w.HANDLE(-1), c.byref(duplicate), 0, False, 2)
                    actions = ['cancel', 'kill', 'topology', 'late', 'unload'] + (['arm'] if rearm else [])
                    order = rng.sample(actions, len(actions))
                    barrier = threading.Barrier(len(actions) + 1)
                    reconnected, late_sent = threading.Event(), threading.Event()
                    arm_seen = threading.Event()
                    commands = threading.Lock()
                    outcomes, errors = {}, []

                    def actor(action):
                        try:
                            barrier.wait(5)
                            time.sleep(order.index(action) * .002)
                            if topology == 'reconnect-first':
                                if action in ('late', 'kill', 'unload'):
                                    assert reconnected.wait(2), 'reattach did not complete'
                                if action == 'unload':
                                    assert late_sent.wait(2), 'remaining submission did not complete'
                            begin, detail = time.perf_counter_ns(), {}
                            if action == 'arm':
                                try:
                                    owner.send(action=5, mode=4, pid=target.proc.pid, delay=500,
                                        Reserved=self.count, expect_error=True)
                                    reply = owner.receive()
                                    # The prior batch is still held. Only busy,
                                    # deleting, or an unload-closed port is valid.
                                    assert reply.get('error') in ('message: 0x800700aa',
                                        'message: 0x801f000b', 'message: 0x80070006'), reply
                                    detail['reply'] = reply
                                finally:
                                    arm_seen.set()
                            elif action == 'cancel':
                                try:
                                    with commands:
                                        target.send(cancel=True, slot=0)
                                    detail['sent'] = True
                                except OSError:
                                    assert target.proc.poll() is not None or killed != 'owner'
                                    detail['sent'] = False
                            elif action == 'kill':
                                if rearm:
                                    assert arm_seen.wait(2), 'new ARM did not reach its response'
                                if killed in ('owner', 'both'):
                                    owner.proc.terminate()
                                if killed in ('target', 'both'):
                                    target.proc.terminate()
                                if killed in ('owner', 'both'):
                                    owner.proc.wait(10)
                                    detail['owner_exit'] = owner.proc.returncode
                            elif action == 'unload':
                                hr = flt.FilterUnload(p.NAME)
                                detail['hr'] = hr & 0xffffffff
                                assert hr >= 0, detail
                                self.loaded = False
                            elif action == 'late':
                                detail['sent'] = 0
                                try:
                                    for slot in range(submitted, self.count):
                                        with commands:
                                            self.read(target, slot)
                                        detail['sent'] += 1
                                except OSError:
                                    assert killed != 'owner'
                                finally:
                                    late_sent.set()
                            else:
                                instance = p.LOWER if topology == 'free-lower' else p.INSTANCE
                                hr = flt.FilterDetach(p.NAME, 'C:', instance)
                                detail['detach_hr'] = hr & 0xffffffff
                                # Only documented absence/deletion races are accepted.
                                assert hr >= 0 or detail['detach_hr'] in (0x801f000b, 0x801f0013, 0x801f0015), detail
                                hr = self.attach(instance)
                                detail['attach_hr'] = hr & 0xffffffff
                                assert hr >= 0 or detail['attach_hr'] in (0x801f000b, 0x801f0013), detail
                                if topology == 'reconnect-first':
                                    assert hr >= 0 and detail['detach_hr'] == 0, detail
                                    state = observer.send()
                                    assert state.RaceCompleted == 0 and state.PreCompleted == 0 and state.Stopping == 0
                                    assert state.ArmedRemaining == state.ArmedGeneration == 0
                                    assert state.TopologyDisarms == 1 and state.LiveInstances == 2
                                    detail['reconnected'] = p.fields(state)
                                reconnected.set()
                            outcomes[action] = dict(start=begin, end=time.perf_counter_ns(), **detail)
                        except BaseException:
                            errors.append(dict(actor=action, error=traceback.format_exc()))

                    actors = [threading.Thread(target=actor, args=(action,)) for action in order]
                    try:
                        held = self.partial(owner, target, observer, submitted)
                        with p.managed.driver_load_privilege():
                            for thread in actors:
                                thread.start()
                            self.record('race-release', label=label, order=order, held=p.fields(held),
                                topology=topology, killed=killed, submitted=submitted)
                            barrier.wait(5)
                            for thread in actors:
                                thread.join(15)
                            assert not errors and all(not t.is_alive() for t in actors), errors
                        messages = []
                        if killed in ('target', 'both'):
                            target.proc.wait(10)
                        else:
                            assert outcomes['late']['sent'] == self.count - submitted
                            assert outcomes['cancel']['sent']
                            messages = [target.receive() for _ in range(self.count + 1)]
                            ios = [row for row in messages if row['kind'] == 'io']
                            cancels = [row for row in messages if row['kind'] == 'cancel']
                            assert len(ios) == self.count and {row['slot'] for row in ios} == set(range(self.count)), messages
                            assert len(cancels) == 1 and (cancels[0]['ok'] or cancels[0]['error'] == 1168), messages
                            assert cancels[0]['started'] < outcomes['unload']['end']
                            for row in ios:
                                assert (row['ok'] and row['bytes'] == 4096 and row['data_matches']) or (
                                    not row['ok'] and row['error'] == 995 and row['bytes'] == 0), row
                                if row['slot'] < submitted:
                                    assert not row['ok'] and row['error'] == 995, row
                                elif topology == 'reconnect-first':
                                    assert row['ok'], row
                        state = self.audit(label)
                        attached = outcomes['topology']['attach_hr'] == 0
                        expected_instances = 2 + int(attached)
                        self.check(label + '-overlap',
                            state.RaceEntered == state.RaceCompleted == state.RaceCancelSeen == state.RaceStopSeen == 1 and
                            state.InstanceStarts == state.InstanceCompletes == expected_instances and
                            state.ManualTeardowns + state.UnloadTeardowns == expected_instances and
                            submitted <= state.PreQueued <= self.count and
                            (not rearm or state.BatchArms == 1) and
                            (killed == 'target' or outcomes['kill']['end'] < outcomes['unload']['end']),
                            state=p.fields(state), order=order, calls=outcomes, messages=messages,
                            topology=topology, killed=killed, submitted=submitted, rearm=rearm)
                        try:
                            observer.send()
                            raise AssertionError('unloaded port still responds')
                        except OSError:
                            pass
                    finally:
                        barrier.abort()
                        reconnected.set()
                        late_sent.set()
                        arm_seen.set()
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
    parser.add_argument('--submitted', type=int, default=2)
    parser.add_argument('--case', choices=('reservation-upper', 'reservation-lower', 'reservation-lower-gap',
        'pair', 'regressions', 'controls', 'races', 'all'), default='all')
    parser.add_argument('--seed', type=int, default=20261025)
    args = parser.parse_args()
    assert c.windll.shell32.IsUserAnAdmin(), 'run elevated'
    assert 1 <= args.iterations <= 100 and 1 <= args.submitted < args.reads
    suite, completed, started = Suite(args.output, args.reads), False, time.monotonic()
    try:
        suite.setup()
        if args.case not in ('controls', 'races'):
            suite.regressions(args.iterations,
                ['reservation-upper', 'reservation-lower', 'reservation-lower-gap', 'pair']
                if args.case in ('regressions', 'all') else [args.case], args.submitted)
        if args.case in ('controls', 'all'):
            suite.controls(args.iterations, args.submitted)
        if args.case in ('races', 'all'):
            suite.partial_races(args.iterations, args.submitted, args.seed)
        completed = True
    finally:
        errors = suite.cleanup()
        result = dict(passed=completed and not errors and all(row['passed'] for row in suite.checks),
            checks=len(suite.checks), iterations=args.iterations, reads=args.reads, submitted=args.submitted,
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
