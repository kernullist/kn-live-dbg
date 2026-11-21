"""Capture overlapping READs, cancellation and upper-instance detach in the owned pending-I/O fixture."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import sys
import tempfile
import winreg

TOOLS = Path(__file__).parent
race = runpy.run_path(str(TOOLS / 'run-pending-io-race-e2e.py'))
trace = runpy.run_path(str(TOOLS / 'replay-pending-io-trace.py'))
p = race['p']
CONNECT = trace['CONNECT'].pack(trace['MAGIC'], trace['VERSION'], trace['CONNECT'].size, 0)


def message(handle, request):
    reply = c.create_string_buffer(trace['PAGE_BYTES'])
    returned = w.DWORD()
    hr = p.flt.FilterSendMessage(handle, c.create_string_buffer(request), len(request),
                                 reply, len(reply), c.byref(returned))
    if hr < 0:
        raise OSError(hr & 0xffffffff, 'trace page request failed')
    if returned.value != len(reply):
        raise ValueError('incomplete trace reply')
    return reply.raw


def capture(port):
    return trace['capture_pages'](lambda request: message(port.handle, request))


def retain(suite, raw, name):
    pin = hashlib.sha256(raw).hexdigest()
    final = suite.output / (name + '.kniotrace')
    fd, path = tempfile.mkstemp(prefix=final.name + '.pending-', dir=suite.output)
    temporary = Path(path)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, final)  # On Windows an existing destination is refused.
    finally:
        temporary.unlink(missing_ok=True)
    suite.record('capture', file=final.name, sha256=pin)
    return trace['replay'](final.read_bytes(), pin)


def expect_error(suite, name, handle, request, expected):
    try:
        message(handle, request)
    except OSError as error:
        suite.check(name, error.errno == expected, hresult=error.errno)
    else:
        suite.check(name, False)


def hold_reads(owner, observer, target):
    before = owner.send(5, 4, target.proc.pid, 500, Reserved=2)
    for slot in range(2):
        target.send(read=True, slot=slot)
    held = p.wait_state(observer, lambda s: s.PreQueued == before.PreQueued + 2 and
                        s.PreCompleted == before.PreCompleted and s.LiveContexts == 4 and
                        s.ActiveWorkers == 1 and s.RaceEntered == before.RaceEntered + 1 and
                        s.RaceCompleted == before.RaceCompleted)
    return before, held


def exercise(suite):
    suite.setup()
    suite.load()
    target = suite.child(io=True)
    discover = trace['QUERY'].pack(trace['MAGIC'], trace['VERSION'], trace['QUERY'].size, 0, bytes(16), 0)
    foreign = p.Child('--trace-owner', script=__file__)
    suite.children.append(foreign)
    with p.Port(CONNECT) as owner, p.Port(CONNECT) as other, p.Port() as legacy:
        duplicate = w.HANDLE()
        if not p.kernel.DuplicateHandle(w.HANDLE(int(foreign.proc._handle)), w.HANDLE(foreign.ready['handle']),
                                        w.HANDLE(-1), c.byref(duplicate), 0, False, 2):
            raise c.WinError(c.get_last_error())
        try:
            expect_error(suite, 'foreign-duplicated-port-denied', duplicate, discover, 0x80070005)
        finally:
            p.kernel.CloseHandle(duplicate)
        foreign.close()
        expect_error(suite, 'legacy-port-trace-denied', legacy.handle, discover, 0x80070005)
        first = trace['decode_page'](message(owner.handle, discover))
        second = trace['decode_page'](message(other.handle, discover))
        suite.check('distinct-empty-captures', first['epoch'] != second['epoch'] and first['last'] == second['last'] == 0)
        wrong = trace['QUERY'].pack(trace['MAGIC'], trace['VERSION'], trace['QUERY'].size, 0, first['epoch'], 0)
        expect_error(suite, 'foreign-epoch-rejected', other.handle, wrong, 0x80070057)
        _, held = hold_reads(owner, legacy, target)
        pending_data = capture(owner)
        target.send(cancel=True, slot=0)
        suite.record('both-lower-reads-pending', state=p.fields(held))
        during = retain(suite, pending_data, 'pending')
        suite.check('two-live-request-generations', len(during['requests']) == 2 and
                    all(r['observation'] == 'unknown_outcome' and
                        r['layers']['lower']['last_stage'] == 'pre_pending' for r in during['requests']))
        # A fast cancellation can finish the READ before its cancel acknowledgement arrives.
        outcomes = []
        for _ in range(3):
            response = target.receive()
            outcomes.append(response)
            if response['kind'] == 'cancel':
                break
        ack = next(r for r in outcomes if r['kind'] == 'cancel')
        suite.check('cancel-acknowledged', ack['slot'] == 0 and ack['ok'], result=ack)
        owner.send(2)
        while sum(r['kind'] == 'io' for r in outcomes) < 2:
            outcomes.append(target.receive())
        results = {r['slot']: r for r in outcomes if r['kind'] == 'io'}
        suite.check('independent-read-results', not results[0]['ok'] and results[0]['error'] == 995 and
                    results[0]['bytes'] == 0 and results[1]['ok'] and
                    results[1]['bytes'] == 4096 and results[1]['data_matches'], results=results)
        p.wait_state(legacy, p.balanced)
        owner.send(3)
        final = retain(suite, capture(owner), 'retired')
        rows = final['requests']
        suite.check('upper-results-and-layer-retirements', len(rows) == 2 and
                    final['capture_epoch'] == during['capture_epoch'] and
                    {r['request'] for r in rows} == {r['request'] for r in during['requests']} and
                    all(r['observation'] == 'upper_fixture_outcome_observed' and len(r['layers']) == 2 and
                        all(l['retired'] for l in r['layers'].values()) for r in rows) and
                    {r['upper_status'] for r in rows} == {0, 0xc0000120} and
                    not final['loss_flags'] and not final['missing_sequences'])
        good = next(r for r in rows if r['upper_status'] == 0)
        suite.check('observed-read-length', any(e['kind'] == 'post_observed' and e['layer'] == 'upper' and
                    e['transferred'] == 4096 for e in good['events']))
        before, _ = hold_reads(owner, legacy, target)
        with p.managed.driver_load_privilege():
            hr = p.flt.FilterDetach(p.NAME, 'C:', p.INSTANCE)
        if hr < 0:
            raise OSError(hr & 0xffffffff, 'owned upper instance detach failed')
        drained = legacy.send()
        owner.send(2)
        suite.check('upper-drained-while-lower-pending', drained.PostDrained == before.PostDrained + 2 and
                    drained.LiveContexts == 2 and drained.PreCompleted == before.PreCompleted, state=p.fields(drained))
        for _ in range(2):
            result = target.receive()
            suite.check('underlying-read-after-draining', result['kind'] == 'io' and result['ok'] and
                        result['bytes'] == 4096 and result['data_matches'], result=result)
        p.wait_state(legacy, p.balanced)
        owner.send(3)
        report = retain(suite, capture(owner), 'drained')
        seen = {r['request'] for r in rows}
        later = [r for r in report['requests'] if r['request'] not in seen]
        suite.check('draining-preserves-unknown-upper-outcome', len(later) == 2 and
                    all(r['observation'] == 'unknown_outcome' and r['upper_status'] is None and
                        [e['kind'] for e in r['events'] if e['layer'] == 'upper'] ==
                        ['dispatch_observed', 'pre_forward_selected', 'draining', 'retired'] and
                        r['layers']['lower']['outcome_sequence'] is not None for r in later))
        suite.check('idle-capture-isolated', trace['decode_page'](message(other.handle, discover))['last'] == 0)
    target.close()
    suite.unload('pending-trace')
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p.SERVICE + '\\Parameters') as key:
        raw, kind = winreg.QueryValueEx(key, 'PendingIoTraceFinalAudit')
    layout = struct.Struct('<4I4Q')
    magic, ver, size, slots, alloc, freed, started, finished = layout.unpack(raw)
    suite.check('post-unregister-trace-ledger', kind == winreg.REG_BINARY and
                (magic, ver, size, slots) == (trace['MAGIC'], trace['VERSION'], layout.size, 16) and
                alloc == freed == 3 and started == finished and finished >= 8,
                allocated=alloc, freed=freed, started=started, completed=finished, available_slots=slots)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory on the C: fixture volume')
    args = parser.parse_args()
    if not __debug__:
        parser.error('this fixture uses checked assertions and requires a normal Python invocation')
    if not c.windll.shell32.IsUserAnAdmin():
        parser.exit(2, 'the live FltMgr fixture requires an elevated Windows test host\n')
    if args.output.resolve().drive.upper() != 'C:':
        parser.error('output must be on the attached C: fixture volume')
    suite = race['Suite'](args.output)
    completed = False
    try:
        exercise(suite)
        completed = True
    finally:
        errors = suite.cleanup()
        (suite.output / 'result.json').write_text(json.dumps(dict(passed=completed and not errors,
            fixture_sha256=suite.hash, cleanup_errors=errors), indent=2), encoding='utf-8')
        if errors:
            raise RuntimeError(errors)


if __name__ == '__main__':
    if sys.argv[1:] == ['--trace-owner']:
        p.child_owner(CONNECT)
    else:
        main()
