"""Independent selected-cohort dispatch, timing, failure and ownership checks."""
import argparse
import json
from pathlib import Path
import subprocess

checks = 0


def check(ok, why):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(why)


def run(exe, *args):
    result = subprocess.run([str(exe.resolve()), *args], capture_output=True, text=True, encoding='utf-8', timeout=180)
    if result.returncode:
        raise AssertionError(f'fixture exit {result.returncode}: {result.stderr}')
    return json.loads(result.stdout)


def histogram(actual, values):
    ordered = sorted(values)
    p95 = ordered[(len(ordered) * 95 + 99) // 100 - 1] if ordered else 0
    check(actual == {'samples': str(len(values)), 'max_ms': str(max(values, default=0)),
                     'p95_upper_ms': str((1 << p95.bit_length()) - 1)}, 'independent sample histogram')


def contract(state):
    check(state['schema'] == 'kn.user_deep_scheduling.v1' and state['scope'] == 'latest_selected_cohort', 'cohort scope')
    check(state['callbacks_per_turn'] == '1' and state['overrun_threshold_ms'] == '250' and
          not state['target_success_reported'] and not state['hard_deadline_enforced'], 'one callback is not successful target observation')
    check(not state['running'], 'no callback or borrowed inspection remains active across a turn')


def deterministic(data):
    names = {'fixed', 'slow', 'faults', 'reject', 'stop_before', 'stop_inside', 'cancel', 'clock_before',
             'clock_inside', 'fault_clock', 'reentrant', 'empty', 'external_cancel'}
    check(data['schema'] == 'kn.user_deep_fixtures.v1' and data['synthetic_clock'] and
          {s['name'] for s in data['scenarios']} == names, 'complete synthetic corpus')
    for scenario in data['scenarios']:
        name = scenario['name']
        count = 0 if name == 'empty' else 8
        outcomes = ['pending'] * count
        starts, ends = [None] * count, [None] * count
        totals = dict(attempts=0, returned=0, identity_rejected=0, faults=0, cancellations=0, pre_entry_stops=0,
                      invalid_clocks=0, reentrant_calls=0, failure_report_faults=0, overruns=0, turns=0)
        service = {k: [] for k in ('returned', 'rejected', 'cancelled', 'faulted')}
        wait, next_index, now, reports = [], 0, 1025, 0
        for turn, frame in enumerate(scenario['frames']):
            if name == 'clock_before' and turn == 3:
                now -= 1000
            check(frame['begin'] == now, f'{name}: independently predicted dispatch clock')
            terminal_without_call = name in ('empty', 'external_cancel') or name in ('stop_before', 'clock_before') and turn == 3
            calls = 0 if terminal_without_call else 1
            check(frame['calls'] == calls, 'at most one native inspection entry in each turn')
            totals['turns'] += name not in ('empty', 'external_cancel')
            cancelled = name == 'external_cancel'
            if terminal_without_call:
                if name == 'stop_before':
                    totals['pre_entry_stops'] += 1
                    cancelled = True
                if name == 'clock_before':
                    totals['invalid_clocks'] += 1
                    cancelled = True
            else:
                index = next_index
                starts[index] = now
                wait.append(now - 1000)
                totals['attempts'] += 1
                invalid = name in ('clock_inside', 'fault_clock') and index == 2
                fault = name == 'faults' and index in (0, 3, 5) or name == 'fault_clock' and index == 2
                rejected = name == 'reject' and index in (2, 6)
                cancelled = not fault and (name == 'stop_inside' and index == 2 or name == 'cancel' and index == 3 or invalid)
                duration = -1 if invalid else 350 if name == 'slow' and index == 0 else 5 + index
                if fault:
                    reports += 1
                    duration += 0 if name == 'fault_clock' else 3
                now += duration
                outcome = 'faulted' if fault else 'cancelled' if cancelled else 'identity_rejected' if rejected else 'returned'
                outcomes[index] = outcome
                counter = {'faulted': 'faults', 'cancelled': 'cancellations'}.get(outcome, outcome)
                totals[counter] += 1
                totals['reentrant_calls'] += name == 'reentrant' and index == 1
                totals['failure_report_faults'] += name == 'faults' and index == 3
                totals['invalid_clocks'] += invalid
                if not invalid:
                    ends[index] = now
                    service['rejected' if rejected else outcome].append(duration)
                    totals['overruns'] += duration > 250
                if outcome != 'cancelled':
                    next_index += 1
                cancelled |= invalid
            check(frame['end'] == now, 'native callback and diagnostic failure costs stay in the service interval')
            state = frame['state']
            contract(state)
            check(all(int(state[k]) == v for k, v in totals.items()), f'{name}: exact outcome and control counters')
            check(int(state['selected_ms']) == 1000 and int(state['selected']) == count and int(state['next_index']) == next_index and
                  int(state['remaining']) == count - next_index, 'original cohort and unserved tail retained')
            complete = next_index == count
            check(state['complete'] == complete and state['cancelled'] == cancelled, 'cancellation is distinct from finishing the selected cohort')
            check(state['pending_age_ms'] == (str(now - 1000) if not complete and not totals['invalid_clocks'] else None), 'pending debt never refreshes on progress')
            check(frame['result'] == (0 if complete else 1 if cancelled else 2), 'continuation result preserves scheduler phase')
            for i, slot in enumerate(state['slots']):
                check(slot == {'index': str(i), 'attempts': str(int(starts[i] is not None)), 'outcome': outcomes[i],
                               'first_dispatch_ms': str(starts[i]) if starts[i] is not None else None,
                               'last_dispatch_ms': str(starts[i]) if starts[i] is not None else None,
                               'end_ms': str(ends[i]) if ends[i] is not None else None}, 'each target has independent terminal or pending evidence')
            histogram(state['selection_to_first_dispatch'], wait)
            for kind, samples in service.items():
                histogram(state[kind + '_service'], samples)
            now += 7
        check(scenario['live_owners'] == 0 and scenario['calls'] == totals['attempts'] and scenario['failure_reports'] == reports,
              'callback-owned resources unwind even after inspection or reporter exceptions')
        if name in ('fixed', 'slow', 'faults', 'reject', 'reentrant'):
            check(next_index == 8 and outcomes[-1] == 'returned', 'slow, failing or rejected heads cannot discard the tail')


def native(data):
    check(data['schema'] == 'kn.user_deep_test.v1' and data['passed'] and data['checks'] == 14, 'actual dispatcher and native ownership controls')
    check(not data['driver_loaded'] and data['native_generation_rejection'] and data['native_thread_queries'] and
          not data['full_target_inspection_validated'], 'bounded native validation scope')
    for key in ('partial', 'complete', 'stopped'):
        state = data[key]
        contract(state)
        expected = 1 if key == 'partial' else 2 if key == 'complete' else 0
        check(int(state['selected']) == 2 and int(state['attempts']) == int(state['identity_rejected']) == expected and
              int(state['next_index']) == expected and int(state['remaining']) == 2 - expected, 'real generation fence and continuation counts')
        check(state['returned'] == state['faults'] == state['cancellations'] == '0', 'native rejections cannot count as returned or successful targets')
        check(state['complete'] == (key == 'complete') and state['cancelled'] == (key == 'stopped'), 'actual lifecycle boundaries')
        check(state['pre_entry_stops'] == ('1' if key == 'stopped' else '0'), 'stop before native inspection')
    check(data['partial']['selected_ms'] == data['complete']['selected_ms'], 'production cohort admission clock unchanged')
    targets = data['partial']['targets']
    check(targets == data['complete']['targets'] and len(targets) == 2 and [int(t['index']) for t in targets] == [0, 1] and
          int(targets[0]['pid']) > 4 and targets[0]['pid'] == targets[1]['pid'] and
          int(targets[0]['inventory_generation']) + 1 == int(targets[1]['inventory_generation']), 'original target identities survive the continuation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core-exe', type=Path)
    parser.add_argument('--exe', type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error('provide --core-exe or --exe')
    if args.core_exe:
        deterministic(run(args.core_exe, '--user-deep-json'))
    if args.exe:
        native(run(args.exe, '--self-test', 'discovery-scheduler')['user_deep'])
    print(json.dumps({'passed': True, 'assertions': checks}))
