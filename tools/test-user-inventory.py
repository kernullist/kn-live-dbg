"""Independent inventory contents, bounded work, timing and ownership oracle."""
import argparse
import json
from pathlib import Path
import subprocess


def run(exe, *args):
    result = subprocess.run([str(exe.resolve()), *args], capture_output=True, text=True, encoding='utf-8', timeout=180)
    if result.returncode:
        raise AssertionError(f'fixture exit {result.returncode}: {result.stderr}')
    return json.loads(result.stdout)


checks = 0


def check(ok, why):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(why)


def deterministic(data):
    names = {'fixed', 'fast', 'slow_open', 'slow_query', 'empty', 'open_error', 'walk_error',
             'cap', 'watch_cap', 'suspect_cap', 'watch_suspect', 'stop', 'fault', 'clock'}
    check(data['schema'] == 'kn.user_inventory_fixtures.v1' and data['synthetic_clock'] is True and
          {s['name'] for s in data['scenarios']} == names, 'explicit synthetic corpus')
    for scenario in data['scenarios']:
        name, frames = scenario['name'], scenario['frames']
        final = frames[-1]['state']
        check(final['schema'] == 'kn.user_inventory.v1' and final['scope'] == 'latest_hostility_inventory' and
              not final['target_success_reported'] and not final['hard_deadline_enforced'], 'bounded inventory claim')
        complete = name not in ('stop', 'fault', 'clock')
        check(final['complete'] == complete and final['cancelled'] == (name in ('stop', 'clock')) and
              final['faulted'] == (name == 'fault') and final['invalid_clock'] == (name == 'clock'), f'{name}: final outcome')
        check(final['walk_complete'] == (complete and name not in ('open_error', 'walk_error', 'cap')) and
              final['capped'] == (name in ('cap', 'watch_cap', 'suspect_cap')), f'{name}: partial inventories cannot assert absence')
        check(scenario['opens'] == scenario['closes'] == (0 if name == 'open_error' else 1), 'native ownership balanced')
        check(scenario['fault'] == (name == 'fault'), 'fault provenance')
        durations, max_steps, total_steps, total_overruns = [], 0, 0, 0
        for i, frame in enumerate(frames):
            state = frame['state']
            steps = int(state['last_steps'])
            total_steps += steps
            max_steps = max(max_steps, steps)
            check(0 <= steps <= 32 and state['step_limit'] == '32' and state['budget_ms'] == '25', 'at most 32 operations per turn')
            check(int(state['started_ms']) == 100 and int(state['turns']) == i + 1, 'original start retained across turns')
            check(int(state['steps']) == total_steps and int(state['max_steps']) == max_steps, 'exact bounded-work counters')
            if not state['invalid_clock']:
                duration = frame['end'] - frame['begin']
                durations.append(duration)
                total_overruns += duration > 25
                # An expensive single operation may overrun, but never starts a second operation afterward.
                # Up to 24ms of earlier work plus the last row's Next+Resolve.
                limit = 80 if name == 'slow_open' else 65 if name == 'slow_query' else 27
                check(0 <= duration <= limit, 'cooperative cutoff after a native operation')
                if name == 'slow_query':
                    prior = frames[i - 1]['state'] if i else {'rows': '0', 'queries': '0'}
                    queries = int(state['queries']) - int(prior['queries'])
                    rows = int(state['rows']) - int(prior['rows'])
                    check(queries <= 1 and duration == rows + 40 * queries + int(state['walk_complete']),
                          'slow row starts only once; skipped rows and final end-read retain their exact cost')
                check(int(state['elapsed_ms']) == frame['end'] - 100, 'cohort age includes gaps')
            check(int(state['service_samples']) == len(durations) and int(state['service_max_ms']) == max(durations, default=0)
                  and int(state['overruns']) == total_overruns, 'exact service and overrun denominators')
            if i < len(frames) - 1:
                check(frame['result'] == 2 and not state['complete'], 'pending work is not returned or cancelled')
        if name in ('slow_open', 'slow_query'):
            check(total_overruns > 0, 'unpreemptible source latency stays visible')
        if name == 'fast':
            check(max_steps == 32 and len(frames) > 1 and max(durations) == 0, 'zero-cost source cannot bypass step quota')
        expected = {}
        if complete:
            pids = [] if name in ('empty', 'open_error', 'watch_cap', 'suspect_cap') else [p for p in range(100, 4400 if name == 'cap' else 200) if p != 150]
            if name == 'walk_error':
                pids = pids[:40]
            pids = pids[:4096]
            for pid in pids:
                expected[pid] = [pid, 0 if pid == 160 else pid * 10, 0, False, '' if pid == 160 else 'owned.exe']
            if name in ('watch_suspect', 'open_error'):
                for pid in (102, 600, 601):
                    expected.setdefault(pid, [pid, pid * 10, 0, False, 'owned.exe'])
            if name == 'watch_suspect':
                for pid, generation in ((160, 777), (165, 1650), (700, 7000)):
                    path = 'owned.exe' if pid == 165 else 'suspect.exe'
                    expected[pid] = [pid, generation, pid * 100, True, path]
            if name in ('watch_cap', 'suspect_cap'):
                for pid in range(8000, 8000 + 8192):
                    expected[pid] = [pid, pid * 10, 0, False, 'owned.exe']
            if name == 'suspect_cap':
                for pid in range(30000, 30000 + 4096):
                    expected[pid] = [pid, pid * 10, pid * 100, True, 'suspect.exe']
        check(scenario['targets'] == list(expected.values()), f'{name}: complete contents and PID-generation suspect merge')
        check(int(final['queries']) == scenario['queries'], 'actual resolver attempts accounted')
        if complete:
            expected_queries = len(expected) - (1 if name == 'watch_suspect' else 4096 if name == 'suspect_cap' else 0)
            check(scenario['queries'] == expected_queries, 'no duplicate, excluded or suspect-only native query')


def native(data):
    check(data['schema'] == 'kn.user_inventory_test.v1' and data['passed'] and data['checks'] == 11, 'actual native ownership controls')
    check(not data['driver_loaded'] and data['native_process_queries'] and not data['latency_slo_proven'], 'read-only native scope')
    state = data['complete']
    check(state['complete'] and state['walk_complete'] and not state['capped'] and not state['cancelled'] and not state['faulted'], 'native source completion')
    check(0 < int(state['queries']) == int(state['targets']) and 0 < int(state['max_steps']) <= 32, 'actual bounded native work')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core-exe', type=Path)
    parser.add_argument('--exe', type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error('provide --core-exe or --exe')
    if args.core_exe:
        deterministic(run(args.core_exe, '--user-inventory-json'))
    if args.exe:
        native(run(args.exe, '--self-test', 'discovery-scheduler')['user_inventory'])
    print(json.dumps({'passed': True, 'assertions': checks}))
