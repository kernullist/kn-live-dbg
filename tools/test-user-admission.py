"""Compare actual inventory and deep selections with a full-population PID model."""
import argparse
import json
from pathlib import Path
import subprocess


checks = 0


def check(condition, why):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(why)


def eligible(values):
    return list(dict.fromkeys(pid for pid in values if pid > 4 and pid != 99))


def first_overflow(groups, limits):
    installed = set()
    for items, limit in zip(groups, limits):
        for pid in items:
            if pid in installed:
                continue
            if len(installed) == limit:
                return pid
            installed.add(pid)
    return 0


def take(items, slots, cursor, reserved):
    rotation = sorted(set(items), key=lambda pid: (pid <= cursor, pid))
    natural = rotation[:slots]
    if reserved in rotation[slots:] and slots:
        ordinary = natural[:-1]
        return ordinary + [reserved], ordinary[-1] if ordinary else cursor
    return natural, natural[-1] if natural else cursor


def schedule(targets, watches, cursors, reserved):
    watched, priority, background = [], [], []
    for pid, _, eprocess, _ in targets:
        if pid in watches:
            watched.append(pid)
        elif eprocess or pid % 3 == 0:
            priority.append(pid)
        else:
            background.append(pid)
    urgent, uc = take([p for p in watched if p % 2 == 0], 2, cursors[3], reserved)
    ordinary, wc = take(set(watched) - set(urgent), 4 - len(urgent), cursors[0], reserved)
    high, pc = take(priority, 6 - len(urgent + ordinary), cursors[1], reserved)
    low, bc = take(background, 2, cursors[2], reserved)
    return urgent + ordinary + high + low, [wc, pc, bc, uc]


def scopes(state, raw):
    ledger = state['admission_deferred']
    counts = [int(s['events']) for s in ledger['scopes']]
    check(ledger['scope'] == 'this_inventory_capacity_events' and len(counts) <= int(ledger['scope_limit']) == 32,
          'bounded per-inventory scopes')
    check(sum(counts) + int(ledger['unrepresented_events']) == int(ledger['events']) and
          bool(int(ledger['events'])) == state['capped'], 'every capacity event has a denominator')
    for s in ledger['scopes']:
        pid = int(s['pid'])
        check(pid in raw[s['source']] and
              s['reason'] in ('metadata_capacity', 'reserved_slot_displacement'), 'scope identifies a real input and reason')
        check(int(state['started_ms']) <= int(s['first_ms']) <= int(s['last_ms']) and int(s['events']) > 0,
              'first and last capacity observations are ordered')
        if s['reason'] == 'metadata_capacity' and s['source'] != 'suspect':
            check(s['generation'] is None, 'unresolved row has no claimed identity')


def verify(data):
    limits = data['limits']
    check(data['synthetic_clock'] and limits == [8, 14, 18], 'small capacities force all production branches')
    names = {s['name'] for s in data['scenarios']}
    check(names == {'fixed', 'growing', 'churn', 'watch_cap', 'suspect_cap', 'open_error',
                    'walk_error', 'stop', 'fault', 'final_clock', 'restore_watch', 'restore_suspect'},
          'fixed, growing, churn, identity reconciliation and failure cases')
    for scenario in data['scenarios']:
        name = scenario['name']
        last = ceiling = 0
        cursors = [0] * 4
        reserved_history = []
        for i, frame in enumerate(scenario['frames']):
            state, mode = frame['state'], frame['mode']
            groups = [eligible(frame[k]) for k in ('rows', 'watches', 'suspects')]
            raw = dict(zip(('snapshot', 'watch', 'suspect'), groups))
            universe = set().union(*groups)
            check(int(state['lap_after_pid']) == last and int(state['lap_through_pid']) == ceiling,
                  'completed proposal supplied to next inventory')
            scopes(state, raw)
            terminal = mode not in ('stop', 'fault', 'final_clock')
            walk_complete = mode not in ('open_error', 'walk_error')
            check(state['complete'] == terminal and state['walk_complete'] == walk_complete and
                  state['faulted'] == frame['fault'] == (mode == 'fault') and
                  state['cancelled'] == (mode in ('stop', 'final_clock')) and
                  state['invalid_clock'] == (mode == 'final_clock'), 'explicit terminal and native-walk outcomes')
            check(int(state['max_steps']) <= 32 and int(state['targets']) <= limits[-1], 'operation and metadata limits')
            reserved = next_ceiling = 0
            if terminal and walk_complete:
                overflow = first_overflow(groups, limits)
                check(state['capped'] == bool(overflow), 'capacity crossing computed from full inputs')
                if overflow:
                    tail = [p for p in universe if last < p <= ceiling]
                    reserved = overflow if not last else min(tail) if tail else min(universe)
                    next_ceiling = ceiling if tail else max(universe)
            check((int(state['reserved_pid']), int(state['reserved_through_pid'])) == (reserved, next_ceiling),
                  f'{name} pass {i}: full-population reservation and frozen ceiling')
            targets = frame['targets']
            resident = {t[0] for t in targets}
            check(len(resident) == len(targets) <= limits[-1] and resident <= universe and (terminal or not targets),
                  'unique bounded residents with no partial transfer after stop or fault')
            for pid, generation, eprocess, path in targets:
                if path == 'pinned':
                    check(generation == 10 * pid + int(pid == 104 and i >= 16), 'actual pinned generation')
                if eprocess:
                    claimed = {777, 1070} if name == 'restore_suspect' and pid == 107 else {
                        777 if pid in (107, 111) else 10 * pid}
                    check(pid in raw['suspect'] and eprocess == 100 * pid and generation in claimed,
                          'suspect identity and path merge')
                if not generation:
                    check(not path and not eprocess, 'unqualified name cannot become an image path')
            if i == 0 and name in ('fixed', 'growing'):
                check(107 not in resident and reserved == 108,
                      'stale suspect cannot reintroduce the displaced native PID under a conflicting generation')
                duplicates = [s for s in state['admission_deferred']['scopes'] if s['source'] == 'snapshot' and s['pid'] == '118']
                check(len(duplicates) == 1 and int(duplicates[0]['events']) == 3, 'repeated deferred rows coalesce with the original scope')
            if i == 0 and name in ('restore_watch', 'restore_suspect'):
                restored = next(t for t in targets if t[0] == 107)
                check(frame['reads_107'] == 1 and restored == [107, 1070, 10700 if name == 'restore_suspect' else 0, 'pinned'],
                      'later watch or matching suspect recovers the original pinned row after a conflicting suspect')
            if terminal and walk_complete and name != 'suspect_cap':
                check(int(state['rows']) == len(frame['rows']), 'snapshot tail consumed in full')
            selected, cursors = schedule(targets, raw['watch'], cursors, reserved)
            check(frame['selected'] == selected and frame['tier_cursors'] == cursors, 'exact tier quotas and ordinary cursor progression')
            check(len(set(selected)) == len(selected) <= 8 and (not reserved or reserved in selected),
                  'resident reservation reaches the real deep selector')
            if reserved:
                last, ceiling = reserved, next_ceiling
                reserved_history.append(reserved)
        if name in ('fixed', 'growing'):
            stable = set(range(100, 119)) | set(range(300, 320)) | set(range(500, 521))
            check(stable <= set(reserved_history), 'every original PID gets a reserved deep slot')
            check(len(reserved_history) == len(scenario['frames']) and
                  len(set(reserved_history[:len(stable)])) == len(stable), 'admissions advance across source and metadata boundaries')
        if name == 'growing':
            check(100 in reserved_history and 1001 in set().union(*(set(f['rows']) for f in scenario['frames'])) and
                  all(p <= 1000 for p in reserved_history[:reserved_history.index(100) + 1]),
                  'higher newcomers cannot postpone wrap to the oldest lower PIDs')
        if name == 'churn':
            check({100, 104, 118, 300, 319, 500, 520} <= set(reserved_history),
                  'changing input order, deletions, reappearance and partial walks preserve cross-source progress')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core-exe', required=True, type=Path)
    args = parser.parse_args()
    result = subprocess.run([str(args.core_exe.resolve()), '--user-admission-json'], capture_output=True, check=True,
                            encoding='utf-8', timeout=180)
    verify(json.loads(result.stdout))
    print(json.dumps({'passed': True, 'scenarios': 12, 'assertions': checks}))
