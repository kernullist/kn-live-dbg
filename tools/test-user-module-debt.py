"""Validate generation-qualified Toolhelp observation history, scheduling, and native receipts."""
import argparse
import json
from pathlib import Path
import subprocess

checks = 0


def check(ok, message):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(message)


def records(state):
    return {(int(s['key']['pid']), int(s['key']['generation'])): s for s in state['scopes']}


def histogram(data, times):
    ordered = sorted(times)

    def upper(percent):
        if not ordered:
            return 0
        value = ordered[(len(ordered) * percent + 99) // 100 - 1]
        return (1 << value.bit_length()) - 1

    check({k: int(v) for k, v in data.items()} == {
        'samples': len(times), 'max_ms': max(times, default=0), 'p95_upper_ms': upper(95),
        'p99_upper_ms': upper(99)}, 'histogram denominator, maximum and bucket bounds')


def contract(state):
    check(state['schema'] == 'kn.user_module_observation_debt.v1' and state['source'] == 'toolhelp_process_modules' and
          state['clock_domain'] == 'GetTickCount64_ms' and state['whole_target_success_reported'] is False,
          'specific acquired source and monotonic clock')
    check(len(state['scopes']) <= 32 and int(state['scopes_omitted']) + len(records(state)) == int(state['retained'])
          <= int(state['history_limit']), 'bounded exact generation history and explicit sample tail')
    check(sum(map(int, state['outcomes'].values())) == int(state['attempts']), 'each closed attempt has exactly one outcome')


def lifecycle(frames):
    for state in frames.values():
        contract(state)
    a, b, c = (10, 100), (20, 200), (30, 300)
    initial = frames['seen']
    check(set(records(initial)) == {a, b} and initial['unknown_inventory_generations'] == '1', 'no PID-only history')
    denied = records(frames['rediscovered'])[a]
    check(denied['first_seen_ms'] == denied['pending_since_ms'] == '100' and denied['last_seen_ms'] == '120' and
          denied['last_attempt_ms'] == '110' and denied['last_success_ms'] is None and
          denied['failure_class'] == 'access_denied' and denied['win32_error'] == '5', 'denial and rediscovery retain first pending time')
    first = records(frames['first'])[a]
    check(first['last_success_ms'] == '135' and first['pending_since_ms'] is None and first['remaining_work'] == 'none' and
          first['failure_class'] == 'none', 'qualified first acquisition closes one source')
    mid = frames['partial_and_pin']
    rows = records(mid)
    check(rows[a]['pending_since_ms'] == '140' and rows[a]['last_attempt_ms'] == '160' and rows[a]['last_success_ms'] == '135' and
          rows[a]['failure_class'] == 'generation_changed', 'partial walk and failed generation fence preserve last success')
    check(rows[c]['first_seen_ms'] == rows[c]['last_attempt_ms'] == '171' and rows[c]['last_success_ms'] == '178' and
          mid['late_pins'] == '1' and (30, 0) not in rows, 'late pin begins named generation at qualification')
    check(rows[b]['suspect_hint_expires_ms'] == '180' and rows[b]['expiry_risk'] == 'suspect_hint_expired' and
          first['expiry_risk'] == 'unknown', 'hint expiry has its own scope')
    last = frames['revisit_and_stop']
    rows = records(last)
    check(rows[a]['last_success_ms'] == '193' and rows[c]['last_success_ms'] == '178' and
          rows[c]['pending_since_ms'] == '195' and rows[c]['failure_class'] == 'cancelled', 'cancelled revisit preserves successful clock')
    histogram(last['first_observation_wait'], [35, 7])
    histogram(last['successful_revisit'], [58])
    histogram(last['observed_service'], [5, 8, 3])
    histogram(last['failed_service'], [4, 5, 7])
    histogram(last['cancelled_service'], [5])
    prior = records(frames['unconfirmed_reuse'])
    check(a in prior and not prior[a]['in_latest_inventory'] and (10, 101) in prior and
          prior[(10, 101)]['last_success_ms'] is None and c in prior, 'unconfirmed reuse and partial absence preserve older history')
    current = frames['confirmed_reuse']
    check(set(records(current)) == {(10, 101), b} and current['retired_replaced'] == current['retired_absent'] == '1' and
          not records(current)[b]['in_latest_inventory'], 'pinned replacement and complete absence retire independently')
    invalid = frames['no_pin_or_bad_terminal']
    check(invalid['untracked_outcomes'] == '1' and invalid['outcomes']['identity_unavailable'] == '2' and
          records(invalid)[(10, 101)]['failure_class'] == 'access_denied' and invalid['outcomes']['observed'] == '3',
          'no success from unknown identity, missing pin or contradictory terminal error')
    reversed_clock = frames['clock_reversals']
    check(reversed_clock['outcomes']['invalid_clock'] == '3' and reversed_clock['invalid_clock_samples'] == '4' and
          all(s['observation_age_ms'] is None for s in reversed_clock['scopes']) and
          records(reversed_clock)[(10, 101)]['pending_since_ms'] == '210', 'clock reversals reject timing and retain original work')
    for key in ('observed_service', 'first_observation_wait', 'successful_revisit'):
        check(invalid[key] == reversed_clock[key], 'invalid clocks cannot refresh qualified timing')


def hint_handoff(frame):
    state = frame['state']
    contract(state)
    scopes = records(state)
    check(set(scopes) == {(41, 410), (42, 420), (160, 1600), (99, 990)}, 'handoff uses matching inventory generations')
    check(scopes[(41, 410)]['suspect_hint_expires_ms'] is None and scopes[(41, 410)]['expiry_risk'] == 'unknown',
          'stale generation cannot attach an earlier hint deadline')
    check(scopes[(42, 420)]['suspect_hint_expires_ms'] == '125' and scopes[(42, 420)]['expiry_risk'] == 'suspect_hint_expired',
          'expired matching hint stays distinguishable in the retained inventory')
    check(frame['loan'] == 160 and scopes[(160, 1600)]['suspect_hint_expires_ms'] == '170' and
          scopes[(99, 990)]['suspect_hint_expires_ms'] == '180', 'earliest current hint wins among equally old generations')


def unsupported_retry(frames):
    before, after = frames['suppressed'], frames['recovered']
    for state in (before, after):
        contract(state)
    initial = records(before)[(19, 190)]
    check(initial['loan_suppressed_unsupported'] and initial['failure_class'] == 'generation_changed' and
          initial['last_success_ms'] is None and initial['pending_since_ms'] == '100', 'conflicting pin invalidates a moved visit')
    check(before['outcomes']['unsupported'] == before['outcomes']['cancelled'] == before['outcomes']['invalid_clock'] ==
          before['outcomes']['generation_changed'] == '1' and before['loan_offers'] == '0' and before['complete_censuses'] == '4',
          'late failures retain unsupported loan suppression past the cooldown')
    recovered = records(after)[(19, 190)]
    check(not recovered['loan_suppressed_unsupported'] and recovered['last_success_ms'] == '71005' and
          after['loan_offers'] == '1' and after['complete_censuses'] == '8', 'successful ordinary acquisition restores loan eligibility')
    histogram(after['first_observation_wait'], [70905])
    histogram(after['failed_service'], [5, 4])
    histogram(after['cancelled_service'], [5])


def capacity(frames):
    for s in frames.values():
        contract(s)
    full = frames['refused']
    check(full['capacity_refusals'] == '2' and full['last_refused'] == {'pid': '40', 'generation': '400'} and
          full['capacity_evictions'] == '0' and full['untracked_outcomes'] == '1', 'protect current keys even for an untracked success')
    histogram(full['observed_service'], [10])
    histogram(full['first_observation_wait'], [])
    partial = frames['partial_eviction']
    check(partial['capacity_evictions'] == '1' and partial['last_evicted'] == {'pid': '10', 'generation': '100'} and
          partial['retired_absent'] == '0' and set(records(partial)) == {(40, 400), (20, 200), (30, 300)},
          'capacity eviction is distinct from evidence of exit')
    check(records(partial)[(40, 400)]['first_seen_ms'] == '130' and records(partial)[(40, 400)]['last_success_ms'] is None,
          'lost history cannot be reconstructed as a recorded prior success')
    retired = frames['retired']
    check(retired['retired_absent'] == retired['retired_replaced'] == '1' and set(records(retired)) == {(20, 201), (40, 400)},
          'definite replacement and absence have separate counts')
    large = frames['full_size']
    check(large['retained'] == large['current_pending'] == large['history_limit'] == '12288' and
          large['capacity_refusals'] == '1' and large['scopes_omitted'] == str(12288 - 32) and
          large['last_refused']['pid'] == str(10 + 12288), 'actual production ceiling and bounded diagnostic payload')


def workload(data, growing):
    history = {}
    counts = dict(observed=0, unsupported=0, access_denied=0)
    first_wait, revisits = [], []
    complete_censuses = offers = 0
    reached = set()
    for i, frame in enumerate(data['rounds']):
        now = 100 + i * 10000
        partial, capped = i % 13 == 7, i % 11 == 5
        size = 26 + (i if growing else 0)
        keys = {p: (p, 10 * p + int(p == 106 and i >= 23)) for p in range(100, 100 + size)}
        for pid, key in keys.items():
            if i == 23 and pid == 106:
                del history[(106, 1060)]
            rec = history.setdefault(key, dict(first=now, pending=now, success=None, attempt=None, outcome='unattempted'))
            if rec['pending'] is None:
                rec['pending'] = now
        complete_censuses += not partial and not capped
        loan = (0, 0)
        if not partial and not capped and complete_censuses % 4 == 0:
            eligible = []
            for pid, key in keys.items():
                r = history[key]
                if r['outcome'] == 'unsupported' or (r['outcome'] == 'access_denied' and now - r['attempt'] < 30000):
                    continue
                # Same-age work with an expiring suspect hint can receive the loan.
                eligible.append((r['success'] if r['success'] is not None else r['first'],
                                 now + 120001 if pid % 9 == 0 else 2**64 - 1,
                                 r['attempt'] is not None, r['attempt'] or 0, key))
            if eligible:
                loan = min(eligible)[-1]
                offers += 1
        check((frame['loan'], frame['generation']) == loan, 'oldest eligible generation, hint expiry and failed/unsupported retry rules')
        selected = frame['selected']
        reserved = 99 + size if capped and not partial else 0
        check(frame['population_reservation'] == reserved and (not reserved or reserved in selected) and
              (not loan[0] or loan[0] in selected), 'real deep selector serves the population or debt reservation')
        check(len(set(selected)) == len(selected) == 8 and
              [sum(p % 3 == k for p in selected) for k in (0, 1, 2)] == [4, 2, 2], 'tier workload bounds')
        for slot, pid in enumerate(selected):
            key, start = keys[pid], now + (slot + 1) * 10
            r = history[key]
            reached.add(key)
            r['attempt'] = start
            r['outcome'] = 'unsupported' if pid == 100 else 'access_denied' if pid % 13 == 0 else 'observed'
            counts[r['outcome']] += 1
            if r['outcome'] == 'observed':
                end = start + 4
                if r['success'] is None:
                    first_wait.append(end - r['first'])
                else:
                    revisits.append(end - r['success'])
                r['success'], r['pending'] = end, None
    state = data['final']
    contract(state)
    check(int(state['loan_offers']) == int(state['loan_entries']) == offers > 0 and int(state['complete_censuses']) == complete_censuses,
          'bounded debt offers progress to actual attempts')
    check(all(int(state['outcomes'][key]) == value for key, value in counts.items()) and int(state['attempts']) == sum(counts.values()),
          'ordinary unsuccessful visits remain in the denominator')
    check({(p, p * 10) for p in range(100, 126)} <= reached and (106, 1061) in reached,
          'growth and reuse preserve service for original generations and replacement')
    histogram(state['first_observation_wait'], first_wait)
    histogram(state['successful_revisit'], revisits)
    histogram(state['observed_service'], [4] * counts['observed'])
    histogram(state['failed_service'], [4] * (counts['unsupported'] + counts['access_denied']))
    for key, scope in records(state).items():
        rec = history[key]
        for field, expected in [('first_seen_ms', rec['first']), ('pending_since_ms', rec['pending']),
                                ('last_success_ms', rec['success']), ('last_attempt_ms', rec['attempt'])]:
            check(scope[field] == (None if expected is None else str(expected)), 'per-generation history against independent event times')


def native(data):
    check(data['passed'] and data['checks'] == 25 and not data['driver_loaded'], 'actual native product controls')
    rejected, first, second, stopped = [data['module_' + s] for s in ('rejected', 'first', 'second', 'stopped')]
    for state in (rejected, first, second, stopped):
        contract(state)
    check(rejected['outcomes']['generation_changed'] == '2' and rejected['outcomes']['observed'] == '0' and
          all(s['last_success_ms'] is None for s in rejected['scopes']), 'real dispatcher generation rejections do not pay debt')
    key = next(iter(records(first)))
    check(len(records(first)) == 1 and key[0] > 4 and key[1] > 0 and first['late_pins'] == '1' and
          first['first_observation_wait']['samples'] == '1' and first['successful_revisit']['samples'] == '0',
          'owned native module acquisition credited to newly pinned generation')
    check(set(records(second)) == set(records(stopped)) == {key} and second['outcomes']['observed'] == stopped['outcomes']['observed'] == '2' and
          second['successful_revisit'] == stopped['successful_revisit'] and second['successful_revisit']['samples'] == '1',
          'two complete native walks produce exactly one successful revisit')
    check(stopped['cancelled_service']['samples'] == '1' and records(stopped)[key]['pending_since_ms'] is not None and
          records(second)[key]['last_success_ms'] == records(stopped)[key]['last_success_ms'], 'native cancellation leaves original qualified receipt')
    after_fault = data['module_after_fault']
    contract(after_fault)
    check(after_fault['outcomes']['observed'] == '3' and after_fault['outcomes']['fault'] == '1' and
          after_fault['successful_revisit']['samples'] == '2' and records(after_fault)[key]['pending_since_ms'] is None,
          'pre-acquisition and post-acquisition exceptions retain their distinct native outcomes')


def run(exe, args):
    result = subprocess.run([str(exe.resolve()), *args], capture_output=True, encoding='utf-8', timeout=180, check=True)
    return json.loads(result.stdout)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core-exe', type=Path)
    parser.add_argument('--exe', type=Path)
    args = parser.parse_args()
    if not (args.core_exe or args.exe):
        parser.error('provide a core harness or product')
    if args.core_exe:
        corpus = run(args.core_exe, ['--user-module-debt-json'])
        check(corpus['synthetic_clock'], 'synthetic workload denominator')
        lifecycle(corpus['lifecycle'])
        capacity(corpus['capacity'])
        unsupported_retry(corpus['unsupported_retry'])
        hint_handoff(corpus['hint_handoff'])
        for name in ('fixed', 'growing'):
            workload(corpus[name], name == 'growing')
    if args.exe:
        native(run(args.exe, ['--self-test', 'discovery-scheduler'])['user_deep'])
    print(json.dumps({'passed': True, 'assertions': checks}))
