"""Audit image-name gaps and bounded recovery evidence in a completed KMON run.

Counts are per snapshot, not distinct mappings or proof of atomic collection.
"""
import argparse
import collections
import json
import pathlib


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check_record(record, allow_legacy=False):
    def n(key):
        value = int(record[key])
        require(value >= 0, 'negative name counter: ' + key)
        return value
    known, failures = n('image_names_known'), n('image_name_failures')
    capacity, query = n('image_name_capacity_failures'), n('image_name_query_failures')
    truncated, unqueryable = n('image_name_truncated'), n('image_name_unqueryable')
    require(known + failures == n('image_allocations'), 'allocation/name/gap mismatch')
    require(capacity + query + truncated + unqueryable == failures, 'gap categories mismatch')
    if 'image_name_diagnostics' not in record:
        require(allow_legacy, 'missing bounded name diagnostics')
        return dict(legacy=True, query_failures=query, truncated=truncated, unqueryable=unqueryable,
                    capacity_failures=capacity, retries=0, recovered=0, omitted=0, diagnostics=[])
    details = record['image_name_diagnostics']
    if isinstance(details, str):
        details = json.loads(details)
    retries, recovered = n('image_name_retry_attempts'), n('image_name_recovered')
    omitted = n('image_name_diagnostics_omitted')
    require(isinstance(details, list) and len(details) <= 32, 'unbounded diagnostics')
    require(len(details) + omitted == query + truncated + recovered, 'missing failure/recovery evidence')
    require(recovered <= retries <= len(details) + omitted, 'retry accounting mismatch')
    observed_retry = observed_recovery = 0
    for item in details:
        require(0 <= int(item['allocation_base']) <= int(item['address']), 'invalid diagnostic address')
        require(type(item['retried']) is bool and type(item['recovered']) is bool, 'invalid retry flags')
        require(int(item['initial_error']) >= 0 and int(item['retry_error']) >= 0, 'invalid error')
        observed_retry += item['retried']
        observed_recovery += item['recovered']
        if item['recovered']:
            require(item['retried'] and item['stage'] == 'recovered' and item['retry_error'] == 0 and
                    int(item['current_allocation_base']) == int(item['allocation_base']) and
                    item['current_state'] == 0x1000 and item['current_type'] == 0x1000000,
                    'recovery without matching committed image')
        else:
            expected = {'retry_failed', 'mapping_unavailable_or_changed_after_retry'} if item['retried'] else {
                'not_retryable', 'mapping_unavailable_or_changed_before_retry'}
            require(item['stage'] in expected, 'invalid unresolved retry stage')
    require(observed_retry <= retries <= observed_retry + omitted and
            observed_recovery <= recovered <= observed_recovery + omitted, 'diagnostic counters mismatch')
    return dict(legacy=False, query_failures=query, truncated=truncated, unqueryable=unqueryable,
                capacity_failures=capacity, retries=retries, recovered=recovered, omitted=omitted, diagnostics=details)


def audit(root, allow_legacy=False):
    root = pathlib.Path(root)
    totals = collections.Counter()
    issues = []
    for path in sorted(root.glob('kmon-events.*.jsonl')):
        for raw in path.open('rb'):
            if b'"kind":"coverage.layout"' not in raw:
                continue
            event = json.loads(raw)
            record = event['evidence']
            result = check_record(record, allow_legacy)
            totals['layout_notices'] += 1
            totals['completed_snapshots'] += int(record.get('cycle', '0')) > 0
            for key, value in result.items():
                if key != 'diagnostics':
                    totals[key] += value
            if result['diagnostics'] or result['query_failures'] or result['truncated']:
                issues.append(dict(pid=event['pid'], created=record['process_create_time'],
                                   cycle=record.get('cycle'), ts=event['ts'], **result))
    require(totals['completed_snapshots'] > 0, 'no completed layout snapshots')
    final = json.loads((root/'layouts-final.json').read_text(encoding='utf-8-sig'))
    for process in final['processes']:
        if process['snapshot_available']:
            check_record(process, allow_legacy)
            require(sum(process['image_name_errors'].values()) ==
                    process['image_name_query_failures'] + process['image_name_truncated'], 'error histogram mismatch')
    report = dict(passed=True, totals=dict(totals), issues=issues)
    (root/'layout-name-audit.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run')
    parser.add_argument('--allow-legacy', action='store_true')
    args = parser.parse_args()
    print(json.dumps(audit(args.run, args.allow_legacy)))
