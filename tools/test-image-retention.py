"""Independent accounting and concurrent admission invariants for the owned policy harness."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', type=Path, required=True)
    args = parser.parse_args()
    process = subprocess.run([str(args.exe.resolve())], capture_output=True, text=True, encoding='utf-8', timeout=60)
    print(process.stderr.strip())
    assert process.returncode == 0, 'compiled resource controls'
    rows = [json.loads(line) for line in process.stdout.splitlines() if line.startswith('{')]
    assert len(rows) == 2
    concurrent, accounting = rows[0]['concurrent'], rows[1]['accounting']
    checks = 0

    def check(value):
        nonlocal checks
        checks += 1
        assert value, f'independent retention invariant {checks}'

    for report in (concurrent, accounting):
        check(report['schema'] == 'kn.image_retention.v1')
        check(report['policy'] == 'kn.image_retention_partition.v1' and report['scope'] == 'recording_session')
        for flag in ('disk_space_reserved', 'cross_session_dedup_established', 'maliciousness_established'):
            check(report[flag] is False)
        check(report['first_retained_requires_complete_journal_batch'] is True)
        for i, lane in enumerate(report['classes']):
            number = lambda key: int(lane[key])
            check(lane['class'] == ('first_difference', 'observation_gap', 'repeat_or_clean')[i])
            check(number('slot_limit') == (4, 2, 2)[i])
            check(number('read_bytes_limit') == (64, 32, 32)[i] * 1024 * 1024)
            check(number('reference_memory_limit') == number('reference_bytes_limit') == 64 * 1024 * 1024)
            check(number('attempted') == sum(number(k) for k in ('admitted', 'slot_denied', 'reference_denied', 'key_denied', 'preparation_denied')))
            check(number('admitted') == number('finished') + number('abandoned') + number('in_flight'))
            check(number('complete') <= number('finished') and number('peak') <= number('slot_limit'))
            check(number('in_flight') == number('reference_held') == 0)
            for stream in ('read', 'reference', 'recipe'):
                check(number(stream + '_bytes') <= number(stream + '_bytes_limit'))
    for lane in concurrent['classes']:
        check(int(lane['attempted']) == 3000)
        check(lane['abandoned'] == lane['reference_denied'] == lane['key_denied'] == '0')
    expected = [dict(attempted=3, admitted=2, reference_denied=1, finished=1, complete=1, abandoned=1, read_bytes=17, reference_bytes=64*1024*1024),
                dict(attempted=2, admitted=1, reference_denied=1, finished=1, complete=1, abandoned=0, read_bytes=0, reference_bytes=0),
                dict(attempted=3, admitted=2, reference_denied=1, finished=2, complete=1, abandoned=0, read_bytes=32*1024*1024, reference_bytes=0)]
    for lane, truth in zip(accounting['classes'], expected):
        for key, value in truth.items():
            check(int(lane[key]) == value)
    check(accounting['tracked_keys'] == '1' and concurrent['tracked_keys'] == '0')
    print(f'[retention.oracle] checks={checks} concurrent_attempts=9000 children_remaining=0')


if __name__ == '__main__':
    main()
