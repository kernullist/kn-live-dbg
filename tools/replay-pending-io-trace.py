"""Decode retained pages from one opted-in cooperative pending-I/O connection."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid

MAGIC, VERSION, CAPACITY, PAGE_ROWS = 0x54494E4B, 1, 128, 8
CONNECT = struct.Struct('<4I')
QUERY = struct.Struct('<4I16sQ')
HEADER = struct.Struct('<4I16s5Q')
EVENT = struct.Struct('<6Q6I')
PAGE_BYTES = HEADER.size + PAGE_ROWS * EVENT.size
MAX_PAGES = CAPACITY // PAGE_ROWS
KINDS = (None, 'dispatch_observed', 'pre_pending', 'pre_forward_selected', 'pre_complete_selected',
         'post_observed', 'post_pending', 'post_resume_selected', 'draining', 'retired',
         'context_unavailable', 'cancel_observed')
SOURCE = 'KnLiveDbgMiniFilterFixture.PendingIo'
PREDECESSORS = {
    'dispatch_observed': (None,),
    'pre_pending': ('dispatch_observed',),
    'pre_forward_selected': ('dispatch_observed', 'pre_pending'),
    'pre_complete_selected': ('dispatch_observed', 'pre_pending'),
    'post_observed': ('pre_forward_selected',),
    'draining': ('pre_forward_selected',),
    'post_pending': ('post_observed',),
    'post_resume_selected': ('post_pending',),
    'retired': ('pre_complete_selected', 'post_observed', 'draining', 'post_resume_selected'),
    'context_unavailable': ('dispatch_observed',),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_page(raw):
    require(len(raw) == PAGE_BYTES, 'trace page length')
    magic, version, size, count, epoch, frequency, after, first, last, loss = HEADER.unpack_from(raw)
    require((magic, version, size) == (MAGIC, VERSION, PAGE_BYTES), 'trace page header')
    require(any(epoch) and frequency and loss & ~7 == 0, 'capture epoch, clock or loss flags')
    require(after <= last and first == (max(1, last - CAPACITY + 1) if last else 0), 'ring bounds')
    start = max(after + 1, first)
    require(count == min(PAGE_ROWS, max(0, last - start + 1)), 'page count')
    events = []
    for index in range(count):
        seq, request, topology, instance, qpc, amount, kind, major, layer, flags, status, length = (
            EVENT.unpack_from(raw, HEADER.size + index * EVENT.size))
        require(seq == start + index and request and topology and instance, 'sequence or source identity')
        require(0 < kind < len(KINDS) and major in (0, 3) and layer in (1, 2), 'event discriminator')
        require(major == 3 or (length == 0 and layer == 1), 'unexpected CREATE shape')
        has_status, has_bytes = bool(flags & 1), bool(flags & 2)
        require(flags & ~3 == 0 and has_status == (kind in (4, 5)), 'status validity')
        require(has_status or status == 0, 'status outside completion')
        require((not has_bytes and amount == 0) or
                (has_bytes and kind == 5 and major == 3 and status == 0 and amount <= length),
                'invalid byte count')
        events.append(dict(sequence=seq, request=request, topology=topology, instance=instance,
                           qpc=qpc, kind=KINDS[kind], major=major, layer='upper' if layer == 1 else 'lower',
                           read_length=length if major == 3 else None, status=status if has_status else None,
                           transferred=amount if has_bytes else None))
    require(not any(raw[HEADER.size + count * EVENT.size:]), 'nonzero unused page slots')
    return dict(epoch=epoch, frequency=frequency, after=after, first=first, last=last,
                loss=loss, events=events)


def capture_pages(read):
    """Keep unmodified replies, ending at the first page's high-water mark."""
    epoch, after, cut = bytes(16), 0, None
    raw_pages = []
    for _ in range(MAX_PAGES):
        raw = read(QUERY.pack(MAGIC, VERSION, QUERY.size, 0, epoch, after))
        page = decode_page(raw)
        require(page['after'] == after, 'cursor echo')
        if cut is None:
            epoch, cut = page['epoch'], page['last']
        require(epoch == page['epoch'], 'capture epoch changed')
        raw_pages.append(raw)
        after = page['events'][-1]['sequence'] if page['events'] else after
        if after >= cut:
            result = b''.join(raw_pages)
            read_stream(result)  # Also check consecutive headers before saving.
            return result
    raise ValueError('fixed capture cut was unreachable')


def read_stream(raw):
    require(0 < len(raw) <= MAX_PAGES * PAGE_BYTES and len(raw) % PAGE_BYTES == 0, 'capture length')
    epoch, frequency, cut, previous_last, cursor, loss = None, 0, 0, 0, 0, 0
    events, gaps, later_rows = [], [], 0
    for offset in range(0, len(raw), PAGE_BYTES):
        page = decode_page(raw[offset:offset + PAGE_BYTES])
        if offset == 0:
            epoch, frequency, cut = page['epoch'], page['frequency'], page['last']
        else:
            require(cursor < cut, 'pages after capture cut')
        require((page['epoch'], page['frequency']) == (epoch, frequency), 'capture identity changed')
        require(page['after'] == cursor and page['last'] >= previous_last, 'page cursor or high-water order')
        require(page['loss'] & loss == loss, 'loss flags cleared')
        if page['first'] > cursor + 1:
            gaps.append([cursor + 1, min(cut, page['first'] - 1)])
        for index, event in enumerate(page['events']):
            if event['sequence'] <= cut:
                event['source_offset'] = offset + HEADER.size + index * EVENT.size
                events.append(event)
            else:
                later_rows += 1
        if page['events']:
            cursor = page['events'][-1]['sequence']
        loss, previous_last = page['loss'], page['last']
    require(cursor >= cut, 'incomplete page stream')
    return epoch, frequency, cut, loss, gaps, events, later_rows


def describe_request(rows, gaps, source_conflicts):
    identity, transitions = set(source_conflicts), set()
    affected = any(begin <= rows[-1]['sequence'] and end >= rows[0]['sequence'] for begin, end in gaps)
    lost_prefix = bool(gaps and gaps[0][0] < rows[0]['sequence'])
    if len({(e['topology'], e['major']) for e in rows}) != 1:
        identity.add('topology_or_major_changed')
    by_layer = {}
    for row in rows:
        by_layer.setdefault(row['layer'], []).append(row)
    if 'lower' in by_layer and 'upper' in by_layer:
        if set(e['instance'] for e in by_layer['lower']) & set(e['instance'] for e in by_layer['upper']):
            identity.add('instance_has_both_roles')
        forwards = [e['sequence'] for e in by_layer['upper'] if e['kind'] == 'pre_forward_selected']
        lower_dispatch = [e['sequence'] for e in by_layer['lower'] if e['kind'] == 'dispatch_observed']
        if not forwards and lower_dispatch:
            if affected or (lost_prefix and by_layer['upper'][0]['kind'] != 'dispatch_observed'):
                affected = True
            else:
                transitions.add('lower_dispatch_without_upper_forward')
        if forwards and lower_dispatch and lower_dispatch[0] < forwards[0]:
            transitions.add('lower_dispatch_before_upper_forward')
        upper_ends = [e['sequence'] for e in by_layer['upper'] if e['kind'] in
                      ('post_observed', 'draining', 'pre_complete_selected', 'retired', 'context_unavailable')]
        if lower_dispatch and upper_ends and upper_ends[0] < lower_dispatch[0]:
            transitions.add('lower_dispatch_after_upper_outcome')
    layers = {}
    for layer, records in by_layer.items():
        if len({(e['instance'], e['read_length']) for e in records}) != 1:
            identity.add(layer + '_source_changed')
        if sum(e['kind'] == 'dispatch_observed' for e in records) > 1:
            identity.add(layer + '_generation_reused')
        previous = outcome = None
        milestones = {}
        prefix_missing = records[0]['kind'] != 'dispatch_observed'
        if prefix_missing and lost_prefix:
            affected = True
        for row in records:
            kind = row['kind']
            if kind == 'cancel_observed':
                if previous not in ('dispatch_observed', 'pre_pending', 'post_pending') and not affected:
                    transitions.add(layer + '_cancel_outside_context')
                continue
            if previous not in PREDECESSORS[kind] and not affected:
                transitions.add(layer + '_unexpected_' + kind)
            if kind in ('pre_complete_selected', 'post_observed'):
                outcome = row
            previous = kind
            milestones[kind] = row
        pre_ticks = post_ticks = elapsed = None
        ordered_clock = all(a['qpc'] <= b['qpc'] for a, b in zip(records, records[1:]))
        if ordered_clock and not prefix_missing and outcome:
            elapsed = outcome['qpc'] - records[0]['qpc']
        if ordered_clock:
            pre_end = milestones.get('pre_forward_selected') or milestones.get('pre_complete_selected')
            if pre_end and 'pre_pending' in milestones:
                pre_ticks = pre_end['qpc'] - milestones['pre_pending']['qpc']
            if 'post_pending' in milestones and 'post_resume_selected' in milestones:
                post_ticks = milestones['post_resume_selected']['qpc'] - milestones['post_pending']['qpc']
        layers[layer] = dict(pre_pending_qpc_ticks=pre_ticks, post_pending_qpc_ticks=post_ticks, last_stage=previous, outcome_sequence=outcome['sequence'] if outcome else None,
                             dispatch_to_outcome_qpc_ticks=elapsed, retired=previous == 'retired')
    if 'upper' not in by_layer:
        if lost_prefix:
            affected = True
        else:
            transitions.add('missing_upper_admission')
    if any(not layer['retired'] for layer in layers.values()) and any(start > rows[-1]['sequence'] for start, _ in gaps):
        affected = True
    upper = layers.get('upper', {})
    outcome_sequence = upper.get('outcome_sequence')
    observation = 'unknown_outcome'
    if identity:
        observation = 'identity_conflict'
    elif transitions:
        observation = 'transition_conflict'
    elif affected or any(e['kind'] == 'context_unavailable' for e in rows):
        observation = 'observation_gap'
    elif outcome_sequence and all(v['retired'] for v in layers.values()):
        observation = 'upper_fixture_outcome_observed'
    if identity or transitions or affected:
        for layer in layers.values():
            for field in ('dispatch_to_outcome_qpc_ticks', 'pre_pending_qpc_ticks', 'post_pending_qpc_ticks'):
                layer[field] = None
    outcome_row = next((e for e in rows if e['sequence'] == outcome_sequence), None)
    return dict(request=rows[0]['request'], observation=observation, identity_conflicts=sorted(identity),
                transition_conflicts=sorted(transitions), layers=layers,
                upper_status=outcome_row['status'] if observation == 'upper_fixture_outcome_observed' else None,
                events=rows)


def replay(raw, expected_hash):
    digest = hashlib.sha256(raw).hexdigest()
    require(isinstance(expected_hash, str) and re.fullmatch('[0-9a-fA-F]{64}', expected_hash) and
            expected_hash.lower() == digest, 'capture SHA-256 mismatch')
    epoch, frequency, cut, loss, gaps, events, later_rows = read_stream(raw)
    requests, roles, conflicts = {}, {}, {}
    high_generation = 0
    for event in events:
        request = event['request']
        requests.setdefault(request, []).append(event)
        roles.setdefault(event['instance'], set()).add(event['layer'])
        if event['kind'] == 'dispatch_observed' and event['layer'] == 'upper':
            if request < high_generation:
                for generation in (request, high_generation):
                    conflicts.setdefault(generation, set()).add('generation_order')
            high_generation = max(high_generation, request)
    for request, rows in requests.items():
        if any(len(roles[e['instance']]) != 1 for e in rows):
            conflicts.setdefault(request, set()).add('instance_role_changed')
    exhausted = [name for bit, name in ((1, 'sequence_exhausted'), (2, 'generation_exhausted'),
                                       (4, 'instance_exhausted')) if loss & bit]
    return dict(schema='kn.pending_io_trace.v1', provider=SOURCE, capture_epoch=str(uuid.UUID(bytes_le=epoch)), sha256=digest,
                qpc_frequency=frequency, through_sequence=cut, missing_sequences=gaps, loss_flags=loss, loss_reasons=exhausted,
                retained_events=len(events), later_rows_in_original_pages=later_rows, requests=[describe_request(rows, gaps, conflicts.get(request, ()))
                for request, rows in requests.items()])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pages', type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        with args.pages.open('rb') as stream:
            data = stream.read(MAX_PAGES * PAGE_BYTES + 1)
        print(json.dumps(replay(data, args.sha256), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f'{parser.prog}: {error}\n')


if __name__ == '__main__':
    main()
