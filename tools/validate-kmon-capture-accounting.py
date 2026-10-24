"""Audit native KMON capture totals and discardable gaps from saved chunks.

Run after validate-kmon-live.ps1 finishes. This does not count skipped bytes as
captured, prove that Windows discarded a section, or establish maliciousness.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import struct

if not __debug__:
    raise RuntimeError('Run this evidence validator without Python -O/PYTHONOPTIMIZE')


def discardable_sections(header, image_size, offset, count):
    assert header[:2] == b'MZ'
    pe, = struct.unpack_from('<I', header, 0x3c)
    assert header[pe:pe+4] == b'PE\0\0'
    sections, = struct.unpack_from('<H', header, pe+6)
    optional_size, = struct.unpack_from('<H', header, pe+20)
    assert 0 < sections <= 96 and optional_size >= 240
    assert struct.unpack_from('<H', header, pe+24)[0] == 0x20b
    assert struct.unpack_from('<I', header, pe+24+56)[0] == image_size
    assert struct.unpack_from('<I', header, pe+24+32)[0] == 4096
    headers_size, = struct.unpack_from('<I', header, pe+24+60)
    assert headers_size <= offset < offset+count <= image_size
    matches = []
    for i in range(sections):
        pos = pe+24+optional_size+40*i
        name, virtual_size, rva, raw_size = struct.unpack_from('<8sIII', header, pos)
        flags, = struct.unpack_from('<I', header, pos+36)
        end = rva + ((max(virtual_size, raw_size)+4095)//4096)*4096
        assert rva % 4096 == 0 and end <= image_size
        if rva < offset+count and end > offset:
            assert flags & 0x02000000 and rva <= offset and offset+count <= end
            matches.append(name.rstrip(b'\0').decode('ascii'))
    assert len(matches) == 1
    return matches[0]


def audit(root, require_discardable=False, require_kernel_quantum=False, require_root_layout_cache=False):
    root = pathlib.Path(root).resolve()
    chunks = collections.defaultdict(dict)
    results, retries, pipeline = {}, {}, {}
    for path in sorted(root.glob('kmon-events.*.jsonl')):
        with path.open('rb') as source:
            for raw in source:
                if not any(k in raw for k in (b'"kind":"coverage.capture', b'"kind":"coverage.pipeline"')):
                    continue
                event = json.loads(raw)
                evidence = event['evidence']
                kind = event['kind']
                if kind == 'coverage.pipeline':
                    pipeline = evidence
                    continue
                if 'capture_id' not in evidence:
                    continue
                capture_id = int(evidence['capture_id'])
                if kind == 'coverage.capture_result':
                    assert capture_id not in results
                    results[capture_id] = evidence
                elif kind == 'coverage.capture_retry':
                    key = (capture_id, int(evidence['address']))
                    assert key not in retries, ('unbounded retry', key)
                    retries[key] = evidence
                elif kind == 'coverage.capture':
                    offset = int(evidence.get('chunk_offset', evidence.get('failed_offset', '-1')))
                    assert offset >= 0 and offset not in chunks[capture_id]
                    chunks[capture_id][offset] = evidence
    def saved_bytes(chunk):
        assert chunk['persistence'] == 'complete'
        path = pathlib.Path(chunk['capture_path']).resolve()
        path.relative_to(root/'captures')
        data = path.read_bytes()
        assert len(data) == int(chunk['capture_bytes']) and hashlib.sha256(data).hexdigest() == chunk['capture_sha256'].lower()
        return len(data)

    # QueueCapturedBytes persists already observed/reference bytes directly,
    # without a queued read request or coverage.capture_result. Check these
    # separately; they are not part of CaptureReadBytes or request coverage.
    standalone_roles = {'layout_image_metadata', 'modified_code', 'expected_code', 'hunt_reference', 'manifest_slot'}
    standalone = set(chunks)-set(results)
    standalone_bytes = 0
    for capture_id in standalone:
        assert set(chunks[capture_id]) == {0}, 'capture chunks without a final result'
        chunk = chunks[capture_id][0]
        assert chunk.get('capture_role') in standalone_roles, 'queued capture without a final result'
        size = saved_bytes(chunk)
        assert 0 < size <= 4096
        standalone_bytes += size
    assert all(capture_id in results for capture_id, _ in retries), 'retry without a final result'
    totals = collections.Counter()
    roles = collections.defaultdict(collections.Counter)
    kernel_spans, full_kernel_spans = [], []
    for capture_id, result in results.items():
        saved = failed = skipped = discardable = 0
        end = 0
        for offset, chunk in sorted(chunks[capture_id].items()):
            size = int(chunk.get('capture_bytes', 0))
            bad, gap = int(chunk.get('failed_bytes', 0)), int(chunk.get('skipped_bytes', 0))
            assert size >= 0 and bad >= 0 and gap >= 0 and size+bad+gap > 0
            assert offset == end, ('missing/overlapping chunk', capture_id, offset, end)
            end += size if size else bad+gap
            if size:
                assert bad == 0 and gap == 0, ('contradictory saved chunk', capture_id, offset)
                saved += saved_bytes(chunk)
            else:
                failed += bad
                skipped += gap
            if chunk.get('coverage_reason') == 'unreadable_discardable_section':
                assert result['capture_role'] == 'driver_image' and bad == 0 and gap > 0
                header = pathlib.Path(chunks[capture_id][0]['capture_path']).read_bytes()
                name = discardable_sections(header, int(result['requested_bytes']), offset, gap)
                assert name == chunk['discardable_section']
                discardable += gap
        unvisited = int(result['unvisited_bytes'])
        assert unvisited >= 0
        assert end+unvisited == int(result['requested_bytes'])
        assert saved == int(result['compared_bytes']) and failed == int(result['failed_bytes'])
        assert skipped == int(result['known_unreadable_bytes'])
        assert skipped+unvisited == int(result['skipped_bytes'])
        assert discardable == int(result.get('discardable_unreadable_bytes', 0))
        values = dict(saved=saved, failed=failed, skipped=skipped, unvisited=unvisited, discardable=discardable)
        totals.update(values)
        roles[result['capture_role']].update(values)
        if result['capture_role'] == 'orphan_wx' and int(result['requested_bytes']) == 16384:
            delays = [int(c['first_byte_delay_ms']) for c in chunks[capture_id].values() if 'first_byte_delay_ms' in c]
            if len(delays) == 4:
                span = max(delays)-min(delays)
                kernel_spans.append(span)
                if saved == 16384: full_kernel_spans.append(span)
    assert results, 'no capture results'
    for field, total in (('capture_read_bytes', 'saved'), ('capture_read_failed_bytes', 'failed'),
                         ('capture_known_unreadable_bytes', 'skipped'), ('capture_discardable_unreadable_bytes', 'discardable')):
        if field in pipeline:
            assert int(pipeline[field]) == totals[total], ('pipeline total mismatch', field)
    recovered = 0
    for (capture_id, address) in retries:
        for chunk in chunks[capture_id].values():
            if int(chunk['address']) == address and chunk.get('persistence') == 'complete':
                recovered += int(chunk['capture_bytes'])
    assert len(retries) == int(pipeline.get('capture_retried_pages', 0))
    assert recovered == int(pipeline.get('capture_recovered_bytes', 0))
    if require_discardable:
        assert totals['discardable'] > 0, 'discardable path was not exercised'
    kernel_continuations = int(pipeline.get('capture_kernel_contiguous_pages', 0))
    if require_kernel_quantum:
        assert kernel_continuations > 0, 'kernel capture quantum was not exercised'
    root_resolutions = int(pipeline.get('capture_root_layout_resolutions', 0))
    root_checks = int(pipeline.get('capture_root_identity_checks', 0))
    if require_root_layout_cache:
        assert root_resolutions == 1 and root_checks > 1, 'single-session root layout cache was not exercised'
    def distribution(values):
        ordered = sorted(values)
        return dict(requests=len(ordered), p50_ms=ordered[len(ordered)//2],
                    p95_ms=ordered[min(len(ordered)-1, (len(ordered)*95)//100)], max_ms=ordered[-1]) if ordered else dict(requests=0)
    return dict(passed=True, requests=len(results), standalone_chunks=len(standalone), standalone_bytes=standalone_bytes,
                retry_pages=len(retries), totals=dict(totals),
                roles={k: dict(v) for k, v in roles.items()},
                retry_recovered_bytes=recovered, kernel_contiguous_pages=kernel_continuations,
                root_layout_resolutions=root_resolutions, root_identity_checks=root_checks,
                kernel_16k_page_span=distribution(kernel_spans), full_kernel_16k_page_span=distribution(full_kernel_spans))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run')
    parser.add_argument('--require-discardable', action='store_true')
    parser.add_argument('--require-kernel-quantum', action='store_true')
    parser.add_argument('--require-root-layout-cache', action='store_true')
    args = parser.parse_args()
    report = audit(args.run, args.require_discardable, args.require_kernel_quantum, args.require_root_layout_cache)
    (pathlib.Path(args.run)/'capture-accounting.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
