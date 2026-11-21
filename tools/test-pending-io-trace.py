"""Independent wire and lifecycle expectations for the fixture ring and retained page decoder."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPLAY = Path(__file__).with_name('replay-pending-io-trace.py')
T = runpy.run_path(str(REPLAY))
EPOCH = bytes(range(16))
ROW = struct.Struct('<6Q6I')
HEAD = struct.Struct('<4I16s5Q')


def row(seq, kind=1, *, request=1, topology=4, instance=5, qpc=None, length=4096,
        layer=1, major=3, status=0, flags=None, amount=0):
    if flags is None:
        flags = int(kind in (4, 5))
    return ROW.pack(seq, request, topology, instance, seq * 7 if qpc is None else qpc, amount,
                    kind, major, layer, flags, status, length)


def page(after, last, rows, epoch=EPOCH, hz=10000000, loss=0):
    first = max(1, last - 127) if last else 0
    header = HEAD.pack(0x54494e4b, 1, 648, len(rows), epoch, hz, after, first, last, loss)
    return header + b''.join(rows) + bytes(72 * (8 - len(rows)))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    return T['replay'](raw, digest(raw))


def stages(kinds, **kwargs):
    return page(0, len(kinds), [row(i, kind, **kwargs) for i, kind in enumerate(kinds, 1)])


class Trace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([EXE], capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        cls.native = result.stdout

    def test_native_publication_and_sample(self):
        self.assertEqual(len(self.native), 648 * 3)
        q1 = HEAD.unpack_from(self.native)
        self.assertEqual(q1[:4], (0x54494e4b, 1, 648, 8))
        self.assertEqual(q1[4], bytes.fromhex('4433221188776655ccbbaa9900ffeedd'))
        self.assertEqual(q1[5:], (10000000, 0, 1, 18, 0))
        self.assertEqual([HEAD.unpack_from(self.native, i * 648)[6] for i in range(3)], [0, 8, 16])
        result = decode(self.native)
        self.assertEqual((result['through_sequence'], result['retained_events'], result['missing_sequences']), (18, 18, []))
        self.assertEqual(result['capture_epoch'], '11223344-7788-5566-ccbb-aa9900ffeedd')
        one, two = result['requests']
        for request in (one, two):
            self.assertEqual(request['observation'], 'upper_fixture_outcome_observed')
            self.assertEqual(set(request['layers']), {'upper', 'lower'})
            self.assertTrue(all(layer['retired'] for layer in request['layers'].values()))
            for event in request['events']:
                self.assertEqual(ROW.unpack_from(self.native, event['source_offset'])[:2],
                                 (event['sequence'], request['request']))
        self.assertEqual([one['request'], one['upper_status'], two['request'], two['upper_status']], [1, 0xc0000120, 2, 0])
        self.assertEqual(one['layers']['lower']['pre_pending_qpc_ticks'], 110)
        self.assertEqual(two['layers']['lower']['pre_pending_qpc_ticks'], 10)
        self.assertEqual([e['transferred'] for e in two['events'] if e['kind'] == 'post_observed'], [4096, 4096])
        self.assertEqual([e['sequence'] for e in one['events']], [1, 2, 3, 4, 14, 15, 16, 17, 18])

    def test_client_snapshot_and_file_publication(self):
        live = runpy.run_path(str(REPLAY.with_name('run-pending-io-trace-e2e.py')))
        port_type = live['p'].Port
        calls, written = [], []
        def connect(_name, _options, context, length, _attrs, out):
            calls.append(ctypes.string_at(context, length) if length else None)
            ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0] = 240
            return 0
        def read(handle, request, size, output, capacity, returned):
            self.assertEqual((handle.value, size, capacity), (240, 40, 648))
            magic, version, expected_size, reserved, epoch, after = struct.unpack('<4I16sQ', ctypes.string_at(request, size))
            self.assertEqual((magic, version, expected_size, reserved), (0x54494e4b, 1, 40, 0))
            self.assertEqual(epoch, self.native[16:32] if after else bytes(16))
            start = {0: 0, 8: 648, 16: 1296}[after]
            ctypes.memmove(output, self.native[start:start + 648], 648)
            ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32))[0] = 648
            return 0
        class Output:
            def record(self, kind, **detail):
                written.append((kind, detail))
        suite = Output()
        with tempfile.TemporaryDirectory() as directory, patch.object(live['p'].flt, 'FilterConnectCommunicationPort', connect), \
                patch.object(live['p'].flt, 'FilterSendMessage', read), \
                patch.object(live['p'].kernel, 'CloseHandle', return_value=1):
            suite.output = Path(directory)
            with port_type(), port_type(live['CONNECT']) as owner:
                raw = live['capture'](owner)
            self.assertEqual(calls, [None, struct.pack('<4I', 0x54494e4b, 1, 16, 0)])
            with self.assertRaises(ValueError):
                port_type(bytes(65536))
            self.assertEqual(raw, self.native)
            report = live['retain'](suite, raw, 'round')
            self.assertEqual(report, decode(self.native))
            with self.assertRaises(FileExistsError):
                live['retain'](suite, page(0, 0, []), 'round')
            with patch('os.fsync', side_effect=OSError('fixture write error')), self.assertRaises(OSError):
                live['retain'](suite, raw, 'failed')
            target, = suite.output.iterdir()
            self.assertEqual(target.name, 'round.kniotrace')
            self.assertEqual(target.read_bytes(), self.native)
            self.assertEqual(written, [('capture', dict(file=target.name, sha256=digest(self.native)))])

    def test_fixture_help_precedes_driver_access(self):
        for script in ('run-pending-io-trace-e2e.py', 'run-pending-io-e2e.py'):
            cmd = [sys.executable, '-I', '-B', REPLAY.with_name(script)]
            help_text = subprocess.run(cmd + ['--help'], capture_output=True, timeout=10)
            self.assertEqual(help_text.returncode, 0)
            self.assertIn(b'--output', help_text.stdout)
            usage = subprocess.run(cmd, capture_output=True, timeout=10)
            self.assertEqual(usage.returncode, 2)
            self.assertNotIn(b'Traceback', usage.stderr)

    def test_cli_pin_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace sample.pages'
            path.write_bytes(self.native)
            cmd = [sys.executable, '-I', '-B', REPLAY, path, '--sha256']
            ok = subprocess.run(cmd + [digest(self.native).upper()], capture_output=True, timeout=10, check=True)
            self.assertEqual(json.loads(ok.stdout), decode(self.native))
            for pin in ('0' * 64, 'bad'):
                fail = subprocess.run(cmd + [pin], capture_output=True, timeout=10)
                self.assertNotEqual(fail.returncode, 0)
                self.assertEqual(fail.stdout, b'')
            path.write_bytes(self.native[:-1])
            fail = subprocess.run(cmd + [digest(self.native)], capture_output=True, timeout=10)
            self.assertIn(b'SHA-256 mismatch', fail.stderr)

    def test_explicit_status_and_retirement(self):
        for kinds in ([1, 2], [1, 2, 11], [1, 3, 5], [1, 3, 8, 9], [1, 2, 4], [1, 3, 5, 6, 11]):
            r, = decode(stages(kinds))['requests']
            self.assertEqual(r['observation'], 'unknown_outcome', kinds)
            self.assertIsNone(r['upper_status'])
        r, = decode(stages([1, 3, 5, 6, 7, 9]))['requests']
        self.assertEqual(r['upper_status'], 0)
        self.assertEqual(r['layers']['upper']['post_pending_qpc_ticks'], 7)
        r, = decode(page(0, 3, [row(1), row(2, 4, status=0xc000009a), row(3, 9)]))['requests']
        self.assertEqual(r['upper_status'], 0xc000009a)
        r, = decode(stages([1, 10]))['requests']
        self.assertEqual(r['observation'], 'observation_gap')

    def test_unknowns_conflicts_and_clock(self):
        for kinds in ([9], [1, 9], [1, 3, 5, 6, 9], [1, 3, 8, 5, 9], [1, 3, 5, 9, 11]):
            r, = decode(stages(kinds))['requests']
            self.assertEqual(r['observation'], 'transition_conflict', kinds)
            self.assertIsNone(r['upper_status'])
        r, = decode(stages([1, 3, 5, 9, 1]))['requests']
        self.assertEqual(r['observation'], 'identity_conflict')
        rows = [row(1), row(2, 3), row(3, 5, instance=9), row(4, 9)]
        r, = decode(page(0, 4, rows))['requests']
        self.assertIn('upper_source_changed', r['identity_conflicts'])
        rows[2] = row(3, 5, qpc=2)
        r, = decode(page(0, 4, rows))['requests']
        self.assertEqual(r['upper_status'], 0)
        self.assertIsNone(r['layers']['upper']['dispatch_to_outcome_qpc_ticks'])

    def test_cross_layer_and_generation_conflicts(self):
        records = [row(1), row(2, layer=2, instance=6), row(3, 4), row(4, 9)]
        r, = decode(page(0, 4, records))['requests']
        self.assertIn('lower_dispatch_without_upper_forward', r['transition_conflicts'])
        records = [row(1, request=2), row(2, request=1)]
        self.assertTrue(all(r['observation'] == 'identity_conflict' for r in decode(page(0, 2, records))['requests']))
        records = [row(1), row(2, 3), row(3, 1, request=2), row(4, 1, layer=2, instance=5)]
        self.assertTrue(all('instance_role_changed' in r['identity_conflicts'] for r in decode(page(0, 4, records))['requests']))

    def test_paging_pins_first_cut_with_later_rows_preserved(self):
        seen = []
        def read(query):
            header = struct.unpack('<4I16sQ', query)
            self.assertEqual(header[:4], (0x54494e4b, 1, 40, 0))
            epoch, after = header[4:]
            seen.append(after)
            self.assertEqual(epoch, EPOCH if after else bytes(16))
            high = 15 if after else 10
            return page(after, high, [row(i, request=i) for i in range(after + 1, min(high, after + 8) + 1)])
        raw = T['capture_pages'](read)
        self.assertEqual(seen, [0, 8])
        r = decode(raw)
        self.assertEqual((r['through_sequence'], r['retained_events'], HEAD.unpack_from(raw, 648)[8]), (10, 10, 15))
        self.assertEqual(len(r['requests']), 10)
        self.assertEqual(r['later_rows_in_original_pages'], 5)

    def test_overwrite_while_reading_and_missing_prefix(self):
        one = page(0, 10, [row(i, request=i) for i in range(1, 9)])
        two = page(8, 147, [row(i, request=i) for i in range(20, 28)])
        result = decode(one + two)
        self.assertEqual(result['missing_sequences'], [[9, 10]])
        self.assertEqual(result['retained_events'], 8)
        self.assertTrue(all(r['observation'] == 'observation_gap' for r in result['requests']))
        first = page(0, 129, [row(2, 5), row(3, 9)] + [row(i, request=i) for i in range(4, 10)])
        rest = page(9, 300, [row(i, request=i) for i in range(173, 181)])
        result = decode(first + rest)
        self.assertEqual(result['missing_sequences'], [[1, 1], [10, 129]])
        self.assertEqual(result['requests'][0]['observation'], 'observation_gap')
        self.assertIsNone(result['requests'][0]['upper_status'])

    def test_page_contract_and_identity(self):
        sample = self.native
        changes = [(0, b'xxxx'), (4, bytes(4)), (8, bytes(4)), (12, bytes(4)), (16, bytes(16)),
                   (32, bytes(8)), (48, bytes(8)), (64, bytes([16])), (72, bytes(8)),
                   (80, bytes(8)), (88, bytes(8)), (96, bytes(8)), (72 + 48, bytes(4)),
                   (648 + 16, bytes(16)), (648 + 32, bytes(8)), (648 + 40, bytes(8)),
                   (648 + 56, bytes(8)), (648 * 3 - 1, bytes([1]))]
        for offset, replacement in changes:
            data = bytearray(sample)
            data[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                decode(data)
        for invalid in (b'', sample[:-1], sample[:-648], sample + sample[-648:], bytes(648 * 17)):
            with self.assertRaises(ValueError):
                decode(invalid)
        mixed = sample[:648] + sample[648:664] + EPOCH + sample[680:]
        with self.assertRaisesRegex(ValueError, 'capture identity changed'):
            decode(mixed)
        raw = page(0, 0, [])
        self.assertEqual(decode(raw)['requests'], [])
        with self.assertRaises(ValueError):
            decode(raw + raw)

    def test_field_validity(self):
        for bad in (row(1, 5, flags=0), row(1, 8, flags=1), row(1, 4, flags=3), row(1, flags=4),
                    row(1, status=9), row(1, 5, flags=3, amount=4097), row(1, 5, amount=1),
                    row(1, 5, flags=3, status=0xc0000120), row(1, 5, flags=3, major=0, length=0),
                    row(1, major=0, layer=2, length=0), row(1, major=1), row(1, layer=3), row(1, kind=12)):
            with self.assertRaises(ValueError):
                decode(page(0, 1, [bad]))
        raw = stages([1, 3, 5, 9], major=0, length=0)
        r, = decode(raw)['requests']
        self.assertIsNone(r['events'][2]['transferred'])

    def test_retained_page_loss_flags_are_monotonic(self):
        rows = [row(i, request=i) for i in range(1, 10)]
        head = page(0, 9, rows[:8], loss=2)
        tail = page(8, 9, rows[8:], loss=6)
        result = decode(head + tail)
        self.assertEqual(result['loss_flags'], 6)
        self.assertEqual(result['loss_reasons'], ['generation_exhausted', 'instance_exhausted'])
        with self.assertRaises(ValueError):
            decode(head + page(8, 9, rows[8:], loss=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    EXE = args.exe.resolve()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
