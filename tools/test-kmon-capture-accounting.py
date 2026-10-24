"""Counterexamples for the saved native capture audit; no driver required."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('capture_audit', pathlib.Path(__file__).with_name('validate-kmon-capture-accounting.py'))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class CaptureAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root/'captures').mkdir()
        header = bytearray(4096)
        header[:2] = b'MZ'
        struct.pack_into('<I', header, 0x3c, 128)
        header[128:132] = b'PE\0\0'
        struct.pack_into('<H', header, 134, 1)
        struct.pack_into('<H', header, 148, 240)
        struct.pack_into('<H', header, 152, 0x20b)
        struct.pack_into('<I', header, 184, 4096)
        struct.pack_into('<II', header, 208, 8192, 4096)
        struct.pack_into('<8sIII', header, 392, b'INIT', 4096, 4096, 512)
        struct.pack_into('<I', header, 428, 0x02000020)
        self.header = bytes(header)
        path = self.root/'captures'/'head.bin'
        path.write_bytes(header)
        self.events = [
            dict(kind='coverage.capture', evidence=dict(capture_id='1', chunk_offset='0', address='65536',
                capture_bytes='4096', capture_path=str(path), capture_sha256=hashlib.sha256(header).hexdigest(), persistence='complete')),
            dict(kind='coverage.capture', evidence=dict(capture_id='1', failed_offset='4096', address='69632',
                failed_bytes='0', skipped_bytes='4096', coverage_reason='unreadable_discardable_section', discardable_section='INIT')),
            dict(kind='coverage.capture_result', evidence=dict(capture_id='1', capture_role='driver_image',
                requested_bytes='8192', compared_bytes='4096', failed_bytes='0', known_unreadable_bytes='4096',
                skipped_bytes='4096', discardable_unreadable_bytes='4096', unvisited_bytes='0')),
        ]

    def run_audit(self, events=None):
        (self.root/'kmon-events.1.0.jsonl').write_text('\n'.join(json.dumps(e, separators=(',', ':')) for e in (self.events if events is None else events))+'\n')
        return audit.audit(self.root, True)

    def test_gap_is_not_coverage(self):
        totals = self.run_audit()['totals']
        self.assertEqual(totals['saved'], 4096)
        self.assertEqual(totals['skipped'], 4096)

    def test_forged_completion(self):
        self.events[2]['evidence']['compared_bytes'] = '8192'
        with self.assertRaises(AssertionError): self.run_audit()

    def test_missing_gap(self):
        with self.assertRaises(AssertionError): self.run_audit([self.events[0], self.events[2]])

    def test_duplicate_chunk(self):
        self.events.append(copy.deepcopy(self.events[0]))
        with self.assertRaises(AssertionError): self.run_audit()

    def test_wrong_section(self):
        self.events[1]['evidence']['discardable_section'] = '.text'
        with self.assertRaises(AssertionError): self.run_audit()

    def test_truncated_header(self):
        with self.assertRaises((AssertionError, struct.error)):
            audit.discardable_sections(self.header[:256], 8192, 4096, 4096)

    def test_not_discardable(self):
        header = bytearray(self.header)
        struct.pack_into('<I', header, 428, 0x60000020)
        with self.assertRaises(AssertionError): audit.discardable_sections(header, 8192, 4096, 4096)

    def test_short_optional_header(self):
        header = bytearray(self.header)
        struct.pack_into('<H', header, 148, 112)
        with self.assertRaises(AssertionError): audit.discardable_sections(header, 8192, 4096, 4096)

    def test_changed_saved_bytes(self):
        (self.root/'captures'/'head.bin').write_bytes(b'x'*4096)
        with self.assertRaises(AssertionError): self.run_audit()

    def test_invented_retry_recovery(self):
        self.events.append(dict(kind='coverage.pipeline', evidence=dict(capture_retried_pages='0', capture_recovered_bytes='4096')))
        with self.assertRaises(AssertionError): self.run_audit()

    def test_saved_chunk_also_claims_failure(self):
        self.events[0]['evidence']['failed_bytes'] = '4096'
        with self.assertRaises(AssertionError): self.run_audit()

    def test_chunk_without_result(self):
        chunk = copy.deepcopy(self.events[0])
        chunk['evidence']['capture_id'] = '2'
        self.events.append(chunk)
        with self.assertRaises(AssertionError): self.run_audit()

    def test_standalone_reference_has_separate_totals(self):
        chunk = copy.deepcopy(self.events[0])
        chunk['evidence'].update(capture_id='2', capture_role='expected_code')
        self.events.append(chunk)
        report = self.run_audit()
        self.assertEqual(report['standalone_bytes'], 4096)
        self.assertEqual(report['totals']['saved'], 4096)

    def test_negative_gap(self):
        self.events[1]['evidence']['failed_bytes'] = '-1'
        self.events[1]['evidence']['skipped_bytes'] = '4097'
        with self.assertRaises(AssertionError): self.run_audit()

    def test_pipeline_total_mismatch(self):
        self.events.append(dict(kind='coverage.pipeline', evidence=dict(capture_read_failed_bytes='4096')))
        with self.assertRaises(AssertionError): self.run_audit()


if __name__ == '__main__':
    unittest.main()
