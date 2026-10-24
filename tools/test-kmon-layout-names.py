"""Counterexamples for name recovery evidence, without a live driver."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('names', pathlib.Path(__file__).with_name('validate-kmon-layout-names.py'))
names = importlib.util.module_from_spec(spec)
spec.loader.exec_module(names)


class NameAuditTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(image_allocations=1, image_names_known=1, image_name_failures=0,
            image_name_capacity_failures=0, image_name_query_failures=0, image_name_truncated=0,
            image_name_unqueryable=0, image_name_retry_attempts=1, image_name_recovered=1,
            image_name_diagnostics_omitted=0, image_name_diagnostics=[dict(address='4096', allocation_base='4096',
            initial_error=59, retry_error=0, retried=True, recovered=True, stage='recovered',
            current_allocation_base='4096', current_state=0x1000, current_type=0x1000000)])

    def test_observed_recovery(self):
        self.assertEqual(names.check_record(self.record)['recovered'], 1)

    def test_changed_allocation_cannot_recover(self):
        self.record['image_name_diagnostics'][0]['current_allocation_base'] = '8192'
        with self.assertRaises(ValueError): names.check_record(self.record)

    def test_unmapped_page_cannot_recover(self):
        self.record['image_name_diagnostics'][0]['current_state'] = 0x10000
        with self.assertRaises(ValueError): names.check_record(self.record)

    def test_missing_diagnostic(self):
        self.record['image_name_diagnostics'] = []
        with self.assertRaises(ValueError): names.check_record(self.record)

    def test_invented_retry(self):
        self.record['image_name_retry_attempts'] = 2
        with self.assertRaises(ValueError): names.check_record(self.record)

    def test_gap_cannot_be_counted_as_known(self):
        self.record['image_name_failures'] = 1
        with self.assertRaises(ValueError): names.check_record(self.record)

    def test_legacy_requires_explicit_option(self):
        del self.record['image_name_diagnostics']
        with self.assertRaises(ValueError): names.check_record(self.record)
        self.assertTrue(names.check_record(self.record, True)['legacy'])

    def test_unresolved_retry_stays_gap(self):
        self.record.update(image_names_known=0, image_name_failures=1, image_name_query_failures=1, image_name_recovered=0)
        self.record['image_name_diagnostics'][0].update(recovered=False, stage='retry_failed', retry_error=59)
        result = names.check_record(self.record)
        self.assertEqual((result['query_failures'], result['recovered']), (1, 0))


if __name__ == '__main__':
    unittest.main()
