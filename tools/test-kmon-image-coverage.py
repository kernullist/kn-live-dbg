"""Counterexamples for cohort and address-range comparisons."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('coverage', pathlib.Path(__file__).with_name('measure-kmon-image-coverage.py'))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


def report(rows):
    return dict(processes={key: dict(group='background', ranges=ranges) for key, ranges in rows.items()},
                completed_images={'background': []})


class CoverageTests(unittest.TestCase):
    def test_overlapping_ranges_count_once(self):
        self.assertEqual(coverage.merge([[10, 20], [12, 15], [20, 30], [1, 4]]), [[1, 4], [10, 30]])

    def test_zero_byte_process_stays_in_cohort(self):
        a, b = report({'boot:1:10': [[1, 5]], 'boot:2:20': [[1, 5]]}), report({'boot:1:10': [], 'boot:2:20': [[1, 5]]})
        result = coverage.compare(a, b)
        self.assertEqual((result['common_background_process_generations'], result['candidate_zero_compared_processes']), (2, 1))
        self.assertEqual((result['jaccard'], result['baseline_only_address_bytes']), (0.5, 4))

    def test_same_pid_different_generation_is_not_common(self):
        self.assertEqual(coverage.cohort([report({'boot:1:10': []}), report({'boot:1:11': []})]), set())

    def test_fixed_cohort_uses_all_runs(self):
        a = report({'boot:1:10': [[1, 10]], 'boot:2:20': [[1, 10]]})
        b = report({'boot:1:10': [[1, 5]], 'boot:2:20': []})
        common = coverage.cohort([a, b, report({'boot:2:20': []})])
        result = coverage.compare(a, b, common)
        self.assertEqual((result['baseline_unique_bytes'], result['candidate_unique_bytes']), (9, 0))

    def test_equal_volume_can_cover_different_addresses(self):
        result = coverage.compare(report({'boot:1:10': [[1, 5]]}), report({'boot:1:10': [[5, 9]]}))
        self.assertEqual((result['jaccard'], result['symmetric_difference_bytes']), (0, 8))

    def test_empty_comparisons_do_not_claim_repeatability(self):
        result = coverage.compare(report({'boot:1:10': []}), report({'boot:1:10': []}))
        self.assertIsNone(result['jaccard'])

    def test_unknown_cohort_rejected(self):
        with self.assertRaises(ValueError):
            coverage.compare(report({'boot:1:10': []}), report({'boot:1:10': []}), {'boot:1:11'})

    def test_invalid_range_rejected(self):
        for value in [[[10, 10]], [[-1, 5]], [[0, 2**64 + 1]]]:
            with self.assertRaises(ValueError): coverage.merge(value)


if __name__ == '__main__':
    unittest.main()
