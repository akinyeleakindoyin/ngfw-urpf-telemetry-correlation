"""Run from lab root: python -m unittest discover -s tests -v"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lab01_correlator import read_csv, correlate, utc  # noqa: E402


class CorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = ROOT / 'examples'
        cls.data = {x: read_csv(d / f'{x}.csv') for x in ('syslog', 'asp', 'nat', 'endpoint')}

    def test_unique_flow_uses_exact_translated_port_not_public_ip_alone(self):
        r = correlate(**self._arguments())
        first = r['correlations'][0]
        self.assertEqual(first['status'], 'CORRELATED_SAMPLE')
        self.assertEqual(first['inside_sockets'], ['10.0.1.50:51543'])
        self.assertEqual(first['nat_candidate_count'], 1)

    def test_colliding_translations_are_ambiguous_not_falsely_proven(self):
        r = correlate(**self._arguments())
        second = r['correlations'][1]
        self.assertEqual(second['status'], 'AMBIGUOUS')
        self.assertEqual(second['nat_candidate_count'], 2)

    def test_syslog_without_asp_is_unpaired(self):
        r = correlate(**self._arguments())
        self.assertEqual(r['unpaired_syslog_ids'], ['SYS-003'])

    def test_unrelated_port_has_no_matching_nat(self):
        d = self._arguments()
        d['asp_drops'] = [dict(d['asp_drops'][0], src_port='99999')]
        report = correlate(**d)
        self.assertEqual(report['correlations'][0]['status'], 'INSUFFICIENT_EVIDENCE')

    def test_naive_timestamps_are_rejected(self):
        with self.assertRaises(ValueError):
            utc('2026-10-20T15:00:00')

    @classmethod
    def _arguments(cls):
        d = cls.data
        return {'syslogs': d['syslog'], 'asp_drops': d['asp'], 'nat_table': d['nat'], 'endpoints': d['endpoint']}


if __name__ == '__main__':
    unittest.main()
