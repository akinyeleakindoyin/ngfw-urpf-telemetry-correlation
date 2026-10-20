"""Additional synthetic SYN series tests for Lab 01 v0.2."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lab01_correlator import read_csv, correlate, utc  # noqa: E402


class TimelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = ROOT / "examples"
        cls.data = {n: read_csv(d / (n + ".csv"))
                    for n in ("syslog", "asp", "nat", "endpoint", "syn_timeline")}

    def calculate(self, series=None, **changes):
        d = self.data.copy()
        d.update(changes)
        return correlate(d["syslog"], d["asp"], d["nat"], d["endpoint"],
                         syn_events=d["syn_timeline"] if series is None else series)

    def test_syn_sequences_are_consistent_across_planes(self):
        first = self.calculate()["correlations"][0]
        self.assertEqual(first["status"], "CORRELATED_SAMPLE")
        t = first["timeline_assessment"]
        self.assertEqual(t["status"], "SEQUENCE_CONSISTENT")
        self.assertEqual(t["firewall_syn_count"], 5)
        self.assertEqual(t["endpoint_syn_count"], 5)
        self.assertEqual(t["firewall_intervals_s"], [1, 2, 4, 8])
        self.assertTrue(t["illustrative_backoff_consistent"])

    def test_timezone_offsets_refer_to_same_instant(self):
        self.assertEqual(utc("2026-10-20T15:00:01.200Z"),
                         utc("2026-10-20T08:00:01.200-07:00"))

    def test_missing_endpoint_syn_is_not_falsely_consistent(self):
        trimmed = [r for r in self.data["syn_timeline"] if r["packet_id"] != "EN-SYN-03"]
        first = self.calculate(series=trimmed)["correlations"][0]
        self.assertEqual(first["timeline_assessment"]["status"], "SEQUENCE_MISMATCH")

    def test_clock_misalignment_is_not_falsely_consistent(self):
        altered = [dict(r) for r in self.data["syn_timeline"]]
        for r in altered:
            if r["packet_id"] == "EN-SYN-04":
                r["timestamp"] = "2026-10-20T15:00:08.280Z"  # +1 s skew for one packet
        first = self.calculate(series=altered)["correlations"][0]
        self.assertEqual(first["timeline_assessment"]["status"], "SEQUENCE_MISMATCH")

    def test_ambiguous_nat_avoids_sequence_assertion(self):
        second = self.calculate()["correlations"][1]
        self.assertEqual(second["status"], "AMBIGUOUS")
        self.assertEqual(second["timeline_assessment"]["status"], "NOT_ASSESSED")

    def test_empty_timeline_is_insufficient(self):
        first = self.calculate(series=[])["correlations"][0]
        self.assertEqual(first["timeline_assessment"]["status"], "INSUFFICIENT_TIMELINE_DATA")

    def test_non_syn_packets_do_not_count(self):
        converted = [dict(r) for r in self.data["syn_timeline"]]
        for r in converted:
            if r["plane"] == "firewall":
                r["tcp_flags"] = "ACK"
        first = self.calculate(series=converted)["correlations"][0]
        self.assertEqual(first["timeline_assessment"]["status"], "INSUFFICIENT_TIMELINE_DATA")

    def test_naive_timestamp_rejected_from_timeline(self):
        modified = [dict(r) for r in self.data["syn_timeline"]]
        modified[0]["timestamp"] = "2026-10-20T15:00:00.200"
        with self.assertRaises(ValueError):
            self.calculate(series=modified)

    def test_correlation_with_no_timeline_provided_is_explicit(self):
        d = self.data
        first = correlate(d["syslog"], d["asp"], d["nat"], d["endpoint"])["correlations"][0]
        self.assertEqual(first["timeline_assessment"]["status"], "NO_TIMELINE_INPUT")

if __name__ == "__main__":
    unittest.main()
