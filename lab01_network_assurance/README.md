# Lab 01 — Synthetic Multi-Plane Network Assurance (v0.2)

**Educational demonstration only.** Developed after the 2026 enterprise investigation; not used in that investigation. The lab has no demonstrated external deployment or adoption.

## Purpose

Illustrate bounded correlation of 106021-style firewall syslogs, ASP reverse-path drop records, NAT/PAT state, endpoint records, and TCP SYN observations. A syslog without Layer 4 ports cannot identify a specific PAT translation.

## Run

Python 3.10+; no additional dependencies. From this folder:

```powershell
python lab01_correlator.py --output lab01_report_v02.json
python -m unittest discover -s tests -v
```

## Inputs

Five fictional CSV fixtures in `examples/`: `syslog.csv`, `asp.csv`, `nat.csv`, `endpoint.csv`, `syn_timeline.csv`. All public IPs are documentation-reserved.

## Expected classifications

| Case | Expected assessment | Explanation |
|---|---|---|
| ASP-001 | CORRELATED_SAMPLE; SEQUENCE_CONSISTENT | One matched translation and endpoint observation, paired SYN series |
| ASP-002 | AMBIGUOUS; NOT_ASSESSED | Two conflicting NAT candidates |
| SYS-003 | Unpaired | No matching ASP record |

Four illustrative intervals (1, 2, 4 and 8 seconds) are NOT a universal TCP retransmission fingerprint. In the bundled synthetic sample, the maximum paired SYN timestamp difference is 0.08 seconds. The 14 tests were run successfully on the sample package; further operational validation is not established.

## Limitations

- Correlation of synthetic observations is not evidence of causation or application identity.
- Matching SYN timestamps does not prove unique packets, full transit, or synchronized clocks.
- Timezone offsets are normalized, but unmeasured clock skew is not estimated.
- The NAT model is simplified and does not implement production translation lifecycles.
- The lab cannot establish effectiveness or adoption in real networks.

The included `expected_report.json` is a synthetic output fixture. This work is separate from the historical employer investigation.
