# NGFW uRPF Telemetry Correlation — Case Study and Synthetic Lab

This repository contains two distinct bodies of work:

- [Technical case study](tech_draft.md): an account of the historical 2026 enterprise investigation.
- [Lab 01](lab01_network_assurance/README.md): an independently developed **synthetic educational demonstration**, created **after** the investigation and **not used** in that employer investigation.

## Run Lab 01

Requires Python 3.10+ and no third-party packages.

```powershell
cd lab01_network_assurance
python lab01_correlator.py --output lab01_report_v02.json
python -m unittest discover -s tests -v
```

The synthetic tests demonstrate unique NAT tuple correlation, ambiguous translations, unpaired events and SYN timing comparison; they do **not** establish application identity, complete packet transit, a general root cause, production utility or external adoption.

## Earlier illustrative parser

[urpf_nat_parser.py](urpf_nat_parser.py) is an older post-investigation proof of concept that correlates on a public IP address alone, which cannot uniquely attribute traffic under PAT. It should not be used for operational root-cause determination. The original file is retained without alteration.

## Confidentiality

The new lab uses fictional examples and documentation-reserved public IPv4 ranges. Do not upload employer records or identifiable operational data.
