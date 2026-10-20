"""Lab 01 v0.2: synthetic multi-plane traffic and SYN-timeline correlation.

Educational code developed AFTER the historical June/July 2026 investigation;
not used in production and not evidence that a root cause has been proven.
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def utc(value: str) -> datetime:
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError(f"Timestamp requires timezone offset: {value}")
    return stamp.astimezone(timezone.utc)


def seconds_apart(a: str, b: str) -> float:
    return abs((utc(a) - utc(b)).total_seconds())


def unique_mappings(matches: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    result = []
    for row in matches:
        key = (row["inside_ip"], row["inside_port"], row["outside_ip"], row["outside_port"])
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def _intervals(rows: list[dict[str, str]]) -> list[float]:
    return [round((utc(b["timestamp"]) - utc(a["timestamp"])).total_seconds(), 3)
            for a, b in zip(rows, rows[1:])]


def assess_syn_timeline(asp: dict[str, str], nat: dict[str, str],
                        syn_events: list[dict[str, str]],
                        anchor_window_s: float = 2.0,
                        pair_tolerance_s: float = 0.3) -> dict:
    """Compare *illustrative* SYN observation series across the two planes.

    No TCP sequence numbers are available; the code reports timing *consistent with*
    retransmission, not verified TCP retransmissions or a confirmed path.
    It requires 3+ records per plane, stable tuples and one-to-one timing alignment.
    """
    limit_s = 18.0  # Separate illustrated burst (0/1/3/7/15 s); NOT production inference.
    def select(plane: str, source_ip: str, source_port: str):
        return sorted((r for r in syn_events
            if r.get("plane") == plane
            and r.get("protocol", "").upper() == "TCP"
            and r.get("tcp_flags", "").upper() == "SYN"
            and r.get("src_ip") == source_ip and r.get("src_port") == source_port
            and r.get("dst_ip") == asp["dst_ip"] and r.get("dst_port") == asp["dst_port"]
            and seconds_apart(r["timestamp"], asp["timestamp"]) <= limit_s),
            key=lambda r: utc(r["timestamp"]))

    firewall = select("firewall", nat["outside_ip"], nat["outside_port"])
    endpoint = select("endpoint", nat["inside_ip"], nat["inside_port"])
    outcome = {
        "status": "INSUFFICIENT_TIMELINE_DATA",
        "firewall_syn_count": len(firewall),
        "endpoint_syn_count": len(endpoint),
        "firewall_intervals_s": _intervals(firewall),
        "endpoint_intervals_s": _intervals(endpoint),
        "max_pair_time_difference_s": None,
        "illustrative_backoff_consistent": False,
        "limitation": "At least three SYN observations per plane are required for an illustrative sequence comparison."
    }
    if len(firewall) < 3 or len(endpoint) < 3:
        return outcome
    if (seconds_apart(firewall[0]["timestamp"], asp["timestamp"]) > anchor_window_s or
        seconds_apart(endpoint[0]["timestamp"], asp["timestamp"]) > anchor_window_s):
        outcome.update(status="SEQUENCE_MISMATCH", limitation="Initial series observations lie outside the ASP anchor window.")
        return outcome
    if len(firewall) != len(endpoint):
        outcome.update(status="SEQUENCE_MISMATCH", limitation="Different SYN observation counts across the two planes; missing or extra evidence.")
        return outcome
    diffs = [seconds_apart(f["timestamp"], e["timestamp"]) for f, e in zip(firewall, endpoint)]
    outcome["max_pair_time_difference_s"] = round(max(diffs), 3)
    if max(diffs) > pair_tolerance_s:
        outcome.update(status="SEQUENCE_MISMATCH", limitation="One or more matched-position observations exceed the allowable time difference; do not assert correlation.")
        return outcome
    # Demonstrate a fixed synthetic pattern, not a universal OS-specific TCP timer.
    ideal = (1, 2, 4, 8)
    gaps_firewall = outcome["firewall_intervals_s"]
    gaps_endpoint = outcome["endpoint_intervals_s"]
    backoff = (len(gaps_firewall) <= len(ideal) and
        all(abs(gaps_firewall[i] - ideal[i]) <= 0.35 and
            abs(gaps_endpoint[i] - ideal[i]) <= 0.35
            for i in range(len(gaps_firewall))))
    outcome.update(
        status="SEQUENCE_CONSISTENT",
        illustrative_backoff_consistent=backoff,
        limitation=("The SYN timestamps/tuples are consistent across two synthetic observation planes. "
                    "Clock synchronization, retransmission identity, complete transit, application owner "
                    "and a general root cause are NOT established."),
    )
    return outcome


def correlate(
    syslogs: list[dict[str, str]],
    asp_drops: list[dict[str, str]],
    nat_table: list[dict[str, str]],
    endpoints: list[dict[str, str]],
    window_s: float = 2.0,
    syn_events: list[dict[str, str]] | None = None,
) -> dict:
    records = []
    related_event_ids = set()
    for asp in asp_drops:
        if asp["drop_reason"] != "rpf-violated":
            continue
        linked_syslogs = [log for log in syslogs
            if log["event_code"] == "106021"
            and log["src_ip"] == asp["src_ip"]
            and log["dst_ip"] == asp["dst_ip"]
            and seconds_apart(log["timestamp"], asp["timestamp"]) <= window_s]
        related_event_ids.update(log["event_id"] for log in linked_syslogs)
        nat_candidates = unique_mappings([entry for entry in nat_table
            if entry["outside_ip"] == asp["src_ip"]
            and entry["outside_port"] == asp["src_port"]
            and entry["state"] == "active"
            and seconds_apart(entry["observed_at"], asp["timestamp"]) <= window_s])
        status = "INSUFFICIENT_EVIDENCE"
        limitation = "No active same-window NAT translation matched the translated source tuple."
        endpoint_matches = []
        timeline = {"status": "NOT_ASSESSED", "limitation": "A unique NAT candidate and endpoint observation are prerequisites."}
        if len(nat_candidates) > 1:
            status = "AMBIGUOUS"
            limitation = "Multiple different inside sockets share the observed translated tuple in this time window."
        elif len(nat_candidates) == 1:
            nat = nat_candidates[0]
            endpoint_matches = [ep for ep in endpoints
                if ep["src_ip"] == nat["inside_ip"]
                and ep["src_port"] == nat["inside_port"]
                and ep["dst_ip"] == asp["dst_ip"]
                and ep["dst_port"] == asp["dst_port"]
                and ep["protocol"].upper() == "TCP"
                and seconds_apart(ep["timestamp"], asp["timestamp"]) <= window_s]
            if endpoint_matches:
                status = "CORRELATED_SAMPLE"
                limitation = ("Matching packet and active translation support this sampled flow only. "
                    "Syslog has no ports; application identity, full transit and overall cause are NOT proven.")
                if syn_events is not None:
                    timeline = assess_syn_timeline(asp, nat, syn_events, anchor_window_s=window_s)
                else:
                    timeline = {"status": "NO_TIMELINE_INPUT", "limitation": "No SYN series provided."}
            else:
                limitation = "NAT candidate exists but no matching same-window endpoint observation was found."
        records.append({
            "asp_id": asp["asp_id"],
            "status": status,
            "public_tuple": f'{asp["src_ip"]}:{asp["src_port"]} -> {asp["dst_ip"]}:{asp["dst_port"]}',
            "syslog_context_ids": [log["event_id"] for log in linked_syslogs],
            "nat_candidate_count": len(nat_candidates),
            "inside_sockets": [f'{n["inside_ip"]}:{n["inside_port"]}' for n in nat_candidates],
            "endpoint_observation_count": len(endpoint_matches),
            "timeline_assessment": timeline,
            "limitation": limitation,
        })
    unpaired = [log["event_id"] for log in syslogs if log["event_id"] not in related_event_ids]
    return {
        "lab": "Lab 01 v0.2 — synthetic multi-plane network assurance",
        "disclaimer": "All observations are synthetic. This code was NOT used in any employer investigation.",
        "matching_window_seconds": window_s,
        "timeline_pair_tolerance_seconds": 0.3,
        "correlations": records,
        "unpaired_syslog_ids": unpaired,
        "warnings": [
            "A 106021 record lacks Layer 4 ports and cannot uniquely identify a PAT translation.",
            "Compatible SYN timing is not proof of application identity, full packet transit, a unique flow, or causality.",
            "Timing comparison assumes reasonably aligned clocks; ISO offsets are normalized, but unknown clock skew is not estimated.",
            "The illustrative 1/2/4/8-second backoff is not a universal TCP retransmission timing guarantee."
        ]
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab 01 v0.2: synthetic telemetry and SYN-timeline comparison")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).parent / "examples")
    parser.add_argument("--output", type=Path, default=Path("lab01_report.json"))
    args = parser.parse_args()
    names = ("syslog", "asp", "nat", "endpoint", "syn_timeline")
    data = {name: read_csv(args.data_dir / f"{name}.csv") for name in names}
    report = correlate(data["syslog"], data["asp"], data["nat"], data["endpoint"], syn_events=data["syn_timeline"])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for item in report["correlations"]:
        print(f'{item["asp_id"]}: {item["status"]} | {item["public_tuple"]}')
        print(f'  NAT candidates: {item["nat_candidate_count"]}; Endpoint records: {item["endpoint_observation_count"]}')
        print(f'  SYN sequence: {item["timeline_assessment"]["status"]}')
    print(f'Unpaired syslogs: {len(report["unpaired_syslog_ids"])}')
    print(f'Saved report to {args.output}')


if __name__ == "__main__":
    main()
