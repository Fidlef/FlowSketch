"""FlowSketch: privacy-aware triage of synthetic network-flow metadata."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def analyze_rows(rows: list[dict]) -> dict:
    flows = defaultdict(list)
    dns_by_source = defaultdict(list)
    for row in rows:
        key = (row["src_ip"], row["dst_ip"], row["dst_port"], row["protocol"].upper())
        flows[key].append(parse_time(row["timestamp"]))
        query = row.get("dns_query", "").strip()
        if query:
            dns_by_source[row["src_ip"]].append(query)

    findings = []
    for key, timestamps in sorted(flows.items()):
        timestamps.sort()
        if len(timestamps) < 5:
            continue
        intervals = [(right - left).total_seconds() for left, right in zip(timestamps, timestamps[1:])]
        mean = statistics.mean(intervals)
        variation = statistics.pstdev(intervals) / mean if mean else 0
        if 5 <= mean <= 3600 and variation <= 0.15:
            findings.append({
                "type": "periodic-flow",
                "priority": "review",
                "flow": {"source": key[0], "destination": key[1], "port": key[2], "protocol": key[3]},
                "evidence": {"observations": len(timestamps), "mean_interval_seconds": round(mean, 2), "coefficient_of_variation": round(variation, 3)},
                "explanation": "Regular timing can indicate automated software, monitoring, updates, or beaconing. Context is required.",
            })

    for source, queries in sorted(dns_by_source.items()):
        labels = [query.split(".")[0] for query in queries]
        average = statistics.mean(len(label) for label in labels)
        unique_ratio = len(set(labels)) / len(labels)
        if len(labels) >= 5 and average >= 30 and unique_ratio >= 0.8:
            findings.append({
                "type": "high-variation-dns-labels",
                "priority": "review",
                "source": source,
                "evidence": {"queries": len(labels), "average_first_label_length": round(average, 1), "unique_ratio": round(unique_ratio, 2)},
                "explanation": "Long, changing labels can be legitimate telemetry or encoded data. FlowSketch does not inspect payloads or resolve domains.",
            })

    return {
        "records_analyzed": len(rows),
        "distinct_flows": len(flows),
        "findings": findings,
        "privacy_note": "Analysis uses supplied metadata only; no packets are captured and no payload content is inspected.",
        "limitations": "Timing heuristics generate false positives and are not evidence of compromise.",
    }


def analyze_csv(path: Path) -> dict:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "dns_query"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"CSV must contain: {', '.join(sorted(required))}")
    return analyze_rows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Find explainable patterns in authorized flow metadata.")
    parser.add_argument("csv_file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = analyze_csv(args.csv_file)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
