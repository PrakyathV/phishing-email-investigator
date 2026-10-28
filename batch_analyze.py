#!/usr/bin/env python3
"""Batch-analyze public .eml artifacts offline."""

import argparse
import csv
from collections import Counter
from pathlib import Path

from main import inspect_email


def main():
    parser = argparse.ArgumentParser(
        description="Batch-analyze email artifacts offline"
    )
    parser.add_argument(
        "--directory",
        required=True,
        help="Directory containing .eml files",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum number of emails to analyze (default: 25)",
    )
    parser.add_argument(
        "--output",
        default="reports/batch-summary.csv",
        help="CSV report path",
    )
    args = parser.parse_args()

    root = Path(args.directory).expanduser()
    if not root.is_dir():
        parser.error(f"Directory does not exist: {root}")
    if args.limit < 1:
        parser.error("--limit must be at least 1")

    files = sorted(root.rglob("*.eml"))[:args.limit]
    if not files:
        parser.error(f"No .eml files found under {root}")

    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    failures = 0

    for path in files:
        try:
            result = inspect_email(path)
            rows.append({
                "file": path.name,
                "sha256": result["sha256"],
                "size_bytes": result["size"],
                "risk_score": result["score"],
                "risk_category": result["rating"],
                "url_count": len(result["urls"]),
                "finding_count": len(result["findings"]),
            })
        except (OSError, ValueError) as exc:
            failures += 1
            print(f"Could not analyze {path.name}: {exc}")

    fields = [
        "file", "sha256", "size_bytes", "risk_score",
        "risk_category", "url_count", "finding_count",
    ]

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    counts = Counter(row["risk_category"] for row in rows)

    print(f"Emails discovered for analysis: {len(files)}")
    print(f"Emails successfully analyzed: {len(rows)}")
    print(f"Analysis failures: {failures}")
    print(f"Risk category counts: {dict(counts)}")
    print(f"CSV report saved to: {output}")


if __name__ == "__main__":
    main()
