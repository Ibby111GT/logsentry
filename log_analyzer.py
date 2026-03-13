#!/usr/bin/env python3
"""
log_analyzer.py -- LogSentry entry point.

Parses one or more log files, runs all detection rules,
and prints a summary report to the terminal.

Usage:
    python log_analyzer.py auth.log
    python log_analyzer.py *.log --output report.json
    python log_analyzer.py /var/log/nginx/access.log --quiet
"""

import argparse
import glob
import sys
import time

from parser   import parse_file
from rules    import ALL_RULES
from reporter import print_summary, save_json


def parse_args():
    p = argparse.ArgumentParser(
        description="LogSentry -- security log analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("logs", nargs="+", metavar="FILE",
                   help="Log file(s) to analyse (globs accepted)")
    p.add_argument("--output", default=None, metavar="FILE",
                   help="Save JSON report to this path")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-alert detail, only show counts")
    return p.parse_args()


def expand_globs(patterns):
    paths = []
    for pat in patterns:
        matched = glob.glob(pat)
        paths.extend(matched if matched else [pat])
    return paths


def main():
    args  = parse_args()
    paths = expand_globs(args.logs)

    if not paths:
        print("[!] No log files found.", file=sys.stderr)
        sys.exit(1)

    t0      = time.time()
    entries = []

    for path in paths:
        try:
            entries.extend(parse_file(path))
        except FileNotFoundError:
            print(f"[!] File not found: {path}", file=sys.stderr)
        except PermissionError:
            print(f"[!] Permission denied: {path}", file=sys.stderr)

    if not entries:
        print("[!] No log entries parsed.", file=sys.stderr)
        sys.exit(1)

    alerts = []
    for rule_fn in ALL_RULES:
        result = rule_fn(entries)
        if result is not None:
            alerts.append(result)

    elapsed = time.time() - t0
    print_summary(alerts, total_entries=len(entries), elapsed=elapsed)

    if args.output:
        save_json(alerts, args.output, total_entries=len(entries), elapsed=elapsed)


if __name__ == "__main__":
    main()
