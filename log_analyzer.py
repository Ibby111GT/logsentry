#!/usr/bin/env python3
"""
log_analyzer.py -- LogSentry entry point.

Parses one or more log files, runs every detection rule, scores the
result and prints a summary report to the terminal.

Usage:
    python log_analyzer.py --demo
    python log_analyzer.py --file samples/auth.log
    python log_analyzer.py --file samples/*.log --severity HIGH
    python log_analyzer.py --demo --json report.json
"""

import argparse
import glob
import os
import sys
import time

from models   import SEVERITIES, filter_by_severity, risk_score
from parser   import parse_file
from rules    import ALL_RULES, rule_catalogue
from reporter import print_summary, save_json


HERE          = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR    = os.path.join(HERE, "samples")
DEMO_LOGS     = [os.path.join(SAMPLE_DIR, "auth.log"),
                 os.path.join(SAMPLE_DIR, "access.log")]


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="LogSentry -- security log analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("logs", nargs="*", metavar="FILE",
                   help="Log file(s) to analyse (globs accepted)")
    p.add_argument("--file", dest="files", nargs="+", action="extend",
                   default=[], metavar="PATH",
                   help="Log file(s) to analyse; may be repeated")
    p.add_argument("--demo", action="store_true",
                   help="Analyse the bundled synthetic sample logs (no arguments needed)")
    p.add_argument("--severity", type=str.upper, choices=SEVERITIES, default=None,
                   metavar="LEVEL",
                   help="Only show findings at or above this severity "
                        "(LOW, MEDIUM, HIGH, CRITICAL)")
    p.add_argument("--json", "--output", dest="json_path", default=None, metavar="PATH",
                   help="Save the machine-readable JSON report to this path")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-finding detail, only show headline counts")
    p.add_argument("--list-rules", action="store_true",
                   help="Print the detection rule catalogue and exit")
    return p.parse_args(argv)


def expand_globs(patterns):
    paths = []
    for pat in patterns:
        matched = sorted(glob.glob(pat))
        paths.extend(matched if matched else [pat])
    return paths


def print_rules():
    catalogue = rule_catalogue()
    print(f"LogSentry detection rules ({len(catalogue)}):")
    for rule in catalogue:
        mitre = f"  [MITRE {rule.mitre}]" if rule.mitre else ""
        print(f"  {rule.id}  {rule.severity:<8} {rule.name}{mitre}")
        print(f"          {rule.why}")


def analyse(paths):
    """Parse the given files and run every rule. Returns (entries, alerts)."""
    entries = []
    for path in paths:
        try:
            entries.extend(parse_file(path))
        except FileNotFoundError:
            print(f"[!] File not found: {path}", file=sys.stderr)
        except PermissionError:
            print(f"[!] Permission denied: {path}", file=sys.stderr)
        except OSError as exc:
            print(f"[!] Could not read {path}: {exc}", file=sys.stderr)

    alerts = []
    for rule_fn in ALL_RULES:
        result = rule_fn(entries)
        if result is not None:
            alerts.append(result)
    return entries, alerts


def main(argv=None):
    args = parse_args(argv)

    if args.list_rules:
        print_rules()
        return 0

    if args.demo:
        paths = list(DEMO_LOGS)
    else:
        paths = expand_globs(list(args.files) + list(args.logs))

    if not paths:
        print("[!] Nothing to analyse. Use --demo, --file PATH, or pass a file name.",
              file=sys.stderr)
        return 1

    t0              = time.time()
    entries, alerts = analyse(paths)

    if not entries:
        print("[!] No log entries parsed.", file=sys.stderr)
        return 1

    # The risk score always covers every finding; --severity only filters
    # what gets displayed and exported.
    risk    = risk_score(alerts)
    shown   = filter_by_severity(alerts, args.severity)
    elapsed = time.time() - t0

    print_summary(shown, total_entries=len(entries), elapsed=elapsed, risk=risk,
                  severity_filter=args.severity, total_findings=len(alerts),
                  quiet=args.quiet)

    if args.json_path:
        save_json(shown, args.json_path, total_entries=len(entries), elapsed=elapsed,
                  risk=risk, files=paths, severity_filter=args.severity)
    return 0


if __name__ == "__main__":
    sys.exit(main())
