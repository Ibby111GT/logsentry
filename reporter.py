"""
reporter.py -- output formatting for LogSentry alerts.

Supports terminal (ANSI colour) and JSON file output.
"""

import json
import sys
from datetime import datetime
from typing import List
from models import Alert, SEVERITY_RANK


_RESET    = "\033[0m"
_BOLD     = "\033[1m"
_RED      = "\033[31m"
_YELLOW   = "\033[33m"
_CYAN     = "\033[36m"
_GREEN    = "\033[32m"
_DIM      = "\033[2m"

_SEVERITY_COLOUR = {
    "CRITICAL": "\033[41m\033[97m",  # white on red bg
    "HIGH":     "\033[31m",            # red
    "MEDIUM":   "\033[33m",            # yellow
    "LOW":      "\033[36m",            # cyan
}


def _c(code: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def print_summary(alerts: List[Alert], total_entries: int, elapsed: float) -> None:
    """Print a coloured summary to stdout."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(_c(_BOLD, "=" * 60))
    print(_c(_BOLD, "  LogSentry -- Security Log Analysis Report"))
    print(f"  Generated : {now}")
    print(f"  Log lines : {total_entries}")
    print(f"  Scan time : {elapsed:.2f}s")
    print(_c(_BOLD, "=" * 60))
    print()

    if not alerts:
        print(_c(_GREEN, "  [OK] No alerts triggered."))
        print()
        return

    sorted_alerts = sorted(alerts, key=lambda a: SEVERITY_RANK.get(a.severity, 0), reverse=True)

    for alert in sorted_alerts:
        colour = _SEVERITY_COLOUR.get(alert.severity, "")
        sev_tag = _c(colour, f"[{alert.severity}]")
        print(f"  {sev_tag}  {_c(_BOLD, alert.rule_name)}")
        print(f"      {alert.description}")
        print(f"      Matched {alert.count} log event(s)")
        if alert.matched:
            # show up to 3 sample lines
            for entry in alert.matched[:3]:
                snippet = entry.raw[:100].rstrip()
                print(f"      {_c(_DIM, snippet)}")
        print()

    print(_c(_BOLD, "-" * 60))
    print(f"  Total alerts : {len(alerts)}")
    critical = sum(1 for a in alerts if a.severity == 'CRITICAL')
    high     = sum(1 for a in alerts if a.severity == 'HIGH')
    if critical:
        print(_c(_RED, f"  CRITICAL     : {critical}"))
    if high:
        print(_c(_YELLOW, f"  HIGH         : {high}"))
    print(_c(_BOLD, "-" * 60))
    print()


def save_json(alerts: List[Alert], path: str, total_entries: int, elapsed: float) -> None:
    """Dump alerts to a JSON file for downstream processing."""
    data = {
        "generated": datetime.now().isoformat(),
        "total_log_entries": total_entries,
        "elapsed_sec": round(elapsed, 3),
        "alert_count": len(alerts),
        "alerts": [
            {
                "rule": a.rule_name,
                "severity": a.severity,
                "description": a.description,
                "matched_count": a.count,
                "samples": [e.raw[:200] for e in a.matched[:5]],
            }
            for a in alerts
        ],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"  Report saved -> {path}")
