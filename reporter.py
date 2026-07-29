"""
reporter.py -- output formatting for LogSentry findings.

Supports terminal (ANSI colour) and JSON file output. The JSON shape is
stable: every key below is always present, even when nothing fired.
"""

import json
import sys
from datetime import datetime
from typing import Dict, List, Optional
from models import Alert, SEVERITY_RANK


SCHEMA_VERSION = 1

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


def top_source_ips(alerts: List[Alert], limit: int = 5) -> List[Dict[str, object]]:
    """Count how many flagged events each source IP is responsible for."""
    counts: Dict[str, int] = {}
    for alert in alerts:
        for entry in alert.matched:
            if entry.ip:
                counts[entry.ip] = counts.get(entry.ip, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"ip": ip, "events": n} for ip, n in ranked[:limit]]


def print_summary(alerts: List[Alert], total_entries: int, elapsed: float,
                  risk: Optional[dict] = None, severity_filter: Optional[str] = None,
                  total_findings: Optional[int] = None, quiet: bool = False) -> None:
    """Print a coloured summary to stdout."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(_c(_BOLD, "=" * 68))
    print(_c(_BOLD, "  LogSentry -- Security Log Analysis Report"))
    print(f"  Generated : {now}")
    print(f"  Log lines : {total_entries}")
    print(f"  Scan time : {elapsed:.2f}s")
    if risk:
        colour = _SEVERITY_COLOUR.get(risk["level"], "")
        print(f"  Risk      : {risk['score']}/100  {_c(colour, risk['level'])}")
    print(_c(_BOLD, "=" * 68))
    print()

    if severity_filter:
        shown = f"{len(alerts)} of {total_findings if total_findings is not None else len(alerts)}"
        print(f"  Severity filter: {severity_filter} and above ({shown} findings shown)")
        print()

    if not alerts:
        print(_c(_GREEN, "  [OK] No findings."))
        print()
        return

    sorted_alerts = sorted(alerts,
                           key=lambda a: (SEVERITY_RANK.get(a.severity, 0), a.count),
                           reverse=True)

    for alert in sorted_alerts:
        colour  = _SEVERITY_COLOUR.get(alert.severity, "")
        sev_tag = _c(colour, f"[{alert.severity}]")
        print(f"  {sev_tag}  {alert.rule_id}  {_c(_BOLD, alert.rule_name)}")
        print(f"      {alert.description}")
        print(f"      Matched {alert.count} log event(s)"
              + (f"   MITRE {alert.mitre}" if alert.mitre else ""))
        if not quiet:
            if alert.why:
                print(f"      Why it matters: {alert.why}")
            for entry in alert.matched[:3]:      # up to 3 sample lines
                print(f"      {_c(_DIM, entry.raw[:110].rstrip())}")
        print()

    print(_c(_BOLD, "-" * 68))
    print(f"  Total findings : {len(alerts)}")
    for sev, colour in (("CRITICAL", _RED), ("HIGH", _RED), ("MEDIUM", _YELLOW), ("LOW", _CYAN)):
        n = sum(1 for a in alerts if a.severity == sev)
        if n:
            print(_c(colour, f"  {sev:<15}: {n}"))

    ips = top_source_ips(alerts)
    if ips:
        print()
        print("  Top source IPs in findings:")
        for row in ips:
            print(f"    {row['ip']:<16} {row['events']} flagged event(s)")
    print(_c(_BOLD, "-" * 68))
    print()


def build_report(alerts: List[Alert], total_entries: int, elapsed: float,
                 risk: Optional[dict] = None, files: Optional[List[str]] = None,
                 severity_filter: Optional[str] = None) -> dict:
    """Build the machine-readable report (stable key set)."""
    return {
        "tool": "LogSentry",
        "schema_version": SCHEMA_VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "files_analysed": list(files or []),
        "total_log_entries": total_entries,
        "elapsed_sec": round(elapsed, 3),
        "severity_filter": severity_filter,
        "risk": risk or {"score": 0, "level": "NONE", "formula": ""},
        "finding_count": len(alerts),
        "findings": [
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "description": a.description,
                "why": a.why,
                "mitre": a.mitre,
                "matched_count": a.count,
                "samples": [e.raw[:200] for e in a.matched[:5]],
            }
            for a in sorted(alerts, key=lambda a: a.rule_id)
        ],
        "top_source_ips": top_source_ips(alerts),
    }


def save_json(alerts: List[Alert], path: str, total_entries: int, elapsed: float,
              risk: Optional[dict] = None, files: Optional[List[str]] = None,
              severity_filter: Optional[str] = None, announce: bool = True) -> dict:
    """Dump findings to a JSON file for downstream processing."""
    data = build_report(alerts, total_entries, elapsed,
                        risk=risk, files=files, severity_filter=severity_filter)
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    if announce:
        print(f"  JSON report saved -> {path}")
    return data
