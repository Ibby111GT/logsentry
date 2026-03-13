"""
rules.py — detection rules for LogSentry.

Each rule is a callable that receives a list of LogEntry objects
and returns an Alert (or None) if it fires.
"""

import re
from typing import List, Optional
from models import LogEntry, Alert


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _grep(entries: List[LogEntry], pattern: str) -> List[LogEntry]:
    rx = re.compile(pattern, re.IGNORECASE)
    return [e for e in entries if rx.search(e.message) or rx.search(e.raw)]


# ---------------------------------------------------------------------------
# individual rules
# ---------------------------------------------------------------------------

def rule_brute_force(entries: List[LogEntry], threshold: int = 5) -> Optional[Alert]:
    """Flag repeated failed login attempts from the same IP."""
    fails = _grep(entries, r"(failed|invalid|wrong).*(password|login|auth)")
    by_ip: dict = {}
    for e in fails:
        key = e.ip or "unknown"
        by_ip.setdefault(key, []).append(e)

    hits = {ip: evts for ip, evts in by_ip.items() if len(evts) >= threshold}
    if not hits:
        return None

    all_entries = [e for evts in hits.values() for e in evts]
    return Alert(
        rule_name="brute_force",
        severity="HIGH",
        description=f"Brute-force suspected: {len(hits)} source IP(s) with >={threshold} failures",
        matched=all_entries,
    )


def rule_privilege_escalation(entries: List[LogEntry]) -> Optional[Alert]:
    """Detect sudo / su abuse or unexpected privilege grants."""
    hits = _grep(entries, r"(sudo|su |privilege|escalat|root shell|NOPASSWD)")
    if not hits:
        return None
    return Alert(
        rule_name="privilege_escalation",
        severity="CRITICAL",
        description="Possible privilege escalation activity detected",
        matched=hits,
    )


def rule_port_scan(entries: List[LogEntry], threshold: int = 10) -> Optional[Alert]:
    """Spot a single IP hitting many ports in a short window."""
    hits = _grep(entries, r"(connection refused|port.*denied|syn|nmap|scan)")
    by_ip: dict = {}
    for e in hits:
        key = e.ip or "unknown"
        by_ip.setdefault(key, set()).add(e.extra.get("port", "?"))

    suspects = {ip: ports for ip, ports in by_ip.items() if len(ports) >= threshold}
    if not suspects:
        return None
    return Alert(
        rule_name="port_scan",
        severity="MEDIUM",
        description=f"Port scan detected from {len(suspects)} IP(s)",
        matched=hits,
    )


def rule_data_exfiltration(entries: List[LogEntry]) -> Optional[Alert]:
    """Large outbound transfers or suspicious data access patterns."""
    hits = _grep(entries, r"(exfil|large transfer|bytes_sent=[1-9][0-9]{6,}|dump|wget|curl.*-o)")
    if not hits:
        return None
    return Alert(
        rule_name="data_exfiltration",
        severity="HIGH",
        description="Potential data exfiltration activity",
        matched=hits,
    )


def rule_malware_indicators(entries: List[LogEntry]) -> Optional[Alert]:
    hits = _grep(entries, r"(malware|ransomware|trojan|backdoor|c2|command.and.control|beacon)")
    if not hits:
        return None
    return Alert(
        rule_name="malware_indicators",
        severity="CRITICAL",
        description="Malware-related keywords found in logs",
        matched=hits,
    )


# ---------------------------------------------------------------------------
# registry — add new rules here
# ---------------------------------------------------------------------------

ALL_RULES = [
    rule_brute_force,
    rule_privilege_escalation,
    rule_port_scan,
    rule_data_exfiltration,
    rule_malware_indicators,
]
