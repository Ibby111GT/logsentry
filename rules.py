"""
rules.py — detection rules for LogSentry.

Each rule is a callable that receives a list of LogEntry objects and
returns an Alert (or None) if it fires. Metadata (id, name, severity,
why it matters, MITRE ATT&CK technique) is attached with @detection and
the function is registered in ALL_RULES.

Every rule here is deliberately simple and pattern-based. They are triage
signals, not proof: they tell an analyst which lines to read first.
"""

import re
from datetime import timedelta
from typing import Dict, List, Optional
from urllib.parse import unquote_plus

from models import LogEntry, Alert, Rule


ALL_RULES: list = []


def detection(rule: Rule):
    """Attach rule metadata to a detection function and register it."""
    def decorate(fn):
        fn.rule = rule
        ALL_RULES.append(fn)
        return fn
    return decorate


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _grep(entries: List[LogEntry], pattern: str) -> List[LogEntry]:
    rx = re.compile(pattern, re.IGNORECASE)
    return [e for e in entries if rx.search(e.message) or rx.search(e.raw)]


def _web_entries(entries: List[LogEntry]) -> List[LogEntry]:
    """Only HTTP request lines -- keeps web rules from firing on shell commands."""
    return [e for e in entries if e.source == "httpd" or "path" in e.extra]


def _grep_web(entries: List[LogEntry], pattern: str) -> List[LogEntry]:
    """Like _grep, but limited to HTTP requests and percent-decoded first,
    so URL-encoded payloads still match."""
    rx = re.compile(pattern, re.IGNORECASE)
    hits = []
    for e in _web_entries(entries):
        text = unquote_plus(e.message) + " " + unquote_plus(e.raw)
        if rx.search(text):
            hits.append(e)
    return hits


def _group_by_ip(entries: List[LogEntry]) -> Dict[str, List[LogEntry]]:
    """Group entries that actually carry a source IP (unknown sources are skipped)."""
    out: Dict[str, List[LogEntry]] = {}
    for e in entries:
        if e.ip:
            out.setdefault(e.ip, []).append(e)
    return out


def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


_FAILED_AUTH = r"(failed password|failed publickey|authentication failure|invalid user|failed none)"
_ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey|keyboard-interactive\S*) for ", re.I)
_INTERACTIVE_SOURCES = {"sshd", "su", "login"}


def _successful_logins(entries: List[LogEntry]) -> List[LogEntry]:
    """Interactive logins that succeeded (sshd 'Accepted ... for <user> from <ip>')."""
    return [e for e in entries if _ACCEPTED_RE.search(e.message or e.raw)]


# ---------------------------------------------------------------------------
# authentication rules
# ---------------------------------------------------------------------------

@detection(Rule(
    id="LS001",
    name="SSH brute force",
    severity="HIGH",
    why=("One source address failed to log in over and over. That is what an "
         "automated password-guessing tool looks like."),
    mitre="T1110.001",
))
def rule_ssh_brute_force(entries: List[LogEntry], threshold: int = 5) -> Optional[Alert]:
    fails = _grep(entries, _FAILED_AUTH)
    hits  = {ip: evts for ip, evts in _group_by_ip(fails).items() if len(evts) >= threshold}
    if not hits:
        return None

    matched = [e for evts in hits.values() for e in evts]
    ips     = ", ".join(sorted(hits))
    return rule_ssh_brute_force.rule.fire(
        f"{len(hits)} source IP(s) with >={threshold} failed logins: {ips}", matched)


@detection(Rule(
    id="LS002",
    name="Successful login after repeated failures",
    severity="CRITICAL",
    why=("A password-guessing run that ends in a successful login usually means "
         "the guessing worked and the account is now in someone else's hands."),
    mitre="T1110",
))
def rule_success_after_failures(entries: List[LogEntry], threshold: int = 3) -> Optional[Alert]:
    fails_seen: Dict[str, int] = {}
    matched: List[LogEntry] = []

    fail_ids = {id(e) for e in _grep(entries, _FAILED_AUTH)}
    for e in entries:                       # file order is the timeline
        if not e.ip:
            continue
        if id(e) in fail_ids:
            fails_seen[e.ip] = fails_seen.get(e.ip, 0) + 1
        elif _ACCEPTED_RE.search(e.message or e.raw) and fails_seen.get(e.ip, 0) >= threshold:
            matched.append(e)
            fails_seen[e.ip] = 0            # only report the first success per burst

    if not matched:
        return None
    who = ", ".join(sorted({f"{e.user or '?'}@{e.ip}" for e in matched}))
    return rule_success_after_failures.rule.fire(
        f"Login succeeded after >={threshold} failures from the same IP: {who}", matched)


@detection(Rule(
    id="LS003",
    name="Interactive root session opened",
    severity="HIGH",
    why=("Root can do anything on the machine. Admins are normally supposed to log "
         "in as themselves and use sudo, so a direct root session is worth checking."),
    mitre="T1078.003",
))
def rule_root_session(entries: List[LogEntry]) -> Optional[Alert]:
    rx = re.compile(r"(Accepted \w+ for root\b|session opened for user root\b|\(to root\))", re.I)
    hits = [e for e in entries
            if e.source.lower() in _INTERACTIVE_SOURCES and rx.search(e.message or e.raw)]
    if not hits:
        return None
    return rule_root_session.rule.fire(
        f"{len(hits)} interactive root session(s) opened (cron/sudo service sessions ignored)",
        hits)


@detection(Rule(
    id="LS004",
    name="Audit logging stopped or cleared",
    severity="CRITICAL",
    why=("Turning off or wiping the audit log is how an intruder hides their tracks. "
         "Logging almost never stops by itself in the middle of the night."),
    mitre="T1562.001 / T1070.002",
))
def rule_audit_tampering(entries: List[LogEntry]) -> Optional[Alert]:
    pattern = (r"(audit[^\n]*\b(exiting|stopped|disabled|cleared)"
               r"|Stopped Security Auditing Service"
               r"|systemctl stop auditd|service auditd stop|auditctl -[eD]"
               r"|Event log cleared|wtmp[^\n]*(truncated|cleared)"
               r"|rm\s+-\w*\s*/var/log)")
    hits = _grep(entries, pattern)
    if not hits:
        return None
    return rule_audit_tampering.rule.fire(
        f"{len(hits)} event(s) show audit logging being stopped or cleared", hits)


@detection(Rule(
    id="LS005",
    name="New user account created",
    severity="MEDIUM",
    why=("Attackers add an account so they can get back in after the original hole "
         "is closed. Every new account should match a real request."),
    mitre="T1136.001",
))
def rule_new_account(entries: List[LogEntry]) -> Optional[Alert]:
    pattern = (r"(new user:\s*name=|useradd\[|adduser\[|new group:\s*name="
               r"|add '[^']+' to group '(sudo|wheel|admin|root)')")
    hits = _grep(entries, pattern)
    if not hits:
        return None
    users = sorted({e.user for e in hits if e.user})
    detail = f" ({', '.join(users)})" if users else ""
    return rule_new_account.rule.fire(
        f"{len(hits)} account/group creation event(s){detail}", hits)


@detection(Rule(
    id="LS006",
    name="Sudo misuse",
    severity="MEDIUM",
    why=("Someone tried to run commands as an administrator and was refused, or got "
         "the sudo password wrong repeatedly. Normal admin work does not look like this."),
    mitre="T1548.003",
))
def rule_sudo_misuse(entries: List[LogEntry]) -> Optional[Alert]:
    pattern = (r"(NOT in sudoers|incorrect password attempt|command not allowed"
               r"|NOPASSWD|pam_unix\(sudo:auth\): authentication failure)")
    hits = _grep(entries, pattern)
    if not hits:
        return None
    return rule_sudo_misuse.rule.fire(
        f"{len(hits)} refused or abnormal sudo event(s)", hits)


@detection(Rule(
    id="LS007",
    name="Off-hours successful login",
    severity="MEDIUM",
    why=("A login in the middle of the night is not automatically bad, but it is "
         "unusual for most staff and is a cheap thing to double-check."),
    mitre="T1078",
))
def rule_off_hours_login(entries: List[LogEntry],
                         start_hour: int = 0, end_hour: int = 6) -> Optional[Alert]:
    hits = [e for e in _successful_logins(entries)
            if e.dt is not None and start_hour <= e.dt.hour < end_hour]
    if not hits:
        return None
    return rule_off_hours_login.rule.fire(
        f"{len(hits)} successful login(s) between {start_hour:02d}:00 and {end_hour:02d}:00",
        hits)


@detection(Rule(
    id="LS008",
    name="Same account logging in from two IPs in quick succession",
    severity="HIGH",
    why=("One account signing in from two different addresses minutes apart usually "
         "means two different people are using it -- a stolen-credential signal."),
    mitre="T1078",
))
def rule_rapid_ip_change(entries: List[LogEntry], window_minutes: int = 15) -> Optional[Alert]:
    by_user: Dict[str, List[LogEntry]] = {}
    for e in _successful_logins(entries):
        if e.user and e.ip and e.dt is not None:
            by_user.setdefault(e.user, []).append(e)

    window  = timedelta(minutes=window_minutes)
    matched: List[LogEntry] = []
    users   = []
    for user, evts in by_user.items():
        evts.sort(key=lambda e: e.dt)
        for prev, cur in zip(evts, evts[1:]):
            if prev.ip != cur.ip and (cur.dt - prev.dt) <= window:
                matched.extend([prev, cur])
                users.append(user)

    if not matched:
        return None
    return rule_rapid_ip_change.rule.fire(
        f"account(s) {', '.join(sorted(set(users)))} logged in from 2+ IPs "
        f"within {window_minutes} minutes", matched)


# ---------------------------------------------------------------------------
# web rules
# ---------------------------------------------------------------------------

@detection(Rule(
    id="LS009",
    name="Path traversal attempt",
    severity="HIGH",
    why=("The request tries to climb out of the web folder ('../') to read files like "
         "the password list. Legitimate visitors never do this."),
    mitre="T1190",
))
def rule_path_traversal(entries: List[LogEntry]) -> Optional[Alert]:
    hits = _grep_web(entries, r"(\.\./|\.\.\\|%2e%2e|\.\.%2f|/etc/(passwd|shadow))")
    if not hits:
        return None
    ips = sorted({e.ip for e in hits if e.ip})
    return rule_path_traversal.rule.fire(
        f"{len(hits)} traversal-style request(s) from {', '.join(ips) or 'unknown source'}",
        hits)


@detection(Rule(
    id="LS010",
    name="SQL injection attempt",
    severity="CRITICAL",
    why=("The request contains database commands instead of ordinary input. If the "
         "site is vulnerable this can dump or destroy the whole database."),
    mitre="T1190",
))
def rule_sql_injection(entries: List[LogEntry]) -> Optional[Alert]:
    pattern = (r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1"
               r"|information_schema|sleep\(\d|benchmark\(|;\s*drop\s+table"
               r"|xp_cmdshell|'\s*or\s*1\s*=\s*1)")
    hits = _grep_web(entries, pattern)
    if not hits:
        return None
    ips = sorted({e.ip for e in hits if e.ip})
    return rule_sql_injection.rule.fire(
        f"{len(hits)} request(s) containing SQL syntax from {', '.join(ips) or 'unknown source'}",
        hits)


@detection(Rule(
    id="LS011",
    name="Scanner-style 404 burst",
    severity="MEDIUM",
    why=("One address asked for dozens of pages that do not exist. That is an "
         "automated tool hunting for forgotten admin panels, backups and config files."),
    mitre="T1595.003",
))
def rule_scanner_404_burst(entries: List[LogEntry], threshold: int = 15) -> Optional[Alert]:
    errors = [e for e in entries if 400 <= _to_int(e.extra.get("status")) < 500]
    hits   = {ip: evts for ip, evts in _group_by_ip(errors).items() if len(evts) >= threshold}
    if not hits:
        return None
    matched = [e for evts in hits.values() for e in evts]
    detail  = ", ".join(f"{ip} ({len(evts)} responses)" for ip, evts in sorted(hits.items()))
    return rule_scanner_404_burst.rule.fire(
        f">={threshold} 4xx responses to a single source: {detail}", matched)


@detection(Rule(
    id="LS012",
    name="Large outbound transfer",
    severity="HIGH",
    why=("A single very large download can be data leaving the building. Worth "
         "confirming it was a real backup or export and not someone copying data out."),
    mitre="T1048",
))
def rule_large_transfer(entries: List[LogEntry],
                        threshold_bytes: int = 50_000_000) -> Optional[Alert]:
    hits = []
    for e in entries:
        size = _to_int(e.extra.get("size"))
        if not size:
            m = re.search(r"bytes_sent[=:\s]+(\d+)", e.message or e.raw, re.I)
            size = _to_int(m.group(1)) if m else 0
        if size >= threshold_bytes:
            hits.append(e)

    if not hits:
        return None
    biggest = max(_to_int(e.extra.get("size")) for e in hits)
    return rule_large_transfer.rule.fire(
        f"{len(hits)} response(s) over {threshold_bytes // 1_000_000} MB "
        f"(largest {biggest // 1_000_000} MB)", hits)


# ---------------------------------------------------------------------------
# registry — ALL_RULES is populated by the @detection decorator above
# ---------------------------------------------------------------------------

def rule_catalogue() -> List[Rule]:
    """Static metadata for every registered rule, in id order."""
    return sorted((fn.rule for fn in ALL_RULES), key=lambda r: r.id)
