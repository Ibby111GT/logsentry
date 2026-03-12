#!/usr/bin/env python3
"""
LogSentry - Security Log Analyzer & Alert Engine
-------------------------------------------------
Parses system/web/auth logs, detects security events using rule-based
pattern matching, and generates risk-scored alerts for SOC triage.

Usage:
    python log_analyzer.py --file /var/log/auth.log
    python log_analyzer.py --file /var/log/nginx/access.log --severity HIGH
    python log_analyzer.py --demo
"""

import re
import sys
import json
import argparse
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# --- Severity levels ---

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Alert:
    timestamp: str
    severity: str
    rule_name: str
    description: str
    source_ip: Optional[str]
    user: Optional[str]
    raw_line: str
    risk_score: int = 0

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "rule": self.rule_name,
            "description": self.description,
            "source_ip": self.source_ip,
            "user": self.user,
            "risk_score": self.risk_score,
        }


# --- Detection rules ---

RULES = [
    {
        "name": "BruteForce_SSH",
        "pattern": r"Failed password for (?:invalid user )?(S+) from ([d.]+)",
        "severity": "HIGH",
        "description": "SSH brute-force attempt detected",
        "threshold": 5,
        "risk_score": 75,
    },
    {
        "name": "RootLogin_Attempt",
        "pattern": r"Failed password for root from ([d.]+)",
        "severity": "CRITICAL",
        "description": "Root login attempt via SSH",
        "threshold": 1,
        "risk_score": 95,
    },
    {
        "name": "InvalidUser_Login",
        "pattern": r"Invalid user (S+) from ([d.]+)",
        "severity": "MEDIUM",
        "description": "Login attempt with non-existent username",
        "threshold": 3,
        "risk_score": 50,
    },
    {
        "name": "PrivEsc_Sudo",
        "pattern": r"sudo:.*COMMAND=(.*)",
        "severity": "MEDIUM",
        "description": "Privilege escalation via sudo",
        "threshold": 1,
        "risk_score": 60,
    },
    {
        "name": "SuccessfulRootLogin",
        "pattern": r"Accepted .* for root from ([d.]+)",
        "severity": "CRITICAL",
        "description": "Successful root login",
        "threshold": 1,
        "risk_score": 99,
    },
    {
        "name": "WebScan_UserAgent",
        "pattern": r'"[A-Z]+ .* HTTP/[d.]+" d+ .* "((?:nikto|sqlmap|nmap|dirbuster|masscan|zgrab)[^"]*)"',
        "severity": "HIGH",
        "description": "Security scanner user-agent detected in web logs",
        "threshold": 1,
        "risk_score": 80,
        "case_insensitive": True,
    },
    {
        "name": "SQLInjection_Attempt",
        "pattern": r"(?:union.*select|select.*from|drop.*table|insert.*into|'.*or.*'.*='|%27|0x[0-9a-f]{4,})",
        "severity": "HIGH",
        "description": "SQL injection pattern in request",
        "threshold": 1,
        "risk_score": 85,
        "case_insensitive": True,
    },
    {
        "name": "XSS_Attempt",
        "pattern": r"(?:<script|javascript:|onerror=|onload=|alert(|document.cookie)",
        "severity": "MEDIUM",
        "description": "Cross-site scripting attempt in request",
        "threshold": 1,
        "risk_score": 65,
        "case_insensitive": True,
    },
    {
        "name": "PathTraversal",
        "pattern": r"(?:\.\./|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow)",
        "severity": "HIGH",
        "description": "Path traversal attempt",
        "threshold": 1,
        "risk_score": 80,
        "case_insensitive": True,
    },
    {
        "name": "HTTP_Error_Spike",
        "pattern": r'" (4dd|5dd) ',
        "severity": "LOW",
        "description": "HTTP error response",
        "threshold": 20,
        "risk_score": 25,
    },
]

IP_PATTERN = re.compile(r'(d{1,3}.d{1,3}.d{1,3}.d{1,3})')
USER_PATTERN = re.compile(r'(?:for|user) (S+)')
TS_PATTERNS = [
    re.compile(r'(d{4}-d{2}-d{2}[T ]d{2}:d{2}:d{2})'),
    re.compile(r'(w{3}s+d{1,2}s+d{2}:d{2}:d{2})'),
]


def extract_ip(line: str) -> Optional[str]:
    m = IP_PATTERN.search(line)
    return m.group(1) if m else None


def extract_user(line: str) -> Optional[str]:
    m = USER_PATTERN.search(line)
    return m.group(1) if m else None


def extract_timestamp(line: str) -> str:
    for pat in TS_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1)
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def analyze_log(lines: list, min_severity: str = "LOW") -> list:
    alerts = []
    counters = defaultdict(lambda: defaultdict(int))
    min_level = SEVERITY_LEVELS.get(min_severity, 1)

    compiled_rules = []
    for rule in RULES:
        flags = re.IGNORECASE if rule.get("case_insensitive") else 0
        compiled_rules.append((rule, re.compile(rule["pattern"], flags)))

    for line in lines:
        line = line.rstrip()
        if not line:
            continue

        for rule, pattern in compiled_rules:
            if pattern.search(line):
                key = rule["name"]
                counters[key]["count"] += 1

                if counters[key]["count"] >= rule["threshold"]:
                    if SEVERITY_LEVELS[rule["severity"]] >= min_level:
                        alert = Alert(
                            timestamp=extract_timestamp(line),
                            severity=rule["severity"],
                            rule_name=rule["name"],
                            description=rule["description"],
                            source_ip=extract_ip(line),
                            user=extract_user(line),
                            raw_line=line[:200],
                            risk_score=rule["risk_score"],
                        )
                        alerts.append(alert)
                    counters[key]["count"] = 0  # reset after alert

    return sorted(alerts, key=lambda a: -a.risk_score)


def generate_demo_logs() -> list:
    return [
        "Dec 10 14:23:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 52341 ssh2",
        "Dec 10 14:23:02 server sshd[1234]: Failed password for root from 192.168.1.100 port 52342 ssh2",
        "Dec 10 14:23:03 server sshd[1234]: Failed password for admin from 10.0.0.5 port 52343 ssh2",
        "Dec 10 14:23:04 server sshd[1234]: Invalid user deployer from 203.0.113.50 port 44444 ssh2",
        "Dec 10 14:23:05 server sshd[1234]: Invalid user deployer from 203.0.113.50 port 44445 ssh2",
        "Dec 10 14:23:06 server sshd[1234]: Invalid user deployer from 203.0.113.50 port 44446 ssh2",
        "Dec 10 14:24:00 server sshd[1234]: Accepted publickey for root from 192.168.1.5 port 22 ssh2",
        "Dec 10 14:25:00 server sudo: alice : COMMAND=/usr/bin/passwd root",
        '192.168.1.200 - - [10/Dec/2024:14:26:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 400 512 "-" "nikto/2.1.6"',
        '10.0.0.99 - - [10/Dec/2024:14:27:00 +0000] "GET /search?q=UNION+SELECT+username,password+FROM+users-- HTTP/1.1" 200 1024 "-" "curl/7.68"',
        '172.16.0.5 - - [10/Dec/2024:14:28:00 +0000] "GET /page?input=<script>alert(document.cookie)</script> HTTP/1.1" 200 256 "-" "Mozilla/5.0"',
    ]


def print_report(alerts: list, source: str = "demo"):
    sep = "=" * 60
    print(f"
{sep}")
    print(f"  LogSentry Security Report")
    print(f"  Source  : {source}")
    print(f"  Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Alerts  : {len(alerts)}")
    print(sep)

    if not alerts:
        print("  No alerts above threshold. System looks clean.")
        return

    by_severity = defaultdict(list)
    for a in alerts:
        by_severity[a.severity].append(a)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        group = by_severity.get(sev, [])
        if group:
            print(f"
  [{sev}] - {len(group)} alert(s)")
            print(f"  {'-'*55}")
            for a in group:
                print(f"  Rule      : {a.rule_name}")
                print(f"  Time      : {a.timestamp}")
                print(f"  Risk      : {a.risk_score}/100")
                if a.source_ip:
                    print(f"  Source IP : {a.source_ip}")
                if a.user:
                    print(f"  User      : {a.user}")
                print(f"  Detail    : {a.description}")
                print()

    print(sep)
    top_ips = defaultdict(int)
    for a in alerts:
        if a.source_ip:
            top_ips[a.source_ip] += 1
    if top_ips:
        print("
  Top Source IPs:")
        for ip, count in sorted(top_ips.items(), key=lambda x: -x[1])[:5]:
            print(f"    {ip:<20} {count} alert(s)")
    print()


def main():
    parser = argparse.ArgumentParser(description="LogSentry - Security log analyzer")
    parser.add_argument("--file", nargs="+", help="Log file(s) to analyze")
    parser.add_argument("--demo", action="store_true", help="Run with demo log data")
    parser.add_argument("--severity", default="LOW", choices=SEVERITY_LEVELS.keys(),
                        help="Minimum severity to report (default: LOW)")
    parser.add_argument("--output", help="Save alerts to JSON file")
    args = parser.parse_args()

    if args.demo:
        lines = generate_demo_logs()
        source = "demo"
    elif args.file:
        lines = []
        source = ", ".join(args.file)
        for path in args.file:
            try:
                with open(path) as f:
                    lines.extend(f.readlines())
            except FileNotFoundError:
                print(f"[!] File not found: {path}")
                sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)

    alerts = analyze_log(lines, min_severity=args.severity)
    print_report(alerts, source=source)

    if args.output:
        with open(args.output, "w") as f:
            json.dump([a.to_dict() for a in alerts], f, indent=2)
        print(f"[+] Alerts saved to {args.output}")


if __name__ == "__main__":
    main()
