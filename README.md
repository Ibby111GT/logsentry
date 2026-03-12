# LogSentry — Security Log Analyzer

A SIEM-style log analysis engine that parses multi-format security logs, applies rule-based detection, and generates risk-scored alerts for SOC triage. Built with Python's standard library — no external dependencies.

## Features

- Multi-format parsing: SSH auth logs, Apache/Nginx access logs, syslog
- Rule engine with 10+ detection rules (brute force, SQLi, XSS, path traversal, scanners)
- Risk scoring 0-100 and severity classification (LOW / MEDIUM / HIGH / CRITICAL)
- Threshold-based alerting to reduce noise
- Top attacker IP summary
- JSON export for SIEM ingestion
- Demo mode with realistic synthetic log data

## Usage

```bash
# Demo mode (no files needed)
python log_analyzer.py --demo

# Analyze a live auth log
python log_analyzer.py --file /var/log/auth.log

# Multiple files, HIGH severity and above only
python log_analyzer.py --file /var/log/auth.log /var/log/nginx/access.log --severity HIGH

# Export alerts to JSON
python log_analyzer.py --demo --output alerts.json
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| BruteForce_SSH | HIGH | SSH brute-force (5+ failures) |
| RootLogin_Attempt | CRITICAL | Any failed root SSH login |
| SuccessfulRootLogin | CRITICAL | Successful root SSH login |
| PrivEsc_Sudo | MEDIUM | Privilege escalation via sudo |
| InvalidUser_Login | MEDIUM | Login with non-existent user |
| WebScan_UserAgent | HIGH | Security scanner detected (nikto, sqlmap, etc.) |
| SQLInjection_Attempt | HIGH | SQL injection patterns in requests |
| XSS_Attempt | MEDIUM | Cross-site scripting patterns |
| PathTraversal | HIGH | Directory traversal attempt |
| HTTP_Error_Spike | LOW | Spike in 4xx/5xx responses |

## Requirements

- Python 3.10+
- No external dependencies (pure stdlib)

## Use Cases

- SOC analyst daily log triage
- Incident response log review
- Security audit automation
- Detection rule development and testing
