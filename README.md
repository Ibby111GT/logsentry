# LogSentry — Security Log Analyzer

A small log analysis engine that parses security logs, applies 12 rule-based
detections, and prints risk-scored findings for triage. Built with Python's
standard library — no external dependencies, no network calls.

## Features

- Multi-format parsing: SSH/syslog (RFC 3164), Apache/Nginx combined access logs,
  JSON-per-line, and a generic fallback
- 12 detection rules covering auth abuse, privilege misuse, log tampering and web attacks
- Risk score 0–100 with a documented formula (see [Risk scoring](#risk-scoring))
- Severity filtering (`--severity`) so you can look at the serious findings first
- Top source IP summary across all findings
- JSON export with a stable key set for downstream tooling
- Demo mode running against bundled synthetic sample logs

## Usage

```bash
# Demo mode — analyses the bundled sample logs, no arguments needed
python3 log_analyzer.py --demo

# Analyse a specific log file
python3 log_analyzer.py --file samples/auth.log

# Several files, HIGH severity and above only
python3 log_analyzer.py --file samples/auth.log samples/access.log --severity HIGH

# Export findings to JSON (--json and --output are the same flag)
python3 log_analyzer.py --demo --json report.json

# Show the rule catalogue
python3 log_analyzer.py --list-rules
```

Files can also be passed positionally (`python3 log_analyzer.py samples/*.log`).
`--quiet` drops the per-finding explanation and sample lines.

## Detection rules

| ID | Rule | Severity | What it looks for | MITRE ATT&CK |
|----|------|----------|-------------------|--------------|
| LS001 | SSH brute force | HIGH | 5+ failed logins from one source IP | T1110.001 |
| LS002 | Successful login after repeated failures | CRITICAL | A success from an IP that just failed 3+ times | T1110 |
| LS003 | Interactive root session opened | HIGH | `Accepted … for root`, `su (to root)`, root sshd session (cron/sudo service sessions ignored) | T1078.003 |
| LS004 | Audit logging stopped or cleared | CRITICAL | auditd exiting/stopped/disabled, audit or event log cleared | T1562.001 / T1070.002 |
| LS005 | New user account created | MEDIUM | `useradd`/`adduser`, new group, or a user added to sudo/wheel/admin | T1136.001 |
| LS006 | Sudo misuse | MEDIUM | "user NOT in sudoers", repeated incorrect sudo passwords, NOPASSWD | T1548.003 |
| LS007 | Off-hours successful login | MEDIUM | Successful interactive logins between 00:00 and 06:00 | T1078 |
| LS008 | Same account logging in from two IPs in quick succession | HIGH | One account, two source IPs, within 15 minutes | T1078 |
| LS009 | Path traversal attempt | HIGH | `../`, encoded traversal, `/etc/passwd` in an HTTP request | T1190 |
| LS010 | SQL injection attempt | CRITICAL | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, etc. in an HTTP request | T1190 |
| LS011 | Scanner-style 404 burst | MEDIUM | 15+ 4xx responses to a single source IP | T1595.003 |
| LS012 | Large outbound transfer | HIGH | A single HTTP response over 50 MB | T1048 |

Thresholds (5 failures, 15 minutes, 50 MB, …) are keyword arguments on each rule
function in `rules.py`, so they are easy to tune.

Web rules (LS009–LS011) only ever look at HTTP request lines, so a shell command
containing `/etc/shadow` will not be reported as a web attack.

## Risk scoring

```
score = min(100, sum over findings of severity_weight x volume_multiplier)

severity_weight     LOW 2   MEDIUM 5   HIGH 10   CRITICAL 20
volume_multiplier   1.0 (<5 matched events)  1.5 (5-19)  2.0 (20+)

level    0 = NONE    1-24 = LOW    25-49 = MEDIUM    50-74 = HIGH    75-100 = CRITICAL
```

That is the whole model — a triage aid, not a statistical risk estimate. It is
deterministic: the same log file always produces the same score. The score always
covers every finding; `--severity` only changes what is displayed and exported.
The bundled demo log is a full end-to-end compromise, so it saturates the scale
at 100/100.

## Sample data

`samples/auth.log` and `samples/access.log` are synthetic, hand-written logs that
contain no real personal data and no real hostnames. All addresses come from the
documentation ranges reserved by RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`). Between them they trigger all 12 rules, and they also contain
benign traffic that must *not* trigger anything (cron root jobs, a normal sudo
command, a routine 404).

LogSentry never reads system logs unless you point it at one, and it makes no
network connections — the demo and the test suite touch only the bundled samples.

## Tests

```bash
python3 -m unittest discover -v
```

54 tests: parser behaviour on well-formed and malformed input, a positive and a
negative case for every rule, severity filtering, risk-score determinism, JSON
key shape, and end-to-end CLI runs.

## Requirements

- Python 3.10+ (developed and tested on 3.14)
- No external dependencies (pure stdlib)

## How it works (plain English)

**What is a log?** Every server keeps a diary. Each time someone signs in, fails
to sign in, runs an admin command, or loads a web page, one line of text is
written to a file. A busy machine writes thousands of these lines a day and
nobody reads them — which is exactly why attackers are comfortable there.

**What is this tool looking for?** LogSentry reads that diary and looks for the
handful of patterns that usually mean trouble: someone guessing passwords over
and over, a login that finally succeeds after all that guessing, the audit log
being switched off, a brand-new account appearing at 2am, a stranger asking the
web server for the password file, or one very large download. Twelve patterns in
total — they are listed in the table above, and each one explains in a sentence
why it matters.

**How do I run the demo?**

```bash
python3 log_analyzer.py --demo
```

That reads the two synthetic sample files in `samples/` — nothing on your own
machine, nothing over the internet — and prints a report.

**How do I read the findings?** Each finding has a severity: how bad it would be
if it is real.

- **CRITICAL** — likely a break-in in progress. Look now.
- **HIGH** — a strong attack signal. Look today.
- **MEDIUM** — suspicious, could be legitimate. Worth a question.
- **LOW** — background noise, useful for context.

The **risk score** rolls all of that into one number out of 100, so you can
compare one machine against another, or today against yesterday. It rises with
both the seriousness of the findings and how many log lines back them up. A score
of 0 means nothing fired; 100 is the top of the scale.

**What would someone actually do with this?** These are leads, not verdicts. An
analyst takes the top finding, reads the sample log lines printed underneath it,
and answers one question: is there an innocent explanation? The off-hours login
may be an engineer in another timezone. The new user account may be a ticket
someone filed. If there is no innocent explanation — a brute force, then a
successful login, then the audit log being turned off — that is an incident: lock
the account, reset the password, and work out what the intruder did next. The
JSON export exists so these findings can be fed into a bigger monitoring system
instead of being read by hand.

## Limitations

- Detections are pattern- and threshold-based. They will miss attacks that do not
  match the patterns, and they can flag legitimate activity (a real backup job
  looks like a large outbound transfer).
- Syslog lines carry no year, so LogSentry anchors them to a fixed placeholder
  year. Only the hour of day and the gap between entries are used, never the
  absolute date.
- There is no cross-file correlation beyond running the same rules over all
  parsed entries together, and no geolocation — LS008 compares IP addresses, not
  physical locations.

## Use cases

- SOC analyst daily log triage
- Incident response log review
- Detection rule development and testing
