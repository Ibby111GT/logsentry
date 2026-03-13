"""
parser.py -- multi-format log parser for LogSentry.

Supports: syslog (RFC 3164), Apache/Nginx combined,
JSON-per-line, and a generic fallback.
"""

import re
import json
from typing import List
from models import LogEntry


# syslog RFC 3164: Oct 12 06:55:04 host sshd[1234]: message
_SYSLOG_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<source>\S+?)(?:\[\d+\])?:\s+(?P<message>.*)"
)

# Apache/Nginx combined log format
_APACHE_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]'
    r'\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

_IP_RE = re.compile(r'(?:^|\s)((?:\d{1,3}\.){3}\d{1,3})(?:\s|$)')


def _parse_syslog(line: str) -> LogEntry:
    m = _SYSLOG_RE.match(line)
    if m:
        g = m.groupdict()
        ts = f"{g['month']} {g['day']} {g['time']}"
        return LogEntry(raw=line, timestamp=ts, source=g['source'],
                        message=g['message'])
    return LogEntry(raw=line, message=line)


def _parse_apache(line: str) -> LogEntry:
    m = _APACHE_RE.match(line)
    if m:
        g = m.groupdict()
        status = int(g['status'])
        level = 'ERROR' if status >= 500 else ('WARNING' if status >= 400 else 'INFO')
        return LogEntry(
            raw=line, timestamp=g['ts'], source='httpd',
            level=level, ip=g['ip'], user=g['user'],
            message=g['request'],
            extra={'status': g['status'], 'size': g['size']},
        )
    return LogEntry(raw=line, message=line)


def _parse_json(line: str) -> LogEntry:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return LogEntry(raw=line, message=line)

    return LogEntry(
        raw=line,
        timestamp=d.get('timestamp') or d.get('time') or d.get('@timestamp'),
        level=(d.get('level') or d.get('severity') or 'INFO').upper(),
        source=d.get('logger') or d.get('source') or 'unknown',
        message=d.get('message') or d.get('msg') or str(d),
        ip=d.get('remote_addr') or d.get('ip'),
        user=d.get('user') or d.get('username'),
        extra={k: str(v) for k, v in d.items()},
    )


def _detect_format(lines_list: list) -> str:
    for line in lines_list:
        line = line.strip()
        if not line:
            continue
        if line.startswith('{'):
            return 'json'
        if _APACHE_RE.match(line):
            return 'apache'
        if _SYSLOG_RE.match(line):
            return 'syslog'
    return 'generic'


def parse_file(path: str) -> List[LogEntry]:
    with open(path, 'r', errors='replace') as fh:
        raw_lines = fh.readlines()

    fmt = _detect_format(raw_lines)
    entries = []
    for line in raw_lines:
        line = line.rstrip('\n')
        if not line.strip():
            continue
        if fmt == 'json':
            entries.append(_parse_json(line))
        elif fmt == 'apache':
            entries.append(_parse_apache(line))
        elif fmt == 'syslog':
            entries.append(_parse_syslog(line))
        else:
            ip_m = _IP_RE.search(line)
            entries.append(LogEntry(raw=line, message=line,
                                    ip=ip_m.group(1) if ip_m else None))
    return entries


def parse_lines(text: str) -> List[LogEntry]:
    """Parse a block of log text directly (handy for unit tests)."""
    return parse_file.__wrapped__(text.splitlines(keepends=True))
