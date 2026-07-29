"""
parser.py -- multi-format log parser for LogSentry.

Supports: syslog (RFC 3164), Apache/Nginx combined,
JSON-per-line, and a generic fallback.

Design rule: never raise on a bad line. Anything the format parsers
choke on comes back as a plain LogEntry with the raw text preserved,
so one mangled line cannot kill a whole scan.
"""

import re
import json
from datetime import datetime, timezone
from typing import List, Optional
from models import LogEntry


# syslog RFC 3164: Oct 12 06:55:04 host sshd[1234]: message
_SYSLOG_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<source>\S+?)(?:\[\d+\])?:\s+(?P<message>.*)"
)

# Apache/Nginx combined log format (referrer + user-agent are optional)
_APACHE_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]'
    r'\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

_IP_RE = re.compile(r'(?:^|\s)((?:\d{1,3}\.){3}\d{1,3})(?:\s|$)')

# metadata we can pull out of an sshd / sudo / useradd syslog message
_FROM_IP_RE   = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})")
_AUTH_USER_RE = re.compile(r"\bfor\s+(?:invalid user\s+)?(?P<user>[\w.$-]+)\s+from\b", re.I)
_SESSION_RE   = re.compile(r"session opened for user\s+(?P<user>[\w.$-]+)", re.I)
_SUDO_USER_RE = re.compile(r"^\s*(?P<user>[\w.$-]+)\s+:\s+", re.I)
_NEWUSER_RE   = re.compile(r"new user:\s*name=(?P<user>[\w.$-]+)", re.I)

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}

# syslog lines carry no year, so we anchor them to a fixed leap year (Feb 29
# still parses). Only the hour-of-day and the gap between two entries are
# ever used by rules -- never the absolute date.
_ASSUMED_YEAR = 2000


def _syslog_dt(month: str, day: str, time_str: str) -> Optional[datetime]:
    try:
        hh, mm, ss = (int(p) for p in time_str.split(':'))
        return datetime(_ASSUMED_YEAR, _MONTHS[month.lower()], int(day), hh, mm, ss)
    except (KeyError, ValueError):
        return None


def _apache_dt(ts: str) -> Optional[datetime]:
    """'12/Jul/2025:09:31:02 +0000' -> naive UTC datetime."""
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            dt = datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
        except (ValueError, IndexError):
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _parse_syslog(line: str) -> LogEntry:
    m = _SYSLOG_RE.match(line)
    if not m:
        return LogEntry(raw=line, message=line)

    g   = m.groupdict()
    msg = g['message']
    ts  = f"{g['month']} {g['day']} {g['time']}"

    ip_m   = _FROM_IP_RE.search(msg)
    user_m = (_AUTH_USER_RE.search(msg) or _SESSION_RE.search(msg)
              or _NEWUSER_RE.search(msg) or _SUDO_USER_RE.search(msg))

    return LogEntry(
        raw=line, timestamp=ts, source=g['source'], message=msg,
        ip=ip_m.group(1) if ip_m else None,
        user=user_m.group('user') if user_m else None,
        dt=_syslog_dt(g['month'], g['day'], g['time']),
        extra={'host': g['host']},
    )


def _parse_apache(line: str) -> LogEntry:
    m = _APACHE_RE.match(line)
    if not m:
        return LogEntry(raw=line, message=line)

    g      = m.groupdict()
    status = int(g['status'])
    level  = 'ERROR' if status >= 500 else ('WARNING' if status >= 400 else 'INFO')

    extra = {'status': g['status'], 'size': g['size']}
    parts = g['request'].split()
    if len(parts) >= 2:
        extra['method'], extra['path'] = parts[0], parts[1]
    if g.get('agent'):
        extra['agent'] = g['agent']
    if g.get('referrer'):
        extra['referrer'] = g['referrer']

    return LogEntry(
        raw=line, timestamp=g['ts'], source='httpd',
        level=level, ip=g['ip'],
        user=None if g['user'] in ('-', '') else g['user'],
        message=g['request'],
        dt=_apache_dt(g['ts']),
        extra=extra,
    )


def _parse_json(line: str) -> LogEntry:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return LogEntry(raw=line, message=line)
    if not isinstance(d, dict):
        return LogEntry(raw=line, message=line)

    return LogEntry(
        raw=line,
        timestamp=d.get('timestamp') or d.get('time') or d.get('@timestamp'),
        level=str(d.get('level') or d.get('severity') or 'INFO').upper(),
        source=d.get('logger') or d.get('source') or 'unknown',
        message=str(d.get('message') or d.get('msg') or d),
        ip=d.get('remote_addr') or d.get('ip'),
        user=d.get('user') or d.get('username'),
        extra={k: str(v) for k, v in d.items()},
    )


def _parse_generic(line: str) -> LogEntry:
    ip_m = _IP_RE.search(line)
    return LogEntry(raw=line, message=line,
                    ip=ip_m.group(1) if ip_m else None)


_PARSERS = {
    'json':    _parse_json,
    'apache':  _parse_apache,
    'syslog':  _parse_syslog,
    'generic': _parse_generic,
}


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


def parse_raw_lines(raw_lines: List[str]) -> List[LogEntry]:
    """Detect the format of a list of raw lines and parse each one."""
    fmt     = _detect_format(raw_lines)
    handler = _PARSERS[fmt]
    entries = []

    for line in raw_lines:
        line = line.rstrip('\n')
        if not line.strip():
            continue
        try:
            entries.append(handler(line))
        except Exception:                  # noqa: BLE001 - one bad line must not kill the scan
            entries.append(LogEntry(raw=line, message=line,
                                    extra={'parse_error': '1'}))
    return entries


def parse_file(path: str) -> List[LogEntry]:
    with open(path, 'r', errors='replace') as fh:
        raw_lines = fh.readlines()
    return parse_raw_lines(raw_lines)


def parse_lines(text: str) -> List[LogEntry]:
    """Parse a block of log text directly (handy for unit tests)."""
    return parse_raw_lines(text.splitlines())
