"""
models.py — shared data structures for LogSentry.

Keeping these in one place makes it easy to swap the
storage backend later without touching parser or rules.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class LogEntry:
    """A single parsed log line with extracted metadata."""
    raw:        str
    timestamp:  Optional[str]  = None
    level:      str             = "INFO"
    source:     str             = "unknown"
    message:    str             = ""
    ip:         Optional[str]  = None
    user:       Optional[str]  = None
    # any extra fields the parser finds go here
    extra:      Dict[str, str]  = field(default_factory=dict)


@dataclass
class Alert:
    """Fired when a rule matches one or more log entries."""
    rule_name:   str
    severity:    str            # LOW / MEDIUM / HIGH / CRITICAL
    description: str
    matched:     List[LogEntry] = field(default_factory=list)
    count:       int            = 0

    def __post_init__(self):
        if self.count == 0:
            self.count = len(self.matched)


# Severity ordering used by the reporter for sorting
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
