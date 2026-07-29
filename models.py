"""
models.py — shared data structures for LogSentry.

Keeping these in one place makes it easy to swap the
storage backend later without touching parser or rules.
"""

from dataclasses import dataclass, field
from datetime import datetime
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
    # parsed form of `timestamp`, when the parser could work one out
    dt:         Optional[datetime] = None
    # any extra fields the parser finds go here
    extra:      Dict[str, str]  = field(default_factory=dict)


@dataclass
class Alert:
    """Fired when a rule matches one or more log entries."""
    rule_id:     str
    rule_name:   str
    severity:    str            # LOW / MEDIUM / HIGH / CRITICAL
    description: str            # what was seen in *this* log set
    why:         str = ""       # plain-English reason it matters
    mitre:       Optional[str] = None
    matched:     List[LogEntry] = field(default_factory=list)
    count:       int            = 0

    def __post_init__(self):
        if self.count == 0:
            self.count = len(self.matched)


@dataclass
class Rule:
    """Static metadata for a detection rule.

    The detection function itself lives in rules.py; this is the part
    we show to humans and export to JSON.
    """
    id:       str
    name:     str
    severity: str
    why:      str
    mitre:    Optional[str] = None

    def fire(self, description: str, matched: List[LogEntry]) -> Alert:
        """Build an Alert for this rule."""
        return Alert(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            description=description,
            why=self.why,
            mitre=self.mitre,
            matched=list(matched),
        )


# Severity ordering used by the reporter for sorting and by --severity
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ---------------------------------------------------------------------------
# risk scoring
# ---------------------------------------------------------------------------
# Deliberately simple and fully documented -- it is a triage aid, not a
# statistical model. Every input is something the tool actually observed.

SEVERITY_WEIGHT = {"LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}

RISK_FORMULA = (
    "score = min(100, sum(severity_weight x volume_multiplier) over all findings); "
    "weights LOW=2 MEDIUM=5 HIGH=10 CRITICAL=20; "
    "volume_multiplier = 1.0 for <5 matched events, 1.5 for 5-19, 2.0 for 20+; "
    "levels: 0=NONE, 1-24=LOW, 25-49=MEDIUM, 50-74=HIGH, 75-100=CRITICAL"
)


def volume_multiplier(count: int) -> float:
    """A finding backed by more events counts for more -- in three coarse steps."""
    if count >= 20:
        return 2.0
    if count >= 5:
        return 1.5
    return 1.0


def risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "NONE"


def risk_score(alerts: List[Alert]) -> Dict[str, object]:
    """Aggregate findings into one 0-100 score. Deterministic: same input, same score."""
    total = 0.0
    for a in alerts:
        total += SEVERITY_WEIGHT.get(a.severity, 0) * volume_multiplier(a.count)
    score = min(100, int(round(total)))
    return {"score": score, "level": risk_level(score), "formula": RISK_FORMULA}


def filter_by_severity(alerts: List[Alert], minimum: Optional[str]) -> List[Alert]:
    """Keep only findings at or above `minimum` (None = keep everything)."""
    if not minimum:
        return list(alerts)
    floor = SEVERITY_RANK.get(minimum.upper(), 0)
    return [a for a in alerts if SEVERITY_RANK.get(a.severity, 0) >= floor]
