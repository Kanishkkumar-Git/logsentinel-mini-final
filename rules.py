"""
Deterministic pre-detection rules.

Why this matters for the resume story: pure "ask an LLM to find attacks"
is expensive and non-deterministic. Real detection pipelines layer cheap,
reliable rules FIRST, and reserve the LLM for ambiguous / novel cases.

This module implements a simple brute-force correlation rule:
  >= FAILURE_THRESHOLD auth failures from the same IP within WINDOW_SECONDS
"""

import re
from collections import defaultdict
from datetime import datetime
from dataclasses import dataclass, field

FAILURE_THRESHOLD = 4
WINDOW_SECONDS = 120

# Matches typical syslog sshd auth failure lines, e.g.:
# Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; ... rhost=1.2.3.4
AUTH_FAIL_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"authentication failure.*?rhost=(?P<ip>[\w\.-]+)(?:\s+user=(?P<user>\S+))?",
    re.IGNORECASE,
)

CURRENT_YEAR = datetime.now().year


@dataclass
class BruteForceHit:
    source_ip: str
    failure_count: int
    window_start: str
    window_end: str
    target_users: set = field(default_factory=set)


def _parse_ts(month: str, day: str, time_str: str) -> datetime:
    ts_str = f"{CURRENT_YEAR} {month} {day} {time_str}"
    return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")


def detect_brute_force(lines: list[str]) -> list[BruteForceHit]:
    """Scan raw log lines for brute-force auth failure patterns.

    Returns a list of BruteForceHit for any IP that crosses the threshold
    within the sliding window. This is deterministic — no LLM involved.
    """
    events_by_ip: dict[str, list[tuple[datetime, str, str]]] = defaultdict(list)

    for line in lines:
        m = AUTH_FAIL_RE.search(line)
        if not m:
            continue
        try:
            ts = _parse_ts(m["month"], m["day"], m["time"])
        except ValueError:
            continue
        ip = m["ip"]
        user = m["user"] or "unknown"
        events_by_ip[ip].append((ts, user, line))

    hits: list[BruteForceHit] = []
    for ip, events in events_by_ip.items():
        events.sort(key=lambda e: e[0])
        window: list[tuple[datetime, str, str]] = []
        for ts, user, _line in events:
            window.append((ts, user, _line))
            # drop events outside the sliding window
            window = [e for e in window if (ts - e[0]).total_seconds() <= WINDOW_SECONDS]
            if len(window) >= FAILURE_THRESHOLD:
                hits.append(
                    BruteForceHit(
                        source_ip=ip,
                        failure_count=len(window),
                        window_start=window[0][0].isoformat(),
                        window_end=window[-1][0].isoformat(),
                        target_users={u for _, u, _ in window},
                    )
                )
                window = []  # reset after firing so we don't spam duplicate hits
    return hits


def lines_needing_llm_review(lines: list[str], brute_force_ips: set[str]) -> list[str]:
    """Return lines that the deterministic rules did NOT already resolve,
    so we only spend LLM tokens on ambiguous/novel content."""
    remaining = []
    for line in lines:
        m = AUTH_FAIL_RE.search(line)
        if m and m["ip"] in brute_force_ips:
            continue  # already explained by the brute-force rule
        remaining.append(line)
    return remaining
